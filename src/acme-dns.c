/*
 * Copyright (C) 2026 Ameleo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Answering dns-01 challenges (RFC 8555 8.4): the TXT record is added to,
 * and then removed from, the zone using DNS UPDATE (RFC 2136) messages
 * signed with TSIG (RFC 8945), using a shared HMAC key, or with GSS-TSIG
 * (RFC 3645), using the host's Kerberos keys.
 *
 * The messages are built and parsed here: the resolver library only
 * sends queries to the system's name servers, and expands compressed names.
 * Queries to a configured resolver, to the zone's name servers, and updates
 * are sent over UDP, or TCP when the answer is truncated, or when the
 * message may be too large for UDP. */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef HAVE_GSS_TSIG
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#include <krb5.h>

#include <talloc.h>

#include "acme.h"
#include "submit-e.h"
#include "submit-u.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define DNS_PORT "53"
#define DNS_HEADER_LENGTH 12
#define DNS_MAX_UDP 512
#define DNS_MAX_MESSAGE 65535
#define DNS_MAX_NAME 255
#define DNS_MAX_LABEL 63
/* How long we wait for an answer, and how many times we ask over UDP. */
#define DNS_TIMEOUT 5
#define DNS_UDP_TRIES 2
/* How long we follow CNAMEs, and wait between checks of the servers. */
#define DNS_MAX_CNAMES 8
#define DNS_CHECK_INTERVAL 2
/* The fudge which we allow, and ask for, in TSIG (RFC 8945 5.2.3). */
#define TSIG_FUDGE 300
#define TSIG_MAX_MAC 1024
/* How long we ask GSS-TSIG keys to be kept by the server. */
#define TKEY_LIFETIME 3600

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_OPCODE_UPDATE (5 << 11)

#define DNS_CLASS_IN 1
#define DNS_CLASS_NONE 254
#define DNS_CLASS_ANY 255
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_TKEY 249
#define DNS_TYPE_TSIG 250

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTAUTH 9
#define TKEY_MODE_GSSAPI 3

enum dns_section {
	dns_answer,
	dns_authority,
	dns_additional,
};

struct dns_buf {
	unsigned char data[DNS_MAX_MESSAGE];
	size_t length;
	int overflow;
};

struct dns_rr {
	char name[NS_MAXDNAME];
	enum dns_section section;
	unsigned int type, class;
	uint32_t ttl;
	size_t offset;			/* where the record starts */
	size_t rdata;			/* where its data starts */
	size_t rdlength;
};

struct dns_reply {
	const unsigned char *msg;
	size_t length;
	unsigned int id, flags, rcode;
	unsigned int counts[4];
	struct dns_rr *rrs;
	size_t n_rrs;
};

struct dns_addr {
	struct sockaddr_storage ss;
	socklen_t length;
	char text[INET6_ADDRSTRLEN + 8];
};

struct dns_addrs {
	struct dns_addr *addrs;
	size_t n;
};

/* A server named by the configuration, or found in the DNS. */
struct dns_server {
	char *host;
	char *port;
};

struct tsig_algorithm {
	const char *name;
	const EVP_MD *(*md)(void);
};

static const struct tsig_algorithm tsig_algorithms[] = {
	{"hmac-sha256", EVP_sha256},
	{"hmac-sha384", EVP_sha384},
	{"hmac-sha512", EVP_sha512},
	{"hmac-sha224", EVP_sha224},
};

struct cm_acme_dns {
	void *ctx;
	struct cm_acme_dns_params params;
	struct dns_server update_server;
	struct dns_server *check_servers;
	size_t n_check_servers;
	struct dns_addrs resolver;
	/* TSIG with a shared key. */
	char *key_name;
	const struct tsig_algorithm *algorithm;
	unsigned char *secret;
	size_t secret_length;
#ifdef HAVE_GSS_TSIG
	/* GSS-TSIG: a security context, established with one server. */
	gss_cred_id_t cred;
	gss_ctx_id_t gss;
	char *gss_server;
	char *gss_key_name;
#endif
};

struct cm_acme_dns_record {
	char *domain;		/* the identifier */
	char *name;		/* where the TXT record goes */
	char *zone;
	char *primary;		/* the SOA's MNAME */
	char *value;
	int added;
};

/* Building messages. */

static void
put_u8(struct dns_buf *b, unsigned int v)
{
	if (b->length + 1 > sizeof(b->data)) {
		b->overflow = 1;
		return;
	}
	b->data[b->length++] = v & 0xff;
}

static void
put_u16(struct dns_buf *b, unsigned int v)
{
	put_u8(b, v >> 8);
	put_u8(b, v);
}

static void
put_u32(struct dns_buf *b, uint32_t v)
{
	put_u16(b, v >> 16);
	put_u16(b, v);
}

static void
put_u48(struct dns_buf *b, uint64_t v)
{
	put_u16(b, (v >> 32) & 0xffff);
	put_u32(b, v & 0xffffffff);
}

static void
put_bytes(struct dns_buf *b, const void *data, size_t length)
{
	if (b->length + length > sizeof(b->data)) {
		b->overflow = 1;
		return;
	}
	memcpy(b->data + b->length, data, length);
	b->length += length;
}

static void
set_u16(unsigned char *p, unsigned int v)
{
	p[0] = (v >> 8) & 0xff;
	p[1] = v & 0xff;
}

static unsigned int
get_u16(const unsigned char *p)
{
	return (p[0] << 8) | p[1];
}

static uint32_t
get_u32(const unsigned char *p)
{
	return ((uint32_t) get_u16(p) << 16) | get_u16(p + 2);
}

/* Check that a name is one which we can use: dot-separated labels of
 * letters, digits, hyphens and underscores, without escapes, and put it
 * in the form in which we keep names: lower case, without a final dot. */
static char *
dns_name(void *parent, const char *name)
{
	char *ret, *p;
	size_t label = 0, length;

	length = strlen(name);
	if ((length > 0) && (name[length - 1] == '.')) {
		length--;
	}
	if ((length == 0) || (length > DNS_MAX_NAME - 2)) {
		return NULL;
	}
	ret = talloc_strndup(parent, name, length);
	for (p = ret; *p != '\0'; p++) {
		if (*p == '.') {
			if (label == 0) {
				talloc_free(ret);
				return NULL;
			}
			label = 0;
			continue;
		}
		if (!isalnum((unsigned char) *p) && (*p != '-') &&
		    (*p != '_')) {
			talloc_free(ret);
			return NULL;
		}
		*p = tolower((unsigned char) *p);
		if (++label > DNS_MAX_LABEL) {
			talloc_free(ret);
			return NULL;
		}
	}
	if (label == 0) {
		talloc_free(ret);
		return NULL;
	}
	return ret;
}

/* A name, in the form in which it goes in messages, uncompressed, which is
 * also the canonical form which TSIG uses, since we keep names in lower
 * case. */
static void
put_name(struct dns_buf *b, const char *name)
{
	const char *p, *dot;
	size_t length;

	for (p = name; (p != NULL) && (*p != '\0'); p = dot ? dot + 1 : NULL) {
		dot = strchr(p, '.');
		length = dot ? (size_t) (dot - p) : strlen(p);
		if ((length == 0) || (length > DNS_MAX_LABEL)) {
			b->overflow = 1;
			return;
		}
		put_u8(b, length);
		put_bytes(b, p, length);
	}
	put_u8(b, 0);
}

static unsigned int
random_id(void)
{
	unsigned char id[2];

	if (RAND_bytes(id, sizeof(id)) != 1) {
		return (unsigned int) (time(NULL) ^ getpid()) & 0xffff;
	}
	return get_u16(id);
}

static void
put_header(struct dns_buf *b, unsigned int flags, unsigned int qd,
	   unsigned int an, unsigned int ns, unsigned int ar)
{
	b->length = 0;
	b->overflow = 0;
	put_u16(b, random_id());
	put_u16(b, flags);
	put_u16(b, qd);
	put_u16(b, an);
	put_u16(b, ns);
	put_u16(b, ar);
}

static int
name_is(const char *a, const char *b)
{
	size_t la, lb;

	la = strlen(a);
	lb = strlen(b);
	if ((la > 0) && (a[la - 1] == '.')) {
		la--;
	}
	if ((lb > 0) && (b[lb - 1] == '.')) {
		lb--;
	}
	return (la == lb) && (strncasecmp(a, b, la) == 0);
}

/* Is "name" "zone", or a name under it? */
static int
name_in(const char *name, const char *zone)
{
	size_t ln, lz;

	ln = strlen(name);
	lz = strlen(zone);
	if (ln == lz) {
		return strcasecmp(name, zone) == 0;
	}
	return (ln > lz) && (name[ln - lz - 1] == '.') &&
	       (strcasecmp(name + ln - lz, zone) == 0);
}

/* Parsing messages. */

static int
expand_name(const unsigned char *msg, size_t length, size_t offset,
	    char *name, size_t size)
{
	int n;

	if (offset >= length) {
		return -1;
	}
	n = dn_expand(msg, msg + length, msg + offset, name, size);
	if ((n < 0) || (offset + n > length)) {
		return -1;
	}
	return n;
}

static int
parse_reply(void *parent, const unsigned char *msg, size_t length,
	    struct dns_reply *reply)
{
	char name[NS_MAXDNAME];
	size_t offset, total, i;
	unsigned int j;
	int n;

	memset(reply, 0, sizeof(*reply));
	if (length < DNS_HEADER_LENGTH) {
		return -1;
	}
	reply->msg = msg;
	reply->length = length;
	reply->id = get_u16(msg);
	reply->flags = get_u16(msg + 2);
	reply->rcode = reply->flags & 0x0f;
	for (j = 0; j < 4; j++) {
		reply->counts[j] = get_u16(msg + 4 + 2 * j);
	}
	offset = DNS_HEADER_LENGTH;
	for (j = 0; j < reply->counts[0]; j++) {
		n = expand_name(msg, length, offset, name, sizeof(name));
		if ((n < 0) || (offset + n + 4 > length)) {
			return -1;
		}
		offset += n + 4;
	}
	total = reply->counts[1] + reply->counts[2] + reply->counts[3];
	reply->rrs = talloc_zero_array(parent, struct dns_rr, total + 1);
	if (reply->rrs == NULL) {
		return -1;
	}
	for (i = 0; i < total; i++) {
		struct dns_rr *rr = &reply->rrs[i];

		rr->offset = offset;
		if (i < reply->counts[1]) {
			rr->section = dns_answer;
		} else
		if (i < reply->counts[1] + reply->counts[2]) {
			rr->section = dns_authority;
		} else {
			rr->section = dns_additional;
		}
		n = expand_name(msg, length, offset, rr->name,
				sizeof(rr->name));
		if ((n < 0) || (offset + n + 10 > length)) {
			return -1;
		}
		offset += n;
		rr->type = get_u16(msg + offset);
		rr->class = get_u16(msg + offset + 2);
		rr->ttl = get_u32(msg + offset + 4);
		rr->rdlength = get_u16(msg + offset + 8);
		rr->rdata = offset + 10;
		offset += 10 + rr->rdlength;
		if (offset > length) {
			return -1;
		}
	}
	reply->n_rrs = total;
	return 0;
}

/* The name at the start of a record's data. */
static char *
rdata_name(void *parent, const struct dns_reply *reply,
	   const struct dns_rr *rr)
{
	char name[NS_MAXDNAME];

	if (expand_name(reply->msg, rr->rdata + rr->rdlength, rr->rdata,
			name, sizeof(name)) < 0) {
		return NULL;
	}
	return dns_name(parent, name);
}

/* Does a TXT record hold exactly this value? */
static int
txt_is(const struct dns_reply *reply, const struct dns_rr *rr,
       const char *value)
{
	const unsigned char *p, *end;
	size_t length = strlen(value), seen = 0, n;

	p = reply->msg + rr->rdata;
	end = p + rr->rdlength;
	while (p < end) {
		n = *p++;
		if ((p + n > end) || (seen + n > length) ||
		    (memcmp(p, value + seen, n) != 0)) {
			return 0;
		}
		seen += n;
		p += n;
	}
	return seen == length;
}

static const char *
rcode_text(unsigned int rcode)
{
	switch (rcode) {
	case 0: return "NOERROR";
	case 1: return "FORMERR";
	case 2: return "SERVFAIL";
	case 3: return "NXDOMAIN";
	case 4: return "NOTIMP";
	case 5: return "REFUSED";
	case 6: return "YXDOMAIN";
	case 7: return "YXRRSET";
	case 8: return "NXRRSET";
	case 9: return "NOTAUTH";
	case 10: return "NOTZONE";
	case 16: return "BADSIG";
	case 17: return "BADKEY";
	case 18: return "BADTIME";
	case 19: return "BADMODE";
	case 20: return "BADNAME";
	case 21: return "BADALG";
	case 22: return "BADTRUNC";
	}
	return "unknown error";
}

/* Talking to servers. */

/* "HOST", "HOST:PORT", "[ADDRESS]:PORT", or an IPv6 address. */
static int
parse_server(void *parent, const char *text, struct dns_server *server)
{
	const char *colon, *end;
	char *p;
	long port;

	server->port = talloc_strdup(parent, DNS_PORT);
	if (text[0] == '[') {
		end = strchr(text, ']');
		if ((end == NULL) || (end == text + 1)) {
			return -1;
		}
		server->host = talloc_strndup(parent, text + 1,
					      end - text - 1);
		colon = (end[1] == ':') ? end + 1 : NULL;
		if ((end[1] != '\0') && (colon == NULL)) {
			return -1;
		}
	} else {
		colon = strchr(text, ':');
		if ((colon != NULL) && (strchr(colon + 1, ':') != NULL)) {
			/* An IPv6 address, without a port. */
			colon = NULL;
		}
		server->host = colon ?
			       talloc_strndup(parent, text, colon - text) :
			       talloc_strdup(parent, text);
	}
	if ((server->host == NULL) || (strlen(server->host) == 0)) {
		return -1;
	}
	if (colon != NULL) {
		port = strtol(colon + 1, &p, 10);
		if ((p == colon + 1) || (*p != '\0') || (port <= 0) ||
		    (port > 65535)) {
			return -1;
		}
		server->port = talloc_asprintf(parent, "%ld", port);
	}
	return 0;
}

static const char *
server_text(void *parent, const struct dns_server *server)
{
	if (strcmp(server->port, DNS_PORT) == 0) {
		return server->host;
	}
	return talloc_asprintf(parent, strchr(server->host, ':') ?
			       "[%s]:%s" : "%s:%s",
			       server->host, server->port);
}

static int
add_addr(void *parent, struct dns_addrs *addrs, const struct sockaddr *sa,
	 socklen_t length)
{
	struct dns_addr *a;
	char host[INET6_ADDRSTRLEN], port[8];

	addrs->addrs = talloc_realloc(parent, addrs->addrs, struct dns_addr,
				      addrs->n + 1);
	if ((addrs->addrs == NULL) || (length > sizeof(a->ss))) {
		addrs->n = 0;
		return -1;
	}
	a = &addrs->addrs[addrs->n++];
	memset(a, 0, sizeof(*a));
	memcpy(&a->ss, sa, length);
	a->length = length;
	if (getnameinfo(sa, length, host, sizeof(host), port, sizeof(port),
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		snprintf(a->text, sizeof(a->text),
			 strchr(host, ':') ? "[%s]:%s" : "%s:%s", host, port);
	}
	return 0;
}

/* Addresses for a literal address, or a name, using the system's
 * resolver. */
static int
system_addrs(void *parent, const char *host, const char *port,
	     struct dns_addrs *addrs)
{
	struct addrinfo hints, *res = NULL, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICSERV;
	if (getaddrinfo(host, port, &hints, &res) != 0) {
		return -1;
	}
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if ((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6)) {
			add_addr(parent, addrs, ai->ai_addr, ai->ai_addrlen);
		}
	}
	freeaddrinfo(res);
	return (addrs->n > 0) ? 0 : -1;
}

static int
wait_for(int fd, short events, time_t deadline)
{
	struct pollfd pfd;
	time_t now;
	int ret;

	for (;;) {
		now = time(NULL);
		if (now >= deadline) {
			errno = ETIMEDOUT;
			return -1;
		}
		pfd.fd = fd;
		pfd.events = events;
		pfd.revents = 0;
		ret = poll(&pfd, 1, (deadline - now) * 1000);
		if (ret > 0) {
			return 0;
		}
		if (ret == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (errno != EINTR) {
			return -1;
		}
	}
}

static int
read_all(int fd, unsigned char *p, size_t length, time_t deadline)
{
	ssize_t n;

	while (length > 0) {
		if (wait_for(fd, POLLIN, deadline) != 0) {
			return -1;
		}
		n = read(fd, p, length);
		if (n <= 0) {
			if ((n < 0) && (errno == EINTR)) {
				continue;
			}
			if (n == 0) {
				errno = ECONNRESET;
			}
			return -1;
		}
		p += n;
		length -= n;
	}
	return 0;
}

static int
write_all(int fd, const unsigned char *p, size_t length, time_t deadline)
{
	ssize_t n;

	while (length > 0) {
		if (wait_for(fd, POLLOUT, deadline) != 0) {
			return -1;
		}
		n = write(fd, p, length);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		p += n;
		length -= n;
	}
	return 0;
}

/* Send a message to one address, and read the answer, checking that it is
 * the answer to it.  Returns 0 if we got one, or -1 and sets errno. */
static int
exchange_one(const struct dns_addr *addr, const struct dns_buf *query,
	     int tcp, struct dns_buf *answer)
{
	unsigned char prefix[2];
	time_t deadline;
	ssize_t n;
	int fd, try, flags, saved;
	socklen_t optlen;
	size_t length;

	answer->length = 0;
	fd = socket(addr->ss.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (fd == -1) {
		return -1;
	}
	flags = fcntl(fd, F_GETFL);
	if ((flags == -1) || (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)) {
		goto fail;
	}
	deadline = time(NULL) + DNS_TIMEOUT;
	if (connect(fd, (const struct sockaddr *) &addr->ss,
		    addr->length) != 0) {
		if (errno != EINPROGRESS) {
			goto fail;
		}
		if (wait_for(fd, POLLOUT, deadline) != 0) {
			goto fail;
		}
		optlen = sizeof(saved);
		if ((getsockopt(fd, SOL_SOCKET, SO_ERROR, &saved,
				&optlen) != 0) ||
		    (saved != 0)) {
			errno = saved ? saved : errno;
			goto fail;
		}
	}
	if (tcp) {
		set_u16(prefix, query->length);
		if ((write_all(fd, prefix, 2, deadline) != 0) ||
		    (write_all(fd, query->data, query->length,
			       deadline) != 0) ||
		    (read_all(fd, prefix, 2, deadline) != 0)) {
			goto fail;
		}
		length = get_u16(prefix);
		if ((length < DNS_HEADER_LENGTH) ||
		    (read_all(fd, answer->data, length, deadline) != 0)) {
			if (length < DNS_HEADER_LENGTH) {
				errno = EPROTO;
			}
			goto fail;
		}
		answer->length = length;
		if ((get_u16(answer->data) != get_u16(query->data)) ||
		    !(get_u16(answer->data + 2) & DNS_FLAG_QR)) {
			errno = EPROTO;
			goto fail;
		}
		close(fd);
		return 0;
	}
	for (try = 0; try < DNS_UDP_TRIES; try++) {
		deadline = time(NULL) + DNS_TIMEOUT;
		if (send(fd, query->data, query->length, 0) < 0) {
			goto fail;
		}
		while (wait_for(fd, POLLIN, deadline) == 0) {
			n = recv(fd, answer->data, sizeof(answer->data), 0);
			if (n < 0) {
				if ((errno == EINTR) || (errno == EAGAIN)) {
					continue;
				}
				goto fail;
			}
			/* Ignore anything which isn't an answer to our
			 * question. */
			if ((n < DNS_HEADER_LENGTH) ||
			    (get_u16(answer->data) != get_u16(query->data)) ||
			    !(get_u16(answer->data + 2) & DNS_FLAG_QR)) {
				continue;
			}
			answer->length = n;
			close(fd);
			return 0;
		}
		if (errno != ETIMEDOUT) {
			goto fail;
		}
	}
fail:
	saved = errno;
	close(fd);
	errno = saved;
	return -1;
}

/* Send a message to the first of a list of addresses which answers, over
 * TCP if the answer is truncated. */
static int
exchange(struct cm_acme_dns *dns, const struct dns_addrs *addrs,
	 const struct dns_buf *query, int tcp, struct dns_buf *answer,
	 const char **error)
{
	size_t i;

	tcp = tcp || (query->length > DNS_MAX_UDP);
	*error = NULL;
	for (i = 0; i < addrs->n; i++) {
		if (dns->params.verbose > 1) {
			fprintf(stderr, "DNS message to %s (%s).\n",
				addrs->addrs[i].text, tcp ? "TCP" : "UDP");
		}
		if (exchange_one(&addrs->addrs[i], query, tcp, answer) == 0) {
			if (!tcp &&
			    (get_u16(answer->data + 2) & DNS_FLAG_TC) &&
			    (exchange_one(&addrs->addrs[i], query, 1,
					  answer) != 0)) {
				*error = talloc_asprintf(dns->ctx, "%s: %s",
							 addrs->addrs[i].text,
							 strerror(errno));
				continue;
			}
			return 0;
		}
		*error = talloc_asprintf(dns->ctx, "%s: %s",
					 addrs->addrs[i].text,
					 strerror(errno));
	}
	if (*error == NULL) {
		*error = _("no address");
	}
	return -1;
}

/* Look a name up, with the configured resolver or else the system's.
 * Returns 0 if a server answered, whatever it said. */
static int
lookup(struct cm_acme_dns *dns, void *parent, const char *name,
       unsigned int type, struct dns_buf *answer, struct dns_reply *reply)
{
	struct dns_buf *query;
	const char *error;
	int n, ret = -1;

	query = talloc_zero(parent, struct dns_buf);
	if (query == NULL) {
		return -1;
	}
	put_header(query, DNS_FLAG_RD, 1, 0, 0, 0);
	put_name(query, name);
	put_u16(query, type);
	put_u16(query, DNS_CLASS_IN);
	if (query->overflow) {
		goto done;
	}
	if (dns->resolver.n > 0) {
		if (exchange(dns, &dns->resolver, query, 0, answer,
			     &error) != 0) {
			if (dns->params.verbose > 0) {
				fprintf(stderr, "No answer from the "
					"resolver: %s.\n", error);
			}
			goto done;
		}
	} else {
		if (!(_res.options & RES_INIT) && (res_init() != 0)) {
			goto done;
		}
		n = res_send(query->data, query->length, answer->data,
			     sizeof(answer->data));
		if (n < DNS_HEADER_LENGTH) {
			if (dns->params.verbose > 0) {
				fprintf(stderr, "No answer from the system's "
					"resolvers.\n");
			}
			goto done;
		}
		answer->length = n;
	}
	if (parse_reply(parent, answer->data, answer->length, reply) != 0) {
		goto done;
	}
	ret = 0;
done:
	talloc_free(query);
	return ret;
}

/* The addresses of a server: a literal address, or a name which we look
 * up with the configured resolver, or else the system's. */
static int
server_addrs(struct cm_acme_dns *dns, void *parent,
	     const struct dns_server *server, struct dns_addrs *addrs)
{
	static const unsigned int types[] = {DNS_TYPE_A, DNS_TYPE_AAAA};
	struct dns_buf *answer;
	struct dns_reply reply;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	unsigned char a[16];
	size_t i, j;

	memset(addrs, 0, sizeof(*addrs));
	if ((inet_pton(AF_INET, server->host, a) == 1) ||
	    (inet_pton(AF_INET6, server->host, a) == 1) ||
	    (dns->resolver.n == 0)) {
		return system_addrs(parent, server->host, server->port, addrs);
	}
	answer = talloc_zero(parent, struct dns_buf);
	if (answer == NULL) {
		return -1;
	}
	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (lookup(dns, parent, server->host, types[i], answer,
			   &reply) != 0) {
			continue;
		}
		for (j = 0; j < reply.n_rrs; j++) {
			const struct dns_rr *rr = &reply.rrs[j];

			if ((rr->section != dns_answer) ||
			    (rr->type != types[i]) ||
			    !name_is(rr->name, server->host)) {
				continue;
			}
			if ((rr->type == DNS_TYPE_A) && (rr->rdlength == 4)) {
				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				sin.sin_port = htons(atoi(server->port));
				memcpy(&sin.sin_addr, reply.msg + rr->rdata, 4);
				add_addr(parent, addrs,
					 (struct sockaddr *) &sin,
					 sizeof(sin));
			} else
			if ((rr->type == DNS_TYPE_AAAA) &&
			    (rr->rdlength == 16)) {
				memset(&sin6, 0, sizeof(sin6));
				sin6.sin6_family = AF_INET6;
				sin6.sin6_port = htons(atoi(server->port));
				memcpy(&sin6.sin6_addr, reply.msg + rr->rdata,
				       16);
				add_addr(parent, addrs,
					 (struct sockaddr *) &sin6,
					 sizeof(sin6));
			}
		}
	}
	talloc_free(answer);
	return (addrs->n > 0) ? 0 : -1;
}

/* TSIG. */

/* The data which the MAC covers (RFC 8945 4.3.3): the request's MAC, when
 * signing or checking a response, the message, without its TSIG record,
 * and the TSIG variables. */
static void
tsig_input(struct dns_buf *in, const unsigned char *request_mac,
	   size_t request_mac_length, const unsigned char *msg,
	   size_t length, const char *key_name, const char *algorithm,
	   uint64_t time_signed, unsigned int fudge, unsigned int error,
	   const unsigned char *other, size_t other_length)
{
	in->length = 0;
	in->overflow = 0;
	if (request_mac != NULL) {
		put_u16(in, request_mac_length);
		put_bytes(in, request_mac, request_mac_length);
	}
	put_bytes(in, msg, length);
	put_name(in, key_name);
	put_u16(in, DNS_CLASS_ANY);
	put_u32(in, 0);
	put_name(in, algorithm);
	put_u48(in, time_signed);
	put_u16(in, fudge);
	put_u16(in, error);
	put_u16(in, other_length);
	put_bytes(in, other, other_length);
}

static const char *
signing_key_name(struct cm_acme_dns *dns)
{
#ifdef HAVE_GSS_TSIG
	if (dns->params.gss_tsig) {
		return dns->gss_key_name;
	}
#endif
	return dns->key_name;
}

static const char *
signing_algorithm(struct cm_acme_dns *dns)
{
	if (dns->params.gss_tsig) {
		return "gss-tsig";
	}
	return dns->algorithm->name;
}

#ifdef HAVE_GSS_TSIG
static char *
gss_error(void *parent, OM_uint32 major, OM_uint32 minor)
{
	OM_uint32 min, ctx = 0;
	gss_buffer_desc text;
	char *ret;

	ret = talloc_strdup(parent, "");
	do {
		text.length = 0;
		text.value = NULL;
		gss_display_status(&min, major, GSS_C_GSS_CODE,
				   GSS_C_NO_OID, &ctx, &text);
		ret = talloc_asprintf_append(ret, "%s%.*s",
					     strlen(ret) ? "; " : "",
					     (int) text.length,
					     (char *) text.value);
		gss_release_buffer(&min, &text);
	} while (ctx != 0);
	if (minor != 0) {
		do {
			text.length = 0;
			text.value = NULL;
			gss_display_status(&min, minor, GSS_C_MECH_CODE,
					   GSS_C_NO_OID, &ctx, &text);
			ret = talloc_asprintf_append(ret, "; %.*s",
						     (int) text.length,
						     (char *) text.value);
			gss_release_buffer(&min, &text);
		} while (ctx != 0);
	}
	return ret;
}
#endif

static int
compute_mac(struct cm_acme_dns *dns, const struct dns_buf *in,
	    unsigned char *mac, size_t *mac_length)
{
	unsigned int length = EVP_MAX_MD_SIZE;
#ifdef HAVE_GSS_TSIG
	OM_uint32 major, minor;
	gss_buffer_desc message, token;

	if (dns->params.gss_tsig) {
		message.value = (void *) in->data;
		message.length = in->length;
		major = gss_get_mic(&minor, dns->gss, GSS_C_QOP_DEFAULT,
				    &message, &token);
		if (GSS_ERROR(major) || (token.length > TSIG_MAX_MAC)) {
			gss_release_buffer(&minor, &token);
			return -1;
		}
		memcpy(mac, token.value, token.length);
		*mac_length = token.length;
		gss_release_buffer(&minor, &token);
		return 0;
	}
#endif
	if (HMAC(dns->algorithm->md(), dns->secret, dns->secret_length,
		 in->data, in->length, mac, &length) == NULL) {
		return -1;
	}
	*mac_length = length;
	return 0;
}

static int
verify_mac(struct cm_acme_dns *dns, const struct dns_buf *in,
	   const unsigned char *mac, size_t mac_length)
{
	unsigned char expected[EVP_MAX_MD_SIZE];
	unsigned int length = sizeof(expected);
#ifdef HAVE_GSS_TSIG
	OM_uint32 major, minor;
	gss_buffer_desc message, token;

	if (dns->params.gss_tsig) {
		message.value = (void *) in->data;
		message.length = in->length;
		token.value = (void *) mac;
		token.length = mac_length;
		major = gss_verify_mic(&minor, dns->gss, &message, &token,
				       NULL);
		return GSS_ERROR(major) ? -1 : 0;
	}
#endif
	if ((HMAC(dns->algorithm->md(), dns->secret, dns->secret_length,
		  in->data, in->length, expected, &length) == NULL) ||
	    (length != mac_length) ||
	    (CRYPTO_memcmp(expected, mac, length) != 0)) {
		return -1;
	}
	return 0;
}

/* Sign a message, adding a TSIG record to it, and keep the MAC, which the
 * answer's MAC covers. */
static int
tsig_sign(struct cm_acme_dns *dns, struct dns_buf *msg, unsigned char *mac,
	  size_t *mac_length)
{
	struct dns_buf *in;
	uint64_t now = time(NULL);
	size_t rdlength_at;
	const char *key_name = signing_key_name(dns);
	const char *algorithm = signing_algorithm(dns);
	int ret = -1;

	in = talloc_zero(dns->ctx, struct dns_buf);
	if (in == NULL) {
		return -1;
	}
	tsig_input(in, NULL, 0, msg->data, msg->length, key_name, algorithm,
		   now, TSIG_FUDGE, 0, NULL, 0);
	if (in->overflow || (compute_mac(dns, in, mac, mac_length) != 0)) {
		goto done;
	}
	put_name(msg, key_name);
	put_u16(msg, DNS_TYPE_TSIG);
	put_u16(msg, DNS_CLASS_ANY);
	put_u32(msg, 0);
	rdlength_at = msg->length;
	put_u16(msg, 0);
	put_name(msg, algorithm);
	put_u48(msg, now);
	put_u16(msg, TSIG_FUDGE);
	put_u16(msg, *mac_length);
	put_bytes(msg, mac, *mac_length);
	put_bytes(msg, msg->data, 2);	/* original ID */
	put_u16(msg, 0);		/* error */
	put_u16(msg, 0);		/* other len */
	if (msg->overflow) {
		goto done;
	}
	set_u16(msg->data + rdlength_at, msg->length - rdlength_at - 2);
	set_u16(msg->data + 10, get_u16(msg->data + 10) + 1);
	ret = 0;
done:
	OPENSSL_cleanse(in->data, in->length);
	talloc_free(in);
	return ret;
}

/* Check the TSIG record of an answer.  Returns 0 if it is signed with our
 * key, or else -1, setting *tsig_error to the TSIG error which the server
 * reported, if it did, and *unsigned_reply if there was no TSIG record. */
static int
tsig_verify(struct cm_acme_dns *dns, const struct dns_reply *reply,
	    const unsigned char *request_mac, size_t request_mac_length,
	    unsigned int *tsig_error, int *unsigned_reply)
{
	const struct dns_rr *rr;
	const unsigned char *p, *end, *mac, *other;
	struct dns_buf *in;
	char algorithm[NS_MAXDNAME];
	uint64_t time_signed;
	unsigned int fudge, mac_length, original_id, error, other_length;
	time_t now;
	int n, ret = -1;

	*tsig_error = 0;
	*unsigned_reply = 0;
	rr = (reply->n_rrs > 0) ? &reply->rrs[reply->n_rrs - 1] : NULL;
	if ((rr == NULL) || (rr->type != DNS_TYPE_TSIG) ||
	    (rr->section != dns_additional)) {
		*unsigned_reply = 1;
		return -1;
	}
	if (!name_is(rr->name, signing_key_name(dns))) {
		return -1;
	}
	n = expand_name(reply->msg, rr->rdata + rr->rdlength, rr->rdata,
			algorithm, sizeof(algorithm));
	if ((n < 0) || !name_is(algorithm, signing_algorithm(dns))) {
		return -1;
	}
	p = reply->msg + rr->rdata + n;
	end = reply->msg + rr->rdata + rr->rdlength;
	if (p + 10 > end) {
		return -1;
	}
	time_signed = ((uint64_t) get_u16(p) << 32) | get_u32(p + 2);
	fudge = get_u16(p + 6);
	mac_length = get_u16(p + 8);
	p += 10;
	mac = p;
	if (p + mac_length + 6 > end) {
		return -1;
	}
	p += mac_length;
	original_id = get_u16(p);
	error = get_u16(p + 2);
	other_length = get_u16(p + 4);
	other = p + 6;
	if (other + other_length != end) {
		return -1;
	}
	if (error != 0) {
		*tsig_error = error;
		return -1;
	}
	in = talloc_zero(dns->ctx, struct dns_buf);
	if (in == NULL) {
		return -1;
	}
	tsig_input(in, request_mac, request_mac_length, reply->msg,
		   rr->offset, signing_key_name(dns), signing_algorithm(dns),
		   time_signed, fudge, error, other, other_length);
	if (in->overflow) {
		goto done;
	}
	/* The message, as it was before the TSIG record was added. */
	set_u16(in->data + (request_mac ? 2 + request_mac_length : 0),
		original_id);
	set_u16(in->data + (request_mac ? 2 + request_mac_length : 0) + 10,
		reply->counts[3] - 1);
	if (verify_mac(dns, in, mac, mac_length) != 0) {
		*tsig_error = 16;	/* BADSIG */
		goto done;
	}
	now = time(NULL);
	if (((uint64_t) now > time_signed + fudge) ||
	    ((uint64_t) now + fudge < time_signed)) {
		*tsig_error = 18;	/* BADTIME */
		goto done;
	}
	ret = 0;
done:
	talloc_free(in);
	return ret;
}

/* Reading the key. */

/* The next token of a BIND configuration file: a word, a quoted string,
 * or one of "{", "}" and ";", skipping comments. */
static char *
next_token(void *parent, const char **p)
{
	const char *s = *p, *start;

	for (;;) {
		while (isspace((unsigned char) *s)) {
			s++;
		}
		if ((*s == '#') || ((s[0] == '/') && (s[1] == '/'))) {
			s += strcspn(s, "\n");
			continue;
		}
		if ((s[0] == '/') && (s[1] == '*')) {
			start = strstr(s + 2, "*/");
			s = start ? start + 2 : s + strlen(s);
			continue;
		}
		break;
	}
	if (*s == '\0') {
		*p = s;
		return NULL;
	}
	if (strchr("{};", *s) != NULL) {
		*p = s + 1;
		return talloc_strndup(parent, s, 1);
	}
	if (*s == '"') {
		start = ++s;
		while ((*s != '\0') && (*s != '"')) {
			s++;
		}
		*p = (*s == '"') ? s + 1 : s;
		return talloc_strndup(parent, start, s - start);
	}
	start = s;
	while ((*s != '\0') && !isspace((unsigned char) *s) &&
	       (strchr("{};\"", *s) == NULL)) {
		s++;
	}
	*p = s;
	return talloc_strndup(parent, start, s - start);
}

/* A key in the form in which BIND's tsig-keygen and ddns-confgen write
 * them:
 *	key "name" { algorithm hmac-sha256; secret "base64"; };
 * of which we use the first, or, on one line, "[algorithm:]name:secret",
 * as nsupdate's -y option takes it. */
static int
parse_key(void *parent, const char *text, char **name, char **algorithm,
	  char **secret)
{
	const char *p = text, *line, *colon, *second;
	char *token, *keyword, *value;
	size_t length;

	*name = *algorithm = *secret = NULL;
	if (strchr(text, '{') == NULL) {
		line = text + strspn(text, " \t");
		length = strcspn(line, " \t\r\n");
		colon = memchr(line, ':', length);
		if (colon == NULL) {
			return -1;
		}
		second = memchr(colon + 1, ':', length - (colon + 1 - line));
		if (second != NULL) {
			*algorithm = talloc_strndup(parent, line,
						    colon - line);
			*name = talloc_strndup(parent, colon + 1,
					       second - (colon + 1));
			colon = second;
		} else {
			*name = talloc_strndup(parent, line, colon - line);
		}
		*secret = talloc_strndup(parent, colon + 1,
					 length - (colon + 1 - line));
		return 0;
	}
	while ((token = next_token(parent, &p)) != NULL) {
		if (strcmp(token, "key") == 0) {
			break;
		}
	}
	if ((token == NULL) || ((*name = next_token(parent, &p)) == NULL) ||
	    ((token = next_token(parent, &p)) == NULL) ||
	    (strcmp(token, "{") != 0)) {
		return -1;
	}
	while (((keyword = next_token(parent, &p)) != NULL) &&
	       (strcmp(keyword, "}") != 0)) {
		value = next_token(parent, &p);
		token = next_token(parent, &p);
		if ((value == NULL) || (token == NULL) ||
		    (strcmp(token, ";") != 0)) {
			return -1;
		}
		if (strcasecmp(keyword, "algorithm") == 0) {
			*algorithm = value;
		} else
		if (strcasecmp(keyword, "secret") == 0) {
			*secret = value;
		}
	}
	return (keyword != NULL) ? 0 : -1;
}

static int
read_key(struct cm_acme_dns *dns, const char *filename)
{
	char *text, *name, *algorithm, *secret;
	void *tmp;
	size_t i;
	int ret = -1;

	text = cm_submit_u_from_file(filename);
	if (text == NULL) {
		printf(_("Error reading the TSIG key from \"%s\".\n"),
		       filename);
		return -1;
	}
	tmp = talloc_new(dns->ctx);
	if (parse_key(tmp, text, &name, &algorithm, &secret) != 0) {
		printf(_("The file \"%s\" does not hold a TSIG key.\n"),
		       filename);
		goto done;
	}
	if (algorithm == NULL) {
		algorithm = "hmac-sha256";
	}
	for (i = 0; i < sizeof(tsig_algorithms) / sizeof(tsig_algorithms[0]);
	     i++) {
		if (name_is(algorithm, tsig_algorithms[i].name)) {
			dns->algorithm = &tsig_algorithms[i];
		}
	}
	if (dns->algorithm == NULL) {
		printf(_("Unsupported TSIG algorithm \"%s\" in \"%s\".\n"),
		       algorithm, filename);
		goto done;
	}
	dns->key_name = dns_name(dns->ctx, name);
	if (dns->key_name == NULL) {
		printf(_("Invalid TSIG key name in \"%s\".\n"), filename);
		goto done;
	}
	dns->secret = cm_acme_b64_decode(dns->ctx, secret,
					 &dns->secret_length);
	if ((dns->secret == NULL) || (dns->secret_length == 0)) {
		printf(_("The TSIG key in \"%s\" is not base64-encoded.\n"),
		       filename);
		goto done;
	}
	ret = 0;
done:
	if (secret != NULL) {
		OPENSSL_cleanse(secret, strlen(secret));
	}
	OPENSSL_cleanse(text, strlen(text));
	free(text);
	talloc_free(tmp);
	return ret;
}

#ifdef HAVE_GSS_TSIG
/* GSS-TSIG (RFC 3645). */

static int
acquire_cred(struct cm_acme_dns *dns)
{
	OM_uint32 major, minor;
	gss_name_t name = GSS_C_NO_NAME;
	gss_buffer_desc buf;
	krb5_context kctx;
	char keytab[PATH_MAX + 16];
	const char *ktname = dns->params.keytab;
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	gss_key_value_element_desc elements[2];
	gss_key_value_set_desc store;
#endif

	if (dns->cred != GSS_C_NO_CREDENTIAL) {
		return 0;
	}
	if (ktname == NULL) {
		if (krb5_init_context(&kctx) != 0) {
			printf(_("Error initializing Kerberos.\n"));
			return -1;
		}
		if (krb5_kt_default_name(kctx, keytab, sizeof(keytab)) != 0) {
			krb5_free_context(kctx);
			printf(_("Error finding the default keytab.\n"));
			return -1;
		}
		krb5_free_context(kctx);
		ktname = keytab;
	}
	if (dns->params.principal != NULL) {
		buf.value = (void *) dns->params.principal;
		buf.length = strlen(dns->params.principal);
		major = gss_import_name(&minor, &buf,
					GSS_KRB5_NT_PRINCIPAL_NAME, &name);
		if (GSS_ERROR(major)) {
			printf(_("Error parsing the principal name \"%s\": "
				 "%s.\n"), dns->params.principal,
			       gss_error(dns->ctx, major, minor));
			return -1;
		}
	}
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	/* Credentials for the keytab's client, in a cache of our own. */
	elements[0].key = "client_keytab";
	elements[0].value = ktname;
	elements[1].key = "ccache";
	elements[1].value = "MEMORY:" PACKAGE_NAME "_acme_dns";
	store.count = 2;
	store.elements = elements;
	major = gss_acquire_cred_from(&minor, name, GSS_C_INDEFINITE,
				      GSS_C_NO_OID_SET, GSS_C_INITIATE,
				      &store, &dns->cred, NULL, NULL);
#else
	setenv("KRB5_CLIENT_KTNAME", ktname, 1);
	setenv("KRB5CCNAME", "MEMORY:" PACKAGE_NAME "_acme_dns", 1);
	major = gss_acquire_cred(&minor, name, GSS_C_INDEFINITE,
				 GSS_C_NO_OID_SET, GSS_C_INITIATE,
				 &dns->cred, NULL, NULL);
#endif
	if (name != GSS_C_NO_NAME) {
		gss_release_name(&minor, &name);
	}
	if (GSS_ERROR(major)) {
		printf(_("Error obtaining Kerberos credentials with the "
			 "keytab \"%s\": %s.\n"), ktname,
		       gss_error(dns->ctx, major, minor));
		dns->cred = GSS_C_NO_CREDENTIAL;
		return -1;
	}
	return 0;
}

static void
forget_context(struct cm_acme_dns *dns)
{
	OM_uint32 minor;

	if (dns->gss != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor, &dns->gss, GSS_C_NO_BUFFER);
	}
	dns->gss = GSS_C_NO_CONTEXT;
	talloc_free(dns->gss_server);
	dns->gss_server = NULL;
	talloc_free(dns->gss_key_name);
	dns->gss_key_name = NULL;
}

/* Establish a security context with the server, exchanging the GSS-API
 * tokens in TKEY queries (RFC 3645 3.1). */
static int
negotiate(struct cm_acme_dns *dns, const char *server,
	  const struct dns_addrs *addrs)
{
	static gss_OID_desc spnego = {6, (void *) "\x2b\x06\x01\x05\x05\x02"};
	OM_uint32 major, minor, flags;
	gss_name_t target = GSS_C_NO_NAME;
	gss_buffer_desc buf, input, output;
	struct dns_buf *query, *answer;
	struct dns_reply reply;
	const struct dns_rr *rr;
	const unsigned char *p, *end;
	unsigned char id[8], address[16];
	const char *error;
	char *service, algorithm[NS_MAXDNAME];
	unsigned int tkey_error, key_size, tsig_error;
	uint32_t now;
	size_t i;
	int n, round, unsigned_reply, have_reply = 0, ret = -1;

	if ((dns->gss != GSS_C_NO_CONTEXT) && (dns->gss_server != NULL) &&
	    name_is(dns->gss_server, server)) {
		return 0;
	}
	forget_context(dns);
	if (acquire_cred(dns) != 0) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if ((inet_pton(AF_INET, server, address) == 1) ||
	    (inet_pton(AF_INET6, server, address) == 1)) {
		printf(_("GSS-TSIG needs the name of the DNS server, not its "
			 "address (%s).\n"), server);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	service = talloc_asprintf(dns->ctx, "DNS@%s", server);
	buf.value = service;
	buf.length = strlen(service);
	major = gss_import_name(&minor, &buf, GSS_C_NT_HOSTBASED_SERVICE,
				&target);
	if (GSS_ERROR(major)) {
		printf(_("Error parsing the service name \"%s\": %s.\n"),
		       service, gss_error(dns->ctx, major, minor));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (RAND_bytes(id, sizeof(id)) != 1) {
		gss_release_name(&minor, &target);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	dns->gss_key_name = talloc_asprintf(dns->ctx,
					    "%02x%02x%02x%02x%02x%02x%02x%02x."
					    "sig-%s", id[0], id[1], id[2],
					    id[3], id[4], id[5], id[6], id[7],
					    server);
	if (strlen(dns->gss_key_name) > DNS_MAX_NAME - 2) {
		dns->gss_key_name[DNS_MAX_NAME - 2] = '\0';
	}
	dns->gss_key_name = dns_name(dns->ctx, dns->gss_key_name);
	if (dns->gss_key_name == NULL) {
		gss_release_name(&minor, &target);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	query = talloc_zero(dns->ctx, struct dns_buf);
	answer = talloc_zero(dns->ctx, struct dns_buf);
	input.length = 0;
	input.value = NULL;
	ret = CM_SUBMIT_STATUS_UNREACHABLE;
	for (round = 0; round < 8; round++) {
		output.length = 0;
		output.value = NULL;
		major = gss_init_sec_context(&minor, dns->cred, &dns->gss,
					     target, &spnego,
					     GSS_C_MUTUAL_FLAG |
					     GSS_C_REPLAY_FLAG |
					     GSS_C_INTEG_FLAG,
					     0, GSS_C_NO_CHANNEL_BINDINGS,
					     input.length ? &input : NULL,
					     NULL, &output, &flags, NULL);
		if (GSS_ERROR(major)) {
			printf(_("Error setting up GSS-TSIG with %s: %s.\n"),
			       service, gss_error(dns->ctx, major, minor));
			gss_release_buffer(&minor, &output);
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		if (output.length == 0) {
			gss_release_buffer(&minor, &output);
			if (major == GSS_S_COMPLETE) {
				break;
			}
			goto done;
		}
		/* A TKEY query, with the token in a TKEY record in the
		 * additional section, as BIND's and Windows' clients do. */
		now = time(NULL);
		put_header(query, 0, 1, 0, 0, 1);
		put_name(query, dns->gss_key_name);
		put_u16(query, DNS_TYPE_TKEY);
		put_u16(query, DNS_CLASS_ANY);
		put_name(query, dns->gss_key_name);
		put_u16(query, DNS_TYPE_TKEY);
		put_u16(query, DNS_CLASS_ANY);
		put_u32(query, 0);
		put_u16(query, strlen("gss-tsig") + 2 + 16 + output.length);
		put_name(query, "gss-tsig");
		put_u32(query, now);
		put_u32(query, now + TKEY_LIFETIME);
		put_u16(query, TKEY_MODE_GSSAPI);
		put_u16(query, 0);
		put_u16(query, output.length);
		put_bytes(query, output.value, output.length);
		put_u16(query, 0);
		gss_release_buffer(&minor, &output);
		if (query->overflow) {
			goto done;
		}
		if (exchange(dns, addrs, query, 1, answer, &error) != 0) {
			printf(_("Error talking to the DNS server: %s.\n"),
			       error);
			goto done;
		}
		if (parse_reply(answer, answer->data, answer->length,
				&reply) != 0) {
			printf(_("Error parsing the DNS server's answer.\n"));
			goto done;
		}
		have_reply = 1;
		if (reply.rcode != DNS_RCODE_NOERROR) {
			printf(_("The DNS server refused to set up GSS-TSIG "
				 "(%s).\n"), rcode_text(reply.rcode));
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		rr = NULL;
		for (i = 0; i < reply.n_rrs; i++) {
			if ((reply.rrs[i].section == dns_answer) &&
			    (reply.rrs[i].type == DNS_TYPE_TKEY) &&
			    name_is(reply.rrs[i].name, dns->gss_key_name)) {
				rr = &reply.rrs[i];
			}
		}
		if (rr == NULL) {
			printf(_("The DNS server did not answer the TKEY "
				 "query.\n"));
			goto done;
		}
		n = expand_name(reply.msg, rr->rdata + rr->rdlength, rr->rdata,
				algorithm, sizeof(algorithm));
		p = reply.msg + rr->rdata + ((n > 0) ? n : 0);
		end = reply.msg + rr->rdata + rr->rdlength;
		if ((n < 0) || !name_is(algorithm, "gss-tsig") ||
		    (p + 14 > end)) {
			printf(_("Error parsing the DNS server's TKEY "
				 "record.\n"));
			goto done;
		}
		tkey_error = get_u16(p + 10);
		key_size = get_u16(p + 12);
		if (tkey_error != 0) {
			printf(_("The DNS server refused to set up GSS-TSIG "
				 "(%s).\n"), rcode_text(tkey_error));
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		if (p + 14 + key_size > end) {
			printf(_("Error parsing the DNS server's TKEY "
				 "record.\n"));
			goto done;
		}
		if (major == GSS_S_COMPLETE) {
			break;
		}
		input.value = talloc_memdup(dns->ctx, p + 14, key_size);
		input.length = key_size;
	}
	if (dns->gss == GSS_C_NO_CONTEXT) {
		goto done;
	}
	/* The server signs its last answer with the new key. */
	if (have_reply &&
	    (tsig_verify(dns, &reply, NULL, 0, &tsig_error,
			 &unsigned_reply) != 0) && !unsigned_reply) {
		printf(_("The DNS server's answer is not signed with the "
			 "GSS-TSIG key (%s).\n"), rcode_text(tsig_error));
		goto done;
	}
	if (dns->params.verbose > 0) {
		fprintf(stderr, "GSS-TSIG key \"%s\" set up with %s.\n",
			dns->gss_key_name, server);
	}
	dns->gss_server = talloc_strdup(dns->ctx, server);
	ret = 0;
done:
	gss_release_name(&minor, &target);
	talloc_free(query);
	talloc_free(answer);
	if (ret != 0) {
		forget_context(dns);
	}
	return ret;
}
#endif

/* Updates. */

/* Add or delete our TXT record (RFC 2136 2.5.1, 2.5.4), and check the
 * server's answer. */
static int
send_update(struct cm_acme_dns *dns, struct cm_acme_dns_record *record,
	    int add)
{
	struct dns_server server;
	struct dns_addrs addrs;
	struct dns_buf *msg, *answer;
	struct dns_reply reply;
	unsigned char mac[TSIG_MAX_MAC];
	size_t mac_length = 0, value_length;
	const char *error;
	unsigned int tsig_error;
	int unsigned_reply, ret = CM_SUBMIT_STATUS_UNREACHABLE;

	if (dns->update_server.host != NULL) {
		server = dns->update_server;
	} else {
		server.host = record->primary;
		server.port = DNS_PORT;
	}
	if (server_addrs(dns, dns->ctx, &server, &addrs) != 0) {
		printf(_("Error finding the address of the DNS server "
			 "\"%s\".\n"), server_text(dns, &server));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
#ifdef HAVE_GSS_TSIG
	if (dns->params.gss_tsig) {
		ret = negotiate(dns, server.host, &addrs);
		if (ret != 0) {
			return ret;
		}
		ret = CM_SUBMIT_STATUS_UNREACHABLE;
	}
#endif
	msg = talloc_zero(dns->ctx, struct dns_buf);
	answer = talloc_zero(dns->ctx, struct dns_buf);
	if ((msg == NULL) || (answer == NULL)) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	value_length = strlen(record->value);
	put_header(msg, DNS_OPCODE_UPDATE, 1, 0, 1, 0);
	put_name(msg, record->zone);
	put_u16(msg, DNS_TYPE_SOA);
	put_u16(msg, DNS_CLASS_IN);
	put_name(msg, record->name);
	put_u16(msg, DNS_TYPE_TXT);
	put_u16(msg, add ? DNS_CLASS_IN : DNS_CLASS_NONE);
	put_u32(msg, add ? dns->params.ttl : 0);
	put_u16(msg, value_length + 1);
	put_u8(msg, value_length);
	put_bytes(msg, record->value, value_length);
	if (msg->overflow ||
	    (tsig_sign(dns, msg, mac, &mac_length) != 0)) {
		printf(_("Error signing the DNS update.\n"));
		ret = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	if (dns->params.verbose > 0) {
		fprintf(stderr, "%s TXT \"%s\" %s %s, in zone %s, at %s.\n",
			add ? "Adding" : "Removing", record->value,
			add ? "to" : "from", record->name, record->zone,
			server_text(dns, &server));
	}
	if (exchange(dns, &addrs, msg, dns->params.gss_tsig, answer,
		     &error) != 0) {
		printf(_("Error sending the DNS update to %s: %s.\n"),
		       server_text(dns, &server), error);
		goto done;
	}
	if (parse_reply(msg, answer->data, answer->length,
			&reply) != 0) {
		printf(_("Error parsing the answer to the DNS update.\n"));
		goto done;
	}
	if (tsig_verify(dns, &reply, mac, mac_length, &tsig_error,
			&unsigned_reply) != 0) {
		if (unsigned_reply && (reply.rcode != DNS_RCODE_NOERROR)) {
			printf(_("The DNS server %s refused the update (%s)."
				 "\n"), server_text(dns, &server),
			       rcode_text(reply.rcode));
			ret = (reply.rcode == DNS_RCODE_SERVFAIL) ?
			      CM_SUBMIT_STATUS_UNREACHABLE :
			      CM_SUBMIT_STATUS_UNCONFIGURED;
		} else
		if (tsig_error != 0) {
			printf(_("The DNS server %s refused the update's "
				 "signature (%s, %s).\n"),
			       server_text(dns, &server),
			       rcode_text(reply.rcode),
			       rcode_text(tsig_error));
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
		} else {
			printf(_("The answer of the DNS server %s to the "
				 "update is not signed with our key.\n"),
			       server_text(dns, &server));
		}
		goto done;
	}
	if (reply.rcode != DNS_RCODE_NOERROR) {
		printf(_("The DNS server %s refused the update (%s).\n"),
		       server_text(dns, &server), rcode_text(reply.rcode));
		ret = (reply.rcode == DNS_RCODE_SERVFAIL) ?
		      CM_SUBMIT_STATUS_UNREACHABLE :
		      CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	ret = 0;
done:
	talloc_free(msg);
	talloc_free(answer);
	return ret;
}

/* Finding where the record goes. */

/* Follow CNAMEs from _acme-challenge.<domain>, which can point to a zone
 * where we are allowed to make changes (RFC 8555 8.4 allows it, and CAs
 * follow them). */
static int
find_name(struct cm_acme_dns *dns, struct cm_acme_dns_record *record)
{
	struct dns_buf *answer;
	struct dns_reply reply;
	char *target;
	size_t i;
	int hops, found, ret = CM_SUBMIT_STATUS_UNREACHABLE;

	record->name = talloc_asprintf(dns->ctx, "_acme-challenge.%s",
				       record->domain);
	answer = talloc_zero(dns->ctx, struct dns_buf);
	if ((record->name == NULL) || (answer == NULL)) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	for (hops = 0; hops < DNS_MAX_CNAMES; hops++) {
		if (lookup(dns, answer, record->name, DNS_TYPE_CNAME,
			   answer, &reply) != 0) {
			printf(_("Error looking up \"%s\".\n"), record->name);
			goto done;
		}
		if ((reply.rcode != DNS_RCODE_NOERROR) &&
		    (reply.rcode != DNS_RCODE_NXDOMAIN)) {
			printf(_("Error looking up \"%s\" (%s).\n"),
			       record->name, rcode_text(reply.rcode));
			goto done;
		}
		found = 0;
		for (i = 0; i < reply.n_rrs; i++) {
			if ((reply.rrs[i].section != dns_answer) ||
			    (reply.rrs[i].type != DNS_TYPE_CNAME) ||
			    !name_is(reply.rrs[i].name, record->name)) {
				continue;
			}
			target = rdata_name(dns->ctx, &reply, &reply.rrs[i]);
			if (target == NULL) {
				printf(_("\"%s\" is an alias for a name which "
					 "we can't use.\n"), record->name);
				ret = CM_SUBMIT_STATUS_UNCONFIGURED;
				goto done;
			}
			if (dns->params.verbose > 0) {
				fprintf(stderr, "%s is an alias for %s.\n",
					record->name, target);
			}
			record->name = target;
			found = 1;
			break;
		}
		if (!found) {
			ret = 0;
			goto done;
		}
	}
	printf(_("Too many aliases for \"_acme-challenge.%s\".\n"),
	       record->domain);
	ret = CM_SUBMIT_STATUS_UNCONFIGURED;
done:
	talloc_free(answer);
	return ret;
}

/* Find the zone of the record, walking up from its name until we find a
 * name which owns an SOA record, and the zone's primary server. */
static int
find_zone(struct cm_acme_dns *dns, struct cm_acme_dns_record *record)
{
	struct dns_buf *answer;
	struct dns_reply reply;
	const char *candidate;
	const struct dns_rr *rr;
	char *jump;
	size_t i;
	int ret = CM_SUBMIT_STATUS_UNREACHABLE;

	answer = talloc_zero(dns->ctx, struct dns_buf);
	if (answer == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (dns->params.zone != NULL) {
		if (!name_in(record->name, dns->params.zone)) {
			printf(_("\"%s\" is not in the zone \"%s\".\n"),
			       record->name, dns->params.zone);
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		candidate = dns->params.zone;
	} else {
		candidate = record->name;
	}
	while ((candidate != NULL) && (*candidate != '\0')) {
		if (lookup(dns, answer, candidate, DNS_TYPE_SOA, answer,
			   &reply) != 0) {
			printf(_("Error looking up the SOA record of \"%s\"."
				 "\n"), candidate);
			goto done;
		}
		if ((reply.rcode != DNS_RCODE_NOERROR) &&
		    (reply.rcode != DNS_RCODE_NXDOMAIN)) {
			printf(_("Error looking up the SOA record of \"%s\" "
				 "(%s).\n"), candidate,
			       rcode_text(reply.rcode));
			goto done;
		}
		jump = NULL;
		for (i = 0; i < reply.n_rrs; i++) {
			rr = &reply.rrs[i];
			if (rr->type != DNS_TYPE_SOA) {
				continue;
			}
			if ((rr->section == dns_answer) &&
			    name_is(rr->name, candidate)) {
				record->zone = dns_name(dns->ctx, candidate);
				record->primary = rdata_name(dns->ctx, &reply,
							     rr);
				if ((record->zone == NULL) ||
				    (record->primary == NULL)) {
					printf(_("Error parsing the SOA record "
						 "of \"%s\".\n"), candidate);
					goto done;
				}
				if (dns->params.verbose > 0) {
					fprintf(stderr, "%s is in zone %s, "
						"whose primary server is %s."
						"\n", record->name,
						record->zone,
						record->primary);
				}
				ret = 0;
				goto done;
			}
			/* A negative answer carries the SOA record of the
			 * zone in which the name would be. */
			if ((rr->section == dns_authority) &&
			    !name_is(rr->name, candidate) &&
			    name_in(candidate, rr->name)) {
				jump = dns_name(dns->ctx, rr->name);
			}
		}
		if (dns->params.zone != NULL) {
			printf(_("\"%s\" is not a zone.\n"), dns->params.zone);
			ret = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		if (jump != NULL) {
			candidate = jump;
		} else {
			candidate = strchr(candidate, '.');
			candidate = candidate ? candidate + 1 : NULL;
		}
	}
	printf(_("Error finding the zone of \"%s\".\n"), record->name);
done:
	talloc_free(answer);
	return ret;
}

/* The servers which we check: the configured ones, or else the zone's
 * name servers. */
static int
zone_servers(struct cm_acme_dns *dns, struct cm_acme_dns_record *record,
	     struct dns_server **servers, size_t *n_servers)
{
	struct dns_buf *answer;
	struct dns_reply reply;
	char *name;
	size_t i;
	int ret = CM_SUBMIT_STATUS_UNREACHABLE;

	if (dns->n_check_servers > 0) {
		*servers = dns->check_servers;
		*n_servers = dns->n_check_servers;
		return 0;
	}
	*servers = NULL;
	*n_servers = 0;
	answer = talloc_zero(dns->ctx, struct dns_buf);
	if (answer == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if ((lookup(dns, answer, record->zone, DNS_TYPE_NS, answer,
		    &reply) != 0) ||
	    (reply.rcode != DNS_RCODE_NOERROR)) {
		printf(_("Error looking up the name servers of \"%s\".\n"),
		       record->zone);
		goto done;
	}
	for (i = 0; i < reply.n_rrs; i++) {
		if ((reply.rrs[i].section != dns_answer) ||
		    (reply.rrs[i].type != DNS_TYPE_NS) ||
		    !name_is(reply.rrs[i].name, record->zone)) {
			continue;
		}
		name = rdata_name(dns->ctx, &reply, &reply.rrs[i]);
		if (name == NULL) {
			continue;
		}
		*servers = talloc_realloc(dns->ctx, *servers,
					  struct dns_server, *n_servers + 1);
		(*servers)[*n_servers].host = name;
		(*servers)[*n_servers].port = DNS_PORT;
		(*n_servers)++;
	}
	if (*n_servers == 0) {
		printf(_("No name servers found for \"%s\".\n"),
		       record->zone);
		goto done;
	}
	ret = 0;
done:
	talloc_free(answer);
	return ret;
}

/* Does the server at this address serve the record?  Returns 1 if it
 * does, 0 if it doesn't, and -1 if it didn't answer. */
static int
serves(struct cm_acme_dns *dns, const struct dns_addr *addr,
       const struct cm_acme_dns_record *record)
{
	struct dns_buf *query, *answer;
	struct dns_reply reply;
	struct dns_addrs one;
	const char *error;
	size_t i;
	int ret = -1;

	query = talloc_zero(dns->ctx, struct dns_buf);
	answer = talloc_zero(dns->ctx, struct dns_buf);
	if ((query == NULL) || (answer == NULL)) {
		goto done;
	}
	put_header(query, 0, 1, 0, 0, 0);
	put_name(query, record->name);
	put_u16(query, DNS_TYPE_TXT);
	put_u16(query, DNS_CLASS_IN);
	one.addrs = (struct dns_addr *) addr;
	one.n = 1;
	if (exchange(dns, &one, query, 0, answer, &error) != 0) {
		if (dns->params.verbose > 0) {
			fprintf(stderr, "No answer from %s.\n", error);
		}
		goto done;
	}
	if (parse_reply(query, answer->data, answer->length,
			&reply) != 0) {
		goto done;
	}
	ret = 0;
	if (!(reply.flags & DNS_FLAG_AA) ||
	    (reply.rcode != DNS_RCODE_NOERROR)) {
		goto done;
	}
	for (i = 0; i < reply.n_rrs; i++) {
		if ((reply.rrs[i].section == dns_answer) &&
		    (reply.rrs[i].type == DNS_TYPE_TXT) &&
		    name_is(reply.rrs[i].name, record->name) &&
		    txt_is(&reply, &reply.rrs[i], record->value)) {
			ret = 1;
		}
	}
done:
	talloc_free(query);
	talloc_free(answer);
	return ret;
}

/* The public interface. */

static int
dns_destructor(struct cm_acme_dns *dns)
{
#ifdef HAVE_GSS_TSIG
	OM_uint32 minor;

	forget_context(dns);
	if (dns->cred != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &dns->cred);
	}
#endif
	if (dns->secret != NULL) {
		OPENSSL_cleanse(dns->secret, dns->secret_length);
	}
	return 0;
}

struct cm_acme_dns *
cm_acme_dns_new(void *parent, const struct cm_acme_dns_params *params)
{
	struct cm_acme_dns *dns;
	struct dns_server resolver;
	char *list, *item, *save = NULL;

	dns = talloc_zero(parent, struct cm_acme_dns);
	if (dns == NULL) {
		return NULL;
	}
	dns->ctx = dns;
	dns->params = *params;
#ifdef HAVE_GSS_TSIG
	dns->cred = GSS_C_NO_CREDENTIAL;
	dns->gss = GSS_C_NO_CONTEXT;
#endif
	talloc_set_destructor(dns, dns_destructor);
	if (dns->params.ttl <= 0) {
		dns->params.ttl = CM_ACME_DNS_DEFAULT_TTL;
	}
	if (dns->params.wait <= 0) {
		dns->params.wait = CM_ACME_DNS_DEFAULT_WAIT;
	}
	if ((params->tsig_key_file != NULL) && params->gss_tsig) {
		printf(_("A TSIG key and GSS-TSIG can't be used together.\n"));
		goto fail;
	}
	if ((params->tsig_key_file == NULL) && !params->gss_tsig) {
		printf(_("No TSIG key, nor GSS-TSIG, for DNS updates.\n"));
		goto fail;
	}
#ifndef HAVE_GSS_TSIG
	if (params->gss_tsig) {
		printf(_("This helper was built without GSS-TSIG support.\n"));
		goto fail;
	}
#endif
	if ((params->tsig_key_file != NULL) &&
	    (read_key(dns, params->tsig_key_file) != 0)) {
		goto fail;
	}
	if ((params->update_server != NULL) &&
	    (parse_server(dns, params->update_server,
			  &dns->update_server) != 0)) {
		printf(_("Invalid DNS server \"%s\".\n"),
		       params->update_server);
		goto fail;
	}
	if (params->zone != NULL) {
		dns->params.zone = dns_name(dns, params->zone);
		if (dns->params.zone == NULL) {
			printf(_("Invalid zone name \"%s\".\n"), params->zone);
			goto fail;
		}
	}
	if (params->resolver != NULL) {
		if ((parse_server(dns, params->resolver, &resolver) != 0) ||
		    (system_addrs(dns, resolver.host, resolver.port,
				  &dns->resolver) != 0)) {
			printf(_("Invalid DNS resolver \"%s\": an address is "
				 "expected.\n"), params->resolver);
			goto fail;
		}
	}
	if (params->check_servers != NULL) {
		list = talloc_strdup(dns, params->check_servers);
		for (item = strtok_r(list, ", ", &save); item != NULL;
		     item = strtok_r(NULL, ", ", &save)) {
			dns->check_servers = talloc_realloc(dns,
							    dns->check_servers,
							    struct dns_server,
							    dns->n_check_servers + 1);
			if (parse_server(dns, item,
					 &dns->check_servers[dns->n_check_servers]) != 0) {
				printf(_("Invalid DNS server \"%s\".\n"),
				       item);
				goto fail;
			}
			dns->n_check_servers++;
		}
	}
	return dns;
fail:
	talloc_free(dns);
	return NULL;
}

int
cm_acme_dns_publish(struct cm_acme_dns *dns, const char *domain,
		    const char *value, struct cm_acme_dns_record **record)
{
	struct cm_acme_dns_record *rec;
	int ret;

	*record = NULL;
	rec = talloc_zero(dns, struct cm_acme_dns_record);
	if (rec == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	rec->domain = dns_name(rec, domain);
	if (rec->domain == NULL) {
		printf(_("Can't publish a record for \"%s\".\n"), domain);
		talloc_free(rec);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	rec->value = talloc_strdup(rec, value);
	ret = find_name(dns, rec);
	if (ret == 0) {
		ret = find_zone(dns, rec);
	}
	if (ret == 0) {
		ret = send_update(dns, rec, 1);
	}
	if (ret != 0) {
		talloc_free(rec);
		return ret;
	}
	rec->added = 1;
	*record = rec;
	return 0;
}

int
cm_acme_dns_wait(struct cm_acme_dns *dns, struct cm_acme_dns_record *record)
{
	struct dns_server *servers;
	struct dns_addrs *addrs;
	size_t n_servers, i, j;
	int *done, answered, all, ret;
	time_t deadline;

	ret = zone_servers(dns, record, &servers, &n_servers);
	if (ret != 0) {
		return ret;
	}
	addrs = talloc_zero_array(dns, struct dns_addrs, n_servers);
	done = talloc_zero_array(dns, int, n_servers);
	if ((addrs == NULL) || (done == NULL)) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	deadline = time(NULL) + dns->params.wait;
	for (;;) {
		all = 1;
		for (i = 0; i < n_servers; i++) {
			if (done[i]) {
				continue;
			}
			if ((addrs[i].n == 0) &&
			    (server_addrs(dns, dns, &servers[i],
					  &addrs[i]) != 0)) {
				if (dns->params.verbose > 0) {
					fprintf(stderr, "No address for %s."
						"\n",
						server_text(dns, &servers[i]));
				}
				all = 0;
				continue;
			}
			/* Every address which answers must serve it, and at
			 * least one must answer. */
			answered = 0;
			done[i] = 1;
			for (j = 0; j < addrs[i].n; j++) {
				ret = serves(dns, &addrs[i].addrs[j], record);
				if (ret >= 0) {
					answered = 1;
				}
				if (ret == 0) {
					done[i] = 0;
				}
			}
			if (!answered) {
				done[i] = 0;
			}
			if (dns->params.verbose > 0) {
				fprintf(stderr, "%s %s.\n",
					server_text(dns, &servers[i]),
					done[i] ? "serves the record" :
					"does not serve the record yet");
			}
			if (!done[i]) {
				all = 0;
			}
		}
		if (all) {
			return 0;
		}
		if (time(NULL) + DNS_CHECK_INTERVAL > deadline) {
			break;
		}
		sleep(DNS_CHECK_INTERVAL);
	}
	printf(_("The record \"%s\" was not served by all of the zone's "
		 "servers within %ld seconds:"), record->name,
	       dns->params.wait);
	for (i = 0; i < n_servers; i++) {
		if (!done[i]) {
			printf(" %s", server_text(dns, &servers[i]));
		}
	}
	printf(".\n");
	return CM_SUBMIT_STATUS_UNREACHABLE;
}

int
cm_acme_dns_remove(struct cm_acme_dns *dns, struct cm_acme_dns_record *record)
{
	int ret;

	if ((record == NULL) || !record->added) {
		return 0;
	}
	ret = send_update(dns, record, 0);
	if (ret == 0) {
		record->added = 0;
	}
	return ret;
}
