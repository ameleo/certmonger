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

#include "config.h"

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <krb5.h>

#include <nss.h>
#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prio.h>
#include <prnetdb.h>
#include <secerr.h>
#include <ssl.h>
#include <sslerr.h>
#include <sslproto.h>

#include <talloc.h>

#include "est.h"
#include "log.h"
#include "store.h"
#include "submit-u.h"

#define EST_N_TIMEOUT 60
#define EST_N_MAX_RESPONSE (16 * 1024 * 1024)

struct cm_est_n_conn {
	const char *pin;
	CERTCertificate *cert;
	SECKEYPrivateKey *key;
	CERTCertList *anchors;
	int verbose;
};

/* Hand out the PIN we were given, once. */
static char *
pin_cb(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	struct cm_est_n_conn *conn = arg;

	if (retry || (conn == NULL) || (conn->pin == NULL)) {
		return NULL;
	}
	return PL_strdup(conn->pin);
}

/* Offer our certificate and key when the server asks for one. */
static SECStatus
client_auth_cb(void *arg, PRFileDesc *fd, CERTDistNames *ca_names,
	       CERTCertificate **cert, SECKEYPrivateKey **key)
{
	struct cm_est_n_conn *conn = arg;

	if ((conn->cert == NULL) || (conn->key == NULL)) {
		return SECFailure;
	}
	*cert = CERT_DupCertificate(conn->cert);
	*key = SECKEY_CopyPrivateKey(conn->key);
	if ((*cert == NULL) || (*key == NULL)) {
		return SECFailure;
	}
	return SECSuccess;
}

/* Check that "issuer" issued "cert", and that both are currently valid. */
static int
issued_by(CERTCertificate *cert, CERTCertificate *issuer, void *wincx)
{
	PRTime now = PR_Now();

	if (SECITEM_CompareItem(&cert->derIssuer,
				&issuer->derSubject) != SECEqual) {
		return 0;
	}
	if (CERT_CheckCertValidTimes(issuer, now, PR_FALSE) != secCertTimeValid) {
		return 0;
	}
	if (CERT_VerifySignedData(&cert->signatureWrap, issuer,
				  now, wincx) != SECSuccess) {
		return 0;
	}
	return 1;
}

/* Verify the server's certificate against the trust anchors we were given,
 * and only against them, instead of against whatever the database trusts:
 * walk up the chain which the server sent until we find a certificate which
 * was issued by one of the anchors, or is one of them. */
static SECStatus
server_auth_cb(void *arg, PRFileDesc *fd, PRBool checksig, PRBool is_server)
{
	struct cm_est_n_conn *conn = arg;
	CERTCertificate *peer, *current;
	CERTCertList *chain;
	CERTCertListNode *node;
	SECStatus rv = SECFailure;
	void *wincx;
	char *host;
	int depth, found;

	peer = SSL_PeerCertificate(fd);
	if (peer == NULL) {
		return SECFailure;
	}
	chain = SSL_PeerCertificateChain(fd);
	wincx = SSL_RevealPinArg(fd);
	if (CERT_CheckCertValidTimes(peer, PR_Now(),
				     PR_FALSE) != secCertTimeValid) {
		PORT_SetError(SEC_ERROR_EXPIRED_CERTIFICATE);
		goto done;
	}
	current = peer;
	for (depth = 0; depth < 16; depth++) {
		/* Is it an anchor, or issued by one? */
		for (node = CERT_LIST_HEAD(conn->anchors);
		     !CERT_LIST_END(node, conn->anchors);
		     node = CERT_LIST_NEXT(node)) {
			if (CERT_CompareCerts(current, node->cert) ||
			    issued_by(current, node->cert, wincx)) {
				rv = SECSuccess;
				break;
			}
		}
		if (rv == SECSuccess) {
			break;
		}
		/* Look for its issuer among the certificates which the server
		 * sent, which must be CA certificates. */
		found = 0;
		for (node = chain ? CERT_LIST_HEAD(chain) : NULL;
		     (node != NULL) && !CERT_LIST_END(node, chain);
		     node = CERT_LIST_NEXT(node)) {
			if (CERT_CompareCerts(current, node->cert) ||
			    !CERT_IsCACert(node->cert, NULL)) {
				continue;
			}
			if (issued_by(current, node->cert, wincx)) {
				current = node->cert;
				found = 1;
				break;
			}
		}
		if (!found) {
			break;
		}
	}
	if (rv != SECSuccess) {
		PORT_SetError(SEC_ERROR_UNTRUSTED_ISSUER);
	} else {
		host = SSL_RevealURL(fd);
		rv = CERT_VerifyCertName(peer, host);
		if (rv != SECSuccess) {
			PORT_SetError(SSL_ERROR_BAD_CERT_DOMAIN);
		}
		PORT_Free(host);
	}
done:
	if (chain != NULL) {
		CERT_DestroyCertList(chain);
	}
	CERT_DestroyCertificate(peer);
	return rv;
}

/* Read the trust anchors from a PEM file. */
static CERTCertList *
read_anchors(void *parent, const char *cainfo)
{
	CERTCertList *list;
	CERTCertificate *cert;
	SECItem item;
	char *pem, *p, *q, *b64;
	unsigned char *der;
	int length;

	pem = cm_submit_u_from_file(cainfo);
	if (pem == NULL) {
		return NULL;
	}
	list = CERT_NewCertList();
	if (list == NULL) {
		free(pem);
		return NULL;
	}
	p = pem;
	while ((p = strstr(p, "-----BEGIN CERTIFICATE-----")) != NULL) {
		p += strlen("-----BEGIN CERTIFICATE-----");
		q = strstr(p, "-----END CERTIFICATE-----");
		if (q == NULL) {
			break;
		}
		b64 = talloc_strndup(parent, p, q - p);
		der = (unsigned char *) cm_store_base64_as_bin(parent, b64,
							       -1, &length);
		if ((der != NULL) && (length > 0)) {
			item.type = siDERCertBuffer;
			item.data = der;
			item.len = length;
			cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
						       &item, NULL,
						       PR_FALSE, PR_TRUE);
			if (cert != NULL) {
				CERT_AddCertToListTail(list, cert);
			}
		}
		p = q;
	}
	free(pem);
	if (CERT_LIST_EMPTY(list)) {
		CERT_DestroyCertList(list);
		return NULL;
	}
	return list;
}

/* Split an https URL into host, port, and path. */
static int
parse_url(void *parent, const char *url,
	  char **host, PRUint16 *port, char **path)
{
	const char *p, *q, *r;
	long l;
	char *end;

	if (strncasecmp(url, "https://", 8) != 0) {
		return -1;
	}
	p = url + 8;
	r = p + strcspn(p, "/?#");
	if (*p == '[') {
		q = memchr(p, ']', r - p);
		if (q == NULL) {
			return -1;
		}
		*host = talloc_strndup(parent, p + 1, q - (p + 1));
		q++;
	} else {
		q = memchr(p, ':', r - p);
		if (q == NULL) {
			q = r;
		}
		*host = talloc_strndup(parent, p, q - p);
	}
	*port = 443;
	if ((q < r) && (*q == ':')) {
		l = strtol(q + 1, &end, 10);
		if ((end != r) || (l <= 0) || (l > 65535)) {
			return -1;
		}
		*port = l;
	} else
	if (q != r) {
		return -1;
	}
	*path = talloc_strdup(parent, (*r != '\0') ? r : "/");
	if ((*host == NULL) || (strlen(*host) == 0) || (*path == NULL)) {
		return -1;
	}
	return 0;
}

/* Open a TCP connection to the first address of the host which answers. */
static PRFileDesc *
connect_to(const char *host, PRUint16 port)
{
	PRAddrInfo *ai;
	PRNetAddr addr;
	PRFileDesc *fd = NULL;
	void *iter = NULL;

	ai = PR_GetAddrInfoByName(host, PR_AF_UNSPEC, PR_AI_ADDRCONFIG);
	if (ai == NULL) {
		return NULL;
	}
	while ((iter = PR_EnumerateAddrInfo(iter, ai, port, &addr)) != NULL) {
		fd = PR_OpenTCPSocket(PR_NetAddrFamily(&addr));
		if (fd == NULL) {
			continue;
		}
		if (PR_Connect(fd, &addr,
			       PR_SecondsToInterval(EST_N_TIMEOUT)) == PR_SUCCESS) {
			break;
		}
		PR_Close(fd);
		fd = NULL;
	}
	PR_FreeAddrInfo(ai);
	return fd;
}

/* Find the end of the line which starts at "p". */
static const char *
line_end(const char *p, const char *end)
{
	const char *q;

	q = memchr(p, '\n', end - p);
	return q ? q : end;
}

/* Undo chunked transfer-encoding, in place. */
static int
dechunk(unsigned char *body, size_t length, size_t *out_length)
{
	const char *p, *end, *q;
	unsigned char *out;
	unsigned long chunk;
	char *e;

	p = (const char *) body;
	end = p + length;
	out = body;
	for (;;) {
		q = line_end(p, end);
		if (q == end) {
			return -1;
		}
		chunk = strtoul(p, &e, 16);
		if (e == p) {
			return -1;
		}
		p = q + 1;
		if (chunk == 0) {
			break;
		}
		if (chunk > (unsigned long) (end - p)) {
			return -1;
		}
		memmove(out, p, chunk);
		out += chunk;
		p += chunk;
		if ((p < end) && (*p == '\r')) {
			p++;
		}
		if ((p < end) && (*p == '\n')) {
			p++;
		}
	}
	*out_length = out - body;
	return 0;
}

/* Pull the status, interesting headers, and body out of a response. */
static int
parse_response(void *parent, unsigned char *data, size_t length,
	       struct cm_est_response *response)
{
	const char *p, *q, *end, *v, *w;
	size_t name_len;
	int chunked = 0;
	char *e;

	p = (const char *) data;
	end = p + length;
	q = line_end(p, end);
	if ((q - p < 12) || (strncmp(p, "HTTP/", 5) != 0)) {
		return -1;
	}
	v = memchr(p, ' ', q - p);
	if (v == NULL) {
		return -1;
	}
	response->response_code = strtol(v + 1, &e, 10);
	if (e == v + 1) {
		return -1;
	}
	for (p = q + 1; p < end; p = q + 1) {
		q = line_end(p, end);
		if ((q == p) || ((q == p + 1) && (*p == '\r'))) {
			/* End of headers. */
			p = q + 1;
			break;
		}
		v = memchr(p, ':', q - p);
		if (v == NULL) {
			continue;
		}
		name_len = v - p;
		v++;
		v += strspn(v, " \t");
		w = q;
		while ((w > v) && (strchr(" \t\r", w[-1]) != NULL)) {
			w--;
		}
		if ((name_len == 12) && (strncasecmp(p, "Content-Type", 12) == 0)) {
			response->content_type = talloc_strndup(parent, v, w - v);
		} else
		if ((name_len == 11) && (strncasecmp(p, "Retry-After", 11) == 0)) {
			response->retry_after = talloc_strndup(parent, v, w - v);
		} else
		if ((name_len == 17) &&
		    (strncasecmp(p, "Transfer-Encoding", 17) == 0) &&
		    (w - v >= 7) &&
		    (strncasecmp(w - 7, "chunked", 7) == 0)) {
			chunked = 1;
		}
	}
	if (p > end) {
		p = end;
	}
	response->length = end - p;
	response->body = (const unsigned char *) p;
	if (chunked) {
		if (dechunk((unsigned char *) p, end - p,
			    &response->length) != 0) {
			return -1;
		}
	}
	return 0;
}

static void
set_nss_error(void *parent, struct cm_est_response *response,
	      const char *what)
{
	PRErrorCode ec;
	const char *name, *text;

	ec = PORT_GetError();
	name = PR_ErrorToName(ec);
	text = PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT);
	response->error = ec ? ec : -1;
	response->error_text = talloc_asprintf(parent, "%s: %s%s%s%s",
					       what,
					       name ? name : "unknown error",
					       (text && strlen(text)) ? " (" : "",
					       (text && strlen(text)) ? text : "",
					       (text && strlen(text)) ? ")" : "");
}

int
cm_est_n_request(void *parent,
		 const char *method, const char *url,
		 const char *content_type, const char *body,
		 const char *cainfo,
		 const char *dbdir, const char *token,
		 const char *cert_pem, const char *pin,
		 int verbose,
		 struct cm_est_response *response)
{
	NSSInitContext *nctx;
	struct cm_est_n_conn conn;
	PK11SlotInfo *slot = NULL;
	PRFileDesc *tcp = NULL, *ssl = NULL;
	SECItem item;
	char *host = NULL, *path = NULL, *request, *b64;
	unsigned char *der, *data = NULL, *tmp;
	size_t data_length = 0, data_size = 0;
	PRUint16 port;
	PRInt32 n, sent;
	int length, ret = -1;

	memset(response, 0, sizeof(*response));
	memset(&conn, 0, sizeof(conn));
	conn.pin = pin;
	conn.verbose = verbose;

	if (parse_url(parent, url, &host, &port, &path) != 0) {
		response->error = -1;
		response->error_text = talloc_asprintf(parent,
						       "can't parse URL \"%s\"",
						       url);
		return -1;
	}

	nctx = NSS_InitContext(dbdir, NULL, NULL, NULL, NULL,
			       NSS_INIT_READONLY);
	if (nctx == NULL) {
		set_nss_error(parent, response, "error opening database");
		return -1;
	}
	NSS_SetDomesticPolicy();
	PK11_SetPasswordFunc(pin_cb);

	/* Locate the certificate which we're renewing, and its key. */
	b64 = cm_submit_u_base64_from_text(cert_pem);
	der = (unsigned char *) cm_store_base64_as_bin(parent, b64, -1,
						       &length);
	free(b64);
	if ((der == NULL) || (length <= 0)) {
		response->error = -1;
		response->error_text = "can't decode the current certificate";
		goto done;
	}
	item.type = siDERCertBuffer;
	item.data = der;
	item.len = length;
	conn.cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &item,
					    NULL, PR_FALSE, PR_TRUE);
	if (conn.cert == NULL) {
		set_nss_error(parent, response,
			      "error parsing the current certificate");
		goto done;
	}
	if ((token != NULL) && (strlen(token) > 0)) {
		slot = PK11_FindSlotByName(token);
		if (slot == NULL) {
			set_nss_error(parent, response, "error finding token");
			goto done;
		}
		if (PK11_NeedLogin(slot) &&
		    (PK11_Authenticate(slot, PR_TRUE, &conn) != SECSuccess)) {
			set_nss_error(parent, response,
				      "error logging in to token");
			goto done;
		}
		conn.key = PK11_FindKeyByDERCert(slot, conn.cert, &conn);
	} else {
		conn.key = PK11_FindKeyByAnyCert(conn.cert, &conn);
	}
	if (conn.key == NULL) {
		set_nss_error(parent, response,
			      "error finding the key for the current "
			      "certificate");
		goto done;
	}

	/* Read our trust anchors, if we were given any. */
	if (cainfo != NULL) {
		conn.anchors = read_anchors(parent, cainfo);
		if (conn.anchors == NULL) {
			response->error = -1;
			response->error_text = talloc_asprintf(parent,
							       "no certificates "
							       "read from \"%s\"",
							       cainfo);
			goto done;
		}
	}

	/* Connect. */
	tcp = connect_to(host, port);
	if (tcp == NULL) {
		set_nss_error(parent, response, "error connecting to server");
		goto done;
	}
	ssl = SSL_ImportFD(NULL, tcp);
	if (ssl == NULL) {
		set_nss_error(parent, response, "error setting up TLS");
		goto done;
	}
	tcp = NULL;
	if ((SSL_OptionSet(ssl, SSL_SECURITY, PR_TRUE) != SECSuccess) ||
	    (SSL_OptionSet(ssl, SSL_HANDSHAKE_AS_CLIENT,
			   PR_TRUE) != SECSuccess) ||
	    (SSL_OptionSet(ssl, SSL_ENABLE_SESSION_TICKETS,
			   PR_FALSE) != SECSuccess) ||
	    (SSL_SetURL(ssl, host) != SECSuccess) ||
	    (SSL_SetPKCS11PinArg(ssl, &conn) != SECSuccess) ||
	    (SSL_GetClientAuthDataHook(ssl, client_auth_cb,
				       &conn) != SECSuccess) ||
	    ((conn.anchors != NULL) &&
	     (SSL_AuthCertificateHook(ssl, server_auth_cb,
				      &conn) != SECSuccess)) ||
	    (SSL_ResetHandshake(ssl, PR_FALSE) != SECSuccess)) {
		set_nss_error(parent, response, "error setting up TLS");
		goto done;
	}
	if (SSL_ForceHandshakeWithTimeout(ssl,
					  PR_SecondsToInterval(EST_N_TIMEOUT)) != SECSuccess) {
		set_nss_error(parent, response, "TLS handshake failed");
		goto done;
	}
	if (verbose > 0) {
		fprintf(stderr, "TLS connection to %s:%d established, "
			"client certificate offered from \"%s\".\n",
			host, port, dbdir);
	}

	/* Send the request. */
	request = talloc_asprintf(parent,
				  "%s %s HTTP/1.1\r\n"
				  "Host: %s%s%s:%d\r\n"
				  "User-Agent: %s/%s\r\n"
				  "Accept: */*\r\n"
				  "Connection: close\r\n"
				  "%s%s%s"
				  "%s"
				  "Content-Length: %lu\r\n"
				  "\r\n"
				  "%s",
				  method, path,
				  strchr(host, ':') ? "[" : "",
				  host,
				  strchr(host, ':') ? "]" : "",
				  port,
				  PACKAGE_NAME, PACKAGE_VERSION,
				  content_type ? "Content-Type: " : "",
				  content_type ? content_type : "",
				  content_type ? "\r\n" : "",
				  body ? "Content-Transfer-Encoding: base64\r\n" : "",
				  body ? (unsigned long) strlen(body) : 0UL,
				  body ? body : "");
	if (request == NULL) {
		response->error = -1;
		response->error_text = "out of memory";
		goto done;
	}
	for (sent = 0; sent < (PRInt32) strlen(request); sent += n) {
		n = PR_Send(ssl, request + sent, strlen(request) - sent, 0,
			    PR_SecondsToInterval(EST_N_TIMEOUT));
		if (n <= 0) {
			set_nss_error(parent, response,
				      "error sending request");
			goto done;
		}
	}

	/* Read the whole response: we asked the server to close the
	 * connection when it's done. */
	for (;;) {
		if (data_length + 4096 + 1 > data_size) {
			if (data_size > EST_N_MAX_RESPONSE) {
				response->error = -1;
				response->error_text = "response too large";
				goto done;
			}
			data_size = data_size ? data_size * 2 : 16384;
			tmp = talloc_realloc_size(parent, data, data_size);
			if (tmp == NULL) {
				response->error = -1;
				response->error_text = "out of memory";
				goto done;
			}
			data = tmp;
		}
		n = PR_Recv(ssl, data + data_length, 4096, 0,
			    PR_SecondsToInterval(EST_N_TIMEOUT));
		if (n == 0) {
			break;
		}
		if (n < 0) {
			/* Servers often drop the connection without sending
			 * close_notify once they've sent the response. */
			if ((data_length > 0) &&
			    ((PORT_GetError() == PR_END_OF_FILE_ERROR) ||
			     (PORT_GetError() == PR_CONNECT_RESET_ERROR))) {
				break;
			}
			set_nss_error(parent, response,
				      "error reading response");
			goto done;
		}
		data_length += n;
	}
	data[data_length] = '\0';
	if (parse_response(parent, data, data_length, response) != 0) {
		response->error = -1;
		response->error_text = "malformed response from server";
		goto done;
	}
	ret = 0;

done:
	if (ssl != NULL) {
		PR_Close(ssl);
	}
	if (tcp != NULL) {
		PR_Close(tcp);
	}
	if (conn.anchors != NULL) {
		CERT_DestroyCertList(conn.anchors);
	}
	if (conn.key != NULL) {
		SECKEY_DestroyPrivateKey(conn.key);
	}
	if (conn.cert != NULL) {
		CERT_DestroyCertificate(conn.cert);
	}
	if (slot != NULL) {
		PK11_FreeSlot(slot);
	}
	SSL_ClearSessionCache();
	if (NSS_ShutdownContext(nctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	return ret;
}
