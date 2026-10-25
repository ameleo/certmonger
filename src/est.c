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
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <krb5.h>

#include <curl/curl.h>

#include <talloc.h>

#include <popt.h>

#include "est.h"
#include "json.h"
#include "log.h"
#include "store.h"
#include "submit-e.h"
#include "submit-h.h"
#include "submit-u.h"
#include "util-o.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

#define CM_CADATA_ROOTS "roots"
#define CM_CADATA_OTHERS "other"
#define CM_CADATA_CERTIFICATE "certificate"
#define CM_CADATA_NICKNAME "nickname"

enum known_ops {
	op_unset,
	op_cacerts,
	op_enroll,
	op_reenroll,
};

/* Build the URL for an operation: the server's base URL, the well-known
 * prefix if the base URL doesn't already include it, the optional CA label,
 * and the operation's name. */
static char *
est_url(void *parent, const char *url, const char *label, const char *op)
{
	char *base;
	size_t len;

	base = talloc_strdup(parent, url);
	len = strlen(base);
	while ((len > 0) && (base[len - 1] == '/')) {
		base[--len] = '\0';
	}
	if (strstr(base, EST_WELL_KNOWN_PATH) == NULL) {
		base = talloc_strdup_append(base, EST_WELL_KNOWN_PATH);
	}
	if ((label != NULL) && (strlen(label) > 0)) {
		base = talloc_asprintf_append(base, "/%s", label);
	}
	return talloc_asprintf_append(base, "/%s", op);
}

/* Read a single line from a file, without its line terminator. */
static char *
read_secret(void *parent, const char *filename)
{
	char *p, *ret;

	p = cm_submit_u_from_file(filename);
	if (p == NULL) {
		return NULL;
	}
	ret = talloc_strndup(parent, p, strcspn(p, "\r\n"));
	memset(p, '\0', strlen(p));
	free(p);
	return ret;
}

/* Decode a PKCS#7 "certs-only" response, which RFC 7030 says is base64
 * encoded, though we also accept plain DER. */
static PKCS7 *
decode_p7(void *parent, const unsigned char *body, size_t length)
{
	const unsigned char *u;
	char *b64;
	unsigned char *der;
	int der_length;
	PKCS7 *p7 = NULL;

	if ((body == NULL) || (length == 0)) {
		return NULL;
	}
	if (body[0] == 0x30) {
		u = body;
		p7 = d2i_PKCS7(NULL, &u, length);
	}
	if (p7 == NULL) {
		b64 = talloc_strndup(parent, (const char *) body, length);
		if (b64 == NULL) {
			return NULL;
		}
		der = (unsigned char *) cm_store_base64_as_bin(parent, b64, -1,
							       &der_length);
		if ((der == NULL) || (der_length <= 0)) {
			return NULL;
		}
		u = der;
		p7 = d2i_PKCS7(NULL, &u, der_length);
	}
	if (p7 == NULL) {
		return NULL;
	}
	if (!PKCS7_type_is_signed(p7) ||
	    (p7->d.sign == NULL) ||
	    (p7->d.sign->cert == NULL) ||
	    (sk_X509_num(p7->d.sign->cert) == 0)) {
		PKCS7_free(p7);
		return NULL;
	}
	return p7;
}

static char *
pem_from_x509(void *parent, X509 *x)
{
	BIO *bio;
	char *p, *ret = NULL;
	long len;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		return NULL;
	}
	if (PEM_write_bio_X509(bio, x) == 1) {
		len = BIO_get_mem_data(bio, &p);
		ret = talloc_strndup(parent, p, len);
	}
	BIO_free(bio);
	return ret;
}

static char *
nickname_from_x509(void *parent, X509 *x)
{
	char buf[LINE_MAX], *p;
	int len;

	len = X509_NAME_get_text_by_NID(X509_get_subject_name(x),
					NID_commonName, buf, sizeof(buf));
	if (len > 0) {
		return talloc_strndup(parent, buf, len);
	}
	p = X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
	return talloc_strdup(parent, p ? p : "EST CA");
}

static int
self_signed(X509 *x)
{
	EVP_PKEY *pubkey;

	if (X509_check_issued(x, x) != X509_V_OK) {
		return 0;
	}
	pubkey = X509_get0_pubkey(x);
	return (pubkey != NULL) && (X509_verify(x, pubkey) == 1);
}

/* Print the CA certificates in the JSON format which the daemon expects in
 * reply to FETCH-ROOTS: self-signed certificates are roots, the others are
 * the rest of the chain. */
static int
output_cacerts(void *parent, PKCS7 *p7)
{
	struct cm_json *json, *roots, *others, *cert, *val;
	STACK_OF(X509) *certs;
	X509 *x;
	char *pem, *nickname;
	int i;

	certs = p7->d.sign->cert;
	json = cm_json_new_object(parent);
	roots = cm_json_new_array(json);
	others = cm_json_new_array(json);
	for (i = 0; i < sk_X509_num(certs); i++) {
		x = sk_X509_value(certs, i);
		pem = pem_from_x509(parent, x);
		nickname = nickname_from_x509(parent, x);
		if ((pem == NULL) || (nickname == NULL)) {
			return -1;
		}
		cert = cm_json_new_object(json);
		val = cm_json_new_string(cert, nickname, -1);
		cm_json_set(cert, CM_CADATA_NICKNAME, val);
		val = cm_json_new_string(cert, pem, -1);
		cm_json_set(cert, CM_CADATA_CERTIFICATE, val);
		cm_json_append(self_signed(x) ? roots : others, cert);
	}
	if (cm_json_array_size(roots) > 0) {
		cm_json_set(json, CM_CADATA_ROOTS, roots);
	}
	if (cm_json_array_size(others) > 0) {
		cm_json_set(json, CM_CADATA_OTHERS, others);
	}
	printf("%s\n", cm_json_encode(parent, json));
	return 0;
}

/* Find the certificate for the key in our request.  RFC 7030 says the reply
 * contains only the new certificate, but be ready for a server which also
 * includes its chain. */
static X509 *
find_issued(PKCS7 *p7, const char *csr)
{
	STACK_OF(X509) *certs;
	X509_REQ *req = NULL;
	EVP_PKEY *reqkey = NULL;
	X509 *x, *ret = NULL;
	BIO *bio;
	int i;

	certs = p7->d.sign->cert;
	if ((csr != NULL) && (strlen(csr) > 0)) {
		bio = BIO_new_mem_buf(csr, -1);
		if (bio != NULL) {
			req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
			BIO_free(bio);
		}
		if (req != NULL) {
			reqkey = X509_REQ_get0_pubkey(req);
		}
	}
	for (i = 0; i < sk_X509_num(certs); i++) {
		x = sk_X509_value(certs, i);
		if (reqkey == NULL) {
			if (sk_X509_num(certs) == 1) {
				ret = x;
			}
			break;
		}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		if (EVP_PKEY_eq(X509_get0_pubkey(x), reqkey) == 1) {
#else
		if (EVP_PKEY_cmp(X509_get0_pubkey(x), reqkey) == 1) {
#endif
			ret = x;
			break;
		}
	}
	if (req != NULL) {
		X509_REQ_free(req);
	}
	return ret;
}

/* Interpret a Retry-After value, either a number of seconds or a date. */
static long
retry_after(const char *value)
{
	time_t when, now;
	long delay;
	char *end;

	if ((value == NULL) || (strlen(value) == 0)) {
		return -1;
	}
	delay = strtol(value, &end, 10);
	if ((end != value) && (*end == '\0') && (delay >= 0)) {
		return delay;
	}
	when = curl_getdate(value, NULL);
	if (when == -1) {
		return -1;
	}
	now = time(NULL);
	return (when > now) ? (long) (when - now) : 0;
}

/* Is the certificate one we can still authenticate with? */
static int
cert_usable(const char *pem)
{
	X509 *x = NULL;
	BIO *bio;
	int ret = 0;

	if ((pem == NULL) || (strlen(pem) == 0)) {
		return 0;
	}
	bio = BIO_new_mem_buf(pem, -1);
	if (bio != NULL) {
		x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	if (x != NULL) {
		ret = (X509_cmp_current_time(X509_get0_notBefore(x)) < 0) &&
		      (X509_cmp_current_time(X509_get0_notAfter(x)) > 0);
		X509_free(x);
	}
	return ret;
}

/* Print what the server said when it turned us down, if it's short text. */
static void
print_server_text(const struct cm_est_response *response)
{
	size_t i, len;

	if ((response->body == NULL) || (response->length == 0)) {
		return;
	}
	if ((response->content_type != NULL) &&
	    (strncasecmp(response->content_type, "text/", 5) != 0)) {
		return;
	}
	len = response->length;
	if (len > 1024) {
		len = 1024;
	}
	for (i = 0; i < len; i++) {
		if (!isprint(response->body[i]) &&
		    !isspace(response->body[i])) {
			return;
		}
	}
	printf("%.*s%s", (int) len, response->body,
	       (response->body[len - 1] == '\n') ? "" : "\n");
}

/* The CA certificates which libcurl trusts when it isn't told which ones to
 * trust, so that we can trust the same ones when we use NSS. */
static const char *
default_cainfo(void *parent)
{
	const char *ret = NULL;
#if HAVE_DECL_CURLINFO_CAINFO
	CURL *curl;
	char *path = NULL;

	curl = curl_easy_init();
	if (curl != NULL) {
		if ((curl_easy_getinfo(curl, CURLINFO_CAINFO,
				       &path) == CURLE_OK) &&
		    (path != NULL) && (access(path, R_OK) == 0)) {
			ret = talloc_strdup(parent, path);
		}
		curl_easy_cleanup(curl);
	}
#endif
	return ret;
}

/* Make a request using libcurl. */
static int
curl_request(void *parent, const char *method, const char *url,
	     const char *content_type, const char *body,
	     const char *cainfo,
	     const char *username, const char *password,
	     const char *sslcert_pem, const char *sslkey, const char *sslpin,
	     int verbose, struct cm_est_response *response)
{
	struct cm_submit_h_context *hctx;
	int length = 0;

	memset(response, 0, sizeof(*response));
	hctx = cm_submit_h_init(parent, method, url, body,
				content_type, NULL, NULL,
				cainfo, NULL, NULL, sslkey, sslpin,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				sslcert_pem ?
				cm_submit_h_clientauth_on :
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				verbose > 1 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	if (hctx == NULL) {
		response->error = -1;
		response->error_text = "out of memory";
		return -1;
	}
	if (sslcert_pem != NULL) {
		cm_submit_h_set_sslcert_pem(hctx, sslcert_pem);
	}
	if ((username != NULL) || (password != NULL)) {
		cm_submit_h_set_basic_auth(hctx, username, password);
	}
	if (body != NULL) {
		cm_submit_h_add_header(hctx,
				       "Content-Transfer-Encoding: base64");
	}
	cm_submit_h_run(hctx);
	response->error = cm_submit_h_result_code(hctx);
	if (response->error != 0) {
		response->error_text = talloc_strdup(parent,
						     cm_submit_h_result_code_text(hctx));
	}
	response->response_code = cm_submit_h_response_code(hctx);
	response->content_type = cm_submit_h_result_type(hctx);
	if (response->content_type != NULL) {
		response->content_type = talloc_strdup(parent,
						       response->content_type);
	}
	response->retry_after = cm_submit_h_result_header(hctx,
							  "Retry-After");
	response->body = (const unsigned char *) cm_submit_h_results(hctx,
								     &length);
	response->length = length;
	if (response->body != NULL) {
		response->body = talloc_memdup(parent, response->body,
					       response->length + 1);
	}
	cm_submit_h_cleanup(hctx);
	return (response->error == 0) ? 0 : -1;
}

int
main(int argc, const char **argv)
{
	const char *url = NULL, *label = NULL, *cainfo = NULL, *mode;
	const char *username = NULL, *password_file = NULL;
	const char *csr, *cert, *cookie, *method, *ctype, *opname;
	const char *key_storage, *key_location, *key_token, *key_pin_file;
	char *password = NULL, *key_pin = NULL, *b64, *p, *full_url;
	char *pem;
	struct cm_est_response response;
	enum known_ops op = op_unset;
	int c, verbose = 0, rval = CM_SUBMIT_STATUS_UNCONFIGURED;
	long reenroll_refused = 0;
	long delay;
	void *ctx;
	PKCS7 *p7;
	X509 *x;
	poptContext pctx = NULL;
	struct poptOption popts[] = {
		{"url", 'u', POPT_ARG_STRING, &url, 0, "EST server location", "URL"},
		{"label", 'i', POPT_ARG_STRING, &label, 0, "CA label, appended to the URL", "LABEL"},
		{"cacert", 'R', POPT_ARG_STRING, &cainfo, 0, "the CA certificate(s), used for verifying TLS connections", "FILENAME"},
		{"username", 'U', POPT_ARG_STRING, &username, 0, "user name for HTTP Basic authentication during enrollment", "NAME"},
		{"password-file", 'W', POPT_ARG_STRING, &password_file, 0, "file containing the password for HTTP Basic authentication during enrollment", "FILENAME"},
		{"retrieve-ca-certificates", 'C', POPT_ARG_NONE, NULL, 'C', "make a cacerts request", NULL},
		{"enroll", 'e', POPT_ARG_NONE, NULL, 'e', "make a simpleenroll request", NULL},
		{"reenroll", 'r', POPT_ARG_NONE, NULL, 'r', "make a simplereenroll request", NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	util_o_init();
	ERR_load_crypto_strings();

	csr = getenv(CM_SUBMIT_CSR_ENV);
	cert = getenv(CM_SUBMIT_CERTIFICATE_ENV);
	cookie = getenv(CM_SUBMIT_COOKIE_ENV);
	key_storage = getenv(CM_SUBMIT_KEY_STORAGE_TYPE_ENV);
	key_location = getenv(CM_SUBMIT_KEY_STORAGE_LOCATION_ENV);
	key_token = getenv(CM_SUBMIT_KEY_TOKEN_ENV);
	key_pin_file = getenv(CM_SUBMIT_KEY_PIN_FILE_ENV);

	mode = getenv(CM_SUBMIT_OPERATION_ENV);
	if (mode != NULL) {
		if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
		    (strcasecmp(mode, CM_OP_POLL) == 0)) {
			/* Decided below, once we know what we have. */
			op = op_unset;
		} else
		if (strcasecmp(mode, CM_OP_FETCH_ROOTS) == 0) {
			op = op_cacerts;
		} else
		if (strcasecmp(mode, CM_OP_IDENTIFY) == 0) {
			printf("EST (%s %s)\n", PACKAGE_NAME, PACKAGE_VERSION);
			return CM_SUBMIT_STATUS_ISSUED;
		} else {
			/* unsupported request */
			return CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED;
		}
	}

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif

	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	poptSetOtherOptionHelp(pctx, "[options] [csr file]");
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'C':
			op = op_cacerts;
			break;
		case 'e':
			op = op_enroll;
			break;
		case 'r':
			op = op_reenroll;
			break;
		}
	}
	if (c != -1) {
		poptPrintUsage(pctx, stdout, 0);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}

	umask(S_IRWXG | S_IRWXO);
	if (isatty(STDERR_FILENO))
		cm_log_set_method(cm_log_stderr);
	else
		cm_log_set_method(cm_log_syslog);
	cm_log_set_level(verbose);

	ctx = talloc_new(NULL);

	if (url == NULL) {
		printf(_("No EST URL (-u) given, and no default known.\n"));
		poptPrintUsage(pctx, stdout, 0);
		goto done;
	}
	if (strncasecmp(url, "https://", 8) != 0) {
		printf(_("EST requires an https URL, not \"%s\".\n"), url);
		goto done;
	}

	/* Read the request from a file if we're run by hand. */
	if ((op != op_cacerts) &&
	    ((csr == NULL) || (strlen(csr) == 0)) &&
	    (poptPeekArg(pctx) != NULL)) {
		csr = cm_submit_u_from_file(poptGetArg(pctx));
	}

	if (op != op_cacerts) {
		/* Credentials for enrollment: the request's challenge
		 * password takes precedence over the one in the CA
		 * configuration.  Without a configured user name, a
		 * "name:password" pair is split at the first colon, as for
		 * HTTP Basic credentials. */
		p = getenv(CM_SUBMIT_CHALLENGE_PASSWORD_ENV);
		if ((p != NULL) && (strlen(p) > 0)) {
			password = talloc_strdup(ctx, p);
		} else
		if (password_file != NULL) {
			password = read_secret(ctx, password_file);
			if (password == NULL) {
				printf(_("Error reading password from \"%s\".\n"),
				       password_file);
				goto done;
			}
		}
		if ((password != NULL) && (username == NULL) &&
		    (strchr(password, ':') != NULL)) {
			p = strchr(password, ':');
			username = talloc_strndup(ctx, password, p - password);
			password = p + 1;
		}

		/* The key's PIN, if it's protected by one. */
		p = getenv(CM_SUBMIT_KEY_PIN_ENV);
		if ((p != NULL) && (strlen(p) > 0)) {
			key_pin = talloc_strdup(ctx, p);
		} else
		if ((key_pin_file != NULL) && (strlen(key_pin_file) > 0)) {
			key_pin = read_secret(ctx, key_pin_file);
			if (key_pin == NULL) {
				printf(_("Error reading key PIN from \"%s\".\n"),
				       key_pin_file);
				goto done;
			}
		}
	}

	/* If we already have a certificate, and know where its key is, we
	 * can re-enroll using it to authenticate.  Otherwise we enroll. */
	if (op == op_unset) {
		if (cookie != NULL) {
			if (strcmp(cookie, EST_OP_SIMPLEREENROLL) == 0) {
				op = op_reenroll;
			} else
			if (strcmp(cookie, EST_OP_SIMPLEENROLL) == 0) {
				op = op_enroll;
			}
		}
	}
	if (op == op_unset) {
		if (cert_usable(cert) &&
		    (key_storage != NULL) && (key_location != NULL)) {
			op = op_reenroll;
		} else {
			op = op_enroll;
		}
	}
	if ((op == op_enroll) || (op == op_reenroll)) {
		if ((csr == NULL) || (strlen(csr) == 0)) {
			printf(_("No certificate signing request to "
				 "submit.\n"));
			goto done;
		}
	}
	if (op == op_reenroll) {
		if ((cert == NULL) || (strlen(cert) == 0) ||
		    (key_storage == NULL) || (key_location == NULL)) {
			printf(_("Re-enrollment needs the current certificate "
				 "and the location of its key.\n"));
			goto done;
		}
	}

again:
	switch (op) {
	case op_unset:
		abort(); /* never reached */
		break;
	case op_cacerts:
		method = "GET";
		ctype = NULL;
		opname = EST_OP_CACERTS;
		b64 = NULL;
		break;
	case op_enroll:
	case op_reenroll:
	default:
		method = "POST";
		ctype = EST_CONTENT_TYPE_PKCS10;
		opname = (op == op_enroll) ?
			 EST_OP_SIMPLEENROLL :
			 EST_OP_SIMPLEREENROLL;
		b64 = cm_submit_u_base64_from_text(csr);
		if (b64 == NULL) {
			printf(_("Error reading request.\n"));
			goto done;
		}
		break;
	}
	full_url = est_url(ctx, url, label, opname);
	if (verbose > 0) {
		fprintf(stderr, "%s \"%s\"\n", method, full_url);
		syslog(LOG_DEBUG, "%s %s\n", method, full_url);
	}

	if ((op == op_reenroll) &&
	    (strcasecmp(key_storage, "NSSDB") == 0)) {
		cm_est_n_request(ctx, method, full_url, ctype, b64,
				 cainfo ? cainfo : default_cainfo(ctx),
				 key_location, key_token,
				 cert, key_pin, verbose, &response);
	} else
	if (op == op_reenroll) {
		curl_request(ctx, method, full_url, ctype, b64,
			     cainfo, NULL, NULL,
			     cert, key_location, key_pin,
			     verbose, &response);
	} else {
		curl_request(ctx, method, full_url, ctype, b64,
			     cainfo,
			     (op == op_enroll) ? username : NULL,
			     (op == op_enroll) ? password : NULL,
			     NULL, NULL, NULL,
			     verbose, &response);
	}
	if (verbose > 0) {
		fprintf(stderr, "response_code = %ld\n",
			response.response_code);
		fprintf(stderr, "content-type = \"%s\"\n",
			response.content_type ? response.content_type : "");
		if (response.retry_after != NULL) {
			fprintf(stderr, "retry-after = \"%s\"\n",
				response.retry_after);
		}
		fprintf(stderr, "code = %d\n", response.error);
		fprintf(stderr, "code_text = \"%s\"\n",
			response.error_text ? response.error_text : "");
		if (response.body != NULL) {
			fprintf(stderr, "results = \"%.*s\"\n",
				(int) response.length, response.body);
		}
	}

	/* Figure out what to output. */
	if (response.error != 0) {
		if (response.error_text != NULL) {
			printf(_("Error %d connecting to %s: %s.\n"),
			       response.error, full_url, response.error_text);
		} else {
			printf(_("Error %d connecting to %s.\n"),
			       response.error, full_url);
		}
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto done;
	}
	switch (response.response_code) {
	case 200:
		break;
	case 202:
		/* Ask again later, sending the same request. */
		delay = retry_after(response.retry_after);
		if (delay >= 0) {
			printf("%ld\n%s\n", delay, opname);
			rval = CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
		} else {
			printf("%s\n", opname);
			rval = CM_SUBMIT_STATUS_WAIT;
		}
		goto done;
		break;
	case 401:
	case 403:
		if ((op == op_reenroll) && (password != NULL)) {
			/* Perhaps the certificate was revoked, and we've
			 * been given credentials to start over with. */
			if (verbose > 0) {
				fprintf(stderr, "Re-enrollment refused, "
					"enrolling with the password.\n");
			}
			reenroll_refused = response.response_code;
			op = op_enroll;
			goto again;
		}
		if (reenroll_refused != 0) {
			printf(_("Server refused re-enrollment using the "
				 "current certificate (%ld).\n"),
			       reenroll_refused);
		}
		if (response.response_code == 401) {
			if ((op == op_enroll) && (password == NULL)) {
				printf(_("Server at %s requires authentication, "
					 "and no password was given.\n"),
				       full_url);
			} else {
				printf(_("Server at %s rejected our "
					 "credentials.\n"),
				       full_url);
			}
		} else {
			printf(_("Server at %s refused the request "
				 "(%ld).\n"),
			       full_url, response.response_code);
		}
		print_server_text(&response);
		rval = CM_SUBMIT_STATUS_REJECTED;
		goto done;
		break;
	default:
		printf(_("Got response code %ld from %s, not 200.\n"),
		       response.response_code, full_url);
		print_server_text(&response);
		if (response.response_code >= 500) {
			/* The server might recover, right? */
			delay = retry_after(response.retry_after);
			if ((op != op_cacerts) && (delay >= 0)) {
				printf("%ld\n%s\n", delay, opname);
				rval = CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
			} else {
				rval = CM_SUBMIT_STATUS_UNREACHABLE;
			}
		} else {
			/* Maybe not? */
			rval = CM_SUBMIT_STATUS_REJECTED;
		}
		goto done;
		break;
	}

	if ((response.content_type == NULL) ||
	    (strncasecmp(response.content_type, EST_CONTENT_TYPE_PKCS7,
			 strlen(EST_CONTENT_TYPE_PKCS7)) != 0)) {
		printf(_("Server reply was of unexpected MIME type "
			 "\"%s\".\n"),
		       response.content_type ? response.content_type : "");
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto done;
	}
	p7 = decode_p7(ctx, response.body, response.length);
	if (p7 == NULL) {
		printf(_("Error: couldn't parse the certificates in the "
			 "server's reply.\n"));
		cm_log_errors(1, "Error parsing PKCS#7 data.\n");
		rval = CM_SUBMIT_STATUS_UNREACHABLE;
		goto done;
	}
	switch (op) {
	case op_unset:
		abort(); /* never reached */
		break;
	case op_cacerts:
		if (output_cacerts(ctx, p7) != 0) {
			printf(_("Error formatting CA certificates.\n"));
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
		} else {
			rval = CM_SUBMIT_STATUS_ISSUED;
		}
		break;
	case op_enroll:
	case op_reenroll:
		x = find_issued(p7, csr);
		if (x == NULL) {
			printf(_("Error: the server's reply contains no "
				 "certificate for the requested key.\n"));
			rval = CM_SUBMIT_STATUS_REJECTED;
			break;
		}
		pem = pem_from_x509(ctx, x);
		if (pem == NULL) {
			printf(_("Error formatting certificate.\n"));
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			break;
		}
		printf("%s", pem);
		rval = CM_SUBMIT_STATUS_ISSUED;
		break;
	}
	PKCS7_free(p7);

done:
	if (password != NULL) {
		memset(password, '\0', strlen(password));
	}
	if (key_pin != NULL) {
		memset(key_pin, '\0', strlen(key_pin));
	}
	if (pctx) {
		poptFreeContext(pctx);
	}
	talloc_free(ctx);
	return rval;
}
