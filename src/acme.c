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

/* An enrollment helper which speaks ACME (RFC 8555), with support for the
 * device-attest-01 challenge (draft-ietf-acme-device-attest) using a TPM. */

#include "config.h"

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <curl/curl.h>

#include <jansson.h>

#include <krb5.h>

#include <talloc.h>

#include <popt.h>

#include "acme.h"
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

/* How long we wait for the server, in total, before handing the order back
 * to the daemon to check on later, and how long we wait between checks. */
#define ACME_INLINE_WAIT 90
#define ACME_DEFAULT_DELAY 3
#define ACME_MAX_INLINE_DELAY 15
#define ACME_DEFAULT_POLL_DELAY 60
/* How many times we retry a request which was refused for its nonce. */
#define ACME_NONCE_RETRIES 3

enum attest_format {
	attest_none,
	attest_tpm,
};

struct acme_client {
	void *ctx;
	const char *directory_url;
	const char *cainfo;
	const char *state_dir;
	int verbose;
	json_t *directory;
	struct cm_acme_signer signer;
	char *jwk, *thumbprint, *kid;
	/* Where the daemon keeps the external account keys it was given. */
	const char *eab_dir;
	char *nonce;
	/* What we learned from the last problem document. */
	char *problem_type;
	time_t deadline;
};

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

/* The external account binding: its key is read only when it is used, to
 * open the account, so that everything through an account we have needs
 * neither the key nor its file. */
struct acme_eab {
	void *ctx;
	const char *kid;
	const char *secret;	/* given with the request */
	const char *file;	/* or kept in this file */
	unsigned char *key;
	size_t length;
	int tried;
};

static int
eab_given(const struct acme_eab *eab)
{
	return (eab->kid != NULL) &&
	       ((eab->secret != NULL) || (eab->file != NULL));
}

static int
eab_key(void *data, const unsigned char **key, size_t *length)
{
	struct acme_eab *eab = data;
	char *secret;

	if (!eab->tried) {
		eab->tried = 1;
		if (eab->secret != NULL) {
			secret = talloc_strdup(eab->ctx, eab->secret);
		} else
		if (eab->file != NULL) {
			secret = read_secret(eab->ctx, eab->file);
			if (secret == NULL) {
				printf(_("Error reading the external account "
					 "key from \"%s\".\n"), eab->file);
			}
		} else {
			secret = NULL;
		}
		if (secret != NULL) {
			eab->key = cm_acme_b64_decode(eab->ctx, secret,
						      &eab->length);
			if ((eab->key == NULL) || (eab->length == 0)) {
				printf(_("The external account key is not "
					 "base64url-encoded.\n"));
				eab->key = NULL;
			}
			memset(secret, '\0', strlen(secret));
		}
	}
	if ((eab->kid == NULL) || (eab->key == NULL)) {
		return -1;
	}
	*key = eab->key;
	*length = eab->length;
	return 0;
}

/* Values which the server gives us and which we put into JSON documents
 * which we build by hand. */
static int
json_safe(const char *s)
{
	const unsigned char *p;

	if (s == NULL) {
		return 0;
	}
	for (p = (const unsigned char *) s; *p != '\0'; p++) {
		if ((*p < 0x20) || (*p == '"') || (*p == '\\')) {
			return 0;
		}
	}
	return 1;
}

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

static int
mkdir_private(const char *path)
{
	struct stat st;

	if (mkdir(path, S_IRWXU) == 0) {
		return 0;
	}
	if ((errno == EEXIST) && (stat(path, &st) == 0) &&
	    S_ISDIR(st.st_mode)) {
		return 0;
	}
	return -1;
}

/* Write a small file atomically. */
static int
write_file(void *parent, const char *path, const char *contents)
{
	char *tmp;
	FILE *fp;
	int fd, ret = -1;

	tmp = talloc_asprintf(parent, "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		return -1;
	}
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	if ((fputs(contents, fp) >= 0) && (fflush(fp) == 0) &&
	    (fsync(fd) == 0)) {
		ret = 0;
	}
	fclose(fp);
	if ((ret == 0) && (rename(tmp, path) != 0)) {
		ret = -1;
	}
	if (ret != 0) {
		unlink(tmp);
	}
	return ret;
}

static char *
state_file(struct acme_client *client, const char *name)
{
	return talloc_asprintf(client->ctx, "%s/%s", client->state_dir, name);
}

/* Make an HTTP request. */
static void
http_request(struct acme_client *client, const char *method,
	     const char *url, const char *content_type, const char *body,
	     struct cm_acme_response *response)
{
	struct cm_submit_h_context *hctx;
	const char *p;
	int length = 0;

	memset(response, 0, sizeof(*response));
	if (client->verbose > 0) {
		fprintf(stderr, "%s \"%s\"\n", method, url);
	}
	hctx = cm_submit_h_init(client->ctx, method, url, body,
				content_type, NULL, NULL,
				client->cainfo, NULL, NULL, NULL, NULL,
				cm_submit_h_negotiate_off,
				cm_submit_h_delegate_off,
				cm_submit_h_clientauth_off,
				cm_submit_h_env_modify_off,
				client->verbose > 2 ?
				cm_submit_h_curl_verbose_on :
				cm_submit_h_curl_verbose_off);
	if (hctx == NULL) {
		response->error = -1;
		response->error_text = "out of memory";
		return;
	}
	cm_submit_h_run(hctx);
	response->error = cm_submit_h_result_code(hctx);
	if (response->error != 0) {
		response->error_text = talloc_strdup(client->ctx,
						     cm_submit_h_result_code_text(hctx));
	}
	response->response_code = cm_submit_h_response_code(hctx);
	p = cm_submit_h_result_type(hctx);
	response->content_type = p ? talloc_strdup(client->ctx, p) : NULL;
	p = cm_submit_h_result_header(hctx, "Location");
	response->location = p ? talloc_strdup(client->ctx, p) : NULL;
	p = cm_submit_h_result_header(hctx, "Retry-After");
	response->retry_after = p ? talloc_strdup(client->ctx, p) : NULL;
	p = cm_submit_h_result_header(hctx, "Replay-Nonce");
	response->replay_nonce = p ? talloc_strdup(client->ctx, p) : NULL;
	p = cm_submit_h_result_header(hctx, "Link");
	response->link = p ? talloc_strdup(client->ctx, p) : NULL;
	p = cm_submit_h_results(hctx, &length);
	if (p != NULL) {
		response->body = talloc_strndup(client->ctx, p, length);
		response->length = length;
	}
	cm_submit_h_cleanup(hctx);
	if (client->verbose > 1) {
		fprintf(stderr, "response_code = %ld\n",
			response->response_code);
		if (response->body != NULL) {
			fprintf(stderr, "results = \"%.*s\"\n",
				(int) response->length, response->body);
		}
	}
	if ((response->replay_nonce != NULL) &&
	    json_safe(response->replay_nonce)) {
		talloc_free(client->nonce);
		client->nonce = talloc_strdup(client->ctx,
					      response->replay_nonce);
	}
}

static json_t *
response_json(const struct cm_acme_response *response)
{
	json_error_t error;

	if ((response->body == NULL) || (response->length == 0)) {
		return NULL;
	}
	return json_loadb(response->body, response->length, 0, &error);
}

static const char *
json_str(json_t *object, const char *key)
{
	json_t *value;

	value = json_object_get(object, key);
	return json_is_string(value) ? json_string_value(value) : NULL;
}

/* Tell the user what the server said was wrong (RFC 7807, RFC 8555 6.7). */
static void
print_problem(struct acme_client *client,
	      const struct cm_acme_response *response, const char *what)
{
	json_t *problem, *sub;
	const char *type, *detail;
	size_t i;

	talloc_free(client->problem_type);
	client->problem_type = NULL;
	problem = response_json(response);
	type = json_str(problem, "type");
	detail = json_str(problem, "detail");
	if ((type != NULL) &&
	    (strncmp(type, ACME_ERROR_PREFIX,
		     strlen(ACME_ERROR_PREFIX)) == 0)) {
		type += strlen(ACME_ERROR_PREFIX);
	}
	if (type != NULL) {
		client->problem_type = talloc_strdup(client->ctx, type);
	}
	if (type != NULL) {
		printf(_("Server refused %s (%ld, %s): %s\n"),
		       what, response->response_code, type,
		       detail ? detail : "");
	} else {
		printf(_("Server refused %s (%ld).\n"),
		       what, response->response_code);
	}
	sub = json_object_get(problem, "subproblems");
	for (i = 0; json_is_array(sub) && (i < json_array_size(sub)); i++) {
		detail = json_str(json_array_get(sub, i), "detail");
		if (detail != NULL) {
			printf("  %s\n", detail);
		}
	}
	json_decref(problem);
}

/* What to tell the daemon when a request failed. */
static int
failure_status(struct acme_client *client,
	       const struct cm_acme_response *response, const char *what)
{
	if (response->error != 0) {
		printf(_("Error %d connecting to %s: %s.\n"),
		       response->error, what,
		       response->error_text ? response->error_text : "");
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	print_problem(client, response, what);
	if ((response->response_code >= 500) ||
	    ((client->problem_type != NULL) &&
	     (strcmp(client->problem_type, "rateLimited") == 0))) {
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	return CM_SUBMIT_STATUS_REJECTED;
}

static const char *
directory_url(struct acme_client *client, const char *name)
{
	const char *url;

	url = json_str(client->directory, name);
	return json_safe(url) ? url : NULL;
}

static int
fetch_directory(struct acme_client *client)
{
	struct cm_acme_response response;

	http_request(client, "GET", client->directory_url, NULL, NULL,
		     &response);
	if ((response.error != 0) || (response.response_code != 200)) {
		return failure_status(client, &response,
				      _("the directory request"));
	}
	client->directory = response_json(&response);
	if (!json_is_object(client->directory) ||
	    (directory_url(client, "newNonce") == NULL) ||
	    (directory_url(client, "newAccount") == NULL) ||
	    (directory_url(client, "newOrder") == NULL)) {
		printf(_("The server at %s did not return an ACME "
			 "directory.\n"), client->directory_url);
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	return 0;
}

static int
fetch_nonce(struct acme_client *client)
{
	struct cm_acme_response response;

	/* Servers answer both HEAD and GET (RFC 8555 7.2). */
	http_request(client, "GET", directory_url(client, "newNonce"),
		     NULL, NULL, &response);
	if (client->nonce == NULL) {
		return failure_status(client, &response,
				      _("the nonce request"));
	}
	return 0;
}

/* POST a JWS to the server, signed with the account key, retrying if the
 * server didn't like our nonce (RFC 8555 6.5).  A NULL payload makes a
 * POST-as-GET request. */
static int
acme_post(struct acme_client *client, const char *url, const char *payload,
	  int use_jwk, struct cm_acme_response *response)
{
	char *jws, *nonce;
	json_t *problem;
	const char *type;
	int i, ret;

	if (!json_safe(url)) {
		printf(_("The server sent an unusable URL.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	for (i = 0; i < ACME_NONCE_RETRIES; i++) {
		if (client->nonce == NULL) {
			ret = fetch_nonce(client);
			if (ret != 0) {
				return ret;
			}
		}
		nonce = client->nonce;
		client->nonce = NULL;
		jws = cm_acme_jws(client->ctx, &client->signer,
				  use_jwk ? NULL : client->kid,
				  client->jwk, nonce, url, payload);
		talloc_free(nonce);
		if (jws == NULL) {
			printf(_("Error signing the request.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		http_request(client, "POST", url, ACME_CONTENT_TYPE_JOSE,
			     jws, response);
		talloc_free(jws);
		if ((response->error != 0) ||
		    (response->response_code != 400)) {
			return 0;
		}
		problem = response_json(response);
		type = json_str(problem, "type");
		if ((type == NULL) ||
		    (strcmp(type, ACME_ERROR_PREFIX "badNonce") != 0)) {
			json_decref(problem);
			return 0;
		}
		json_decref(problem);
		if (client->verbose > 0) {
			fprintf(stderr, "Nonce refused, retrying.\n");
		}
	}
	return 0;
}

/* POST-as-GET a resource and parse it. */
static int
acme_get(struct acme_client *client, const char *url, const char *what,
	 json_t **object, struct cm_acme_response *response)
{
	int ret;

	*object = NULL;
	ret = acme_post(client, url, NULL, 0, response);
	if (ret != 0) {
		return ret;
	}
	if ((response->error != 0) || (response->response_code != 200)) {
		return failure_status(client, response, what);
	}
	*object = response_json(response);
	if (!json_is_object(*object)) {
		printf(_("Error parsing %s.\n"), what);
		json_decref(*object);
		*object = NULL;
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	return 0;
}

/* Wait before checking on something again, if we still have time. */
static int
wait_a_bit(struct acme_client *client,
	   const struct cm_acme_response *response)
{
	long delay;

	delay = retry_after(response->retry_after);
	if (delay < 0) {
		delay = ACME_DEFAULT_DELAY;
	}
	if (delay > ACME_MAX_INLINE_DELAY) {
		return -1;
	}
	if (time(NULL) + delay > client->deadline) {
		return -1;
	}
	if (client->verbose > 0) {
		fprintf(stderr, "Waiting %ld seconds.\n", delay);
	}
	sleep(delay ? delay : 1);
	return 0;
}

/* Tell the daemon to come back later, and to bring the order's URL. */
static int
come_back_later(const struct cm_acme_response *response,
		const char *order_url)
{
	long delay;

	delay = retry_after(response->retry_after);
	if (delay < 0) {
		delay = ACME_DEFAULT_POLL_DELAY;
	}
	printf("%ld\n%s\n", delay, order_url);
	return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
}

/* The external account binding serves once, to open the account (RFC 8555
 * 7.3.4): from then on the account key proves who we are.  The copy of its
 * key which the daemon keeps for us goes, and so does what we read. */
static void
forget_eab(struct acme_client *client, struct acme_eab *eab)
{
	size_t length;

	if (eab->key != NULL) {
		memset(eab->key, '\0', eab->length);
		eab->key = NULL;
	}
	if ((eab->file == NULL) || (client->eab_dir == NULL)) {
		return;
	}
	length = strlen(client->eab_dir);
	if ((strncmp(eab->file, client->eab_dir, length) == 0) &&
	    (eab->file[length] == '/') &&
	    (strchr(eab->file + length + 1, '/') == NULL)) {
		if ((unlink(eab->file) != 0) && (errno != ENOENT)) {
			printf(_("Error removing \"%s\": %s.\n"), eab->file,
			       strerror(errno));
		} else
		if (client->verbose > 0) {
			fprintf(stderr, "Removed the external account key, "
				"which served its purpose.\n");
		}
	}
}

/* Use the account we have, or create one, binding it to the account which
 * the CA gave us if we have its credentials. */
static int
setup_account(struct acme_client *client, struct acme_eab *eab)
{
	const unsigned char *key;
	size_t key_length;
	struct cm_acme_response response;
	json_t *meta, *account;
	const char *error, *url, *status, *name;
	char *path, *payload, *binding, *kid;
	int ret;

	/* Where there is a TPM, the account key is generated in our TPM
	 * token and never leaves it; elsewhere it is a file only we read. */
	if (cm_acme_p11_available()) {
		name = strrchr(client->state_dir, '/');
		name = (name != NULL) ? name + 1 : client->state_dir;
		client->signer.p11 = cm_acme_p11_account_key(client->ctx, name,
							     1, &error);
		if (client->signer.p11 == NULL) {
			printf(_("Error with the account key in the TPM "
				 "token: %s.\n"), error);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
	} else {
		path = state_file(client, ACME_ACCOUNT_KEY_FILE);
		client->signer.key = cm_acme_account_key(path, 1, &error);
		if (client->signer.key == NULL) {
			printf(_("Error with account key \"%s\": %s.\n"),
			       path, error);
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
	}
	client->jwk = cm_acme_jwk(client->ctx, &client->signer);
	if (client->jwk == NULL) {
		printf(_("Error encoding the account key.\n"));
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	client->thumbprint = cm_acme_jwk_thumbprint(client->ctx, client->jwk);

	path = state_file(client, ACME_ACCOUNT_URL_FILE);
	kid = (access(path, F_OK) == 0) ? cm_submit_u_from_file(path) : NULL;
	if (kid != NULL) {
		kid[strcspn(kid, "\r\n")] = '\0';
		if (json_safe(kid) && (strlen(kid) > 0)) {
			client->kid = talloc_strdup(client->ctx, kid);
		}
		free(kid);
	}
	if (client->kid != NULL) {
		return 0;
	}

	/* A new account.  If the key is already registered, the server
	 * tells us so, and where the account is (RFC 8555 7.3.1). */
	url = directory_url(client, "newAccount");
	if (eab_given(eab)) {
		if (!json_safe(eab->kid)) {
			printf(_("Invalid external account key ID.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		if (eab_key(eab, &key, &key_length) != 0) {
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		binding = cm_acme_eab(client->ctx, eab->kid, key, key_length,
				      client->jwk, url);
		if (binding == NULL) {
			printf(_("Error binding the external account.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		payload = talloc_asprintf(client->ctx,
					  "{\"termsOfServiceAgreed\":true,"
					  "\"externalAccountBinding\":%s}",
					  binding);
	} else {
		meta = json_object_get(client->directory, "meta");
		if (json_is_true(json_object_get(meta,
						 "externalAccountRequired"))) {
			printf(_("The server requires an external account "
				 "binding, and none was given.\n"));
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		payload = talloc_strdup(client->ctx,
					"{\"termsOfServiceAgreed\":true}");
	}
	ret = acme_post(client, url, payload, 1, &response);
	if (ret != 0) {
		return ret;
	}
	if ((response.error != 0) ||
	    ((response.response_code != 200) &&
	     (response.response_code != 201))) {
		return failure_status(client, &response,
				      _("the account creation"));
	}
	account = response_json(&response);
	status = json_str(account, "status");
	if ((status != NULL) && (strcmp(status, "valid") != 0)) {
		printf(_("The account is %s.\n"), status);
		json_decref(account);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	json_decref(account);
	if (!json_safe(response.location) ||
	    (strlen(response.location) == 0)) {
		printf(_("The server did not say where the new account "
			 "is.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	client->kid = talloc_strdup(client->ctx, response.location);
	if (write_file(client->ctx, path, client->kid) != 0) {
		printf(_("Error saving the account URL to \"%s\".\n"), path);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	forget_eab(client, eab);
	return 0;
}

/* Forget the account, so that we create a new one next time. */
static void
forget_account(struct acme_client *client)
{
	unlink(state_file(client, ACME_ACCOUNT_URL_FILE));
	talloc_free(client->kid);
	client->kid = NULL;
}

/* The identifiers to ask for: the configured permanent identifier when we
 * attest the device, or else the names in the request. */
static json_t *
order_identifiers(void *parent, X509_REQ *req,
		  const char *permanent_identifier, int attest)
{
	json_t *identifiers;
	STACK_OF(X509_EXTENSION) *extensions;
	GENERAL_NAMES *names = NULL;
	GENERAL_NAME *name;
	X509_NAME *subject;
	ASN1_STRING *cn;
	unsigned char *utf8;
	char ip[64];
	int i, n, length;

	identifiers = json_array();
	subject = X509_REQ_get_subject_name(req);
	cn = NULL;
	i = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
	if (i >= 0) {
		cn = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i));
	}
	if ((permanent_identifier != NULL) || attest) {
		if (permanent_identifier != NULL) {
			json_array_append_new(identifiers,
					      json_pack("{s:s,s:s}",
							"type", ACME_IDENTIFIER_PERMANENT,
							"value", permanent_identifier));
		} else
		if (cn != NULL) {
			length = ASN1_STRING_to_UTF8(&utf8, cn);
			if (length > 0) {
				json_array_append_new(identifiers,
						      json_pack("{s:s,s:s%}",
								"type", ACME_IDENTIFIER_PERMANENT,
								"value", utf8, (size_t) length));
				OPENSSL_free(utf8);
			}
		}
		return identifiers;
	}
	extensions = X509_REQ_get_extensions(req);
	if (extensions != NULL) {
		names = X509V3_get_d2i(extensions, NID_subject_alt_name,
				       NULL, NULL);
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	}
	n = names ? sk_GENERAL_NAME_num(names) : 0;
	for (i = 0; i < n; i++) {
		name = sk_GENERAL_NAME_value(names, i);
		switch (name->type) {
		case GEN_DNS:
			json_array_append_new(identifiers,
					      json_pack("{s:s,s:s%}",
							"type", "dns",
							"value",
							ASN1_STRING_get0_data(name->d.dNSName),
							(size_t) ASN1_STRING_length(name->d.dNSName)));
			break;
		case GEN_IPADD:
			/* RFC 8738 */
			length = ASN1_STRING_length(name->d.iPAddress);
			utf8 = (unsigned char *) ASN1_STRING_get0_data(name->d.iPAddress);
			if (((length != 4) && (length != 16)) ||
			    (inet_ntop((length == 4) ? AF_INET : AF_INET6,
				       utf8, ip, sizeof(ip)) == NULL)) {
				continue;
			}
			json_array_append_new(identifiers,
					      json_pack("{s:s,s:s}",
							"type", "ip",
							"value", ip));
			break;
		}
	}
	GENERAL_NAMES_free(names);
	if ((json_array_size(identifiers) == 0) && (cn != NULL)) {
		length = ASN1_STRING_to_UTF8(&utf8, cn);
		if (length > 0) {
			json_array_append_new(identifiers,
					      json_pack("{s:s,s:s%}",
							"type", "dns",
							"value", utf8, (size_t) length));
			OPENSSL_free(utf8);
		}
	}
	(void) parent;
	return identifiers;
}

#ifdef HAVE_TSS2
/* The device attestation code talks to the server's attestation key
 * certification service with ACME requests, signed by the account. */
static int
post_signed(void *parent, void *data, const char *url, const char *payload,
	    struct cm_acme_response *response)
{
	struct acme_client *client = data;

	(void) parent;
	memset(response, 0, sizeof(*response));
	if (acme_post(client, url, payload, 0, response) != 0) {
		if (response->error_text == NULL) {
			response->error_text = "error signing or sending the "
					       "request";
		}
		return -1;
	}
	return (response->error == 0) ? 0 : -1;
}

static int
http_get(void *parent, void *data, const char *url,
	 struct cm_acme_response *response)
{
	struct acme_client *client = data;

	(void) parent;
	http_request(client, "GET", url, NULL, NULL, response);
	return (response->error == 0) ? 0 : -1;
}

/* Where the attestation key certification service is: next to the
 * directory. */
static char *
attestation_service_url(void *parent, const char *directory)
{
	char *ret, *p;

	ret = talloc_strdup(parent, directory);
	p = strrchr(ret, '/');
	if ((p != NULL) && (p > ret + strlen("https://"))) {
		*p = '\0';
	}
	return ret;
}
#endif

struct acme_attestation {
	enum attest_format format;
	const char *tcti;
	const char *key_storage_type, *key_location, *key_token, *key_pin;
	const char *csr;
};

/* Answer a device-attest-01 challenge (draft-ietf-acme-device-attest 5). */
static int
answer_device_attest(struct acme_client *client,
		     struct acme_attestation *attestation,
		     const char *challenge_url, const char *token)
{
#ifdef HAVE_TSS2
	struct cm_acme_tpm_params params;
	struct cm_acme_response response;
	unsigned char *att_obj = NULL;
	size_t att_obj_length = 0;
	const char *error = NULL;
	char *key_authorization, *payload;
	int ret;

	if (!json_safe(token)) {
		printf(_("The server sent an unusable challenge token.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	key_authorization = talloc_asprintf(client->ctx, "%s.%s",
					    token, client->thumbprint);
	memset(&params, 0, sizeof(params));
	params.state_dir = client->state_dir;
	params.tcti = attestation->tcti;
	params.service_url = attestation_service_url(client->ctx,
						     client->directory_url);
	params.key_storage_type = attestation->key_storage_type;
	params.key_location = attestation->key_location;
	params.key_token = attestation->key_token;
	params.key_pin = attestation->key_pin;
	params.csr = attestation->csr;
	params.verbose = client->verbose;
	params.post_signed = post_signed;
	params.get = http_get;
	params.http_data = client;
	ret = cm_acme_tpm_attest(client->ctx, &params, key_authorization,
				 &att_obj, &att_obj_length, &error);
	if (ret != 0) {
		printf(_("Error attesting the key with the TPM: %s.\n"),
		       error ? error : _("unknown error"));
		return ret;
	}
	payload = talloc_asprintf(client->ctx, "{\"attObj\":\"%s\"}",
				  cm_acme_b64url_encode(client->ctx, att_obj,
							att_obj_length));
	ret = acme_post(client, challenge_url, payload, 0, &response);
	if (ret != 0) {
		return ret;
	}
	if ((response.error != 0) || (response.response_code != 200)) {
		return failure_status(client, &response,
				      _("the attestation"));
	}
	return 0;
#else
	(void) client;
	(void) attestation;
	(void) challenge_url;
	(void) token;
	printf(_("This helper was built without TPM support.\n"));
	return CM_SUBMIT_STATUS_UNCONFIGURED;
#endif
}

/* Get an authorization to valid, answering the challenge which we can
 * answer. */
static int
process_authorization(struct acme_client *client, const char *url,
		      struct acme_attestation *attestation)
{
	struct cm_acme_response response;
	json_t *authz, *challenges, *challenge, *chosen, *identifier, *error;
	const char *status, *type, *offered;
	char *list;
	size_t i;
	int ret, answered = 0;

	for (;;) {
		ret = acme_get(client, url, _("the authorization"), &authz,
			       &response);
		if (ret != 0) {
			return ret;
		}
		status = json_str(authz, "status");
		identifier = json_object_get(authz, "identifier");
		if ((status != NULL) && (strcmp(status, "valid") == 0)) {
			json_decref(authz);
			return 0;
		}
		if ((status == NULL) || (strcmp(status, "pending") != 0)) {
			printf(_("Authorization for %s is %s.\n"),
			       json_str(identifier, "value") ?
			       json_str(identifier, "value") : "?",
			       status ? status : "?");
			challenges = json_object_get(authz, "challenges");
			for (i = 0; i < json_array_size(challenges); i++) {
				error = json_object_get(json_array_get(challenges, i),
							"error");
				if (json_str(error, "detail") != NULL) {
					printf("  %s\n",
					       json_str(error, "detail"));
				}
			}
			json_decref(authz);
			return CM_SUBMIT_STATUS_REJECTED;
		}
		if (answered) {
			/* We answered, and the server is checking. */
			json_decref(authz);
			if (wait_a_bit(client, &response) != 0) {
				return -1;
			}
			continue;
		}
		challenges = json_object_get(authz, "challenges");
		chosen = NULL;
		list = talloc_strdup(client->ctx, "");
		for (i = 0; i < json_array_size(challenges); i++) {
			challenge = json_array_get(challenges, i);
			type = json_str(challenge, "type");
			if (type == NULL) {
				continue;
			}
			list = talloc_asprintf_append(list, "%s%s",
						      strlen(list) ? ", " : "",
						      type);
			if ((strcmp(type, ACME_CHALLENGE_DEVICE_ATTEST) == 0) &&
			    (attestation->format != attest_none)) {
				chosen = challenge;
			}
		}
		if (chosen == NULL) {
			offered = strlen(list) ? list : _("none");
			printf(_("No challenge we can answer for %s "
				 "(offered: %s).\n"),
			       json_str(identifier, "value") ?
			       json_str(identifier, "value") : "?",
			       offered);
			json_decref(authz);
			return CM_SUBMIT_STATUS_REJECTED;
		}
		status = json_str(chosen, "status");
		if ((status == NULL) || (strcmp(status, "pending") == 0)) {
			ret = answer_device_attest(client, attestation,
						   json_str(chosen, "url"),
						   json_str(chosen, "token"));
			if (ret != 0) {
				json_decref(authz);
				return ret;
			}
		}
		answered = 1;
		json_decref(authz);
	}
}

/* Check that a certificate is for the key in the request. */
static int
cert_matches_request(X509 *cert, X509_REQ *req)
{
	EVP_PKEY *a, *b;
	int ret;

	a = X509_get0_pubkey(cert);
	b = X509_REQ_get0_pubkey(req);
	if ((a == NULL) || (b == NULL)) {
		return 0;
	}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ret = EVP_PKEY_eq(a, b);
#else
	ret = EVP_PKEY_cmp(a, b);
#endif
	return ret == 1;
}

/* Download the certificate, and output it. */
static int
download_certificate(struct acme_client *client, const char *url,
		     X509_REQ *req)
{
	struct cm_acme_response response;
	BIO *in, *out;
	X509 *cert;
	char *pem;
	long length;
	int ret;

	ret = acme_post(client, url, NULL, 0, &response);
	if (ret != 0) {
		return ret;
	}
	if ((response.error != 0) || (response.response_code != 200)) {
		return failure_status(client, &response,
				      _("the certificate download"));
	}
	in = BIO_new_mem_buf(response.body, response.length);
	cert = in ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;
	BIO_free(in);
	if (cert == NULL) {
		printf(_("Error parsing the certificate.\n"));
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (!cert_matches_request(cert, req)) {
		printf(_("Error: the server issued a certificate for another "
			 "key.\n"));
		X509_free(cert);
		return CM_SUBMIT_STATUS_REJECTED;
	}
	out = BIO_new(BIO_s_mem());
	if ((out == NULL) || (PEM_write_bio_X509(out, cert) != 1)) {
		BIO_free(out);
		X509_free(cert);
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	length = BIO_get_mem_data(out, &pem);
	printf("%.*s", (int) length, pem);
	BIO_free(out);
	X509_free(cert);
	return CM_SUBMIT_STATUS_ISSUED;
}

/* Take an order to valid, and output its certificate. */
static int
process_order(struct acme_client *client, const char *order_url,
	      json_t *order, X509_REQ *req, const char *csr_der_b64,
	      struct acme_attestation *attestation)
{
	struct cm_acme_response response;
	json_t *authorizations, *error;
	const char *status, *url;
	char *payload;
	size_t i;
	int ret, finalized = 0;

	memset(&response, 0, sizeof(response));
	for (;;) {
		status = json_str(order, "status");
		if (status == NULL) {
			printf(_("The order has no status.\n"));
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (client->verbose > 0) {
			fprintf(stderr, "Order is %s.\n", status);
		}
		if (strcmp(status, "pending") == 0) {
			authorizations = json_object_get(order,
							 "authorizations");
			for (i = 0; i < json_array_size(authorizations); i++) {
				url = json_string_value(json_array_get(authorizations, i));
				if (url == NULL) {
					continue;
				}
				ret = process_authorization(client, url,
							    attestation);
				if (ret == -1) {
					return come_back_later(&response,
							       order_url);
				}
				if (ret != 0) {
					return ret;
				}
			}
		} else
		if (strcmp(status, "ready") == 0) {
			if (finalized) {
				/* The server hasn't caught up yet. */
				if (wait_a_bit(client, &response) != 0) {
					return come_back_later(&response,
							       order_url);
				}
			} else {
				url = json_str(order, "finalize");
				payload = talloc_asprintf(client->ctx,
							  "{\"csr\":\"%s\"}",
							  csr_der_b64);
				ret = acme_post(client, url, payload, 0,
						&response);
				if (ret != 0) {
					return ret;
				}
				if ((response.error != 0) ||
				    (response.response_code != 200)) {
					return failure_status(client, &response,
							      _("the finalization"));
				}
				finalized = 1;
				json_decref(order);
				order = response_json(&response);
				if (!json_is_object(order)) {
					printf(_("Error parsing the order.\n"));
					return CM_SUBMIT_STATUS_UNREACHABLE;
				}
				continue;
			}
		} else
		if (strcmp(status, "processing") == 0) {
			if (wait_a_bit(client, &response) != 0) {
				return come_back_later(&response, order_url);
			}
		} else
		if (strcmp(status, "valid") == 0) {
			url = json_str(order, "certificate");
			if (url == NULL) {
				printf(_("The order has no certificate.\n"));
				return CM_SUBMIT_STATUS_UNREACHABLE;
			}
			return download_certificate(client, url, req);
		} else {
			printf(_("The order is %s.\n"), status);
			error = json_object_get(order, "error");
			if (json_str(error, "detail") != NULL) {
				printf("  %s\n", json_str(error, "detail"));
			}
			return CM_SUBMIT_STATUS_REJECTED;
		}
		json_decref(order);
		ret = acme_get(client, order_url, _("the order"), &order,
			       &response);
		if (ret != 0) {
			return ret;
		}
	}
}

/* The request, and its DER encoding in base64url. */
static X509_REQ *
read_request(void *parent, const char *csr, char **der_b64)
{
	X509_REQ *req;
	BIO *in;
	unsigned char *der = NULL;
	int length;

	in = BIO_new_mem_buf(csr, -1);
	req = in ? PEM_read_bio_X509_REQ(in, NULL, NULL, NULL) : NULL;
	BIO_free(in);
	if (req == NULL) {
		return NULL;
	}
	length = i2d_X509_REQ(req, &der);
	if (length <= 0) {
		X509_REQ_free(req);
		return NULL;
	}
	*der_b64 = cm_acme_b64url_encode(parent, der, length);
	OPENSSL_free(der);
	return req;
}

/* Each directory URL gets an account, and a directory of its own. */
static char *
account_dir(void *parent, const char *base, const char *url)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	char hex[2 * 16 + 1];
	int i;

	SHA256((const unsigned char *) url, strlen(url), md);
	for (i = 0; i < 16; i++) {
		snprintf(hex + 2 * i, 3, "%02x", md[i]);
	}
	return talloc_asprintf(parent, "%s/%s", base, hex);
}

int
main(int argc, const char **argv)
{
	const char *url = NULL, *cainfo = NULL, *mode, *state_base = NULL;
	const char *eab_kid = NULL, *eab_key_file = NULL, *attest = NULL;
	const char *permanent_identifier = NULL, *tcti = NULL;
	const char *csr, *cookie, *key_pin_file, *p;
	struct acme_client client;
	struct acme_attestation attestation;
	struct cm_acme_response response;
	struct acme_eab eab;
	char *key_pin = NULL, *csr_der_b64 = NULL;
	char *payload, *order_url, *path;
	json_t *identifiers, *order;
	X509_REQ *req = NULL;
	int c, verbose = 0, rval = CM_SUBMIT_STATUS_UNCONFIGURED;
	int lock_fd = -1;
	void *ctx;
	poptContext pctx = NULL;
	struct poptOption popts[] = {
		{"directory", 'u', POPT_ARG_STRING, &url, 0, "ACME directory URL", "URL"},
		{"cacert", 'R', POPT_ARG_STRING, &cainfo, 0, "the CA certificate(s), used for verifying TLS connections", "FILENAME"},
		{"eab-kid", 'k', POPT_ARG_STRING, &eab_kid, 0, "key identifier for external account binding", "KID"},
		{"eab-key-file", 'K', POPT_ARG_STRING, &eab_key_file, 0, "file containing the MAC key for external account binding", "FILENAME"},
		{"attest", 'a', POPT_ARG_STRING, &attest, 0, "answer device-attest-01 challenges using the given attestation format (\"tpm\")", "FORMAT"},
		{"permanent-identifier", 'P', POPT_ARG_STRING, &permanent_identifier, 0, "the device's permanent identifier, to request", "VALUE"},
		{"state-dir", 's', POPT_ARG_STRING, &state_base, 0, "directory for account and attestation data", "DIRECTORY"},
		{"tcti", 'T', POPT_ARG_STRING, &tcti, 0, "TPM command transmission interface", "TCTI"},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	util_o_init();
	ERR_load_crypto_strings();

	csr = getenv(CM_SUBMIT_CSR_ENV);
	cookie = getenv(CM_SUBMIT_COOKIE_ENV);
	key_pin_file = getenv(CM_SUBMIT_KEY_PIN_FILE_ENV);

	mode = getenv(CM_SUBMIT_OPERATION_ENV);
	if (mode != NULL) {
		if ((strcasecmp(mode, CM_OP_SUBMIT) == 0) ||
		    (strcasecmp(mode, CM_OP_POLL) == 0)) {
			/* handled below */
		} else
		if (strcasecmp(mode, CM_OP_IDENTIFY) == 0) {
			printf("ACME (%s %s)\n", PACKAGE_NAME, PACKAGE_VERSION);
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
	memset(&client, 0, sizeof(client));
	memset(&attestation, 0, sizeof(attestation));
	memset(&eab, 0, sizeof(eab));
	eab.ctx = ctx;
	client.ctx = ctx;
	client.verbose = verbose;
	client.cainfo = cainfo;

	if (url == NULL) {
		printf(_("No ACME directory URL (-u) given.\n"));
		poptPrintUsage(pctx, stdout, 0);
		goto done;
	}
	if ((strncasecmp(url, "https://", 8) != 0) || !json_safe(url)) {
		printf(_("ACME requires an https URL, not \"%s\".\n"), url);
		goto done;
	}
	client.directory_url = url;
	if (attest != NULL) {
		if (strcasecmp(attest, "tpm") == 0) {
			attestation.format = attest_tpm;
		} else {
			printf(_("Unknown attestation format \"%s\".\n"),
			       attest);
			goto done;
		}
	}

	/* Read the request from a file if we're run by hand. */
	if (((csr == NULL) || (strlen(csr) == 0)) &&
	    (poptPeekArg(pctx) != NULL)) {
		csr = cm_submit_u_from_file(poptGetArg(pctx));
	}
	if ((csr == NULL) || (strlen(csr) == 0)) {
		printf(_("No certificate signing request to submit.\n"));
		goto done;
	}
	req = read_request(ctx, csr, &csr_der_b64);
	if (req == NULL) {
		printf(_("Error reading request.\n"));
		goto done;
	}

	/* The external account binding: a challenge password of the form
	 * "KID:KEY", given with the request, takes precedence over the one
	 * in the CA configuration. */
	p = getenv(CM_SUBMIT_CHALLENGE_PASSWORD_ENV);
	if ((p != NULL) && (strchr(p, ':') != NULL)) {
		eab.kid = talloc_strndup(ctx, p, strchr(p, ':') - p);
		eab.secret = talloc_strdup(ctx, strchr(p, ':') + 1);
	} else {
		eab.kid = eab_kid;
		eab.file = eab_key_file;
	}
	if ((eab.kid == NULL) &&
	    ((eab.secret != NULL) || (eab.file != NULL))) {
		printf(_("An external account key was given without "
			 "its key ID.\n"));
		goto done;
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
	attestation.tcti = tcti;
	attestation.key_storage_type = getenv(CM_SUBMIT_KEY_STORAGE_TYPE_ENV);
	attestation.key_location = getenv(CM_SUBMIT_KEY_STORAGE_LOCATION_ENV);
	attestation.key_token = getenv(CM_SUBMIT_KEY_TOKEN_ENV);
	attestation.key_pin = key_pin;
	attestation.csr = csr;

	/* Where we keep the account's key. */
	if (state_base == NULL) {
		state_base = getenv(CM_STORE_ACME_DIRECTORY_ENV);
	}
	if ((state_base == NULL) || (strlen(state_base) == 0)) {
		state_base = CM_STORE_ACME_DIRECTORY;
	}
	client.state_dir = account_dir(ctx, state_base, url);
	client.eab_dir = talloc_asprintf(ctx, "%s/%s", state_base,
					 CM_STORE_ACME_EAB_SUBDIR);
	if ((mkdir_private(state_base) != 0) ||
	    (mkdir_private(client.state_dir) != 0)) {
		printf(_("Error creating directory \"%s\": %s.\n"),
		       client.state_dir, strerror(errno));
		goto done;
	}
	/* One of us at a time per account: the account, and the attestation
	 * key, are created on first use. */
	path = state_file(&client, ACME_LOCK_FILE);
	lock_fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if ((lock_fd == -1) || (flock(lock_fd, LOCK_EX) != 0)) {
		printf(_("Error locking \"%s\": %s.\n"), path,
		       strerror(errno));
		goto done;
	}
	path = state_file(&client, "directory");
	if (access(path, F_OK) != 0) {
		write_file(ctx, path, url);
	}

	client.deadline = time(NULL) + ACME_INLINE_WAIT;
	rval = fetch_directory(&client);
	if (rval != 0) {
		goto done;
	}
	rval = setup_account(&client, &eab);
	if (rval != 0) {
		goto done;
	}

	/* Pick up where we left off, or place a new order. */
	order = NULL;
	order_url = NULL;
	if ((cookie != NULL) && (strncasecmp(cookie, "https://", 8) == 0) &&
	    json_safe(cookie)) {
		order_url = talloc_strdup(ctx, cookie);
		rval = acme_get(&client, order_url, _("the order"), &order,
				&response);
		if ((rval == CM_SUBMIT_STATUS_REJECTED) &&
		    (response.response_code == 404)) {
			/* Gone: start over. */
			order_url = NULL;
		} else
		if (rval != 0) {
			goto done;
		}
	}
	if (order_url == NULL) {
		identifiers = order_identifiers(ctx, req,
						permanent_identifier,
						attestation.format != attest_none);
		if (json_array_size(identifiers) == 0) {
			printf(_("The request names nothing to ask for.\n"));
			json_decref(identifiers);
			rval = CM_SUBMIT_STATUS_UNCONFIGURED;
			goto done;
		}
		p = json_dumps(identifiers, JSON_COMPACT);
		payload = talloc_asprintf(ctx, "{\"identifiers\":%s}", p);
		free((void *) p);
		json_decref(identifiers);
		rval = acme_post(&client, directory_url(&client, "newOrder"),
				 payload, 0, &response);
		if ((rval == 0) && (response.error == 0) &&
		    ((response.response_code == 400) ||
		     (response.response_code == 401) ||
		     (response.response_code == 403))) {
			/* The account may be gone: make a new one if we can,
			 * and try again. */
			json_t *problem = response_json(&response);
			const char *type = json_str(problem, "type");
			if ((type != NULL) && eab_given(&eab) &&
			    ((strcmp(type, ACME_ERROR_PREFIX "accountDoesNotExist") == 0) ||
			     (strcmp(type, ACME_ERROR_PREFIX "unauthorized") == 0))) {
				forget_account(&client);
				rval = setup_account(&client, &eab);
				if (rval == 0) {
					rval = acme_post(&client,
							 directory_url(&client, "newOrder"),
							 payload, 0, &response);
				}
			}
			json_decref(problem);
		}
		if (rval != 0) {
			goto done;
		}
		if ((response.error != 0) ||
		    ((response.response_code != 201) &&
		     (response.response_code != 200))) {
			rval = failure_status(&client, &response,
					      _("the order"));
			goto done;
		}
		if (!json_safe(response.location)) {
			printf(_("The server did not say where the order "
				 "is.\n"));
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto done;
		}
		order_url = talloc_strdup(ctx, response.location);
		order = response_json(&response);
		if (!json_is_object(order)) {
			printf(_("Error parsing the order.\n"));
			rval = CM_SUBMIT_STATUS_UNREACHABLE;
			goto done;
		}
	}
	rval = process_order(&client, order_url, order, req, csr_der_b64,
			     &attestation);

done:
	if (eab.key != NULL) {
		memset(eab.key, '\0', eab.length);
	}
	if (key_pin != NULL) {
		memset(key_pin, '\0', strlen(key_pin));
	}
	if (client.signer.key != NULL) {
		EVP_PKEY_free(client.signer.key);
	}
	json_decref(client.directory);
	X509_REQ_free(req);
	if (lock_fd != -1) {
		close(lock_fd);
	}
	if (pctx) {
		poptFreeContext(pctx);
	}
	talloc_free(ctx);
	return rval;
}
