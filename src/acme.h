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

#ifndef cmacme_h
#define cmacme_h

#include <openssl/evp.h>

#define ACME_CONTENT_TYPE_JOSE "application/jose+json"
#define ACME_CONTENT_TYPE_PROBLEM "application/problem+json"
#define ACME_CONTENT_TYPE_PEM_CHAIN "application/pem-certificate-chain"

#define ACME_ERROR_PREFIX "urn:ietf:params:acme:error:"

#define ACME_CHALLENGE_DEVICE_ATTEST "device-attest-01"
#define ACME_CHALLENGE_DNS "dns-01"
#define ACME_IDENTIFIER_PERMANENT "permanent-identifier"

/* Files in an account's state directory. */
#define ACME_ACCOUNT_KEY_FILE "account.key"
#define ACME_ACCOUNT_URL_FILE "account.url"
#define ACME_LOCK_FILE "lock"

/* What we got back from the server. */
struct cm_acme_response {
	int error;			/* nonzero if we couldn't get a reply */
	const char *error_text;
	long response_code;		/* HTTP status */
	const char *content_type;
	const char *location;
	const char *retry_after;
	const char *replay_nonce;
	const char *link;
	const char *body;
	size_t length;
};

/* acme-jose.c: base64url, JWK, JWS (RFC 7515, 7517, 7638) and the external
 * account binding (RFC 8555 7.3.4). */
char *cm_acme_b64url_encode(void *parent, const unsigned char *data,
			    size_t length);
char *cm_acme_b64_encode(void *parent, const unsigned char *data,
			 size_t length);
unsigned char *cm_acme_b64_decode(void *parent, const char *text,
				  size_t *length);
EVP_PKEY *cm_acme_account_key(const char *filename, int create,
			      const char **error);
char *cm_acme_jwk(void *parent, EVP_PKEY *key);
char *cm_acme_jwk_thumbprint(void *parent, const char *jwk);
char *cm_acme_jws(void *parent, EVP_PKEY *key, const char *kid,
		  const char *jwk, const char *nonce, const char *url,
		  const char *payload);
char *cm_acme_eab(void *parent, const char *eab_kid,
		  const unsigned char *eab_key, size_t eab_key_length,
		  const char *jwk, const char *url);
int cm_acme_hmac_sha256(const unsigned char *key, size_t key_length,
			const unsigned char *data, size_t length,
			unsigned char *mac);

/* An HTTP POST of a JSON document, which the attestation code uses to talk
 * to the server's attestation key certification service.  Returns 0 if a
 * response was received, whatever its status. */
typedef int (*cm_acme_post_json_fn)(void *parent, void *data,
				    const char *url, const char *body,
				    struct cm_acme_response *response);
/* An HTTP GET, which it uses to fetch the certificates of the CAs which
 * issued the endorsement key's certificate. */
typedef int (*cm_acme_get_fn)(void *parent, void *data, const char *url,
			      struct cm_acme_response *response);

/* acme-tpm.c: device attestation with a TPM. */
struct cm_acme_tpm_params {
	const char *state_dir;		/* where the AK is kept */
	const char *tcti;		/* NULL for the default TCTI */
	const char *service_url;	/* base of attest/v1/ak/{begin,finish} */
	const char *eab_kid;
	const unsigned char *eab_key;
	size_t eab_key_length;
	/* The device key, as the daemon describes it. */
	const char *key_storage_type;
	const char *key_location;
	const char *key_token;
	const char *key_pin;
	const char *csr;
	int verbose;
	cm_acme_post_json_fn post_json;
	cm_acme_get_fn get;
	void *http_data;
};
int cm_acme_tpm_attest(void *parent, struct cm_acme_tpm_params *params,
		       const char *key_authorization,
		       unsigned char **att_obj, size_t *att_obj_length,
		       const char **error);

/* acme-dns.c: publishing dns-01 records (RFC 8555 8.4) with DNS UPDATE
 * (RFC 2136), signed with TSIG (RFC 8945) or GSS-TSIG (RFC 3645).  The
 * functions print what went wrong, and return 0 or one of the
 * CM_SUBMIT_STATUS_* values. */
#define CM_ACME_DNS_DEFAULT_TTL 60
#define CM_ACME_DNS_DEFAULT_WAIT 120
struct cm_acme_dns_params {
	const char *update_server;	/* HOST[:PORT], else the SOA's MNAME */
	const char *zone;		/* else found with SOA queries */
	const char *resolver;		/* ADDRESS[:PORT], else the system's */
	const char *check_servers;	/* HOST[:PORT],..., else the NS set */
	const char *tsig_key_file;
	int gss_tsig;
	const char *keytab;		/* for GSS-TSIG, else the default */
	const char *principal;		/* for GSS-TSIG, else the keytab's */
	long ttl;
	long wait;			/* for the servers to serve the record */
	int verbose;
};
struct cm_acme_dns;
struct cm_acme_dns_record;
struct cm_acme_dns *cm_acme_dns_new(void *parent,
				    const struct cm_acme_dns_params *params);
int cm_acme_dns_publish(struct cm_acme_dns *dns, const char *domain,
			const char *value, struct cm_acme_dns_record **record);
int cm_acme_dns_wait(struct cm_acme_dns *dns,
		     struct cm_acme_dns_record *record);
int cm_acme_dns_remove(struct cm_acme_dns *dns,
		       struct cm_acme_dns_record *record);

#endif
