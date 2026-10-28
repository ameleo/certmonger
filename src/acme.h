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

/* acme-p11.c: the account key in our TPM token, where there is a TPM. */
struct cm_acme_p11_key;
/* Whether the account key belongs in the TPM token: there is a TPM. */
int cm_acme_p11_available(void);
/* The account key of the account whose state directory has this name,
 * generated in the token if asked to when it isn't there yet. */
struct cm_acme_p11_key *cm_acme_p11_account_key(void *parent,
						const char *name, int create,
						const char **error);
/* Its public key, as an uncompressed point. */
const unsigned char *cm_acme_p11_point(struct cm_acme_p11_key *key);
/* An ES256 signature of the input, R || S, 64 bytes. */
int cm_acme_p11_sign_es256(struct cm_acme_p11_key *key, const char *input,
			   unsigned char *signature);

/* The account key: in a file, or in the TPM token. */
struct cm_acme_signer {
	EVP_PKEY *key;
	struct cm_acme_p11_key *p11;
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
char *cm_acme_jwk(void *parent, const struct cm_acme_signer *signer);
char *cm_acme_jwk_thumbprint(void *parent, const char *jwk);
char *cm_acme_jws(void *parent, const struct cm_acme_signer *signer,
		  const char *kid,
		  const char *jwk, const char *nonce, const char *url,
		  const char *payload);
char *cm_acme_eab(void *parent, const char *eab_kid,
		  const unsigned char *eab_key, size_t eab_key_length,
		  const char *jwk, const char *url);
int cm_acme_hmac_sha256(const unsigned char *key, size_t key_length,
			const unsigned char *data, size_t length,
			unsigned char *mac);

/* An ACME request carrying a JSON document, signed by the account, which
 * the attestation code uses to talk to the server's attestation key
 * certification service.  Returns 0 if a response was received, whatever
 * its status. */
typedef int (*cm_acme_post_signed_fn)(void *parent, void *data,
				      const char *url, const char *payload,
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
	/* The device key, as the daemon describes it. */
	const char *key_storage_type;
	const char *key_location;
	const char *key_token;
	const char *key_pin;
	const char *csr;
	int verbose;
	cm_acme_post_signed_fn post_signed;
	cm_acme_get_fn get;
	void *http_data;
};
int cm_acme_tpm_attest(void *parent, struct cm_acme_tpm_params *params,
		       const char *key_authorization,
		       unsigned char **att_obj, size_t *att_obj_length,
		       const char **error);

#endif
