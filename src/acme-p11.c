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

/* The ACME account key, where there is a TPM: an ECDSA P-256 key generated
 * in our TPM token, which signs our requests without ever leaving the TPM.
 * It is generated and used through PKCS#11 directly, not through NSS, whose
 * templates for EC keys the TPM module refuses. */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <talloc.h>

#include "acme.h"
#include "log.h"
#include "tpm-token.h"
#include "tpm-token-p11.h"

#define ES256_COORDINATE_LENGTH 32

struct cm_acme_p11_key {
	struct cm_tpm_token_session *token;
	CK_OBJECT_HANDLE private_key;
	unsigned char point[1 + 2 * ES256_COORDINATE_LENGTH];
};

int
cm_acme_p11_available(void)
{
	const char *ours;

	/* The daemon tells us when our environment points the module at its
	 * token, and how to reach the TPM. */
	ours = getenv(CM_TPM_TOKEN_ENV);
	if ((ours == NULL) || (strcmp(ours, "1") != 0)) {
		return 0;
	}
	return cm_tpm_token_available();
}

/* The DER encoding of the OID of P-256, as CKA_EC_PARAMS holds it. */
static const CK_BYTE p256_params[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};

/* Find the one object of a class with the label. */
static CK_OBJECT_HANDLE
find_object(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session,
	    CK_OBJECT_CLASS class, const char *label)
{
	CK_ATTRIBUTE attrs[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_LABEL, (void *) label, strlen(label)},
	};
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_ULONG count = 0;

	if (f->C_FindObjectsInit(session, attrs, 2) != CKR_OK) {
		return CK_INVALID_HANDLE;
	}
	if ((f->C_FindObjects(session, &object, 1, &count) != CKR_OK) ||
	    (count != 1)) {
		object = CK_INVALID_HANDLE;
	}
	f->C_FindObjectsFinal(session);
	return object;
}

/* The uncompressed point of a public key, which CKA_EC_POINT holds as a DER
 * OCTET STRING, or bare in modules which don't wrap it. */
static int
read_point(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session,
	   CK_OBJECT_HANDLE public_key, unsigned char *point)
{
	CK_BYTE value[128];
	CK_ATTRIBUTE attr = {CKA_EC_POINT, value, sizeof(value)};
	const CK_BYTE *p = value;
	CK_ULONG length;

	if (f->C_GetAttributeValue(session, public_key, &attr, 1) != CKR_OK) {
		return -1;
	}
	length = attr.ulValueLen;
	if ((length == 2 + 1 + 2 * ES256_COORDINATE_LENGTH) &&
	    (p[0] == 0x04) && (p[1] == 1 + 2 * ES256_COORDINATE_LENGTH)) {
		p += 2;
		length -= 2;
	}
	if ((length != 1 + 2 * ES256_COORDINATE_LENGTH) || (p[0] != 0x04)) {
		return -1;
	}
	memcpy(point, p, length);
	return 0;
}

static int
generate(CK_FUNCTION_LIST_PTR f, CK_SESSION_HANDLE session,
	 const char *label, const unsigned char *id, size_t id_length,
	 CK_OBJECT_HANDLE *public_key, CK_OBJECT_HANDLE *private_key)
{
	CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ATTRIBUTE public_attrs[] = {
		{CKA_TOKEN, &yes, sizeof(yes)},
		{CKA_VERIFY, &yes, sizeof(yes)},
		{CKA_EC_PARAMS, (void *) p256_params, sizeof(p256_params)},
		{CKA_LABEL, (void *) label, strlen(label)},
		{CKA_ID, (void *) id, id_length},
	};
	CK_ATTRIBUTE private_attrs[] = {
		{CKA_TOKEN, &yes, sizeof(yes)},
		{CKA_PRIVATE, &yes, sizeof(yes)},
		{CKA_SIGN, &yes, sizeof(yes)},
		{CKA_SENSITIVE, &yes, sizeof(yes)},
		{CKA_EXTRACTABLE, &no, sizeof(no)},
		{CKA_LABEL, (void *) label, strlen(label)},
		{CKA_ID, (void *) id, id_length},
	};
	CK_RV rv;

	rv = f->C_GenerateKeyPair(session, &mechanism,
				  public_attrs,
				  sizeof(public_attrs) / sizeof(public_attrs[0]),
				  private_attrs,
				  sizeof(private_attrs) /
				  sizeof(private_attrs[0]),
				  public_key, private_key);
	if (rv != CKR_OK) {
		cm_log(1, "Error generating the account key in the TPM token: "
		       "0x%lx.\n", (unsigned long) rv);
		return -1;
	}
	return 0;
}

struct cm_acme_p11_key *
cm_acme_p11_account_key(void *parent, const char *name, int create,
			const char **error)
{
	struct cm_acme_p11_key *key;
	CK_OBJECT_HANDLE public_key;
	unsigned char id[SHA256_DIGEST_LENGTH];
	char *label;

	key = talloc_zero(parent, struct cm_acme_p11_key);
	if (key == NULL) {
		*error = "out of memory";
		return NULL;
	}
	key->token = cm_tpm_token_open(key, 1, error);
	if (key->token == NULL) {
		talloc_free(key);
		return NULL;
	}
	/* One key per account, named after its state directory. */
	label = talloc_asprintf(key, "acme-account-%s", name);
	if (label == NULL) {
		*error = "out of memory";
		talloc_free(key);
		return NULL;
	}
	SHA256((const unsigned char *) label, strlen(label), id);
	key->private_key = find_object(key->token->f, key->token->session,
				       CKO_PRIVATE_KEY, label);
	public_key = find_object(key->token->f, key->token->session,
				 CKO_PUBLIC_KEY, label);
	if ((key->private_key == CK_INVALID_HANDLE) ||
	    (public_key == CK_INVALID_HANDLE)) {
		if (!create) {
			*error = "the account key is not in the TPM token";
			talloc_free(key);
			return NULL;
		}
		if (generate(key->token->f, key->token->session, label,
			     id, 20, &public_key, &key->private_key) != 0) {
			*error = "error generating the account key in the "
				 "TPM token";
			talloc_free(key);
			return NULL;
		}
	}
	if (read_point(key->token->f, key->token->session, public_key,
		       key->point) != 0) {
		*error = "the account key in the TPM token is not a P-256 key";
		talloc_free(key);
		return NULL;
	}
	return key;
}

const unsigned char *
cm_acme_p11_point(struct cm_acme_p11_key *key)
{
	return key->point;
}

int
cm_acme_p11_sign_es256(struct cm_acme_p11_key *key, const char *input,
		       unsigned char *signature)
{
	CK_MECHANISM mechanism = {CKM_ECDSA, NULL, 0};
	unsigned char md[SHA256_DIGEST_LENGTH];
	CK_ULONG length = 2 * ES256_COORDINATE_LENGTH;
	CK_FUNCTION_LIST_PTR f = key->token->f;
	CK_RV rv;

	/* CKM_ECDSA signs a digest, and gives the signature as R || S, which
	 * is what ES256 wants (RFC 7518 3.4). */
	SHA256((const unsigned char *) input, strlen(input), md);
	rv = f->C_SignInit(key->token->session, &mechanism, key->private_key);
	if (rv == CKR_OK) {
		rv = f->C_Sign(key->token->session, md, sizeof(md),
			       signature, &length);
	}
	if ((rv != CKR_OK) || (length != 2 * ES256_COORDINATE_LENGTH)) {
		cm_log(1, "Error signing with the account key in the TPM "
		       "token: 0x%lx.\n", (unsigned long) rv);
		return -1;
	}
	return 0;
}
