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

/* Certifying a key which the daemon generated in a TPM through the
 * tpm2-pkcs11 PKCS#11 module with another key of the TPM.
 *
 * TPM2_Certify needs the authorization value of the key which is
 * certified, which the module keeps to itself, so the module performs it:
 * its vendor mechanism CKM_TPM2_CERTIFY is a "signature" by the key which
 * is certified, whose parameter names the signing key, which is not an
 * object of the token, and whose output is the TPM2B_ATTEST and the
 * TPMT_SIGNATURE which TPM2_Certify returns.  We hand it the attestation
 * key as a saved context, which the module loads in its own connection to
 * the TPM. */

#include "config.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include <talloc.h>

#include "acme-tpm.h"

/* tpm2-pkcs11's vendor attribute and mechanism (its installed header
 * tpm2-pkcs11/pkcs11-tpm2.h). */
#define CKA_VENDOR_TPM2_DEFINED 0x0F000000UL
#define CKA_TPM2_PUB_BLOB (CKA_VENDOR_DEFINED | CKA_VENDOR_TPM2_DEFINED | 0x2UL)
#define CKM_VENDOR_TPM2_DEFINED 0x0F000000UL
#define CKM_TPM2_CERTIFY (CKM_VENDOR_DEFINED | CKM_VENDOR_TPM2_DEFINED | 0x1UL)
#define CKF_TPM2_SIGNER_CONTEXT 0x1UL

typedef struct CK_TPM2_CERTIFY_PARAMS {
	CK_FLAGS flags;
	CK_BYTE_PTR pSigner;
	CK_ULONG ulSignerLen;
	CK_BYTE_PTR pSignerAuth;
	CK_ULONG ulSignerAuthLen;
	CK_BYTE_PTR pInScheme;
	CK_ULONG ulInSchemeLen;
} CK_TPM2_CERTIFY_PARAMS;

static char *
pin_cb(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	const char *pin = arg;

	(void) slot;
	if (retry || (pin == NULL)) {
		return NULL;
	}
	return PL_strdup(pin);
}

static const char *
nss_error(void *parent, const char *what)
{
	PRErrorCode ec;
	const char *name;

	ec = PORT_GetError();
	name = PR_ErrorToName(ec);
	return talloc_asprintf(parent, "%s: %s", what,
			       name ? name : "unknown error");
}

/* The public key of the request, as NSS sees it. */
static SECKEYPublicKey *
request_public_key(const char *csr)
{
	X509_REQ *req;
	EVP_PKEY *pkey;
	BIO *in;
	unsigned char *der = NULL;
	int length;
	SECItem item;
	CERTSubjectPublicKeyInfo *spki;
	SECKEYPublicKey *ret = NULL;

	in = BIO_new_mem_buf(csr, -1);
	req = in ? PEM_read_bio_X509_REQ(in, NULL, NULL, NULL) : NULL;
	BIO_free(in);
	if (req == NULL) {
		return NULL;
	}
	pkey = X509_REQ_get0_pubkey(req);
	length = pkey ? i2d_PUBKEY(pkey, &der) : -1;
	X509_REQ_free(req);
	if (length <= 0) {
		return NULL;
	}
	item.type = siBuffer;
	item.data = der;
	item.len = length;
	spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&item);
	OPENSSL_free(der);
	if (spki != NULL) {
		ret = SECKEY_ExtractPublicKey(spki);
		SECKEY_DestroySubjectPublicKeyInfo(spki);
	}
	return ret;
}

/* The private key for the request's public key in the token. */
static SECKEYPrivateKey *
find_key(PK11SlotInfo *slot, const char *pin, const char *csr)
{
	SECKEYPublicKey *pub;
	SECKEYPrivateKey *key = NULL;
	SECItem *id = NULL;

	pub = request_public_key(csr);
	if (pub == NULL) {
		return NULL;
	}
	/* NSS sets the ID of the keys it generates from their public key. */
	switch (pub->keyType) {
	case rsaKey:
		id = PK11_MakeIDFromPubKey(&pub->u.rsa.modulus);
		break;
	case ecKey:
		id = PK11_MakeIDFromPubKey(&pub->u.ec.publicValue);
		break;
	default:
		break;
	}
	if (id != NULL) {
		key = PK11_FindKeyByKeyID(slot, id, (void *) pin);
		SECITEM_FreeItem(id, PR_TRUE);
	}
	SECKEY_DestroyPublicKey(pub);
	return key;
}

int
cm_acme_tpm_p11_certify(void *parent, const char *dbdir, const char *token,
			const char *pin, const char *csr,
			const unsigned char *signer_context,
			size_t signer_context_length,
			const unsigned char *qualifying,
			size_t qualifying_length,
			TPM2B_PUBLIC *public, TPM2B_ATTEST *certify_info,
			TPMT_SIGNATURE *signature, const char **error)
{
	NSSInitContext *nctx;
	PK11SlotInfo *slot = NULL;
	SECKEYPrivateKey *key = NULL;
	SECItem pub_blob, param, data, out;
	CK_TPM2_CERTIFY_PARAMS params;
	unsigned char *buf = NULL;
	size_t offset;
	int ret = -1;

	if ((token == NULL) || (strlen(token) == 0)) {
		*error = "the key is not in a token";
		return -1;
	}
	if (pin == NULL) {
		pin = "";
	}
	memset(&pub_blob, 0, sizeof(pub_blob));
	nctx = NSS_InitContext(dbdir, NULL, NULL, NULL, NULL,
			       NSS_INIT_READONLY);
	if (nctx == NULL) {
		*error = nss_error(parent, "error opening the NSS database");
		return -1;
	}
	PK11_SetPasswordFunc(pin_cb);
	slot = PK11_FindSlotByName(token);
	if (slot == NULL) {
		*error = nss_error(parent, "error finding the token");
		goto done;
	}
	if (!PK11_DoesMechanism(slot, CKM_TPM2_CERTIFY)) {
		*error = "the token does not support TPM2_Certify (the "
			 "CKM_TPM2_CERTIFY mechanism of the tpm2-pkcs11 module)";
		ret = CM_ACME_TPM_P11_NO_CERTIFY;
		goto done;
	}
	if (PK11_NeedLogin(slot) &&
	    (PK11_Authenticate(slot, PR_TRUE, (void *) pin) != SECSuccess)) {
		*error = nss_error(parent, "error logging in to the token");
		goto done;
	}
	key = find_key(slot, pin, csr);
	if (key == NULL) {
		*error = "the key of the request is not in the token";
		goto done;
	}

	/* The key's public area, which the attestation statement carries. */
	offset = 0;
	memset(public, 0, sizeof(*public));
	if ((PK11_ReadRawAttribute(PK11_TypePrivKey, key, CKA_TPM2_PUB_BLOB,
				   &pub_blob) != SECSuccess) ||
	    (Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_blob.data, pub_blob.len,
					    &offset, public) !=
	     TSS2_RC_SUCCESS)) {
		*error = "the key is not a TPM key of the tpm2-pkcs11 module";
		goto done;
	}

	memset(&params, 0, sizeof(params));
	params.flags = CKF_TPM2_SIGNER_CONTEXT;
	params.pSigner = (CK_BYTE_PTR) signer_context;
	params.ulSignerLen = signer_context_length;
	param.type = siBuffer;
	param.data = (unsigned char *) &params;
	param.len = sizeof(params);
	data.type = siBuffer;
	data.data = (unsigned char *) qualifying;
	data.len = qualifying_length;
	buf = talloc_size(parent, sizeof(*certify_info) + sizeof(*signature));
	out.type = siBuffer;
	out.data = buf;
	out.len = buf ? sizeof(*certify_info) + sizeof(*signature) : 0;
	if ((buf == NULL) ||
	    (PK11_SignWithMechanism(key, CKM_TPM2_CERTIFY, &param, &out,
				    &data) != SECSuccess)) {
		*error = nss_error(parent, "error certifying the key");
		goto done;
	}

	/* TPM2B_ATTEST || TPMT_SIGNATURE */
	offset = 0;
	memset(certify_info, 0, sizeof(*certify_info));
	memset(signature, 0, sizeof(*signature));
	if ((Tss2_MU_TPM2B_ATTEST_Unmarshal(out.data, out.len, &offset,
					    certify_info) !=
	     TSS2_RC_SUCCESS) ||
	    (Tss2_MU_TPMT_SIGNATURE_Unmarshal(out.data, out.len, &offset,
					      signature) !=
	     TSS2_RC_SUCCESS) ||
	    (offset != out.len)) {
		*error = "the token returned a malformed attestation";
		goto done;
	}
	ret = 0;
done:
	talloc_free(buf);
	if (pub_blob.data != NULL) {
		SECITEM_FreeItem(&pub_blob, PR_FALSE);
	}
	if (key != NULL) {
		SECKEY_DestroyPrivateKey(key);
	}
	if (slot != NULL) {
		PK11_FreeSlot(slot);
	}
	NSS_ShutdownContext(nctx);
	return ret;
}
