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

/* Device attestation with a TPM, for the device-attest-01 challenge
 * (draft-ietf-acme-device-attest) in the WebAuthn "tpm" attestation
 * statement format (WebAuthn Level 2, 8.3).
 *
 * An attestation key (AK), a restricted signing key which we create under
 * the endorsement key (EK), certifies the device key using TPM2_Certify.
 * The server learns that the AK belongs to the TPM of the EK because the AK
 * is certified by an HMAC key which the server encrypted to the EK, which
 * only that TPM can import (the TCG's "EK-based key attestation" which does
 * not rely on TPM2_ActivateCredential), and then gives us a certificate for
 * the AK, which goes into the attestation statement. */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <jansson.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <talloc.h>

#include "acme.h"
#include "acme-tpm.h"
#include "log.h"
#include "submit-e.h"

#define AK_PUBLIC_FILE "ak.pub"
#define AK_PRIVATE_FILE "ak.priv"
#define AK_CERTIFICATE_FILE "ak.crt"

/* Renew the AK's certificate when it has less than this left. */
#define AK_RENEWAL_MARGIN (30 * 24 * 60 * 60)

/* Where TPMs keep their EK certificates (TCG EK Credential Profile 2.0,
 * 2.2.1.4). */
#define EK_CERT_NV_RSA 0x01c00002
#define EK_CERT_NV_ECC 0x01c0000a
#define NV_READ_CHUNK 512
/* Where they may keep the certificates of the CAs which issued them (TCG EK
 * Credential Profile 2.0, 2.2.1.5). */
#define EK_CHAIN_NV_FIRST 0x01c00100
#define EK_CHAIN_NV_LAST 0x01c001ff

/* How many certificates we follow up the EK certificate's chain. */
#define EK_CHAIN_MAX 4

/* COSE algorithm identifiers (RFC 9053, RFC 8812). */
#define COSE_ES256 (-7)
#define COSE_RS256 (-257)

/* The authorization policy of the default EK templates:
 * PolicySecret(TPM_RH_ENDORSEMENT) (TCG EK Credential Profile 2.0, B.3.3). */
static const BYTE ek_policy[] = {
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
	0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
	0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
	0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};

enum ek_type {
	ek_rsa,
	ek_ecc,
};

struct tpm_state {
	void *ctx;
	struct cm_acme_tpm_params *params;
	ESYS_CONTEXT *esys;
	TSS2_TCTI_CONTEXT *tcti;
	enum ek_type type;
	unsigned char *ek_cert;
	size_t ek_cert_length;
	ESYS_TR ek, ak;
	TPM2B_PUBLIC ak_public;
	X509 *ak_cert;
	STACK_OF(X509) *ak_chain;
	const char *error;
};

/* A minimal CBOR encoder (RFC 8949), for the attestation object, which
 * only holds maps, arrays, text and byte strings, and small negative
 * integers, all of definite length. */
struct cbor {
	void *ctx;
	unsigned char *buf;
	size_t length, size;
	int failed;
};

static void
cbor_put(struct cbor *c, const void *data, size_t length)
{
	unsigned char *p;
	size_t size;

	if (c->failed) {
		return;
	}
	if (c->length + length > c->size) {
		size = (c->size + length) * 2;
		p = talloc_realloc_size(c->ctx, c->buf, size);
		if (p == NULL) {
			c->failed = 1;
			return;
		}
		c->buf = p;
		c->size = size;
	}
	memcpy(c->buf + c->length, data, length);
	c->length += length;
}

static void
cbor_head(struct cbor *c, unsigned int major, uint64_t value)
{
	unsigned char head[9];
	size_t n;
	int i;

	if (value < 24) {
		head[0] = (major << 5) | value;
		n = 1;
	} else
	if (value <= 0xff) {
		head[0] = (major << 5) | 24;
		head[1] = value;
		n = 2;
	} else
	if (value <= 0xffff) {
		head[0] = (major << 5) | 25;
		head[1] = value >> 8;
		head[2] = value;
		n = 3;
	} else
	if (value <= 0xffffffff) {
		head[0] = (major << 5) | 26;
		for (i = 0; i < 4; i++) {
			head[1 + i] = value >> (24 - 8 * i);
		}
		n = 5;
	} else {
		head[0] = (major << 5) | 27;
		for (i = 0; i < 8; i++) {
			head[1 + i] = value >> (56 - 8 * i);
		}
		n = 9;
	}
	cbor_put(c, head, n);
}

static void
cbor_int(struct cbor *c, int64_t value)
{
	if (value >= 0) {
		cbor_head(c, 0, value);
	} else {
		cbor_head(c, 1, -1 - value);
	}
}

static void
cbor_bytes(struct cbor *c, const void *data, size_t length)
{
	cbor_head(c, 2, length);
	cbor_put(c, data, length);
}

static void
cbor_text(struct cbor *c, const char *text)
{
	cbor_head(c, 3, strlen(text));
	cbor_put(c, text, strlen(text));
}

static void
cbor_array(struct cbor *c, size_t n)
{
	cbor_head(c, 4, n);
}

static void
cbor_map(struct cbor *c, size_t n)
{
	cbor_head(c, 5, n);
}

static void
set_error(struct tpm_state *state, const char *what, TSS2_RC rc)
{
	state->error = talloc_asprintf(state->ctx, "%s: %s", what,
				       Tss2_RC_Decode(rc));
}

static char *
state_path(struct tpm_state *state, const char *name)
{
	return talloc_asprintf(state->ctx, "%s/%s",
			       state->params->state_dir, name);
}

static unsigned char *
read_file(void *parent, const char *path, size_t *length)
{
	unsigned char *ret = NULL, buf[4096];
	size_t n;
	FILE *fp;

	*length = 0;
	fp = fopen(path, "r");
	if (fp == NULL) {
		return NULL;
	}
	ret = talloc_size(parent, 0);
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
		ret = talloc_realloc_size(parent, ret, *length + n);
		if (ret == NULL) {
			break;
		}
		memcpy(ret + *length, buf, n);
		*length += n;
	}
	fclose(fp);
	return ret;
}

static int
write_file(void *parent, const char *path, const void *data, size_t length)
{
	char *tmp;
	int fd, ret = -1;

	tmp = talloc_asprintf(parent, "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		return -1;
	}
	if ((write(fd, data, length) == (ssize_t) length) &&
	    (fsync(fd) == 0)) {
		ret = 0;
	}
	close(fd);
	if ((ret == 0) && (rename(tmp, path) != 0)) {
		ret = -1;
	}
	if (ret != 0) {
		unlink(tmp);
	}
	return ret;
}

TSS2_RC
cm_acme_tpm_start_session(ESYS_CONTEXT *esys, ESYS_TR salt_key,
			  ESYS_TR *session)
{
	TPMT_SYM_DEF symmetric = {
		.algorithm = TPM2_ALG_AES,
		.keyBits = { .aes = 128 },
		.mode = { .aes = TPM2_ALG_CFB },
	};
	TSS2_RC rc;

	rc = Esys_StartAuthSession(esys, salt_key, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   NULL, TPM2_SE_HMAC, &symmetric,
				   TPM2_ALG_SHA256, session);
	if (rc != TSS2_RC_SUCCESS) {
		return rc;
	}
	return Esys_TRSess_SetAttributes(esys, *session,
					 TPMA_SESSION_CONTINUESESSION |
					 TPMA_SESSION_DECRYPT |
					 TPMA_SESSION_ENCRYPT,
					 0xff);
}

/* A policy session which satisfies the EK's policy, PolicySecret of the
 * endorsement hierarchy, whose authorization value we assume is empty. */
static TSS2_RC
ek_session(struct tpm_state *state, ESYS_TR *session)
{
	TPMT_SYM_DEF symmetric = {
		.algorithm = TPM2_ALG_AES,
		.keyBits = { .aes = 128 },
		.mode = { .aes = TPM2_ALG_CFB },
	};
	TSS2_RC rc;

	rc = Esys_StartAuthSession(state->esys, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   NULL, TPM2_SE_POLICY, &symmetric,
				   TPM2_ALG_SHA256, session);
	if (rc != TSS2_RC_SUCCESS) {
		return rc;
	}
	rc = Esys_PolicySecret(state->esys, ESYS_TR_RH_ENDORSEMENT, *session,
			       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			       NULL, NULL, NULL, 0, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		Esys_FlushContext(state->esys, *session);
		*session = ESYS_TR_NONE;
	}
	return rc;
}

/* Read an NV index which holds a certificate, or several. */
static unsigned char *
read_nv(struct tpm_state *state, TPM2_HANDLE index, int first_only,
	size_t *length)
{
	ESYS_TR nv = ESYS_TR_NONE;
	TPM2B_NV_PUBLIC *nv_public = NULL;
	TPM2B_MAX_NV_BUFFER *chunk = NULL;
	unsigned char *ret = NULL;
	size_t size, offset, der_length;
	UINT16 n;
	TSS2_RC rc;

	*length = 0;
	rc = Esys_TR_FromTPMPublic(state->esys, index, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		return NULL;
	}
	rc = Esys_NV_ReadPublic(state->esys, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &nv_public, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		goto done;
	}
	size = nv_public->nvPublic.dataSize;
	ret = talloc_size(state->ctx, size);
	for (offset = 0; offset < size; offset += n) {
		n = (size - offset > NV_READ_CHUNK) ?
		    NV_READ_CHUNK : size - offset;
		rc = Esys_NV_Read(state->esys, ESYS_TR_RH_OWNER, nv,
				  ESYS_TR_PASSWORD, ESYS_TR_NONE,
				  ESYS_TR_NONE, n, offset, &chunk);
		if ((rc != TSS2_RC_SUCCESS) || (chunk->size != n)) {
			talloc_free(ret);
			ret = NULL;
			goto done;
		}
		memcpy(ret + offset, chunk->buffer, n);
		Esys_Free(chunk);
		chunk = NULL;
	}
	/* The index may be larger than the certificate: keep its DER
	 * encoding only. */
	if (first_only && (size >= 4) && (ret[0] == 0x30) &&
	    (ret[1] == 0x82)) {
		der_length = 4 + ((ret[2] << 8) | ret[3]);
		if (der_length <= size) {
			size = der_length;
		}
	}
	*length = size;
done:
	Esys_Free(chunk);
	Esys_Free(nv_public);
	Esys_TR_Close(state->esys, &nv);
	return ret;
}

/* Whether the public key of a TPM object is the one in a certificate.  The
 * modulus of an RSA key, or the coordinates of an EC key, appear as they
 * are in the DER encoding of the certificate's SubjectPublicKeyInfo. */
static int
public_matches(const TPM2B_PUBLIC *public, X509 *cert)
{
	unsigned char *der = NULL, point[2 * TPM2_MAX_ECC_KEY_BYTES];
	const unsigned char *needle;
	size_t needle_length;
	int der_length, ret = 0;
	EVP_PKEY *pkey;

	pkey = X509_get0_pubkey(cert);
	if (pkey == NULL) {
		return 0;
	}
	switch (public->publicArea.type) {
	case TPM2_ALG_RSA:
		needle = public->publicArea.unique.rsa.buffer;
		needle_length = public->publicArea.unique.rsa.size;
		break;
	case TPM2_ALG_ECC:
		needle_length = public->publicArea.unique.ecc.x.size;
		if ((needle_length == 0) ||
		    (needle_length != public->publicArea.unique.ecc.y.size)) {
			return 0;
		}
		memcpy(point, public->publicArea.unique.ecc.x.buffer,
		       needle_length);
		memcpy(point + needle_length,
		       public->publicArea.unique.ecc.y.buffer, needle_length);
		needle = point;
		needle_length *= 2;
		break;
	default:
		return 0;
	}
	der_length = i2d_PUBKEY(pkey, &der);
	if ((der_length > 0) && (needle_length > 0) &&
	    (memmem(der, der_length, needle, needle_length) != NULL)) {
		ret = 1;
	}
	OPENSSL_free(der);
	return ret;
}

/* Read the EK certificate, and create the EK from the default template for
 * its type, which is what the certificate was issued for. */
static int
setup_ek(struct tpm_state *state)
{
	TPM2B_SENSITIVE_CREATE sensitive;
	TPM2B_PUBLIC template;
	TPM2B_DATA outside;
	TPML_PCR_SELECTION pcrs;
	TPM2B_PUBLIC *public = NULL;
	const unsigned char *p;
	X509 *cert;
	TSS2_RC rc;
	int ret = -1;

	state->ek_cert = read_nv(state, EK_CERT_NV_RSA, 1,
				 &state->ek_cert_length);
	state->type = ek_rsa;
	if (state->ek_cert == NULL) {
		state->ek_cert = read_nv(state, EK_CERT_NV_ECC, 1,
					 &state->ek_cert_length);
		state->type = ek_ecc;
	}
	if (state->ek_cert == NULL) {
		state->error = "the TPM has no endorsement key certificate";
		return -1;
	}
	p = state->ek_cert;
	cert = d2i_X509(NULL, &p, state->ek_cert_length);
	if (cert == NULL) {
		state->error = "can't parse the endorsement key certificate";
		return -1;
	}

	memset(&sensitive, 0, sizeof(sensitive));
	memset(&template, 0, sizeof(template));
	memset(&outside, 0, sizeof(outside));
	memset(&pcrs, 0, sizeof(pcrs));
	template.publicArea.nameAlg = TPM2_ALG_SHA256;
	template.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
					       TPMA_OBJECT_FIXEDPARENT |
					       TPMA_OBJECT_SENSITIVEDATAORIGIN |
					       TPMA_OBJECT_ADMINWITHPOLICY |
					       TPMA_OBJECT_RESTRICTED |
					       TPMA_OBJECT_DECRYPT;
	template.publicArea.authPolicy.size = sizeof(ek_policy);
	memcpy(template.publicArea.authPolicy.buffer, ek_policy,
	       sizeof(ek_policy));
	switch (state->type) {
	case ek_rsa:
		/* Template L-1 */
		template.publicArea.type = TPM2_ALG_RSA;
		template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
		template.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
		template.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		template.publicArea.parameters.rsaDetail.keyBits = 2048;
		template.publicArea.parameters.rsaDetail.exponent = 0;
		template.publicArea.unique.rsa.size = 256;
		break;
	case ek_ecc:
		/* Template L-2 */
		template.publicArea.type = TPM2_ALG_ECC;
		template.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
		template.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
		template.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		template.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		template.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
		template.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		template.publicArea.unique.ecc.x.size = 32;
		template.publicArea.unique.ecc.y.size = 32;
		break;
	}
	rc = Esys_CreatePrimary(state->esys, ESYS_TR_RH_ENDORSEMENT,
				ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				&sensitive, &template, &outside, &pcrs,
				&state->ek, &public, NULL, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error creating the endorsement key", rc);
		goto done;
	}
	if (!public_matches(public, cert)) {
		state->error = "the endorsement key is not the one in the "
			       "TPM's endorsement key certificate";
		goto done;
	}
	ret = 0;
done:
	Esys_Free(public);
	X509_free(cert);
	return ret;
}

static int
marshal_public(void *parent, const TPM2B_PUBLIC *public,
	       unsigned char **buf, size_t *length)
{
	size_t offset = 0;

	*buf = talloc_size(parent, sizeof(*public));
	if ((*buf == NULL) ||
	    (Tss2_MU_TPM2B_PUBLIC_Marshal(public, *buf, sizeof(*public),
					  &offset) != TSS2_RC_SUCCESS)) {
		return -1;
	}
	*length = offset;
	return 0;
}

/* Load the AK, or create it if we don't have one yet. */
static int
setup_ak(struct tpm_state *state)
{
	TPM2B_SENSITIVE_CREATE sensitive;
	TPM2B_PUBLIC template, *public = NULL;
	TPM2B_PRIVATE private, *created = NULL;
	TPM2B_DATA outside;
	TPML_PCR_SELECTION pcrs;
	ESYS_TR session = ESYS_TR_NONE;
	unsigned char *pub_buf, *priv_buf;
	size_t pub_length, priv_length, offset;
	TSS2_RC rc;
	int ret = -1;

	pub_buf = read_file(state->ctx, state_path(state, AK_PUBLIC_FILE),
			    &pub_length);
	priv_buf = read_file(state->ctx, state_path(state, AK_PRIVATE_FILE),
			     &priv_length);
	memset(&state->ak_public, 0, sizeof(state->ak_public));
	memset(&private, 0, sizeof(private));
	offset = 0;
	if ((pub_buf != NULL) && (priv_buf != NULL) &&
	    (Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_buf, pub_length, &offset,
					    &state->ak_public) ==
	     TSS2_RC_SUCCESS) &&
	    ((offset = 0),
	     Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_buf, priv_length, &offset,
					     &private) == TSS2_RC_SUCCESS) &&
	    (state->ak_public.publicArea.type ==
	     ((state->type == ek_rsa) ? TPM2_ALG_RSA : TPM2_ALG_ECC))) {
		rc = ek_session(state, &session);
		if (rc == TSS2_RC_SUCCESS) {
			rc = Esys_Load(state->esys, state->ek, session,
				       ESYS_TR_NONE, ESYS_TR_NONE,
				       &private, &state->ak_public,
				       &state->ak);
		}
		if (session != ESYS_TR_NONE) {
			Esys_FlushContext(state->esys, session);
			session = ESYS_TR_NONE;
		}
		if (rc == TSS2_RC_SUCCESS) {
			return 0;
		}
		/* Not this TPM's, or not this EK's: start over. */
		if (state->params->verbose > 0) {
			fprintf(stderr, "Can't load the attestation key (%s), "
				"creating a new one.\n", Tss2_RC_Decode(rc));
		}
	}

	memset(&sensitive, 0, sizeof(sensitive));
	memset(&template, 0, sizeof(template));
	memset(&outside, 0, sizeof(outside));
	memset(&pcrs, 0, sizeof(pcrs));
	template.publicArea.nameAlg = TPM2_ALG_SHA256;
	template.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM |
					       TPMA_OBJECT_FIXEDPARENT |
					       TPMA_OBJECT_SENSITIVEDATAORIGIN |
					       TPMA_OBJECT_USERWITHAUTH |
					       TPMA_OBJECT_RESTRICTED |
					       TPMA_OBJECT_SIGN_ENCRYPT;
	switch (state->type) {
	case ek_rsa:
		template.publicArea.type = TPM2_ALG_RSA;
		template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
		template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
		template.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
		template.publicArea.parameters.rsaDetail.keyBits = 2048;
		break;
	case ek_ecc:
		template.publicArea.type = TPM2_ALG_ECC;
		template.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
		template.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
		template.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
		template.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
		template.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		break;
	}
	rc = ek_session(state, &session);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error authorizing use of the endorsement key",
			  rc);
		return -1;
	}
	rc = Esys_Create(state->esys, state->ek, session, ESYS_TR_NONE,
			 ESYS_TR_NONE, &sensitive, &template, &outside, &pcrs,
			 &created, &public, NULL, NULL, NULL);
	Esys_FlushContext(state->esys, session);
	session = ESYS_TR_NONE;
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error creating the attestation key", rc);
		goto done;
	}
	rc = ek_session(state, &session);
	if (rc == TSS2_RC_SUCCESS) {
		rc = Esys_Load(state->esys, state->ek, session, ESYS_TR_NONE,
			       ESYS_TR_NONE, created, public, &state->ak);
		Esys_FlushContext(state->esys, session);
	}
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error loading the attestation key", rc);
		goto done;
	}
	state->ak_public = *public;
	priv_buf = talloc_size(state->ctx, sizeof(*created));
	offset = 0;
	if ((marshal_public(state->ctx, public, &pub_buf, &pub_length) != 0) ||
	    (Tss2_MU_TPM2B_PRIVATE_Marshal(created, priv_buf,
					   sizeof(*created), &offset) !=
	     TSS2_RC_SUCCESS)) {
		state->error = "error encoding the attestation key";
		goto done;
	}
	priv_length = offset;
	/* A new AK needs a new certificate. */
	unlink(state_path(state, AK_CERTIFICATE_FILE));
	if ((write_file(state->ctx, state_path(state, AK_PRIVATE_FILE),
			priv_buf, priv_length) != 0) ||
	    (write_file(state->ctx, state_path(state, AK_PUBLIC_FILE),
			pub_buf, pub_length) != 0)) {
		state->error = "error saving the attestation key";
		goto done;
	}
	ret = 0;
done:
	Esys_Free(created);
	Esys_Free(public);
	return ret;
}

/* The AK's certificate and chain, if we have one which will do for a
 * while. */
static int
read_ak_cert(struct tpm_state *state)
{
	BIO *in;
	X509 *cert;
	char *path;
	time_t limit;

	path = state_path(state, AK_CERTIFICATE_FILE);
	in = BIO_new_file(path, "r");
	if (in == NULL) {
		return -1;
	}
	state->ak_cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
	state->ak_chain = sk_X509_new_null();
	while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
		sk_X509_push(state->ak_chain, cert);
	}
	BIO_free(in);
	if (state->ak_cert == NULL) {
		return -1;
	}
	limit = time(NULL) + AK_RENEWAL_MARGIN;
	if ((X509_cmp_time(X509_get0_notAfter(state->ak_cert), &limit) < 0) ||
	    !public_matches(&state->ak_public, state->ak_cert)) {
		X509_free(state->ak_cert);
		state->ak_cert = NULL;
		sk_X509_pop_free(state->ak_chain, X509_free);
		state->ak_chain = NULL;
		return -1;
	}
	return 0;
}

static X509 *
x509_from_b64(void *parent, const char *b64)
{
	unsigned char *der;
	const unsigned char *p;
	size_t length;

	der = cm_acme_b64_decode(parent, b64, &length);
	if (der == NULL) {
		return NULL;
	}
	p = der;
	return d2i_X509(NULL, &p, length);
}

static void
append_cert(struct tpm_state *state, json_t *chain, X509 *cert)
{
	unsigned char *der = NULL;
	int der_length;

	der_length = i2d_X509(cert, &der);
	if (der_length > 0) {
		json_array_append_new(chain,
				      json_string(cm_acme_b64_encode(state->ctx,
								     der,
								     der_length)));
	}
	OPENSSL_free(der);
}

/* The certificates of the CAs which issued the EK certificate which the TPM
 * keeps, each index holding one or more DER-encoded certificates. */
static void
ek_chain_from_nv(struct tpm_state *state, json_t *chain)
{
	TPMS_CAPABILITY_DATA *data = NULL;
	TPMI_YES_NO more = TPM2_NO;
	const unsigned char *p, *end;
	unsigned char *buf;
	size_t length;
	UINT32 i;
	X509 *cert;

	if (Esys_GetCapability(state->esys, ESYS_TR_NONE, ESYS_TR_NONE,
			       ESYS_TR_NONE, TPM2_CAP_HANDLES,
			       EK_CHAIN_NV_FIRST,
			       EK_CHAIN_NV_LAST - EK_CHAIN_NV_FIRST + 1,
			       &more, &data) != TSS2_RC_SUCCESS) {
		return;
	}
	for (i = 0; i < data->data.handles.count; i++) {
		if (data->data.handles.handle[i] > EK_CHAIN_NV_LAST) {
			break;
		}
		buf = read_nv(state, data->data.handles.handle[i], 0, &length);
		p = buf;
		end = buf + length;
		while ((p != NULL) && (p < end) && (*p == 0x30) &&
		       ((cert = d2i_X509(NULL, &p, end - p)) != NULL)) {
			append_cert(state, chain, cert);
			X509_free(cert);
		}
	}
	Esys_Free(data);
}

/* The EK certificate's chain: what the TPM keeps of it, or else what its
 * authorityInfoAccess caIssuers pointers lead to, for the server's
 * benefit. */
static json_t *
ek_chain(struct tpm_state *state)
{
	struct cm_acme_response response;
	AUTHORITY_INFO_ACCESS *aia;
	ACCESS_DESCRIPTION *ad;
	const unsigned char *p;
	const char *uri;
	json_t *chain;
	X509 *cert, *next;
	BIO *in;
	int i, n;

	chain = json_array();
	ek_chain_from_nv(state, chain);
	if (json_array_size(chain) > 0) {
		return chain;
	}
	p = state->ek_cert;
	cert = d2i_X509(NULL, &p, state->ek_cert_length);
	for (n = 0; (cert != NULL) && (n < EK_CHAIN_MAX); n++) {
		if (X509_check_issued(cert, cert) == X509_V_OK) {
			break;
		}
		aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
		uri = NULL;
		for (i = 0; (aia != NULL) &&
			    (i < sk_ACCESS_DESCRIPTION_num(aia)); i++) {
			ad = sk_ACCESS_DESCRIPTION_value(aia, i);
			if ((OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) &&
			    (ad->location->type == GEN_URI)) {
				uri = (const char *) ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
				break;
			}
		}
		next = NULL;
		if ((uri != NULL) &&
		    ((strncasecmp(uri, "http://", 7) == 0) ||
		     (strncasecmp(uri, "https://", 8) == 0)) &&
		    (state->params->get(state->ctx, state->params->http_data,
					uri, &response) == 0) &&
		    (response.response_code == 200) &&
		    (response.body != NULL)) {
			p = (const unsigned char *) response.body;
			next = d2i_X509(NULL, &p, response.length);
			if (next == NULL) {
				in = BIO_new_mem_buf(response.body,
						     response.length);
				next = PEM_read_bio_X509(in, NULL, NULL, NULL);
				BIO_free(in);
			}
		}
		AUTHORITY_INFO_ACCESS_free(aia);
		X509_free(cert);
		cert = next;
		if (cert != NULL) {
			append_cert(state, chain, cert);
		}
	}
	X509_free(cert);
	return chain;
}

static int
service_post(struct tpm_state *state, const char *op, json_t *request,
	     json_t **reply)
{
	struct cm_acme_response response;
	json_error_t jerror;
	json_t *problem;
	const char *detail;
	char *body, *url;
	int ret;

	*reply = NULL;
	url = talloc_asprintf(state->ctx, "%s/attest/v1/ak/%s",
			      state->params->service_url, op);
	body = json_dumps(request, JSON_COMPACT);
	if (body == NULL) {
		state->error = "out of memory";
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	ret = state->params->post_json(state->ctx, state->params->http_data,
				       url, body, &response);
	free(body);
	if (ret != 0) {
		state->error = talloc_asprintf(state->ctx,
					       "error connecting to %s: %s",
					       url, response.error_text ?
					       response.error_text : "");
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (response.response_code != 200) {
		problem = json_loadb(response.body ? response.body : "",
				     response.length, 0, &jerror);
		detail = json_string_value(json_object_get(problem, "detail"));
		state->error = talloc_asprintf(state->ctx,
					       "the attestation key "
					       "certification service refused "
					       "the %s request (%ld)%s%s", op,
					       response.response_code,
					       detail ? ": " : "",
					       detail ? detail : "");
		json_decref(problem);
		return (response.response_code >= 500) ?
		       CM_SUBMIT_STATUS_UNREACHABLE :
		       CM_SUBMIT_STATUS_REJECTED;
	}
	*reply = json_loadb(response.body, response.length, 0, &jerror);
	if (!json_is_object(*reply)) {
		state->error = "error parsing the attestation key "
			       "certification service's reply";
		json_decref(*reply);
		*reply = NULL;
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	return 0;
}

static const char *
reply_str(json_t *reply, const char *key)
{
	return json_string_value(json_object_get(reply, key));
}

/* Have the server certify the AK (contract section 2): it sends us an HMAC
 * key encrypted to our EK, which we import and use to certify the AK. */
static int
certify_ak(struct tpm_state *state)
{
	struct cm_acme_tpm_params *params = state->params;
	json_t *request, *reply = NULL, *chain;
	unsigned char *ak_buf, mac[SHA256_DIGEST_LENGTH], *sig_buf;
	unsigned char *import_pub_buf, *dup_buf, *seed_buf, *nonce_buf;
	size_t ak_length, length, offset, i;
	TPM2B_PUBLIC import_public;
	TPM2B_PRIVATE duplicate, *imported = NULL;
	TPM2B_ENCRYPTED_SECRET seed;
	TPM2B_DATA encryption_key, qualifying;
	TPMT_SYM_DEF_OBJECT symmetric;
	TPMT_SIG_SCHEME scheme;
	TPM2B_ATTEST *certify_info = NULL;
	TPMT_SIGNATURE *signature = NULL;
	ESYS_TR session = ESYS_TR_NONE, hmac = ESYS_TR_NONE;
	BIO *out = NULL;
	X509 *cert;
	char *pem, *session_id;
	long pem_length;
	TSS2_RC rc;
	const unsigned char *eab_key;
	size_t eab_key_length;
	int ret = CM_SUBMIT_STATUS_UNCONFIGURED;

	if ((params->eab_kid == NULL) || (params->eab_key == NULL) ||
	    (params->eab_key(params->eab_data, &eab_key,
			     &eab_key_length) != 0)) {
		state->error = "certifying the attestation key needs the "
			       "external account binding credentials";
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (marshal_public(state->ctx, &state->ak_public, &ak_buf,
			   &ak_length) != 0) {
		state->error = "error encoding the attestation key";
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	if (cm_acme_hmac_sha256(eab_key, eab_key_length,
				ak_buf, ak_length, mac) != 0) {
		state->error = "error computing the proof of the external "
			       "account binding";
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	request = json_pack("{s:s,s:o,s:s,s:s,s:s}",
			    "ek_certificate",
			    cm_acme_b64_encode(state->ctx, state->ek_cert,
					       state->ek_cert_length),
			    "ek_chain", ek_chain(state),
			    "ak_public",
			    cm_acme_b64_encode(state->ctx, ak_buf, ak_length),
			    "eab_kid", params->eab_kid,
			    "eab_proof",
			    cm_acme_b64_encode(state->ctx, mac, sizeof(mac)));
	memset(mac, 0, sizeof(mac));
	if (params->verbose > 0) {
		fprintf(stderr, "Requesting certification of the attestation "
			"key.\n");
	}
	ret = service_post(state, "begin", request, &reply);
	json_decref(request);
	if (ret != 0) {
		return ret;
	}
	ret = CM_SUBMIT_STATUS_UNREACHABLE;
	session_id = talloc_strdup(state->ctx, reply_str(reply, "session"));
	import_pub_buf = cm_acme_b64_decode(state->ctx,
					    reply_str(reply, "import_public"),
					    &length);
	memset(&import_public, 0, sizeof(import_public));
	offset = 0;
	if ((session_id == NULL) || (import_pub_buf == NULL) ||
	    (Tss2_MU_TPM2B_PUBLIC_Unmarshal(import_pub_buf, length, &offset,
					    &import_public) !=
	     TSS2_RC_SUCCESS)) {
		state->error = "malformed import_public in the reply";
		goto done;
	}
	dup_buf = cm_acme_b64_decode(state->ctx,
				     reply_str(reply, "import_duplicate"),
				     &length);
	memset(&duplicate, 0, sizeof(duplicate));
	offset = 0;
	if ((dup_buf == NULL) ||
	    (Tss2_MU_TPM2B_PRIVATE_Unmarshal(dup_buf, length, &offset,
					     &duplicate) != TSS2_RC_SUCCESS)) {
		state->error = "malformed import_duplicate in the reply";
		goto done;
	}
	seed_buf = cm_acme_b64_decode(state->ctx,
				      reply_str(reply, "import_seed"),
				      &length);
	memset(&seed, 0, sizeof(seed));
	offset = 0;
	if ((seed_buf == NULL) ||
	    (Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(seed_buf, length,
						      &offset, &seed) !=
	     TSS2_RC_SUCCESS)) {
		state->error = "malformed import_seed in the reply";
		goto done;
	}
	nonce_buf = cm_acme_b64_decode(state->ctx, reply_str(reply, "nonce"),
				       &length);
	memset(&qualifying, 0, sizeof(qualifying));
	if ((nonce_buf == NULL) || (length == 0) ||
	    (length > sizeof(qualifying.buffer))) {
		state->error = "malformed nonce in the reply";
		goto done;
	}
	qualifying.size = length;
	memcpy(qualifying.buffer, nonce_buf, length);

	/* Import the HMAC key under the EK: it is wrapped with an outer
	 * wrapper only. */
	ret = CM_SUBMIT_STATUS_REJECTED;
	memset(&encryption_key, 0, sizeof(encryption_key));
	memset(&symmetric, 0, sizeof(symmetric));
	symmetric.algorithm = TPM2_ALG_NULL;
	rc = ek_session(state, &session);
	if (rc == TSS2_RC_SUCCESS) {
		rc = Esys_Import(state->esys, state->ek, session,
				 ESYS_TR_NONE, ESYS_TR_NONE, &encryption_key,
				 &import_public, &duplicate, &seed,
				 &symmetric, &imported);
		Esys_FlushContext(state->esys, session);
		session = ESYS_TR_NONE;
	}
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error importing the server's key", rc);
		goto done;
	}
	rc = ek_session(state, &session);
	if (rc == TSS2_RC_SUCCESS) {
		rc = Esys_Load(state->esys, state->ek, session, ESYS_TR_NONE,
			       ESYS_TR_NONE, imported, &import_public, &hmac);
		Esys_FlushContext(state->esys, session);
		session = ESYS_TR_NONE;
	}
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error loading the server's key", rc);
		goto done;
	}

	/* Certify the AK with it. */
	memset(&scheme, 0, sizeof(scheme));
	scheme.scheme = TPM2_ALG_NULL;
	rc = Esys_Certify(state->esys, state->ak, hmac, ESYS_TR_PASSWORD,
			  ESYS_TR_PASSWORD, ESYS_TR_NONE, &qualifying, &scheme,
			  &certify_info, &signature);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error certifying the attestation key", rc);
		goto done;
	}
	sig_buf = talloc_size(state->ctx, sizeof(*signature));
	offset = 0;
	if (Tss2_MU_TPMT_SIGNATURE_Marshal(signature, sig_buf,
					   sizeof(*signature), &offset) !=
	    TSS2_RC_SUCCESS) {
		state->error = "error encoding the certification";
		goto done;
	}
	request = json_pack("{s:s,s:s,s:s}",
			    "session", session_id,
			    "certify_info",
			    cm_acme_b64_encode(state->ctx,
					       certify_info->attestationData,
					       certify_info->size),
			    "certify_signature",
			    cm_acme_b64_encode(state->ctx, sig_buf, offset));
	json_decref(reply);
	reply = NULL;
	ret = service_post(state, "finish", request, &reply);
	json_decref(request);
	if (ret != 0) {
		goto done;
	}
	ret = CM_SUBMIT_STATUS_UNREACHABLE;
	cert = x509_from_b64(state->ctx, reply_str(reply, "ak_certificate"));
	if ((cert == NULL) || !public_matches(&state->ak_public, cert)) {
		X509_free(cert);
		state->error = "the server did not return a certificate for "
			       "the attestation key";
		goto done;
	}
	state->ak_cert = cert;
	state->ak_chain = sk_X509_new_null();
	chain = json_object_get(reply, "chain");
	for (i = 0; i < json_array_size(chain); i++) {
		cert = x509_from_b64(state->ctx,
				     json_string_value(json_array_get(chain, i)));
		if (cert != NULL) {
			sk_X509_push(state->ak_chain, cert);
		}
	}

	/* Keep it. */
	out = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(out, state->ak_cert);
	for (i = 0; i < (size_t) sk_X509_num(state->ak_chain); i++) {
		PEM_write_bio_X509(out, sk_X509_value(state->ak_chain, i));
	}
	pem_length = BIO_get_mem_data(out, &pem);
	if (write_file(state->ctx, state_path(state, AK_CERTIFICATE_FILE),
		       pem, pem_length) != 0) {
		state->error = "error saving the attestation key's "
			       "certificate";
		ret = CM_SUBMIT_STATUS_UNCONFIGURED;
		goto done;
	}
	if (params->verbose > 0) {
		fprintf(stderr, "Attestation key certified.\n");
	}
	ret = 0;
done:
	BIO_free(out);
	if (hmac != ESYS_TR_NONE) {
		Esys_FlushContext(state->esys, hmac);
	}
	Esys_Free(imported);
	Esys_Free(certify_info);
	Esys_Free(signature);
	json_decref(reply);
	return ret;
}

/* Certify the device key with the AK, through the module which holds the
 * device key. */
static int
certify_device_key(struct tpm_state *state, const unsigned char *qualifying,
		   size_t qualifying_length, TPM2B_PUBLIC *device_public,
		   TPM2B_ATTEST *certify_info, TPMT_SIGNATURE *signature)
{
	struct cm_acme_tpm_params *params = state->params;
	TPMS_CONTEXT *context = NULL;
	unsigned char *context_buf;
	size_t context_length = 0;
	TSS2_RC rc;

	/* The module loads the AK in its own connection to the TPM. */
	rc = Esys_ContextSave(state->esys, state->ak, &context);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(state, "error saving the attestation key's context",
			  rc);
		return -1;
	}
	context_buf = talloc_size(state->ctx, sizeof(*context));
	if ((context_buf == NULL) ||
	    (Tss2_MU_TPMS_CONTEXT_Marshal(context, context_buf,
					  sizeof(*context),
					  &context_length) !=
	     TSS2_RC_SUCCESS)) {
		Esys_Free(context);
		state->error = "error encoding the attestation key's context";
		return -1;
	}
	Esys_Free(context);
	if (cm_acme_tpm_p11_certify(state->ctx, params->key_location,
				    params->key_token, params->key_pin,
				    params->csr, context_buf, context_length,
				    qualifying, qualifying_length,
				    device_public, certify_info, signature,
				    &state->error) != 0) {
		return -1;
	}
	return 0;
}

/* Certify the device key with the AK, binding the statement to the key
 * authorization, and build the attestation object. */
static int
attest_device_key(struct tpm_state *state, const char *key_authorization,
		  unsigned char **att_obj, size_t *att_obj_length)
{
	unsigned char qualifying[SHA256_DIGEST_LENGTH];
	TPM2B_PUBLIC device_public;
	TPM2B_ATTEST certify_info;
	TPMT_SIGNATURE signature;
	unsigned char *sig_buf, *pub_buf, *der;
	size_t sig_length = 0, pub_length = 0;
	struct cbor c;
	int i, n, der_length;

	/* The key authorization is attToBeSigned, and the TPM signs its
	 * digest, with the hash algorithm of the AK's signature algorithm,
	 * as extraData (draft-ietf-acme-device-attest 5, WebAuthn 8.3).  Both
	 * kinds of AK which we create use SHA-256. */
	SHA256((const unsigned char *) key_authorization,
	       strlen(key_authorization), qualifying);
	if (certify_device_key(state, qualifying, sizeof(qualifying),
			       &device_public, &certify_info,
			       &signature) != 0) {
		return -1;
	}

	/* sig is the TPMT_SIGNATURE which the TPM returned, and pubArea a
	 * TPMT_PUBLIC (WebAuthn 8.3). */
	sig_buf = talloc_size(state->ctx, sizeof(signature));
	pub_buf = talloc_size(state->ctx, sizeof(device_public.publicArea));
	if ((sig_buf == NULL) || (pub_buf == NULL) ||
	    (Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, sig_buf,
					    sizeof(signature),
					    &sig_length) != TSS2_RC_SUCCESS) ||
	    (Tss2_MU_TPMT_PUBLIC_Marshal(&device_public.publicArea, pub_buf,
					 sizeof(device_public.publicArea),
					 &pub_length) != TSS2_RC_SUCCESS)) {
		state->error = "error encoding the attestation";
		return -1;
	}

	/* The attestation object, without authData, which has no meaning
	 * here (draft-ietf-acme-device-attest 5). */
	memset(&c, 0, sizeof(c));
	c.ctx = state->ctx;
	cbor_map(&c, 2);
	cbor_text(&c, "fmt");
	cbor_text(&c, "tpm");
	cbor_text(&c, "attStmt");
	cbor_map(&c, 6);
	cbor_text(&c, "ver");
	cbor_text(&c, "2.0");
	cbor_text(&c, "alg");
	cbor_int(&c, (state->ak_public.publicArea.type == TPM2_ALG_RSA) ?
		     COSE_RS256 : COSE_ES256);
	cbor_text(&c, "x5c");
	n = sk_X509_num(state->ak_chain);
	cbor_array(&c, 1 + n);
	for (i = -1; i < n; i++) {
		der = NULL;
		der_length = i2d_X509((i < 0) ? state->ak_cert :
				      sk_X509_value(state->ak_chain, i),
				      &der);
		if (der_length <= 0) {
			c.failed = 1;
			break;
		}
		cbor_bytes(&c, der, der_length);
		OPENSSL_free(der);
	}
	cbor_text(&c, "sig");
	cbor_bytes(&c, sig_buf, sig_length);
	cbor_text(&c, "certInfo");
	cbor_bytes(&c, certify_info.attestationData, certify_info.size);
	cbor_text(&c, "pubArea");
	cbor_bytes(&c, pub_buf, pub_length);
	if (c.failed) {
		state->error = "error encoding the attestation object";
		return -1;
	}
	*att_obj = c.buf;
	*att_obj_length = c.length;
	return 0;
}

static const char *
default_tcti(const char *tcti)
{
	const char *p;

	if ((tcti != NULL) && (strlen(tcti) > 0)) {
		return tcti;
	}
	/* The TPM which tpm2-pkcs11 uses holds the key. */
	p = getenv("TPM2_PKCS11_TCTI");
	if ((p != NULL) && (strlen(p) > 0)) {
		return p;
	}
	p = getenv("TPM2TOOLS_TCTI");
	if ((p != NULL) && (strlen(p) > 0)) {
		return p;
	}
	return NULL;
}

int
cm_acme_tpm_attest(void *parent, struct cm_acme_tpm_params *params,
		   const char *key_authorization,
		   unsigned char **att_obj, size_t *att_obj_length,
		   const char **error)
{
	struct tpm_state state;
	TSS2_RC rc;
	int ret = CM_SUBMIT_STATUS_UNCONFIGURED;

	*error = NULL;
	memset(&state, 0, sizeof(state));
	state.ctx = talloc_new(parent);
	state.params = params;
	state.ek = ESYS_TR_NONE;
	state.ak = ESYS_TR_NONE;

	if ((params->key_storage_type == NULL) ||
	    (strcasecmp(params->key_storage_type, "NSSDB") != 0) ||
	    (params->key_location == NULL) || (params->key_token == NULL)) {
		*error = "TPM attestation needs a key in a TPM token which is "
			 "accessible through an NSS database";
		goto done;
	}
	rc = Tss2_TctiLdr_Initialize(default_tcti(params->tcti), &state.tcti);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(&state, "error connecting to the TPM", rc);
		goto done;
	}
	rc = Esys_Initialize(&state.esys, state.tcti, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		set_error(&state, "error initializing the TSS", rc);
		goto done;
	}
	if ((setup_ek(&state) != 0) || (setup_ak(&state) != 0)) {
		goto done;
	}
	if (read_ak_cert(&state) != 0) {
		ret = certify_ak(&state);
		if (ret != 0) {
			goto done;
		}
		ret = CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	/* The EK is no longer needed. */
	Esys_FlushContext(state.esys, state.ek);
	state.ek = ESYS_TR_NONE;
	if (attest_device_key(&state, key_authorization, att_obj,
			      att_obj_length) != 0) {
		goto done;
	}
	talloc_steal(parent, *att_obj);
	ret = 0;
done:
	if (ret != 0) {
		*error = talloc_strdup(parent, state.error ? state.error :
				       *error);
	}
	if (state.esys != NULL) {
		if (state.ak != ESYS_TR_NONE) {
			Esys_FlushContext(state.esys, state.ak);
		}
		if (state.ek != ESYS_TR_NONE) {
			Esys_FlushContext(state.esys, state.ek);
		}
		Esys_Finalize(&state.esys);
	}
	if (state.tcti != NULL) {
		Tss2_TctiLdr_Finalize(&state.tcti);
	}
	X509_free(state.ak_cert);
	sk_X509_pop_free(state.ak_chain, X509_free);
	talloc_free(state.ctx);
	return ret;
}
