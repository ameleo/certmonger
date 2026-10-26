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

/* Getting a TPM handle on a key which the daemon generated in a TPM
 * through the tpm2-pkcs11 PKCS#11 module, so that another key of the TPM
 * can certify it, for modules which lack the CKM_TPM2_CERTIFY mechanism
 * (see acme-tpm-p11.c).
 *
 * TPM2_Certify needs the
 * authorization value of the key which is certified.  tpm2-pkcs11 gives
 * each key a random authorization value, which it keeps encrypted with a
 * token-wide wrapping key, which is itself sealed in the TPM and unsealed
 * using the user PIN.  We read the key's TPM blobs and its encrypted
 * authorization value through PKCS#11 (tpm2-pkcs11 exposes them as vendor
 * attributes of the object), and the parent object and sealed wrapping key
 * of the token from the module's store, then do what the module does when
 * the user logs in: unseal the wrapping key with the PIN, decrypt the key's
 * authorization value, and load the key under its parent.
 *
 * This ties us to the module's store format (its schema version 7, used
 * since tpm2-pkcs11 1.3) for the token-wide data.  The alternative, having
 * the helper generate the key itself and add it to the token, would tie us
 * to the same format for writing, and would take key generation away from
 * the daemon. */

#include "config.h"

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nss.h>
#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secmod.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <sqlite3.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

#include <talloc.h>

#include "acme-tpm.h"

/* tpm2-pkcs11's vendor attributes (src/lib/attrs.h there). */
#define CKA_VENDOR_TPM2_DEFINED 0x0F000000UL
#define CKA_TPM2_OBJAUTH_ENC (CKA_VENDOR_DEFINED | CKA_VENDOR_TPM2_DEFINED | 0x1UL)
#define CKA_TPM2_PUB_BLOB (CKA_VENDOR_DEFINED | CKA_VENDOR_TPM2_DEFINED | 0x2UL)
#define CKA_TPM2_PRIV_BLOB (CKA_VENDOR_DEFINED | CKA_VENDOR_TPM2_DEFINED | 0x3UL)

#define TPM2_PKCS11_DB "tpm2_pkcs11.sqlite3"
#define TPM2_PKCS11_SYSTEM_STORE "/etc/tpm2_pkcs11"

/* What we take from the PKCS#11 object. */
struct p11_object {
	SECItem *pub, *priv, *auth_enc;
};

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

/* Find the private key for the request's public key in the token, and
 * read its TPM blobs. */
static int
read_p11_object(void *parent, const char *dbdir, const char *token,
		const char *pin, const char *csr, struct p11_object *object,
		char **token_label, const char **error)
{
	NSSInitContext *nctx;
	PK11SlotInfo *slot = NULL;
	SECKEYPublicKey *pub = NULL;
	SECKEYPrivateKey *key = NULL;
	SECItem *id = NULL;
	int ret = -1;

	memset(object, 0, sizeof(*object));
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
	if (PK11_NeedLogin(slot) &&
	    (PK11_Authenticate(slot, PR_TRUE, (void *) pin) != SECSuccess)) {
		*error = nss_error(parent, "error logging in to the token");
		goto done;
	}
	pub = request_public_key(csr);
	if (pub == NULL) {
		*error = "error reading the public key of the request";
		goto done;
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
	}
	if (key == NULL) {
		*error = "the key of the request is not in the token";
		goto done;
	}
	object->pub = SECITEM_AllocItem(NULL, NULL, 0);
	object->priv = SECITEM_AllocItem(NULL, NULL, 0);
	object->auth_enc = SECITEM_AllocItem(NULL, NULL, 0);
	if ((PK11_ReadRawAttribute(PK11_TypePrivKey, key, CKA_TPM2_PUB_BLOB,
				   object->pub) != SECSuccess) ||
	    (PK11_ReadRawAttribute(PK11_TypePrivKey, key, CKA_TPM2_PRIV_BLOB,
				   object->priv) != SECSuccess) ||
	    (PK11_ReadRawAttribute(PK11_TypePrivKey, key, CKA_TPM2_OBJAUTH_ENC,
				   object->auth_enc) != SECSuccess) ||
	    (object->pub->len == 0) || (object->priv->len == 0)) {
		*error = "the key is not a TPM key of the tpm2-pkcs11 module";
		goto done;
	}
	*token_label = talloc_strdup(parent, PK11_GetTokenName(slot));
	ret = 0;
done:
	if (id != NULL) {
		SECITEM_FreeItem(id, PR_TRUE);
	}
	if (key != NULL) {
		SECKEY_DestroyPrivateKey(key);
	}
	if (pub != NULL) {
		SECKEY_DestroyPublicKey(pub);
	}
	if (slot != NULL) {
		PK11_FreeSlot(slot);
	}
	NSS_ShutdownContext(nctx);
	return ret;
}

static void
free_p11_object(struct p11_object *object)
{
	if (object->pub != NULL) {
		SECITEM_FreeItem(object->pub, PR_TRUE);
	}
	if (object->priv != NULL) {
		SECITEM_FreeItem(object->priv, PR_TRUE);
	}
	if (object->auth_enc != NULL) {
		SECITEM_ZfreeItem(object->auth_enc, PR_TRUE);
	}
}

/* What we take from the module's store about the token. */
struct p11_token {
	char *pobject_config;		/* YAML */
	char *pobject_auth;
	unsigned char *seal_pub, *seal_priv;
	int seal_pub_len, seal_priv_len;
	char *seal_salt;
};

static int
read_token(void *parent, const char *db, const char *label,
	   struct p11_token *tok)
{
	sqlite3 *sql = NULL;
	sqlite3_stmt *stmt = NULL;
	sqlite3_int64 tokid = -1;
	int ret = -1;

	memset(tok, 0, sizeof(*tok));
	if (sqlite3_open_v2(db, &sql, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK) {
		goto done;
	}
	if (sqlite3_prepare_v2(sql,
			       "SELECT tokens.id, pobjects.config, "
			       "pobjects.objauth FROM tokens JOIN pobjects "
			       "ON tokens.pid = pobjects.id "
			       "WHERE tokens.label = ?",
			       -1, &stmt, NULL) != SQLITE_OK) {
		goto done;
	}
	sqlite3_bind_text(stmt, 1, label, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		goto done;
	}
	tokid = sqlite3_column_int64(stmt, 0);
	tok->pobject_config = talloc_strdup(parent,
					    (const char *) sqlite3_column_text(stmt, 1));
	tok->pobject_auth = talloc_strdup(parent,
					  sqlite3_column_text(stmt, 2) ?
					  (const char *) sqlite3_column_text(stmt, 2) :
					  "");
	sqlite3_finalize(stmt);
	stmt = NULL;
	if (sqlite3_prepare_v2(sql,
			       "SELECT userpub, userpriv, userauthsalt "
			       "FROM sealobjects WHERE tokid = ?",
			       -1, &stmt, NULL) != SQLITE_OK) {
		goto done;
	}
	sqlite3_bind_int64(stmt, 1, tokid);
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		goto done;
	}
	tok->seal_pub_len = sqlite3_column_bytes(stmt, 0);
	tok->seal_pub = talloc_memdup(parent, sqlite3_column_blob(stmt, 0),
				      tok->seal_pub_len);
	tok->seal_priv_len = sqlite3_column_bytes(stmt, 1);
	tok->seal_priv = talloc_memdup(parent, sqlite3_column_blob(stmt, 1),
				       tok->seal_priv_len);
	tok->seal_salt = talloc_strdup(parent,
				       (const char *) sqlite3_column_text(stmt, 2));
	if ((tok->pobject_config != NULL) && (tok->seal_pub_len > 0) &&
	    (tok->seal_priv_len > 0) && (tok->seal_salt != NULL)) {
		ret = 0;
	}
done:
	sqlite3_finalize(stmt);
	sqlite3_close(sql);
	return ret;
}

/* Look for the token in the places where the module looks for its
 * store. */
static int
find_token(void *parent, const char *label, struct p11_token *tok,
	   char **where)
{
	const char *dirs[5];
	const char *env;
	char *db;
	int i, n = 0;

	env = getenv("TPM2_PKCS11_STORE");
	if ((env != NULL) && (strlen(env) > 0)) {
		dirs[n++] = env;
	}
	dirs[n++] = TPM2_PKCS11_SYSTEM_STORE;
	env = getenv("XDG_DATA_HOME");
	if ((env != NULL) && (strlen(env) > 0)) {
		dirs[n++] = talloc_asprintf(parent, "%s/tpm2-pkcs11", env);
	}
	env = getenv("HOME");
	if ((env != NULL) && (strlen(env) > 0)) {
		dirs[n++] = talloc_asprintf(parent,
					    "%s/.local/share/tpm2-pkcs11",
					    env);
		dirs[n++] = talloc_asprintf(parent, "%s/.tpm2_pkcs11", env);
	}
	for (i = 0; i < n; i++) {
		db = talloc_asprintf(parent, "%s/%s", dirs[i],
				     TPM2_PKCS11_DB);
		if ((access(db, R_OK) == 0) &&
		    (read_token(parent, db, label, tok) == 0)) {
			*where = db;
			return 0;
		}
	}
	return -1;
}

/* Find a value in the module's YAML description of the parent object, which
 * it writes in either the plain or the tagged style. */
static char *
yaml_value(void *parent, const char *yaml, const char *key)
{
	const char *p, *q;
	size_t len = strlen(key);

	for (p = strstr(yaml, key); p != NULL; p = strstr(p + 1, key)) {
		q = p + len;
		if ((p > yaml) && (p[-1] == '"') && (*q == '"')) {
			q++;
		} else
		if ((p > yaml) && (strchr(" \t\n{", p[-1]) == NULL)) {
			continue;
		}
		q += strspn(q, " \t\r\n");
		if (*q != ':') {
			continue;
		}
		q++;
		q += strspn(q, " \t\r\n");
		if (strncmp(q, "!!str", 5) == 0) {
			q += 5;
		} else
		if (strncmp(q, "!!bool", 6) == 0) {
			q += 6;
		}
		q += strspn(q, " \t\r\n");
		if (*q == '"') {
			q++;
			return talloc_strndup(parent, q, strcspn(q, "\""));
		}
		return talloc_strndup(parent, q, strcspn(q, ",} \t\r\n"));
	}
	return NULL;
}

static unsigned char *
unhex(void *parent, const char *hex, size_t *length)
{
	unsigned char *ret;
	size_t i, n;
	unsigned int v;

	n = strlen(hex);
	if (n % 2) {
		return NULL;
	}
	ret = talloc_size(parent, n / 2 + 1);
	for (i = 0; i < n / 2; i++) {
		if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
			return NULL;
		}
		ret[i] = v;
	}
	*length = n / 2;
	return ret;
}

/* The authorization value of the sealed wrapping key: the first half of
 * the SHA-256 digest of the PIN and the salt, in hex. */
static int
seal_auth(const char *pin, const char *salt, TPM2B_AUTH *auth)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;
	EVP_MD_CTX *mctx;
	int i, ret = -1;

	memset(auth, 0, sizeof(*auth));
	mctx = EVP_MD_CTX_new();
	if ((mctx != NULL) &&
	    (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) == 1) &&
	    (EVP_DigestUpdate(mctx, pin, strlen(pin)) == 1) &&
	    (EVP_DigestUpdate(mctx, salt, strlen(salt)) == 1) &&
	    (EVP_DigestFinal_ex(mctx, md, &md_len) == 1) &&
	    (md_len == SHA256_DIGEST_LENGTH)) {
		for (i = 0; i < SHA256_DIGEST_LENGTH / 2; i++) {
			snprintf((char *) auth->buffer + 2 * i, 3, "%02x",
				 md[i]);
		}
		auth->size = SHA256_DIGEST_LENGTH;
		ret = 0;
	}
	EVP_MD_CTX_free(mctx);
	memset(md, 0, sizeof(md));
	return ret;
}

/* Decrypt "IV:TAG:CIPHERTEXT" (hex) with AES-256-GCM. */
static int
unwrap_auth(void *parent, const unsigned char *key, size_t key_length,
	    const unsigned char *wrapped, size_t wrapped_length,
	    TPM2B_AUTH *auth)
{
	char *copy, *tag, *ctext;
	unsigned char *iv, *tagb, *ctextb;
	size_t iv_len, tag_len, ctext_len;
	EVP_CIPHER_CTX *cctx;
	int len = 0, fin = 0, ret = -1;

	copy = talloc_strndup(parent, (const char *) wrapped, wrapped_length);
	tag = copy ? strchr(copy, ':') : NULL;
	if (tag == NULL) {
		return -1;
	}
	*tag++ = '\0';
	ctext = strchr(tag, ':');
	if (ctext == NULL) {
		return -1;
	}
	*ctext++ = '\0';
	iv = unhex(parent, copy, &iv_len);
	tagb = unhex(parent, tag, &tag_len);
	ctextb = unhex(parent, ctext, &ctext_len);
	if ((iv == NULL) || (iv_len != 12) || (tagb == NULL) ||
	    (tag_len != 16) || (ctextb == NULL) ||
	    (ctext_len > sizeof(auth->buffer)) || (key_length != 32)) {
		return -1;
	}
	memset(auth, 0, sizeof(*auth));
	cctx = EVP_CIPHER_CTX_new();
	if ((cctx != NULL) &&
	    (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, key, iv) == 1) &&
	    (EVP_DecryptUpdate(cctx, auth->buffer, &len, ctextb,
			       ctext_len) == 1) &&
	    (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, 16,
				 tagb) == 1) &&
	    (EVP_DecryptFinal_ex(cctx, auth->buffer + len, &fin) == 1)) {
		auth->size = len + fin;
		ret = 0;
	}
	EVP_CIPHER_CTX_free(cctx);
	memset(ctextb, 0, ctext_len);
	return ret;
}

int
cm_acme_tpm_p11_load(void *parent, ESYS_CONTEXT *esys,
		     const char *dbdir, const char *token, const char *pin,
		     const char *csr, ESYS_TR *key, TPM2B_PUBLIC *public,
		     const char **error)
{
	struct p11_object object;
	struct p11_token tok;
	char *label = NULL, *where, *value;
	unsigned char *buf;
	size_t length, offset;
	ESYS_TR parent_tr = ESYS_TR_NONE, seal = ESYS_TR_NONE;
	ESYS_TR session = ESYS_TR_NONE, loaded = ESYS_TR_NONE;
	TPM2B_PUBLIC seal_public, key_public;
	TPM2B_PRIVATE seal_private, key_private;
	TPM2B_SENSITIVE_DATA *wrapping = NULL;
	TPM2B_AUTH auth;
	unsigned char *wrapping_key;
	size_t wrapping_key_length;
	TSS2_RC rc;
	int ret = -1;

	*key = ESYS_TR_NONE;
	if ((token == NULL) || (strlen(token) == 0)) {
		*error = "the key is not in a token";
		return -1;
	}
	if (pin == NULL) {
		pin = "";
	}
	if (read_p11_object(parent, dbdir, token, pin, csr, &object,
			    &label, error) != 0) {
		return -1;
	}
	if (find_token(parent, label, &tok, &where) != 0) {
		*error = talloc_asprintf(parent,
					 "token \"%s\" not found in the "
					 "tpm2-pkcs11 store", label);
		goto done;
	}

	/* The token's parent object: persistent, its ESYS_TR serialized in
	 * hex. */
	value = yaml_value(parent, tok.pobject_config, "transient");
	if ((value != NULL) && (strcmp(value, "true") == 0)) {
		*error = "tokens with a transient primary object are not "
			 "supported";
		goto done;
	}
	value = yaml_value(parent, tok.pobject_config, "esys-tr");
	buf = value ? unhex(parent, value, &length) : NULL;
	if (buf == NULL) {
		*error = talloc_asprintf(parent,
					 "can't read the token's primary "
					 "object in \"%s\"", where);
		goto done;
	}
	rc = Esys_TR_Deserialize(esys, buf, length, &parent_tr);
	if (rc != TSS2_RC_SUCCESS) {
		*error = talloc_asprintf(parent, "error using the token's "
					 "primary object: %s",
					 Tss2_RC_Decode(rc));
		goto done;
	}
	memset(&auth, 0, sizeof(auth));
	if (strlen(tok.pobject_auth) < sizeof(auth.buffer)) {
		auth.size = strlen(tok.pobject_auth);
		memcpy(auth.buffer, tok.pobject_auth, auth.size);
	}
	Esys_TR_SetAuth(esys, parent_tr, &auth);

	/* A session salted with the parent, so that the values which we
	 * unseal don't travel in the clear. */
	rc = cm_acme_tpm_start_session(esys, parent_tr, &session);
	if (rc != TSS2_RC_SUCCESS) {
		*error = talloc_asprintf(parent, "error starting a session: "
					 "%s", Tss2_RC_Decode(rc));
		goto done;
	}

	/* Unseal the token's wrapping key using the PIN. */
	offset = 0;
	memset(&seal_public, 0, sizeof(seal_public));
	memset(&seal_private, 0, sizeof(seal_private));
	if ((Tss2_MU_TPM2B_PUBLIC_Unmarshal(tok.seal_pub, tok.seal_pub_len,
					    &offset, &seal_public) !=
	     TSS2_RC_SUCCESS) ||
	    ((offset = 0),
	     Tss2_MU_TPM2B_PRIVATE_Unmarshal(tok.seal_priv, tok.seal_priv_len,
					     &offset, &seal_private) !=
	     TSS2_RC_SUCCESS)) {
		*error = "can't read the token's sealed wrapping key";
		goto done;
	}
	rc = Esys_Load(esys, parent_tr, session, ESYS_TR_NONE, ESYS_TR_NONE,
		       &seal_private, &seal_public, &seal);
	if (rc != TSS2_RC_SUCCESS) {
		*error = talloc_asprintf(parent, "error loading the token's "
					 "wrapping key: %s",
					 Tss2_RC_Decode(rc));
		goto done;
	}
	if (seal_auth(pin, tok.seal_salt, &auth) != 0) {
		*error = "error deriving the PIN's authorization value";
		goto done;
	}
	Esys_TR_SetAuth(esys, seal, &auth);
	memset(&auth, 0, sizeof(auth));
	rc = Esys_Unseal(esys, seal, session, ESYS_TR_NONE, ESYS_TR_NONE,
			 &wrapping);
	if (rc != TSS2_RC_SUCCESS) {
		*error = talloc_asprintf(parent, "error unsealing the token's "
					 "wrapping key (wrong PIN?): %s",
					 Tss2_RC_Decode(rc));
		goto done;
	}
	value = talloc_strndup(parent, (const char *) wrapping->buffer,
			       wrapping->size);
	wrapping_key = unhex(parent, value, &wrapping_key_length);
	memset(value, 0, strlen(value));
	if (wrapping_key == NULL) {
		*error = "the token's wrapping key is malformed";
		goto done;
	}

	/* The key's authorization value. */
	if (unwrap_auth(parent, wrapping_key, wrapping_key_length,
			object.auth_enc->data, object.auth_enc->len,
			&auth) != 0) {
		memset(wrapping_key, 0, wrapping_key_length);
		*error = "error decrypting the key's authorization value";
		goto done;
	}
	memset(wrapping_key, 0, wrapping_key_length);

	/* And the key. */
	offset = 0;
	memset(&key_public, 0, sizeof(key_public));
	memset(&key_private, 0, sizeof(key_private));
	if ((Tss2_MU_TPM2B_PUBLIC_Unmarshal(object.pub->data, object.pub->len,
					    &offset, &key_public) !=
	     TSS2_RC_SUCCESS) ||
	    ((offset = 0),
	     Tss2_MU_TPM2B_PRIVATE_Unmarshal(object.priv->data,
					     object.priv->len, &offset,
					     &key_private) !=
	     TSS2_RC_SUCCESS)) {
		*error = "can't read the key's TPM blobs";
		goto done;
	}
	rc = Esys_Load(esys, parent_tr, session, ESYS_TR_NONE, ESYS_TR_NONE,
		       &key_private, &key_public, &loaded);
	if (rc != TSS2_RC_SUCCESS) {
		*error = talloc_asprintf(parent, "error loading the key: %s",
					 Tss2_RC_Decode(rc));
		goto done;
	}
	Esys_TR_SetAuth(esys, loaded, &auth);
	memset(&auth, 0, sizeof(auth));
	*key = loaded;
	loaded = ESYS_TR_NONE;
	*public = key_public;
	ret = 0;
done:
	if (wrapping != NULL) {
		memset(wrapping, 0, sizeof(*wrapping));
		Esys_Free(wrapping);
	}
	if (seal != ESYS_TR_NONE) {
		Esys_FlushContext(esys, seal);
	}
	if (session != ESYS_TR_NONE) {
		Esys_FlushContext(esys, session);
	}
	if (parent_tr != ESYS_TR_NONE) {
		/* Persistent: only forget about it. */
		Esys_TR_Close(esys, &parent_tr);
	}
	free_p11_object(&object);
	return ret;
}
