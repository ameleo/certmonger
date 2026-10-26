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

/* The parts of JOSE which ACME needs: JWS with an ES256 account key in the
 * flattened JSON serialization, the JWK of that key and its thumbprint, and
 * an HS256 JWS for the external account binding. */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <talloc.h>

#include "acme.h"
#include "log.h"

#define ES256_COORDINATE_LENGTH 32

static const char b64std[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64url[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *
b64_encode(void *parent, const unsigned char *data, size_t length,
	   const char *alphabet, int pad)
{
	char *ret, *p;
	size_t i;
	unsigned int v;

	ret = talloc_size(parent, ((length + 2) / 3) * 4 + 1);
	if (ret == NULL) {
		return NULL;
	}
	p = ret;
	for (i = 0; i + 2 < length; i += 3) {
		v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
		*p++ = alphabet[(v >> 18) & 0x3f];
		*p++ = alphabet[(v >> 12) & 0x3f];
		*p++ = alphabet[(v >> 6) & 0x3f];
		*p++ = alphabet[v & 0x3f];
	}
	if (i < length) {
		v = data[i] << 16;
		if (i + 1 < length) {
			v |= data[i + 1] << 8;
		}
		*p++ = alphabet[(v >> 18) & 0x3f];
		*p++ = alphabet[(v >> 12) & 0x3f];
		if (i + 1 < length) {
			*p++ = alphabet[(v >> 6) & 0x3f];
		} else
		if (pad) {
			*p++ = '=';
		}
		if (pad) {
			*p++ = '=';
		}
	}
	*p = '\0';
	return ret;
}

char *
cm_acme_b64url_encode(void *parent, const unsigned char *data, size_t length)
{
	return b64_encode(parent, data, length, b64url, 0);
}

char *
cm_acme_b64_encode(void *parent, const unsigned char *data, size_t length)
{
	return b64_encode(parent, data, length, b64std, 1);
}

/* Decode base64, in either alphabet, with or without padding, ignoring
 * whitespace. */
unsigned char *
cm_acme_b64_decode(void *parent, const char *text, size_t *length)
{
	unsigned char *ret;
	const char *p;
	unsigned int v = 0;
	int bits = 0, c;
	size_t n = 0;

	*length = 0;
	if (text == NULL) {
		return NULL;
	}
	ret = talloc_size(parent, strlen(text) * 3 / 4 + 3);
	if (ret == NULL) {
		return NULL;
	}
	for (p = text; *p != '\0'; p++) {
		if ((*p >= 'A') && (*p <= 'Z')) {
			c = *p - 'A';
		} else
		if ((*p >= 'a') && (*p <= 'z')) {
			c = *p - 'a' + 26;
		} else
		if ((*p >= '0') && (*p <= '9')) {
			c = *p - '0' + 52;
		} else
		if ((*p == '+') || (*p == '-')) {
			c = 62;
		} else
		if ((*p == '/') || (*p == '_')) {
			c = 63;
		} else
		if (*p == '=') {
			break;
		} else
		if (strchr(" \t\r\n", *p) != NULL) {
			continue;
		} else {
			talloc_free(ret);
			return NULL;
		}
		v = (v << 6) | c;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			ret[n++] = (v >> bits) & 0xff;
		}
	}
	*length = n;
	return ret;
}

/* Generate a P-256 key. */
static EVP_PKEY *
generate_p256(void)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *key = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL) {
		return NULL;
	}
	if ((EVP_PKEY_keygen_init(pctx) != 1) ||
	    (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
						    NID_X9_62_prime256v1) != 1) ||
	    (EVP_PKEY_keygen(pctx, &key) != 1)) {
		key = NULL;
	}
	EVP_PKEY_CTX_free(pctx);
	return key;
}

/* The uncompressed point of a P-256 key. */
static int
p256_point(EVP_PKEY *key, unsigned char *point)
{
	unsigned char *der = NULL, *p;
	int length, ret = -1;

	if (EVP_PKEY_base_id(key) != EVP_PKEY_EC) {
		return -1;
	}
	/* The SubjectPublicKeyInfo of a P-256 key ends with its
	 * uncompressed point; this works the same way with every version
	 * of OpenSSL. */
	length = i2d_PUBKEY(key, NULL);
	if (length < 1 + 2 * ES256_COORDINATE_LENGTH) {
		return -1;
	}
	der = OPENSSL_malloc(length);
	if (der == NULL) {
		return -1;
	}
	p = der;
	if (i2d_PUBKEY(key, &p) == length) {
		p = der + length - (1 + 2 * ES256_COORDINATE_LENGTH);
		if (p[0] == 0x04) {
			memcpy(point, p, 1 + 2 * ES256_COORDINATE_LENGTH);
			ret = 0;
		}
	}
	OPENSSL_free(der);
	return ret;
}

/* Read the account key from a file, creating it if asked to and if there
 * is none yet.  The file is only ever readable by its owner. */
EVP_PKEY *
cm_acme_account_key(const char *filename, int create, const char **error)
{
	EVP_PKEY *key = NULL;
	unsigned char point[1 + 2 * ES256_COORDINATE_LENGTH];
	FILE *fp;
	int fd;

	*error = NULL;
	fp = fopen(filename, "r");
	if (fp != NULL) {
		key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
		if ((key == NULL) || (p256_point(key, point) != 0)) {
			*error = "the account key is not a P-256 key";
			EVP_PKEY_free(key);
			return NULL;
		}
		return key;
	}
	if ((errno != ENOENT) || !create) {
		*error = "error reading the account key";
		return NULL;
	}
	key = generate_p256();
	if (key == NULL) {
		*error = "error generating an account key";
		return NULL;
	}
	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		*error = "error creating the account key file";
		EVP_PKEY_free(key);
		return NULL;
	}
	fp = fdopen(fd, "w");
	if ((fp == NULL) ||
	    (PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) ||
	    (fflush(fp) != 0) || (fsync(fd) != 0)) {
		*error = "error saving the account key";
		if (fp != NULL) {
			fclose(fp);
		} else {
			close(fd);
		}
		unlink(filename);
		EVP_PKEY_free(key);
		return NULL;
	}
	fclose(fp);
	return key;
}

/* The JWK of the account key, with its members in lexicographic order and
 * no whitespace, which is also the form its thumbprint is computed over
 * (RFC 7638 3.2). */
char *
cm_acme_jwk(void *parent, EVP_PKEY *key)
{
	unsigned char point[1 + 2 * ES256_COORDINATE_LENGTH];
	char *x, *y, *ret;

	if (p256_point(key, point) != 0) {
		return NULL;
	}
	x = cm_acme_b64url_encode(parent, point + 1, ES256_COORDINATE_LENGTH);
	y = cm_acme_b64url_encode(parent,
				  point + 1 + ES256_COORDINATE_LENGTH,
				  ES256_COORDINATE_LENGTH);
	if ((x == NULL) || (y == NULL)) {
		return NULL;
	}
	ret = talloc_asprintf(parent,
			      "{\"crv\":\"P-256\",\"kty\":\"EC\","
			      "\"x\":\"%s\",\"y\":\"%s\"}", x, y);
	talloc_free(x);
	talloc_free(y);
	return ret;
}

char *
cm_acme_jwk_thumbprint(void *parent, const char *jwk)
{
	unsigned char md[SHA256_DIGEST_LENGTH];

	SHA256((const unsigned char *) jwk, strlen(jwk), md);
	return cm_acme_b64url_encode(parent, md, sizeof(md));
}

/* Sign with ES256, giving the signature as R || S (RFC 7518 3.4). */
static char *
es256_sign(void *parent, EVP_PKEY *key, const char *input)
{
	EVP_MD_CTX *mctx;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *r, *s;
	unsigned char der[80], raw[2 * ES256_COORDINATE_LENGTH];
	const unsigned char *p;
	size_t length = sizeof(der);
	char *ret = NULL;

	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		return NULL;
	}
	if ((EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, key) != 1) ||
	    (EVP_DigestSign(mctx, der, &length,
			    (const unsigned char *) input,
			    strlen(input)) != 1)) {
		cm_log_errors(1, "Error signing with the account key.\n");
		goto done;
	}
	p = der;
	sig = d2i_ECDSA_SIG(NULL, &p, length);
	if (sig == NULL) {
		goto done;
	}
	ECDSA_SIG_get0(sig, &r, &s);
	if ((BN_bn2binpad(r, raw, ES256_COORDINATE_LENGTH) !=
	     ES256_COORDINATE_LENGTH) ||
	    (BN_bn2binpad(s, raw + ES256_COORDINATE_LENGTH,
			  ES256_COORDINATE_LENGTH) !=
	     ES256_COORDINATE_LENGTH)) {
		goto done;
	}
	ret = cm_acme_b64url_encode(parent, raw, sizeof(raw));
done:
	ECDSA_SIG_free(sig);
	EVP_MD_CTX_free(mctx);
	return ret;
}

/* Build a JWS in the flattened JSON serialization, identifying the key
 * either by its JWK (for newAccount) or by the account URL.  A NULL payload
 * makes a POST-as-GET request, whose payload is empty (RFC 8555 6.3). */
char *
cm_acme_jws(void *parent, EVP_PKEY *key, const char *kid, const char *jwk,
	    const char *nonce, const char *url, const char *payload)
{
	char *protected, *b64p, *b64b, *input, *sig, *ret;
	void *tctx;

	tctx = talloc_new(parent);
	if (kid != NULL) {
		protected = talloc_asprintf(tctx,
					    "{\"alg\":\"ES256\",\"kid\":\"%s\","
					    "\"nonce\":\"%s\",\"url\":\"%s\"}",
					    kid, nonce, url);
	} else {
		protected = talloc_asprintf(tctx,
					    "{\"alg\":\"ES256\",\"jwk\":%s,"
					    "\"nonce\":\"%s\",\"url\":\"%s\"}",
					    jwk, nonce, url);
	}
	if (protected == NULL) {
		talloc_free(tctx);
		return NULL;
	}
	b64p = cm_acme_b64url_encode(tctx, (unsigned char *) protected,
				     strlen(protected));
	if (payload != NULL) {
		b64b = cm_acme_b64url_encode(tctx,
					     (const unsigned char *) payload,
					     strlen(payload));
	} else {
		b64b = talloc_strdup(tctx, "");
	}
	input = talloc_asprintf(tctx, "%s.%s", b64p, b64b);
	if (input == NULL) {
		talloc_free(tctx);
		return NULL;
	}
	sig = es256_sign(tctx, key, input);
	if (sig == NULL) {
		talloc_free(tctx);
		return NULL;
	}
	ret = talloc_asprintf(parent,
			      "{\"protected\":\"%s\",\"payload\":\"%s\","
			      "\"signature\":\"%s\"}", b64p, b64b, sig);
	talloc_free(tctx);
	return ret;
}

int
cm_acme_hmac_sha256(const unsigned char *key, size_t key_length,
		    const unsigned char *data, size_t length,
		    unsigned char *mac)
{
	unsigned int mac_length = SHA256_DIGEST_LENGTH;

	if (HMAC(EVP_sha256(), key, key_length, data, length,
		 mac, &mac_length) == NULL) {
		return -1;
	}
	return (mac_length == SHA256_DIGEST_LENGTH) ? 0 : -1;
}

/* The externalAccountBinding member of a newAccount request: the account's
 * JWK, signed using the MAC key which the CA gave us (RFC 8555 7.3.4). */
char *
cm_acme_eab(void *parent, const char *eab_kid,
	    const unsigned char *eab_key, size_t eab_key_length,
	    const char *jwk, const char *url)
{
	unsigned char mac[SHA256_DIGEST_LENGTH];
	char *protected, *b64p, *b64b, *input, *ret = NULL;
	void *tctx;

	tctx = talloc_new(parent);
	protected = talloc_asprintf(tctx,
				    "{\"alg\":\"HS256\",\"kid\":\"%s\","
				    "\"url\":\"%s\"}", eab_kid, url);
	if (protected == NULL) {
		goto done;
	}
	b64p = cm_acme_b64url_encode(tctx, (unsigned char *) protected,
				     strlen(protected));
	b64b = cm_acme_b64url_encode(tctx, (const unsigned char *) jwk,
				     strlen(jwk));
	input = talloc_asprintf(tctx, "%s.%s", b64p, b64b);
	if ((input == NULL) ||
	    (cm_acme_hmac_sha256(eab_key, eab_key_length,
				 (unsigned char *) input, strlen(input),
				 mac) != 0)) {
		goto done;
	}
	ret = talloc_asprintf(parent,
			      "{\"protected\":\"%s\",\"payload\":\"%s\","
			      "\"signature\":\"%s\"}", b64p, b64b,
			      cm_acme_b64url_encode(tctx, mac, sizeof(mac)));
done:
	memset(mac, 0, sizeof(mac));
	talloc_free(tctx);
	return ret;
}
