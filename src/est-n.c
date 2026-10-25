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

#define _GNU_SOURCE

#include "config.h"

#include <sys/types.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <krb5.h>

#include <nss.h>
#include <cert.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secmod.h>

#include <talloc.h>

#include "est.h"
#include "log.h"
#include "store.h"
#include "submit-u.h"

#define SOFTOKEN_LIBRARY "libsoftokn3.so"

/* Hand out the PIN we were given, once. */
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
	const char *name, *text;

	ec = PORT_GetError();
	name = PR_ErrorToName(ec);
	text = PR_ErrorToString(ec, PR_LANGUAGE_I_DEFAULT);
	return talloc_asprintf(parent, "%s: %s%s%s%s",
			       what,
			       name ? name : "unknown error",
			       (text && strlen(text)) ? " (" : "",
			       (text && strlen(text)) ? text : "",
			       (text && strlen(text)) ? ")" : "");
}

/* Percent-encode a value for use in a PKCS#11 URI (RFC 7512). */
static char *
pct_encode(void *parent, const unsigned char *data, size_t length)
{
	char *ret;
	size_t i;

	ret = talloc_strdup(parent, "");
	for (i = 0; (ret != NULL) && (i < length); i++) {
		if ((data[i] != '\0') &&
		    (strchr("abcdefghijklmnopqrstuvwxyz"
			    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "0123456789-._~", data[i]) != NULL)) {
			ret = talloc_asprintf_append(ret, "%c", data[i]);
		} else {
			ret = talloc_asprintf_append(ret, "%%%02x", data[i]);
		}
	}
	return ret;
}

/* NSS loads its software token without telling us where from, so look for
 * the library among the ones which are loaded. */
static int
find_softoken(struct dl_phdr_info *info, size_t size, void *arg)
{
	char **path = arg;
	const char *base;

	(void) size;
	if ((info->dlpi_name == NULL) || (strlen(info->dlpi_name) == 0)) {
		return 0;
	}
	base = strrchr(info->dlpi_name, '/');
	base = base ? base + 1 : info->dlpi_name;
	if (strcmp(base, SOFTOKEN_LIBRARY) == 0) {
		*path = strdup(info->dlpi_name);
		return 1;
	}
	return 0;
}

int
cm_est_n_key_location(void *parent,
		      const char *dbdir, const char *token,
		      const char *cert_pem, const char *pin,
		      struct cm_est_key_location *location,
		      const char **error)
{
	NSSInitContext *nctx;
	CERTCertificate *cert = NULL;
	SECKEYPrivateKey *key = NULL;
	PK11SlotInfo *slot = NULL;
	SECMODModule *module;
	SECItem item, *id = NULL;
	const char *token_name;
	char *b64, *nickname = NULL, *softoken = NULL, *uri;
	unsigned char *der;
	int length, ret = -1;

	memset(location, 0, sizeof(*location));
	*error = NULL;

	nctx = NSS_InitContext(dbdir, NULL, NULL, NULL, NULL,
			       NSS_INIT_READONLY);
	if (nctx == NULL) {
		*error = nss_error(parent, "error opening database");
		return -1;
	}
	PK11_SetPasswordFunc(pin_cb);

	/* Locate the certificate which we're renewing, and its key. */
	b64 = cm_submit_u_base64_from_text(cert_pem);
	der = (unsigned char *) cm_store_base64_as_bin(parent, b64, -1,
						       &length);
	free(b64);
	if ((der == NULL) || (length <= 0)) {
		*error = "can't decode the current certificate";
		goto done;
	}
	item.type = siDERCertBuffer;
	item.data = der;
	item.len = length;
	cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), &item,
				       NULL, PR_FALSE, PR_TRUE);
	if (cert == NULL) {
		*error = nss_error(parent,
				   "error parsing the current certificate");
		goto done;
	}
	if ((token != NULL) && (strlen(token) > 0)) {
		slot = PK11_FindSlotByName(token);
		if (slot == NULL) {
			*error = nss_error(parent, "error finding token");
			goto done;
		}
		if (PK11_NeedLogin(slot) &&
		    (PK11_Authenticate(slot, PR_TRUE,
				       (void *) pin) != SECSuccess)) {
			*error = nss_error(parent,
					   "error logging in to token");
			goto done;
		}
		key = PK11_FindKeyByDERCert(slot, cert, (void *) pin);
	} else {
		key = PK11_FindKeyByAnyCert(cert, (void *) pin);
	}
	if (key == NULL) {
		*error = nss_error(parent,
				   "error finding the key for the current "
				   "certificate");
		goto done;
	}

	/* The module which holds the key, and how it was initialized. */
	module = PK11_GetModule(key->pkcs11Slot);
	if (module == NULL) {
		*error = "error finding the module which holds the key";
		goto done;
	}
	if (module->internal) {
		dl_iterate_phdr(find_softoken, &softoken);
		location->module = talloc_strdup(parent,
						 softoken ?
						 softoken :
						 SOFTOKEN_LIBRARY);
		free(softoken);
	} else
	if (module->dllName != NULL) {
		location->module = talloc_strdup(parent, module->dllName);
	}
	if ((module->libraryParams != NULL) &&
	    (strlen(module->libraryParams) > 0)) {
		location->init_args = talloc_strdup(parent,
						    module->libraryParams);
	}

	/* A PKCS#11 URI for the key.  The software token's name depends on
	 * whether or not it's in FIPS mode, and the module's other token
	 * never holds keys, so we leave the name out for it. */
	uri = talloc_strdup(parent, "pkcs11:");
	if (!module->internal) {
		token_name = PK11_GetTokenName(key->pkcs11Slot);
		uri = talloc_asprintf_append(uri, "token=%s;",
					     pct_encode(parent,
							(const unsigned char *) token_name,
							strlen(token_name)));
	}
	id = PK11_GetLowLevelKeyIDForPrivateKey(key);
	if ((id != NULL) && (id->len > 0)) {
		uri = talloc_asprintf_append(uri, "id=%s;",
					     pct_encode(parent,
							id->data, id->len));
	} else {
		nickname = PK11_GetPrivateKeyNickname(key);
		if ((nickname == NULL) || (strlen(nickname) == 0)) {
			*error = "the key has neither an ID nor a label";
			goto done;
		}
		uri = talloc_asprintf_append(uri, "object=%s;",
					     pct_encode(parent,
							(const unsigned char *) nickname,
							strlen(nickname)));
	}
	location->uri = talloc_strdup_append(uri, "type=private");
	if ((location->module == NULL) || (location->uri == NULL)) {
		*error = "error describing the key's location";
		goto done;
	}
	ret = 0;

done:
	if (nickname != NULL) {
		PORT_Free(nickname);
	}
	if (id != NULL) {
		SECITEM_FreeItem(id, PR_TRUE);
	}
	if (key != NULL) {
		SECKEY_DestroyPrivateKey(key);
	}
	if (cert != NULL) {
		CERT_DestroyCertificate(cert);
	}
	if (slot != NULL) {
		PK11_FreeSlot(slot);
	}
	if (NSS_ShutdownContext(nctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	return ret;
}
