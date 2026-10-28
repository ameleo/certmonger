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
#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <pk11pub.h>
#include <pkcs11.h>
#include <prerror.h>
#include <secmod.h>

#include <talloc.h>

#include "log.h"
#include "store.h"
#include "store-int.h"
#include "tpm-token.h"
#include "tpm-token-p11.h"

int
cm_tpm_token_ca_attests(struct cm_store_ca *ca)
{
	if ((ca == NULL) || (ca->cm_ca_type != cm_ca_external)) {
		return 0;
	}
	return cm_tpm_token_helper_attests(ca->cm_ca_external_helper);
}

/* Find our token, or initialize one: through the module directly, as NSS
 * has no way to initialize a token of another module. */
static int
init_token(void *parent, const char **error)
{
	struct cm_tpm_token_session *s;

	s = cm_tpm_token_open(parent, CM_TPM_TOKEN_LABEL, 1, error);
	if (s == NULL) {
		return -1;
	}
	talloc_free(s);
	return 0;
}

int
cm_tpm_token_ca_wants(struct cm_store_ca *ca)
{
	if ((ca == NULL) || (ca->cm_ca_type != cm_ca_external)) {
		return 0;
	}
	if (cm_tpm_token_helper_attests(ca->cm_ca_external_helper)) {
		return 1;
	}
	return cm_tpm_token_helper_is_acme(ca->cm_ca_external_helper) &&
	       cm_tpm_token_available();
}

/* Make sure the NSS database in the token's directory exists and loads the
 * module. */
static int
add_module(void *parent, const char *dir, const char **error)
{
	NSSInitContext *ctx;
	SECMODModuleList *mlp;
	SECMODListLock *lock;
	PK11SlotInfo *slot;
	const char *es;
	int found = 0, ret = 0;

	ctx = NSS_InitContext(dir, NULL, NULL, NULL, NULL,
			      NSS_INIT_NOROOTINIT);
	if (ctx == NULL) {
		es = PR_ErrorToName(PORT_GetError());
		*error = talloc_asprintf(parent, "error initializing database "
					 "'%s': %s", dir, es ? es : "?");
		return -1;
	}
	lock = SECMOD_GetDefaultModuleListLock();
	SECMOD_GetReadLock(lock);
	for (mlp = SECMOD_GetDefaultModuleList(); mlp != NULL; mlp = mlp->next) {
		if ((mlp->module->dllName != NULL) &&
		    (strcmp(mlp->module->dllName,
			    CM_TPM2_PKCS11_MODULE) == 0)) {
			found = 1;
		}
	}
	SECMOD_ReleaseReadLock(lock);
	/* Where p11-kit makes the module known to every NSS database, NSS
	 * already sees the token, and the module can't be loaded twice. */
	if (!found) {
		slot = PK11_FindSlotByName(CM_TPM_TOKEN_LABEL);
		if (slot != NULL) {
			PK11_FreeSlot(slot);
			found = 1;
		}
	}
	if (!found &&
	    (SECMOD_AddNewModule(CM_TPM_TOKEN_MODULE_NAME,
				 CM_TPM2_PKCS11_MODULE, 0, 0) != SECSuccess)) {
		es = PR_ErrorToName(PORT_GetError());
		*error = talloc_asprintf(parent, "error adding %s to database "
					 "'%s': %s", CM_TPM2_PKCS11_MODULE,
					 dir, es ? es : "?");
		ret = -1;
	}
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	return ret;
}

int
cm_tpm_token_prepare(void *parent, const char **error)
{
	const char *dir;

	dir = cm_tpm_token_dir();
	if (dir == NULL) {
		*error = "error creating the TPM token's directory";
		return -1;
	}
	cm_tpm_token_setenv();
	if (init_token(parent, error) != 0) {
		return -1;
	}
	return add_module(parent, dir, error);
}
