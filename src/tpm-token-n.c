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
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int
cm_tpm_token_ca_attests(struct cm_store_ca *ca)
{
	if ((ca == NULL) || (ca->cm_ca_type != cm_ca_external)) {
		return 0;
	}
	return cm_tpm_token_helper_attests(ca->cm_ca_external_helper);
}

/* A random SO PIN, which nobody will ever need. */
static int
random_pin(char *pin, size_t size)
{
	unsigned char bytes[16];
	const char hex[] = "0123456789abcdef";
	ssize_t n;
	size_t i;
	int fd;

	if (size < 2 * sizeof(bytes) + 1) {
		return -1;
	}
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		return -1;
	}
	n = read(fd, bytes, sizeof(bytes));
	close(fd);
	if (n != (ssize_t) sizeof(bytes)) {
		return -1;
	}
	for (i = 0; i < sizeof(bytes); i++) {
		pin[2 * i] = hex[bytes[i] >> 4];
		pin[2 * i + 1] = hex[bytes[i] & 0x0f];
	}
	pin[2 * sizeof(bytes)] = '\0';
	memset(bytes, 0, sizeof(bytes));
	return 0;
}

/* Find our token among the module's, or initialize one: through the module
 * itself, before NSS loads it, since NSS keeps sessions open on its slots
 * and a token can't be initialized while any is. */
static int
init_token(void *parent, const char **error)
{
	CK_C_GetFunctionList get_function_list;
	CK_FUNCTION_LIST_PTR f = NULL;
	CK_SLOT_ID *slots = NULL, slot = 0;
	CK_ULONG n_slots, i;
	CK_TOKEN_INFO info;
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR label[32];
	CK_UTF8CHAR empty[1] = "";
	CK_RV rv;
	char so_pin[33];
	void *module;
	int found = 0, free_slot = 0, ret = -1;

	memset(label, ' ', sizeof(label));
	memcpy(label, CM_TPM_TOKEN_LABEL, strlen(CM_TPM_TOKEN_LABEL));
	module = dlopen(CM_TPM2_PKCS11_MODULE, RTLD_NOW | RTLD_LOCAL);
	if (module == NULL) {
		*error = talloc_asprintf(parent, "error loading %s: %s",
					 CM_TPM2_PKCS11_MODULE, dlerror());
		return -1;
	}
	get_function_list = (CK_C_GetFunctionList) dlsym(module,
							 "C_GetFunctionList");
	if ((get_function_list == NULL) ||
	    (get_function_list(&f) != CKR_OK) ||
	    (f == NULL)) {
		*error = talloc_asprintf(parent, "%s is not a PKCS#11 module",
					 CM_TPM2_PKCS11_MODULE);
		dlclose(module);
		return -1;
	}
	rv = f->C_Initialize(NULL);
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error initializing the TPM "
					 "module (0x%lx)", (unsigned long) rv);
		dlclose(module);
		return -1;
	}
	rv = f->C_GetSlotList(CK_TRUE, NULL, &n_slots);
	if ((rv == CKR_OK) && (n_slots > 0)) {
		slots = talloc_array(parent, CK_SLOT_ID, n_slots);
		if (slots == NULL) {
			*error = "out of memory";
			goto done;
		}
		rv = f->C_GetSlotList(CK_TRUE, slots, &n_slots);
	}
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error listing the TPM "
					 "module's tokens (0x%lx)",
					 (unsigned long) rv);
		goto done;
	}
	for (i = 0; (i < n_slots) && !found; i++) {
		if (f->C_GetTokenInfo(slots[i], &info) != CKR_OK) {
			continue;
		}
		if (info.flags & CKF_TOKEN_INITIALIZED) {
			if (memcmp(info.label, label, sizeof(label)) == 0) {
				slot = slots[i];
				found = 1;
			}
		} else
		if (!free_slot) {
			slot = slots[i];
			free_slot = 1;
		}
	}
	if (found) {
		ret = 0;
		goto done;
	}
	if (!free_slot) {
		*error = "the TPM module offers no token to initialize";
		goto done;
	}
	if (random_pin(so_pin, sizeof(so_pin)) != 0) {
		*error = "error generating a PIN";
		goto done;
	}
	cm_log(3, "Initializing the TPM token \"%s\".\n", CM_TPM_TOKEN_LABEL);
	rv = f->C_InitToken(slot, (CK_UTF8CHAR_PTR) so_pin, strlen(so_pin),
			    label);
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error initializing the TPM "
					 "token (0x%lx)", (unsigned long) rv);
		goto done;
	}
	rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
			      NULL, NULL, &session);
	if (rv == CKR_OK) {
		rv = f->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR) so_pin,
				strlen(so_pin));
		if (rv == CKR_OK) {
			/* An empty PIN, as a buffer of no length: the module
			 * takes no PIN at all for a NULL one. */
			rv = f->C_InitPIN(session, empty, 0);
			f->C_Logout(session);
		}
		f->C_CloseSession(session);
	}
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error setting the TPM "
					 "token's PIN (0x%lx)",
					 (unsigned long) rv);
		goto done;
	}
	ret = 0;
done:
	memset(so_pin, 0, sizeof(so_pin));
	talloc_free(slots);
	f->C_Finalize(NULL);
	dlclose(module);
	return ret;
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
