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

#include <talloc.h>

#include "log.h"
#include "tpm-token.h"
#include "tpm-token-p11.h"

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

/* Initialize our token in a slot the module offers for a new one, with an
 * empty user PIN and a random SO PIN which we forget. */
static int
init_token(void *parent, CK_FUNCTION_LIST_PTR f, CK_SLOT_ID slot,
	   const char **error)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR label[32];
	CK_UTF8CHAR empty[1] = "";
	CK_RV rv;
	char so_pin[33];

	memset(label, ' ', sizeof(label));
	memcpy(label, CM_TPM_TOKEN_LABEL, strlen(CM_TPM_TOKEN_LABEL));
	if (random_pin(so_pin, sizeof(so_pin)) != 0) {
		*error = "error generating a PIN";
		return -1;
	}
	cm_log(3, "Initializing the TPM token \"%s\".\n", CM_TPM_TOKEN_LABEL);
	rv = f->C_InitToken(slot, (CK_UTF8CHAR_PTR) so_pin, strlen(so_pin),
			    label);
	if (rv != CKR_OK) {
		memset(so_pin, 0, sizeof(so_pin));
		*error = talloc_asprintf(parent, "error initializing the TPM "
					 "token (0x%lx)", (unsigned long) rv);
		return -1;
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
	memset(so_pin, 0, sizeof(so_pin));
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error setting the TPM "
					 "token's PIN (0x%lx)",
					 (unsigned long) rv);
		return -1;
	}
	return 0;
}

static int
session_destructor(struct cm_tpm_token_session *s)
{
	if (s->f != NULL) {
		if (s->session != CK_INVALID_HANDLE) {
			s->f->C_CloseSession(s->session);
		}
		s->f->C_Finalize(NULL);
	}
	if (s->module != NULL) {
		dlclose(s->module);
	}
	return 0;
}

struct cm_tpm_token_session *
cm_tpm_token_open(void *parent, int create, const char **error)
{
#ifdef CM_TPM2_PKCS11_MODULE
	struct cm_tpm_token_session *s;
	CK_C_GetFunctionList get_function_list;
	CK_SLOT_ID *slots = NULL, slot = 0;
	CK_ULONG n_slots = 0, i;
	CK_TOKEN_INFO info;
	CK_UTF8CHAR label[32];
	CK_UTF8CHAR empty[1] = "";
	CK_RV rv;
	int found = 0, free_slot = 0;

	s = talloc_zero(parent, struct cm_tpm_token_session);
	if (s == NULL) {
		*error = "out of memory";
		return NULL;
	}
	s->session = CK_INVALID_HANDLE;
	talloc_set_destructor(s, session_destructor);
	memset(label, ' ', sizeof(label));
	memcpy(label, CM_TPM_TOKEN_LABEL, strlen(CM_TPM_TOKEN_LABEL));
	s->module = dlopen(CM_TPM2_PKCS11_MODULE, RTLD_NOW | RTLD_LOCAL);
	if (s->module == NULL) {
		*error = talloc_asprintf(parent, "error loading %s: %s",
					 CM_TPM2_PKCS11_MODULE, dlerror());
		goto fail;
	}
	get_function_list = (CK_C_GetFunctionList) dlsym(s->module,
							 "C_GetFunctionList");
	if ((get_function_list == NULL) ||
	    (get_function_list(&s->f) != CKR_OK) ||
	    (s->f == NULL)) {
		*error = talloc_asprintf(parent, "%s is not a PKCS#11 module",
					 CM_TPM2_PKCS11_MODULE);
		s->f = NULL;
		goto fail;
	}
	rv = s->f->C_Initialize(NULL);
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error initializing the TPM "
					 "module (0x%lx)", (unsigned long) rv);
		s->f = NULL;
		goto fail;
	}
	rv = s->f->C_GetSlotList(CK_TRUE, NULL, &n_slots);
	if ((rv == CKR_OK) && (n_slots > 0)) {
		slots = talloc_array(s, CK_SLOT_ID, n_slots);
		if (slots == NULL) {
			*error = "out of memory";
			goto fail;
		}
		rv = s->f->C_GetSlotList(CK_TRUE, slots, &n_slots);
	}
	if (rv != CKR_OK) {
		*error = talloc_asprintf(parent, "error listing the TPM "
					 "module's tokens (0x%lx)",
					 (unsigned long) rv);
		goto fail;
	}
	for (i = 0; i < n_slots; i++) {
		if (s->f->C_GetTokenInfo(slots[i], &info) != CKR_OK) {
			continue;
		}
		if (info.flags & CKF_TOKEN_INITIALIZED) {
			if (memcmp(info.label, label, sizeof(label)) == 0) {
				slot = slots[i];
				found = 1;
			}
		} else
		if (!free_slot && !found) {
			slot = slots[i];
			free_slot = 1;
		}
	}
	if (!found) {
		if (!create) {
			*error = "the TPM token doesn't exist";
			goto fail;
		}
		if (!free_slot) {
			*error = "the TPM module offers no token to initialize";
			goto fail;
		}
		if (init_token(parent, s->f, slot, error) != 0) {
			goto fail;
		}
	}
	rv = s->f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				 NULL, NULL, &s->session);
	if (rv != CKR_OK) {
		s->session = CK_INVALID_HANDLE;
		*error = talloc_asprintf(parent, "error opening a session with "
					 "the TPM token (0x%lx)",
					 (unsigned long) rv);
		goto fail;
	}
	/* The user PIN is empty.  A module which says no login is needed
	 * refuses none either. */
	rv = s->f->C_Login(s->session, CKU_USER, empty, 0);
	if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN)) {
		cm_log(3, "Logging in to the TPM token: 0x%lx.\n",
		       (unsigned long) rv);
	}
	s->slot = slot;
	talloc_free(slots);
	return s;
fail:
	talloc_free(s);
	return NULL;
#else
	(void) parent;
	(void) create;
	*error = "built without the TPM module";
	return NULL;
#endif
}
