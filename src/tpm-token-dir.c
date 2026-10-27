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
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include "env.h"
#include "log.h"
#include "store.h"
#include "store-int.h"
#include "tpm-token.h"

/* Compare two NSS database locations, ignoring a "sql:" prefix and
 * trailing slashes. */
static int
same_dir(const char *a, const char *b)
{
	size_t la, lb;

	if (strncmp(a, "sql:", 4) == 0) {
		a += 4;
	}
	if (strncmp(b, "sql:", 4) == 0) {
		b += 4;
	}
	la = strlen(a);
	while ((la > 1) && (a[la - 1] == '/')) {
		la--;
	}
	lb = strlen(b);
	while ((lb > 1) && (b[lb - 1] == '/')) {
		lb--;
	}
	return (la == lb) && (strncmp(a, b, la) == 0);
}

int
cm_tpm_token_entry_uses(struct cm_store_entry *entry)
{
	const char *dir;

	if ((entry == NULL) ||
	    (entry->cm_key_storage_type != cm_key_storage_nssdb) ||
	    (entry->cm_key_storage_location == NULL) ||
	    (entry->cm_key_token == NULL) ||
	    (strcmp(entry->cm_key_token, CM_TPM_TOKEN_LABEL) != 0)) {
		return 0;
	}
	dir = cm_env_tpm_dir();
	return (dir != NULL) &&
	       same_dir(entry->cm_key_storage_location, dir);
}

const char *
cm_tpm_token_dir(void)
{
	const char *dir;

	dir = cm_env_tpm_dir();
	if (dir == NULL) {
		return NULL;
	}
	if ((mkdir(dir, S_IRWXU) != 0) && (errno != EEXIST)) {
		cm_log(1, "Error creating \"%s\": %s.\n", dir,
		       strerror(errno));
		return NULL;
	}
	return dir;
}

void
cm_tpm_token_setenv(void)
{
	const char *dir;

	dir = cm_env_tpm_dir();
	if (dir == NULL) {
		return;
	}
	/* The token's store is ours, whatever store the module is told to
	 * use for other tokens, and it is a store of the "esysdb" kind. */
	setenv("TPM2_PKCS11_STORE", dir, 1);
	setenv("TPM2_PKCS11_BACKEND", "esysdb", 1);
	/* The kernel's resource manager is there whenever there is a TPM,
	 * and the SELinux policy lets us use it. */
	if (getenv("TPM2_PKCS11_TCTI") == NULL) {
		setenv("TPM2_PKCS11_TCTI", "device:/dev/tpmrm0", 1);
	}
}


/* Whether we pointed tpm2-pkcs11 at our store, and quieted it, ourselves. */
static int cm_tpm_token_set_store, cm_tpm_token_set_log_level;

void
cm_tpm_token_startup(void)
{
#ifdef CM_TPM2_PKCS11_MODULE
	const char *dir;

	if (access(CM_TPM2_PKCS11_MODULE, R_OK) != 0) {
		return;
	}
	/* Where p11-kit makes the module known to every user of NSS, NSS
	 * loads it into this process too, and the module complains loudly
	 * when it finds no store of its own.  Give it ours, made now rather
	 * than at the first request for a CA which attests, as the module
	 * looks for its store whenever NSS loads it: an empty directory, in
	 * which the module creates an empty store.  A store named in our
	 * environment is left as it is. */
	if (getenv("TPM2_PKCS11_STORE") == NULL) {
		dir = cm_tpm_token_dir();
		if (dir != NULL) {
			setenv("TPM2_PKCS11_STORE", dir, 1);
			cm_tpm_token_set_store = 1;
		}
	}
	/* The module also warns about its FAPI backend, which we don't use,
	 * on every system which hasn't provisioned it.  Errors still show. */
	if (getenv("TPM2_PKCS11_LOG_LEVEL") == NULL) {
		setenv("TPM2_PKCS11_LOG_LEVEL", "0", 1);
		cm_tpm_token_set_log_level = 1;
	}
#endif
}

void
cm_tpm_token_child_setenv(struct cm_store_entry *entry)
{
	if (cm_tpm_token_entry_uses(entry)) {
		cm_tpm_token_setenv();
		return;
	}
	/* Anything else sees the module as it would have without us: a key
	 * in a token of someone else's finds that token's store. */
	if (cm_tpm_token_set_store) {
		unsetenv("TPM2_PKCS11_STORE");
	}
	if (cm_tpm_token_set_log_level) {
		unsetenv("TPM2_PKCS11_LOG_LEVEL");
	}
}
