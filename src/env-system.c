/*
 * Copyright (C) 2011 Red Hat, Inc.
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

#include <paths.h>
#include <stdlib.h>
#include <string.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include "env.h"
#include "tdbus.h"

char *
cm_env_home_dir(void)
{
	return CM_HOMEDIR;
}

char *
cm_env_config_dir(void)
{
	char *ret;
	ret = getenv(CM_STORE_CONFIG_DIRECTORY_ENV);
	if (ret == NULL) {
		ret = CM_STORE_CONFIG_DIRECTORY;
	}
	return ret;
}

char *
cm_env_request_dir(void)
{
	char *ret;
	ret = getenv(CM_STORE_REQUESTS_DIRECTORY_ENV);
	if (ret == NULL) {
		ret = CM_STORE_REQUESTS_DIRECTORY;
	}
	return ret;
}

char *
cm_env_ca_dir(void)
{
	char *ret;
	ret = getenv(CM_STORE_CAS_DIRECTORY_ENV);
	if (ret == NULL) {
		ret = CM_STORE_CAS_DIRECTORY;
	}
	return ret;
}

char *
cm_env_local_ca_dir(void)
{
	static char *ret = NULL;

	if (ret == NULL) {
		ret = getenv(CM_STORE_LOCAL_CA_DIRECTORY_ENV);
		if (ret == NULL) {
			ret = CM_STORE_LOCAL_CA_DIRECTORY;
		}
	}
	return ret;
}

char *
cm_env_acme_dir(void)
{
	char *ret;

	ret = getenv(CM_STORE_ACME_DIRECTORY_ENV);
	if (ret == NULL) {
		ret = CM_STORE_ACME_DIRECTORY;
	}
	return ret;
}

char *
cm_env_tpm_dir(void)
{
	char *ret;

	ret = getenv(CM_STORE_TPM_DIRECTORY_ENV);
	if (ret == NULL) {
		ret = CM_STORE_TPM_DIRECTORY;
	}
	return ret;
}

char *
cm_env_tmp_dir(void)
{
	char *ret;
	ret = getenv(CM_TMPDIR_ENV);
	if ((ret == NULL) || (strlen(ret) == 0)) {
		ret = CM_TMPDIR;
		if ((ret == NULL) || (strlen(ret) == 0)) {
			ret = getenv("TMPDIR");
			if ((ret == NULL) || (strlen(ret) == 0)) {
				ret = _PATH_VARTMP;
			}
		}
	}
	return ret;
}

char *
cm_env_whoami(void)
{
	return "certmonger";
}

enum cm_tdbus_type
cm_env_default_bus(void)
{
	return cm_tdbus_system;
}

dbus_bool_t
cm_env_default_fork(void)
{
	return TRUE;
}

int
cm_env_default_bus_timeout(void)
{
	return 0;
}

char *
cm_env_lock_file(void)
{
	char *ret;
	ret = getenv(CM_STORE_SYSTEM_LOCK_FILE_ENV);
	if (ret == NULL) {
		ret = CM_STORE_SYSTEM_LOCK_FILE;
	}
	return ret;
}
