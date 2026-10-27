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

#ifndef cmenv_h
#define cmenv_h

char *cm_env_config_dir(void);
char *cm_env_config(const char *subdir, const char *subfile);
char *cm_env_lock_file(void);
char *cm_env_request_dir(void);
char *cm_env_local_ca_dir(void);
char *cm_env_acme_dir(void);
char *cm_env_tpm_dir(void);
char *cm_env_tpm_system_store(void);
char *cm_env_ca_dir(void);
char *cm_env_tmp_dir(void);
char *cm_env_home_dir(void);
char *cm_env_whoami(void);
enum cm_tdbus_type cm_env_default_bus(void);
dbus_bool_t cm_env_default_fork(void);
int cm_env_default_bus_timeout(void);

#endif
