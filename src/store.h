/*
 * Copyright (C) 2009,2011,2012,2014,2015,2016 Red Hat, Inc.
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

#ifndef cmstore_h
#define cmstore_h

struct cm_store_entry;
struct cm_store_ca;

/* Generic routines. */
struct cm_store_entry *cm_store_entry_new(void *parent);
struct cm_store_ca *cm_store_ca_new(void *parent);
struct cm_store_entry *cm_store_entry_dup(void *parent,
					  struct cm_store_entry *entry);
struct cm_store_ca *cm_store_ca_dup(void *parent,
				    struct cm_store_ca *ca);

/* Store-specific entry storage. */
int cm_store_entry_save(struct cm_store_entry *entry);
int cm_store_entry_delete(struct cm_store_entry *entry);
struct cm_store_entry **cm_store_get_all_entries(void *parent);

/* Store-specific CA storage. */
int cm_store_ca_save(struct cm_store_ca *ca);
int cm_store_ca_delete(struct cm_store_ca *ca);
struct cm_store_ca **cm_store_get_all_cas(void *parent);

/* Utility functions. */
time_t cm_store_time_from_timestamp(const char *timestamp);
char *cm_store_timestamp_from_time(time_t when, char timestamp[15]);
int cm_store_make_uuid_string(char out[37]);
int cm_store_make_uuid_string_underscore(char out[37]);
char *cm_store_timestamp_from_time_for_display(time_t when, char timestamp[25]);
char *cm_store_local_timestamp_from_time_for_display(time_t when);
char *cm_store_increment_serial(void *parent, const char *old_serial);
char *cm_store_serial_to_binary(void *parent,
				const unsigned char *serial, int length);
char *cm_store_serial_to_der(void *parent, const char *serial);
char *cm_store_hex_from_bin(void *parent,
			    const unsigned char *serial, int length);
int cm_store_hex_to_bin(const char *serial, unsigned char *buf, int length);
char *cm_store_base64_from_bin(void *parent,
			       const unsigned char *buf, int length);
int cm_store_base64_to_bin(const char *serial, int insize,
			   unsigned char *buf, int maxlength);
char *cm_store_base64_as_bin(void *parent, const char *serial, int insize,
			     int *length);
char *cm_store_base64_from_hex(void *parent, const char *hex);
char *cm_store_canonicalize_path(void *parent, const char *path);
char *cm_store_maybe_strdup(void *parent, const char *s);
char **cm_store_maybe_strdupv(void *parent, char **s);

void cm_store_set_if_not_set_s(void *parent, char **dest, char *src);
void cm_store_set_if_not_set_as(void *parent, char ***dest, char **src);

int cm_store_utf8_to_bmp_string(char *s,
				unsigned char **bmp, unsigned int *len);
char *cm_store_utf8_from_bmp_string(unsigned char *bmp, unsigned int len);
const char *cm_store_algorithm_to_name(int algorithm);

/* Where, beside the state of the ACME helper, we keep the keys of external
 * account bindings given when ACME CAs are added, until the helper has
 * opened the account with them. */
#define CM_STORE_ACME_EAB_SUBDIR "eab"

#endif
