/*
 * Copyright (C) 2010,2011 Red Hat, Inc.
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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <nss.h>
#include <pk11pub.h>
#include <prmem.h>

#include <talloc.h>

#include "log.h"
#include "pin.h"
#include "store-int.h"
#include "tpm-token.h"

enum cm_pin_type {
	cm_pin_for_key,
	cm_pin_for_cert,
};

static int
cm_pin_read(struct cm_store_entry *entry, enum cm_pin_type pin_type, char **pin)
{
	const char *pinfile, *pinvalue;
	struct stat st;
	int fd, l, err;

	switch (pin_type) {
	case cm_pin_for_key:
		pinfile = entry->cm_key_pin_file;
		pinvalue = entry->cm_key_pin;
		break;
	case cm_pin_for_cert:
		pinfile = entry->cm_key_pin_file; /* XXX */
		pinvalue = entry->cm_key_pin; /* XXX */
		break;
	default:
		pinfile = NULL;
		pinvalue = NULL;
		break;
	}

	if (pin == NULL) {
		return EINVAL;
	}
	*pin = NULL;
	err = 0;
	if ((pinfile != NULL) && (strlen(pinfile) > 0)) {
		fd = open(pinfile, O_RDONLY);
		if (fd != -1) {
			if ((fstat(fd, &st) == 0) && (st.st_size > 0)) {
				*pin = talloc_zero_size(entry, st.st_size + 1);
				if (*pin != NULL) {
					if (read(fd, *pin, st.st_size) != -1) {
						l = strcspn(*pin, "\r\n");
						if (l == 0) {
							talloc_free(*pin);
							*pin = NULL;
						} else {
							(*pin)[l] = '\0';
						}
					} else {
						err = errno;
						cm_log(-1,
						       "Error reading \"%s\": "
						       "%s.\n",
						       pinfile, strerror(err));
						talloc_free(*pin);
						*pin = NULL;
					}
				}
			} else {
				err = errno;
				cm_log(-1, "Error determining size of \"%s\": "
				       "%s.\n",
				       pinfile, strerror(err));
			}
			close(fd);
		} else {
			err = errno;
			cm_log(-1, "Error reading PIN from \"%s\": %s.\n",
			       pinfile, strerror(err));
		}
	}
	if ((pin != NULL) && (*pin == NULL) && (err == 0)) {
		if (pinvalue != NULL) {
			*pin = talloc_strdup(entry, pinvalue);
		} else
		if (cm_tpm_token_entry_uses(entry)) {
			/* Our TPM token's user PIN is empty. */
			*pin = talloc_strdup(entry, "");
		}
	}
	return err;
}

int
cm_pin_read_for_key_ossl_cb(char *buf, int size, int rwflag, void *u)
{
	struct cm_pin_cb_data *cb_data;
	char *pin;
	int ret;

	/* Record that we were called, so a PIN was needed. */
	cb_data = u;
	cb_data->n_attempts++;

	memset(buf, '\0', size);
	if (cm_pin_read(cb_data->entry, cm_pin_for_key, &pin) == 0) {
		if (pin != NULL) {
			ret = strlen(pin);
			if (ret < size) {
				strcpy(buf, pin);
			} else {
				ret = 0;
			}
			talloc_free(pin);
		} else {
			ret = 0;
		}
	} else {
		ret = 0;
	}

	return ret;
}

static char *
cm_pin_nss_cb(PK11SlotInfo *slot, PRBool retry, void *arg,
	      enum cm_pin_type pin_type)
{
	struct cm_pin_cb_data *cb_data;
	char *pin, *ret;

	/* Record that we were called, so a PIN was needed. */
	cb_data = arg;
	cb_data->n_attempts++;

	if (retry) {
		/* We're not going to change what we're suggesting. */
		ret = NULL;
	} else {
		if (cm_pin_read(cb_data->entry, pin_type, &pin) == 0) {
			if (pin != NULL) {
				ret = PR_Malloc(strlen(pin) + 1);
				if (ret != NULL) {
					strcpy(ret, pin);
				}
				talloc_free(pin);
			} else {
				ret = NULL;
			}
		} else {
			ret = NULL;
		}
	}

	return ret;
}

int
cm_pin_read_for_key(struct cm_store_entry *entry, char **pin)
{
	return cm_pin_read(entry, cm_pin_for_key, pin);
}

char *
cm_pin_read_for_key_nss_cb(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	return cm_pin_nss_cb(slot, retry, arg, cm_pin_for_key);
}

int
cm_pin_read_for_cert(struct cm_store_entry *entry, char **pin)
{
	return cm_pin_read(entry, cm_pin_for_cert, pin);
}

char *
cm_pin_read_for_cert_nss_cb(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	return cm_pin_nss_cb(slot, retry, arg, cm_pin_for_cert);
}
