/*
 * Copyright (C) 2009,2011,2012,2013,2014,2015,2016 Red Hat, Inc.
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
#include <sys/param.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <iconv.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include "store.h"
#include "store-int.h"

#define BASE64_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
			"abcdefghijklmnopqrstuvwxyz" \
			"0123456789" \
			"+/="

static const struct {
	const char *name;
	enum cm_state state;
} cm_state_names[] = {
	{"NEED_KEY_PAIR", CM_NEED_KEY_PAIR},
	{"GENERATING_KEY_PAIR", CM_GENERATING_KEY_PAIR},
	{"NEED_KEY_GEN_PERMS", CM_NEED_KEY_GEN_PERMS},
	{"NEED_KEY_GEN_PIN", CM_NEED_KEY_GEN_PIN},
	{"NEED_KEY_GEN_TOKEN", CM_NEED_KEY_GEN_TOKEN},
	{"HAVE_KEY_PAIR", CM_HAVE_KEY_PAIR},
	{"NEED_KEYINFO", CM_NEED_KEYINFO},
	{"READING_KEYINFO", CM_READING_KEYINFO},
	{"NEED_KEYINFO_READ_PIN", CM_NEED_KEYINFO_READ_PIN},
	{"NEED_KEYINFO_READ_TOKEN", CM_NEED_KEYINFO_READ_TOKEN},
	{"HAVE_KEYINFO", CM_HAVE_KEYINFO},
	{"NEED_CSR", CM_NEED_CSR},
	{"GENERATING_CSR", CM_GENERATING_CSR},
	{"NEED_CSR_GEN_PIN", CM_NEED_CSR_GEN_PIN},
	{"NEED_CSR_GEN_TOKEN", CM_NEED_CSR_GEN_TOKEN},
	{"HAVE_CSR", CM_HAVE_CSR},
	{"NEED_SCEP_DATA", CM_NEED_SCEP_DATA},
	{"GENERATING_SCEP_DATA", CM_GENERATING_SCEP_DATA},
	{"NEED_SCEP_GEN_PIN", CM_NEED_SCEP_GEN_PIN},
	{"NEED_SCEP_GEN_TOKEN", CM_NEED_SCEP_GEN_TOKEN},
	{"NEED_SCEP_ENCRYPTION_CERT", CM_NEED_SCEP_ENCRYPTION_CERT},
	{"NEED_SCEP_RSA_CLIENT_KEY", CM_NEED_SCEP_RSA_CLIENT_KEY},
	{"HAVE_SCEP_DATA", CM_HAVE_SCEP_DATA},
	{"NEED_TO_SUBMIT", CM_NEED_TO_SUBMIT},
	{"SUBMITTING", CM_SUBMITTING},
	{"NEED_CA", CM_NEED_CA},
	{"CA_UNREACHABLE", CM_CA_UNREACHABLE},
	{"CA_UNCONFIGURED", CM_CA_UNCONFIGURED},
	{"CA_REJECTED", CM_CA_REJECTED},
	{"CA_WORKING", CM_CA_WORKING},
	{"NEED_TO_SAVE_CERT", CM_NEED_TO_SAVE_CERT},
	{"PRE_SAVE_CERT", CM_PRE_SAVE_CERT},
	{"START_SAVING_CERT", CM_START_SAVING_CERT},
	{"SAVING_CERT", CM_SAVING_CERT},
	{"NEED_CERTSAVE_PERMS", CM_NEED_CERTSAVE_PERMS},
	{"NEED_CERTSAVE_TOKEN", CM_NEED_CERTSAVE_TOKEN},
	{"NEED_CERTSAVE_PIN", CM_NEED_CERTSAVE_PIN},
	{"NEED_TO_READ_CERT", CM_NEED_TO_READ_CERT},
	{"READING_CERT", CM_READING_CERT},
	{"SAVED_CERT", CM_SAVED_CERT},
	{"POST_SAVED_CERT", CM_POST_SAVED_CERT},
	{"MONITORING", CM_MONITORING},
	{"NEED_TO_NOTIFY_VALIDITY", CM_NEED_TO_NOTIFY_VALIDITY},
	{"NOTIFYING_VALIDITY", CM_NOTIFYING_VALIDITY},
	{"NEED_TO_NOTIFY_REJECTION", CM_NEED_TO_NOTIFY_REJECTION},
	{"NOTIFYING_REJECTION", CM_NOTIFYING_REJECTION},
	{"NEED_TO_NOTIFY_ISSUED_SAVE_FAILED", CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED},
	{"NOTIFYING_ISSUED_SAVE_FAILED", CM_NOTIFYING_ISSUED_SAVE_FAILED},
	{"NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED", CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED},
	{"NOTIFYING_ISSUED_CA_SAVE_FAILED", CM_NOTIFYING_ISSUED_CA_SAVE_FAILED},
	{"NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED", CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED},
	{"NOTIFYING_ONLY_CA_SAVE_FAILED", CM_NOTIFYING_ONLY_CA_SAVE_FAILED},
	{"NEED_TO_SAVE_CA_CERTS", CM_NEED_TO_SAVE_CA_CERTS},
	{"NEED_TO_SAVE_ONLY_CA_CERTS", CM_NEED_TO_SAVE_ONLY_CA_CERTS},
	{"NEED_TO_NOTIFY_ISSUED_SAVED", CM_NEED_TO_NOTIFY_ISSUED_SAVED},
	{"NOTIFYING_ISSUED_SAVED", CM_NOTIFYING_ISSUED_SAVED},
	{"NEED_GUIDANCE", CM_NEED_GUIDANCE},
	{"NEWLY_ADDED", CM_NEWLY_ADDED},
	{"NEWLY_ADDED_START_READING_KEYINFO", CM_NEWLY_ADDED_START_READING_KEYINFO},
	{"NEWLY_ADDED_READING_KEYINFO", CM_NEWLY_ADDED_READING_KEYINFO},
	{"NEWLY_ADDED_NEED_KEYINFO_READ_PIN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN},
	{"NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN},
	{"NEWLY_ADDED_START_READING_CERT", CM_NEWLY_ADDED_START_READING_CERT},
	{"NEWLY_ADDED_READING_CERT", CM_NEWLY_ADDED_READING_CERT},
	{"NEWLY_ADDED_DECIDING", CM_NEWLY_ADDED_DECIDING},
	{"START_SAVING_CA_CERTS", CM_START_SAVING_CA_CERTS},
	{"SAVING_CA_CERTS", CM_SAVING_CA_CERTS},
	{"START_SAVING_ONLY_CA_CERTS", CM_START_SAVING_ONLY_CA_CERTS},
	{"SAVING_ONLY_CA_CERTS", CM_SAVING_ONLY_CA_CERTS},
	{"NEED_CA_CERT_SAVE_PERMS", CM_NEED_CA_CERT_SAVE_PERMS},
	{"NEED_ONLY_CA_CERT_SAVE_PERMS", CM_NEED_ONLY_CA_CERT_SAVE_PERMS},
	{"INVALID", CM_INVALID},
	/* old names for since-renamed states */
	{"NEED_TO_NOTIFY", CM_NEED_TO_NOTIFY_VALIDITY},
	{"NOTIFYING", CM_NOTIFYING_VALIDITY},
	{"NEWLY_ADDED_START_READING_KEYI", CM_NEWLY_ADDED_START_READING_KEYINFO},
	{"NEWLY_ADDED_READING_KEYI", CM_NEWLY_ADDED_READING_KEYINFO},
	{"NEWLY_ADDED_NEED_KEYI_READ_PIN", CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN},
	{"NEED_TO_NOTIFY_ISSUED_FAILED", CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED},
	{"NOTIFYING_ISSUED_FAILED", CM_NOTIFYING_ISSUED_SAVE_FAILED},
};

static const struct {
	const char *name;
	enum cm_ca_phase_state state;
} cm_ca_state_names[] = {
	{"IDLE", CM_CA_IDLE},
	{"NEED_TO_REFRESH", CM_CA_NEED_TO_REFRESH},
	{"REFRESHING", CM_CA_REFRESHING},
	{"UNREACHABLE", CM_CA_DATA_UNREACHABLE},
	{"NEED_TO_SAVE_DATA", CM_CA_NEED_TO_SAVE_DATA},
	{"PRE_SAVE_DATA", CM_CA_PRE_SAVE_DATA},
	{"START_SAVING_DATA", CM_CA_START_SAVING_DATA},
	{"SAVING_DATA", CM_CA_SAVING_DATA,},
	{"NEED_POST_SAVE_DATA", CM_CA_NEED_POST_SAVE_DATA},
	{"POST_SAVE_DATA", CM_CA_POST_SAVE_DATA},
	{"SAVED_DATA", CM_CA_SAVED_DATA},
	{"NEED_TO_ANALYZE", CM_CA_NEED_TO_ANALYZE},
	{"ANALYZING", CM_CA_ANALYZING},
	{"DISABLED", CM_CA_DISABLED},
};

static const struct {
	const char *name;
	enum cm_ca_phase phase;
} cm_ca_phase_names[] = {
	{"identify", cm_ca_phase_identify},
	{"certs", cm_ca_phase_certs},
	{"profiles", cm_ca_phase_profiles},
	{"default_profile", cm_ca_phase_default_profile},
	{"enrollment_reqs", cm_ca_phase_enroll_reqs},
	{"renewal_reqs", cm_ca_phase_renew_reqs},
	{"capabilities", cm_ca_phase_capabilities},
	{"encryption_certs", cm_ca_phase_encryption_certs},
	{"invalid", cm_ca_phase_invalid},
};

const char *
cm_store_ca_state_as_string(enum cm_ca_phase_state state)
{
	unsigned int i;

	for (i = 0;
	     i < sizeof(cm_ca_state_names) / sizeof(cm_ca_state_names[0]);
	     i++) {
		if (cm_ca_state_names[i].state == state) {
			return cm_ca_state_names[i].name;
		}
	}
	return "UNKNOWN";
}

const char *
cm_store_ca_phase_as_string(enum cm_ca_phase phase)
{
	unsigned int i;

	for (i = 0;
	     i < sizeof(cm_ca_phase_names) / sizeof(cm_ca_phase_names[0]);
	     i++) {
		if (cm_ca_phase_names[i].phase == phase) {
			return cm_ca_phase_names[i].name;
		}
	}
	return "invalid";
}

const char *
cm_store_state_as_string(enum cm_state state)
{
	unsigned int i;
	for (i = 0;
	     i < sizeof(cm_state_names) / sizeof(cm_state_names[0]);
	     i++) {
		if (cm_state_names[i].state == state) {
			return cm_state_names[i].name;
		}
	}
	return "UNKNOWN";
}

enum cm_ca_phase_state
cm_store_ca_state_from_string(const char *name)
{
	unsigned long l;
	unsigned i;
	char *p;

	for (i = 0;
	     i < sizeof(cm_ca_state_names) / sizeof(cm_ca_state_names[0]);
	     i++) {
		if (strcasecmp(cm_ca_state_names[i].name, name) == 0) {
			return cm_ca_state_names[i].state;
		}
	}
	l = strtoul(name, &p, 10);
	if ((*name != '\0') && (p != NULL) && (*p == '\0')) {
		return l;
	}
	return CM_CA_DISABLED;
}

enum cm_ca_phase
cm_store_ca_phase_from_string(const char *name)
{
	unsigned long l;
	unsigned int i;
	char *p;

	for (i = 0;
	     i < sizeof(cm_ca_phase_names) / sizeof(cm_ca_phase_names[0]);
	     i++) {
		if (strcasecmp(cm_ca_phase_names[i].name, name) == 0) {
			return cm_ca_phase_names[i].phase;
		}
	}
	l = strtoul(name, &p, 10);
	if ((*name != '\0') && (p != NULL) && (*p == '\0')) {
		return l;
	}
	return cm_ca_phase_invalid;
}

enum cm_state
cm_store_state_from_string(const char *name)
{
	unsigned long l;
	unsigned int i;
	char *p;

	for (i = 0;
	     i < sizeof(cm_state_names) / sizeof(cm_state_names[0]);
	     i++) {
		if (strcasecmp(cm_state_names[i].name, name) == 0) {
			return cm_state_names[i].state;
		}
	}
	l = strtoul(name, &p, 10);
	if ((*name != '\0') && (p != NULL) && (*p == '\0')) {
		return l;
	}
	return CM_INVALID;
}

char *
cm_store_maybe_strdup(void *parent, const char *s)
{
	if ((s != NULL) && (strlen(s) > 0)) {
		return talloc_strdup(parent, s);
	}
	return NULL;
}

char **
cm_store_maybe_strdupv(void *parent, char **s)
{
	int i;
	char **ret = NULL;
	for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
		continue;
	}
	if (i > 0) {
		ret = talloc_array_ptrtype(parent, ret, i + 1);
		if (ret != NULL) {
			for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
				ret[i] = talloc_strdup(ret, s[i]);
			}
			ret[i] = NULL;
		}
	}
	return ret;
}

/* Generic routines. */
struct cm_store_entry *
cm_store_entry_new(void *parent)
{
	struct cm_store_entry *entry;
	entry = talloc_ptrtype(parent, entry);
	if (entry != NULL) {
		memset(entry, 0, sizeof(*entry));
	}
	return entry;
}

struct cm_store_ca *
cm_store_ca_new(void *parent)
{
	struct cm_store_ca *ca;
	ca = talloc_ptrtype(parent, ca);
	if (ca != NULL) {
		memset(ca, 0, sizeof(*ca));
	}
	return ca;
}

static int
timestamp_field(const char *buf, int min, int max, int *value)
{
	size_t i;
	for (i = 0; buf[i] != '\0'; i++) {
		if (!isdigit((unsigned char) buf[i])) {
			return -1;
		}
	}
	*value = atoi(buf);
	if ((*value < min) || (*value > max)) {
		return -1;
	}
	return 0;
}

time_t
cm_store_time_from_timestamp(const char *timestamp)
{
	struct tm stamp;
	char buf[5];
	time_t t;
	int i, value;
	if (strlen(timestamp) < 12) {
		return 0;
	}
	memset(&stamp, 0, sizeof(stamp));
	if ((strlen(timestamp) == 14) || (strlen(timestamp) == 15)){
		memcpy(buf, timestamp, 4);
		i = 4;
		buf[i] = '\0';
		if (timestamp_field(buf, 0, 9999, &value) != 0) {
			return 0;
		}
		stamp.tm_year = value - 1900;
	} else {
		if ((strlen(timestamp) == 12) || (strlen(timestamp) == 13)) {
			memcpy(buf, timestamp, 2);
			i = 2;
			buf[i] = '\0';
			if (timestamp_field(buf, 0, 99, &value) != 0) {
				return 0;
			}
			stamp.tm_year = value;
			if (stamp.tm_year < 50) {
				stamp.tm_year += 100;
			}
		} else {
			return 0;
		}
	}
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	if (timestamp_field(buf, 1, 12, &value) != 0) {
		return 0;
	}
	stamp.tm_mon = value - 1;
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	if (timestamp_field(buf, 1, 31, &value) != 0) {
		return 0;
	}
	stamp.tm_mday = value;
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	if (timestamp_field(buf, 0, 23, &value) != 0) {
		return 0;
	}
	stamp.tm_hour = value;
	memcpy(buf, timestamp + i, 2);
	i += 2;
	buf[2] = '\0';
	if (timestamp_field(buf, 0, 59, &value) != 0) {
		return 0;
	}
	stamp.tm_min = value;
	memcpy(buf, timestamp + i, 2);
	buf[2] = '\0';
	if (timestamp_field(buf, 0, 60, &value) != 0) {
		return 0;
	}
	stamp.tm_sec = value;
	t = timegm(&stamp);
	return t;
}

char *
cm_store_timestamp_from_time(time_t when, char timestamp[15])
{
	struct tm tm;
	if ((when != 0) && (gmtime_r(&when, &tm) == &tm)) {
		snprintf(timestamp, 15, "%04hu%02hu%02hu%02hu%02hu%02hu",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		strcpy(timestamp, "19700101000000");
	}
	return timestamp;
}

char *
cm_store_local_timestamp_from_time_for_display(time_t when)
{
	char *timestamp;
	struct tm tm;
	size_t len;
	tzset();
	if ((when != 0) && (localtime_r(&when, &tm) == &tm)) {
		len = 24 + strlen(tm.tm_zone);
		timestamp = malloc(len);
		if (timestamp != NULL) {
			snprintf(timestamp, len,
				"%04hu-%02hu-%02hu %02hu:%02hu:%02hu %s",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_zone);
		}
	} else {
		timestamp = malloc(24);
		if (timestamp != NULL) {
			strcpy(timestamp, "1970-01-01 00:00:00 UTC");
		}
	}
	return timestamp;
}

char *
cm_store_timestamp_from_time_for_display(time_t when, char timestamp[25])
{
	struct tm tm;
	if ((when != 0) && (gmtime_r(&when, &tm) == &tm)) {
		snprintf(timestamp, 25, "%04hu-%02hu-%02hu %02hu:%02hu:%02hu UTC",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else {
		strcpy(timestamp, "1970-01-01 00:00:00 UTC");
	}
	return timestamp;
}

char *
cm_store_increment_serial(void *parent, const char *old_serial)
{
	char *tmp, *serial;
	int len, i;
	if ((old_serial == NULL) || (strlen(old_serial) < 2)) {
		return talloc_strdup(parent, "01");
	}
	tmp = talloc_strdup(parent, old_serial);
	len = strlen(tmp);
	for (i = len - 1; i >= 0; i--) {
		switch (tmp[i]) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
			tmp[i]++;
			break;
		case '9':
			tmp[i] = 'A';
			break;
		case 'F':
		case 'f':
			tmp[i] = '0';
			/* carry */
			continue;
			break;
		}
		/* stop */
		break;
	}
	if (i < 0) {
		/* ran out of digits, need to prepend another byte */
		serial = talloc_asprintf(parent, "01%s", tmp);
		talloc_free(tmp);
	} else {
		if (strchr("89abcdefABCDEF", tmp[0]) != NULL) {
			/* prepend a zero byte to keep it unsigned */
			serial = talloc_asprintf(parent, "00%s", tmp);
			talloc_free(tmp);
		} else {
			/* ok as is */
			serial = tmp;
		}
	}
	return serial;
}

/* Produce a hex representation of the binary data. */
char *
cm_store_hex_from_bin(void *parent, const unsigned char *serial, int length)
{
	const char *hexchars = "0123456789ABCDEF";
	char *ret;
	int i;

	if (length < 0) {
		length = strlen((const char *) serial);
	}
	ret = talloc_zero_size(parent, length * 2 + 1);
	for (i = 0; i < length; i++) {
		ret[i * 2] = hexchars[(serial[i] >> 4) & 0x0f];
		ret[i * 2 + 1] = hexchars[(serial[i]) & 0x0f];
	}
	ret[i * 2] = '\0';
	return ret;
}

/* Produce a hex representation of the hex serial number encoded as a DER
 * integer. XXX has an upper limit on the length. */
char *
cm_store_serial_to_der(void *parent, const char *serial)
{
	const char *hexchars = "0123456789ABCDEF";
	char *ret;
	int length;
	length = strlen(serial);
	ret = talloc_zero_size(parent, length + 5);
	ret[0] = '0';
	ret[1] = '2';
	ret[2] = hexchars[((length / 2) >> 4) & 0x0f];
	ret[3] = hexchars[(length / 2) & 0x0f];
	strcpy(ret + 4, serial);
	return ret;
}

/* Convert hex chars to fill a buffer.  Input characters which don't belong are
 * treated as zeros.  We stop when we run out of input characters or run out of
 * space in the output buffer. */
int
cm_store_hex_to_bin(const char *serial, unsigned char *buf, int length)
{
	const char *p, *q, *chars = "0123456789abcdef";
	unsigned char *b, u;

	u = 0;
	for (p = serial, b = buf;
	     ((*p != '\0') && ((b - buf) < length));
	     p++) {
		switch ((p - serial) % 2) {
		case 0:
			q = strchr(chars, tolower(*p));
			if (q == NULL) {
				q = strchr(chars, toupper(*p));
			}
			u = q ? q - chars : 0;
			break;
		case 1:
			q = strchr(chars, tolower(*p));
			if (q == NULL) {
				q = strchr(chars, toupper(*p));
			}
			u = (u << 4) | (q ? q - chars : 0);
			*b++ = u;
			break;
		}
	}
	return b - buf;
}

char *
cm_store_canonicalize_path(void *parent, const char *path)
{
	char *tmp = NULL, *p, *q, buf[PATH_MAX], *prefix;
	int i;

	if (strncmp(path, "dbm:", 4) == 0) {
		prefix = "dbm";
		path += 4;
	} else
	if (strncmp(path, "sql:", 4) == 0) {
		prefix = "sql";
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		prefix = "rdb";
		path += 4;
	} else
	if (strncmp(path, "extern:", 4) == 0) {
		prefix = "extern";
		path += 7;
	} else {
		prefix = NULL;
	}
	i = strlen(path);
	if (i > 1) {
		while ((i > 1) && (path[i - 1] == '/')) {
			i--;
		}
		tmp = talloc_strndup(parent, path, i);
	} else {
		tmp = talloc_strdup(parent, path);
	}
	if ((tmp != NULL) && (tmp[0] != '/')) {
		memset(buf, '\0', sizeof(buf));
		if (getcwd(buf, sizeof(buf) - 1) != NULL) {
			tmp = talloc_asprintf(parent, "%s//%s", buf, tmp);
		}
	}
	if (tmp != NULL) {
		for (p = tmp; *p != '\0'; p++) {
			if ((strncmp(p, "/", 1) == 0) &&
			    ((p[1] == '/') || (p[1] == '\0'))) {
				memmove(p, p + 1, strlen(p + 1) + 1);
			}
		}
		for (p = tmp; *p != '\0'; p++) {
			if ((strncmp(p, "/.", 2) == 0) &&
			    ((p[2] == '/') || (p[2] == '\0'))) {
				memmove(p, p + 2, strlen(p + 2) + 1);
			}
		}
		for (p = tmp; *p != '\0'; p++) {
			if ((strncmp(p, "/..", 3) == 0) &&
			    ((p[3] == '/') || (p[3] == '\0'))) {
				q = p - 1;
				while ((q >= tmp) && (*q != '/')) {
					q--;
				}
				if (*q == '/') {
					memmove(q, p + 3, strlen(p + 3) + 1);
				} else {
					break;
				}
			}
		}
		if (prefix != NULL) {
			tmp = talloc_asprintf(parent, "%s:%s", prefix, tmp);
		}
	}
	return tmp;
}

void
cm_store_set_if_not_set_s(void *parent, char **dest, char *src)
{
	if ((*dest == NULL) && (src != NULL) && (strlen(src) > 0)) {
		*dest = talloc_strdup(parent, src);
	}
}

void
cm_store_set_if_not_set_as(void *parent, char ***dest, char **src)
{
	int i, j;
	char **ret;
	if (*dest == NULL) {
		for (i = 0; (src != NULL) && (src[i] != NULL); i++) {
			continue;
		}
		if (i > 0) {
			ret = talloc_zero_size(parent,
					       sizeof(char *) * (i + 1));
			if (ret != NULL) {
				for (j = 0; j < i; j++) {
					ret[j] = talloc_strdup(ret, src[j]);
					if (ret[j] == NULL) {
						/* Out of space? */
						break;
					}
				}
				ret[j] = NULL;
				if (i != j) {
					/* Out of space? */
					ret = NULL;
				}
			}
			*dest = ret;
		}
	}
}

int
cm_store_utf8_to_bmp_string(char *s,
			    unsigned char **bmp,
			    unsigned int *len)
{
	iconv_t conv;
	unsigned int i;
	const unsigned char *u;
	uint16_t *u16;
	char *inbuf, *outbuf;
	size_t inleft, outleft, res, space;

	*bmp = NULL;
	conv = iconv_open("UTF16BE", "UTF8");
	if (conv != NULL) {
		inbuf = s;
		space = strlen(s) * 4;
		*bmp = malloc(space);
		outbuf = (char *) *bmp;
		if (outbuf == NULL) {
			iconv_close(conv);
			return -1;
		}
		memset(*bmp, 0, space);
		inleft = strlen(s);
		outleft = space;
		res = iconv(conv, &inbuf, &inleft, &outbuf, &outleft);
		iconv_close(conv);
		switch (res) {
		case (size_t) -1:
			return -1;
			break;
		default:
			*len = space - outleft;
			return 0;
			break;
		}
	} else {
		/* Impressively wrong. */
		u16 = malloc((strlen(s) + 1) * 2);
		if (u16 == NULL) {
			return -1;
		}
		u = (const unsigned char *) s;
		for (i = 0; u[i] != '\0'; i++) {
			u16[i] = htons(u[i]);
		}
		*bmp = (unsigned char *) u16;
		*len = i * 2;
	}
	return 0;
}

char *
cm_store_utf8_from_bmp_string(unsigned char *bmp, unsigned int len)
{
	iconv_t conv;
	char *inbuf, *outbuf, *s;
	size_t inleft, outleft, res, space;

	conv = iconv_open("UTF8", "UTF16BE");
	if (conv != NULL) {
		inbuf = (char *) bmp;
		space = len * 3;
		s = malloc(space);
		outbuf = s;
		if (outbuf == NULL) {
			iconv_close(conv);
			return NULL;
		}
		memset(s, '\0', space);
		inleft = len;
		outleft = space;
		res = iconv(conv, &inbuf, &inleft, &outbuf, &outleft);
		iconv_close(conv);
		switch (res) {
		case (size_t) -1:
			free(s);
			return NULL;
			break;
		default:
			return s;
			break;
		}
	}
	return NULL;
}

char *
cm_store_base64_from_bin(void *parent, const unsigned char *buf, int length)
{
	char *p, *ret;
	int max, i, j;
	uint32_t acc;

	if (length < 0) {
		length = strlen((const char *) buf);
	}

	max = 4 * howmany(length, 3) + 1;
	p = malloc(max);
	if (p == NULL) {
		return NULL;
	}

	for (i = 0, j = 0, acc = 0; i < length; i++) {
		acc = (acc << 8) | buf[i];
		if ((i % 3) == 2) {
			p[j++] = BASE64_ALPHABET[(acc >> 18) & 0x3f];
			p[j++] = BASE64_ALPHABET[(acc >> 12) & 0x3f];
			p[j++] = BASE64_ALPHABET[(acc >>  6) & 0x3f];
			p[j++] = BASE64_ALPHABET[(acc >>  0) & 0x3f];
			acc = 0;
		}
	}
	switch (i % 3) {
	case 0:
		break;
	case 1:
		acc = (acc << 8) | 0;
		acc = (acc << 8) | 0;
		p[j++] = BASE64_ALPHABET[(acc >> 18) & 0x3f];
		p[j++] = BASE64_ALPHABET[(acc >> 12) & 0x3f];
		p[j++] = '=';
		p[j++] = '=';
		break;
	case 2:
		acc = (acc << 8) | 0;
		p[j++] = BASE64_ALPHABET[(acc >> 18) & 0x3f];
		p[j++] = BASE64_ALPHABET[(acc >> 12) & 0x3f];
		p[j++] = BASE64_ALPHABET[(acc >>  6) & 0x3f];
		p[j++] = '=';
		break;
	}
	p[j++] = '\0';

	ret = talloc_strdup(parent, p);
	free(p);
	return ret;
}

int
cm_store_base64_to_bin(const char *serial, int insize,
		       unsigned char *buf, int length)
{
	const char *p, *q, *chars = BASE64_ALPHABET;
	unsigned char *b;
	uint32_t u, count;

	u = 0;
	count = 0;
	if (insize < 0) {
		insize = strlen(serial);
	}
	for (p = serial, b = buf;
	     (((p - serial) < insize) && (*p != '\0') && (*p != '=') &&
	      ((b - buf) < length));
	     p++) {
		q = strchr(chars, *p);
		if (q != NULL) {
			switch (count % 4) {
			case 0:
				u = q - chars;
				break;
			case 1:
				u = (u << 6) | (q - chars);
				break;
			case 2:
				u = (u << 6) | (q - chars);
				break;
			case 3:
				u = (u << 6) | (q - chars);
				*b++ = (u >> 16) & 0xff;
				if (b - buf >= length) {
					break;
				}
				*b++ = (u >>  8) & 0xff;
				if (b - buf >= length) {
					break;
				}
				*b++ = (u >>  0) & 0xff;
				u = 0;
				break;
			}
			count++;
		}
	}
	switch (count % 4) {
	case 0:
	case 1:
		break;
	case 2:
		u = (u << 12);
		*b++ = (u >> 16) & 0xff;
		break;
	case 3:
		u = (u <<  6);
		*b++ = (u >> 16) & 0xff;
		if (b - buf >= length) {
			break;
		}
		*b++ = (u >>  8) & 0xff;
		break;
	}
	return b - buf;
}

char *
cm_store_base64_as_bin(void *parent, const char *serial, int size, int *length)
{
	unsigned char *buf;
	ssize_t l;

	if (size < 0) {
		size = strlen(serial);
	}
	l = howmany(size, 4) * 3 + 1;
	buf = talloc_size(parent, l);
	if (buf != NULL) {
		l = cm_store_base64_to_bin(serial, size, buf, l - 1);
		buf[l] = '\0';
		if (length != NULL) {
			*length = l;
		}
	}
	return (char *) buf;
}

char *
cm_store_base64_from_hex(void *parent, const char *s)
{
	unsigned char *buf;
	char *ret;
	unsigned int length;

	length = strlen(s) / 2;
	buf = malloc(length);
	if (buf == NULL) {
		return NULL;
	}
	length = cm_store_hex_to_bin(s, buf, length);
	ret = cm_store_base64_from_bin(parent, buf, length);
	free(buf);
	return ret;
}
