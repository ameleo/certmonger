/*
 * Copyright (C) 2009,2010,2011,2012 Red Hat, Inc.
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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <krb5.h>

#ifdef HAVE_UUID
#if defined(HAVE_UUID_H)
#include <uuid.h>
#elif defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#endif
#endif

#include "log.h"
#include "submit-u.h"

#define BASE64_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
			"abcdefghijklmnopqrstuvwxyz" \
			"0123456789" \
			"+/="

static char *
my_stpcpy(char *dest, const char *src)
{
	size_t len;
	len = strlen(src);
	memcpy(dest, src, len);
	dest[len] = '\0';
	return dest + len;
}

/* Read submission data from a file or stdin. */
char *
cm_submit_u_from_file(const char *filename)
{
	char *csr;
	size_t len;

	if (filename != NULL && strcmp(filename, "-") != 0) {
		FILE *fp;
		struct stat st;

		fp = fopen(filename, "r");
		if (fp == NULL) {
			fprintf(stderr, "Error opening \"%s\": %s.\n",
				filename, strerror(errno));
			return NULL;
		}
		if (fstat(fileno(fp), &st) != 0) {
			fprintf(stderr, "Error reading \"%s\": %s.\n",
				filename, strerror(errno));
			fclose(fp);
			return NULL;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "Error reading \"%s\": not a regular file.\n",
				filename);
			fclose(fp);
			return NULL;
		}
		/* +2: room to append trailing newline (if absent) and NUL */
		csr = malloc((size_t)st.st_size + 2);
		if (csr == NULL) {
			fclose(fp);
			return NULL;
		}
		len = fread(csr, 1, (size_t)st.st_size, fp);
		fclose(fp);
	} else {
		char *p;
		size_t alloc, n;

		alloc = BUFSIZ;
		csr = malloc(alloc);
		if (csr == NULL) {
			return NULL;
		}
		len = 0;
		while ((n = fread(csr + len, 1, alloc - len - 1, stdin)) > 0) {
			len += n;
			if (len + 2 >= alloc) {
				if (alloc > SIZE_MAX / 2) {
					free(csr);
					return NULL;
				}
				alloc *= 2;
				p = realloc(csr, alloc);
				if (p == NULL) {
					free(csr);
					return NULL;
				}
				csr = p;
			}
		}
	}

	if (len == 0 || memchr(csr, '\0', len) != NULL) {
		free(csr);
		return NULL;
	}
	if (csr[len - 1] != '\n') {
		csr[len++] = '\n';
	}
	csr[len] = '\0';
	return csr;
}

/* Read a CSR from a file and return it as a single base64 blob. */
char *
cm_submit_u_from_file_single(const char *filename)
{
	char *csr, *p, *q;
	unsigned int i;
	const char *strip[] = {
		"-----BEGIN CERTIFICATE REQUEST-----",
		"-----END CERTIFICATE REQUEST-----",
		"-----BEGIN NEW CERTIFICATE REQUEST-----",
		"-----END NEW CERTIFICATE REQUEST-----",
	};
	csr = cm_submit_u_from_file(filename);
	if (csr == NULL) {
		return NULL;
	}
	for (i = 0; i < sizeof(strip) / sizeof(strip[0]); i++) {
		while ((p = strstr(csr, strip[i])) != NULL) {
			q = p + strcspn(p, "\r\n");
			memmove(p, q, strlen(q) + 1);
		}
	}
	q = strdup(csr);
	for (p = csr, i = 0; *p != '\0'; p++) {
		if (strchr("\r\n\t ", *p) == NULL) {
			q[i++] = *p;
		}
	}
	q[i] = '\0';
	free(csr);
	return q;
}

/* Return a simple base64 string from a data item in PEM format or already in
 * simple base64 format. */
char *
cm_submit_u_base64_from_text(const char *base64_or_pem)
{
	const char *p, *q;
	char *ret, *s;
	int i;
	p = strstr(base64_or_pem, "-----BEGIN");
	if (p != NULL) {
		q = p + 10;
		q += strcspn(q, "-");
		p = q + strcspn(q, "\r\n");
		q = strstr(p, "-----END");
		if (q != NULL) {
			ret = malloc(q - p + 1);
			if (ret != NULL) {
				s = ret;
				for (i = 0; i < (q - p); i++) {
					if (strchr(BASE64_ALPHABET, p[i])) {
						*s++ = p[i];
					}
				}
				*s++ = '\0';
			}
		} else {
			ret = NULL;
		}
		return ret;
	} else {
		p = base64_or_pem;
		ret = malloc(strlen(p) + 1);
		if (ret != NULL) {
			s = ret;
			for (i = 0; p[i] != '\0'; i++) {
				if (strchr(BASE64_ALPHABET, p[i])) {
					*s++ = p[i];
				}
			}
			*s++ = '\0';
		}
		return ret;
	}
}

char *
cm_submit_u_pem_from_base64(const char *what, int dos, const char *base64)
{
	char *ret, *tmp, *p;
	const char *q;
	int i;
	const unsigned int width = 64;

	tmp = strdup(base64);
	if (tmp == NULL) {
		return NULL;
	}
	for (p = tmp, q = base64; *q != '\0'; q++) {
		if (strchr(BASE64_ALPHABET, *q)) {
			*p++ = *q;
		}
	}
	*p = '\0';
	i = strlen("-----BEGIN -----\r\n"
		   "-----END -----\r\n") +
		   strlen(what) * 2 +
		   strlen(tmp) +
		   howmany(strlen(tmp), width) * 2;
	ret = malloc(i + 1);
	if (ret != NULL) {
		p = my_stpcpy(ret, "-----BEGIN ");
		p = my_stpcpy(p, what);
		p = my_stpcpy(p, dos ? "-----\r\n" : "-----\n");
		q = tmp;
		while (strlen(q) > width) {
			memcpy(p, q, width);
			p += width;
			q += width;
			p = my_stpcpy(p, dos ? "\r\n" : "\n");
		}
		if (strlen(q) > 0) {
			p = my_stpcpy(p, q);
			p = my_stpcpy(p, dos ? "\r\n" : "\n");
		}
		p = my_stpcpy(p, "-----END ");
		p = my_stpcpy(p, what);
		strcpy(p, dos ? "-----\r\n" : "-----\n");
	}
	free(tmp);
	return ret;
}

char *
cm_submit_princ_realm_data(krb5_context ctx, krb5_principal princ)
{
#if HAVE_DECL_KRB5_PRINC_COMPONENT
	return (krb5_princ_realm(ctx, princ))->data;
#else
	return princ->realm;
#endif
}

int
cm_submit_princ_realm_len(krb5_context ctx, krb5_principal princ)
{
#if HAVE_DECL_KRB5_PRINC_COMPONENT
	return (krb5_princ_realm(ctx, princ))->length;
#else
	return strlen(princ->realm);
#endif
}

char *
cm_submit_u_url_encode(const char *plain)
{
	const char *hexchars = "0123456789ABCDEF";
	const char *unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				 "abcdefghijklmnopqrstuvwxyz"
				 "0123456789-_.~";
	char *ret = malloc(strlen(plain) * 3 + 1);
	int i, j;
	unsigned int c;

	if (ret != NULL) {
		for (i = 0, j = 0; plain[i] != '\0'; i++) {
			c = ((unsigned char) plain[i]) & 0xff;
			if (strchr(unreserved, c) != NULL) {
				ret[j++] = plain[i];
			} else {
				if (c == 32) {
					ret[j++] = '+';
				} else {
					ret[j++] = '%';
					ret[j++] = hexchars[(c & 0xf0) >> 4];
					ret[j++] = hexchars[(c & 0x0f)];
				}
			}
		}
		ret[j] = '\0';
	}
	return ret;
}

#ifdef HAVE_UUID
int cm_submit_uuid_fixed_for_testing = 0;
int
cm_submit_uuid_new(unsigned char uuid[16])
{
	uuid_t res;
	uuid_clear(res);
	if (cm_submit_uuid_fixed_for_testing) {
		int i;
		for (i = 0; i < 16; i++) {
			res[i] = i + 1;
		}
	} else {
		uuid_generate(res);
	}
	if (uuid_is_null(res)) {
		return -1;
	}
	/* For whatever reason, NSS assumes that any of the final bits which
	 * are clear are unused rather than simply set to zero, so we force the
	 * least significant bit to 1 to preserve the entire (hopefully still
	 * unique) UUID. */
	res[15] |= 1;
	memcpy(uuid, res, 16);
	return 0;
}
#endif

/* Convert a delta string to a time_t. */
int
cm_submit_u_delta_from_string(const char *deltas, time_t now, time_t *delta)
{
	struct tm now_tm, *pnow;
	time_t start, val;
	int multiple, i, done, digits;
	unsigned char c;
	val = 0;
	digits = 0;
	done = 0;
	if (strlen(deltas) == 0) {
		return -1;
	}
	start = now;
	for (i = 0; !done; i++) {
		c = (unsigned char) deltas[i];
		switch (c) {
		case '\0':
			done++;
			/* fall through */
		case 's':
			multiple = 1;
			now += val * multiple;
			val = 0;
			break;
		case 'm':
			multiple = 60;
			now += val * multiple;
			val = 0;
			break;
		case 'h':
			multiple = 60 * 60;
			now += val * multiple;
			val = 0;
			break;
		case 'd':
			multiple = 60 * 60 * 24;
			now += val * multiple;
			val = 0;
			break;
		case 'w':
			multiple = 60 * 60 * 24 * 7;
			now += val * multiple;
			val = 0;
			break;
		case 'M':
			pnow = localtime_r(&now, &now_tm);
			if (pnow == NULL) {
				multiple = 60 * 60 * 24 * 30;
				now += val * multiple;
			} else {
				now_tm.tm_mon += val;
				now_tm.tm_year += (now_tm.tm_mon / 12);
				now_tm.tm_mon %= 12;
				now_tm.tm_isdst = -1; /* don't tell libc that
						       * we "know" what's up
						       * with DST for the time
						       * in this structure */
				now = mktime(&now_tm);
			}
			val = 0;
			break;
		case 'y':
			pnow = localtime_r(&now, &now_tm);
			if (pnow == NULL) {
				multiple = 60 * 60 * 24 * 365;
				now += val * multiple;
			} else {
				now_tm.tm_year += val;
				now = mktime(&now_tm);
			}
			val = 0;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = (val * 10) + (c - '0');
			digits++;
			break;
		default:
			/* just skip this character */
			break;
		}
	}
	if (digits == 0) {
		return -1;
	}
	*delta = now + val - start;
	return 0;
}
