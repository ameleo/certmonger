/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015,2017 Red Hat, Inc.
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
#include <glob.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <dbus/dbus.h>
#include <talloc.h>

#include <krb5.h>

#ifdef HAVE_UUID
#if defined(HAVE_UUID_H)
#include <uuid.h>
#elif defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#endif
#endif

#ifdef HAVE_GMP
#include <gmp.h>
#endif

#include "env.h"
#include "store.h"
#include "store-int.h"
#include "submit-e.h"
#include "submit-u.h"
#include "log.h"
#include "tm.h"

static unsigned long long cm_entry_name_last, cm_ca_name_last;


enum cm_store_file_field {
	cm_store_file_field_invalid = 0,
	cm_store_file_field_id,

	cm_store_entry_field_key_type,
	cm_store_entry_field_key_gen_type,
	cm_store_entry_field_key_size,
	cm_store_entry_field_key_gen_size,

	cm_store_entry_field_key_next_type,
	cm_store_entry_field_key_next_gen_type,
	cm_store_entry_field_key_next_size,
	cm_store_entry_field_key_next_gen_size,

	cm_store_entry_field_key_preserve,
	cm_store_entry_field_key_next_marker,

	cm_store_entry_field_key_storage_type,
	cm_store_entry_field_key_storage_location,
	cm_store_entry_field_key_token,
	cm_store_entry_field_key_nickname,
	cm_store_entry_field_key_pin,
	cm_store_entry_field_key_pin_file,
	cm_store_entry_field_key_owner,
	cm_store_entry_field_key_perms,
	cm_store_entry_field_key_pubkey,
	cm_store_entry_field_key_pubkey_info,

	cm_store_entry_field_key_next_pubkey,
	cm_store_entry_field_key_next_pubkey_info,

	cm_store_entry_field_key_generated_date,
	cm_store_entry_field_key_next_generated_date,
	cm_store_entry_field_key_requested_count,
	cm_store_entry_field_key_next_requested_count,
	cm_store_entry_field_key_issued_count,

	cm_store_entry_field_cert_storage_type,
	cm_store_entry_field_cert_storage_location,
	cm_store_entry_field_cert_token,
	cm_store_entry_field_cert_nickname,
	cm_store_entry_field_cert_owner,
	cm_store_entry_field_cert_perms,

	cm_store_entry_field_nss_user,

	cm_store_entry_field_cert_issuer_der,
	cm_store_entry_field_cert_issuer,
	cm_store_entry_field_cert_serial,
	cm_store_entry_field_cert_subject_der,
	cm_store_entry_field_cert_subject,
	cm_store_entry_field_cert_spki,
	cm_store_entry_field_cert_not_before,
	cm_store_entry_field_cert_not_after,
	cm_store_entry_field_cert_hostname,
	cm_store_entry_field_cert_email,
	cm_store_entry_field_cert_principal,
	cm_store_entry_field_cert_ipaddress,
	cm_store_entry_field_cert_ku,
	cm_store_entry_field_cert_eku,
	cm_store_entry_field_cert_is_ca,
	cm_store_entry_field_cert_ca_path_length,
	cm_store_entry_field_cert_crl_distribution_point,
	cm_store_entry_field_cert_freshest_crl,
	cm_store_entry_field_cert_ocsp_location,
	cm_store_entry_field_cert_ns_comment,
	cm_store_entry_field_cert_profile,
	cm_store_entry_field_cert_no_ocsp_check,
	cm_store_entry_field_cert_ns_certtype,

	cm_store_entry_field_last_expiration_check,
	cm_store_entry_field_last_need_notify_check,
	cm_store_entry_field_last_need_enroll_check,

	cm_store_entry_field_template_subject_der,
	cm_store_entry_field_template_subject,
	cm_store_entry_field_template_hostname,
	cm_store_entry_field_template_email,
	cm_store_entry_field_template_principal,
	cm_store_entry_field_template_ipaddress,
	cm_store_entry_field_template_ku,
	cm_store_entry_field_template_eku,
	cm_store_entry_field_template_is_ca,
	cm_store_entry_field_template_ca_path_length,
	cm_store_entry_field_template_crl_distribution_point,
	cm_store_entry_field_template_freshest_crl,
	cm_store_entry_field_template_ocsp_location,
	cm_store_entry_field_template_ns_comment,
	cm_store_entry_field_template_profile,
	cm_store_entry_field_template_issuer,
	cm_store_entry_field_template_certificate_template,
	cm_store_entry_field_template_no_ocsp_check,
	cm_store_entry_field_template_ns_certtype,

	cm_store_entry_field_challenge_password,
	cm_store_entry_field_challenge_password_file,

	cm_store_entry_field_csr,
	cm_store_entry_field_spkac,
	cm_store_entry_field_scep_tx,
	cm_store_entry_field_scep_nonce,
	cm_store_entry_field_scep_last_nonce,
	cm_store_entry_field_scep_gic,
	cm_store_entry_field_scep_gic_next,
	cm_store_entry_field_scep_req,
	cm_store_entry_field_scep_req_next,
	cm_store_entry_field_minicert,

	cm_store_entry_field_state,

	cm_store_entry_field_autorenew,
	cm_store_entry_field_monitor,

	cm_store_entry_field_ca_nickname,

	cm_store_entry_field_submitted,
	cm_store_entry_field_ca_cookie,
	cm_store_entry_field_ca_error,

	cm_store_entry_field_cert,
	cm_store_entry_field_cert_chain,
	cm_store_entry_field_cert_roots,

	cm_store_entry_field_pre_certsave_command,
	cm_store_entry_field_pre_certsave_uid,
	cm_store_entry_field_post_certsave_command,
	cm_store_entry_field_post_certsave_uid,

	cm_store_entry_field_root_cert_files,
	cm_store_entry_field_other_root_cert_files,
	cm_store_entry_field_other_cert_files,
	cm_store_entry_field_root_cert_nssdbs,
	cm_store_entry_field_other_root_cert_nssdbs,
	cm_store_entry_field_other_cert_nssdbs,

	cm_store_ca_field_aka,
	cm_store_ca_field_known_issuer_names,
	cm_store_ca_field_is_default,

	cm_store_ca_field_type,
	cm_store_ca_field_internal_serial,
	cm_store_ca_field_internal_issue_time,
	cm_store_ca_field_external_helper,

	cm_store_ca_field_root_certs,
	cm_store_ca_field_other_root_certs,
	cm_store_ca_field_other_certs,

	cm_store_ca_field_required_enroll_attributes,
	cm_store_ca_field_required_renewal_attributes,
	cm_store_ca_field_profiles,
	cm_store_ca_field_default_profile,

	cm_store_ca_field_pre_save_command,
	cm_store_ca_field_pre_save_uid,
	cm_store_ca_field_post_save_command,
	cm_store_ca_field_post_save_uid,

	cm_store_ca_field_root_cert_files,
	cm_store_ca_field_other_root_cert_files,
	cm_store_ca_field_other_cert_files,
	cm_store_ca_field_root_cert_nssdbs,
	cm_store_ca_field_other_root_cert_nssdbs,
	cm_store_ca_field_other_cert_nssdbs,

	cm_store_ca_field_capabilities,
	cm_store_ca_field_scep_cipher,
	cm_store_ca_field_scep_digest,
	cm_store_ca_field_scep_ca_identifier,
	cm_store_ca_field_encryption_cert,
	cm_store_ca_field_encryption_issuer_cert,
	cm_store_ca_field_encryption_cert_pool,

	cm_store_file_field_invalid_high,
};
static struct cm_store_file_field_list {
	enum cm_store_file_field field;
	const char *name;
} cm_store_file_field_list[] = {
	{cm_store_file_field_id, "id"}, /* ipa-client-install assumes that we'll
					 * never rename this, so now we can't */
	{cm_store_entry_field_key_type, "key_type"},
	{cm_store_entry_field_key_gen_type, "key_gen_type"},
	{cm_store_entry_field_key_size, "key_size"},
	{cm_store_entry_field_key_gen_size, "key_gen_size"},

	{cm_store_entry_field_key_next_type, "key_next_type"},
	{cm_store_entry_field_key_next_gen_type, "key_next_gen_type"},
	{cm_store_entry_field_key_next_size, "key_next_size"},
	{cm_store_entry_field_key_next_gen_size, "key_next_gen_size"},

	{cm_store_entry_field_key_preserve, "key_preserve"},
	{cm_store_entry_field_key_next_marker, "key_next_marker"},

	{cm_store_entry_field_key_generated_date, "key_generated_date"},
	{cm_store_entry_field_key_next_generated_date, "key_next_generated_date"},
	{cm_store_entry_field_key_requested_count, "key_requested_count"},
	{cm_store_entry_field_key_next_requested_count, "key_next_requested_count"},
	{cm_store_entry_field_key_issued_count, "key_issued_count"},

	{cm_store_entry_field_key_storage_type, "key_storage_type"},
	{cm_store_entry_field_key_storage_location, "key_storage_location"},
	{cm_store_entry_field_key_token, "key_token"},
	{cm_store_entry_field_key_nickname, "key_nickname"},
	{cm_store_entry_field_key_pin, "key_pin"},
	{cm_store_entry_field_key_pin_file, "key_pin_file"},
	{cm_store_entry_field_key_owner, "key_owner"},
	{cm_store_entry_field_key_perms, "key_perms"},
	{cm_store_entry_field_key_pubkey, "key_pubkey"},
	{cm_store_entry_field_key_pubkey_info, "key_pubkey_info"},

	{cm_store_entry_field_key_next_pubkey, "key_next_pubkey"},
	{cm_store_entry_field_key_next_pubkey_info, "key_next_pubkey_info"},

	{cm_store_entry_field_cert_storage_type, "cert_storage_type"},
	{cm_store_entry_field_cert_storage_location, "cert_storage_location"},
	{cm_store_entry_field_cert_token, "cert_token"},
	{cm_store_entry_field_cert_nickname, "cert_nickname"},
	{cm_store_entry_field_cert_owner, "cert_owner"},
	{cm_store_entry_field_cert_perms, "cert_perms"},

	{cm_store_entry_field_nss_user, "nss_user"},

	{cm_store_entry_field_cert_issuer_der, "cert_issuer_der"},
	{cm_store_entry_field_cert_issuer, "cert_issuer"},
	{cm_store_entry_field_cert_serial, "cert_serial"},
	{cm_store_entry_field_cert_subject_der, "cert_subject_der"},
	{cm_store_entry_field_cert_subject, "cert_subject"},
	{cm_store_entry_field_cert_spki, "cert_spki"},
	{cm_store_entry_field_cert_not_before, "cert_not_before"}, /* right */
	{cm_store_entry_field_cert_not_before, "cert_issued"}, /* so wrong */
	{cm_store_entry_field_cert_not_after, "cert_not_after"}, /* right */
	{cm_store_entry_field_cert_not_after, "cert_expiration"}, /* wrong */
	{cm_store_entry_field_cert_hostname, "cert_hostname"},
	{cm_store_entry_field_cert_email, "cert_email"},
	{cm_store_entry_field_cert_principal, "cert_principal"},
	{cm_store_entry_field_cert_ipaddress, "cert_ipaddress"},
	{cm_store_entry_field_cert_ku, "cert_ku"},
	{cm_store_entry_field_cert_eku, "cert_eku"},
	{cm_store_entry_field_cert_is_ca, "cert_is_ca"},
	{cm_store_entry_field_cert_ca_path_length, "cert_ca_path_length"},
	{cm_store_entry_field_cert_crl_distribution_point, "cert_crldp"},
	{cm_store_entry_field_cert_freshest_crl, "cert_freshest_crl"},
	{cm_store_entry_field_cert_ocsp_location, "cert_ocsp"},
	{cm_store_entry_field_cert_ns_comment, "cert_ns_comment"},
	{cm_store_entry_field_cert_profile, "cert_profile"},
	{cm_store_entry_field_cert_no_ocsp_check, "cert_no_ocsp_check"},
	{cm_store_entry_field_cert_ns_certtype, "cert_ns_certtype"},

	{cm_store_entry_field_last_expiration_check, "last_expiration_check"},
	{cm_store_entry_field_last_need_notify_check, "last_need_notify_check"},
	{cm_store_entry_field_last_need_enroll_check, "last_need_enroll_check"},

	{cm_store_entry_field_template_subject_der, "template_subject_der"},
	{cm_store_entry_field_template_subject, "template_subject"},
	{cm_store_entry_field_template_hostname, "template_hostname"},
	{cm_store_entry_field_template_email, "template_email"},
	{cm_store_entry_field_template_principal, "template_principal"},
	{cm_store_entry_field_template_ipaddress, "template_ipaddress"},
	{cm_store_entry_field_template_ku, "template_ku"},
	{cm_store_entry_field_template_eku, "template_eku"},
	{cm_store_entry_field_template_is_ca, "template_is_ca"},
	{cm_store_entry_field_template_ca_path_length, "template_ca_path_length"},
	{cm_store_entry_field_template_crl_distribution_point, "template_crldp"},
	{cm_store_entry_field_template_freshest_crl, "template_freshest_crl"},
	{cm_store_entry_field_template_ocsp_location, "template_ocsp"},
	{cm_store_entry_field_template_ns_comment, "template_ns_comment"},
	{cm_store_entry_field_template_profile, "template_profile"}, /* right */
	{cm_store_entry_field_template_profile, "ca_profile"}, /* wrong */
	{cm_store_entry_field_template_issuer, "template_issuer"},
	{cm_store_entry_field_template_certificate_template, "template_certificate_template"},
	{cm_store_entry_field_template_no_ocsp_check, "template_no_ocsp_check"},
	{cm_store_entry_field_template_ns_certtype, "template_ns_certtype"},

	{cm_store_entry_field_challenge_password, "template_challenge_password"}, /* right */
	{cm_store_entry_field_challenge_password, "challenge_password"}, /* wrong */
	{cm_store_entry_field_challenge_password_file, "template_challenge_password_file"},

	{cm_store_entry_field_csr, "csr"},
	{cm_store_entry_field_spkac, "spkac"},
	{cm_store_entry_field_scep_tx, "scep_tx"},
	{cm_store_entry_field_scep_nonce, "scep_nonce"},
	{cm_store_entry_field_scep_last_nonce, "scep_last_nonce"},
	{cm_store_entry_field_scep_gic, "scep_gic"},
	{cm_store_entry_field_scep_gic_next, "scep_gic_next"},
	{cm_store_entry_field_scep_req, "scep_req"},
	{cm_store_entry_field_scep_req_next, "scep_req_next"},
	{cm_store_entry_field_minicert, "minicert"},

	{cm_store_entry_field_state, "state"},

	{cm_store_entry_field_autorenew, "autorenew"},
	{cm_store_entry_field_monitor, "monitor"},

	{cm_store_entry_field_ca_nickname, "ca_name"},

	{cm_store_entry_field_submitted, "submitted"},
	{cm_store_entry_field_ca_cookie, "ca_cookie"},
	{cm_store_entry_field_ca_error, "ca_error"},

	{cm_store_entry_field_cert, "cert"},
	{cm_store_entry_field_cert_chain, "cert_chain"},
	{cm_store_entry_field_cert_roots, "cert_roots"},

	{cm_store_entry_field_pre_certsave_command, "pre_certsave_command"},
	{cm_store_entry_field_pre_certsave_uid, "pre_certsave_uid"},
	{cm_store_entry_field_post_certsave_command, "post_certsave_command"},
	{cm_store_entry_field_post_certsave_uid, "post_certsave_uid"},

	{cm_store_entry_field_root_cert_files, "root_cert_files"},
	{cm_store_entry_field_other_root_cert_files, "other_root_cert_files"},
	{cm_store_entry_field_other_cert_files, "other_cert_files"},
	{cm_store_entry_field_root_cert_nssdbs, "root_cert_dbs"},
	{cm_store_entry_field_other_root_cert_nssdbs, "other_root_cert_dbs"},
	{cm_store_entry_field_other_cert_nssdbs, "other_cert_dbs"},

	{cm_store_ca_field_aka, "ca_aka"},
	{cm_store_ca_field_known_issuer_names, "ca_issuer_names"},
	{cm_store_ca_field_is_default, "ca_is_default"},

	{cm_store_ca_field_type, "ca_type"},
	{cm_store_ca_field_internal_serial, "ca_internal_serial"},
	{cm_store_ca_field_internal_issue_time, "ca_internal_issue_time"},
	{cm_store_ca_field_external_helper, "ca_external_helper"},

	{cm_store_ca_field_root_certs, "ca_root_certs"},
	{cm_store_ca_field_other_root_certs, "ca_other_root_certs"},
	{cm_store_ca_field_other_certs, "ca_other_certs"},

	{cm_store_ca_field_required_enroll_attributes,
	 "ca_required_enroll_attributes"},
	{cm_store_ca_field_required_renewal_attributes,
	 "ca_required_renewal_attributes"},
	{cm_store_ca_field_profiles, "ca_profiles"},
	{cm_store_ca_field_default_profile, "ca_default_profile"},

	{cm_store_ca_field_pre_save_command, "ca_pre_save_command"},
	{cm_store_ca_field_pre_save_uid, "ca_pre_save_uid"},
	{cm_store_ca_field_post_save_command, "ca_post_save_command"},
	{cm_store_ca_field_post_save_uid, "ca_post_save_uid"},

	{cm_store_ca_field_root_cert_files, "ca_root_cert_files"},
	{cm_store_ca_field_other_root_cert_files, "ca_other_root_cert_files"},
	{cm_store_ca_field_other_cert_files, "ca_other_cert_files"},
	{cm_store_ca_field_root_cert_nssdbs, "ca_root_cert_dbs"},
	{cm_store_ca_field_other_root_cert_nssdbs, "ca_other_root_cert_dbs"},
	{cm_store_ca_field_other_cert_nssdbs, "ca_other_cert_dbs"},

	{cm_store_ca_field_capabilities, "ca_capabilities"},
	{cm_store_ca_field_scep_cipher, "scep_cipher"},
	{cm_store_ca_field_scep_digest, "scep_digest"},
	{cm_store_ca_field_scep_ca_identifier, "scep_ca_identifier"},
	{cm_store_ca_field_encryption_cert, "ca_encryption_cert"},
	{cm_store_ca_field_encryption_issuer_cert, "ca_encryption_issuer_cert"},
	{cm_store_ca_field_encryption_cert_pool, "ca_encryption_cert_pool"},
};

static enum cm_store_file_field
cm_store_file_field_of_line(char *p)
{
	unsigned int i, len;
	struct cm_store_file_field_list *entry;
	for (i = 0;
	     i < sizeof(cm_store_file_field_list) /
		 sizeof(cm_store_file_field_list[0]);
	     i++) {
		entry = &cm_store_file_field_list[i];
		len = strlen(entry->name);
		if (strcspn(p, "\r\n") < len) {
			continue;
		}
		if ((strncasecmp(p, entry->name, len) == 0) &&
		    (p[len] == '=')) {
			memmove(p, p + len + 1, strlen(p + len));
			return entry->field;
		}
	}
	return cm_store_file_field_invalid_high;
}

static const char *
cm_store_file_line_of_field(enum cm_store_file_field field)
{
	unsigned int i;
	struct cm_store_file_field_list *entry;
	for (i = 0;
	     i < sizeof(cm_store_file_field_list) /
		 sizeof(cm_store_file_field_list[0]);
	     i++) {
		entry = &cm_store_file_field_list[i];
		if (entry->field == field) {
			return entry->name;
		}
	}
	return NULL;
}

static dbus_bool_t
cm_store_should_ignore_file(const char *filename)
{
	const char *ignore[] = {".tmp",
				".rpmsave", ".rpmorig", ".rpmnew",
				"~", "#"};
	unsigned int i, len, ilen;
	len = strlen(filename);
	for (i = 0; i < sizeof(ignore) / sizeof(ignore[0]); i++) {
		ilen = strlen(ignore[i]);
		if ((len > ilen) &&
		    (strcmp(filename + len - ilen, ignore[i]) == 0)) {
			return TRUE;
		}
	}
	return FALSE;
}

static ssize_t
my_getline(char **buf, size_t *n, FILE *stream)
{
	size_t used = 0, max = 128;
	char *ret, *tmp;

	*buf = NULL;
	*n = 0;
	ret = malloc(max);
	if (ret == NULL) {
		return -1;
	}
	while (fgets(ret + used, max - used, stream) != NULL) {
		used += strlen(ret + used);
		if ((used > 0) && (ret[used - 1] == '\n')) {
			break;
		}
		if (used >= max - 1) {
			max *= 2;
			if (max > 1024 * 1024) {
				free(ret);
				return -1;
			}
			tmp = realloc(ret, max);
			if (tmp == NULL) {
				free(ret);
				return -1;
			}
			ret = tmp;
		}
	}
	*buf = ret;
	*n = used;
	return used;
}

static char **
cm_store_file_read_lines(void *parent, FILE *fp)
{
	char *buf, *s, *t, **lines, **tlines;
	int n_lines, trim, offset;
	size_t buflen;

	s = NULL;
	lines = NULL;
	n_lines = 0;
	trim = 1;
	buf = NULL;
	buflen = 0;
	while (my_getline(&buf, &buflen, fp) > 0) {
		offset = 0;
		switch (buf[0]) {
		case '=':
			offset = 1;
			/* fall through */
		default:
			/* If we've already been reading a line, append it to
			 * the list. */
			if (s != NULL) {
				tlines = talloc_realloc(parent, lines,
							char *, n_lines + 2);
				if (tlines != NULL) {
					if (trim) {
						s[strcspn(s, "\r\n")] = '\0';
					}
					talloc_steal(tlines, s);
					tlines[n_lines++] = s;
					tlines[n_lines] = NULL;
					lines = tlines;
				}
			}
			/* Store this line's data, and default to trimming off
			 * end-of-line markers. */
			trim = 1;
			s = talloc_strdup(parent, buf + offset);
			break;
		case ' ':
			/* Since this is a multi-line item, refrain from
			 * trimming off any end-of-line characters, and just
			 * append it to the list of things we've read. */
			trim = 0;
			t = talloc_strdup_append(s, buf + 1);
			if (t != NULL) {
				s = t;
			}
			break;
		case '#':
		case ';':
			break;
		}
		free(buf);
		buf = NULL;
	}
	/* If we were reading a line, append it to the list. */
	if (s != NULL) {
		tlines = talloc_realloc(parent, lines, char *, n_lines + 2);
		if (tlines != NULL) {
			if (trim) {
				s[strcspn(s, "\r\n")] = '\0';
			}
			talloc_steal(tlines, s);
			tlines[n_lines++] = s;
			tlines[n_lines] = NULL;
			lines = tlines;
		}
	}
	free(buf);
	return lines;
}

static char *
free_if_empty(char *s)
{
	if ((s != NULL) && (strlen(s) == 0)) {
		talloc_free(s);
		s = NULL;
	}
	return s;
}

static char **
free_if_empty_multi(void *parent, char *p)
{
	char **s;
	int i, j, k;
	if ((p == NULL) || (strlen(p) == 0)) {
		if (p != NULL) {
			talloc_free(p);
		}
		return NULL;
	}
	s = talloc_zero_array(parent, char *, strlen(p) + 2);
	i = 0;
	while (*p != '\0') {
		s[i] = talloc_strdup(parent, p);
		j = 0;
		k = 0;
		while ((p[j] != ',') && (p[j] != '\0')) {
			switch (p[j]) {
			case '\\':
				j++;
				memmove(s[i] + k, p + j,
					strlen(p + j));
				break;
			default:
				break;
			}
			j++;
			k++;
		}
		s[i][k] = '\0';
		if (k > 0) {
			i++;
		} else {
			talloc_free(s[i]);
			s[i] = NULL;
		}
		if (p[j] == '\0') {
			break;
		} else {
			p += (j + 1);
		}
	}
	s[i] = NULL;
	if (i > 0) {
		return s;
	} else {
		talloc_free(s);
		return NULL;
	}
}

static struct cm_nickcert **
parse_nickcert_list(void *parent, const char *s)
{
	struct cm_nickcert **ret = NULL, **tmp, *nc;
	const char *p, *q;
	int i = 0, j;

	p = s;
	while (*p != '\0') {
		nc = talloc_ptrtype(parent, nc);
		if (nc == NULL) {
			return NULL;
		}
		memset(nc, 0, sizeof(*nc));
		q = p + strcspn(p, "\r\n");
		nc->cm_nickname = talloc_strndup(nc, p, q - p);
		if (nc->cm_nickname == NULL) {
			talloc_free(ret);
			return NULL;
		}
		for (j = 0; nc->cm_nickname[j] != '\0'; j++) {
			if (nc->cm_nickname[j] == '\\') {
				memmove(nc->cm_nickname + j,
					nc->cm_nickname + j + 1,
					strlen(nc->cm_nickname + j));
			}
		}
		p = q + strspn(q, "\r\n");
		q = strstr(p, "-----END");
		if (q == NULL) {
			talloc_free(ret);
			return NULL;
		}
		q += strcspn(q, "\r\n");
		q += strspn(q, "\r\n");
		nc->cm_cert = talloc_strndup(nc, p, q - p);
		if (nc->cm_cert == NULL) {
			talloc_free(ret);
			return NULL;
		}
		tmp = talloc_realloc(parent, ret, struct cm_nickcert *, i + 2);
		if (tmp == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret = tmp;
		talloc_steal(ret, nc);
		ret[i++] = nc;
		ret[i] = NULL;
		p = q;
	}
	return ret;
}

#ifdef HAVE_GMP
static void
fill_uuid(unsigned char *uuid, size_t length)
{
	gmp_randstate_t state;
	unsigned int i;

	gmp_randinit_default(state);
	for (i = 0; i < length; i++) {
		uuid[i] = gmp_urandomb_ui(state, 8);
	}
}
#endif

int
cm_store_make_uuid_string(char out[37])
{
	unsigned char uuid[16];
	char *p;
	int i;

#ifdef HAVE_UUID
	if (cm_submit_uuid_new(uuid) == 0) {
		/* we're good */
	} else
#endif
#ifdef HAVE_GMP
	fill_uuid(uuid, sizeof(uuid));
#else
	return -1;
#endif
	for (i = 0, p = out; i < 16; i++) {
		switch (i) {
		case 4:
		case 6:
		case 8:
		case 10:
			*p++ = '-';
			break;
		default:
			break;
		}
		snprintf(p, 3, "%02x", uuid[i]);
		p += 2;
	}
	return p - out;
}

int
cm_store_make_uuid_string_underscore(char out[37])
{
	int i, j;

	i = cm_store_make_uuid_string(out);
	if (i > 0) {
		for (j = 0; j < i; j++) {
			if (out[j] == '-') {
				out[j] = '_';
			}
		}
	}
	return i;
}

char *
cm_store_entry_next_busname(void *parent)
{
	return talloc_asprintf(parent, "Request%llu", ++cm_entry_name_last);
}

static struct cm_store_entry *
cm_store_entry_read(void *parent, const char *filename, FILE *fp)
{
	struct cm_store_entry *ret;
	char **s, *p, *end;
	int i;
	enum cm_store_file_field field;

	ret = cm_store_entry_new(parent);
	if (ret != NULL) {
		s = cm_store_file_read_lines(ret, fp);
		ret->cm_busname = cm_store_entry_next_busname(ret);
		ret->cm_store_private = talloc_strdup(ret, filename);
		ret->cm_template_ca_path_length = -1;
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			p = s[i];
			field = cm_store_file_field_of_line(p);
			switch (field) {
			case cm_store_file_field_invalid:
			case cm_store_file_field_invalid_high:
				break;
			case cm_store_ca_field_aka:
			case cm_store_ca_field_known_issuer_names:
			case cm_store_ca_field_is_default:
			case cm_store_ca_field_type:
			case cm_store_ca_field_internal_serial:
			case cm_store_ca_field_internal_issue_time:
			case cm_store_ca_field_external_helper:
			case cm_store_ca_field_root_certs:
			case cm_store_ca_field_other_root_certs:
			case cm_store_ca_field_other_certs:
			case cm_store_ca_field_required_enroll_attributes:
			case cm_store_ca_field_required_renewal_attributes:
			case cm_store_ca_field_profiles:
			case cm_store_ca_field_default_profile:
			case cm_store_ca_field_pre_save_command:
			case cm_store_ca_field_pre_save_uid:
			case cm_store_ca_field_post_save_command:
			case cm_store_ca_field_post_save_uid:
			case cm_store_ca_field_root_cert_files:
			case cm_store_ca_field_other_root_cert_files:
			case cm_store_ca_field_other_cert_files:
			case cm_store_ca_field_root_cert_nssdbs:
			case cm_store_ca_field_other_root_cert_nssdbs:
			case cm_store_ca_field_other_cert_nssdbs:
			case cm_store_ca_field_capabilities:
			case cm_store_ca_field_scep_cipher:
			case cm_store_ca_field_scep_digest:
			case cm_store_ca_field_scep_ca_identifier:
			case cm_store_ca_field_encryption_cert:
			case cm_store_ca_field_encryption_issuer_cert:
			case cm_store_ca_field_encryption_cert_pool:
				break;
			case cm_store_file_field_id:
				ret->cm_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_key_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_rsa;
#ifdef CM_ENABLE_DSA
				} else
				if (strcasecmp(s[i], "DSA") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
				} else
				if ((strcasecmp(s[i], "ECDSA") == 0) ||
				    (strcasecmp(s[i], "EC") == 0)) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
				} else
				if (strcasecmp(s[i], "ML-DSA-44") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_ml_dsa_44;
				} else
				if (strcasecmp(s[i], "ML-DSA-65") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_ml_dsa_65;
				} else
				if (strcasecmp(s[i], "ML-DSA-87") == 0) {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_ml_dsa_87;
#endif
				} else {
					ret->cm_key_type.cm_key_algorithm =
						cm_key_unspecified;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_gen_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_rsa;
#ifdef CM_ENABLE_DSA
				} else
				if (strcasecmp(s[i], "DSA") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
				} else
				if ((strcasecmp(s[i], "ECDSA") == 0) ||
				    (strcasecmp(s[i], "EC") == 0)) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
				} else
				if (strcasecmp(s[i], "ML-DSA-44") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_44;
				} else
				if (strcasecmp(s[i], "ML-DSA-65") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_65;
				} else
				if (strcasecmp(s[i], "ML-DSA-87") == 0) {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_87;
#endif
				} else {
					ret->cm_key_type.cm_key_gen_algorithm =
						cm_key_unspecified;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_size:
				ret->cm_key_type.cm_key_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_gen_size:
				ret->cm_key_type.cm_key_gen_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_rsa;
#ifdef CM_ENABLE_DSA
				} else
				if (strcasecmp(s[i], "DSA") == 0) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
				} else
				if ((strcasecmp(s[i], "ECDSA") == 0) ||
				    (strcasecmp(s[i], "EC") == 0)) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
				} else
				if (strcasecmp(s[i], "ML-DSA-44") == 0) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_ml_dsa_44;
				} else
				if (strcasecmp(s[i], "ML-DSA-65") == 0) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_ml_dsa_65;
				} else
				if (strcasecmp(s[i], "ML-DSA-87") == 0) {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_ml_dsa_87;
#endif
				} else {
					ret->cm_key_next_type.cm_key_algorithm =
						cm_key_unspecified;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_gen_type:
				if (strcasecmp(s[i], "RSA") == 0) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_rsa;
#ifdef CM_ENABLE_DSA
				} else
				if (strcasecmp(s[i], "DSA") == 0) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
				} else
				if ((strcasecmp(s[i], "ECDSA") == 0) ||
				    (strcasecmp(s[i], "EC") == 0)) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
				} else
				if (strcasecmp(s[i], "ML-DSA-44") == 0) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_44;
				} else
				if (strcasecmp(s[i], "ML-DSA-65") == 0) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_65;
				} else
				if (strcasecmp(s[i], "ML-DSA-87") == 0) {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_ml_dsa_87;
#endif
				} else {
					ret->cm_key_next_type.cm_key_gen_algorithm =
						cm_key_unspecified;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_size:
				ret->cm_key_next_type.cm_key_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_gen_size:
				ret->cm_key_next_type.cm_key_gen_size = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_preserve:
				ret->cm_key_preserve = atoi(p) != 0;
				break;
			case cm_store_entry_field_key_next_marker:
				ret->cm_key_next_marker = free_if_empty(p);
				break;
			case cm_store_entry_field_key_storage_type:
				ret->cm_key_storage_type = cm_key_storage_none;
				if (strcasecmp(p, "FILE") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_file;
				} else
				if (strcasecmp(p, "NSSDB") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_nssdb;
				} else
				if (strcasecmp(p, "NONE") == 0) {
					ret->cm_key_storage_type =
						cm_key_storage_none;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_key_storage_location:
				ret->cm_key_storage_location = free_if_empty(p);
				if (ret->cm_key_storage_location != NULL) {
					p = cm_store_canonicalize_path(ret,
								       ret->cm_key_storage_location);
					talloc_free(ret->cm_key_storage_location);
					ret->cm_key_storage_location = p;
				}
				break;
			case cm_store_entry_field_key_token:
				ret->cm_key_token = free_if_empty(p);
				break;
			case cm_store_entry_field_key_nickname:
				ret->cm_key_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_key_pin:
				ret->cm_key_pin = free_if_empty(p);
				if (ret->cm_key_pin_file != NULL) {
					ret->cm_key_pin = NULL;
				}
				break;
			case cm_store_entry_field_key_pin_file:
				ret->cm_key_pin_file = free_if_empty(p);
				if (ret->cm_key_pin_file != NULL) {
					ret->cm_key_pin = NULL;
				}
				break;
			case cm_store_entry_field_key_owner:
				ret->cm_key_owner = free_if_empty(p);
				break;
			case cm_store_entry_field_key_perms:
				if (strlen(p) > 0) {
					ret->cm_key_perms = strtoul(p, &end, 8);
					if ((end == NULL) || (*end != '\0')) {
						ret->cm_key_perms = 0;
					}
				}
				break;
			case cm_store_entry_field_key_pubkey:
				ret->cm_key_pubkey = free_if_empty(p);
				break;
			case cm_store_entry_field_key_pubkey_info:
				ret->cm_key_pubkey_info = free_if_empty(p);
				break;
			case cm_store_entry_field_key_next_pubkey:
				ret->cm_key_next_pubkey = free_if_empty(p);
				break;
			case cm_store_entry_field_key_next_pubkey_info:
				ret->cm_key_next_pubkey_info = free_if_empty(p);
				break;
			case cm_store_entry_field_key_generated_date:
				ret->cm_key_generated_date =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_generated_date:
				ret->cm_key_next_generated_date =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_requested_count:
				ret->cm_key_requested_count = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_next_requested_count:
				ret->cm_key_next_requested_count = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_key_issued_count:
				ret->cm_key_issued_count = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_nss_user:
				ret->cm_nss_user = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_storage_type:
				if (strcasecmp(p, "FILE") == 0) {
					ret->cm_cert_storage_type =
						cm_cert_storage_file;
				} else
				if (strcasecmp(p, "NSSDB") == 0) {
					ret->cm_cert_storage_type =
						cm_cert_storage_nssdb;
				} else {
					ret->cm_cert_storage_type =
						cm_cert_storage_file;
				}
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_storage_location:
				ret->cm_cert_storage_location = free_if_empty(p);
				if (ret->cm_cert_storage_location != NULL) {
					p = cm_store_canonicalize_path(ret,
								       ret->cm_cert_storage_location);
					talloc_free(ret->cm_cert_storage_location);
					ret->cm_cert_storage_location = p;
				}
				break;
			case cm_store_entry_field_cert_token:
				ret->cm_cert_token = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_nickname:
				ret->cm_cert_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_owner:
				ret->cm_cert_owner = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_perms:
				if (strlen(p) > 0) {
					ret->cm_cert_perms = strtoul(p, &end, 8);
					if ((end == NULL) || (*end != '\0')) {
						ret->cm_cert_perms = 0;
					}
				}
				break;
			case cm_store_entry_field_cert_issuer_der:
				ret->cm_cert_issuer_der = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_issuer:
				ret->cm_cert_issuer = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_serial:
				ret->cm_cert_serial = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_subject_der:
				ret->cm_cert_subject_der = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_subject:
				ret->cm_cert_subject = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_spki:
				ret->cm_cert_spki = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_not_before:
				ret->cm_cert_not_before =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_not_after:
				ret->cm_cert_not_after =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_hostname:
				ret->cm_cert_hostname =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_email:
				ret->cm_cert_email =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_principal:
				ret->cm_cert_principal =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_ipaddress:
				ret->cm_cert_ipaddress =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_ku:
				ret->cm_cert_ku = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_eku:
				ret->cm_cert_eku = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_is_ca:
				ret->cm_cert_is_ca = atoi(p) != 0;
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_ca_path_length:
				ret->cm_cert_ca_path_length = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_crl_distribution_point:
				ret->cm_cert_crl_distribution_point =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_freshest_crl:
				ret->cm_cert_freshest_crl =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_ocsp_location:
				ret->cm_cert_ocsp_location =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_cert_ns_comment:
				ret->cm_cert_ns_comment = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_profile:
				ret->cm_cert_profile = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_no_ocsp_check:
				ret->cm_cert_no_ocsp_check = atoi(p) != 0;
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_ns_certtype:
				ret->cm_cert_ns_certtype = free_if_empty(p);
				break;
			case cm_store_entry_field_last_expiration_check:
				/* backward compatibility before we split them
				 * into two settings */
				ret->cm_last_need_notify_check =
					cm_store_time_from_timestamp(p);
				ret->cm_last_need_enroll_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_last_need_notify_check:
				ret->cm_last_need_notify_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_last_need_enroll_check:
				ret->cm_last_need_enroll_check =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_template_subject_der:
				ret->cm_template_subject_der = free_if_empty(p);
				break;
			case cm_store_entry_field_template_subject:
				ret->cm_template_subject = free_if_empty(p);
				break;
			case cm_store_entry_field_template_hostname:
				ret->cm_template_hostname =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_email:
				ret->cm_template_email =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_principal:
				ret->cm_template_principal =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_ipaddress:
				ret->cm_template_ipaddress =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_ku:
				ret->cm_template_ku = free_if_empty(p);
				break;
			case cm_store_entry_field_template_eku:
				ret->cm_template_eku = free_if_empty(p);
				break;
			case cm_store_entry_field_template_is_ca:
				ret->cm_template_is_ca = atoi(p) != 0;
				talloc_free(p);
				break;
			case cm_store_entry_field_template_ca_path_length:
				ret->cm_template_ca_path_length = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_template_crl_distribution_point:
				ret->cm_template_crl_distribution_point =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_freshest_crl:
				ret->cm_template_freshest_crl =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_ocsp_location:
				ret->cm_template_ocsp_location =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_template_ns_comment:
				ret->cm_template_ns_comment = free_if_empty(p);
				break;
			case cm_store_entry_field_template_profile:
				ret->cm_template_profile = free_if_empty(p);
				break;
			case cm_store_entry_field_template_certificate_template:
				ret->cm_template_certificate_template = free_if_empty(p);
				break;
			case cm_store_entry_field_template_issuer:
				ret->cm_template_issuer = free_if_empty(p);
				break;
			case cm_store_entry_field_template_no_ocsp_check:
				ret->cm_template_no_ocsp_check = atoi(p) != 0;
				talloc_free(p);
				break;
			case cm_store_entry_field_template_ns_certtype:
				ret->cm_template_ns_certtype = free_if_empty(p);
				break;
			case cm_store_entry_field_challenge_password:
				ret->cm_template_challenge_password = free_if_empty(p);
				break;
			case cm_store_entry_field_challenge_password_file:
				ret->cm_template_challenge_password_file = free_if_empty(p);
				break;
			case cm_store_entry_field_csr:
				ret->cm_csr = free_if_empty(p);
				break;
			case cm_store_entry_field_spkac:
				ret->cm_spkac = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_tx:
				ret->cm_scep_tx = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_nonce:
				ret->cm_scep_nonce = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_last_nonce:
				ret->cm_scep_last_nonce = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_gic:
				ret->cm_scep_gic = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_gic_next:
				ret->cm_scep_gic_next = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_req:
				ret->cm_scep_req = free_if_empty(p);
				break;
			case cm_store_entry_field_scep_req_next:
				ret->cm_scep_req_next = free_if_empty(p);
				break;
			case cm_store_entry_field_minicert:
				ret->cm_minicert = free_if_empty(p);
				break;
			case cm_store_entry_field_state:
				ret->cm_state = cm_store_state_from_string(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_autorenew:
				ret->cm_autorenew = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_monitor:
				ret->cm_monitor = atoi(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_nickname:
				ret->cm_ca_nickname = free_if_empty(p);
				break;
			case cm_store_entry_field_submitted:
				ret->cm_submitted =
					cm_store_time_from_timestamp(p);
				talloc_free(p);
				break;
			case cm_store_entry_field_ca_cookie:
				ret->cm_ca_cookie = free_if_empty(p);
				break;
			case cm_store_entry_field_ca_error:
				ret->cm_ca_error = free_if_empty(p);
				break;
			case cm_store_entry_field_cert:
				ret->cm_cert = free_if_empty(p);
				break;
			case cm_store_entry_field_cert_chain:
				ret->cm_cert_chain =
					parse_nickcert_list(ret, p);
				talloc_free(p);
				break;
			case cm_store_entry_field_cert_roots:
				ret->cm_cert_roots =
					parse_nickcert_list(ret, p);
				talloc_free(p);
				break;
			case cm_store_entry_field_pre_certsave_command:
				ret->cm_pre_certsave_command  = free_if_empty(p);
				break;
			case cm_store_entry_field_pre_certsave_uid:
				ret->cm_pre_certsave_uid = free_if_empty(p);
				break;
			case cm_store_entry_field_post_certsave_command:
				ret->cm_post_certsave_command  = free_if_empty(p);
				break;
			case cm_store_entry_field_post_certsave_uid:
				ret->cm_post_certsave_uid = free_if_empty(p);
				break;
			case cm_store_entry_field_root_cert_files:
				ret->cm_root_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_other_root_cert_files:
				ret->cm_other_root_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_other_cert_files:
				ret->cm_other_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_root_cert_nssdbs:
				ret->cm_root_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_other_root_cert_nssdbs:
				ret->cm_other_root_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_entry_field_other_cert_nssdbs:
				ret->cm_other_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			}
		}
	}
	return ret;
}

struct cm_store_entry *
cm_store_files_entry_read(void *parent, const char *filename)
{
	FILE *fp;
	struct cm_store_entry *ret;
	if (filename != NULL) {
		fp = fopen(filename, "r");
		if (fp != NULL) {
			ret = cm_store_entry_read(parent, filename, fp);
			fclose(fp);
		} else {
			ret = NULL;
		}
	} else {
		ret = NULL;
	}
	return ret;
}

char *
cm_store_ca_next_busname(void *parent)
{
	return talloc_asprintf(parent, "CA%llu", ++cm_ca_name_last);
}

static struct cm_store_ca *
cm_store_ca_read(void *parent, const char *filename, FILE *fp)
{
	struct cm_store_ca *ret;
	char **s, *p;
	int i;
	enum cm_store_file_field field;

	ret = cm_store_ca_new(parent);
	if (ret != NULL) {
		s = cm_store_file_read_lines(ret, fp);
		ret->cm_busname = cm_store_ca_next_busname(ret);
		ret->cm_store_private = talloc_strdup(ret, filename);
		for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
			p = s[i];
			field = cm_store_file_field_of_line(p);
			switch (field) {
			case cm_store_file_field_invalid:
			case cm_store_file_field_invalid_high:
				break;
			case cm_store_entry_field_key_type:
			case cm_store_entry_field_key_gen_type:
			case cm_store_entry_field_key_size:
			case cm_store_entry_field_key_gen_size:
			case cm_store_entry_field_key_next_type:
			case cm_store_entry_field_key_next_gen_type:
			case cm_store_entry_field_key_next_size:
			case cm_store_entry_field_key_next_gen_size:
			case cm_store_entry_field_key_preserve:
			case cm_store_entry_field_key_next_marker:
			case cm_store_entry_field_key_storage_type:
			case cm_store_entry_field_key_storage_location:
			case cm_store_entry_field_key_token:
			case cm_store_entry_field_key_nickname:
			case cm_store_entry_field_key_pin:
			case cm_store_entry_field_key_pin_file:
			case cm_store_entry_field_key_owner:
			case cm_store_entry_field_key_perms:
			case cm_store_entry_field_key_pubkey:
			case cm_store_entry_field_key_pubkey_info:
			case cm_store_entry_field_key_next_pubkey:
			case cm_store_entry_field_key_next_pubkey_info:
			case cm_store_entry_field_key_generated_date:
			case cm_store_entry_field_key_next_generated_date:
			case cm_store_entry_field_key_requested_count:
			case cm_store_entry_field_key_next_requested_count:
			case cm_store_entry_field_key_issued_count:
			case cm_store_entry_field_nss_user:
			case cm_store_entry_field_cert_storage_type:
			case cm_store_entry_field_cert_storage_location:
			case cm_store_entry_field_cert_token:
			case cm_store_entry_field_cert_nickname:
			case cm_store_entry_field_cert_owner:
			case cm_store_entry_field_cert_perms:
			case cm_store_entry_field_cert_issuer_der:
			case cm_store_entry_field_cert_issuer:
			case cm_store_entry_field_cert_serial:
			case cm_store_entry_field_cert_subject_der:
			case cm_store_entry_field_cert_subject:
			case cm_store_entry_field_cert_spki:
			case cm_store_entry_field_cert_not_before:
			case cm_store_entry_field_cert_not_after:
			case cm_store_entry_field_cert_hostname:
			case cm_store_entry_field_cert_email:
			case cm_store_entry_field_cert_principal:
			case cm_store_entry_field_cert_ipaddress:
			case cm_store_entry_field_cert_ku:
			case cm_store_entry_field_cert_eku:
			case cm_store_entry_field_cert_is_ca:
			case cm_store_entry_field_cert_ca_path_length:
			case cm_store_entry_field_cert_crl_distribution_point:
			case cm_store_entry_field_cert_freshest_crl:
			case cm_store_entry_field_cert_ocsp_location:
			case cm_store_entry_field_cert_ns_comment:
			case cm_store_entry_field_cert_profile:
			case cm_store_entry_field_cert_no_ocsp_check:
			case cm_store_entry_field_cert_ns_certtype:
			case cm_store_entry_field_last_expiration_check:
			case cm_store_entry_field_last_need_notify_check:
			case cm_store_entry_field_last_need_enroll_check:
			case cm_store_entry_field_template_subject_der:
			case cm_store_entry_field_template_subject:
			case cm_store_entry_field_template_hostname:
			case cm_store_entry_field_template_email:
			case cm_store_entry_field_template_principal:
			case cm_store_entry_field_template_ipaddress:
			case cm_store_entry_field_template_ku:
			case cm_store_entry_field_template_eku:
			case cm_store_entry_field_template_is_ca:
			case cm_store_entry_field_template_ca_path_length:
			case cm_store_entry_field_template_crl_distribution_point:
			case cm_store_entry_field_template_freshest_crl:
			case cm_store_entry_field_template_ocsp_location:
			case cm_store_entry_field_template_ns_comment:
			case cm_store_entry_field_template_profile:
			case cm_store_entry_field_template_certificate_template:
			case cm_store_entry_field_template_issuer:
			case cm_store_entry_field_template_no_ocsp_check:
			case cm_store_entry_field_template_ns_certtype:
			case cm_store_entry_field_challenge_password:
			case cm_store_entry_field_challenge_password_file:
			case cm_store_entry_field_csr:
			case cm_store_entry_field_spkac:
			case cm_store_entry_field_scep_tx:
			case cm_store_entry_field_scep_nonce:
			case cm_store_entry_field_scep_last_nonce:
			case cm_store_entry_field_scep_gic:
			case cm_store_entry_field_scep_gic_next:
			case cm_store_entry_field_scep_req:
			case cm_store_entry_field_scep_req_next:
			case cm_store_entry_field_minicert:
			case cm_store_entry_field_state:
			case cm_store_entry_field_autorenew:
			case cm_store_entry_field_monitor:
			case cm_store_entry_field_ca_nickname:
			case cm_store_entry_field_submitted:
			case cm_store_entry_field_ca_cookie:
			case cm_store_entry_field_ca_error:
			case cm_store_entry_field_cert:
			case cm_store_entry_field_cert_chain:
			case cm_store_entry_field_cert_roots:
			case cm_store_entry_field_pre_certsave_command:
			case cm_store_entry_field_pre_certsave_uid:
			case cm_store_entry_field_post_certsave_command:
			case cm_store_entry_field_post_certsave_uid:
			case cm_store_entry_field_root_cert_files:
			case cm_store_entry_field_other_root_cert_files:
			case cm_store_entry_field_other_cert_files:
			case cm_store_entry_field_root_cert_nssdbs:
			case cm_store_entry_field_other_root_cert_nssdbs:
			case cm_store_entry_field_other_cert_nssdbs:
				break;
			case cm_store_file_field_id:
				ret->cm_nickname = free_if_empty(p);
				break;
			case cm_store_ca_field_aka:
				ret->cm_ca_aka = free_if_empty(p);
				break;
			case cm_store_ca_field_known_issuer_names:
				ret->cm_ca_known_issuer_names =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_is_default:
				ret->cm_ca_is_default = atoi(p);
				talloc_free(p);
				break;
			case cm_store_ca_field_type:
				if (strcasecmp(p, "EXTERNAL") == 0) {
					ret->cm_ca_type = cm_ca_external;
				} else
				if (strcasecmp(p, "INTERNAL:SELF") == 0) {
					ret->cm_ca_type = cm_ca_internal_self;
				} else {
					ret->cm_ca_type = cm_ca_external;
				}
				talloc_free(p);
				break;
			case cm_store_ca_field_internal_serial:
				ret->cm_ca_internal_serial = free_if_empty(p);
				break;
			case cm_store_ca_field_internal_issue_time:
				ret->cm_ca_internal_force_issue_time = 1;
				ret->cm_ca_internal_issue_time = atol(p);
				talloc_free(p);
				break;
			case cm_store_ca_field_external_helper:
				ret->cm_ca_external_helper = free_if_empty(p);
				break;
			case cm_store_ca_field_root_certs:
				ret->cm_ca_root_certs =
					parse_nickcert_list(ret, p);
				talloc_free(p);
				break;
			case cm_store_ca_field_other_root_certs:
				ret->cm_ca_other_root_certs =
					parse_nickcert_list(ret, p);
				talloc_free(p);
				break;
			case cm_store_ca_field_other_certs:
				ret->cm_ca_other_certs =
					parse_nickcert_list(ret, p);
				talloc_free(p);
				break;
			case cm_store_ca_field_required_enroll_attributes:
				ret->cm_ca_required_enroll_attributes =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_required_renewal_attributes:
				ret->cm_ca_required_renewal_attributes =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_profiles:
				ret->cm_ca_profiles =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_default_profile:
				ret->cm_ca_default_profile = free_if_empty(p);
				break;
			case cm_store_ca_field_pre_save_command:
				ret->cm_ca_pre_save_command = free_if_empty(p);
				break;
			case cm_store_ca_field_pre_save_uid:
				ret->cm_ca_pre_save_uid = free_if_empty(p);
				break;
			case cm_store_ca_field_post_save_command:
				ret->cm_ca_post_save_command = free_if_empty(p);
				break;
			case cm_store_ca_field_post_save_uid:
				ret->cm_ca_post_save_uid = free_if_empty(p);
				break;
			case cm_store_ca_field_root_cert_files:
				ret->cm_ca_root_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_other_root_cert_files:
				ret->cm_ca_other_root_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_other_cert_files:
				ret->cm_ca_other_cert_store_files =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_root_cert_nssdbs:
				ret->cm_ca_root_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_other_root_cert_nssdbs:
				ret->cm_ca_other_root_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_other_cert_nssdbs:
				ret->cm_ca_other_cert_store_nssdbs =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_capabilities:
				ret->cm_ca_capabilities =
					free_if_empty_multi(ret, p);
				break;
			case cm_store_ca_field_scep_cipher:
				ret->cm_ca_scep_cipher =
					free_if_empty(p);
				break;
			case cm_store_ca_field_scep_digest:
				ret->cm_ca_scep_digest =
					free_if_empty(p);
				break;
			case cm_store_ca_field_scep_ca_identifier:
				ret->cm_ca_scep_ca_identifier =
					free_if_empty(p);
				break;
			case cm_store_ca_field_encryption_cert:
				ret->cm_ca_encryption_cert =
					free_if_empty(p);
				break;
			case cm_store_ca_field_encryption_issuer_cert:
				ret->cm_ca_encryption_issuer_cert =
					free_if_empty(p);
				break;
			case cm_store_ca_field_encryption_cert_pool:
				ret->cm_ca_encryption_cert_pool =
					free_if_empty(p);
				break;
			}
		}
		if (ret->cm_ca_internal_serial == NULL) {
			ret->cm_ca_internal_serial = talloc_strdup(ret, CM_DEFAULT_CERT_SERIAL);
		}
	}
	return ret;
}

struct cm_store_ca *
cm_store_files_ca_read(void *parent, const char *filename)
{
	FILE *fp;
	struct cm_store_ca *ret;
	if (filename != NULL) {
		fp = fopen(filename, "r");
		if (fp != NULL) {
			ret = cm_store_ca_read(parent, filename, fp);
			fclose(fp);
		} else {
			ret = NULL;
		}
	} else {
		ret = NULL;
	}
	return ret;
}

static int
cm_store_file_write_octal(FILE *fp, enum cm_store_file_field field, unsigned long value)
{
	fprintf(fp, "%s=%lo\n", cm_store_file_line_of_field(field), value);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_int(FILE *fp, enum cm_store_file_field field, long value)
{
	fprintf(fp, "%s=%ld\n", cm_store_file_line_of_field(field), value);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_str(FILE *fp, enum cm_store_file_field field, const char *s)
{
	const char *p, *q;
	if ((s == NULL) || (s[0] == '\0')) {
		return 0;
	}
	p = s;
	q = p + strcspn(p, "\r\n");
	fprintf(fp, "%s=%.*s\n", cm_store_file_line_of_field(field),
		(int) (q - p), p);
	p = q + strspn(q, "\r\n");
	while (*p != '\0') {
		q = p + strcspn(p, "\r\n");
		fprintf(fp, " %.*s\n", (int) (q - p), p);
		if (*q == '\r') {
			q++;
		}
		if (*q == '\n') {
			q++;
		}
		if (p == q) {
			break;
		}
		p = q;
	}
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

static int
cm_store_file_write_strs(FILE *fp, enum cm_store_file_field field, char **s)
{
	int i, j;
	if ((s == NULL) || (s[0] == NULL)) {
		return 0;
	}
	fprintf(fp, "%s=", cm_store_file_line_of_field(field));
	for (i = 0; (s != NULL) && (s[i] != NULL); i++) {
		if (i > 0) {
			fputc(',', fp);
		}
		for (j = 0; s[i][j] != '\0'; j++) {
			switch (s[i][j]) {
			case '\\':
			case ',':
				fputc('\\', fp);
				/* fall through */
			default:
				fputc(s[i][j], fp);
				break;
			}
		}
		if (ferror(fp)) {
			return -1;
		}
	}
	fprintf(fp, "\n");
	return 0;
}

static int
cm_store_file_write_nickcert_list(FILE *fp, enum cm_store_file_field field,
				  struct cm_nickcert **nc)
{
	const char *p, *q;
	int i, j;

	if ((nc == NULL) || (nc[0] == NULL)) {
		return 0;
	}
	fprintf(fp, "%s=", cm_store_file_line_of_field(field));
	for (i = 0; nc[i] != NULL; i++) {
		if (i > 0) {
			fputc(' ', fp);
		}
		for (j = 0; nc[i]->cm_nickname[j] != '\0'; j++) {
			switch (nc[i]->cm_nickname[j]) {
			case '\\':
			case ',':
				fputc('\\', fp);
				/* fall through */
			default:
				fputc(nc[i]->cm_nickname[j], fp);
				break;
			}
		}
		if (ferror(fp)) {
			return -1;
		}
		fprintf(fp, "\n");
		p = nc[i]->cm_cert;
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			fprintf(fp, " %.*s\n", (int) (q - p), p);
			p = q + strspn(q, "\r\n");
		}
		if (ferror(fp)) {
			return -1;
		}
	}
	return 0;
}

static int
cm_store_entry_write(FILE *fp, struct cm_store_entry *entry)
{
	char timestamp[15];
	const char *p;

	if (entry->cm_nickname == NULL) {
		p = cm_store_timestamp_from_time(cm_time(NULL), timestamp);
	} else {
		p = entry->cm_nickname;
	}
	cm_store_file_write_str(fp, cm_store_file_field_id, p);

	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"UNSPECIFIED");
		break;
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"RSA");
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"DSA");
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"EC");
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"ML-DSA-44");
		break;
	case cm_key_ml_dsa_65:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"ML-DSA-65");
		break;
	case cm_key_ml_dsa_87:
		cm_store_file_write_str(fp, cm_store_entry_field_key_type,
					"ML-DSA-87");
		break;
#endif
	}
	switch (entry->cm_key_type.cm_key_gen_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"UNSPECIFIED");
		break;
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"RSA");
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"DSA");
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"EC");
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"ML-DSA-44");
		break;
	case cm_key_ml_dsa_65:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"ML-DSA-65");
		break;
	case cm_key_ml_dsa_87:
		cm_store_file_write_str(fp, cm_store_entry_field_key_gen_type,
					"ML-DSA-87");
		break;
#endif
	}
	cm_store_file_write_int(fp, cm_store_entry_field_key_size,
				entry->cm_key_type.cm_key_size);
	cm_store_file_write_int(fp, cm_store_entry_field_key_gen_size,
				entry->cm_key_type.cm_key_gen_size);
	switch (entry->cm_key_next_type.cm_key_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"UNSPECIFIED");
		break;
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"RSA");
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"DSA");
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"EC");
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"ML-DSA-44");
		break;
	case cm_key_ml_dsa_65:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"ML-DSA-65");
		break;
	case cm_key_ml_dsa_87:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_type,
					"ML-DSA-87");
		break;
#endif
	}
	switch (entry->cm_key_next_type.cm_key_gen_algorithm) {
	case cm_key_unspecified:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"UNSPECIFIED");
		break;
	case cm_key_rsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"RSA");
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"DSA");
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"EC");
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"ML-DSA-44");
		break;
	case cm_key_ml_dsa_65:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"ML-DSA-65");
		break;
	case cm_key_ml_dsa_87:
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_gen_type,
					"ML-DSA-87");
		break;
#endif
	}
	cm_store_file_write_int(fp, cm_store_entry_field_key_next_size,
				entry->cm_key_next_type.cm_key_size);
	cm_store_file_write_int(fp, cm_store_entry_field_key_next_gen_size,
				entry->cm_key_next_type.cm_key_gen_size);
	cm_store_file_write_str(fp, cm_store_entry_field_key_next_marker,
				entry->cm_key_next_marker);
	cm_store_file_write_int(fp, cm_store_entry_field_key_preserve,
				entry->cm_key_preserve);

	switch (entry->cm_key_storage_type) {
	case cm_key_storage_file:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"FILE");
		break;
	case cm_key_storage_nssdb:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"NSSDB");
		break;
	case cm_key_storage_none:
		cm_store_file_write_str(fp,
					cm_store_entry_field_key_storage_type,
					"NONE");
		break;
	}
	cm_store_file_write_str(fp, cm_store_entry_field_key_storage_location,
				entry->cm_key_storage_location);
	cm_store_file_write_str(fp, cm_store_entry_field_key_token,
				entry->cm_key_token);
	cm_store_file_write_str(fp, cm_store_entry_field_key_nickname,
				entry->cm_key_nickname);
	if (entry->cm_key_pin_file == NULL) {
		cm_store_file_write_str(fp, cm_store_entry_field_key_pin,
					entry->cm_key_pin);
	}
	cm_store_file_write_str(fp, cm_store_entry_field_key_pin_file,
				entry->cm_key_pin_file);
	cm_store_file_write_str(fp, cm_store_entry_field_key_owner,
				entry->cm_key_owner);
	cm_store_file_write_octal(fp, cm_store_entry_field_key_perms,
				  entry->cm_key_perms);
	cm_store_file_write_str(fp, cm_store_entry_field_key_pubkey,
				entry->cm_key_pubkey);
	cm_store_file_write_str(fp, cm_store_entry_field_key_pubkey_info,
				entry->cm_key_pubkey_info);

	cm_store_file_write_str(fp, cm_store_entry_field_key_next_pubkey,
				entry->cm_key_next_pubkey);
	cm_store_file_write_str(fp, cm_store_entry_field_key_next_pubkey_info,
				entry->cm_key_next_pubkey_info);

	if (entry->cm_key_generated_date != 0) {
		cm_store_file_write_str(fp, cm_store_entry_field_key_generated_date,
					cm_store_timestamp_from_time(entry->cm_key_generated_date,
								     timestamp));
	}
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		cm_store_file_write_str(fp, cm_store_entry_field_key_next_generated_date,
					cm_store_timestamp_from_time(entry->cm_key_next_generated_date,
								     timestamp));
	}
	cm_store_file_write_int(fp, cm_store_entry_field_key_requested_count,
				entry->cm_key_requested_count);
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		cm_store_file_write_int(fp, cm_store_entry_field_key_next_requested_count,
					entry->cm_key_next_requested_count);
	}
	cm_store_file_write_int(fp, cm_store_entry_field_key_issued_count,
				entry->cm_key_issued_count);

	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		cm_store_file_write_str(fp,
					cm_store_entry_field_cert_storage_type,
					"FILE");
		break;
	case cm_cert_storage_nssdb:
		cm_store_file_write_str(fp,
					cm_store_entry_field_cert_storage_type,
					"NSSDB");
		break;
	}
	cm_store_file_write_str(fp, cm_store_entry_field_cert_storage_location,
				entry->cm_cert_storage_location);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_token,
				entry->cm_cert_token);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_nickname,
				entry->cm_cert_nickname);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_owner,
				entry->cm_cert_owner);
	cm_store_file_write_octal(fp, cm_store_entry_field_cert_perms,
				  entry->cm_cert_perms);

	cm_store_file_write_str(fp, cm_store_entry_field_cert_issuer_der,
				entry->cm_cert_issuer_der);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_issuer,
				entry->cm_cert_issuer);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_serial,
				entry->cm_cert_serial);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_subject_der,
				entry->cm_cert_subject_der);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_subject,
				entry->cm_cert_subject);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_spki,
				entry->cm_cert_spki);
	if (entry->cm_cert_not_before != 0) {
		cm_store_file_write_str(fp, cm_store_entry_field_cert_not_before,
					cm_store_timestamp_from_time(entry->cm_cert_not_before,
								     timestamp));
	}
	if (entry->cm_cert_not_after != 0) {
		cm_store_file_write_str(fp, cm_store_entry_field_cert_not_after,
					cm_store_timestamp_from_time(entry->cm_cert_not_after,
								     timestamp));
	}
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_hostname,
				 entry->cm_cert_hostname);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_email,
				 entry->cm_cert_email);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_principal,
				 entry->cm_cert_principal);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_ipaddress,
				 entry->cm_cert_ipaddress);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_ku,
				entry->cm_cert_ku);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_eku,
				entry->cm_cert_eku);
	cm_store_file_write_int(fp, cm_store_entry_field_cert_is_ca,
				entry->cm_cert_is_ca ? 1 : 0);
	cm_store_file_write_int(fp, cm_store_entry_field_cert_ca_path_length,
				entry->cm_cert_ca_path_length);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_crl_distribution_point,
				 entry->cm_cert_crl_distribution_point);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_freshest_crl,
				 entry->cm_cert_freshest_crl);
	cm_store_file_write_strs(fp, cm_store_entry_field_cert_ocsp_location,
				 entry->cm_cert_ocsp_location);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_ns_comment,
				entry->cm_cert_ns_comment);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_profile,
				entry->cm_cert_profile);
	cm_store_file_write_str(fp, cm_store_entry_field_cert_ns_certtype,
				entry->cm_cert_ns_certtype);
	cm_store_file_write_int(fp, cm_store_entry_field_cert_no_ocsp_check,
				entry->cm_cert_no_ocsp_check ? 1 : 0);

	cm_store_file_write_str(fp, cm_store_entry_field_nss_user,
				entry->cm_nss_user);

	cm_store_file_write_str(fp, cm_store_entry_field_last_need_notify_check,
				cm_store_timestamp_from_time(entry->cm_last_need_notify_check,
							     timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_last_need_enroll_check,
				cm_store_timestamp_from_time(entry->cm_last_need_enroll_check,
							     timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_template_subject_der,
				entry->cm_template_subject_der);
	cm_store_file_write_str(fp, cm_store_entry_field_template_subject,
				entry->cm_template_subject);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_hostname,
				 entry->cm_template_hostname);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_email,
				 entry->cm_template_email);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_principal,
				 entry->cm_template_principal);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_ipaddress,
				 entry->cm_template_ipaddress);
	cm_store_file_write_str(fp, cm_store_entry_field_template_ku,
				entry->cm_template_ku);
	cm_store_file_write_str(fp, cm_store_entry_field_template_eku,
				entry->cm_template_eku);
	cm_store_file_write_int(fp, cm_store_entry_field_template_is_ca,
				entry->cm_template_is_ca ? 1 : 0);
	cm_store_file_write_int(fp, cm_store_entry_field_template_ca_path_length,
				entry->cm_template_ca_path_length);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_crl_distribution_point,
				 entry->cm_template_crl_distribution_point);
	cm_store_file_write_strs(fp, cm_store_entry_field_template_freshest_crl,
				 entry->cm_template_freshest_crl);
	cm_store_file_write_strs(fp,
				 cm_store_entry_field_template_ocsp_location,
				 entry->cm_template_ocsp_location);
	cm_store_file_write_str(fp, cm_store_entry_field_template_ns_comment,
				entry->cm_template_ns_comment);
	cm_store_file_write_str(fp, cm_store_entry_field_template_profile,
				entry->cm_template_profile);
	cm_store_file_write_str(fp, cm_store_entry_field_template_issuer,
				entry->cm_template_issuer);
	cm_store_file_write_int(fp, cm_store_entry_field_template_no_ocsp_check,
				entry->cm_template_no_ocsp_check ? 1 : 0);
	cm_store_file_write_str(fp, cm_store_entry_field_template_ns_certtype,
				entry->cm_template_ns_certtype);
	cm_store_file_write_str(fp, cm_store_entry_field_template_certificate_template,
				entry->cm_template_certificate_template);

	cm_store_file_write_str(fp, cm_store_entry_field_challenge_password,
				entry->cm_template_challenge_password);
	cm_store_file_write_str(fp, cm_store_entry_field_challenge_password_file,
				entry->cm_template_challenge_password_file);

	cm_store_file_write_str(fp, cm_store_entry_field_csr, entry->cm_csr);
	cm_store_file_write_str(fp, cm_store_entry_field_spkac,
				entry->cm_spkac);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_tx,
				entry->cm_scep_tx);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_nonce,
				entry->cm_scep_nonce);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_last_nonce,
				entry->cm_scep_last_nonce);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_gic,
				entry->cm_scep_gic);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_gic_next,
				entry->cm_scep_gic_next);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_req,
				entry->cm_scep_req);
	cm_store_file_write_str(fp, cm_store_entry_field_scep_req_next,
				entry->cm_scep_req_next);
	cm_store_file_write_str(fp, cm_store_entry_field_minicert,
				entry->cm_minicert);

	cm_store_file_write_str(fp, cm_store_entry_field_state,
				cm_store_state_as_string(entry->cm_state));

	cm_store_file_write_int(fp, cm_store_entry_field_autorenew,
				entry->cm_autorenew);

	cm_store_file_write_int(fp, cm_store_entry_field_monitor,
				entry->cm_monitor);

	cm_store_file_write_str(fp, cm_store_entry_field_ca_nickname,
				entry->cm_ca_nickname);
	cm_store_file_write_str(fp, cm_store_entry_field_submitted,
				cm_store_timestamp_from_time(entry->cm_submitted,
							      timestamp));
	cm_store_file_write_str(fp, cm_store_entry_field_ca_cookie,
				entry->cm_ca_cookie);
	cm_store_file_write_str(fp, cm_store_entry_field_ca_error,
				entry->cm_ca_error);
	cm_store_file_write_str(fp, cm_store_entry_field_cert, entry->cm_cert);
	cm_store_file_write_nickcert_list(fp, cm_store_entry_field_cert_chain,
					  entry->cm_cert_chain);
	cm_store_file_write_nickcert_list(fp, cm_store_entry_field_cert_roots,
					  entry->cm_cert_roots);
	cm_store_file_write_str(fp, cm_store_entry_field_pre_certsave_command,
				entry->cm_pre_certsave_command);
	cm_store_file_write_str(fp, cm_store_entry_field_pre_certsave_uid,
				entry->cm_pre_certsave_uid);
	cm_store_file_write_str(fp, cm_store_entry_field_post_certsave_command,
				entry->cm_post_certsave_command);
	cm_store_file_write_str(fp, cm_store_entry_field_post_certsave_uid,
				entry->cm_post_certsave_uid);

	cm_store_file_write_strs(fp, cm_store_entry_field_root_cert_files,
				 entry->cm_root_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_entry_field_other_root_cert_files,
				 entry->cm_other_root_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_entry_field_other_cert_files,
				 entry->cm_other_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_entry_field_root_cert_nssdbs,
				 entry->cm_root_cert_store_nssdbs);
	cm_store_file_write_strs(fp, cm_store_entry_field_other_root_cert_nssdbs,
				 entry->cm_other_root_cert_store_nssdbs);
	cm_store_file_write_strs(fp, cm_store_entry_field_other_cert_nssdbs,
				 entry->cm_other_cert_store_nssdbs);

	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

int
cm_store_entry_delete(struct cm_store_entry *entry)
{
	int ret;
	const char *filename;

	if (entry->cm_store_private != NULL) {
		filename = (const char *) entry->cm_store_private;
		ret = remove(filename);
		if (ret == 0) {
			cm_log(3, "Removed file \"%s\".\n", filename);
			talloc_free(entry->cm_store_private);
			entry->cm_store_private = NULL;
		} else {
			cm_log(0, "Failed to remove file \"%s\": %s.\n",
			       filename, strerror(errno));
		}
	} else {
		cm_log(3, "No file to remove for \"%s\".\n",
		       entry->cm_nickname);
	}
	return 0;
}

static void
cm_store_create_containing_dir(const char *path, int mode)
{
	char dir[PATH_MAX];
	int i;
	if (strlen(path) >= sizeof(dir)) {
		return;
	}
	for (i = 0, dir[0] = '\0'; path[i] != '\0'; i++) {
		if ((i > 0) && (path[i] == '/')) {
			if (mkdir(dir, mode) == -1) {
				if (errno != EEXIST) {
					cm_log(1, "Failed to create \"%s\": "
					       "%s.\n", dir, strerror(errno));
					break;
				}
			} else {
				cm_log(2, "Created \"%s\".\n", dir);
			}
		}
		dir[i] = path[i];
		dir[i + 1] = '\0';
	}
}

static void
cm_store_fsync_parent_dir(const char *filepath)
{
	char dir[PATH_MAX];
	int dfd;
	if (strlen(filepath) >= sizeof(dir)) {
		return;
	}
	strcpy(dir, filepath);
	dfd = open(dirname(dir), O_RDONLY);
	if (dfd != -1) {
		fsync(dfd);
		close(dfd);
	}
}

int
cm_store_entry_save(struct cm_store_entry *entry)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd = -1, give_up;
	const char *directory, *dest;

	if (entry->cm_store_private == NULL) {
		cm_store_timestamp_from_time(cm_time(NULL), timestamp);
		directory = cm_env_request_dir();
		if (directory != NULL) {
			snprintf(path, sizeof(path), "%s/%s",
				 directory, timestamp);
			fd = open(path,
				  O_WRONLY | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
			if ((fd == -1) && (errno == ENOENT)) {
				cm_store_create_containing_dir(path, S_IRWXU);
				fd = open(path,
					  O_WRONLY | O_CREAT | O_EXCL,
					  S_IRUSR | S_IWUSR);
			}
		}
		if (fd == -1) {
			switch (errno) {
			case ENOENT:
			case EPERM:
			case EACCES:
				break;
			default:
				for (give_up = 0, i = 1;
				     !give_up && (i < 1024);
				     i++) {
					snprintf(path, sizeof(path), "%s/%s-%d",
						 directory, timestamp, i);
					fd = open(path,
						  O_WRONLY | O_CREAT | O_EXCL,
						  S_IRUSR | S_IWUSR);
					if (fd != -1) {
						break;
					}
					switch (errno) {
					case ENOENT:
					case EPERM:
					case EACCES:
						give_up++;
						break;
					}
				}
				break;
			}
		}
		if (fd == -1) {
			return -1;
		}
		close(fd);
		entry->cm_store_private = talloc_strdup(entry, path);
	}

	snprintf(path, sizeof(path), "%s.tmp",
		 (const char *) entry->cm_store_private);
	fp = fopen(path, "w");
	if (fp != NULL) {
		if (cm_store_entry_write(fp, entry) == 0) {
			if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
				cm_log(0, "Error syncing \"%s\": %s.\n",
				       path, strerror(errno));
				fclose(fp);
				remove(path);
				return -1;
			}
			fclose(fp);
			dest = (const char *) entry->cm_store_private;
			cm_log(0, "Wrote to %s\n", dest);
			if (rename(path, dest) != 0) {
				cm_log(0, "Error renaming \"%s\" to \"%s\": "
				       "%s.\n", path, dest, strerror(errno));
				return -1;
			}
			cm_store_fsync_parent_dir(dest);
			return 0;
		} else {
			fclose(fp);
			if (remove(path) != 0) {
				cm_log(0, "Error removing \"%s\": %s.\n", path,
				       strerror(errno));
			}
			return -1;
		}
	} else {
		cm_log(1, "Error opening \"%s\" for writing: %s.\n",
		       path, strerror(errno));
		return -1;
	}
}

struct cm_store_entry **
cm_store_get_all_entries(void *parent)
{
	struct cm_store_entry **ret;
	unsigned int i;
	int j, k;
	const char *directory;
	char path[PATH_MAX + 1], *p;
	FILE *fp;
	glob_t globs;

	directory = cm_env_request_dir();
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) == 0) {
		ret = talloc_array_ptrtype(parent, ret, globs.gl_pathc + 1);
		if (ret != NULL) {
			for (i = 0, j = 0; i < globs.gl_pathc; i++) {
				p = globs.gl_pathv[i];
				if (cm_store_should_ignore_file(p)) {
					continue;
				}
				fp = fopen(globs.gl_pathv[i], "r");
				if (fp != NULL) {
					ret[j] = cm_store_entry_read(ret,
								     globs.gl_pathv[i],
								     fp);
					if ((ret[j] != NULL) &&
					    (ret[j]->cm_nickname == NULL)) {
						talloc_free(ret[j]);
						ret[j] = NULL;
					}
					if (ret[j] != NULL) {
						/* Check for duplicate names. */
						for (k = 0; k < j; k++) {
							if (strcmp(ret[k]->cm_nickname,
								   ret[j]->cm_nickname) == 0) {
								cm_store_entry_delete(ret[j]);
								talloc_free(ret[j]);
								ret[j] = NULL;
								break;
							}
						}
						if (k == j) {
							j++;
						}
					}
					fclose(fp);
				}
			}
			ret[j] = NULL;
		}
		globfree(&globs);
	}
	return ret;
}

static int
cm_store_ca_write(FILE *fp, struct cm_store_ca *ca)
{
	const char *p;
	char timestamp[15];

	if (ca->cm_nickname == NULL) {
		p = cm_store_timestamp_from_time(cm_time(NULL), timestamp);
	} else {
		p = ca->cm_nickname;
	}
	cm_store_file_write_str(fp, cm_store_file_field_id, p);
	cm_store_file_write_str(fp, cm_store_ca_field_aka, ca->cm_ca_aka);
	cm_store_file_write_strs(fp,
				 cm_store_ca_field_known_issuer_names,
				 ca->cm_ca_known_issuer_names);
	cm_store_file_write_int(fp, cm_store_ca_field_is_default,
				ca->cm_ca_is_default);
	switch (ca->cm_ca_type) {
	case cm_ca_internal_self:
		cm_store_file_write_str(fp, cm_store_ca_field_type,
					"INTERNAL:SELF");
		cm_store_file_write_str(fp, cm_store_ca_field_internal_serial,
					ca->cm_ca_internal_serial);
		if (ca->cm_ca_internal_force_issue_time) {
			cm_store_file_write_int(fp, cm_store_ca_field_internal_issue_time,
						ca->cm_ca_internal_issue_time);
		}
		break;
	case cm_ca_external:
		cm_store_file_write_str(fp, cm_store_ca_field_type,
					"EXTERNAL");
		cm_store_file_write_str(fp, cm_store_ca_field_external_helper,
					ca->cm_ca_external_helper);
		break;
	}
	cm_store_file_write_nickcert_list(fp, cm_store_ca_field_root_certs,
					  ca->cm_ca_root_certs);
	cm_store_file_write_nickcert_list(fp, cm_store_ca_field_other_root_certs,
					  ca->cm_ca_other_root_certs);
	cm_store_file_write_nickcert_list(fp, cm_store_ca_field_other_certs,
					  ca->cm_ca_other_certs);
	cm_store_file_write_strs(fp,
				 cm_store_ca_field_required_enroll_attributes,
				 ca->cm_ca_required_enroll_attributes);
	cm_store_file_write_strs(fp,
				 cm_store_ca_field_required_renewal_attributes,
				 ca->cm_ca_required_renewal_attributes);
	cm_store_file_write_strs(fp, cm_store_ca_field_profiles,
				 ca->cm_ca_profiles);
	cm_store_file_write_str(fp, cm_store_ca_field_default_profile,
				ca->cm_ca_default_profile);
	cm_store_file_write_str(fp, cm_store_ca_field_pre_save_command,
				ca->cm_ca_pre_save_command);
	cm_store_file_write_str(fp, cm_store_ca_field_pre_save_uid,
				ca->cm_ca_pre_save_uid);
	cm_store_file_write_str(fp, cm_store_ca_field_post_save_command,
				ca->cm_ca_post_save_command);
	cm_store_file_write_str(fp, cm_store_ca_field_post_save_uid,
				ca->cm_ca_post_save_uid);
	cm_store_file_write_strs(fp, cm_store_ca_field_root_cert_files,
				 ca->cm_ca_root_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_ca_field_other_root_cert_files,
				 ca->cm_ca_other_root_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_ca_field_other_cert_files,
				 ca->cm_ca_other_cert_store_files);
	cm_store_file_write_strs(fp, cm_store_ca_field_root_cert_nssdbs,
				 ca->cm_ca_root_cert_store_nssdbs);
	cm_store_file_write_strs(fp, cm_store_ca_field_other_root_cert_nssdbs,
				 ca->cm_ca_other_root_cert_store_nssdbs);
	cm_store_file_write_strs(fp, cm_store_ca_field_other_cert_nssdbs,
				 ca->cm_ca_other_cert_store_nssdbs);
	cm_store_file_write_strs(fp, cm_store_ca_field_capabilities,
				 ca->cm_ca_capabilities);
	cm_store_file_write_str(fp, cm_store_ca_field_scep_cipher,
				ca->cm_ca_scep_cipher);
	cm_store_file_write_str(fp, cm_store_ca_field_scep_digest,
				ca->cm_ca_scep_digest);
	cm_store_file_write_str(fp, cm_store_ca_field_scep_ca_identifier,
				ca->cm_ca_scep_ca_identifier);
	cm_store_file_write_str(fp, cm_store_ca_field_encryption_cert,
				ca->cm_ca_encryption_cert);
	cm_store_file_write_str(fp, cm_store_ca_field_encryption_issuer_cert,
				ca->cm_ca_encryption_issuer_cert);
	cm_store_file_write_str(fp, cm_store_ca_field_encryption_cert_pool,
				ca->cm_ca_encryption_cert_pool);
	if (ferror(fp)) {
		return -1;
	}
	return 0;
}

int
cm_store_ca_delete(struct cm_store_ca *ca)
{
	int ret;
	const char *filename;

	if (ca->cm_store_private != NULL) {
		filename = (const char *) ca->cm_store_private;
		ret = remove(ca->cm_store_private);
		if (ret == 0) {
			cm_log(3, "Removed file \"%s\".\n", filename);
			talloc_free(ca->cm_store_private);
			ca->cm_store_private = NULL;
		} else {
			cm_log(1, "Failed to remove file \"%s\": %s.\n",
			       filename, strerror(errno));
		}
	} else {
		cm_log(3, "No file to remove for \"%s\".\n", ca->cm_nickname);
	}
	return 0;
}

int
cm_store_ca_save(struct cm_store_ca *ca)
{
	FILE *fp;
	char timestamp[15], path[PATH_MAX];
	int i, fd = -1, give_up;
	const char *directory, *dest;

	if (ca->cm_store_private == NULL) {
		cm_store_timestamp_from_time(cm_time(NULL), timestamp);
		directory = cm_env_ca_dir();
		if (directory != NULL) {
			snprintf(path, sizeof(path), "%s/%s", directory, timestamp);
			fd = open(path,
				  O_WRONLY | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
			if ((fd == -1) && (errno == ENOENT)) {
				cm_store_create_containing_dir(path, S_IRWXU);
				fd = open(path,
					  O_WRONLY | O_CREAT | O_EXCL,
					  S_IRUSR | S_IWUSR);
			}
			if (fd == -1) {
				switch (errno) {
				case ENOENT:
				case EPERM:
				case EACCES:
					break;
				default:
					for (give_up = 0, i = 1;
					     !give_up && (i < 1024);
					     i++) {
						snprintf(path, sizeof(path), "%s/%s-%d",
							 directory, timestamp, i);
						fd = open(path,
							  O_WRONLY | O_CREAT | O_EXCL,
							  S_IRUSR | S_IWUSR);
						if (fd != -1) {
							break;
						}
						switch (errno) {
						case ENOENT:
						case EPERM:
						case EACCES:
							give_up++;
							break;
						}
					}
					break;
				}
			}
		}
		if (fd == -1) {
			return -1;
		}
		close(fd);
		ca->cm_store_private = talloc_strdup(ca, path);
	}

	snprintf(path, sizeof(path), "%s.tmp",
		 (const char *) ca->cm_store_private);
	fp = fopen(path, "w");
	if (fp != NULL) {
		if (cm_store_ca_write(fp, ca) == 0) {
			if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
				cm_log(0, "Error syncing \"%s\": %s.\n",
				       path, strerror(errno));
				fclose(fp);
				remove(path);
				return -1;
			}
			fclose(fp);
			dest = (const char *) ca->cm_store_private;
			if (rename(path, dest) != 0) {
				cm_log(0, "Error renaming \"%s\" to \"%s\": "
				       "%s.\n", path, dest, strerror(errno));
				return -1;
			}
			cm_store_fsync_parent_dir(dest);
			return 0;
		} else {
			fclose(fp);
			if (remove(path) != 0) {
				cm_log(0, "Error removing \"%s\": %s.\n", path,
				       strerror(errno));
			}
			return -1;
		}
	} else {
		cm_log(1, "Error opening \"%s\" for writing: %s.\n", path,
		       strerror(errno));
		return -1;
	}
}

struct cm_store_ca **
cm_store_get_all_cas(void *parent)
{
	struct cm_store_ca **ret;
	unsigned int i;
	int j, k;
	const char *directory;
	char path[PATH_MAX + 1], *p;
	FILE *fp;
	glob_t globs;

	directory = cm_env_ca_dir();
	snprintf(path, sizeof(path), "%s/*", directory);
	memset(&globs, 0, sizeof(globs));
	ret = NULL;
	if (glob(path, 0, NULL, &globs) != 0) {
		globs.gl_pathc = 0;
	}
	ret = talloc_array_ptrtype(parent, ret, globs.gl_pathc + 6);
	if (ret != NULL) {
		for (i = 0, j = 0; i < globs.gl_pathc; i++) {
			p = globs.gl_pathv[i];
			if (cm_store_should_ignore_file(p)) {
				continue;
			}
			fp = fopen(globs.gl_pathv[i], "r");
			if (fp != NULL) {
				ret[j] = cm_store_ca_read(ret,
							  globs.gl_pathv[i],
							  fp);
				if ((ret[j] != NULL) &&
				    (ret[j]->cm_nickname == NULL)) {
					talloc_free(ret[j]);
					ret[j] = NULL;
				}
				if (ret[j] != NULL) {
					/* Check for duplicate names. */
					for (k = 0; k < j; k++) {
						if (strcmp(ret[k]->cm_nickname,
							   ret[j]->cm_nickname) == 0) {
							cm_store_ca_delete(ret[j]);
							talloc_free(ret[j]);
							ret[j] = NULL;
							break;
						}
					}
					if (k == j) {
						j++;
					}
				}
				fclose(fp);
			}
		}
		/* Make sure we get at least one internal/self sign entry. */
		for (k = 0; k < j; k++) {
			if (ret[k]->cm_ca_type == cm_ca_internal_self) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_SELF_SIGN_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_internal_self;
			ret[j]->cm_ca_internal_serial = talloc_strdup(ret[j],
								      CM_DEFAULT_CERT_SERIAL);
			j++;
		}
#ifdef WITH_IPA
		/* Make sure we get at least one IPA entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_IPA_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_IPA_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_IPA_HELPER_PATH);
			j++;
		}
#endif
#ifdef WITH_XMLRPC
#ifdef WITH_CERTMASTER
		/* Make sure we get at least one certmaster entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_CERTMASTER_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_CERTMASTER_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_CERTMASTER_HELPER_PATH);
			j++;
		}
#endif
#endif
#ifdef WITH_IPA
		/* Make sure we get at least 1 dogtag-ipa-renew-agent entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_DOGTAG_IPA_RENEW_AGENT_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_DOGTAG_IPA_RENEW_AGENT_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_DOGTAG_IPA_RENEW_AGENT_HELPER_PATH);
			j++;
		}
#endif
#ifdef WITH_LOCAL
		/* Make sure we get at least 1 "local" entry. */
		for (k = 0; k < j; k++) {
			if ((ret[k]->cm_ca_type == cm_ca_external) &&
			    (strcmp(ret[k]->cm_nickname,
				    CM_LOCAL_CA_NAME) == 0)) {
				break;
			}
		}
		if (k == j) {
			ret[j] = cm_store_ca_new(ret);
			ret[j]->cm_busname = cm_store_ca_next_busname(ret[j]);
			ret[j]->cm_nickname = talloc_strdup(ret[j],
							    CM_LOCAL_CA_NAME);
			ret[j]->cm_ca_type = cm_ca_external;
			ret[j]->cm_ca_external_helper = talloc_strdup(ret[j],
								      CM_LOCAL_HELPER_PATH);
			j++;
		}
#endif
		ret[j] = NULL;
	}
	if (globs.gl_pathc > 0) {
		globfree(&globs);
	}
	return ret;
}

static struct cm_nickcert **
cm_store_maybe_dup_nickcert_list(void *parent, struct cm_nickcert **certs)
{
	struct cm_nickcert **ret = NULL, *nc;
	int i;

	if (certs == NULL) {
		return NULL;
	}
	for (i = 0; certs[i] != NULL; i++) {
		continue;
	}
	ret = talloc_array_ptrtype(parent, ret, i + 1);
	if (ret == NULL) {
		return NULL;
	}
	for (i = 0; certs[i] != NULL; i++) {
		nc = talloc_ptrtype(parent, nc);
		if (nc == NULL) {
			talloc_free(ret);
			return NULL;
		}
		memset(nc, 0, sizeof(*nc));
		nc->cm_nickname = talloc_strdup(nc, certs[i]->cm_nickname);
		nc->cm_cert = talloc_strdup(nc, certs[i]->cm_cert);
		if ((nc->cm_nickname == NULL) || (nc->cm_cert == NULL)) {
			talloc_free(ret);
			return NULL;
		}
		ret[i] = nc;
	}
	ret[i] = NULL;
	return ret;
}

struct cm_store_entry *
cm_store_entry_dup(void *parent, struct cm_store_entry *entry)
{
	struct cm_store_entry *ret;

	ret = cm_store_entry_new(parent);
	if (ret == NULL) {
		return ret;
	}

	ret->cm_busname = cm_store_maybe_strdup(ret, entry->cm_busname);
	ret->cm_store_private =
		cm_store_maybe_strdup(ret, entry->cm_store_private);
	ret->cm_nickname = cm_store_maybe_strdup(ret, entry->cm_nickname);

	ret->cm_key_type = entry->cm_key_type;
	ret->cm_key_storage_type = entry->cm_key_storage_type;
	ret->cm_key_storage_location = cm_store_maybe_strdup(ret, entry->cm_key_storage_location);
	ret->cm_key_token = cm_store_maybe_strdup(ret, entry->cm_key_token);
	ret->cm_key_nickname = cm_store_maybe_strdup(ret, entry->cm_key_nickname);
	ret->cm_key_pin = cm_store_maybe_strdup(ret, entry->cm_key_pin);
	ret->cm_key_pin_file = cm_store_maybe_strdup(ret, entry->cm_key_pin_file);
	if (ret->cm_key_pin_file != NULL) {
		ret->cm_key_pin = NULL;
	}
	ret->cm_key_owner = cm_store_maybe_strdup(ret, entry->cm_key_owner);
	ret->cm_key_perms = entry->cm_key_perms;
	ret->cm_key_pubkey = cm_store_maybe_strdup(ret, entry->cm_key_pubkey);
	ret->cm_key_pubkey_info = cm_store_maybe_strdup(ret, entry->cm_key_pubkey_info);

	ret->cm_key_next_type = entry->cm_key_next_type;
	ret->cm_key_next_pubkey = cm_store_maybe_strdup(ret, entry->cm_key_next_pubkey);
	ret->cm_key_next_pubkey_info = cm_store_maybe_strdup(ret, entry->cm_key_next_pubkey_info);
	ret->cm_key_next_marker = cm_store_maybe_strdup(ret, entry->cm_key_next_marker);
	ret->cm_key_preserve = entry->cm_key_preserve;

	ret->cm_key_generated_date = entry->cm_key_generated_date;
	ret->cm_key_next_generated_date = entry->cm_key_next_generated_date;
	ret->cm_key_requested_count = entry->cm_key_requested_count;
	ret->cm_key_next_requested_count = entry->cm_key_next_requested_count;
	ret->cm_key_issued_count = entry->cm_key_issued_count;

	ret->cm_nss_user = cm_store_maybe_strdup(ret, entry->cm_nss_user);

	ret->cm_cert_storage_type = entry->cm_cert_storage_type;
	ret->cm_cert_storage_location = cm_store_maybe_strdup(ret, entry->cm_cert_storage_location);
	ret->cm_cert_token = cm_store_maybe_strdup(ret, entry->cm_cert_token);
	ret->cm_cert_nickname = cm_store_maybe_strdup(ret, entry->cm_cert_nickname);
	ret->cm_cert_owner = cm_store_maybe_strdup(ret, entry->cm_cert_owner);
	ret->cm_cert_perms = entry->cm_cert_perms;

	ret->cm_cert_issuer_der = cm_store_maybe_strdup(ret, entry->cm_cert_issuer_der);
	ret->cm_cert_issuer = cm_store_maybe_strdup(ret, entry->cm_cert_issuer);
	ret->cm_cert_serial = cm_store_maybe_strdup(ret, entry->cm_cert_serial);
	ret->cm_cert_subject_der = cm_store_maybe_strdup(ret, entry->cm_cert_subject_der);
	ret->cm_cert_subject = cm_store_maybe_strdup(ret, entry->cm_cert_subject);
	ret->cm_cert_spki = cm_store_maybe_strdup(ret, entry->cm_cert_spki);
	ret->cm_cert_not_before = entry->cm_cert_not_before;
	ret->cm_cert_not_after = entry->cm_cert_not_after;
	ret->cm_cert_hostname = cm_store_maybe_strdupv(ret, entry->cm_cert_hostname);
	ret->cm_cert_email = cm_store_maybe_strdupv(ret, entry->cm_cert_email);
	ret->cm_cert_principal = cm_store_maybe_strdupv(ret, entry->cm_cert_principal);
	ret->cm_cert_ipaddress = cm_store_maybe_strdupv(ret, entry->cm_cert_ipaddress);
	ret->cm_cert_ku = cm_store_maybe_strdup(ret, entry->cm_cert_ku);
	ret->cm_cert_eku = cm_store_maybe_strdup(ret, entry->cm_cert_eku);
	ret->cm_cert_is_ca = entry->cm_cert_is_ca;
	ret->cm_cert_ca_path_length = entry->cm_cert_ca_path_length;
	ret->cm_cert_crl_distribution_point = cm_store_maybe_strdupv(ret, entry->cm_cert_crl_distribution_point);
	ret->cm_cert_freshest_crl = cm_store_maybe_strdupv(ret, entry->cm_cert_freshest_crl);
	ret->cm_cert_ocsp_location = cm_store_maybe_strdupv(ret, entry->cm_cert_ocsp_location);
	ret->cm_cert_ns_comment = cm_store_maybe_strdup(ret, entry->cm_cert_ns_comment);
	ret->cm_cert_profile = cm_store_maybe_strdup(ret,
						     entry->cm_cert_profile);
	ret->cm_cert_no_ocsp_check = entry->cm_cert_no_ocsp_check;
	ret->cm_cert_ns_certtype = cm_store_maybe_strdup(ret,
							 entry->cm_cert_ns_certtype);

	ret->cm_last_need_notify_check = entry->cm_last_need_notify_check;
	ret->cm_last_need_enroll_check = entry->cm_last_need_enroll_check;
	ret->cm_notification_method = entry->cm_notification_method;
	ret->cm_notification_destination = cm_store_maybe_strdup(ret, entry->cm_notification_destination);

	ret->cm_template_subject_der = cm_store_maybe_strdup(ret, entry->cm_template_subject_der);
	ret->cm_template_subject = cm_store_maybe_strdup(ret, entry->cm_template_subject);
	ret->cm_template_hostname = cm_store_maybe_strdupv(ret, entry->cm_template_hostname);
	ret->cm_template_email = cm_store_maybe_strdupv(ret, entry->cm_template_email);
	ret->cm_template_principal = cm_store_maybe_strdupv(ret, entry->cm_template_principal);
	ret->cm_template_ipaddress = cm_store_maybe_strdupv(ret, entry->cm_template_ipaddress);
	ret->cm_template_ku = cm_store_maybe_strdup(ret, entry->cm_template_ku);
	ret->cm_template_eku = cm_store_maybe_strdup(ret, entry->cm_template_eku);
	ret->cm_template_is_ca = entry->cm_template_is_ca;
	ret->cm_template_ca_path_length = entry->cm_template_ca_path_length;
	ret->cm_template_crl_distribution_point = cm_store_maybe_strdupv(ret, entry->cm_template_crl_distribution_point);
	ret->cm_template_freshest_crl = cm_store_maybe_strdupv(ret, entry->cm_template_freshest_crl);
	ret->cm_template_ocsp_location = cm_store_maybe_strdupv(ret, entry->cm_template_ocsp_location);
	ret->cm_template_ns_comment = cm_store_maybe_strdup(ret, entry->cm_template_ns_comment);
	ret->cm_template_profile = cm_store_maybe_strdup(ret, entry->cm_template_profile);
	ret->cm_template_issuer = cm_store_maybe_strdup(ret, entry->cm_template_issuer);
	ret->cm_template_no_ocsp_check = entry->cm_template_no_ocsp_check;
	ret->cm_template_certificate_template =
		cm_store_maybe_strdup(ret, entry->cm_template_certificate_template);
	ret->cm_template_ns_certtype = cm_store_maybe_strdup(ret,
							     entry->cm_template_ns_certtype);

	ret->cm_template_challenge_password = cm_store_maybe_strdup(ret, entry->cm_template_challenge_password);
	ret->cm_template_challenge_password_file = cm_store_maybe_strdup(ret, entry->cm_template_challenge_password_file);
	ret->cm_csr = cm_store_maybe_strdup(ret, entry->cm_csr);
	ret->cm_spkac = cm_store_maybe_strdup(ret, entry->cm_spkac);
	ret->cm_scep_tx = cm_store_maybe_strdup(ret, entry->cm_scep_tx);
	ret->cm_scep_nonce = cm_store_maybe_strdup(ret, entry->cm_scep_nonce);
	ret->cm_scep_last_nonce = cm_store_maybe_strdup(ret, entry->cm_scep_last_nonce);
	ret->cm_scep_gic = cm_store_maybe_strdup(ret, entry->cm_scep_gic);
	ret->cm_scep_gic_next = cm_store_maybe_strdup(ret, entry->cm_scep_gic_next);
	ret->cm_scep_req = cm_store_maybe_strdup(ret, entry->cm_scep_req);
	ret->cm_scep_req_next = cm_store_maybe_strdup(ret, entry->cm_scep_req_next);
	ret->cm_minicert = cm_store_maybe_strdup(ret, entry->cm_minicert);
	ret->cm_state = entry->cm_state;
	ret->cm_autorenew = entry->cm_autorenew;
	ret->cm_monitor = entry->cm_monitor;
	ret->cm_ca_nickname = cm_store_maybe_strdup(ret, entry->cm_ca_nickname);
	ret->cm_submitted = entry->cm_submitted;
	ret->cm_ca_cookie = cm_store_maybe_strdup(ret, entry->cm_ca_cookie);
	ret->cm_ca_error = cm_store_maybe_strdup(ret, entry->cm_ca_error);
	ret->cm_cert = cm_store_maybe_strdup(ret, entry->cm_cert);
	ret->cm_cert_chain = cm_store_maybe_dup_nickcert_list(ret, entry->cm_cert_chain);
	ret->cm_cert_roots = cm_store_maybe_dup_nickcert_list(ret, entry->cm_cert_roots);
	ret->cm_pre_certsave_command = cm_store_maybe_strdup(ret, entry->cm_pre_certsave_command);
	ret->cm_pre_certsave_uid = cm_store_maybe_strdup(ret, entry->cm_pre_certsave_uid);
	ret->cm_post_certsave_command = cm_store_maybe_strdup(ret, entry->cm_post_certsave_command);
	ret->cm_post_certsave_uid = cm_store_maybe_strdup(ret, entry->cm_post_certsave_uid);
	ret->cm_root_cert_store_files = cm_store_maybe_strdupv(ret, entry->cm_root_cert_store_files);
	ret->cm_other_root_cert_store_files = cm_store_maybe_strdupv(ret, entry->cm_other_root_cert_store_files);
	ret->cm_other_cert_store_files = cm_store_maybe_strdupv(ret, entry->cm_other_cert_store_files);
	ret->cm_root_cert_store_nssdbs = cm_store_maybe_strdupv(ret, entry->cm_other_cert_store_nssdbs);
	ret->cm_other_root_cert_store_nssdbs = cm_store_maybe_strdupv(ret, entry->cm_other_cert_store_nssdbs);
	ret->cm_other_cert_store_nssdbs = cm_store_maybe_strdupv(ret, entry->cm_other_cert_store_nssdbs);

	return ret;
}

struct cm_store_ca *
cm_store_ca_dup(void *parent, struct cm_store_ca *ca)
{
	struct cm_store_ca *ret;

	ret = cm_store_ca_new(parent);
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_busname = cm_store_maybe_strdup(ret, ca->cm_busname);
	ret->cm_store_private =
		cm_store_maybe_strdup(ret, ca->cm_store_private);
	ret->cm_nickname = cm_store_maybe_strdup(ret, ca->cm_nickname);
	ret->cm_ca_aka = cm_store_maybe_strdup(ret, ca->cm_ca_aka);
	ret->cm_ca_error = cm_store_maybe_strdup(ret, ca->cm_ca_error);
	ret->cm_ca_known_issuer_names =
		cm_store_maybe_strdupv(ret, ca->cm_ca_known_issuer_names);
	ret->cm_ca_is_default = ca->cm_ca_is_default;
	ret->cm_ca_type = ca->cm_ca_type;
	ret->cm_ca_internal_serial =
		cm_store_maybe_strdup(ret, ca->cm_ca_internal_serial);
	ret->cm_ca_internal_force_issue_time =
		ca->cm_ca_internal_force_issue_time;
	ret->cm_ca_internal_issue_time = ca->cm_ca_internal_issue_time;
	ret->cm_ca_external_helper =
		cm_store_maybe_strdup(ret, ca->cm_ca_external_helper);
	ret->cm_ca_root_certs =
		cm_store_maybe_dup_nickcert_list(ret, ca->cm_ca_root_certs);
	ret->cm_ca_other_root_certs =
		cm_store_maybe_dup_nickcert_list(ret,
						 ca->cm_ca_other_root_certs);
	ret->cm_ca_other_certs =
		cm_store_maybe_dup_nickcert_list(ret, ca->cm_ca_other_certs);
	ret->cm_ca_required_enroll_attributes =
		cm_store_maybe_strdupv(ret,
				       ca->cm_ca_required_enroll_attributes);
	ret->cm_ca_required_renewal_attributes =
		cm_store_maybe_strdupv(ret,
				       ca->cm_ca_required_renewal_attributes);
	ret->cm_ca_profiles = cm_store_maybe_strdupv(ret, ca->cm_ca_profiles);
	ret->cm_ca_default_profile =
		cm_store_maybe_strdup(ret, ca->cm_ca_default_profile);

	ret->cm_ca_pre_save_command =
		cm_store_maybe_strdup(ret, ca->cm_ca_pre_save_command);
	ret->cm_ca_pre_save_uid =
		cm_store_maybe_strdup(ret, ca->cm_ca_pre_save_uid);
	ret->cm_ca_post_save_command =
		cm_store_maybe_strdup(ret, ca->cm_ca_post_save_command);
	ret->cm_ca_post_save_uid =
		cm_store_maybe_strdup(ret, ca->cm_ca_post_save_uid);

	ret->cm_ca_root_cert_store_files =
		cm_store_maybe_strdupv(ret, ca->cm_ca_root_cert_store_files);
	ret->cm_ca_other_root_cert_store_files =
		cm_store_maybe_strdupv(ret, ca->cm_ca_other_root_cert_store_files);
	ret->cm_ca_other_cert_store_files =
		cm_store_maybe_strdupv(ret, ca->cm_ca_other_cert_store_files);
	ret->cm_ca_root_cert_store_nssdbs =
		cm_store_maybe_strdupv(ret, ca->cm_ca_other_cert_store_nssdbs);
	ret->cm_ca_other_root_cert_store_nssdbs =
		cm_store_maybe_strdupv(ret, ca->cm_ca_other_cert_store_nssdbs);
	ret->cm_ca_other_cert_store_nssdbs =
		cm_store_maybe_strdupv(ret, ca->cm_ca_other_cert_store_nssdbs);

	ret->cm_ca_capabilities =
		cm_store_maybe_strdupv(ret, ca->cm_ca_capabilities);
	ret->cm_ca_scep_cipher =
		cm_store_maybe_strdup(ret, ca->cm_ca_scep_cipher);
	ret->cm_ca_scep_digest =
		cm_store_maybe_strdup(ret, ca->cm_ca_scep_digest);
	ret->cm_ca_scep_ca_identifier =
		cm_store_maybe_strdup(ret, ca->cm_ca_scep_ca_identifier);
	ret->cm_ca_encryption_cert =
		cm_store_maybe_strdup(ret, ca->cm_ca_encryption_cert);
	ret->cm_ca_encryption_issuer_cert =
		cm_store_maybe_strdup(ret, ca->cm_ca_encryption_issuer_cert);
	ret->cm_ca_encryption_cert_pool =
		cm_store_maybe_strdup(ret, ca->cm_ca_encryption_cert_pool);

	return ret;
}

const char *cm_store_algorithm_to_name(int algorithm)
{
	/* See cm_key_algorithm in store-int.h */
	switch(algorithm) {
	case cm_key_rsa:
		return "RSA";
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		return "DSA";
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		return "EC";
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		return "ML-DSA-44";
		break;
	case cm_key_ml_dsa_65:
		return "ML-DSA-65";
		break;
	case cm_key_ml_dsa_87:
		return "ML-DSA-87";
		break;
#endif
	default:
		return "UNKNOWN";
		break;
	}
};
