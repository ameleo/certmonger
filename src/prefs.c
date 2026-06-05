/*
 * Copyright (C) 2010,2011,2012,2014,2015 Red Hat, Inc.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>

#include <dbus/dbus.h>

#include "env.h"
#include "prefs.h"
#include "store-int.h"
#include "submit.h"
#include "submit-u.h"
#include "util.h"
#include "tm.h"

static char *
cm_prefs_read(void)
{
	const char *dir, *base = "/" PACKAGE_NAME ".conf";
	char *path, *ret;
	ret = NULL;
	dir = cm_env_config_dir();
	if (dir != NULL) {
		path = malloc(strlen(dir) + strlen(base) + 1);
		if (path != NULL) {
			snprintf(path, strlen(dir) + strlen(base) + 1,
				 "%s%s", dir, base);
			ret = read_config_file(path);
			free(path);
		}
	}
	return ret;
}

static void cm_prefs_free(void);

static char *
cm_prefs_config(const char *section, const char *key)
{
	static char *cm_configuration = NULL;
	if (key == NULL) {
		return cm_configuration;
	}
	if (cm_configuration == NULL) {
		cm_configuration = cm_prefs_read();
		if (cm_configuration != NULL) {
			atexit(cm_prefs_free);
		}
	}
	if (cm_configuration != NULL) {
		return get_config_entry(cm_configuration,
					section ? section : "defaults",
					key);
	}
	return NULL;
}

static void
cm_prefs_free(void)
{
	char *prefs;
	prefs = cm_prefs_config(NULL, NULL);
	if (prefs != NULL) {
		free(prefs);
	}
}

enum cm_prefs_cipher
cm_prefs_preferred_cipher(void)
{
	char *cipher;
	cipher = cm_prefs_config(NULL, "symmetric_cipher");
	if (cipher != NULL) {
		if (strcasecmp(cipher, "aes") == 0) {
			free(cipher);
			return cm_prefs_aes128;
		}
		if ((strcasecmp(cipher, "aes128") == 0) ||
		    (strcasecmp(cipher, "aes-128") == 0)) {
			free(cipher);
			return cm_prefs_aes128;
		}
		if ((strcasecmp(cipher, "aes256") == 0) ||
		    (strcasecmp(cipher, "aes-256") == 0)) {
			free(cipher);
			return cm_prefs_aes256;
		}
		if (strcasecmp(cipher, "des") == 0) {
			free(cipher);
			return cm_prefs_des;
		}
		if (strcasecmp(cipher, "des3") == 0) {
			free(cipher);
			return cm_prefs_des3;
		}
		free(cipher);
	}
	return cm_prefs_aes128;
}

enum cm_prefs_digest
cm_prefs_preferred_digest(void)
{
	char *digest;
	digest = cm_prefs_config(NULL, "digest");
	if (digest != NULL) {
		if ((strcasecmp(digest, "md5") == 0) ||
		    (strcasecmp(digest, "md-5") == 0)) {
			free(digest);
			return cm_prefs_md5;
		}
		if ((strcasecmp(digest, "sha1") == 0) ||
		    (strcasecmp(digest, "sha-1") == 0)) {
			free(digest);
			return cm_prefs_sha1;
		}
		if ((strcasecmp(digest, "sha256") == 0) ||
		    (strcasecmp(digest, "sha-256") == 0)) {
			free(digest);
			return cm_prefs_sha256;
		}
		if ((strcasecmp(digest, "sha384") == 0) ||
		    (strcasecmp(digest, "sha-384") == 0)) {
			free(digest);
			return cm_prefs_sha384;
		}
		if ((strcasecmp(digest, "sha512") == 0) ||
		    (strcasecmp(digest, "sha-512") == 0)) {
			free(digest);
			return cm_prefs_sha512;
		}
		free(digest);
	}
	return cm_prefs_sha256;
}

static int
cm_prefs_compare_ttl_values(const void *a, const void *b)
{
	time_t ta = *(const time_t *)a;
	time_t tb = *(const time_t *)b;
	if (ta < tb) return -1;
	if (ta > tb) return 1;
	return 0;
}

static int
cm_prefs_ttls(time_t **config, const time_t **ttls, unsigned int *n_ttls,
	      const char *preferred, const char *fallback)
{
	static time_t default_ttls[] = {CM_DEFAULT_TTL_LIST};
	static unsigned int n_config = 0;
	char *confttls, *p, *q, c;
	int i;
	if (*config == NULL) {
		confttls = cm_prefs_config(NULL, preferred);
		if (confttls == NULL) {
			confttls = cm_prefs_config(NULL, fallback);
		}
		if (confttls == NULL) {
			*config = default_ttls;
			n_config = sizeof(default_ttls) /
				   sizeof(default_ttls[0]);
			qsort(*config, n_config, sizeof((*config)[0]),
			      &cm_prefs_compare_ttl_values);
		} else {
			*config = malloc(strlen(confttls) * sizeof((*config)[0]));
			if (*config != NULL) {
				i = 0;
				p = confttls;
				while (strcspn(p, " \t,") > 0) {
					q = p + strcspn(p, " \t,");
					c = *q;
					*q = '\0';
					if (cm_submit_u_delta_from_string(p, cm_time(NULL),
									  &(*config)[i]) == 0) {
						i++;
					};
					*q = c;
					p = q + strspn(q, " \t,");
				}
				n_config = i;
				qsort(*config, n_config, sizeof((*config)[0]),
				      &cm_prefs_compare_ttl_values);
			}
			free(confttls);
		}
	}
	if (*config != NULL) {
		*ttls = *config;
		*n_ttls = n_config;
		return 0;
	}
	return -1;
}

int
cm_prefs_enroll_ttls(const time_t **ttls, unsigned int *n_ttls)
{
	static time_t *config = NULL;
	return cm_prefs_ttls(&config, ttls, n_ttls, "enroll_ttls", "ttls");
}

int
cm_prefs_notify_ttls(const time_t **ttls, unsigned int *n_ttls)
{
	static time_t *config = NULL;
	return cm_prefs_ttls(&config, ttls, n_ttls, "notify_ttls", "ttls");
}

enum cm_notification_method
cm_prefs_notification_method(void)
{
	char *method;
	enum cm_notification_method ret;
	ret = CM_DEFAULT_NOTIFICATION_METHOD;
	method = cm_prefs_config(NULL, "notification_method");
	if (method != NULL) {
		if (strcasecmp(method, "none") == 0) {
			ret = cm_notification_none;
		}
		if (strcasecmp(method, "syslog") == 0) {
			ret = cm_notification_syslog;
		}
		if ((strcasecmp(method, "email") == 0) ||
		    (strcasecmp(method, "mail") == 0) ||
		    (strcasecmp(method, "mailto") == 0)) {
			ret = cm_notification_email;
		}
		if (strcasecmp(method, "stdout") == 0) {
			ret = cm_notification_stdout;
		}
		if (strcasecmp(method, "command") == 0) {
			ret = cm_notification_command;
		}
		free(method);
	}
	return ret;
}

const char *
cm_prefs_notification_destination(void)
{
	static const char *destination;
	if (destination == NULL) {
		destination = cm_prefs_config(NULL, "notification_destination");
		if (destination == NULL) {
			destination = CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY;
		}
	}
	return destination;
}

const char *
cm_prefs_default_ca(void)
{
	static const char *ca;
	if (ca == NULL) {
		ca = cm_prefs_config(NULL, "default_ca");
	}
	return ca;
}

const char *
cm_prefs_selfsign_validity_period(void)
{
	static const char *period;
	if (period == NULL) {
		period = cm_prefs_config("selfsign", "validity_period");
		if (period == NULL) {
			period = CM_DEFAULT_CERT_LIFETIME;
		}
	}
	return period;
}

const char *
cm_prefs_local_validity_period(void)
{
	static const char *period;

	if (period == NULL) {
		period = cm_prefs_config("local", "validity_period");
		if (period == NULL) {
			period = cm_prefs_config("selfsign", "validity_period");
			if (period == NULL) {
				period = CM_DEFAULT_CERT_LIFETIME;
			}
		}
	}
	return period;
}

static const char *
yes_words[] = {"yes", "y", "true", "t", "1"};

static const char *
no_words[] = {"no", "n", "false", "f", "0"};

static int
cm_prefs_yesno(const char *val)
{
	unsigned int i;
	if (val != NULL) {
		for (i = 0;
		     i < sizeof(yes_words) / sizeof(yes_words[0]);
		     i++) {
			if (strcasecmp(yes_words[i], val) == 0) {
				return 1;
			}
		}
		for (i = 0;
		     i < sizeof(no_words) / sizeof(no_words[0]);
		     i++) {
			if (strcasecmp(no_words[i], val) == 0) {
				return 0;
			}
		}
	}
	return -1;
}

int
cm_prefs_populate_unique_id(void)
{
	static int populate = -1;
	if (populate == -1) {
		const char *val;
		val = cm_prefs_config("selfsign", "populate_unique_id");
		if (val == NULL) {
			val = CM_DEFAULT_POPULATE_UNIQUE_ID;
		}
		if (val != NULL) {
			populate = cm_prefs_yesno(val);
		}
	}
	return populate != -1 ? populate : 0;
}

int
cm_prefs_monitor(void)
{
	/* The documented hard-coded default is to try. */
	return 1;
}

int
cm_prefs_autorenew(void)
{
	/* The documented hard-coded default is to try. */
	return 1;
}

const char *
cm_prefs_dogtag_ee_url(void)
{
	static const char *url;
#if 0
	if (url == NULL) {
		url = cm_prefs_config("dogtag", "ee_url");
	}
#endif
	return url;
}

const char *
cm_prefs_dogtag_agent_url(void)
{
	static const char *url;
#if 0
	if (url == NULL) {
		url = cm_prefs_config("dogtag", "agent_url");
	}
#endif
	return url;
}

const char *
cm_prefs_dogtag_profile(void)
{
	static const char *profile;
#if 0
	if (profile == NULL) {
		profile = cm_prefs_config("dogtag", "profile");
	}
#endif
	return profile;
}

int
cm_prefs_dogtag_renew(void)
{
	static int prefer = -1;
#if 0
	if (prefer == -1) {
		prefer = cm_prefs_yesno(cm_prefs_config("dogtag",
							"prefer_renewal"));
	}
#endif
	return (prefer != -1) ? (prefer != 0) : TRUE;
}

const char *
cm_prefs_dogtag_ca_info(void)
{
	static const char *info;
#if 0
	if (info == NULL) {
		info = cm_prefs_config("dogtag", "ca_info");
	}
#endif
	return info;
}

const char *
cm_prefs_dogtag_ca_path(void)
{
	static const char *path;
#if 0
	if (path == NULL) {
		path = cm_prefs_config("dogtag", "ca_path");
	}
#endif
	return path;
}

const char *
cm_prefs_dogtag_ssldir(void)
{
	static const char *dbdir;
#if 0
	if (dbdir == NULL) {
		dbdir = cm_prefs_config("dogtag", "nss_dbdir");
	}
#endif
	return dbdir;
}

const char *
cm_prefs_dogtag_sslcert(void)
{
	static const char *cert;
#if 0
	if (cert == NULL) {
		cert = cm_prefs_config("dogtag", "ssl_certificate");
		if (cert == NULL) {
			cert = cm_prefs_config("dogtag", "nss_nickname");
		}
	}
#endif
	return cert;
}

const char *
cm_prefs_dogtag_sslkey(void)
{
	static const char *key;
#if 0
	if (key == NULL) {
		key = cm_prefs_config("dogtag", "ssl_key");
	}
#endif
	return key;
}

const char *
cm_prefs_dogtag_sslpinfile(void)
{
	static const char *pinfile;
#if 0
	if (pinfile == NULL) {
		pinfile = cm_prefs_config("dogtag", "ssl_pinfile");
	}
#endif
	return pinfile;
}

enum cm_key_algorithm
cm_prefs_preferred_key_algorithm(void)
{
	char *keytype;
	keytype = cm_prefs_config(NULL, "key_type");
	if (keytype != NULL) {
		if (strcasecmp(keytype, "RSA") == 0) {
			free(keytype);
			return cm_key_rsa;
		}
#ifdef CM_ENABLE_DSA
		else if (strcasecmp(keytype, "DSA") == 0) {
			free(keytype);
			return cm_key_dsa;
		}
#endif
#ifdef CM_ENABLE_EC
		else if ((strcasecmp(keytype, "ECDSA") == 0) ||
			 (strcasecmp(keytype, "EC") == 0)) {
			free(keytype);
			return cm_key_rsa;
		}
#endif
#ifdef CM_ENABLE_ML_DSA
		else if (strcasecmp(keytype, "ML-DSA-44") == 0) {
			free(keytype);
			return cm_key_ml_dsa_44;
		}
		else if (strcasecmp(keytype, "ML-DSA-65") == 0) {
			free(keytype);
			return cm_key_ml_dsa_65;
		}
		else if (strcasecmp(keytype, "ML-DSA-87") == 0) {
			free(keytype);
			return cm_key_ml_dsa_87;
		}
#endif
	}
	return CM_DEFAULT_PUBKEY_TYPE;
}

int
cm_prefs_preferred_rsa_key_size(void)
{
	char *keysize;
	keysize = cm_prefs_config(NULL, "rsa_key_size");
	int size = CM_DEFAULT_PUBKEY_SIZE;

	if (keysize != NULL) {
		size = atoi(keysize);
		if ((size == 0) || (size < CM_MINIMUM_RSA_KEY_SIZE)) {
			size = CM_DEFAULT_PUBKEY_SIZE;
		}
		free(keysize);
	}
	return size;
}

int
cm_prefs_default_key_gen_size(enum cm_key_algorithm gen_algorithm)
{
	switch (gen_algorithm) {
	case cm_key_rsa:
		return cm_prefs_preferred_rsa_key_size();
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		return CM_MINIMUM_DSA_KEY_SIZE;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		return CM_MINIMUM_EC_KEY_SIZE;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		return 10496;
	case cm_key_ml_dsa_65:
		return 15616;
	case cm_key_ml_dsa_87:
		return 20736;
#endif
	case cm_key_unspecified:
	default:
		return cm_prefs_preferred_rsa_key_size();
	}
}

const char *
cm_prefs_nss_ca_trust(void)
{
	static const char *trust;

	if (trust == NULL) {
		trust = cm_prefs_config(NULL, "nss_ca_trust");
	}
	return trust;
}

const char *
cm_prefs_nss_other_trust(void)
{
	static const char *trust;

	if (trust == NULL) {
		trust = cm_prefs_config(NULL, "nss_other_trust");
	}
	return trust;
}

long long
prefs_key_end_of_life(time_t ref)
{
	const char *cfg;
	time_t tmp;

	tmp = -1;
	cfg = cm_prefs_config(NULL, "max_key_lifetime");
	if (cfg != NULL) {
		if (cm_submit_u_delta_from_string(cfg, ref, &tmp) == 0) {
			return tmp;
		}
	}
	return -1;
}

long
prefs_max_key_use_count(void)
{
	static long count = -2;
	long tmp;
	const char *cfg;
	char *p;

	if (count == -2) {
		count = -1;
		cfg = cm_prefs_config(NULL, "max_key_use_count");
		if (cfg != NULL) {
			tmp = strtol(cfg, &p, 10);
			if ((p != NULL) && (*p == '\0')) {
				count = tmp;
			}
		}
	}
	return count;
}

int
cm_prefs_scep_password_otp(void)
{
    static int populate = -1;
    if (populate == -1) {
        const char *val;
        val = cm_prefs_config("scep", "challenge_password_otp");
        if (val == NULL) {
            val = "no";
        }
        populate = cm_prefs_yesno(val);
    }
    return populate != -1 ? populate : 0;
}
