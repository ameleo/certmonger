/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "cm.h"
#include "certext.h"
#include "env.h"
#include "prefs.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "submit-int.h"
#include "tdbus.h"
#include "tdbush.h"
#include "tdbusm.h"
#include "tpm-token.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif

/* Things we know about the calling client. */
struct cm_client_info {
	uid_t uid;
	pid_t pid;
};

/* Convenience functions. */
static struct cm_store_entry *
get_entry_for_path(struct cm_context *ctx, const char *path)
{
	int initial;
	if (path != NULL) {
		initial = strlen(CM_DBUS_REQUEST_PATH);
		if (strncmp(path, CM_DBUS_REQUEST_PATH, initial) == 0) {
			if (path[initial] == '/') {
				return cm_get_entry_by_busname(ctx,
							       path +
							       initial +
							       1);
			}
		}
	}
	return NULL;
}
static struct cm_store_entry *
get_entry_for_request_message(DBusMessage *msg, struct cm_context *ctx)
{
	return msg ? get_entry_for_path(ctx, dbus_message_get_path(msg)) : NULL;
}
static struct cm_store_ca *
get_ca_for_path(struct cm_context *ctx, const char *path)
{
	int initial;
	if (path != NULL) {
		initial = strlen(CM_DBUS_CA_PATH);
		if (strncmp(path, CM_DBUS_CA_PATH, initial) == 0) {
			if (path[initial] == '/') {
				return cm_get_ca_by_busname(ctx,
							    path + initial + 1);
			}
		}
	}
	return NULL;
}
static struct cm_store_ca *
get_ca_for_request_message(DBusMessage *msg, struct cm_context *ctx)
{
	return msg ? get_ca_for_path(ctx, dbus_message_get_path(msg)) : NULL;
}

/* These used to be local functions, but we ended up using them elsewhere.
 * Should probably just be reworked where we use them. */
static char *
maybe_strdup(void *parent, const char *s)
{
	return cm_store_maybe_strdup(parent, s);
}
static char **
maybe_strdupv(void *parent, char **s)
{
	return cm_store_maybe_strdupv(parent, s);
}

/* Convenience functions for returning errors from the base object to callers. */
static DBusHandlerResult
send_internal_base_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_missing_arg_error(DBusConnection *conn, DBusMessage *req,
				     const char *text, const char *arg)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_MISSING_ARG, text);
	if (msg != NULL) {
		cm_tdbusm_set_s(msg, arg);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_bad_arg_error(DBusConnection *conn, DBusMessage *req,
				 const char *text, const char *badval,
				 const char *arg)
{
	DBusMessage *msg;
	msg = dbus_message_new_error_printf(req, CM_DBUS_ERROR_BASE_BAD_ARG,
					    text, badval);
	if (msg != NULL) {
		cm_tdbusm_set_s(msg, arg);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_duplicate_error(DBusConnection *conn, DBusMessage *req,
				   const char *text, const char *dup,
				   const char *arg1, const char *arg2)
{
	DBusMessage *msg;
	const char *args[] = {arg1, arg2, NULL};
	msg = dbus_message_new_error_printf(req, CM_DBUS_ERROR_BASE_DUPLICATE,
					    text, dup);
	if (msg != NULL) {
		cm_tdbusm_set_as(msg, args);
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
send_internal_base_no_such_entry_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_BASE_NO_SUCH_ENTRY,
				     _("No matching entry found.\n"));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Some validity-testing we do for caller-supplied arguments. */
static int
check_arg_is_absolute_path(const char *path)
{
	if (path[0] == '/') {
		return 0;
	} else {
		errno = EINVAL;
		return -1;
	}
}

static int
check_arg_is_absolute_nss_path(const char *path)
{
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		path += 7;
	}
	if (path[0] == '/') {
		return 0;
	} else {
		errno = EINVAL;
		return -1;
	}
}

static int
check_arg_is_directory(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			if (access(path, R_OK | W_OK) == 0) {
				return 0;
			}
		}
	}
	return -1;
}

static int
check_arg_is_nss_directory(const char *path)
{
	struct stat st;
	if (strncmp(path, "sql:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		path += 7;
	}
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			if (access(path, R_OK | W_OK) == 0) {
				return 0;
			}
		}
	}
	return -1;
}

static int
check_arg_is_reg_or_missing(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISREG(st.st_mode)) {
			return 0;
		}
	} else {
		if (errno == ENOENT) {
			return 0;
		}
	}
	return -1;
}

static int
check_arg_parent_is_directory(const char *path)
{
	char *tmp, *p;
	int ret, err;

	if (check_arg_is_absolute_path(path) != 0) {
		return -1;
	}
	tmp = strdup(path);
	if (tmp != NULL) {
		p = strrchr(tmp, '/');
		if (p != NULL) {
			if (p > tmp) {
				*p = '\0';
			} else {
				*(p + 1) = '\0';
			}
			ret = check_arg_is_directory(tmp);
			err = errno;
			free(tmp);
			errno = err;
			return ret;
		} else {
			free(tmp);
			errno = EINVAL;
			return -1;
		}
	}
	errno = ENOMEM;
	return -1;
}

/* The key of an external account binding given when an ACME CA is added
 * is kept by us, in a file of our own beside the state of the ACME helper,
 * which the helper is told to read.  The file which the user had it in may
 * be anywhere, readable by the user but not by us (a home directory, under
 * a SELinux policy), and may be removed once the CA is added; nothing of
 * the key shows in the CA's command line. */
#define CM_ACME_EAB_SUBDIR "eab"

static char *
acme_eab_dir(void *parent)
{
	const char *acme;

	acme = cm_env_acme_dir();
	if (acme == NULL) {
		return NULL;
	}
	return talloc_asprintf(parent, "%s/%s", acme, CM_ACME_EAB_SUBDIR);
}

/* A key is base64 or base64url text on one line. */
static int
acme_eab_key_valid(const char *key)
{
	const char *p;

	if ((key == NULL) || (strlen(key) == 0)) {
		return 0;
	}
	for (p = key; *p != '\0'; p++) {
		if ((strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "abcdefghijklmnopqrstuvwxyz"
			    "0123456789-_+/=", *p) == NULL)) {
			return 0;
		}
	}
	return 1;
}

/* Save the key in a file of its own, readable by us only, and return the
 * file's name. */
static char *
acme_eab_store(void *parent, const char *key)
{
	char *dir, *path;
	const char *acme;
	mode_t mask;
	size_t length;
	int fd;

	acme = cm_env_acme_dir();
	dir = acme_eab_dir(parent);
	if ((acme == NULL) || (dir == NULL)) {
		return NULL;
	}
	if (((mkdir(acme, S_IRWXU) != 0) && (errno != EEXIST)) ||
	    ((mkdir(dir, S_IRWXU) != 0) && (errno != EEXIST))) {
		cm_log(1, "Error creating \"%s\": %s.\n", dir,
		       strerror(errno));
		return NULL;
	}
	path = talloc_asprintf(parent, "%s/key-XXXXXX", dir);
	if (path == NULL) {
		return NULL;
	}
	mask = umask(S_IRWXG | S_IRWXO);
	fd = mkstemp(path);
	umask(mask);
	if (fd == -1) {
		cm_log(1, "Error creating a file in \"%s\": %s.\n", dir,
		       strerror(errno));
		return NULL;
	}
	length = strlen(key);
	if ((write(fd, key, length) != (ssize_t) length) ||
	    (write(fd, "\n", 1) != 1) ||
	    (fsync(fd) != 0)) {
		cm_log(1, "Error writing \"%s\": %s.\n", path,
		       strerror(errno));
		close(fd);
		unlink(path);
		return NULL;
	}
	close(fd);
	return path;
}

/* Remove the key which the helper of a CA we no longer know was told to
 * read, if it is one of ours. */
static void
acme_eab_forget(void *parent, const char *helper)
{
	char **argv, *dir;
	const char *file;
	size_t length;
	int i;

	dir = acme_eab_dir(parent);
	argv = cm_subproc_parse_args(parent, helper, NULL);
	if ((dir == NULL) || (argv == NULL)) {
		return;
	}
	length = strlen(dir);
	for (i = 1; argv[i] != NULL; i++) {
		file = NULL;
		if (((strcmp(argv[i], "-K") == 0) ||
		     (strcmp(argv[i], "--eab-key-file") == 0)) &&
		    (argv[i + 1] != NULL)) {
			file = argv[++i];
		} else
		if (strncmp(argv[i], "--eab-key-file=", 15) == 0) {
			file = argv[i] + 15;
		}
		if ((file != NULL) &&
		    (strncmp(file, dir, length) == 0) &&
		    (file[length] == '/') &&
		    (strchr(file + length + 1, '/') == NULL) &&
		    (unlink(file) != 0) && (errno != ENOENT)) {
			cm_log(1, "Error removing \"%s\": %s.\n", file,
			       strerror(errno));
		}
	}
}

/* Add a CA whose helper is the given command, telling an ACME helper to read
 * the key of its external account binding, when one is given, from a file
 * of ours. */
static DBusHandlerResult
add_known_ca(DBusConnection *conn, DBusMessage *msg, struct cm_context *ctx,
	     void *parent, const char *ca_name, const char *ca_command,
	     char **ca_issuer_names, const char *eab_key)
{
	DBusMessage *rep;
	char *path, *eab_file = NULL, **argv;
	const char *base;
	struct cm_store_ca *ca, *new_ca;
	int i, n_cas;

	n_cas = cm_get_n_cas(ctx);
	for (i = 0; i < n_cas; i++) {
		ca = cm_get_ca_by_index(ctx, i);
		if (strcasecmp(ca->cm_nickname, ca_name) == 0) {
			cm_log(1, "There is already a CA with "
			       "the nickname \"%s\": %s.\n", ca->cm_nickname,
			       ca->cm_busname);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("There is already a CA with the nickname \"%s\"."),
								  ca->cm_nickname,
								  NULL,
								  NULL);
		}
	}
	if (eab_key != NULL) {
		/* Only the ACME helper reads one. */
		argv = cm_subproc_parse_args(parent, ca_command, NULL);
		base = ((argv != NULL) && (argv[0] != NULL)) ?
		       strrchr(argv[0], '/') : NULL;
		base = (base != NULL) ? base + 1 :
		       (((argv != NULL) && (argv[0] != NULL)) ? argv[0] : "");
		if ((strcmp(base, "acme-submit") != 0) ||
		    !acme_eab_key_valid(eab_key)) {
			cm_log(1, "An external account key can only be given "
			       "to the ACME helper, as base64 text.\n");
			talloc_free(parent);
			return send_internal_base_bad_arg_error(conn, msg,
								_("An external account key can only be given to the ACME helper, as base64 text."),
								ca_command, NULL);
		}
		eab_file = acme_eab_store(parent, eab_key);
		if (eab_file == NULL) {
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}
		ca_command = talloc_asprintf(parent, "%s -K %s", ca_command,
					     shell_escape(parent, eab_file));
	}
	/* Okay, we can go ahead and add the CA. */
	new_ca = cm_store_ca_new(parent);
	if (new_ca == NULL) {
		if (eab_file != NULL) {
			unlink(eab_file);
		}
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_ca, 0, sizeof(*new_ca));
	/* Populate it with all of the information we have. */
	new_ca->cm_busname = cm_store_ca_next_busname(new_ca);
	new_ca->cm_nickname = talloc_strdup(new_ca, ca_name);
	new_ca->cm_ca_known_issuer_names = maybe_strdupv(new_ca,
							 ca_issuer_names);
	new_ca->cm_ca_is_default = 0;
	new_ca->cm_ca_type = cm_ca_external;
	new_ca->cm_ca_external_helper = talloc_strdup(new_ca, ca_command);
	/* Hand it off to the main loop. */
	if (cm_add_ca(ctx, new_ca) != 0) {
		cm_log(1, "Error adding CA to main context.\n");
		if (eab_file != NULL) {
			unlink(eab_file);
		}
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, FALSE);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       new_ca->cm_busname);
			cm_tdbusm_set_bp(rep, TRUE, path);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}
	}
}

/* org.fedorahosted.certmonger.add_known_ca */
static DBusHandlerResult
base_add_known_ca(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	void *parent;
	char *ca_name, *ca_command, **ca_issuer_names;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ssoas(msg, parent,
				&ca_name, &ca_command,
				&ca_issuer_names) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	return add_known_ca(conn, msg, ctx, parent, ca_name, ca_command,
			    ca_issuer_names, NULL);
}

/* org.fedorahosted.certmonger.add_known_ca_with_eab_key */
static DBusHandlerResult
base_add_known_ca_with_eab_key(DBusConnection *conn, DBusMessage *msg,
			       struct cm_client_info *ci,
			       struct cm_context *ctx)
{
	void *parent;
	char *ca_name, *ca_command, **ca_issuer_names, *eab_key;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ss_as_s(msg, parent,
				  &ca_name, &ca_command,
				  &ca_issuer_names, &eab_key) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	return add_known_ca(conn, msg, ctx, parent, ca_name, ca_command,
			    ca_issuer_names,
			    ((eab_key != NULL) && (strlen(eab_key) > 0)) ?
			    eab_key : NULL);
}

#ifdef CM_ENABLE_ML_DSA
/* For ML-DSA the only meaningful "size" is the parameter-set identifier
 * (44/65/87), which is fixed by the chosen key type.  If the client
 * explicitly requested a size it must match "want"; reject the request
 * otherwise rather than silently ignoring it.  On success record the
 * EVP_PKEY_bits()-style size keyiread reports, so that resubmit never sees a
 * mismatch that would spuriously regenerate the key.  Returns 0 on success,
 * or -1 after queueing an error reply (*ret holds the handler result). */
static int
base_add_request_ml_dsa_size(DBusConnection *conn, DBusMessage *msg,
			     struct cm_store_entry *entry, void *parent,
			     const struct cm_tdbusm_dict *param, long want,
			     DBusHandlerResult *ret)
{
	if ((param != NULL) && (param->value.n != want)) {
		cm_log(1, "Invalid key size %ld for ML-DSA-%ld; "
		       "the only valid size is %ld.\n",
		       param->value.n, want, want);
		/* send_internal_base_bad_arg_error() substitutes a single %s
		 * (the offending value), so bake the variant name and the one
		 * valid dimension into the format string first. */
		*ret = send_internal_base_bad_arg_error(conn, msg,
			talloc_asprintf(parent,
				_("Invalid key size \"%%s\" for ML-DSA-%ld; the only valid size is %ld."),
				want, want),
			talloc_asprintf(parent, "%ld", param->value.n),
			"KEY_SIZE");
		return -1;
	}
	entry->cm_key_type.cm_key_gen_size =
		cm_prefs_default_key_gen_size(entry->cm_key_type.cm_key_gen_algorithm);
	return 0;
}
#endif

/* org.fedorahosted.certmonger.add_request */
/* A request which says nothing of where to keep its key and certificate,
 * for a CA which wants keys that the TPM attests, keeps both in our TPM
 * token, under the request's nickname. */
static struct cm_tdbusm_dict **
add_tpm_token_defaults(void *parent, struct cm_context *ctx,
		       struct cm_tdbusm_dict **d)
{
	const char *storage_keys[] = {
		"CERT_STORAGE", CM_DBUS_PROP_CERT_LOCATION_TYPE,
		"KEY_STORAGE", CM_DBUS_PROP_KEY_LOCATION_TYPE,
		NULL,
	};
	const char *defaults[] = {
		"CERT_STORAGE", "KEY_STORAGE",
		"CERT_LOCATION", "KEY_LOCATION",
		"CERT_TOKEN", "KEY_TOKEN",
		"CERT_NICKNAME", "KEY_NICKNAME",
	};
	static unsigned int serial;
	const struct cm_tdbusm_dict *param;
	struct cm_tdbusm_dict **nd, *entries;
	struct cm_store_ca *ca;
	const char *dir, *nickname;
	int i, n, n_defaults;

	for (i = 0; storage_keys[i] != NULL; i++) {
		if (cm_tdbusm_find_dict_entry(d, storage_keys[i],
					      cm_tdbusm_dict_s) != NULL) {
			return d;
		}
	}
	param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_p);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d, CM_DBUS_PROP_CA,
						  cm_tdbusm_dict_p);
	}
	ca = (param != NULL) ? get_ca_for_path(ctx, param->value.s) : NULL;
	if (!cm_tpm_token_ca_attests(ca)) {
		return d;
	}
	dir = cm_tpm_token_dir();
	if (dir == NULL) {
		return d;
	}
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d, CM_DBUS_PROP_NICKNAME,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		nickname = param->value.s;
	} else {
		nickname = talloc_asprintf(parent, "certmonger-%lu-%u",
					   (unsigned long) time(NULL),
					   serial++);
	}
	for (n = 0; (d != NULL) && (d[n] != NULL); n++) {
		continue;
	}
	n_defaults = sizeof(defaults) / sizeof(defaults[0]);
	nd = talloc_array(parent, struct cm_tdbusm_dict *, n + n_defaults + 1);
	entries = talloc_zero_array(parent, struct cm_tdbusm_dict, n_defaults);
	if ((nd == NULL) || (entries == NULL) || (nickname == NULL)) {
		return d;
	}
	for (i = 0; i < n; i++) {
		nd[i] = d[i];
	}
	for (i = 0; i < n_defaults; i++) {
		entries[i].key = (char *) defaults[i];
		entries[i].value_type = cm_tdbusm_dict_s;
		switch (i / 2) {
		case 0:
			entries[i].value.s = "NSSDB";
			break;
		case 1:
			entries[i].value.s = (char *) dir;
			break;
		case 2:
			entries[i].value.s = CM_TPM_TOKEN_LABEL;
			break;
		default:
			entries[i].value.s = (char *) nickname;
			break;
		}
		nd[n + i] = &entries[i];
	}
	nd[n + n_defaults] = NULL;
	cm_log(3, "Keeping the key and certificate in the TPM token, as "
	       "\"%s\".\n", nickname);
	return nd;
}

static DBusHandlerResult
base_add_request(DBusConnection *conn, DBusMessage *msg,
		 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	DBusHandlerResult ret;
	void *parent;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	struct cm_store_entry *e, *new_entry;
	struct cm_store_ca *ca;
	int i, n_entries;
	enum cm_key_storage_type key_storage;
	char *key_location, *key_nickname, *key_token, *key_pin, *key_pin_file;
	char *challenge_password, *challenge_password_file;
	enum cm_cert_storage_type cert_storage;
	char *cert_location, *cert_nickname, *cert_token;
	char *cert_owner, *key_owner;
	char *nss_user;
	mode_t cert_perms, key_perms;
	char *path, *pre_command, *post_command;
	char **root_cert_nssdbs, **root_cert_files;
	char **other_root_cert_nssdbs, **other_root_cert_files;
	char **other_cert_nssdbs, **other_cert_files;

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	d = add_tpm_token_defaults(parent, ctx, d);

	/* Certificate storage. */
	param = cm_tdbusm_find_dict_entry(d, "CERT_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_CERT_LOCATION_TYPE,
						  cm_tdbusm_dict_s);
	}
	if (param == NULL) {
		/* This is a required parameter. */
		cm_log(1, "Certificate storage type not specified.\n");
		talloc_free(parent);
		return send_internal_base_missing_arg_error(conn, msg,
							    _("Certificate storage type not specified."),
							    "CERT_STORAGE");
	} else {
		/* Check that it's a known/supported type. */
		if (strcasecmp(param->value.s, "FILE") == 0) {
			cert_storage = cm_cert_storage_file;
		} else
		if (strcasecmp(param->value.s, "NSSDB") == 0) {
			cert_storage = cm_cert_storage_nssdb;
		} else {
			cm_log(1, "Unknown cert storage type \"%s\".\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("Certificate storage type \"%s\" not supported."),
							       param->value.s,
							       "CERT_STORAGE");
			talloc_free(parent);
			return ret;
		}
	}
	/* Handle parameters for either a PIN or the location of a PIN. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_PIN", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_PIN,
						  cm_tdbusm_dict_s);
	}
	if ((param == NULL) ||
	    (param->value.s == NULL) ||
	    (strlen(param->value.s) == 0)) {
		key_pin = NULL;
	} else {
		key_pin = param->value.s;
		key_pin_file = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_PIN_FILE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_PIN_FILE,
						  cm_tdbusm_dict_s);
	}
	if ((param == NULL) ||
	    (param->value.s == NULL) ||
	    (strlen(param->value.s) == 0)) {
		key_pin_file = NULL;
	} else {
		if (check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "PIN storage location is not an absolute "
			       "path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "KEY_PIN_FILE");
			talloc_free(parent);
			return ret;
		}
		key_pin_file = param->value.s;
		key_pin = NULL;
	}
	/* Check that other required information about the
	 * certificate's location is provided. */
	cert_location = NULL;
	cert_nickname = NULL;
	cert_token = NULL;
	switch (cert_storage) {
	case cm_cert_storage_file:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_FILE,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cm_log(1, "Certificate storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "Certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		if (check_arg_parent_is_directory(param->value.s) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" could not be accessed due "
									"to insufficient permissions."),
								       param->value.s,
								       "CERT_LOCATION");
				break;
			default:
				cm_log(1, "Certificate storage location is not inside of a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" must be a valid directory."),
								       param->value.s,
								       "CERT_LOCATION");
				break;
			}
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_reg_or_missing(param->value.s) != 0) {
			cm_log(1, "Certificate storage location is not a regular file.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a file."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		cert_location = param->value.s;
		cert_nickname = NULL;
		cert_token = NULL;
		break;
	case cm_cert_storage_nssdb:
		param = cm_tdbusm_find_dict_entry(d, "CERT_LOCATION",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_DATABASE,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cm_log(1, "Certificate storage location not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate storage location not specified."),
								    "CERT_LOCATION");
		}
		if (check_arg_is_absolute_nss_path(param->value.s) != 0) {
			cm_log(1, "Certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       "CERT_LOCATION");
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_nss_directory(param->value.s) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" could not be accessed due "
									"to insufficient permissions."),
								       param->value.s,
								       "CERT_LOCATION");
				break;
			default:
				cm_log(1, "Certificate storage location must be a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       "CERT_LOCATION");
				break;
			}
			talloc_free(parent);
			return ret;
		}
		cert_location = cm_store_canonicalize_path(parent,
							   param->value.s);
		param = cm_tdbusm_find_dict_entry(d, "CERT_NICKNAME",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_NICKNAME,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL || param->value.s == NULL || strlen(param->value.s) == 0) {
			cm_log(1, "Certificate nickname not specified.\n");
			talloc_free(parent);
			return send_internal_base_missing_arg_error(conn, msg,
								    _("Certificate nickname not specified."),
								    "CERT_NICKNAME");
		}
		cert_nickname = param->value.s;
		param = cm_tdbusm_find_dict_entry(d, "CERT_TOKEN",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CERT_LOCATION_TOKEN,
							  cm_tdbusm_dict_s);
		}
		if (param == NULL) {
			cert_token = NULL;
		} else {
			cert_token = param->value.s;
		}
		break;
	}
	if (cert_location == NULL) {
		cm_log(1, "Certificate storage location not specified.\n");
		talloc_free(parent);
		return send_internal_base_missing_arg_error(conn, msg,
							    _("Certificate storage location not specified."),
							    "CERT_LOCATION");
	}
	/* Check that the requested nickname will be unique. */
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_NICKNAME,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			e = cm_get_entry_by_index(ctx, i);
			if (strcasecmp(e->cm_nickname, param->value.s) == 0) {
				cm_log(1, "There is already a request with "
				       "the nickname \"%s\": %s.\n",
				       e->cm_nickname, e->cm_busname);
				talloc_free(parent);
				return send_internal_base_duplicate_error(conn,
									  msg,
									  _("There is already a request with the nickname \"%s\"."),
									  e->cm_nickname,
									  "NICKNAME",
									  NULL);
			}
		}
	}
	/* Check for a duplicate of another entry's certificate storage
	 * information. */
	n_entries = cm_get_n_entries(ctx);
	for (i = 0; i < n_entries; i++) {
		e = cm_get_entry_by_index(ctx, i);
		if (cert_storage != e->cm_cert_storage_type) {
			continue;
		}
		if ((e->cm_cert_storage_location == NULL) || strcmp(cert_location, e->cm_cert_storage_location) != 0) {
			continue;
		}
		switch (cert_storage) {
		case cm_cert_storage_file:
			break;
		case cm_cert_storage_nssdb:
			if ((e->cm_cert_nickname == NULL) || strcmp(cert_nickname, e->cm_cert_nickname) != 0) {
				continue;
			}
			break;
		}
		break;
	}
	if (i < n_entries) {
		/* We found a match, and that's bad. */
		cm_log(1, "Certificate at same location is already being "
		       "used for request %s with nickname \"%s\".\n",
		       e->cm_busname, e->cm_nickname);
		talloc_free(parent);
		return send_internal_base_duplicate_error(conn, msg,
							  _("Certificate at same location is already used by request with nickname \"%s\"."),
							  e->cm_nickname,
							  "CERT_LOCATION",
							  cert_storage == cm_cert_storage_nssdb ?
							  "CERT_NICKNAME" : NULL);
	}
	/* Key storage.  We can afford to be a bit more lax about this because
	 * we don't require that we know anything about the key. */
	param = cm_tdbusm_find_dict_entry(d, "KEY_STORAGE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_LOCATION_TYPE,
						  cm_tdbusm_dict_s);
	}
	if (param == NULL) {
		key_storage = cm_key_storage_none;
		key_location = NULL;
		key_token = NULL;
		key_nickname = NULL;
	} else {
		/* Check that it's a known/supported type. */
		if (strcasecmp(param->value.s, "FILE") == 0) {
			key_storage = cm_key_storage_file;
		} else
		if (strcasecmp(param->value.s, "NSSDB") == 0) {
			key_storage = cm_key_storage_nssdb;
		} else
		if (strcasecmp(param->value.s, "NONE") == 0) {
			key_storage = cm_key_storage_none;
		} else {
			cm_log(1, "Unknown key storage type \"%s\".\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("Key storage type \"%s\" not supported."),
							       param->value.s,
							       "KEY_STORAGE");
			talloc_free(parent);
			return ret;
		}
		/* Check that other required information about the key's
		 * location is provided. */
		switch (key_storage) {
		case cm_key_storage_none:
			key_location = NULL;
			key_nickname = NULL;
			key_token = NULL;
			break;
		case cm_key_storage_file:
			param = cm_tdbusm_find_dict_entry(d, "KEY_LOCATION",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_FILE,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1, "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (check_arg_is_absolute_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an absolute path.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be an absolute path."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			if (check_arg_parent_is_directory(param->value.s) != 0) {
				switch (errno) {
				case EACCES:
				case EPERM:
					cm_log(1, "Not allowed to access key storage location.\n");
					ret = send_internal_base_bad_arg_error(conn, msg,
									       _("The parent of location \"%s\" could not be accessed due "
										 "to insufficient permissions."),
									       param->value.s,
									       "KEY_LOCATION");
					break;
				default:
					cm_log(1, "Key storage location is not inside of a directory.\n");
					ret = send_internal_base_bad_arg_error(conn, msg,
									       _("The parent of location \"%s\" must be a valid directory."),
									       param->value.s,
									       "KEY_LOCATION");
					break;
				}
				talloc_free(parent);
				return ret;
			}
			if (check_arg_is_reg_or_missing(param->value.s) != 0) {
				cm_log(1, "Key storage location is not a regular file.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a file."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			key_location = param->value.s;
			key_nickname = NULL;
			key_token = NULL;
			break;
		case cm_key_storage_nssdb:
			param = cm_tdbusm_find_dict_entry(d, "KEY_LOCATION",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_DATABASE,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1, "Key storage location not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key storage location not specified."),
									    "KEY_LOCATION");
			}
			if (check_arg_is_absolute_nss_path(param->value.s) != 0) {
				cm_log(1, "Key storage location is not an absolute path.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be an absolute path."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			if (check_arg_is_nss_directory(param->value.s) != 0) {
				cm_log(1, "Key storage location must be a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       "KEY_LOCATION");
				talloc_free(parent);
				return ret;
			}
			key_location = cm_store_canonicalize_path(parent,
								  param->value.s);
			param = cm_tdbusm_find_dict_entry(d, "KEY_NICKNAME",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_NICKNAME,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				cm_log(1, "Key nickname not specified.\n");
				talloc_free(parent);
				return send_internal_base_missing_arg_error(conn, msg,
									    _("Key nickname not specified."),
									    "KEY_NICKNAME");
			}
			key_nickname = param->value.s;
			param = cm_tdbusm_find_dict_entry(d, "KEY_TOKEN",
							  cm_tdbusm_dict_s);
			if (param == NULL) {
				param = cm_tdbusm_find_dict_entry(d,
								  CM_DBUS_PROP_KEY_LOCATION_TOKEN,
								  cm_tdbusm_dict_s);
			}
			if (param == NULL) {
				key_token = NULL;
			} else {
				key_token = param->value.s;
			}
			break;
		}
		/* Check for a duplicate of another entry's key storage
		 * information. */
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			e = cm_get_entry_by_index(ctx, i);
			if (key_storage != e->cm_key_storage_type) {
				continue;
			}
			switch (key_storage) {
			case cm_key_storage_none:
				continue;
				break;
			case cm_key_storage_file:
				if (strcmp(key_location,
					   e->cm_key_storage_location) != 0) {
					continue;
				}
				break;
			case cm_key_storage_nssdb:
				if (strcmp(key_location,
					   e->cm_key_storage_location) != 0) {
					continue;
				}
				if (strcmp(key_nickname,
					   e->cm_key_nickname) != 0) {
					continue;
				}
				break;
			}
			break;
		}
		if (i < n_entries) {
			/* We found a match, and that's bad. */
			cm_log(1, "Key at same location is already being "
			       "used for request %s with nickname \"%s\".\n",
			       e->cm_busname, e->cm_nickname);
			talloc_free(parent);
			return send_internal_base_duplicate_error(conn, msg,
								  _("Key at same location is already used by request with nickname \"%s\"."),
								  e->cm_nickname,
								  "KEY_LOCATION",
								  key_storage == cm_key_storage_nssdb ?
								  "KEY_NICKNAME" : NULL);
		}
	}
	/* Find out where to save the root certificates. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_ROOT_CERT_NSSDBS,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_nss_path(param->value.as[i]) != 0) {
			cm_log(1, "Root certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_ROOT_CERT_NSSDBS);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_nss_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access root certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.s,
								       CM_DBUS_PROP_ROOT_CERT_NSSDBS);
				break;
			default:
				cm_log(1, "Certificate storage location must be a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       CM_DBUS_PROP_ROOT_CERT_NSSDBS);
				break;
			}
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		root_cert_nssdbs = param->value.as;
	} else {
		root_cert_nssdbs = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_ROOT_CERT_FILES,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_path(param->value.as[i]) != 0) {
			cm_log(1, "Root certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_ROOT_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_parent_is_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access root certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.as[i],
								       CM_DBUS_PROP_ROOT_CERT_FILES);
				break;
			default:
				cm_log(1, "Root certificate storage location is not inside of a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" must be a valid directory."),
								       param->value.as[i],
								       CM_DBUS_PROP_ROOT_CERT_FILES);
				break;
			}
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_reg_or_missing(param->value.as[i]) != 0) {
			cm_log(1, "Root certificate storage location is not a regular file.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a file."),
							       param->value.as[i],
							       CM_DBUS_PROP_ROOT_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		root_cert_files = param->value.as;
	} else {
		root_cert_files = NULL;
	}
	/* Find out where to save the other root certificates. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_nss_path(param->value.as[i]) != 0) {
			cm_log(1, "Other root certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_nss_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access root certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.s,
								       CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS);
				break;
			default:
				cm_log(1, "Certificate storage location must be a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS);
				break;
			}
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		other_root_cert_nssdbs = param->value.as;
	} else {
		other_root_cert_nssdbs = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_OTHER_ROOT_CERT_FILES,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_path(param->value.as[i]) != 0) {
			cm_log(1, "Other root certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_ROOT_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_parent_is_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access other root certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.as[i],
								       CM_DBUS_PROP_OTHER_ROOT_CERT_FILES);
				break;
			default:
				cm_log(1, "Other root certificate storage location is not inside of a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" must be a valid directory."),
								       param->value.as[i],
								       CM_DBUS_PROP_OTHER_ROOT_CERT_FILES);
				break;
			}
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_reg_or_missing(param->value.as[i]) != 0) {
			cm_log(1, "Other root certificate storage location is not a regular file.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a file."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_ROOT_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		other_root_cert_files = param->value.as;
	} else {
		other_root_cert_files = NULL;
	}
	/* Find out where to save the other certificates supplied by the CA. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_OTHER_CERT_NSSDBS,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_nss_path(param->value.as[i]) != 0) {
			cm_log(1, "Other certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_CERT_NSSDBS);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_nss_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access other certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.s,
								       CM_DBUS_PROP_OTHER_CERT_NSSDBS);
				break;
			default:
				cm_log(1, "Other certificate storage location must be a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The location \"%s\" must be a directory."),
								       param->value.s,
								       CM_DBUS_PROP_OTHER_CERT_NSSDBS);
				break;
			}
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		other_cert_nssdbs = param->value.as;
	} else {
		other_cert_nssdbs = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_OTHER_CERT_FILES,
					  cm_tdbusm_dict_as);
	for (i = 0;
	     (param != NULL) &&
	     (param->value.as != NULL) &&
	     (param->value.as[i] != NULL);
	     i++) {
		if (check_arg_is_absolute_path(param->value.as[i]) != 0) {
			cm_log(1, "Other root certificate storage location is not an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
		if (check_arg_parent_is_directory(param->value.as[i]) != 0) {
			switch (errno) {
			case EACCES:
			case EPERM:
				cm_log(1, "Not allowed to access other root certificate storage location.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" could not be accessed due "
									 "to insufficient permissions."),
								       param->value.as[i],
								       CM_DBUS_PROP_OTHER_CERT_FILES);
				break;
			default:
				cm_log(1, "Other root certificate storage location is not inside of a directory.\n");
				ret = send_internal_base_bad_arg_error(conn, msg,
								       _("The parent of location \"%s\" must be a valid directory."),
								       param->value.as[i],
								       CM_DBUS_PROP_OTHER_CERT_FILES);
				break;
			}
			talloc_free(parent);
			return ret;
		}
		if (check_arg_is_reg_or_missing(param->value.as[i]) != 0) {
			cm_log(1, "Other root certificate storage location is not a regular file.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be a file."),
							       param->value.as[i],
							       CM_DBUS_PROP_OTHER_CERT_FILES);
			talloc_free(parent);
			return ret;
		}
	}
	if (param != NULL) {
		other_cert_files = param->value.as;
	} else {
		other_cert_files = NULL;
	}
	/* What to run before we save the certificate. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_PRESAVE_COMMAND,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		pre_command = param->value.s;
	} else {
		pre_command = NULL;
	}
	/* What to run after we save the certificate. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_POSTSAVE_COMMAND,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		post_command = param->value.s;
	} else {
		post_command = NULL;
	}
	/* Permissions to set on the keys and certificates. */
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_OWNER,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		cert_owner = param->value.s;
	} else {
		cert_owner = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_CERT_PERMS,
					  cm_tdbusm_dict_n);
	if (param != NULL) {
		cert_perms = param->value.n;
	} else {
		cert_perms = 0;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_KEY_OWNER,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		key_owner = param->value.s;
	} else {
		key_owner = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_KEY_PERMS,
					  cm_tdbusm_dict_n);
	if (param != NULL) {
		key_perms = param->value.n;
	} else {
		key_perms = 0;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_NSS_USER,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		nss_user = param->value.s;
		cm_log(1, "Setting CM_DBUS_PROP_NSS_USER to %s\n", nss_user);
	} else {
		nss_user = NULL;
	}
	/* Okay, we can go ahead and add the entry. */
	new_entry = cm_store_entry_new(parent);
	if (new_entry == NULL) {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
	memset(new_entry, 0, sizeof(*new_entry));
	/* Populate it with all of the information we have. */
	new_entry->cm_busname = cm_store_entry_next_busname(new_entry);
	param = cm_tdbusm_find_dict_entry(d, "NICKNAME", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_NICKNAME,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		new_entry->cm_nickname = talloc_strdup(new_entry,
						       param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "KEY_TYPE", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_TYPE,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		if (strcasecmp(param->value.s, "RSA") == 0) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_rsa;
#ifdef CM_ENABLE_DSA
		} else
		if (strcasecmp(param->value.s, "DSA") == 0) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
		} else
		if ((strcasecmp(param->value.s, "ECDSA") == 0) ||
		    (strcasecmp(param->value.s, "EC") == 0)) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
		} else
		if (strcasecmp(param->value.s, "ML-DSA-44") == 0) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_ml_dsa_44;
		} else
		if (strcasecmp(param->value.s, "ML-DSA-65") == 0) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_ml_dsa_65;
		} else
		if (strcasecmp(param->value.s, "ML-DSA-87") == 0) {
			new_entry->cm_key_type.cm_key_gen_algorithm =
				cm_key_ml_dsa_87;
#endif
		} else {
			cm_log(1, "No support for generating \"%s\" keys.\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("No support for key type \"%s\"."),
							       param->value.s,
							       "KEY_TYPE");
			talloc_free(parent);
			return ret;
		}
	} else {
		new_entry->cm_key_type.cm_key_gen_algorithm = cm_prefs_preferred_key_algorithm();
	}
	new_entry->cm_key_next_type.cm_key_gen_algorithm = new_entry->cm_key_type.cm_key_gen_algorithm;
	param = cm_tdbusm_find_dict_entry(d, "KEY_SIZE", cm_tdbusm_dict_n);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_KEY_SIZE,
						  cm_tdbusm_dict_n);
	}
	if (param != NULL) {
		new_entry->cm_key_type.cm_key_gen_size = param->value.n;
	} else {
		new_entry->cm_key_type.cm_key_gen_size =
			cm_prefs_default_key_gen_size(new_entry->cm_key_type.cm_key_gen_algorithm);
	}
	switch (new_entry->cm_key_type.cm_key_gen_algorithm) {
	case cm_key_rsa:
		if (new_entry->cm_key_type.cm_key_gen_size < CM_MINIMUM_RSA_KEY_SIZE) {
			new_entry->cm_key_type.cm_key_gen_size = CM_MINIMUM_RSA_KEY_SIZE;
		}
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		if (new_entry->cm_key_type.cm_key_gen_size < CM_MINIMUM_DSA_KEY_SIZE) {
			new_entry->cm_key_type.cm_key_gen_size = CM_MINIMUM_DSA_KEY_SIZE;
		}
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		if (new_entry->cm_key_type.cm_key_gen_size < CM_MINIMUM_EC_KEY_SIZE) {
			new_entry->cm_key_type.cm_key_gen_size = CM_MINIMUM_EC_KEY_SIZE;
		}
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		if (base_add_request_ml_dsa_size(conn, msg, new_entry, parent,
						 param, 44, &ret) != 0) {
			talloc_free(parent);
			return ret;
		}
		break;
	case cm_key_ml_dsa_65:
		if (base_add_request_ml_dsa_size(conn, msg, new_entry, parent,
						 param, 65, &ret) != 0) {
			talloc_free(parent);
			return ret;
		}
		break;
	case cm_key_ml_dsa_87:
		if (base_add_request_ml_dsa_size(conn, msg, new_entry, parent,
						 param, 87, &ret) != 0) {
			talloc_free(parent);
			return ret;
		}
		break;
#endif
	case cm_key_unspecified:
	default:
		break;
	}
	new_entry->cm_key_next_type.cm_key_gen_size = new_entry->cm_key_type.cm_key_gen_size;
	/* Key and certificate storage. */
	new_entry->cm_key_storage_type = key_storage;
	new_entry->cm_key_storage_location = maybe_strdup(new_entry,
							  key_location);
	new_entry->cm_key_nickname = maybe_strdup(new_entry, key_nickname);
	new_entry->cm_key_token = maybe_strdup(new_entry, key_token);
	new_entry->cm_key_pin = maybe_strdup(new_entry, key_pin);
	new_entry->cm_key_pin_file = maybe_strdup(new_entry, key_pin_file);
	new_entry->cm_key_owner = maybe_strdup(new_entry, key_owner);
	new_entry->cm_key_perms = key_perms;
	new_entry->cm_cert_storage_type = cert_storage;
	new_entry->cm_cert_storage_location = maybe_strdup(new_entry,
							   cert_location);
	new_entry->cm_cert_nickname = maybe_strdup(new_entry, cert_nickname);
	new_entry->cm_cert_token = maybe_strdup(new_entry, cert_token);
	new_entry->cm_cert_owner = maybe_strdup(new_entry, cert_owner);
	new_entry->cm_cert_perms = cert_perms;
	new_entry->cm_nss_user = maybe_strdup(new_entry, nss_user);

	new_entry->cm_root_cert_store_nssdbs = maybe_strdupv(new_entry, root_cert_nssdbs);
	new_entry->cm_root_cert_store_files = maybe_strdupv(new_entry, root_cert_files);
	new_entry->cm_other_root_cert_store_nssdbs = maybe_strdupv(new_entry, other_root_cert_nssdbs);
	new_entry->cm_other_root_cert_store_files = maybe_strdupv(new_entry, other_root_cert_files);
	new_entry->cm_other_cert_store_nssdbs = maybe_strdupv(new_entry, other_cert_nssdbs);
	new_entry->cm_other_cert_store_files = maybe_strdupv(new_entry, other_cert_files);

	/* Which CA to use. */
	param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_p);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_CA,
						  cm_tdbusm_dict_p);
	}
	if (param != NULL) {
		ca = get_ca_for_path(ctx, param->value.s);
		if (ca != NULL) {
			new_entry->cm_ca_nickname = talloc_strdup(new_entry,
								  ca->cm_nickname);
		} else {
			cm_log(1, "No CA with path \"%s\" known.\n",
			       param->value.s);
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("No such CA."),
							       param->value.s,
							       "CA");
			talloc_free(parent);
			return ret;
		}
	}

	/* What to tell the CA we want. */
	param = cm_tdbusm_find_dict_entry(d, CM_DBUS_PROP_CA_PROFILE, cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_profile = maybe_strdup(new_entry,
							      param->value.s);
	}
	/* Behavior settings. */
	param = cm_tdbusm_find_dict_entry(d, "TRACK", cm_tdbusm_dict_b);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_MONITORING,
						  cm_tdbusm_dict_b);
	}
	if (param != NULL) {
		new_entry->cm_monitor = param->value.b;
	} else {
		new_entry->cm_monitor = cm_prefs_monitor();
	}
	param = cm_tdbusm_find_dict_entry(d, "RENEW", cm_tdbusm_dict_b);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_AUTORENEW,
						  cm_tdbusm_dict_b);
	}
	if (param != NULL) {
		new_entry->cm_autorenew = param->value.b;
	} else {
		new_entry->cm_autorenew = cm_prefs_autorenew();
	}
	if (pre_command != NULL) {
		new_entry->cm_pre_certsave_uid = talloc_asprintf(new_entry,
								 "%lu",
								 (unsigned long) ci->uid);
		if (new_entry->cm_pre_certsave_uid != NULL) {
			new_entry->cm_pre_certsave_command = maybe_strdup(new_entry,
									  pre_command);
		}
	}
	if (post_command != NULL) {
		new_entry->cm_post_certsave_uid = talloc_asprintf(new_entry,
								  "%lu",
								  (unsigned long) ci->uid);
		if (new_entry->cm_post_certsave_uid != NULL) {
			new_entry->cm_post_certsave_command = maybe_strdup(new_entry,
									   post_command);
		}
	}
	/* Template information. */
	param = cm_tdbusm_find_dict_entry(d, "SUBJECT", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_SUBJECT,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		new_entry->cm_template_subject = maybe_strdup(new_entry,
							      param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "KU", cm_tdbusm_dict_s);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_KU,
						  cm_tdbusm_dict_s);
	}
	if (param != NULL) {
		new_entry->cm_template_ku = maybe_strdup(new_entry,
							 param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d, "EKU", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_EKU,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_eku = cm_submit_maybe_joinv(new_entry,
								   ",",
								   param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "PRINCIPAL", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_principal = maybe_strdupv(new_entry,
								 param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "DNS", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_HOSTNAME,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_hostname = maybe_strdupv(new_entry,
								param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d, "EMAIL", cm_tdbusm_dict_as);
	if (param == NULL) {
		param = cm_tdbusm_find_dict_entry(d,
						  CM_DBUS_PROP_TEMPLATE_EMAIL,
						  cm_tdbusm_dict_as);
	}
	if (param != NULL) {
		new_entry->cm_template_email = maybe_strdupv(new_entry,
							     param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_IP_ADDRESS,
					  cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_ipaddress = maybe_strdupv(new_entry,
								 param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_IS_CA,
					  cm_tdbusm_dict_b);
	if (param != NULL) {
		new_entry->cm_template_is_ca = param->value.b;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH,
					  cm_tdbusm_dict_n);
	if (param != NULL) {
		new_entry->cm_template_ca_path_length = param->value.n;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_OCSP,
					  cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_ocsp_location = maybe_strdupv(new_entry,
								     param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_CRL_DP,
					  cm_tdbusm_dict_as);
	if (param != NULL) {
		new_entry->cm_template_crl_distribution_point = maybe_strdupv(new_entry,
									      param->value.as);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_NS_COMMENT,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_ns_comment = maybe_strdup(new_entry,
								 param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_PROFILE,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_profile = maybe_strdup(new_entry,
							      param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_ISSUER,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		new_entry->cm_template_issuer = maybe_strdup(new_entry,
							     param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE,
					  cm_tdbusm_dict_s);
	if (param != NULL) {
		if (param->value.s != NULL
		    && strlen(param->value.s) > 0
		    && !cm_ms_template_valid(param->value.s)) {
			cm_log(1, "Invalid V2 certificate template specifier: %s", param->value.s);
			ret = send_internal_base_bad_arg_error(
				conn, msg,
				_("Invalid V2 certificate template specifier: %s"),
				param->value.s,
				CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE);
			talloc_free(parent);
			return ret;
		}
		new_entry->cm_template_certificate_template = maybe_strdup(new_entry,
									   param->value.s);
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD,
					  cm_tdbusm_dict_s);
	if ((param != NULL) &&
	    (param->value.s != NULL) &&
	    (strlen(param->value.s) != 0)) {
		challenge_password = param->value.s;
		challenge_password_file = NULL;
	} else {
		challenge_password = NULL;
	}
	param = cm_tdbusm_find_dict_entry(d,
					  CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE,
					  cm_tdbusm_dict_s);
	if ((param != NULL) &&
	    (param->value.s != NULL) &&
	    (strlen(param->value.s) != 0)) {
		if (check_arg_is_absolute_path(param->value.s) != 0) {
			cm_log(1, "Challenge password storage location is not "
			       "an absolute path.\n");
			ret = send_internal_base_bad_arg_error(conn, msg,
							       _("The location \"%s\" must be an absolute path."),
							       param->value.s,
							       CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE);
			talloc_free(parent);
			return ret;
		}
		challenge_password_file = param->value.s;
		challenge_password = NULL;
	} else {
		challenge_password_file = NULL;
	}
	new_entry->cm_template_challenge_password = maybe_strdup(new_entry,
								 challenge_password);
	new_entry->cm_template_challenge_password_file = maybe_strdup(new_entry,
								      challenge_password_file);
	/* Hand it off to the main loop. */
	new_entry->cm_state = CM_NEWLY_ADDED;
	if (cm_add_entry(ctx, new_entry) != 0) {
		cm_log(1, "Error adding entry to main loop.\n");
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			cm_tdbusm_set_b(rep, FALSE);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		rep = dbus_message_new_method_return(msg);
		if (rep != NULL) {
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       new_entry->cm_busname);
			cm_tdbusm_set_bp(rep, TRUE, path);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}
	}
}

/* org.fedorahosted.certmonger.find_request_by_nickname */
static DBusHandlerResult
base_find_request_by_nickname(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	struct cm_store_entry *entry;
	DBusMessage *rep;
	void *parent;
	char *arg, *path;
	int i, n_entries;

	parent = talloc_new(NULL);
	path = NULL;
	if (cm_tdbusm_get_s(msg, parent, &arg) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		n_entries = cm_get_n_entries(ctx);
		for (i = 0; i < n_entries; i++) {
			entry = cm_get_entry_by_index(ctx, i);
			if (strcmp(arg, entry->cm_nickname) == 0) {
				path = talloc_asprintf(ctx, "%s/%s",
						       CM_DBUS_REQUEST_PATH,
						       entry->cm_busname);
				break;
			}
		}
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (path != NULL) {
			cm_tdbusm_set_p(rep, path);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.find_ca_by_nickname */
static DBusHandlerResult
base_find_ca_by_nickname(DBusConnection *conn, DBusMessage *msg,
			 struct cm_client_info *ci, struct cm_context *ctx)
{
	struct cm_store_ca *ca;
	DBusMessage *rep;
	void *parent;
	char *arg, *path;
	int i, n_cas;

	parent = talloc_new(NULL);
	path = NULL;
	if (cm_tdbusm_get_s(msg, parent, &arg) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		n_cas = cm_get_n_cas(ctx);
		for (i = 0; i < n_cas; i++) {
			ca = cm_get_ca_by_index(ctx, i);
			if (strcmp(arg, ca->cm_nickname) == 0) {
				path = talloc_asprintf(ctx, "%s/%s",
						       CM_DBUS_CA_PATH,
						       ca->cm_busname);
				break;
			}
		}
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (path != NULL) {
			cm_tdbusm_set_p(rep, path);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(parent);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_known_cas */
static DBusHandlerResult
base_get_known_cas(DBusConnection *conn, DBusMessage *msg,
		   struct cm_client_info *ci, struct cm_context *ctx)
{
	int i, n_cas;
	struct cm_store_ca *ca;
	char **ret;
	DBusMessage *rep;
	n_cas = cm_get_n_cas(ctx);
	ret = talloc_array(ctx, char *, n_cas + 1);
	if (ret != NULL) {
		for (i = 0; i < n_cas; i++) {
			ca = cm_get_ca_by_index(ctx, i);
			if (ca == NULL) {
				break;
			}
			ret[i] = talloc_asprintf(ret, "%s/%s",
						 CM_DBUS_CA_PATH,
						 ca->cm_busname);
		}
		ret[i] = NULL;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ap(rep, (const char **) ret);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(ret);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(ret);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_requests */
static DBusHandlerResult
base_get_requests(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	int i, n_entries;
	struct cm_store_entry *entry;
	char **ret;
	DBusMessage *rep;
	n_entries = cm_get_n_entries(ctx);
	ret = talloc_array(ctx, char *, n_entries + 1);
	if (ret != NULL) {
		for (i = 0; i < n_entries; i++) {
			entry = cm_get_entry_by_index(ctx, i);
			if (entry == NULL) {
				break;
			}
			ret[i] = talloc_asprintf(ret, "%s/%s",
						 CM_DBUS_REQUEST_PATH,
						 entry->cm_busname);
		}
		ret[i] = NULL;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ap(rep, (const char **) ret);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(ret);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		talloc_free(ret);
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_supported_key_types */
static DBusHandlerResult
base_get_supported_key_types(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	const char *key_types[] = {
		"RSA",
#ifdef CM_ENABLE_DSA
		"DSA",
#endif
#ifdef CM_ENABLE_EC
		"EC",
#endif
#ifdef CM_ENABLE_ML_DSA
		"ML-DSA-44",
		"ML-DSA-65",
		"ML-DSA-87",
#endif
		NULL
	};
	DBusMessage *rep;
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_as(rep, key_types);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_base_error(conn, msg);
	}
}

static DBusHandlerResult
base_get_supported_key_and_cert_storage(DBusConnection *conn, DBusMessage *msg,
					struct cm_client_info *ci, struct cm_context *ctx)
{
#ifdef HAVE_OPENSSL
	const char *maybe_file = "FILE";
#else
	const char *maybe_file = NULL;
#endif
	const char *storage_types[] = {"NSSDB", maybe_file, NULL};
	DBusMessage *rep;
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_as(rep, storage_types);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_base_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.get_supported_key_storage */
static DBusHandlerResult
base_get_supported_key_storage(DBusConnection *conn, DBusMessage *msg,
			       struct cm_client_info *ci, struct cm_context *ctx)
{
	return base_get_supported_key_and_cert_storage(conn, msg, ci, ctx);
}

/* org.fedorahosted.certmonger.get_supported_cert_storage */
static DBusHandlerResult
base_get_supported_cert_storage(DBusConnection *conn, DBusMessage *msg,
				struct cm_client_info *ci, struct cm_context *ctx)
{
	return base_get_supported_key_and_cert_storage(conn, msg, ci, ctx);
}

/* org.fedorahosted.certmonger.remove_known_ca */
static DBusHandlerResult
base_remove_known_ca(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	int ret;
	void *parent;
	char *path, *helper;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_p(msg, parent, &path) == 0) {
		ca = get_ca_for_path(ctx, path);
		if (ca != NULL) {
			helper = talloc_strdup(parent,
					       ca->cm_ca_external_helper);
			ret = cm_remove_ca(ctx, ca->cm_nickname);
			if ((ret == 0) && (helper != NULL)) {
				acme_eab_forget(parent, helper);
			}
			talloc_free(parent);
			cm_tdbusm_set_b(rep, (ret == 0));
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			talloc_free(parent);
			dbus_message_unref(rep);
			return send_internal_base_no_such_entry_error(conn,
								      msg);
		}
	} else {
		talloc_free(parent);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
}

/* org.fedorahosted.certmonger.remove_request */
static DBusHandlerResult
base_remove_request(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	int ret;
	void *parent;
	char *path;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_p(msg, parent, &path) == 0) {
		entry = get_entry_for_path(ctx, path);
		talloc_free(parent);
		if (entry != NULL) {
			ret = cm_remove_entry(ctx, entry->cm_nickname);
			cm_tdbusm_set_b(rep, (ret == 0));
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			dbus_message_unref(rep);
			return send_internal_base_no_such_entry_error(conn,
								      msg);
		}
	} else {
		talloc_free(parent);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
}

/* Convenience functions for returning errors from a CA object to callers. */
static DBusHandlerResult
send_internal_ca_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_CA_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for CA objects.  Most of the "get_XXX" functions
 * predate the properties interface being added, so they're redundant now. */

/* org.fedorahosted.certonger.ca.get_nickname */
static DBusHandlerResult
ca_get_nickname(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;

	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (ca->cm_nickname != NULL) {
			cm_tdbusm_set_s(rep, ca->cm_nickname);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_is_default */
static DBusHandlerResult
ca_get_is_default(DBusConnection *conn, DBusMessage *msg,
		  struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, ca->cm_ca_is_default);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_issuer_names */
static DBusHandlerResult
ca_get_issuer_names(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char **names;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		names = (const char **) ca->cm_ca_known_issuer_names;
		cm_tdbusm_set_as(rep, names);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_location */
static DBusHandlerResult
ca_get_location(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, ca->cm_ca_external_helper);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_type */
static DBusHandlerResult
ca_get_type(DBusConnection *conn, DBusMessage *msg,
	    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *ca_type;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		ca_type = NULL;
		switch (ca->cm_ca_type) {
		case cm_ca_internal_self:
			ca_type = "INTERNAL:SELF";
			break;
		case cm_ca_external:
			ca_type = "EXTERNAL";
			break;
		}
		cm_tdbusm_set_s(rep, ca_type);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_serial */
static DBusHandlerResult
ca_get_serial(DBusConnection *conn, DBusMessage *msg,
	      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	const char *serial;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		switch (ca->cm_ca_type) {
		case cm_ca_internal_self:
			serial = ca->cm_ca_internal_serial;
			cm_tdbusm_set_s(rep, serial);
			break;
		case cm_ca_external:
			break;
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.get_config_file_path */
static DBusHandlerResult
ca_get_config_file_path(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, ca->cm_store_private);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* org.fedorahosted.certonger.ca.refresh */
static DBusHandlerResult
ca_refresh(DBusConnection *conn, DBusMessage *msg,
	   struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_ca *ca;
	enum cm_ca_phase phase;
	dbus_bool_t result = TRUE;

	ca = get_ca_for_request_message(msg, ctx);
	if (ca == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
		if (!cm_restart_ca(ctx, ca->cm_nickname, phase)) {
			result = FALSE;
		}
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, result);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_ca_error(conn, msg);
	}
}

/* Custom property get/set logic for CA structures. */
static dbus_bool_t
ca_prop_get_is_default(struct cm_context *ctx, void *parent,
		       void *record, const char *name)
{
	struct cm_store_ca *ca = record;
	if (strcmp(name, CM_DBUS_PROP_IS_DEFAULT) == 0) {
		return ca->cm_ca_is_default ? TRUE : FALSE;
	}
	return FALSE;
}

static void
ca_prop_set_is_default(struct cm_context *ctx, void *parent,
		       void *record, const char *name,
		       dbus_bool_t new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record, *other;
	int i;

	if (strcmp(name, CM_DBUS_PROP_IS_DEFAULT) == 0) {
		propname[0] = CM_DBUS_PROP_IS_DEFAULT;
		propname[1] = NULL;
		if (new_value) {
			i = 0;
			/* There can be only one... default. */
			while ((other = cm_get_ca_by_index(ctx, i++)) != NULL) {
				if ((other != ca) &&
				    (other->cm_ca_is_default)) {
					other->cm_ca_is_default = FALSE;
					path = talloc_asprintf(parent, "%s/%s",
							       CM_DBUS_CA_PATH,
							       other->cm_busname);
					cm_tdbush_property_emit_changed(ctx, path,
									CM_DBUS_CA_INTERFACE,
									propname);
				}
			}
		}
		if ((!ca->cm_ca_is_default && new_value) ||
		    (ca->cm_ca_is_default && !new_value)) {
			ca->cm_ca_is_default = new_value;
			path = talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       ca->cm_busname);
			cm_tdbush_property_emit_changed(ctx, path,
							CM_DBUS_CA_INTERFACE,
							propname);
		}
	}
}

static const char *
ca_prop_get_external_helper(struct cm_context *ctx, void *parent,
			    void *record, const char *name)
{
	struct cm_store_ca *ca = record;

	if (strcmp(name, CM_DBUS_PROP_EXTERNAL_HELPER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return "";
		}
		if (ca->cm_ca_external_helper != NULL) {
			return ca->cm_ca_external_helper;
		} else {
			return "";
		}
	}
	return NULL;
}

static void
ca_prop_set_external_helper(struct cm_context *ctx, void *parent,
			    void *record, const char *name,
			    const char *new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record;
	enum cm_ca_phase phase;

	if (strcmp(name, CM_DBUS_PROP_EXTERNAL_HELPER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return;
		}
		talloc_free(ca->cm_ca_external_helper);
		ca->cm_ca_external_helper = new_value ?
					    talloc_strdup(ca, new_value) :
					    NULL;
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			cm_restart_ca(ctx, ca->cm_nickname, phase);
		}
		propname[0] = CM_DBUS_PROP_EXTERNAL_HELPER;
		propname[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_CA_PATH,
				       ca->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_CA_INTERFACE,
						propname);
	}
}

static const char *
ca_prop_get_scep_cipher(struct cm_context *ctx, void *parent,
			       void *record, const char *name)
{
	struct cm_store_ca *ca = record;

	if (strcmp(name, CM_DBUS_PROP_SCEP_CIPHER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return "";
		}
		if (ca->cm_ca_scep_cipher != NULL) {
			return ca->cm_ca_scep_cipher;
		} else {
			return "";
		}
	}
	return NULL;
}

static void
ca_prop_set_scep_cipher(struct cm_context *ctx, void *parent,
			       void *record, const char *name,
			       const char *new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record;
	enum cm_ca_phase phase;

	if (strcmp(name, CM_DBUS_PROP_SCEP_CIPHER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return;
		}
		talloc_free(ca->cm_ca_scep_cipher);
		ca->cm_ca_scep_cipher = new_value ?
					       talloc_strdup(ca, new_value) :
					       NULL;
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			cm_restart_ca(ctx, ca->cm_nickname, phase);
		}
		propname[0] = CM_DBUS_PROP_SCEP_CIPHER;
		propname[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_CA_PATH,
				       ca->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_CA_INTERFACE,
						propname);
	}
}

static const char *
ca_prop_get_scep_digest(struct cm_context *ctx, void *parent,
			       void *record, const char *name)
{
	struct cm_store_ca *ca = record;

	if (strcmp(name, CM_DBUS_PROP_SCEP_DIGEST) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return "";
		}
		if (ca->cm_ca_scep_digest != NULL) {
			return ca->cm_ca_scep_digest;
		} else {
			return "";
		}
	}
	return NULL;
}

static void
ca_prop_set_scep_digest(struct cm_context *ctx, void *parent,
			       void *record, const char *name,
			       const char *new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record;
	enum cm_ca_phase phase;

	if (strcmp(name, CM_DBUS_PROP_SCEP_DIGEST) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return;
		}
		talloc_free(ca->cm_ca_scep_digest);
		ca->cm_ca_scep_digest = new_value ?
					       talloc_strdup(ca, new_value) :
					       NULL;
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			cm_restart_ca(ctx, ca->cm_nickname, phase);
		}
		propname[0] = CM_DBUS_PROP_SCEP_DIGEST;
		propname[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_CA_PATH,
				       ca->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_CA_INTERFACE,
						propname);
	}
}

static const char *
ca_prop_get_scep_ca_identifier(struct cm_context *ctx, void *parent,
			       void *record, const char *name)
{
	struct cm_store_ca *ca = record;

	if (strcmp(name, CM_DBUS_PROP_SCEP_CA_IDENTIFIER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return "";
		}
		if (ca->cm_ca_scep_ca_identifier != NULL) {
			return ca->cm_ca_scep_ca_identifier;
		} else {
			return "";
		}
	}
	return NULL;
}

static void
ca_prop_set_scep_ca_identifier(struct cm_context *ctx, void *parent,
			       void *record, const char *name,
			       const char *new_value)
{
	const char *propname[2], *path;
	struct cm_store_ca *ca = record;
	enum cm_ca_phase phase;

	if (strcmp(name, CM_DBUS_PROP_SCEP_CA_IDENTIFIER) == 0) {
		if (ca->cm_ca_type != cm_ca_external) {
			return;
		}
		talloc_free(ca->cm_ca_scep_ca_identifier);
		ca->cm_ca_scep_ca_identifier = new_value ?
					       talloc_strdup(ca, new_value) :
					       NULL;
		for (phase = 0; phase < cm_ca_phase_invalid; phase++) {
			cm_restart_ca(ctx, ca->cm_nickname, phase);
		}
		propname[0] = CM_DBUS_PROP_SCEP_CA_IDENTIFIER;
		propname[1] = NULL;
		path = talloc_asprintf(parent, "%s/%s",
				       CM_DBUS_CA_PATH,
				       ca->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_CA_INTERFACE,
						propname);
	}
}

static const char **
ca_prop_read_nickcerts(struct cm_context *ctx, void *parent,
		       struct cm_nickcert **nickcerts)
{
	char **ret = NULL, **tmp;
	int i;

	for (i = 0; (nickcerts != NULL) && (nickcerts[i] != NULL); i++) {
		tmp = talloc_realloc(parent, ret, char *, i * 2 + 3);
		if (tmp == NULL) {
			talloc_free(ret);
			return NULL;
		}
		tmp[i * 2] = talloc_strdup(tmp, nickcerts[i]->cm_nickname);
		tmp[i * 2 + 1] = talloc_strdup(tmp, nickcerts[i]->cm_cert);
		tmp[i * 2 + 2] = NULL;
		ret = tmp;
	}
	return (const char **) ret;
}

static const char **
ca_prop_get_nickcerts(struct cm_context *ctx, void *parent,
		      void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	struct cm_store_ca *ca = record;

	if (strcmp(name, CM_DBUS_PROP_CERT_CHAIN) == 0) {
		return ca_prop_read_nickcerts(ctx, parent,
					      entry->cm_cert_chain);
	} else
	if (strcmp(name, CM_DBUS_PROP_CERT_ROOTS) == 0) {
		return ca_prop_read_nickcerts(ctx, parent,
					      entry->cm_cert_roots);
	} else
	if (strcmp(name, CM_DBUS_PROP_ROOT_CERTS) == 0) {
		return ca_prop_read_nickcerts(ctx, parent,
					      ca->cm_ca_root_certs);
	} else
	if (strcmp(name, CM_DBUS_PROP_OTHER_ROOT_CERTS) == 0) {
		return ca_prop_read_nickcerts(ctx, parent,
					      ca->cm_ca_other_root_certs);
	} else
	if (strcmp(name, CM_DBUS_PROP_OTHER_CERTS) == 0) {
		return ca_prop_read_nickcerts(ctx, parent,
					      ca->cm_ca_other_certs);
	}
	return NULL;
}

/* Convenience functions for returning errors from a request object to callers. */
static DBusHandlerResult
send_internal_request_error(DBusConnection *conn, DBusMessage *req)
{
	DBusMessage *msg;
	msg = dbus_message_new_error(req, CM_DBUS_ERROR_REQUEST_INTERNAL,
				     _("An internal error has occurred."));
	if (msg != NULL) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* Functions implemented for request objects.  Most of the "get_XXX" functions
 * predate the properties interface being added, so they're redundant now. */

/* org.fedorahosted.certmonger.request.get_nickname */
static DBusHandlerResult
request_get_nickname(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_nickname != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_nickname);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_pin */
static DBusHandlerResult
request_get_key_pin(DBusConnection *conn, DBusMessage *msg,
		    struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, entry->cm_key_pin);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_pin_file */
static DBusHandlerResult
request_get_key_pin_file(DBusConnection *conn, DBusMessage *msg,
			 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, entry->cm_key_pin_file);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_autorenew */
static DBusHandlerResult
request_get_autorenew(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, entry->cm_autorenew);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_data */
static DBusHandlerResult
request_get_cert_data(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_cert != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_cert);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* convert our text bit string into a number */
static long
ku_from_string(const char *ku)
{
	long i = 0, mask = 1;
	while ((ku != NULL) && (*ku != '\0')) {
		switch (*ku++) {
		case '1':
			i |= mask;
			break;
		case '0':
		default:
			break;
		}
		mask <<= 1;
	}
	return i;
}

#if 0
/* convert our number into a text bit string */
static const char *
ku_to_string(unsigned long ku, char *output, ssize_t len)
{
	static char local_output[33];
	char *p;
	if (output == NULL) {
		output = local_output;
		len = sizeof(local_output);
	}
	p = output;
	while (((p - output) < len) && (ku != 0)) {
		*p++ = (ku & 1) ? '1' : '0';
		ku >>= 1;
	}
	if (p - output == len) {
		return NULL;
	}
	*p++ = '\0';
	return output;
}
#endif

/* split the comma-separated list into an array */
static char **
eku_splitv(void *parent, const char *eku)
{
	char **ret = NULL;
	const char *p, *q;
	int i;
	if ((eku != NULL) && (strlen(eku) > 0)) {
		ret = talloc_array_ptrtype(parent, ret, strlen(eku) + 1);
		p = eku;
		i = 0;
		while (*p != '\0') {
			q = p + strcspn(p, ",");
			if (p != q) {
				ret[i++] = talloc_strndup(ret, p, q - p);
			}
			p = q + strspn(q, ",");
		}
		ret[i] = NULL;
		if (i == 0) {
			talloc_free(ret);
			ret = NULL;
		}
	}
	return ret;
}

/* org.fedorahosted.certmonger.request.get_cert_info */
static DBusHandlerResult
request_get_cert_info(DBusConnection *conn, DBusMessage *msg,
		      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char **eku;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		eku = eku_splitv(entry, entry->cm_cert_eku);
		cm_tdbusm_set_sssnasasasnasn(rep,
					    entry->cm_cert_issuer,
					    entry->cm_cert_serial,
					    entry->cm_cert_subject,
					    entry->cm_cert_not_after,
					    (const char **) entry->cm_cert_email,
					    (const char **) entry->cm_cert_hostname,
					    (const char **) entry->cm_cert_principal,
					    ku_from_string(entry->cm_cert_ku),
					    (const char **) eku,
					    entry->cm_cert_not_before);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(eku);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_last_checked */
static DBusHandlerResult
request_get_cert_last_checked(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_submitted != 0) {
			cm_tdbusm_set_n(rep, entry->cm_submitted);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_cert_storage_info */
static DBusHandlerResult
request_get_cert_storage_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		location = entry->cm_cert_storage_location;
		switch (entry->cm_cert_storage_type) {
		case cm_cert_storage_file:
			type = "FILE";
			cm_tdbusm_set_ss(rep, type, location);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_cert_storage_nssdb:
			type = "NSSDB";
			token = entry->cm_cert_token;
			nick = entry->cm_cert_nickname;
			if (token != NULL) {
				cm_tdbusm_set_ssss(rep, type,
						   location, nick, token);
				dbus_connection_send(conn, rep, NULL);
			} else
			if (nick != NULL) {
				cm_tdbusm_set_sss(rep, type, location, nick);
				dbus_connection_send(conn, rep, NULL);
			} else {
				cm_tdbusm_set_ss(rep, type, location);
				dbus_connection_send(conn, rep, NULL);
			}
			break;
		}
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_csr_data */
static DBusHandlerResult
request_get_csr_data(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_csr != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_csr);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_csr_info */
static DBusHandlerResult
request_get_csr_info(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	char **eku;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_csr != NULL) {
			eku = eku_splitv(entry, entry->cm_template_eku);
			cm_tdbusm_set_sasasasnas(rep,
						 entry->cm_template_subject,
						 (const char **) entry->cm_template_email,
						 (const char **) entry->cm_template_hostname,
						 (const char **) entry->cm_template_principal,
						 ku_from_string(entry->cm_template_ku),
						 (const char **) eku);
			talloc_free(eku);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_storage_info */
static DBusHandlerResult
request_get_key_storage_info(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type, *location, *nick, *token;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		location = entry->cm_key_storage_location;
		switch (entry->cm_key_storage_type) {
		case cm_key_storage_none:
			type = "NONE";
			cm_tdbusm_set_s(rep, type);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_key_storage_file:
			type = "FILE";
			cm_tdbusm_set_ss(rep, type, location);
			dbus_connection_send(conn, rep, NULL);
			break;
		case cm_key_storage_nssdb:
			type = "NSSDB";
			token = entry->cm_key_token;
			nick = entry->cm_key_nickname;
			if (token != NULL) {
				cm_tdbusm_set_ssss(rep, type,
						   location, nick, token);
				dbus_connection_send(conn, rep, NULL);
			} else
			if (nick != NULL) {
				cm_tdbusm_set_sss(rep, type, location, nick);
				dbus_connection_send(conn, rep, NULL);
			} else {
				cm_tdbusm_set_ss(rep, type, location);
				dbus_connection_send(conn, rep, NULL);
			}
			break;
		}
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_key_type_and_size */
static DBusHandlerResult
request_get_key_type_and_size(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *type;
	int size;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	type = cm_store_algorithm_to_name(entry->cm_key_type.cm_key_algorithm);
	if (rep != NULL) {
		size = entry->cm_key_type.cm_key_size;
		cm_tdbusm_set_sn(rep, type, size);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_monitoring */
static DBusHandlerResult
request_get_monitoring(DBusConnection *conn, DBusMessage *msg,
		       struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_b(rep, entry->cm_monitor);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_notification_info */
static DBusHandlerResult
request_get_notification_info(DBusConnection *conn, DBusMessage *msg,
			      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	enum cm_notification_method m;
	const char *method, *d;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	m = cm_prefs_notification_method();
	d = cm_prefs_notification_destination();
	method = NULL;
	switch (m) {
	case cm_notification_unspecified:
		abort();
		break;
	case cm_notification_none:
		method = "none";
		break;
	case cm_notification_stdout:
		method = "stdout";
		break;
	case cm_notification_syslog:
		method = "syslog";
		break;
	case cm_notification_email:
		method = "email";
		break;
	case cm_notification_command:
		method = "command";
		break;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_ss(rep, method, d);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

static dbus_bool_t request_prop_get_stuck(struct cm_context *ctx, void *parent,
					  void *record, const char *name);

/* org.fedorahosted.certmonger.request.get_status */
static DBusHandlerResult
request_get_status(DBusConnection *conn, DBusMessage *msg,
		   struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *state;
	dbus_bool_t stuck;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		state = cm_store_state_as_string(entry->cm_state);
		stuck = request_prop_get_stuck(ctx, NULL, entry, CM_DBUS_PROP_STUCK);
		cm_tdbusm_set_sb(rep, state, stuck);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_ca */
static DBusHandlerResult
request_get_ca(DBusConnection *conn, DBusMessage *msg,
	       struct cm_client_info *ci, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *path;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		parent = talloc_new(NULL);
		if ((entry->cm_ca_nickname != NULL) &&
		    (strlen(entry->cm_ca_nickname) > 0)) {
			ca = cm_get_ca_by_nickname(ctx, entry->cm_ca_nickname);
			if ((ca != NULL) &&
			    (ca->cm_busname != NULL) &&
			    (strlen(ca->cm_busname) > 0)) {
				path = talloc_asprintf(parent, "%s/%s",
						       CM_DBUS_CA_PATH,
						       ca->cm_busname);
				cm_tdbusm_set_p(rep, path);
			}
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_ca_error */
static DBusHandlerResult
request_get_ca_error(DBusConnection *conn, DBusMessage *msg,
		     struct cm_client_info *ci, struct cm_context *ctx)
{
	void *parent;
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		parent = talloc_new(NULL);
		if ((entry->cm_ca_error != NULL) &&
		    (strlen(entry->cm_ca_error) > 0)) {
			cm_tdbusm_set_s(rep, entry->cm_ca_error);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_submitted_cookie */
static DBusHandlerResult
request_get_submitted_cookie(DBusConnection *conn, DBusMessage *msg,
			     struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_ca_cookie != NULL) {
			cm_tdbusm_set_s(rep, entry->cm_ca_cookie);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.get_submitted_date */
static DBusHandlerResult
request_get_submitted_date(DBusConnection *conn, DBusMessage *msg,
			   struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (entry->cm_submitted != 0) {
			cm_tdbusm_set_n(rep, entry->cm_submitted);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.modify */
static DBusHandlerResult
request_modify(DBusConnection *conn, DBusMessage *msg,
	       struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	struct cm_tdbusm_dict **d;
	const struct cm_tdbusm_dict *param;
	char *new_request_path;
	void *parent;
	const char *propname[sizeof(*entry)];
	int i;
	size_t n_propname = 0;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	parent = talloc_new(NULL);
	if (cm_tdbusm_get_d(msg, parent, &d) != 0) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		/* Check any new nickname values, because we need to reject
		 * those outright if the new value's already being used. */
		param = cm_tdbusm_find_dict_entry(d, "NICKNAME",
						  cm_tdbusm_dict_s);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_NICKNAME,
							  cm_tdbusm_dict_s);
		}
		if (param != NULL) {
			if (cm_get_entry_by_nickname(ctx, param->value.s) != NULL) {
				return send_internal_base_duplicate_error(conn, msg,
									  _("There is already a request with the nickname \"%s\"."),
									  param->value.s,
									  "NICKNAME",
									  NULL);
			}
		}
		/* If we're being asked to change the CA, check that the new CA
		 * exists. */
		param = cm_tdbusm_find_dict_entry(d, "CA", cm_tdbusm_dict_p);
		if (param == NULL) {
			param = cm_tdbusm_find_dict_entry(d,
							  CM_DBUS_PROP_CA,
							  cm_tdbusm_dict_p);
		}
		if (param != NULL) {
			ca = get_ca_for_path(ctx, param->value.s);
			if (ca == NULL) {
				return send_internal_base_bad_arg_error(conn, msg,
									_("Certificate authority \"%s\" not known."),
									param->value.s,
									"CA");
			}
		}
		/* Now walk the list of other things the client asked us to
		 * change. */
		for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
			param = d[i];
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KEY_TYPE") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_TYPE) == 0))) {
				if (strcasecmp(param->value.s, "RSA") == 0) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_rsa;
#ifdef CM_ENABLE_DSA
				} else
				if (strcasecmp(param->value.s, "DSA") == 0) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_dsa;
#endif
#ifdef CM_ENABLE_EC
				} else
				if ((strcasecmp(param->value.s, "ECDSA") == 0) ||
				    (strcasecmp(param->value.s, "EC") == 0)) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_ecdsa;
#endif
#ifdef CM_ENABLE_ML_DSA
				} else
				if (strcasecmp(param->value.s, "ML-DSA-44") == 0) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_ml_dsa_44;
				} else
				if (strcasecmp(param->value.s, "ML-DSA-65") == 0) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_ml_dsa_65;
				} else
				if (strcasecmp(param->value.s, "ML-DSA-87") == 0) {
					entry->cm_key_type.cm_key_gen_algorithm = cm_key_ml_dsa_87;
#endif
				} else {
					cm_log(1, "No support for generating \"%s\" keys.\n",
					       param->value.s);
					return send_internal_base_bad_arg_error(conn, msg,
										_("No support for key type \"%s\"."),
										param->value.s,
										"KEY_TYPE");
				}
				entry->cm_key_next_type.cm_key_gen_algorithm = entry->cm_key_type.cm_key_gen_algorithm;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_TYPE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_n) &&
			    ((strcasecmp(param->key, "KEY_SIZE") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_SIZE) == 0))) {
				entry->cm_key_type.cm_key_gen_size = param->value.n;
				entry->cm_key_next_type.cm_key_gen_size = entry->cm_key_type.cm_key_gen_size;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_SIZE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_OWNER) == 0)) {
				entry->cm_cert_owner = talloc_strdup(entry, param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_OWNER;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_n) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_PERMS) == 0)) {
				entry->cm_cert_perms = param->value.n;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_PERMS;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_KEY_OWNER) == 0)) {
				entry->cm_key_owner = talloc_strdup(entry, param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_OWNER;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_n) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_KEY_PERMS) == 0)) {
				entry->cm_key_perms = param->value.n;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_PERMS;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_NSS_USER) == 0)) {
				entry->cm_nss_user = talloc_strdup(entry, param->value.s);
		        cm_log(1, "Param CM_DBUS_PROP_NSS_USER to %s\n", entry->cm_nss_user);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_NSS_USER;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    ((strcasecmp(param->key, "RENEW") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_AUTORENEW) == 0))) {
				entry->cm_autorenew = param->value.b;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_AUTORENEW;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    ((strcasecmp(param->key, "TRACK") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_MONITORING) == 0))) {
				entry->cm_monitor = param->value.b;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_MONITORING;
				}
			} else
			if (((param->value_type == cm_tdbusm_dict_s) ||
			     (param->value_type == cm_tdbusm_dict_p)) &&
			    ((strcasecmp(param->key, "CA") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_CA) == 0))) {
				ca = get_ca_for_path(ctx, param->value.s);
				talloc_free(entry->cm_ca_nickname);
				entry->cm_ca_nickname = talloc_strdup(entry,
								      ca->cm_nickname);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CA;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CA_PROFILE) == 0)) {
				talloc_free(entry->cm_template_profile);
				entry->cm_template_profile = talloc_strdup(entry,
									   param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CA_PROFILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "NICKNAME") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_NICKNAME) == 0))) {
				talloc_free(entry->cm_nickname);
				entry->cm_nickname = talloc_strdup(entry,
								   param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_NICKNAME;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "SUBJECT") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_SUBJECT) == 0))) {
				talloc_free(entry->cm_template_subject);
				entry->cm_template_subject = maybe_strdup(entry,
									  param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_SUBJECT;
				}
				/* Clear the would-be-preferred DER version. */
				talloc_free(entry->cm_template_subject_der);
				entry->cm_template_subject_der = NULL;
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KEY_PIN") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_PIN) == 0))) {
				talloc_free(entry->cm_key_pin);
				entry->cm_key_pin = maybe_strdup(entry,
								 param->value.s);
				if (entry->cm_key_pin != NULL) {
					entry->cm_key_pin_file = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_PIN;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KEY_PIN_FILE") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_KEY_PIN_FILE) == 0))) {
				if ((param->value.s != NULL) &&
				    (strlen(param->value.s) != 0) &&
				    (check_arg_is_absolute_path(param->value.s) != 0)) {
					cm_log(1, "PIN storage location is not "
					       "an absolute path.\n");
					return send_internal_base_bad_arg_error(conn, msg,
										_("The location \"%s\" must be an absolute path."),
										param->value.s,
										"KEY_PIN_FILE");
				}
				talloc_free(entry->cm_key_pin_file);
				entry->cm_key_pin_file = maybe_strdup(entry,
								      param->value.s);
				if (entry->cm_key_pin_file != NULL) {
					entry->cm_key_pin = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_KEY_PIN_FILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    ((strcasecmp(param->key, "KU") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_KU) == 0))) {
				talloc_free(entry->cm_template_ku);
				entry->cm_template_ku = maybe_strdup(entry,
								     param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_KU;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "EKU") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_EKU) == 0))) {
				talloc_free(entry->cm_template_eku);
				entry->cm_template_eku = cm_submit_maybe_joinv(entry,
									       ",",
									       param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_EKU;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "PRINCIPAL") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_PRINCIPAL) == 0))) {
				talloc_free(entry->cm_template_principal);
				entry->cm_template_principal = maybe_strdupv(entry,
									     param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "DNS") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_HOSTNAME) == 0))) {
				talloc_free(entry->cm_template_hostname);
				entry->cm_template_hostname = maybe_strdupv(entry,
									    param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_HOSTNAME;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    ((strcasecmp(param->key, "EMAIL") == 0) ||
			     (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_EMAIL) == 0))) {
				talloc_free(entry->cm_template_email);
				entry->cm_template_email = maybe_strdupv(entry,
									 param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_EMAIL;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_IP_ADDRESS) == 0)) {
				entry->cm_template_ipaddress = maybe_strdupv(entry,
									     param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_IP_ADDRESS;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_b) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_IS_CA) == 0)) {
				entry->cm_template_is_ca = param->value.b;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_IS_CA;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_n) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH) == 0)) {
				entry->cm_template_ca_path_length = param->value.n;
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_OCSP) == 0)) {
				talloc_free(entry->cm_template_ocsp_location);
				entry->cm_template_ocsp_location = maybe_strdupv(entry,
										 param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_OCSP;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_CRL_DP) == 0)) {
				talloc_free(entry->cm_template_crl_distribution_point);
				entry->cm_template_crl_distribution_point = maybe_strdupv(entry,
											  param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_CRL_DP;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_NS_COMMENT) == 0)) {
				talloc_free(entry->cm_template_ns_comment);
				entry->cm_template_ns_comment = maybe_strdup(entry,
									     param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_NS_COMMENT;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_PROFILE) == 0)) {
				talloc_free(entry->cm_template_profile);
				entry->cm_template_profile = maybe_strdup(entry,
									  param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_PROFILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_ISSUER) == 0)) {
				talloc_free(entry->cm_template_issuer);
				entry->cm_template_issuer = maybe_strdup(entry, param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_ISSUER;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE) == 0)) {
				if (param->value.s != NULL
				    && strlen(param->value.s) > 0
				    && !cm_ms_template_valid(param->value.s)) {
					cm_log(1, "Invalid V2 certificate template specifier: %s", param->value.s);
					return send_internal_base_bad_arg_error(
						conn, msg,
						_("Invalid V2 certificate template specifier: %s"),
						param->value.s,
						CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE);
				}
				talloc_free(entry->cm_template_certificate_template);
				entry->cm_template_certificate_template =
					maybe_strdup(entry, param->value.s);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] =
						CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD) == 0)) {
				talloc_free(entry->cm_template_challenge_password);
				entry->cm_template_challenge_password = maybe_strdup(entry,
										     param->value.s);
				if (entry->cm_template_challenge_password != NULL) {
					entry->cm_template_challenge_password_file = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE) == 0)) {
				if ((param->value.s != NULL) &&
				    (strlen(param->value.s) != 0) &&
				    (check_arg_is_absolute_path(param->value.s) != 0)) {
					cm_log(1, "Challenge password storage "
					       "location is not an absolute "
					       "path.\n");
					return send_internal_base_bad_arg_error(conn, msg,
										_("The location \"%s\" must be an absolute path."),
										param->value.s,
										CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE);
				}
				talloc_free(entry->cm_template_challenge_password_file);
				entry->cm_template_challenge_password_file = maybe_strdup(entry,
											  param->value.s);
				if (entry->cm_template_challenge_password_file != NULL) {
					entry->cm_template_challenge_password = NULL;
				}
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_PRESAVE_COMMAND) == 0)) {
				talloc_free(entry->cm_pre_certsave_command);
				entry->cm_pre_certsave_command = maybe_strdup(entry,
									      param->value.s);
				talloc_free(entry->cm_pre_certsave_uid);
				if (entry->cm_pre_certsave_command != NULL) {
					entry->cm_pre_certsave_uid = talloc_asprintf(entry, "%lu",
										     (unsigned long) ci->uid);
					if (entry->cm_pre_certsave_uid == NULL) {
						talloc_free(entry->cm_pre_certsave_command);
						entry->cm_pre_certsave_command = NULL;
					}
				} else {
					entry->cm_pre_certsave_uid = NULL;
				}
				if (n_propname + 3 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
					propname[n_propname++] = CM_DBUS_PROP_CERT_PRESAVE_UID;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_s) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_CERT_POSTSAVE_COMMAND) == 0)) {
				talloc_free(entry->cm_post_certsave_command);
				entry->cm_post_certsave_command = maybe_strdup(entry,
									       param->value.s);
				talloc_free(entry->cm_post_certsave_uid);
				if (entry->cm_post_certsave_command != NULL) {
					entry->cm_post_certsave_uid = talloc_asprintf(entry, "%lu",
										      (unsigned long) ci->uid);
					if (entry->cm_post_certsave_uid == NULL) {
						talloc_free(entry->cm_post_certsave_command);
						entry->cm_post_certsave_command = NULL;
					}
				} else {
					entry->cm_post_certsave_uid = NULL;
				}
				if (n_propname + 3 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
					propname[n_propname++] = CM_DBUS_PROP_CERT_POSTSAVE_UID;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_ROOT_CERT_FILES) == 0)) {
				talloc_free(entry->cm_root_cert_store_files);
				entry->cm_root_cert_store_files = maybe_strdupv(entry,
										param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_ROOT_CERT_FILES;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_OTHER_ROOT_CERT_FILES) == 0)) {
				talloc_free(entry->cm_other_root_cert_store_files);
				entry->cm_other_root_cert_store_files = maybe_strdupv(entry,
										      param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_OTHER_ROOT_CERT_FILES;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_OTHER_CERT_FILES) == 0)) {
				talloc_free(entry->cm_other_cert_store_nssdbs);
				entry->cm_other_cert_store_nssdbs = maybe_strdupv(entry,
										 param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_OTHER_CERT_FILES;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_ROOT_CERT_NSSDBS) == 0)) {
				talloc_free(entry->cm_root_cert_store_nssdbs);
				entry->cm_root_cert_store_nssdbs = maybe_strdupv(entry,
										param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_ROOT_CERT_NSSDBS;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS) == 0)) {
				talloc_free(entry->cm_other_root_cert_store_nssdbs);
				entry->cm_other_root_cert_store_nssdbs = maybe_strdupv(entry,
										      param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS;
				}
			} else
			if ((param->value_type == cm_tdbusm_dict_as) &&
			    (strcasecmp(param->key, CM_DBUS_PROP_OTHER_CERT_NSSDBS) == 0)) {
				talloc_free(entry->cm_other_cert_store_nssdbs);
				entry->cm_other_cert_store_nssdbs = maybe_strdupv(entry,
										 param->value.as);
				if (n_propname + 2 < sizeof(propname) / sizeof(propname[0])) {
					propname[n_propname++] = CM_DBUS_PROP_OTHER_CERT_NSSDBS;
				}
			} else {
				break;
			}
		}
		if (d != NULL) {
			if (d[i] == NULL) {
				new_request_path = talloc_asprintf(parent, "%s/%s",
								   CM_DBUS_REQUEST_PATH,
								   entry->cm_busname);
				if ((n_propname > 0) &&
				    (n_propname + 1 < sizeof(propname) / sizeof(propname[0]))) {
					propname[n_propname] = NULL;
					cm_tdbush_property_emit_changed(ctx, new_request_path,
									CM_DBUS_REQUEST_INTERFACE,
									propname);
				}
				cm_tdbusm_set_bp(rep,
						 cm_restart_entry(ctx,
								  entry->cm_nickname),
						 new_request_path);
				dbus_connection_send(conn, rep, NULL);
				dbus_message_unref(rep);
				talloc_free(new_request_path);
				return DBUS_HANDLER_RESULT_HANDLED;
			} else {
				dbus_message_unref(rep);
				rep = dbus_message_new_error(msg,
							     CM_DBUS_ERROR_REQUEST_BAD_ARG,
							     _("Unrecognized parameter or wrong value type."));
				if (rep != NULL) {
					cm_tdbusm_set_s(rep, d[i]->key);
					dbus_connection_send(conn, rep, NULL);
					dbus_message_unref(rep);
					return DBUS_HANDLER_RESULT_HANDLED;
				}
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
		}
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* org.fedorahosted.certmonger.request.resubmit */
static DBusHandlerResult
request_resubmit(DBusConnection *conn, DBusMessage *msg,
		 struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *propname[2];
	char *path;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (cm_stop_entry(ctx, entry->cm_nickname)) {
			/* if we have a key of the right type and size, the
			 * thing to do now is to generate a new CSR, otherwise
			 * we have to generate a new key first */
			if ((entry->cm_key_type.cm_key_size == 0) ||
			    (entry->cm_key_type.cm_key_algorithm != entry->cm_key_type.cm_key_gen_algorithm) ||
			    (entry->cm_key_type.cm_key_size != entry->cm_key_type.cm_key_gen_size)) {
				entry->cm_state = CM_NEED_KEY_PAIR;
			} else {
				entry->cm_state = CM_NEED_CSR;
			}
			/* emit a properties-changed signal for the state */
			propname[0] = CM_DBUS_PROP_STATUS;
			propname[1] = NULL;
			path = talloc_asprintf(entry, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       entry->cm_busname);
			cm_tdbush_property_emit_changed(ctx, path,
							CM_DBUS_REQUEST_INTERFACE,
							propname);
			talloc_free(path);
			if (cm_start_entry(ctx, entry->cm_nickname)) {
				cm_tdbusm_set_b(rep, TRUE);
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
		} else {
			cm_tdbusm_set_b(rep, FALSE);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.refresh */
static DBusHandlerResult
request_refresh(DBusConnection *conn, DBusMessage *msg,
		struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		switch (entry->cm_state) {
		case CM_CA_WORKING:
		case CM_CA_UNREACHABLE:
			if (cm_stop_entry(ctx, entry->cm_nickname)) {
				if (cm_start_entry(ctx, entry->cm_nickname)) {
					cm_tdbusm_set_b(rep, TRUE);
				} else {
					cm_tdbusm_set_b(rep, FALSE);
				}
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
			break;
		default:
			cm_tdbusm_set_b(rep, FALSE);
			break;
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* org.fedorahosted.certmonger.request.rekey */
static DBusHandlerResult
request_rekey(DBusConnection *conn, DBusMessage *msg,
	      struct cm_client_info *ci, struct cm_context *ctx)
{
	DBusMessage *rep;
	struct cm_store_entry *entry;
	const char *propname[2];
	char *path;

	entry = get_entry_for_request_message(msg, ctx);
	if (entry == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		if (cm_stop_entry(ctx, entry->cm_nickname)) {
			/* need a new key pair */
			entry->cm_state = CM_NEED_KEY_PAIR;
			/* emit a properties-changed signal for the state */
			propname[0] = CM_DBUS_PROP_STATUS;
			propname[1] = NULL;
			path = talloc_asprintf(entry, "%s/%s",
					       CM_DBUS_REQUEST_PATH,
					       entry->cm_busname);
			cm_tdbush_property_emit_changed(ctx, path,
							CM_DBUS_REQUEST_INTERFACE,
							propname);
			talloc_free(path);
			if (cm_start_entry(ctx, entry->cm_nickname)) {
				cm_tdbusm_set_b(rep, TRUE);
			} else {
				cm_tdbusm_set_b(rep, FALSE);
			}
		} else {
			cm_tdbusm_set_b(rep, FALSE);
		}
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
		return send_internal_request_error(conn, msg);
	}
}

/* Custom property get/set logic for request structures. */
static dbus_bool_t
request_prop_get_autorenew(struct cm_context *ctx, void *parent,
			   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_autorenew ? TRUE : FALSE;
}

static dbus_bool_t
request_prop_get_monitoring(struct cm_context *ctx, void *parent,
			    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_monitor ? TRUE : FALSE;
}

static const char *
request_prop_get_cert_location_type(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		return "FILE";
		break;
	case cm_cert_storage_nssdb:
		return "NSSDB";
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_file(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_nssdb:
		break;
	case cm_cert_storage_file:
		return entry->cm_cert_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_database(struct cm_context *ctx, void *parent,
					void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_nickname(struct cm_context *ctx, void *parent,
					void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_nickname;
		break;
	}
	return "";
}

static const char *
request_prop_get_cert_location_token(struct cm_context *ctx, void *parent,
				     void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_cert_storage_type) {
	case cm_cert_storage_file:
		break;
	case cm_cert_storage_nssdb:
		return entry->cm_cert_token;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_type(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		return "NONE";
		break;
	case cm_key_storage_file:
		return "FILE";
		break;
	case cm_key_storage_nssdb:
		return "NSSDB";
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_file(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_nssdb:
		break;
	case cm_key_storage_file:
		return entry->cm_key_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_database(struct cm_context *ctx, void *parent,
				       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_storage_location;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_nickname(struct cm_context *ctx, void *parent,
				       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_nickname;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_location_token(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
	case cm_key_storage_file:
		break;
	case cm_key_storage_nssdb:
		return entry->cm_key_token;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_type(struct cm_context *ctx, void *parent,
			  void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		return "";
		break;
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
	}
	return "";
}

static long
request_prop_get_key_size(struct cm_context *ctx, void *parent,
			  void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_unspecified:
		return 0;
		break;
	case cm_key_rsa:
		/* fall through */
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		/* fall through */
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
	case cm_key_ml_dsa_65:
	case cm_key_ml_dsa_87:
		/* fall through */
#endif
		return entry->cm_key_type.cm_key_size;
		break;
	}
	return 0;
}

static const char *
request_prop_get_notification_type(struct cm_context *ctx, void *parent,
				   void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
		return "";
		break;
	case cm_notification_syslog:
		return "SYSLOG";
		break;
	case cm_notification_email:
		return "EMAIL";
		break;
	case cm_notification_stdout:
		return "STDOUT";
		break;
	case cm_notification_command:
		return "COMMAND";
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_syslog(struct cm_context *ctx, void *parent,
				     void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_email:
	case cm_notification_stdout:
	case cm_notification_command:
		return "";
		break;
	case cm_notification_syslog:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_email(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_syslog:
	case cm_notification_stdout:
	case cm_notification_command:
		return "";
		break;
	case cm_notification_email:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_notification_command(struct cm_context *ctx, void *parent,
				      void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	switch (entry->cm_notification_method) {
	case cm_notification_unspecified:
	case cm_notification_none:
	case cm_notification_email:
	case cm_notification_stdout:
	case cm_notification_syslog:
		return "";
		break;
	case cm_notification_command:
		return entry->cm_notification_destination;
		break;
	}
	return "";
}

static const char *
request_prop_get_key_pin(struct cm_context *ctx, void *parent,
			 void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_key_pin ? entry->cm_key_pin : "";
}

static void
request_prop_set_key_pin(struct cm_context *ctx, void *parent,
			 void *record, const char *name, const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_key_pin = maybe_strdup(entry, value);
	if (entry->cm_key_pin != NULL) {
		entry->cm_key_pin_file = NULL;
		properties[0] = CM_DBUS_PROP_KEY_PIN_FILE;
		properties[1] = NULL;
		path = talloc_asprintf(record, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static const char *
request_prop_get_key_pin_file(struct cm_context *ctx, void *parent,
			      void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_key_pin_file ? entry->cm_key_pin_file : "";
}

static void
request_prop_set_key_pin_file(struct cm_context *ctx, void *parent,
			      void *record, const char *name, const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_key_pin_file = maybe_strdup(entry, value);
	if (entry->cm_key_pin_file != NULL) {
		entry->cm_key_pin = NULL;
		properties[0] = CM_DBUS_PROP_KEY_PIN;
		properties[1] = NULL;
		path = talloc_asprintf(record, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static long
request_prop_get_key_issued_count(struct cm_context *ctx, void *parent,
				  void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_key_issued_count;
}

static const char *
request_prop_get_challenge_password(struct cm_context *ctx, void *parent,
				    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_template_challenge_password ?
	       entry->cm_template_challenge_password : "";
}

static void
request_prop_set_challenge_password(struct cm_context *ctx, void *parent,
				    void *record, const char *name,
				    const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_template_challenge_password = maybe_strdup(entry, value);
	if (entry->cm_template_challenge_password != NULL) {
		entry->cm_template_challenge_password_file = NULL;
		properties[0] = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE,
		properties[1] = NULL;
		path = talloc_asprintf(record, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static const char *
request_prop_get_challenge_password_file(struct cm_context *ctx,
					 void *parent,
					 void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_template_challenge_password_file ?
	       entry->cm_template_challenge_password_file : "";
}

static void
request_prop_set_challenge_password_file(struct cm_context *ctx,
					 void *parent,
					 void *record, const char *name,
					 const char *value)
{
	struct cm_store_entry *entry = record;
	const char *properties[2];
	char *path;

	entry->cm_template_challenge_password_file = maybe_strdup(entry, value);
	if (entry->cm_template_challenge_password_file != NULL) {
		entry->cm_template_challenge_password = NULL;
		properties[0] = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD,
		properties[1] = NULL;
		path = talloc_asprintf(record, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		cm_tdbush_property_emit_changed(ctx, path,
						CM_DBUS_REQUEST_INTERFACE,
						properties);
	}
}

static const char *
request_prop_get_status(struct cm_context *ctx, void *parent,
			void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return cm_store_state_as_string(entry->cm_state);
}

static dbus_bool_t
request_prop_get_stuck(struct cm_context *ctx, void *parent,
		       void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	dbus_bool_t stuck = FALSE;
	switch (entry->cm_state) {
	case CM_INVALID:
	case CM_NEED_KEY_PAIR:
	case CM_GENERATING_KEY_PAIR:
	case CM_HAVE_KEY_PAIR:
	case CM_NEED_KEYINFO:
	case CM_READING_KEYINFO:
	case CM_HAVE_KEYINFO:
	case CM_NEED_CSR:
	case CM_GENERATING_CSR:
	case CM_HAVE_CSR:
	case CM_NEED_SCEP_DATA:
	case CM_GENERATING_SCEP_DATA:
	case CM_HAVE_SCEP_DATA:
	case CM_NEED_TO_SUBMIT:
	case CM_SUBMITTING:
	case CM_CA_WORKING:
	case CM_CA_UNREACHABLE:
	case CM_NEED_TO_SAVE_CERT:
	case CM_PRE_SAVE_CERT:
	case CM_START_SAVING_CERT:
	case CM_SAVING_CERT:
	case CM_NEED_TO_READ_CERT:
	case CM_READING_CERT:
	case CM_SAVED_CERT:
	case CM_POST_SAVED_CERT:
	case CM_MONITORING:
	case CM_NEED_TO_NOTIFY_VALIDITY:
	case CM_NOTIFYING_VALIDITY:
	case CM_NEED_TO_NOTIFY_REJECTION:
	case CM_NOTIFYING_REJECTION:
	case CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED:
	case CM_NOTIFYING_ISSUED_SAVE_FAILED:
	case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
	case CM_NOTIFYING_ISSUED_SAVED:
	case CM_NEWLY_ADDED:
	case CM_NEWLY_ADDED_START_READING_KEYINFO:
	case CM_NEWLY_ADDED_READING_KEYINFO:
	case CM_NEWLY_ADDED_START_READING_CERT:
	case CM_NEWLY_ADDED_READING_CERT:
	case CM_NEWLY_ADDED_DECIDING:
	case CM_NEED_TO_SAVE_CA_CERTS:
	case CM_START_SAVING_CA_CERTS:
	case CM_SAVING_CA_CERTS:
	case CM_NEED_TO_SAVE_ONLY_CA_CERTS:
	case CM_START_SAVING_ONLY_CA_CERTS:
	case CM_SAVING_ONLY_CA_CERTS:
	case CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED:
	case CM_NOTIFYING_ONLY_CA_SAVE_FAILED:
	case CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED:
	case CM_NOTIFYING_ISSUED_CA_SAVE_FAILED:
		stuck = FALSE;
		break;
	case CM_NEED_KEYINFO_READ_TOKEN:
	case CM_NEED_KEYINFO_READ_PIN:
	case CM_NEED_KEY_GEN_PERMS:
	case CM_NEED_KEY_GEN_TOKEN:
	case CM_NEED_KEY_GEN_PIN:
	case CM_NEED_CSR_GEN_TOKEN:
	case CM_NEED_CSR_GEN_PIN:
	case CM_NEED_SCEP_GEN_TOKEN:
	case CM_NEED_SCEP_GEN_PIN:
	case CM_NEED_SCEP_ENCRYPTION_CERT:
	case CM_NEED_SCEP_RSA_CLIENT_KEY:
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
	case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
	case CM_NEED_CA_CERT_SAVE_PERMS:
	case CM_NEED_CERTSAVE_PERMS:
	case CM_NEED_CERTSAVE_TOKEN:
	case CM_NEED_CERTSAVE_PIN:
	case CM_NEED_ONLY_CA_CERT_SAVE_PERMS:
	case CM_NEED_GUIDANCE:
	case CM_NEED_CA:
	case CM_CA_REJECTED:
	case CM_CA_UNCONFIGURED:
		stuck = TRUE;
		break;
	}
	return stuck;
}

static const char *
request_prop_get_ca(struct cm_context *ctx, void *parent,
		    void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	struct cm_store_ca *ca;
	if (entry->cm_ca_nickname != NULL) {
		ca = cm_get_ca_by_nickname(ctx, entry->cm_ca_nickname);
		if (ca != NULL) {
			return talloc_asprintf(parent, "%s/%s",
					       CM_DBUS_CA_PATH,
					       ca->cm_busname);
		}
	}
	return "";
}

static dbus_bool_t
request_prop_get_template_is_ca(struct cm_context *ctx, void *parent,
				void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_template_is_ca != 0;
}

static long
request_prop_get_template_ca_path_length(struct cm_context *ctx, void *parent,
					 void *record, const char *name)
{
	struct cm_store_entry *entry = record;
	return entry->cm_template_is_ca != 0 ?
	       entry->cm_template_ca_path_length :
	       -1;
}

/* the types of objects we have in our D-Bus object tree */
enum cm_tdbush_object_type {
	cm_tdbush_object_type_none,
	cm_tdbush_object_type_parent_of_base,
	cm_tdbush_object_type_base,
	cm_tdbush_object_type_parent_of_cas,
	cm_tdbush_object_type_group_of_cas,
	cm_tdbush_object_type_ca,
	cm_tdbush_object_type_parent_of_requests,
	cm_tdbush_object_type_group_of_requests,
	cm_tdbush_object_type_request
};

/* an annotation attached to a method or data field */
struct cm_tdbush_member_annotation {
	const char *cm_name;
	const char *cm_value;
	struct cm_tdbush_member_annotation *cm_next;
};

/* a callable method on an object */
struct cm_tdbush_method {
	const char *cm_name;
	struct cm_tdbush_method_arg {
		const char *cm_name;
		const char *cm_bus_type;
		enum cm_tdbush_method_arg_direction {
			cm_tdbush_method_arg_in,
			cm_tdbush_method_arg_out,
		} cm_direction;
		struct cm_tdbush_method_arg *cm_next;
	} *cm_args;
	struct cm_tdbush_member_annotation *cm_annotations;
	DBusHandlerResult (*cm_fn)(DBusConnection *conn,
				   DBusMessage *msg,
				   struct cm_client_info *ci,
				   struct cm_context *ctx);
};

/* a signal emitted by an object */
struct cm_tdbush_signal {
	const char *cm_name;
	struct cm_tdbush_signal_arg {
		const char *cm_name;
		const char *cm_bus_type;
		struct cm_tdbush_signal_arg *cm_next;
	} *cm_args;
};

/* a data property of an object */
struct cm_tdbush_property {
	const char *cm_name;
	/* what it looks like on the bus */
	enum cm_tdbush_property_bus_type {
		cm_tdbush_property_path,
		cm_tdbush_property_string,
		cm_tdbush_property_strings,
		cm_tdbush_property_string_pairs,
		cm_tdbush_property_boolean,
		cm_tdbush_property_number
	} cm_bus_type;
	enum cm_tdbush_property_access {
		cm_tdbush_property_read,
		cm_tdbush_property_write,
		cm_tdbush_property_readwrite
	} cm_access;
	/* how we represent it internally */
	enum cm_tdbush_property_local_type {
		cm_tdbush_property_special,
		cm_tdbush_property_char_p,
		cm_tdbush_property_char_pp,
		cm_tdbush_property_time_t,
		cm_tdbush_property_long_long,
		cm_tdbush_property_comma_list,
		cm_tdbush_property_mode_t,
	} cm_local_type;
	/* for char_p, char_pp, time_t, long long, comma_list, mode_t members */
	ptrdiff_t cm_offset;
	/* for "special" members */
	const char * (*cm_read_string)(struct cm_context *ctx, void *parent,
				       void *structure, const char *name);
	const char ** (*cm_read_strings)(struct cm_context *ctx, void *parent,
					 void *structure, const char *name);
	const char ** (*cm_read_string_pairs)(struct cm_context *ctx,
					      void *parent, void *structure,
					      const char *name);
	dbus_bool_t (*cm_read_boolean)(struct cm_context *ctx, void *parent,
				       void *structure, const char *name);
	long (*cm_read_number)(struct cm_context *ctx, void *parent,
			       void *structure, const char *name);
	void (*cm_write_string)(struct cm_context *ctx, void *parent,
				void *structure, const char *name,
				const char *new_value);
	void (*cm_write_strings)(struct cm_context *ctx, void *parent,
				 void *structure, const char *name,
				 const char **new_value);
	void (*cm_write_string_pairs)(struct cm_context *ctx, void *parent,
				      void *structure, const char *name,
				      const char **new_value);
	void (*cm_write_boolean)(struct cm_context *ctx, void *parent,
				 void *structure, const char *name,
				 dbus_bool_t new_value);
	void (*cm_write_number)(struct cm_context *ctx, void *parent,
				void *structure, const char *name,
				long new_value);
	struct cm_tdbush_member_annotation *cm_annotations;
};

/* methods, signals, and members are grouped by interface name */
struct cm_tdbush_interface {
	const char *cm_name;
	struct cm_tdbush_interface_item {
		enum cm_tdbush_interface_member_type {
			cm_tdbush_interface_method,
			cm_tdbush_interface_signal,
			cm_tdbush_interface_property,
		} cm_member_type;
		struct cm_tdbush_method *cm_method;
		struct cm_tdbush_signal *cm_signal;
		struct cm_tdbush_property *cm_property;
		struct cm_tdbush_interface_item *cm_next;
	} *cm_items;
};

/* a mapping from an object type to an interface that applies to it */
struct cm_tdbush_interface_map {
	enum cm_tdbush_object_type cm_type;
	struct cm_tdbush_interface * (*cm_interface)(void);
};
static enum cm_tdbush_object_type cm_tdbush_classify_path(struct cm_context *ctx,
							  const char *path);
static struct cm_tdbush_interface_map *cm_tdbush_object_type_map_get_n(unsigned int i);

static struct cm_tdbush_method_arg *
make_method_arg(const char *name,
		const char *bus_type,
		enum cm_tdbush_method_arg_direction direction,
		struct cm_tdbush_method_arg *next)
{
	struct cm_tdbush_method_arg *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_direction = direction;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_member_annotation *
make_member_annotation(const char *name,
		       const char *value,
		       struct cm_tdbush_member_annotation *next)
{
	struct cm_tdbush_member_annotation *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_value = value;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_method *
make_method(const char *name,
	    DBusHandlerResult (*fn)(DBusConnection *conn,
				    DBusMessage *msg,
				    struct cm_client_info *ci,
				    struct cm_context *ctx),
	    struct cm_tdbush_method_arg *args,
	    struct cm_tdbush_member_annotation *annotations)
{
	struct cm_tdbush_method *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_fn = fn;
	ret->cm_args = args;
	ret->cm_annotations = annotations;
	return ret;
}

static struct cm_tdbush_signal_arg *
make_signal_arg(const char *name,
		const char *bus_type,
		struct cm_tdbush_signal_arg *next)
{
	struct cm_tdbush_signal_arg *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_signal *
make_signal(const char *name, struct cm_tdbush_signal_arg *args)
{
	struct cm_tdbush_signal *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_args = args;
	return ret;
}

static struct cm_tdbush_property *
make_property(const char *name,
	      enum cm_tdbush_property_bus_type bus_type,
	      enum cm_tdbush_property_access acces,
	      enum cm_tdbush_property_local_type local_type,
	      ptrdiff_t offset,
	      const char * (*read_string)(struct cm_context *ctx, void *parent,
					  void *structure, const char *name),
	      const char ** (*read_strings)(struct cm_context *ctx,
					    void *parent,
					    void *structure,
					    const char *name),
	      const char ** (*read_string_pairs)(struct cm_context *ctx,
						 void *parent,
						 void *structure,
						 const char *name),
	      dbus_bool_t (*read_boolean)(struct cm_context *ctx, void *parent,
					  void *structure, const char *name),
	      long (*read_number)(struct cm_context *ctx, void *parent,
				  void *structure, const char *name),
	      void (*write_string)(struct cm_context *ctx, void *parent,
				   void *structure, const char *name,
				   const char *new_value),
	      void (*write_strings)(struct cm_context *ctx, void *parent,
				    void *structure, const char *name,
				    const char **new_values),
	      void (*write_string_pairs)(struct cm_context *ctx, void *parent,
					 void *structure, const char *name,
					 const char **new_values),
	      void (*write_boolean)(struct cm_context *ctx, void *parent,
				    void *structure, const char *name,
				    dbus_bool_t),
	      void (*write_number)(struct cm_context *ctx, void *parent,
				   void *structure, const char *name,
				   long new_value),
	      struct cm_tdbush_member_annotation *annotations)
{
	struct cm_tdbush_property *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_bus_type = bus_type;
	ret->cm_access = acces;
	ret->cm_local_type = local_type;
	ret->cm_offset = offset;
	ret->cm_read_string = read_string;
	ret->cm_read_strings = read_strings;
	ret->cm_read_string_pairs = read_string_pairs;
	ret->cm_read_number = read_number;
	ret->cm_read_boolean = read_boolean;
	ret->cm_write_string = write_string;
	ret->cm_write_strings = write_strings;
	ret->cm_write_string_pairs = write_string_pairs;
	ret->cm_write_number = write_number;
	ret->cm_write_boolean = write_boolean;
	ret->cm_annotations = annotations;
	switch (ret->cm_local_type) {
	case cm_tdbush_property_char_p:
	case cm_tdbush_property_char_pp:
	case cm_tdbush_property_time_t:
	case cm_tdbush_property_long_long:
	case cm_tdbush_property_comma_list:
	case cm_tdbush_property_mode_t:
		assert(ret->cm_offset != 0);
		break;
	case cm_tdbush_property_special:
		assert(ret->cm_offset == 0);
		if ((ret->cm_access == cm_tdbush_property_read) ||
		    (ret->cm_access == cm_tdbush_property_readwrite)) {
			switch (ret->cm_bus_type) {
			case cm_tdbush_property_path:
			case cm_tdbush_property_string:
				assert(ret->cm_read_string != NULL);
				break;
			case cm_tdbush_property_strings:
				assert(ret->cm_read_strings != NULL);
				break;
			case cm_tdbush_property_string_pairs:
				assert(ret->cm_read_string_pairs != NULL);
				break;
			case cm_tdbush_property_boolean:
				assert(ret->cm_read_boolean != NULL);
				break;
			case cm_tdbush_property_number:
				assert(ret->cm_read_number != NULL);
				break;
			}
		}
		if ((ret->cm_access == cm_tdbush_property_readwrite) ||
		    (ret->cm_access == cm_tdbush_property_write)) {
			switch (ret->cm_bus_type) {
			case cm_tdbush_property_path:
			case cm_tdbush_property_string:
				assert(ret->cm_write_string != NULL);
				break;
			case cm_tdbush_property_strings:
				assert(ret->cm_write_strings != NULL);
				break;
			case cm_tdbush_property_string_pairs:
				assert(ret->cm_write_string_pairs != NULL);
				break;
			case cm_tdbush_property_boolean:
				assert(ret->cm_write_boolean != NULL);
				break;
			case cm_tdbush_property_number:
				assert(ret->cm_write_number != NULL);
				break;
			}
		}
		break;
	}
	return ret;
}

static struct cm_tdbush_interface_item *
make_interface_item(enum cm_tdbush_interface_member_type member_type,
		    void *ptr,
		    struct cm_tdbush_interface_item *next)
{
	struct cm_tdbush_interface_item *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_member_type = member_type;
	switch (ret->cm_member_type) {
	case cm_tdbush_interface_method:
		ret->cm_method = ptr;
		break;
	case cm_tdbush_interface_signal:
		ret->cm_signal = ptr;
		break;
	case cm_tdbush_interface_property:
		ret->cm_property = ptr;
		break;
	}
	ret->cm_next = next;
	return ret;
}

static struct cm_tdbush_interface *
make_interface(const char *name,
	       struct cm_tdbush_interface_item *items)
{
	struct cm_tdbush_interface *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->cm_name = name;
	ret->cm_items = items;
	return ret;
}

/* introspection callbacks for specific parts of an interface */
static char *
cm_tdbush_introspect_method(void *parent,
			    struct cm_tdbush_method *method)
{
	char *ret = NULL;
	const char *direction;
	struct cm_tdbush_method_arg *arg;
	struct cm_tdbush_member_annotation *annotation;

	ret = talloc_asprintf(parent, "  <method name=\"%s\">",
			      method->cm_name);
	arg = method->cm_args;
	while (arg != NULL) {
		switch (arg->cm_direction) {
		case cm_tdbush_method_arg_in:
			direction = "in";
			break;
		case cm_tdbush_method_arg_out:
			direction = "out";
			break;
		default:
			direction = "unknown";
			break;
		}
		ret = talloc_asprintf(parent,
				      "%s\n   <arg name=\"%s\" type=\"%s\" "
				      "direction=\"%s\"/>",
				      ret,
				      arg->cm_name, arg->cm_bus_type,
				      direction);
		arg = arg->cm_next;
	}
	annotation = method->cm_annotations;
	while (annotation != NULL) {
		ret = talloc_asprintf(parent,
				      "%s\n   <annotation name=\"%s\" "
				      "value=\"%s\"/>",
				      ret,
				      annotation->cm_name,
				      annotation->cm_value);
		annotation = annotation->cm_next;
	}
	ret = talloc_asprintf(parent, "%s\n  </method>", ret);
	return ret;
}

static char *
cm_tdbush_introspect_signal(void *parent,
			    struct cm_tdbush_signal *sig)
{
	char *ret = NULL;
	struct cm_tdbush_signal_arg *arg;

	ret = talloc_asprintf(parent, "  <signal name=\"%s\">",
			      sig->cm_name);
	arg = sig->cm_args;
	while (arg != NULL) {
		ret = talloc_asprintf(parent,
				      "%s\n   <arg name=\"%s\" type=\"%s\"/>",
				      ret, arg->cm_name, arg->cm_bus_type);
		arg = arg->cm_next;
	}
	ret = talloc_asprintf(parent, "%s\n  </signal>", ret);
	return ret;
}

static char *
cm_tdbush_introspect_property(void *parent,
			      struct cm_tdbush_property *prop)
{
	char *ret = NULL;
	const char *bus_type = "unknown", *access_type = "unknown";
	struct cm_tdbush_member_annotation *annotation;

	switch (prop->cm_bus_type) {
	case cm_tdbush_property_path:
		bus_type = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	case cm_tdbush_property_string:
		bus_type = DBUS_TYPE_STRING_AS_STRING;
		break;
	case cm_tdbush_property_strings:
		bus_type = DBUS_TYPE_ARRAY_AS_STRING
			   DBUS_TYPE_STRING_AS_STRING;
		break;
	case cm_tdbush_property_string_pairs:
		bus_type = DBUS_TYPE_ARRAY_AS_STRING
			   DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			   DBUS_TYPE_STRING_AS_STRING
			   DBUS_TYPE_STRING_AS_STRING
			   DBUS_STRUCT_END_CHAR_AS_STRING;
		break;
	case cm_tdbush_property_boolean:
		bus_type = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case cm_tdbush_property_number:
		bus_type = DBUS_TYPE_INT64_AS_STRING;
		break;
	}
	switch (prop->cm_access) {
	case cm_tdbush_property_read:
		access_type = "read";
		break;
	case cm_tdbush_property_write:
		access_type = "write";
		break;
	case cm_tdbush_property_readwrite:
		access_type = "readwrite";
		break;
	}
	annotation = prop->cm_annotations;
	if (annotation == NULL) {
		ret = talloc_asprintf(parent,
				      "  <property name=\"%s\" "
				      "type=\"%s\" access=\"%s\"/>",
				      prop->cm_name, bus_type, access_type);
	} else {
		ret = talloc_asprintf(parent,
				      "  <property name=\"%s\" "
				      "type=\"%s\" access=\"%s\">",
				      prop->cm_name, bus_type, access_type);
		while (annotation != NULL) {
			ret = talloc_asprintf(parent,
					      "%s\n   <annotation name=\"%s\" "
					      "value=\"%s\"/>",
					      ret,
					      annotation->cm_name,
					      annotation->cm_value);
			annotation = annotation->cm_next;
		}
		ret = talloc_asprintf(parent, "%s\n  </property>", ret);
	}
	return ret;
}

/* when we're introspecting a node, we need to return a list of its direct
 * children as part of that node's data */
static char *
cm_tdbush_introspect_childlist(struct cm_context *ctx, void *parent,
			       const char *path,
			       enum cm_tdbush_object_type type)
{
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *ret = NULL;
	const char *p;
	int i;

	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_request:
	case cm_tdbush_object_type_ca:
		/* these have no child nodes */
		break;
	case cm_tdbush_object_type_parent_of_base:
		/* the next intermediate node in the base object's path */
		p = CM_DBUS_BASE_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_base:
		/* the base itself is a parent of the groups of other objects,
		 * so include the next nodes in those paths */
		p = CM_DBUS_REQUEST_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		p = CM_DBUS_CA_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "%s\n <node name=\"%.*s\"/>",
				      ret, i, p);
		break;
	case cm_tdbush_object_type_parent_of_cas:
		/* a child of the base node that is not the immediate parent of
		 * the CAs */
		p = CM_DBUS_CA_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_group_of_cas:
		/* a child of the base node that is the immediate parent of the
		 * CAs */
		i = cm_get_n_cas(ctx) - 1;
		while (i >= 0) {
			ca = cm_get_ca_by_index(ctx, i);
			if (ca != NULL) {
				ret = talloc_asprintf(parent,
						      "\n <node name=\"%s\"/>%s",
						      ca->cm_busname,
						      ret ? ret : "");
			}
			i--;
		}
		break;
	case cm_tdbush_object_type_parent_of_requests:
		/* a child of the base node that is not the immediate parent of
		 * the requests */
		p = CM_DBUS_REQUEST_PATH + strlen(path);
		p += strspn(p, "/");
		i = strcspn(p, "/");
		ret = talloc_asprintf(parent, "\n <node name=\"%.*s\"/>", i, p);
		break;
	case cm_tdbush_object_type_group_of_requests:
		/* a child of the base node that is the immediate parent of the
		 * requests */
		i = cm_get_n_entries(ctx) - 1;
		while (i >= 0) {
			entry = cm_get_entry_by_index(ctx, i);
			if (entry != NULL) {
				ret = talloc_asprintf(parent,
						      "\n <node name=\"%s\"/>%s",
						      entry->cm_busname,
						      ret ? ret : "");
			}
			i--;
		}
		break;
	}
	return ret;
}

/* org.freedesktop.DBus.Introspectable.Introspect */
static DBusHandlerResult
cm_tdbush_introspect(DBusConnection *conn,
		     DBusMessage *msg,
		     struct cm_client_info *ci,
		     struct cm_context *ctx)
{
	const char *path;
	void *parent;
	char *xml, *member;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	enum cm_tdbush_object_type type;
	unsigned int i;
	DBusMessage *rep;

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);
	parent = talloc_new(NULL);
	xml = talloc_asprintf(parent, "%s\n<node name=\"%s\">",
			      DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE,
			      path);
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		xml = talloc_asprintf(parent, "%s\n <interface name=\"%s\">",
				      xml, iface->cm_name);
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			member = NULL;
			switch (item->cm_member_type) {
			case cm_tdbush_interface_method:
				member = cm_tdbush_introspect_method(parent,
								     item->cm_method);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			case cm_tdbush_interface_signal:
				member = cm_tdbush_introspect_signal(parent,
								     item->cm_signal);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			case cm_tdbush_interface_property:
				member = cm_tdbush_introspect_property(parent,
								       item->cm_property);
				if (member != NULL) {
					xml = talloc_asprintf(parent, "%s\n%s",
							      xml, member);
				}
				break;
			}
		}
		xml = talloc_asprintf(parent, "%s\n </interface>", xml);
	}
	member = cm_tdbush_introspect_childlist(ctx, parent, path, type);
	if (member != NULL) {
		xml = talloc_asprintf(parent, "%s%s", xml, member);
	}
	xml = talloc_asprintf(parent, "%s\n</node>", xml);
	rep = dbus_message_new_method_return(msg);
	if (rep != NULL) {
		cm_tdbusm_set_s(rep, xml);
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(parent);
	return DBUS_HANDLER_RESULT_HANDLED;

}

/* Loose name matching: consider '-' and '_' equivalent, and consider either
 * followed by a lower-case character to be equivalent to just that character
 * in upper case. */
static int
cm_is_lower(char c)
{
	return (c >= 'a') && (c <= 'z');
}
static int
cm_is_upper(char c)
{
	return (c >= 'A') && (c <= 'Z');
}
static char
cm_to_upper(char c)
{
	return c - ('a' - 'A');
}
int
cm_name_cmp(const char *a, const char *b)
{
	const char *p, *q;

	if (strcmp(a, b) == 0) {
		return 0;
	}
	p = a;
	q = b;
	while ((*p != '\0') && (*q != '\0')) {
		if (*p == *q) {
			p++;
			q++;
			continue;
		}
		if (((*p == '-') && (*q == '_')) ||
		    ((*p == '_') && (*q == '-'))) {
			p++;
			q++;
			continue;
		}
		if ((p == a) && (q == b)) {
			if (cm_is_lower(*p) && cm_is_upper(*q) &&
			    (cm_to_upper(*p) == *q)) {
				p++;
				q++;
				continue;
			}
			if (cm_is_lower(*q) && cm_is_upper(*p) &&
			    (cm_to_upper(*q) == *p)) {
				p++;
				q++;
				continue;
			}
		}
		if ((*p == '-') || (*p == '_')) {
			if (cm_is_lower(*(p + 1)) && cm_is_upper(*q) &&
			    (cm_to_upper(*(p + 1)) == *q)) {
				p += 2;
				q++;
				continue;
			}
		}
		if ((*q == '-') || (*q == '_')) {
			if (cm_is_lower(*(q + 1)) && cm_is_upper(*p) &&
			    (cm_to_upper(*(q + 1)) == *p)) {
				p++;
				q += 2;
				continue;
			}
		}
		return *p - *q;
	}
	return *p - *q;
}

/* org.freedesktop.DBus.Properties.Get */
static DBusHandlerResult
cm_tdbush_property_get(DBusConnection *conn,
		       DBusMessage *msg,
		       struct cm_client_info *ci,
		       struct cm_context *ctx)
{
	const char *path;
	char *interface, *property;
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *record, **wpp, ***wppp;
	const char *p, **pp;
	dbus_bool_t b;
	long l;
	long long *llp;
	time_t *tp;
	mode_t *mp;
	enum cm_tdbusm_dict_value_type value_type;
	union cm_tdbusm_variant value;
	DBusMessage *rep;

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ss(msg, parent, &interface, &property) != 0) {

		if (errno == ENOMEM) {
			cm_log(0, "Out of memory.\n");
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}

		cm_log(1, "Error parsing arguments.\n");
		rep = dbus_message_new_error(msg,
					     CM_DBUS_ERROR_REQUEST_BAD_ARG,
					     _("Error parsing arguments."));
		if (rep != NULL) {
			cm_tdbusm_set_s(rep, property);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Locate the property. */
	item = NULL;
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (cm_name_cmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			if ((property != NULL) &&
			    (cm_name_cmp(property, prop->cm_name) != 0)) {
				continue;
			}
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
			case cm_tdbush_property_readwrite:
				break;
			case cm_tdbush_property_write:
				/* not allowed! should we return an error? */
				continue;
				break;
			}
			break;
		}
		if (item != NULL) {
			break;
		}
	}
	if (item == NULL) {
		rep = dbus_message_new_error(msg,
					     CM_DBUS_ERROR_REQUEST_BAD_ARG,
					     _("Unrecognized property name."));
		if (rep != NULL) {
			cm_tdbusm_set_s(rep, property);
			dbus_connection_send(conn, rep, NULL);
			dbus_message_unref(rep);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	prop = item->cm_property;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Read the property data and set it as an argument. */
	memset(&value, 0, sizeof(value));
	switch (prop->cm_local_type) {
	case cm_tdbush_property_char_p:
		record += prop->cm_offset;
		wpp = (char **) record;
		value.s = *wpp;
		break;
	case cm_tdbush_property_char_pp:
		record += prop->cm_offset;
		wppp = (char ***) record;
		value.as = *wppp;
		value.ass = *wppp;
		break;
	case cm_tdbush_property_time_t:
		record += prop->cm_offset;
		tp = (time_t *) record;
		value.n = *tp;
		break;
	case cm_tdbush_property_long_long:
		record += prop->cm_offset;
		llp = (long long *) record;
		value.n = *llp;
		break;
	case cm_tdbush_property_comma_list:
		record += prop->cm_offset;
		pp = (const char **) record;
		wpp = eku_splitv(record - prop->cm_offset, *pp);
		if (wpp != NULL) {
			value.as = wpp;
		}
		break;
	case cm_tdbush_property_mode_t:
		record += prop->cm_offset;
		mp = (mode_t *) record;
		value.n = *mp;
		break;
	case cm_tdbush_property_special:
		switch (prop->cm_bus_type) {
		case cm_tdbush_property_path:
			p = (*(prop->cm_read_string))(ctx, parent,
						      record, property);
			value.s = (char *) p;
			break;
		case cm_tdbush_property_string:
			p = (*(prop->cm_read_string))(ctx, parent,
						      record, property);
			value.s = (char *) p;
			break;
		case cm_tdbush_property_strings:
			pp = (*(prop->cm_read_strings))(ctx, parent,
							record, property);
			value.as = (char **) pp;
			break;
		case cm_tdbush_property_string_pairs:
			pp = (*(prop->cm_read_string_pairs))(ctx, parent,
							     record, property);
			value.ass = (char **) pp;
			break;
		case cm_tdbush_property_boolean:
			b = (*(prop->cm_read_boolean))(ctx, parent,
						       record, property);
			value.b = b;
			break;
		case cm_tdbush_property_number:
			l = (*(prop->cm_read_number))(ctx, parent,
						      record, property);
			value.n = l;
			break;
		}
		break;
	}
	switch (prop->cm_bus_type) {
	case cm_tdbush_property_path:
		value_type = cm_tdbusm_dict_p;
		if ((value.s != NULL) && (strlen(value.s) > 0)) {
			cm_tdbusm_set_v(rep, value_type, &value);
		}
		break;
	case cm_tdbush_property_string:
		value_type = cm_tdbusm_dict_s;
		if (value.s != NULL) {
			cm_tdbusm_set_v(rep, value_type, &value);
		}
		break;
	case cm_tdbush_property_strings:
		value_type = cm_tdbusm_dict_as;
		cm_tdbusm_set_v(rep, value_type, &value);
		break;
	case cm_tdbush_property_string_pairs:
		value_type = cm_tdbusm_dict_ass;
		cm_tdbusm_set_v(rep, value_type, &value);
		break;
	case cm_tdbush_property_boolean:
		value_type = cm_tdbusm_dict_b;
		cm_tdbusm_set_v(rep, value_type, &value);
		break;
	case cm_tdbush_property_number:
		value_type = cm_tdbusm_dict_n;
		cm_tdbusm_set_v(rep, value_type, &value);
		break;
	}
	if (rep != NULL) {
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}
	talloc_free(parent);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* org.freedesktop.DBus.Properties.Set */
static DBusHandlerResult
cm_tdbush_property_set(DBusConnection *conn,
		       DBusMessage *msg,
		       struct cm_client_info *ci,
		       struct cm_context *ctx)
{
	const char *path;
	char *interface, *property;
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i;
	struct cm_store_entry *entry = NULL;
	struct cm_store_ca *ca = NULL;
	char *record, *wp, **wpp, ***wppp;
	time_t *tp;
	long long *llp;
	mode_t *mp;
	DBusMessage *rep;
	const char *properties[2];
	enum cm_tdbusm_dict_value_type value_type;
	union cm_tdbusm_variant v;

	path = dbus_message_get_path(msg);
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	parent = talloc_new(NULL);
	if (cm_tdbusm_get_ssv(msg, parent, &interface, &property,
			      &value_type, &v) != 0) {

		if (errno == ENOMEM) {
			cm_log(0, "Out of memory.\n");
			talloc_free(parent);
			return send_internal_base_error(conn, msg);
		}

		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Locate the property. */
	item = NULL;
	for (i = 0; (map = cm_tdbush_object_type_map_get_n(i)) != NULL; i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (cm_name_cmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			if ((property != NULL) &&
			    (cm_name_cmp(property, prop->cm_name) != 0)) {
				continue;
			}
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
				/* not allowed! should we return an error? */
				continue;
				break;
			case cm_tdbush_property_readwrite:
			case cm_tdbush_property_write:
				break;
			}
			break;
		}
		if (item != NULL) {
			break;
		}
	}
	if (item == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	prop = item->cm_property;

	rep = dbus_message_new_method_return(msg);
	if (rep == NULL) {
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Set the property. */
	switch (prop->cm_local_type) {
	case cm_tdbush_property_char_p:
		if (value_type == cm_tdbusm_dict_invalid) {
			v.s = NULL;
		} else
		if ((value_type != cm_tdbusm_dict_s) &&
		    (value_type != cm_tdbusm_dict_p)) {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		wpp = (char **) record;
		*wpp = maybe_strdup(record - prop->cm_offset, v.s);
		break;
	case cm_tdbush_property_char_pp:
		if (value_type == cm_tdbusm_dict_invalid) {
			wpp = NULL;
		} else
		if (value_type == cm_tdbusm_dict_as) {
			wpp = v.as;
		} else
		if (value_type == cm_tdbusm_dict_ass) {
			wpp = v.ass;
		} else {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		wppp = (char ***) record;
		*wppp = maybe_strdupv(record - prop->cm_offset, wpp);
		break;
	case cm_tdbush_property_time_t:
		if (value_type == cm_tdbusm_dict_invalid) {
			v.n = 0;
		} else
		if (value_type != cm_tdbusm_dict_n) {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		tp = (time_t *) record;
		*tp = v.n;
		break;
	case cm_tdbush_property_long_long:
		if (value_type == cm_tdbusm_dict_invalid) {
			v.n = 0;
		} else
		if (value_type != cm_tdbusm_dict_n) {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		llp = (long long *) record;
		*llp = v.n;
		break;
	case cm_tdbush_property_comma_list:
		if (value_type == cm_tdbusm_dict_invalid) {
			v.as = NULL;
		} else
		if (value_type != cm_tdbusm_dict_as) {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		wp = cm_submit_maybe_joinv(record, ",", v.as);
		record += prop->cm_offset;
		wpp = (char **) record;
		*wpp = maybe_strdup(record - prop->cm_offset, wp);
		break;
	case cm_tdbush_property_mode_t:
		if (value_type == cm_tdbusm_dict_invalid) {
			v.n = 0;
		} else
		if (value_type != cm_tdbusm_dict_n) {
			cm_log(1, "Error: arguments type mismatch.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record += prop->cm_offset;
		mp = (mode_t *) record;
		*mp = v.n;
		break;
	case cm_tdbush_property_special:
		switch (prop->cm_bus_type) {
		case cm_tdbush_property_path:
		case cm_tdbush_property_string:
			if (value_type == cm_tdbusm_dict_invalid) {
				v.s = NULL;
			} else
			if ((value_type != cm_tdbusm_dict_s) &&
			    (value_type != cm_tdbusm_dict_p)) {
				cm_log(1, "Error: arguments type mismatch.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_string))(ctx, parent,
						   record, property, v.s);
			break;
		case cm_tdbush_property_strings:
			if (value_type == cm_tdbusm_dict_invalid) {
				v.as = NULL;
			} else
			if (value_type != cm_tdbusm_dict_as) {
				cm_log(1, "Error: arguments type mismatch.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_strings))(ctx, parent,
						    record, property,
						    (const char **) v.as);
			break;
		case cm_tdbush_property_string_pairs:
			if (value_type == cm_tdbusm_dict_invalid) {
				v.ass = NULL;
			} else
			if (value_type != cm_tdbusm_dict_ass) {
				cm_log(1, "Error: arguments type mismatch.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_string_pairs))(ctx, parent,
							 record, property,
							 (const char **) v.ass);
			break;
		case cm_tdbush_property_boolean:
			if (value_type == cm_tdbusm_dict_invalid) {
				v.b = FALSE;
			} else
			if (value_type != cm_tdbusm_dict_b) {
				cm_log(1, "Error: arguments type mismatch.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_boolean))(ctx, parent,
						    record, property, v.b);
			break;
		case cm_tdbush_property_number:
			if (value_type == cm_tdbusm_dict_invalid) {
				v.n = 0;
			} else
			if (value_type != cm_tdbusm_dict_n) {
				cm_log(1, "Error: arguments type mismatch.\n");
				talloc_free(parent);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			(*(prop->cm_write_number))(ctx, parent,
						   record, property, v.n);
			break;
		}
		break;
	}
	if (rep != NULL) {
		dbus_connection_send(conn, rep, NULL);
		dbus_message_unref(rep);
	}

	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		/* Not reached, since we returned on these earlier. */
		break;
	case cm_tdbush_object_type_base:
		break;
	case cm_tdbush_object_type_ca:
		cm_store_ca_save(ca);
		break;
	case cm_tdbush_object_type_request:
		cm_store_entry_save(entry);
		break;
	}

	properties[0] = prop->cm_name;
	properties[1] = NULL;
	cm_tdbush_property_emit_changed(ctx, path, interface, properties);

	talloc_free(parent);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* compare arrays of strings for having the same set of unique members */
static int
compare_strv(const char **a, const char **b)
{
	int m, n, i, j;
	if ((a == NULL) && (b == NULL)) {
		return 0;
	}
	for (m = 0; (a != NULL) && (a[m] != NULL); m++) {
		continue;
	}
	for (n = 0; (b != NULL) && (b[n] != NULL); n++) {
		continue;
	}
	if (m != n) {
		return -1;
	}
	for (i = 0; i < m; i++) {
		for (j = 0; j < n; j++) {
			if (strcmp(a[i], b[j]) == 0) {
				break;
			}
		}
		if (b[j] == NULL) {
			return -1;
		}
	}
	return 0;
}

/* do the heavy lifting for two cases:
 * org.freedesktop.DBus.Properties.GetAll method (old_record is NULL)
 * org.freedesktop.DBus.Properties.PropertiesChanged signal (old_record is not NULL) */
static DBusHandlerResult
cm_tdbush_property_get_all_or_changed(struct cm_context *ctx,
				      DBusConnection *conn,
				      DBusMessage *req,
				      const char *path,
				      const char *interface,
				      char *old_record,
				      const char **properties)
{
	void *parent;
	static struct cm_tdbush_interface_map *map;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_property *prop;
	enum cm_tdbush_object_type type;
	unsigned int i, j;
	struct cm_store_entry *entry;
	struct cm_store_ca *ca;
	char *record, *rec, *old_rec, **wpp, *ifacetmp;
	const char *p, **pp, ***ppp, **old_pp, *old_p, ***old_ppp;
	time_t *tp, *old_tp;
	dbus_bool_t b, old_b;
	long l, old_l;
	long long *llp, *old_llp;
	mode_t *mp, *old_mp;
	DBusMessage *rep;
	const struct cm_tdbusm_dict **d;
	struct cm_tdbusm_dict *dict, **dtmp;
	int n, m, n_dictvals = 0;

	/* If this is the method call, pull the path and interface from it.
	 * Either way, we need to be sure we have them. */
	parent = talloc_new(NULL);
	if (req != NULL) {
		path = dbus_message_get_path(req);
		if (cm_tdbusm_get_s(req, parent, &ifacetmp) != 0) {
			cm_log(1, "Error parsing arguments.\n");
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		interface = ifacetmp;
	}
	if (path == NULL) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	if (interface == NULL) {
		cm_log(1, "Error parsing arguments.\n");
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	type = cm_tdbush_classify_path(ctx, path);

	/* Get a pointer to the record. */
	record = NULL;
	switch (type) {
	case cm_tdbush_object_type_none:
	case cm_tdbush_object_type_parent_of_base:
	case cm_tdbush_object_type_parent_of_requests:
	case cm_tdbush_object_type_parent_of_cas:
	case cm_tdbush_object_type_group_of_requests:
	case cm_tdbush_object_type_group_of_cas:
		cm_log(1, "No properties on (%s).\n", path);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		break;
	case cm_tdbush_object_type_base:
		/* no object */
		record = NULL;
		break;
	case cm_tdbush_object_type_ca:
		ca = get_ca_for_path(ctx, path);
		if (ca == NULL) {
			cm_log(1, "No such CA (%s).\n", path);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) ca;
		break;
	case cm_tdbush_object_type_request:
		entry = get_entry_for_path(ctx, path);
		if (entry == NULL) {
			cm_log(1, "No such request (%s).\n", path);
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		record = (char *) entry;
		break;
	}
	if ((record == NULL) && (type != cm_tdbush_object_type_base)) {
		cm_log(1, "No properties on (%s).\n", path);
		talloc_free(parent);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Create the message we're sending. */
	if (req != NULL) {
		/* GetAll method reply. */
		rep = dbus_message_new_method_return(req);
		if (rep == NULL) {
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	} else {
		/* PropertiesChanged signal. */
		rep = dbus_message_new_signal(path,
					      DBUS_INTERFACE_PROPERTIES,
					      "PropertiesChanged");
		if (rep == NULL) {
			talloc_free(parent);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
	}

	/* Examine all properties. */
	item = NULL;
	n_dictvals = 0;
	dict = NULL;
	d = NULL;
	for (i = 0, n = 0;
	     (map = cm_tdbush_object_type_map_get_n(i)) != NULL;
	     i++) {
		if (map->cm_type != type) {
			continue;
		}
		iface = (*(map->cm_interface))();
		if ((interface != NULL) &&
		    (strlen(interface) > 0) &&
		    (cm_name_cmp(interface, iface->cm_name) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type !=
			    cm_tdbush_interface_property) {
				continue;
			}
			prop = item->cm_property;
			switch (prop->cm_access) {
			case cm_tdbush_property_read:
			case cm_tdbush_property_readwrite:
				break;
			case cm_tdbush_property_write:
				/* nope! */
				continue;
				break;
			}
			if (properties != NULL) {
				/* skip this property if we have a list of
				 * properties to list and this one's not
				 * included */
				for (j = 0; properties[j] != NULL; j++) {
					if (cm_name_cmp(properties[j],
							  prop->cm_name) == 0) {
						break;
					}
				}
				if (properties[j] == NULL) {
					continue;
				}
			}
			/* Resize the result dictionary if we need to. */
			if (n + 1 >= n_dictvals) {
				dict = talloc_realloc(parent, dict, struct cm_tdbusm_dict, n_dictvals + 32);
				if (dict == NULL) {
					cm_log(1, "Out of memory.\n");
					talloc_free(parent);
					return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
				}
				dtmp = talloc_realloc(parent, d, struct cm_tdbusm_dict *, n_dictvals + 33);
				d = (const struct cm_tdbusm_dict **) dtmp;
				if (d == NULL) {
					cm_log(1, "Out of memory.\n");
					talloc_free(parent);
					return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
				}
				for (m = 0; m < n; m++) {
					d[m] = &dict[m];
				}
				d[n] = NULL;
				n_dictvals += 32;
			}
			/* Read the property data and add it to the dict. */
			dict[n].key = talloc_strdup(parent, prop->cm_name);
			switch (prop->cm_bus_type) {
			case cm_tdbush_property_path:
				dict[n].value_type = cm_tdbusm_dict_p;
				break;
			case cm_tdbush_property_string:
				dict[n].value_type = cm_tdbusm_dict_s;
				break;
			case cm_tdbush_property_strings:
				dict[n].value_type = cm_tdbusm_dict_as;
				break;
			case cm_tdbush_property_string_pairs:
				dict[n].value_type = cm_tdbusm_dict_ass;
				break;
			case cm_tdbush_property_boolean:
				dict[n].value_type = cm_tdbusm_dict_b;
				break;
			case cm_tdbush_property_number:
				dict[n].value_type = cm_tdbusm_dict_n;
				break;
			}
			switch (prop->cm_local_type) {
			case cm_tdbush_property_char_p:
				rec = record + prop->cm_offset;
				pp = (const char **) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_pp = (const char **) old_rec;
					if ((*pp == NULL) &&
					    (*old_pp == NULL)) {
						continue;
					}
					if ((*pp != NULL) &&
					    (*old_pp != NULL) &&
					    (strcmp(*pp, *old_pp) == 0)) {
						continue;
					}
				}
				if ((pp != NULL) && (*pp != NULL)) {
					dict[n].value.s = (char *) *pp;
					if ((dict[n].value.s == NULL) ||
					    (strlen(dict[n].value.s) == 0)) {
						if (prop->cm_bus_type == cm_tdbush_property_path) {
							continue;
						}
						if (prop->cm_bus_type == cm_tdbush_property_string) {
							dict[n].value.s = "";
						}
					}
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_char_pp:
				rec = record + prop->cm_offset;
				ppp = (const char ***) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_ppp = (const char ***) old_rec;
					if (compare_strv(*old_ppp, *ppp) == 0) {
						continue;
					}
				}
				if ((ppp != NULL) && (*ppp != NULL)) {
					dict[n].value.as = (char **) *ppp;
					dict[n].value.ass = (char **) *ppp;
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_comma_list:
				rec = record + prop->cm_offset;
				wpp = (char **) rec;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_pp = (const char **) old_rec;
					if ((*wpp == NULL) &&
					    (*old_pp == NULL)) {
						continue;
					}
					if ((*wpp != NULL) &&
					    (*old_pp != NULL) &&
					    (strcmp(*wpp, *old_pp) == 0)) {
						continue;
					}
				}
				wpp = eku_splitv(record, *wpp);
				if (wpp != NULL) {
					dict[n].value.as = wpp;
					d[n] = &dict[n];
					n++;
				}
				break;
			case cm_tdbush_property_time_t:
				rec = record + prop->cm_offset;
				tp = (time_t *) rec;
				dict[n].value.n = *tp;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_tp = (time_t *) old_rec;
					if (*tp == *old_tp) {
						continue;
					}
				}
				d[n] = &dict[n];
				n++;
				break;
			case cm_tdbush_property_long_long:
				rec = record + prop->cm_offset;
				llp = (long long *) rec;
				dict[n].value.n = *llp;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_llp = (long long *) old_rec;
					if (*llp == *old_llp) {
						continue;
					}
				}
				d[n] = &dict[n];
				n++;
				break;
			case cm_tdbush_property_mode_t:
				rec = record + prop->cm_offset;
				mp = (mode_t *) rec;
				dict[n].value.n = *mp;
				if (old_record != NULL) {
					/* if we have an old record, compare
					 * its value to the current one, and
					 * skip this if they're "the same" */
					old_rec = old_record + prop->cm_offset;
					old_mp = (mode_t *) old_rec;
					if (*mp == *old_mp) {
						continue;
					}
				}
				d[n] = &dict[n];
				n++;
				break;
			case cm_tdbush_property_special:
				switch (prop->cm_bus_type) {
				case cm_tdbush_property_path:
				case cm_tdbush_property_string:
					p = (*(prop->cm_read_string))(ctx, parent,
								      record,
								      prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_p = (*(prop->cm_read_string))(ctx, parent,
										  old_record,
										  prop->cm_name);
						if ((p == NULL) &&
						    (old_p == NULL)) {
							continue;
						}
						if ((p != NULL) &&
						    (old_p != NULL) &&
						    (strcmp(p, old_p) == 0)) {
							continue;
						}
					}
					if ((p == NULL) || (strlen(p) == 0)) {
						if (prop->cm_bus_type == cm_tdbush_property_path) {
							continue;
						}
						if (prop->cm_bus_type == cm_tdbush_property_string) {
							p = "";
						}
					}
					dict[n].value.s = (char *) p;
					d[n] = &dict[n];
					n++;
					break;
				case cm_tdbush_property_strings:
					pp = (*(prop->cm_read_strings))(ctx, parent,
									record,
									prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_pp = (*(prop->cm_read_strings))(ctx, parent,
										    old_record,
										    prop->cm_name);
						if (compare_strv(old_pp, pp) == 0) {
							continue;
						}
					}
					if ((pp != NULL) && (*pp != NULL)) {
						dict[n].value.as = (char **) pp;
						d[n] = &dict[n];
						n++;
					}
					break;
				case cm_tdbush_property_string_pairs:
					pp = (*(prop->cm_read_string_pairs))(ctx, parent,
									     record,
									     prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_pp = (*(prop->cm_read_string_pairs))(ctx, parent,
											 old_record,
											 prop->cm_name);
						if (compare_strv(old_pp, pp) == 0) {
							continue;
						}
					}
					if ((pp != NULL) && (*pp != NULL)) {
						dict[n].value.ass = (char **) pp;
						d[n] = &dict[n];
						n++;
					}
					break;
				case cm_tdbush_property_boolean:
					b = (*(prop->cm_read_boolean))(ctx, parent,
								       record,
								       prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_b = (*(prop->cm_read_boolean))(ctx, parent,
										   old_record,
										   prop->cm_name);
						if (b == old_b) {
							continue;
						}
					}
					dict[n].value.b = b;
					d[n] = &dict[n];
					n++;
					break;
				case cm_tdbush_property_number:
					l = (*(prop->cm_read_number))(ctx, parent,
								      record,
								      prop->cm_name);
					if (old_record != NULL) {
						/* if we have an old record,
						 * compare its value to the
						 * current one, and skip this
						 * if they're "the same" */
						old_l = (*(prop->cm_read_number))(ctx, parent,
										  old_record,
										  prop->cm_name);
						if (l == old_l) {
							continue;
						}
					}
					dict[n].value.n = l;
					d[n] = &dict[n];
					n++;
					break;
				}
				break;
			}
		}
	}
	if (d != NULL) {
		d[n] = NULL;
	}

	if (req != NULL) {
		cm_tdbusm_set_d(rep, d);
	} else {
		cm_tdbusm_set_sd(rep, interface, d);
	}

	if (rep != NULL) {
		if ((old_record == NULL) || ((d != NULL) && (d[0] != NULL))) {
			dbus_connection_send(conn, rep, NULL);
		}
		dbus_message_unref(rep);
	}
	talloc_free(parent);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/* org.freedesktop.DBus.Properties.GetAll */
static DBusHandlerResult
cm_tdbush_property_get_all(DBusConnection *conn,
			   DBusMessage *msg,
			   struct cm_client_info *ci,
			   struct cm_context *ctx)
{
	return cm_tdbush_property_get_all_or_changed(ctx, conn, msg,
						     NULL, NULL, NULL, NULL);
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for a specific set of
 * properties */
DBusHandlerResult
cm_tdbush_property_emit_changed(struct cm_context *ctx,
				const char *path,
				const char *interface,
				const char **properties)
{
	if (cm_get_conn_ptr(ctx) == NULL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else {
		return cm_tdbush_property_get_all_or_changed(ctx,
							     cm_get_conn_ptr(ctx),
							     NULL,
							     path,
							     interface,
							     NULL,
							     properties);
	}
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for the properties
 * which differ between the old and new entries */
void
cm_tdbush_property_emit_entry_changes(struct cm_context *ctx,
				      struct cm_store_entry *old_entry,
				      struct cm_store_entry *new_entry)
{
	char *path;
	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(old_entry, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       old_entry->cm_busname);
		if (path != NULL) {
			cm_tdbush_property_get_all_or_changed(ctx,
							      cm_get_conn_ptr(ctx),
							      NULL,
							      path,
							      CM_DBUS_REQUEST_INTERFACE,
							      (char *) old_entry,
							      NULL);
			talloc_free(path);
		}
	}
}

/* emit org.fedorahosted.certmonger.request.SavedCertificate, for clients whom
 * filtering on PropertiesChanged isn't enough */
void
cm_tdbush_property_emit_entry_saved_cert(struct cm_context *ctx,
					 struct cm_store_entry *entry)
{
	DBusMessage *msg;
	char *path;

	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(entry, "%s/%s",
				       CM_DBUS_REQUEST_PATH,
				       entry->cm_busname);
		if (path != NULL) {
			msg = dbus_message_new_signal(path,
						      CM_DBUS_REQUEST_INTERFACE,
						      CM_DBUS_SIGNAL_REQUEST_CERT_SAVED);
			if (msg != NULL) {
				dbus_connection_send(cm_get_conn_ptr(ctx),
						     msg, NULL);
				dbus_message_unref(msg);
			}
			talloc_free(path);
		}
	}
}

/* emit org.freedesktop.DBus.Properties.PropertiesChanged for the properties
 * which differ between the old and new CAs */
void
cm_tdbush_property_emit_ca_changes(struct cm_context *ctx,
				   struct cm_store_ca *old_ca,
				   struct cm_store_ca *new_ca)
{
	char *path;
	if (cm_get_conn_ptr(ctx) != NULL) {
		path = talloc_asprintf(old_ca, "%s/%s",
				       CM_DBUS_CA_PATH,
				       old_ca->cm_busname);
		if (path != NULL) {
			cm_tdbush_property_get_all_or_changed(ctx,
							      cm_get_conn_ptr(ctx),
							      NULL,
							      path,
							      CM_DBUS_CA_INTERFACE,
							      (char *) old_ca,
							      NULL);
			talloc_free(path);
		}
	}
}

/* interface for org.freedesktop.DBus.Introspectable */
static struct cm_tdbush_interface *
cm_tdbush_iface_introspection(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(DBUS_INTERFACE_INTROSPECTABLE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Introspect",
								     cm_tdbush_introspect,
								     make_method_arg("xml_data",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
							 NULL));
	}
	return ret;
}

/* interface for org.freedesktop.DBus.Properties */
static struct cm_tdbush_interface *
cm_tdbush_iface_properties(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(DBUS_INTERFACE_PROPERTIES,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Get",
								     cm_tdbush_property_get,
								     make_method_arg("interface_name",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("property_name",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("value",
										     DBUS_TYPE_VARIANT_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("Set",
								     cm_tdbush_property_set,
								     make_method_arg("interface_name",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("property_name",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("value",
										     DBUS_TYPE_VARIANT_AS_STRING,
										     cm_tdbush_method_arg_in,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("GetAll",
								     cm_tdbush_property_get_all,
								     make_method_arg("interface_name",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("props",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING
										     DBUS_TYPE_VARIANT_AS_STRING
										     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_signal,
							 make_signal("PropertiesChanged",
								     make_signal_arg("interface_name",
										     DBUS_TYPE_STRING_AS_STRING,
								     make_signal_arg("changed_properties",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING
										     DBUS_TYPE_VARIANT_AS_STRING
										     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
								     make_signal_arg("invalidated_properties",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     NULL)))),
							 NULL)))));
	}
	return ret;
}


/* interface for org.freedesktop.certmonger.request */
static struct cm_tdbush_interface *
cm_tdbush_iface_request(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_REQUEST_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_nickname",
								     request_get_nickname,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_nickname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_autorenew",
								     request_get_autorenew,
								     make_method_arg("enabled",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_AUTORENEW,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, request_prop_get_autorenew, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_data",
								     request_get_cert_data,
								     make_method_arg("pem",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       make_member_annotation("org.freedesktop.DBus.Property.EmitsChangedSignal",
											      "true",
											      NULL)),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_CHAIN,
								       cm_tdbush_property_string_pairs,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_nickcerts, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_ROOTS,
								       cm_tdbush_property_string_pairs,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_nickcerts, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_info",
								     request_get_cert_info,
								     make_method_arg("issuer",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("serial_hex",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("subject",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("not_after",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("email",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("dns",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("principal_names",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("key_usage",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("extended_key_usage",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("not_before",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)))))))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_ISSUER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_issuer),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_SERIAL,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_serial),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_SUBJECT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_subject),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_NOT_VALID_BEFORE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_cert_not_before),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_NOT_VALID_AFTER,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_cert_not_after),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_EMAIL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_email),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_KU,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_ku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_EKU,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_comma_list,
								       offsetof(struct cm_store_entry, cm_cert_eku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_HOSTNAME,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_hostname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRINCIPAL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_cert_principal),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_last_checked",
								     request_get_cert_last_checked,
								     make_method_arg("date",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LAST_CHECKED,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_last_need_notify_check),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_cert_storage_info",
								     request_get_cert_storage_info,
								     make_method_arg("type",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("location_or_nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("nss_token",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_type, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_file, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_DATABASE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_database, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_nickname, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_LOCATION_TOKEN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_cert_location_token, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_OWNER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_owner),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PERMS,
								       cm_tdbush_property_number,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_mode_t,
								       offsetof(struct cm_store_entry, cm_cert_perms),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_csr_data",
								     request_get_csr_data,
								     make_method_arg("pem",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CSR,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_csr),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_csr_info",
								     request_get_csr_info,
								     make_method_arg("subject",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("email",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("dns",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("principal_names",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("key_usage",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("extended_key_usage",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_PIN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_pin, NULL, NULL, NULL, NULL,
								       request_prop_set_key_pin, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_PIN_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_pin_file, NULL, NULL, NULL, NULL,
								       request_prop_set_key_pin_file, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_GEN_DATE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_key_generated_date),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_ISSUED_COUNT,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, NULL, request_prop_get_key_issued_count,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_SUBJECT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_subject),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_EMAIL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_email),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_KU,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_ku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_EKU,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_comma_list,
								       offsetof(struct cm_store_entry, cm_template_eku),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_HOSTNAME,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_hostname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_PRINCIPAL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_principal),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_IP_ADDRESS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_ipaddress),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_IS_CA,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, request_prop_get_template_is_ca, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, NULL, request_prop_get_template_ca_path_length,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_OCSP,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_ocsp_location),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_CRL_DP,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_crl_distribution_point),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_FRESHEST_CRL,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_template_freshest_crl),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_NS_COMMENT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_ns_comment),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_PROFILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_profile),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_ISSUER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_issuer),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_certificate_template),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_NS_CERTTYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_template_ns_certtype),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_challenge_password, NULL, NULL, NULL, NULL,
								       request_prop_set_challenge_password, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_challenge_password_file, NULL, NULL, NULL, NULL,
								       request_prop_set_challenge_password_file, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_pin",
								     request_get_key_pin,
								     make_method_arg("pin",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_pin_file",
								     request_get_key_pin_file,
								     make_method_arg("pin_file",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_storage_info",
								     request_get_key_storage_info,
								     make_method_arg("type",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("location_or_nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("nss_token",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_type, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_FILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_file, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_DATABASE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_database, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_nickname, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_LOCATION_TOKEN,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_location_token, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_OWNER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_key_owner),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_PERMS,
								       cm_tdbush_property_number,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_mode_t,
								       offsetof(struct cm_store_entry, cm_key_perms),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_key_type_and_size",
								     request_get_key_type_and_size,
								     make_method_arg("type",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("size",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_key_type, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_KEY_SIZE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, NULL, request_prop_get_key_size,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_monitoring",
								     request_get_monitoring,
								     make_method_arg("enabled",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_MONITORING,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, request_prop_get_monitoring, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_notification_info",
								     request_get_notification_info,
								     make_method_arg("method",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("destination",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_TYPE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_type, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_SYSLOG_PRIORITY,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_syslog, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_EMAIL,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_email, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NOTIFICATION_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_notification_command, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_status",
								     request_get_status,
								     make_method_arg("state",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("blocked",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_STATUS,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_status, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_STUCK,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, request_prop_get_stuck, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_ca",
								     request_get_ca,
								     make_method_arg("name",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA,
								       cm_tdbush_property_path,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       request_prop_get_ca, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_PROFILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_cert_profile),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NSS_USER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_nss_user),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ROOT_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_root_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_ROOT_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_other_root_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_other_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ROOT_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_root_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_other_root_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_entry, cm_other_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_submitted_cookie",
								     request_get_submitted_cookie,
								     make_method_arg("cookie",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_COOKIE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_ca_cookie),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_ca_error",
								     request_get_ca_error,
								     make_method_arg("text",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_ERROR,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_ca_error),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_submitted_date",
								     request_get_submitted_date,
								     make_method_arg("date",
										     DBUS_TYPE_INT64_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SUBMITTED_DATE,
								       cm_tdbush_property_number,
								       cm_tdbush_property_read,
								       cm_tdbush_property_time_t,
								       offsetof(struct cm_store_entry, cm_submitted),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("modify",
								     request_modify,
								     make_method_arg("updates",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING
										     DBUS_TYPE_VARIANT_AS_STRING
										     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("path",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("rekey",
								     request_rekey,
								     make_method_arg("working",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("resubmit",
								     request_resubmit,
								     make_method_arg("working",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("refresh",
								     request_refresh,
								     make_method_arg("working",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRESAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_pre_certsave_command),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_PRESAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_pre_certsave_uid),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_POSTSAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_post_certsave_command),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CERT_POSTSAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_entry, cm_post_certsave_uid),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_signal,
							 make_signal(CM_DBUS_SIGNAL_REQUEST_CERT_SAVED,
								     NULL),
							 NULL))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
	}
	return ret;
}

/* interface for org.freedesktop.certmonger.ca */
static struct cm_tdbush_interface *
cm_tdbush_iface_ca(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_CA_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_config_file_path",
								     ca_get_config_file_path,
								     make_method_arg("path",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_nickname",
								     ca_get_nickname,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_NICKNAME,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_nickname),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_AKA,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_aka),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_is_default",
								     ca_get_is_default,
								     make_method_arg("default",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_IS_DEFAULT,
								       cm_tdbush_property_boolean,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, NULL, ca_prop_get_is_default, NULL,
								       NULL, NULL, NULL, ca_prop_set_is_default, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_type",
								     ca_get_type,
								     make_method_arg("type",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_serial",
								     ca_get_serial,
								     make_method_arg("serial_hex",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_location",
								     ca_get_location,
								     make_method_arg("path",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_EXTERNAL_HELPER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       ca_prop_get_external_helper, NULL, NULL, NULL, NULL,
								       ca_prop_set_external_helper, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_issuer_names",
								     ca_get_issuer_names,
								     make_method_arg("names",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("refresh",
								     ca_refresh,
								     make_method_arg("working",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_ERROR,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_error),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ISSUER_NAMES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_known_issuer_names),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ROOT_CERTS,
								       cm_tdbush_property_string_pairs,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_nickcerts, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_ROOT_CERTS,
								       cm_tdbush_property_string_pairs,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_nickcerts, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_CERTS,
								       cm_tdbush_property_string_pairs,
								       cm_tdbush_property_read,
								       cm_tdbush_property_special,
								       0,
								       NULL, NULL, ca_prop_get_nickcerts, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_REQUIRED_ENROLL_ATTRIBUTES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_required_enroll_attributes),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_REQUIRED_RENEW_ATTRIBUTES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_required_renewal_attributes),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SUPPORTED_PROFILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_profiles),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_DEFAULT_PROFILE,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_default_profile),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ROOT_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_root_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_ROOT_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_other_root_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_CERT_FILES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_other_cert_store_files),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_ROOT_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_root_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_other_root_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_OTHER_CERT_NSSDBS,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_other_cert_store_nssdbs),
								       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_PRESAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_pre_save_command),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_PRESAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_pre_save_uid),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_POSTSAVE_COMMAND,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_post_save_command),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_CA_POSTSAVE_UID,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_post_save_uid),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_CIPHER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       ca_prop_get_scep_cipher, NULL, NULL, NULL, NULL,
								       ca_prop_set_scep_cipher, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_DIGEST,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       ca_prop_get_scep_digest, NULL, NULL, NULL, NULL,
								       ca_prop_set_scep_digest, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_CA_IDENTIFIER,
								       cm_tdbush_property_string,
								       cm_tdbush_property_readwrite,
								       cm_tdbush_property_special,
								       0,
								       ca_prop_get_scep_ca_identifier, NULL, NULL, NULL, NULL,
								       ca_prop_set_scep_ca_identifier, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_CA_CAPABILITIES,
								       cm_tdbush_property_strings,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_pp,
								       offsetof(struct cm_store_ca, cm_ca_capabilities),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_RA_CERT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_encryption_cert),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_CA_CERT,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_encryption_issuer_cert),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     make_interface_item(cm_tdbush_interface_property,
							 make_property(CM_DBUS_PROP_SCEP_OTHER_CERTS,
								       cm_tdbush_property_string,
								       cm_tdbush_property_read,
								       cm_tdbush_property_char_p,
								       offsetof(struct cm_store_ca, cm_ca_encryption_cert_pool),
								       NULL, NULL, NULL, NULL, NULL,
								       NULL, NULL, NULL, NULL, NULL,
								       NULL),
				     NULL)))))))))))))))))))))))))))))))))))))));
	}
	return ret;
}

/* interface for org.freedesktop.certmonger */
static struct cm_tdbush_interface *
cm_tdbush_iface_base(void)
{
	static struct cm_tdbush_interface *ret;
	if (ret == NULL) {
		ret = make_interface(CM_DBUS_BASE_INTERFACE,
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("add_known_ca",
								     base_add_known_ca,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("command",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("known_names",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("name",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("add_known_ca_with_eab_key",
								     base_add_known_ca_with_eab_key,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("command",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("known_names",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("eab_key",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("name",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)))))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("add_request",
								     base_add_request,
								     make_method_arg("template",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING
										     DBUS_TYPE_VARIANT_AS_STRING
										     DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
								     make_method_arg("name",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL))),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("find_ca_by_nickname",
								     base_find_ca_by_nickname,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("ca",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("find_request_by_nickname",
								     base_find_request_by_nickname,
								     make_method_arg("nickname",
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("request",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_known_cas",
								     base_get_known_cas,
								     make_method_arg("ca_list",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_requests",
								     base_get_requests,
								     make_method_arg("requests",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_key_types",
								     base_get_supported_key_types,
								     make_method_arg("key_type_list",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_key_storage",
								     base_get_supported_key_storage,
								     make_method_arg("key_storage_type_list",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("get_supported_cert_storage",
								     base_get_supported_cert_storage,
								     make_method_arg("cert_storage_type_list",
										     DBUS_TYPE_ARRAY_AS_STRING
										     DBUS_TYPE_STRING_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("remove_known_ca",
								     base_remove_known_ca,
								     make_method_arg("ca",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     make_interface_item(cm_tdbush_interface_method,
							 make_method("remove_request",
								     base_remove_request,
								     make_method_arg("request",
										     DBUS_TYPE_OBJECT_PATH_AS_STRING,
										     cm_tdbush_method_arg_in,
								     make_method_arg("status",
										     DBUS_TYPE_BOOLEAN_AS_STRING,
										     cm_tdbush_method_arg_out,
										     NULL)),
								     NULL),
				     NULL)))))))))))));
	}
	return ret;
}

/* map object types to an get-interface functions */
struct cm_tdbush_interface_map
cm_tdbush_object_type_map[] = {
	{cm_tdbush_object_type_parent_of_base, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_base, &cm_tdbush_iface_base},
	{cm_tdbush_object_type_parent_of_cas, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_group_of_cas, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_ca, &cm_tdbush_iface_ca},
	{cm_tdbush_object_type_parent_of_requests, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_group_of_requests, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_introspection},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_properties},
	{cm_tdbush_object_type_request, &cm_tdbush_iface_request},
};

static struct cm_tdbush_interface_map *
cm_tdbush_object_type_map_get_n(unsigned int i)
{
	if (i < (sizeof(cm_tdbush_object_type_map) /
		 sizeof(cm_tdbush_object_type_map[0]))) {
		return cm_tdbush_object_type_map + i;
	} else {
		return NULL;
	}
}

static enum cm_tdbush_object_type
cm_tdbush_classify_path(struct cm_context *ctx, const char *path)
{
	int basepathlen = strlen(CM_DBUS_BASE_PATH);
	int capathlen = strlen(CM_DBUS_CA_PATH);
	int reqpathlen = strlen(CM_DBUS_REQUEST_PATH);
	int pathlen = strlen(path);

	/* Base is just a name, so check for it first. */
	if (strcmp(path, CM_DBUS_BASE_PATH) == 0) {
		return cm_tdbush_object_type_base;
	}
	/* The group of requests is just a name, so check for it. */
	if (strcmp(path, CM_DBUS_REQUEST_PATH) == 0) {
		return cm_tdbush_object_type_group_of_requests;
	}
	/* The group of CAs is just a name, so check for it. */
	if (strcmp(path, CM_DBUS_CA_PATH) == 0) {
		return cm_tdbush_object_type_group_of_cas;
	}
	/* Check for things above the base node. */
	if ((strcmp(path, "/") == 0) ||
	    ((pathlen < basepathlen) &&
	     (strncmp(path, CM_DBUS_BASE_PATH, pathlen) == 0) &&
	     (CM_DBUS_BASE_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_base;
	}
	/* Check for things above the request group node. */
	if (((pathlen < reqpathlen) &&
	     (strncmp(path, CM_DBUS_REQUEST_PATH, pathlen) == 0) &&
	     (CM_DBUS_REQUEST_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_requests;
	}
	/* Check for things above the CA group node. */
	if (((pathlen < capathlen) &&
	     (strncmp(path, CM_DBUS_CA_PATH, pathlen) == 0) &&
	     (CM_DBUS_CA_PATH[pathlen] == '/'))) {
		return cm_tdbush_object_type_parent_of_cas;
	}
	/* Check if it names a request. */
	if ((pathlen > reqpathlen) &&
	    (strncmp(path, CM_DBUS_REQUEST_PATH, reqpathlen) == 0) &&
	    (path[reqpathlen] == '/') &&
	    (cm_get_entry_by_busname(ctx, path + reqpathlen + 1) != NULL)) {
		return cm_tdbush_object_type_request;
	}
	/* Check if it names a CA. */
	if ((pathlen > capathlen) &&
	    (strncmp(path, CM_DBUS_CA_PATH, capathlen) == 0) &&
	    (path[capathlen] == '/') &&
	    (cm_get_ca_by_busname(ctx, path + capathlen + 1) != NULL)) {
		return cm_tdbush_object_type_ca;
	}
	/* It's not classifiable. */
	return cm_tdbush_object_type_none;
}

/* the list of method calls that we've made that we haven't yet received
 * responses for, and the methods to invoke once we've gotten responses for our
 * outstanding requests  */
struct cm_tdbush_pending_call {
	DBusMessage *cm_msg;
	const char *cm_path, *cm_interface, *cm_method;
	enum cm_tdbush_object_type cm_type;
	DBusHandlerResult (*cm_fn)(DBusConnection *conn,
				   DBusMessage *msg,
				   struct cm_client_info *ci,
				   struct cm_context *ctx);
	dbus_bool_t cm_know_uid; /* GetConnectionUnixUser replied? */
	dbus_uint32_t cm_pending_uid; /* pending GetConnectionUnixUser call */
	dbus_bool_t cm_know_pid; /* GetConnectionUnixProcessID replied? */
	dbus_uint32_t cm_pending_pid; /* pending GetConnectionUnixProcessID call */
	uid_t cm_uid;
	pid_t cm_pid;
	struct cm_tdbush_pending_call *cm_next;
} *cm_pending_calls;

/* read the UID and PID of a directly-connected client */
static int
cm_tdbush_read_conn_id(DBusConnection *conn, uid_t *uid, pid_t *pid)
{
	unsigned long utmp, ptmp;

	if (!dbus_connection_get_unix_user(conn, &utmp) ||
	    !dbus_connection_get_unix_process_id(conn, &ptmp)) {
		return -1;
	}
	*uid = utmp;
	*pid = ptmp;
	return 0;
}

/* handle a method call by either asserting that we don't support a method, or
 * by asking for information about the caller */
DBusHandlerResult
cm_tdbush_handle_method_call(DBusConnection *conn, DBusMessage *msg,
			     enum cm_tdbus_type bus, struct cm_context *ctx)
{
	struct cm_tdbush_pending_call pending, *tmp;
	struct cm_tdbush_interface *iface;
	struct cm_tdbush_interface_item *item;
	struct cm_tdbush_method *meth;
	unsigned int i;

	memset(&pending, 0, sizeof(pending));
	pending.cm_msg = dbus_message_ref(msg);
	pending.cm_path = dbus_message_get_path(pending.cm_msg);
	pending.cm_interface = dbus_message_get_interface(pending.cm_msg);
	pending.cm_method = dbus_message_get_member(pending.cm_msg);
	pending.cm_type = cm_tdbush_classify_path(ctx, pending.cm_path);
	pending.cm_know_uid = FALSE;
	pending.cm_uid = (uid_t) -1;
	pending.cm_know_pid = FALSE;
	pending.cm_pid = (pid_t) -1;
	for (i = 0;
	     i < sizeof(cm_tdbush_object_type_map) / sizeof(cm_tdbush_object_type_map[i]);
	     i++) {
		if (cm_tdbush_object_type_map[i].cm_type != pending.cm_type) {
			continue;
		}
		iface = (*((cm_tdbush_object_type_map[i]).cm_interface))();
		if ((pending.cm_interface != NULL) &&
		    (cm_name_cmp(iface->cm_name, pending.cm_interface) != 0)) {
			continue;
		}
		for (item = iface->cm_items;
		     item != NULL;
		     item = item->cm_next) {
			if (item->cm_member_type != cm_tdbush_interface_method) {
				continue;
			}
			meth = item->cm_method;
			if (cm_name_cmp(meth->cm_name, pending.cm_method) != 0) {
				continue;
			}

			/* found it */
			pending.cm_fn = meth->cm_fn;

			/* "private": no bus daemon, so identify the client */
			if (bus == cm_tdbus_private) {
				struct cm_client_info self;
				/* just run the method */
				if (cm_tdbush_read_conn_id(conn,
							   &pending.cm_uid,
							   &pending.cm_pid) != 0) {
					cm_log(4, "Error reading client ID, "
					       "ignoring.\n");
				} else {
					pending.cm_know_uid = TRUE;
					pending.cm_know_pid = TRUE;
					if (pending.cm_uid != getuid()) {
						cm_log(4, "Client's UID is "
						       "not the same as ours, "
						       "ignoring.\n");
					} else {
						self.uid = pending.cm_uid;
						self.pid = pending.cm_pid;
						cm_log(4, "User ID %lu PID %lu "
						       "called %s:%s.%s.\n",
						       (unsigned long) pending.cm_uid,
						       (unsigned long) pending.cm_pid,
						       pending.cm_path,
						       pending.cm_interface,
						       pending.cm_method);
						(*meth->cm_fn)(conn, pending.cm_msg, &self, ctx);
					}
				}
				dbus_message_unref(pending.cm_msg);
				cm_reset_timeout(ctx);
				return DBUS_HANDLER_RESULT_HANDLED;
			}

			/* "public": go ask the daemon who the client is */
			tmp = talloc_ptrtype(NULL, tmp);
			if (tmp != NULL) {
				memset(tmp, 0, sizeof(*tmp));
				/* we need to know who this is */
				msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
								   DBUS_PATH_DBUS,
								   DBUS_INTERFACE_DBUS,
								   "GetConnectionUnixUser");
				if (msg != NULL) {
					cm_tdbusm_set_s(msg, dbus_message_get_sender(pending.cm_msg));
					if (!dbus_connection_send(conn, msg,
								  &pending.cm_pending_uid)) {
						cm_log(4, "Error calling GetConnectionUnixUser\n");
						talloc_free(tmp);
						tmp = NULL;
					}
					dbus_message_unref(msg);
				}
				msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
								   DBUS_PATH_DBUS,
								   DBUS_INTERFACE_DBUS,
								   "GetConnectionUnixProcessID");
				if (msg != NULL) {
					cm_tdbusm_set_s(msg, dbus_message_get_sender(pending.cm_msg));
					if (!dbus_connection_send(conn, msg,
								  &pending.cm_pending_pid)) {
						cm_log(4, "Error calling GetConnectionUnixProcessID\n");
						talloc_free(tmp);
						tmp = NULL;
					}
					dbus_message_unref(msg);
				}
				if (tmp != NULL) {
					*tmp = pending;
					tmp->cm_next = cm_pending_calls;
					cm_pending_calls = tmp;
					cm_log(4, "Pending GetConnectionUnixUser serial %lu\n",
					       (unsigned long) pending.cm_pending_uid);
					cm_log(4, "Pending GetConnectionUnixProcessID serial %lu\n",
					       (unsigned long) pending.cm_pending_pid);
					cm_reset_timeout(ctx);
					return DBUS_HANDLER_RESULT_HANDLED;
				}
			}
			dbus_message_unref(pending.cm_msg);
			cm_reset_timeout(ctx);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (item == NULL) {
			continue;
		}
	}
	dbus_message_unref(pending.cm_msg);
	cm_reset_timeout(ctx);
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult
cm_tdbush_handle_method_return(DBusConnection *conn, DBusMessage *msg,
			       enum cm_tdbus_type bus, struct cm_context *ctx)
{
	struct cm_tdbush_pending_call **p, *call = NULL, *next = NULL;
	dbus_uint32_t serial;
	struct cm_client_info client_info;
	long uid, pid;

	serial = dbus_message_get_reply_serial(msg);
	/* figure out which of our pending calls this goes with */
	for (p = &cm_pending_calls;
	     (p != NULL) && (*p != NULL);
	     p = &((*p)->cm_next)) {
		call = *p;
		next = call->cm_next;
		if (call->cm_pending_uid == serial) {
			if (cm_tdbusm_get_n(msg, call, &uid) != 0) {
				cm_log(1, "Result error from GetConnectionUnixUser().\n");
				dbus_message_unref(call->cm_msg);
				talloc_free(call);
				*p = next;
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			call->cm_uid = uid;
			call->cm_know_uid = TRUE;
			break;
		}
		if (call->cm_pending_pid == serial) {
			if (cm_tdbusm_get_n(msg, call, &pid) != 0) {
				cm_log(1, "Result error from GetConnectionUnixProcessID().\n");
				dbus_message_unref(call->cm_msg);
				talloc_free(call);
				*p = next;
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
			call->cm_pid = pid;
			call->cm_know_pid = TRUE;
			break;
		}
	}
	if ((p == NULL) || (*p == NULL)) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	/* do we know enough now? if not, we're done here */
	if (!call->cm_know_uid || !call->cm_know_pid) {
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* actually run the method */
	cm_log(4, "User ID %lu PID %lu called %s:%s.%s.\n",
	       (unsigned long) call->cm_uid, (unsigned long) call->cm_pid,
	       call->cm_path, call->cm_interface, call->cm_method);

	client_info.uid = call->cm_uid;
	client_info.pid = call->cm_pid;
	(*call->cm_fn)(conn, call->cm_msg, &client_info, ctx);

	/* remove the pending call record */
	dbus_message_unref(call->cm_msg);
	talloc_free(call);
	*p = next;
	cm_reset_timeout(ctx);

	return DBUS_HANDLER_RESULT_HANDLED;
}
