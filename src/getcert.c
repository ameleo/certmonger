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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include <nss.h>
#include <pk11pub.h>

#include <krb5.h>

#include <popt.h>

#include "cm.h"
#include "kudict.h"
#include "oiddict.h"
#include "store.h"
#include "store-int.h"
#include "submit-e.h"
#include "submit-u.h"
#include "tdbus.h"
#include "tdbusm.h"
#include "tpm-token.h"
#include "util-o.h"
#include "util.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(_text) dgettext(PACKAGE, _text)
#else
#define _(_text) (_text)
#endif
#define N_(_msg) (_msg)

#define HELP_TYPE_COMMAND _("COMMAND")
#define HELP_TYPE_DIRECTORY _("DIRECTORY")
#define HELP_TYPE_EKU _("LIST")
#define HELP_TYPE_EMAIL _("ADDRESS")
#define HELP_TYPE_FILENAME _("FILENAME")
#define HELP_TYPE_HOSTNAME _("HOSTNAME")
#define HELP_TYPE_ID _("ID")
#define HELP_TYPE_IP _("ADDRESS")
#define HELP_TYPE_KEYSIZE _("BITS")
#define HELP_TYPE_KU _("LIST")
#define HELP_TYPE_MODE _("MODE")
#define HELP_TYPE_NAME _("NAME")
#define HELP_TYPE_PRINCIPAL _("PRINCIPAL")
#define HELP_TYPE_SUBJECT _("SUBJECT")
#define HELP_TYPE_URL _("URL")
#define HELP_TYPE_USER _("USERNAME[:GROUPNAME]")

#ifdef FORCE_CA
#define DEFAULT_CA FORCE_CA
#else
#define DEFAULT_CA NULL
#endif

static void help(const char *cmd, const char *category);
static char *thumbprint(const char *s, SECOidTag tag, int bits);

static struct {
	const char *argv0, *verb;
	DBusConnection *conn;
	void *tctx;
} globals = {
	.conn = NULL,
	.tctx = NULL
};

static char *find_ca_by_name(void *parent, enum cm_tdbus_type bus,
			     const char *nickname, int verbose);
static int ca_attests_with_tpm(enum cm_tdbus_type bus, const char *ca,
			       int verbose, int argc, const char **argv);
static char *find_request_by_name(void *parent, enum cm_tdbus_type bus,
				  const char *path, int verbose);
static char *find_ca_name(void *parent, enum cm_tdbus_type bus,
			  const char *path, int verbose);
static char *find_request_name(void *parent, enum cm_tdbus_type bus,
			       const char *path, int verbose);

/* Ensure that a pathname is an absolute pathname. */
static char *
ensure_path_is_absolute(void *parent, const char *path)
{
	char buf[PATH_MAX + 1], *ret;
	if (path[0] == '/') {
		return talloc_strdup(parent, path);
	} else {
		if (getcwd(buf, sizeof(buf)) == buf) {
			ret = talloc_asprintf(parent, "%s/%s", buf, path);
			printf(_("Path \"%s\" is not absolute, "
				 "attempting to "
				 "use \"%s\" instead.\n"), path, ret);
			return ret;
		} else {
			printf(_("Path \"%s\" is not absolute, and "
				 "there was an error determining the "
				 "name of the current directory.\n"),
			       path);
			exit(1);
		}
	}
}

/* Ensure that a pathname is a directory. */
static int
ensure_path_is_directory(char *path)
{
	struct stat st;
	int err;

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			if (access(path, R_OK | W_OK) == 0) {
				return 0;
			} else {
				err = errno;
				printf(_("Path \"%s\": insufficient "
					 "permissions.\n"), path);
				errno = err;
				return -1;
			}
		} else {
			printf(_("Path \"%s\" is not a directory.\n"),
			       path);
			return -1;
		}
	} else {
		err = errno;
		printf(_("Path \"%s\": %s.\n"), path, strerror(errno));
		errno = err;
		return -1;
	}
}

/* Ensure that a pathname is at least in a directory which exists. */
static int
ensure_parent_is_directory(void *parent, const char *path)
{
	char *tmp, *p;
	tmp = talloc_strdup(parent, path);
	if (tmp != NULL) {
		p = strrchr(tmp, '/');
		if (p != NULL) {
			if (p > tmp) {
				*p = '\0';
			} else {
				*(p + 1) = '\0';
			}
			return ensure_path_is_directory(tmp);
		}
	}
	return -1;
}

/* Ensure that a pathname is a regular file or missing. */
static int
ensure_path_is_regular(const char *path)
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
	printf(_("Path \"%s\" is not a regular file.\n"), path);
	return -1;
}

/* Ensure that we have a suitable NSS database location. */
static char *
ensure_nss(void *parent, const char *path, char **nss_scheme)
{
	char *ret;
	*nss_scheme = NULL;
	if (strncmp(path, "sql:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "sql");
		path += 4;
	} else
	if (strncmp(path, "dbm:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "dbm");
		path += 4;
	} else
	if (strncmp(path, "rdb:", 4) == 0) {
		*nss_scheme = talloc_strdup(parent, "rdb");
		path += 4;
	} else
	if (strncmp(path, "extern:", 7) == 0) {
		*nss_scheme = talloc_strdup(parent, "extern");
		path += 7;
	}
	ret = ensure_path_is_absolute(parent, path);
	if (ret != NULL) {
		ret = cm_store_canonicalize_path(parent, ret);
	}
	if (ret != NULL) {
		if (ensure_path_is_directory(ret) != 0) {
			ret = NULL;
		}
	}
	if (ret == NULL) {
		exit(1);
	}
	return ret;
}

/* Ensure that we have a suitable location for a PEM file. */
static char *
ensure_pem(void *parent, const char *path)
{
	char *ret;
	ret = ensure_path_is_absolute(parent, path);
	if (ret != NULL) {
		ret = cm_store_canonicalize_path(parent, ret);
	}
	if (ret != NULL) {
		if (ensure_parent_is_directory(parent, ret) != 0) {
			ret = NULL;
		}
	}
	if (ret != NULL) {
		if (ensure_path_is_regular(ret) != 0) {
			ret = NULL;
		}
	}
	if (ret == NULL) {
		exit(1);
	}
	return ret;
}

/* Add a string to a list. */
static void
add_string(void *parent, char ***dest, const char *value)
{
	char **tmp;
	int i;
	for (i = 0; ((*dest) != NULL) && ((*dest)[i] != NULL); i++) {
		continue;
	}
	tmp = talloc_array_ptrtype(parent, tmp, i + 2);
	if (tmp == NULL) {
		printf(_("Out of memory.\n"));
		exit(1);
	}
	if (*dest)
		memcpy(tmp, *dest, sizeof(tmp[0]) * i);
	tmp[i] = talloc_strdup(tmp, value);
	i++;
	tmp[i] = NULL;
	*dest = tmp;
}

/* Connect to the bus, or not. */
static void
prep_bus(enum cm_tdbus_type which, const char *mode,
	 int verbose, int argc, const char **argv)
{
	DBusError err;
	char *nargv[7] = {
		CM_CERTMONGER_DAEMON_PATH,
		"-n",
		"-L",
		"-c",
	};
	char *cmd = NULL;
	int i;

	if ((which != cm_tdbus_system) || (globals.conn != NULL) ||
	    (getuid() != 0)) {
		return;
	}
	memset(&err, 0, sizeof(err));
	globals.conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (globals.conn != NULL) {
		return;
	}
	if (!dbus_error_has_name(&err, DBUS_ERROR_NO_SERVER) &&
	    !dbus_error_has_name(&err, DBUS_ERROR_FILE_NOT_FOUND)) {
		return;
	}
	cmd = talloc_asprintf(NULL, "%s/%s %s", CM_GETCERT_DIR, globals.argv0,
			      globals.verb);
	for (i = 1; i < argc; i++) {
		cmd = talloc_strdup_append(cmd, " ");
		cmd = talloc_strdup_append(cmd, shell_escape(cmd, argv[i]));
	}
	nargv[4] = cmd;
	if (verbose > 0) {
		nargv[5] = talloc_asprintf(cmd, "-d%d", verbose);
	}
	if (verbose) {
		printf(_("No system bus running.\n"));
		printf(_("Running as UID 0.\n"));
		printf(_("Launching temporary dedicated service daemon.\n"));
	}
	execv(nargv[0], nargv);
}

/* Connect to the bus and set up as much of the request as we can. */
static DBusMessage *
prep_req(enum cm_tdbus_type which,
	 const char *path, const char *interface, const char *method)
{
	DBusMessage *msg;
	const char *busaddr;

	if (globals.conn == NULL) {
		switch (which) {
		case cm_tdbus_session:
			globals.conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
			break;
		case cm_tdbus_system:
			globals.conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
			break;
		case cm_tdbus_private:
			busaddr = getenv(CERTMONGER_PVT_ADDRESS_ENV);
			if (busaddr != NULL) {
				globals.conn = dbus_connection_open_private(busaddr, NULL);
			}
			break;
		}
		if (globals.conn == NULL) {
			printf(_("Error connecting to D-Bus.\n"));
			printf(_("Please verify that the message bus (D-Bus) service is running.\n"));
			exit(1);
		}
	}
	msg = dbus_message_new_method_call(CM_DBUS_NAME,
					   path, interface, method);
	if (msg == NULL) {
		printf(_("Error creating DBus request message.\n"));
		exit(1);
	}
	return msg;
}

/* Produce a useful error about popt. */
static const char *
make_popt_error(poptContext ctx, int code)
{
	char *p;

	switch (code) {
	case POPT_ERROR_NOARG:
		p = talloc_asprintf(NULL, _("missing argument for %s"),
				    poptBadOption(ctx, 0));
		if (p != NULL) {
			return p;
		}
		return _("missing argument");
		break;
	case POPT_ERROR_BADOPT:
		p = talloc_asprintf(NULL, _("unrecognized option %s"),
				    poptBadOption(ctx, 0));
		if (p != NULL) {
			return p;
		}
		return _("unrecognized option");
		break;
	case POPT_ERROR_OPTSTOODEEP:
		return _("aliases nested too deeply");
		break;
	case POPT_ERROR_BADQUOTE:
		return _("bad parameter quoting");
		break;
	case POPT_ERROR_ERRNO:
		return strerror(errno);
		break;
	case POPT_ERROR_BADNUMBER:
		return _("invalid numeric value");
		break;
	case POPT_ERROR_OVERFLOW:
		return _("number too large or too small");
		break;
	case POPT_ERROR_BADOPERATION:
		return _("bad operation");
		break;
	case POPT_ERROR_NULLARG:
		return _("internal error");
		break;
	case POPT_ERROR_MALLOC:
		return _("out of memory");
		break;
#ifdef POPT_ERROR_BADCONFIG
	case POPT_ERROR_BADCONFIG:
		return _("error in popt configuration file");
		break;
#endif
	}
	return poptStrerror(code);
}

/* Try to offer some advice based on the error. */
static enum { hint_unknown, hint_found }
print_hint(const char *error, const char *message)
{
	char *text = NULL;
	void *ctx;
	ctx = talloc_new(NULL);
	text = cm_tdbusm_hint(ctx, error, message);
	if ((text == NULL) &&
	    (strncmp(error, CM_DBUS_ERROR_BASE,
		     strlen(CM_DBUS_ERROR_BASE)) == 0)) {
		text = talloc_asprintf(ctx, "%s\n", _(message));
	}
	if (text != NULL) {
		printf("%s", _(text));
	}
	talloc_free(ctx);
	return text ? hint_found : hint_unknown;
}

/* Send our request and return the response.  If there's an error, exit. */
static DBusMessage *
send_req(DBusMessage *req, int verbose)
{
	DBusMessage *rep;
	DBusError err;
	memset(&err, 0, sizeof(err));
	rep = dbus_connection_send_with_reply_and_block(globals.conn, req,
							30 * 1000, &err);
	if (rep == NULL) {
		if (dbus_error_is_set(&err)) {
			if (err.name != NULL) {
				if ((print_hint(err.name,
						err.message) == hint_unknown) ||
				    verbose) {
					if ((err.message != NULL) && verbose) {
						printf(_("Error %s: %s\n"),
						       err.name,
						       err.message);
					} else {
						printf(_("Error %s\n"),
						       err.name);
					}
				}
			} else {
				if (err.message != NULL) {
					printf(_("Error: %s\n"), err.message);
				} else {
					printf(_("Received error response from "
						 "local %s service.\n"),
						 CM_DBUS_NAME);
				}
			}
		} else {
			printf(_("No response received from %s service.\n"),
			       CM_DBUS_NAME);
		}
		if ((err.name != NULL) && strcmp(err.name, "org.fedorahosted.certmonger.duplicate") == 0) {
			exit(2);
		}
		exit(1);
	}
	dbus_message_unref(req);
	return rep;
}

/* Send the specified, argument-less method call to the named object and return
 * the reply message. */
static DBusMessage *
query_rep(enum cm_tdbus_type which,
	  const char *path, const char *interface, const char *method,
	  int verbose)
{
	return send_req(prep_req(which, path, interface, method), verbose);
}

/* Send the specified, argument-less method call to the named object, and
 * return a sole boolean response. */
static dbus_bool_t
query_rep_b(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    int verbose,
	    void *parent)
{
	DBusMessage *rep;
	dbus_bool_t b;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_b(rep, parent, &b) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return b;
}

/* Send the specified, argument-less method call to the named object, and
 * return the single string from the response. */
static char *
query_rep_s(enum cm_tdbus_type which,
	    const char *path, const char *interface, const char *method,
	    int verbose,
	    void *parent)
{
	DBusMessage *rep;
	char *s;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_s(rep, parent, &s) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return s;
}

/* Send the specified, argument-less method call to the named object, and
 * return the array of strings from the response. */
static char **
query_rep_as(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *method,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char **as;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_as(rep, parent, &as) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return as;
}

/* Send the specified, argument-less method call to the named object, and
 * return the array of paths from the response. */
static char **
query_rep_ap(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *method,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char **ap;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_ap(rep, parent, &ap) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return ap;
}

/* Send the specified, argument-less method call to the named object, and
 * return from two to four strings from the response. */
static void
query_rep_sososos(enum cm_tdbus_type which,
		  const char *path, const char *interface, const char *method,
		  int verbose,
		  void *parent, char **s1, char **s2, char **s3, char **s4)
{
	DBusMessage *rep;
	rep = query_rep(which, path, interface, method, verbose);
	if (cm_tdbusm_get_sososos(rep, parent, s1, s2, s3, s4) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
}

/* Send a query for the value of the specified property to the named object and
 * return the reply message. */
static DBusMessage *
query_prop(enum cm_tdbus_type which,
	   const char *path, const char *interface, const char *prop,
	   int verbose)
{
	DBusMessage *req;
	req = prep_req(which, path, DBUS_INTERFACE_PROPERTIES, "Get");
	cm_tdbusm_set_ss(req, interface, prop);
	return send_req(req, verbose);
}

/* Read a string property. */
static char *
query_prop_s(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *prop,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	char *s;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_vs(rep, parent, &s) != 0) {
		s = "";
	}
	dbus_message_unref(rep);
	return s;
}

/* Read an array-of-strings property. */
static char **
query_prop_as(enum cm_tdbus_type which,
	      const char *path, const char *interface, const char *prop,
	      int verbose,
	      void *parent)
{
	DBusMessage *rep;
	char **as;
	rep = query_prop(which, path, interface, prop, verbose);
	if (cm_tdbusm_get_as(rep, parent, &as) != 0) {
		as = NULL;
	}
	dbus_message_unref(rep);
	return as;
}

/* Read a numeric property. */
static long
query_prop_n(enum cm_tdbus_type which,
	     const char *path, const char *interface, const char *prop,
	     int verbose,
	     void *parent)
{
	DBusMessage *rep;
	DBusMessage *res;
	long n;
	rep = prep_req(which, path, DBUS_INTERFACE_PROPERTIES, "Get");
	cm_tdbusm_set_ss(rep, interface, prop);
	res = send_req(rep, verbose);
	if (cm_tdbusm_get_vn(res, parent, &n) != 0) {
		n = 0;
	}
	dbus_message_unref(res);
	return n;
}

/* Evaluate a single request's status. */
static int
evaluate_status(const char *state, dbus_bool_t stuck)
{
	if (strcmp(state,
		   cm_store_state_as_string(CM_MONITORING)) == 0) {
		return CM_SUBMIT_STATUS_ISSUED;
	}
	if (strcmp(state,
		   cm_store_state_as_string(CM_CA_REJECTED)) == 0) {
		return CM_SUBMIT_STATUS_REJECTED;
	}
	if (strcmp(state,
		   cm_store_state_as_string(CM_CA_WORKING)) == 0) {
		return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
	}
	if (strcmp(state,
		   cm_store_state_as_string(CM_CA_UNREACHABLE)) == 0) {
		return CM_SUBMIT_STATUS_UNREACHABLE;
	}
	if (stuck) {
		return CM_SUBMIT_STATUS_UNCONFIGURED;
	}
	return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
}

/* Read the status of a single request, and return a status value. */
static int
waitfor(void *parent, enum cm_tdbus_type bus, const char *path, int timeout,
	int verbose)
{
	DBusMessage *rep;
	char *state, *old_state = NULL;
	dbus_bool_t stuck;
	int i = 0;

	while (timeout != 0) {
		rep = query_rep(bus, path, CM_DBUS_REQUEST_INTERFACE,
				"get_status", verbose);
		if (cm_tdbusm_get_sb(rep, globals.tctx, &state, &stuck) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		if (verbose &&
		    ((old_state == NULL) || (strcmp(old_state, state) != 0))) {
			printf(_("State %s, stuck: %s.\n"),
			       state, stuck ? "yes" : "no");
		}
		if (strcmp(state,
			   cm_store_state_as_string(CM_MONITORING)) == 0) {
			return CM_SUBMIT_STATUS_ISSUED;
		}
		if (strcmp(state,
			   cm_store_state_as_string(CM_CA_REJECTED)) == 0) {
			return CM_SUBMIT_STATUS_REJECTED;
		}
		if (strcmp(state,
			   cm_store_state_as_string(CM_CA_WORKING)) == 0) {
			return CM_SUBMIT_STATUS_WAIT_WITH_DELAY;
		}
		if (strcmp(state,
			   cm_store_state_as_string(CM_CA_UNREACHABLE)) == 0) {
			return CM_SUBMIT_STATUS_UNREACHABLE;
		}
		if (stuck) {
			return CM_SUBMIT_STATUS_UNCONFIGURED;
		}
		old_state = talloc_strdup(parent, state);
		/* FIXME: we should be waiting for signals that the state
		 * property has changed and then asking if we're stuck, not
		 * just polling using a timer.  But that would require a whole
		 * event loop. */
		usleep(125000);
		if (timeout > 0) {
			i++;
			if ((i % 8) == 0) {
				timeout--;
				i = 0;
			}
		}
	}
	return CM_SUBMIT_STATUS_WAIT;
}

/* Add a new request. */
static int
request(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char subject_default[LINE_MAX];
	char *nss_scheme, *dbdir = NULL, *token = NULL, *nickname = NULL;
	char *keytype = NULL, *keyfile = NULL, *certfile = NULL, *capath;
	char **anchor_dbs = NULL, **anchor_files = NULL;
	char *pin = NULL, *pinfile = NULL, *cpass = NULL, *cpassfile = NULL;
	int keysize = 0, auto_renew = 1, verbose = 0, ku = 0, kubit, c, i, j;
	char *ca = DEFAULT_CA, *subject = NULL, **eku = NULL, *oid, *id = NULL;
	char *profile = NULL, *issuer = NULL, kustring[16];
	char *ms_template_spec = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL, **ipaddr = NULL;
	char *key_owner = NULL, *key_perms = NULL;
	char *cert_owner = NULL, *cert_perms = NULL;
	char *nss_user = NULL;
	struct cm_tdbusm_dict param[52];
	const struct cm_tdbusm_dict *params[51];
	DBusMessage *req, *rep;
	int waitreq = 0, timeout = -1;
	int is_ca = 0, path_length = -1;
	dbus_bool_t b;
	char *p;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprinc;
	char *krealm, *kuprinc, *precommand = NULL, *postcommand = NULL;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"keyfile", 'k', POPT_ARG_STRING, NULL, 'k', _("PEM file for private key"), HELP_TYPE_FILENAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate (only valid with -k)"), HELP_TYPE_FILENAME},
		{"pinfile", 'p', POPT_ARG_STRING, NULL, 'p', _("file which holds the private key encryption PIN"), HELP_TYPE_FILENAME},
		{"pin", 'P', POPT_ARG_STRING, NULL, 'P', _("private key encryption PIN"), NULL},
		{"key-owner", 'o', POPT_ARG_STRING, NULL, 'o', _("owner information for private key"), HELP_TYPE_USER},
		{"key-perms", 'm', POPT_ARG_STRING, NULL, 'm', _("file permissions for private key"), HELP_TYPE_MODE},
		{"cert-owner", 'O', POPT_ARG_STRING, NULL, 'O', _("owner information for certificate"), HELP_TYPE_USER},
		{"cert-perms", 'M', POPT_ARG_STRING, NULL, 'M', _("file permissions for certificate"), HELP_TYPE_MODE},
		{"nss-user", 'Z', POPT_ARG_STRING, NULL, 'Z', _("user to save NSS private and public keys as"), HELP_TYPE_USER},
		{"ca-dbdir", 'a', POPT_ARG_STRING, NULL, 'a', _("NSS database in which to store the CA's certificates"), HELP_TYPE_DIRECTORY},
		{"ca-file", 'F', POPT_ARG_STRING, NULL, 'F', _("file in which to store the CA's certificates"), HELP_TYPE_FILENAME},
		{"before-command", 'B', POPT_ARG_STRING, NULL, 'B', _("command to run before saving the certificate"), HELP_TYPE_COMMAND},
		{"after-command", 'C', POPT_ARG_STRING, NULL, 'C', _("command to run after saving the certificate"), HELP_TYPE_COMMAND},
		{"id", 'I', POPT_ARG_STRING, NULL, 'I', _("nickname to assign to the request"), HELP_TYPE_ID},
		{"key-type", 'G', POPT_ARG_STRING, NULL, 'G', _("type of key to be generated if one is not already in place"), NULL},
		{"key-size", 'g', POPT_ARG_STRING, NULL, 'g', _("size of key to be generated if one is not already in place"), HELP_TYPE_KEYSIZE},
		{"renew", 'r', POPT_ARG_NONE, NULL, 'r', _("attempt to renew the certificate when expiration nears (default)"), NULL},
		{"no-renew", 'R', POPT_ARG_NONE, NULL, 'R', _("don't attempt to renew the certificate when expiration nears"), NULL},
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &ca, 0, _("use the specified CA configuration rather than the default"), HELP_TYPE_NAME},
#endif
		{"profile", 'T', POPT_ARG_STRING, NULL, 'T', _("ask the CA to process the request using the named profile or template"), HELP_TYPE_NAME},
		{"ms-template-spec", 0, POPT_ARG_STRING, NULL, 'Y', _("include V2 template specifier in CSR (format: OID:MAJOR-VERSION[:MINOR-VERSION])"), HELP_TYPE_NAME},
		{"issuer", 'X', POPT_ARG_STRING, NULL, 'X', _("ask the CA to process the request using the named issuer"), HELP_TYPE_NAME},
		{"subject-name", 'N', POPT_ARG_STRING, NULL, 'N', _("set requested subject name (default: CN=<hostname>)"), HELP_TYPE_SUBJECT},
		{"key-usage", 'u', POPT_ARG_STRING, NULL, 'u', _("set requested key usage value"), HELP_TYPE_KU},
		{"extended-key-usage", 'U', POPT_ARG_STRING, NULL, 'U', _("set requested extended key usage OID"), HELP_TYPE_EKU},
		{"principal", 'K', POPT_ARG_STRING, NULL, 'K', _("set requested principal name"), HELP_TYPE_PRINCIPAL},
		{"dns", 'D', POPT_ARG_STRING, NULL, 'D', _("set requested DNS name"), HELP_TYPE_HOSTNAME},
		{"email", 'E', POPT_ARG_STRING, NULL, 'E', _("set requested email address"), HELP_TYPE_EMAIL},
		{"ip-address", 'A', POPT_ARG_STRING, NULL, 'A', _("set requested IP address"), HELP_TYPE_IP},
		{"challenge-password-file", 'l', POPT_ARG_STRING, NULL, 'l', _("file which holds an optional challenge password value"), HELP_TYPE_FILENAME},
		{"challenge-password", 'L', POPT_ARG_STRING, NULL, 'L', _("an optional challenge password value"), NULL},
		{"for-ca", 0, POPT_ARG_VAL, &is_ca, 1, _("request a CA certificate"), NULL},
		{"not-for-ca", 0, POPT_ARG_VAL, &is_ca, 0, _("request a non-CA certificate"), NULL},
		{"ca-path-length", 0, POPT_ARG_INT, &path_length, 0, _("path length for CA certificate"), NULL},
		{"wait", 'w', POPT_ARG_NONE, NULL, 'w', _("try to wait for the certificate to be issued"), NULL},
		{"wait-timeout", 0, POPT_ARG_INT, &timeout, 0, _("maximum time to wait for the certificate to be issued"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	memset(subject_default, '\0', sizeof(subject_default));
	strcpy(subject_default, "CN=");
	if (gethostname(subject_default + 3,
			sizeof(subject_default) - 4) != 0) {
		strcpy(subject_default, "CN=localhost");
	}
	subject = subject_default;

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}
	krealm = NULL;
	if (krb5_get_default_realm(kctx, &krealm) != 0) {
		krealm = NULL;
	}

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "request");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'k':
			keyfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'o':
			key_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'm':
			key_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'O':
			cert_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'M':
			cert_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'G':
			if ((strcasecmp(poptarg, "RSA") != 0)
#ifdef CM_ENABLE_DSA
			    && (strcasecmp(poptarg, "DSA") != 0)
#endif
#ifdef CM_ENABLE_EC
			    && (strcasecmp(poptarg, "ECDSA") != 0)
			    && (strcasecmp(poptarg, "EC") != 0)
#endif
#ifdef CM_ENABLE_ML_DSA
			    && (strcasecmp(poptarg, "MLDSA") != 0)
			    && (strcasecmp(poptarg, "ML-DSA") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-44") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-65") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-87") != 0)
#endif
			    ) {
				printf(_("No support for generating \"%s\" keys.\n"),
				       poptarg);
				printf(_("Known key types include:"));
				printf(" RSA");
#ifdef CM_ENABLE_DSA
				printf(" DSA");
#endif
#ifdef CM_ENABLE_EC
				printf(" EC");
#endif
#ifdef CM_ENABLE_ML_DSA
				printf(" MLDSA ML-DSA ML-DSA-44 ML-DSA-65 ML-DSA-87");
#endif
				printf("\n");
				return 1;
			}
			keytype = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'g':
			keysize = atoi(poptarg);
			break;
		case 'I':
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'r':
			auto_renew++;
			break;
		case 'R':
			auto_renew = 0;
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'T':
			profile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Y':
			ms_template_spec = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'X':
			issuer = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Z':
			nss_user = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'N':
			subject = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'u':
			kubit = cm_ku_from_name(poptarg);
			if (kubit == -1) {
				printf(_("Unrecognized keyUsage \"%s\".\n"),
				       poptarg);
				return 1;
			}
			ku |= (1 << kubit);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, poptarg);
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
				printf(_("Could not evaluate OID \"%s\".\n"),
				       poptarg);
				return 1;
			}
			add_string(globals.tctx, &eku, oid);
			break;
		case 'K':
			kprinc = NULL;
			if (strlen(poptarg) > 0) {
				if ((kret = krb5_parse_name(kctx, poptarg,
							    &kprinc)) != 0) {
					printf(_("Error parsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				kuprinc = NULL;
				if ((kret = krb5_unparse_name(kctx, kprinc,
							      &kuprinc)) != 0) {
					printf(_("Error unparsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				add_string(globals.tctx, &principal, kuprinc);
				krb5_free_principal(kctx, kprinc);
			} else {
				add_string(globals.tctx, &principal, "");
			}
			break;
		case 'D':
			add_string(globals.tctx, &dns, poptarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, poptarg);
			break;
		case 'A':
			add_string(globals.tctx, &ipaddr, poptarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'p':
			pinfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'P':
			pin = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'l':
			cpassfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'L':
			cpass = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'B':
			precommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'C':
			postcommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'a':
			p = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (p != NULL)) {
				p = talloc_asprintf(globals.tctx, "%s:%s",
						    nss_scheme, p);
			}
			if (p != NULL) {
				add_string(globals.tctx, &anchor_dbs, p);
			} else {
				fprintf(stderr,
					_("%s: invalid value -- '%s'\n"),
					"request", poptarg);
				help(argv0, "request");
				return 1;
			}
			break;
		case 'F':
			add_string(globals.tctx, &anchor_files,
				   ensure_pem(globals.tctx, poptarg));
			break;
		case 'w':
			waitreq++;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"request", optopt);
			} else {
				fprintf(stderr,
					_("%s: invalid option -- '%c'\n"),
					"request", optopt);
			}
			help(argv0, "request");
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "request");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		while (poptPeekArg(pctx) != NULL) {
			printf(_("Error: unused extra argument \"%s\".\n"),
			       poptGetArg(pctx));
		}
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "request");
		return 1;
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf(_("Database location or nickname specified "
			 "without the other.\n"));
		help(argv0, "request");
		return 1;
	}
	if ((dbdir != NULL) && (certfile != NULL)) {
		printf(_("Database directory and certificate file "
			 "both specified.\n"));
		help(argv0, "request");
		return 1;
	}
	/* With none of them, the daemon keeps the key in a TPM token of its
	 * own, but only for a CA which wants keys that the TPM attests. */
	if ((dbdir == NULL) &&
	    (nickname == NULL) &&
	    (certfile == NULL)) {
		switch (ca_attests_with_tpm(bus, ca, verbose, argc, argv)) {
		case 1:
			break;
		case -1:
			printf(_("No CA with name \"%s\" found.\n"), ca);
			return 1;
		case 0:
			if (ca != NULL) {
				printf(_("The CA \"%s\" doesn't have keys "
					 "attested by the TPM, so a database "
					 "directory and nickname or a "
					 "certificate file must be "
					 "specified.\n"), ca);
			} else {
				printf(_("None of database directory and "
					 "nickname or certificate file "
					 "specified.\n"));
			}
			help(argv0, "request");
			return 1;
		}
	}
	if ((certfile != NULL) && (keyfile != NULL) &&
	    (strcmp(certfile, keyfile) == 0)) {
		printf(_("Key and certificate can not both be saved to the "
			 "same file.\n"));
		help(argv0, "request");
		return 1;
	}
	prep_bus(bus, "request", verbose, argc, argv);
	i = 0;
	/* If the caller supplied _no_ naming information, substitute our own
	 * defaults. */
	if ((subject == subject_default) &&
	    (eku == NULL) &&
	    (principal == NULL) &&
	    (dns == NULL) &&
	    (email == NULL) &&
	    (ipaddr == NULL)) {
		add_string(globals.tctx, &eku, "id-kp-serverAuth");
		if (krealm != NULL) {
			add_string(globals.tctx, &principal,
				   talloc_asprintf(globals.tctx,
						   "host/%s@%s",
						   subject + 3, krealm));
		}
		add_string(globals.tctx, &dns, subject + 3);
	}
#ifdef WITH_IPA
	if ((ca != NULL) && (strcmp(ca, "IPA") == 0)) {
		if (principal == NULL) {
			printf(_("The IPA backend requires the use of the -K option (principal name) when any of the -N (subject name), -E (email address), -A (IP address), -D (DNS name), or -U (extendedKeyUsage) options is used.\n"));
			help(argv0, "request");
			return 1;
		}
	}
#endif
#ifdef CM_ENABLE_ML_DSA
	if ((keytype != NULL) && ((strcasecmp(keytype, "ML-DSA") == 0) ||
							  (strcasecmp(keytype, "MLDSA") == 0))) {
		talloc_free(keytype);
		switch(keysize) {
		case 44:
			keytype = talloc_strdup(globals.tctx, "ML-DSA-44");
			break;
		case 65:
			keytype = talloc_strdup(globals.tctx, "ML-DSA-65");
			break;
		case 87:
			keytype = talloc_strdup(globals.tctx, "ML-DSA-87");
			break;
		default:
			keytype = talloc_strdup(globals.tctx, "ML-DSA-65");
			break;
		}
	}
#endif
	if ((dbdir != NULL) && (nickname != NULL)) {
		param[i].key = "KEY_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "KEY_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "CERT_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
	} else
	if (certfile != NULL) {
		if (keyfile != NULL) {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "FILE";
			params[i] = &param[i];
			i++;
			param[i].key = "KEY_LOCATION";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = keyfile;
			params[i] = &param[i];
			i++;
		} else {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "NONE";
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "FILE";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = certfile;
		params[i] = &param[i];
		i++;
	}
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
		params[i] = &param[i];
		i++;
	}
	if (cpass != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpass;
		params[i] = &param[i];
		i++;
	}
	if (cpassfile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpassfile;
		params[i] = &param[i];
		i++;
	}
	param[i].key = CM_DBUS_PROP_TEMPLATE_IS_CA;
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = is_ca;
	params[i] = &param[i];
	i++;
	param[i].key = CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH;
	param[i].value_type = cm_tdbusm_dict_n;
	param[i].value.n = path_length;
	params[i] = &param[i];
	i++;
	param[i].key = "TRACK";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = TRUE;
	params[i] = &param[i];
	i++;
	param[i].key = "RENEW";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = auto_renew > 0;
	params[i] = &param[i];
	i++;
	if (key_owner != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = key_owner;
		params[i] = &param[i];
		i++;
	}
	if (key_perms != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(key_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (cert_owner != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cert_owner;
		params[i] = &param[i];
		i++;
	}
	if (cert_perms != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(cert_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (nss_user != NULL) {
		param[i].key = CM_DBUS_PROP_NSS_USER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nss_user;
		params[i] = &param[i];
		i++;
	}
	if (keytype != NULL) {
		param[i].key = "KEY_TYPE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = keytype;
		params[i] = &param[i];
		i++;
	}
	if (keysize > 0) {
		param[i].key = "KEY_SIZE";
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = keysize;
		params[i] = &param[i];
		i++;
	}
	if (id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = id;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			return 1;
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
		param[i].value.s = capath;
		params[i] = &param[i];
		i++;
	} else {
		capath = NULL;
	}
	param[i].key = CM_DBUS_PROP_TEMPLATE_SUBJECT;
	param[i].value_type = cm_tdbusm_dict_s;
	param[i].value.s = subject;
	params[i] = &param[i];
	i++;
	if (principal != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = principal;
		params[i] = &param[i];
		i++;
	}
	if (dns != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_HOSTNAME;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = dns;
		params[i] = &param[i];
		i++;
	}
	if (email != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_EMAIL;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = email;
		params[i] = &param[i];
		i++;
	}
	if (ipaddr != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_IP_ADDRESS;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = ipaddr;
		params[i] = &param[i];
		i++;
	}
	if (ku != 0) {
		for (j = 0; (ku >> j) != 0; j++) {
			kustring[j] = ((ku >> j) & 1) ? '1' : '0';
		}
		kustring[j] = '\0';
		param[i].key = CM_DBUS_PROP_TEMPLATE_KU;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = kustring;
		params[i] = &param[i];
		i++;
	}
	if (eku != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_EKU;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = eku;
		params[i] = &param[i];
		i++;
	}
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (ms_template_spec != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = ms_template_spec;
		params[i] = &param[i];
		i++;
	}
	if (issuer != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_ISSUER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = issuer;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
		params[i] = &param[i];
		i++;
	}
	if (anchor_files != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_FILES;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_files;
		params[i] = &param[i];
		i++;
	}
	if (anchor_dbs != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_NSSDBS;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_dbs;
		params[i] = &param[i];
		i++;
	}
	params[i] = NULL;
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_request");
	if (cm_tdbusm_set_d(req, params) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_request_name(globals.tctx, bus, p, verbose);
		printf(_("New signing request \"%s\" added.\n"),
		       nickname ? nickname : p);
		if (waitreq) {
			return waitfor(globals.tctx, bus, p, timeout, verbose);
		}
	} else {
		printf(_("New signing request could not be added.\n"));
		exit(1);
	}
	return 0;
}

static char *
find_request_name(void *parent, enum cm_tdbus_type bus, const char *path,
		  int verbose)
{
	return query_rep_s(bus, path, CM_DBUS_REQUEST_INTERFACE, "get_nickname",
			   verbose, parent);
}

static char *
find_ca_name(void *parent, enum cm_tdbus_type bus, const char *path,
	     int verbose)
{
	return query_rep_s(bus, path, CM_DBUS_CA_INTERFACE, "get_nickname",
			   verbose, parent);
}

static char *
find_request_by_name(void *parent, enum cm_tdbus_type bus, const char *name,
		     int verbose)
{
	char **requests;
	int i, which;
	char *thisname;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		thisname = find_request_name(parent, bus, requests[i], verbose);
		if (thisname != NULL) {
			if (strcasecmp(name, thisname) == 0) {
				which = i;
			}
			talloc_free(thisname);
		}
	}
	if (which != -1) {
		return requests[which];
	}
	return NULL;
}

static const char *
find_request_by_storage(void *parent, enum cm_tdbus_type bus,
			const char *dbdir,
			const char *nickname,
			const char *token,
			const char *certfile,
			int verbose)
{
	char **requests;
	int i, which;
	char *cert_stype, *cert_sloc, *cert_nick, *cert_tok;
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	which = -1;
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		query_rep_sososos(bus, requests[i],
				  CM_DBUS_REQUEST_INTERFACE,
				  "get_cert_storage_info",
				  verbose, parent,
				  &cert_stype, &cert_sloc,
				  &cert_nick, &cert_tok);
		if (strcasecmp(cert_stype, "NSSDB") == 0) {
			if (dbdir == NULL) {
				continue;
			}
			if ((cert_sloc == NULL) ||
			    (strcmp(dbdir, cert_sloc) != 0)) {
				continue;
			}
			if (nickname == NULL) {
				continue;
			}
			if ((cert_nick == NULL) ||
			    (strcmp(nickname, cert_nick) != 0)) {
				continue;
			}
			if ((token != NULL) &&
			    ((cert_tok == NULL) ||
			     (strcmp(token, cert_tok) != 0))) {
				continue;
			}
		} else
		if (strcasecmp(cert_stype, "FILE") == 0) {
			if (certfile == NULL) {
				continue;
			}
			if (strcmp(certfile, cert_sloc) != 0) {
				continue;
			}
		}
		if (which != -1) {
			/* Multiple matches? We have to give up. */
			return NULL;
		}
		which = i;
	}
	if (which != -1) {
		return requests[which];
	}
	return NULL;
}

static char *
find_ca_by_name(void *parent, enum cm_tdbus_type bus, const char *name,
		int verbose)
{
	char **cas;
	int i, which;
	char *thisname;
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", verbose, globals.tctx);
	which = -1;
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		thisname = find_ca_name(parent, bus, cas[i], verbose);
		if (thisname != NULL) {
			if (strcasecmp(name, thisname) == 0) {
				which = i;
			}
			talloc_free(thisname);
		}
	}
	if (which != -1) {
		return cas[which];
	}
	return NULL;
}

/* Whether the named CA answers device-attest-01 challenges with a TPM
 * attestation: 1 if it does, 0 if it doesn't or none is named, -1 if
 * there is no CA of that name. */
static int
ca_attests_with_tpm(enum cm_tdbus_type bus, const char *ca, int verbose,
		    int argc, const char **argv)
{
	char *capath, *helper;

	if (ca == NULL) {
		return 0;
	}
	prep_bus(bus, "request", verbose, argc, argv);
	capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
	if (capath == NULL) {
		return -1;
	}
	helper = query_prop_s(bus, capath, CM_DBUS_CA_INTERFACE,
			      CM_DBUS_PROP_EXTERNAL_HELPER, verbose,
			      globals.tctx);
	return cm_tpm_token_helper_attests(helper);
}

static int
add_basic_request(enum cm_tdbus_type bus, char *id,
		  char *dbdir, char *nickname, char *token,
		  char *keyfile, char *certfile,
		  char *key_owner, char *cert_owner,
		  char *key_perms, char *cert_perms,
		  char *nss_user,
		  char *pin, char *pinfile,
		  char *cpass, char *cpassfile,
		  char *ca, char *profile, char *issuer,
		  char *ms_template_spec,
		  char **principal,
		  char *precommand, char *postcommand,
		  char **anchor_dbs, char **anchor_files,
		  int is_ca, int path_length,
		  dbus_bool_t auto_renew_stop, int waitreq,
		  int timeout, int verbose)
{
	DBusMessage *req, *rep;
	int i;
	struct cm_tdbusm_dict param[32];
	const struct cm_tdbusm_dict *params[32];
	dbus_bool_t b;
	const char *capath;
	char *p;
	i = 0;
	if (id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = id;
		params[i] = &param[i];
		i++;
	}
	if ((dbdir != NULL) && (nickname != NULL)) {
		param[i].key = "KEY_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "KEY_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "KEY_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "NSSDB";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = dbdir;
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nickname;
		params[i] = &param[i];
		i++;
		if (token != NULL) {
			param[i].key = "CERT_TOKEN";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = token;
			params[i] = &param[i];
			i++;
		}
		if (nss_user != NULL) {
			param[i].key = CM_DBUS_PROP_NSS_USER;
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = nss_user;
			params[i] = &param[i];
			i++;
		}
	} else
	if (certfile != NULL) {
		if (keyfile != NULL) {
			param[i].key = "KEY_STORAGE";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = "FILE";
			params[i] = &param[i];
			i++;
			param[i].key = "KEY_LOCATION";
			param[i].value_type = cm_tdbusm_dict_s;
			param[i].value.s = keyfile;
			params[i] = &param[i];
			i++;
		}
		param[i].key = "CERT_STORAGE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = "FILE";
		params[i] = &param[i];
		i++;
		param[i].key = "CERT_LOCATION";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = certfile;
		params[i] = &param[i];
		i++;
	}
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
		params[i] = &param[i];
		i++;
	}
	if (key_owner != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = key_owner;
		params[i] = &param[i];
		i++;
	}
	if (key_perms != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(key_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (cert_owner != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cert_owner;
		params[i] = &param[i];
		i++;
	}
	if (cert_perms != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(cert_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (cpass != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpass;
		params[i] = &param[i];
		i++;
	}
	if (cpassfile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpassfile;
		params[i] = &param[i];
		i++;
	}
	param[i].key = CM_DBUS_PROP_TEMPLATE_IS_CA;
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = is_ca;
	params[i] = &param[i];
	i++;
	param[i].key = CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH;
	param[i].value_type = cm_tdbusm_dict_n;
	param[i].value.n = path_length;
	params[i] = &param[i];
	i++;
	param[i].key = "TRACK";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = TRUE;
	params[i] = &param[i];
	i++;
	param[i].key = "RENEW";
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = !auto_renew_stop;
	params[i] = &param[i];
	i++;
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (ms_template_spec != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = ms_template_spec;
		params[i] = &param[i];
		i++;
	}
	if (principal != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = principal;
		params[i] = &param[i];
		i++;
	}
	if (issuer != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_ISSUER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = issuer;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			return 1;
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
		param[i].value.s = talloc_strdup(globals.tctx, capath);
		params[i] = &param[i];
		i++;
	} else {
		capath = NULL;
	}
	if (anchor_files != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_FILES;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_files;
		params[i] = &param[i];
		i++;
	}
	if (anchor_dbs != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_NSSDBS;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_dbs;
		params[i] = &param[i];
		i++;
	}
	params[i] = NULL;
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_request");
	if (cm_tdbusm_set_d(req, params) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_request_name(globals.tctx, bus, p, verbose);
		printf(_("New tracking request \"%s\" added.\n"),
		       nickname ? nickname : p);
		if (waitreq) {
			return waitfor(globals.tctx, bus, p, timeout, verbose);
		}
		return 0;
	} else {
		printf(_("New tracking request could not be added.\n"));
		return 1;
	}
}

static int
set_tracking(const char *argv0, const char *category,
	     int argc, const char **argv, dbus_bool_t track)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *req, *rep;
	const char *request, *capath;
	struct cm_tdbusm_dict param[29];
	const struct cm_tdbusm_dict *params[30];
	char *nss_scheme, *dbdir = NULL, *token = NULL, *nickname = NULL;
	char **anchor_dbs = NULL, **anchor_files = NULL;
	char *id = NULL, *new_id = NULL, *new_request;
	char *keyfile = NULL, *certfile = NULL, *ca = DEFAULT_CA;
	char *profile = NULL, *issuer = NULL;
	char *ms_template_spec = NULL;
	char *pin = NULL, *pinfile = NULL, *cpass = NULL, *cpassfile = NULL;
	char *key_owner = NULL, *key_perms = NULL;
	char *nss_user = NULL;
	char *cert_owner = NULL, *cert_perms = NULL;
	dbus_bool_t b;
	char *p;
	int c, auto_renew_start = 0, auto_renew_stop = 0, verbose = 0, i, j;
	int ku = 0, kubit, waitreq = 0, timeout = -1;
	int is_ca = 0, path_length = -1;
	char **eku = NULL, *oid, kustring[16];
	char **principal = NULL, **dns = NULL, **email = NULL, **ipaddr = NULL;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprinc;
	char *krealm, *kuprinc;
	char *precommand = NULL, *postcommand = NULL;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"keyfile", 'k', POPT_ARG_STRING, NULL, 'k', _("PEM file for private key (only valid with -f)"), HELP_TYPE_FILENAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate"), HELP_TYPE_FILENAME},
		{"pinfile", 'p', POPT_ARG_STRING, NULL, 'p', _("file which holds the private key encryption PIN"), HELP_TYPE_FILENAME},
		{"pin", 'P', POPT_ARG_STRING, NULL, 'P', _("private key encryption PIN"), NULL},
		{"key-owner", 'o', POPT_ARG_STRING, NULL, 'o', _("owner information for private key"), HELP_TYPE_USER},
		{"key-perms", 'm', POPT_ARG_STRING, NULL, 'm', _("file permissions for private key"), HELP_TYPE_MODE},
		{"cert-owner", 'O', POPT_ARG_STRING, NULL, 'O', _("owner information for certificate"), HELP_TYPE_USER},
		{"cert-perms", 'M', POPT_ARG_STRING, NULL, 'M', _("file permissions for certificate"), HELP_TYPE_MODE},
		{"nss-user", 'Z', POPT_ARG_STRING, NULL, 'Z', _("user to save NSS private and public keys as"), HELP_TYPE_USER},
		{"ca-dbdir", 'a', POPT_ARG_STRING, NULL, 'a', _("NSS database in which to store the CA's certificates"), HELP_TYPE_DIRECTORY},
		{"ca-file", 'F', POPT_ARG_STRING, NULL, 'F', _("file in which to store the CA's certificates"), HELP_TYPE_FILENAME},
		{"before-command", 'B', POPT_ARG_STRING, NULL, 'B', _("command to run before saving the certificate"), HELP_TYPE_COMMAND},
		{"after-command", 'C', POPT_ARG_STRING, NULL, 'C', _("command to run after saving the certificate"), HELP_TYPE_COMMAND},
		{"id", 'i', POPT_ARG_STRING, NULL, 'i', _("nickname of an existing request"), HELP_TYPE_ID},
		{"new-id", 'I', POPT_ARG_STRING, NULL, 'I', _("nickname to give to tracking request"), HELP_TYPE_ID},
		{"renew", 'r', POPT_ARG_NONE, NULL, 'r', _("attempt to renew the certificate when expiration nears (default)"), NULL},
		{"no-renew", 'R', POPT_ARG_NONE, NULL, 'R', _("don't attempt to renew the certificate when expiration nears"), NULL},
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &ca, 0, _("use the specified CA configuration rather than the default"), HELP_TYPE_NAME},
#endif
		{"profile", 'T', POPT_ARG_STRING, NULL, 'T', _("ask the CA to process the request using the named profile or template"), HELP_TYPE_NAME},
		{"ms-template-spec", 0, POPT_ARG_STRING, NULL, 'Y', _("include V2 template specifier in CSR (format: OID:MAJOR-VERSION[:MINOR-VERSION])"), HELP_TYPE_NAME},
		{"issuer", 'X', POPT_ARG_STRING, NULL, 'X', _("ask the CA to process the request using the named issuer"), HELP_TYPE_NAME},
		{"key-usage", 'u', POPT_ARG_STRING, NULL, 'u', _("override requested key usage value"), HELP_TYPE_KU},
		{"extended-key-usage", 'U', POPT_ARG_STRING, NULL, 'U', _("override requested extended key usage OID"), HELP_TYPE_EKU},
		{"principal", 'K', POPT_ARG_STRING, NULL, 'K', _("override requested principal name"), HELP_TYPE_PRINCIPAL},
		{"dns", 'D', POPT_ARG_STRING, NULL, 'D', _("override requested DNS name"), HELP_TYPE_HOSTNAME},
		{"email", 'E', POPT_ARG_STRING, NULL, 'E', _("override requested email address"), HELP_TYPE_EMAIL},
		{"ip-address", 'A', POPT_ARG_STRING, NULL, 'A', _("override requested IP address"), HELP_TYPE_IP},
		{"challenge-password-file", 'l', POPT_ARG_STRING, NULL, 'l', _("file which holds an optional challenge password value"), HELP_TYPE_FILENAME},
		{"challenge-password", 'L', POPT_ARG_STRING, NULL, 'L', _("an optional challenge password value"), NULL},
		{"for-ca", 0, POPT_ARG_VAL, &is_ca, 1, _("request a CA certificate"), NULL},
		{"not-for-ca", 0, POPT_ARG_VAL, &is_ca, 0, _("request a non-CA certificate"), NULL},
		{"ca-path-length", 0, POPT_ARG_INT, &path_length, 0, _("path length for CA certificate"), NULL},
		{"wait", 'w', POPT_ARG_NONE, NULL, 'w', _("try to wait for the certificate to be issued"), NULL},
		{"wait-timeout", 0, POPT_ARG_INT, &timeout, 0, _("maximum time to wait for the certificate to be issued"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}
	krealm = NULL;
	if (krb5_get_default_realm(kctx, &krealm) != 0) {
		krealm = NULL;
	}

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, category);
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'k':
			keyfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'o':
			key_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'm':
			key_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'O':
			cert_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'M':
			cert_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'r':
			if (track) {
				auto_renew_start++;
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'R':
			if (track) {
				auto_renew_stop++;
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'c':
			if (track) {
				ca = talloc_strdup(globals.tctx, poptarg);
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'T':
			profile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Y':
			ms_template_spec = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'X':
			issuer = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Z':
			nss_user = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'I':
			new_id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'u':
			kubit = cm_ku_from_name(poptarg);
			if (kubit == -1) {
				printf(_("Unrecognized keyUsage \"%s\".\n"),
				       poptarg);
				return 1;
			}
			ku |= (1 << kubit);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, poptarg);
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
				printf(_("Could not evaluate OID \"%s\".\n"),
				       poptarg);
				return 1;
			}
			add_string(globals.tctx, &eku, oid);
			break;
		case 'K':
			kprinc = NULL;
			if (strlen(poptarg) > 0) {
				if ((kret = krb5_parse_name(kctx, poptarg,
							    &kprinc)) != 0) {
					printf(_("Error parsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				kuprinc = NULL;
				if ((kret = krb5_unparse_name(kctx, kprinc,
							      &kuprinc)) != 0) {
					printf(_("Error unparsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				add_string(globals.tctx, &principal, kuprinc);
				krb5_free_principal(kctx, kprinc);
			} else {
				add_string(globals.tctx, &principal, "");
			}
			break;
		case 'D':
			add_string(globals.tctx, &dns, poptarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, poptarg);
			break;
		case 'A':
			add_string(globals.tctx, &ipaddr, poptarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'p':
			pinfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'P':
			pin = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'l':
			cpassfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'L':
			cpass = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'B':
			precommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'C':
			postcommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'a':
			p = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (p != NULL)) {
				p = talloc_asprintf(globals.tctx, "%s:%s",
						    nss_scheme, p);
			}
			if (p != NULL) {
				add_string(globals.tctx, &anchor_dbs, p);
			} else {
				fprintf(stderr,
					_("%s: invalid value -- '%s'\n"),
					"request", poptarg);
				help(argv0, "request");
				return 1;
			}
			break;
		case 'F':
			add_string(globals.tctx, &anchor_files,
				   ensure_pem(globals.tctx, poptarg));
			break;
		case 'w':
			if (track) {
				waitreq++;
			} else {
				help(argv0, category);
				return 1;
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					category, optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					category, optopt);
			}
			help(argv0, category);
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, category);
		return 1;
	}

	krb5_free_context(kctx);

	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, category);
		return 1;
	}
	if (((dbdir != NULL) && (nickname == NULL)) ||
	    ((dbdir == NULL) && (nickname != NULL))) {
		printf(_("Database location or nickname specified "
			 "without the other.\n"));
		help(argv0, category);
		return 1;
	}
	if ((dbdir != NULL) && (certfile != NULL)) {
		printf(_("Database directory and certificate file "
			 "both specified.\n"));
		help(argv0, category);
		return 1;
	}
	if ((id == NULL) &&
	    (dbdir == NULL) &&
	    (nickname == NULL) &&
	    (certfile == NULL)) {
		printf(_("None of ID or database directory and nickname or "
			 "certificate file specified.\n"));
		help(argv0, category);
		return 1;
	}
	if ((certfile != NULL) && (keyfile != NULL) &&
	    (strcmp(certfile, keyfile) == 0)) {
		printf(_("Key and certificate can not both be saved to the "
			 "same file.\n"));
		help(argv0, category);
		return 1;
	}
	prep_bus(bus, category, verbose, argc, argv);
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile, verbose);
	}
	if (track) {
		if (request != NULL) {
			/* Modify settings for an existing request. */
			i = 0;
			param[i].key = "TRACK";
			param[i].value_type = cm_tdbusm_dict_b;
			param[i].value.b = TRUE;
			params[i] = &param[i];
			i++;
			if (auto_renew_start || auto_renew_stop) {
				param[i].key = "RENEW";
				param[i].value_type = cm_tdbusm_dict_b;
				param[i].value.b = auto_renew_start > 0;
				params[i] = &param[i];
				i++;
			}
			if (principal != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = principal;
				params[i] = &param[i];
				i++;
			}
			if (dns != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_HOSTNAME;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = dns;
				params[i] = &param[i];
				i++;
			}
			if (email != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_EMAIL;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = email;
				params[i] = &param[i];
				i++;
			}
			if (ipaddr != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_IP_ADDRESS;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = ipaddr;
				params[i] = &param[i];
				i++;
			}
			if (ku != 0) {
				for (j = 0; (ku >> j) != 0; j++) {
					kustring[j] = ((ku >> j) & 1) ?
						      '1' : '0';
				}
				kustring[j] = '\0';
				param[i].key = CM_DBUS_PROP_TEMPLATE_KU;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = kustring;
				params[i] = &param[i];
				i++;
			}
			if (eku != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_EKU;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = eku;
				params[i] = &param[i];
				i++;
			}
			if (new_id != NULL) {
				param[i].key = "NICKNAME";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = new_id;
				params[i] = &param[i];
				i++;
			}
			if (key_owner != NULL) {
				param[i].key = CM_DBUS_PROP_KEY_OWNER;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = key_owner;
				params[i] = &param[i];
				i++;
			}
			if (key_perms != NULL) {
				param[i].key = CM_DBUS_PROP_KEY_PERMS;
				param[i].value_type = cm_tdbusm_dict_n;
				param[i].value.n = strtol(key_perms, NULL, 8);
				params[i] = &param[i];
				i++;
			}
			if (cert_owner != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_OWNER;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = cert_owner;
				params[i] = &param[i];
				i++;
			}
			if (cert_perms != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_PERMS;
				param[i].value_type = cm_tdbusm_dict_n;
				param[i].value.n = strtol(cert_perms, NULL, 8);
				params[i] = &param[i];
				i++;
			}
			if (nss_user != NULL) {
				param[i].key = CM_DBUS_PROP_NSS_USER;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = nss_user;
				params[i] = &param[i];
				i++;
			}
			if (pin != NULL) {
				param[i].key = "KEY_PIN";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = pin;
				params[i] = &param[i];
				i++;
			}
			if (pinfile != NULL) {
				param[i].key = "KEY_PIN_FILE";
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = pinfile;
				params[i] = &param[i];
				i++;
			}
			if (ca != NULL) {
				capath = find_ca_by_name(globals.tctx, bus, ca,
							 verbose);
				if (capath == NULL) {
					printf(_("No CA with name \"%s\" "
					       "found.\n"), ca);
					return 1;
				}
				param[i].key = "CA";
				param[i].value_type = cm_tdbusm_dict_p;
				param[i].value.s = talloc_strdup(globals.tctx,
								 capath);
				params[i] = &param[i];
				i++;
			} else {
				capath = NULL;
			}
			if (cpass != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = cpass;
				params[i] = &param[i];
				i++;
			}
			if (cpassfile != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = cpassfile;
				params[i] = &param[i];
				i++;
			}
			param[i].key = CM_DBUS_PROP_TEMPLATE_IS_CA;
			param[i].value_type = cm_tdbusm_dict_b;
			param[i].value.b = is_ca;
			params[i] = &param[i];
			i++;
			param[i].key = CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH;
			param[i].value_type = cm_tdbusm_dict_n;
			param[i].value.n = path_length;
			params[i] = &param[i];
			i++;
			if (profile != NULL) {
				param[i].key = CM_DBUS_PROP_TEMPLATE_PROFILE;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = profile;
				params[i] = &param[i];
				i++;
			}
			if (precommand != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = precommand;
				params[i] = &param[i];
				i++;
			}
			if (postcommand != NULL) {
				param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
				param[i].value_type = cm_tdbusm_dict_s;
				param[i].value.s = postcommand;
				params[i] = &param[i];
				i++;
			}
			if (anchor_files != NULL) {
				param[i].key = CM_DBUS_PROP_ROOT_CERT_FILES;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = anchor_files;
				params[i] = &param[i];
				i++;
			}
			if (anchor_dbs != NULL) {
				param[i].key = CM_DBUS_PROP_ROOT_CERT_NSSDBS;
				param[i].value_type = cm_tdbusm_dict_as;
				param[i].value.as = anchor_dbs;
				params[i] = &param[i];
				i++;
			}
			params[i] = NULL;
			req = prep_req(bus, request, CM_DBUS_REQUEST_INTERFACE,
				       "modify");
			if (cm_tdbusm_set_d(req, params) != 0) {
				printf(_("Error setting request arguments.\n"));
				exit(1);
			}
			rep = send_req(req, verbose);
			if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
					     &new_request) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			request = new_request;
			dbus_message_unref(rep);
			nickname = find_request_name(globals.tctx, bus,
						     request, verbose);
			if (b) {
				printf(_("Request \"%s\" modified.\n"),
				       nickname ? nickname : request);
				return 0;
			} else {
				printf(_("Request \"%s\" could not be "
					 "modified.\n"),
				       nickname ? nickname : request);
				return 1;
			}
		} else {
			/* Add a new request. */
			if (id != NULL) {
				printf(_("No request found with specified "
					 "nickname.\n"));
				help(argv0, category);
				return 1;
			}
			if (((dbdir != NULL) && (nickname == NULL)) ||
			    ((dbdir == NULL) && (nickname != NULL))) {
				printf(_("Database location or nickname "
					 "specified without the other.\n"));
				help(argv0, category);
				return 1;
			}
			if ((dbdir != NULL) && (certfile != NULL)) {
				printf(_("Database directory and certificate "
					 "file both specified.\n"));
				help(argv0, category);
				return 1;
			}
			if ((dbdir == NULL) &&
			    (nickname == NULL) &&
			    (certfile == NULL)) {
				printf(_("None of database directory and "
					 "nickname or certificate file "
					 "specified.\n"));
				help(argv0, category);
				return 1;
			}
			return add_basic_request(bus, new_id,
						 dbdir, nickname, token,
						 keyfile, certfile,
						 key_owner, cert_owner,
						 key_perms, cert_perms,
						 nss_user,
						 pin, pinfile,
						 cpass, cpassfile,
						 ca, profile, issuer,
						 ms_template_spec,
						 principal,
						 precommand, postcommand,
						 anchor_dbs, anchor_files,
						 is_ca, path_length,
						 (auto_renew_stop > 0),
						 waitreq, timeout, verbose);
		}
	} else {
		/* Drop a request. */
		if ((request == NULL) &&
		    (id == NULL) &&
		    (dbdir == NULL) &&
		    (nickname == NULL) &&
		    (certfile == NULL)) {
			help(argv0, category);
			return 1;
		}
		if (request == NULL) {
			printf(_("No request found that matched arguments.\n"));
			return 1;
		}
		nickname = find_request_name(globals.tctx, bus, request,
					     verbose);
		req = prep_req(bus, CM_DBUS_BASE_PATH,
			       CM_DBUS_BASE_INTERFACE,
			       "remove_request");
		if (cm_tdbusm_set_p(req, request) != 0) {
			printf(_("Error setting request arguments.\n"));
			exit(1);
		}
		rep = send_req(req, verbose);
		if (cm_tdbusm_get_b(rep, globals.tctx, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		if (b) {
			printf(_("Request \"%s\" removed.\n"),
			       nickname ? nickname : request);
			return 0;
		} else {
			printf(_("Request \"%s\" could not be removed.\n"),
			       nickname ? nickname : request);
			return 1;
		}
	}
}

static int
start_tracking(const char *argv0, int argc, const char **argv)
{
	return set_tracking(argv0, "start-tracking", argc, argv, TRUE);
}

static int
stop_tracking(const char *argv0, int argc, const char **argv)
{
	return set_tracking(argv0, "stop-tracking", argc, argv, FALSE);
}

static int
rekey_or_resubmit(const char *argv0, const char *category, int argc,
		  const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *req, *rep;
	const char *request;
	char *capath;
	struct cm_tdbusm_dict param[32];
	const struct cm_tdbusm_dict *params[33];
	char *dbdir = NULL, *token = NULL, *nickname = NULL, *certfile = NULL;
	char **anchor_dbs = NULL, **anchor_files = NULL;
	char *pin = NULL, *pinfile = NULL, *cpass = NULL, *cpassfile = NULL;
	char *id = NULL, *new_id = NULL, *ca = NULL, *new_request, *nss_scheme;
	char *subject = NULL, **eku = NULL, *oid = NULL;
	char **principal = NULL, **dns = NULL, **email = NULL, **ipaddr = NULL;
	char *profile = NULL, *issuer = NULL, kustring[16];
	char *ms_template_spec = NULL;
	char *key_owner = NULL, *key_perms = NULL;
	char *cert_owner = NULL, *cert_perms = NULL;
	char *nss_user = NULL;
	char *keytype = NULL;
	int keysize = 0;
	dbus_bool_t b;
	char *p;
	int verbose = 0, ku = 0, kubit, c, i, j, waitreq = 0, timeout = -1;
	int is_ca = 0, path_length = -1;
	krb5_context kctx;
	krb5_error_code kret;
	krb5_principal kprinc;
	char *kuprinc, *precommand = NULL, *postcommand = NULL;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate"), HELP_TYPE_FILENAME},
		{"id", 'i', POPT_ARG_STRING, NULL, 'i', _("nickname for tracking request"), HELP_TYPE_ID},
		{"new-id", 'I', POPT_ARG_STRING, NULL, 'I', _("new nickname to give to tracking request"), HELP_TYPE_ID},
		{"key-type", 'G', POPT_ARG_STRING, NULL, 'G', _("type of new key to be generated"), NULL},
		{"key-size", 'g', POPT_ARG_STRING, NULL, 'g', _("size of new key to be generated"), HELP_TYPE_KEYSIZE},
		{"pinfile", 'p', POPT_ARG_STRING, NULL, 'p', _("file which holds the private key encryption PIN"), HELP_TYPE_FILENAME},
		{"pin", 'P', POPT_ARG_STRING, NULL, 'P', _("private key encryption PIN"), NULL},
		{"key-owner", 'o', POPT_ARG_STRING, NULL, 'o', _("owner information for private key"), HELP_TYPE_USER},
		{"key-perms", 'm', POPT_ARG_STRING, NULL, 'm', _("file permissions for private key"), HELP_TYPE_MODE},
		{"cert-owner", 'O', POPT_ARG_STRING, NULL, 'O', _("owner information for certificate"), HELP_TYPE_USER},
		{"cert-perms", 'M', POPT_ARG_STRING, NULL, 'M', _("file permissions for certificate"), HELP_TYPE_MODE},
		{"nss-user", 'Z', POPT_ARG_STRING, NULL, 'Z', _("user to save NSS private and public keys as"), HELP_TYPE_USER},
		{"ca-dbdir", 'a', POPT_ARG_STRING, NULL, 'a', _("NSS database in which to store the CA's certificates"), HELP_TYPE_DIRECTORY},
		{"ca-file", 'F', POPT_ARG_STRING, NULL, 'F', _("file in which to store the CA's certificates"), HELP_TYPE_FILENAME},
		{"before-command", 'B', POPT_ARG_STRING, NULL, 'B', _("command to run before saving the certificate"), HELP_TYPE_COMMAND},
		{"after-command", 'C', POPT_ARG_STRING, NULL, 'C', _("command to run after saving the certificate"), HELP_TYPE_COMMAND},
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &ca, 0, _("use the specified CA configuration rather than the current one"), HELP_TYPE_NAME},
#endif
		{"profile", 'T', POPT_ARG_STRING, NULL, 'T', _("ask the CA to process the request using the named profile or template"), HELP_TYPE_NAME},
		{"ms-template-spec", 0, POPT_ARG_STRING, NULL, 'Y', _("include V2 template specifier in CSR (format: OID:MAJOR-VERSION[:MINOR-VERSION])"), HELP_TYPE_NAME},
		{"issuer", 'X', POPT_ARG_STRING, NULL, 'X', _("ask the CA to process the request using the named issuer"), HELP_TYPE_NAME},
		{"subject-name", 'N', POPT_ARG_STRING, NULL, 'N', _("set requested subject name (default: CN=<hostname>)"), HELP_TYPE_SUBJECT},
		{"key-usage", 'u', POPT_ARG_STRING, NULL, 'u', _("set requested key usage value"), HELP_TYPE_KU},
		{"extended-key-usage", 'U', POPT_ARG_STRING, NULL, 'U', _("set requested extended key usage OID"), HELP_TYPE_EKU},
		{"principal", 'K', POPT_ARG_STRING, NULL, 'K', _("set requested principal name"), HELP_TYPE_PRINCIPAL},
		{"dns", 'D', POPT_ARG_STRING, NULL, 'D', _("set requested DNS name"), HELP_TYPE_HOSTNAME},
		{"email", 'E', POPT_ARG_STRING, NULL, 'E', _("set requested email address"), HELP_TYPE_EMAIL},
		{"ip-address", 'A', POPT_ARG_STRING, NULL, 'A', _("set requested IP address"), HELP_TYPE_IP},
		{"challenge-password-file", 'l', POPT_ARG_STRING, NULL, 'l', _("file which holds an optional challenge password value"), HELP_TYPE_FILENAME},
		{"challenge-password", 'L', POPT_ARG_STRING, NULL, 'L', _("an optional challenge password value"), NULL},
		{"for-ca", 0, POPT_ARG_VAL, &is_ca, 1, _("request a CA certificate"), NULL},
		{"not-for-ca", 0, POPT_ARG_VAL, &is_ca, 0, _("request a non-CA certificate"), NULL},
		{"ca-path-length", 0, POPT_ARG_INT, &path_length, 0, _("path length for CA certificate"), NULL},
		{"wait", 'w', POPT_ARG_NONE, NULL, 'w', _("try to wait for the certificate to be issued"), NULL},
		{"wait-timeout", 0, POPT_ARG_INT, &timeout, 0, _("maximum time to wait for the certificate to be issued"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	kctx = NULL;
	if ((kret = krb5_init_context(&kctx)) != 0) {
		kctx = NULL;
		printf(_("Error initializing Kerberos library: %s.\n"),
		       error_message(kret));
		return 1;
	}

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, category);
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'n':
			nickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'o':
			key_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'm':
			key_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'O':
			cert_owner = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'M':
			cert_perms = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'c':
			ca = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'T':
			profile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Y':
			ms_template_spec = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'X':
			issuer = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'Z':
			nss_user = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'I':
			new_id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'G':
			if ((strcasecmp(poptarg, "RSA") != 0)
#ifdef CM_ENABLE_DSA
			    && (strcasecmp(poptarg, "DSA") != 0)
#endif
#ifdef CM_ENABLE_EC
			    && (strcasecmp(poptarg, "ECDSA") != 0)
			    && (strcasecmp(poptarg, "EC") != 0)
#endif
#ifdef CM_ENABLE_ML_DSA
			    && (strcasecmp(poptarg, "MLDSA") != 0)
			    && (strcasecmp(poptarg, "ML-DSA") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-44") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-65") != 0)
			    && (strcasecmp(poptarg, "ML-DSA-87") != 0)
#endif
			    ) {
				printf(_("No support for generating \"%s\" keys.\n"),
				       poptarg);
				printf(_("Known key types include:"));
				printf(" RSA");
#ifdef CM_ENABLE_DSA
				printf(" DSA");
#endif
#ifdef CM_ENABLE_EC
				printf(" EC");
#endif
				printf("\n");
				return 1;
			}
			keytype = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'g':
			keysize = atoi(poptarg);
			break;
		case 'N':
			subject = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'u':
			kubit = cm_ku_from_name(poptarg);
			if (kubit == -1) {
				printf(_("Unrecognized keyUsage \"%s\".\n"),
				       poptarg);
				return 1;
			}
			ku |= (1 << kubit);
			break;
		case 'U':
			oid = cm_oid_from_name(globals.tctx, poptarg);
			if ((oid == NULL) ||
			    (strspn(oid, "0123456789.") != strlen(oid))) {
				printf(_("Could not evaluate OID \"%s\".\n"),
				       poptarg);
				return 1;
			}
			add_string(globals.tctx, &eku, oid);
			break;
		case 'K':
			kprinc = NULL;
			if (strlen(poptarg) > 0) {
				if ((kret = krb5_parse_name(kctx, poptarg,
							    &kprinc)) != 0) {
					printf(_("Error parsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				kuprinc = NULL;
				if ((kret = krb5_unparse_name(kctx, kprinc,
							      &kuprinc)) != 0) {
					printf(_("Error unparsing Kerberos "
						 "principal name \"%s\": "
						 "%s.\n"), poptarg,
					       error_message(kret));
					return 1;
				}
				add_string(globals.tctx, &principal, kuprinc);
				krb5_free_principal(kctx, kprinc);
			} else {
				add_string(globals.tctx, &principal, "");
			}
			break;
		case 'D':
			add_string(globals.tctx, &dns, poptarg);
			break;
		case 'E':
			add_string(globals.tctx, &email, poptarg);
			break;
		case 'A':
			add_string(globals.tctx, &ipaddr, poptarg);
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'p':
			pinfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'P':
			pin = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'l':
			cpassfile = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'L':
			cpass = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'B':
			precommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'C':
			postcommand = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'a':
			p = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (p != NULL)) {
				p = talloc_asprintf(globals.tctx, "%s:%s",
						    nss_scheme, p);
			}
			if (p != NULL) {
				add_string(globals.tctx, &anchor_dbs, p);
			} else {
				fprintf(stderr,
					_("%s: invalid value -- '%s'\n"),
					"request", poptarg);
				help(argv0, "request");
				return 1;
			}
			break;
		case 'F':
			add_string(globals.tctx, &anchor_files,
				   ensure_pem(globals.tctx, poptarg));
			break;
		case 'w':
			waitreq++;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					category, optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					category, optopt);
			}
			help(argv0, category);
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, category);
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, category);
		return 1;
	}

	krb5_free_context(kctx);

	prep_bus(bus, category, verbose, argc, argv);
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, nickname, token,
						  certfile, verbose);
	}
	if (request == NULL) {
		if (id != NULL) {
			printf(_("No request found with specified "
				 "nickname.\n"));
			help(argv0, category);
			return 1;
		}
		if (((dbdir != NULL) && (nickname == NULL)) ||
		    ((dbdir == NULL) && (nickname != NULL))) {
			printf(_("Database location or nickname "
				 "specified without the other.\n"));
			help(argv0, category);
			return 1;
		}
		if ((dbdir != NULL) && (certfile != NULL)) {
			printf(_("Database directory and certificate "
				 "file both specified.\n"));
			help(argv0, category);
			return 1;
		}
		if ((dbdir == NULL) &&
		    (nickname == NULL) &&
		    (certfile == NULL)) {
			printf(_("None of database directory and "
				 "nickname or certificate file "
				 "specified.\n"));
			help(argv0, category);
			return 1;
		}
		printf(_("No request found that matched arguments.\n"));
		return 1;
	}
	i = 0;
	if (key_owner != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = key_owner;
		params[i] = &param[i];
		i++;
	}
	if (key_perms != NULL) {
		param[i].key = CM_DBUS_PROP_KEY_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(key_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (cert_owner != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_OWNER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cert_owner;
		params[i] = &param[i];
		i++;
	}
	if (cert_perms != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PERMS;
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = strtol(cert_perms, NULL, 8);
		params[i] = &param[i];
		i++;
	}
	if (nss_user != NULL) {
		param[i].key = CM_DBUS_PROP_NSS_USER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = nss_user;
		params[i] = &param[i];
		i++;
	}
	if (keytype != NULL) {
		param[i].key = "KEY_TYPE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = keytype;
		params[i] = &param[i];
		i++;
	}
	if (keysize > 0) {
		param[i].key = "KEY_SIZE";
		param[i].value_type = cm_tdbusm_dict_n;
		param[i].value.n = keysize;
		params[i] = &param[i];
		i++;
	}
	if (new_id != NULL) {
		param[i].key = "NICKNAME";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = new_id;
		params[i] = &param[i];
		i++;
	}
	if (ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), ca);
			exit(1);
		}
		param[i].key = "CA";
		param[i].value_type = cm_tdbusm_dict_p;
		param[i].value.s = talloc_strdup(globals.tctx, capath);
		params[i] = &param[i];
		i++;
	}
	if (subject != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_SUBJECT;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = subject;
		params[i] = &param[i];
		i++;
	}
	if (principal != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PRINCIPAL;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = principal;
		params[i] = &param[i];
		i++;
	}
	if (dns != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_HOSTNAME;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = dns;
		params[i] = &param[i];
		i++;
	}
	if (email != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_EMAIL;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = email;
		params[i] = &param[i];
		i++;
	}
	if (ipaddr != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_IP_ADDRESS;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = ipaddr;
		params[i] = &param[i];
		i++;
	}
	if (ku != 0) {
		for (j = 0; (ku >> j) != 0; j++) {
			kustring[j] = ((ku >> j) & 1) ?
				      '1' : '0';
		}
		kustring[j] = '\0';
		param[i].key = CM_DBUS_PROP_TEMPLATE_KU;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = kustring;
		params[i] = &param[i];
		i++;
	}
	if (eku != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_EKU;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = eku;
		params[i] = &param[i];
		i++;
	}
	if (pin != NULL) {
		param[i].key = "KEY_PIN";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pin;
		params[i] = &param[i];
		i++;
	}
	if (pinfile != NULL) {
		param[i].key = "KEY_PIN_FILE";
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = pinfile;
		params[i] = &param[i];
		i++;
	}
	if (cpass != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpass;
		params[i] = &param[i];
		i++;
	}
	if (cpassfile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_CHALLENGE_PASSWORD_FILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = cpassfile;
		params[i] = &param[i];
		i++;
	}
	param[i].key = CM_DBUS_PROP_TEMPLATE_IS_CA;
	param[i].value_type = cm_tdbusm_dict_b;
	param[i].value.b = is_ca;
	params[i] = &param[i];
	i++;
	param[i].key = CM_DBUS_PROP_TEMPLATE_CA_PATH_LENGTH;
	param[i].value_type = cm_tdbusm_dict_n;
	param[i].value.n = path_length;
	params[i] = &param[i];
	i++;
	if (profile != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_PROFILE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = profile;
		params[i] = &param[i];
		i++;
	}
	if (ms_template_spec != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = ms_template_spec;
		params[i] = &param[i];
		i++;
	}
	if (issuer != NULL) {
		param[i].key = CM_DBUS_PROP_TEMPLATE_ISSUER;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = issuer;
		params[i] = &param[i];
		i++;
	}
	if (precommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_PRESAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = precommand;
		params[i] = &param[i];
		i++;
	}
	if (postcommand != NULL) {
		param[i].key = CM_DBUS_PROP_CERT_POSTSAVE_COMMAND;
		param[i].value_type = cm_tdbusm_dict_s;
		param[i].value.s = postcommand;
		params[i] = &param[i];
		i++;
	}
	if (anchor_files != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_FILES;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_files;
		params[i] = &param[i];
		i++;
	}
	if (anchor_dbs != NULL) {
		param[i].key = CM_DBUS_PROP_ROOT_CERT_NSSDBS;
		param[i].value_type = cm_tdbusm_dict_as;
		param[i].value.as = anchor_dbs;
		params[i] = &param[i];
		i++;
	}
	params[i] = NULL;
	if (i > 0) {
		req = prep_req(bus, request, CM_DBUS_REQUEST_INTERFACE,
			       "modify");
		if (cm_tdbusm_set_d(req, params) != 0) {
			printf(_("Error setting request arguments.\n"));
			exit(1);
		}
		rep = send_req(req, verbose);
		if (cm_tdbusm_get_bp(rep, globals.tctx, &b,
				     &new_request) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		request = new_request;
		dbus_message_unref(rep);
		if (!b) {
			nickname = find_request_name(globals.tctx, bus,
						     request, verbose);
			printf(_("Error modifying \"%s\".\n"),
			       nickname ? nickname : request);
			exit(1);
		}
	}
	rep = query_rep(bus, request,
			CM_DBUS_REQUEST_INTERFACE, "get_ca", verbose);
	if (cm_tdbusm_get_p(rep, globals.tctx, &capath) == 0) {
		ca = find_ca_name(globals.tctx, bus, capath, verbose);
	} else {
		ca = NULL;
	}
	nickname = find_request_name(globals.tctx, bus, request, verbose);
	if (query_rep_b(bus, request, CM_DBUS_REQUEST_INTERFACE, category,
			verbose, globals.tctx)) {
		if (ca != NULL) {
			printf(_("Resubmitting \"%s\" to \"%s\".\n"),
			       nickname ? nickname : request, ca);
		} else {
			printf(_("Resubmitting \"%s\".\n"),
			       nickname ? nickname : request);
		}
		if (waitreq) {
			return waitfor(globals.tctx, bus, request, timeout, verbose);
		}
		return 0;
	} else {
		if (ca != NULL) {
			printf(_("Error attempting to submit \"%s\" to "
				 "\"%s\".\n"), request, ca);
		} else {
			printf(_("Error attempting to submit \"%s\".\n"),
			       request);
		}
		return 1;
	}
}

static int
rekey(const char *argv0, int argc, const char **argv)
{
	return rekey_or_resubmit(argv0, "rekey", argc, argv);
}

static int
resubmit(const char *argv0, int argc, const char **argv)
{
	return rekey_or_resubmit(argv0, "resubmit", argc, argv);
}

static int
refresh(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *rep;
	const char *only_ca = DEFAULT_CA;
	char **requests, *p, *nickname, *ca_name;
	char *dbdir = NULL, *dbnickname = NULL, *certfile = NULL, *id = NULL;
	char *nss_scheme, *token = NULL;
	const char *capath;
	dbus_bool_t b, all = FALSE;
	char *s1, *s2, *s3, *s4;
	enum cm_state state;
	int verbose = 0, c, i;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"all", 'a', POPT_ARG_NONE, NULL, 'a', _("refresh information about all outstanding requests"), NULL},
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &only_ca, 0, _("refresh information only for requests using the specified CA configuration"), HELP_TYPE_NAME},
#endif
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate"), HELP_TYPE_FILENAME},
		{"id", 'i', POPT_ARG_STRING, NULL, 'i', _("nickname for tracking request"), HELP_TYPE_ID},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "refresh");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 'c':
			only_ca = poptarg;
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'a':
			all = TRUE;
			nss_scheme = NULL;
			dbdir = NULL;
			dbnickname = NULL;
			certfile = NULL;
			id = NULL;
			break;
		case 'd':
			all = FALSE;
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 't':
			token = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'n':
			all = FALSE;
			dbnickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'f':
			all = FALSE;
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'i':
			all = FALSE;
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"refresh", optopt);
			} else {
				fprintf(stderr,
					_("%s: invalid option -- '%c'\n"),
					"refresh", optopt);
			}
			help(argv0, "refresh");
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "refresh");
		return 1;
	}
	if (!all && (id == NULL) &&
	    ((dbdir == NULL) || (dbnickname == NULL)) && (certfile == NULL)) {
		printf(_("None of ID or database directory and nickname or "
			 "certificate file specified.\n"));
		help(argv0, "refresh");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "refresh");
		return 1;
	}
	prep_bus(bus, "refresh", verbose, argc, argv);
	if (only_ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, only_ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), only_ca);
			return 1;
		}
	}
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_ca", verbose);
		if (cm_tdbusm_get_p(rep, globals.tctx, &p) == 0) {
			ca_name = find_ca_name(globals.tctx, bus, p, verbose);
		}
		dbus_message_unref(rep);
		if (only_ca != NULL) {
			if (ca_name == NULL) {
				continue;
			}
			if (strcmp(only_ca, ca_name) != 0) {
				continue;
			}
		}
		/* Filter based on request name or storage. */
		nickname = find_request_name(globals.tctx, bus, requests[i],
					     verbose);
		if ((id != NULL) && (strcmp(nickname, id) != 0)) {
			continue;
		}
		if ((dbdir != NULL) || (dbnickname != NULL) ||
		    (certfile != NULL)) {
			rep = query_rep(bus, requests[i],
					CM_DBUS_REQUEST_INTERFACE,
					"get_cert_storage_info", verbose);
			if (cm_tdbusm_get_ssosos(rep, globals.tctx,
						 &s1, &s2, &s3, &s4) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			dbus_message_unref(rep);
			if ((dbdir != NULL) || (dbnickname != NULL)) {
				if ((strcmp(s1, "NSSDB") != 0) ||
				    ((dbdir != NULL) &&
				     (strcmp(dbdir, s2) != 0)) ||
				    ((dbnickname != NULL) &&
				     (s3 != NULL) &&
				     (strcmp(dbnickname, s3) != 0)) ||
				    ((token != NULL) &&
				     (s4 != NULL) &&
				     (strcmp(token, s4) != 0))) {
					continue;
				}
			}
			if (certfile != NULL) {
				if ((strcmp(s1, "FILE") != 0) ||
				    (strcmp(certfile, s2) != 0)) {
					continue;
				}
			}
		}
		/* Get the status of this request. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_status", verbose);
		if (cm_tdbusm_get_sb(rep, globals.tctx, &s1, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		/* Filter out based on the current state. */
		state = cm_store_state_from_string(s1);
		switch (state) {
		case CM_CA_WORKING:
		case CM_CA_UNREACHABLE:
			break;
		default:
			continue;
			break;
		}
		/* Tell the daemon to refresh for this request. */
		b = query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"refresh", verbose, globals.tctx);
		if (b) {
			printf(_("Request ID '%s' being refreshed.\n"), nickname);
		} else {
			printf(_("Request ID '%s' NOT being refreshed.\n"),
			       nickname);
		}
	}
	return 0;
}

/* Check if a CA is an SCEP CA. */
static dbus_bool_t
ca_is_scep(void *parent, enum cm_tdbus_type bus,
	   const char *nickname, int verbose)
{
	char *busname, *s;

	if (nickname == NULL) {
		return FALSE;
	}
	busname = find_ca_by_name(parent, bus, nickname, verbose);
	if (busname == NULL) {
		return FALSE;
	}
	s = query_prop_s(bus, busname, CM_DBUS_CA_INTERFACE,
			 CM_DBUS_PROP_SCEP_RA_CERT,
			 verbose, parent);
	if ((s != NULL) && (strlen(s) > 0)) {
		return TRUE;
	}
	s = query_prop_s(bus, busname, CM_DBUS_CA_INTERFACE,
			 CM_DBUS_PROP_SCEP_CA_CERT,
			 verbose, parent);
	if ((s != NULL) && (strlen(s) > 0)) {
		return TRUE;
	}
	return FALSE;
}

static int
list(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	enum cm_state state;
	DBusMessage *rep;
	char **requests, *s, *p, *nickname, *only_ca = DEFAULT_CA, *ca_name;
	char *dbdir = NULL, *dbnickname = NULL, *certfile = NULL, *id = NULL;
	char *nss_scheme, *token = NULL, *when = NULL;
	int force_utc = 0;
	const char *capath, *request;
	dbus_bool_t b;
	char *s1, *s2, *s3, *s4, *s5, *s6;
	long perms;
	char *owner;
	long n1, n2, n3;
	char **as, **as1, **as2, **as3, **as4, **as5, t[25];
	int requests_only = 0, tracking_only = 0, verbose = 0, c, i, j;
	unsigned int k;
	char key_usages[LINE_MAX];
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"requests-only", 'r', POPT_ARG_NONE, NULL, 'r', _("list only information about outstanding requests"), NULL},
		{"tracking-only", 't', POPT_ARG_NONE, NULL, 't', _("list only information about tracked certificates"), NULL},
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &only_ca, 0, _("list only requests and certs associated with this CA configuration"), HELP_TYPE_NAME},
#endif
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate"), HELP_TYPE_FILENAME},
		{"id", 'i', POPT_ARG_STRING, NULL, 'i', _("nickname for tracking request"), HELP_TYPE_ID},
		{"utc", 'u', POPT_ARG_NONE, NULL, 'u', _("display times in UTC instead of local time"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "list");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 'r':
			requests_only++;
			break;
		case 't':
			tracking_only++;
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 'n':
			dbnickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		case 'u':
			force_utc++;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"list", optopt);
			} else {
				fprintf(stderr,
					_("%s: invalid option -- '%c'\n"),
					"list", optopt);
			}
			help(argv0, "list");
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "list");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "list");
		return 1;
	}
	prep_bus(bus, "list", verbose, argc, argv);
	if (only_ca != NULL) {
		capath = find_ca_by_name(globals.tctx, bus, only_ca, verbose);
		if (capath == NULL) {
			printf(_("No CA with name \"%s\" found.\n"), only_ca);
			return 1;
		}
	}
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
		if (request == NULL) {
			printf(_("No request found with specified "
				 "nickname.\n"));
			return 1;
		}
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, dbnickname, token,
						  certfile, verbose);
		if (request == NULL) {
			if (((dbdir != NULL) && (dbnickname != NULL)) ||
			    (certfile != NULL)) {
				printf(_("No request found that matched "
					 "arguments.\n"));
				return 1;
			}
		}
	}
	requests = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
				"get_requests", verbose, globals.tctx);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		continue;
	}
	printf(_("Number of certificates and requests being tracked: %d.\n"),
	       i);
	for (i = 0; (requests != NULL) && (requests[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = NULL;
		rep = query_rep(bus, requests[i],
				CM_DBUS_REQUEST_INTERFACE, "get_ca", verbose);
		if (cm_tdbusm_get_p(rep, globals.tctx, &p) == 0) {
			ca_name = find_ca_name(globals.tctx, bus, p, verbose);
		}
		dbus_message_unref(rep);
		if (only_ca != NULL) {
			if (ca_name == NULL) {
				continue;
			}
			if (strcmp(only_ca, ca_name) != 0) {
				continue;
			}
		}
		/* Get the status of this request. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_status", verbose);
		if (cm_tdbusm_get_sb(rep, globals.tctx, &s, &b) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		/* Filter out based on the current state. */
		state = cm_store_state_from_string(s);
		switch (state) {
		case CM_INVALID:
			printf(("'%s' is in an invalid state!\n"), s);
			continue;
			break;
		case CM_NEED_KEY_PAIR:
		case CM_NEED_KEY_GEN_PERMS:
		case CM_NEED_KEY_GEN_PIN:
		case CM_NEED_KEY_GEN_TOKEN:
		case CM_GENERATING_KEY_PAIR:
		case CM_HAVE_KEY_PAIR:
		case CM_NEED_KEYINFO:
		case CM_READING_KEYINFO:
		case CM_NEED_KEYINFO_READ_PIN:
		case CM_NEED_KEYINFO_READ_TOKEN:
		case CM_HAVE_KEYINFO:
		case CM_NEED_CSR:
		case CM_NEED_CSR_GEN_PIN:
		case CM_NEED_CSR_GEN_TOKEN:
		case CM_GENERATING_CSR:
		case CM_HAVE_CSR:
		case CM_NEED_SCEP_DATA:
		case CM_NEED_SCEP_GEN_PIN:
		case CM_NEED_SCEP_GEN_TOKEN:
		case CM_NEED_SCEP_ENCRYPTION_CERT:
		case CM_NEED_SCEP_RSA_CLIENT_KEY:
		case CM_GENERATING_SCEP_DATA:
		case CM_HAVE_SCEP_DATA:
		case CM_NEED_TO_SUBMIT:
		case CM_SUBMITTING:
		case CM_NEED_TO_SAVE_CERT:
		case CM_PRE_SAVE_CERT:
		case CM_START_SAVING_CERT:
		case CM_SAVING_CERT:
		case CM_NEED_CERTSAVE_PERMS:
		case CM_NEED_CERTSAVE_TOKEN:
		case CM_NEED_CERTSAVE_PIN:
		case CM_SAVED_CERT:
		case CM_POST_SAVED_CERT:
		case CM_NEED_TO_READ_CERT:
		case CM_READING_CERT:
		case CM_CA_WORKING:
		case CM_CA_REJECTED:
		case CM_CA_UNREACHABLE:
		case CM_CA_UNCONFIGURED:
		case CM_NEED_GUIDANCE:
		case CM_NEED_CA:
		case CM_NEWLY_ADDED:
		case CM_NEWLY_ADDED_START_READING_KEYINFO:
		case CM_NEWLY_ADDED_READING_KEYINFO:
		case CM_NEWLY_ADDED_NEED_KEYINFO_READ_PIN:
		case CM_NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN:
		case CM_NEWLY_ADDED_START_READING_CERT:
		case CM_NEWLY_ADDED_READING_CERT:
		case CM_NEWLY_ADDED_DECIDING:
		case CM_NEED_TO_SAVE_CA_CERTS:
		case CM_NEED_TO_SAVE_ONLY_CA_CERTS:
		case CM_START_SAVING_CA_CERTS:
		case CM_START_SAVING_ONLY_CA_CERTS:
		case CM_SAVING_CA_CERTS:
		case CM_SAVING_ONLY_CA_CERTS:
		case CM_NEED_CA_CERT_SAVE_PERMS:
		case CM_NEED_ONLY_CA_CERT_SAVE_PERMS:
			if (tracking_only) {
				continue;
			}
			break;
		case CM_MONITORING:
		case CM_NEED_TO_NOTIFY_VALIDITY:
		case CM_NOTIFYING_VALIDITY:
		case CM_NEED_TO_NOTIFY_REJECTION:
		case CM_NOTIFYING_REJECTION:
		case CM_NEED_TO_NOTIFY_ISSUED_SAVE_FAILED:
		case CM_NOTIFYING_ISSUED_SAVE_FAILED:
		case CM_NEED_TO_NOTIFY_ISSUED_CA_SAVE_FAILED:
		case CM_NOTIFYING_ISSUED_CA_SAVE_FAILED:
		case CM_NEED_TO_NOTIFY_ISSUED_SAVED:
		case CM_NOTIFYING_ISSUED_SAVED:
		case CM_NEED_TO_NOTIFY_ONLY_CA_SAVE_FAILED:
		case CM_NOTIFYING_ONLY_CA_SAVE_FAILED:
			if (requests_only) {
				continue;
			}
			break;
		}
		/* Basic info. */
		nickname = find_request_name(globals.tctx, bus, requests[i],
					     verbose);
		if ((id != NULL) && (strcmp(nickname, id) != 0)) {
			continue;
		}
		if ((dbdir != NULL) || (dbnickname != NULL) ||
		    (certfile != NULL)) {
			rep = query_rep(bus, requests[i],
					CM_DBUS_REQUEST_INTERFACE,
					"get_cert_storage_info", verbose);
			if (cm_tdbusm_get_ssosos(rep, globals.tctx,
						 &s1, &s2, &s3, &s4) != 0) {
				printf(_("Error parsing server response.\n"));
				exit(1);
			}
			dbus_message_unref(rep);
			if ((dbdir != NULL) || (dbnickname != NULL)) {
				if ((strcmp(s1, "NSSDB") != 0) ||
				    ((dbdir != NULL) &&
				     (s2 != NULL) &&
				     (strcmp(dbdir, s2) != 0)) ||
				    ((dbnickname != NULL) &&
				     (s3 != NULL) &&
				     (strcmp(dbnickname, s3) != 0))) {
					continue;
				}
			}
			if (certfile != NULL) {
				if ((strcmp(s1, "FILE") != 0) ||
				    (strcmp(certfile, s2) != 0)) {
					continue;
				}
			}
		}
		printf(_("Request ID '%s':\n"), nickname);
		printf(_("\tstatus: %s\n"), s);
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_ca_error", verbose);
		if (cm_tdbusm_get_s(rep, globals.tctx, &s) == 0) {
			printf(_("\tca-error: %s\n"), s);
		}
		printf(_("\tstuck: %s\n"), b ? "yes" : "no");
		/* Get key/cert storage info. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_key_storage_info", verbose);
		if (cm_tdbusm_get_sososos(rep, globals.tctx,
					  &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		s5 = query_rep_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				 "get_key_pin", verbose, globals.tctx);
		if ((s5 != NULL) && (strlen(s5) == 0)) {
			s5 = NULL;
		}
		s6 = query_rep_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				 "get_key_pin_file", verbose, globals.tctx);
		if ((s6 != NULL) && (strlen(s6) == 0)) {
			s6 = NULL;
		}
		owner = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				  CM_DBUS_PROP_KEY_OWNER, verbose, globals.tctx);
		if ((owner != NULL) && (strlen(owner) == 0)) {
			owner = NULL;
		}
		perms = query_prop_n(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				  CM_DBUS_PROP_KEY_PERMS, verbose, globals.tctx);
		printf(_("\tkey pair storage: type=%s"), s1 ? s1 : _("NONE"));
		if (s2 != NULL) {
			printf(_(",location='%s'"), s2);
		}
		if (s3 != NULL) {
			printf(_(",nickname='%s'"), s3);
		}
		if (s4 != NULL) {
			printf(_(",token='%s'"), s4);
		}
		if (s5 != NULL) {
			printf(_(",pin set"));
		}
		if (s6 != NULL) {
			printf(_(",pinfile='%s'"), s6);
		}
		if (owner != NULL) {
			printf(_(",owner=%s"), owner);
		}
		if (perms > 0) {
			printf(_(",perms=%04o"), (unsigned int)perms & 07777);
		}
		printf("\n");
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_storage_info", verbose);
		if (cm_tdbusm_get_ssosos(rep, globals.tctx,
					 &s1, &s2, &s3, &s4) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		owner = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				  CM_DBUS_PROP_CERT_OWNER, verbose, globals.tctx);
		if ((owner != NULL) && (strlen(owner) == 0)) {
			owner = NULL;
		}
		perms = query_prop_n(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				  CM_DBUS_PROP_CERT_PERMS, verbose, globals.tctx);
		dbus_message_unref(rep);
		printf(_("\tcertificate: type=%s,location='%s'"), s1, s2);
		if (s3 != NULL) {
			printf(_(",nickname='%s'"), s3);
		}
		if (s4 != NULL) {
			printf(_(",token='%s'"), s4);
		}
		if (owner != NULL) {
			printf(_(",owner=%s"), owner);
		}
		if (perms > 0) {
			printf(_(",perms=%04o"), (unsigned int)perms & 07777);
		}
		printf("\n");
		/* Information about the CSR. */
		if ((ca_name != NULL) &&
		    ca_is_scep(globals.tctx, bus, ca_name, verbose)) {
			s1 = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
					  CM_DBUS_PROP_CSR, verbose, globals.tctx);
			if ((s1 != NULL) && (strlen(s1) > 0)) {
				s2 = thumbprint(s1, SEC_OID_MD5, 128);
				if ((s2 != NULL) && (strlen(s2) > 0)) {
					printf(_("\tsigning request thumbprint (MD5): %s\n"), s2);
				}
				free(s2);
				s2 = thumbprint(s1, SEC_OID_SHA1, 160);
				if ((s2 != NULL) && (strlen(s2) > 0)) {
					printf(_("\tsigning request thumbprint (SHA1): %s\n"), s2);
				}
				free(s2);
			}
		}
		/* Information from the certificate. */
		rep = query_rep(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				"get_cert_info", verbose);
		if (cm_tdbusm_get_sssnasasasnasn(rep, globals.tctx,
						&s1, &s2, &s3, &n1,
						&as1, &as2, &as3,
						&n2, &as4, &n3) != 0) {
			printf(_("Error parsing server response.\n"));
			exit(1);
		}
		dbus_message_unref(rep);
		if (ca_name != NULL) {
			printf(_("\tCA: %s\n"), ca_name);
		}
		printf(_("\tissuer: %s\n"), s1);
		printf(_("\tsubject: %s\n"), s3);
		when = _("unknown");
		if (n3 != 0) {
			if (force_utc) {
				when = cm_store_timestamp_from_time_for_display(n3, t);
				printf(_("\tissued: %s\n"), when);
			} else {
				when = cm_store_local_timestamp_from_time_for_display(n3);
				if (when != NULL) {
					printf(_("\tissued: %s\n"), when);
					free(when);
				}
			}
		} else {
			printf(_("\tissued: %s\n"), when);
		}
		when = _("unknown");
		if (n1 != 0) {
			if (force_utc) {
				when = cm_store_timestamp_from_time_for_display(n1, t);
				printf(_("\texpires: %s\n"), when);
			} else {
				when = cm_store_local_timestamp_from_time_for_display(n1);
				if (when != NULL) {
					printf(_("\texpires: %s\n"), when);
					free(when);
				}
			}
		} else {
			printf(_("\texpires: %s\n"), when);
		}
		for (j = 0; (as1 != NULL) && (as1[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\temail: ") : ",",
			       as1[j],
			       as1[j + 1] ? "" : "\n");
		}
		for (j = 0; (as2 != NULL) && (as2[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\tdns: ") : ",",
			       as2[j],
			       as2[j + 1] ? "" : "\n");
		}
		for (j = 0; (as3 != NULL) && (as3[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\tprincipal name: ") : ",",
			       as3[j],
			       as3[j + 1] ? "" : "\n");
		}
		as5 = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				    CM_DBUS_PROP_TEMPLATE_IP_ADDRESS, verbose, globals.tctx);
		for (j = 0; (as5 != NULL) && (as5[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\tIP address: ") : ",",
			       as5[j],
			       as5[j + 1] ? "" : "\n");
		}
		if (n2 != 0) {
			const char *ku;
			memset(key_usages, '\0', sizeof(key_usages));
			for (k = 0; (n2 >> k) != 0; k++) {
				if ((((n2 >> k) & 1) != 0) &&
				    ((ku = cm_ku_to_name(k)) != NULL)) {
					snprintf(key_usages +
						 strlen(key_usages),
						 sizeof(key_usages) -
						 strlen(key_usages),
						 "%s%s",
						 strlen(key_usages) ? "," : "",
						 ku);
				}
			}
			printf(_("\tkey usage: %s\n"), key_usages);
		}
		for (j = 0; (as4 != NULL) && (as4[j] != NULL); j++) {
			printf("%s%s%s",
			       j == 0 ? _("\teku: ") : ",",
			       cm_oid_to_name(NULL, as4[j]),
			       as4[j + 1] ? "" : "\n");
		}
		s1 = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				  CM_DBUS_PROP_CA_PROFILE, verbose,
				  globals.tctx);
		if ((s1 != NULL) && (strlen(s1) > 0)) {
			printf(_("\tcertificate template/profile: %s\n"), s1);
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_ROOT_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\troot certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_OTHER_ROOT_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother root certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_OTHER_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_ROOT_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\troot certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother root certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   CM_DBUS_PROP_OTHER_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		s1 = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
					CM_DBUS_PROP_TEMPLATE_PROFILE, verbose, globals.tctx);
		if (s1 != NULL && strlen(s1) > 0) {
			printf(_("\tprofile: %s\n"), s1);
		}
		s1 = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
					CM_DBUS_PROP_TEMPLATE_MS_CERTIFICATE_TEMPLATE,
					verbose, globals.tctx);
		if (s1 != NULL && strlen(s1) > 0) {
			printf(_("\tms v2 template: %s\n"), s1);
		}
		s1 = query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
					CM_DBUS_PROP_TEMPLATE_ISSUER, verbose, globals.tctx);
		if (s1 != NULL && strlen(s1) > 0) {
			printf(_("\tissuer template: %s\n"), s1);
		}
		printf(_("\tpre-save command: %s\n"),
		       query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				    CM_DBUS_PROP_CERT_PRESAVE_COMMAND, verbose, globals.tctx));
		printf(_("\tpost-save command: %s\n"),
		       query_prop_s(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				    CM_DBUS_PROP_CERT_POSTSAVE_COMMAND, verbose, globals.tctx));
		printf(_("\ttrack: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_monitoring", verbose, globals.tctx) ?
		       "yes" : "no");
		printf(_("\tauto-renew: %s\n"),
		       query_rep_b(bus, requests[i], CM_DBUS_REQUEST_INTERFACE,
				   "get_autorenew", verbose, globals.tctx) ?
		       "yes" : "no");
	}
	return 0;
}

static int
status(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	DBusMessage *rep;
	char *dbdir = NULL, *dbnickname = NULL, *certfile = NULL, *id = NULL;
	char *nss_scheme, *token = NULL;
	const char *request;
	char *s;
	dbus_bool_t b;
	int verbose = 0, c;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"dbdir", 'd', POPT_ARG_STRING, NULL, 'd', _("NSS database for key and cert"), HELP_TYPE_DIRECTORY},
		{"nickname", 'n', POPT_ARG_STRING, NULL, 'n', _("nickname for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"token", 't', POPT_ARG_STRING, NULL, 't', _("optional token name for NSS-based storage (only valid with -d)"), HELP_TYPE_NAME},
		{"certfile", 'f', POPT_ARG_STRING, NULL, 'f', _("PEM file for certificate"), HELP_TYPE_FILENAME},
		{"id", 'i', POPT_ARG_STRING, NULL, 'i', _("nickname for tracking request"), HELP_TYPE_ID},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "status");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'd':
			nss_scheme = NULL;
			dbdir = ensure_nss(globals.tctx, poptarg, &nss_scheme);
			if ((nss_scheme != NULL) && (dbdir != NULL)) {
				dbdir = talloc_asprintf(globals.tctx, "%s:%s",
							nss_scheme, dbdir);
			}
			break;
		case 'n':
			dbnickname = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'f':
			certfile = ensure_pem(globals.tctx, poptarg);
			break;
		case 'i':
			id = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "status");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "status");
		return 1;
	}
	prep_bus(bus, "status", verbose, argc, argv);
	if (id != NULL) {
		request = find_request_by_name(globals.tctx, bus, id, verbose);
		if (request == NULL) {
			printf(_("No request found with specified "
				 "nickname.\n"));
			return 1;
		}
	} else {
		request = find_request_by_storage(globals.tctx, bus,
						  dbdir, dbnickname, token,
						  certfile, verbose);
		if (request == NULL) {
			if (((dbdir != NULL) && (dbnickname != NULL)) ||
			    (certfile != NULL)) {
				printf(_("No request found that matched "
					 "arguments.\n"));
				return 1;
			} else {
				printf(_("None of ID or database directory and "
					 "and nickname or certificate file "
					 "specified.\n"));
				help(argv0, "status");
				return 1;
			}
		}
	}
	/* Get the status of this request. */
	rep = query_rep(bus, request, CM_DBUS_REQUEST_INTERFACE,
			"get_status", verbose);
	if (cm_tdbusm_get_sb(rep, globals.tctx, &s, &b) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (verbose) {
		printf(_("State %s, stuck: %s.\n"),
		       s, b ? "yes" : "no");
	}
	return evaluate_status(s, b);
}

char *
thumbprint(const char *s, SECOidTag tag, int bits)
{
	unsigned char digest[CM_DIGEST_MAX], *u = NULL;
	char *t = NULL;
	char *ret = NULL;
	int length, i;
	const char *hexchars = "0123456789ABCDEF";

	t = cm_submit_u_base64_from_text(s);
	if (t == NULL) {
		goto done;
	}
	length = strlen(t);
	if (length == 0) {
		free(t);
		goto done;
	}
	u = malloc(length + 1);
	if (u == NULL) {
		goto done;
	}
	length = cm_store_base64_to_bin(t, -1, u, length);
	if (PK11_HashBuf(tag, digest, u, length) == SECSuccess) {
		free(t);
		t = malloc(bits / 4 + howmany(bits, 32));
		if (t != NULL) {
			ret = t;
			for (i = 0; i < bits / 8; i++) {
				if ((i > 0) && ((i % 4) == 0)) {
					*t++ = ' ';
				}
				*t++ = hexchars[(digest[i] >> 4) & 0x0f];
				*t++ = hexchars[(digest[i]) & 0x0f];
			}
			*t++ = '\0';
		}
	} else {
        free(t);
        t = NULL;
    }
done:
	free(u);
	return ret;
}

static int
list_cas(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char **cas, *s, *only_ca = DEFAULT_CA, *thumb, *ca_name;
	char **as;
	int c, i, j, verbose = 0;
	poptContext pctx;
	struct poptOption popts[] = {
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &only_ca, 0, _("list only the specified CA configuration"), HELP_TYPE_NAME},
#endif
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "list-cas");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		default:
			if (c == ':') {
				fprintf(stderr,
					_("%s: option requires an argument -- '%c'\n"),
					"list-cas", optopt);
			} else {
				fprintf(stderr, _("%s: invalid option -- '%c'\n"),
					"list-cas", optopt);
			}
			help(argv0, "list-cas");
			return 1;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "list-cas");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "list-cas");
		return 1;
	}
	prep_bus(bus, "list-cas", verbose, argc, argv);
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", verbose, globals.tctx);
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		/* Filter out based on the CA. */
		ca_name = find_ca_name(globals.tctx, bus, cas[i], verbose);
		if (ca_name != NULL) {
			if ((only_ca != NULL) && (strcmp(ca_name, only_ca) != 0)) {
				continue;
			}
		}
		printf(_("CA '%s':\n"), ca_name);
		if (verbose > 0) {
			s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					 CM_DBUS_PROP_AKA,
					 verbose, globals.tctx);
			if ((s != NULL) && (strlen(s) > 0)) {
				printf(_("\tself-identifies as: %s\n"), s);
			}
		}
		printf("\tis-default: %s\n",
		       query_rep_b(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   "get_is_default", verbose, globals.tctx) ?
		       "yes" : "no");
		s = query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				"get_type", verbose, globals.tctx);
		printf(_("\tca-type: %s\n"), s);
		if (strcmp(s, "EXTERNAL") == 0) {
			printf(_("\thelper-location: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_location",
					   verbose, globals.tctx));
		} else {
			printf(_("\tnext-serial-number: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_serial",
					   verbose, globals.tctx));
		}
		as = query_rep_as(bus, cas[i],
				  CM_DBUS_CA_INTERFACE, "get_issuer_names",
				  verbose,
				  globals.tctx);
		if (as != NULL) {
			printf(_("\tknown-issuer-names:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_DEFAULT_PROFILE,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tknown profiles/templates/certtypes:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_ROOT_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\troot certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_OTHER_ROOT_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother root certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_OTHER_CERT_FILES,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother certificates saved to files:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_ROOT_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\troot certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_OTHER_ROOT_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother root certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		as = query_prop_as(bus, cas[i], CM_DBUS_CA_INTERFACE,
				   CM_DBUS_PROP_OTHER_CERT_NSSDBS,
				   verbose, globals.tctx);
		if (as != NULL) {
			printf(_("\tother certificates saved to databases:\n"));
			for (j = 0; as[j] != NULL; j++) {
				printf("\t\t%s\n", as[j]);
			}
		}
		s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				 CM_DBUS_PROP_DEFAULT_PROFILE,
				 verbose, globals.tctx);
		if ((s != NULL) && (strlen(s) > 0)) {
			printf(_("\tdefault profile/template/certtype: %s\n"),
			       s);
		}
		if (ca_is_scep(globals.tctx, bus, ca_name, verbose)) {
			s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					 CM_DBUS_PROP_SCEP_CA_IDENTIFIER,
					 verbose, globals.tctx);
			if ((s != NULL) && (strlen(s) > 0)) {
				printf(_("\tSCEP CA identifier: %s\n"), s);
			}
			s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					 CM_DBUS_PROP_SCEP_CA_CERT,
					 verbose, globals.tctx);
			if ((s == NULL) || (strlen(s) == 0)) {
				s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
						 CM_DBUS_PROP_SCEP_RA_CERT,
						 verbose, globals.tctx);
			}
			if ((s != NULL) && (strlen(s) > 0)) {
				thumb = thumbprint(s, SEC_OID_MD5, 128);
				if ((thumb != NULL) && (strlen(thumb) > 0)) {
					printf(_("\tSCEP CA certificate thumbprint (MD5): %s\n"),
					       thumb);
				}
				free(thumb);
				thumb = thumbprint(s, SEC_OID_SHA1, 160);
				if ((thumb != NULL) && (strlen(thumb) > 0)) {
					printf(_("\tSCEP CA certificate thumbprint (SHA1): %s\n"),
					       thumb);
				}
				free(thumb);
			}
		}
		s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				 CM_DBUS_PROP_CA_PRESAVE_COMMAND,
				 verbose, globals.tctx);
		if ((s != NULL) && (strlen(s) > 0)) {
			printf(_("\tpre-save command: %s\n"), s);
		}
		s = query_prop_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
				 CM_DBUS_PROP_CA_POSTSAVE_COMMAND,
				 verbose, globals.tctx);
		if ((s != NULL) && (strlen(s) > 0)) {
			printf(_("\tpost-save command: %s\n"), s);
		}
		if (verbose > 0) {
			printf(_("\tconfig-path: %s\n"),
			       query_rep_s(bus, cas[i], CM_DBUS_CA_INTERFACE,
					   "get_config_file_path",
					   verbose, globals.tctx));
		}
	}
	return 0;
}

static int
refresh_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char **cas, *s, *only_ca = DEFAULT_CA;
	int c, i, verbose = 0;
	dbus_bool_t b, all = FALSE;
	poptContext pctx;
	struct poptOption popts[] = {
#ifndef FORCE_CA
		{"ca", 'c', POPT_ARG_STRING, &only_ca, 0, _("refresh information about the CA configuration with this name"), HELP_TYPE_NAME},
#endif
		{"all", 'a', POPT_ARG_NONE, NULL, 'a', _("refresh information about all known CAs"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "refresh-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 'a':
			all = TRUE;
			break;
		case 'c':
			all = FALSE;
			break;
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "refresh-ca");
		return 1;
	}
	if (!all && (only_ca == NULL)) {
		printf(_("Neither CA nickname nor -a flag specified.\n"));
		help(argv0, "refresh-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "refresh-ca");
		return 1;
	}
	prep_bus(bus, "refresh-ca", verbose, argc, argv);
	cas = query_rep_ap(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			   "get_known_cas", verbose, globals.tctx);
	for (i = 0; (cas != NULL) && (cas[i] != NULL); i++) {
		/* Filter out based on the CA. */
		s = find_ca_name(globals.tctx, bus, cas[i], verbose);
		if ((s != NULL) && !all) {
			if ((only_ca != NULL) && (strcmp(s, only_ca) != 0)) {
				continue;
			}
		}
		b = query_rep_b(bus, cas[i],
				CM_DBUS_CA_INTERFACE, "refresh",
				verbose,
				globals.tctx);
		if (b) {
			if (s != NULL) {
				printf(_("Data for CA '%s' being refreshed.\n"), s);
			} else {
				printf(_("Data for unnamed CA being refreshed.\n"));
			}
		} else {
			printf(_("\terror refreshing CA data\n"));
		}
	}
	return 0;
}

#ifndef FORCE_CA
static int
add_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *command = NULL, *p = NULL, *nickname;
	int c, verbose = 0;
	dbus_bool_t b;
	static DBusMessage *req, *rep;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname to give to the new CA configuration"), HELP_TYPE_NAME},
		{"command", 'e', POPT_ARG_STRING, &command, 0, _("helper command to run to communicate with CA"), HELP_TYPE_COMMAND},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "add-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "add-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "add-ca");
		return 1;
	}
	if (command == NULL) {
		printf(_("CA helper command not specified.\n"));
		help(argv0, "add-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "add-ca");
		return 1;
	}
	prep_bus(bus, "add-ca", verbose, argc, argv);
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_known_ca");
	if (cm_tdbusm_set_ssoas(req, caname, command, NULL) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &p) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_ca_name(globals.tctx, bus, p, verbose);
		printf(_("New CA \"%s\" added.\n"),
		       nickname ? nickname : p);
	} else {
		printf(_("New CA could not be added.\n"));
		exit(1);
	}
	return 0;
}

static int
add_scep_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *url = NULL, *path = NULL, *id = NULL;
	char *root = NULL, *racert = NULL, *certs = NULL, *nickname, *command;
	char *signingca = NULL;
	const char *err;
	int c, prefer_non_renewal = 0, verbose = 0;
	dbus_bool_t b;
	static DBusMessage *req, *rep;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname to give to the new CA configuration"), HELP_TYPE_NAME},
		{"url", 'u', POPT_ARG_STRING, &url, 0, _("location of SCEP server"), HELP_TYPE_URL},
		{"id", 'i', POPT_ARG_STRING, &id, 0, _("CA identifier"), HELP_TYPE_ID},
		{"ca-cert", 'R', POPT_ARG_STRING, NULL, 'R', _("file containing CA's certificate"), HELP_TYPE_FILENAME},
		{"ra-cert", 'r', POPT_ARG_STRING, NULL, 'r', _("file containing RA's certificate"), HELP_TYPE_FILENAME},
		{"other-certs", 'I', POPT_ARG_STRING, NULL, 'I', _("file containing certificates in RA's certifying chain"), HELP_TYPE_FILENAME},
		{"signingca", 'N', POPT_ARG_STRING, NULL, 'N', _("the CA certificate which signed the RA certificate"), HELP_TYPE_FILENAME},
		{"non-renewal", 'n', POPT_ARG_NONE, &prefer_non_renewal, 0, _("prefer to not use the SCEP Renewal feature"), NULL},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "add-scep-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		case 'R':
            if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The root certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			root = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'r':
            if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The RA certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			racert = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'I':
            if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			certs = talloc_strdup(globals.tctx, poptarg);
			break;
		case 'N':
            if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			signingca = talloc_strdup(globals.tctx, poptarg);
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "add-scep-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "add-scep-ca");
		return 1;
	}
	if (url == NULL) {
		printf(_("server URL not specified.\n"));
		help(argv0, "add-scep-ca");
		return 1;
	}
	if ((root == NULL) && (strncmp(url, "https:", 6) == 0)) {
		printf(_("HTTPS requires a CA certificate.\n"));
		help(argv0, "add-scep-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "add-scep-ca");
		return 1;
	}
	command = talloc_asprintf(globals.tctx,
				  "%s -u %s %s %s %s %s %s %s %s %s %s %s %s",
				  shell_escape(globals.tctx,
					       CM_SCEP_HELPER_PATH),
				  shell_escape(globals.tctx, url),
				  root ? "-R" : "",
				  root ? shell_escape(globals.tctx, root) : "",
				  racert ? "-r" : "",
				  racert ? shell_escape(globals.tctx, racert) : "",
				  id ? "-i" : "",
				  id ? shell_escape(globals.tctx, id) : "",
				  certs ? "-I" : "",
				  certs ? shell_escape(globals.tctx, certs) : "",
				  signingca ? "-N" : "",
				  signingca ? shell_escape(globals.tctx, signingca) : "",
				  prefer_non_renewal ? "-n" : "");
	for (c = 0; c < verbose; c++) {
		command = talloc_strdup_append(command, " -v");
	}
	if (command == NULL) {
		printf(_("Error building command line.\n"));
		exit(1);
	}
	prep_bus(bus, "add-scep-ca", verbose, argc, argv);
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_known_ca");
	if (cm_tdbusm_set_ssoas(req, caname, command, NULL) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &path) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_ca_name(globals.tctx, bus, path, verbose);
		printf(_("New CA \"%s\" added.\n"),
		       nickname ? nickname : path);
		if (id != NULL) {
			req = prep_req(bus, path, DBUS_INTERFACE_PROPERTIES,
				       "Set");
			if (cm_tdbusm_set_ssvs(req, CM_DBUS_CA_INTERFACE,
					       CM_DBUS_PROP_SCEP_CA_IDENTIFIER,
					       id) != 0) {
				printf(_("Error setting request arguments.\n"));
				exit(1);
			}
			rep = send_req(req, verbose);
			err = dbus_message_get_error_name(rep);
			if (err != NULL) {
				printf(_("Error setting CA identifier.\n"));
				exit(1);
			}
			dbus_message_unref(rep);
		}
	} else {
		printf(_("New CA could not be added.\n"));
		exit(1);
	}
	return 0;
}

static int
add_est_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *url = NULL, *path = NULL, *label = NULL;
	char *root = NULL, *username = NULL, *password_file = NULL;
	char *nickname, *command;
	int c, verbose = 0;
	dbus_bool_t b;
	static DBusMessage *req, *rep;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname to give to the new CA configuration"), HELP_TYPE_NAME},
		{"url", 'u', POPT_ARG_STRING, &url, 0, _("location of EST server"), HELP_TYPE_URL},
		{"label", 'i', POPT_ARG_STRING, &label, 0, _("CA label"), HELP_TYPE_ID},
		{"ca-cert", 'R', POPT_ARG_STRING, NULL, 'R', _("file containing certificate of the CA which issued the EST server's certificate"), HELP_TYPE_FILENAME},
		{"username", 'U', POPT_ARG_STRING, &username, 0, _("user name for enrollment"), HELP_TYPE_NAME},
		{"password-file", 'W', POPT_ARG_STRING, &password_file, 0, _("file containing password for enrollment"), HELP_TYPE_FILENAME},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "add-est-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		case 'R':
			if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The root certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			root = ensure_path_is_absolute(globals.tctx, poptarg);
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "add-est-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "add-est-ca");
		return 1;
	}
	if (url == NULL) {
		printf(_("server URL not specified.\n"));
		help(argv0, "add-est-ca");
		return 1;
	}
	if (strncasecmp(url, "https://", 8) != 0) {
		printf(_("EST requires an HTTPS URL.\n"));
		help(argv0, "add-est-ca");
		return 1;
	}
	if (password_file != NULL) {
		password_file = ensure_path_is_absolute(globals.tctx,
							password_file);
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "add-est-ca");
		return 1;
	}
	command = talloc_asprintf(globals.tctx, "%s -u %s",
				  shell_escape(globals.tctx,
					       CM_EST_HELPER_PATH),
				  shell_escape(globals.tctx, url));
	if (label != NULL) {
		command = talloc_asprintf_append(command, " -i %s",
						 shell_escape(globals.tctx,
							      label));
	}
	if (root != NULL) {
		command = talloc_asprintf_append(command, " -R %s",
						 shell_escape(globals.tctx,
							      root));
	}
	if (username != NULL) {
		command = talloc_asprintf_append(command, " -U %s",
						 shell_escape(globals.tctx,
							      username));
	}
	if (password_file != NULL) {
		command = talloc_asprintf_append(command, " -W %s",
						 shell_escape(globals.tctx,
							      password_file));
	}
	for (c = 0; c < verbose; c++) {
		command = talloc_strdup_append(command, " -v");
	}
	if (command == NULL) {
		printf(_("Error building command line.\n"));
		exit(1);
	}
	prep_bus(bus, "add-est-ca", verbose, argc, argv);
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "add_known_ca");
	if (cm_tdbusm_set_ssoas(req, caname, command, NULL) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &path) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_ca_name(globals.tctx, bus, path, verbose);
		printf(_("New CA \"%s\" added.\n"),
		       nickname ? nickname : path);
	} else {
		printf(_("New CA could not be added.\n"));
		exit(1);
	}
	return 0;
}

/* The key of an external account binding, the first line of a file. */
static char *
read_eab_key(void *parent, const char *filename)
{
	char buf[4096], *ret;
	ssize_t n;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		return NULL;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0) {
		return NULL;
	}
	buf[n] = '\0';
	ret = talloc_strndup(parent, buf, strcspn(buf, "\r\n"));
	memset(buf, '\0', sizeof(buf));
	return ret;
}

static int
add_acme_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *url = NULL, *path = NULL, *root = NULL;
	char *eab_kid = NULL, *eab_key_file = NULL, *attest = NULL;
	char *eab_key = NULL;
	char *permanent_identifier = NULL;
	char *nickname, *command;
	int c, i, verbose = 0;
	dbus_bool_t b;
	static DBusMessage *req, *rep;
	const char *poptarg;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname to give to the new CA configuration"), HELP_TYPE_NAME},
		{"directory", 'u', POPT_ARG_STRING, &url, 0, _("location of the ACME server's directory"), HELP_TYPE_URL},
		{"ca-cert", 'R', POPT_ARG_STRING, NULL, 'R', _("file containing certificate of the CA which issued the ACME server's certificate"), HELP_TYPE_FILENAME},
		{"eab-kid", '\0', POPT_ARG_STRING, &eab_kid, 0, _("key identifier for external account binding"), HELP_TYPE_ID},
		{"eab-key-file", '\0', POPT_ARG_STRING, &eab_key_file, 0, _("file containing the MAC key for external account binding"), HELP_TYPE_FILENAME},
		{"attest", '\0', POPT_ARG_STRING, &attest, 0, _("answer device-attest-01 challenges using the given attestation format"), HELP_TYPE_MODE},
		{"permanent-identifier", '\0', POPT_ARG_STRING, &permanent_identifier, 0, _("the device's permanent identifier"), HELP_TYPE_ID},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "add-acme-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		poptarg = poptGetOptArg(pctx);
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		case 'R':
			if (validate_pem(globals.tctx, poptarg) != 0) {
				printf("The root certificate(s) in %s is not valid PEM\n", poptarg);
				return 1;
			}
			root = ensure_path_is_absolute(globals.tctx, poptarg);
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "add-acme-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "add-acme-ca");
		return 1;
	}
	if (url == NULL) {
		printf(_("directory URL not specified.\n"));
		help(argv0, "add-acme-ca");
		return 1;
	}
	if (strncasecmp(url, "https://", 8) != 0) {
		printf(_("ACME requires an HTTPS URL.\n"));
		help(argv0, "add-acme-ca");
		return 1;
	}
	if ((eab_key_file != NULL) && (eab_kid == NULL)) {
		printf(_("An external account key file was given without its "
			 "key ID.\n"));
		help(argv0, "add-acme-ca");
		return 1;
	}
	if (eab_key_file != NULL) {
		/* The service keeps a copy of the key, so that it does not
		 * depend on where the file is and who may read it, and the
		 * file can be removed once the CA is added. */
		eab_key = read_eab_key(globals.tctx, eab_key_file);
		if (eab_key == NULL) {
			printf(_("Can't read \"%s\".\n"), eab_key_file);
			return 1;
		}
		if (strlen(eab_key) == 0) {
			printf(_("No external account key in \"%s\".\n"),
			       eab_key_file);
			return 1;
		}
	}
	if ((attest != NULL) && (strcasecmp(attest, "tpm") != 0)) {
		printf(_("Unknown attestation format \"%s\".\n"), attest);
		help(argv0, "add-acme-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "add-acme-ca");
		return 1;
	}
	command = talloc_asprintf(globals.tctx, "%s -u %s",
				  shell_escape(globals.tctx,
					       CM_ACME_HELPER_PATH),
				  shell_escape(globals.tctx, url));
	if (root != NULL) {
		command = talloc_asprintf_append(command, " -R %s",
						 shell_escape(globals.tctx,
							      root));
	}
	if (eab_kid != NULL) {
		command = talloc_asprintf_append(command, " -k %s",
						 shell_escape(globals.tctx,
							      eab_kid));
	}
	if (attest != NULL) {
		command = talloc_asprintf_append(command, " -a %s",
						 shell_escape(globals.tctx,
							      attest));
	}
	if (permanent_identifier != NULL) {
		command = talloc_asprintf_append(command, " -P %s",
						 shell_escape(globals.tctx,
							      permanent_identifier));
	}
	for (c = 0; c < verbose; c++) {
		command = talloc_strdup_append(command, " -v");
	}
	if (command == NULL) {
		printf(_("Error building command line.\n"));
		exit(1);
	}
	prep_bus(bus, "add-acme-ca", verbose, argc, argv);
	if (eab_key != NULL) {
		req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			       "add_known_ca_with_eab_key");
		i = cm_tdbusm_set_ss_as_s(req, caname, command, NULL, eab_key);
		memset(eab_key, '\0', strlen(eab_key));
	} else {
		req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
			       "add_known_ca");
		i = cm_tdbusm_set_ssoas(req, caname, command, NULL);
	}
	if (i != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_bp(rep, globals.tctx, &b, &path) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		nickname = find_ca_name(globals.tctx, bus, path, verbose);
		printf(_("New CA \"%s\" added.\n"),
		       nickname ? nickname : path);
	} else {
		printf(_("New CA could not be added.\n"));
		exit(1);
	}
	return 0;
}

static int
modify_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *command = NULL, *nickname, *path;
	const char *err;
	int c, verbose = 0;
	static DBusMessage *req, *rep;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname of the CA configuration"), HELP_TYPE_NAME},
		{"command", 'e', POPT_ARG_STRING, &command, 0, _("updated helper command to run to communicate with CA"), HELP_TYPE_COMMAND},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "modify-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "modify-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "modify-ca");
		return 1;
	}
	if (command == NULL) {
		printf(_("CA helper command not specified.\n"));
		help(argv0, "modify-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "modify-ca");
		return 1;
	}
	prep_bus(bus, "modify-ca", verbose, argc, argv);
	path = find_ca_by_name(globals.tctx, bus, caname, verbose);
	req = prep_req(bus, path, DBUS_INTERFACE_PROPERTIES, "Set");
	if (cm_tdbusm_set_ssvs(req, CM_DBUS_CA_INTERFACE,
			       CM_DBUS_PROP_EXTERNAL_HELPER,
			       command) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	err = dbus_message_get_error_name(rep);
	if (err == NULL) {
		nickname = find_ca_name(globals.tctx, bus, path, verbose);
		printf(_("CA \"%s\" modified.\n"),
		       nickname ? nickname : caname);
	} else {
		printf(_("CA could not be modified.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	return 0;
}

static int
remove_ca(const char *argv0, int argc, const char **argv)
{
	enum cm_tdbus_type bus = CM_DBUS_DEFAULT_BUS;
	char *caname = NULL, *path;
	int c, verbose = 0;
	dbus_bool_t b;
	static DBusMessage *req, *rep;
	poptContext pctx;
	struct poptOption popts[] = {
		{"ca", 'c', POPT_ARG_STRING, &caname, 0, _("nickname of CA configuration to remove"), HELP_TYPE_NAME},
		{"session", 's', POPT_ARG_NONE, NULL, 's', _("connect to the certmonger service on the session bus"), NULL},
		{"system", 'S', POPT_ARG_NONE, NULL, 'S', _("connect to the certmonger service on the system bus"), NULL},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	if ((getenv(CERTMONGER_PVT_ADDRESS_ENV) != NULL) &&
	    (strlen(getenv(CERTMONGER_PVT_ADDRESS_ENV)) > 0)) {
		bus = cm_tdbus_private;
	}

	pctx = poptGetContext(argv0, argc, argv, popts, 0);
	if (pctx == NULL) {
		help(argv0, "remove-ca");
		return 1;
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'v':
			verbose++;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			return 1;
			break;
		}
	}
	if (c != -1) {
		printf("%s\n", make_popt_error(pctx, c));
		help(argv0, "remove-ca");
		return 1;
	}
	if (caname == NULL) {
		printf(_("CA nickname not specified.\n"));
		help(argv0, "remove-ca");
		return 1;
	}
	if (poptPeekArg(pctx) != NULL) {
		printf(_("Error: unused extra arguments were supplied.\n"));
		help(argv0, "remove-ca");
		return 1;
	}
	prep_bus(bus, "remove-ca", verbose, argc, argv);
	path = find_ca_by_name(globals.tctx, bus, caname, verbose);
	if (path == NULL) {
		printf(_("No CA with name \"%s\" found.\n"), caname);
		return 1;
	}
	req = prep_req(bus, CM_DBUS_BASE_PATH, CM_DBUS_BASE_INTERFACE,
		       "remove_known_ca");
	if (cm_tdbusm_set_p(req, path) != 0) {
		printf(_("Error setting request arguments.\n"));
		exit(1);
	}
	rep = send_req(req, verbose);
	if (cm_tdbusm_get_b(rep, globals.tctx, &b) != 0) {
		printf(_("Error parsing server response.\n"));
		exit(1);
	}
	dbus_message_unref(rep);
	if (b) {
		printf(_("CA \"%s\" removed.\n"), caname);
	} else {
		printf(_("CA could not be removed.\n"));
		exit(1);
	}
	return 0;
}
#endif

static struct {
	const char *verb;
	int (*fn)(const char *, int, const char **);
} verbs[] = {
	{"request", request},
	{"start-tracking", start_tracking},
	{"stop-tracking", stop_tracking},
	{"resubmit", resubmit},
	{"rekey", rekey},
	{"refresh", refresh},
	{"list", list},
	{"status", status},
#ifndef FORCE_CA
	{"add-ca", add_ca},
	{"add-scep-ca", add_scep_ca},
	{"add-est-ca", add_est_ca},
	{"add-acme-ca", add_acme_ca},
#endif
	{"list-cas", list_cas},
#ifndef FORCE_CA
	{"modify-ca", modify_ca},
#endif
	{"refresh-ca", refresh_ca},
#ifndef FORCE_CA
	{"remove-ca", remove_ca},
#endif
};

static void
help(const char *twopartcmd, const char *category)
{
	unsigned int i, j;
	const char *general_help[] = {
		N_("%s - client certificate enrollment tool\n"),
		NULL,
	};
	const char *request_help[] = {
		N_("Usage: %s request [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE, --keyfile=FILE\n"),
		N_("			PEM file for private key\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate (only valid with -k)\n"),
		N_("* If keys are to be encrypted:\n"),
		N_("  -p FILE, --pinfile=FILE\n"),
		N_("			file which holds the encryption PIN\n"),
		N_("  -P PIN, --pin=PIN	PIN value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME, --new-id=NAME\n"),
		N_("			new nickname to give to tracking request\n"),
		N_("  -G TYPE, --key-type=TYPE\n"),
		N_("			type of key to be generated if one is not already\n"),
		N_("			in place\n"),
		N_("  -g BITS, --key-size=BITS\n"),
		N_("			size of key to be generated if one is not already\n"),
		N_("			in place\n"),
		N_("  -r, --renew		attempt to renew the certificate when\n"),
		N_("			expiration nears (default)\n"),
		N_("  -R, --no-renew	don't attempt to renew the certificate when\n"),
		N_("			expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE, --profile=NAME\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named profile or template\n"),
		N_("  --ms-template-spec SPEC\n"),
		N_("	 		include V2 template specifier in CSR\n"),
		N_("			(format: OID:MAJOR-VERSION[:MINOR-VERSION])\n"),
		N_("  -X ISSUER, --issuer=ISSUER\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named issuer\n"),
        "\n",
		N_("* Parameters for the signing request:\n"),
		N_("  -N NAME, --subject-name=NAME\n"),
		N_("			set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE, --extended-key-usage=EXTUSAGE\n"),
		N_("			override requested extended key usage OID\n"),
		N_("  -u KEYUSAGE, --key-usage=KEYUSAGE\n"),
		N_("			set requested key usage value\n"),
		N_("  -K NAME, --principal=NAME\n"),
		N_("			override requested principal name\n"),
		N_("  -D DNSNAME, --dns=DNSNAME\n"),
		N_("			override requested DNS name\n"),
		N_("  -E EMAIL, --email=EMAIL\n"),
		N_("			override requested email address\n"),
		N_("  -A ADDRESS, --ip-address=ADDRESS\n"),
		N_("			override requested IP address\n"),
		N_("  -l FILE, --challenge-password-file=FILE\n"),
		N_("			file which holds an optional challenge password\n"),
		N_("  -L PASSWORD, --challenge-password=PASSWORD\n"),
		N_("			an optional challenge password value\n"),
		"\n",
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B COMMAND, --before-command=COMMAND\n"),
		N_("			command to run before saving the certificate\n"),
		N_("  -C COMMAND, --after-command=COMMAND\n"),
		N_("			command to run after saving the certificate\n"),
		N_("  -F FILE, --ca-file=FILE\n"),
		N_("			file in which to store the CA's certificates\n"),
		N_("  -a DIR, --ca-dbdir=DIR\n"),
		N_("			NSS database in which to store the CA's certificates\n"),
		N_("  -w, --wait		try to wait for the certificate to be issued\n"),
		N_("  --wait-timeout TIMEOUT\n"),
		N_("			Maximum time to wait for the certificateto be issued\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		N_("  -o OWNER, --key-owner=OWNER\n"),
		N_("			owner information for private key\n"),
		N_("  -m MODE, --key-perms=MODE\n"),
		N_("			file permissions for private key\n"),
		N_("  -O OWNER, --cert-owner=OWNER\n"),
		N_("			owner information for certificate\n"),
		N_("  -M MODE, --cert-perms=MODE\n"),
		N_("			file permissions for certificate\n"),
		N_("  -Z USER, --nss-user=USER\n"),
		N_("			User to switch to during NSS save operations\n"),
		NULL,
	};
	const char *start_tracking_help[] = {
		N_("Usage: %s start-tracking [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* If modifying an existing request:\n"),
		N_("  -i NAME, --id=NAME	nickname of an existing tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME, --token=NAME	optional token name for NSS-based storage\n"),
		N_("			(only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE, --keyfile=FILE\n"),
		N_("			PEM file for private key\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate (only valid with -k)\n"),
		N_("* If keys are encrypted:\n"),
		N_("  -p FILE, --pinfile=FILE\n"),
		N_("			file which holds the encryption PIN\n"),
		N_("  -P PIN, --pin=PIN	PIN value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME, --new-id=NAME\n"),
		N_("			new nickname to give to tracking request\n"),
		N_("  -r, --renew		attempt to renew the certificate when\n"),
		N_("			expiration nears (default)\n"),
		N_("  -R, --no-renew	don't attempt to renew the certificate when\n"),
		N_("			expiration nears\n"),
#ifndef FORCE_CA
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE, --profile=NAME\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named profile or template\n"),
		N_("  --ms-template-spec SPEC\n"),
		N_("	 		include V2 template specifier in CSR\n"),
		N_("			(format: OID:MAJOR-VERSION[:MINOR-VERSION])\n"),
		N_("  -X ISSUER, --issuer=ISSUER\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named issuer\n"),
		"\n",
		N_("* Parameters for the signing request at renewal time:\n"),
		N_("  -U EXTUSAGE, --extended-key-usage=EXTUSAGE\n"),
		N_("			override requested extended key usage OID\n"),
		N_("  -u KEYUSAGE, --key-usage=KEYUSAGE\n"),
		N_("			set requested key usage value\n"),
		N_("  -K NAME, --principal=NAME\n"),
		N_("			override requested principal name\n"),
		N_("  -D DNSNAME, --dns=DNSNAME\n"),
		N_("			override requested DNS name\n"),
		N_("  -E EMAIL, --email=EMAIL\n"),
		N_("			override requested email address\n"),
		N_("  -A ADDRESS, --ip-address=ADDRESS\n"),
		N_("			override requested IP address\n"),
		N_("  -l FILE, --challenge-password-file=FILE\n"),
		N_("			file which holds an optional challenge password\n"),
		N_("  -L PASSWORD, --challenge-password=PASSWORD\n"),
		N_("			an optional challenge password value\n"),
		"\n",
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		"\n",
		N_("* Other options:\n"),
		N_("  -B COMMAND, --before-command=COMMAND\n"),
		N_("			command to run before saving the certificate\n"),
		N_("  -C COMMAND, --after-command=COMMAND\n"),
		N_("			command to run after saving the certificate\n"),
		N_("  -F FILE, --ca-file=FILE\n"),
		N_("			file in which to store the CA's certificates\n"),
		N_("  -a DIR, --ca-dbdir=DIR\n"),
		N_("			NSS database in which to store the CA's certificates\n"),
		N_("  -w, --wait		try to wait for the certificate to be issued\n"),
		N_("  --wait-timeout TIMEOUT\n"),
		N_("			Maximum time to wait for the certificateto be issued\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		N_("  -o OWNER, --key-owner=OWNER\n"),
		N_("			owner information for private key\n"),
		N_("  -m MODE, --key-perms=MODE\n"),
		N_("			file permissions for private key\n"),
		N_("  -O OWNER, --cert-owner=OWNER\n"),
		N_("			owner information for certificate\n"),
		N_("  -M MODE, --cert-perms=MODE\n"),
		N_("			file permissions for certificate\n"),
		N_("  -Z USER, --nss-user=USER\n"),
		N_("			User to switch to during NSS save operations\n"),
		NULL,
	};
	const char *stop_tracking_help[] = {
		N_("Usage: %s stop-tracking [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -k FILE, --keyfile=FILE\n"),
		N_("			PEM file for private key\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate (only valid with -k)\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		"\n",
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *resubmit_help[] = {
		N_("Usage: %s resubmit [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME, --token=NAME	optional token name for NSS-based storage\n"),
		N_("			(only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate\n"),
		"\n",
		N_("* If keys are encrypted:\n"),
		N_("  -p FILE, --pinfile=FILE\n"),
		N_("			file which holds the encryption PIN\n"),
		N_("  -P PIN, --pin=PIN	PIN value\n"),
		"\n",
		N_("* New parameter values for the signing request:\n"),
		N_("  -N NAME, --subject-name=NAME\n"),
		N_("			set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE, --extended-key-usage=EXTUSAGE\n"),
		N_("			override requested extended key usage OID\n"),
		N_("  -u KEYUSAGE, --key-usage=KEYUSAGE\n"),
		N_("			set requested key usage value\n"),
		N_("  -K NAME, --principal=NAME\n"),
		N_("			override requested principal name\n"),
		N_("  -D DNSNAME, --dns=DNSNAME\n"),
		N_("			override requested DNS name\n"),
		N_("  -E EMAIL, --email=EMAIL\n"),
		N_("			override requested email address\n"),
		N_("  -A ADDRESS, --ip-address=ADDRESS\n"),
		N_("			override requested IP address\n"),
		N_("  -l FILE, --challenge-password-file=FILE\n"),
		N_("			file which holds an optional challenge password\n"),
		N_("  -L PASSWORD, --challenge-password=PASSWORD\n"),
		N_("			an optional challenge password value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME, --new-id=NAME\n"),
		N_("			new nickname to give to tracking request\n"),
#ifndef FORCE_CA
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE, --profile=NAME\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named profile or template\n"),
		N_("  --ms-template-spec SPEC\n"),
		N_("	 		include V2 template specifier in CSR\n"),
		N_("			(format: OID:MAJOR-VERSION[:MINOR-VERSION])\n"),
		N_("  -X ISSUER, --issuer=ISSUER\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named issuer\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B COMMAND, --before-command=COMMAND\n"),
		N_("			command to run before saving the certificate\n"),
		N_("  -C COMMAND, --after-command=COMMAND\n"),
		N_("			command to run after saving the certificate\n"),
		N_("  -F FILE, --ca-file=FILE\n"),
		N_("			file in which to store the CA's certificates\n"),
		N_("  -a DIR, --ca-dbdir=DIR\n"),
		N_("			NSS database in which to store the CA's certificates\n"),
		N_("  -w, --wait		try to wait for the certificate to be issued\n"),
		N_("  --wait-timeout TIMEOUT\n"),
		N_("			Maximum time to wait for the certificateto be issued\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		N_("  -o OWNER, --key-owner=OWNER\n"),
		N_("			owner information for private key\n"),
		N_("  -m MODE, --key-perms=MODE\n"),
		N_("			file permissions for private key\n"),
		N_("  -O OWNER, --cert-owner=OWNER\n"),
		N_("			owner information for certificate\n"),
		N_("  -M MODE, --cert-perms=MODE\n"),
		N_("			file permissions for certificate\n"),
		N_("  -Z USER, --nss-user=USER\n"),
		N_("			User to switch to during NSS save operations\n"),
		NULL,
	};
	const char *rekey_help[] = {
		N_("Usage: %s rekey [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME, --token=NAME	optional token name for NSS-based storage\n"),
		N_("			(only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate\n"),
		"\n",
		N_("* If keys are encrypted:\n"),
		N_("  -p FILE, --pinfile=FILE\n"),
		N_("			file which holds the encryption PIN\n"),
		N_("  -P PIN, --pin=PIN	PIN value\n"),
		"\n",
		N_("* New parameter values for the signing request:\n"),
		N_("  -N NAME, --subject-name=NAME\n"),
		N_("			set requested subject name (default: CN=<hostname>)\n"),
		N_("  -U EXTUSAGE, --extended-key-usage=EXTUSAGE\n"),
		N_("			override requested extended key usage OID\n"),
		N_("  -u KEYUSAGE, --key-usage=KEYUSAGE\n"),
		N_("			set requested key usage value\n"),
		N_("  -K NAME, --principal=NAME\n"),
		N_("			override requested principal name\n"),
		N_("  -D DNSNAME, --dns=DNSNAME\n"),
		N_("			override requested DNS name\n"),
		N_("  -E EMAIL, --email=EMAIL\n"),
		N_("			override requested email address\n"),
		N_("  -A ADDRESS, --ip-address=ADDRESS\n"),
		N_("			override requested IP address\n"),
		N_("  -l FILE, --challenge-password-file=FILE\n"),
		N_("			file which holds an optional challenge password\n"),
		N_("  -L PASSWORD, --challenge-password=PASSWORD\n"),
		N_("			an optional challenge password value\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Certificate handling settings:\n"),
		N_("  -I NAME, --new-id=NAME\n"),
		N_("			new nickname to give to tracking request\n"),
#ifndef FORCE_CA
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("  -T PROFILE, --profile=NAME\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named profile or template\n"),
		N_("  --ms-template-spec SPEC\n"),
		N_("	 		include V2 template specifier in CSR\n"),
		N_("			(format: OID:MAJOR-VERSION[:MINOR-VERSION])\n"),
		N_("  -X ISSUER, --issuer=ISSUER\n"),
		N_("			ask the CA to process the request using the\n"),
		N_("			named issuer\n"),
		N_("  -G TYPE, --key-type=TYPE\n"),
		N_("			type of key to be generated if one is not already\n"),
		N_("			in place\n"),
		N_("  -g BITS, --key-size=BITS\n"),
		N_("			size of key to be generated if one is not already\n"),
		N_("			in place\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -B COMMAND, --before-command=COMMAND\n"),
		N_("			command to run before saving the certificate\n"),
		N_("  -C COMMAND, --after-command=COMMAND\n"),
		N_("			command to run after saving the certificate\n"),
		N_("  -F FILE, --ca-file=FILE\n"),
		N_("			file in which to store the CA's certificates\n"),
		N_("  -a DIR, --ca-dbdir=DIR\n"),
		N_("			NSS database in which to store the CA's certificates\n"),
		N_("  -w, --wait		try to wait for the certificate to be issued\n"),
		N_("  --wait-timeout TIMEOUT\n"),
		N_("			Maximum time to wait for the certificateto be issued\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *list_help[] = {
		N_("Usage: %s list [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
#ifndef FORCE_CA
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("  -r, --requests-only	list only information about outstanding requests\n"),
		N_("  -t, --tracking-only	list only information about tracked certificates\n"),
		N_("  -u, --utc		display times in UTC instead of local time\n"),
		N_("* If selecting a specific request:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			only list requests and certs stored in this PEM file\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *refresh_help[] = {
		N_("Usage: %s refresh [options]\n"),
		"\n",
		N_("* General options:\n"),
		N_("  -a, --all		refresh information about all outstanding requests\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* By request identifier:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* If using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("  -t NAME, --token=NAME	optional token name for NSS-based storage\n"),
		N_("			(only valid with -d)\n"),
		N_("* If using files for storage:\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			PEM file for certificate\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *status_help[] = {
		N_("Usage: %s status [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* Selecting a specific request:\n"),
		N_("  -i NAME, --id=NAME	nickname for tracking request\n"),
		N_("* When using an NSS database for storage:\n"),
		N_("  -d DIR, --dbdir=DIR	NSS database for key and cert\n"),
		N_("  -n NAME, --nickname NAME\n"),
		N_("			nickname for NSS-based storage (only valid with -d)\n"),
		N_("* When using files for storage:\n"),
		N_("  -f FILE, --certfile=FILE\n"),
		N_("			return status for cert stored in this PEM file\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *list_cas_help[] = {
		N_("Usage: %s list-cas [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
#ifndef FORCE_CA
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
#endif
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *refresh_ca_help[] = {
		N_("Usage: %s refresh-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
#ifndef FORCE_CA
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("  -a, --all		refresh information about all known CAs\n"),
#endif
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
#ifndef FORCE_CA
	const char *add_ca_help[] = {
		N_("Usage: %s add-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("  -e CMD, --command CMD	helper command to run to communicate with CA\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *add_scep_ca_help[] = {
		N_("Usage: %s add-scep-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("  -u URL, --URL URL	location of SCEP server\n"),
		N_("  -i ID, --id ID	CA identifier\n"),
		N_("  -R FILE, --ca-cert=FILE\n"),
		N_("			file containing web server's certificate\n"),
		N_("  -r FILE, --ra-cert=FILE\n"),
		N_("			file containing RA's certificate\n"),
		N_("  -N FILE, --signingca=FILE\n"),
		N_("			file containing CA's certificate\n"),
		N_("  -I FILE, --other-certs=FILE\n"),
		N_("			file containing certificates in RA's certifying chain\n"),
		N_("  -n, --non-renewal	prefer not to use the SCEP Renewal feature\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *add_est_ca_help[] = {
		N_("Usage: %s add-est-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("  -u URL, --URL URL	location of EST server\n"),
		N_("  -i LABEL, --label LABEL\n"),
		N_("			CA label\n"),
		N_("  -R FILE, --ca-cert=FILE\n"),
		N_("			file containing web server's CA certificate\n"),
		N_("  -U NAME, --username=NAME\n"),
		N_("			user name for enrollment\n"),
		N_("  -W FILE, --password-file=FILE\n"),
		N_("			file containing password for enrollment\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *add_acme_ca_help[] = {
		N_("Usage: %s add-acme-ca [options]\n"),
		"\n",
		N_("Required arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	nickname to give to the new CA configuration\n"),
		N_("  -u URL, --directory=URL\n"),
		N_("			location of the ACME server's directory\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -R FILE, --ca-cert=FILE\n"),
		N_("			file containing web server's CA certificate\n"),
		N_("  --eab-kid=KID		key identifier for external account binding\n"),
		N_("  --eab-key-file=FILE	file containing the MAC key for external account binding\n"),
		N_("  --attest=tpm		answer device-attest-01 challenges with a TPM attestation\n"),
		N_("  --permanent-identifier=ID\n"),
		N_("			the device's permanent identifier\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *modify_ca_help[] = {
		N_("Usage: %s modify-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("  -e CMD, --command CMD	helper command to run to communicate with CA\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
	const char *remove_ca_help[] = {
		N_("Usage: %s remove-ca [options]\n"),
		"\n",
		N_("Optional arguments:\n"),
		N_("* General options:\n"),
		N_("  -c CA, --ca=NAME	use the specified CA rather than the default\n"),
		N_("* Bus options:\n"),
		N_("  -S, --system		connect to the certmonger service on the system bus\n"),
		N_("  -s, --session		connect to the certmonger service on the session bus\n"),
		N_("* Other options:\n"),
		N_("  -v, --verbose		report all details of errors\n"),
		NULL,
	};
#endif
	struct {
		const char *category;
		const char **msgs;
		const char *brief;
	} msgs[] = {
		{NULL, general_help,
		 N_("Usage: %s command [options]\n")},
		{"request", request_help,
		 N_("request a new certificate from a CA\n")},
		{"start-tracking", start_tracking_help,
		 N_("begin monitoring an already-issued certificate\n")},
		{"stop-tracking", stop_tracking_help,
		 N_("stop monitoring a certificate\n")},
		{"resubmit", resubmit_help,
		 N_("resubmit an in-progress enrollment request, or start a new one\n")},
		{"rekey", rekey_help,
		 N_("generate a new private key and replace a certificate\n")},
		{"refresh", refresh_help,
		 N_("check on the status of an in-progress enrollment request\n")},
		{"list", list_help,
		 N_("list certificates being monitored and requested\n")},
		{"status", status_help,
		 N_("check the status of a certificate being monitored or requested\n")},
#ifndef FORCE_CA
		{"add-ca", add_ca_help,
		 N_("add a CA configuration\n")},
		{"add-scep-ca", add_scep_ca_help,
		 N_("add an SCEP CA configuration\n")},
		{"add-est-ca", add_est_ca_help,
		 N_("add an EST CA configuration\n")},
		{"add-acme-ca", add_acme_ca_help,
		 N_("add an ACME CA configuration\n")},
#endif
		{"list-cas", list_cas_help,
		 N_("list known CA configurations\n")},
#ifndef FORCE_CA
		{"modify-ca", modify_ca_help,
		 N_("modify a CA configuration\n")},
#endif
		{"refresh-ca", refresh_ca_help,
		 N_("refresh cache of all information obtained from a CA\n")},
#ifndef FORCE_CA
		{"remove-ca", remove_ca_help,
		 N_("remove a CA configuration\n")},
#endif
	};
	char *cmd;

	cmd = strdup(twopartcmd);
	if (cmd == NULL) {
		return;
	}
	cmd[strcspn(cmd, " \t")] = '\0';
	for (i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
		if ((category != NULL) && (msgs[i].category != NULL) &&
		    (strcmp(category, msgs[i].category) != 0)) {
			continue;
		}
		if (category == NULL) {
			if (msgs[i].category != NULL) {
				printf("%-15s\t", msgs[i].category);
			} else {
				for (j = 0; msgs[i].msgs[j] != NULL; j++) {
					printf(_(msgs[i].msgs[j]), cmd);
				}
				printf("\n");
			}
			printf(_(msgs[i].brief), cmd);
		} else {
			if (i > 0) {
				printf("\n");
			}
			for (j = 0; msgs[i].msgs[j] != NULL; j++) {
				printf(_(msgs[i].msgs[j]), cmd);
			}
		}
	}
	free(cmd);
}

int
main(int argc, const char **argv)
{
	const char *p, *argv1;
	char poptname[LINE_MAX];
	unsigned int i;
	mode_t mask;
	int ret;
#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
#endif
	/* Before NSS loads the tpm2-pkcs11 module, if it does, which makes
	 * an empty store in the daemon's directory if there is none yet:
	 * only we may read it, as the daemon's own files. */
	cm_tpm_token_client_setenv();
	mask = umask(S_IRWXG | S_IRWXO);
	NSS_NoDB_Init(NULL);
	umask(mask);
	p = argv[0];
	if (strchr(p, '/') != NULL) {
		p = strrchr(p, '/') + 1;
	}
	globals.argv0 = p;
	if (argc > 1) {
		globals.verb = argv[1];
		snprintf(poptname, sizeof(poptname), "%s %s", globals.argv0,
			 globals.verb);
		globals.tctx = talloc_new(NULL);
		for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
			if (strcmp(verbs[i].verb, globals.verb) == 0) {
				argv1 = argv[1];
				argv[1] = poptname;
				ret = (*verbs[i].fn)(poptname, argc - 1,
						     argv + 1);
				argv[1] = argv1;
				return ret;
			}
		}
		fprintf(stderr, _("%s: unrecognized command\n"), globals.verb);
		if (globals.verb[0] == '-') {
			help(globals.argv0, NULL);
		}
		talloc_free(globals.tctx);
		globals.tctx = NULL;
		return 1;
	} else {
		help(globals.argv0, NULL);
		return 1;
	}
}
