/*
 * Copyright (C) 2009,2011,2012,2013,2014,2015 Red Hat, Inc.
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
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <talloc.h>
#include <tevent.h>

#include <dbus/dbus.h>

#include <popt.h>

#include "cm.h"
#include "env.h"
#include "log.h"
#include "tdbus.h"
#include "tdbusm.h"
#include "util-n.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define N_(_text) _text
#define _(_text) dgettext(PACKAGE, _text)
#else
#define N_(_text) _text
#define _(_text) (_text)
#endif

int
main(int argc, const char **argv)
{
	struct tevent_context *ec;
	struct cm_context *ctx;
	enum cm_tdbus_type bus;
	int i, c, dlevel = 0, pfd = -1, lfd = -1, version = 0;
	unsigned int u;
	long l;
	pid_t pid;
	FILE *pfp;
	const char *pidfile = NULL, *tmpdir, *gate_command = NULL, *path = NULL;
	char *env_tmpdir, *hint, *address;
	dbus_bool_t dofork, server, server_only;
	enum force_fips_mode forcefips;
	int bustime;
	DBusError error;
	poptContext pctx;
	struct poptOption popts[] = {
		{"session-bus", 's', POPT_ARG_NONE, NULL, 's', N_("use session bus"), NULL},
		{"system-bus", 'S', POPT_ARG_NONE, NULL, 'S', N_("use system bus"), NULL},
		{"listening-socket", 'l', POPT_ARG_NONE, NULL, 'l', N_("start a dedicated listening socket"), NULL},
		{"only-listening-socket", 'L', POPT_ARG_NONE, NULL, 'L', N_("only use a dedicated listening socket"), NULL},
		{"listening-socket-path", 'P', POPT_ARG_STRING, &path, 0, N_("specify the dedicated listening socket"), N_("PATHNAME")},
		{"nofork", 'n', POPT_ARG_NONE, NULL, 'n', N_("don't become a daemon"), NULL},
		{"fork", 'f', POPT_ARG_NONE, NULL, 'f', N_("do become a daemon"), NULL},
		{"bus-activation-timeout", 'b', POPT_ARG_INT, NULL, 'b', N_("bus-activated, idle timeout"), N_("SECONDS")},
		{"no-bus-activation-timeout", 'B', POPT_ARG_NONE, NULL, 'B', N_("don't use an idle timeout"), NULL},
		{"debug-level", 'd', POPT_ARG_INT, NULL, 'd', N_("set debugging level (implies -n)"), N_("NUMBER")},
		{"command", 'c', POPT_ARG_STRING, &gate_command, 'c', N_("start COMMAND and exit when it does"), N_("COMMAND")},
		/* this next one is there to paper over documentation that named the flag wrong */
		{NULL, 'C', POPT_ARG_STRING | POPT_ARGFLAG_DOC_HIDDEN, &gate_command, 'c', N_("start COMMAND and exit when it does"), N_("COMMAND")},
		{"pidfile", 'p', POPT_ARG_STRING, &pidfile, 0, N_("write service PID to file"), N_("FILENAME")},
		{"fips", 'F', POPT_ARG_NONE, NULL, 'F', N_("force NSS into FIPS mode"), NULL},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h', NULL, NULL},
		{"version", 'v', POPT_ARG_NONE, &version, 0, N_("print version information"), NULL},
		{"autohelp", 'H', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, NULL, 'H', NULL, NULL},
		POPT_TABLEEND
	};

	bus = cm_env_default_bus();
	dofork = cm_env_default_fork();
	bustime = cm_env_default_bus_timeout();
	forcefips = do_not_force_fips;
	server = FALSE;
	server_only = FALSE;

#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, MYLOCALEDIR);
	for (u = 0; u < sizeof(popts) / sizeof(popts[0]); u++) {
		if (popts[u].descrip != NULL) {
			popts[u].descrip = dgettext(PACKAGE, popts[u].descrip);
		}
		if (popts[u].argDescrip != NULL) {
			popts[u].argDescrip = dgettext(PACKAGE,
						       popts[u].argDescrip);
		}
	}
#endif

	if (cm_env_whoami() == NULL) {
		printf("internal error\n");
		exit(1);
	}
	if ((cm_env_config_dir() == NULL) ||
	    (cm_env_request_dir() == NULL) ||
	    (cm_env_ca_dir() == NULL) ||
	    (cm_env_tmp_dir() == NULL)) {
		printf("%s: unable to determine storage locations\n",
		       cm_env_whoami());
		exit(1);
	};

	pctx = poptGetContext(argv[0], argc, argv, popts, 0);
	if (pctx == NULL) {
		exit(1);
	}
	while ((c = poptGetNextOpt(pctx)) > 0) {
		switch (c) {
		case 's':
			bus = cm_tdbus_session;
			break;
		case 'S':
			bus = cm_tdbus_system;
			break;
		case 'l':
			server = TRUE;
			break;
		case 'L':
			server = TRUE;
			server_only = TRUE;
			break;
		case 'c':
			bustime = 0;
			break;
		case 'f':
			dofork = TRUE;
			break;
		case 'b':
			gate_command = NULL;
			bustime = atoi(poptGetOptArg(pctx));
			break;
		case 'B':
			bustime = 0;
			break;
		case 'd':
			dlevel = atoi(poptGetOptArg(pctx));
			/* fall through */
		case 'n':
			dofork = FALSE;
			break;
		case 'F':
			forcefips = do_force_fips;
			break;
		case 'H':
			poptPrintHelp(pctx, stdout, 0);
			exit(1);
			break;
		default:
			printf(_("Usage: %s [-s|-S] [-n|-f] [-d LEVEL] "
				 "[-p FILE] [-F] [-v]\n"), cm_env_whoami());
			printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			       _("\t-s         use session bus\n"),
			       _("\t-S         use system bus\n"),
			       _("\t-l         start a dedicated listening socket\n"),
			       _("\t-L         only use a dedicated listening socket\n"),
			       _("\t-P PATH    specify the dedicated listening socket\n"),
			       _("\t-n         don't become a daemon\n"),
			       _("\t-f         do become a daemon\n"),
			       _("\t-b TIMEOUT bus-activated, idle timeout\n"),
			       _("\t-B         don't use an idle timeout\n"),
			       _("\t-d LEVEL   set debugging level (implies -n)\n"),
			       _("\t-c COMMAND start COMMAND and exit when it does\n"),
			       _("\t-p FILE    write service PID to file\n"),
			       _("\t-F         force NSS into FIPS mode\n"),
			       _("\t-v         print version information and exit\n"));
			exit(1);
			break;
		}
	}
	if (c != -1) {
		exit(1);
	}
	if (version) {
		printf("%s %s\n", PACKAGE, PACKAGE_VERSION);
		exit(0);
	}

	cm_log_set_level(dlevel);
	cm_log_set_method(dofork ? cm_log_syslog : cm_log_stderr);
	util_n_set_fips(forcefips);
	cm_log(3, "Starting up.\n");

	tmpdir = cm_env_tmp_dir();
	if (tmpdir != NULL) {
		env_tmpdir = malloc(8 + strlen(tmpdir));
		if (env_tmpdir == NULL) {
			fprintf(stderr, "Out of memory.\n");
			exit(1);
		}
		snprintf(env_tmpdir, 8 + strlen(tmpdir), "TMPDIR=%s", tmpdir);
		if (putenv(env_tmpdir) != 0) {
			printf("internal error: %s\n", strerror(errno));
			exit(1);
		}
	}

	ec = tevent_context_init(NULL);
	if (ec == NULL) {
		fprintf(stderr, "Error initializing tevent.\n");
		exit(1);
	}
	if (dlevel > 0) {
		tevent_set_debug_stderr(ec);
	}

	umask(S_IRWXG | S_IRWXO);

	/* Set our working directory - the root for a system instance, the
	 * configuration directory for a session instance. */
	switch (bus) {
	case cm_tdbus_private:
	case cm_tdbus_system:
		cm_log(2, "Changing to root directory.\n");
		if (chdir("/") != 0) {
			cm_log(0, "Error in chdir(\"/\"): %s.\n",
			       strerror(errno));
		}
		cm_log(2, "Obtaining system lock.\n");
		break;
	case cm_tdbus_session:
		cm_log(2, "Changing to config directory.\n");
		if (chdir(cm_env_config_dir()) != 0) {
			cm_log(2, "Error in chdir(\"%s\"): %s.\n",
			       cm_env_config_dir(), strerror(errno));
		}
		cm_log(2, "Obtaining session lock.\n");
		break;
	}

	/* Open the lock file.  This is primarily here to avoid having multiple
	 * session copies attempting to read and write and operate on the same
	 * records at the same time. */
	lfd = open(cm_env_lock_file(), O_RDWR | O_CREAT,
		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (lfd == -1) {
		fprintf(stderr, "Error opening lockfile \"%s\": %s\n",
			cm_env_lock_file(), strerror(errno));
		exit(1);
	}
	if (lockf(lfd, F_TLOCK, 0) != 0) {
		fprintf(stderr, "Error locking lockfile \"%s\": %s\n",
			cm_env_lock_file(), strerror(errno));
		close(lfd);
		exit(1);
	}
	l = fcntl(lfd, F_GETFD);
	if (l != -1) {
		l = fcntl(lfd, F_SETFD, l | FD_CLOEXEC);
		if (l == -1) {
			fprintf(stderr,
				"Error setting close-on-exec flag on "
				"\"%s\": %s\n",
				cm_env_lock_file(), strerror(errno));
			close(lfd);
			exit(1);
		}
	}

	/* Load up all of our data. */
	ctx = NULL;
	i = cm_init(ec, &ctx, bustime, gate_command);
	if (i != 0) {
		fprintf(stderr, "Error: %s\n", strerror(i));
		talloc_free(ec);
		exit(1);
	}

	if (!server_only) {
		/* Join a bus and obtain our well-known name. */
		if (cm_tdbus_setup_public(ec, bus, ctx, &error) != 0) {
			fprintf(stderr, "Error connecting to D-Bus.\n");
			hint = cm_tdbusm_hint(ec, error.name, error.message);
			if (hint != NULL) {
				fprintf(stderr, "%s", hint);
			}
			talloc_free(ec);
			exit(1);
		}
	}
	if (server) {
		/* Set up a private listening socket. */
		if (cm_tdbus_setup_private(ec, ctx, path, &address,
					   &error) != 0) {
			fprintf(stderr, "Error setting up D-Bus listener.\n");
			hint = cm_tdbusm_hint(ec, error.name, error.message);
			if (hint != NULL) {
				fprintf(stderr, "%s", hint);
			}
			talloc_free(ec);
			exit(1);
		}
		cm_set_server_address(ctx, address);
	}

	/* Create the pid file, if we need to. */
	if (pidfile != NULL) {
		pfd = open(pidfile, O_RDWR | O_CREAT,
			   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pfd == -1) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			exit(1);
		}
		if (lockf(pfd, F_TLOCK, 0) != 0) {
			fprintf(stderr, "Error locking pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
		if (ftruncate(pfd, 0) != 0) {
			fprintf(stderr, "Error truncating pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
		l = fcntl(pfd, F_GETFD);
		if (l != -1) {
			if (fcntl(pfd, F_SETFD, l | FD_CLOEXEC) != 0) {
				fprintf(stderr, "Error marking pidfile \"%s\" "
					"as close-on-exec: %s\n",
					pidfile, strerror(errno));
				close(pfd);
				exit(1);
			}
		}
		pfp = fdopen(pfd, "w");
		if (pfp == NULL) {
			fprintf(stderr, "Error opening pidfile \"%s\": %s\n",
				pidfile, strerror(errno));
			close(pfd);
			exit(1);
		}
	} else {
		pfp = NULL;
	}

	if (dofork) {
		pid = fork();
		switch (pid) {
		case -1:
			/* failure */
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			if ((pidfile != NULL) && (pfp != NULL)) {
				fclose(pfp);
			}
			exit(1);
			break;
		case 0:
			/* child; keep going */
			if (daemon(0, 0) != 0) {
				fprintf(stderr, "daemon() error: %s\n",
					strerror(errno));
				exit(1);
			}
			/* lock the pid file now that our parent is exiting and
			 * thus losing its lock; it should be safe to block
			 * here, even if the parent gives up the lock before we
			 * get here, because we've already ensured that only we
			 * and our parent have the named connection to the bus,
			 * and wouldn't have gotten here otherwise */
			if ((pidfile != NULL) && (pfp != NULL)) {
				if (lockf(pfd, F_LOCK, 0) != 0) {
					cm_log(0,
					       "Error locking pidfile \"%s\": "
					       "%s\n",
					       pidfile, strerror(errno));
					exit(1);
				}
				fprintf(pfp, "%ld\n", (long) getpid());
				fflush(pfp);
			}
			break;
		default:
			/* parent; exit cleanly */
			exit(0);
			break;
		}
	} else {
		if ((pidfile != NULL) && (pfp != NULL)) {
			fprintf(pfp, "%ld\n", (long) getpid());
			fflush(pfp);
		}
	}

	/* Kick each request and CA's state machine off. */
	if (cm_start_all(ctx) == 0) {
		do {
			i = tevent_loop_once(ec);
			if (i != 0) {
				cm_log(3, "Event loop exits with status %d.\n",
				       i);
				break;
			}
		} while (cm_keep_going(ctx) == 0);
		cm_log(3, "Shutting down.\n");
		cm_stop_all(ctx);
	}

	/* Clean up. */
	talloc_free(ctx);
	talloc_free(ec);

	/* Remove the PID file. */
	if ((pidfile != NULL) && (pfp != NULL)) {
		if (remove(pidfile) != 0) {
			cm_log(0, "Error removing pidfile \"%s\": %s.\n",
			       pidfile, strerror(errno));
		}
		fclose(pfp);
	}
	return 0;
}
