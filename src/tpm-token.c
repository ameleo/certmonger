/*
 * Copyright (C) 2026 Ameleo
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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <talloc.h>

#include "tpm-token.h"

/* Split a helper's command line into words, as the shell would for the
 * simple quoting which "getcert add-*-ca" uses. */
static char **
split_words(void *parent, const char *cmdline)
{
	char **words, *word, quote;
	const char *p;
	int n = 0, len;

	words = talloc_zero_array(parent, char *, strlen(cmdline) + 1);
	word = talloc_size(parent, strlen(cmdline) + 1);
	if ((words == NULL) || (word == NULL)) {
		return NULL;
	}
	p = cmdline;
	while (*p != '\0') {
		while ((*p == ' ') || (*p == '\t')) {
			p++;
		}
		if (*p == '\0') {
			break;
		}
		len = 0;
		quote = '\0';
		while ((*p != '\0') &&
		       ((quote != '\0') || ((*p != ' ') && (*p != '\t')))) {
			if ((quote == '\0') && ((*p == '\'') || (*p == '"'))) {
				quote = *p;
			} else
			if ((quote != '\0') && (*p == quote)) {
				quote = '\0';
			} else
			if ((quote != '\'') && (*p == '\\') && (p[1] != '\0')) {
				word[len++] = *++p;
			} else {
				word[len++] = *p;
			}
			p++;
		}
		word[len] = '\0';
		words[n++] = talloc_strdup(words, word);
	}
	talloc_free(word);
	return words;
}

/* The ACME helper's options which ask for a TPM attestation: "-a tpm" or
 * "--attest=tpm", as "getcert add-acme-ca --attest tpm" writes them. */
int
cm_tpm_token_helper_attests(const char *helper)
{
	char **argv;
	const char *base;
	int i, ret = 0;

	if (helper == NULL) {
		return 0;
	}
	argv = split_words(NULL, helper);
	if ((argv == NULL) || (argv[0] == NULL)) {
		talloc_free(argv);
		return 0;
	}
	base = strrchr(argv[0], '/');
	base = (base != NULL) ? base + 1 : argv[0];
	if (strcmp(base, "acme-submit") == 0) {
		for (i = 1; argv[i] != NULL; i++) {
			if (((strcmp(argv[i], "-a") == 0) ||
			     (strcmp(argv[i], "--attest") == 0)) &&
			    (argv[i + 1] != NULL) &&
			    (strcasecmp(argv[i + 1], "tpm") == 0)) {
				ret = 1;
			}
			if ((strcasecmp(argv[i], "-atpm") == 0) ||
			    (strcasecmp(argv[i], "--attest=tpm") == 0)) {
				ret = 1;
			}
		}
	}
	talloc_free(argv);
	return ret;
}

void
cm_tpm_token_client_setenv(void)
{
#ifdef CM_TPM2_PKCS11_MODULE
	const char *dir;

	if (access(CM_TPM2_PKCS11_MODULE, R_OK) != 0) {
		return;
	}
	/* NSS loads the module into this process too where p11-kit makes it
	 * known to every user of NSS.  Point it at the daemon's store, as the
	 * daemon does, when the daemon has made its directory and we may use
	 * it, so that the module doesn't complain about finding no store. */
	if ((getenv("TPM2_PKCS11_STORE") == NULL) &&
	    (access(CM_TPM2_PKCS11_DEFAULT_STORE, F_OK) != 0)) {
		dir = getenv(CM_STORE_TPM_DIRECTORY_ENV);
		if (dir == NULL) {
			dir = CM_STORE_TPM_DIRECTORY;
		}
		if (access(dir, R_OK | W_OK | X_OK) == 0) {
			setenv("TPM2_PKCS11_STORE", dir, 1);
		}
	}
	/* We use no token at all: what the module warns about is noise. */
	if (getenv("TPM2_PKCS11_LOG_LEVEL") == NULL) {
		setenv("TPM2_PKCS11_LOG_LEVEL", "0", 1);
	}
#endif
}
