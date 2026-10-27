/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>

#include <krb5.h>

#include <talloc.h>

#include "certext.h"
#include "certext-n.h"
#include "certread.h"
#include "certread-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tpm-token.h"
#include "util-n.h"

struct cm_certread_state {
	struct cm_certread_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};
struct cm_certread_n_settings {
	unsigned int readwrite:1;
};

static int
cm_certread_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	int status = CM_SUB_STATUS_INTERNAL_ERROR, readwrite, ec;
	char *pin;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotInfo *slot = NULL;
	CERTCertificate *cert;
	struct cm_certread_n_settings *settings;
	struct cm_pin_cb_data cb_data;
	FILE *fp;
	const char *es;
	char *nickname;

	if (entry->cm_cert_storage_location == NULL) {
		cm_log(1, "Error reading certificate: no location "
		       "specified.\n");
		_exit(1);
	}
	if (entry->cm_cert_nickname == NULL) {
		cm_log(1, "Error reading certificate: no nickname "
		       "specified.\n");
		_exit(1);
	}

	/* Open the status descriptor for stdio. */
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(1);
	}
	/* A certificate in our TPM token: set the token up first, if it
	 * isn't. */
	if (cm_tpm_token_entry_uses(entry) &&
	    (cm_tpm_token_prepare(entry, &es) != 0)) {
		cm_log(1, "Error preparing the TPM token: %s.\n", es);
	}
	/* Open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	ctx = NSS_InitContext(entry->cm_cert_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	ec = PORT_GetError();
	if (ctx == NULL) {
		if ((ec == SEC_ERROR_BAD_DATABASE) && readwrite) {
			switch (errno) {
			case EACCES:
			case EPERM:
				ec = PR_NO_ACCESS_RIGHTS_ERROR;
				break;
			default:
				/* Sigh.  Not a lot of detail.  Check if we
				 * succeed in read-only mode, which we'll
				 * interpret as lack of write permissions. */
				ctx = NSS_InitContext(entry->cm_key_storage_location,
						      NULL, NULL, NULL, NULL,
						      NSS_INIT_READONLY |
						      NSS_INIT_NOROOTINIT |
						      NSS_INIT_NOMODDB);
				if (ctx != NULL) {
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down "
						       "NSS.\n");
					}
					ctx = NULL;
					ec = PR_NO_ACCESS_RIGHTS_ERROR;
				}
				break;
			}
		}
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(0, "Unable to open NSS database '%s': %s.\n",
			       entry->cm_cert_storage_location, es);
		} else {
			cm_log(0, "Unable to open NSS database '%s'.\n",
			       entry->cm_cert_storage_location);
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			status = CM_SUB_STATUS_ERROR_PERMS;
			break;
		default:
			status = CM_SUB_STATUS_ERROR_INITIALIZING;
			break;
		}
		cm_log(0, "Unable to open NSS database.\n");
		_exit(status);
	}
    /* Re-open the database with modules enabled */
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
		_exit(1);
	}
	ctx = NSS_InitContext(entry->cm_cert_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT);
	if (ctx == NULL) {
		cm_log(0, "Unable to initialize NSS db\n");
		_exit(1);
	}
	es = util_n_fips_hook();
	if (es != NULL) {
		cm_log(0, "Error putting NSS into FIPS mode: %s\n", es);
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}
	cert = NULL;
	if (cm_pin_read_for_cert(entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for cert db.\n");
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	if (entry->cm_cert_token == NULL) {
		entry->cm_cert_token = util_internal_token_name(entry);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_cert_nss_cb);
	es = util_internal_token_name(entry);
	if (strcmp(entry->cm_cert_token, es) == 0) {
		slot = PK11_GetInternalKeySlot();
		nickname = talloc_strdup(entry, entry->cm_cert_nickname);
	} else {
		slot = PK11_FindSlotByName(entry->cm_cert_token);
		nickname = talloc_asprintf(entry, "%s:%s",
			entry->cm_cert_token, entry->cm_cert_nickname);
	}
	if (slot == NULL) {
		cm_log(0, "Could not find the slot slot %s.\n", entry->cm_cert_token);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}
	/* Be ready to count our uses of a PIN. */
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	/* If we're supposed to be using a PIN, and we're offered a
	 * chance to set one, do it now. */
	if (readwrite) {
		if (PK11_NeedUserInit(slot)) {
			if (cm_pin_read_for_cert(entry, &pin) != 0) {
				cm_log(0, "Error reading PIN to assign "
				       "to storage slot.\n");
				PK11_FreeSlot(slot);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(2);
			}
			PK11_InitPin(slot, NULL, pin);
			if (PK11_NeedUserInit(slot)) {
				cm_log(0, "Cert storage slot still "
				       "needs user PIN to be set.\n");
				PK11_FreeSlot(slot);
				if (NSS_ShutdownContext(ctx) != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(2);
			}
			/* We're authenticated now, so count this as a
			 * use of the PIN. */
			cb_data.n_attempts++;
		} 
	}
	/* If we need to log in in order to read certificates, do so. */
	if (PK11_NeedLogin(slot)) {
		cm_log(3, "Need login to token %s\n", PK11_GetTokenName(slot));
		if (cm_pin_read_for_cert(entry, &pin) != 0) {
			cm_log(0, "Error reading PIN for cert db\n");
			PK11_FreeSlot(slot);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(2);
		}
		error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
		if (error != SECSuccess) {
			cm_log(0, "certread-n: Error authenticating to cert db "
				   "slot %s.\n", PK11_GetTokenName(slot));
			PK11_FreeSlot(slot);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(2);
		}
		if ((pin != NULL) &&
		    (strlen(pin) > 0) &&
		    (cb_data.n_attempts == 0)) {
			cm_log(0, "PIN was not needed to auth to token "
			       "%s, though one was provided. "
			       "Treating this as an error.\n", PK11_GetTokenName(slot));
			PK11_FreeSlot(slot);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(2);
		}
	}
	cm_log(3, "Looking for nickname %s\n", nickname);
	cert = PK11_FindCertFromNickname(nickname, pin);

	if (cert) {
		cm_log(3, "Located the certificate \"%s\".\n", nickname);
	} else {
		cm_log(3, "Error locating certificate.\n");
		PK11_FreeSlot(slot);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(2);
	}

	cm_certread_n_parse(entry, cert->derCert.data, cert->derCert.len);
	cm_certread_write_data_to_pipe(entry, fp);
	fclose(fp);
	PK11_FreeSlot(slot);
	CERT_DestroyCertificate(cert);
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	_exit(0);
}

/* Parse the certificate in the entry, and refresh the certificate-based
 * fields. */
void
cm_certread_n_parse(struct cm_store_entry *entry,
		    unsigned char *der_cert, unsigned int der_cert_len)
{
	PLArenaPool *arena;
	SECItem item, *items;
	CERTCertificate *cert, **certs;
	NSSInitContext *ctx;
	char *p;
	const char *nl, *es = NULL;
	unsigned int i;

	/* Initialize the library. */
	ctx = NSS_InitContext(NULL,
			      NULL, NULL, NULL, NULL,
			      NSS_INIT_NOCERTDB |
			      NSS_INIT_NOMODDB |
			      NSS_INIT_READONLY |
			      NSS_INIT_NOROOTINIT);
	if (ctx == NULL) {
		PRErrorCode ec = PR_GetError();
		if (ec) {
			es = PR_ErrorToName(ec);
		}
		cm_log(1, "Unable to initialize NSS %s\n", es ? es: "");
        
		_exit(1);
	}
	es = util_n_fips_hook();
	if (es != NULL) {
		cm_log(1, "Error putting NSS into FIPS mode: %s\n", es);
		_exit(1);
	}
	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Error opening database '%s'.\n",
		       entry->cm_cert_storage_location);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(ENOMEM);
	}
	/* Decode the certificate. */
	item.data = der_cert;
	item.len = der_cert_len;
	items = &item;
	certs = NULL;
	if ((CERT_ImportCerts(CERT_GetDefaultCertDB(), 0,
			      1, &items, &certs, PR_FALSE, PR_FALSE,
			      "temp") != SECSuccess) ||
	    (certs == NULL) ||
	    (certs[0] == NULL)) {
		cm_log(1, "Error decoding certificate.\n");
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(1);
	}
	cert = certs[0];
	/* Pick out the interesting bits. */
	/* Issuer name */
	talloc_free(entry->cm_cert_issuer_der);
	entry->cm_cert_issuer_der = cm_store_hex_from_bin(entry,
							  cert->derIssuer.data,
							  cert->derIssuer.len);
	talloc_free(entry->cm_cert_issuer);
	entry->cm_cert_issuer = talloc_strdup(entry, cert->issuerName);
	/* Serial number */
	talloc_free(entry->cm_cert_serial);
	item = cert->serialNumber;
	entry->cm_cert_serial = cm_store_hex_from_bin(entry, item.data,
						      item.len);
	/* Subject name */
	talloc_free(entry->cm_cert_subject_der);
	item = cert->derSubject;
	entry->cm_cert_subject_der = cm_store_hex_from_bin(entry, item.data,
							   item.len);
	talloc_free(entry->cm_cert_subject);
	entry->cm_cert_subject = talloc_strdup(entry, cert->subjectName);
	/* Subject Public Key Info, encoded into a blob. */
	talloc_free(entry->cm_cert_spki);
	if (SEC_ASN1EncodeItem(arena, items, &cert->subjectPublicKeyInfo,
			       CERT_SubjectPublicKeyInfoTemplate) != items) {
		cm_log(1, "Error encoding subjectPublicKeyInfo.\n");
		CERT_DestroyCertArray(certs, 1);
		PORT_FreeArena(arena, PR_TRUE);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(1);
	}
	entry->cm_cert_spki = cm_store_hex_from_bin(entry, items->data,
						    items->len);
	/* Not-before date. */
	p = talloc_strndup(entry, (char *) cert->validity.notBefore.data,
			   cert->validity.notBefore.len);
	if (p != NULL) {
		entry->cm_cert_not_before = cm_store_time_from_timestamp(p);
	} else {
		entry->cm_cert_not_before = 0;
	}
	/* Not-after date. */
	p = talloc_strndup(entry, (char *) cert->validity.notAfter.data,
			   cert->validity.notAfter.len);
	if (p != NULL) {
		entry->cm_cert_not_after = cm_store_time_from_timestamp(p);
	} else {
		entry->cm_cert_not_after = 0;
	}
	/* Hostname from subjectAltName extension. */
	talloc_free(entry->cm_cert_hostname);
	entry->cm_cert_hostname = NULL;
	/* Email address from subjectAltName extension. */
	talloc_free(entry->cm_cert_email);
	entry->cm_cert_email = NULL;
	/* Principal name from subjectAltName extension. */
	talloc_free(entry->cm_cert_principal);
	entry->cm_cert_principal = NULL;
	/* IP address from subjectAltName extension. */
	talloc_free(entry->cm_cert_ipaddress);
	entry->cm_cert_ipaddress = NULL;
	/* Key usage from keyUsage extension. */
	talloc_free(entry->cm_cert_ku);
	entry->cm_cert_ku = NULL;
	/* Extended key usage from extendedKeyUsage extension. */
	talloc_free(entry->cm_cert_eku);
	entry->cm_cert_eku = NULL;
	/* Parse the extensions. */
	cm_certext_read_extensions(entry, arena, cert->extensions);
	/* The certificate itself. */
	p = NSSBase64_EncodeItem(arena, NULL, 0, &cert->derCert);
	if (p != NULL) {
		i = strlen(p);
		if ((i > 0) && (p[i - 1] != '\n')) {
			nl = "\n";
		} else {
			nl = "";
		}
		talloc_free(entry->cm_cert);
		p = talloc_asprintf(entry, "%s%s%s%s",
				    "-----BEGIN CERTIFICATE-----\n",
				    p, nl,
				    "-----END CERTIFICATE-----\n");
		entry->cm_cert = p;
	}
	/* Clean up. */
	CERT_DestroyCertArray(certs, 1);
	PORT_FreeArena(arena, PR_TRUE);
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
}

/* Check if something changed, for example we finished reading the data we need
 * from the cert. */
static int
cm_certread_n_ready(struct cm_certread_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Check if we were able to successfully read the certificate. */
static int
cm_certread_n_finished_reading(struct cm_certread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_certread_n_get_fd(struct cm_certread_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Clean up after reading the certificate. */
static void
cm_certread_n_done(struct cm_certread_state *state)
{
	const char *msg;

	if (state->subproc != NULL) {
		msg = cm_subproc_get_msg(state->subproc, NULL);
		cm_certread_read_data_from_buffer(state->entry, msg);
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start reading the certificate from the configured location. */
struct cm_certread_state *
cm_certread_n_start(struct cm_store_entry *entry)
{
	struct cm_certread_state *state;
	struct cm_certread_n_settings settings = {
		.readwrite = 1,
	};
	if (entry->cm_cert_storage_type != cm_cert_storage_nssdb) {
		cm_log(1, "Wrong read method: can only read certificates "
		       "from an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_certread_n_ready;
		state->pvt.finished_reading = cm_certread_n_finished_reading;
		state->pvt.get_fd= cm_certread_n_get_fd;
		state->pvt.done= cm_certread_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_certread_n_main, state,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
