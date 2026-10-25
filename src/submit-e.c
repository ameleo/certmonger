/*
 * Copyright (C) 2009,2011,2012,2013,2014,2015,2017 Red Hat, Inc.
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
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <krb5.h>

#include <dbus/dbus.h>

#include <talloc.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "csrgen.h"
#include "csrgen-int.h"
#include "env.h"
#include "json.h"
#include "log.h"
#include "pkcs7.h"
#include "store.h"
#include "store-int.h"
#include "submit.h"
#include "submit-e.h"
#include "submit-int.h"
#include "submit-u.h"
#include "subproc.h"

#define CM_SUBMIT_E_CERTIFICATE "certificate"
#define CM_SUBMIT_E_NICKNAME "nickname"
#define CM_SUBMIT_E_ROOTS "roots"
#define CM_SUBMIT_E_CHAIN "chain"

struct cm_submit_external_state {
	enum cm_submit_external_phase {
		running_helper,
		postprocessing,
	} phase;
	struct cm_store_ca *ca;
	struct cm_store_entry *entry;
	const char *msg;
	int msg_length;
};
static int cm_submit_e_postprocess_main(int fd, struct cm_store_ca *ca,
					struct cm_store_entry *entry,
					void *userdata);

/* Clean up a cookie value in a way that's compatible with what happens when we
 * save and then reload an entry: if the value fits on a single line (whether
 * or not it ends with a newline), we strip the newline off of the end.
 * Otherwise we strip out blank lines and make sure they end with a single
 * character. */
static char *
sanitize_cookie(void *parent, const char *value)
{
	const char *p, *q;
	char *ret;

	p = value + strcspn(value, "\r\n");
	ret = talloc_strndup(parent, value, p - value);
	if (ret != NULL) {
		if (*p == '\r') {
			p++;
		}
		if (*p == '\n') {
			p++;
		}
		if (*p != '\0') {
			ret = talloc_strdup_append(ret, "\n");
		}
		while (*p != '\0') {
			q = p + strcspn(p, "\r\n");
			ret = talloc_asprintf_append(ret, "%.*s\n",
						     (int) (q - p), p);
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
	}
	return ret;
}

/* Try to save a CA-specific identifier for our submitted request.  That is, if
 * it even gave us one. */
static int
cm_submit_e_save_ca_cookie(struct cm_submit_state *state)
{
	int status;
	long delay;
	const char *msg;
	char *p;

	talloc_free(state->entry->cm_ca_cookie);
	state->entry->cm_ca_cookie = NULL;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    ((WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT) ||
	     (WEXITSTATUS(status) == CM_SUBMIT_STATUS_WAIT_WITH_DELAY))) {
		msg = cm_subproc_get_msg(state->subproc, NULL);
		if ((msg != NULL) && (strlen(msg) > 0)) {
			if (WEXITSTATUS(status) ==
			    CM_SUBMIT_STATUS_WAIT_WITH_DELAY) {
				/* Pull off the first line. */
				delay = strtol(msg, &p, 10);
				if ((p == NULL) ||
				    (strchr("\r\n", *p) == NULL)) {
					cm_log(1, "Error parsing result: %s.\n",
					       msg);
					return -1;
				}
				state->delay = delay;
				msg = p + strspn(p, "\r\n");
			}
			state->entry->cm_ca_cookie = sanitize_cookie(state->entry,
								     msg);
			if (state->entry->cm_ca_cookie == NULL) {
				cm_log(1, "Out of memory.\n");
				return -ENOMEM;
			}
			cm_log(1, "Saved cookie \"%s\".\n",
			       state->entry->cm_ca_cookie);
			return 0;
		} else {
			cm_log(1, "No cookie.\n");
			return -1;
		}
	}
	return -1;
}

/* Check if an attempt to submit the CSR has completed. */
static int
cm_submit_e_ready(struct cm_submit_state *state)
{
	int status, ready, length;
	const char *msg;
	char *tmp;
	struct cm_submit_external_state *estate;
	struct cm_subproc_state *subproc;

	estate = state->reserved;
	ready = cm_subproc_ready(state->subproc);
	switch (ready) {
	case 0:
		status = cm_subproc_get_exitstatus(state->subproc);
		switch (estate->phase) {
		case running_helper:
			cm_log(1, "Certificate submission attempt complete.\n");
			if (WIFEXITED(status)) {
				cm_log(1, "Child status = %d.\n", WEXITSTATUS(status));
				msg = cm_subproc_get_msg(state->subproc, &length);
				if ((msg != NULL) && (length > 0)) {
					cm_log(1, "Child output:\n\"%.*s\"\n", length, msg);
					/* If it's a single line, assume it's
					 * log-worthy unless the code is all we
					 * care about. */
					if (strcspn(msg, "\n") >= (strlen(msg) - 2)) {
						switch (WEXITSTATUS(status)) {
						case CM_SUBMIT_STATUS_ISSUED:
						case CM_SUBMIT_STATUS_WAIT:
						case CM_SUBMIT_STATUS_WAIT_WITH_DELAY:
						case CM_SUB_STATUS_NEED_SCEP_DATA:
							break;
						default:
							cm_log(0, "%s", msg);
							break;
						}
					}
					/* If it was an error, save it. */
					if ((WEXITSTATUS(status) ==
					     CM_SUBMIT_STATUS_ISSUED) ||
					    (WEXITSTATUS(status) ==
					     CM_SUBMIT_STATUS_WAIT) ||
					    (WEXITSTATUS(status) ==
					     CM_SUBMIT_STATUS_WAIT_WITH_DELAY)) {
						/* Clear any old error messages. */
						talloc_free(state->entry->cm_ca_error);
						state->entry->cm_ca_error = NULL;
					} else {
						/* Save the new error message. */
						talloc_free(state->entry->cm_ca_error);
						state->entry->cm_ca_error =
							talloc_strndup(state->entry,
								       msg,
								       strcspn(msg,
									       "\r\n"));
					}
					/* Save the output for processing later. */
					tmp = talloc_size(estate, length + 1);
					if (tmp != NULL) {
						memcpy(tmp, msg, length);
						tmp[length] = '\0';
						estate->msg_length = length;
					}
					estate->msg = tmp;
					/* Now launch the postprocessing step,
					 * if we've got data to process. */
					if (WEXITSTATUS(status) ==
					    CM_SUBMIT_STATUS_ISSUED) {
						subproc = cm_subproc_start(cm_submit_e_postprocess_main,
									   state, estate->ca, estate->entry,
									   estate);
						if (subproc != NULL) {
							cm_subproc_done(state->subproc);
							state->subproc = subproc;
							estate->phase = postprocessing;
							return -1;
						}
					}
				}
				return 0;
			} else {
				cm_log(1, "Child exited unexpectedly.\n");
				return 0;
			}
			break;
		case postprocessing:
			cm_log(1, "Certificate submission postprocessing complete.\n");
			if (WIFEXITED(status)) {
				cm_log(1, "Child status = %d.\n", WEXITSTATUS(status));
				msg = cm_subproc_get_msg(state->subproc, &length);
				/* Clear intermediate output. */
				estate->msg = NULL;
				estate->msg_length = 0;
				/* If we got output from the child, save it. */
				if ((msg != NULL) && (length > 0)) {
					/* If it was an error, save it. */
					if (WEXITSTATUS(status) == 0) {
						/* Save the output for processing later. */
						cm_log(1, "Child output:\n\"%.*s\"\n", length, msg);
						tmp = talloc_size(estate, length + 1);
						if (tmp != NULL) {
							memcpy(tmp, msg, length);
							tmp[length] = '\0';
							estate->msg_length = length;
						}
						estate->msg = tmp;
					} else{
						cm_log(1, "Exit status was %d.\n",
						       WEXITSTATUS(status));
					}
				}
				return 0;
			} else {
				cm_log(1, "Child exited unexpectedly.\n");
				return 0;
			}
			break;
		}
		/* Shouldn't ever get here. */
		abort();
		return 0;
		break;
	default:
		cm_log(1, "Certificate submission still ongoing.\n");
		return -1;
		break;
	}
}

/* Check if the certificate was issued.  If the exit status was 0, it was
 * issued. */
static int
cm_submit_e_issued(struct cm_submit_state *state)
{
	struct cm_json *json, *cert, *chain, *roots, *val, *nick;
	const char *msg, *k, *eom = NULL;
	struct cm_submit_external_state *estate;
	struct cm_nickcert **nickcerts, *nickcert;
	ssize_t i, j;
	int status;

	status = cm_subproc_get_exitstatus(state->subproc);
	if (!WIFEXITED(status) ||
	    (WEXITSTATUS(status) != CM_SUBMIT_STATUS_ISSUED)) {
		cm_log(1, "Certificate not (yet?) issued.\n");
		return -1;
	}
	estate = state->reserved;
	msg = estate->msg;
	if (msg != NULL) {
		if ((cm_json_decode(state, msg, -1, &json, &eom) != 0) ||
		    (*eom != '\0')) {
			cm_log(1, "Error parsing child output as JSON.\n");
			return -1;
		}
	} else {
		json = NULL;
	}
	if ((json == NULL) || (cm_json_get(json, CM_SUBMIT_E_CERTIFICATE) == NULL)) {
		cm_log(1, "No issued certificate read.\n");
		return -1;
	}
	talloc_free(state->entry->cm_cert);
	state->entry->cm_cert = NULL;
	cert = cm_json_get(json, CM_SUBMIT_E_CERTIFICATE);
	if (cm_json_type(cert) != cm_json_type_string) {
		cm_log(1, "Error parsing child output as JSON.\n");
		return -1;
	}
	state->entry->cm_cert = talloc_strdup(state->entry,
					      cm_json_string(cert, NULL));
	cm_log(1, "Issued certificate is \"%s\".\n", state->entry->cm_cert);
	talloc_free(state->entry->cm_cert_chain);
	state->entry->cm_cert_chain = NULL;
	chain = cm_json_get(json, CM_SUBMIT_E_CHAIN);
	if (cm_json_type(chain) == cm_json_type_array) {
		nickcerts = talloc_array_ptrtype(state->entry, nickcerts,
						 cm_json_array_size(chain) + 1);
		for (i = 0, j = 0; i < cm_json_array_size(chain); i++) {
			cert = cm_json_n(chain, i);
			if (cm_json_type(cert) != cm_json_type_object) {
				continue;
			}
			val = cm_json_get(cert, CM_SUBMIT_E_CERTIFICATE);
			if ((val == NULL) ||
			    (cm_json_type(val) != cm_json_type_string)) {
				continue;
			}
			nick = cm_json_get(cert, CM_SUBMIT_E_NICKNAME);
			if ((nick == NULL) ||
			    (cm_json_type(nick) != cm_json_type_string)) {
				continue;
			}
			nickcert = talloc_zero(nickcerts, struct cm_nickcert);
			k = cm_json_string(nick, NULL);
			nickcert->cm_nickname = talloc_strdup(nickcert, k);
			k = cm_json_string(val, NULL);
			nickcert->cm_cert = talloc_strdup(nickcert, k);
			nickcerts[j++] = nickcert;
		}
		nickcerts[j] = NULL;
		state->entry->cm_cert_chain = nickcerts;
	}
	talloc_free(state->entry->cm_cert_roots);
	state->entry->cm_cert_roots = NULL;
	roots = cm_json_get(json, CM_SUBMIT_E_ROOTS);
	if (cm_json_type(roots) == cm_json_type_array) {
		nickcerts = talloc_array_ptrtype(state->entry, nickcerts,
						 cm_json_array_size(roots) + 1);
		for (i = 0, j = 0; i < cm_json_array_size(roots); i++) {
			cert = cm_json_n(roots, i);
			if (cm_json_type(cert) != cm_json_type_object) {
				continue;
			}
			val = cm_json_get(cert, CM_SUBMIT_E_CERTIFICATE);
			if ((val == NULL) ||
			    (cm_json_type(val) != cm_json_type_string)) {
				continue;
			}
			nick = cm_json_get(cert, CM_SUBMIT_E_NICKNAME);
			if ((nick == NULL) ||
			    (cm_json_type(nick) != cm_json_type_string)) {
				continue;
			}
			nickcert = talloc_zero(nickcerts, struct cm_nickcert);
			k = cm_json_string(nick, NULL);
			nickcert->cm_nickname = talloc_strdup(nickcert, k);
			k = cm_json_string(val, NULL);
			nickcert->cm_cert = talloc_strdup(nickcert, k);
			nickcerts[j++] = nickcert;
		}
		nickcerts[j] = NULL;
		state->entry->cm_cert_roots = nickcerts;
	}
	cm_log(1, "Certificate issued (%ld chain certificates, %ld roots).\n",
	       cm_json_array_size(chain) > 0 ? (long) cm_json_array_size(chain) : 0,
	       cm_json_array_size(roots) > 0 ? (long) cm_json_array_size(roots) : 0);
	return 0;
}

/* Check if the submission helper can't request certificates. */
static int
cm_submit_e_unsupported(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED)) {
		return 0;
	}
	return -1;
}

/* Check if the submission helper is just unconfigured. */
static int
cm_submit_e_unconfigured(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNCONFIGURED)) {
		return 0;
	}
	return -1;
}

/* Check if the certificate request was rejected. */
static int
cm_submit_e_rejected(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_REJECTED)) {
		return 0;
	}
	return -1;
}

/* Check if we need SCEP data for this helper. */
static int
cm_submit_e_need_scep_messages(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES)) {
		return 0;
	}
	return -1;
}

/* Check if the CA says we need to use a new public key. */
static int
cm_submit_e_need_rekey(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_NEED_REKEY)) {
		return 0;
	}
	return -1;
}

/* Check if the CA was unreachable.  If the exit status was right, then we
 * never actually talked to the CA. */
static int
cm_submit_e_unreachable(struct cm_submit_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUBMIT_STATUS_UNREACHABLE)) {
		return 0;
	}
	return -1;
}

/* Done talking to the CA; clean up. */
static void
cm_submit_e_done(struct cm_submit_state *state)
{
	if (state->subproc != NULL) {
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Dig the SubjectPublicKeyInfo out of the certificate, and return it
 * hex-encoded, as we do when we're reading key information, so that we can
 * easily compare it to values obtained from there. */
static char *
cm_submit_e_get_spki(void *parent, const char *pem)
{
	X509 *x = NULL;
	BIO *in;
	unsigned char *pubkey, *p;
	char *wpem, *ret = NULL;
	int pubkey_len;

	wpem = talloc_strdup(parent, pem);
	if (wpem != NULL) {
		in = BIO_new_mem_buf(wpem, -1);
		if (in != NULL) {
			x = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
		}
	}
	if (x != NULL) {
		pubkey_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), NULL);
		if (pubkey_len > 0) {
			pubkey = talloc_size(wpem, pubkey_len);
			if (pubkey != NULL) {
				p = pubkey;
				i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &p);
				ret = cm_store_hex_from_bin(parent,
							    pubkey,
							    pubkey_len);
			}
		}
		X509_free(x);
	}
	talloc_free(wpem);
	return ret;
}

/* Attempt to postprocess the helper output, breaking up PKCS#7 signed data
 * blobs into certificates, decrypting PKCS#7 enveloped data, and making a few
 * sanity checks. */
static int
cm_submit_e_postprocess_main(int fd, struct cm_store_ca *ca,
			     struct cm_store_entry *entry, void *userdata)
{
	struct cm_submit_external_state *estate = userdata;
	struct cm_json *msg, *json, *chain, *roots, *tmp, *cert, *val, *nick;
	char *leaf = NULL, *top = NULL, **others = NULL, *encoded, *spki;
	const char *eom = NULL, *nickname, *p;
	const unsigned char *u;
	char *toproot = NULL, *leafroot = NULL, **otherroots = NULL;
	char *nthnick;
	ssize_t length;
	int i, j;
	FILE *status;
	void (*decrypt)(const unsigned char *envelope, size_t length,
			void *decrypt_userdata, unsigned char **payload,
			size_t *payload_length) = NULL;
	struct cm_submit_decrypt_envelope_args decrypt_args;

	status = fdopen(fd, "w");
	if (status == NULL) {
		cm_log(1, "Internal error.\n");
		_exit(errno);
	}
	cm_log(1, "Postprocessing output \"%.*s\".\n", estate->msg_length,
	       estate->msg);
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		decrypt = NULL;
		break;
	case cm_key_storage_file:
		decrypt = &cm_submit_o_decrypt_envelope;
		break;
	case cm_key_storage_nssdb:
		decrypt = &cm_submit_n_decrypt_envelope;
		break;
	}
	memset(&decrypt_args, 0, sizeof(decrypt_args));
	decrypt_args.ca = ca;
	decrypt_args.entry = entry;
	/* If we can't decode it as JSON, decode it as basic data. */
	if ((cm_json_decode(estate, estate->msg, estate->msg_length, &msg,
			    &eom) != 0) ||
	    (eom != estate->msg + estate->msg_length)) {
		/* Data is one or more certificates and PKCS#7 bundles,
		 * probably in PEM format, or if there's only one, possibly in
		 * DER format.  Take it apart and build a JSON structure out of
		 * it to mimic an incoming message. */
		i = cm_pkcs7_parse(0, estate, &leaf, &top, &others,
				   decrypt, &decrypt_args,
				   (const unsigned char *) estate->msg,
				   estate->msg_length, NULL);
		msg = cm_json_new_object(estate);
		chain = cm_json_new_array(msg);
		if (i == 0) {
			if (leaf != NULL) {
				cert = cm_json_new_string(msg, leaf, -1);
				cm_json_set(msg, CM_SUBMIT_E_CERTIFICATE, cert);
			}
			for (i = 0;
			     (others != NULL) && (others[i] != NULL);
			     i++) {
				cert = cm_json_new_object(chain);
				val = cm_json_new_string(cert, others[i], -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nthnick = talloc_asprintf(cert, "chain #%d", i + 1);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(chain, cert);
			}
			if (top!= NULL) {
				cert = cm_json_new_object(chain);
				val = cm_json_new_string(cert, top, -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nthnick = talloc_asprintf(cert, "chain #%d", i + 1);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(chain, cert);
			}
			if (cm_json_array_size(chain) > 0) {
				cm_json_set(msg, CM_SUBMIT_E_CHAIN, chain);
			}
		}
	}
	/* Get ready to build an output message. */
	json = cm_json_new_object(entry);
	roots = cm_json_new_array(json);
	chain = cm_json_new_array(json);
	/* Data is a JSON object, with a "certificate" PEM string, and possibly
	 * "chain" and "roots" arrays containing objects which are
	 * nickname/string sets.  Parse out the certificate, keeping the leaf
	 * node as the certificate, relegating the rest to the chain list. */
	cert = cm_json_get(msg, CM_SUBMIT_E_CERTIFICATE);
	u = (const unsigned char *) cm_json_string(cert, &length);
	i = cm_pkcs7_parse(0, estate,
			   &leaf, &top, &others,
			   NULL, NULL, u, length, NULL);
	if (i == 0) {
		if (leaf != NULL) {
			cert = cm_json_new_string(json, leaf, -1);
			cm_json_set(json, CM_SUBMIT_E_CERTIFICATE, cert);
		}
		for (i = 0;
		     (others != NULL) && (others[i] != NULL);
		     i++) {
			cert = cm_json_new_object(chain);
			val = cm_json_new_string(cert, others[i], -1);
			cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
			nthnick = talloc_asprintf(cert, "chain #0.%d", i + 1);
			nick = cm_json_new_string(cert, nthnick, -1);
			cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
			cm_json_append(chain, cert);
		}
		if (top!= NULL) {
			cert = cm_json_new_object(chain);
			val = cm_json_new_string(cert, top, -1);
			cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
			nthnick = talloc_asprintf(cert, "chain #0.%d", i + 1);
			nick = cm_json_new_string(cert, nthnick, -1);
			cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
			cm_json_append(chain, cert);
		}
	}
	/* Now look at each item in the roots list. */
	tmp = cm_json_get(msg, CM_SUBMIT_E_ROOTS);
	for (i = 0; i < cm_json_array_size(tmp); i++) {
		cert = cm_json_n(tmp, i);
		if (cm_json_type(cert) != cm_json_type_object) {
			continue;
		}
		/* Pull the root certificate, or whatever it is. */
		val = cm_json_get(cert, CM_SUBMIT_E_CERTIFICATE);
		if ((val == NULL) ||
		    (cm_json_type(val) != cm_json_type_string)) {
			continue;
		}
		/* Read the nickname, or provide a default. */
		nick = cm_json_get(cert, CM_SUBMIT_E_NICKNAME);
		if ((nick == NULL) ||
		    (cm_json_type(nick) != cm_json_type_string)) {
			p = talloc_asprintf(cert, "root #%d", i + 1);
			nick = cm_json_new_string(roots, p, -1);
		}
		nickname = cm_json_string(nick, NULL);
		/* Let the parser at it. */
		u = (const unsigned char *) cm_json_string(val, &length);
		j = cm_pkcs7_parse(0, estate,
				   &leafroot, &toproot, &otherroots,
				   NULL, NULL, u, length, NULL);
		if (j == 0) {
			if (leafroot != NULL) {
				cert = cm_json_new_object(roots);
				val = cm_json_new_string(cert, leafroot, -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nick = cm_json_new_string(cert, nickname, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(roots, cert);
			}
			for (j = 0;
			     (otherroots != NULL) && (otherroots[j] != NULL);
			     j++) {
				cert = cm_json_new_object(roots);
				val = cm_json_new_string(cert, otherroots[i],
							 -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE,
					    val);
				nthnick = talloc_asprintf(cert, "%s #%d",
							  nickname, j + 2);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(roots, cert);
			}
			if (toproot != NULL) {
				cert = cm_json_new_object(roots);
				val = cm_json_new_string(cert, toproot, -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nthnick = talloc_asprintf(cert, "%s #%d",
							  nickname, j + 2);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(roots, cert);
			}
		}
	}
	/* Now do the same for any chain certificates. */
	tmp = cm_json_get(msg, CM_SUBMIT_E_CHAIN);
	for (i = 0; i < cm_json_array_size(tmp); i++) {
		cert = cm_json_n(tmp, i);
		if (cm_json_type(cert) != cm_json_type_object) {
			continue;
		}
		/* Pull the chain certificate, or whatever it is. */
		val = cm_json_get(cert, CM_SUBMIT_E_CERTIFICATE);
		if ((val == NULL) ||
		    (cm_json_type(val) != cm_json_type_string)) {
			continue;
		}
		/* Read the nickname, or provide a default. */
		nick = cm_json_get(cert, CM_SUBMIT_E_NICKNAME);
		if ((nick == NULL) ||
		    (cm_json_type(nick) != cm_json_type_string)) {
			p = talloc_asprintf(cert, "chain #%d", i + 1);
			nick = cm_json_new_string(chain, p, -1);
		}
		nickname = cm_json_string(nick, NULL);
		/* Let the parser at it. */
		u = (const unsigned char *) cm_json_string(val, &length);
		j = cm_pkcs7_parse(0, estate,
				   &leafroot, &toproot, &otherroots,
				   NULL, NULL, u, length, NULL);
		if (j == 0) {
			if (leafroot != NULL) {
				cert = cm_json_new_object(chain);
				val = cm_json_new_string(cert, leafroot, -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nick = cm_json_new_string(cert, nickname, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(chain, cert);
			}
			for (j = 0;
			     (otherroots != NULL) && (otherroots[j] != NULL);
			     j++) {
				cert = cm_json_new_object(chain);
				val = cm_json_new_string(cert, otherroots[i],
							 -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE,
					    val);
				nthnick = talloc_asprintf(cert, "%s #%d",
							  nickname, j + 2);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(chain, cert);
			}
			if (toproot != NULL) {
				cert = cm_json_new_object(chain);
				val = cm_json_new_string(cert, toproot, -1);
				cm_json_set(cert, CM_SUBMIT_E_CERTIFICATE, val);
				nthnick = talloc_asprintf(cert, "%s #%d",
							  nickname, j + 2);
				nick = cm_json_new_string(cert, nthnick, -1);
				cm_json_set(cert, CM_SUBMIT_E_NICKNAME, nick);
				cm_json_append(chain, cert);
			}
		}
	}
	/* and put the lists into the final document. */
	if (cm_json_array_size(chain) > 0) {
		cm_json_set(json, CM_SUBMIT_E_CHAIN, chain);
	}
	if (cm_json_array_size(roots) > 0) {
		cm_json_set(json, CM_SUBMIT_E_ROOTS, roots);
	}
	/* Provide some indications about the key. */
	spki = cm_submit_e_get_spki(json, leaf);
	if (spki != NULL) {
		if ((entry->cm_key_next_pubkey_info != NULL) &&
		    (strlen(entry->cm_key_next_pubkey_info) > 0)) {
			if (strcmp(spki, entry->cm_key_pubkey_info) == 0) {
				/* We were issued a certificate
				 * containing a the OLD pubkey. */
				cm_json_set(json, "key_reused",
					    cm_json_new_boolean(json, 1));
			} else
			if ((strcmp(spki, entry->cm_key_next_pubkey_info) != 0)) {
				/* We were issued a certificate
				 * containing a pubkey different from
				 * one we asked to be signed. */
				cm_json_set(json, "key_mismatch",
					    cm_json_new_boolean(json, 1));
			} else {
				cm_json_set(json, "key_checked",
					    cm_json_new_boolean(json, 1));
			}
		} else {
			if ((strcmp(spki, entry->cm_key_pubkey_info) != 0)) {
				/* We were issued a certificate
				 * containing a pubkey different from
				 * one we asked to be signed. */
				cm_json_set(json, "key_mismatch",
					    cm_json_new_boolean(json, 1));
			} else {
				cm_json_set(json, "key_checked",
					    cm_json_new_boolean(json, 1));
			}
		}
	} else {
		cm_log(3, "Error retrieving SPKI from certificate.\n");
	}
	encoded = cm_json_encode(entry, json);
	fprintf(status, "%s\n", encoded);
	fflush(status);
	_exit(0);
}

/* Attempt to exec the helper. */
struct cm_submit_e_helper_args {
	int error_fd;
	const char *spki, *operation;
};

static int
maybe_setenv(const char *var, const char *val)
{
	if ((var == NULL) || (val == NULL) || (strlen(val) == 0)) {
		return -1;
	}
	cm_log(2, "Setting \"%s\" to \"%s\" for child.\n", var, val);
	return setenv(var, val, 1);
}

/* Like maybe_setenv(), but don't log the value. */
static int
maybe_setenv_secret(const char *var, const char *val)
{
	if ((var == NULL) || (val == NULL) || (strlen(val) == 0)) {
		return -1;
	}
	cm_log(2, "Setting \"%s\" for child.\n", var);
	return setenv(var, val, 1);
}

static int
cm_submit_e_helper_main(int fd, struct cm_store_ca *ca,
			struct cm_store_entry *entry, void *userdata)
{
	struct cm_submit_e_helper_args *args = userdata;
	char **argv;
	const char *error, *key_type, *key_storage;
	char *password;
	unsigned char u;

	maybe_setenv(CM_SUBMIT_REQ_SUBJECT_ENV,
		     entry->cm_template_subject);
	maybe_setenv(CM_SUBMIT_REQ_EMAIL_ENV,
		     cm_submit_maybe_joinv(NULL, "\n",
					   entry->cm_template_email));
	maybe_setenv(CM_SUBMIT_REQ_HOSTNAME_ENV,
		     cm_submit_maybe_joinv(NULL, "\n",
					   entry->cm_template_hostname));
	maybe_setenv(CM_SUBMIT_REQ_PRINCIPAL_ENV,
		     cm_submit_maybe_joinv(NULL, "\n",
					   entry->cm_template_principal));
	maybe_setenv(CM_SUBMIT_OPERATION_ENV, args->operation);
	maybe_setenv(CM_SUBMIT_CSR_ENV, entry->cm_csr);
	maybe_setenv(CM_SUBMIT_SPKAC_ENV, entry->cm_spkac);
	maybe_setenv(CM_SUBMIT_SPKI_ENV, args->spki);
	maybe_setenv(CM_STORE_LOCAL_CA_DIRECTORY_ENV,
		     cm_env_local_ca_dir());
	key_type = NULL;
	switch (entry->cm_key_type.cm_key_algorithm) {
	case cm_key_rsa:
		key_type = "RSA";
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		key_type = "DSA";
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		key_type = "EC";
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		key_type = "ML-DSA-44";
		break;
	case cm_key_ml_dsa_65:
		key_type = "ML-DSA-65";
		break;
	case cm_key_ml_dsa_87:
		key_type = "ML-DSA-87";
		break;
#endif
	case cm_key_unspecified:
		key_type = NULL;
		break;
	}
	maybe_setenv(CM_SUBMIT_KEY_TYPE_ENV, key_type);
	maybe_setenv(CM_SUBMIT_COOKIE_ENV, entry->cm_ca_cookie);
	maybe_setenv(CM_SUBMIT_CA_NICKNAME_ENV, entry->cm_ca_nickname);
	maybe_setenv(CM_SUBMIT_PROFILE_ENV, entry->cm_template_profile);
	maybe_setenv(CM_SUBMIT_ISSUER_ENV, entry->cm_template_issuer);
	maybe_setenv(CM_SUBMIT_CERTIFICATE_ENV, entry->cm_cert);
	/* Only pass SCEP data to the helper if we haven't used this set of
	 * nonced data before.  It'll ask for fresh data if it needs it. */
	maybe_setenv(CM_SUBMIT_SCEP_CA_IDENTIFIER_ENV,
		     ca->cm_ca_scep_ca_identifier);
	maybe_setenv(CM_SUBMIT_SCEP_RA_CERTIFICATE_ENV,
		     ca->cm_ca_encryption_cert);
	maybe_setenv(CM_SUBMIT_SCEP_CA_CERTIFICATE_ENV,
		     ca->cm_ca_encryption_issuer_cert);
	maybe_setenv(CM_SUBMIT_SCEP_CERTIFICATES_ENV,
		     ca->cm_ca_encryption_cert_pool);
	if ((entry->cm_scep_last_nonce == NULL) ||
	    (entry->cm_scep_nonce == NULL) ||
	    (strcmp(entry->cm_scep_last_nonce, entry->cm_scep_nonce) != 0)) {
		maybe_setenv(CM_SUBMIT_SCEP_PKCSREQ_ENV,
			     entry->cm_scep_req);
		maybe_setenv(CM_SUBMIT_SCEP_GETCERTINITIAL_ENV,
			     entry->cm_scep_gic);
		maybe_setenv(CM_SUBMIT_SCEP_PKCSREQ_REKEY_ENV,
			     entry->cm_scep_req_next);
		maybe_setenv(CM_SUBMIT_SCEP_GETCERTINITIAL_REKEY_ENV,
			     entry->cm_scep_gic_next);
	}
	maybe_setenv(CM_SUBMIT_REQ_IP_ADDRESS_ENV,
		     cm_submit_maybe_joinv(NULL, "\n",
					   entry->cm_template_ipaddress));
	/* Tell the helper where the key is, so that it can use it with the
	 * current certificate to authenticate to the CA when renewing. */
	key_storage = NULL;
	switch (entry->cm_key_storage_type) {
	case cm_key_storage_none:
		break;
	case cm_key_storage_file:
		key_storage = "FILE";
		break;
	case cm_key_storage_nssdb:
		key_storage = "NSSDB";
		break;
	}
	maybe_setenv(CM_SUBMIT_KEY_STORAGE_TYPE_ENV, key_storage);
	maybe_setenv(CM_SUBMIT_KEY_STORAGE_LOCATION_ENV,
		     entry->cm_key_storage_location);
	maybe_setenv(CM_SUBMIT_KEY_TOKEN_ENV, entry->cm_key_token);
	maybe_setenv(CM_SUBMIT_KEY_NICKNAME_ENV, entry->cm_key_nickname);
	maybe_setenv(CM_SUBMIT_KEY_PIN_FILE_ENV, entry->cm_key_pin_file);
	maybe_setenv_secret(CM_SUBMIT_KEY_PIN_ENV, entry->cm_key_pin);
	/* The challenge password, which a helper may need to authenticate
	 * to the CA. */
	if ((cm_csrgen_read_challenge_password(entry, &password) == 0) &&
	    (password != NULL)) {
		maybe_setenv_secret(CM_SUBMIT_CHALLENGE_PASSWORD_ENV, password);
	}
	if (dup2(fd, STDOUT_FILENO) == -1) {
		u = errno;
		cm_log(1, "Error redirecting standard out for "
		       "enrollment helper: %s.\n",
		       strerror(errno));
		if (write(args->error_fd, &u, 1) != 1) {
			cm_log(1, "Error sending error result to parent.\n");
		}
		return u;
	}
	error = NULL;
	argv = cm_subproc_parse_args(ca, ca->cm_ca_external_helper, &error);
	if (argv == NULL) {
		if (error != NULL) {
			cm_log(0, "Error parsing \"%s\": %s.\n",
			       ca->cm_ca_external_helper, error);
		} else {
			cm_log(0, "Error parsing \"%s\".\n",
			       ca->cm_ca_external_helper);
		}
		return -1;
	}
	cm_log(2, "Redirecting stdin to /dev/null, leaving stdout and stderr open for child \"%s\".\n", argv[0]);
	cm_subproc_mark_most_cloexec(STDOUT_FILENO, STDERR_FILENO, -1);
	cm_log(1, "Running enrollment helper \"%s\".\n", argv[0]);
	execvp(argv[0], argv);
	u = errno;
	if (write(args->error_fd, &u, 1) != 1) {
		cm_log(1, "Error sending error result to parent.\n");
	}
	return u;
}

/* Start CSR submission using parameters stored in the entry. */
static struct cm_submit_state *
cm_submit_e_start_or_resume(struct cm_store_ca *ca,
			    struct cm_store_entry *entry,
			    const char *spki,
			    const char *operation)
{
	int errorfds[2], nread;
	unsigned char u;
	struct cm_submit_state *state;
	struct cm_submit_external_state *estate;
	struct cm_submit_e_helper_args args;

	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->entry = entry;
		state->save_ca_cookie = cm_submit_e_save_ca_cookie;
		state->ready = cm_submit_e_ready;
		state->issued = cm_submit_e_issued;
		state->rejected = cm_submit_e_rejected;
		state->need_scep_messages = cm_submit_e_need_scep_messages;
		state->need_rekey = cm_submit_e_need_rekey;
		state->unreachable = cm_submit_e_unreachable;
		state->unconfigured = cm_submit_e_unconfigured;
		state->unsupported = cm_submit_e_unsupported;
		state->done = cm_submit_e_done;
		state->delay = -1;
		estate = talloc_ptrtype(state, estate);
		if (estate == NULL) {
			talloc_free(state);
			return NULL;
		}
		memset(estate, 0, sizeof(*estate));
		estate->phase = running_helper;
		estate->ca = ca;
		estate->entry = entry;
		state->reserved = estate;
		if (pipe(errorfds) != -1) {
			if (fcntl(errorfds[1], F_SETFD, 1L) == -1) {
				close(errorfds[0]);
				close(errorfds[1]);
				cm_log(-1, "Unexpected error while "
				       "starting helper \"%s\".",
				       ca->cm_ca_external_helper);
				cm_subproc_done(state->subproc);
				talloc_free(state);
				state = NULL;
			} else {
				args.error_fd = errorfds[1];
				args.spki = spki;
				args.operation = operation;
				state->subproc = cm_subproc_start(cm_submit_e_helper_main,
								  state,
								  ca, entry,
								  &args);
				close(errorfds[1]);
				if (state->subproc == NULL) {
					talloc_free(state);
					state = NULL;
				} else {
					nread = read(errorfds[0], &u, 1);
					switch (nread) {
					case 0:
						/* no data = kernel
						 * closed-on-exec, so the
						 * helper started */
						break;
					case -1:
						/* huh? */
						cm_log(-1, "Unexpected error "
						       "while starting helper "
						       "\"%s\".\n",
						       ca->cm_ca_external_helper);
						cm_subproc_done(state->subproc);
						talloc_free(state);
						state = NULL;
						break;
					case 1:
					default:
						cm_log(-1,
						       "Error while starting "
						       "helper \"%s\": %s.\n",
						       ca->cm_ca_external_helper,
						       strerror(u));
						cm_subproc_done(state->subproc);
						talloc_free(state);
						state = NULL;
						break;
					}
				}
				close(errorfds[0]);
			}
		}
	}
	return state;
}

/* Start CSR submission using parameters stored in the entry. */
struct cm_submit_state *
cm_submit_e_start(struct cm_store_ca *ca, struct cm_store_entry *entry)
{
	struct cm_submit_state *ret;
	char *spki = NULL;

	if (entry->cm_key_pubkey_info != NULL) {
		spki = cm_store_base64_from_hex(entry,
						entry->cm_key_pubkey_info);
	}
	if ((entry->cm_ca_cookie != NULL) &&
	    (strlen(entry->cm_ca_cookie) > 0)) {
		ret = cm_submit_e_start_or_resume(ca, entry, spki, "POLL");
	} else {
		ret = cm_submit_e_start_or_resume(ca, entry, spki, "SUBMIT");
		if ((entry->cm_key_next_marker != NULL) &&
		    (strlen(entry->cm_key_next_marker) > 0)) {
			entry->cm_key_next_requested_count++;
		} else {
			entry->cm_key_requested_count++;
		}
	}
	if (spki != NULL) {
		talloc_free(spki);
	}
	return ret;
}

const char *
cm_submit_e_status_text(enum cm_external_status status)
{
	switch (status) {
	case CM_SUBMIT_STATUS_ISSUED:
		return "ISSUED";
	case CM_SUBMIT_STATUS_WAIT:
		return "WAIT";
	case CM_SUBMIT_STATUS_REJECTED:
		return "REJECTED";
	case CM_SUBMIT_STATUS_UNREACHABLE:
		return "UNREACHABLE";
	case CM_SUBMIT_STATUS_UNCONFIGURED:
		return "UNCONFIGURED";
	case CM_SUBMIT_STATUS_WAIT_WITH_DELAY:
		return "WAIT_WITH_DELAY";
	case CM_SUBMIT_STATUS_OPERATION_NOT_SUPPORTED:
		return "OPERATION_NOT_SUPPORTED_BY_HELPER";
	case CM_SUBMIT_STATUS_NEED_SCEP_MESSAGES:
		return "NEED_SCEP_MESSAGES";
	case CM_SUBMIT_STATUS_NEED_REKEY:
		return "NEED_REKEY";
	}
	return "(unknown)";
}
