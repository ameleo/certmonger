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

#ifndef cmtpmtoken_h
#define cmtpmtoken_h

/* When a CA wants keys which a TPM attests, or is an ACME CA on a machine
 * with a TPM, and a request doesn't say where to keep its key, we keep it in
 * a TPM token of our own: a tpm2-pkcs11 token
 * in the module's system store, which only root can read, or in our own
 * directory where there is none, with an NSS database in our directory.  The
 * key can't leave the TPM, so the token has an empty user PIN, and its SO
 * PIN is random and forgotten: starting over means removing the
 * directory. */

#define CM_TPM_TOKEN_LABEL "certmonger"
/* Our own keys, such as those of ACME accounts, are kept in a token of their
 * own, so that whoever uses the device's keys and certificates, a VPN or a
 * Wi-Fi client, doesn't see them beside those. */
#define CM_TPM_ACCOUNT_TOKEN_LABEL "certmonger-acme"
#define CM_TPM_TOKEN_MODULE_NAME "tpm2"

struct cm_store_ca;
struct cm_store_entry;

/* Whether a CA's helper, given as its command line, answers
 * device-attest-01 challenges with a TPM attestation. */
int cm_tpm_token_helper_attests(const char *helper);

/* Whether the CA's helper answers device-attest-01 challenges with a TPM
 * attestation, so that its keys belong in the TPM. */
int cm_tpm_token_ca_attests(struct cm_store_ca *ca);

/* Whether a CA's helper, given as its command line, is our ACME helper. */
int cm_tpm_token_helper_is_acme(const char *helper);

/* Whether this machine has a TPM we can use through the module: the module
 * is installed, and something tells it how to reach a TPM or we may use the
 * kernel's resource manager. */
int cm_tpm_token_available(void);

/* Whether the keys of the CA's requests which don't say where to keep them
 * belong in our token: those of a CA which attests with the TPM, and those
 * of an ACME CA wherever there is a TPM, which keeps them out of reach. */
int cm_tpm_token_ca_wants(struct cm_store_ca *ca);

/* Whether the entry's key is in our token. */
int cm_tpm_token_entry_uses(struct cm_store_entry *entry);

/* The token's directory, created if it isn't there yet: it holds the NSS
 * database, and the module's store when the module has no system store. */
const char *cm_tpm_token_dir(void);

/* The file of a tpm2-pkcs11 store, in its directory. */
#define CM_TPM2_PKCS11_STORE_FILE "tpm2_pkcs11.sqlite3"

/* Where the token's store is: the module's system store when there is one we
 * may use, so that every program of the system sees the token, unless a store
 * of our own which couldn't be moved there is still in our directory. */
const char *cm_tpm_token_store(void);

/* Point tpm2-pkcs11 at the token's store, and at the TPM if nothing else
 * says how to reach it, and tell a helper that it may keep keys of its own
 * there. */
void cm_tpm_token_setenv(void);

/* Set for a helper when its environment points tpm2-pkcs11 at our token:
 * the ACME helper then keeps its account key there. */
#define CM_TPM_TOKEN_ENV "CERTMONGER_TPM_TOKEN"

/* Whether the entry's key is in a token other than ours, which the module
 * may only find through a store of its own. */
int cm_tpm_token_entry_uses_other(struct cm_store_entry *entry);

/* Where tpm2-pkcs11 looks for its store first, unless told otherwise. */
#define CM_TPM2_PKCS11_DEFAULT_STORE "/etc/tpm2_pkcs11"

/* At the daemon's start, before anything loads NSS: point tpm2-pkcs11 at
 * the token's store, which is created if need be, and quiet its warnings,
 * unless our environment or a store where the module looks by default says
 * otherwise.  Nothing happens when the module isn't installed. */
void cm_tpm_token_startup(void);

/* In a client, before it loads NSS: point tpm2-pkcs11 at the daemon's store
 * if we can use it, and quiet its warnings, unless our environment says
 * otherwise. */
void cm_tpm_token_client_setenv(void);

/* Initialize the token if it doesn't exist yet, and make sure the NSS
 * database knows about the module.  Run in a subprocess, before NSS has
 * loaded the module. */
int cm_tpm_token_prepare(void *parent, const char **error);

#endif
