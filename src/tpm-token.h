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

/* When a CA wants keys which a TPM attests, and a request doesn't say where
 * to keep its key, we keep it in a TPM token of our own: a tpm2-pkcs11 token
 * whose store and NSS database are in a directory only we can read.  The
 * key can't leave the TPM, so the token has an empty user PIN, and its SO
 * PIN is random and forgotten: starting over means removing the
 * directory. */

#define CM_TPM_TOKEN_LABEL "certmonger"
#define CM_TPM_TOKEN_MODULE_NAME "tpm2"

struct cm_store_ca;
struct cm_store_entry;

/* Whether a CA's helper, given as its command line, answers
 * device-attest-01 challenges with a TPM attestation. */
int cm_tpm_token_helper_attests(const char *helper);

/* Whether the CA's helper answers device-attest-01 challenges with a TPM
 * attestation, so that its keys belong in the TPM. */
int cm_tpm_token_ca_attests(struct cm_store_ca *ca);

/* Whether the entry's key is in our token. */
int cm_tpm_token_entry_uses(struct cm_store_entry *entry);

/* The token's directory, created if it isn't there yet. */
const char *cm_tpm_token_dir(void);

/* Point tpm2-pkcs11 at the token's store, and at the TPM if nothing else
 * says how to reach it. */
void cm_tpm_token_setenv(void);

/* Initialize the token if it doesn't exist yet, and make sure the NSS
 * database knows about the module.  Run in a subprocess, before NSS has
 * loaded the module. */
int cm_tpm_token_prepare(void *parent, const char **error);

#endif
