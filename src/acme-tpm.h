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

#ifndef cmacmetpm_h
#define cmacmetpm_h

#include <tss2/tss2_esys.h>

/* Start an HMAC session salted with the given key, with parameter
 * encryption in both directions. */
TSS2_RC cm_acme_tpm_start_session(ESYS_CONTEXT *esys, ESYS_TR salt_key,
				  ESYS_TR *session);

/* Certify the key which the daemon generated through the tpm2-pkcs11
 * module, whose public key is the one in the request, with the signing key
 * whose saved context (a marshalled TPMS_CONTEXT) is given, through the
 * module's CKM_TPM2_CERTIFY mechanism.  Returns 0, -1 on error, or
 * CM_ACME_TPM_P11_NO_CERTIFY if the token lacks the mechanism. */
#define CM_ACME_TPM_P11_NO_CERTIFY 1
int cm_acme_tpm_p11_certify(void *parent, const char *dbdir,
			    const char *token, const char *pin,
			    const char *csr,
			    const unsigned char *signer_context,
			    size_t signer_context_length,
			    const unsigned char *qualifying,
			    size_t qualifying_length,
			    TPM2B_PUBLIC *public, TPM2B_ATTEST *certify_info,
			    TPMT_SIGNATURE *signature, const char **error);

#endif
