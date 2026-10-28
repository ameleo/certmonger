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

#ifndef cmtpmtokenp11_h
#define cmtpmtokenp11_h

#include <pkcs11.h>

/* Our TPM token, reached through the tpm2-pkcs11 module directly rather
 * than through NSS. */
struct cm_tpm_token_session {
	void *module;
	CK_FUNCTION_LIST_PTR f;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
};

/* Load the module, find our token, initializing it if asked to when it
 * doesn't exist yet, and open a read-write session logged in with its empty
 * user PIN.  Freeing the result closes everything. */
struct cm_tpm_token_session *cm_tpm_token_open(void *parent, int create,
					       const char **error);

#endif
