/*
 * Copyright (C) 2009,2010,2011,2012,2013,2014,2015,2017 Red Hat, Inc.
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
#include <sys/param.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <nssb64.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11pub.h>
#include <prerror.h>

#include <talloc.h>

#include "keyiread.h"
#include "keyiread-int.h"
#include "keyiread-n.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "tpm-token.h"
#include "util-n.h"

#ifndef PRIVKEY_LIST_EMPTY
#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)
#endif

const char *
cm_GetSignatureAlgorithmFromPrivateKey(SECKEYPrivateKey *privKey)
{
	SECOidTag hashAlgTag = SEC_OID_UNKNOWN;
	SECOidTag enctag;

	if (privKey->keyType != mldsaKey) {
		return "Invalid ML-DSA key";
	}

	enctag = SEC_GetSignatureAlgorithmOidTagByKey(privKey, NULL, hashAlgTag);

	if (enctag == SEC_OID_UNKNOWN) {
		return "UNKNOWN";
	}
	switch (enctag) {
	case SEC_OID_ML_DSA_44_PUBLIC_KEY:
		return "ML-DSA-44";
	case SEC_OID_ML_DSA_65_PUBLIC_KEY:
		return "ML-DSA-65";
	case SEC_OID_ML_DSA_87_PUBLIC_KEY:
		return "ML-DSA-87";
	default:
		return "UNKNOWN";
	}
}

struct cm_keyiread_state {
	struct cm_keyiread_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};
struct cm_keyiread_n_settings {
	unsigned int readwrite:1;
};

struct cm_keyiread_n_ctx_and_keys *
cm_keyiread_n_get_keys(struct cm_store_entry *entry, int readwrite)
{
	const char *token, *nickname = "(no such key)", *reason, *es;
	char *pin, *pubhex, *nextnick;
	PLArenaPool *arena;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotInfo *slot;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	SECKEYPrivateKeyList *keys;
	SECKEYPrivateKeyListNode *knode;
	SECKEYPrivateKey *key, *ckey, *nextkey = NULL;
	SECKEYPublicKey *pubkey, *nextpubkey = NULL;
	CK_MECHANISM_TYPE mech;
	CERTCertList *certs;
	CERTCertListNode *cnode;
	CERTCertificate *cert;
	CERTSubjectPublicKeyInfo *spki;
	SECItem item;
	struct cm_pin_cb_data cb_data;
	int n_tokens, ec;
	struct cm_keyiread_n_ctx_and_keys *ret;

	/* A key in our TPM token: set the token up first, if it isn't. */
	if (cm_tpm_token_entry_uses(entry) &&
	    (cm_tpm_token_prepare(entry, &es) != 0)) {
		cm_log(1, "Error preparing the TPM token: %s.\n", es);
	}
	/* Open the database. */
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	if (ctx == NULL) {
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Unable to open NSS database '%s': %s.\n",
			       entry->cm_key_storage_location, es);
		} else {
			cm_log(1, "Unable to open NSS database '%s'.\n",
			       entry->cm_key_storage_location);
		}
		switch (PORT_GetError()) {
		case PR_NO_ACCESS_RIGHTS_ERROR:
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
			break;
		}
	}
	if (NSS_ShutdownContext(ctx) != SECSuccess) {
		cm_log(0, "Error shutting down NSS.\n");
		_exit(1);
	}
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT);
	if (ctx == NULL) {
		cm_log(0, "Unable to initialize NSS %s.\n", entry->cm_key_storage_location);
		_exit(1);
	}
	reason = util_n_fips_hook();
	if (reason != NULL) {
		cm_log(1, "Error putting NSS into FIPS mode: %s\n", reason);
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	/* Allocate a memory pool. */
	arena = PORT_NewArena(sizeof(double));
	if (arena == NULL) {
		cm_log(1, "Out of memory opening database '%s'.\n",
		       entry->cm_key_storage_location);
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
	}

	/* Find the tokens that we might use for key storage. */
	mech = 0;
	slotlist = PK11_GetAllTokens(mech, PR_FALSE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		cm_log(1, "Error locating token to be used for key storage.\n");
		if (NSS_ShutdownContext(ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}

	/* Walk the list looking for the requested token, or look at all of
	 * them if none specifically was requested. */
	key = NULL;
	pin = NULL;
	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for key storage.\n");
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_cert_nss_cb);
	if (entry->cm_key_token == NULL) {
		entry->cm_key_token = util_internal_token_name(entry);
	}
	n_tokens = 0;
	pubkey = NULL;
	/* In practice, the internal slot is either a non-storage slot (in
	 * non-FIPS mode) or the database slot (in FIPS mode), and we only want
	 * to skip over the one that can't be used to store things. */
	for (sle = slotlist->head;
	     (key == NULL) && ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		slot = sle->slot;
		if (PK11_IsInternal(slot) &&
		    !PK11_IsInternalKeySlot(slot)) {
			cm_log(3, "Skipping NSS internal slot (%s).\n",
			       PK11_GetTokenName(slot));
			goto next_slot;
		}
		/* Read the token's name. */
		token = PK11_GetTokenName(slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		} else {
			cm_log(3, "Found unnamed token.\n");
		}

		/* If this is the wrong token, move on. */
		if ((entry->cm_key_token != NULL) &&
		    (strlen(entry->cm_key_token) > 0) &&
		    ((token == NULL) ||
		     (strcmp(entry->cm_key_token, token) != 0))) {
			if (token != NULL) {
				cm_log(1,
				       "Token is named \"%s\", not \"%s\", "
				       "skipping.\n",
				       token, entry->cm_key_token);
			} else {
				cm_log(1,
				       "Token is unnamed, not \"%s\", "
				       "skipping.\n",
				       entry->cm_key_token);
			}
			goto next_slot;
		}
		n_tokens++;

		/* Be ready to count our uses of a PIN. */
		memset(&cb_data, 0, sizeof(cb_data));
		cb_data.entry = entry;
		cb_data.n_attempts = 0;

		/* If we're supposed to be using a PIN, and we're offered a
		 * chance to set one, do it now. */
		if (readwrite) {
			if (PK11_NeedUserInit(slot)) {
				if (cm_pin_read_for_key(entry, &pin) != 0) {
					cm_log(1, "Error reading PIN to assign "
					       "to storage slot, skipping.\n");
					goto next_slot;
				}
				PK11_InitPin(slot, NULL, pin ? pin : "");
				if (PK11_NeedUserInit(slot)) {
					cm_log(1, "Key storage slot still "
					       "needs user PIN to be set.\n");
					goto next_slot;
				}
				if ((pin != NULL) && (strlen(pin) > 0)) {
					/* We're authenticated now, so count
					 * this as a use of the PIN. */
					cb_data.n_attempts++;
				}
			}
		}

		/* Now log in, if we have to. */
		if (cm_pin_read_for_key(entry, &pin) != 0) {
			cm_log(1, "Error reading PIN for key storage "
			       "token \"%s\", skipping.\n", token);
			PK11_FreeSlotList(slotlist);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_SUB_STATUS_ERROR_AUTH);
		}
		error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
		if (error != SECSuccess) {
			cm_log(1, "Error authenticating to token "
			       "\"%s\".\n", token);
			PK11_FreeSlotList(slotlist);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_SUB_STATUS_ERROR_AUTH);
		}
		if ((pin != NULL) &&
		    (strlen(pin) > 0) &&
		    (cb_data.n_attempts == 0)) {
			cm_log(1, "PIN was not needed to auth to token"
			       ", though one was provided. "
			       "Treating this as an error.\n");
			PK11_FreeSlotList(slotlist);
			error = NSS_ShutdownContext(ctx);
			if (error != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			_exit(CM_SUB_STATUS_ERROR_AUTH);
		}

		/* Look up the "next" key. */
		if ((entry->cm_key_next_marker != NULL) &&
		    (strlen(entry->cm_key_next_marker) != 0)) {
			nextnick = util_build_next_nickname(entry->cm_key_nickname,
							    entry->cm_key_next_marker);
			keys = PK11_ListPrivKeysInSlot(slot, nextnick, NULL);
			if (keys != NULL) {
				for (knode = PRIVKEY_LIST_HEAD(keys);
				     !PRIVKEY_LIST_EMPTY(keys) &&
				     !PRIVKEY_LIST_END(knode, keys);
				     knode = PRIVKEY_LIST_NEXT(knode)) {
					nickname = PK11_GetPrivateKeyNickname(knode->key);
					if ((nickname != NULL) &&
					    (strcmp(nextnick, nickname) == 0)) {
						cm_log(3, "Located the key '%s'.\n",
						       nextnick);
						nextkey = SECKEY_CopyPrivateKey(knode->key);
						break;
					}
				}
				SECKEY_DestroyPrivateKeyList(keys);
			}

			/* Try to recover a public key. */
			nextpubkey = nextkey ? SECKEY_ConvertToPublicKey(nextkey) : NULL;
			if (pubkey != NULL) {
				cm_log(3, "Converted private key '%s' to public key.\n",
				       nextnick);
			}
		}

		/* Walk the list of private keys in the token, looking at each
		 * one to see if it matches the specified nickname. */
		keys = PK11_ListPrivKeysInSlot(slot,
					       entry->cm_key_nickname,
					       NULL);
		if (keys != NULL) {
			for (knode = PRIVKEY_LIST_HEAD(keys);
			     !PRIVKEY_LIST_EMPTY(keys) &&
			     !PRIVKEY_LIST_END(knode, keys);
			     knode = PRIVKEY_LIST_NEXT(knode)) {
				nickname = PK11_GetPrivateKeyNickname(knode->key);
				if ((nickname != NULL) &&
				    (entry->cm_key_nickname != NULL) &&
				    (strcmp(entry->cm_key_nickname,
					    nickname) == 0)) {
					cm_log(3, "Located the key '%s'.\n",
					       nickname);
					key = SECKEY_CopyPrivateKey(knode->key);
					break;
				}
			}
			SECKEY_DestroyPrivateKeyList(keys);
		}

		/* Try to recover a public key. */
		pubkey = key ? SECKEY_ConvertToPublicKey(key) : NULL;
		if (pubkey != NULL) {
			cm_log(3, "Converted private key '%s' to public key.\n",
			       nickname);
		}

		/* Walk the list of certificates in the token, looking at each
		 * one to see if it matches the specified nickname and has a
		 * private key associated with it. */
		if ((key == NULL) || (pubkey == NULL)) {
			certs = PK11_ListCertsInSlot(slot);
		} else {
			certs = NULL;
		}
		if (certs != NULL) {
			cert = NULL;
			for (cnode = CERT_LIST_HEAD(certs);
			     !CERT_LIST_EMPTY(certs) &&
			     !CERT_LIST_END(cnode, certs);
			     cnode = CERT_LIST_NEXT(cnode)) {
				nickname = entry->cm_key_nickname;
				cert = cnode->cert;
				es = talloc_asprintf(entry, "%s:%s",
									         entry->cm_cert_token,
											 entry->cm_cert_nickname);
				if ((nickname != NULL) &&
				    ((strcmp(cert->nickname, nickname) == 0) ||
					(strcmp(cert->nickname, es) == 0))) {
					cm_log(3, "Located a certificate with "
					       "the key's nickname (\"%s\").\n",
					       nickname);
					ckey = PK11_FindPrivateKeyFromCert(slot,
									   cert,
									   NULL);
					if (ckey != NULL) {
						if (key == NULL) {
							cm_log(3, "Located "
							       "its private "
							       "key.\n");
							key = ckey;
							break;
						} else {
							if ((key->pkcs11Slot == ckey->pkcs11Slot) &&
							    (key->pkcs11ID == ckey->pkcs11ID)) {
								cm_log(3,
								       "Located its "
								       "private key.\n");
								SECKEY_DestroyPrivateKey(ckey);
								break;
							}
						}
					}
					cm_log(3, "But we didn't find "
					       "its private key.\n");
				}
				cert = NULL;
			}
			/* If we don't have the public key, try to extract it
			 * from the private key. */
			if ((pubkey == NULL) && (key != NULL)) {
				pubkey = SECKEY_ConvertToPublicKey(key);
				if (pubkey != NULL) {
					cm_log(3, "Recovered public key "
					       "from private key.\n");
				}
			}
			/* If we don't have the public key, try to extract it
			 * from the certificate. */
			if ((pubkey == NULL) && (cert != NULL)) {
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&cert->derPublicKey);
				if (spki != NULL) {
					pubkey = SECKEY_ExtractPublicKey(spki);
					SECKEY_DestroySubjectPublicKeyInfo(spki);
					if (pubkey != NULL) {
						cm_log(3,
						       "Recovered public key "
						       "from certificate.\n");
					}
				}
			}
			CERT_DestroyCertList(certs);
		}
		/* If we don't have the public key, try to use a cached copy of
		 * it. */
		if ((pubkey == NULL) && (entry->cm_key_pubkey_info != NULL)) {
			memset(&item, 0, sizeof(item));
			pubhex = entry->cm_key_pubkey_info;
			item.len = strlen(pubhex) / 2;
			item.data = malloc(item.len);
			if (item.data != NULL) {
				item.len = cm_store_hex_to_bin(pubhex,
							       item.data,
							       item.len);
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(&item);
				if (spki != NULL) {
					pubkey = SECKEY_ExtractPublicKey(spki);
					SECKEY_DestroySubjectPublicKeyInfo(spki);
				}
			}
			if (pubkey != NULL) {
				cm_log(3, "Using cached public key.\n");
			}
		}

next_slot:
		/* If this was the last token, stop walking. */
		if (sle == slotlist->tail) {
			break;
		}
	}

	PK11_FreeSlotList(slotlist);

	if ((key == NULL) ||
	    ((entry->cm_key_next_marker != NULL) &&
	     (strlen(entry->cm_key_next_marker) != 0) &&
	     (nextkey == NULL))) {
		cm_log(1, "Error locating a key.\n");
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		PORT_FreeArena(arena, PR_TRUE);
		ret = NULL;
	} else {
		ret = PORT_ArenaZAlloc(arena, sizeof(*ret));
		if (ret == NULL) {
			cm_log(1, "Out of memory searching database '%s'.\n",
			       entry->cm_key_storage_location);
			if (NSS_ShutdownContext(ctx) != SECSuccess) {
				cm_log(1, "Error shutting down NSS.\n");
			}
			PORT_FreeArena(arena, PR_TRUE);
			_exit(CM_SUB_STATUS_ERROR_INITIALIZING);
		}
		ret->arena = arena;
		ret->ctx = ctx;
		ret->privkey = key;
		ret->pubkey = pubkey;
		ret->privkey_next = nextkey;
		ret->pubkey_next = nextpubkey;
	}

	if ((n_tokens == 0) &&
	    (entry->cm_key_token != NULL) &&
	    (strlen(entry->cm_key_token) > 0)) {
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}

	return ret;
}

static int
cm_keyiread_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		   void *userdata)
{
	struct cm_keyiread_n_ctx_and_keys *keys;
	CERTSubjectPublicKeyInfo *spki;
	PK11SlotInfo *slot;
	const char *alg, *name;
	SECItem *info;
	char *pubhex, *pubihex;
	int status = 1, size, readwrite;
	FILE *fp;
	struct cm_keyiread_n_settings *settings;

	/* Open the status descriptor for stdio. */
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		cm_log(1, "Unable to initialize I/O.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}

	/* Read the key. */
	settings = userdata;
	readwrite = settings->readwrite;
	keys = cm_keyiread_n_get_keys(entry, readwrite);
	alg = "";
	if (keys != NULL) {
		switch (SECKEY_GetPrivateKeyType(keys->privkey)) {
		case rsaKey:
			cm_log(3, "Key is an RSA key.\n");
			alg = "RSA";
			break;
		case dsaKey:
			cm_log(3, "Key is a DSA key.\n");
			alg = "DSA";
			break;
		case ecKey:
			cm_log(3, "Key is an EC key.\n");
			alg = "EC";
			break;
		case mldsaKey:
			alg = cm_GetSignatureAlgorithmFromPrivateKey(keys->privkey);
			cm_log(3, "Key is an ML-DSA key %s.\n", alg);
			break;
		case nullKey:
		default:
			cm_log(3, "Key is of an unknown type.\n");
			break;
		}
		slot = PK11_GetSlotFromPrivateKey(keys->privkey);
		if (slot != NULL) {
			name = PK11_GetTokenName(slot);
			if ((name != NULL) && (strlen(name) == 0)) {
				name = NULL;
			} else {
				name = talloc_strdup(entry, name);
			}
			PK11_FreeSlot(slot);
		} else {
			name = NULL;
		}
		if (strlen(alg) > 0) {
			if (keys->pubkey != NULL) {
				size = SECKEY_PublicKeyStrengthInBits(keys->pubkey);
				cm_log(3, "Key size is %d.\n", size);
				info = SECKEY_EncodeDERSubjectPublicKeyInfo(keys->pubkey);
				pubihex = cm_store_hex_from_bin(NULL,
								info->data,
								info->len);
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(info);
				pubhex = cm_store_hex_from_bin(NULL,
							       spki->subjectPublicKey.data,
							       howmany(spki->subjectPublicKey.len, 8));
				fprintf(fp, "%s/%d/%s/%s%s%s\n", alg, size,
					pubihex,
					pubhex,
					(name != NULL ? "/" : ""),
					(name != NULL ? name : ""));
				status = 0;
				SECITEM_FreeItem(info, PR_TRUE);
			} else {
				cm_log(1, "Error reading public key.\n");
			}
		}
		if ((entry->cm_key_next_marker != NULL) &&
		    (strlen(entry->cm_key_next_marker) != 0)) {
			if ((keys->privkey_next == NULL) || (keys->pubkey_next == NULL)) {
				cm_log(1, "Error reading next key.\n");
				fprintf(fp, "\n");
			} else {
				switch (SECKEY_GetPrivateKeyType(keys->privkey_next)) {
				case rsaKey:
					cm_log(3, "Next key is an RSA key.\n");
					alg = "RSA";
					break;
				case dsaKey:
					cm_log(3, "Next key is a DSA key.\n");
					alg = "DSA";
					break;
				case ecKey:
					cm_log(3, "Next key is an EC key.\n");
					alg = "EC";
					break;
				case mldsaKey:
					alg = cm_GetSignatureAlgorithmFromPrivateKey(keys->privkey_next);
					cm_log(3, "Next key is an ML-DSA key %s.\n", alg);
					break;
				case nullKey:
				default:
					cm_log(3, "Next key is of an unknown type.\n");
					break;
				}
				size = SECKEY_PublicKeyStrengthInBits(keys->pubkey_next);
				cm_log(3, "Next key size is %d.\n", size);
				info = SECKEY_EncodeDERSubjectPublicKeyInfo(keys->pubkey_next);
				pubihex = cm_store_hex_from_bin(NULL,
								info->data,
								info->len);
				spki = SECKEY_DecodeDERSubjectPublicKeyInfo(info);
				pubhex = cm_store_hex_from_bin(NULL,
							       spki->subjectPublicKey.data,
							       howmany(spki->subjectPublicKey.len, 8));
				fprintf(fp, "%s/%d/%s/%s\n", alg, size,
					pubihex,
					pubhex);
				status = 0;
				SECITEM_FreeItem(info, PR_TRUE);
			}
		}
		if (keys->pubkey != NULL) {
			SECKEY_DestroyPublicKey(keys->pubkey);
		}
		if (keys->pubkey_next != NULL) {
			SECKEY_DestroyPublicKey(keys->pubkey_next);
		}
		SECKEY_DestroyPrivateKey(keys->privkey);
		if (keys->privkey_next != NULL) {
			SECKEY_DestroyPrivateKey(keys->privkey_next);
		}
	}
	fclose(fp);
	if (keys != NULL) {
		if (NSS_ShutdownContext(keys->ctx) != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		PORT_FreeArena(keys->arena, PR_TRUE);
	}
	if (status != 0) {
		_exit(status);
	}
	return 0;
}

/* Check if something changed, for example we finished reading the data we need
 * from the key data. */
static int
cm_keyiread_n_ready(struct cm_keyiread_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Check if we were able to successfully read the key information. */
static int
cm_keyiread_n_finished_reading(struct cm_keyiread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Check if we need a PIN (or a new PIN) to access the key information. */
static int
cm_keyiread_n_need_pin(struct cm_keyiread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to access the key information. */
static int
cm_keyiread_n_need_token(struct cm_keyiread_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keyiread_n_get_fd(struct cm_keyiread_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Clean up after reading the key info. */
static void
cm_keyiread_n_done(struct cm_keyiread_state *state)
{
	if (state->subproc != NULL) {
		cm_keyiread_read_data_from_buffer(state->entry,
						  cm_subproc_get_msg(state->subproc,
								     NULL));
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start reading the key info from the configured location. */
struct cm_keyiread_state *
cm_keyiread_n_start(struct cm_store_entry *entry)
{
	struct cm_keyiread_state *state;
	struct cm_keyiread_n_settings settings = {
		.readwrite = 0,
	};
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		cm_log(1, "Wrong read method: can only read keys "
		       "from an NSS database.\n");
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.finished_reading = cm_keyiread_n_finished_reading;
		state->pvt.need_pin = cm_keyiread_n_need_pin;
		state->pvt.need_token = cm_keyiread_n_need_token;
		state->pvt.ready = cm_keyiread_n_ready;
		state->pvt.get_fd= cm_keyiread_n_get_fd;
		state->pvt.done= cm_keyiread_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_keyiread_n_main, state,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
