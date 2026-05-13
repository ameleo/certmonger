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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pqg.h>
#include <pk11pub.h>
#include <cert.h>
#include <keyhi.h>
#include <keythi.h>
#include <prerror.h>
#include <secerr.h>
#include <cryptohi.h>

#include <talloc.h>

#include "keygen.h"
#include "keygen-int.h"
#include "log.h"
#include "pin.h"
#include "store.h"
#include "store-int.h"
#include "subproc.h"
#include "util-n.h"

#define PRIVKEY_LIST_EMPTY(l) PRIVKEY_LIST_END(PRIVKEY_LIST_HEAD(l), l)

struct cm_keygen_state {
	struct cm_keygen_state_pvt pvt;
	struct cm_store_entry *entry;
	struct cm_subproc_state *subproc;
};
struct cm_keygen_n_settings {
	unsigned int readwrite:1;
};

#ifdef CM_ENABLE_DSA
static int
pqg_size(int key_size)
{
	if (key_size < 512) {
		key_size = 512;
	}
	if (key_size < 1024) {
		key_size = howmany(key_size, 64) * 64;
	}
	if (key_size > 1024) {
		key_size = howmany(key_size, 1024) * 1024;
	}
	if (key_size > 3072) {
		key_size = 3072;
	}
	return key_size;
}
#endif

static char *
make_nickname(const char *prefix, char **marker)
{
	unsigned char suffix[6];
	char *ret;
	size_t l;

	if (PK11_GenerateRandom(suffix, sizeof(suffix)) != SECSuccess) {
		/* Try again sometime later. */
		cm_log(1, "Error generating suffix: %s.\n",
		       PR_ErrorToName(PORT_GetError()));
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	*marker = cm_store_base64_from_bin(NULL, suffix, sizeof(suffix));
	if (*marker == NULL) {
		/* Try again sometime later. */
		cm_log(1, "Error generating suffix.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	while ((l = strcspn(*marker, "+/")) != strlen(*marker)) {
		switch ((*marker)[l]) {
		case '+':
			(*marker)[l] = '=';
			break;
		case '/':
			(*marker)[l] = '_';
			break;
		}
	}
	ret = util_build_next_nickname(prefix, *marker);
	return ret;
}

static int
cm_keygen_n_main(int fd, struct cm_store_ca *ca, struct cm_store_entry *entry,
		 void *userdata)
{
	FILE *status;
	enum cm_key_algorithm cm_key_algorithm;
	int cm_key_size, cm_requested_key_size, readwrite, ec;
	CK_MECHANISM_TYPE mech, pmech;
	SECStatus error;
	NSSInitContext *ctx;
	PK11SlotList *slotlist;
	PK11SlotListElement *sle;
	PK11SlotInfo *slot = NULL;
	PK11RSAGenParams rsa_params;
#ifdef CM_ENABLE_DSA
	PQGParams *pqg_params = NULL;
	PQGVerify *pqg_verify;
	SECStatus pqg_ok;
	SECKEYPQGParams dsa_params;
	int pqg_s;
#endif
	SECItem *spki;
	CERTSubjectPublicKeyInfo *pubkeyinfo;
	void *params;
#ifdef CM_ENABLE_EC
	SECOidData *ecurve;
	SECItem ec_params;
#endif
#ifdef CM_ENABLE_ML_DSA
	CK_ULONG ml_params;
#endif
	SECKEYPrivateKey *privkey, *delkey, *ckey;
	SECKEYPrivateKeyList *privkeys;
	SECKEYPrivateKeyListNode *node;
	SECKEYPublicKey *pubkey;
	CERTCertList *certs;
	CERTCertListNode *cnode;
	CERTCertificate *cert;
	const char *es, *token, *keyname, *reason;
	char *nickname, *marker = "", *markertmp;
	char *pin, *pubhex, *pubihex;
	struct cm_keygen_n_settings *settings;
	struct cm_pin_cb_data cb_data;
	int retry, generated_size;

	status = fdopen(fd, "w");
	if (status == NULL) {
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	/* Start up NSS and open the database. */
	settings = userdata;
	readwrite = settings->readwrite;
	errno = 0;
	ctx = NSS_InitContext(entry->cm_key_storage_location,
			      NULL, NULL, NULL, NULL,
			      (readwrite ? 0 : NSS_INIT_READONLY) |
			      NSS_INIT_NOROOTINIT |
			      NSS_INIT_NOMODDB);
	ec = PORT_GetError();
	if (ctx == NULL) {
		if ((ec == SEC_ERROR_READ_ONLY) && readwrite) {
			ec = PR_NO_ACCESS_RIGHTS_ERROR;
		}
		else if ((ec == SEC_ERROR_BAD_DATABASE) && readwrite) {
			switch (errno) {
			case EACCES:
			case EPERM:
			case ENOENT:
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
			fprintf(status, "Error initializing database "
				"'%s': %s.\n",
				entry->cm_key_storage_location, es);
			cm_log(1, "Error initializing database '%s': %s.\n",
			       entry->cm_key_storage_location, es);
		} else {
			fprintf(status, "Error initializing database '%s'.\n",
				entry->cm_key_storage_location);
			cm_log(1, "Error initializing database '%s'.\n",
			       entry->cm_key_storage_location);
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
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
	/* Handle the key size. */
	cm_key_algorithm = entry->cm_key_type.cm_key_gen_algorithm;
	if (cm_key_algorithm == cm_key_unspecified) {
		cm_key_algorithm = CM_DEFAULT_PUBKEY_TYPE;
	}
	cm_requested_key_size = entry->cm_key_type.cm_key_gen_size;
	if (cm_requested_key_size <= 0) {
		cm_requested_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	/* Convert our key type to a mechanism. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		mech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pmech = CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_requested_key_size = pqg_size(cm_requested_key_size);
		mech = CKM_DSA_KEY_PAIR_GEN;
		pmech = CKM_DSA_PARAMETER_GEN;
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		mech = CKM_EC_KEY_PAIR_GEN;
		pmech = CKM_EC_KEY_PAIR_GEN;
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		cm_requested_key_size = ML_DSA_44_PRIVATEKEY_LEN;
		mech = CKM_ML_DSA_KEY_PAIR_GEN;
		pmech = CKM_ML_DSA_KEY_PAIR_GEN;
		break;
	case cm_key_ml_dsa_65:
		cm_requested_key_size = ML_DSA_65_PRIVATEKEY_LEN;
		mech = CKM_ML_DSA_KEY_PAIR_GEN;
		pmech = CKM_ML_DSA_KEY_PAIR_GEN;
		break;
	case cm_key_ml_dsa_87:
		cm_requested_key_size = ML_DSA_87_PRIVATEKEY_LEN;
		mech = CKM_ML_DSA_KEY_PAIR_GEN;
		pmech = CKM_ML_DSA_KEY_PAIR_GEN;
		break;
#endif
	default:
		fprintf(status, "Unknown or unsupported key type.\n");
		cm_log(1, "Unknown or unsupported key type.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		break;
	}
	/* Find the tokens that we might use for key generation. */
	slotlist = PK11_GetAllTokens(mech, PR_TRUE, PR_FALSE, NULL);
	if (slotlist == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}
	if (entry->cm_cert_token == NULL) {
		entry->cm_cert_token = util_internal_token_name(entry);
	}
	/* Walk the list looking for the requested slot, or the first one if
	 * none was requested. */
	slot = NULL;
	for (sle = slotlist->head;
	     ((sle != NULL) && (sle->slot != NULL));
	     sle = sle->next) {
		if (PK11_IsInternal(sle->slot) &&
		    !PK11_IsInternalKeySlot(sle->slot)) {
			cm_log(3, "Skipping NSS internal slot (%s).\n",
			       PK11_GetTokenName(sle->slot));
			goto next_slot;
		}
		token = PK11_GetTokenName(sle->slot);
		if (token != NULL) {
			cm_log(3, "Found token '%s'.\n", token);
		} else {
			cm_log(3, "Found unnamed token.\n");
		}
		if ((entry->cm_key_token == NULL) ||
		    (strlen(entry->cm_key_token) == 0) ||
		    ((token != NULL) &&
		     (strcmp(entry->cm_key_token, token) == 0))) {
			slot = sle->slot;
			break;
		}
next_slot:
		if (sle == slotlist->tail) {
			break;
		}
	}
	if (slot == NULL) {
		fprintf(status, "Error locating token for key generation.\n");
		cm_log(1, "Error locating token for key generation.\n");
		_exit(CM_SUB_STATUS_ERROR_NO_TOKEN);
	}
	/* Be ready to count our uses of a PIN. */
	memset(&cb_data, 0, sizeof(cb_data));
	cb_data.entry = entry;
	cb_data.n_attempts = 0;
	pin = NULL;
	/* If we're supposed to be using a PIN, and we're offered a chance to
	 * set one, do it now. */
	if (readwrite) {
		if (PK11_NeedUserInit(slot)) {
			if (cm_pin_read_for_key(entry, &pin) != 0) {
				cm_log(1, "Error reading PIN to assign "
				       "to storage slot, skipping.\n");
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_SUB_STATUS_ERROR_AUTH);
			}
			PK11_InitPin(slot, NULL, pin ? pin : "");
			ec = PORT_GetError();
			if (ec != 0) {
				es = PR_ErrorToName(ec);
			} else {
				es = NULL;
			}
			if (PK11_NeedUserInit(slot)) {
				if (es != NULL) {
					cm_log(1, "Key generation slot still "
					       "needs user PIN to be set: "
					       "%s.\n", es);
				} else {
					cm_log(1, "Key generation slot still "
					       "needs user PIN to be set.\n");
				}
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				switch (ec) {
				case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
					_exit(CM_SUB_STATUS_ERROR_PERMS);
					break;
				default:
					_exit(CM_SUB_STATUS_ERROR_AUTH);
					break;
				}
			}
			/* We're authenticated now, so count this as a use of
			 * the PIN. */
			if ((pin != NULL) && (strlen(pin) > 0)) {
				cb_data.n_attempts++;
			}
		}
	}
	/* Now log in, if we have to. */
	if (cm_pin_read_for_key(entry, &pin) != 0) {
		cm_log(1, "Error reading PIN for key store, "
		       "failing to generate CSR.\n");
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	PK11_SetPasswordFunc(&cm_pin_read_for_key_nss_cb);
	error = PK11_Authenticate(slot, PR_TRUE, &cb_data);
	ec = PORT_GetError();
	if (error != SECSuccess) {
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error authenticating to key store: %s.\n",
			       es);
		} else {
			cm_log(1, "Error authenticating to key store.\n");
		}
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
		cm_log(1, "PIN was not needed to auth to key "
		       "store token %s, though one was provided. "
		       "Treating this as an error.\n", token);
		PK11_FreeSlotList(slotlist);
		error = NSS_ShutdownContext(ctx);
		if (error != SECSuccess) {
			cm_log(1, "Error shutting down NSS.\n");
		}
		_exit(CM_SUB_STATUS_ERROR_AUTH);
	}
	/* Select an initial key size. */
	if (cm_requested_key_size == 0) {
		cm_requested_key_size = CM_DEFAULT_PUBKEY_SIZE;
	}
	cm_key_size = cm_requested_key_size;
retry_gen:
	/* Initialize the parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		/* no parameters */
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		cm_log(1, "Computing parameters for domain generation.\n");
		pqg_ok = SECFailure;
		cm_key_size = pqg_size(cm_key_size);
		retry = 0;
		while (pqg_ok == SECFailure) {
			pqg_params = NULL;
			pqg_verify = NULL;
			pqg_s = cm_key_size / 32;
			if (pqg_s < 20) {
				pqg_s = 20;
			} else
			if (pqg_s > 64) {
				pqg_s = 64;
			}
			cm_log(1, "Generating domain parameters (L=%d,N=%d,S=%d).\n",
			       cm_key_size, 0, pqg_s);
			while (PK11_PQG_ParamGenV2(cm_key_size,
						   0,
						   pqg_s,
						   &pqg_params,
						   &pqg_verify) != SECSuccess) {
				ec = PORT_GetError();
				if (ec != 0) {
					es = PR_ErrorToName(ec);
				} else {
					es = NULL;
				}
				if (es != NULL) {
					cm_log(1,
					       "Error generating params: %s.\n",
					       es);
				} else {
					cm_log(1, "Error generating params.\n");
				}
				if ((ec != SEC_ERROR_BAD_DATA) || (++retry > 10)) {
					PK11_FreeSlotList(slotlist);
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down NSS.\n");
					}
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
				cm_log(1, "Trying again.\n");
				pqg_params = NULL;
				pqg_verify = NULL;
				goto retry_gen;
			}
			if (PK11_PQG_VerifyParams(pqg_params, pqg_verify,
						  &pqg_ok) != SECSuccess) {
				ec = PORT_GetError();
				if (ec != 0) {
					es = PR_ErrorToName(ec);
				} else {
					es = NULL;
				}
				if (es != NULL) {
					cm_log(1,
					       "Error verifying params: %s.\n",
					       es);
				} else {
					cm_log(1, "Error verifying params.\n");
				}
				if (++retry > 10) {
					PK11_FreeSlotList(slotlist);
					error = NSS_ShutdownContext(ctx);
					if (error != SECSuccess) {
						cm_log(1, "Error shutting down NSS.\n");
					}
					_exit(CM_SUB_STATUS_INTERNAL_ERROR);
				}
			}
			generated_size = pqg_params->prime.len * 8;
			if (generated_size < (cm_key_size * 9 / 10)) {
				cm_log(1, "Params are a too small (%d vs %d).\n",
				       pqg_params->prime.len * 8, cm_key_size);
				PK11_FreeSlotList(slotlist);
				error = NSS_ShutdownContext(ctx);
				if (error != SECSuccess) {
					cm_log(1, "Error shutting down NSS.\n");
				}
				_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			}
			if (pqg_ok == SECFailure) {
				cm_log(1, "Params are bad.  Retrying.\n");
			}
		}
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		/* no parameters to generate */
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
	case cm_key_ml_dsa_65:
	case cm_key_ml_dsa_87:
		/* no parameters to generate */
		break;
#endif
	default:
		params = NULL;
		break;
	}
	/* Initialize the key generation parameters. */
	switch (cm_key_algorithm) {
	case cm_key_rsa:
		memset(&rsa_params, 0, sizeof(rsa_params));
		rsa_params.keySizeInBits = cm_key_size;
		rsa_params.pe = CM_DEFAULT_RSA_EXPONENT;
		params = &rsa_params;
		break;
#ifdef CM_ENABLE_DSA
	case cm_key_dsa:
		memset(&dsa_params, 0, sizeof(dsa_params));
		PK11_PQG_GetPrimeFromParams(pqg_params, &dsa_params.prime);
		PK11_PQG_GetSubPrimeFromParams(pqg_params, &dsa_params.subPrime);
		PK11_PQG_GetBaseFromParams(pqg_params, &dsa_params.base);
		params = &dsa_params;
		break;
#endif
#ifdef CM_ENABLE_EC
	case cm_key_ecdsa:
		memset(&ec_params, 0, sizeof(ec_params));
		if (cm_key_size <= 256)
			ecurve = SECOID_FindOIDByTag(SEC_OID_ANSIX962_EC_PRIME256V1);
		else if (cm_key_size <= 384)
			ecurve = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP384R1);
		else
			ecurve = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP521R1);
		SEC_ASN1EncodeItem(NULL, &ec_params,
				   &ecurve->oid, SEC_ObjectIDTemplate);
		params = &ec_params;
		break;
#endif
#ifdef CM_ENABLE_ML_DSA
	case cm_key_ml_dsa_44:
		memset(&ml_params, 0, sizeof(ml_params));
		ml_params = CKP_ML_DSA_44;
		params = &ml_params;
		break;
	case cm_key_ml_dsa_65:
		memset(&ml_params, 0, sizeof(ml_params));
		ml_params = CKP_ML_DSA_65;
		params = &ml_params;
		break;
	case cm_key_ml_dsa_87:
		memset(&ml_params, 0, sizeof(ml_params));
		ml_params = CKP_ML_DSA_87;
		params = &ml_params;
		break;
#endif
	default:
		params = NULL;
		break;
	}
	/* Generate the key pair. */
	cm_log(0, "Generating key pair of size %d.\n", cm_key_size);
	pubkey = NULL;
	privkey = PK11_GenerateKeyPair(slot, mech, params, &pubkey,
				       PR_TRUE, PR_TRUE, NULL);

	/* Retry with the optimum key size. */
	if (privkey == NULL) {
		if (cm_key_size == -1) {
			cm_log(1, "Error generating key pair.\n");
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
		}
		cm_key_size = PK11_GetBestKeyLength(slot, pmech);
		if (cm_key_size != cm_requested_key_size) {
			cm_log(1,
			       "Overriding requested key size of %d with %d.\n",
			       cm_requested_key_size, cm_key_size);
			goto retry_gen;
		}
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error generating key pair: %s.\n", es);
		} else {
			cm_log(1, "Error generating key pair.\n");
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			break;
		}
	}
	cm_log(1, "Ended up with %d bit public key.\n",
	       SECKEY_PublicKeyStrengthInBits(pubkey));
	/* Check for keys with the desired name, selecting a new name if
	 * there's already one with the desired name. */
	nickname = strdup(entry->cm_key_nickname);
	if (nickname == NULL) {
		cm_log(1, "Out of memory.\n");
		_exit(CM_SUB_STATUS_INTERNAL_ERROR);
	}
	privkeys = PK11_ListPrivKeysInSlot(slot, nickname, NULL);
	while ((privkeys != NULL) && !PRIVKEY_LIST_EMPTY(privkeys)) {
		markertmp = NULL;
		for (node = PRIVKEY_LIST_HEAD(privkeys);
		     !PRIVKEY_LIST_EMPTY(privkeys) &&
		     !PRIVKEY_LIST_END(node, privkeys);
		     node = PRIVKEY_LIST_NEXT(node)) {
			keyname = PK11_GetPrivateKeyNickname(node->key);
			if ((keyname != NULL) &&
			    (strcmp(keyname, nickname) == 0)) {
				/* We're going to need to use a different nickname. */
				cm_log(1, "Key already exists with nickname \"%s\".\n", nickname);
				free(nickname);
				nickname = make_nickname(entry->cm_key_nickname, &markertmp);
				break;
			}
		}
		SECKEY_DestroyPrivateKeyList(privkeys);
		if (markertmp != NULL) {
			/* If we found at least one match, scan again for the new nickname. */
			privkeys = PK11_ListPrivKeysInSlot(slot,
							   nickname,
							   NULL);
			marker = markertmp;
		} else {
			cm_log(1, "Nickname \"%s\" appears to be unused.\n", nickname);
			privkeys = NULL;
		}
	}
	if ((marker == NULL) || (strlen(marker) == 0)) {
		/* Look harder.  Walk the list of certificates in the token,
		 * looking at each one to see if it matches the specified
		 * nickname. */
		markertmp = NULL;
		certs = PK11_ListCertsInSlot(slot);
		while (certs != NULL) {
			cert = NULL;
			for (cnode = CERT_LIST_HEAD(certs);
			     !CERT_LIST_EMPTY(certs) &&
			     !CERT_LIST_END(cnode, certs);
			     cnode = CERT_LIST_NEXT(cnode)) {
				cert = cnode->cert;
				if ((nickname != NULL) &&
				    (strcmp(cert->nickname, nickname) == 0)) {
					cm_log(3, "Located a certificate with "
					       "the desired nickname (\"%s\").\n",
					       nickname);
					ckey = PK11_FindPrivateKeyFromCert(slot,
									   cert,
									   NULL);
					if (ckey != NULL) {
						cm_log(3, "And we found "
						       "its private key.\n");
						SECKEY_DestroyPrivateKey(ckey);
					} else {
						cm_log(3, "But we didn't find "
						       "its private key.\n");
					}
					break;
				}
				cert = NULL;
			}
			if (cert == NULL) {
				cm_log(1, "Nickname \"%s\" appears to be unused.\n", nickname);
				CERT_DestroyCertList(certs);
				certs = NULL;
			} else {
				free(nickname);
				nickname = make_nickname(entry->cm_key_nickname, &markertmp);
				marker = markertmp;
			}
		}
	}

	/* Attach the specified nickname to the key. */
	error = PK11_SetPrivateKeyNickname(privkey, nickname);
	if (error != SECSuccess) {
		ec = PORT_GetError();
		if (ec != 0) {
			es = PR_ErrorToName(ec);
		} else {
			es = NULL;
		}
		if (es != NULL) {
			cm_log(1, "Error setting nickname \"%s\" on private key: "
			       "%s.\n", nickname, es);
		} else {
			cm_log(1, "Error setting nickname \"%s\" on private key.\n",
			       nickname);
		}
		switch (ec) {
		case PR_NO_ACCESS_RIGHTS_ERROR: /* EACCES or EPERM */
			_exit(CM_SUB_STATUS_ERROR_PERMS);
			break;
		default:
			_exit(CM_SUB_STATUS_INTERNAL_ERROR);
			break;
		}
	}
	cm_log(1, "Set nickname \"%s\" on private key.\n", nickname);
	/* Encode the public key to hex, and print it. */
	spki = SECKEY_EncodeDERSubjectPublicKeyInfo(pubkey);
	if (spki != NULL) {
		pubihex = cm_store_hex_from_bin(NULL, spki->data,
						spki->len);
		SECITEM_FreeItem(spki, PR_TRUE);
	} else {
		pubihex = "";
	}
	pubkeyinfo = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (pubkeyinfo != NULL) {
		pubhex = cm_store_hex_from_bin(NULL,
					       pubkeyinfo->subjectPublicKey.data,
					       howmany(pubkeyinfo->subjectPublicKey.len, 8));
		SECKEY_DestroySubjectPublicKeyInfo(pubkeyinfo);
	} else {
		pubhex = "";
	}
	fprintf(status, "%s\n%s\n%s\n", pubihex, pubhex, marker ? marker : "");
	SECKEY_DestroyPrivateKey(privkey);
	SECKEY_DestroyPublicKey(pubkey);
	/* Try to remove any keys with old candidate names. */
	if ((entry->cm_key_next_marker != NULL) &&
	    (strlen(entry->cm_key_next_marker) > 0)) {
		free(nickname);
		nickname = util_build_next_nickname(entry->cm_key_nickname, entry->cm_key_next_marker);
		privkeys = PK11_ListPrivKeysInSlot(slot, nickname, NULL);
		while ((privkeys != NULL) && !PRIVKEY_LIST_EMPTY(privkeys)) {
			delkey = NULL;
			for (node = PRIVKEY_LIST_HEAD(privkeys);
			     !PRIVKEY_LIST_EMPTY(privkeys) &&
			     !PRIVKEY_LIST_END(node, privkeys);
			     node = PRIVKEY_LIST_NEXT(node)) {
				keyname = PK11_GetPrivateKeyNickname(node->key);
				if ((keyname != NULL) && (nickname != NULL) &&
				    (strcmp(keyname, nickname) == 0)) {
					/* Avoid stealing the key reference from the
					 * list. */
					delkey = SECKEY_CopyPrivateKey(node->key);
					break;
				}
			}
			SECKEY_DestroyPrivateKeyList(privkeys);
			if (delkey != NULL) {
				PK11_DeleteTokenPrivateKey(delkey, PR_FALSE);
				cm_log(1, "Removing key with nickname \"%s\".\n", nickname);
				/* If we found at least one key before, scan again. */
				privkeys = PK11_ListPrivKeysInSlot(slot,
								   nickname,
								   NULL);
			} else {
				privkeys = NULL;
			}
		}
	}
	PK11_FreeSlotList(slotlist);
	error = NSS_ShutdownContext(ctx);
	free(nickname);
	util_set_db_entry_key_owner(entry->cm_key_storage_location, entry);
	if (error != SECSuccess) {
		cm_log(1, "Error shutting down NSS.\n");
	}
	fclose(status);
	return 0;
}

/* Check if the keypair is ready. */
static int
cm_keygen_n_ready(struct cm_keygen_state *state)
{
	return cm_subproc_ready(state->subproc);
}

/* Get a selectable-for-read descriptor we can poll for status changes. */
static int
cm_keygen_n_get_fd(struct cm_keygen_state *state)
{
	return cm_subproc_get_fd(state->subproc);
}

/* Tell us if the keypair was saved to the location specified in the entry. */
static int
cm_keygen_n_saved_keypair(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}
	return -1;
}

/* Tell us if we don't have permissions. */
static int
cm_keygen_n_need_perms(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_PERMS)) {
		return 0;
	}
	return -1;
}

/* Tell us if we need a new/correct PIN to use the key store. */
static int
cm_keygen_n_need_pin(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_AUTH)) {
		return 0;
	}
	return -1;
}

/* Check if we need a token to be inserted to generate the key. */
static int
cm_keygen_n_need_token(struct cm_keygen_state *state)
{
	int status;
	status = cm_subproc_get_exitstatus(state->subproc);
	if (WIFEXITED(status) &&
	    (WEXITSTATUS(status) == CM_SUB_STATUS_ERROR_NO_TOKEN)) {
		return 0;
	}
	return -1;
}

/* Clean up after key generation. */
static void
cm_keygen_n_done(struct cm_keygen_state *state)
{
	const char *output, *p, *q;
	char *pubkey_info, *pubkey, *marker = NULL;
	int len;

	if (state->subproc != NULL) {
		output = cm_subproc_get_msg(state->subproc, NULL);
		if (output != NULL) {
			p = output;
			len = strcspn(output, "\r\n");
			pubkey_info = talloc_strndup(state->entry, p, len);
			q = p + len;
			p = q + strspn(q, "\r\n");
			len = strcspn(p, "\r\n");
			pubkey = talloc_strndup(state->entry, p, len);
			q = p + len;
			p = q + strspn(q, "\r\n");
			len = strcspn(p, "\r\n");
			if (len > 0) {
				marker = talloc_strndup(state->entry, p, len);
			}
			if ((marker != NULL) && (strlen(marker) > 0)) {
				state->entry->cm_key_next_pubkey_info = pubkey_info;
				state->entry->cm_key_next_pubkey = pubkey;
				state->entry->cm_key_next_marker = marker;
				state->entry->cm_key_next_generated_date = time(NULL);
				state->entry->cm_key_next_requested_count = 0;
			} else {
				state->entry->cm_key_next_pubkey_info = NULL;
				state->entry->cm_key_next_pubkey = NULL;
				state->entry->cm_key_next_marker = NULL;
				state->entry->cm_key_next_generated_date = 0;
				state->entry->cm_key_pubkey_info = pubkey_info;
				state->entry->cm_key_pubkey = pubkey;
				state->entry->cm_key_generated_date = time(NULL);
				state->entry->cm_key_requested_count = 0;
				state->entry->cm_key_issued_count = 0;
			}
		}
		cm_subproc_done(state->subproc);
	}
	talloc_free(state);
}

/* Start keypair generation using parameters stored in the entry. */
struct cm_keygen_state *
cm_keygen_n_start(struct cm_store_entry *entry)
{
	struct cm_keygen_state *state;
	struct cm_keygen_n_settings settings = {
		.readwrite = 1,
	};
	if (entry->cm_key_storage_type != cm_key_storage_nssdb) {
		return NULL;
	}
	state = talloc_ptrtype(entry, state);
	if (state != NULL) {
		memset(state, 0, sizeof(*state));
		state->pvt.ready = cm_keygen_n_ready;
		state->pvt.get_fd = cm_keygen_n_get_fd;
		state->pvt.saved_keypair = cm_keygen_n_saved_keypair;
		state->pvt.need_perms = cm_keygen_n_need_perms;
		state->pvt.need_pin = cm_keygen_n_need_pin;
		state->pvt.need_token = cm_keygen_n_need_token;
		state->pvt.done = cm_keygen_n_done;
		state->entry = entry;
		state->subproc = cm_subproc_start(cm_keygen_n_main, state,
						  NULL, entry, &settings);
		if (state->subproc == NULL) {
			talloc_free(state);
			state = NULL;
		}
	}
	return state;
}
