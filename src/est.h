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

#ifndef cmest_h
#define cmest_h

/* RFC 7030 operation path segments. */
#define EST_WELL_KNOWN_PATH "/.well-known/est"
#define EST_OP_CACERTS "cacerts"
#define EST_OP_SIMPLEENROLL "simpleenroll"
#define EST_OP_SIMPLEREENROLL "simplereenroll"

#define EST_CONTENT_TYPE_PKCS10 "application/pkcs10"
#define EST_CONTENT_TYPE_PKCS7 "application/pkcs7-mime"

/* What we got back from the server. */
struct cm_est_response {
	int error;			/* nonzero if we couldn't get a reply */
	const char *error_text;
	long response_code;		/* HTTP status */
	const char *content_type;
	const char *retry_after;
	const unsigned char *body;
	size_t length;
};

/* Where the key which goes with the current certificate is, when it's
 * stored in an NSS database or in a token which is accessible through one,
 * in terms which OpenSSL's PKCS#11 provider understands. */
struct cm_est_key_location {
	char *module;			/* the PKCS#11 module which holds it */
	char *init_args;		/* arguments for initializing it */
	char *uri;			/* a PKCS#11 URI (RFC 7512) for it */
};

/* Find the key which goes with the current certificate in an NSS database,
 * or in a token which is accessible through it, and describe its location. */
int cm_est_n_key_location(void *parent,
			  const char *dbdir, const char *token,
			  const char *cert_pem, const char *pin,
			  struct cm_est_key_location *location,
			  const char **error);

#endif
