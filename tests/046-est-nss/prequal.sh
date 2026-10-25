#!/bin/bash
PYTHON=${PYTHON:-python3}

if ! $PYTHON -c 'import http.server, ssl' 2> /dev/null ; then
	echo $PYTHON with http.server and ssl not found
	exit 1
fi
if ! test -x "$builddir"/../src/est-submit ; then
	echo est-submit not built
	exit 1
fi
if ! openssl list -providers -provider pkcs11 > /dev/null 2>&1 ; then
	echo OpenSSL PKCS#11 provider not found
	exit 1
fi
