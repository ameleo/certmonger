#!/bin/bash
PYTHON=${PYTHON:-python3}

if ! $PYTHON -c 'import http.server, ssl, cryptography' 2> /dev/null ; then
	echo $PYTHON with http.server, ssl and cryptography not found
	exit 1
fi
if ! test -x "$builddir"/../src/acme-submit ; then
	echo acme-submit not built
	exit 1
fi
