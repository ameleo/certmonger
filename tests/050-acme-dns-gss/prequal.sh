#!/bin/bash
PYTHON=${PYTHON:-python3}

if ! $PYTHON -c 'import http.server, ssl, cryptography' 2> /dev/null ; then
	echo $PYTHON with http.server, ssl and cryptography not found
	exit 1
fi
if ! grep -q "define HAVE_GSS_TSIG 1" "$builddir"/../src/config.h 2> /dev/null ; then
	echo acme-submit not built with GSS-TSIG support
	exit 1
fi
PATH=$PATH:/usr/sbin:/sbin
for tool in named krb5kdc kdb5_util kadmin.local ; do
	if ! command -v $tool > /dev/null ; then
		echo $tool not found
		exit 1
	fi
done
