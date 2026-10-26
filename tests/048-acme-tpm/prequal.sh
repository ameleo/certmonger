#!/bin/bash
PYTHON=${PYTHON:-python3}

if ! $PYTHON -c 'import http.server, ssl, cryptography' 2> /dev/null ; then
	echo $PYTHON with http.server, ssl and cryptography not found
	exit 1
fi
if ! grep -q "define HAVE_TSS2 1" "$builddir"/../src/config.h 2> /dev/null ; then
	echo acme-submit not built with TPM support
	exit 1
fi
for tool in swtpm swtpm_setup swtpm_localca tpm2-abrmd tpm2_ptool \
	    tpm2_getcap certutil modutil ; do
	if ! command -v $tool > /dev/null ; then
		echo $tool not found
		exit 1
	fi
done
if ! ls /usr/lib64/pkcs11/libtpm2_pkcs11.so /usr/lib/*/pkcs11/libtpm2_pkcs11.so \
       /usr/lib/pkcs11/libtpm2_pkcs11.so > /dev/null 2>&1 ; then
	echo tpm2-pkcs11 not found
	exit 1
fi
