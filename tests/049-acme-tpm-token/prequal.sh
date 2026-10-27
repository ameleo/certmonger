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
	    tpm2_getcap certutil modutil pkcs11-tool ; do
	if ! command -v $tool > /dev/null ; then
		echo $tool not found
		exit 1
	fi
done
for module in /usr/lib64/pkcs11/libtpm2_pkcs11.so \
	      /usr/lib/*/pkcs11/libtpm2_pkcs11.so \
	      /usr/lib/pkcs11/libtpm2_pkcs11.so ; do
	test -e $module && break
done
if ! test -e $module ; then
	echo tpm2-pkcs11 not found
	exit 1
fi

# The module certifies keys through its CKM_TPM2_CERTIFY mechanism, which it
# lists when asked about a TPM.
dir=`mktemp -d`
swtpm socket --tpm2 --tpmstate dir="$dir" \
	--server type=unixio,path="$dir"/sock \
	--ctrl type=unixio,path="$dir"/sock.ctrl \
	--flags not-need-init,startup-clear > /dev/null 2>&1 &
swtpm=$!
for i in `seq 50` ; do test -S "$dir"/sock && break ; sleep 0.1 ; done
mechanisms=`TPM2_PKCS11_TCTI=swtpm:path="$dir"/sock TPM2_PKCS11_STORE="$dir" \
	    TPM2_PKCS11_LOG_LEVEL=0 pkcs11-tool --module $module -M 2> /dev/null`
kill $swtpm
wait $swtpm 2> /dev/null
rm -fr "$dir"
if ! echo "$mechanisms" | grep -qi "mechtype-0x8F000001" ; then
	echo tpm2-pkcs11 without the CKM_TPM2_CERTIFY mechanism
	exit 1
fi
exit 0
