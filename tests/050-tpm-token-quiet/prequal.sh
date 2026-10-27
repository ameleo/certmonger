#!/bin/bash
# Everything 049-acme-tpm-token needs, on a system set up as Fedora is: the
# module made known to p11-kit, and no store where it looks by default.
"$srcdir"/049-acme-tpm-token/prequal.sh || exit 1
if ! ls /usr/share/p11-kit/modules/*.module 2> /dev/null |
     xargs grep -l libtpm2_pkcs11 > /dev/null 2>&1 ; then
	echo tpm2-pkcs11 not made known to p11-kit
	exit 1
fi
if test -e /etc/tpm2_pkcs11 ; then
	echo /etc/tpm2_pkcs11 exists
	exit 1
fi
exit 0
