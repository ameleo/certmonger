#!/bin/bash
#
# Exercise acme-submit through the certmonger daemon against a live ACME
# server.  This is not part of "make check": it needs a server, and
# credentials which may only be good for one account each.
#
# Usage: run.sh [options]
#   -u URL        ACME directory (required)
#   -R FILE       CA certificate(s) for verifying the server
#   -e FILE       external account binding credentials ("KID:KEY")
#   -n NAME       name to request: a DNS name, or with -a, the device's
#                 permanent identifier
#   -a            device attestation with the TPM: the key is generated in
#                 the tpm2-pkcs11 token named with -t, in the NSS database
#                 named with -d, whose PIN is in the file named with -p
#   -d DIR        NSS database
#   -t TOKEN      token
#   -p FILE       PIN file
#   -k            also change keys ("getcert rekey")
#
# Run it from the build directory's "tests" subdirectory, or set builddir.
# The TPM is reached as tpm2-pkcs11 reaches it (TPM2_PKCS11_TCTI).

builddir=${builddir:-`pwd`}
timeout=${timeout:-180}
url= cacert= cred= name= attest= db= token= pin= rekey=
while getopts u:R:e:n:ad:t:p:k opt ; do
	case $opt in
	u) url=$OPTARG ;;
	R) cacert=$OPTARG ;;
	e) cred=$OPTARG ;;
	n) name=$OPTARG ;;
	a) attest=1 ;;
	d) db=$OPTARG ;;
	t) token=$OPTARG ;;
	p) pin=$OPTARG ;;
	k) rekey=1 ;;
	*) exit 1 ;;
	esac
done
if test -z "$url" || test -z "$name" ||
   { test -n "$attest" && { test -z "$db" || test -z "$token" || test -z "$pin" ; } ; } ; then
	echo "Usage: $0 -u URL -n NAME [-R FILE] [-e FILE] [-a -d DIR -t TOKEN -p FILE] [-k]"
	exit 1
fi

tmpdir=${tmpdir:-`mktemp -d ${TMPDIR:-/tmp}/acmeliveXXXXXX`}
mkdir -p "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/files "$tmpdir"/state
cd "$tmpdir"
echo "Working in $tmpdir"

if test -z "$DBUS_SESSION_BUS_ADDRESS" ; then
	eval `dbus-launch --sh-syntax`
	trap 'kill "$DBUS_SESSION_BUS_PID"' EXIT
fi

run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*" 2>> "$tmpdir"/daemon.log
}
getcert() {
	run "$builddir"/../src/getcert "$@"
}
show() {
	getcert list -i "$1" | grep -E "status:|ca-error:|key pair storage:|subject:|issuer:|expires:"
}
certificate() {
	if test -n "$attest" ; then
		certutil -L -d "$db" -h "$token" -f "$pin" -n "$token:$name" -a 2> /dev/null
	else
		cat "$tmpdir"/files/cert
	fi
}
describe() {
	openssl x509 -noout -serial -subject -issuer -ext subjectAltName,certificatePolicies 2> /dev/null
}

echo "[getcert add-acme-ca]"
getcert add-acme-ca -c ACME -u "$url" ${cacert:+-R "$cacert"} ${attest:+--attest tpm}
# Use the helper we just built.
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$builddir/../src/acme-submit ," "$tmpdir"/cas/*
grep ^ca_external_helper "$tmpdir"/cas/*

challenge=
test -n "$cred" && challenge="-l $cred"
if test -n "$attest" ; then
	echo "[getcert request: an RSA key generated in the TPM, attested]"
	getcert request -c ACME -I live -w --wait-timeout=$timeout \
		-d "$db" -t "$token" -n "$name" -p "$pin" \
		-G RSA -g 2048 -N CN="$name" $challenge
else
	echo "[getcert request: an EC key in a file]"
	getcert request -c ACME -I live -w --wait-timeout=$timeout \
		-k "$tmpdir"/files/key -f "$tmpdir"/files/cert \
		-G EC -g 256 -N CN="$name" -D "$name" $challenge
fi
show live
certificate > first.pem
describe < first.pem

echo "[getcert resubmit: renewal]"
getcert resubmit -i live -w --wait-timeout=$timeout
show live
certificate > second.pem
describe < second.pem
test "`openssl x509 -in first.pem -noout -pubkey`" = \
     "`openssl x509 -in second.pem -noout -pubkey`" && echo "same key"

if test -n "$rekey" ; then
	echo "[getcert rekey]"
	getcert rekey -i live -w --wait-timeout=$timeout
	show live
	certificate > third.pem
	describe < third.pem
	test "`openssl x509 -in second.pem -noout -pubkey`" != \
	     "`openssl x509 -in third.pem -noout -pubkey`" && echo "new key"
fi
ls -l "$tmpdir"/state/*/
