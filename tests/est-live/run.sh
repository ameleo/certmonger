#!/bin/bash
#
# Exercise est-submit through the certmonger daemon against a live EST
# server.  This is not part of "make check": it needs a server, and
# credentials which may only be good for one enrollment each.
#
# Usage: run.sh [options]
#   -u URL        EST server (required)
#   -i LABEL      CA label
#   -R FILE       CA certificate(s) for verifying the server
#   -1 FILE       credentials ("name:password") for the EC enrollment
#   -2 FILE       credentials for the RSA enrollment in an NSS database
#   -s NAME       DNS name to request in the first enrollment
#   -t NAME       DNS name to request in the second enrollment
#   -k            also try to change keys ("getcert rekey")
#
# Run it from the build directory's "tests" subdirectory, or set builddir.

builddir=${builddir:-`pwd`}
timeout=${timeout:-120}
url= label= cacert= cred1= cred2= name1=est1.example.com name2=est2.example.com
rekey=
while getopts u:i:R:1:2:s:t:k opt ; do
	case $opt in
	u) url=$OPTARG ;;
	i) label=$OPTARG ;;
	R) cacert=$OPTARG ;;
	1) cred1=$OPTARG ;;
	2) cred2=$OPTARG ;;
	s) name1=$OPTARG ;;
	t) name2=$OPTARG ;;
	k) rekey=1 ;;
	*) exit 1 ;;
	esac
done
if test -z "$url" ; then
	echo "Usage: $0 -u URL [-i LABEL] [-R FILE] [-1 FILE] [-2 FILE] [-k]"
	exit 1
fi

tmpdir=${tmpdir:-`mktemp -d ${TMPDIR:-/tmp}/estliveXXXXXX`}
mkdir -p "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/files "$tmpdir"/db
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
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*" 2>> "$tmpdir"/daemon.log
}
getcert() {
	run "$builddir"/../src/getcert "$@"
}
show() {
	getcert list -i "$1" | grep -E "status:|ca-error:|issuer:|subject:|expires:|key pair storage:"
}
describe() {
	openssl x509 -in "$1" -noout -serial -subject -issuer -ext subjectAltName 2> /dev/null | grep -v "X509v3"
	openssl x509 -in "$1" -noout -text | grep -E "Public Key Algorithm|Public-Key|NIST CURVE"
}
same_key() {
	if test "`openssl x509 -in $1 -noout -pubkey`" = "`openssl x509 -in $2 -noout -pubkey`" ; then
		echo "same key"
	else
		echo "different keys"
	fi
}
helper_to_builddir() {
	sed -i -e "s,^ca_external_helper=[^ ]*est-submit ,ca_external_helper=$builddir/../src/est-submit ," "$tmpdir"/cas/*
}

echo "[add-est-ca]"
getcert add-est-ca -c EST -u "$url" ${label:+-i "$label"} ${cacert:+-R "$cacert"}
helper_to_builddir
grep ca_external_helper "$tmpdir"/cas/*

if test -n "$cred1" ; then
	echo "[request: EC P-256, PEM files]"
	getcert request -c EST -I ec -w --wait-timeout=$timeout \
		-G EC -g 256 -N "CN=$name1" -D "$name1" -l "$cred1" \
		-k "$tmpdir"/files/ec.key -f "$tmpdir"/files/ec.crt \
		-F "$tmpdir"/files/ca.crt
	show ec
	describe files/ec.crt
	echo "CA certificates saved by the daemon:"
	openssl crl2pkcs7 -nocrl -certfile files/ca.crt | openssl pkcs7 -print_certs -noout | grep subject

	echo "[resubmit: re-enrollment with the certificate, no password]"
	cp files/ec.crt files/ec.crt.1
	getcert resubmit -i ec -w --wait-timeout=$timeout
	show ec
	describe files/ec.crt
	same_key files/ec.crt files/ec.crt.1

	if test -n "$rekey" ; then
		echo "[rekey: re-enrollment with a new key]"
		cp files/ec.crt files/ec.crt.2
		getcert rekey -i ec -w --wait-timeout=$timeout
		show ec
		same_key files/ec.crt files/ec.crt.2
	fi
fi

if test -n "$cred2" ; then
	echo "[request: RSA 3072, NSS database protected by a PIN]"
	echo nsspin > "$tmpdir"/nsspin
	certutil -N -d "$tmpdir"/db -f "$tmpdir"/nsspin
	getcert request -c EST -I nss -w --wait-timeout=$timeout \
		-G RSA -g 3072 -N "CN=$name2" -D "$name2" -l "$cred2" \
		-d "$tmpdir"/db -n est -p "$tmpdir"/nsspin
	show nss
	certutil -L -d "$tmpdir"/db -n est -a > files/nss.crt.1
	describe files/nss.crt.1

	echo "[resubmit: re-enrollment with the certificate, no password]"
	getcert resubmit -i nss -w --wait-timeout=$timeout
	show nss
	certutil -L -d "$tmpdir"/db -n est -a > files/nss.crt
	describe files/nss.crt
	same_key files/nss.crt files/nss.crt.1
fi

echo "[request: wrong credentials]"
echo "nosuchuser:wrongpassword" > "$tmpdir"/badcred
getcert request -c EST -I bad -w --wait-timeout=$timeout \
	-G EC -g 256 -N CN=bad.example.com -l "$tmpdir"/badcred \
	-k "$tmpdir"/files/bad.key -f "$tmpdir"/files/bad.crt
show bad

echo "[request: server not trusted]"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$tmpdir"/other.key -out "$tmpdir"/other.crt \
	-subj "/CN=Unrelated CA" -days 1 2> /dev/null
getcert add-est-ca -c Untrusted -u "$url" ${label:+-i "$label"} -R "$tmpdir"/other.crt
helper_to_builddir
getcert request -c Untrusted -I untrusted -w --wait-timeout=30 \
	-G EC -g 256 -N CN=untrusted.example.com -l "$tmpdir"/badcred \
	-k "$tmpdir"/files/untrusted.key -f "$tmpdir"/files/untrusted.crt
show untrusted

echo "[list]"
getcert list | grep -E "^Request ID|status:|CA:"
