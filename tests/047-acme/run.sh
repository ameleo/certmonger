#!/bin/bash
#
# ACME enrollment with acme-submit, against a small ACME server which
# authorizes the names of an order as soon as the account is bound to an
# external account.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
ACME="$builddir"/../src/acme-submit
timeout=300
KID=kid1
KEY=c2VjcmV0LW1hYy1rZXktZm9yLXRlc3Rpbmc

mkdir -p "$tmpdir"/ca
cd "$tmpdir"/ca
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout root.key -out root.crt -subj "/CN=ACME Test Root CA" -days 2 \
	-addext basicConstraints=critical,CA:true \
	-addext keyUsage=critical,keyCertSign,cRLSign 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout server.key -out server.csr -subj /CN=localhost 2> /dev/null
printf "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA root.crt -CAkey root.key -set_serial 1 \
	-days 2 -out server.crt -extfile server.ext 2> /dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout other.key -out other.crt -subj "/CN=Some Other CA" -days 2 \
	2> /dev/null
cd "$tmpdir"

pid=
start_server() {
	stop_server
	rm -f "$tmpdir"/port "$tmpdir"/server.log "$tmpdir"/server.seen
	$PYTHON "$srcdir"/acmeserver.py --cert ca/server.crt --key ca/server.key \
		--ca ca/root.crt --ca-key ca/root.key \
		--port-file "$tmpdir"/port --log "$tmpdir"/server.log "$@" \
		> "$tmpdir"/server.out 2>&1 &
	pid=$!
	for i in `seq 100` ; do
		test -s "$tmpdir"/port && break
		sleep 0.1
	done
	url=https://localhost:`cat "$tmpdir"/port`/directory
}
stop_server() {
	if test -n "$pid" ; then
		kill $pid 2> /dev/null
		wait $pid 2> /dev/null
		pid=
	fi
}
trap stop_server EXIT

# Run the helper the way the daemon does, with nothing in the environment
# but what the daemon passes, and report how it went.
acme() {
	env -i PATH="$PATH" CERTMONGER_ACME_DIR="$tmpdir"/state "$@" > out 2> err
	echo exit: $?
	cp out out.raw
	sed -i -e 's,localhost:[0-9]*,localhost,g' out
}
csr() {
	openssl req -new -key "$1" -subj "/CN=$2" ${3:+-addext "$3"} \
		-out "$1".csr 2> /dev/null
}
matches() {
	if test "`openssl pkey -in $1 -pubout`" = \
		"`openssl x509 -in $2 -noout -pubkey`" ; then
		echo "certificate is for the key"
	else
		echo "certificate is NOT for the key"
	fi
}
# What the server saw since the last time we looked.
log() {
	touch "$tmpdir"/server.seen
	tail -n +$((`wc -l < "$tmpdir"/server.seen` + 1)) "$tmpdir"/server.log
	cp "$tmpdir"/server.log "$tmpdir"/server.seen
}

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key
csr ec.key ec.example.com "subjectAltName=DNS:ec.example.com,DNS:www.example.com,IP:192.0.2.1"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
csr rsa.key rsa.example.com

start_server --eab-kid $KID --eab-key $KEY

echo "[identify]"
acme CERTMONGER_OPERATION=IDENTIFY "$ACME"
cut -f1 -d' ' out

echo "[plain http]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u http://localhost/directory -R ca/root.crt
cat out

echo "[untrusted server]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/other.crt

echo "[no external account binding]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
cat out
rm -fr "$tmpdir"/state
log > /dev/null

echo "[bad external account key]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=$KID:d3Jvbmc \
	"$ACME" -u $url -R ca/root.crt
cat out
log
rm -fr "$tmpdir"/state

echo "[enroll, EC P-256, external account in the challenge password]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=$KID:$KEY \
	"$ACME" -u $url -R ca/root.crt
cp out ec.crt
matches ec.key ec.crt
log
ls "$tmpdir"/state/*/ | sort
stat -c %a "$tmpdir"/state/*/account.key

echo "[enroll, RSA, existing account]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat rsa.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
matches rsa.key out
log

echo "[enroll, external account key in a file]"
rm -fr "$tmpdir"/state
echo $KEY > eab.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat rsa.key.csr`" \
	"$ACME" -u $url -R ca/root.crt -k $KID -K "$tmpdir"/eab.key
matches rsa.key out
log | head -n 2
grep -c $KEY err

echo "[enroll, existing account: the external account key is not read]"
rm -f eab.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt -k $KID -K "$tmpdir"/eab.key
matches ec.key out
log | head -n 2

echo "[enroll, nonce refused once]"
start_server --eab-kid $KID --eab-key $KEY --bad-nonce
rm -fr "$tmpdir"/state
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=$KID:$KEY \
	"$ACME" -u $url -R ca/root.crt
matches ec.key out
log | head -n 3

echo "[enroll, the server takes a few seconds]"
start_server --processing 2
rm -fr "$tmpdir"/state
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
matches ec.key out
log | grep order

echo "[enroll, the server takes longer]"
start_server --processing 1 --retry-after 30
rm -fr "$tmpdir"/state
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
cat out
log | grep order
echo "[poll]"
acme CERTMONGER_OPERATION=POLL CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CA_COOKIE="`tail -n 1 out.raw`" \
	"$ACME" -u $url -R ca/root.crt
matches ec.key out
log

echo "[challenges which we can't answer]"
start_server --offer http-01
rm -fr "$tmpdir"/state
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
cat out
start_server --attest
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt -P device42
cat out
log | grep identifiers

# Now through the daemon.
start_server --eab-kid $KID --eab-key $KEY
rm -fr "$tmpdir"/state
mkdir -p "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/files
run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}
status() {
	run "$builddir"/../src/getcert list -i "$1" | grep -E "status:|ca-error:" | sed -e 's,localhost:[0-9]*,localhost,'
}

echo "[getcert add-acme-ca]"
echo $KEY > "$tmpdir"/files/eab.key
run "$builddir"/../src/getcert add-acme-ca -c ACME -u $url -R "$tmpdir"/ca/root.crt \
	--eab-kid $KID --eab-key-file "$tmpdir"/files/eab.key
# The service keeps a copy of the key: the file is no longer needed.
rm -f "$tmpdir"/files/eab.key
sed -n -e 's,localhost:[0-9]*,localhost,' -e "s,$tmpdir,\$tmpdir,g" -e 's,key-[A-Za-z0-9]*$,key-XXXXXX,' -e 's,^ca_external_helper=.*/acme-submit,ca_external_helper=acme-submit,p' "$tmpdir"/cas/*
# Use the helper we just built.
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*

echo "[getcert request, EC P-256, files]"
run "$builddir"/../src/getcert request -c ACME -I files -w --wait-timeout=$timeout \
	-G EC -g 256 -N CN=files.example.com -D files.example.com \
	-k "$tmpdir"/files/key -f "$tmpdir"/files/cert > /dev/null
status files
matches files/key files/cert
openssl x509 -in files/cert -noout -ext subjectAltName | tail -n 1
log | grep -E "new-account|identifiers"

echo "[getcert resubmit, files]"
cp files/cert files/cert.first
run "$builddir"/../src/getcert resubmit -i files -w --wait-timeout=$timeout > /dev/null
status files
matches files/key files/cert
cmp -s files/cert files/cert.first && echo ERROR: certificate was not replaced
log | grep -E "new-account|identifiers"

echo OK
