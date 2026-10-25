#!/bin/bash

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
EST="$builddir"/../src/est-submit
timeout=300

# A CA, a certificate for the server, and an unrelated CA.
mkdir -p "$tmpdir"/ca
cd "$tmpdir"/ca
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout root.key -out root.crt -subj "/CN=EST Test Root CA" -days 2 \
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
	rm -f "$tmpdir"/port "$tmpdir"/server.log
	$PYTHON "$srcdir"/estserver.py --cert ca/server.crt --key ca/server.key \
		--ca ca/root.crt --ca-key ca/root.key --cacerts ca/root.crt \
		--port-file "$tmpdir"/port --log "$tmpdir"/server.log "$@" \
		> "$tmpdir"/server.out 2>&1 &
	pid=$!
	for i in `seq 100` ; do
		test -s "$tmpdir"/port && break
		sleep 0.1
	done
	url=https://localhost:`cat "$tmpdir"/port`
}
stop_server() {
	if test -n "$pid" ; then
		kill $pid 2> /dev/null
		wait $pid 2> /dev/null
		pid=
	fi
}
trap stop_server EXIT

# Run the helper the way the daemon does, and report how it went.
est() {
	env -u CERTMONGER_CHALLENGE_PASSWORD "$@" > out 2> err
	echo exit: $?
	sed -i -e 's,localhost:[0-9]*,localhost,g' out
}
csr() {
	openssl req -new -key "$1" -subj "/CN=$2" -out "$1".csr 2> /dev/null
}
matches() {
	if test "`openssl pkey -in $1 -pubout`" = \
		"`openssl x509 -in $2 -noout -pubkey`" ; then
		echo "certificate is for the key"
	else
		echo "certificate is NOT for the key"
	fi
}
lastlog() {
	grep POST "$tmpdir"/server.log | tail -n 1
}

start_server

echo "[identify]"
est env CERTMONGER_OPERATION=IDENTIFY "$EST"
cut -f1 -d' ' out

echo "[fetch roots]"
est env CERTMONGER_OPERATION=FETCH-ROOTS "$EST" -u $url -R ca/root.crt
$PYTHON -c 'import json, sys
roots = json.load(open(sys.argv[1]))
for kind in sorted(roots):
    for cert in roots[kind]:
        print(kind, cert["nickname"], cert["certificate"].splitlines()[0])' out

echo "[fetch roots, untrusted server]"
est env CERTMONGER_OPERATION=FETCH-ROOTS "$EST" -u $url -R ca/other.crt

echo "[fetch roots, plain http]"
est env CERTMONGER_OPERATION=FETCH-ROOTS "$EST" -u http://localhost/ -R ca/root.crt
cat out

echo "[enroll, EC P-256, no password]"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key
csr ec.key ec
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$EST" -u $url -R ca/root.crt
cat out
lastlog

echo "[enroll, EC P-256, bad password]"
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=user:wrong "$EST" -u $url -R ca/root.crt
head -n 1 out
lastlog

echo "[enroll, EC P-256, untrusted server]"
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=user:secret "$EST" -u $url -R ca/other.crt

echo "[enroll, EC P-256]"
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=user:secret "$EST" -u $url -R ca/root.crt
cp out ec.crt
matches ec.key ec.crt
lastlog

echo "[enroll, RSA, credentials in the CA configuration]"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
csr rsa.key rsa
echo secret > password
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat rsa.key.csr`" \
	"$EST" -u $url -R ca/root.crt -U user -W "$tmpdir"/password
cp out rsa.crt
matches rsa.key rsa.crt
lastlog

echo "[re-enroll, key in a file]"
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=FILE \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/ec.key \
	"$EST" -u $url -R ca/root.crt
matches ec.key out
lastlog

echo "[re-enroll, encrypted key in a file]"
echo keypin > keypin
openssl pkey -in rsa.key -aes256 -passout file:keypin -out rsa-enc.key
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat rsa.key.csr`" \
	CERTMONGER_CERTIFICATE="`cat rsa.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=FILE \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/rsa-enc.key \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/keypin \
	"$EST" -u $url -R ca/root.crt
matches rsa.key out
lastlog

echo "[re-enroll, key in an NSS database]"
mkdir db
echo dbpin > dbpin
certutil -N -d db -f dbpin
openssl pkcs12 -export -inkey ec.key -in ec.crt -name ec -passout pass:p12 \
	-out ec.p12
pk12util -i ec.p12 -d db -k dbpin -W p12 > /dev/null
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db \
	CERTMONGER_KEY_NICKNAME=ec \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/dbpin \
	"$EST" -u $url -R ca/root.crt
matches ec.key out
lastlog

echo "[re-enroll, key in an NSS database, untrusted server]"
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/dbpin \
	"$EST" -u $url -R ca/other.crt
cat out

echo "[enroll, pending]"
start_server --pending 1 --retry-after 42 --label lab
est env CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CHALLENGE_PASSWORD=user:secret \
	"$EST" -u $url -R ca/root.crt -i lab
cat out
lastlog
echo "[poll]"
est env CERTMONGER_OPERATION=POLL CERTMONGER_CSR="`cat ec.key.csr`" \
	CERTMONGER_CA_COOKIE=simpleenroll \
	CERTMONGER_CHALLENGE_PASSWORD=user:secret \
	"$EST" -u $url -R ca/root.crt -i lab
matches ec.key out
lastlog

# Now through the daemon.
start_server
mkdir -p "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/files
run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}
status() {
	run "$builddir"/../src/getcert list -i "$1" | grep -E "status:|ca-error:" | sed -e 's,localhost:[0-9]*,localhost,'
}

echo "[getcert add-est-ca]"
run "$builddir"/../src/getcert add-est-ca -c EST -u $url -R "$tmpdir"/ca/root.crt
sed -n -e 's,localhost:[0-9]*,localhost,' -e "s,$tmpdir,\$tmpdir,g" -e 's,^ca_external_helper=.*/est-submit,ca_external_helper=est-submit,p' "$tmpdir"/cas/*
# Use the helper we just built.
sed -i -e "s,^ca_external_helper=[^ ]*est-submit ,ca_external_helper=$EST ," "$tmpdir"/cas/*

echo "[getcert request, EC P-256, files]"
run "$builddir"/../src/getcert request -c EST -I files -w --wait-timeout=$timeout \
	-G EC -g 256 -N CN=files -L user:secret -F "$tmpdir"/files/ca.crt \
	-k "$tmpdir"/files/key -f "$tmpdir"/files/cert > /dev/null
status files
matches files/key files/cert
lastlog
openssl x509 -in files/ca.crt -noout -subject

echo "[getcert resubmit, files]"
cp files/cert files/cert.first
run "$builddir"/../src/getcert resubmit -i files -w --wait-timeout=$timeout > /dev/null
status files
matches files/key files/cert
cmp -s files/cert files/cert.first && echo ERROR: certificate was not replaced
lastlog

echo "[getcert request, RSA, NSS database]"
mkdir -p "$tmpdir"/files/db
certutil -N -d "$tmpdir"/files/db --empty-password
run "$builddir"/../src/getcert request -c EST -I nss -w --wait-timeout=$timeout \
	-G RSA -g 2048 -N CN=nss -L user:secret \
	-d "$tmpdir"/files/db -n nss > /dev/null
status nss
lastlog

echo "[getcert resubmit, NSS database]"
run "$builddir"/../src/getcert resubmit -i nss -w --wait-timeout=$timeout > /dev/null
status nss
lastlog

echo "[getcert request, bad password]"
run "$builddir"/../src/getcert request -c EST -I bad -w --wait-timeout=$timeout \
	-G EC -g 256 -N CN=bad -L user:wrong \
	-k "$tmpdir"/files/bad.key -f "$tmpdir"/files/bad.cert > /dev/null
status bad
lastlog

echo OK
