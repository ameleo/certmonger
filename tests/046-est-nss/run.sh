#!/bin/bash
#
# Re-enrollment with keys in NSS databases, which est-submit uses through
# OpenSSL's PKCS#11 provider.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
EST="$builddir"/../src/est-submit
timeout=300

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
	$PYTHON "$srcdir"/../045-est/estserver.py \
		--cert ca/server.crt --key ca/server.key \
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

# Run the helper the way the daemon does, with nothing in the environment
# but what the daemon passes.
est() {
	env -i PATH="$PATH" "$@" > out 2> err
	echo exit: $?
	sed -i -e 's,localhost:[0-9]*,localhost,g' out
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
# A key, a request, and a first certificate for it.
enroll() {
	openssl genpkey "$@" -out $name.key
	openssl req -new -key $name.key -subj "/CN=$name" -out $name.csr 2> /dev/null
	env -i PATH="$PATH" CERTMONGER_OPERATION=SUBMIT \
		CERTMONGER_CSR="`cat $name.csr`" \
		CERTMONGER_CHALLENGE_PASSWORD=user:secret \
		"$EST" -u $url -R ca/root.crt > $name.crt
	openssl pkcs12 -export -inkey $name.key -in $name.crt -name $name \
		-passout pass:p12 -out $name.p12
}

start_server

echo "[re-enroll, EC key in an NSS database protected by a PIN]"
name=ec enroll -algorithm EC -pkeyopt ec_paramgen_curve:P-256
mkdir db-pin
echo dbpin > dbpin
certutil -N -d db-pin -f dbpin
pk12util -i ec.p12 -d db-pin -k dbpin -W p12 > /dev/null
est CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db-pin \
	CERTMONGER_KEY_NICKNAME=ec \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/dbpin \
	"$EST" -u $url -R ca/root.crt
matches ec.key out
lastlog

echo "[re-enroll, RSA key in an NSS database without a PIN]"
name=rsa enroll -algorithm RSA -pkeyopt rsa_keygen_bits:2048
mkdir db-nopin
certutil -N -d db-nopin --empty-password
pk12util -i rsa.p12 -d db-nopin -W p12 > /dev/null
est CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat rsa.csr`" \
	CERTMONGER_CERTIFICATE="`cat rsa.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db-nopin \
	CERTMONGER_KEY_NICKNAME=rsa \
	"$EST" -u $url -R ca/root.crt
matches rsa.key out
lastlog

echo "[re-enroll, key in an NSS database, wrong PIN]"
echo wrong > wrongpin
est CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db-pin \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/wrongpin \
	"$EST" -u $url -R ca/root.crt
cat out

echo "[re-enroll, key in an NSS database, untrusted server]"
est CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.csr`" \
	CERTMONGER_CERTIFICATE="`cat ec.crt`" \
	CERTMONGER_KEY_STORAGE_TYPE=NSSDB \
	CERTMONGER_KEY_STORAGE_LOCATION="$tmpdir"/db-pin \
	CERTMONGER_KEY_PIN_FILE="$tmpdir"/dbpin \
	"$EST" -u $url -R ca/other.crt
cat out

# Now through the daemon.
mkdir -p "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/files/db
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
sed -i -e "s,^ca_external_helper=[^ ]*est-submit ,ca_external_helper=$EST ," "$tmpdir"/cas/*

echo "[getcert request, RSA, NSS database]"
echo nsspin > "$tmpdir"/nsspin
certutil -N -d "$tmpdir"/files/db -f "$tmpdir"/nsspin
run "$builddir"/../src/getcert request -c EST -I nss -w --wait-timeout=$timeout \
	-G RSA -g 2048 -N CN=nss -L user:secret \
	-d "$tmpdir"/files/db -n nss -p "$tmpdir"/nsspin > /dev/null
status nss
lastlog
certutil -L -d "$tmpdir"/files/db -n nss -a > files/nss.crt.first

echo "[getcert resubmit, NSS database]"
run "$builddir"/../src/getcert resubmit -i nss -w --wait-timeout=$timeout > /dev/null
status nss
lastlog
certutil -L -d "$tmpdir"/files/db -n nss -a > files/nss.crt
cmp -s files/nss.crt files/nss.crt.first && echo ERROR: certificate was not replaced
test "`openssl x509 -in files/nss.crt -noout -pubkey`" = \
	"`openssl x509 -in files/nss.crt.first -noout -pubkey`" && echo "same key"

echo OK
