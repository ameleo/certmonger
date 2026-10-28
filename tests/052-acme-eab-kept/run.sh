#!/bin/bash
#
# The key of an external account binding, given in a file when an ACME CA is
# added, is kept by the service: the file can be removed at once, the key
# shows nowhere in the CA's configuration, and it goes when the CA goes.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
timeout=120
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
cd "$tmpdir"

pid=
start_server() {
	rm -f "$tmpdir"/port
	$PYTHON "$srcdir"/../047-acme/acmeserver.py --cert ca/server.crt \
		--key ca/server.key --ca ca/root.crt --ca-key ca/root.key \
		--port-file "$tmpdir"/port --log "$tmpdir"/server.log \
		--eab-kid $KID --eab-key $KEY > "$tmpdir"/server.out 2>&1 &
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

mkdir -p "$tmpdir"/cas "$tmpdir"/requests
run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}
status() {
	run "$builddir"/../src/getcert list -i "$1" | grep -E "status:|ca-error:"
}

start_server

echo "[getcert add-acme-ca, the key in a file removed afterwards]"
umask 077
echo $KEY > "$tmpdir"/eab.key
run "$builddir"/../src/getcert add-acme-ca -c EAB -u $url \
	-R "$tmpdir"/ca/root.crt --eab-kid $KID --eab-key-file "$tmpdir"/eab.key
rm -f "$tmpdir"/eab.key
run "$builddir"/../src/getcert list-cas -c EAB > list
echo "files showing the key: `grep -l $KEY list "$tmpdir"/cas/* | wc -l`"
grep helper-location list | sed -e 's,localhost:[0-9]*,localhost,' -e 's,[^ ]*/acme-submit,acme-submit,' \
	-e "s,$tmpdir,\$tmpdir,g" -e 's,key-[A-Za-z0-9]*,key-XXXXXX,' \
	-e 's,^[[:space:]]*,,' -e 's, -R [^ ]*,,'
stored=`ls "$tmpdir"/state/eab/`
echo "stored: `stat -c %a "$tmpdir"/state/eab/$stored`, `grep -c $KEY "$tmpdir"/state/eab/$stored` key"
# Use the helper we just built.
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$builddir/../src/acme-submit ," "$tmpdir"/cas/*

echo "[getcert request]"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmpdir"/key.pem 2> /dev/null
run "$builddir"/../src/getcert request -c EAB -I r1 -k "$tmpdir"/key.pem \
	-f "$tmpdir"/cert.pem -N CN=localhost -D localhost \
	-w --wait-timeout=$timeout > /dev/null
status r1
grep -c "new-account (eab)" "$tmpdir"/server.log

echo "[getcert resubmit]"
run "$builddir"/../src/getcert resubmit -i r1 -w --wait-timeout=$timeout > /dev/null
status r1

echo "[getcert remove-ca: the key goes with it]"
run "$builddir"/../src/getcert stop-tracking -i r1 > /dev/null
run "$builddir"/../src/getcert remove-ca -c EAB
ls "$tmpdir"/state/eab/ | wc -l

echo OK
