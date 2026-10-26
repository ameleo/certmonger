#!/bin/bash
#
# ACME enrollment with acme-submit, answering dns-01 challenges by adding
# TXT records to zones served by BIND's named, using DNS updates signed
# with TSIG, against the test ACME server, which looks the records up.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
ACME="$builddir"/../src/acme-submit
acmeserver="$srcdir"/../047-acme/acmeserver.py
timeout=300

. "$srcdir"/dns.sh

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
	stop_server
	rm -f "$tmpdir"/port "$tmpdir"/server.log "$tmpdir"/server.seen
	$PYTHON "$acmeserver" --cert ca/server.crt --key ca/server.key \
		--ca ca/root.crt --ca-key ca/root.key \
		--port-file "$tmpdir"/port --log "$tmpdir"/server.log \
		--offer dns-01 --dns-server 127.0.0.1:$PRIMARY "$@" \
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
cleanup() {
	stop_server
	stop_named
}
trap cleanup EXIT

# Run the helper the way the daemon does, and report how it went.
acme() {
	env -i PATH="$PATH" CERTMONGER_ACME_DIR="$tmpdir"/state "$@" > out 2> err
	echo exit: $?
	sed -i -e "s,localhost:[0-9]*,localhost,g" -e "s,:$PRIMARY,:PRIMARY,g" \
		-e "s,:$SECONDARY,:SECONDARY,g" -e "s,:$STALE,:STALE,g" \
		-e "s,$tmpdir,\$tmpdir,g" out
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
log() {
	touch "$tmpdir"/server.seen
	tail -n +$((`wc -l < "$tmpdir"/server.seen` + 1)) "$tmpdir"/server.log
	cp "$tmpdir"/server.log "$tmpdir"/server.seen
}
# How many TXT records the primary serves at these names now.
records() {
	for name in "$@" ; do
		echo "$name: `dns_query $PRIMARY $name | grep -v CNAME | wc -l` record(s)"
	done
}

start_dns

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key
csr ec.key www.example.test "subjectAltName=DNS:www.example.test,DNS:host.example.test"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out wild.key
csr wild.key example.test "subjectAltName=DNS:*.example.test,DNS:example.test"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out locked.key
csr locked.key www.locked.test "subjectAltName=DNS:www.locked.test"

start_server

echo "[dns-01 offered, no DNS configuration]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt
cat out
log | grep -v -e "^GET /directory" -e new-account

echo "[DNS options without a key]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt --dns-update-server 127.0.0.1
cat out

echo "[enroll, two names, a secondary server]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS
matches ec.key out
log | grep -v -e "^GET /directory" -e new-account
records _acme-challenge.www.example.test _acme-challenge.host.example.test
grep -c "updating zone 'example.test/IN': adding an RR" dns/primary/named.log
grep -c "updating zone 'example.test/IN': deleting an RR" dns/primary/named.log
grep -q "transfer of 'example.test/IN' from 127.0.0.1#$PRIMARY: Transfer completed" \
	dns/secondary/named.log && echo "the secondary got the changes by zone transfer"

echo "[enroll, wildcard]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat wild.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS
matches wild.key out
openssl x509 -in out -noout -ext subjectAltName | tail -n 1
log | grep -v -e "^GET /directory"
records _acme-challenge.example.test

echo "[enroll, the challenge's name is an alias in another zone]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat locked.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS
matches locked.key out
log | grep "dns-01"
records www.challenges.test
grep -c "updating zone 'challenges.test/IN': adding an RR" dns/primary/named.log

echo "[enroll, zone given, key in nsupdate's form]"
echo hmac-sha256:acme-key:$TSIG_SECRET > "$tmpdir"/acme.key.y
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --dns-zone example.test \
	--tsig-key-file "$tmpdir"/acme.key.y
matches ec.key out
log | grep "dns-01"
grep -c $TSIG_SECRET err

echo "[the zone given isn't the name's]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --dns-zone challenges.test
cat out

echo "[bad TSIG key]"
printf "key \"acme-key\" {\n\talgorithm hmac-sha256;\n\tsecret \"%s\";\n};\n" \
	$OTHER_SECRET > "$tmpdir"/bad.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --tsig-key-file "$tmpdir"/bad.key
cat out
log | grep -c "/chall/"

echo "[unknown TSIG key]"
echo hmac-sha256:unknown-key:$TSIG_SECRET > "$tmpdir"/unknown.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --tsig-key-file "$tmpdir"/unknown.key
cat out

echo "[TSIG key which may not update the zone]"
echo other-key:$OTHER_SECRET > "$tmpdir"/other.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --tsig-key-file "$tmpdir"/other.key
cat out

echo "[unsupported TSIG algorithm]"
echo hmac-md5:acme-key:$TSIG_SECRET > "$tmpdir"/md5.key
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --tsig-key-file "$tmpdir"/md5.key
cat out
log > /dev/null

echo "[a server which doesn't get the record in time]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --dns-wait 3 \
	--dns-check-servers 127.0.0.1:$PRIMARY,127.0.0.1:$STALE
cat out
log | grep -c "/chall/"
records _acme-challenge.www.example.test

echo "[the server refuses the record]"
start_server --dns-fail
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat ec.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS
cat out
log | grep -v -e "^GET /directory" -e new-account
records _acme-challenge.www.example.test _acme-challenge.host.example.test

# Now through the daemon.
start_server
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
run "$builddir"/../src/getcert add-acme-ca -c ACME -u $url -R "$tmpdir"/ca/root.crt \
	--tsig-key-file "$tmpdir"/acme.key --dns-resolver 127.0.0.1:$PRIMARY \
	--dns-update-server 127.0.0.1:$PRIMARY --dns-zone example.test \
	--dns-check-servers 127.0.0.1:$PRIMARY,127.0.0.1:$SECONDARY --dns-wait 30
sed -n -e 's,localhost:[0-9]*,localhost,' -e "s,$tmpdir,\$tmpdir,g" \
	-e "s,:$PRIMARY,:PRIMARY,g" -e "s,:$SECONDARY,:SECONDARY,g" \
	-e 's,^ca_external_helper=.*/acme-submit,ca_external_helper=acme-submit,p' "$tmpdir"/cas/*
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*

echo "[getcert request]"
run "$builddir"/../src/getcert request -c ACME -I files -w --wait-timeout=$timeout \
	-G EC -g 256 -N CN=www.example.test -D www.example.test \
	-k "$tmpdir"/files/key -f "$tmpdir"/files/cert > /dev/null
status files
matches files/key files/cert
log | grep "dns-01"
records _acme-challenge.www.example.test

echo OK
