#!/bin/bash
#
# ACME enrollment with acme-submit, answering dns-01 challenges with DNS
# updates signed with GSS-TSIG, using a host's keytab, with a KDC and
# BIND's named which accepts updates from hosts for names under their own
# (krb5-selfsub).

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
ACME="$builddir"/../src/acme-submit
acmeserver="$srcdir"/../047-acme/acmeserver.py
PATH=$PATH:/usr/sbin:/sbin

. "$srcdir"/../049-acme-dns/dns.sh

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

# A KDC for EXAMPLE.TEST, with the principals of the DNS server and of two
# hosts.
KDC=`free_port`
K="$tmpdir"/krb5
mkdir -p "$K"
cat > "$K"/krb5.conf << EOF2
[libdefaults]
	default_realm = EXAMPLE.TEST
	dns_lookup_kdc = false
	dns_lookup_realm = false
	rdns = false
	dns_canonicalize_hostname = false
[realms]
	EXAMPLE.TEST = {
		kdc = 127.0.0.1:$KDC
	}
[domain_realm]
	.example.test = EXAMPLE.TEST
	example.test = EXAMPLE.TEST
EOF2
cat > "$K"/kdc.conf << EOF2
[kdcdefaults]
	kdc_ports = $KDC
	kdc_tcp_ports = $KDC
[realms]
	EXAMPLE.TEST = {
		database_name = $K/principal
		key_stash_file = $K/stash
		acl_file = $K/kadm5.acl
	}
[logging]
	kdc = FILE:$K/kdc.log
EOF2
export KRB5_CONFIG="$K"/krb5.conf KRB5_KDC_PROFILE="$K"/kdc.conf
kdb5_util create -s -r EXAMPLE.TEST -P master-password > "$K"/setup.log 2>&1
for p in DNS/ns1.example.test host/client.example.test host/other.example.test ; do
	kadmin.local -r EXAMPLE.TEST -q "addprinc -randkey $p" >> "$K"/setup.log 2>&1
done
kadmin.local -r EXAMPLE.TEST -q "ktadd -k $K/dns.keytab DNS/ns1.example.test" >> "$K"/setup.log 2>&1
kadmin.local -r EXAMPLE.TEST -q "ktadd -k $K/client.keytab host/client.example.test" >> "$K"/setup.log 2>&1
kadmin.local -r EXAMPLE.TEST -q "ktadd -k $K/other.keytab host/other.example.test" >> "$K"/setup.log 2>&1
krb5kdc -n -P "$K"/kdc.pid > "$K"/kdc.out 2>&1 &
kdc_pid=$!

# The DNS server.
PRIMARY=`free_port`
d="$tmpdir"/dns
mkdir -p $d/primary
zone_file $d/primary/example.test.zone
cat >> $d/primary/example.test.zone << EOF2
ns1 IN A 127.0.0.1
ns2 IN A 127.0.0.1
client IN A 192.0.2.30
EOF2
named_conf $d/primary $PRIMARY "notify no; tkey-gssapi-keytab \"$K/dns.keytab\";" \
	"zone \"example.test\" { type primary; file \"example.test.zone\";
		update-policy { grant EXAMPLE.TEST krb5-selfsub . TXT; }; };"
start_named $d/primary

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
	kill $kdc_pid 2> /dev/null
}
trap cleanup EXIT

acme() {
	env -i PATH="$PATH" CERTMONGER_ACME_DIR="$tmpdir"/state \
		KRB5_CONFIG="$KRB5_CONFIG" "$@" > out 2> err
	echo exit: $?
	sed -i -e "s,localhost:[0-9]*,localhost,g" -e "s,:$PRIMARY,:PRIMARY,g" \
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
records() {
	for name in "$@" ; do
		echo "$name: `dns_query $PRIMARY $name | grep -v CNAME | wc -l` record(s)"
	done
}

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client.key
csr client.key client.example.test "subjectAltName=DNS:client.example.test"

start_server
DNS="--gss-tsig --dns-resolver 127.0.0.1:$PRIMARY
	--dns-update-server ns1.example.test:$PRIMARY
	--dns-check-servers 127.0.0.1:$PRIMARY"

echo "[enroll, GSS-TSIG, the keytab's principal]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat client.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --keytab "$K"/client.keytab
matches client.key out
log | grep "dns-01"
records _acme-challenge.client.example.test
grep -o 'key host/client.example.test\\@EXAMPLE.TEST: updating zone .example.test/IN.: [a-z]* an RR' \
	dns/primary/named.log

echo "[enroll, GSS-TSIG, principal given]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat client.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --keytab "$K"/client.keytab \
	--principal host/client.example.test@EXAMPLE.TEST
matches client.key out
log | grep "dns-01"

echo "[another host may not update the name]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat client.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --keytab "$K"/other.keytab
cat out
records _acme-challenge.client.example.test

echo "[a principal which isn't in the keytab]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat client.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --keytab "$K"/client.keytab \
	--principal host/other.example.test@EXAMPLE.TEST
sed -e 's,: .*\.$,: ...,' out

echo "[the DNS server given by its address]"
acme CERTMONGER_OPERATION=SUBMIT CERTMONGER_CSR="`cat client.key.csr`" \
	"$ACME" -u $url -R ca/root.crt $DNS --keytab "$K"/client.keytab \
	--dns-update-server 127.0.0.1:$PRIMARY
cat out

echo OK
