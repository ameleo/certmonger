# Name servers for the dns-01 tests, using BIND's named on unprivileged
# ports of the loopback interface:
#   primary: example.test, challenges.test and locked.test, which accept
#            updates of TXT records signed with acme-key, except locked.test,
#            whose _acme-challenge.www is an alias for www.challenges.test;
#   secondary: a copy of them, which the primary notifies of changes;
#   stale: a copy of example.test which is never updated.
# Sourced by the tests, with $tmpdir and $PYTHON set.

NAMED=${NAMED:-`PATH=$PATH:/usr/sbin:/sbin command -v named`}
TSIG_SECRET=c2VjcmV0LXRzaWcta2V5LWZvci10ZXN0aW5nLTEyMzQ1Njc=
OTHER_SECRET=b3RoZXIta2V5LXdoaWNoLWlzLW5vdC1hbGxvd2VkLTEyMzQ=

free_port() {
	$PYTHON -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])'
}

dns_query() {
	$PYTHON "$acmeserver" --dns-query 127.0.0.1:$1 "$2"
}

zone_file() {
	cat > "$1" <<- EOZ
	\$TTL 300
	@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 60
	@ IN NS ns1.example.test.
	@ IN NS ns2.example.test.
	EOZ
}

named_conf() { # dir port extra-options zones
	mkdir -p "$1"
	cat > "$1"/named.conf <<- EOC
	options {
		directory "$1";
		pid-file "$1/named.pid";
		session-keyfile "$1/session.key";
		listen-on port $2 { 127.0.0.1; };
		listen-on-v6 { none; };
		recursion no;
		dnssec-validation no;
		$3
	};
	controls { };
	logging {
		channel log { file "$1/named.log"; severity info; print-time yes; };
		category default { log; };
		category update { log; };
		category update-security { log; };
		category xfer-in { log; };
		category notify { log; };
	};
	key "acme-key" { algorithm hmac-sha256; secret "$TSIG_SECRET"; };
	key "other-key" { algorithm hmac-sha256; secret "$OTHER_SECRET"; };
	$4
	EOC
}

start_named() { # dir
	if ! "$NAMED" -c "$1"/named.conf -n 1 -4 > "$1"/named.out 2>&1 ; then
		named-checkconf "$1"/named.conf
	fi
	for i in `seq 100` ; do
		test -s "$1"/named.pid && return 0
		sleep 0.1
	done
	echo "named did not start in $1:"
	cat "$1"/named.out "$1"/named.log
	exit 1
}

stop_named() {
	for d in "$tmpdir"/dns/* ; do
		if test -s "$d"/named.pid ; then
			kill `cat "$d"/named.pid` 2> /dev/null
			rm -f "$d"/named.pid
		fi
	done
}

start_dns() {
	PRIMARY=`free_port`
	SECONDARY=`free_port`
	STALE=`free_port`
	d="$tmpdir"/dns
	mkdir -p $d/primary $d/secondary $d/stale
	zone_file $d/primary/example.test.zone
	cat >> $d/primary/example.test.zone <<- EOZ
	ns1 IN A 127.0.0.1
	ns2 IN A 127.0.0.1
	www IN A 192.0.2.10
	host IN A 192.0.2.11
	EOZ
	zone_file $d/primary/challenges.test.zone
	zone_file $d/primary/locked.test.zone
	cat >> $d/primary/locked.test.zone <<- EOZ
	www IN A 192.0.2.20
	_acme-challenge.www IN CNAME www.challenges.test.
	EOZ
	cp $d/primary/example.test.zone $d/stale/example.test.zone
	policy='update-policy { grant acme-key zonesub TXT; };'
	named_conf $d/primary $PRIMARY \
		"notify explicit; also-notify { 127.0.0.1 port $SECONDARY; }; allow-transfer { 127.0.0.1; };" \
		"zone \"example.test\" { type primary; file \"example.test.zone\"; $policy };
		zone \"challenges.test\" { type primary; file \"challenges.test.zone\"; $policy };
		zone \"locked.test\" { type primary; file \"locked.test.zone\"; };"
	secondary=""
	for zone in example.test challenges.test locked.test ; do
		secondary="$secondary zone \"$zone\" { type secondary; file \"$zone.bk\"; primaries { 127.0.0.1 port $PRIMARY; }; };"
	done
	named_conf $d/secondary $SECONDARY "notify no;" "$secondary"
	named_conf $d/stale $STALE "notify no;" \
		"zone \"example.test\" { type primary; file \"example.test.zone\"; };"
	start_named $d/primary
	start_named $d/secondary
	start_named $d/stale
	# Wait for the secondary's first transfers.
	for i in `seq 100` ; do
		test -s $d/secondary/example.test.bk -a \
		     -s $d/secondary/challenges.test.bk -a \
		     -s $d/secondary/locked.test.bk && break
		sleep 0.1
	done
	printf "key \"acme-key\" {\n\talgorithm hmac-sha256;\n\tsecret \"%s\";\n};\n" \
		$TSIG_SECRET > "$tmpdir"/acme.key
	# The options which the helper is given.
	DNS="--tsig-key-file $tmpdir/acme.key --dns-resolver 127.0.0.1:$PRIMARY
		--dns-update-server 127.0.0.1:$PRIMARY
		--dns-check-servers 127.0.0.1:$PRIMARY,127.0.0.1:$SECONDARY"
}
