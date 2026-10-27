#!/bin/bash
#
# A request for a CA which attests with the TPM, on a system set up as
# Fedora is: the tpm2-pkcs11 package makes the module known to p11-kit, so
# that every user of NSS loads it, and there is no store where it looks by
# default.  The daemon starts with nothing in its environment, as systemd
# starts it, but how to reach the TPM.  Neither it nor getcert should make
# the module complain, and the key still ends up in the daemon's token.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
ACME="$builddir"/../src/acme-submit
timeout=120
KID=device-kid
KEY=ZGV2aWNlLW1hYy1rZXktZm9yLXRlc3Rpbmc

T="$tmpdir"/tpm
TOKEN="$tmpdir"/token
mkdir -p "$T"/state "$T"/localca

cat > "$T"/swtpm_setup.conf <<- EOF2
	create_certs_tool = `command -v swtpm_localca`
	create_certs_tool_config = $T/swtpm-localca.conf
	create_certs_tool_options = $T/swtpm-localca.options
	active_pcr_banks = sha256
EOF2
cat > "$T"/swtpm-localca.conf <<- EOF2
	statedir = $T/localca
	signingkey = $T/localca/signkey.pem
	issuercert = $T/localca/issuercert.pem
	certserial = $T/localca/certserial
EOF2
cat > "$T"/swtpm-localca.options <<- EOF2
	--platform-manufacturer certmonger
	--platform-version 1.0
	--platform-model test
EOF2
swtpm_setup --tpm2 --tpmstate "$T"/state --config "$T"/swtpm_setup.conf \
	--create-ek-cert --overwrite > "$T"/setup.log 2>&1 ||
	{ echo swtpm_setup failed; cat "$T"/setup.log; exit 1; }

swtpm=
abrmd=
pid=
cleanup() {
	stop_server
	test -n "$abrmd" && kill $abrmd 2> /dev/null
	test -n "$swtpm" && kill $swtpm 2> /dev/null
	wait 2> /dev/null
}
trap cleanup EXIT
swtpm socket --tpm2 --tpmstate dir="$T"/state \
	--server type=unixio,path="$T"/sock --ctrl type=unixio,path="$T"/sock.ctrl \
	--flags not-need-init,startup-clear > "$T"/swtpm.log 2>&1 &
swtpm=$!
for i in `seq 50` ; do test -S "$T"/sock.ctrl && break ; sleep 0.1 ; done
bus_name=com.intel.tss2.Tabrmd.certmonger$$
test `id -u` -eq 0 && allow_root=--allow-root
tpm2-abrmd --session --dbus-name=$bus_name --tcti=swtpm:path="$T"/sock $allow_root \
	> "$T"/abrmd.log 2>&1 &
abrmd=$!
tcti=tabrmd:bus_name=$bus_name,bus_type=session
for i in `seq 50` ; do
	TPM2TOOLS_TCTI=$tcti tpm2_getcap properties-fixed > /dev/null 2>&1 && break
	sleep 0.1
done

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

stop_server() {
	if test -n "$pid" ; then
		kill $pid 2> /dev/null
		wait $pid 2> /dev/null
		pid=
	fi
}
rm -f "$tmpdir"/port
$PYTHON "$srcdir"/../047-acme/acmeserver.py --cert ca/server.crt \
	--key ca/server.key --ca ca/root.crt --ca-key ca/root.key \
	--port-file "$tmpdir"/port --log "$tmpdir"/server.log \
	--eab-kid $KID --eab-key $KEY --attest --device-id device42 \
	--ek-ca "$T"/localca/issuercert.pem > "$tmpdir"/server.out 2>&1 &
pid=$!
for i in `seq 100` ; do test -s "$tmpdir"/port && break ; sleep 0.1 ; done
url=https://localhost:`cat "$tmpdir"/port`/directory

# The daemon, with nothing in its environment but where we keep things for
# the test, how to reach the TPM, and the bus the resource manager is on;
# what it runs is the getcert command, as a user would run it, without what
# the daemon put in its own environment.
mkdir -p "$tmpdir"/cas "$tmpdir"/requests
run() {
	env -i PATH="$PATH" HOME="$tmpdir" \
	DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
	TPM2_PKCS11_TCTI=$tcti \
	CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	CERTMONGER_TPM_DIR="$TOKEN" \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n \
	-c "env -u TPM2_PKCS11_STORE -u TPM2_PKCS11_LOG_LEVEL $*"
}
# What the module says when it finds no store, or when it warns about its
# FAPI backend; the TSS libraries' own messages are theirs.
complaints() {
	grep -E "Unhandled search index|pkcs11 store|TPM2_PKCS11_STORE|backend was not initialized|backends could be initialized|Cannot open database|Listing FAPI token objects|tokens from fapi backend|version query" "$1" |
		sed -e 's,^,  ,'
}
quiet() {
	if test -n "`complaints "$1"`" ; then
		echo "$2: the module complained:"
		complaints "$1"
	else
		echo "$2: no complaint from the module"
	fi
}

echo "[getcert add-acme-ca]"
run "$builddir"/../src/getcert add-acme-ca -c TPM -u $url \
	-R "$tmpdir"/ca/root.crt --attest tpm 2> "$tmpdir"/add.err
quiet "$tmpdir"/add.err "daemon and getcert"
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*
echo "token directory: `stat -c %a "$TOKEN"`"

echo "[getcert list-cas]"
run "$builddir"/../src/getcert list-cas -c TPM > /dev/null 2> "$tmpdir"/list-cas.err
quiet "$tmpdir"/list-cas.err "daemon and getcert"

echo "[getcert request, nothing said of the key's storage]"
run "$builddir"/../src/getcert request -c TPM -I device -w --wait-timeout=$timeout \
	-N CN=device42 -L $KID:$KEY > /dev/null 2> "$tmpdir"/request.err
quiet "$tmpdir"/request.err "daemon, getcert and helpers"
run "$builddir"/../src/getcert list -i device 2> /dev/null |
	grep -E "status:|ca-error:|key pair storage:" |
	sed -e "s,$tmpdir,\$tmpdir,g"

echo "[a CA which doesn't exist]"
run "$builddir"/../src/getcert request -c NONE -I none -N CN=device42 2> /dev/null | head -n 1
echo "[a CA without attestation]"
run "$builddir"/../src/getcert add-acme-ca -c PLAIN -u $url \
	-R "$tmpdir"/ca/root.crt 2> /dev/null
run "$builddir"/../src/getcert request -c PLAIN -I plain -N CN=device42 2> /dev/null | head -n 1
echo "[no CA named]"
run "$builddir"/../src/getcert request -I plain -N CN=device42 2> /dev/null | head -n 1

echo OK
