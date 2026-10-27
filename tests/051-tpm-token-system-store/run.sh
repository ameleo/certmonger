#!/bin/bash
#
# A token kept in our own directory, because the module had no system store
# when it was made, moves to the module's system store once there is one, and
# its key keeps working: the certificate is renewed with the same key.  From
# then on, any program which loads the module with that store sees the token
# and can sign with its key.

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

SYS="$tmpdir"/system-store
mkdir -p "$tmpdir"/cas "$tmpdir"/requests
# The daemon, as in 050-tpm-token-quiet; the module's system store is the
# one named by $system, or none.
system="$tmpdir"/no-system-store
run() {
	env -i PATH="$PATH" HOME="$tmpdir" \
	DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
	TPM2_PKCS11_TCTI=$tcti \
	CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	CERTMONGER_TPM_DIR="$TOKEN" \
	CERTMONGER_TPM_SYSTEM_STORE="$system" \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n \
	-c "env -u TPM2_PKCS11_STORE -u TPM2_PKCS11_LOG_LEVEL $*"
}
status() {
	run "$builddir"/../src/getcert list -i device 2> /dev/null |
		grep -E "status:|ca-error:|key pair storage:" |
		sed -e "s,$tmpdir,\$tmpdir,g"
}
# The public key of the certificate in the token, seen through the NSS
# database with the store named.
echo > "$tmpdir"/empty-pin
pubkey() {
	TPM2_PKCS11_STORE="$1" TPM2_PKCS11_BACKEND=esysdb TPM2_PKCS11_TCTI=$tcti \
	certutil -L -d "$TOKEN" -h certmonger -f "$tmpdir"/empty-pin \
		-n certmonger:device -a 2> /dev/null | openssl x509 -noout -pubkey | sha256sum
}
stores() {
	for d in "$TOKEN" "$SYS" ; do
		if test -e "$d"/tpm2_pkcs11.sqlite3 ; then
			echo "  `echo $d | sed -e "s,$tmpdir,\\$tmpdir,"`: store, `stat -c %a "$d"/tpm2_pkcs11.sqlite3`"
		else
			echo "  `echo $d | sed -e "s,$tmpdir,\\$tmpdir,"`: no store"
		fi
	done
}

echo "[no system store: the token's store is ours]"
run "$builddir"/../src/getcert add-acme-ca -c TPM -u $url \
	-R "$tmpdir"/ca/root.crt --attest tpm > /dev/null 2>&1
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*
run "$builddir"/../src/getcert request -c TPM -I device -w --wait-timeout=$timeout \
	-N CN=device42 -L $KID:$KEY > /dev/null 2>&1
status
stores
before=`pubkey "$TOKEN"`

echo "[a system store appears: the token's store moves there]"
mkdir -m 700 "$SYS"
system="$SYS"
run "$builddir"/../src/getcert resubmit -i device -w --wait-timeout=$timeout > /dev/null 2>&1
status
stores
after=`pubkey "$SYS"`
if test "$before" = "$after" ; then
	echo "renewed with the same key"
else
	echo "renewed with another key"
fi

echo "[another program, with the system store]"
TPM2_PKCS11_STORE="$SYS" TPM2_PKCS11_BACKEND=esysdb TPM2_PKCS11_TCTI=$tcti \
	certutil -U -d "$TOKEN" 2> /dev/null | grep -E "token: certmonger" | sed -e 's,^ *,,'
TPM2_PKCS11_STORE="$SYS" TPM2_PKCS11_BACKEND=esysdb TPM2_PKCS11_TCTI=$tcti \
	certutil -R -d "$TOKEN" -h certmonger -f "$tmpdir"/empty-pin \
	-k device -s CN=another-program -a -o "$tmpdir"/another.csr > "$tmpdir"/another.err 2>&1
if openssl req -in "$tmpdir"/another.csr -noout -verify > /dev/null 2>&1 ; then
	echo "signed a request with the token's key"
else
	echo "could not sign with the token's key"
	sed -e "s,^,  ," "$tmpdir"/another.err
fi

echo "[both stores there: ours stays in use]"
cp "$SYS"/tpm2_pkcs11.sqlite3 "$TOKEN"/tpm2_pkcs11.sqlite3
run "$builddir"/../src/getcert list -i device > /dev/null 2> "$tmpdir"/both.err
stores
grep -c "Moved the TPM token" "$tmpdir"/both.err

echo OK
