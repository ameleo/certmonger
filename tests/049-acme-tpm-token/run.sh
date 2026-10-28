#!/bin/bash
#
# ACME enrollment with device attestation, for a request which doesn't say
# where to keep its key: the daemon sets up a TPM token of its own, with no
# PIN, generates the key there, and keeps the certificate there too.

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

# A software TPM with EK certificates issued by a CA of our own.
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
# A resource manager of our own, on the session bus.  The daemon reaches the
# TPM through it, as TPM2_PKCS11_TCTI says, and chooses the token's store.
bus_name=com.intel.tss2.Tabrmd.certmonger$$
test `id -u` -eq 0 && allow_root=--allow-root
tpm2-abrmd --session --dbus-name=$bus_name --tcti=swtpm:path="$T"/sock $allow_root \
	> "$T"/abrmd.log 2>&1 &
abrmd=$!
export TPM2TOOLS_TCTI=tabrmd:bus_name=$bus_name,bus_type=session
export TPM2_PKCS11_TCTI=$TPM2TOOLS_TCTI
export TPM2_PKCS11_LOG_LEVEL=0
unset TPM2_PKCS11_STORE TPM2_PKCS11_BACKEND
for i in `seq 50` ; do tpm2_getcap properties-fixed > /dev/null 2>&1 && break ; sleep 0.1 ; done

# The CA's certificates.
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

start_server() {
	stop_server
	rm -f "$tmpdir"/port "$tmpdir"/server.log "$tmpdir"/server.seen
	$PYTHON "$srcdir"/../047-acme/acmeserver.py --cert ca/server.crt \
		--key ca/server.key --ca ca/root.crt --ca-key ca/root.key \
		--port-file "$tmpdir"/port --log "$tmpdir"/server.log \
		--eab-kid $KID --eab-key $KEY --attest --device-id device42 \
		--ek-ca "$T"/localca/issuercert.pem "$@" \
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
log() {
	touch "$tmpdir"/server.seen
	tail -n +$((`wc -l < "$tmpdir"/server.seen` + 1)) "$tmpdir"/server.log
	cp "$tmpdir"/server.log "$tmpdir"/server.seen
}

mkdir -p "$tmpdir"/cas "$tmpdir"/requests
run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	CERTMONGER_ACME_DIR="$tmpdir"/state \
	CERTMONGER_TPM_DIR="$TOKEN" \
	CERTMONGER_TPM_SYSTEM_STORE="$tmpdir"/no-system-store \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}
status() {
	run "$builddir"/../src/getcert list -i "$1" | grep -E "status:|ca-error:|key pair storage:|certificate:" |
		sed -e 's,localhost:[0-9]*,localhost,' -e "s,$tmpdir,\$tmpdir,g"
}
# What the token holds, seen as the daemon sees it: through its NSS
# database, with the empty PIN.
token() {
	TPM2_PKCS11_STORE="$TOKEN" TPM2_PKCS11_BACKEND=esysdb "$@"
}
echo > "$tmpdir"/empty-pin
cert() {
	token certutil -L -d "$TOKEN" -h certmonger -f "$tmpdir"/empty-pin \
		-n certmonger:device -a 2> /dev/null > "$1"
}
in_token() {
	if token certutil -K -d "$TOKEN" -h certmonger -f "$tmpdir"/empty-pin \
	   2> /dev/null | grep -q "certmonger:device" ; then
		echo "key is in the TPM token"
	else
		echo "key is NOT in the TPM token"
	fi
}
attested() {
	if openssl x509 -in "$1" -noout -ext certificatePolicies 2> /dev/null |
	   grep -q 1.3.6.1.4.1.99999.1.1 ; then
		echo "certificate is attested"
	else
		echo "certificate is NOT attested"
	fi
}
transient() {
	echo "TPM objects left: `tpm2_getcap handles-transient | wc -l`"
}
# The objects of the token, by class, its account keys left aside: a request
# has one key pair and one certificate, whatever its renewals and rekeys.
objects() {
	token tpm2_ptool listobjects --label=certmonger --path "$TOKEN" 2> /dev/null |
		awk '/CKA_CLASS:/ {class = $NF} /CKA_LABEL:/ {print class, $NF}' |
		grep -v ' acme-account-' | awk '{print $1}' | sort | uniq -c |
		awk '{printf "%s %s\n", $2, $1}'
}
# The ACME account key: in the token of our own keys, where there is a TPM,
# never a file nor in the device's token; the token lists its two halves.
account_key() {
	echo "account key files: `ls "$tmpdir"/state/*/account.key 2> /dev/null | wc -l`"
	echo "account keys in the device token: `token tpm2_ptool listobjects --label=certmonger --path "$TOKEN" 2> /dev/null | grep -c 'CKA_LABEL: acme-account-'`"
	echo "account keys in the token of our own keys: `token tpm2_ptool listobjects --label=certmonger-acme --path "$TOKEN" 2> /dev/null | grep -c 'CKA_LABEL: acme-account-'`"
}

start_server

echo "[getcert add-acme-ca]"
run "$builddir"/../src/getcert add-acme-ca -c TPM -u $url \
	-R "$tmpdir"/ca/root.crt --attest tpm
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*

echo "[getcert request, nothing said of the key's storage]"
run "$builddir"/../src/getcert request -c TPM -I device -w --wait-timeout=$timeout \
	-N CN=device42 -L $KID:$KEY > /dev/null
status device
cert first.pem
in_token
attested first.pem
openssl x509 -in first.pem -noout -subject
log | grep -E "^POST /(new|attest|chall)|^  "
echo "token directory: `stat -c %a "$TOKEN"`"
ls "$TOKEN" | sort
transient
account_key

echo "[getcert resubmit]"
run "$builddir"/../src/getcert resubmit -i device -w --wait-timeout=$timeout > /dev/null
status device
cert second.pem
attested second.pem
test "`openssl x509 -in first.pem -noout -pubkey`" = \
     "`openssl x509 -in second.pem -noout -pubkey`" && echo "same key"

echo "[getcert rekey: a new key in the token]"
run "$builddir"/../src/getcert rekey -i device -w --wait-timeout=$timeout > /dev/null
status device
cert third.pem
attested third.pem
in_token
test "`openssl x509 -in second.pem -noout -pubkey`" = \
     "`openssl x509 -in third.pem -noout -pubkey`" && echo "ERROR: same key"
transient
objects

echo "[a second request: the same token]"
run "$builddir"/../src/getcert request -c TPM -I other -w --wait-timeout=$timeout \
	-N CN=device42 -L $KID:$KEY > /dev/null
status other

account_key

echo "[a CA without attestation, on a machine with a TPM: its keys go to the token too]"
run "$builddir"/../src/getcert add-acme-ca -c PLAIN -u $url \
	-R "$tmpdir"/ca/root.crt
run "$builddir"/../src/getcert request -c PLAIN -I plain -N CN=device42 | head -n 1
run "$builddir"/../src/getcert list -i plain | grep -E "key pair storage:" |
	sed -e "s,$tmpdir,\$tmpdir,g"

echo "[a CA which attests: no key in files]"
run "$builddir"/../src/getcert request -c TPM -I file -N CN=device42 \
	-k "$tmpdir"/file.key -f "$tmpdir"/file.crt | head -n 1

echo OK
