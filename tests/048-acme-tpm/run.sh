#!/bin/bash
#
# ACME enrollment with device attestation: the daemon generates the key in a
# software TPM through tpm2-pkcs11, and acme-submit proves it with a TPM
# attestation in answer to a device-attest-01 challenge.

srcdir=$PWD
cd "$tmpdir"

PYTHON=${PYTHON:-python3}
ACME="$builddir"/../src/acme-submit
timeout=300
KID=device-kid
KEY=ZGV2aWNlLW1hYy1rZXktZm9yLXRlc3Rpbmc

T="$tmpdir"/tpm
mkdir -p "$T"/state "$T"/localca "$T"/store "$tmpdir"/db

# A software TPM with EK certificates issued by a CA of our own.
cat > "$T"/swtpm_setup.conf <<- EOF
	create_certs_tool = `command -v swtpm_localca`
	create_certs_tool_config = $T/swtpm-localca.conf
	create_certs_tool_options = $T/swtpm-localca.options
	active_pcr_banks = sha256
EOF
cat > "$T"/swtpm-localca.conf <<- EOF
	statedir = $T/localca
	signingkey = $T/localca/signkey.pem
	issuercert = $T/localca/issuercert.pem
	certserial = $T/localca/certserial
EOF
cat > "$T"/swtpm-localca.options <<- EOF
	--platform-manufacturer certmonger
	--platform-version 1.0
	--platform-model test
EOF
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
# A resource manager of our own, on the session bus.
bus_name=com.intel.tss2.Tabrmd.certmonger$$
test `id -u` -eq 0 && allow_root=--allow-root
tpm2-abrmd --session --dbus-name=$bus_name --tcti=swtpm:path="$T"/sock $allow_root \
	> "$T"/abrmd.log 2>&1 &
abrmd=$!
export TPM2TOOLS_TCTI=tabrmd:bus_name=$bus_name,bus_type=session
export TPM2_PKCS11_TCTI=$TPM2TOOLS_TCTI
export TPM2_PKCS11_STORE="$T"/store
export TPM2_PKCS11_BACKEND=esysdb
export TPM2_PKCS11_LOG_LEVEL=0
for i in `seq 50` ; do tpm2_getcap properties-fixed > /dev/null 2>&1 && break ; sleep 0.1 ; done

# A tpm2-pkcs11 token, which an NSS database knows about.
tpm2_ptool init --path "$T"/store > /dev/null
tpm2_ptool addtoken --pid=1 --label=certmonger --userpin=123456 \
	--sopin=654321 --path "$T"/store > /dev/null
echo 123456 > "$tmpdir"/pin
certutil -N -d "$tmpdir"/db --empty-password
for module in /usr/lib64/pkcs11/libtpm2_pkcs11.so \
	      /usr/lib/*/pkcs11/libtpm2_pkcs11.so \
	      /usr/lib/pkcs11/libtpm2_pkcs11.so ; do
	test -e $module && break
done
echo | modutil -dbdir "$tmpdir"/db -add tpm2 -force -libfile $module \
	> /dev/null 2>&1

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
	# Point the CA configuration at the new server.
	if ls "$tmpdir"/cas/* > /dev/null 2>&1 ; then
		sed -i -e "s,https://localhost:[0-9]*/,https://localhost:`cat "$tmpdir"/port`/," "$tmpdir"/cas/*
	fi
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
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}
status() {
	run "$builddir"/../src/getcert list -i "$1" | grep -E "status:|ca-error:" | sed -e 's,localhost:[0-9]*,localhost,'
}
cert() {
	certutil -L -d "$tmpdir"/db -h certmonger -f "$tmpdir"/pin \
		-n certmonger:device -a 2> /dev/null > "$1"
}
attested() {
	if openssl x509 -in "$1" -noout -ext certificatePolicies 2> /dev/null |
	   grep -q 1.3.6.1.4.1.99999.1.1 ; then
		echo "certificate is attested"
	else
		echo "certificate is NOT attested"
	fi
}
# The certificate is for a key in the TPM token.
in_token() {
	if certutil -K -d "$tmpdir"/db -h certmonger -f "$tmpdir"/pin \
	   2> /dev/null | grep -q "certmonger:device" ; then
		echo "key is in the TPM token"
	else
		echo "key is NOT in the TPM token"
	fi
}
transient() {
	echo "TPM objects left: `tpm2_getcap handles-transient | wc -l`"
}

# The test server takes "sig" only as WebAuthn defines it, a TPMT_SIGNATURE,
# and refuses anything else, so that the enrollments below show what the
# helper sends.
echo "[the test server's check of the attestation signature]"
$PYTHON "$srcdir"/../047-acme/acmeserver.py --self-test

start_server

echo "[getcert add-acme-ca]"
run "$builddir"/../src/getcert add-acme-ca -c TPM -u $url \
	-R "$tmpdir"/ca/root.crt --attest tpm
sed -n -e 's,localhost:[0-9]*,localhost,' -e "s,$tmpdir,\$tmpdir,g" -e 's,^ca_external_helper=.*/acme-submit,ca_external_helper=acme-submit,p' "$tmpdir"/cas/*
sed -i -e "s,^ca_external_helper=[^ ]*acme-submit ,ca_external_helper=$ACME ," "$tmpdir"/cas/*

echo "[getcert request, RSA key generated in the TPM]"
run "$builddir"/../src/getcert request -c TPM -I tpm -w --wait-timeout=$timeout \
	-d "$tmpdir"/db -t certmonger -n device -p "$tmpdir"/pin \
	-G RSA -g 2048 -N CN=device42 -L $KID:$KEY > /dev/null
status tpm
cert first.pem
in_token
attested first.pem
openssl x509 -in first.pem -noout -subject
log | grep -E "^POST /(new|attest|chall)|^  "
ls "$tmpdir"/state/*/ | sort
transient

echo "[getcert resubmit: the attestation key's certificate is reused]"
run "$builddir"/../src/getcert resubmit -i tpm -w --wait-timeout=$timeout > /dev/null
status tpm
cert second.pem
cmp -s first.pem second.pem && echo ERROR: certificate was not replaced
attested second.pem
test "`openssl x509 -in first.pem -noout -pubkey`" = \
     "`openssl x509 -in second.pem -noout -pubkey`" && echo "same key"
log | grep -E "^POST /(new|attest|chall)|^  "
transient

echo "[getcert rekey: a new key in the TPM]"
run "$builddir"/../src/getcert rekey -i tpm -w --wait-timeout=$timeout > /dev/null
status tpm
cert third.pem
attested third.pem
in_token
test "`openssl x509 -in second.pem -noout -pubkey`" = \
     "`openssl x509 -in third.pem -noout -pubkey`" && echo "ERROR: same key"
log | grep -E "^POST /(new|attest|chall)|^  "
transient

# A server elsewhere, so a new account, and a new attestation key whose
# certificate expires soon, and is renewed the next time.
echo "[the attestation key's certificate is renewed when it expires soon]"
start_server --ak-days 10
run "$builddir"/../src/getcert resubmit -i tpm -w --wait-timeout=$timeout > /dev/null
status tpm
log | grep -E "^POST /(attest|chall)|^  attestation"
run "$builddir"/../src/getcert resubmit -i tpm -w --wait-timeout=$timeout > /dev/null
status tpm
log | grep -E "^POST /(attest|chall)|^  attestation"

echo "[the server doesn't know the device]"
start_server --device-id device43
run "$builddir"/../src/getcert resubmit -i tpm -w --wait-timeout=$timeout > /dev/null
status tpm

echo OK
