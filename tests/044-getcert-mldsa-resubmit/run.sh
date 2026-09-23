#!/bin/bash -e
#
# End-to-end: getcert resubmit must renew an ML-DSA certificate without
# regenerating the key. Covers both create styles:
#   -G ML-DSA-65
#   -G ML-DSA -g 65  (parameter-set ID mapped to EVP_PKEY_bits()-style size)

cd "$tmpdir"
mkdir "$tmpdir"/cas "$tmpdir"/requests "$tmpdir"/local "$tmpdir"/files
timeout=120

cat > "$tmpdir"/cas/local << EOF
id=local
ca_type=EXTERNAL
ca_external_helper="$builddir"/../src/local-submit -d "$tmpdir"/local
EOF

run() {
	env CERTMONGER_CONFIG_DIR="$tmpdir" CERTMONGER_TMPDIR="$tmpdir" \
	CERTMONGER_REQUESTS_DIR="$tmpdir"/requests \
	CERTMONGER_CAS_DIR="$tmpdir"/cas \
	"$builddir"/../src/certmonger-session -L -P "$tmpdir/certmonger.sock" -n -c "$*"
}

mldsa_from_cert() {
	openssl x509 -in "$1" -noout -text 2>/dev/null \
		| grep Public-Key \
		| grep -o 'ML-DSA-[0-9]*' \
		| head -1
}

pubkey_sha() {
	openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl sha256
}

check_resubmit_preserves_key() {
	local label="$1"
	shift
	local req_opts=("$@")
	local cert="$tmpdir"/files/cert."$label".pem
	local key="$tmpdir"/files/key."$label".pem
	local before_pub after_pub alg

	rm -f "$cert" "$key"
	run "$builddir"/../src/getcert request -c local -I "mldsa-$label" \
		-w --wait-timeout=$timeout \
		-N "cn=MldsaResubmit-$label" \
		"${req_opts[@]}" \
		-f "$cert" -k "$key" > /dev/null

	alg=$(mldsa_from_cert "$cert")
	if test "$alg" != "ML-DSA-65"; then
		echo "FAIL ($label initial): expected ML-DSA-65, got '$alg'" >&2
		exit 1
	fi
	echo "OK ($label initial): $alg"

	before_pub=$(pubkey_sha "$cert")
	cp "$key" "$tmpdir"/files/key."$label".before
	cp "$cert" "$tmpdir"/files/cert."$label".before

	run "$builddir"/../src/getcert resubmit -c local \
		-w --wait-timeout=$timeout \
		-f "$cert" > /dev/null

	alg=$(mldsa_from_cert "$cert")
	after_pub=$(pubkey_sha "$cert")
	if test "$alg" != "ML-DSA-65"; then
		echo "FAIL ($label after resubmit): expected ML-DSA-65, got '$alg'" >&2
		exit 1
	fi
	if test "$before_pub" != "$after_pub"; then
		echo "FAIL ($label after resubmit): public key changed" >&2
		exit 1
	fi
	if ! cmp -s "$key" "$tmpdir"/files/key."$label".before; then
		echo "FAIL ($label after resubmit): key file changed" >&2
		exit 1
	fi
	if cmp -s "$cert" "$tmpdir"/files/cert."$label".before; then
		echo "FAIL ($label after resubmit): certificate was not renewed" >&2
		exit 1
	fi
	echo "OK ($label after resubmit): key preserved, cert renewed"

	run "$builddir"/../src/getcert stop-tracking -i "mldsa-$label" > /dev/null || true
}

check_resubmit_preserves_key "G-only" -G ML-DSA-65
check_resubmit_preserves_key "G-and-g" -G ML-DSA -g 65

echo Test complete.
