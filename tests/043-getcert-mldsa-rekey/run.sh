#!/bin/bash -e
#
# End-to-end: getcert rekey across ML-DSA parameter sets (65 -> 87).
# Exercises request.modify(KEY_TYPE) + restart/keyiread + request.rekey
# via the real getcert / certmonger-session D-Bus path.

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

cert="$tmpdir"/files/cert.pem
key="$tmpdir"/files/key.pem

run "$builddir"/../src/getcert request -c local -I mldsa \
	-w --wait-timeout=$timeout \
	-N cn=MldsaRekey \
	-G ML-DSA-65 \
	-f "$cert" -k "$key" > /dev/null

alg=$(mldsa_from_cert "$cert")
if test "$alg" != "ML-DSA-65"; then
	echo "FAIL (initial): expected ML-DSA-65, got '$alg'" >&2
	exit 1
fi
echo "OK (initial): $alg"

cp "$key" "$tmpdir"/files/key.before
run "$builddir"/../src/getcert rekey -c local \
	-w --wait-timeout=$timeout \
	-G ML-DSA-87 \
	-f "$cert" > /dev/null

alg=$(mldsa_from_cert "$cert")
if test "$alg" != "ML-DSA-87"; then
	echo "FAIL (after rekey): expected ML-DSA-87, got '$alg'" >&2
	exit 1
fi
if cmp -s "$key" "$tmpdir"/files/key.before; then
	echo "FAIL (after rekey): key file was not replaced" >&2
	exit 1
fi
echo "OK (after rekey): $alg"

echo Test complete.
