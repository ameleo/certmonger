#!/bin/bash -e
#
# End-to-end: getcert resubmit must renew an ML-DSA certificate without
# regenerating the key, for every ML-DSA parameter set and both create
# styles:
#   -G ML-DSA-44 / -G ML-DSA-65 / -G ML-DSA-87
#   -G ML-DSA -g 44 / -g 65 / -g 87  (parameter-set ID mapped to the
#                                     EVP_PKEY_bits()-style size)
# An explicitly requested rekey -- either the dedicated "rekey" verb or a
# "resubmit" that changes the key type -- must still replace the key.

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

# create <label> <expect-alg> <request-opts...>
create() {
	local label="$1" expect="$2"
	shift 2
	local cert="$tmpdir"/files/cert."$label".pem
	local key="$tmpdir"/files/key."$label".pem
	local alg

	rm -f "$cert" "$key"
	run "$builddir"/../src/getcert request -c local -I "mldsa-$label" \
		-w --wait-timeout=$timeout \
		-N "cn=MldsaResubmit-$label" \
		"$@" \
		-f "$cert" -k "$key" > /dev/null

	alg=$(mldsa_from_cert "$cert")
	if test "$alg" != "$expect"; then
		echo "FAIL ($label initial): expected $expect, got '$alg'" >&2
		exit 1
	fi
	echo "OK ($label initial): $alg"
}

# resubmit_preserves_key <label> <expect-alg>
#
# A plain resubmit must renew the certificate while leaving the key in
# place.
resubmit_preserves_key() {
	local label="$1" expect="$2"
	local cert="$tmpdir"/files/cert."$label".pem
	local key="$tmpdir"/files/key."$label".pem
	local before_pub after_pub alg

	before_pub=$(pubkey_sha "$cert")
	cp "$key" "$tmpdir"/files/key."$label".before
	cp "$cert" "$tmpdir"/files/cert."$label".before

	run "$builddir"/../src/getcert resubmit -c local \
		-w --wait-timeout=$timeout \
		-f "$cert" > /dev/null

	alg=$(mldsa_from_cert "$cert")
	after_pub=$(pubkey_sha "$cert")
	if test "$alg" != "$expect"; then
		echo "FAIL ($label after resubmit): expected $expect, got '$alg'" >&2
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
}

# explicit_rekey_replaces_key <label> <expect-alg> <rekey-opts...>
#
# An explicitly requested rekey must replace the key.  The caller passes
# the full getcert sub-command and options (e.g. "rekey" or
# "resubmit -G ML-DSA-87").
explicit_rekey_replaces_key() {
	local label="$1" expect="$2"
	shift 2
	local cert="$tmpdir"/files/cert."$label".pem
	local key="$tmpdir"/files/key."$label".pem
	local before_pub after_pub alg

	before_pub=$(pubkey_sha "$cert")
	cp "$key" "$tmpdir"/files/key."$label".before

	run "$builddir"/../src/getcert "$@" -c local \
		-w --wait-timeout=$timeout \
		-f "$cert" > /dev/null

	alg=$(mldsa_from_cert "$cert")
	after_pub=$(pubkey_sha "$cert")
	if test "$alg" != "$expect"; then
		echo "FAIL ($label after rekey): expected $expect, got '$alg'" >&2
		exit 1
	fi
	if test "$before_pub" == "$after_pub"; then
		echo "FAIL ($label after rekey): public key was not replaced" >&2
		exit 1
	fi
	if cmp -s "$key" "$tmpdir"/files/key."$label".before; then
		echo "FAIL ($label after rekey): key file was not replaced" >&2
		exit 1
	fi
	echo "OK ($label after rekey): key replaced to $alg"
}

# expect_rejected <label> <request-opts...>
#
# A size that does not match the chosen ML-DSA parameter set must be
# rejected: getcert prints an "Invalid key size" error and issues no key or
# certificate.  getcert exits nonzero, but certmonger-session -- which the
# harness uses to run it -- does not propagate that status, so assert on the
# message and the absence of output files rather than on the exit status.
expect_rejected() {
	local label="$1"
	shift
	local cert="$tmpdir"/files/cert."$label".pem
	local key="$tmpdir"/files/key."$label".pem
	local out msg

	rm -f "$cert" "$key"
	out=$(run "$builddir"/../src/getcert request -c local -I "mldsa-$label" \
		-w --wait-timeout=$timeout \
		-N "cn=MldsaResubmit-$label" \
		"$@" \
		-f "$cert" -k "$key" 2>&1 || true)

	msg=$(printf '%s\n' "$out" | grep -m1 'Invalid key size')
	if test -z "$msg"; then
		echo "FAIL ($label rejected): expected an 'Invalid key size' error, got: $out" >&2
		exit 1
	fi
	if test -s "$cert" || test -s "$key"; then
		echo "FAIL ($label rejected): a key or certificate was issued" >&2
		exit 1
	fi
	echo "OK ($label rejected): $msg"
	stop "$label"
}

stop() {
	run "$builddir"/../src/getcert stop-tracking -i "mldsa-$1" > /dev/null || true
}

# A plain resubmit preserves the key for every parameter set, created
# both with "-G ML-DSA-NN" and with "-G ML-DSA -g NN".
for set in 44 65 87; do
	create "G-$set"  "ML-DSA-$set" -G "ML-DSA-$set"
	resubmit_preserves_key "G-$set" "ML-DSA-$set"
	stop "G-$set"

	create "Gg-$set" "ML-DSA-$set" -G ML-DSA -g "$set"
	resubmit_preserves_key "Gg-$set" "ML-DSA-$set"
	stop "Gg-$set"
done

# The dedicated rekey verb replaces the key even within the same
# parameter set.
create "rekey" "ML-DSA-65" -G ML-DSA-65
explicit_rekey_replaces_key "rekey" "ML-DSA-65" rekey
stop "rekey"

# A resubmit that explicitly changes the key type replaces the key too.
create "retype" "ML-DSA-65" -G ML-DSA-65
explicit_rekey_replaces_key "retype" "ML-DSA-87" resubmit -G ML-DSA-87
stop "retype"

# A size that does not match the chosen parameter set is rejected: a wrong
# but otherwise valid set id, an arbitrary value, and the bare "-G ML-DSA"
# (which getcert maps to ML-DSA-65) combined with an RSA-style size.
expect_rejected "G-44-g65"   -G ML-DSA-44 -g 65
expect_rejected "G-44-g64"   -G ML-DSA-44 -g 64
expect_rejected "G-mldsa-g2048" -G ML-DSA -g 2048

echo Test complete.
