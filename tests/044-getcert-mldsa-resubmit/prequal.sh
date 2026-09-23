#!/bin/sh
source "$srcdir"/functions
initnssdb "$tmpdir"

run_certutil -d "$tmpdir" -S -n test \
	-s "cn=Test" -c "cn=Test" \
	-x -t u -k mldsa -q ML-DSA-65

if [ $? -ne 0 ]; then
	echo "ML-DSA is not available or not allowed in NSS crypto policy."
	exit 1
fi
