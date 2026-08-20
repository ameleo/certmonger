#!/bin/bash -e

cd "$tmpdir"

echo '['Tests begin.']'

"$toolsdir"/timestamp good \
	"19700101000000" \
	"20000229120000" \
	"20260820123456" \
	"99991231235959"

"$toolsdir"/timestamp bad \
	"abcd0101000000" \
	"-9990101000000" \
	"19700099000000" \
	"19701301000000" \
	"19700132000000" \
	"19700101250000" \
	"19700101006000" \
	"19700101000061" \
	"99999999235959"

"$toolsdir"/timestamp overflow-guard "12026"

echo '['Test complete.']'
