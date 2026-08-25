#!/usr/bin/env bash
# Regenerates the README memory numbers. Everything is measured from the
# code being committed, never hand-computed: struct sizes from sizeof,
# stack peaks from bench/stack.py, which walks the real call graph
# (otool-extracted edges weighted by -fstack-usage frames) instead of any
# hand-picked chain. Host-native today; the cross-compiled ASIC model
# (pushkin's device-ram.sh) lands with the bench.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/sz.c" <<'EOF'
#include <stdio.h>
#include "tls.h"
int main(void) {
    printf("ch_tls %zu\n", sizeof(ch_tls));
    return 0;
}
EOF
cc -std=c11 -I. -o "$TMP/sz" "$TMP/sz.c"
SESSION=$("$TMP/sz" | awk '{print $2}')
cc -std=c11 -DCH_KEX_PQ -I. -o "$TMP/sz_pq" "$TMP/sz.c"
SESSION_PQ=$("$TMP/sz_pq" | awk '{print $2}')

echo "session struct:          ${SESSION} B"
echo "static working set:      $((SESSION + 2048)) B (with a 2048 B receive buffer)"
echo "session struct (KEX=pq): ${SESSION_PQ} B"
echo "static working set:      $((SESSION_PQ + 2048)) B (KEX=pq, 2048 B receive buffer)"
echo "-- default build (PIN=rsa); ch_connect peak = pinned RSA verify --"
python3 bench/stack.py
echo "-- PIN=ecdsa build; ch_connect peak = pinned P-256 verify --"
STACK_CFLAGS=-DCH_PIN_ECDSA python3 bench/stack.py | head -1
echo "-- PSK-mode ch_connect (server_auth pruned: PSK never enters it) --"
STACK_PRUNE=hsa_server_auth python3 bench/stack.py | head -1
echo "-- TRUST=ca PIN=rsa; ch_connect peak = chain verify + leaf frame --"
STACK_CFLAGS=-DCH_TRUST_CA python3 bench/stack.py | head -1
echo "-- TRUST=ca PIN=ecdsa --"
STACK_CFLAGS="-DCH_TRUST_CA -DCH_PIN_ECDSA" python3 bench/stack.py | head -1
echo "-- KEX=pq; ch_connect peak includes ML-KEM's K-PKE frames --"
STACK_CFLAGS=-DCH_KEX_PQ python3 bench/stack.py | head -1
