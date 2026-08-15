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
    printf("ms_tls %zu\n", sizeof(ms_tls));
    return 0;
}
EOF
cc -std=c11 -I. -o "$TMP/sz" "$TMP/sz.c"
SESSION=$("$TMP/sz" | awk '{print $2}')

echo "session struct:          ${SESSION} B"
echo "static working set:      $((SESSION + 2048)) B (with a 2048 B receive buffer)"
python3 bench/stack.py
