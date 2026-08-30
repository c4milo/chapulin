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
cc -std=c11 -DCH_RAND_EXTERN -I. -o "$TMP/sz" "$TMP/sz.c"
SESSION=$("$TMP/sz" | awk '{print $2}')
cc -std=c11 -DCH_RAND_EXTERN -DCH_KEX_PQ -I. -o "$TMP/sz_pq" "$TMP/sz.c"
SESSION_PQ=$("$TMP/sz_pq" | awk '{print $2}')

# The same struct on a 32-bit target. The pointer fields are what move, so
# the host number overstates what a device needs, and the README used to
# publish only the host one with a sentence saying a 32-bit target shrinks
# them (https://github.com/c4milo/chapulin/issues/52). Nothing can run an
# rv32 binary here, so the size is read out of the object: a char array
# declared at sizeof(ch_tls) has exactly that size in the symbol table.
RV32_CLANG=$(command -v /opt/homebrew/opt/llvm/bin/clang || command -v clang || true)
RV32_NM=$(command -v llvm-nm || command -v /opt/homebrew/opt/llvm/bin/llvm-nm || true)
SESSION_RV32="unmeasured"
SESSION_RV32_PQ="unmeasured"
if [ -n "$RV32_CLANG" ] && [ -n "$RV32_NM" ]; then
    cat > "$TMP/probe.c" <<'PROBE'
#include "session.h"
char probe_ch_tls[sizeof(ch_tls)];
PROBE
    rv32_size() { # $1 = extra defines
        # shellcheck disable=SC2086
        "$RV32_CLANG" -target riscv32-unknown-elf -march=rv32ic -mabi=ilp32 -Os \
            -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN $1 -I. -c "$TMP/probe.c" \
            -o "$TMP/probe.o" 2>/dev/null || { echo "unmeasured"; return; }
        # llvm-nm prints the size in hex, and macOS awk has no strtonum.
        local hex
        hex=$("$RV32_NM" --print-size --defined-only "$TMP/probe.o" 2>/dev/null \
              | awk '/probe_ch_tls/ {print $2}')
        if [ -n "$hex" ]; then echo $((16#$hex)); else echo "unmeasured"; fi
    }
    SESSION_RV32=$(rv32_size "")
    SESSION_RV32_PQ=$(rv32_size "-DCH_KEX_PQ")
fi

echo "session struct:          ${SESSION} B"
echo "static working set:      $((SESSION + 2048)) B (with a 2048 B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32} B"
echo "session struct (KEX=pq): ${SESSION_PQ} B"
echo "static working set:      $((SESSION_PQ + 2048)) B (KEX=pq, 2048 B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32_PQ} B (KEX=pq)"
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
