#!/usr/bin/env bash
# Regenerates the README memory numbers. Everything is measured from the
# code being committed, never hand-computed: struct sizes from sizeof,
# stack peaks from bench/stack.py, which walks the real call graph
# (otool-extracted edges weighted by -fstack-usage frames) instead of any
# hand-picked chain. Host-native today; the cross-compiled ASIC model
# (pushkin's device-ram.sh) lands with the bench. Prints the report and
# writes bench/results-sram.csv, the file make lint-bench-numbers compares
# against the README's Memory table
# (https://github.com/c4milo/chapulin/issues/90).
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The receive buffer the table shows; the static working sets add it.
RXBUF=2048

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
echo "static working set:      $((SESSION + RXBUF)) B (with a ${RXBUF} B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32} B"
echo "session struct (KEX=pq): ${SESSION_PQ} B"
echo "static working set:      $((SESSION_PQ + RXBUF)) B (KEX=pq, ${RXBUF} B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32_PQ} B (KEX=pq)"

# Each stack.py report is saved whole, so the CSV rows below come from the
# same run the report prints.
stack_report() { # $1 = report name, $2.. = VAR=value settings for stack.py
    local name=$1
    shift
    env "$@" python3 bench/stack.py > "$TMP/$name.stack"
}
peak() { # $1 = report name, $2 = entry point -> its peak stack in bytes
    awk -v entry="$2" '$1 == entry { print $2 }' "$TMP/$1.stack"
}

echo "-- default build (PIN=rsa); ch_connect peak = pinned RSA verify --"
stack_report default
cat "$TMP/default.stack"
echo "-- PIN=ecdsa build; ch_connect peak = pinned P-256 verify --"
stack_report ecdsa STACK_CFLAGS=-DCH_PIN_ECDSA
head -1 "$TMP/ecdsa.stack"
echo "-- PSK-mode ch_connect (server_auth pruned: PSK never enters it) --"
stack_report psk STACK_PRUNE=hsa_server_auth
head -1 "$TMP/psk.stack"
echo "-- TRUST=ca PIN=rsa; ch_connect peak = chain verify + leaf frame --"
stack_report ca_rsa STACK_CFLAGS=-DCH_TRUST_CA
head -1 "$TMP/ca_rsa.stack"
echo "-- TRUST=ca PIN=ecdsa --"
stack_report ca_ecdsa "STACK_CFLAGS=-DCH_TRUST_CA -DCH_PIN_ECDSA"
head -1 "$TMP/ca_ecdsa.stack"
echo "-- KEX=pq; ch_connect peak includes ML-KEM's K-PKE frames --"
stack_report pq STACK_CFLAGS=-DCH_KEX_PQ
head -1 "$TMP/pq.stack"

# The CSV carries every column or nothing: without the rv32 toolchain the
# report above says "unmeasured", and the committed CSV keeps the last
# full measurement.
if [ "$SESSION_RV32" = unmeasured ] || [ "$SESSION_RV32_PQ" = unmeasured ]; then
    echo "SKIP bench/results-sram.csv: no rv32 toolchain, so the rv32 column is unmeasured" >&2
    exit 0
fi

row() { # $1 = quantity, $2 = bytes -> one CSV line; refuses a non-number
    case "$2" in
    '' | *[!0-9]*) echo "FAIL: $1 measured as '$2', not a byte count" >&2; return 1 ;;
    esac
    echo "$1,$2"
}
# Written to a temporary file first: redirecting straight at the committed
# file would truncate it before a failing row could stop the run.
TMPOUT="$TMP/results-sram.csv"
{
    echo "quantity,bytes"
    row session_struct_arm64 "$SESSION"
    row session_struct_rv32 "$SESSION_RV32"
    row receive_buffer "$RXBUF"
    row static_working_set_arm64 "$((SESSION + RXBUF))"
    row static_working_set_rv32 "$((SESSION_RV32 + RXBUF))"
    row session_struct_pq_arm64 "$SESSION_PQ"
    row session_struct_pq_rv32 "$SESSION_RV32_PQ"
    row static_working_set_pq_arm64 "$((SESSION_PQ + RXBUF))"
    row static_working_set_pq_rv32 "$((SESSION_RV32_PQ + RXBUF))"
    row stack_connect_rsa "$(peak default ch_connect)"
    row stack_connect_ecdsa "$(peak ecdsa ch_connect)"
    row stack_connect_psk "$(peak psk ch_connect)"
    row stack_connect_ca_rsa "$(peak ca_rsa ch_connect)"
    row stack_connect_ca_ecdsa "$(peak ca_ecdsa ch_connect)"
    row stack_read "$(peak default ch_read)"
    row stack_connect_pq "$(peak pq ch_connect)"
    row stack_write "$(peak default ch_write)"
    row stack_close "$(peak default ch_close)"
} > "$TMPOUT"
mv "$TMPOUT" bench/results-sram.csv
echo "wrote bench/results-sram.csv" >&2
