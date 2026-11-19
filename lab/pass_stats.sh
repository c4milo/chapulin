#!/usr/bin/env bash
# Lab only: the instructions of chacha20_sve2.c's pass under each compiler given: a count of each
# mnemonic, and the loads and stores that address the stack.
set -uo pipefail
cd "$(dirname "$0")/.."
for cc in "$@"; do
    echo "== $cc: $($cc --version | head -1)"
    W=$(mktemp -d)
    $cc -O2 -std=c11 -DCH_CPU_RUNTIME -Isrc -Iinclude/chapulin -Iinclude -c src/chacha20_sve2.c -o "$W/sve2.o" || continue
    objdump -d --no-show-raw-insn "$W/sve2.o" > "$W/sve2.s"
    awk '/^[0-9a-f]+ <pass/{on=1; print; next} /^[0-9a-f]+ </{on=0} on' "$W/sve2.s" > "$W/pass.s"
    echo "pass instructions: $(grep -cE '^\s+[0-9a-f]+:' "$W/pass.s")"
    echo "stack loads and stores: $(grep -cE '\[sp' "$W/pass.s")"
    grep -E '^\s+[0-9a-f]+:' "$W/pass.s" | awk '{print $2}' | sort | uniq -c | sort -rn | head -25
    echo "-- the first 80 lines of the pass"
    head -80 "$W/pass.s"
done
