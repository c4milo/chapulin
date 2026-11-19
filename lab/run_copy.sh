#!/usr/bin/env bash
# Lab only: builds chacha20_sve2.c's copy with each compiler given, with no -march, and runs
# lab/sve2_copy.c against it.
set -uo pipefail
cd "$(dirname "$0")/.."
grep -m1 '^Features' /proc/cpuinfo
for cc in "$@"; do
    echo "== $cc: $($cc --version | head -1)"
    W=$(mktemp -d)
    ok=1
    for f in src/chacha20.c src/chacha20_vector.c src/chacha20_sve2.c src/ct.c src/ct_wipe.c lab/sve2_copy.c; do
        if ! $cc -O2 -std=c11 -Wall -Wextra -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_CPU_RUNTIME -Isrc \
            -Iinclude/chapulin -Iinclude -I. -c "$f" -o "$W/$(basename "$f" .c).o"; then
            echo "COMPILE FAILED: $f under $cc"
            ok=0
        fi
    done
    [ "$ok" = 1 ] || continue
    nm "$W/chacha20_sve2.o" | grep chacha20_sve2_xor || echo "no chacha20_sve2_xor under $cc"
    objdump -d "$W/chacha20_sve2.o" | grep -c '\bxar\b' | sed 's/^/xar count: /'
    objdump -d "$W/chacha20_sve2.o" | grep -cE '\b(sp|x29)\]' | sed 's/^/stack accesses: /'
    $cc "$W"/*.o -o "$W/copy" && "$W/copy"
done
