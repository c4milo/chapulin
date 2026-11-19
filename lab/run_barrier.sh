#!/usr/bin/env bash
# Lab only: builds the shipped copy and the pinned variant under each compiler given and times both.
set -uo pipefail
cd "$(dirname "$0")/.."
for cc in "$@"; do
    echo "== $cc: $($cc --version | head -1)"
    W=$(mktemp -d)
    ok=1
    for f in src/chacha20.c src/chacha20_vector.c src/chacha20_sve2.c src/ct.c src/ct_wipe.c lab/sve2_barrier.c lab/barrier_main.c; do
        $cc -O2 -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_CPU_RUNTIME -Isrc -Iinclude/chapulin \
            -Iinclude -c "$f" -o "$W/$(basename "$f" .c).o" || { echo "COMPILE FAILED: $f"; ok=0; }
    done
    [ "$ok" = 1 ] || continue
    objdump -d "$W/sve2_barrier.o" | grep -cE '\[sp|\[x[0-9]+(, #[0-9-]+)?(, mul vl)?\]' | sed 's/^/pinned memory operands: /'
    objdump -d "$W/chacha20_sve2.o" | grep -cE '\[sp|\[x[0-9]+(, #[0-9-]+)?(, mul vl)?\]' | sed 's/^/shipped memory operands: /'
    $cc "$W"/*.o -o "$W/b" && "$W/b"
done
