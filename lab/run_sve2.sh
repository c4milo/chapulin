#!/usr/bin/env bash
# Lab only: builds lab/sve2_chacha.c beside the library's ChaCha20 under gcc and clang, and runs it.
set -uo pipefail
cd "$(dirname "$0")/.."
grep -m1 '^Features' /proc/cpuinfo
for cc in gcc "$CLANG_RV"; do
    echo "== $($cc --version | head -1)"
    W=$(mktemp -d)
    for f in src/chacha20.c src/chacha20_vector.c src/ct.c src/ct_wipe.c; do
        $cc -O2 -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_CPU_RUNTIME -Isrc -Iinclude/chapulin \
            -Iinclude -I. -c "$f" -o "$W/$(basename "$f" .c).o" || exit 1
    done
    $cc -O2 -std=c11 -march=armv8-a+sve2 -msve-vector-bits=128 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN \
        -DCH_CPU_RUNTIME -Isrc -Iinclude/chapulin -Iinclude -I. -c lab/sve2_chacha.c -o "$W/lab.o" || exit 1
    $cc "$W"/*.o -o "$W/sve2" && "$W/sve2"
done
