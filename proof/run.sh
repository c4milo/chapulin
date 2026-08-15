#!/usr/bin/env bash
# Runs every CBMC harness. Each proof checks memory safety (bounds,
# pointer validity), UB (signed overflow, undefined shifts, division), and
# the harness's explicit asserts, over all inputs within the documented
# bounds; --unwinding-assertions proves the loop bounds themselves.
#
# Every harness gets its full dependency closure on the command line — a
# missing body would make CBMC havoc the callee and the proof unsound.
# run() rejects "no body" for exactly that reason. Loops that contain the
# block functions get tight per-loop bounds (they run at most a few
# times); plain byte loops just get the buffer bound.
set -euo pipefail
cd "$(dirname "$0")/.."

CBMC="${CBMC:-cbmc}"
FLAGS=(--bounds-check --pointer-check --pointer-overflow-check
       --signed-overflow-check --undefined-shift-check --div-by-zero-check
       --unwinding-assertions --slice-formula)

run() {
    local name="$1" unwind="$2" unwindset="$3"
    shift 3
    printf '%-10s' "$name"
    local args=("proof/${name}_harness.c" "$@" -I . --unwind "$unwind")
    if [ -n "$unwindset" ]; then
        args+=(--unwindset "$unwindset")
    fi
    local out
    if ! out=$("$CBMC" "${args[@]}" "${FLAGS[@]}" 2>&1); then
        echo "FAILED"
        echo "$out" | grep -E "FAILURE|no body" | sort -u | head -20
        exit 1
    fi
    if echo "$out" | grep -q "no body for callee"; then
        echo "UNSOUND (missing body)"
        echo "$out" | grep "no body" | sort -u
        exit 1
    fi
    echo "$out" | awk '/^\*\* .* failed/ {printf "  %s\n", $0; exit}'
}

run ct 65 ""
run buf 100 ""
run sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
run hkdf 165 "sha256_update.1:4,hkdf_expand.0:4" sha256.c ct.c
run chacha20 165 "chacha20_xor.0:5"
run poly1305 85 "blocks.0:8" ct.c
run aead 85 "blocks.0:10,chacha20_xor.0:4" chacha20.c poly1305.c ct.c
run x25519 35 "" ct.c
run record 130 "blocks.0:12,chacha20_xor.0:4,sha256_update.1:4,hkdf_expand.0:3" \
    hkdf.c sha256.c aead.c chacha20.c poly1305.c ct.c
run hsparse 260 "parse_sh.0:66,parse_ee.0:66,main.0:600,main.1:600" buf.c

echo "prove: all harnesses verified"
