#!/usr/bin/env bash
# Runs every CBMC harness. Each proof checks memory safety (bounds,
# pointer validity), UB (signed overflow, undefined shifts, division), and
# the harness's explicit asserts, over all inputs within the documented
# bounds; --unwinding-assertions proves the loop bounds themselves.
#
# Structure is layered, mlkem-native style: leaf modules (ct, buf,
# sha256, chacha20, poly1305, aead, x25519 field ops) are proven concrete;
# upper layers (hkdf, record) are proven against contract-checking stubs
# of the already-proven layer below — every stub asserts pointer/size
# validity and havocs outputs, so nothing upper depends on crypto values.
#
# Every harness gets its full dependency closure on the command line — a
# missing body would make CBMC havoc the callee and the proof unsound, so
# run() hard-fails on "no body". Loops that contain block functions get
# tight per-loop bounds; plain byte loops get the buffer bound.
#
# x25519 splits one proof in two: the concrete harness runs without the
# signed-overflow class (mul's 256 symbolic multiplies never converge
# under SAT with it), and x25519_mul proves the overflow lemma covering
# exactly that arithmetic with full checks.
set -euo pipefail
cd "$(dirname "$0")/.."

CBMC="${CBMC:-cbmc}"
BASE=(--bounds-check --pointer-check --pointer-overflow-check
      --undefined-shift-check --div-by-zero-check
      --unwinding-assertions --slice-formula)
FLAGS=("${BASE[@]}" --signed-overflow-check)
FLAGS_NOOVF=("${BASE[@]}")

run_with() {
    local mode="$1" name="$2" unwind="$3" unwindset="$4"
    shift 4
    local flags=("${FLAGS[@]}")
    if [ "$mode" = "noovf" ]; then
        flags=("${FLAGS_NOOVF[@]}")
    fi
    printf '%-12s' "$name"
    local args=("proof/${name}_harness.c" "$@" -I . --unwind "$unwind")
    if [ -n "$unwindset" ]; then
        args+=(--unwindset "$unwindset")
    fi
    local out
    if ! out=$("$CBMC" "${args[@]}" "${flags[@]}" 2>&1); then
        echo "FAILED"
        echo "$out" | grep -E "FAILURE|no body" | sort -u | head -20
        exit 1
    fi
    if echo "$out" | grep -q "no body for callee"; then
        echo "UNSOUND (missing body)"
        echo "$out" | grep "no body" | sort -u
        exit 1
    fi
    echo "$out" | awk '/^\*\* .* failed/ {printf " %s\n", $0; exit}'
}

run() {
    run_with full "$@"
}

run ct 65 ""
run buf 100 ""
run sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
run hkdf 165 "hkdf_expand.0:5" ct.c
run chacha20 165 "chacha20_xor.1:5"
run poly1305 85 "blocks.0:8" ct.c
run aead 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
run x25519_mul 20 ""
run_with noovf x25519 65 "" ct.c
run record 165 "" ct.c
run hsparse 260 "parse_sh.0:66,parse_ee.0:66,main.0:600,main.1:600" buf.c

echo "prove: all harnesses verified"
