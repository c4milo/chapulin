#!/usr/bin/env bash
# Runs every CBMC harness. Each proof checks memory safety (bounds,
# pointer validity), UB (signed overflow, undefined shifts, division), and
# the harness's explicit asserts, over all inputs within the documented
# bounds. Unwinding assertions prove the loop bounds themselves.
set -euo pipefail
cd "$(dirname "$0")/.."

CBMC="${CBMC:-cbmc}"
FLAGS=(--bounds-check --pointer-check --pointer-overflow-check
       --signed-overflow-check --undefined-shift-check --div-by-zero-check
       --unwinding-assertions)

run() {
    local name="$1" unwind="$2"
    printf '%-22s' "$name"
    local out
    if ! out=$("$CBMC" "proof/${name}.c" -I . --unwind "$unwind" "${FLAGS[@]}" 2>&1); then
        echo "FAILED"
        echo "$out" | tail -40
        exit 1
    fi
    echo "$out" | grep -q "VERIFICATION SUCCESSFUL" || {
        echo "NO VERDICT"
        echo "$out" | tail -40
        exit 1
    }
    echo "$out" | awk '/^\*\* / {print "  " $0; exit}'
}

run ct_harness 65
run sha256_harness 165
run hkdf_harness 165
run chacha20_harness 165
run poly1305_harness 85
run aead_harness 85
run x25519_harness 35

echo "prove: all harnesses verified"
