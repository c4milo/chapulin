#!/usr/bin/env bash
# Runs every CBMC harness through a bounded parallel pool (PROVE_JOBS,
# default 4) — the proofs are independent, but each SAT instance can eat
# gigabytes, so unbounded parallelism thrashes the machine into being
# slower than sequential. Longest jobs launch first. Each proof checks memory
# safety (bounds, pointer validity), UB (signed overflow, undefined
# shifts, division), and the harness's explicit asserts, over all inputs
# within the documented bounds; --unwinding-assertions proves the loop
# bounds themselves.
#
# Structure is layered, mlkem-native style: leaf modules (ct, buf,
# sha256, chacha20, poly1305, aead, x25519 field ops) are proven concrete;
# upper layers (hkdf, record, the handshake driver) are proven against
# contract-checking stubs of the already-proven layer below — every stub
# asserts pointer/size validity and havocs outputs, so nothing upper
# depends on crypto values.
#
# Every harness gets its full dependency closure on the command line — a
# missing body would make CBMC havoc the callee and the proof unsound, so
# results are rejected on "no body". Loops that contain block functions
# get tight per-loop bounds; plain byte loops get the buffer bound.
#
# x25519 splits one proof in two: the concrete harness runs without the
# signed-overflow class (mul's 256 symbolic multiplies never converge
# under SAT with it), and x25519_mul proves the overflow lemma covering
# exactly that arithmetic with full checks.
set -uo pipefail
cd "$(dirname "$0")/.."

CBMC="${CBMC:-cbmc}"
LOGDIR=proof/results
mkdir -p "$LOGDIR"
BASE=(--bounds-check --pointer-check --pointer-overflow-check
      --undefined-shift-check --div-by-zero-check
      --unwinding-assertions --slice-formula)

POOL="${PROVE_JOBS:-4}"

launch() {
    while [ "$(jobs -pr | wc -l)" -ge "$POOL" ]; do
        sleep 1
    done
    local mode="$1" name="$2" unwind="$3" unwindset="$4"
    shift 4
    local flags=("${BASE[@]}" --signed-overflow-check)
    if [ "$mode" = "noovf" ]; then
        flags=("${BASE[@]}")
    fi
    local args=("proof/${name}_harness.c" "$@" -I . --unwind "$unwind")
    if [ -n "$unwindset" ]; then
        args+=(--unwindset "$unwindset")
    fi
    "$CBMC" "${args[@]}" "${flags[@]}" > "$LOGDIR/$name.log" 2>&1 &
    NAMES+=("$name")
    PIDS+=($!)
}

# Longest first, so stragglers overlap the quick wins instead of
# trailing them.
NAMES=()
PIDS=()
launch full handshake 100 "fetch_record.0:45,next_msg.0:140,parse_sh.0:66,parse_ee.0:66,fill_nondet.0:600" buf.c ct.c
launch full aead 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
launch noovf x25519 65 "" ct.c
launch full hkdf_expand 120 "hkdf_expand.0:5" ct.c
launch full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
launch full record 165 "" ct.c
launch full p256 85 "" buf.c
launch full hkdf 120 "" ct.c
launch full hsparse 260 "parse_sh.0:66,parse_ee.0:66,main.0:600,main.1:600" buf.c
launch full chacha20 165 "chacha20_xor.1:5"
launch full poly1305 85 "blocks.0:8" ct.c
launch full buf 100 ""
launch full ct 65 ""
launch full x25519_mul 20 ""
launch full p256_mul 20 ""

FAIL=0
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}"
    rc=$?
    name="${NAMES[$i]}"
    log="$LOGDIR/$name.log"
    printf '%-14s' "$name"
    if grep -q "no body for callee" "$log"; then
        echo "UNSOUND (missing body)"
        grep "no body" "$log" | sort -u
        FAIL=1
    elif [ $rc -ne 0 ] || ! grep -q "VERIFICATION SUCCESSFUL" "$log"; then
        echo "FAILED"
        grep -E "FAILURE" "$log" | sort -u | head -10
        FAIL=1
    else
        awk '/^\*\* .* failed/ {printf " %s\n", $0; exit}' "$log"
    fi
done

if [ $FAIL -ne 0 ]; then
    exit 1
fi
echo "prove: all harnesses verified"
