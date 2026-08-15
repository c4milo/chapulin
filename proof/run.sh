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

# Tier argument: "fast" (seconds-to-minutes, runs in every make check),
# "slow" (the four SAT heavyweights, run by CI and before release), or
# "all" (default).
TIER="${1:-all}"

CBMC="${CBMC:-cbmc}"
# PROVE_SOLVER=smt2 routes proofs through an incremental SMT solver (z3)
# instead of the built-in SAT back end. Measured a memory loss, not a win,
# on this codebase: z3 peaked near 22 GB on the aead proof because the
# bit-vector-heavy crypto bit-blasts inside the SMT solver too. Kept as an
# escape hatch for a future arithmetic-heavy harness, but SAT is the
# default and the better choice for these formulas.
SMT_ARGS=()
if [ "${PROVE_SOLVER:-sat}" = "smt2" ]; then
    command -v z3 >/dev/null || { echo "PROVE_SOLVER=smt2 needs z3"; exit 1; }
    SMT_ARGS=(--incremental-smt2-solver "z3 -smt2 -in")
fi
LOGDIR=proof/results
mkdir -p "$LOGDIR"
BASE=(--bounds-check --pointer-check --pointer-overflow-check
      --undefined-shift-check --div-by-zero-check
      --unwinding-assertions --slice-formula)

# Pool size defaults to available memory divided by a 6 GB per-solver
# budget (the biggest harnesses peak at a few GB), capped at 4. Each
# solver also runs under a hard address-space cap (Linux/CI, where OOM
# bites hardest; a no-op on macOS, which lacks ulimit -v) so an outlier
# dies as a clean FAILED instead of dragging the machine into swap.
MEM_GB=8
if [ "$(uname)" = "Darwin" ]; then
    MEM_GB=$(($(sysctl -n hw.memsize) / 1073741824))
elif [ -r /proc/meminfo ]; then
    MEM_GB=$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)
fi
DEFAULT_POOL=$((MEM_GB / 6))
if [ "$DEFAULT_POOL" -lt 1 ]; then DEFAULT_POOL=1; fi
if [ "$DEFAULT_POOL" -gt 4 ]; then DEFAULT_POOL=4; fi
POOL="${PROVE_JOBS:-$DEFAULT_POOL}"
SOLVER_MEM_KB=$((6 * 1024 * 1024))

launch() {
    local tier="$1"
    shift
    if [ "$TIER" != "all" ] && [ "$TIER" != "$tier" ]; then
        return
    fi
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
    if [ ${#SMT_ARGS[@]} -gt 0 ]; then
        args+=("${SMT_ARGS[@]}")
    fi
    if [ -n "$unwindset" ]; then
        args+=(--unwindset "$unwindset")
    fi
    (
        ulimit -v "$SOLVER_MEM_KB" 2>/dev/null || true
        exec "$CBMC" "${args[@]}" "${flags[@]}"
    ) > "$LOGDIR/$name.log" 2>&1 &
    NAMES+=("$name")
    PIDS+=($!)
}

# Longest first, so stragglers overlap the quick wins instead of
# trailing them.
NAMES=()
PIDS=()
launch slow full handshake 100 "fetch_record.0:45,next_msg.0:140,parse_sh.0:66,parse_ee.0:66,fill_nondet.0:600" buf.c ct.c
launch slow full aead 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
launch slow noovf x25519 65 "" ct.c
launch slow full hkdf_expand 120 "hkdf_expand.0:5" ct.c
launch fast full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
launch fast full record 165 "" ct.c
launch fast full p256 85 "" buf.c
launch fast full hkdf 120 "" ct.c
launch fast full hsparse 260 "parse_sh.0:66,parse_ee.0:66,main.0:600,main.1:600" buf.c
launch fast full tlspost 132 "handle_post_hs.0:33,fill_nondet.0:130" --object-bits 11 buf.c ct.c session.c
launch fast full chacha20 165 "chacha20_xor.1:5"
launch fast full poly1305 85 "blocks.0:8" ct.c
launch fast full buf 100 ""
launch fast full ct 65 ""
launch fast full x25519_mul 20 ""
launch fast full drbg 100 "ch_rand_bytes.3:4" ct.c
launch fast full p256_mul 20 ""

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
        if grep -qiE "bad_alloc|out of memory|Cannot allocate" "$log"; then
            echo "FAILED (memory cap: raise PROVE_JOBS budget or split the harness)"
        else
        echo "FAILED"
        fi
        grep -E "FAILURE" "$log" | sort -u | head -10
        FAIL=1
    else
        awk '/^\*\* .* failed/ {printf " %s\n", $0; exit}' "$log"
    fi
done

if [ $FAIL -ne 0 ]; then
    exit 1
fi
echo "prove($TIER): all harnesses verified"
