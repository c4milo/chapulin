#!/usr/bin/env bash
# Runs every CBMC harness through a budget-aware parallel pool. The
# proofs are independent, but each SAT instance can eat gigabytes, so a
# job is admitted by its memory weight (slow tier 6 GB, fast tier 2 GB —
# the biggest measured fast peak, rsa, is under 0.5 GB) against the
# machine's budget, plus a free core; unbounded parallelism would thrash
# the machine into being slower than sequential. Longest jobs launch
# first. Each proof checks memory safety (bounds, pointer validity), UB
# (signed overflow, undefined shifts, division), and the harness's
# explicit asserts, over all inputs within the documented bounds;
# --unwinding-assertions proves the loop bounds themselves.
#
# Results are cached by content: a harness whose inputs are byte-identical
# to its last VERIFICATION SUCCESSFUL run is skipped. The key hashes the
# cbmc version, the exact argv, and the preprocessed translation unit of
# the harness and every dependency source — cc -E resolves the include
# closure, so any header edit lands in the key and re-proves. Identical
# input, identical verdict; PROVE_NO_CACHE=1 forces a full re-run.
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
# exactly that arithmetic with full checks. p256 and rsa split the same
# way, and hsparse/eeparse split one parser per formula: SAT time grows
# super-linearly with formula size, so two small instances beat one big
# one by hours.
set -uo pipefail
cd "$(dirname "$0")/.."

# Tier argument: "fast" (seconds-to-minutes, runs in every make check),
# "slow" (the four SAT heavyweights, run by CI and before release), or
# "all" (default).
TIER="${1:-all}"

CBMC="${CBMC:-cbmc}"

# SAT back end. kissat, when installed, replaces the built-in solver:
# measured on the largest parser formula it returned a verdict in 93
# minutes where the built-in solver had none after 131 — verdicts are
# solver-independent, only the search differs. PROVE_SOLVER=builtin
# forces the built-in solver. PROVE_SOLVER=smt2 routes through
# incremental z3 instead; measured a memory loss on this codebase (z3
# peaked near 22 GB on the aead proof because the bit-vector-heavy
# crypto bit-blasts inside the SMT solver too), kept as an escape hatch
# for a future arithmetic-heavy harness.
SOLVER_ARGS=()
case "${PROVE_SOLVER:-auto}" in
smt2)
    command -v z3 >/dev/null || { echo "PROVE_SOLVER=smt2 needs z3"; exit 1; }
    SOLVER_ARGS=(--incremental-smt2-solver "z3 -smt2 -in")
    ;;
builtin) ;;
*)
    if command -v kissat >/dev/null; then
        SOLVER_ARGS=(--external-sat-solver kissat)
    fi
    ;;
esac

LOGDIR=proof/results
CACHEDIR=proof/.cache
mkdir -p "$LOGDIR" "$CACHEDIR"
BASE=(--bounds-check --pointer-check --pointer-overflow-check
      --undefined-shift-check --div-by-zero-check
      --unwinding-assertions --slice-formula)

# Admission budget: total memory minus headroom for the OS and whatever
# else is open, and two cores held back. Each solver also runs under a
# hard address-space cap of its weight plus 4 GB, floor 6 (Linux/CI,
# where OOM bites hardest; a no-op on macOS, which lacks ulimit -v) so an
# outlier dies as a clean FAILED instead of dragging the machine into
# swap. ulimit -v caps VIRTUAL address space, which runs well above
# resident size — size caps from measured peaks, not wishes: a 5.7 GB-RSS
# solve dies under a 6 GB VA cap. PROVE_JOBS still caps the number of
# concurrent jobs when set.
MEM_GB=8
if [ "$(uname)" = "Darwin" ]; then
    MEM_GB=$(($(sysctl -n hw.memsize) / 1073741824))
elif [ -r /proc/meminfo ]; then
    MEM_GB=$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)
fi
BUDGET_GB=$((MEM_GB - 6))
if [ "$BUDGET_GB" -lt 4 ]; then BUDGET_GB=4; fi
CPU_CAP=$(($(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4) - 2))
if [ "$CPU_CAP" -lt 1 ]; then CPU_CAP=1; fi
if [ -n "${PROVE_JOBS:-}" ] && [ "$PROVE_JOBS" -lt "$CPU_CAP" ]; then
    CPU_CAP=$PROVE_JOBS
fi

HASHER="shasum -a 256"
command -v shasum >/dev/null || HASHER="sha256sum"

# Everything the verdict depends on, in one hash: the checker's version,
# the exact argv, and the preprocessed sources. -D__CPROVER__ keeps the
# include closure aligned with what cbmc itself reads.
cache_key() {
    {
        "$CBMC" --version 2>/dev/null
        printf '%s\n' "$@"
        local a
        for a in "$@"; do
            case "$a" in
            *.c) cc -E -D__CPROVER__ -I . "$a" 2>/dev/null || true ;;
            esac
        done
    } | $HASHER | awk '{print $1}'
}

# Live jobs as "pid:gb" pairs in a plain string — macOS ships bash 3.2,
# where expanding an empty array under set -u is an error.
RUNNING=""
INFLIGHT_N=0
INFLIGHT_GB=0
inflight() {
    local live="" sum=0 n=0 e
    for e in $RUNNING; do
        if kill -0 "${e%%:*}" 2>/dev/null; then
            live="$live $e"
            sum=$((sum + ${e##*:}))
            n=$((n + 1))
        fi
    done
    RUNNING=$live
    INFLIGHT_N=$n
    INFLIGHT_GB=$sum
}

NJOBS=0
NCACHED=0
# launch <tier>[:<weight-gb>] <mode> <name> <unwind> <unwindset> [deps...]
# The optional weight overrides the tier default (fast 2, slow 6) for
# harnesses whose measured peak demands it; the job's address-space cap
# follows as weight + 4 GB.
launch() {
    local tier="$1"
    shift
    local w=""
    case "$tier" in
    *:*)
        w="${tier##*:}"
        tier="${tier%%:*}"
        ;;
    esac
    if [ "$TIER" != "all" ] && [ "$TIER" != "$tier" ]; then
        return
    fi
    if [ -z "$w" ]; then
        w=2
        if [ "$tier" = "slow" ]; then
            w=6
        fi
    fi
    local mode="$1" name="$2" unwind="$3" unwindset="$4"
    shift 4
    local flags=("${BASE[@]}" --signed-overflow-check)
    if [ "$mode" = "noovf" ]; then
        flags=("${BASE[@]}")
    fi
    local args=("proof/${name}_harness.c" "$@" -I . --unwind "$unwind")
    if [ ${#SOLVER_ARGS[@]} -gt 0 ]; then
        args+=("${SOLVER_ARGS[@]}")
    fi
    if [ -n "$unwindset" ]; then
        args+=(--unwindset "$unwindset")
    fi

    local key=""
    if [ "${PROVE_NO_CACHE:-0}" != 1 ]; then
        key=$(cache_key "${args[@]}" "${flags[@]}")
        if [ -n "$key" ] && [ -f "$CACHEDIR/$name-$key.ok" ]; then
            printf '%-14s cached (inputs unchanged since last success)\n' "$name"
            NCACHED=$((NCACHED + 1))
            return
        fi
    fi

    while :; do
        inflight
        if [ "$INFLIGHT_N" -eq 0 ]; then
            break # never deadlock: an oversized job runs alone
        fi
        if [ "$INFLIGHT_N" -lt "$CPU_CAP" ] && [ $((INFLIGHT_GB + w)) -le "$BUDGET_GB" ]; then
            break
        fi
        sleep 1
    done
    local cap_gb=$((w + 4))
    if [ "$cap_gb" -lt 6 ]; then cap_gb=6; fi
    (
        ulimit -v $((cap_gb * 1024 * 1024)) 2>/dev/null || true
        t0=$SECONDS
        "$CBMC" "${args[@]}" "${flags[@]}"
        rc=$?
        echo "run.sh: wall $((SECONDS - t0))s"
        exit $rc
    ) > "$LOGDIR/$name.log" 2>&1 &
    NAMES[$NJOBS]="$name"
    PIDS[$NJOBS]=$!
    KEYS[$NJOBS]="$key"
    NJOBS=$((NJOBS + 1))
    RUNNING="$RUNNING $!:$w"
}

# Longest first, so stragglers overlap the quick wins instead of
# trailing them.
launch slow full handshake 100 "fetch_record.0:45,next_msg.0:140,parse_sh.0:66,parse_ee.0:66,fill_nondet.0:600" buf.c ct.c
launch slow full aead 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
launch slow noovf x25519 65 "" ct.c
launch slow full hkdf_expand 120 "hkdf_expand.0:5" ct.c
# Measured kissat-path peaks (macOS /usr/bin/time -l, RSS): hsparse
# 9.9 GB, sha256 5.7 GB — both above the default weight and cap.
launch fast:10 full hsparse 260 "parse_sh.0:66,main.0:600,main.1:600" buf.c
launch fast full eeparse 260 "parse_ee.0:66,main.0:600" buf.c
launch fast:6 full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
launch fast full record 165 "" ct.c
launch fast full rsa 385 "fill_nondet.0:385,ct_memeq.0:33,ge_bytes.0:385,modulus_bits.0:385,modulus_bits.1:9,mgf1.0:12,emsa_pss_verify.0:352,emsa_pss_verify.1:320,rsa_pss_verify.0:385" --object-bits 11 --max-field-sensitivity-array-size 385 ct.c
launch fast full p256 85 "" buf.c
launch fast full hkdf 120 "" ct.c
launch fast full tlspost 132 "handle_post_hs.0:33,fill_nondet.0:130" --object-bits 11 buf.c ct.c session.c
launch fast full chacha20 165 "chacha20_xor.1:5"
launch fast full poly1305 85 "blocks.0:8" ct.c
launch fast full buf 100 ""
launch fast full ct 65 ""
launch fast full x25519_mul 20 ""
launch fast full drbg 100 "ch_rand_bytes.3:4" ct.c
launch fast full p256_mul 20 ""
launch fast full rsa_mul 20 "fill_nondet.0:385,from_bytes.0:97,main.0:97,to_bytes.0:97"

FAIL=0
i=0
while [ "$i" -lt "$NJOBS" ]; do
    wait "${PIDS[$i]}"
    rc=$?
    name="${NAMES[$i]}"
    log="$LOGDIR/$name.log"
    wall=$(awk '/^run.sh: wall/ {print $3}' "$log")
    printf '%-14s' "$name"
    if grep -q "no body for callee" "$log"; then
        echo "UNSOUND (missing body)"
        grep "no body" "$log" | sort -u
        FAIL=1
    elif [ $rc -ne 0 ] || ! grep -q "VERIFICATION SUCCESSFUL" "$log"; then
        if grep -qiE "bad_alloc|out of memory|out-of-memory|Cannot allocate|Killed" "$log"; then
            echo "FAILED (memory cap: raise the harness weight or split it)"
        else
            echo "FAILED"
        fi
        grep -E "FAILURE" "$log" | sort -u | head -10
        FAIL=1
    else
        awk -v w="$wall" '/^\*\* .* failed/ {printf " %s  %s\n", $0, w; exit}' "$log"
        if [ -n "${KEYS[$i]}" ]; then
            rm -f "$CACHEDIR/$name-"*.ok
            : > "$CACHEDIR/$name-${KEYS[$i]}.ok"
        fi
    fi
    i=$((i + 1))
done

if [ $FAIL -ne 0 ]; then
    exit 1
fi
echo "prove($TIER): $NJOBS proved + $NCACHED cached, all verified"
