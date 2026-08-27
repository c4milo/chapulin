#!/usr/bin/env bash
# Runs every CBMC harness through a budget-aware parallel pool. The
# proofs are independent, but each SAT instance can eat gigabytes, so a
# job is admitted by its memory weight (slow tier 6 GB, fast tier 2 GB —
# the biggest measured fast peak, rsa, is under 0.5 GB) against the
# machine's budget, plus a free core; unbounded parallelism would thrash
# the machine into being slower than sequential. Each proof checks memory safety (bounds, pointer validity), UB
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
# contract-checking stubs of the layer below — every stub asserts
# pointer/size validity and havocs outputs, so nothing upper depends on
# crypto values. Most stubbed layers are proven in their own harnesses;
# io.c, keysched.c, and handshake_message.c have none (the README says so), so
# their stubs assert contracts the unit tests carry.
#
# Every harness gets its full dependency closure on the command line — a
# missing body would make CBMC havoc the callee and the proof unsound, so
# results are rejected on "no body". Loops that contain block functions
# get tight per-loop bounds; plain byte loops get the buffer bound.
#
# x25519 splits by check set and by shape: the mul harnesses run
# without the signed-overflow class (mul's 256 symbolic multiplies
# never converge under SAT with it) at one caller aliasing shape per
# formula, x25519_mul proves the overflow lemma for that arithmetic
# with full checks, and x25519_ops proves the linear ops whole with
# full checks. p256 and rsa split by check set the same way, and
# handshake_parser/eeparse split one parser per formula: SAT time grows
# super-linearly with formula size, so two small instances beat one big
# one by hours.
set -uo pipefail
# Every path below is relative to the repo root, and set -e is off, so a
# failed cd would run the proofs against the sources in the caller's
# directory instead.
cd "$(dirname "$0")/.." || exit 1

# Tier argument: "fast" (seconds-to-minutes, runs in every make check),
# "slow" (the SAT heavyweights, run by CI and before release), or
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

# The slow tier's default weight is solver-dependent: the external-solver
# path materializes the whole formula before the DIMACS handoff and the
# heavyweights peak past 10 GB there (measured as cbmc-side OOMs on a
# 16 GB box), where the built-in incremental solver stays under 6.
SLOW_W=6
# Guarded copy: bash 3.2 errors on expanding an empty array under set -u,
# and SOLVER_ARGS is empty whenever the built-in solver is in use.
SLOW_SOLVER_ARGS=()
if [ ${#SOLVER_ARGS[@]} -gt 0 ]; then
    SLOW_SOLVER_ARGS=("${SOLVER_ARGS[@]}")
fi
if [ ${#SOLVER_ARGS[@]} -gt 0 ] && [ "${SOLVER_ARGS[0]}" = "--external-sat-solver" ]; then
    SLOW_W=12
fi

LOGDIR=proof/results
CACHEDIR=proof/.cache
mkdir -p "$LOGDIR" "$CACHEDIR"
BASE=(--bounds-check --pointer-check --pointer-overflow-check
      --undefined-shift-check --div-by-zero-check
      --unwinding-assertions --slice-formula)

# Admission budget: total memory minus headroom for the OS and whatever
# else is open, and two cores held back. Each solver also runs under a
# hard address-space cap: weight + 4 GB for fast jobs, + 10 for slow
# ones, floor 6 (Linux/CI,
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
# The external solver is a big-box optimization: its slow-tier jobs
# weigh 12 GB, and a machine whose budget cannot admit that would
# serialize them at a weight it cannot honor. Fall back to the built-in
# solver for the slow tier there. The fast tier keeps the external
# solver either way: its wins live there — the ServerHello parser
# returns no verdict in 131 minutes built-in and under a minute with
# kissat — and its jobs never carry the slow tier's weight.
#
# PROVE_ONLY is the exception, and it is what CI runs: one harness per
# job. The weight decides only how many jobs share a machine, the
# launch loop admits a lone job whatever it weighs, and the
# address-space cap below is MEM_GB-1 either way. So the downgrade
# would cost kissat's hours and buy nothing.
if [ "$SLOW_W" -gt "$BUDGET_GB" ] && [ -z "${PROVE_ONLY:-}" ]; then
    echo "prove: budget ${BUDGET_GB} GB cannot admit ${SLOW_W} GB external-solver jobs; the slow tier uses the built-in solver"
    SLOW_SOLVER_ARGS=()
    SLOW_W=6
fi
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
        # Launch-line defines (-DCH_PIN_ECDSA and friends) select code;
        # the preprocess must see them or an edit inside a gated block
        # would reuse another variant's cached proof.
        local a defs=""
        for a in "$@"; do
            case "$a" in
            -D*) defs="$defs $a" ;;
            esac
        done
        for a in "$@"; do
            # defs holds one -D argument per define, and the unquoted
            # expansion below passes each one to cc as its own argument.
            # shellcheck disable=SC2086
            case "$a" in
            *.c) cc -E -D__CPROVER__ $defs -I . "$a" 2>/dev/null || true ;;
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
# harnesses whose measured peak demands it; the address-space cap adds
# the tier's headroom on top.
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
    # A weight above the budget could never be admitted and the
    # launch loop would wait forever; clamp it and let the address-
    # space cap turn a genuinely oversized solve into a named FAILED.
    if [ -n "$w" ] && [ "$w" -gt "$BUDGET_GB" ]; then
        echo "prove: clamping $2 weight ${w} to the ${BUDGET_GB} GB budget"
        w=$BUDGET_GB
    fi
    if [ "$TIER" != "all" ] && [ "$TIER" != "$tier" ]; then
        return
    fi
    # PROVE_ONLY runs a single named harness. CI gives each slow proof
    # its own job this way, so one that never converges starves only
    # itself of the job's time budget instead of the whole tier.
    if [ -n "${PROVE_ONLY:-}" ] && [ "$PROVE_ONLY" != "$2" ]; then
        return
    fi
    if [ -z "$w" ]; then
        w=2
        if [ "$tier" = "slow" ]; then
            w=$SLOW_W
        fi
    fi
    local mode="$1" name="$2" unwind="$3" unwindset="$4"
    shift 4
    local flags=("${BASE[@]}" --signed-overflow-check)
    if [ "$mode" = "noovf" ]; then
        flags=("${BASE[@]}")
    fi
    # cfg.h demands a declared entropy pattern
    # (https://github.com/c4milo/chapulin/issues/41). Every harness either
    # defines ch_rand_bytes itself or never reaches randomness, so they all
    # declare extern, the same way the host binaries in the Makefile do.
    local args=("proof/${name}_harness.c" "$@" -DCH_RAND_EXTERN -I . --unwind "$unwind")
    # bash 3.2 errors on expanding an empty array under set -u, so each
    # arm checks its length before expanding, as the caller below does.
    local solver=()
    if [ "$tier" = "slow" ]; then
        if [ ${#SLOW_SOLVER_ARGS[@]} -gt 0 ]; then
            solver=("${SLOW_SOLVER_ARGS[@]}")
        fi
    elif [ ${#SOLVER_ARGS[@]} -gt 0 ]; then
        solver=("${SOLVER_ARGS[@]}")
    fi
    if [ ${#solver[@]} -gt 0 ]; then
        args+=("${solver[@]}")
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
    # Fast jobs get a tight cap sized from their measured peaks. Slow
    # jobs get weight + 10: cbmc's VIRTUAL footprint under the built-in
    # solver runs far past resident (measured on CI: the aead formula
    # died at a 10 GB VA cap in 43 s, and x25519 proved all 501
    # properties and then died in the final phase), and slow jobs run
    # close to serial anyway, so the OS's OOM handling is the real
    # backstop there.
    local headroom=4
    if [ "$tier" = "slow" ]; then headroom=10; fi
    local cap_gb=$((w + headroom))
    if [ "$cap_gb" -lt 6 ]; then cap_gb=6; fi
    # Never hand a solver more address space than the machine has:
    # past that line the OS kills the runner, not the job.
    if [ "$MEM_GB" -gt 2 ] && [ "$cap_gb" -gt $((MEM_GB - 1)) ]; then cap_gb=$((MEM_GB - 1)); fi
    (
        ulimit -v $((cap_gb * 1024 * 1024)) 2>/dev/null || true
        t0=$SECONDS
        "$CBMC" "${args[@]}" "${flags[@]}"
        rc=$?
        echo "run.sh: wall $((SECONDS - t0))s"
        exit $rc
    ) > "$LOGDIR/$name.log" 2>&1 &
    NAMES[NJOBS]="$name"
    PIDS[NJOBS]=$!
    KEYS[NJOBS]="$key"
    NJOBS=$((NJOBS + 1))
    RUNNING="$RUNNING $!:$w"
}

# Shortest first: on CI the slow jobs run close to serial, and a run
# that hits the workflow timeout banks every finished proof — so the
# order decides how much a partial run saves. Re-dispatching the
# workflow finishes the remainder from the banked cache.
# hkdf_expand splits one function per formula: widening the domains to
# the contract bounds (info 64, output 96) stopped the combined formula
# converging in 1800 s. Measured apart (kissat): expand 745 s / 2.2 GB,
# expand_label 747 s / 2.2 GB.
launch slow full hkdf_expand 120 "hkdf_expand.0:5" --object-bits 11 ct.c
launch slow full hkdf_expand_label 120 "hkdf_expand.0:5" --object-bits 11 ct.c
launch slow full aead 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
launch slow full aead_overlap 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
launch slow full aead_forge 85 "blocks.0:10,chacha20_xor.1:4" chacha20.c poly1305.c ct.c
# aead_inplace has no launch line: its formula returned no verdict in an
# hour under kissat (3.8 GB and climbing), and an unconverged launch line
# proves nothing (docs/proofs.md). The harness is written and reviewed, so
# adding the line is the whole job once the formula converges.
launch slow:5 noovf x25519 65 "" ct.c
launch slow:5 noovf x25519_mul_alias_a 65 ""
launch slow:5 noovf x25519_mul_alias_b 65 ""
launch slow:5 noovf x25519_mul_inputs_alias 65 ""
launch slow:5 noovf x25519_sqr 65 ""
launch slow full handshake_psk 100 "hsr_fetch_record.0:45,hsr_next_msg.0:140,fill_nondet.0:600" handshake_auth.c handshake_record.c buf.c ct.c
launch slow full handshake_pin 100 "hsr_fetch_record.0:45,hsr_next_msg.0:140,fill_nondet.0:600" handshake_auth.c handshake_record.c buf.c ct.c
# ML-KEM's chained-product functions, one formula each; the inverse
# NTT is two half formulas, because the whole transform returns no
# verdict in 900 s (the mlkem comment below states the split and the
# measured peaks).
launch slow:5 full mlkem_ntt 260 ""
launch slow:4 full mlkem_invntt_low 260 ""
launch slow:4 full mlkem_invntt_high 260 ""
launch slow:5 full mlkem_basemul 260 ""
# Measured kissat-path peaks (macOS /usr/bin/time -l, RSS): handshake_parser
# 9.9 GB, sha256 5.7 GB — both above the default weight and cap.
launch fast:10 full handshake_parser 260 "hsp_parse_server_hello.0:66,main.0:600" handshake_parser.c buf.c
launch fast full eeparse 260 "hsp_parse_encrypted_exts.0:66" handshake_parser.c buf.c
launch fast full certparse 260 "" handshake_parser.c buf.c
launch fast:6 full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
# sha3's loops number by back-edge order, so the block loops' inner
# copy loop precedes its while: absorb is head, block-copy, block-while,
# tail; squeeze is head, block-copy, block-while. Measured peaks: sha3
# 2.7 GB / 174 s, sha3_stream 1.8 GB / 139 s (cbmc 6.11.0, 4 cores).
launch fast:4 full sha3 26 "absorb.0:2,absorb.1:169,absorb.2:4,absorb.3:169,squeeze.0:170,squeeze.1:169,squeeze.2:5,ct_wipe.0:201,fill_nondet.0:202" ct.c
launch fast full sha3_stream 26 "absorb.0:34,absorb.1:1,absorb.2:1,absorb.3:34,squeeze.0:34,squeeze.1:34,squeeze.2:2,ct_wipe.0:201,fill_nondet.0:202" ct.c
# ML-KEM splits six ways: the KEM layer over contract stubs of the
# polynomial layer; the polynomial layer minus its chained-product
# functions; and one slow formula each for the NTT, the two halves of
# the inverse NTT, and the base multiplication, whose signed-overflow
# proofs over full-range coefficients are the SAT-hard part. SAT cost
# grows with the multiply count in one formula, so the split follows
# the multiplies — and every formula keeps the checks on, no noovf
# mode. Measured peaks (kissat): mlkem 1.4 GB / 45 s, mlkem_poly
# 2.2 GB / 167 s, ntt 3.3 GB / 195 s, invntt halves 2.7 GB / 349 s
# and 2.8 GB / 186 s, basemul 3.6 GB / 254 s.
launch fast full mlkem 385 "fill_nondet.0:2401,ct_wipe.0:1537,ct_memeq.0:1089" ct.c
launch fast:3 full mlkem_poly 260 "mlk_sample_ntt.0:513,fill_nondet.0:1537,ct_wipe.0:225" ct.c
# record: measured 830 s / 3.0 GB (kissat) since the direction-domain
# and in-place-open shapes joined the formula — under the fast pool's
# 1034 s pole (x509parse_ecdsa), so it stays a push-gate leg.
launch fast:4 full record 165 "" ct.c
launch fast full rsa 385 "fill_nondet.0:385,ct_memeq.0:33,greater_or_equal.0:385,modulus_bits.0:385,modulus_bits.1:9,mgf1.0:12,emsa_pss_verify.0:352,emsa_pss_verify.1:320,rsa_pss_verify.0:385" --object-bits 11 --max-field-sensitivity-array-size 385 ct.c
launch fast full p256 85 "" buf.c
launch fast full hkdf 120 "" ct.c
# io: 458 s under this script's own flags. The transport shim over the
# caller's callbacks, proven against a recv that honours no contract: it
# returns any int, so read_exact's got <= 0 || got > n is under proof
# rather than assumed. The 16-byte buffer bounds its per-byte loop, which
# is what sets the unwind.
launch fast:4 full io 24 ""
# keysched: 13 s under this script's own flags. Extract and Expand-Label sequencing
# over 32-byte secrets; sha256 is harness.h's stub, since the schedule's
# arithmetic is length handling rather than compression.
launch fast full keysched 120 "" ct.c
# epoch: 0 s, 27 MB. The CA arm's own rules. handshake_ca drives the whole CA
# driver and does not converge (https://github.com/c4milo/chapulin/issues/37),
# so this proves the part that is specific to the arm -- the verdict matching
# its reported status, and the stored epoch never moving backwards -- and
# leaves the record reading to handshake_psk and handshake_pin.
launch fast full epoch 40 "" ct.c
launch fast full handshake_post 132 "handle_post_handshake.0:33,fill_nondet.0:130" --object-bits 11 buf.c ct.c session.c
# The only launch line that builds the hybrid key exchange
# (https://github.com/c4milo/chapulin/issues/47). hybrid_secret over any seed,
# any server ciphertext and any server share, with mlkem and x25519 stubbed to
# their headers' contracts — their own harnesses prove the arithmetic, and
# driving a 2400-byte expansion and 256 symbolic multiplies here would be the
# shape docs/proofs.md says not to build. Measured: 508 properties, 3 s, 78 MB
# (kissat). The hybrid ServerHello parser stays unproven: the 256-byte
# handshake_parser bound cannot hold a 1,128-byte key share.
launch fast full hybrid_secret 65 "fill_nondet.0:2401,ct_wipe.0:2401" -DCH_KEX_PQ ct.c
# The parser half of the hybrid build
# (https://github.com/c4milo/chapulin/issues/47). parse_key_share is driven
# directly because handshake_parser bounds its message at 256 bytes and a
# hybrid key_share extension is 1,128: raising that bound would grow the fast
# tier's heaviest formula (9.9 GB) rather than add a second cheap one. Proves
# what hybrid_secret's harness assumes — an accepted share hands back a whole
# readable ciphertext inside the bytes the parser consumed, so neither proof
# rests on the assumption alone. Measured: 654 properties, 1 s, 164 MB
# (kissat).
launch fast full key_share 1200 "fill_nondet.0:1133" -DCH_KEX_PQ buf.c
# handshake_message.c was the last library source no harness compiled
# (https://github.com/c4milo/chapulin/issues/33). Beyond memory safety this
# checks the constant handshake.c asserts CH_TX_STAGE against: at CH_HELLO_MAX
# the build always succeeds, so the bound is sufficient rather than plausible.
# wbuf is real here — refusing to overflow is its contract, and the point is
# that the builder uses it correctly. Measured: 486 properties, 5 s, 46 MB
# (kissat).
launch fast full hello_build 400 "fill_nondet.0:321,wb_bytes.0:321" buf.c
# x509: primitives concrete (both variants), the walker with stubbed
# primitives. The ECDSA walker proves the full two-entry bound in
# every check; the RSA walker's formula is a SAT heavyweight, so it
# runs in the slow tier at the single-max-RSA-certificate bound.
# Weights are measured peaks (kissat): der 1.4 GB, parse_ecdsa
# 2.4 GB (down from 5.6 with the typed stub stores), parse rsa
# 7.1 GB.
launch fast:3 full x509der 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch fast:3 full x509der_ecdsa 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch fast:4 full x509parse_ecdsa 260 "fill_nondet.0:257,ct_memeq.0:68" buf.c ct.c
launch slow:8 full x509parse 844 "fill_nondet.0:841,ct_memeq.0:68" buf.c ct.c
launch fast full chacha20 165 "chacha20_xor.1:5"
launch fast full poly1305 85 "blocks.0:8" ct.c
launch fast full buf 100 ""
launch fast full ct 65 ""
# The software multiply, for cores with no multiplier. UB and the fixed
# loop counts over unconstrained 32- and 64-bit inputs; the product
# itself against the C operator only at 8-bit operands, the widest
# bound whose formula converges. Measured: 5 properties, 34 s. The
# harness comment carries the widths that gave no verdict; multiplier
# equivalence is the classic hard SAT instance.
launch fast full softmul 65 ""
launch fast full x25519_mul 20 ""
launch fast full x25519_ops 260 ""
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
# A PROVE_ONLY that matched no launch line proves nothing, and "all
# verified" over zero jobs reads as success. A typo in the harness name
# lands here; fail rather than bless it.
if [ -n "${PROVE_ONLY:-}" ] && [ $((NJOBS + NCACHED)) -eq 0 ]; then
    echo "prove: PROVE_ONLY='$PROVE_ONLY' matched no launch line in the $TIER tier"
    exit 1
fi
echo "prove($TIER): $NJOBS proved + $NCACHED cached, all verified"
