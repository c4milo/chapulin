#!/usr/bin/env bash
# Runs every CBMC harness through a budget-aware parallel pool. The
# proofs are independent, but each SAT instance can eat gigabytes, so a
# job is admitted by its memory weight against the machine's budget,
# plus a free core; unbounded parallelism would thrash the machine into
# being slower than sequential. The weight is the tier default (fast
# 2 GB; slow 6 GB, or 12 GB under the external solver) unless the launch
# line carries one sized from a measured peak. The biggest measured fast
# peak was handshake_parser at 9.9 GB, so its launch line carries
# fast:10 (its comment records a later 4.6 GB measurement); sha256,
# now in the slow tier, peaked at 5.7 GB and carries slow:6. Each proof checks
# memory safety (bounds, pointer validity), UB (signed overflow,
# undefined shifts, division), and the harness's explicit asserts, over
# all inputs within the documented bounds; --unwinding-assertions proves
# the loop bounds themselves.
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
# results are rejected on "no body". Results are also rejected when cbmc
# warns that an --unwindset id names a loop or a function the goto model
# does not have: that entry bounds nothing, and the loop it was written
# for runs under the global --unwind instead
# (https://github.com/c4milo/chapulin/issues/136). `cbmc --show-loops`
# on a harness's command lists the ids it has. Loops that contain block
# functions get tight per-loop bounds; plain byte loops get the buffer
# bound.
#
# x25519 splits by check set and by shape: the mul harnesses run
# without the signed-overflow class (mul's 256 symbolic multiplies
# never converge under SAT with it) at one caller aliasing shape per
# formula, x25519_mul proves the overflow lemma for that arithmetic
# with full checks, and x25519_ops proves the linear ops whole with
# full checks. x25519_step and x25519_tail prove the ladder keeps its
# limbs inside the range those proofs assume, with mul's multiply
# replaced by the magnitude contract (proof/x25519_stubs.h) that
# x25519_mul discharges on the native multiply and x25519_mul_ct on
# the shipped decomposition. p256 and rsa split by check set the same way, and
# handshake_parser/eeparse split one parser per formula: SAT time grows
# super-linearly with formula size, so two small instances beat one big
# one by hours.
set -uo pipefail
# Every path below is relative to the repo root, and set -e is off, so a
# failed cd would run the proofs against the sources in the caller's
# directory instead.
cd "$(dirname "$0")/.." || exit 1

# Tier argument: "fast" (seconds-to-minutes; make check-slow runs it
# through the prove target, and CI runs that on every push to main but
# not on a pull request, so make check never runs a proof), "slow" (the
# SAT heavyweights, run by CI and before release), or "all" (default).
# A harness that takes more than about five minutes on the check job's
# runner goes to the slow tier. An edit to a header most harnesses read,
# cfg.h for one, re-proves the whole fast tier, and on 2026-09-24 that
# took 91 minutes with nine such harnesses in it (353 to 816 s each);
# they now run nightly, one job each.
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
    # -DCH_NATIVE_WIDEMUL, for the same reason the Makefile passes it to host
    # binaries: ct.h has no architecture allowlist, and proving the four 16x16
    # pieces inside every poly1305, x25519 and mlkem formula multiplies the
    # multiply count these solvers already struggle with. The composed proofs
    # therefore verify the single-multiply form. ctwidemul proves the two
    # forms compute the same function at 8-bit operands, the widest bound
    # whose formula converges, so those verdicts carry to a target that runs
    # the decomposition for operands inside that bound. x25519_mul_ct proves
    # the product bound the ladder proofs rest on directly on the
    # decomposition, at the full operand range
    # (https://github.com/c4milo/chapulin/issues/145). Both harnesses
    # override this with CH_CT_WIDEMUL, which ct.h lets win.
    local args=("proof/${name}_harness.c" "$@" -DCH_RAND_EXTERN -DCH_NATIVE_WIDEMUL \
                -I . --unwind "$unwind")
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
# the contract bounds (info at the CH_ASSERT bound, output 96) stopped
# the combined formula converging in 1800 s. The info bound was a
# literal 64 and is HKDF_INFO_MAX now, 54 at the default label cap, so
# the harness proves the contract rather than a number above it.
# Measured apart (kissat), first at the old 64 and then at 54 on an
# arm64 development machine: expand 745 s / 2.2 GB, then 525 s / 2.1 GB
# over 283 properties; expand_label 747 s / 2.2 GB, then 549 s / 2.16 GB
# over 299. Re-measured after hash_len joined the signatures, with make
# check running beside them: expand 283 properties, 660 s wall and 631 s
# of CPU, 1.95 GB; expand_label 299, 668 s wall and 640 s of CPU, 1.98 GB.
launch slow full hkdf_expand 120 "hkdf_expand.0:5" --object-bits 11 ct.c
launch slow full hkdf_expand_label 120 "hkdf_expand.0:5" --object-bits 11 ct.c
# The SHA-384 arms of the two lines above, under CH_HASH_SHA384 with
# hash_len fixed at 48: output up to three 48-byte blocks, info up to the
# 70-byte HKDF_INFO_MAX that build declares, and the SHA-512 context
# stubs' 208-byte fill and wipe, which set the unwindset. Measured (arm64
# macOS, cbmc 6.11.0, kissat, PROVE_ONLY=<name> PROVE_NO_CACHE=1
# /usr/bin/time -l, slow tier, with make check running beside them):
# expand 348 properties, 1817 s wall and 1365 s of CPU, 3.50 GB peak;
# expand_label 364 properties, 1828 s wall and 1375 s of CPU, 3.61 GB.
launch slow full hkdf384_expand 130 "hkdf_expand.0:5,fill_nondet.0:209,ct_wipe.0:209" --object-bits 11 ct.c
launch slow full hkdf384_expand_label 130 "hkdf_expand.0:5,fill_nondet.0:209,ct_wipe.0:209" --object-bits 11 ct.c
# These three prove aead.c's framing against the contract stubs in
# proof/aead_stubs.h rather than compiling chacha20.c and poly1305.c into
# every formula. Concretely they returned no verdict in five hours a night;
# measured now: 3 s, 2 s and 2 s. What the stubs model, and what moved from
# proof to argument, is written at the top of that header
# (https://github.com/c4milo/chapulin/issues/56).
launch fast full aead 85 "fill_nondet.0:65" ct.c
launch fast full aead_overlap 85 "fill_nondet.0:65" ct.c
launch fast full aead_forge 85 "fill_nondet.0:65" ct.c
# aead_inplace has no launch line: its formula returned no verdict in an
# hour under kissat (3.8 GB and climbing), and an unconverged launch line
# proves nothing (docs/proofs.md). The harness is written and reviewed, so
# adding the line is the whole job once the formula converges.
launch slow:5 noovf x25519 65 "" ct.c
launch slow:5 noovf x25519_mul_alias_a 65 ""
launch slow:5 noovf x25519_mul_alias_b 65 ""
launch slow:5 noovf x25519_mul_inputs_alias 65 ""
launch slow:5 noovf x25519_sqr 65 ""
# The two drivers, over the record reader's contract: b7cf0f3 stubbed the
# reader and the formulas converge (https://github.com/c4milo/chapulin/issues/37).
# The nightlies of 2026-09-02 proved handshake_pin (1673 properties, 245 s
# and 274 s on two runs) and handshake_psk (1671 properties, 1743 s). A
# second handshake_psk run that evening failed at the runner's memory
# limit, 10 GB resident on a 16 GB machine
# (https://github.com/c4milo/chapulin/issues/140).
#
# ct_wipe.0 is 449: ch_handshake wipes the whole handshake_state, and
# sizeof(handshake_state) is 448 against a global unwind of 100. fill_nondet.0
# is 618: send_client_hello passes sizeof t->tx - REC_HDR, which is 617, and
# the ClientHello stub fills all of it. Both bounds were short or absent until
# https://github.com/c4milo/chapulin/issues/37 stubbed the record reader; the
# driver returned no verdict before that, so the unwinding assertions never
# ran. fill_buf_nondet.0 is 97: the record reader's stubs fill at most the
# 96-byte receive buffer, and both lengths they fill are symbolic to symbolic
# execution, so that loop unrolls to its bound on every message and needs a
# bound of its own (the harness says why).
#
# The psk leg sat at the nightly runner's memory limit
# (https://github.com/c4milo/chapulin/issues/140) because the ClientHello stub
# filled a symbolic n <= 617 bytes, 618 guarded array updates per call that the
# formula kept, and the reader's fills shared that 618 bound. Measured under
# this script's flags (kissat; /usr/bin/time -l plus a 1 s RSS sampler of cbmc
# and its kissat child, on a 10-core M1 Pro running other proofs), before and
# after: psk 1671 properties, 1462 s, cbmc 5.9 GB, kissat 5.9 GB, then 1683,
# 231 s, cbmc 1.6 GB, kissat 7.8 GB; pin 1673, 415 s, cbmc 5.9 GB, kissat
# 4.2 GB, then 1685, 55 s, cbmc 1.1 GB, kissat 2.2 GB. In the pinned
# ubuntu-24.04 container (cbmc 6.11.0, kissat 4.0.4, VmHWM from /proc) the psk
# leg now takes 191 s at cbmc 1.9 GB and kissat 3.7 GB, 5.6 GB together, where
# the runner measured 10 GB of cbmc alone. kissat's peak on this one formula
# has been 3.7, 5.7 and 7.8 GB across three solves, so the tier's 12 GB default
# weight stays.
# handshake_flight.c joins both lines because the flight handlers moved
# there out of handshake.c, which these harnesses still include whole.
# Re-measured under this script's flags with the handlers external
# (kissat, PROVE_NO_CACHE=1 /usr/bin/time -l, 10-core M1 Pro, one formula
# at a time): psk 1784 properties in 195 s at 3.78 GB resident, pin 1786
# in 48 s at 1.73 GB, where the numbers above read 1683 in 231 s and 1685
# in 55 s.
# The property counts move because the six wipes hsf_derive_handshake_secrets
# gained are six more objects to check.
# The drivers now take the Certificate fork from ch_tls.psk_selected, and
# the harness asserts what the session reports: a PSK session that
# connects has psk_selected set, and a pinned one never does
# (docs/decisions.md 55). Measured the same way on 2026-09-24, with other
# lanes' work on the machine: psk 1809 properties in 147 s at 5.94 GB, pin
# 1811 in 41 s at 3.69 GB, the peak being kissat's, which has varied as
# much between solves of one formula before. The psk assertion still holds
# with decline_psk's refusal removed, because a PSK configuration carries
# no pin and check_certificate_verify then verifies nothing, so no
# declined session connects either way; bin/unit's handler row is what
# catches that mutant (inv14-raw-accepts-declined-psk).
# The key schedule then took a hash length, the transcript became
# ch_transcript, and hsr_restart_transcript joined the stubbed record
# reader as a contract stub that transcript384 proves (docs/decisions.md
# 58). Measured the same way on 2026-09-24: psk 1808 properties in 179 s
# at 4.76 GB, pin 1810 in 41 s at 3.55 GB.
launch slow full handshake_psk 100 "fill_nondet.0:618,fill_buf_nondet.0:97,ct_wipe.0:449" handshake_auth.c handshake_flight.c buf.c ct.c
launch slow full handshake_pin 100 "fill_nondet.0:618,fill_buf_nondet.0:97,ct_wipe.0:449" handshake_auth.c handshake_flight.c buf.c ct.c
# ML-KEM's chained-product functions, one formula each; the inverse
# NTT is two half formulas, because the whole transform returns no
# verdict in 900 s (the mlkem comment below states the split and the
# measured peaks).
launch slow:5 full mlkem_ntt 260 ""
launch slow:4 full mlkem_invntt_low 260 ""
launch slow:4 full mlkem_invntt_high 260 ""
launch slow:5 full mlkem_basemul 260 ""
# Measured kissat-path peaks (macOS /usr/bin/time -l, RSS): handshake_parser
# 9.9 GB when its weight was set (4aa2eb7), sha256 5.7 GB — both above
# the default weight and cap. handshake_parser's unwindset carried
# main.0:600 from the first version of its harness, whose main looped;
# c8e3c79 removed the last of those loops and kept the entry. The
# model's loops are fill_nondet.0, hsp_parse_server_hello.0 and
# memcmp.0 (`cbmc --show-loops`), so the entry bounded nothing and is
# gone (https://github.com/c4milo/chapulin/issues/136). Measured without
# it: 663 properties, 58 s, 4.6 GB, and 656 properties, 63 s, 4.0 GB
# once the EncryptedExtensions parser left handshake_parser.c for
# handshake_parser_ee.c. The weight stays at 10: the address-space cap
# it sizes applies on Linux only, where this formula was not
# re-measured.
launch fast:10 full handshake_parser 260 "hsp_parse_server_hello.0:66" handshake_parser.c buf.c
# The same harness in the client that offers both cipher suites
# (docs/decisions.md entry 45): cipher_suite may carry AES-128-GCM there,
# and the harness asserts an accepted message carries one of the two
# offered suites. -DCH_AES_HW and -DCH_NATIVE_AES answer ct.h's refusal of
# the suite define; the parser runs no cipher, so no AES source is
# compiled. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l
# over this script, a spec build running beside it): 761 properties, 76 s,
# 4.5 GB peak, the parent's shape, and 675 properties, 65 s, 4.1 GB once
# the EncryptedExtensions parser left handshake_parser.c. The same
# formula with an assert that no accepted message carries AES-128-GCM
# fails it (1 of 762), so that arm is reached. -DCH_TRUST_WEBPKI now
# compiles the two-group key_share arms too, the x25519 share and the
# hybrid one (docs/decisions.md entry 53), and the formula grew to 719
# properties, 128 s, 5.1 GB peak (the same command, nothing beside it).
# With TLS_AES_256_GCM_SHA384 as a third offered suite (docs/decisions.md
# entry 58): 719 properties, 93 s, 4.45 GB peak.
launch fast:10 full handshake_parser_suite 260 "hsp_parse_server_hello.0:66" handshake_parser.c buf.c -DCH_SUITE_AES_GCM -DCH_TRUST_WEBPKI -DCH_AES_HW -DCH_NATIVE_AES
launch fast full eeparse 260 "hsp_parse_encrypted_exts.0:66" handshake_parser_ee.c buf.c
launch fast full certparse 260 "" handshake_parser.c buf.c
# The eeparse lines compile handshake_parser_ee.c, which holds the
# EncryptedExtensions parser alone; the certparse, certverify and
# handshake_parser lines compile handshake_parser.c, which holds the
# other three parsers.
#
# The TRUST=webpki arms of the same two parsers, at the same 256-byte
# bound: EncryptedExtensions admitting one empty server_name
# acknowledgement when the ClientHello sent server_name and one
# server_certificate_type from the certificate types it offered, and
# writing decode_error for either one of the wrong length, and
# CertificateVerify admitting three schemes, with certparse_webpki
# asserting that an accepted scheme is one of them (the assertion fails
# when one of the three is struck from it, so it is reached). Both
# eeparse harnesses assert the alert contract: the parser keeps the seed
# or writes unsupported_extension, and the webpki arm may also write
# decode_error and illegal_parameter. eeparse_webpki draws whether
# server_name was sent and the certificate type offer over every value,
# and asserts that an accepted certificate type is the caller's seed or
# one the offer holds; with the offer check replaced by a check against
# both types this client knows, the formula fails that assertion (1 of
# 544), so it is reached. It drives the block with an empty ALPN offer,
# the shape a caller that skips ALPN configures, and asserts that the
# parser then reports no selection; eeparse_alpn below proves the arm
# that reads an offered protocol. -DCH_TRUST_WEBPKI is on the launch
# line because handshake_parser_ee.c is its own translation unit.
# Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over
# this script, one harness at a time): eeparse_webpki 550 properties,
# 132 s and 128 s over two runs, peaking at 2.6 GB and 5.9 GB, which its
# weight records. The ALPN and certificate type arms sit inside the
# per-extension read, so their formulas ride along on every extension,
# and the certificate type arm took the time up from 61 s. eeparse 378
# properties, 34 s, 2.1 GB, inside the fast tier's default weight;
# certparse 525 properties, 0.7 s, 36 MB; certparse_webpki 532
# properties, 0.6 s, 36 MB.
launch fast:6 full eeparse_webpki 260 "hsp_parse_encrypted_exts.0:66" -DCH_TRUST_WEBPKI handshake_parser_ee.c buf.c
# eeparse_alpn: the ALPN arm (RFC 7301 §3.2) at the offer bound
# ch_connect admits — CH_ALPN_MAX names of up to CH_ALPN_NAME_MAX bytes,
# every byte and every length symbolic — over any extension body up to
# 40 bytes. It asserts the selection contract on top of memory safety:
# an accepted body names a protocol the offer holds, a refused one
# leaves the caller's CH_ALPN_NONE, and the alert is the seed or one of
# the arm's two. It reaches the static parse_alpn by including
# handshake_parser_ee.c, so buf.c is its whole dependency line. Driving the
# same offer through the whole EncryptedExtensions loop instead
# multiplies the two bounds: at a 256-byte message that formula reached
# the SAT solver after 21 minutes with no verdict, and at 48 bytes it
# verified once at 14.7 GB and then lost its solver to the machine's
# memory. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l over this script): 616 properties, 4 s, 414 MB, and
# 552 properties, 5 s, 377 MB once it included handshake_parser_ee.c
# rather than handshake_parser.c.
launch fast full eeparse_alpn 260 "parse_alpn.0:9,memcmp.0:33" -DCH_TRUST_WEBPKI buf.c
launch fast full certparse_webpki 260 "" -DCH_TRUST_WEBPKI handshake_parser.c buf.c
# certverify_webpki: the arm that reads what certparse_webpki parsed.
# The scheme must be the one the leaf key's family can produce, and only
# the P-384 scheme's signed content takes SHA-384. Both rules run over
# every scheme value and every leaf key byte, which the vectors in
# test/webpki_auth_vectors.h sample at three families. The record
# reader, the hashes and the three verifiers are stubs the harness
# defines; handshake_record, sha256, sha512 and the three verifier
# harnesses prove them. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l over this script, one harness at a time): 766
# properties, 3.4 s, 44 MB, well inside the fast tier's default weight.
# main never reaches the SPKI pin half of hsa_server_auth, so the log
# names no callee without a body for webpki_verify_raw_key,
# webpki_verify_leaf_pin or webpki_path_pinned; webpki_pin and
# webpki_leaf_pin prove them. Re-measured when webpki_server_key took the
# leaf pin call: 802 properties, 1.6 s, 45 MB.
# Each of the three inv14-webpki-certificate-verify violations fails a
# named assertion here as well as bin/webpki_auth_test.
launch fast full certverify_webpki 260 "fill_nondet.0:513" -DCH_TRUST_WEBPKI handshake_parser.c buf.c
# webpki_ticket: the resumption rule of a TRUST=webpki client
# (webpki_ticket.h), at a hostname of up to CH_HOSTNAME_MAX bytes and up
# to CH_WEBPKI_ANCHOR_MAX anchors, over every PSK field NULL or set. buf.c,
# ct.c and hkdf.c are real; SHA-256 is the contract stub in harness.h,
# which the harness comment prices. The unwindset bounds the hostname
# loop at 254, the anchor loop at 13 and the pin loop at 5, because symex
# cannot read those bounds from the harness's assumptions; loop 0 is
# CH_ASSERT's do-while. ct_wipe clears hkdf.c's 112-byte SHA-256
# context. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l over this script): 942 properties, 9 s, 149 MB. The
# same formula with its verdict assertion narrowed to an unset config
# fails, so the formula reaches the ticket path.
launch fast full webpki_ticket 66 "fill_nondet.0:254,webpki_ticket_config_hash.1:254,webpki_ticket_config_hash.2:13,webpki_ticket_config_hash.3:5,ct_wipe.0:113" --object-bits 10 -DCH_TRUST_WEBPKI buf.c ct.c hkdf.c
launch slow:6 full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
# SHA-512 splits as ML-KEM does: the framing over a stubbed compression,
# and the compression alone. One formula carrying both hashes and the
# real compression returned no verdict in 43 min at a 12.9 GB peak; the
# sha512 path alone with the real compression verified in 1308 s at
# 15.3 GB, above the nightly runner's memory. The compression's cost was
# never its own: over any state and block it proves in under a second.
# The framing harness — both hashes, the compression stubbed — first
# closed in seven hours at 10.2 GB with sha256.c's padding idiom, which
# routes each pad byte through update; written flat into the pending
# block (sha512.c's finalize) it closes in nine minutes. Measured after
# the split (cbmc 6.11.0, kissat, /usr/bin/time -l): sha512_compress
# 0.5 s / 24 MB, 259 properties; sha512 536 s / 2.0 GB, 417 properties.
launch fast full sha512_compress 3 "main.0:9,fill_nondet.0:129,sha512_compress.0:17,sha512_compress.1:65,sha512_compress.2:81,load_be64.0:9"
launch slow:3 full sha512 3 "fill_nondet.0:193,sha512_update.0:130,sha512_update.1:3,sha512_update.2:130,sha512_final.0:9,sha384_final.0:7,sha512_compress.0:9,store_be64.0:9,finalize.0:130,finalize.1:130"
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
# and in-place-open shapes joined the formula. With rec_dir's suite and
# its key and IV derived at the suite's hash (docs/decisions.md entry
# 58): 435 properties, 596 s, 3.88 GB peak (arm64 macOS, cbmc 6.11.0,
# kissat, PROVE_ONLY=record PROVE_NO_CACHE=1 /usr/bin/time -l).
launch slow:4 full record 165 "" ct.c
# record_suite: rec_dir_init_suite, rec_dir_update and one seal and one
# open in the -DCH_SUITE_AES_GCM build, over each of the three suites,
# with hkdf, the ChaCha20 AEAD and the AES-GCM traffic entries stubbed to
# their contracts; the stubs assert the suite's hash and key length.
# Measured (arm64 macOS, cbmc 6.11.0, kissat, PROVE_ONLY=record_suite
# PROVE_NO_CACHE=1 /usr/bin/time -l): 579 properties, 30 s, 0.59 GB peak.
# rec_dir_update deriving at SHA256_LEN under every suite fails the hash
# assertion, and an AES dispatch that names AES-128-GCM alone fails the
# seal and open assertions, so both properties are reached.
launch fast full record_suite 250 "" ct.c -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
# The x25519 ladder keeps its limbs inside the range the field-op proofs
# assume (https://github.com/c4milo/chapulin/issues/50). x25519_step
# proves one loop step on the shipped step(): from any state with
# every limb in (-2^17, 2^17), the step hands mul only operands under
# 2^18 and lands back inside the bound, so the 255 steps follow by
# induction. x25519_tail proves mul's output form, one invert round and
# the final multiply and pack from the same bound. Both replace mul's
# multiply with the magnitude contract in proof/x25519_stubs.h, which
# x25519_mul discharges: the step over the real products had no verdict
# past 14 GB, and even with the contract, one formula holding the step
# and the tail together had none after 27 minutes, so they are two.
# Measured (kissat): x25519_step 473 properties, 513 s, 2.6 GB;
# x25519_tail 458 properties, 156 s, 2.6 GB.
launch slow:3 full x25519_step 17 ""
launch fast:3 full x25519_tail 17 ""
launch fast full rsa 385 "fill_nondet.0:385,ct_memeq.0:33,greater_or_equal.0:385,modulus_bits.0:385,modulus_bits.1:9,mgf1.0:12,emsa_pss_verify.0:352,emsa_pss_verify.1:320,rsa_pss_verify.0:385" --object-bits 11 --max-field-sensitivity-array-size 385 ct.c
# rsa_webpki is the same harness with CH_TRUST_WEBPKI set, so
# CH_RSA_MODULUS_MAX is 512 (RSA-4096, the bound the webpki build
# accepts): every bound above grows from the 384-byte width to the
# 512-byte one, and the field-sensitivity size follows. Measured (cbmc
# 6.11.0, kissat, /usr/bin/time -l): 250 properties, 70 s, 595 MB for
# cbmc and 89 MB for kissat.
launch fast full rsa_webpki 513 "fill_nondet.0:513,ct_memeq.0:33,greater_or_equal.0:513,modulus_bits.0:513,modulus_bits.1:9,mgf1.0:16,emsa_pss_verify.0:480,emsa_pss_verify.1:448,rsa_pss_verify.0:513" --object-bits 11 --max-field-sensitivity-array-size 513 ct.c
# rsa_pkcs1 is rsa's shape without the alignment pins: v1.5 fills every
# em_len byte, so the modulus stays wholly nondet and one call per
# admitted digest length runs the encode-and-compare end to end over the
# same rsa_vp1 stub. Measured (cbmc 6.11.0, kissat, /usr/bin/time -l):
# 321 properties, 9.8 s, 105 MB.
launch fast full rsa_pkcs1 385 "fill_nondet.0:385,ct_memeq.0:385,ct_wipe.0:385,greater_or_equal.0:385" --object-bits 11 --max-field-sensitivity-array-size 385 ct.c
# rsa_pkcs1_webpki: the same harness at the 512-byte bound, as rsa_webpki
# is to rsa. Measured (cbmc 6.11.0, kissat, /usr/bin/time -l): 321
# properties, 17 s, 154 MB for cbmc and 84 MB for kissat.
launch fast full rsa_pkcs1_webpki 513 "fill_nondet.0:513,ct_memeq.0:513,ct_wipe.0:513,greater_or_equal.0:513" --object-bits 11 --max-field-sensitivity-array-size 513 ct.c
launch fast full p256 85 "" buf.c
# p256_field is the constant-time twin, and it proves more than p256 does
# because the arithmetic is written as masks: every masked choice against
# a reference that branches, the field contract on add, subtract and
# negate, the three predicates, the byte round trip, and memory safety
# over full-range limbs in every aliasing shape a point routine uses. The
# Montgomery product is memory-safe here and nothing asserts its value --
# equality of multipliers is the hard SAT instance (docs/proofs.md) -- so
# its value rests on test/p256_field_test.c and its carry chain on the
# p256_mul lemma below. Measured (cbmc 6.11.0, kissat, /usr/bin/time -l):
# 524 properties, 4.7 s, and 64 MB of cbmc, the higher of two runs.
launch fast full p256_field 34 ""
# p256_scalar is the signer's arithmetic mod the group order, and it
# proves what p256_field's twin proves one modulus over: every masked
# choice against a reference that branches, the two predicates, the byte
# round trip, and the two contracts p256_sign.c rests on -- that
# p256_scalar_reduce lands ANY 256-bit value below n, which is what makes
# a message hash a valid z and an x coordinate a valid r, and that
# p256_scalar_add leaves a scalar. The Montgomery product is memory-safe
# here and nothing asserts its value: equality of multipliers is the hard
# SAT instance (docs/proofs.md), so its value rests on
# test/p256_sign_test.c. p256_scalar_inverse is not called -- 512
# Montgomery products in one formula return no verdict -- and only its
# exponent index expressions are proven in bounds, which is what the
# unwindset below bounds at 257. Measured (cbmc 6.11.0, kissat,
# /usr/bin/time -l): 483 properties, 4.6 s, and 60 MB of cbmc, the higher
# of two runs.
launch fast full p256_scalar 34 "prove_exponent_index_bounds.0:257"
# p256_point is the complete addition and the affine reader over the
# field stubs in proof/p256_field_stubs.h, the layering hkdf_harness.c
# uses: one addition runs 14 Montgomery products and a formula that
# unrolled them would return no verdict. It covers all four aliasing
# shapes, including both inputs the same object, which is the doubling
# the ladder performs and the shape a formula that wrote a coordinate
# before its last read would get wrong. ct.c is on the line because
# p256_point_affine wipes its inverse. Measured (cbmc 6.11.0, kissat,
# /usr/bin/time -l): 176 properties, 2.2 s, and 40 MB of cbmc.
launch fast full p256_point 34 "" ct.c
# p256_point_ladder is one round of p256_point_mul over the same field
# stubs, on the shipped ladder_round rather than a copy, for any scalar,
# any three points and any bit index in [0, 255]: the index and the shift
# the round reads the scalar with are proven in bounds, and the mask the
# round builds is 0 or all ones at every cswap, which is the ladder's
# whole constant-time claim. The loop in p256_point_mul calls nothing but
# this round, 256 times, and carries the proof the way ladder() carries
# x25519's step(). The 256 rounds unrolled in one formula returned no
# verdict in 42 minutes. Measured (cbmc 6.11.0, kissat, /usr/bin/time -l):
# 152 properties, 0.4 s, and 26 MB of cbmc.
launch fast full p256_point_ladder 34 ""
# p256_sign is the RFC 6979 generator and the DER writer with the
# arithmetic stubbed by proof/p256_scalar_stubs.h and
# proof/p256_point_stubs.h, the layering hkdf_harness.c uses: the real
# p256_sign runs 512 complete point additions and a formula that unrolled
# them would return no verdict. The stubs havoc every candidate nonce, so
# the proof covers every acceptance pattern the four candidates can have,
# including none of them. Two claims beyond memory safety: the generator
# spends the same number of HMAC calls whatever those candidates were,
# which is the constant-time claim p256_sign.h makes about the retry, and
# the DER writer stays inside P256_SIG_MAX and writes a minimal INTEGER
# for every pair of 32-byte scalars. Measured (cbmc 6.11.0, kissat,
# /usr/bin/time -l): 791 properties, 36 s, and 1.2 GB of cbmc.
launch fast:3 full p256_sign 100 "" buf.c ct.c
# p256_ecdh is the three public entries over the scalar and point layers
# stubbed to their contracts, proof/p256_scalar_stubs.h and
# proof/p256_point_stubs.h, which p256_sign shares: memory safety over any
# 65 peer bytes and any 32 scalar bytes, that each entry answers 0 or 1,
# and that a refusal leaves no private key, no public key and no shared
# secret behind, for every verdict the stubbed arithmetic can give. The
# ladder and the point decode are p256_point's, so nothing here unrolls
# them; a harness that did returned no verdict in 854 s. Measured (cbmc
# 6.11.0, kissat, /usr/bin/time -l): 284 properties, 1.4 s, and 27 MB of
# cbmc.
launch fast full p256_ecdh 100 "" ct.c
# webpki_spki: webpki_read_spki over any bytes up to CH_WEBPKI_CERT_MAX,
# with the real DER primitives, rbuf and ct_memeq, at the webpki
# CH_RSA_MODULUS_MAX of 512. x509_der.c is its own translation unit on
# the line because webpki_spki.c has a static of the same name.
# Measured (cbmc 6.11.0, kissat, /usr/bin/time -l): 977 properties,
# 16 s, 2.1 GB.
launch fast:3 full webpki_spki 22 "fill_nondet.0:3073" -DCH_TRUST_WEBPKI x509_der.c buf.c ct.c
# webpki_sigalg: webpki_read_sigalg concrete at the same bound, and
# webpki_verify's dispatch over any certificate and signer with the two
# hashes and the three verifiers stubbed to their headers' contracts.
# The global unwind of 50 covers the stubs' 48-byte memcmp. Measured
# (cbmc 6.11.0, kissat, /usr/bin/time -l): 1392 properties, 10 s, 1.1 GB.
launch fast:2 full webpki_sigalg 50 "fill_nondet.0:3073" -DCH_TRUST_WEBPKI x509_der.c buf.c ct.c
# p384 is p256's harness at twelve limbs: the same concrete pieces, the
# same two loop drivers left to their proven bodies, sig up to 112 bytes
# (a valid one is at most 104), the bit walk over [0,383]. Measured (cbmc
# 6.11.0, kissat, /usr/bin/time -l): 975 properties, 46 s, 410 MB.
launch fast full p384 113 "" buf.c
launch fast full hkdf 120 "" ct.c
# hkdf384: the hmac and extract leg under CH_HASH_SHA384, with keys up
# to 160 bytes, one past SHA-512's 128-byte block plus 32, and extract's
# hash_len free over the two values the dispatcher takes. Measured the
# way the expand lines above were: 347 properties, 6 s, 0.10 GB peak.
# The SHA-256 leg on the line above measured 282 properties, 2 s,
# 0.04 GB after hash_len joined the signatures.
launch fast full hkdf384 170 "fill_nondet.0:209,ct_wipe.0:209" ct.c
# io: 458 s under this script's own flags. The transport shim over the
# caller's callbacks, proven against a recv that honours no contract: it
# returns any int, so read_exact's got <= 0 || got > n is under proof
# rather than assumed. The 16-byte buffer bounds its per-byte loop, which
# is what sets the unwind.
launch slow:4 full io 24 ""
# keysched: 13 s under this script's own flags. Extract and Expand-Label sequencing
# over 32-byte secrets; sha256 is harness.h's stub, since the schedule's
# arithmetic is length handling rather than compression.
launch fast full keysched 120 "" ct.c
# keysched384: the same harness under CH_HASH_SHA384, every secret,
# transcript hash and PSK at 48 bytes. Measured the same way: 359
# properties, 27 s, 0.28 GB peak; the SHA-256 line above measured 294
# properties, 18 s, 0.18 GB after hash_len joined the signatures.
launch fast full keysched384 130 "fill_nondet.0:209,ct_wipe.0:209" ct.c
# transcript384: the transcript's two hashes and hsr_transcript_hash,
# transcript_hash_after and hsr_restart_transcript under CH_HASH_SHA384,
# hash_len free over 32 and 48, with both hashes stubbed to their
# contracts; the SHA-512 context stubs' 208-byte fill sets the unwindset.
# Measured the same way: 434 properties, 5 s, 0.05 GB peak. A synthetic
# message buffer of SHA256_LEN in hsr_restart_transcript fails five
# bounds properties at hash_len 48.
launch fast full transcript384 70 "fill_nondet.0:209"
# The same harness under the EXPORTER axis, which compiles two more ks_
# calls and widens hkdf's label cap from 12 to 32. It would be a second
# launch line rather than a define on the one above for quic_step_ca's
# reason: the two builds serialize different-sized info buffers, and a
# proof at one size does not carry to the other.
#
# No launch line: this formula has not been seen to converge. Measured
# under this script's flags on an arm64 development machine, with the
# same -DCH_EXPORTER -DHKDF_LABEL_MAX=32 ct.c the line would carry: no
# verdict in 10 minutes at 1.4 GB with the label length free over 1..32,
# and none in 7 minutes 50 seconds at 1.16 GB with it fixed at 13 and
# 32 and only the label's bytes, the context length and the output
# length free. The base leg above converges in 13 s, so what costs is
# specific to the two exporter calls and not yet located: strlen over
# free bytes and the wider info copy are the suspects, and neither has
# been measured alone. A line here would hang the fast tier, which is
# the mistake CLAUDE.md names. Until it converges, ks_exp_master and
# ks_exporter are covered by bin/exporter_test's cross-checked vectors
# and refusals, and README says not proved.
# epoch: 0 s, 27 MB. The CA arm's own rules. handshake_ca drives the whole CA
# driver and has no launch line: its header records the runs that returned no
# verdict (https://github.com/c4milo/chapulin/issues/37). handshake_psk and
# handshake_pin run the same driver over the stubbed record reader and
# converge. So this proves the part that is specific to the arm -- the
# verdict matching its reported status, and the stored epoch never moving
# backwards -- and leaves the driver's record reading to handshake_psk and
# handshake_pin.
launch fast full epoch 40 "" ct.c
# Weighted from the measured peak: 694 properties, 2.6 GB RSS in 293 s,
# up from 1.9 GB in 154 s before handle_ticket read the ticket's
# extensions vector, compared rb_left against zero and refused a message
# its fields do not fill (INV-25). Measured again on 2026-09-24 at 211 to
# 226 s and 4.1 to 4.8 GB peak on an M1 Pro, over the slow tier's line
# at the top of this file, so it runs nightly: slow:5 covers that peak.
# With the ks_ calls taking the suite's hash length and the ticket
# carrying psk_len (docs/decisions.md 58): 695 properties, 261 s,
# 4.26 GB peak.
launch slow:5 full handshake_post 132 "handle_post_handshake.0:33,fill_nondet.0:130" --object-bits 11 buf.c ct.c session.c
# The only launch line that builds the hybrid key exchange
# (https://github.com/c4milo/chapulin/issues/47). hybrid_secret over any seed,
# any server ciphertext and any server share, with mlkem and x25519 stubbed to
# their headers' contracts — their own harnesses prove the arithmetic, and
# driving a 2400-byte expansion and 256 symbolic multiplies here would be the
# shape docs/proofs.md says not to build. Re-measured with handshake_flight.c
# beside handshake.c: 639 properties, 2.9 s, 74 MB (kissat), where it read 508
# in 3 s and 78 MB before the handlers moved out of the driver. hybrid_secret
# now wipes the seed h->dz once the dk is expanded from it, and the harness
# asserts all 64 bytes zero on both exits: 641 properties, 3.6 s, 75 MB
# (PROVE_NO_CACHE=1 /usr/bin/time -l over this script). The hybrid ServerHello
# parser stays unproven: the 256-byte handshake_parser bound cannot hold a
# 1,128-byte key share.
launch fast full hybrid_secret 65 "fill_nondet.0:2401,ct_wipe.0:2401" -DCH_KEX_PQ ct.c
# The server's half of the hybrid, and its group choice: srv_kex.c over any
# groups and shares a parsed ClientHello reports, with mlkem_encaps_derand,
# x25519 and ch_rand_bytes stubbed to their headers' contracts, the shape
# hybrid_secret above takes on the client. The harness states the six facts
# it proves beside memory safety, among them the preference, RFC 10024's
# order of the two secrets and the wipes on both exits. Measured (arm64
# macOS, cbmc 6.11.0, kissat, PROVE_ONLY=srv_kex PROVE_NO_CACHE=1
# /usr/bin/time -l over this script, on a machine running other lanes'
# work): 438 properties, 1.4 s, 0.04 GB peak. The same formula with an
# assert of 0 at each of its six arms -- the x25519 share, the hybrid
# share, the refused key, the refused secret and both accepted secrets --
# fails all six, and with srv_kex_secret's two halves swapped it fails
# the two order assertions, so the arms are reached and the order is held.
# With secp256r1 as the third group (docs/decisions.md 63), the three
# p256_ecdh entries stubbed to their contracts and a fill of the 65-byte
# point, measured the same way: 561 properties, 2.7 s, 0.14 GB. A probe
# asserting false at the P-256 share, the refused point and the refused
# P-256 secret fails all three.
launch fast full srv_kex 66 "fill_nondet.0:66,same.0:33,zero.0:65" ct.c -DCH_ROLE_SERVER
# The TRUST=webpki client's three-group rules (docs/decisions.md 63):
# handshake_groups.c with ch_rand_bytes, the P-256 keygen and exchange, and
# x25519 stubbed to their headers' contracts, the srv_kex shape on the
# client. The harness states the six facts it proves beside memory safety.
# Measured (cbmc 6.11.0, kissat, PROVE_ONLY=handshake_groups
# PROVE_NO_CACHE=1 /usr/bin/time -l over this script, M1 Pro): 253
# properties, 1.7 s, 0.04 GB. A probe asserting false in each arm -- the
# cookie retry taken, the retry refused under require_pq, the P-256
# secret accepted and refused, and the x25519 secret refused -- fails all
# five, so every arm is reached.
launch fast full handshake_groups 66 "fill_nondet.0:66,zero.0:65" -DCH_TRUST_WEBPKI ct.c
# The parser half of the hybrid build
# (https://github.com/c4milo/chapulin/issues/47). parse_key_share is driven
# directly because handshake_parser bounds its message at 256 bytes and a
# hybrid key_share extension is 1,128: raising that bound would grow the fast
# tier's heaviest formula (9.9 GB) rather than add a second cheap one. Proves
# two facts. First, what hybrid_secret's harness assumes: on acceptance the
# parser returns a whole readable ciphertext inside the bytes it consumed, so
# this proof discharges that assumption. Second, that the group the parser
# records is the one this build offers, the value ch_tls.group reports and
# cfg.require_pq compares. Measured: 661 properties, 1 s, 207 MB (kissat,
# /usr/bin/time -l over this script), and 648 properties, 1 s, 197 MB once
# the EncryptedExtensions parser left the handshake_parser.c it includes.
launch fast full key_share 1200 "fill_nondet.0:1133" -DCH_KEX_PQ buf.c
# The same arm in the build that offers two groups with a key share for each
# (docs/decisions.md entry 53): -DCH_TRUST_WEBPKI turns on CH_KEX_TWO_GROUPS,
# where a ServerHello may select x25519 with a 32-byte share beside the
# hybrid one, and a retry key_share is refused as in every build. cfg.h
# refuses -DCH_KEX_PQ beside it. The harness states the x25519 shape's
# contract beside the hybrid one. That require_pq refuses an x25519
# selection is hsf_accept_server_hello's check, and bin/webpki_session_test
# tests it; this formula holds the parser alone. Measured (cbmc 6.11.0,
# kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this script): 696
# properties, 1.5 s and 1.6 s in two runs, 0.22 GB peak, where the formula
# with the retry shape the arm no longer accepts measured 704 properties,
# 1.4 s, 0.21 GB. The same formula with an assert of 0 in the x25519 arm
# and in the hybrid arm fails both, so both arms are reached. With
# secp256r1 listed without a share (docs/decisions.md 63) the arm takes two
# more shapes, a ServerHello selecting secp256r1 with a 65-byte point and a
# retry naming secp256r1, which a one-group build still refuses: 740
# properties, 1.3 s, 0.23 GB (PROVE_ONLY=key_share_webpki PROVE_NO_CACHE=1
# /usr/bin/time -l), and a probe in each of the two new arms fails both.
launch fast full key_share_webpki 1200 "fill_nondet.0:1133" -DCH_TRUST_WEBPKI buf.c
# handshake_message.c was the last library source no harness compiled
# (https://github.com/c4milo/chapulin/issues/33). Beyond memory safety this
# checks the constant handshake.c asserts CH_TX_STAGE against: at CH_HELLO_MAX
# the build always succeeds, so the bound is sufficient rather than plausible.
# wbuf is real here — refusing to overflow is its contract, and the point is
# that the builder uses it correctly. fill_nondet.0 is the only loop in the
# goto model (`cbmc --show-loops`): wb_bytes copies with memcpy and has
# none, so the wb_bytes.0 entry this line carried from the day it was
# written matched nothing and is gone
# (https://github.com/c4milo/chapulin/issues/136). Measured: 486
# properties, 3 s, 61 MB (kissat).
launch fast full hello_build 400 "fill_nondet.0:321" buf.c
# hello_build_webpki: the builder's TRUST=webpki arm — the server_name
# extension over any hostname of up to CH_HOSTNAME_MAX bytes and none at
# length 0, the ALPN extension over any offer of up to CH_ALPN_MAX names
# of up to CH_ALPN_NAME_MAX bytes, the five signature schemes, and the
# server_certificate_type offer of SPKI pins, which the harness stubs to
# answer every offer webpki_cert_types_offered can give, and the two key
# shares, the one secp256r1 share of a retry hello, or the hybrid one
# alone under a nondet require_pq (docs/decisions.md entries 53 and 63) —
# against that build's CH_HELLO_MAX of 2396, which the certificate path in
# a resuming hello raised from 2371 (docs/decisions.md 55) and the third
# listed group from 2394. The sufficiency assertion is tight: moved to
# CH_HELLO_MAX - 1 it fails, and a probe asserting false after the
# two-type offer is written
# fails too, so that arm is reached; a probe in each require_pq arm of
# write_two_groups fails both, and so does one asserting that no secp256r1
# retry hello is built. With the retry arm (docs/decisions.md 63):
# 602 properties, 109 s, 0.19 GB (PROVE_ONLY=hello_build_webpki
# PROVE_NO_CACHE=1 /usr/bin/time -l, M1 Pro, other lanes' work on the
# machine). The two ALPN loops carry their own bounds
# because the global 400 unrolled both past the array they walk, and
# CBMC then ran out of addressed objects (--object-bits, 256) rather than
# returning a verdict. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l over this script): 584 properties, 62 s, 170 MB with
# one key share, and 602 properties, 65 s and 88 s in two runs, 160 MB,
# with both. With signature_algorithms and server_certificate_type in the
# pre_shared_key arm too: 602 properties, 79 s, 160 MB, and the assertion
# moved to CH_HELLO_MAX - 1 still fails. An assertion that a PSK hello ends
# with its binders list, which would make pre_shared_key's position a
# proof, returned no verdict in nine minutes at 5.7 GB of kissat, so it is
# not here and the tests hold that order.
launch fast full hello_build_webpki 400 "fill_nondet.0:321,main.0:9,write_alpn.0:9" -DCH_TRUST_WEBPKI buf.c
# x509: primitives concrete (both variants), the walker with stubbed
# primitives. The ECDSA walker proves the full two-entry bound in
# every check; the RSA walker's formula is a SAT heavyweight, so it
# runs in the slow tier at the single-max-RSA-certificate bound.
# Weights are measured peaks (kissat): der 1.4 GB, parse_ecdsa
# 2.4 GB (down from 5.6 with the typed stub stores), parse rsa
# 7.1 GB.
# The provisioning path (https://github.com/c4milo/chapulin/issues/39),
# proved in three pieces because the decoder is the shape bounded model
# checking pays most for: a per-character state machine over symbolic
# bytes, measured at roughly the third power of the input length.
#
# pem_step carries the weight. It proves b64_value against RFC 4648
# section 4's table on all 256 bytes, pad_ok against section 3.5, and
# b64_step's invariant from an ARBITRARY state -- so induction over it
# holds at any length, not just the driver's bound. Measured 0.3 s,
# 25 MB, 550 properties.
#
# pem proves the whole entry at the SHIPPED caps with the input length
# bounded. 64 is the floor: the shortest accepting input is 58 bytes,
# and at 56 the CH_OK arm is unreachable and its assertion passes
# vacuously while the run still says SUCCESSFUL (confirmed by asserting
# 0 there). Measured at 64: 63 s / 1.4 GB rsa, 71 s / 1.5 GB ecdsa, 551
# properties. Higher bounds converge and cost more without covering a
# new shape -- 80 is 195 s / 4.6 GB, 160 is 1348 s / 7.3 GB -- and the
# differential in test/diff_pem.h runs the full range to CH_PEM_MAX
# against the Lean oracle, so the extra bound buys quantum count rather
# than coverage. What no bound here proves is stated in README's
# verification section.
#
# x509ca proves the provisioning walk over any input, with the DER
# primitives stubbed to the contracts x509der proves. Measured 7 s /
# 0.34 GB rsa, 5 s / 0.15 GB ecdsa, 730 properties.
launch fast full pem_step 66 "" buf.c ct.c
launch fast full pem_step_ecdsa 66 "" buf.c ct.c
launch fast:2 full pem 66 "" -DCH_PROOF_PEM_LEN=64 buf.c ct.c
launch fast:2 full pem_ecdsa 66 "" -DCH_PROOF_PEM_LEN=64 buf.c ct.c
launch fast:1 full x509ca 400 "fill_nondet.0:1537" buf.c ct.c
launch fast:1 full x509ca_ecdsa 400 "fill_nondet.0:1537" buf.c ct.c
# The TRUST=webpki pieces that read no certificate. webpki_time proves
# the Time reader over 40 nondet bytes from any reader state and the
# clock packer over every uint64. The packer's order, a later clock
# never packing lower, is left to the Lean model and the differential,
# because asserting it over two nondet clocks returned no verdict in 30
# minutes where the rest closes in seconds (the harness header says
# so). webpki_name proves the hostname shape check at its real
# 253-byte bound, and the per-entry dNSName compare with a 253-byte
# host and a presented name of up to 1024 bytes, the Extension bound;
# fill_nondet.0:1025 unwinds the fill of that name. The walk over a
# whole GeneralNames is webpki_san below, because one formula holding
# both wrote a 7.9 GB CNF at a 64-byte GeneralNames and returned no
# verdict. webpki_san splits that walk the way pem_step and pem split
# the PEM decoder: one entry (read_entry) from any reader state at the
# real 1024-byte GeneralNames bound, and the loop over it at 32 bytes,
# the bound where the unrolled loop converges. The same formula with
# the loop at 64 bytes ran in kissat for 16 minutes with no verdict,
# and before the split the whole walk at 1024 bytes was still
# converting SSA at 30 minutes. The entry's contract, position forward
# by two or more and never past the end, is the induction step that
# extends the loop's proof to any length. Measured (cbmc 6.11.0,
# kissat, /usr/bin/time -l, plus cbmc and kissat resident size summed
# once a second): webpki_time 1065 properties, 4.3 s, 80 MB;
# webpki_name 1019 properties, 171 s, 9.4 GB peak for one process
# (maximum resident set size 9430302720 bytes under /usr/bin/time -l,
# run alone through PROVE_ONLY on 2026-09-16 with no other proof
# beside it). Two earlier readings, 205 s at 4.9 GB for this formula
# and 5.8 GB for the 977-property one, were taken while other proofs
# held 6 GB of swap, and resident size reads low under swap. The
# 9.4 GB reading is above the fast:7 weight the launch line carries;
# webpki_san 975
# properties, 234 s, 2.6 GB for one process and 3.1 GiB summed, which
# fast:4 covers.
launch fast full webpki_time 41 "" buf.c x509_der.c ct.c
launch fast:7 full webpki_name 254 "fill_nondet.0:1025" buf.c x509_der.c ct.c
launch fast:4 full webpki_san 17 "fill_nondet.0:1025,webpki_match_san.0:17" -DCH_PROOF_SAN_LEN=32 -DCH_PROOF_HOST_LEN=16 buf.c x509_der.c ct.c
# The TRUST=webpki certificate parser and its extension walk. Every
# number below is cbmc 6.11.0 with kissat under /usr/bin/time -l on a
# 10-core development machine, measured while other proofs ran beside
# it; "under run.sh" means PROVE_ONLY through this script's own launch.
#
# webpki_cert proves webpki_parse_certificate over any bytes up to one
# past CH_WEBPKI_CERT_MAX and any arm value, with the four readers it
# hands fields to stubbed to the contracts their own harnesses prove and
# the DER primitives real. Under run.sh: 1200 properties, 189 s, 3.7 GB.
# The same formula with an assert of 0 at its CH_OK tail fails that one
# assert (1 of 1201, 300 s, 4.4 GB), so the tail is reached; fast:5
# covers that peak. Re-measured under run.sh when the parser started
# recording the SubjectPublicKeyInfo TLV, which the tail now asserts
# lies inside tbs around the key: 1232 properties, 222 s, 3.2 GB.
#
# The extension walk splits the way webpki_san does, because a harness
# cannot replace its statics with their contracts, so every composition
# unrolls the readers below it. webpki_ext proves the pieces that read
# one element at the real 1024-byte bound (one KeyPurposeId and
# x509_read_extension from any reader state, basicConstraints over any
# extnValue) and the purposes loop at 64 bytes. Under run.sh: 1217
# properties, 386 s, 3.0 GB; run apart, the x509_read_extension half
# peaked at 5.0 GB in 54 s, which slow:5 covers.
#
# webpki_ext_one judges one Extension from any reader and walk state
# over a list of up to CH_PROOF_ONE_LEN bytes: at 64 bytes 249 s and
# 1.6 GB; at 96 bytes 900 s and 2.6 GB, and under run.sh 1217
# properties, 1278 s, 2.4 GB; at 128 bytes no verdict in 31 minutes. So
# it runs at 96 bytes in the slow tier.
#
# webpki_ext_walk runs webpki_read_extensions whole over up to
# CH_PROOF_EXT_LEN bytes read from their first byte. From any reader
# state the walk converged at 32 bytes (314 s, 3.0 GB), where an assert
# of 0 on each arm's success tail showed neither tail reached, and at
# 40 bytes (1583 s, 5.3 GB); at 48 and 64 bytes it returned no verdict
# in 31 minutes, kissat at 7.4 GB in one 64-byte run. From the first
# byte it converged at 48 bytes (1218 properties, 1519 s, 3.0 GB; under
# run.sh 1255 s, 5.0 GB), the first measured bound that holds the leaf's
# shortest accepted field of 47 bytes, and returned no verdict at 64
# bytes in 30 minutes. At 48 bytes an assert of 0 on each arm's success
# tail fails both (2 of 1220, 2687 s, 7.5 GB), so both tails are
# reached. So it runs at 48 bytes in the slow tier.
# Re-measured under run.sh when the reader stubs moved to
# proof/webpki_cert_stubs.h, webpki_parse_certificate took its head from
# read_certificate_head and read_tbs_key, and webpki_read_certificate_key
# joined the file unreached here (docs/decisions.md 65), on an arm64 macOS
# development machine: 1250 properties, 217 s at 3.8 GB with one other
# proof running, 212 s at 5.6 GB beside a differential run, and 217 s at
# 6.2 GB alone. fast:7 covers the highest of those peaks.
launch fast:7 full webpki_cert 17 "fill_nondet.0:3074,ct_memeq.0:16" -DCH_TRUST_WEBPKI x509_der.c buf.c ct.c
# webpki_cert_key proves webpki_read_certificate_key, the reader a leaf
# pinned with no anchor goes through, over the same bytes and the same
# stubs, with x509_skip real for the fields it frames after the key: its
# pointers land inside the certificate as webpki_cert's do, the
# extensions reader never runs, and the fields it does not write keep the
# caller's values. Under run.sh (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l, alone): 1316 properties, 180 s, 4.2 GB, and 176 s at
# 4.4 GB beside a differential run; 55 s at 3.2 GB before the reader
# framed those fields. An assert of 0 at its CH_OK tail fails that one
# assert (210 s, 4.7 GB, beside a cover run), so the tail is reached.
# inv05-webpki-leaf-key-reads-extensions fails it.
launch fast:5 full webpki_cert_key 17 "fill_nondet.0:3074,ct_memeq.0:16" -DCH_TRUST_WEBPKI x509_der.c buf.c ct.c
launch slow:5 full webpki_ext 18 "fill_nondet.0:1026,read_ext_key_usage.0:23,oid_minimal.0:17,ct_memeq.0:9" x509_der.c buf.c ct.c
launch slow:3 full webpki_ext_one 18 "fill_nondet.0:97,read_ext_key_usage.0:33,oid_minimal.0:17,ct_memeq.0:9" -DCH_PROOF_ONE_LEN=96 x509_der.c buf.c ct.c
launch slow:5 full webpki_ext_walk 18 "fill_nondet.0:49,webpki_read_extensions.0:8,read_ext_key_usage.0:13,oid_minimal.0:17,ct_memeq.0:9" --object-bits 11 -DCH_PROOF_EXT_LEN=48 x509_der.c buf.c ct.c
# The TRUST=webpki chain walk, over a CertificateEntry list of up to
# CH_PROOF_LIST_LEN bytes and CH_PROOF_ANCHORS anchors of unconstrained
# bytes, with the five calls it makes stubbed to the contracts their own
# harnesses prove. docs/webpki.md expected this to be the hardest formula
# in the tree; it is not, because the stubs keep every certificate byte
# out of it. What the formula does not say is which chains reach CH_OK:
# the verify and match stubs answer a nondet verdict, so the walk's
# soundness is the Lean model's and the corpus test's, not this proof's.
#
# 48 bytes is the bound: read_entries refuses a zero-length certificate,
# so the shortest entry it accepts is 6 bytes (a 3-byte length, one
# certificate byte, a 2-byte extensions vector) and 48 bytes holds
# exactly eight. Both the CH_WEBPKI_FLIGHT_ENTRIES refusal and the
# CH_WEBPKI_CHAIN_MAX one are inside that. Measured (cbmc 6.11.0, kissat,
# /usr/bin/time -l, these flags): 1103 properties, 105 s, 3.3 GB at 48
# bytes and 2 anchors, re-measured when read_entries' refusal started
# writing its own alert; 1097 properties, 113 s and 3.0 GB before that; 142 s and 6.6 GB at 48 bytes and 3 anchors, and 62
# s and 1.9 GB at 30 bytes. The same formula with an assert of 0 at its
# CH_OK tail fails that one assert (1 of 1098, 133 s, 3.1 GB), so the
# tail is reached. fast:4 covers the peak. Re-measured under run.sh when
# the walk started reporting path_entries and anchor_index and the tail
# started asserting them against the certificates parsed and the anchor
# that verified: 1204 properties, 138 s, 3.6 GB; with an assert of 0 at
# the tail, 1 of 1205 fails (240 s, 2.3 GB, beside another proof).
# Re-measured when webpki.c gained webpki_read_leaf_entry, which this
# formula holds unreached: 1216 properties, 122 s and 5.6 GB alone, and
# 126 s and 7.3 GB beside another proof. The tree before that change
# measured 1204 properties, 131 s and 4.6 GB the same day, so the peak had
# already moved past the 3.6 GB recorded above; fast:8 covers the highest
# peak seen.
launch fast:8 full webpki_chain 49 "main.0:3,fill_nondet.0:49,read_entries.0:7,anchor_verifies.0:3,webpki_verify_chain.0:5" -DCH_TRUST_WEBPKI -DCH_PROOF_LIST_LEN=48 buf.c ct.c
# webpki_pin: the SPKI pin calls of webpki_pin.c (webpki_pin.h). The raw
# public key half runs at its real bound, a list one byte past an entry at
# CH_WEBPKI_SPKI_MAX, so both sides of the entry cap and of the exact fill
# are inside it, under CH_SPKI_PIN_MAX pins or fewer; the path half runs
# over a 24-byte list, CH_WEBPKI_CHAIN_MAX entries of a few bytes and one
# past them, two anchors and any leaf. webpki_read_entry, rbuf and
# ct_memeq are real; webpki_read_spki and webpki_parse_certificate are
# stubs to what webpki_spki and webpki_cert prove, and SHA-256 is
# harness.h's contract with a record of what it hashed. The global unwind
# of 5 bounds the pin loop at CH_SPKI_PIN_MAX and the path loop at
# CH_WEBPKI_CHAIN_MAX; the unwindset covers the list fill and the two
# 32-byte compares. copy_key's one memcpy is a stub to C's contract,
# which also asserts the copy fits webpki_leaf_info.key; the harness says
# why. With the copy's data flow in the formula, copying a key of up to
# CH_WEBPKI_KEY_MAX bytes from any offset of the 556-byte list was 31.1 of
# the raw half's 31.6 million clauses: 1347 properties, 385 s at
# 7.4 GB on arm64 macOS, and on the nightly's Linux runner kissat reached
# its 13 GB address-space cap at 8.1 GB resident. Measured with the stub
# (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1 over this script): 1330
# properties, 24 s at 0.9 GB on arm64 macOS; 26 s on x86-64 Linux, with
# kissat's address space peaking at 0.9 GB. With an assert of 0 at the
# raw half's CH_OK tail and at the path half's tail after a match, those
# two fail, so both tails are reached.
launch fast full webpki_pin 5 "fill_nondet.0:557,ct_memeq.0:33,memcmp.0:33" -DCH_TRUST_WEBPKI webpki.c buf.c ct.c
# webpki_leaf_pin proves webpki_verify_leaf_pin, the rule for a chain
# under SPKI pins alone (docs/decisions.md 65), apart from the other two
# calls, whose formula is near its weight already. The list framing in
# webpki.c is real over a 24-byte list, four one-byte entries and part of
# a fifth, which the global unwind of 6 covers with the framing loop's
# CH_WEBPKI_FLIGHT_ENTRIES and one; webpki_read_certificate_key is a stub
# to what webpki_cert_key proves, and SHA-256 a stub that records what it
# hashed. Under run.sh (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l): 1280 properties, 38 s, 1.7 GB. An assert of 0 at its
# CH_OK tail fails that one assert, so the tail is reached.
launch fast full webpki_leaf_pin 6 "fill_nondet.0:129,ct_memeq.0:33,memcmp.0:33" -DCH_TRUST_WEBPKI webpki.c buf.c ct.c
launch fast:3 full x509der 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch fast:3 full x509der_ecdsa 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch slow:4 full x509parse_ecdsa 260 "fill_nondet.0:257,ct_memeq.0:68" buf.c ct.c
launch slow:8 full x509parse 844 "fill_nondet.0:841,ct_memeq.0:68" buf.c ct.c
launch fast full chacha20 165 "chacha20_xor.1:5"
# The AES-128 forward cipher and the two aes_public_key constructors,
# TRANSPORT=quic-nonblocking. HKDF is a contract stub (proof/aes_stubs.h), so
# this formula holds the key schedule and the cipher and not five HMAC
# derivations; that header states what the composition gives up.
# Re-measured on the commit that moved this file under the codegen gates
# (arm64 macOS, the pinned cbmc, PROVE_NO_CACHE=1 /usr/bin/time -l): 434
# properties, 26 s, 0.67 GB peak. The 377 recorded before predates the
# split of the cipher into quic_aes_soft.c.
launch fast full aes 45 "fill_nondet.0:177" -DCH_TRANSPORT_QUIC_NONBLOCKING
# The software AES-256 reference and the round-count dispatch in
# aes_encrypt_schedule, under -DCH_AES_256_TEST, which only tests and
# proofs define: the key schedule's 52 words, the fourteen rounds and both
# arms of the dispatch over a havocked round count. HKDF is the stub
# the aes harness uses. Measured (arm64 macOS, cbmc 6.11.0, kissat,
# PROVE_NO_CACHE=1 /usr/bin/time -l): 614 properties, 25 s, 0.92 GB peak.
launch fast full aes256 60 "fill_nondet.0:241" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_AES_256_TEST
# The traffic-key constructor a -DCH_SUITE_AES_GCM build compiles, over
# contract stubs of the four AES=hw block entries the harness defines,
# because CBMC cannot read the instructions: both key lengths, the round
# count each writes, and the dispatch that count drives. Measured the
# same way: 140 properties, under 1 s, 0.02 GB peak.
launch fast full aes_traffic 45 "fill_nondet.0:241" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
# The three RFC 9001 §5.1 derivations and the §6.1 key update. HKDF is
# the same contract stub the aes harness uses, so this formula holds the
# framing of the three calls and not four HMAC derivations; ct.c is
# compiled in because quic_keys_update wipes its own copy of the new
# secret. Measured, these flags: 79 properties, 0.24 s, 0.02 GB peak.
launch fast full quic_keys 45 "fill_nondet.0:177" ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING
# quic_keys_suite: the three derivations and the update in the
# -DCH_SUITE_AES_GCM QUIC build, over each of the three suites, with HKDF
# a stub that asserts the suite's hash and key lengths.
# Measured the same way: 141 properties, 1 s, 0.04 GB peak. An update
# that derives at SHA256_LEN under every suite fails two of the hash
# assertions. The one-suite line above measured 106 properties, under
# 1 s, 0.02 GB.
launch fast full quic_keys_suite 60 "" ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
# The RFC 9001 §5.8 Retry tag check. gcm_seal and aes_public_key_retry
# are contract stubs the harness defines, so this formula holds the one
# call's framing and its verdict and not AES-128-GCM; the harness states
# what those stubs assert. ct.c is compiled in because the verdict is
# ct_memeq's. Measured on an idle development machine (arm64 macOS, the
# pinned cbmc, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this
# script): 160 properties, 3.5 s, 0.10 GB peak.
launch fast full quic_retry 70 "fill_nondet.0:177" ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING
# The Initial packet path: both entries over unconstrained lengths, with
# the eight calls they make stubbed to their contracts
# (proof/quic_initial_stubs.h). The cipher, the AEAD and the header
# protection pair are proven by their own harnesses, so this formula
# holds the length refusals and the offsets alone. The unwindset is the
# one the other quic lines carry, because the key schedule an
# aes_public_key holds is what fill_nondet writes most of. Measured on a
# development machine (arm64 macOS, the pinned cbmc, kissat,
# /usr/bin/time -l): 285 properties, 10 s, 0.23 GB peak.
launch fast full quic_initial 40 "fill_nondet.0:177" -DCH_TRANSPORT_QUIC_NONBLOCKING
# RFC 9001 §5.3 packet protection, §5.4 header protection, the §6.5 key
# set selection and the §6.6 limits, over a 40-byte packet with a
# symbolic length and a symbolic packet number offset. ChaCha20 and the
# AEAD are contract stubs inside the harness, which states what that
# gives up; buf.c is compiled in because the header copy is a wb_bytes,
# and ct.c because every path wipes. The unwindset is fill_nondet over
# the three key sets, 132 bytes, which is the only loop past the global
# bound. Measured (cbmc 6.11.0, kissat, /usr/bin/time -l, these flags):
# 923 properties, 9.7 s, 0.23 GB peak. The same formula with an assert
# of 0 at each of its three CH_OK tails fails all three (3 of 926, 4
# iterations), so every tail is reached.
launch fast full quic_packet 65 "fill_nondet.0:133" buf.c ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING
# quic_packet_suite: the same file in the -DCH_SUITE_AES_GCM QUIC build,
# over each of the three suites: the mask, the seal and the Handshake open
# run the cipher the set's suite names at its key length, and the seal
# counts and refuses under AES-GCM's §6.6 limit alone. Every cipher is a
# contract stub, because the AES entries run on the instructions.
# Measured (arm64 macOS, cbmc 6.11.0, kissat, PROVE_ONLY=quic_packet_suite
# PROVE_NO_CACHE=1 /usr/bin/time -l): 1142 properties, 23 s, 0.45 GB peak.
# A header protection key cut to AES_128_KEY under every suite fails the
# key length assertion, and a seal that skips the §6.6 check fails the
# limit assertion, so both are reached. The one-suite line above
# measured 923 properties, 8 s, 0.23 GB after quic_packet_seal lost its
# const.
launch fast full quic_packet_suite 250 "" buf.c ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
# AEAD_AES_128_GCM's memory safety, its all-or-nothing refusal, and
# GHASH on its own. The forward cipher is a contract stub
# (proof/gcm_stubs.h); the unwindset names hash_data and
# counter_mode because both loop on a symbolic count, and without them
# each unwinds to the global 130 and carries 130 copies of SP
# 800-38D's 128-step multiply. The wipe of the running multiple sits
# inside multiply_by_subkey, so the solver carries one 16-byte volatile
# loop per call, and hash_data unwinds to 3 of them. Measured after the
# stub took the name gcm.c calls, aes_encrypt_schedule (arm64
# macOS, the pinned cbmc, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over
# this script, two other processes busy on two of ten cores):
# gcm_safety 388 properties, 416 s, 2.5 GB peak; gcm_refusal
# 393 properties, 34 s, 1.9 GB; ghash 386 properties, 235 s,
# 1.8 GB. The property counts are the ones recorded before 234ec4e.
# gcm_refusal peaked at 0.97 GB at 3ff8517 under the same command,
# so its weight moves from 1 to 2. Measured again under the same command
# after gcm.c gained its AES=hw arm, which these lines do not compile
# because they define no CH_AES_HW, at load averages of 3.4 to 6.0 on ten
# cores: gcm_safety 388 properties, 370 s, 2.6 GB; gcm_refusal
# 393 properties, 33 s, 1.9 GB; ghash 386 properties, 213 s, 1.8 GB.
# Neither proves a functional or authenticity property; the two harnesses
# that state those carry no launch line, below.
launch slow:3 full gcm_safety 130 "fill_nondet.0:177,hash_data.1:3,counter_mode.1:3" --object-bits 11 ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_GCM_PT_MAX=32 -DCH_GCM_AAD_MAX=32
launch slow:2 full gcm_refusal 130 "fill_nondet.0:177,hash_data.1:3,counter_mode.1:3" --object-bits 11 ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_GCM_PT_MAX=32 -DCH_GCM_AAD_MAX=32
launch slow:2 full ghash 130 "fill_nondet.0:257,hash_data.1:17" ct.c -DCH_TRANSPORT_QUIC_NONBLOCKING
launch fast full poly1305 85 "blocks.0:8" ct.c
# The ROLE=server authentication flight: the two slot predicates over
# every SignatureScheme code point, the CertificateVerify signed content
# of RFC 9846 section 4.5.2 at every transcript length the contract
# admits, and both refusals srv_sign_certificate_verify documents.
# SHA-256 is a contract stub, so this formula holds the assembly and the
# selection and not the compression function; no signer exists in this
# tree, so the harness states what stays out of reach. ct.c is compiled
# in because three paths wipe. The global unwind covers fill_nondet over
# the 384-byte signature buffer, which is the longest loop here.
# Measured on an idle development machine (arm64 macOS, cbmc 6.11.0,
# kissat, PROVE_NO_CACHE=1 /usr/bin/time -l through this script): 385
# properties, 8 s, 0.43 GB peak, after srv_select_sigalg moved into
# srv_auth.c; the 223 this line once recorded was stale, because the
# source before that move also measures 385. The same formula with an
# assert of 0 at each of its four tails -- the assembly's wipe, the cap
# refusal, the signing refusal and the provisioned arm of the boot
# check -- fails all four, so every tail is reached.
launch fast full srv_auth 385 "" ct.c -DCH_ROLE_SERVER
# The server's ticket selection and issue, srv_resume.c, over any
# identities and binders lists up to the bounds the harness states, any
# ticket key, clock, modes and ALPN selection, with srv_ticket.c, the key
# schedule and the builders as contract stubs. It is in the slow tier
# because it measured over the fast tier's two minutes and 3 GB: 1017
# properties, 186 s, 4.22 GB peak (arm64 macOS, cbmc 6.11.0, kissat,
# PROVE_ONLY=srv_resume PROVE_NO_CACHE=1 /usr/bin/time -l over this script,
# slow tier). An assert of 0 at the decrypt_error, the refusal, the
# selected-ticket and the sent-ticket arms fails all four, so every arm is
# reached. Before the binders bound fell to one binder and the start of a
# second, the same formula took 268 s and 7.4 GB. With the assertion that
# a selected ticket leaves no signature scheme: 1024 properties, 138 s,
# 4.95 GB, measured the same way on 2026-09-24. With a ticket resumed
# only under a suite of its own hash (docs/decisions.md 58), and the
# selection's hash length set to SHA256_LEN, the one hash this build
# holds: 1046 properties, 143 s, 7.94 GB, measured the same way the same
# day. The peak is the solver's; the nightly runs this proof in a job of
# its own.
launch slow full srv_resume 120 "fill_nondet.0:118,find_ticket.0:24,binder_at.0:36,ct_wipe.0:84,ct_memeq.0:33" buf.c ct.c -DCH_ROLE_SERVER
# gcm and gcm_forge have no launch line, for the reason
# aead_inplace has none: neither formula returned a verdict, and an
# unconverged launch line proves nothing (docs/proofs.md). Measured with
# the flags above, at --unwind 130 and "fill_nondet.0:177": the gcm
# harness ran 2,144 s under kissat with no verdict, and gcm_forge passed ten
# minutes at 2.6 GB resident and climbing. The unwind is what costs: SP
# 800-38D §6.3's multiply is 128 steps per block, gcm_seal and gcm_open
# each run it once per block plus twice more, and both harnesses run the
# whole pipeline twice over symbolic data. Both harnesses are written and
# reviewed, so adding the lines is the whole job once the formulas
# converge -- the likely next step is the split aead needed, one property
# per formula, and a bound below one block.
# The ROLE=server message builders and the HelloRetryRequest cookie. Both
# compile under -DCH_ROLE_SERVER, which is what declares anything in either
# source. buf.c is real in both, because refusing to overflow is the writer's
# contract and the point is that the callers use it correctly; ct.c and hkdf.c
# are real in the cookie, and SHA-256 alone is the contract stub in
# harness.h, which the harness comment prices. The unwindsets name
# fill_nondet over the longest buffer each harness havocs: the cookie at
# SRV_COOKIE_MAX in the builders, and one byte past it in the cookie's own
# open case. Measured on a development machine (arm64 macOS, cbmc 6.11.0,
# kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this script): srv_message 551
# properties, 4 s, 0.14 GB peak, with the ServerHello's pre_shared_key and
# the NewSessionTicket builder; srv_cookie 797 properties, 3 s, 0.07 GB. The
# same srv_message formula with its ServerHello assertion tightened to n < cap
# fails, so the formula reaches the builder rather than passing vacuously.
# The ServerHello now carries either group's share, the 1120-byte hybrid one
# included, into a buffer one byte past SRV_SERVER_HELLO_MAX, and two more
# assertions hold that bound: no ServerHello is longer, and a buffer that long
# always holds one. Measured under the same command: 553 properties, 9 s,
# 0.18 GB peak. With the bound one byte smaller both assertions fail, so it is
# tight in both directions.
launch fast full srv_message 130 "fill_nondet.0:118" buf.c -DCH_ROLE_SERVER
launch fast full srv_cookie 130 "fill_nondet.0:119" buf.c ct.c hkdf.c -DCH_ROLE_SERVER
# srv_select_suite: suite.h's srv_first_offered_suite, the walk
# srv_select runs over the server's order, in the -DCH_SUITE_AES_GCM
# build, over every offer of the three suites and every order of up to
# three code points; the choice is offered, held, in the order, and
# first. Measured the same way: 41 properties, under 1 s, 0.02 GB peak. A
# walk that takes the first suite in the order whether or not the client
# offered it fails three of the assertions.
launch fast full srv_select_suite 5 "" -DCH_ROLE_SERVER -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
# The resumption ticket's seal and open, over every contents and every
# ticket length up to one byte past SRV_TICKET_LEN. buf.c and ct.c are real;
# aead_seal and aead_open are contract stubs the harness defines, which the
# harness comment prices. fill_nondet's longest call is the 105-byte ticket.
# Measured (arm64 macOS, cbmc 6.11.0, kissat, PROVE_ONLY=srv_ticket
# PROVE_NO_CACHE=1 /usr/bin/time -l over this script): 693 properties, 1 s,
# 0.03 GB peak. The same formula with an assert of 0 at the seal's success
# arm and at the open's CH_OK and refusal arms fails all three, so every arm
# is reached.
launch fast full srv_ticket 110 "fill_nondet.0:106" buf.c ct.c -DCH_ROLE_SERVER
# The QUIC server's Retry token, the same shape as the cookie above: buf.c,
# ct.c and hkdf.c real, SHA-256 the contract stub in harness.h, and both
# calls over unconstrained inputs, the address length and the two connection
# ID lengths included. It compiles under both defines, because only a server
# role with TRANSPORT=quic-nonblocking declares anything in quic_token.c. fill_nondet's
# longest call is the stub's 112-byte SHA-256 context, so it unwinds to 113,
# and the harness's four loops over one connection ID unwind to 21. Measured
# on a development machine (arm64 macOS, cbmc 6.11.0, kissat,
# PROVE_ONLY=quic_token PROVE_NO_CACHE=1 /usr/bin/time -l over this script):
# 916 properties, 36 s and 52 s in two runs, 1.02 GB peak. The same formula
# with an assert of 0 at each call's CH_OK tail and refusal tail fails all
# four, so every tail is reached.
launch fast full quic_token 130 "fill_nondet.0:113,prove_mint.1:21,prove_mint.2:21,prove_check.1:21,prove_check.2:21" buf.c ct.c hkdf.c -DCH_ROLE_SERVER -DCH_TRANSPORT_QUIC_NONBLOCKING
# The ROLE=server ClientHello parser, split in two at srv_read_extension,
# the one entry between its files. This line is the readers half: every
# reader in srv_parser_ext.c over an unconstrained extension body, any
# type and any offset, with buf.c and ct.c real and SHA-256 the contract
# stub in harness.h. Measured (arm64 macOS, cbmc 6.11.0, kissat,
# /usr/bin/time -l, idle machine): 927 properties, 34 s, 985 MB. With the
# pre_shared_key reader recording its two lists: 987 properties, 37 s of
# solver time and 0.62 GB, measured at 72 s wall on a machine running
# other lanes' proofs. With supported_groups and key_share reading both
# groups: 1000 properties, 27 s, 0.92 GB (PROVE_ONLY=srv_parser_ext
# PROVE_NO_CACHE=1 /usr/bin/time -l). With secp256r1 as a third group
# (docs/decisions.md 63): 1012 properties, 29 s, 1.05 GB. EXT_MAX keeps a
# body under the 32 bytes of the shortest share, so this formula holds the
# key_share reader's refusals and its walk; bin/srv_test holds each group's
# exact length.
launch fast:2 full srv_parser_ext 26 "fill_nondet.0:129,ct_memeq.0:33" buf.c ct.c -DCH_ROLE_SERVER
# The walk half, proof/srv_parser_walk_harness.c: srv_parser.c real with
# srv_read_extension stubbed to its contract, over any message up to 64
# bytes, which leaves room for five empty extensions after the head.
#
# It had no launch line before docs/decisions.md 59, and the cause was the
# SHA-256 contract stub in harness.h, not the walk. That stub havocs a
# 112-byte context on every call: the formula converged in 0.32 s at 818
# properties with fill_nondet bounded at 97, which is too small to cover
# the context, and returned no verdict in 200 s at 113. The harness now
# keeps SHA-256 stubs of its own that hold no context, because the walk
# never reads it. Making it converge showed two faults in the harness
# itself, both fixed: the reader stub wrote any alert byte, and the refusal
# assertion left out unsupported_extension, which srv_parser_ext.c writes
# for quic_transport_parameters in a TCP build. The stub now writes one of
# the four alerts the readers write and consumes any part of its body.
#
# The cost is the two walks that loop inside a loop: the duplicate check
# reads the block up to each extension, and the frozen digest reads the
# whole block once per covered extension. Before the parser bounded the
# extension count, the formula returned no verdict in 18 minutes at 64
# bytes, and at 60 it took 548 s and 2.25 GB peak beside the
# srv_parser_frozen formula.
#
# The bound changed the cost. The harness takes SRV_CLIENT_HELLO_EXT_MAX at
# 4, and the unwind bounds below hold the count's loop, the duplicate
# check's two loops, the walk and the frozen digest's two loops to four
# extensions, one fewer than a 64-byte message holds. Each unwinding
# assertion fails if its loop ever runs over a fifth extension, which is
# the claim that the count is checked before both walks
# (docs/decisions.md 59).
# Measured under this script's flags (arm64 macOS, cbmc 6.11.0, kissat,
# PROVE_ONLY=srv_parser_walk PROVE_NO_CACHE=1 /usr/bin/time -l, on a
# machine whose load average stood above 40 from other work): 834
# properties, 489 s, 1.34 GB peak. That is still past the fast tier's
# budget, so the nightly keeps its job, and the weight stays 3. With
# srv_ext_over_max moved below srv_ext_duplicate, the unwinding assertion
# of type_before, the duplicate check's inner loop, fails: 1 of 834
# properties, 492 s (test/violations/srv-parser-ext-max-after-duplicate.violation).
# So the formula holds blocks past the bound, and the refusal is what
# keeps them out of both walks. With check_required's supported_versions
# refusal removed, the assertion that an accepted hello carried
# supported_versions fails (420 s; 794 s at 60 bytes before the bound), so
# the formula holds accepted hellos too and does not pass on refusals
# alone.
# parse_head.0 is the one pass over cipher_suites that replaced a
# srv_list_has call per suite (docs/decisions.md 58), at the bound
# srv_list_has.0 had; at the default unwind of 8 its unwinding assertion
# fails. Measured under this script's flags on 2026-09-24: 834 properties, 304 s, 1.20 GB peak.
launch slow:3 full srv_parser_walk 8 "main.0:65,sha256_final.0:33,parse_head.0:33,srv_ext_over_max.0:5,srv_ext_duplicate.0:5,type_before.0:4,srv_parse_client_hello.0:5,next_covered.0:5,add_frozen_extensions.0:5" buf.c ct.c -DCH_ROLE_SERVER
# The frozen digest's walk and the duplicate check under it, over any
# extension block up to 24 bytes, six extensions: the walk reads only
# inside the block, srv_ext_duplicate answers 1 on a whole block exactly
# when two types match, and on a whole block with no duplicate the walk
# hands SHA-256 each covered extension once, whole, in strictly ascending
# type order (docs/decisions.md 59). buf.c and srv_parser.c are real;
# SHA-256 is a stub of the harness's own that records what it is handed.
# Measured the same way, with srv_parser_walk solving beside it for its
# first 548 s: 700 properties, 909 s, 1.85 GB peak; an earlier run beside
# other lanes' proofs took 947 s at 1.72 GB. The cost is the walk: split by
# property at the same 24 bytes, each beside other formulas, memory safety
# alone took 209 s, the duplicate answer alone 51 s and the order and count
# alone 393 s, and all of it at 16 bytes took 161 s. Four mutants of
# srv_parser.c each fail it: the walk in wire order fails the ascending
# assertion (162 s); a pass that keeps the first covered extension at or
# above lowest_type rather than the smallest, and one that takes only types
# strictly above it, fail the count (592 s and 991 s); and srv_ext_duplicate
# over recognized types alone fails the duplicate answer (822 s).
launch slow:3 full srv_parser_frozen 8 "main.0:25" buf.c -DCH_ROLE_SERVER
# srv_ext_over_max, the count that bounds both walks above
# (docs/decisions.md 59), over any extension block up to 24 bytes:
# memory safe, 1 exactly when the block begins with more than
# SRV_CLIENT_HELLO_EXT_MAX whole extensions, and never a header read past
# the one that passes the bound. The harness takes the bound at 3, so six
# empty extensions sit on both sides of it, and the count's loop is bounded
# at four passes: its unwinding assertion fails if the walk reads a fifth
# header. buf.c and srv_parser.c are real. Measured the same way: 565
# properties, 1 s, 0.03 GB peak. Two mutants of srv_ext_over_max fail it:
# the bound one higher fails the loop bound, and with that bound raised to
# 5 it fails the answer; a count that walks the whole block before it
# answers fails the loop bound. Asserting each answer in turn fails both,
# so both are reached.
launch fast full srv_parser_count 8 "main.0:25,srv_ext_over_max.0:4,whole_prefix.0:7" buf.c -DCH_ROLE_SERVER
launch fast full buf 100 ""
# handshake_record on its own, so the two drivers can stub it
# (https://github.com/c4milo/chapulin/issues/37). Before this harness,
# proof-coverage reported the module as covered by handshake_psk and
# handshake_pin alone, and neither returned a verdict, so that coverage was
# nominal. Both drivers converge over the stub now (their launch lines above
# carry the 2026-09-02 numbers), and the reader's own contract is proven here.
#
# The receive buffer and CH_QUIET_CAP are small on purpose: the formula costs
# their product with the fetch bound. Every reader state stays reachable
# because the harness havocs pt_off, pt_len, ccs_seen, quiet and every buffer
# byte on entry rather than walking records to get there. Measured under this
# script's flags: 567 properties, 457 s, 0.99 GB.
# fill_nondet.0 is 113 because hsr_transcript_hash now runs
# transcript_hash_after, whose sha256_update stub havocs the 112-byte
# context copy before sha256_final writes the digest. Measured the same
# way on 2026-09-24 (arm64 macOS, cbmc 6.11.0, kissat,
# PROVE_ONLY=handshake_record PROVE_NO_CACHE=1 /usr/bin/time -l): 597
# properties, 530 s, 3.51 GB peak.
launch slow:4 full handshake_record 65 "hsr_fetch_record.0:6,hsr_next_msg.0:11,fill_nondet.0:113,fill_buf_nondet.0:13" --object-bits 11 -DCH_QUIET_CAP=1 -DCH_PROOF_RXBUF=12
# The TRANSPORT=quic-nonblocking driver and its step table, one formula each, with
# the contract between them written twice: quic_driver stubs
# hsq_advance to what quic_step.h states, and quic_step proves the
# table against that same statement, so a reader checks the pair rather
# than one side. quic_driver compiles the QUIC arm of
# handshake_record.c and all of quic_config.c real, which is what makes
# it the leg proof-cover credits for those two. Each harness says what
# it does not carry.
#
# Measured under this script's flags (kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l, 10-core M1 Pro, one formula at a time on an otherwise
# idle machine): quic_driver 1455 properties, 72 s, 0.84 GB resident,
# and 1461 properties, 78 s of solver time and 0.91 GB after quic_config.c
# took the webpki resumption rule, measured at 116 s wall on a machine
# running other lanes' proofs. After a failure kept the write keys for
# ch_quic_seal_close and the harness proved that call and the failure's
# wipe over havocked key bytes (docs/decisions.md 57): 1525 properties,
# 93 to 95 s of solver time, 103 to 119 s wall at load 10 to 21, 0.97 GB
# resident; the unchanged harness measured 83 s and 0.89 GB on the same
# machine that day. A second assert_dead on the integrity-limit path took
# the formula to 1.54 GB, so that path checks the bits alone;
# quic_step 546 properties, 4.0 s, 42 MB; quic_step_ca 553 properties,
# 4.8 s, 45 MB. After the table took its Certificate fork from
# ch_tls.psk_selected and the harness asserted that fork
# (docs/decisions.md 55): quic_step 559 properties, 3.7 s, 42 MB;
# quic_step_ca 566 properties, 4.6 s, 45 MB. With the fork read from
# cfg.psk instead, quic_step fails that assertion.
# quic_driver carries fast:4 rather than the tier default of 2: the tier
# default caps its address space at 6 GB, and cbmc's virtual footprint on
# this formula runs past that and dies mid-solve at about 70 s, where
# resident size stays under a gigabyte. The CA leg exists because
# hsa_epoch_commit sits behind CH_TRUST_CA and its wipe bound is the
# larger handshake_state that mode carries.
launch fast:4 full quic_driver 5 "fill_nondet.0:257,ct_wipe.0:441,drive.0:8,assert_dead.0:33,zero_bytes.0:133" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PROOF_RXBUF=12 handshake_record.c quic_config.c ct.c
launch fast full quic_step 5 "fill_nondet.0:37,ct_wipe.0:441" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PROOF_RXBUF=12 ct.c
# quic_config_webpki: the configuration rules ch_quic_init applies under
# TRUST=webpki, which are webpki_cfg_ok's plus RFC 9001's, SPKI pins
# included (docs/decisions.md 64). quic_driver compiles quic_config.c
# without CH_TRUST_WEBPKI, so its formula holds the raw arm alone, and no
# other harness compiles webpki_cfg.c. quic_config.c and webpki_cfg.c are
# real; webpki_hostname_ok, webpki_resumption_ok and ct_memeq are
# contract stubs the harness states, proven by webpki_name, webpki_ticket
# and ct. The global unwind of 9 bounds the ALPN loops, whose walk runs
# at most CH_ALPN_MAX times; the unwindset gives the anchor loops 13 and
# the hostname fill 255. Measured under this script's flags (arm64 macOS,
# cbmc 6.11.0, kissat, PROVE_ONLY=quic_config_webpki PROVE_NO_CACHE=1
# /usr/bin/time -l): 557 properties, 1.8 s, 68 MB peak. With the real
# ct_memeq the same formula took 141 s and 2.67 GB. Narrowing the verdict
# assertion to exclude pins alone with no hostname, pins beside anchors
# at both caps, or a presented ticket fails each, so the formula reaches
# all three. inv14-webpki-cfg-resumption-first fails it.
launch fast full quic_config_webpki 9 "fill_nondet.0:255,webpki_resumption_ok.0:13,havoc_anchors.0:13,anchors_ok.0:13" -DCH_TRUST_WEBPKI -DCH_TRANSPORT_QUIC_NONBLOCKING quic_config.c webpki_cfg.c
launch fast full quic_step_ca 5 "fill_nondet.0:37,ct_wipe.0:849" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_CA -DCH_PROOF_RXBUF=12 ct.c
# The ROLE=server public calls and the flight driver above them. The
# fourteen srv_flight.h handlers are contract stubs the harness defines,
# because a handler and the driver that calls it are separate formulas;
# srv_auth.c's two entries are stubs for a second reason the harness
# states, that the real pair signs and verifies with a havocked ch_cfg
# that names no provisioned identity, which would leave this formula
# proving one branch.
#
# Three unwindset entries are what make this formula converge, and each
# one was measured rather than guessed. alpn_ok.0 and
# alpn_name_repeats.0 are 9 because the ALPN walk runs at most
# CH_ALPN_MAX times: alpn_ok refuses a count above it before the loop, so
# the global unwind of 100 was unrolling a nest that can only reach 8 by
# 8, each iteration carrying a 33-deep ct_memeq, and the run had no
# verdict after 13 minutes. fill_names carries the 256-byte ALPN bound on
# a loop of its own, because an unwindset entry bounds a loop and not a
# call site: the same bound on fill_nondet unrolls that loop 256 times at
# the four 32-byte call sites the flight stubs make as well. ct_wipe.0 is
# 521 for the reason the two client drivers give, that the driver wipes
# the whole handshake_state on the way out; a server's is 520 bytes since
# it carries a resumed ticket's instant, the 32-byte ML-KEM shared secret
# of a hybrid key exchange and the 32-byte P-256 scalar of a secp256r1 one
# (docs/decisions.md 63).
#
# Measured under this script's flags (arm64 macOS, the pinned cbmc,
# kissat, PROVE_ONLY=srv_accept PROVE_NO_CACHE=1 /usr/bin/time -l, on a
# development machine running other lanes' work): 871 properties, 32 s,
# 2.39 GB peak, with srv_resume.h's ticket call stubbed beside the
# fourteen handlers, and 871 properties, 35 s, 2.39 GB once ct_wipe.0 rose
# to 489 for the ML-KEM secret, and 871 properties, 29 s, 2.39 GB at 521 for
# the P-256 scalar. The weight is 3 because that peak is over the fast
# tier's 2 GB default.
launch fast:3 full srv_accept 100 "alpn_ok.0:9,alpn_name_repeats.0:9,ct_wipe.0:521,ct_memeq.0:33,fill_names.0:257,fill_nondet.0:33" -DCH_ROLE_SERVER srv.c srv_handshake.c ct.c session.c
# The ROLE=server tcp-nonblocking driver and the inbound framing under it, with
# srv_accept's layering: srv_tcp_nonblocking.c and tcp_nonblocking_frame.c
# real, the fifteen handlers contract stubs. It would cover the step table, the
# record loop and the wipe without resting on a handler.
#
# No launch line: this formula has never been seen to converge either.
# Two loops nest here -- the record loop runs the message loop, which
# runs the step table -- so CBMC unrolls the global unwind squared, and
# step_client_hello's arm calls eight stubbed handlers in a row, each
# answering one of six codes. Measured on an arm64 development machine
# under this script's flags: no verdict in 11 minutes at 1.36 GB with
# 12-byte buffers and --unwind 8, and none in 9 minutes 52 seconds at
# 6.2 GB with 8-byte buffers and --unwind 4, where the second run was
# still growing when it was stopped. A line here would hang the fast
# tier the way the one committed in 657da14 did, which is the mistake
# CLAUDE.md names: a launch line whose formula has not been seen to
# converge proves nothing.
#
# The split it needs is srv_flight's, layered rather than smaller: one
# formula for the step table entered through advance, where no record
# loop wraps it, and one for ch_srv_record_in's framing with the step
# held at a single cheap handler. Neither has been measured, so neither
# is here. Until one lands, srv_tcp_nonblocking.c is covered by
# bin/srv_tcp_nonblocking_test and bin/tcp_nonblocking_loop_test and
# guarded by two .violation mutants, and README says so.
# The ROLE=server flight handlers, with srv_accept's layering turned
# around: the fifteen handlers are real here and everything they call is
# a contract stub, so the two formulas together cover the driver and the
# handlers without either resting on the other's code. ct.c is real,
# because the wipes and the two constant-time comparisons are the
# handlers' own steps. The harness states which three bounds are the
# harness's and not the build's.
#
# The unwindset entries are the loops a global bound would unroll to no
# purpose: ct_wipe and ct_memeq run over 32-byte secrets, fill_nondet's
# longest call is the 117-byte cookie the mint stub writes, and the two
# fragment loops are bounded by the harness's record limit against the
# longest message its builder stubs report.
# No launch line: this formula has never been seen to converge. All
# fifteen handlers are real in one formula, and it returned no verdict
# in 55 minutes at --unwind 40 (1.7 GB), nor in 4 minutes at 20 or 18,
# with the bounds above. The harness is kept because the split it needs
# is layered rather than smaller, the way proof/srv_parser_ext_harness.c
# and proof/p256_ecdh_harness.c divide theirs: one formula per handler,
# or per flight, over the callees stubbed to their contracts. The line
# that stood here was committed in 657da14 without a measurement, which
# is the mistake CLAUDE.md names -- a launch line whose formula has not
# been seen to converge proves nothing -- and it hung the proof tier.
# Until the split lands the handlers are tested by bin/srv_flight_test
# and guarded by four .violation mutants, and README says so.
launch fast full ct 65 ""
# The 16x16 decomposition, which is what every other proof rests on. Those
# formulas verify the single-multiply form, because the launch line above
# asserts CH_NATIVE_WIDEMUL; a target with no constant-time widening multiply
# runs the decomposition instead, so the verdicts carry only if the two forms
# compute the same function. This proves that. UB and shift range at full
# 32-bit width, the products themselves at 8-bit operands -- the same bound
# softmul uses, and for the same reason: multiplier equivalence is the classic
# hard SAT instance. The x25519 ladder proofs ask less of the decomposition,
# a product bound rather than equality, and x25519_mul_ct below proves that
# at the ladder's full operand range. Measured, these flags: 6 properties,
# 31 s.
launch fast:3 full ctwidemul 65 "" -DCH_WIDEMUL_BOUND=0xFFU
# The software multiply, for cores with no multiplier. UB and the fixed
# loop counts over unconstrained 32- and 64-bit inputs; the product
# itself against the C operator only at 8-bit operands, the widest
# bound whose formula converges. Measured: 5 properties, 34 s. The
# harness comment carries the widths that gave no verdict; multiplier
# equivalence is the classic hard SAT instance.
launch fast full softmul 65 ""
launch fast full x25519_mul 20 ""
# The same lemma with ct_widemul_s resolved to the 16x16 decomposition
# firmware ships (the harness defines CH_CT_WIDEMUL), so the product
# bound proof/x25519_stubs.h states is proven on the multiply that runs
# on the target, not only on the native arm x25519_mul compiles
# (https://github.com/c4milo/chapulin/issues/145). A bound is a cheaper
# question than ctwidemul's equality: the product block alone proves in
# 21 s. Measured, these flags: 8 properties, 128 s, 1.7 GB, and 2.1 GB
# summed with kissat, which fast:3 covers.
launch fast:3 full x25519_mul_ct 20 ""
launch fast full x25519_ops 260 ""
# The X25519=wide field, x25519_wide.c, and its ladder (INV-34). Every line
# compiles the field under the two defines ct.h requires of it, and every
# line adds --unsigned-overflow-check. The field computes in uint64_t and
# unsigned __int128, where C defines every wrap, so the checks this script
# passes by default see none of them; with the flag, each column sum, each
# carry between columns, each carry folded in times 19, each doubled or
# scaled limb and each a + 2p - b is a property of its own.
# x25519_wide_mul, x25519_wide_sqr and x25519_wide_ops run the real
# 64x64->128 multiply. x25519_wide_step and x25519_wide_tail run the
# contract in proof/x25519_wide_stubs.h, and x25519_wide_mul128 discharges it
# on the real multiply; x25519_wide_invert runs the whole of invert() over
# it. None of these needs the split the 16-limb field's mul does: a
# 64x64->128 product of operands with their top bits clear converges in
# seconds with every check on. Measured one line at a time with
# PROVE_ONLY=<name> PROVE_NO_CACHE=1 /usr/bin/time -l ./proof/run.sh fast
# (cbmc 6.11.0, kissat 4.0.4, an arm64 development machine under load):
#   x25519_wide_mul128     3 properties, 0.4 s, 20 MB
#   x25519_wide_mul     1448 properties, 3.6 s, 620 MB
#   x25519_wide_sqr     1447 properties, 1.8 s, 287 MB
#   x25519_wide_ops     1598 properties, 1.2 s, 41 MB
#   x25519_wide_step    1494 properties, 3.4 s, 213 MB
#   x25519_wide_tail    1496 properties, 2.1 s, 138 MB
#   x25519_wide_invert  1472 properties, 17.8 s, 2.7 GB, hence fast:3
# One step over the real products instead of the contract also converged,
# in 64 s at 4.5 GB, past what this tier admits; it has no line, and the
# contract's composition is what x25519_wide_step states.
launch fast full x25519_wide_mul128 2 "" -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast full x25519_wide_mul 6 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast full x25519_wide_sqr 6 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast full x25519_wide_ops 256 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast full x25519_wide_step 6 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast full x25519_wide_tail 41 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
launch fast:3 full x25519_wide_invert 101 "" ct.c -DCH_X25519_WIDE -DCH_NATIVE_MUL128 --unsigned-overflow-check
# drbg: ch_drbg_seed hashes a seed of 32 to 96 bytes through the SHA-256
# stub, then wipes the 112-byte context, so the stub's fill_nondet and
# ct_wipe each loop 112 times, past the global bound. Measured (cbmc
# 6.11.0, kissat, /usr/bin/time -l): 131 properties, 23 s, 671 MB.
launch fast full drbg 100 "ch_rand_bytes.3:4,fill_nondet.0:113,ct_wipe.0:113" ct.c
launch fast full p256_mul 20 ""
# p384_mul is p256_mul's carry lemma at twelve limbs. Measured (cbmc
# 6.11.0, kissat, /usr/bin/time -l): 7 properties, 2.1 s, 106 MB.
launch fast full p384_mul 20 ""
launch fast full rsa_mul 20 "fill_nondet.0:385,from_bytes.0:97,main.0:97,to_bytes.0:97"
# rsa_mul_webpki: the marshalling at 128 limbs, the LIMBS_MAX of a
# CH_TRUST_WEBPKI build (RSA-4096); the carry lemma is bound-free.
# Measured (cbmc 6.11.0, kissat, /usr/bin/time -l): 331 properties,
# 2.1 s, 73 MB.
launch fast full rsa_mul_webpki 20 "fill_nondet.0:513,from_bytes.0:129,main.0:129,to_bytes.0:129"
# The signer: the marshalling and every limb helper at 96 limbs, the mask,
# the exponent index and the PSS encoder whole over a stubbed SHA-256,
# plus the CIOS carry lemma. One global unwind of 385 covers all of it --
# the longest loop is fill_nondet over the 384-byte encoded message -- so
# the line carries no unwindset. Measured (cbmc 6.11.0, kissat,
# /usr/bin/time -l, with other jobs on the machine): 759 properties,
# 7 s, 194 MB.
launch fast full rsa_sign 385 "" ct.c

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
    elif grep -q "^loop identifier .* provided with unwindset" "$log"; then
        # cbmc's three warnings for an id that bounds no single loop:
        # "does not match any loop" when the function has no such loop,
        # "for non-existent function" when the model has no such
        # function, and "is ambiguous" when more than one loop matches.
        # A verdict under any of them is not the verdict the launch line
        # claims, so it is neither reported as verified nor cached.
        # cbmc's line names the id.
        echo "FAILED (unwindset names a loop the goto model does not have)"
        grep "^loop identifier .* provided with unwindset" "$log" | sort -u
        FAIL=1
    else
        awk -v w="$wall" '/^\*\* .* failed/ {printf " %s  %s\n", $0, w; exit}' "$log"
        if [ -n "${KEYS[$i]:-}" ]; then
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
