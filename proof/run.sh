#!/usr/bin/env bash
# Runs every CBMC harness through a budget-aware parallel pool. The
# proofs are independent, but each SAT instance can eat gigabytes, so a
# job is admitted by its memory weight against the machine's budget,
# plus a free core; unbounded parallelism would thrash the machine into
# being slower than sequential. The weight is the tier default (fast
# 2 GB; slow 6 GB, or 12 GB under the external solver) unless the launch
# line carries one sized from a measured peak. The biggest measured fast
# peak was handshake_parser at 9.9 GB, so its launch line carries
# fast:10 (its comment records a later 4.6 GB measurement); sha256
# follows at 5.7 GB with fast:6. Each proof checks
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
# the contract bounds (info 64, output 96) stopped the combined formula
# converging in 1800 s. Measured apart (kissat): expand 745 s / 2.2 GB,
# expand_label 747 s / 2.2 GB.
launch slow full hkdf_expand 120 "hkdf_expand.0:5" --object-bits 11 ct.c
launch slow full hkdf_expand_label 120 "hkdf_expand.0:5" --object-bits 11 ct.c
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
# model's loops are fill_nondet.0, hsp_parse_server_hello.0,
# hsp_parse_encrypted_exts.0 and memcmp.0 (`cbmc --show-loops`), so the
# entry bounded nothing and is gone
# (https://github.com/c4milo/chapulin/issues/136). Measured without it:
# 663 properties, 58 s, 4.6 GB. The weight stays at 10: the
# address-space cap it sizes applies on Linux only, where this formula
# was not re-measured.
launch fast:10 full handshake_parser 260 "hsp_parse_server_hello.0:66" handshake_parser.c buf.c
launch fast full eeparse 260 "hsp_parse_encrypted_exts.0:66" handshake_parser.c buf.c
launch fast full certparse 260 "" handshake_parser.c buf.c
# The TRUST=webpki arms of the same two parsers, at the same 256-byte
# bound: EncryptedExtensions admitting one empty server_name
# acknowledgement and writing decode_error for one that carries data,
# and CertificateVerify admitting three schemes, with certparse_webpki
# asserting that an accepted scheme is one of them (the assertion fails
# when one of the three is struck from it, so it is reached). Both
# eeparse harnesses assert the alert contract: the parser keeps the seed
# or writes unsupported_extension, and the webpki arm may also write
# decode_error. eeparse_webpki drives the block with an empty ALPN
# offer, the shape a caller that skips ALPN configures, and asserts that
# the parser then reports no selection; eeparse_alpn below proves the
# arm that reads an offered protocol. -DCH_TRUST_WEBPKI is on the launch
# line because handshake_parser.c is its own translation unit. Measured
# (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this
# script, one harness at a time): eeparse_webpki 611 properties, 61 s,
# 5.1 GB, which its weight records — the ALPN arm sits inside the
# per-extension read, so its formula rides along even where no offer
# lets it run; eeparse 504 properties, 29 s, 2.5 GB, inside the fast
# tier's default weight; certparse_webpki 545 properties, 1 s, 38 MB.
launch fast:6 full eeparse_webpki 260 "hsp_parse_encrypted_exts.0:66" -DCH_TRUST_WEBPKI handshake_parser.c buf.c
# eeparse_alpn: the ALPN arm (RFC 7301 §3.2) at the offer bound
# ch_connect admits — CH_ALPN_MAX names of up to CH_ALPN_NAME_MAX bytes,
# every byte and every length symbolic — over any extension body up to
# 40 bytes. It asserts the selection contract on top of memory safety:
# an accepted body names a protocol the offer holds, a refused one
# leaves the caller's CH_ALPN_NONE, and the alert is the seed or one of
# the arm's two. It reaches the static parse_alpn by including
# handshake_parser.c, so buf.c is its whole dependency line. Driving the
# same offer through the whole EncryptedExtensions loop instead
# multiplies the two bounds: at a 256-byte message that formula reached
# the SAT solver after 21 minutes with no verdict, and at 48 bytes it
# verified once at 14.7 GB and then lost its solver to the machine's
# memory. Measured (cbmc 6.11.0, kissat, PROVE_NO_CACHE=1
# /usr/bin/time -l over this script): 616 properties, 4 s, 414 MB.
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
# /usr/bin/time -l over this script, one harness at a time): 743
# properties, 1.4 s, 44 MB, well inside the fast tier's default weight.
# Each of the three inv14-webpki-certificate-verify violations fails a
# named assertion here as well as bin/webpki_auth_test.
launch fast full certverify_webpki 260 "fill_nondet.0:513" -DCH_TRUST_WEBPKI handshake_parser.c buf.c
launch fast:6 full sha256 3 "fill_nondet.0:97,sha256_update.0:66,sha256_update.1:3,sha256_update.2:66,sha256_final.0:65,sha256_final.1:9,sha256_final.2:9,compress.0:17,compress.1:49,compress.2:65"
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
launch fast:3 full sha512 3 "fill_nondet.0:193,sha512_update.0:130,sha512_update.1:3,sha512_update.2:130,sha512_final.0:9,sha384_final.0:7,sha512_compress.0:9,store_be64.0:9,finalize.0:130,finalize.1:130"
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
launch fast:3 full x25519_step 17 ""
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
# its fields do not fill (INV-25).
launch fast:3 full handshake_post 132 "handle_post_handshake.0:33,fill_nondet.0:130" --object-bits 11 buf.c ct.c session.c
# The only launch line that builds the hybrid key exchange
# (https://github.com/c4milo/chapulin/issues/47). hybrid_secret over any seed,
# any server ciphertext and any server share, with mlkem and x25519 stubbed to
# their headers' contracts — their own harnesses prove the arithmetic, and
# driving a 2400-byte expansion and 256 symbolic multiplies here would be the
# shape docs/proofs.md says not to build. Re-measured with handshake_flight.c
# beside handshake.c: 639 properties, 2.9 s, 74 MB (kissat), where it read 508
# in 3 s and 78 MB before the handlers moved out of the driver. The hybrid ServerHello
# parser stays unproven: the 256-byte handshake_parser bound cannot hold a
# 1,128-byte key share.
launch fast full hybrid_secret 65 "fill_nondet.0:2401,ct_wipe.0:2401" -DCH_KEX_PQ ct.c
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
# /usr/bin/time -l over this script).
launch fast full key_share 1200 "fill_nondet.0:1133" -DCH_KEX_PQ buf.c
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
# extension over any hostname of up to CH_HOSTNAME_MAX bytes, the ALPN
# extension over any offer of up to CH_ALPN_MAX names of up to
# CH_ALPN_NAME_MAX bytes, and the five signature schemes — against that
# build's CH_HELLO_MAX of 1149. The sufficiency assertion is tight:
# moved to CH_HELLO_MAX - 1 it fails. The two ALPN loops carry their own
# bounds because the global 400 unrolled both past the array they walk,
# and CBMC then ran out of addressed objects (--object-bits, 256) rather
# than returning a verdict. Measured (cbmc 6.11.0, kissat,
# PROVE_NO_CACHE=1 /usr/bin/time -l over this script): 575 properties,
# 62 s, 133 MB.
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
# covers that peak.
#
# The extension walk splits the way webpki_san does, because a harness
# cannot replace its statics with their contracts, so every composition
# unrolls the readers below it. webpki_ext proves the pieces that read
# one element at the real 1024-byte bound (one KeyPurposeId and
# x509_read_extension from any reader state, basicConstraints over any
# extnValue) and the purposes loop at 64 bytes. Under run.sh: 1217
# properties, 386 s, 3.0 GB; run apart, the x509_read_extension half
# peaked at 5.0 GB in 54 s, which fast:5 covers.
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
launch fast:5 full webpki_cert 17 "fill_nondet.0:3074,ct_memeq.0:16" -DCH_TRUST_WEBPKI x509_der.c buf.c ct.c
launch fast:5 full webpki_ext 18 "fill_nondet.0:1026,read_ext_key_usage.0:23,oid_minimal.0:17,ct_memeq.0:9" x509_der.c buf.c ct.c
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
# tail is reached. fast:4 covers the peak.
launch fast:4 full webpki_chain 49 "main.0:3,fill_nondet.0:49,read_entries.0:7,anchor_verifies.0:3,webpki_verify_chain.0:5" -DCH_TRUST_WEBPKI -DCH_PROOF_LIST_LEN=48 buf.c ct.c
launch fast:3 full x509der 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch fast:3 full x509der_ecdsa 452 "fill_nondet.0:449,ct_memeq.0:68" buf.c ct.c
launch fast:4 full x509parse_ecdsa 260 "fill_nondet.0:257,ct_memeq.0:68" buf.c ct.c
launch slow:8 full x509parse 844 "fill_nondet.0:841,ct_memeq.0:68" buf.c ct.c
launch fast full chacha20 165 "chacha20_xor.1:5"
# The AES-128 forward cipher and the two aes_public_key constructors,
# TRANSPORT=quic. HKDF is a contract stub (proof/quic_aes_stubs.h), so
# this formula holds the key schedule and the cipher and not five HMAC
# derivations; that header states what the composition gives up.
# Measured, these flags: 377 properties, 23 s, 0.67 GB peak.
launch fast full quic_aes 45 "fill_nondet.0:177" -DCH_TRANSPORT_QUIC
# The three RFC 9001 §5.1 derivations and the §6.1 key update. HKDF is
# the same contract stub quic_aes uses, so this formula holds the
# framing of the three calls and not four HMAC derivations; ct.c is
# compiled in because quic_keys_update wipes its own copy of the new
# secret. Measured, these flags: 79 properties, 0.24 s, 0.02 GB peak.
launch fast full quic_keys 45 "fill_nondet.0:177" ct.c -DCH_TRANSPORT_QUIC
# The RFC 9001 §5.8 Retry tag check. gcm_seal and aes_public_key_retry
# are contract stubs the harness defines, so this formula holds the one
# call's framing and its verdict and not AES-128-GCM; the harness states
# what those stubs assert. ct.c is compiled in because the verdict is
# ct_memeq's. Measured on an idle development machine (arm64 macOS, the
# pinned cbmc, kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this
# script): 160 properties, 3.5 s, 0.10 GB peak.
launch fast full quic_retry 70 "fill_nondet.0:177" ct.c -DCH_TRANSPORT_QUIC
# The Initial packet path: both entries over unconstrained lengths, with
# the eight calls they make stubbed to their contracts
# (proof/quic_initial_stubs.h). The cipher, the AEAD and the header
# protection pair are proven by their own harnesses, so this formula
# holds the length refusals and the offsets alone. The unwindset is the
# one the other quic lines carry, because the key schedule an
# aes_public_key holds is what fill_nondet writes most of. Measured on a
# development machine (arm64 macOS, the pinned cbmc, kissat,
# /usr/bin/time -l): 285 properties, 10 s, 0.23 GB peak.
launch fast full quic_initial 40 "fill_nondet.0:177" -DCH_TRANSPORT_QUIC
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
launch fast full quic_packet 65 "fill_nondet.0:133" buf.c ct.c -DCH_TRANSPORT_QUIC
# AEAD_AES_128_GCM's memory safety, its all-or-nothing refusal, and
# GHASH on its own. The forward cipher is a contract stub
# (proof/quic_gcm_stubs.h); the unwindset names hash_data and
# counter_mode because both loop on a symbolic count, and without them
# each unwinds to the global 130 and carries 130 copies of SP
# 800-38D's 128-step multiply. Measured on an idle development machine
# (arm64 macOS, the pinned cbmc, PROVE_NO_CACHE=1 /usr/bin/time -l):
# quic_gcm_safety 388 properties, 269 s, 2.3 GB peak; quic_gcm_refusal
# 393 properties, 48 s, 1.0 GB; quic_ghash 386 properties, 260 s,
# 1.7 GB. Neither proves a functional or authenticity property; the two
# harnesses that state those carry no launch line, below.
launch slow:3 full quic_gcm_safety 130 "fill_nondet.0:177,hash_data.1:3,counter_mode.1:3" --object-bits 11 ct.c -DCH_TRANSPORT_QUIC -DCH_GCM_PT_MAX=32 -DCH_GCM_AAD_MAX=32
launch slow:1 full quic_gcm_refusal 130 "fill_nondet.0:177,hash_data.1:3,counter_mode.1:3" --object-bits 11 ct.c -DCH_TRANSPORT_QUIC -DCH_GCM_PT_MAX=32 -DCH_GCM_AAD_MAX=32
launch slow:2 full quic_ghash 130 "fill_nondet.0:257,hash_data.1:17" ct.c -DCH_TRANSPORT_QUIC
launch fast full poly1305 85 "blocks.0:8" ct.c
# The ROLE=server authentication flight: the two slot predicates over
# every SignatureScheme code point, the CertificateVerify signed content
# of RFC 9846 section 4.4.3 at every transcript length the contract
# admits, and both refusals srv_sign_certificate_verify documents.
# SHA-256 is a contract stub, so this formula holds the assembly and the
# selection and not the compression function; no signer exists in this
# tree, so the harness states what stays out of reach. ct.c is compiled
# in because three paths wipe. The global unwind covers fill_nondet over
# the 384-byte signature buffer, which is the longest loop here.
# Measured on an idle development machine (arm64 macOS, cbmc 6.11.0,
# kissat, PROVE_NO_CACHE=1 /usr/bin/time -l through this script): 223
# properties, 3 s, 0.16 GB peak, two runs. The same formula with an
# assert of 0 at each of its four tails -- the assembly's wipe, the cap
# refusal, the signing refusal and the provisioned arm of the boot
# check -- fails all four, so every tail is reached.
launch fast full srv_auth 385 "" ct.c -DCH_ROLE_SERVER
# quic_gcm and quic_gcm_forge have no launch line, for the reason
# aead_inplace has none: neither formula returned a verdict, and an
# unconverged launch line proves nothing (docs/proofs.md). Measured with
# the flags above, at --unwind 130 and "fill_nondet.0:177": quic_gcm ran
# 2,144 s under kissat with no verdict, and quic_gcm_forge passed ten
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
# kissat, PROVE_NO_CACHE=1 /usr/bin/time -l over this script): srv_message 538
# properties, 4 s, 0.11 GB peak; srv_cookie 797 properties, 3 s, 0.07 GB. The
# same srv_message formula with its ServerHello assertion tightened to n < cap
# fails, so the formula reaches the builder rather than passing vacuously.
launch fast full srv_message 130 "fill_nondet.0:118" buf.c -DCH_ROLE_SERVER
launch fast full srv_cookie 130 "fill_nondet.0:119" buf.c ct.c hkdf.c -DCH_ROLE_SERVER
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
launch fast:4 full handshake_record 65 "hsr_fetch_record.0:6,hsr_next_msg.0:11,fill_nondet.0:33,fill_buf_nondet.0:13" --object-bits 11 -DCH_QUIET_CAP=1 -DCH_PROOF_RXBUF=12
# The TRANSPORT=quic driver and its step table, one formula each, with
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
# idle machine): quic_driver 1455 properties, 72 s, 0.84 GB resident;
# quic_step 546 properties, 4.0 s, 42 MB; quic_step_ca 553 properties,
# 4.8 s, 45 MB.
# quic_driver carries fast:4 rather than the tier default of 2: the tier
# default caps its address space at 6 GB, and cbmc's virtual footprint on
# this formula runs past that and dies mid-solve at about 70 s, where
# resident size stays under a gigabyte. The CA leg exists because
# hsa_epoch_commit sits behind CH_TRUST_CA and its wipe bound is the
# larger handshake_state that mode carries.
launch fast:4 full quic_driver 5 "fill_nondet.0:257,ct_wipe.0:441,drive.0:8,assert_dead.0:33" -DCH_TRANSPORT_QUIC -DCH_PROOF_RXBUF=12 handshake_record.c quic_config.c ct.c
launch fast full quic_step 5 "fill_nondet.0:37,ct_wipe.0:441" -DCH_TRANSPORT_QUIC -DCH_PROOF_RXBUF=12 ct.c
launch fast full quic_step_ca 5 "fill_nondet.0:37,ct_wipe.0:849" -DCH_TRANSPORT_QUIC -DCH_TRUST_CA -DCH_PROOF_RXBUF=12 ct.c
# The ROLE=server public calls and the flight driver above them. The
# fourteen srv_flight.h handlers are contract stubs the harness defines,
# because a handler and the driver that calls it are separate formulas;
# srv_auth.c's two entries are stubs for a second reason the harness
# states, that the srv_auth.c in the tree answers "no identity" for every
# configuration and would leave this formula proving one branch.
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
# 449 for the reason the two client drivers give, that the driver wipes
# the whole handshake_state on the way out.
#
# Measured under this script's flags (arm64 macOS, the pinned cbmc,
# kissat, /usr/bin/time -l, on a development machine running another
# lane's proof): 821 properties, 32.8 s, 2.23 GB peak. The weight is 3
# because that peak is over the fast tier's 2 GB default.
launch fast:3 full srv_accept 100 "alpn_ok.0:9,alpn_name_repeats.0:9,ct_wipe.0:449,ct_memeq.0:33,fill_names.0:257,fill_nondet.0:33" -DCH_ROLE_SERVER srv.c srv_handshake.c ct.c session.c
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
launch fast full drbg 100 "ch_rand_bytes.3:4" ct.c
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
