#!/usr/bin/env bash
# Times every primitive chapulin ships, and whole handshakes between this
# tree's client and server, on this machine. Writes
# bench/results-primitives-<arch>.csv, one file per architecture, and
# bench/results-primitives-calls.csv, how many times each end of each
# handshake calls each primitive. bench/notes-primitives.md reads both.
#
# It builds bench/primitives.c into eleven timed programs and three
# counting ones, because the multiply, the key exchange and the pinned
# algorithm are build choices, and a host object picks its multiply and
# its X25519 field for each session:
#
#   primitives                  every primitive, over the 16x16 multiply
#                               a device object ships (ct.h)
#   primitives CH_NATIVE_WIDEMUL
#                               the aead and secret_key groups again, over
#                               the native multiply WIDEMUL=native states;
#                               the other groups compile to the same code
#   primitives CH_CPU_CONSTANT_TIME_MULTIPLY
#                               the two x25519 rows again, in a host
#                               object's sources under the multiply bit,
#                               which run x25519_wide.c: the one code its
#                               rows run that the build above does not
#                               (docs/decisions.md 89); built only where
#                               the compiler passes the host test
#   handshake, default, CH_NATIVE_WIDEMUL, CH_CPU_CONSTANT_TIME_MULTIPLY
#   and KEX=pq, once pinning an RSA modulus and once pinning a P-256 point
#   (-DCH_PIN_ECDSA); the host object's program holds both multiplies and
#   both ends state the bit; the KEX=pq client offers X25519MLKEM768 alone
#   and the server selects it
#   calls, the RSA and ECDSA handshake programs and the ECDSA hybrid one
#                               again with -finstrument-functions, which
#                               count calls and time nothing
#
# Each device build changes one choice from the default, so a row's
# difference from its default row is that choice's alone. The host
# object's rows change two from the CH_NATIVE_WIDEMUL rows: the X25519
# field, and one branch on the answer per operation.
#
# Every timed build is -O2, the level the packaged object uses. CC picks
# the compiler (default cc); the x86-64 row uses CC=gcc. RUNS (default 3)
# sets how many times each program runs its whole set of rows in turn.
#
# Timings are properties of the machine that ran them. Never record a run
# under emulation: `bench/primitives.sh --quick` builds everything, checks
# every known answer, takes three short samples per row, prints them and
# writes nothing, which is what an emulated or CI run is for.
#
# The handshake programs link the sources the Makefile names for
# bin/tcp_nonblocking_loop_test. The primitives programs link a list of
# this script's own, PRIMITIVE_SRCS, so `make check` runs
# `bench/primitives.sh --build`, which builds every program and runs
# none: a call one of those sources gains into a file the list leaves out
# fails check (docs/decisions.md 88).
set -euo pipefail
cd "$(dirname "$0")/.."

QUICK=""
BUILD_ONLY=""
case "${1:-}" in
--quick) QUICK=--quick ;;
--build) BUILD_ONLY=yes ;;
esac
RUNS=${RUNS:-3}
CC=${CC:-cc}
case "$(uname -m)" in
arm64 | aarch64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=x86_64 ;;
*) ARCH=$(uname -m) ;;
esac
OUT=bench/results-primitives-$ARCH.csv
CALLS_OUT=bench/results-primitives-calls.csv

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

FLAGS=(-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Wvla -D_DEFAULT_SOURCE -DCH_RAND_DRBG
    -I. -Ibench -Itest)
# The primitives program links each module it times and what that module
# calls, and nothing else. CH_RSA_MODULUS_MAX=512 is the bound TRUST=webpki
# gives rsa.h, so the RSA-4096 rows run.
PRIMITIVE_SRCS=(bench/primitives.c bench/primitives_symmetric.c bench/primitives_public_key.c
    drbg.c ct.c ct_wipe.c buf.c sha256.c sha512.c sha512_compress.c sha3.c hkdf.c chacha20.c poly1305.c
    aead.c x25519.c mlkem.c mlkem_poly.c p256.c p384.c p384_field.c rsa.c rsa_mont.c rsa_pkcs1.c
    rsa_sign.c p256_ecdh.c p256_sign.c p256_scalar.c p256_point.c p256_field.c)
# The handshake program links what bin/tcp_nonblocking_loop_test links, under
# the defines of the ROLE=both TRANSPORT=tcp-nonblocking object, at the device
# RSA bound.
read -r -a LOOP_SRCS <<<"$(make -s --no-print-directory print-tcp-nonblocking-loop-srcs)"
if [ "${#LOOP_SRCS[@]}" -eq 0 ]; then
    echo "FAIL primitives bench: make print-tcp-nonblocking-loop-srcs returned no sources" >&2
    exit 1
fi
HANDSHAKE_DEFS=(-DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DBENCH_HANDSHAKE_PROGRAM)
HANDSHAKE_SRCS=(bench/primitives.c bench/primitives_handshake.c drbg.c "${LOOP_SRCS[@]}")

# --build times nothing, so it compiles every program at once, each into
# a log of its own, and names the programs that failed once all have
# ended.
BUILDS=()
build() { # $1 = program name; the rest = flags and sources
    local name=$1
    shift
    if [ -n "$BUILD_ONLY" ]; then
        "$CC" "${FLAGS[@]}" -o "$W/$name" "$@" >"$W/$name.log" 2>&1 &
        BUILDS+=("$name:$!")
        return
    fi
    "$CC" "${FLAGS[@]}" -o "$W/$name" "$@"
}
echo "primitives bench: building with $CC" >&2
build primitives -DCH_RSA_MODULUS_MAX=512 "${PRIMITIVE_SRCS[@]}"
build primitives_native -DCH_RSA_MODULUS_MAX=512 -DCH_NATIVE_WIDEMUL "${PRIMITIVE_SRCS[@]}"
build handshake_rsa "${HANDSHAKE_DEFS[@]}" "${HANDSHAKE_SRCS[@]}"
build handshake_rsa_native "${HANDSHAKE_DEFS[@]}" -DCH_NATIVE_WIDEMUL "${HANDSHAKE_SRCS[@]}"
build handshake_ecdsa "${HANDSHAKE_DEFS[@]}" -DCH_PIN_ECDSA "${HANDSHAKE_SRCS[@]}"
build handshake_ecdsa_native "${HANDSHAKE_DEFS[@]}" -DCH_PIN_ECDSA -DCH_NATIVE_WIDEMUL \
    "${HANDSHAKE_SRCS[@]}"
# The hybrid key exchange. The server carries ML-KEM in every build, so
# LOOP_SRCS already holds its sources; -DCH_KEX_PQ makes the client offer it.
build handshake_rsa_hybrid "${HANDSHAKE_DEFS[@]}" -DCH_KEX_PQ "${HANDSHAKE_SRCS[@]}"
build handshake_ecdsa_hybrid "${HANDSHAKE_DEFS[@]}" -DCH_PIN_ECDSA -DCH_KEX_PQ "${HANDSHAKE_SRCS[@]}"
# The host object's programs, where the compiler passes the host test: the
# two source lists as a host object holds them, with the native copies and
# the wide X25519 field make adds (print-host-srcs), under
# -DCH_CPU_RUNTIME. A compiler that fails the test skips them.
HOST=""
if [ "$(make -s --no-print-directory print-host-target CC="$CC")" = yes ]; then
    HOST=yes
    read -r -a HOST_PRIMITIVE_SRCS <<<"$(make -s --no-print-directory print-host-srcs \
        HOST_SRCS_OF="${PRIMITIVE_SRCS[*]}")"
    read -r -a HOST_HANDSHAKE_SRCS <<<"$(make -s --no-print-directory print-host-srcs \
        HOST_SRCS_OF="${HANDSHAKE_SRCS[*]}")"
    if [ "${#HOST_PRIMITIVE_SRCS[@]}" -le "${#PRIMITIVE_SRCS[@]}" ] ||
        [ "${#HOST_HANDSHAKE_SRCS[@]}" -le "${#HANDSHAKE_SRCS[@]}" ]; then
        echo "FAIL primitives bench: make print-host-srcs added no source for a host object" >&2
        exit 1
    fi
    build primitives_host -DCH_RSA_MODULUS_MAX=512 -DCH_CPU_RUNTIME "${HOST_PRIMITIVE_SRCS[@]}"
    build handshake_rsa_host "${HANDSHAKE_DEFS[@]}" -DCH_CPU_RUNTIME "${HOST_HANDSHAKE_SRCS[@]}"
    build handshake_ecdsa_host "${HANDSHAKE_DEFS[@]}" -DCH_PIN_ECDSA -DCH_CPU_RUNTIME \
        "${HOST_HANDSHAKE_SRCS[@]}"
else
    echo "primitives bench: $CC fails the host test, so the host object's rows are skipped" >&2
fi
build calls_rsa "${HANDSHAKE_DEFS[@]}" -DBENCH_COUNT_CALLS -finstrument-functions \
    "${HANDSHAKE_SRCS[@]}"
build calls_ecdsa "${HANDSHAKE_DEFS[@]}" -DBENCH_COUNT_CALLS -finstrument-functions \
    -DCH_PIN_ECDSA "${HANDSHAKE_SRCS[@]}"
build calls_ecdsa_hybrid "${HANDSHAKE_DEFS[@]}" -DBENCH_COUNT_CALLS -finstrument-functions \
    -DCH_PIN_ECDSA -DCH_KEX_PQ "${HANDSHAKE_SRCS[@]}"
if [ -n "$BUILD_ONLY" ]; then
    FAILED=""
    for entry in "${BUILDS[@]}"; do
        wait "${entry#*:}" || {
            cat "$W/${entry%%:*}.log" >&2
            FAILED="$FAILED ${entry%%:*}"
        }
    done
    if [ -n "$FAILED" ]; then
        echo "primitives bench: --build could not build:$FAILED" >&2
        exit 1
    fi
    echo "primitives bench: --build built every program and ran nothing" >&2
    exit 0
fi

load() { # the three load averages, space separated
    uptime | sed -e 's/.*load average[s]*: //' -e 's/,//g'
}

cpu() {
    if [ "$(uname -s)" = Darwin ]; then
        sysctl -n machdep.cpu.brand_string
    else
        sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1
    fi
}

OPTIONS=(--runs "$RUNS")
if [ -n "$QUICK" ]; then
    OPTIONS=("$QUICK")
fi
: >"$W/rows"
: >"$W/notes"
run() { # $1 = program; the rest = groups. Rows to rows, run notes to notes.
    local name=$1
    shift
    echo "primitives bench: $name $*" >&2
    "$W/$name" "${OPTIONS[@]}" "$@" >"$W/out"
    grep -v '^#' "$W/out" >>"$W/rows" || true
    grep '^#' "$W/out" | sed "s/^# /# $name: /" >>"$W/notes" || true
}

LOAD_BEFORE=$(load)
run primitives hash cipher aead verify secret_key
run primitives_native aead secret_key
if [ -n "$HOST" ]; then
    run primitives_host x25519
fi
run handshake_rsa handshake
run handshake_rsa_native handshake
if [ -n "$HOST" ]; then
    run handshake_rsa_host handshake
fi
run handshake_ecdsa handshake
run handshake_ecdsa_native handshake
if [ -n "$HOST" ]; then
    run handshake_ecdsa_host handshake
fi
run handshake_rsa_hybrid handshake
run handshake_ecdsa_hybrid handshake
LOAD_AFTER=$(load)
"$W/calls_rsa" --quick handshake | grep -v '^#' >"$W/calls"
"$W/calls_ecdsa" --quick handshake | grep -v '^#' | tail -n +2 >>"$W/calls"
"$W/calls_ecdsa_hybrid" --quick handshake | grep -v '^#' | tail -n +2 >>"$W/calls"

if [ -n "$QUICK" ]; then
    cat "$W/rows" "$W/calls"
    echo "primitives bench: --quick ran every row and wrote nothing" >&2
    exit 0
fi

TREE=$(git describe --always --dirty 2>/dev/null || echo unknown)
{
    echo "# bench/primitives.sh on $(cpu) ($ARCH), $(uname -s) $(uname -r), $(date -u +%Y-%m-%d)," \
        "tree $TREE"
    echo "# $("$CC" --version | head -1); ${FLAGS[*]}"
    echo "# primitives adds -DCH_RSA_MODULUS_MAX=512; handshake adds ${HANDSHAKE_DEFS[*]}," \
        "and -DCH_PIN_ECDSA for the ecdsa rows"
    echo "# the CH_CPU_CONSTANT_TIME_MULTIPLY rows add -DCH_CPU_RUNTIME, the native copies and x25519_wide.c," \
        "and run under that bit"
    echo "# the _hybrid handshake rows add -DCH_KEX_PQ: the client offers X25519MLKEM768 alone"
    echo "# load average (1, 5, 15 min) before: $LOAD_BEFORE; after: $LOAD_AFTER"
    cat "$W/notes"
    echo "# ns: nanoseconds per byte (unit byte) or per operation (unit op), the median over" \
        "$RUNS runs of each run's median; per_second: 10^6 bytes, or operations, per second at" \
        "that median; samples: the fewest one run took; iqr_pct: the largest 25th to 75th" \
        "percentile spread inside one run, percent of its median; run_spread_pct: slowest run" \
        "median minus fastest, percent of the median"
    echo "primitive,build,unit,bytes,ns,per_second,samples,iqr_pct,run_spread_pct"
    cat "$W/rows"
} >"$OUT"
{
    echo "# bench/primitives.sh -finstrument-functions count of calls into each primitive during" \
        "one handshake, per end; $("$CC" --version | head -1), tree $TREE"
    cat "$W/calls"
} >"$CALLS_OUT"
cat "$OUT" "$CALLS_OUT"
echo "primitives bench: wrote $OUT and $CALLS_OUT" >&2
