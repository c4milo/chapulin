#!/usr/bin/env bash
# Times every primitive chapulin ships, and whole handshakes between this
# tree's client and server, on this machine, with OpenSSL's figure for the
# same primitive beside it. Writes bench/results-primitives-<os>-<arch>-<compiler>.csv,
# one file per machine and compiler, the compiler being clang or gcc as
# bench/record.sh names its files, and bench/results-primitives-calls.csv, how
# many times each end of each handshake calls each primitive.
# docs/performance.md, "chapulin beside OpenSSL", renders its table from the
# first, and bench/notes-primitives.md reads both.
#
# Every timed program is a host object, built with -DCH_CPU_RUNTIME from the
# sources make names for one (print-host-srcs), so it holds each fast path
# beside the portable code and a session's ch_cfg.cpu picks among them
# (docs/decisions.md 89). Each program takes the value as --cpu and runs
# every row under it, and the build column names it:
#
#   0x1      CH_CPU_PROBED alone, the value of a caller that states
#            nothing: the 16x16 multiply decomposition and the 16-word
#            X25519 field, which a device object runs too. Its ChaCha20
#            runs the 128-bit vector path, as every host session's does; a
#            device object runs chacha20.c's portable loop, which
#            bench/aead.sh times
#   0xe7 ... every bit this CPU has that an object reads, the value a
#            caller on it would state (cpu_value below): the native
#            copies, the wide X25519 field, the vector Poly1305, SHA-256
#            on the CPU's SHA-256 instructions, on arm64 SHA-384 and
#            SHA-512 on its SHA-512 instructions and, in a program clang
#            built, SHA-3, SHAKE and ML-KEM on its SHA-3 instructions, and
#            on x86-64 the AVX2 ChaCha20. On a CPU with AVX-512 IFMA the
#            value also holds CH_CPU_AVX512_IFMA, which no path reads yet
#
# The programs are bench/primitives.c with the primitives' rows, and with
# the handshake's rows once pinning an RSA modulus and once pinning a P-256
# point (-DCH_PIN_ECDSA), each again with -DCH_KEX_PQ, whose client offers
# X25519MLKEM768 alone and whose server selects it. Three more programs
# count calls and time nothing: a device object's sources with
# -finstrument-functions.
#
# OpenSSL's rows come from `openssl speed -mr -seconds 1`, on the binary
# test/e2e.sh takes (bench/openssl.sh). OpenSSL divides the operations it
# ran by the user CPU time its process took, and bench/primitives.c times
# each sample on its thread's CPU clock, so both sides leave out the time a
# loaded machine gave to other work. An OpenSSL row carries the name of the
# chapulin row that times the same operation. `openssl speed` signs and
# verifies RSA with PKCS#1 v1.5 padding, so those rows are named
# rsa_pkcs1_sign_<bits> and rsa_pkcs1_verify_<bits>: chapulin signs PSS
# alone, and no chapulin row carries the first name.
#
# RUNS (default 5) sets how many times the whole set runs in turn. One run
# is every chapulin row under each value, then one second of each OpenSSL
# row, so the two sides of a comparison are never more than a run apart,
# and a burst of load lands in one run of a row rather than in all of them.
# A row's figure is the median over the runs.
#
# Every timed build is -O2, the level the packaged object uses. CC picks
# the compiler (default cc). bench.yml times the x86-64 runner under gcc and
# under the pinned clang: CI compiles with gcc, and build.zig, which a Zig
# project such as colibri builds the object with, compiles with clang.
#
# Timings are properties of the machine that ran them. Never record a run
# under emulation: `bench/primitives.sh --quick` builds everything, checks
# every known answer, takes three short samples per row, prints them and
# writes nothing, which is what an emulated or CI run is for.
#
# The handshake programs link the sources the Makefile names for
# bin/tcp_nonblocking_loop_test. The primitives program links a list of
# this script's own, PRIMITIVE_SRCS, so `make check` runs
# `bench/primitives.sh --build`, which builds every program and runs
# none: a call one of those sources gains into a file the list leaves out
# fails check (docs/decisions.md 88).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=bench/openssl.sh
. bench/openssl.sh

QUICK=""
BUILD_ONLY=""
case "${1:-}" in
--quick) QUICK=--quick ;;
--build) BUILD_ONLY=yes ;;
esac
RUNS=${RUNS:-5}
CC=${CC:-cc}
case "$(uname -m)" in
arm64 | aarch64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=x86_64 ;;
*) ARCH=$(uname -m) ;;
esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
# The two compilers compile the wide fields' carries differently, so each
# writes a file of its own, named as bench/record.sh names its.
if "$CC" --version 2>/dev/null | head -1 | grep -qi clang; then
    FAMILY=clang
else
    FAMILY=gcc
fi
OUT=bench/results-primitives-$OS-$ARCH-$FAMILY.csv
CALLS_OUT=bench/results-primitives-calls.csv

# Every timed program is a host object, which a compiler that fails the
# host test cannot build (cpu_cfg.h).
if [ "$(make -s --no-print-directory print-host-target CC="$CC")" != yes ]; then
    echo "FAIL primitives bench: $CC fails the host test, so no timed program can build" >&2
    exit 1
fi

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
# The two lists as a host object holds them: with the native copies, the
# wide X25519 field and the vector paths make adds.
read -r -a HOST_PRIMITIVE_SRCS <<<"$(make -s --no-print-directory print-host-srcs \
    HOST_SRCS_OF="${PRIMITIVE_SRCS[*]}")"
read -r -a HOST_HANDSHAKE_SRCS <<<"$(make -s --no-print-directory print-host-srcs \
    HOST_SRCS_OF="${HANDSHAKE_SRCS[*]}")"
if [ "${#HOST_PRIMITIVE_SRCS[@]}" -le "${#PRIMITIVE_SRCS[@]}" ] ||
    [ "${#HOST_HANDSHAKE_SRCS[@]}" -le "${#HANDSHAKE_SRCS[@]}" ]; then
    echo "FAIL primitives bench: make print-host-srcs added no source for a host object" >&2
    exit 1
fi

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
build primitives -DCH_RSA_MODULUS_MAX=512 -DCH_CPU_RUNTIME "${HOST_PRIMITIVE_SRCS[@]}"
HANDSHAKES=(handshake_rsa handshake_ecdsa handshake_rsa_hybrid handshake_ecdsa_hybrid)
build handshake_rsa "${HANDSHAKE_DEFS[@]}" -DCH_CPU_RUNTIME "${HOST_HANDSHAKE_SRCS[@]}"
build handshake_ecdsa "${HANDSHAKE_DEFS[@]}" -DCH_CPU_RUNTIME -DCH_PIN_ECDSA \
    "${HOST_HANDSHAKE_SRCS[@]}"
# The hybrid key exchange. The server carries ML-KEM in every build, so
# LOOP_SRCS already holds its sources; -DCH_KEX_PQ makes the client offer it.
build handshake_rsa_hybrid "${HANDSHAKE_DEFS[@]}" -DCH_CPU_RUNTIME -DCH_KEX_PQ \
    "${HOST_HANDSHAKE_SRCS[@]}"
build handshake_ecdsa_hybrid "${HANDSHAKE_DEFS[@]}" -DCH_CPU_RUNTIME -DCH_PIN_ECDSA -DCH_KEX_PQ \
    "${HOST_HANDSHAKE_SRCS[@]}"
# The counting programs: a device object's sources, whose calls carry the
# names the count's table holds.
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
    elif grep -q '^model name' /proc/cpuinfo; then
        sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1
    else
        # arm64 Linux names the core by its implementer and part numbers.
        printf 'implementer %s part %s' \
            "$(sed -n 's/^CPU implementer[[:space:]]*: //p' /proc/cpuinfo | head -1)" \
            "$(sed -n 's/^CPU part[[:space:]]*: //p' /proc/cpuinfo | head -1)"
    fi
}

# The bits of ch_cfg.cpu (cpu_cfg.h).
CPU_PROBED=0x1
CPU_CONSTANT_TIME_AES=0x2
CPU_CONSTANT_TIME_MULTIPLY=0x4
CPU_AVX2=0x8
CPU_VAES=0x10
CPU_CONSTANT_TIME_SHA256=0x20
CPU_CONSTANT_TIME_SHA512=0x40
CPU_CONSTANT_TIME_SHA3=0x80
CPU_AVX512_IFMA=0x100

# Whether a CPU's feature list names every word given.
reports() { # $1 = the list, space separated; the rest = the words
    local features=" $1 " word
    shift
    for word in "$@"; do
        case "$features" in
        *" $word "*) ;;
        *) return 1 ;;
        esac
    done
}

# The ch_cfg.cpu value a caller on this CPU would state: CH_CPU_PROBED, the
# multiply bit, the AES bit where the CPU reports the AES instructions and
# the carry-less multiply, the SHA-256 bit where it reports the SHA-256
# instructions, on arm64 the SHA-512 bit where it reports the SHA-512
# instructions and the SHA-3 bit where it reports the SHA-3 ones, and on
# x86-64 the AVX2 and VAES bits where it reports those and the IFMA bit
# where it reports AVX-512F and AVX-512 IFMA. A program gcc
# built holds no Keccak on the SHA-3 instructions, and there the SHA-3
# bit picks nothing (docs/decisions.md 99). BENCH_CPU from the
# environment wins, for a system this function has no probe for. The
# five timing bits also state that the instructions run in constant time
# in the thread's mode. The bench sets
# no such mode, neither PSTATE.DIT nor DOITM: it times the paths the bits
# pick and states nothing a deployment could rely on.
cpu_value() {
    if [ -n "${BENCH_CPU:-}" ]; then
        printf '0x%x\n' "$((BENCH_CPU))"
        return
    fi
    local features="" value=$((CPU_PROBED | CPU_CONSTANT_TIME_MULTIPLY))
    case "$(uname -s) $ARCH" in
    "Darwin arm64")
        # macOS names each feature in a sysctl of its own; the words below
        # are the ones arm64 Linux gives the same features.
        if [ "$(sysctl -n hw.optional.arm.FEAT_AES 2>/dev/null)" = 1 ] &&
            [ "$(sysctl -n hw.optional.arm.FEAT_PMULL 2>/dev/null)" = 1 ]; then
            features="aes pmull"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA256 2>/dev/null)" = 1 ]; then
            features="$features sha2"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA512 2>/dev/null)" = 1 ]; then
            features="$features sha512"
        fi
        if [ "$(sysctl -n hw.optional.arm.FEAT_SHA3 2>/dev/null)" = 1 ]; then
            features="$features sha3"
        fi
        ;;
    "Linux arm64") features=$(sed -n 's/^Features[[:space:]]*: //p' /proc/cpuinfo | head -1) ;;
    "Linux x86_64") features=$(sed -n 's/^flags[[:space:]]*: //p' /proc/cpuinfo | head -1) ;;
    *)
        echo "FAIL primitives bench: no probe here for this system's CPU; state BENCH_CPU," \
            "the ch_cfg.cpu value a caller on it would" >&2
        exit 1
        ;;
    esac
    if reports "$features" aes pmull || reports "$features" aes pclmulqdq; then
        value=$((value | CPU_CONSTANT_TIME_AES))
    fi
    # arm64 Linux names FEAT_SHA256 sha2, and x86-64 Linux the SHA
    # extensions sha_ni, which the bit names with SSSE3 and SSE4.1.
    if { [ "$ARCH" = arm64 ] && reports "$features" sha2; } ||
        { [ "$ARCH" = x86_64 ] && reports "$features" sha_ni ssse3 sse4_1; }; then
        value=$((value | CPU_CONSTANT_TIME_SHA256))
    fi
    # arm64 Linux names FEAT_SHA512 sha512. An x86-64 object refuses the
    # bit.
    if [ "$ARCH" = arm64 ] && reports "$features" sha512; then
        value=$((value | CPU_CONSTANT_TIME_SHA512))
    fi
    # arm64 Linux names FEAT_SHA3 sha3. An x86-64 object refuses the bit.
    if [ "$ARCH" = arm64 ] && reports "$features" sha3; then
        value=$((value | CPU_CONSTANT_TIME_SHA3))
    fi
    if [ "$ARCH" = x86_64 ] && reports "$features" avx2; then
        value=$((value | CPU_AVX2))
        if reports "$features" vaes vpclmulqdq; then
            value=$((value | CPU_VAES))
        fi
    fi
    # x86-64 Linux names AVX-512F avx512f and AVX-512 IFMA avx512ifma. A
    # CPU can have the first without the second, so the probe asks for
    # both.
    if [ "$ARCH" = x86_64 ] && reports "$features" avx512f avx512ifma; then
        value=$((value | CPU_AVX512_IFMA))
    fi
    printf '0x%x\n' "$value"
}

# The names of the bits a value holds, for the CSV's header. Each word of
# the list names one variable above and the bit of cpu_cfg.h it stands for.
cpu_names() { # $1 = a ch_cfg.cpu value
    local names=CH_CPU_PROBED bit variable
    for bit in CONSTANT_TIME_AES CONSTANT_TIME_MULTIPLY AVX2 VAES CONSTANT_TIME_SHA256 \
        CONSTANT_TIME_SHA512 AVX512_IFMA; do
        variable=CPU_$bit
        if [ $(($1 & ${!variable})) -ne 0 ]; then
            names="$names, CH_CPU_$bit"
        fi
    done
    printf '%s\n' "$names"
}

CPU_NOTHING=$(printf '0x%x' "$((CPU_PROBED))")
CPU_ALL=$(cpu_value)

# One run of every chapulin row under one value, as rows of primitive,
# build, unit, bytes, ns, samples, iqr_pct and instructions.
chapulin_run() { # $1 = a ch_cfg.cpu value
    local program
    "$W/primitives" ${QUICK:+"$QUICK"} --cpu "$1" hash cipher aead verify secret_key
    for program in "${HANDSHAKES[@]}"; do
        "$W/$program" ${QUICK:+"$QUICK"} --cpu "$1" handshake
    done
}

OPENSSL_BIN=""
OPENSSL_LABEL=""
if [ -z "$QUICK" ]; then
    OPENSSL_BIN=$(openssl_find)
fi
if [ -n "$OPENSSL_BIN" ]; then
    OPENSSL_LABEL=$(openssl_label "$OPENSSL_BIN")
fi

# One second of one `openssl speed` algorithm, as rows shaped like
# chapulin_run's. awk reads the +F line whose tag is $1 and prints one row
# for each "name=field" in $2: the row's name, and the field of that line
# that holds operations a second, or for a digest bytes a second. An
# OpenSSL without the algorithm prints no such line, and the row is then
# missing from the CSV. $1 is the +F tag, $2 the "name=field" list, $3 the
# unit and $4 the bytes; the rest are `openssl speed`'s arguments.
openssl_rows() {
    local tag=$1 fields=$2 unit=$3 bytes=$4
    shift 4
    { "$OPENSSL_BIN" speed -mr -seconds 1 "$@" 2>/dev/null || true; } |
        awk -F: -v tag="$tag" -v fields="$fields" -v unit="$unit" -v bytes="$bytes" \
            -v build="$OPENSSL_LABEL" '
            $1 == tag {
                count = split(fields, pair, " ")
                for (i = 1; i <= count; i++) {
                    split(pair[i], part, "=")
                    if ($(part[2]) > 0) {
                        printf "%s,%s,%s,%s,%.4f,,,\n", part[1], build, unit, bytes, 1e9 / $(part[2])
                    }
                }
            }'
}

# One run of every OpenSSL row: one second of each algorithm. The KEM
# lines hold key generations, encapsulations and decapsulations a second,
# and the X25519 and ECP-256 key generations are the first of theirs.
openssl_run() {
    local bytes
    for bytes in 64 16384; do
        openssl_rows +F sha256=4 byte "$bytes" -bytes "$bytes" -evp sha256
        openssl_rows +F sha384=4 byte "$bytes" -bytes "$bytes" -evp sha384
        openssl_rows +F sha3_256=4 byte "$bytes" -bytes "$bytes" -evp sha3-256
    done
    openssl_rows +F9 x25519_base=3 op 0 X25519
    openssl_rows +F5 x25519=4 op 0 ecdhx25519
    openssl_rows +F9 p256_ecdh_keygen=3 op 0 ECP-256
    openssl_rows +F5 p256_ecdh=4 op 0 ecdhp256
    openssl_rows +F4 "p256_sign=4 p256_ecdsa_verify=5" op 0 ecdsap256
    openssl_rows +F4 p384_ecdsa_verify=5 op 0 ecdsap384
    openssl_rows +F2 "rsa_pkcs1_sign_2048=4 rsa_pkcs1_verify_2048=5" op 0 rsa2048
    openssl_rows +F2 "rsa_pkcs1_sign_3072=4 rsa_pkcs1_verify_3072=5" op 0 rsa3072
    openssl_rows +F9 "mlkem768_keygen=3 mlkem768_encaps=4 mlkem768_decaps=5" op 0 ML-KEM-768
}

# Each row's figures over the runs: the median of its ns, the rate that
# median gives, the fewest samples a run took, the largest spread inside a
# run, the spread between the runs, and the median of its instructions.
summarize() {
    awk -F, '
        function median(values, key, count,    i, j, held, sorted) {
            for (i = 1; i <= count; i++) {
                held = values[key, i] + 0
                for (j = i - 1; j >= 1 && sorted[j] > held; j--) {
                    sorted[j + 1] = sorted[j]
                }
                sorted[j + 1] = held
            }
            lowest = sorted[1]
            highest = sorted[count]
            if (count % 2 == 1) {
                return sorted[(count + 1) / 2]
            }
            return (sorted[count / 2] + sorted[count / 2 + 1]) / 2
        }
        {
            key = $1 FS $2 FS $3 FS $4
            if (!(key in runs)) {
                order[++keys] = key
                unit[key] = $3
            }
            ns[key, ++runs[key]] = $5
            if ($6 != "" && (!(key in samples) || $6 + 0 < samples[key] + 0)) {
                samples[key] = $6
            }
            if ($7 != "" && (!(key in iqr) || $7 + 0 > iqr[key] + 0)) {
                iqr[key] = $7
            }
            if ($8 != "") {
                instructions[key, ++counted[key]] = $8
            }
        }
        END {
            for (k = 1; k <= keys; k++) {
                key = order[k]
                middle = median(ns, key, runs[key])
                spread = 100 * (highest - lowest) / middle
                retired = ""
                if (counted[key] > 0) {
                    retired = sprintf(unit[key] == "byte" ? "%.2f" : "%.0f",
                                      median(instructions, key, counted[key]))
                }
                printf "%s,%.4f,%.1f,%s,%s,%.1f,%s\n", key, middle,
                    (unit[key] == "byte" ? 1000 : 1e9) / middle, samples[key], iqr[key], spread,
                    retired
            }
        }'
}

if [ -n "$QUICK" ]; then
    RUNS=1
fi
: >"$W/raw"
: >"$W/notes"
LOAD_BEFORE=$(load)
for run in $(seq 1 "$RUNS"); do
    echo "primitives bench: run $run of $RUNS" >&2
    echo "# run $run of $RUNS: 1-minute load average $(load | cut -d' ' -f1) at its start" >>"$W/notes"
    chapulin_run "$CPU_NOTHING" >>"$W/raw"
    chapulin_run "$CPU_ALL" >>"$W/raw"
    if [ -n "$OPENSSL_BIN" ]; then
        openssl_run >>"$W/raw"
    fi
done
LOAD_AFTER=$(load)
summarize <"$W/raw" >"$W/rows"
# A row whose runs differ by half its median had a run the machine slowed.
# On Apple silicon that is a run macOS placed on efficiency cores, which
# take about three times as long, and a CPU clock cannot leave that out.
# The CSV keeps the row, and its run_spread_pct states the spread.
SLOWED=$(awk -F, '$9 + 0 > 50 { printf " %s (%s)", $1, $2 }' "$W/rows")
if [ -n "$SLOWED" ]; then
    echo "primitives bench: these rows moved by more than half between runs, so the machine" \
        "slowed some of them; run again before recording:$SLOWED" >&2
fi
"$W/calls_rsa" --quick handshake >"$W/calls"
"$W/calls_ecdsa" --quick handshake | tail -n +2 >>"$W/calls"
"$W/calls_ecdsa_hybrid" --quick handshake | tail -n +2 >>"$W/calls"

if [ -n "$QUICK" ]; then
    cat "$W/rows" "$W/calls"
    echo "primitives bench: --quick ran every row and wrote nothing" >&2
    exit 0
fi

# The tree is named before the CSVs are opened: the redirects below truncate
# tracked files, and a later describe would call every tree dirty. A copy
# of the tree without git, such as a container's, names it in BENCH_TREE.
TREE=$(git describe --always --dirty 2>/dev/null || echo "${BENCH_TREE:-unknown}")
{
    echo "# bench/primitives.sh on $(cpu) ($ARCH)${BENCH_HOST:+, $BENCH_HOST}, $(uname -s)" \
        "$(uname -r), $(date -u +%Y-%m-%d), tree $TREE"
    echo "# $("$CC" --version | head -1); ${FLAGS[*]} -DCH_CPU_RUNTIME; primitives adds" \
        "-DCH_RSA_MODULUS_MAX=512; handshake adds ${HANDSHAKE_DEFS[*]}, -DCH_PIN_ECDSA for the" \
        "ecdsa rows, and -DCH_KEX_PQ for the _hybrid rows, whose client offers X25519MLKEM768 alone"
    echo "# every timed program is a host object, and the build column is the ch_cfg.cpu value" \
        "its rows run under: $CPU_NOTHING is $(cpu_names "$CPU_NOTHING") alone, and $CPU_ALL is every" \
        "bit this CPU has that an object reads: $(cpu_names "$CPU_ALL")"
    if [ -n "$OPENSSL_BIN" ]; then
        echo "# $OPENSSL_LABEL rows: \`$OPENSSL_BIN speed -mr -seconds 1\`, one second a run:" \
            "sha256, sha384 and sha3_256 are -evp over -bytes; x25519_base and p256_ecdh_keygen" \
            "are the key generations of X25519 and ECP-256, which draw their random bytes;" \
            "x25519 and p256_ecdh are ecdhx25519 and ecdhp256; p256_sign, p256_ecdsa_verify and" \
            "p384_ecdsa_verify are ecdsap256 and ecdsap384; the mlkem768 rows are ML-KEM-768;" \
            "rsa_pkcs1_sign and rsa_pkcs1_verify are rsa2048 and rsa3072, which sign and verify" \
            "with PKCS#1 v1.5 padding, where chapulin signs PSS"
    else
        echo "# no OpenSSL rows: no OpenSSL 3 found"
    fi
    echo "# load average (1, 5, 15 min) before: $LOAD_BEFORE; after: $LOAD_AFTER"
    cat "$W/notes"
    echo "# ns: nanoseconds of CPU time per byte (unit byte) or per operation (unit op), the" \
        "median over $RUNS runs; a chapulin run's figure is the median of its samples, on the" \
        "thread's CPU clock, and an OpenSSL run's is one second's operations over its user CPU" \
        "time; per_second: 10^6 bytes, or operations, per second at that median; samples: the" \
        "fewest one run took; iqr_pct: the largest 25th to 75th percentile spread inside one" \
        "run, percent of its median; run_spread_pct: slowest run less fastest, percent of the" \
        "median; instructions: retired per byte or per operation, the median over the runs," \
        "where the system counts them"
    echo "primitive,build,unit,bytes,ns,per_second,samples,iqr_pct,run_spread_pct,instructions"
    cat "$W/rows"
} >"$OUT"
{
    echo "# bench/primitives.sh -finstrument-functions count of calls into each primitive during" \
        "one handshake, per end; $("$CC" --version | head -1), tree $TREE"
    cat "$W/calls"
} >"$CALLS_OUT"
cat "$OUT" "$CALLS_OUT"
echo "primitives bench: wrote $OUT and $CALLS_OUT" >&2
