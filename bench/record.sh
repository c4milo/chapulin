#!/usr/bin/env bash
# Times one TLS record's protection on this machine, split into its stages,
# for https://github.com/c4milo/chapulin/issues/184 (AES-GCM) and
# https://github.com/c4milo/chapulin/issues/181 (ChaCha20-Poly1305), and
# writes bench/results-record-<os>-<arch>-<compiler>.csv, the compiler being
# clang or gcc. `make bench-record` runs it.
#
# It asks make for the flags the library's objects compile with, LIB_CFLAGS,
# and for the flags AES_HW_PROBE found for the AES instructions, so the
# bench compiles the library sources as make lib does. CC picks the
# compiler (default cc). It builds bench/record.c four times, each time
# with the library sources it times:
#
#   the SUITE=aesgcm AES=hw object's defines, -DCH_SUITE_AES_GCM -DCH_AES_HW,
#   with CH_NATIVE_AES, the builder's statement ct.h requires of that
#   build, and the widening multiply the packaged object ships: the
#   AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 rows
#
#   the same with -DCH_NATIVE_WIDEMUL, which WIDEMUL=native puts in an
#   object: the ChaCha20-Poly1305 rows again, because Poly1305 is the one
#   stage the multiply changes
#
#   each of those two with -DCH_CHACHA_VECTOR, chacha20_vector.c and
#   poly1305_vector.c, which CHACHA=vector puts in an object: the
#   ChaCha20-Poly1305 rows on the vector paths
#   (https://github.com/c4milo/chapulin/issues/181), where the compiler
#   targets NEON or SSE2. poly1305_vector.c compiles to nothing without
#   -DCH_NATIVE_WIDEMUL, so only the second build runs the vector Poly1305,
#   as only a CHACHA=vector WIDEMUL=native object carries it
#
# Each library source compiles as its own translation unit, as make lib
# compiles it, so no call the library makes across sources is inlined
# here either. -DCH_RAND_EXTERN names the entropy pattern cfg.h demands;
# nothing timed draws randomness.
#
# Two ceilings on the same machine follow when their tools are on PATH.
# `openssl speed -aead` seals (and with -decrypt opens) one 16 KiB record
# per operation, with 13 bytes of associated data and a tag, in five
# one-second runs of each; OpenSSL divides by the user CPU time its
# process took. bench/record_zig.zig times Zig's std.crypto over the same
# records by bench/record.c's method, built ReleaseFast for this CPU, when
# zig is the version tools/toolchain.env pins.
#
# Timings belong to the machine that ran them. `bench/record.sh --quick`
# builds both binaries, runs every row once and writes nothing, which is
# the form for an emulated machine.
set -euo pipefail
cd "$(dirname "$0")/.."

QUICK=""
if [ "${1:-}" = "--quick" ]; then
    QUICK=--quick
fi

CC=${CC:-cc}
# CC may carry flags of its own, such as -arch x86_64, as it may for make.
read -r -a CC_WORDS <<<"$CC"
LIB_CFLAGS=$(make -s --no-print-directory print-lib-cflags CC="$CC")
AES_HW_PROBE=$(make -s --no-print-directory print-aes-hw-probe CC="$CC")
if [ -z "$LIB_CFLAGS" ]; then
    echo "FAIL record bench: make print-lib-cflags returned no flags" >&2
    exit 1
fi
# The probe prints the flags that turn the instructions on, `none` when the
# compiler has them without a flag, and nothing when it cannot have them.
case "$AES_HW_PROBE" in
"")
    echo "FAIL record bench: $CC targets no AES instructions, so the AES=hw rows cannot build" >&2
    exit 1
    ;;
none) AES_HW_CFLAGS="" ;;
*) AES_HW_CFLAGS=$AES_HW_PROBE ;;
esac

case "$(uname -m)" in
arm64 | aarch64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=x86_64 ;;
*)
    echo "SKIP record bench: $(uname -m) has no AES or carry-less multiply path here" >&2
    exit 0
    ;;
esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
# The two compilers vectorize the record path's byte loops differently, so
# each writes a file of its own.
if "${CC_WORDS[@]}" --version 2>/dev/null | head -1 | grep -qi clang; then
    FAMILY=clang
else
    FAMILY=gcc
fi
OUT=bench/results-record-$OS-$ARCH-$FAMILY.csv

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# LIB_CFLAGS and AES_HW_CFLAGS are lists of flags, so they split on spaces.
# shellcheck disable=SC2206
FLAGS=($LIB_CFLAGS -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES
    $AES_HW_CFLAGS -I. -Ibench)
SRCS=(bench/record.c bench/record_rows.c bench/record_gcm.c bench/record_layer.c
    bench/record_chacha.c bench/record_aead.c bench/record_stub.c
    record.c gcm.c aes.c aes_hw.c ghash_hw.c gcm_hw.c aead.c chacha20.c poly1305.c ct.c hkdf.c sha256.c
    sha512.c sha512_compress.c)
"${CC_WORDS[@]}" "${FLAGS[@]}" -o "$W/record" "${SRCS[@]}"
"${CC_WORDS[@]}" "${FLAGS[@]}" -DCH_NATIVE_WIDEMUL -o "$W/record_native" "${SRCS[@]}"
# The CHACHA=vector builds, on either multiply, where the compiler targets
# NEON or SSE2 on a little-endian core, as chacha20_vector.h requires.
VECTOR_SRCS=("${SRCS[@]}" chacha20_vector.c poly1305_vector.c bench/record_chacha_vector.c)
VECTOR=""
VECTOR_NOTE="no CHACHA=vector rows: $CC targets neither NEON nor SSE2 on a little-endian core"
if printf '#include "chacha20_vector.h"\n' | "${CC_WORDS[@]}" -DCH_CHACHA_VECTOR -I. -x c -fsyntax-only - 2>/dev/null; then
    VECTOR=yes
    VECTOR_NOTE="CHACHA=vector adds -DCH_CHACHA_VECTOR, chacha20_vector.c, poly1305_vector.c and bench/record_chacha_vector.c"
    "${CC_WORDS[@]}" "${FLAGS[@]}" -DCH_CHACHA_VECTOR -o "$W/record_vector" "${VECTOR_SRCS[@]}"
    "${CC_WORDS[@]}" "${FLAGS[@]}" -DCH_CHACHA_VECTOR -DCH_NATIVE_WIDEMUL -o "$W/record_vector_native" \
        "${VECTOR_SRCS[@]}"
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

# One `openssl speed -aead` figure: bytes per second over a 16 KiB record.
openssl_rate() { # $1 = cipher, $2 = empty or -decrypt
    openssl speed -mr -seconds 1 -bytes 16384 -aead -evp "$1" ${2:+"$2"} 2>/dev/null |
        awk -F: '/^\+F:/ { print $4 }'
}

# The median of five runs and their spread, as bench/record.c writes a row.
openssl_rows() { # $1 = cipher, $2 = the aead column, $3 = the stage, $4 = empty or -decrypt
    local rates=()
    for _ in 1 2 3 4 5; do
        rates+=("$(openssl_rate "$1" "${4:-}")")
    done
    printf '%s\n' "${rates[@]}" | sort -g | awk -v aead="$2" -v stage="$3" -v build="$OPENSSL" '
        { rate[NR] = $1 }
        END {
            ns = 16384 * 1e9 / rate[3]
            spread = 100 * (16384e9 / rate[1] - 16384e9 / rate[5]) / ns
            printf "%s,%s,%s,16384,%.1f,%.4f,%.1f,%.1f,,\n", aead, build, stage, ns, ns / 16384,
                rate[3] / 1e6, spread
        }'
}

ZIG_PIN=$(sed -n 's/^ZIG_VERSION=//p' tools/toolchain.env)
ZIG_NOTE="no zig row: zig $ZIG_PIN is not on PATH"
if [ -z "$QUICK" ] && [ "$(zig version 2>/dev/null)" = "$ZIG_PIN" ]; then
    zig build-exe -O ReleaseFast --cache-dir "$W/zig-cache" -femit-bin="$W/record_zig" \
        bench/record_zig.zig
    ZIG_NOTE="zig $ZIG_PIN rows: bench/record_zig.zig, ReleaseFast, for this CPU"
fi

OPENSSL=""
if [ -z "$QUICK" ] && command -v openssl >/dev/null; then
    OPENSSL=$(openssl version | awk '{ print $1 " " $2 }')
fi

LOAD_BEFORE=$(load)
{
    "$W/record" ${QUICK:+"$QUICK"} aes128gcm aes256gcm chacha20poly1305
    "$W/record_native" ${QUICK:+"$QUICK"} chacha20poly1305
    if [ -n "$VECTOR" ]; then
        "$W/record_vector" ${QUICK:+"$QUICK"} chacha20poly1305
        "$W/record_vector_native" ${QUICK:+"$QUICK"} chacha20poly1305
    fi
    if [ -x "$W/record_zig" ]; then
        "$W/record_zig"
    fi
    if [ -n "$OPENSSL" ]; then
        openssl_rows aes-128-gcm aes128gcm openssl_seal
        openssl_rows aes-128-gcm aes128gcm openssl_open -decrypt
        openssl_rows aes-256-gcm aes256gcm openssl_seal
        openssl_rows aes-256-gcm aes256gcm openssl_open -decrypt
        openssl_rows chacha20-poly1305 chacha20poly1305 openssl_seal
        openssl_rows chacha20-poly1305 chacha20poly1305 openssl_open -decrypt
    fi
} >"$W/rows"
LOAD_AFTER=$(load)

if [ -n "$QUICK" ]; then
    cat "$W/rows"
    echo "record bench: --quick ran every row and wrote nothing" >&2
    exit 0
fi

# The tree is named before the CSV is opened: the redirect below truncates
# a tracked file, and a later describe would call every tree dirty. A copy
# of the tree without git, such as a container's, names it in BENCH_TREE.
TREE=$(git describe --always --dirty 2>/dev/null || echo "${BENCH_TREE:-unknown}")
{
    echo "# bench/record.sh on $(cpu) ($ARCH)${BENCH_HOST:+, $BENCH_HOST}, $(uname -s)" \
        "$(uname -r), $(date -u +%Y-%m-%d), tree $TREE"
    echo "# $("${CC_WORDS[@]}" --version | head -1); $CC ${FLAGS[*]}; WIDEMUL=native adds -DCH_NATIVE_WIDEMUL;" \
        "$VECTOR_NOTE"
    echo "# $ZIG_NOTE; ${OPENSSL:-no openssl on PATH}"
    echo "# load average (1, 5, 15 min) before: $LOAD_BEFORE; after: $LOAD_AFTER"
    echo "# ns: per record, the median of 5 runs, each the median of 15 batches of at least" \
        "1 ms; ns_per_byte and mb_per_s: per byte of the record's plaintext; spread_pct: the" \
        "slowest run less the fastest, percent of ns; p10_ns and p90_ns: the batches at the" \
        "10th and 90th percentile over every run; # check lines: aead, build, record_bytes," \
        "a whole and its parts, the whole's ns, the parts' summed ns, and their difference"
    echo "aead,build,stage,record_bytes,ns,ns_per_byte,mb_per_s,spread_pct,p10_ns,p90_ns"
    cat "$W/rows"
} >"$OUT"
cat "$OUT"
echo "record bench: wrote $OUT" >&2
