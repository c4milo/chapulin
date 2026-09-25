#!/usr/bin/env bash
# Times chapulin's ChaCha20-Poly1305 and AES-128-GCM per byte on this
# machine, with each AEAD split into its cipher half and its hash half.
# Writes bench/results-aead-<arch>.csv, one file per architecture, so an
# x86-64 run and an arm64 run sit side by side.
#
# It builds bench/aead.c three times, because each build carries one AES
# implementation and one multiply:
#
#   AES=soft                    ChaCha20, ChaCha20-Poly1305 and Poly1305
#                               over the 16x16 multiply the packaged
#                               object ships, and AES-128-GCM over the
#                               S-box table and quic_gcm.c's portable
#                               GHASH
#   AES=soft CH_NATIVE_WIDEMUL  ChaCha20-Poly1305 and Poly1305 again, over
#                               the native multiply the host tests assert
#   AES=hw                      AES-128-GCM over the AES instructions and
#                               quic_ghash_hw.c's GHASH on PMULL or
#                               PCLMULQDQ
#
# Every build is -O2, the level the packaged object uses. CC picks the
# compiler (default cc); CI and the x86-64 row use CC=gcc.
#
# HW_FLAGS expands as ${HW_FLAGS[@]+"${HW_FLAGS[@]}"}, because bash 3.2,
# the one macOS ships, calls an empty array unbound under set -u.
#
# Timings are properties of the machine that ran them. Never record a run
# under emulation: `bench/aead.sh --quick` builds everything, takes three
# short samples per row, prints them and writes nothing, which is what an
# emulated run is for. test/ghash_equiv_test.c, not this script, holds the
# two GHASHes to the same answer.
set -euo pipefail
cd "$(dirname "$0")/.."

QUICK=""
if [ "${1:-}" = "--quick" ]; then
    QUICK=--quick
fi

CC=${CC:-cc}
case "$(uname -m)" in
arm64 | aarch64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=x86_64 ;;
*)
    echo "SKIP aead bench: $(uname -m) has no AES or carry-less multiply path here" >&2
    exit 0
    ;;
esac
OUT=bench/results-aead-$ARCH.csv

# The flags that turn on the AES and carry-less multiply instructions,
# probed the way the Makefile's AES_HW_PROBE probes them. clang on Apple
# silicon predefines __ARM_FEATURE_AES with no flag, and PMULL comes with
# it; gcc on arm64 Linux needs +crypto; x86-64 needs -maes for AES-NI and
# -mpclmul for PCLMULQDQ.
defines() { # $@ = extra flags: the compiler's predefined macros on stdout
    "$CC" "$@" -dM -E -x c /dev/null 2>/dev/null
}
if defines | grep -q __ARM_FEATURE_AES; then
    HW_FLAGS=()
elif defines -maes -mpclmul | grep -q __PCLMUL__; then
    HW_FLAGS=(-maes -mpclmul)
elif defines -march=armv8-a+crypto | grep -q __ARM_FEATURE_AES; then
    HW_FLAGS=(-march=armv8-a+crypto)
else
    echo "FAIL aead bench: $CC targets no AES instructions, so the AES=hw row cannot build" >&2
    exit 1
fi

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

FLAGS=(-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Wvla -D_DEFAULT_SOURCE
    -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -Ibench)
COMMON=(bench/aead.c bench/aead_gcm.c quic_aes.c hkdf.c sha256.c ct.c chacha20.c poly1305.c
    aead.c)
"$CC" "${FLAGS[@]}" -o "$W/soft" "${COMMON[@]}" quic_aes_soft.c
"$CC" "${FLAGS[@]}" -DCH_NATIVE_WIDEMUL -o "$W/native" "${COMMON[@]}" quic_aes_soft.c
"$CC" "${FLAGS[@]}" ${HW_FLAGS[@]+"${HW_FLAGS[@]}"} -DCH_AES_HW -o "$W/hw" "${COMMON[@]}" \
    quic_aes_hw.c quic_ghash_hw.c

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

LOAD_BEFORE=$(load)
"$W/soft" ${QUICK:+"$QUICK"} chacha20 chachapoly gcm >"$W/rows"
"$W/native" ${QUICK:+"$QUICK"} chachapoly >>"$W/rows"
"$W/hw" ${QUICK:+"$QUICK"} gcm >>"$W/rows"
LOAD_AFTER=$(load)

if [ -n "$QUICK" ]; then
    cat "$W/rows"
    echo "aead bench: --quick ran every row and wrote nothing" >&2
    exit 0
fi

# The tree is named before the CSV is opened: the redirect below truncates
# a tracked file, and a later describe would call every tree dirty.
TREE=$(git describe --always --dirty 2>/dev/null || echo unknown)
{
    echo "# bench/aead.sh on $(cpu) ($ARCH), $(uname -s) $(uname -r), $(date -u +%Y-%m-%d)," \
        "tree $TREE"
    echo "# $("$CC" --version | head -1); ${FLAGS[*]}; AES=hw adds ${HW_FLAGS[*]:-no flag} -DCH_AES_HW"
    echo "# load average (1, 5, 15 min) before: $LOAD_BEFORE; after: $LOAD_AFTER"
    echo "# ns_per_byte: median of 101 samples of 2 to 4 ms each; mb_per_s: 10^6 bytes per" \
        "second at that median; iqr_pct: 25th to 75th percentile spread, percent of the median"
    echo "primitive,build,bytes,ns_per_byte,mb_per_s,iqr_pct"
    cat "$W/rows"
} >"$OUT"
cat "$OUT"
echo "aead bench: wrote $OUT" >&2
