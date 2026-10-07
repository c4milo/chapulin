#!/usr/bin/env bash
# Times one TLS record's protection on this machine, split into its stages,
# for https://github.com/c4milo/chapulin/issues/184 (AES-GCM) and
# https://github.com/c4milo/chapulin/issues/181 (ChaCha20-Poly1305), and
# writes bench/results-record-<os>-<arch>-<compiler>.csv, the compiler being
# clang or gcc. `make bench-record` runs it.
#
# It asks make for the flags the library's objects compile with, LIB_CFLAGS,
# and whether this compiler passes the host test, so the bench compiles the
# library sources as make lib does. CC picks the compiler (default cc). It
# builds bench/record.c with the sources and defines of a SUITE=aesgcm host
# object, -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME, which holds every path
# (docs/decisions.md 89), once for each ch_cfg.cpu value it times. The
# value is -DBENCH_CPU on the compile line, every row hands it to the calls
# a session hands its own to, and the build column names it:
#
#   0x3, the probe's bit and the AES bit: the AES-128-GCM and AES-256-GCM
#   rows on the AES instructions' 128-bit loops, and the
#   ChaCha20-Poly1305 rows on the vector ChaCha20, NEON or SSE2, and
#   Poly1305's loop on the 16x16 decomposition
#
#   0x7, those and the multiply bit: the ChaCha20-Poly1305 rows again,
#   whose Poly1305 then runs the vector path on the native multiply
#   (docs/decisions.md 83), because Poly1305 is the one stage the bit
#   changes
#
#   0x1f, those and the two kernel bits, on an x86-64 CPU with AVX2, VAES and VPCLMULQDQ:
#   every row again, with the ChaCha20 keystream on chacha20_avx2.c's
#   kernel, Poly1305's long updates on poly1305_avx2.c's and AES-GCM's
#   whole blocks on gcm_vaes.c's (docs/decisions.md 90 and 110). --build compiles this one for every x86-64
#   target, and a run takes its rows only where /proc/cpuinfo names the
#   instructions
#
# A host object never runs chacha20.c's portable loop, so no row here
# times it; bench/aead.sh times it in a device object's sources.
#
# Each library source compiles as its own translation unit, as make lib
# compiles it, so no call the library makes across sources is inlined
# here either. -DCH_RAND_EXTERN names the entropy pattern cfg.h demands;
# nothing timed draws randomness.
#
# Two other libraries on the same machine follow when their tools are
# present. `openssl speed -aead` runs over 16 KiB, and with -decrypt the
# other way, in five one-second runs of each; OpenSSL divides by the user
# CPU time its process took. The binary is the one test/e2e.sh takes
# (bench/openssl.sh). What one operation of `speed -aead` holds depends on
# the release, so each OpenSSL row's stage is openssl_ and the name of the
# stage here that times the same operation (openssl_stage below).
# bench/record_zig.zig times Zig's std.crypto over the same records by
# bench/record.c's method, built ReleaseFast for this CPU, when zig is the
# version tools/toolchain.env pins.
#
# Timings belong to the machine that ran them. `bench/record.sh --quick`
# builds every binary, runs every row once and writes nothing, which is
# the form for an emulated machine.
#
# The AES instructions' sources come from the Makefile's AES_HW_SRCS,
# through `make print-aes-hw-srcs`. The rest of the list is this script's own, so `make
# check` runs `bench/record.sh --build`, which builds every binary above
# and stops before the first row: a call one of these sources gains into a
# file the list leaves out fails check (docs/decisions.md 88).
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

CC=${CC:-cc}
# CC may carry flags of its own, such as -arch x86_64, as it may for make.
read -r -a CC_WORDS <<<"$CC"
LIB_CFLAGS=$(make -s --no-print-directory print-lib-cflags CC="$CC")
HOST_TARGET=$(make -s --no-print-directory print-host-target CC="$CC")
if [ -z "$LIB_CFLAGS" ]; then
    echo "FAIL record bench: make print-lib-cflags returned no flags" >&2
    exit 1
fi
# The AES rows run in a host object, which a compiler that fails the host
# test cannot build (cpu_cfg.h).
if [ -z "$HOST_TARGET" ]; then
    echo "FAIL record bench: $CC fails the host test, so the AES-GCM rows cannot build" >&2
    exit 1
fi

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

read -r -a AES_HW_SRCS <<<"$(make -s --no-print-directory print-aes-hw-srcs)"
if [ "${#AES_HW_SRCS[@]}" -eq 0 ]; then
    echo "FAIL record bench: make print-aes-hw-srcs returned no sources" >&2
    exit 1
fi

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# LIB_CFLAGS is a list of flags, so it splits on spaces.
# shellcheck disable=SC2206
FLAGS=($LIB_CFLAGS -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME -I. -Ibench)
SRCS=(bench/record.c bench/record_rows.c bench/record_gcm.c bench/record_layer.c
    bench/record_chacha_vector.c bench/record_aead.c bench/record_stub.c
    record.c gcm.c aes.c "${AES_HW_SRCS[@]}" aead.c chacha20.c chacha20_vector.c chacha20_avx2.c
    poly1305.c poly1305_native.c poly1305_vector_native.c poly1305_avx2_native.c ct.c ct_wipe.c
    hkdf.c hkdf_hw.c sha256.c sha256_hw.c sha512.c sha512_compress.c sha512_hw.c)
"${CC_WORDS[@]}" "${FLAGS[@]}" -DBENCH_CPU=0x3 -o "$W/record" "${SRCS[@]}"
"${CC_WORDS[@]}" "${FLAGS[@]}" -DBENCH_CPU=0x7 -o "$W/record_multiply" "${SRCS[@]}"
# The x86-64 kernels' build. It compiles for every x86-64 target, and its
# rows run only where this CPU has the kernels' instructions.
KERNELS=""
KERNELS_NOTE="no ch_cfg.cpu 0x1f rows: this CPU is not x86-64 with AVX2, VAES and VPCLMULQDQ"
if "${CC_WORDS[@]}" -dM -E -x c /dev/null | grep -qw __x86_64__; then
    "${CC_WORDS[@]}" "${FLAGS[@]}" -DBENCH_CPU=0x1f -o "$W/record_kernels" "${SRCS[@]}"
    if [ -r /proc/cpuinfo ] && grep -qw avx2 /proc/cpuinfo && grep -qw vaes /proc/cpuinfo &&
        grep -qw vpclmulqdq /proc/cpuinfo; then
        KERNELS=yes
        KERNELS_NOTE="ch_cfg.cpu 0x1f adds CH_CPU_AVX2 and CH_CPU_VAES, the AVX2 ChaCha20 and Poly1305 and the VAES AES-GCM"
    fi
fi
if [ -n "$BUILD_ONLY" ]; then
    echo "record bench: --build built every binary and ran nothing" >&2
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

# The stage an OpenSSL row carries: openssl_ and the stage of this bench
# that times what one operation of that release's `speed -aead` holds.
# apps/speed.c of each release states it, and the time of a 16-byte
# operation on an M1 Pro agrees: 155 ns under either AES key length on
# 3.0.13 against 136 and 144 ns on 3.6.5, and for ChaCha20-Poly1305 386 ns
# on 3.0.13 against 45 ns on 3.6.5.
#
#   OpenSSL 3.0 sets the IV, hashes 13 bytes of associated data, encrypts
#   the 16 KiB and computes the tag, under a key set before the loop:
#   aead_seal and aead_open, for the three AEADs. Its open decrypts and
#   then checks a tag that does not match.
#
#   OpenSSL 3.6 does the same for AES-GCM and sets the key as well, for
#   every operation: seal_aes_gcm and open_aes_gcm, the AEAD under a key
#   expanded for the record, as record.c runs it. For ChaCha20-Poly1305 it
#   runs one update over the 16 KiB, with no nonce, associated data or tag:
#   aead_seal_data and aead_open_data, the AEAD less its tag's fixed work.
#
# For a release this script has not read, the stage is the command's name,
# which no stage here carries, so nothing sets its figure beside one.
openssl_stage() { # $1 = aes or chacha, $2 = seal or open
    case "$OPENSSL_LABEL $1" in
    "OpenSSL 3.0."*) echo "openssl_aead_$2" ;;
    "OpenSSL 3.6."*" aes") echo "openssl_${2}_aes_gcm" ;;
    "OpenSSL 3.6."*" chacha") echo "openssl_aead_${2}_data" ;;
    *) echo "openssl_speed_aead_$2" ;;
    esac
}

# One `openssl speed -aead` figure: bytes per second over 16 KiB.
openssl_rate() { # $1 = cipher, $2 = empty or -decrypt
    "$OPENSSL_BIN" speed -mr -seconds 1 -bytes 16384 -aead -evp "$1" ${2:+"$2"} 2>/dev/null |
        awk -F: '/^\+F:/ { print $4 }'
}

# The median of five runs and their spread, as bench/record.c writes a row.
openssl_rows() { # $1 = cipher, $2 = the aead column, $3 = the stage, $4 = empty or -decrypt
    local rates=()
    for _ in 1 2 3 4 5; do
        rates+=("$(openssl_rate "$1" "${4:-}")")
    done
    printf '%s\n' "${rates[@]}" | sort -g | awk -v aead="$2" -v stage="$3" -v build="$OPENSSL_LABEL" '
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

OPENSSL_BIN=""
OPENSSL_LABEL=""
if [ -z "$QUICK" ]; then
    OPENSSL_BIN=$(openssl_find)
fi
if [ -n "$OPENSSL_BIN" ]; then
    OPENSSL_LABEL=$(openssl_label "$OPENSSL_BIN")
fi

LOAD_BEFORE=$(load)
{
    "$W/record" ${QUICK:+"$QUICK"} aes128gcm aes256gcm chacha20poly1305
    "$W/record_multiply" ${QUICK:+"$QUICK"} chacha20poly1305
    if [ -n "$KERNELS" ]; then
        "$W/record_kernels" ${QUICK:+"$QUICK"} aes128gcm aes256gcm chacha20poly1305
    fi
    if [ -x "$W/record_zig" ]; then
        "$W/record_zig"
    fi
    if [ -n "$OPENSSL_BIN" ]; then
        openssl_rows aes-128-gcm aes128gcm "$(openssl_stage aes seal)"
        openssl_rows aes-128-gcm aes128gcm "$(openssl_stage aes open)" -decrypt
        openssl_rows aes-256-gcm aes256gcm "$(openssl_stage aes seal)"
        openssl_rows aes-256-gcm aes256gcm "$(openssl_stage aes open)" -decrypt
        openssl_rows chacha20-poly1305 chacha20poly1305 "$(openssl_stage chacha seal)"
        openssl_rows chacha20-poly1305 chacha20poly1305 "$(openssl_stage chacha open)" -decrypt
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
    echo "# $("${CC_WORDS[@]}" --version | head -1); $CC ${FLAGS[*]}; the build column is the ch_cfg.cpu value the rows run under, -DBENCH_CPU: 0x3 states the AES instructions, and 0x7 adds CH_CPU_CONSTANT_TIME_MULTIPLY, the vector Poly1305;" \
        "$KERNELS_NOTE"
    echo "# $ZIG_NOTE; ${OPENSSL_LABEL:-no OpenSSL 3 found}, whose rows' stages are openssl_" \
        "and the stage here that times one operation of its \`speed -aead\`"
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
