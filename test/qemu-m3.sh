#!/usr/bin/env bash
# Runs chapulin's crypto on an emulated Cortex-M3 and holds the output
# to the host build of the same main: SHA-256, x25519 and the AEAD,
# byte for byte, with the SHA-256 line also checked against the
# FIPS 180-4 "abc" vector so host and target cannot both be wrong the
# same way. The target build is the shipped shape -- freestanding, the
# 16x16 multiply decomposition, and no libc but the mem routines
# test/qemu/m3_runtime.c defines, which test/qemu/libc/string.h declares
# for ct_wipe.c -- on QEMU's MPS2-AN385, the same Cortex-M3
# lint-wide-multiply checks by disassembly.
#
# Needs qemu-system-arm, a clang with the Arm backend and its ld.lld. On
# a development machine it skips, with the reason, when one is missing.
# On CI it fails instead, because the run is the one check of the target
# build: `make check` builds the host binary alone, so a skip on CI hides
# a target build that no longer compiles (docs/invariants.md, INV-40).
#
# SRCS below is this script's own list, so `make check` runs
# `test/qemu-m3.sh --build`, which builds the host binary from it with the
# host compiler, needs neither tool and runs nothing: a call one of these
# sources gains into a file the list leaves out fails check
# (docs/decisions.md 88).
set -euo pipefail
cd "$(dirname "$0")/.."

SRCS="test/qemu/m3_kat.c sha256.c x25519.c chacha20.c poly1305.c aead.c ct.c ct_wipe.c softmul.c"

# The host build of the same main, same multiply path, host libc.
host_build() { # $1 = the binary to write
    # SRCS holds the paths as one string, which the shell must split.
    # shellcheck disable=SC2086
    cc -Os -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -I. \
        -o "$1" $SRCS test/qemu/host_runtime.c
}

if [ "${1:-}" = "--build" ]; then
    W=$(mktemp -d)
    trap 'rm -rf "$W"' EXIT
    host_build "$W/host"
    echo "qemu-m3: --build built the host binary and ran nothing" >&2
    exit 0
fi

# A missing tool skips the run on a development machine and fails it on
# CI, where GitHub sets CI.
missing() { # $1 = what is missing
    if [ -n "${CI:-}" ]; then
        echo "FAIL qemu-m3: $1, and CI must run this check" >&2
        exit 1
    fi
    echo "SKIP qemu-m3: $1" >&2
    exit 0
}

CLANG=${CLANG:-$(command -v clang-23 || command -v /opt/homebrew/opt/llvm/bin/clang || command -v clang || true)}
[ -n "$CLANG" ] || missing "no clang on PATH"
# apt.llvm.org names its linker for the major, ld.lld-23 beside clang-23,
# so the text after "clang" in $CLANG names the linker that matches it.
LLD=${LLD:-$(command -v "ld.lld${CLANG##*clang}" || command -v ld.lld || echo "$(dirname "$CLANG")/ld.lld")}
[ -x "$LLD" ] || missing "no ld.lld beside $CLANG"
QEMU=${QEMU:-$(command -v qemu-system-arm || true)}
[ -n "$QEMU" ] || missing "qemu-system-arm not on PATH"
echo 'int probe;' | "$CLANG" -target thumbv7m-none-eabi -c -x c - -o /dev/null 2>/dev/null ||
    missing "$CLANG has no Arm backend"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The target build: the shipped multiply path (no CH_NATIVE_WIDEMUL), no
# libc but test/qemu/libc's string.h over m3_runtime.c's mem routines,
# everything at address zero per test/qemu/m3.ld.
# shellcheck disable=SC2086
"$CLANG" -target thumbv7m-none-eabi -mcpu=cortex-m3 -Os -std=c11 \
    -ffreestanding -nostdlibinc -nostdlib -isystem test/qemu/libc \
    -fuse-ld="$LLD" \
    -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -I. \
    -Wl,--entry=reset_handler -T test/qemu/m3.ld -o "$W/m3.elf" $SRCS test/qemu/m3_runtime.c

host_build "$W/host"
"$W/host" > "$W/host.out"

# Semihosting writes CRLF line endings; normalize so the diff and the
# vector grep compare bytes the two runtimes actually share.
"$QEMU" -M mps2-an385 -cpu cortex-m3 -nographic -semihosting \
    -kernel "$W/m3.elf" 2>&1 | tr -d '\r' > "$W/m3.out" || {
    echo "FAIL qemu-m3: the target run exited nonzero" >&2
    sed 's/^/  m3: /' "$W/m3.out" >&2
    exit 1
}

grep -q "^sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad$" \
    "$W/m3.out" || {
    echo "FAIL qemu-m3: SHA-256 on the target does not match FIPS 180-4" >&2
    sed 's/^/  m3: /' "$W/m3.out" >&2
    exit 1
}

diff "$W/host.out" "$W/m3.out" >/dev/null || {
    echo "FAIL qemu-m3: host and Cortex-M3 outputs differ" >&2
    diff "$W/host.out" "$W/m3.out" | sed 's/^/  /' >&2
    exit 1
}

echo "qemu-m3: host and Cortex-M3 agree on sha256, x25519 and the AEAD (FIPS vector anchored)"
