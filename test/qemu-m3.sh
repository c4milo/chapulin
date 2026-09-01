#!/usr/bin/env bash
# Runs chapulin's crypto on an emulated Cortex-M3 and holds the output
# to the host build of the same main: SHA-256, x25519 and the AEAD,
# byte for byte, with the SHA-256 line also checked against the
# FIPS 180-4 "abc" vector so host and target cannot both be wrong the
# same way. The target build is the shipped shape -- freestanding, no
# libc, the 16x16 multiply decomposition -- on QEMU's MPS2-AN385, the
# same Cortex-M3 lint-wide-multiply gates by disassembly.
#
# Needs qemu-system-arm and a clang with the Arm backend. Skips, with
# the reason, when either is missing.
set -euo pipefail
cd "$(dirname "$0")/.."

CLANG=${CLANG:-$(command -v clang-23 || command -v /opt/homebrew/opt/llvm/bin/clang || command -v clang)}
LLD=${LLD:-$(command -v ld.lld || echo "$(dirname "$CLANG")/ld.lld")}
[ -x "$LLD" ] || {
    echo "SKIP qemu-m3: no ld.lld beside $CLANG" >&2
    exit 0
}
QEMU=${QEMU:-$(command -v qemu-system-arm || true)}
[ -n "$QEMU" ] || {
    echo "SKIP qemu-m3: qemu-system-arm not on PATH" >&2
    exit 0
}
echo 'int probe;' | "$CLANG" -target thumbv7m-none-eabi -c -x c - -o /dev/null 2>/dev/null || {
    echo "SKIP qemu-m3: $CLANG has no Arm backend" >&2
    exit 0
}

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

SRCS="test/qemu/m3_kat.c sha256.c x25519.c chacha20.c poly1305.c aead.c ct.c softmul.c"

# The target build: the shipped multiply path (no CH_NATIVE_WIDEMUL),
# no libc, everything at address zero per test/qemu/m3.ld.
# shellcheck disable=SC2086
"$CLANG" -target thumbv7m-none-eabi -mcpu=cortex-m3 -Os -std=c11 \
    -ffreestanding -nostdlibinc -nostdlib \
    -fuse-ld="$LLD" \
    -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -I. \
    -Wl,--entry=reset_handler -T test/qemu/m3.ld -o "$W/m3.elf" $SRCS test/qemu/m3_runtime.c

# The host build of the same main, same multiply path, host libc.
# shellcheck disable=SC2086
cc -Os -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -I. \
    -o "$W/host" $SRCS test/qemu/host_runtime.c

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
