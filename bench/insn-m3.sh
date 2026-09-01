#!/usr/bin/env bash
# Measures the crypto in Cortex-M3 units: dynamic thumbv7m INSTRUCTION
# counts, the ISA the m3 and freertos CI lanes execute. Builds each
# operation from the shared bench/insn_driver.c with the Arm GNU
# toolchain (newlib + rdimon semihosting, the m3-check build shape),
# boots it on QEMU's MPS2-AN385 with one instruction per translation
# block, and counts executed instructions from the exec log. No timer
# or interrupt is ever enabled, so counts are deterministic; an ITERS=0
# build of the same binary is the baseline and the subtraction removes
# boot, runtime setup and input setup. Counts are frequency-independent.
# Writes bench/results-insn-m3.csv. Skips without the toolchain or QEMU.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/toolchain.env
. tools/toolchain.env

M3_CC=$(command -v \
    "/Applications/ArmGNUToolchain/$ARM_GNU_VERSION/arm-none-eabi/bin/arm-none-eabi-gcc" \
    || command -v arm-none-eabi-gcc || true)
M3_QEMU=$(command -v qemu-system-arm || true)
[ -n "$M3_CC" ] || { echo "SKIP m3 insn count: no arm-none-eabi-gcc" >&2; exit 0; }
[ -n "$M3_QEMU" ] || { echo "SKIP m3 insn count: no qemu-system-arm" >&2; exit 0; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The runtime under the shared driver: newlib's main calls app_main and
# exits with its status through semihosting. ch_assert_fail is the only
# chapulin hook a linked source can pull in; the driver never draws
# randomness.
cat > "$W/runtime.c" <<'RUNTIME'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int app_main(void);

void ch_assert_fail(const char *expr, const char *file, unsigned line) {
    (void)expr;
    (void)file;
    (void)line;
    fputs("ch_assert\n", stderr);
    exit(134);
}

int main(void) {
    return app_main();
}
RUNTIME

CC="$M3_CC -std=c11 -O2 -mcpu=cortex-m3 -mthumb --specs=rdimon.specs \
    -Wl,--no-warn-rwx-segments -T test/qemu/m3_semi.ld test/qemu/m3_start.c \
    -DCH_NATIVE_WIDEMUL -I. -Ibench"
SRCS="ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c \
      rsa.c rsa_mont.c buf.c keysched.c record.c sha3.c mlkem.c mlkem_poly.c"

build() { # $1 = OP macro  $2 = ITERS  -> binary path on stdout
    # CC holds the compiler and its flags, SRCS the sixteen source paths;
    # the shell must split both into separate arguments. Neither value
    # holds a glob character, so the other half of SC2086 does not apply.
    # shellcheck disable=SC2086
    $CC "-DOP_$1" "-DITERS=$2" bench/insn_driver.c "$W/runtime.c" $SRCS \
        -o "$W/bin_$1_$2"
    echo "$W/bin_$1_$2"
}

count_once() { # $1 = binary: exec-log line count on stdout
    # The exec log goes to its own file: with -nographic the semihosting
    # console shares stdout, and a console byte must never count as an
    # instruction. The binary's own exit status still fails the run.
    "$M3_QEMU" -M mps2-an385 -cpu cortex-m3 -nographic -semihosting \
        -icount shift=0,sleep=off -accel tcg,one-insn-per-tb=on \
        -d exec,nochain -D "$W/exec.log" -kernel "$1" \
        || { echo "FAIL: guest exited $? running $1" >&2; exit 1; }
    wc -l < "$W/exec.log" | tr -d ' '
    rm -f "$W/exec.log"
}

count() { # $1 = binary: executed-instruction count on stdout
    # icount pins the virtual clock to the instruction stream, but a
    # translation block a host event interrupts is still logged at
    # entry, restarted, and logged again — a busy host adds a line or
    # two. A restart only ever adds lines, so the clean count is the
    # minimum over three runs; the determinism check below holds the
    # method to that.
    local best=""
    for _ in 1 2 3; do
        c=$(count_once "$1")
        [ -n "$best" ] && [ "$best" -le "$c" ] || best=$c
    done
    echo "$best"
}

# Determinism spot check: identical counts or the method is broken.
BIN=$(build SHA256_1K 4)
C1=$(count "$BIN")
C2=$(count "$BIN")
[ "$C1" -eq "$C2" ] || { echo "FAIL: counts not deterministic ($C1 vs $C2)" >&2; exit 1; }
echo "determinism check: two runs, both $C1 insns" >&2

TMPOUT=$(mktemp)
# Redirecting straight at the committed file would truncate it the moment
# the run starts, so a failing measurement would destroy the last good
# numbers (the insn-mips.sh lesson).
{
    echo "op,insns"
    row() { # $1 = CSV name  $2 = OP macro  $3 = ITERS
        BASE=$(count "$(build "$2" 0)")
        FULL=$(count "$(build "$2" "$3")")
        INSNS=$(( (FULL - BASE) / $3 ))
        echo "$1,$INSNS"
        echo "  $1: $INSNS insns" >&2
    }
    row sha256_1kib SHA256_1K 16
    row hkdf_expand_label_32b HKDF 16
    row aead_seal_1kib AEAD_1K 16
    row x25519_scalarmult X25519 1
    row p256_ecdsa_verify P256 1
    row rsa_pss_verify_3072 RSA 1
    row mlkem_keygen MLKEM_KEYGEN 4
    row mlkem_decaps MLKEM_DECAPS 4
    row handshake_crypto HANDSHAKE 1
    row handshake_crypto_pq HANDSHAKE_PQ 1
} > "$TMPOUT"
mv "$TMPOUT" bench/results-insn-m3.csv
echo "wrote bench/results-insn-m3.csv" >&2
