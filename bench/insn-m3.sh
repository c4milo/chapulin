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
# Each row is measured twice: over the multiply decomposition firmware
# ships (insns) and over the same driver built with -DCH_NATIVE_WIDEMUL
# (native_insns), the pair the README's decomposition sentence is
# rendered from. Writes bench/results-insn-m3.csv. Skips without a
# toolchain or QEMU; fails on a toolchain other than the pinned release.
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

# Every row is a property of what one compiler emits, and the README
# credits this column to the Arm GNU release ARM_GNU_VERSION pins, so
# an arm-none-eabi-gcc of another release stops the script instead of
# measuring (the device-ram.sh rule). The unversioned PATH candidate
# above can be any release, which is why this check is not optional.
# The compiler prints the release as 15.3.Rel1 where tools/toolchain.env
# spells the download path's 15.3.rel1, so the match ignores case.
M3_VERSION=$("$M3_CC" --version | head -1)
case "$(printf '%s' "$M3_VERSION" | tr '[:upper:]' '[:lower:]')" in
*"$(printf '%s' "$ARM_GNU_VERSION" | tr '[:upper:]' '[:lower:]')"*) ;;
*)
    echo "FAIL m3 insn count: $M3_CC is $M3_VERSION" >&2
    echo "FAIL m3 insn count: the pin is Arm GNU $ARM_GNU_VERSION (tools/toolchain.env). Every row of" >&2
    echo "FAIL m3 insn count: bench/results-insn-m3.csv is a property of that compiler, so install" >&2
    echo "FAIL m3 insn count: it, or bump the pin and re-measure; never measure with another." >&2
    exit 1
    ;;
esac

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

# The multiply macro is per build (see build below): the insns column
# is for firmware, which ships the decomposition (LIB_CFLAGS filters
# CH_NATIVE_WIDEMUL out), and the native_insns column is the same
# driver over the umull the decomposition exists to avoid.
CC="$M3_CC -std=c11 -O2 -mcpu=cortex-m3 -mthumb --specs=rdimon.specs \
    -Wl,--no-warn-rwx-segments -T test/qemu/m3_semi.ld test/qemu/m3_start.c \
    -I. -Ibench"
SRCS="ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c \
      rsa.c rsa_mont.c buf.c keysched.c record.c sha3.c mlkem.c mlkem_poly.c"

# $3 selects the multiply: CH_CT_WIDEMUL is the decomposition firmware
# ships (ct.h takes it as the default, so the define only names the
# choice), CH_NATIVE_WIDEMUL the native instruction.
build() { # $1 = OP macro  $2 = ITERS  $3 = multiply macro  -> binary path on stdout
    # CC holds the compiler and its flags, SRCS the sixteen source paths;
    # the shell must split both into separate arguments. Neither value
    # holds a glob character, so the other half of SC2086 does not apply.
    # shellcheck disable=SC2086
    $CC "-DOP_$1" "-DITERS=$2" "-D$3" bench/insn_driver.c "$W/runtime.c" $SRCS \
        -o "$W/bin_$1_$2_$3"
    echo "$W/bin_$1_$2_$3"
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
BIN=$(build SHA256_1K 4 CH_CT_WIDEMUL)
C1=$(count "$BIN")
C2=$(count "$BIN")
[ "$C1" -eq "$C2" ] || { echo "FAIL: counts not deterministic ($C1 vs $C2)" >&2; exit 1; }
echo "determinism check: two runs, both $C1 insns" >&2

TMPOUT=$(mktemp)
# Redirecting straight at the committed file would truncate it the moment
# the run starts, so a failing measurement would destroy the last good
# numbers (the insn-mips.sh lesson).
# The comment line names the compiler that produced every row, in the
# shape insn-rv32.sh writes, so a reader can tell a source change from
# a compiler change. tools/bench-numbers.py skips lines that start
# with #.
{
    echo "# $M3_VERSION; -mcpu=cortex-m3 -mthumb -O2; qemu-system-arm mps2-an385; native_insns adds -DCH_NATIVE_WIDEMUL"
    echo "op,insns,native_insns"
    measure() { # $1 = OP macro  $2 = ITERS  $3 = multiply macro  -> per-op insns on stdout
        BASE=$(count "$(build "$1" 0 "$3")")
        FULL=$(count "$(build "$1" "$2" "$3")")
        echo $(( (FULL - BASE) / $2 ))
    }
    row() { # $1 = CSV name  $2 = OP macro  $3 = ITERS
        INSNS=$(measure "$2" "$3" CH_CT_WIDEMUL)
        NATIVE=$(measure "$2" "$3" CH_NATIVE_WIDEMUL)
        echo "$1,$INSNS,$NATIVE"
        echo "  $1: $INSNS insns, $NATIVE with CH_NATIVE_WIDEMUL" >&2
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
