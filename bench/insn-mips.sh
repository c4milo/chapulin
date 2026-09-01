#!/usr/bin/env bash
# Measures the crypto in honest device-CPU units: dynamic INSTRUCTION
# counts for mips32r2, not guessed milliseconds. Builds a freestanding
# big-endian Linux binary per operation (own __start, exit/write syscalls,
# byte-wise mem routines — no libc), runs it under qemu-user with one
# instruction per translation block, and counts executed instructions from
# the exec log. Counts are deterministic and baseline-subtracted: an
# ITERS=0 build of the same binary removes startup, input setup, and the
# stack paint. Every input is fixed and no I/O happens inside a measured
# loop. memcpy is byte-wise here, so counts lean conservative. Writes
# bench/results-insn.csv. Skips without docker.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=bench/toolchain.env
    . bench/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP insn count: docker not available" >&2
        exit 0
    }
    TMPOUT=$(mktemp)
    trap 'rm -f "$TMPOUT"' EXIT
    docker run --rm -e "CLANG_MAJOR=$CLANG_MAJOR" \
        -v "$PWD":/src:ro -w /src "alpine@$ALPINE_DIGEST" \
        sh -c 'apk add -q bash clang lld qemu-mips >/dev/null 2>&1 \
               && exec bash /src/bench/insn-mips.sh --inside' \
        > "$TMPOUT"
    # Redirecting straight at the committed file truncated it the moment the
    # run started, so a failing measurement destroyed the last good numbers.
    mv "$TMPOUT" bench/results-insn.csv
    echo "wrote bench/results-insn.csv" >&2
    exit 0
fi

# ---- inside the container from here on; CSV goes to stdout ----
# The digest pins the base image, not apk, which resolves against the live
# repository. A compiler whose major moved would publish different numbers
# for unchanged sources, so stop rather than measure (bench/toolchain.env).
cver=$(clang --version | head -1)
case "$cver" in
*"clang version ${CLANG_MAJOR:?}."*) ;;
*) echo "FAIL: expected clang $CLANG_MAJOR, container has: $cver" >&2; exit 1 ;;
esac
echo "$cver" >&2

W=/tmp/insn
mkdir -p "$W/shim"

# Declaration-only libc surface; the runtime below supplies the bodies.
cat > "$W/shim/string.h" <<'EOF'
#pragma once
#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
EOF

# The runtime a libc would provide: entry, exit/write syscalls (o32 ABI),
# byte-wise mem/str routines, and the two chapulin platform hooks. Stack
# painting mirrors how firmware measures high-water; its cost lands in
# baseline and full runs alike, so the subtraction drops it.
cat > "$W/runtime.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>

static void sys_exit(long code) {
    register long v0 __asm__("$2") = 4001;
    register long a0 __asm__("$4") = code;
    __asm__ volatile("syscall" : "+r"(v0) : "r"(a0) : "memory");
}
static void sys_write(long fd, const void *buf, unsigned long n) {
    register long v0 __asm__("$2") = 4004;
    register long a0 __asm__("$4") = fd;
    register long a1 __asm__("$5") = (long)buf;
    register long a2 __asm__("$6") = (long)n;
    __asm__ volatile("syscall" : "+r"(v0) : "r"(a0), "r"(a1), "r"(a2) : "$7", "memory");
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    while (n--) { *dp++ = *sp++; }
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    if (dp < sp) {
        while (n--) { *dp++ = *sp++; }
    } else {
        while (n--) { dp[n] = sp[n]; }
    }
    return d;
}
void *memset(void *d, int c, size_t n) {
    unsigned char *dp = d;
    while (n--) { *dp++ = (unsigned char)c; }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *ap = a;
    const unsigned char *bp = b;
    for (; n--; ap++, bp++) {
        if (*ap != *bp) { return *ap - *bp; }
    }
    return 0;
}
size_t strlen(const char *s) {
    const char *p = s;
    while (*p) { p++; }
    return (size_t)(p - s);
}

// chapulin's platform hooks. The bench needs determinism, not entropy;
// nothing in the measured paths calls ch_rand_bytes anyway.
void ch_rand_bytes(uint8_t *p, size_t n) {
    uint32_t x = 0x2545f491u;
    while (n--) {
        x = x * 1103515245u + 12345u;
        *p++ = (uint8_t)(x >> 16);
    }
}
_Noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    sys_write(2, "ch_assert\n", 10);
    sys_exit(134);
    __builtin_unreachable();
}

static void write_num(unsigned long v) {
    char buf[12];
    int i = 11;
    buf[11] = '\n';
    if (v == 0) { buf[--i] = '0'; }
    while (v) { buf[--i] = (char)('0' + (v % 10)); v /= 10; }
    sys_write(1, buf + i, (unsigned long)(12 - i));
}

// Stack painting, the way firmware measures high-water: paint below $sp at
// entry, run, then scan up for the deepest word the run dirtied.
enum { PAINT_WORDS = (16384 / 4) - 16 };
int app_main(void);
void __start(void) {
    long sp;
    __asm__("move %0, $sp" : "=r"(sp));
    volatile unsigned *lo = (volatile unsigned *)((sp - 16384) & ~3L);
    for (int i = 0; i < PAINT_WORDS; i++) { lo[i] = 0xA5A5A5A5U; }
    int rc = app_main();
    unsigned long high_water = 0;
    for (int i = 0; i < PAINT_WORDS; i++) {
        if (lo[i] != 0xA5A5A5A5U) {
            high_water = (unsigned long)(sp - (long)&lo[i]);
            break;
        }
    }
    write_num(high_water);
    sys_exit(rc);
    __builtin_unreachable();
}
EOF

# The per-operation driver and its vectors are committed files shared
# with bench/insn-m3.sh: bench/insn_driver.c, bench/insn_vectors.h.

# Alpine clang defaults the stack protector ON; there is no libc to supply
# __stack_chk_fail here, and canaries would inflate the counts anyway. -G0
# keeps data out of the $gp-relative small-data sections: nothing sets up
# $gp without a crt0, and gp-relative loads fault at address zero.
CC="clang -target mips-linux-musl -march=mips32r2 -mno-abicalls -fno-pic -G0 \
    -Os -fno-stack-protector -ffreestanding -nostdlibinc -nostdlib \
    -fuse-ld=lld -static -I/src -I/src/bench -I$W/shim -I$W"
SRCS="/src/ct.c /src/sha256.c /src/hkdf.c /src/chacha20.c /src/poly1305.c \
      /src/aead.c /src/x25519.c /src/p256.c /src/rsa.c /src/rsa_mont.c \
      /src/buf.c /src/keysched.c /src/record.c \
      /src/sha3.c /src/mlkem.c /src/mlkem_poly.c"

build() { # $1 = OP macro  $2 = ITERS  -> binary path on stdout
    # CC holds the compiler and its flags, SRCS the sixteen source paths.
    # The shell has to split both into separate arguments; quoting either
    # would hand clang one argument containing spaces. Neither value holds a
    # glob character, so the other half of SC2086 does not apply.
    # shellcheck disable=SC2086
    $CC "-DOP_$1" "-DITERS=$2" /src/bench/insn_driver.c "$W/runtime.c" $SRCS -o "$W/bin_$1_$2"
    echo "$W/bin_$1_$2"
}

run_plain() { # $1 = binary: guest's stack high-water on stdout, dies on bad exit
    HW=$(qemu-mips "$1") || { echo "FAIL: guest exited $? running $1" >&2; exit 1; }
    echo "$HW"
}

count() { # $1 = binary: executed-instruction count on stdout
    run_plain "$1" >/dev/null
    qemu-mips -one-insn-per-tb -d exec,nochain -D /dev/stdout "$1" | wc -l || exit 1
}

# Determinism spot check: identical counts or the method is broken.
BIN=$(build SHA256_1K 4)
C1=$(count "$BIN")
C2=$(count "$BIN")
[ "$C1" -eq "$C2" ] || { echo "FAIL: counts not deterministic ($C1 vs $C2)" >&2; exit 1; }
echo "determinism check: two runs, both $C1 insns" >&2

echo "op,insns,stack_high_water_bytes"
row() { # $1 = CSV name  $2 = OP macro  $3 = ITERS  -> per-op insns on stdout fd 3
    BASE=$(count "$(build "$2" 0)")
    FULL_BIN=$(build "$2" "$3")
    HW=$(run_plain "$FULL_BIN")
    FULL=$(count "$FULL_BIN")
    INSNS=$(( (FULL - BASE) / $3 ))
    echo "$1,$INSNS,$HW"
    echo "  $1: $INSNS insns, stack $HW B" >&2
    eval "N_$2=$INSNS"
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

awk -v s="$N_SHA256_1K" -v h="$N_HKDF" -v a="$N_AEAD_1K" \
    -v x="$N_X25519" -v p="$N_P256" -v r="$N_RSA" -v hs="$N_HANDSHAKE" 'BEGIN {
    printf "# at 500 MHz and 1.0 IPC: sha256_1kib %.3f ms, hkdf_expand_label_32b %.3f ms, ", s / 5e5, h / 5e5
    printf "aead_seal_1kib %.3f ms, x25519_scalarmult %.3f ms, ", a / 5e5, x / 5e5
    printf "p256_ecdsa_verify %.3f ms, rsa_pss_verify_3072 %.3f ms, handshake_crypto %.3f ms\n", p / 5e5, r / 5e5, hs / 5e5
}'
awk -v x="$N_X25519" -v hs="$N_HANDSHAKE" 'BEGIN {
    printf "x25519 share of handshake_crypto: 2 x %d = %d of %d insns (%.1f%%)\n",
        x, 2 * x, hs, 200.0 * x / hs
}' >&2
