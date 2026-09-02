#!/usr/bin/env bash
# Measures the crypto in rv32imac units: dynamic INSTRUCTION counts for
# the 32-bit little-endian build the riscv32 CI lane ships, compiled by
# the Bootlin gcc tools/toolchain.env pins at -march=rv32imac
# -mabi=ilp32 -Os. Builds a freestanding static Linux binary per
# operation from the shared bench/insn_driver.c (own _start, exit/write
# ecalls, byte-wise mem routines, no libc), runs it under qemu-riscv32
# user mode with one instruction per translation block, and counts
# executed instructions from the exec log. Counts are deterministic and
# baseline-subtracted: an ITERS=0 build of the same binary removes
# startup, input setup and the stack paint. Every input is fixed and no
# I/O happens inside a measured loop. memcpy is byte-wise here, so
# counts lean conservative. The toolchain ships x86_64 host binaries, so
# the measurement runs inside the x86_64 ubuntu container
# test/docker-riscv32.sh uses, and the download lands in
# bin/rv32tc-docker, where that script also keeps it. Writes
# bench/results-insn-rv32.csv. Skips without docker.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=tools/toolchain.env
    . tools/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP rv32 insn count: docker not available" >&2
        exit 0
    }
    TMPOUT=$(mktemp)
    trap 'rm -f "$TMPOUT"' EXIT
    # /src is writable for the toolchain download alone. The CSV comes
    # back on stdout: redirecting straight at the committed file would
    # truncate it the moment the run started, so a failing measurement
    # would destroy the last good numbers (the insn-mips.sh lesson).
    docker run --rm --platform linux/amd64 \
        -e "RV32_TC_VERSION=$RV32_TC_VERSION" \
        -e "RV32_TC_SHA256=$RV32_TC_SHA256" \
        -v "$PWD":/src -w /src "ubuntu@$UBUNTU_DIGEST" \
        bash /src/bench/insn-rv32.sh --inside > "$TMPOUT"
    mv "$TMPOUT" bench/results-insn-rv32.csv
    echo "wrote bench/results-insn-rv32.csv" >&2
    exit 0
fi

# ---- inside the container from here on; CSV goes to stdout ----
# Everything that is not a CSV line goes to stderr, apt and the checksum
# verdict included.
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q ca-certificates curl xz-utils qemu-user >/dev/null

# The same toolchain fetch as test/docker-riscv32.sh: the publisher's
# sha256 from tools/toolchain.env verifies the tarball before extraction.
tc=/src/bin/rv32tc-docker
name="riscv32-ilp32d--musl--${RV32_TC_VERSION:?}"
GCC="$tc/$name/bin/riscv32-linux-gcc"
if [ ! -x "$GCC" ]; then
    url="https://toolchains.bootlin.com/downloads/releases/toolchains/riscv32-ilp32d/tarballs/${name}.tar.xz"
    curl -sSL -o /tmp/rv32tc.tar.xz "$url"
    echo "${RV32_TC_SHA256:?}  /tmp/rv32tc.tar.xz" | sha256sum -c - >&2
    mkdir -p "$tc"
    tar -xJf /tmp/rv32tc.tar.xz -C "$tc"
fi
# The sha256 pin fixes the compiler, so its version needs no check here;
# it is printed, and the CSV header records it beside the numbers.
cver=$("$GCC" --version | head -1)
echo "$cver" >&2
qemu-riscv32 --version | head -1 >&2

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

# The runtime a libc would provide: entry, exit/write system calls
# (the rv32 Linux ABI: number in a7, arguments in a0..a2, ecall),
# byte-wise mem/str routines, and the two chapulin platform hooks.
# Stack painting mirrors how firmware measures high-water; its cost
# lands in baseline and full runs alike, so the subtraction drops it.
cat > "$W/runtime.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>

static void sys_exit(long code) {
    register long a7 __asm__("a7") = 93;
    register long a0 __asm__("a0") = code;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
}
static void sys_write(long fd, const void *buf, unsigned long n) {
    register long a7 __asm__("a7") = 64;
    register long a0 __asm__("a0") = fd;
    register long a1 __asm__("a1") = (long)buf;
    register long a2 __asm__("a2") = (long)n;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2) : "memory");
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

// gcc at -Os lowers a 64-bit shift by a runtime count to a libgcc call.
// The toolchain's libgcc is built for the ilp32d ABI and cannot link
// into an ilp32 image, so the runtime supplies the two routines the
// sources pull under the compiler's own names (the softmul.c
// precedent), written the way libgcc2.c writes them. Every count is
// public: a byte position, a length, a sequence number or a Keccak
// rotation constant.
typedef union {
    uint64_t ll;
    struct {
        uint32_t low, high; // little-endian halves
    } s;
} dword;
uint64_t __ashldi3(uint64_t u, int b) {
    if (b == 0) { return u; }
    dword uu = {.ll = u};
    dword w;
    int bm = 32 - b;
    if (bm <= 0) {
        w.s.low = 0;
        w.s.high = uu.s.low << -bm;
    } else {
        uint32_t carries = uu.s.low >> bm;
        w.s.low = uu.s.low << b;
        w.s.high = (uu.s.high << b) | carries;
    }
    return w.ll;
}
uint64_t __lshrdi3(uint64_t u, int b) {
    if (b == 0) { return u; }
    dword uu = {.ll = u};
    dword w;
    int bm = 32 - b;
    if (bm <= 0) {
        w.s.high = 0;
        w.s.low = uu.s.high >> -bm;
    } else {
        uint32_t carries = uu.s.high << bm;
        w.s.high = uu.s.high >> b;
        w.s.low = (uu.s.low >> b) | carries;
    }
    return w.ll;
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

// The entry point. The kernel sets sp and nothing else; the linker
// relaxes global accesses against gp, and only the entry may load it
// (with relaxation off, or the load itself relaxes to nothing), which
// firmware's crt0 does the same way. Everything else runs as C.
__asm__(".globl _start\n"
        "_start:\n"
        ".option push\n"
        ".option norelax\n"
        "la gp, __global_pointer$\n"
        ".option pop\n"
        "call start_c\n");

// Stack painting, the way firmware measures high-water: paint below sp
// at entry, run, then scan up for the deepest word the run dirtied.
enum { PAINT_WORDS = (16384 / 4) - 16 };
int app_main(void);
_Noreturn void start_c(void);
_Noreturn void start_c(void) {
    long sp;
    __asm__("mv %0, sp" : "=r"(sp));
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
# with bench/insn-mips.sh and bench/insn-m3.sh: bench/insn_driver.c,
# bench/insn_vectors.h.

# -nostdinc keeps musl's headers out and -isystem puts the compiler's
# own (stddef.h, stdint.h, stdnoreturn.h) back, so the shim is the whole
# libc surface. No libgcc: the toolchain carries one for ilp32d only,
# and the runtime above defines the two shift routines an rv32imac
# build pulls. No stack protector: nothing would supply
# __stack_chk_fail, and canaries would inflate the counts. The linker's
# one segment is read-write-execute, which a Linux process tolerates
# and firmware never links this way; the warning is noise here.
GCC_INCLUDE=$("$GCC" -print-file-name=include)
CC="$GCC -std=c11 -march=rv32imac -mabi=ilp32 -Os -ffreestanding \
    -nostdinc -isystem $GCC_INCLUDE -nostdlib -static -fno-pic -fno-pie -no-pie \
    -fno-stack-protector -Wl,--no-warn-rwx-segments \
    -I/src -I/src/bench -I$W/shim -I$W"
SRCS="/src/ct.c /src/sha256.c /src/hkdf.c /src/chacha20.c /src/poly1305.c \
      /src/aead.c /src/x25519.c /src/p256.c /src/rsa.c /src/rsa_mont.c \
      /src/buf.c /src/keysched.c /src/record.c \
      /src/sha3.c /src/mlkem.c /src/mlkem_poly.c"

build() { # $1 = OP macro  $2 = ITERS  -> binary path on stdout
    # CC holds the compiler and its flags, SRCS the sixteen source paths.
    # The shell has to split both into separate arguments; quoting either
    # would hand gcc one argument containing spaces. Neither value holds a
    # glob character, so the other half of SC2086 does not apply.
    # shellcheck disable=SC2086
    $CC "-DOP_$1" "-DITERS=$2" /src/bench/insn_driver.c "$W/runtime.c" $SRCS -o "$W/bin_$1_$2" \
        || { echo "FAIL: build $1 ITERS=$2" >&2; exit 1; }
    echo "$W/bin_$1_$2"
}

run_plain() { # $1 = binary: guest's stack high-water on stdout, dies on bad exit
    HW=$(qemu-riscv32 "$1") || { echo "FAIL: guest exited $? running $1" >&2; exit 1; }
    echo "$HW"
}

count() { # $1 = binary: executed-instruction count on stdout
    run_plain "$1" >/dev/null
    # The exec log goes to a pipe of its own (fd 3) and the guest's
    # stdout to /dev/null, so the high-water line the guest prints
    # never counts as an instruction and no multi-gigabyte log touches
    # the disk.
    qemu-riscv32 -one-insn-per-tb -d exec,nochain -D /dev/fd/3 "$1" 3>&1 >/dev/null | wc -l \
        || exit 1
}

# Determinism spot check: identical counts or the method is broken.
BIN=$(build SHA256_1K 4)
C1=$(count "$BIN")
C2=$(count "$BIN")
[ "$C1" -eq "$C2" ] || { echo "FAIL: counts not deterministic ($C1 vs $C2)" >&2; exit 1; }
echo "determinism check: two runs, both $C1 insns" >&2

echo "# $cver; -march=rv32imac -mabi=ilp32 -Os; qemu-riscv32 user mode"
echo "op,insns,stack_high_water_bytes"
row() { # $1 = CSV name  $2 = OP macro  $3 = ITERS
    BASE=$(count "$(build "$2" 0)")
    FULL_BIN=$(build "$2" "$3")
    HW=$(run_plain "$FULL_BIN")
    FULL=$(count "$FULL_BIN")
    INSNS=$(( (FULL - BASE) / $3 ))
    echo "$1,$INSNS,$HW"
    echo "  $1: $INSNS insns, stack $HW B" >&2
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
