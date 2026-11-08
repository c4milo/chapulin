// aead_avx2.c's one-pass ChaCha20-Poly1305 against the two-pass AEAD: the
// same key, nonce, associated data and input give the same output and the
// same tag, byte for byte (docs/decisions.md 199). The two-pass AEAD runs
// under ch_cfg.cpu CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY, which
// names chacha20_vector.c's SSE2 keystream and the vector Poly1305, and
// bin/chacha20_equiv_test and bin/poly1305_equiv_test hold those paths to
// the portable loops. The one pass runs under the same value with
// CH_CPU_AVX2, through aead_seal_cpu and aead_open_cpu, as a record calls
// them.
//
// Every case checks the output bytes, the tag or the open's verdict, and
// that no byte outside the output changed, in each aliasing shape aead.h
// allows: a separate output, the output on the input, and the output
// below the input, as rec_open decrypts over its 5-byte header. The
// inputs, in order:
//
//   - every length from 0 to LENGTH_MAX, six passes of eight blocks, each
//     at one alignment past a 32-byte boundary, 7 times the length modulo
//     32, so the lengths take every alignment, with 0 to 20 bytes of
//     associated data;
//   - every length of the first one-pass pass that absorbs, 1,024 to
//     1,535 bytes, and the edges of the passes after it, at every
//     alignment;
//   - a 16 KiB record with its content type byte, 16,385 bytes, and 16
//     KiB, at every alignment;
//   - for each length above, the open of a ciphertext with one bit of its
//     tag changed, which returns 0, and on the one pass leaves zeros where
//     the plaintext was.
//
// On a CPU with AVX2 the binary then searches the stack below a seal and
// an open for the key's eight words side by side and for r^2 to r^8, and
// reads ymm0 to ymm15 back as zero after each entry (test/avx2_registers.h).
// A CPU without AVX2 skips every case, unless CH_REQUIRE_X86_KERNELS is 1.
// On arm64 the binary has nothing to compare and says so.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "aead_avx2.h"
#include "ch_assert.h"
#include "cpu_cfg.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// aead_avx2.h defines CH_AEAD_AVX2 on x86-64 alone; the second test keeps
// a checker that sets the first by hand from an arm it cannot run.
#if defined(CH_AEAD_AVX2) && defined(__x86_64__)

#define TWO_PASS (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)
#define ONE_PASS (TWO_PASS | CH_CPU_AVX2)

#define LENGTH_MAX ((size_t)3072)
#define ALIGN_MAX ((size_t)32)
#define AAD_MAX ((size_t)20)
#define RECORD ((size_t)16384)
// The record layer opens a record 5 bytes below its ciphertext.
#define SHIFT ((size_t)5)
#define GUARD ((size_t)32)
#define GUARD_BYTE 0xa5
// A separate output sits GUARD bytes past the input, and the start moves
// up to 31 bytes to a 32-byte boundary.
#define BUFFER (2 * (RECORD + 1) + 2 * ALIGN_MAX + SHIFT + 3 * GUARD)

// xorshift64 with a fixed seed, so a mismatch reproduces bit for bit.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

static unsigned long compared;
static unsigned long failures;

typedef enum { SEPARATE, IN_PLACE, BELOW } shape;

static const char *const shape_names[] = {"separate output", "in place", "output below input"};

static uint8_t key[AEAD_KEY];
static uint8_t nonce[AEAD_NONCE];
static uint8_t aad[AAD_MAX];
static uint8_t message[RECORD + 1];
static uint8_t sealed[RECORD + 1];
static uint8_t sealed_tag[AEAD_TAG];
static uint8_t buffer[BUFFER];

static void report(const char *what, size_t n, size_t offset, shape aliasing) {
    failures++;
    if (failures <= 20) {
        (void)fprintf(stderr, "aead avx2 equivalence: %s: %zu bytes at offset %zu, %s\n", what, n,
                      offset, shape_names[aliasing]);
    }
}

// Where the input and the output of a case sit in buffer, after GUARD
// bytes and offset bytes past a 32-byte boundary.
static void place(shape aliasing, size_t offset, size_t n, uint8_t **in, uint8_t **out) {
    uint8_t *base = buffer + GUARD + offset;
    base += (size_t)(-(uintptr_t)buffer % 32);
    switch (aliasing) {
    case SEPARATE:
        *in = base;
        *out = base + n + GUARD;
        return;
    case IN_PLACE:
        *in = base;
        *out = base;
        return;
    case BELOW:
        *in = base + SHIFT;
        *out = base;
        return;
    }
}

// Whether every byte of buffer outside [out, out + n) holds GUARD_BYTE or
// sits in [in, in + n).
static int outside_kept(const uint8_t *in, const uint8_t *out, size_t n) {
    for (size_t i = 0; i < BUFFER; i++) {
        const uint8_t *at = buffer + i;
        int inside = (at >= out && at < out + n) || (at >= in && at < in + n);
        if (!inside && *at != GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

// The input of a case: GUARD_BYTE everywhere, then src's n bytes at in.
static void load(uint8_t *in, const uint8_t *src, size_t n) {
    memset(buffer, GUARD_BYTE, sizeof buffer);
    memcpy(in, src, n);
}

static void check_seal(size_t n, size_t aad_len, size_t offset, shape aliasing) {
    uint8_t *in;
    uint8_t *out;
    uint8_t tag[AEAD_TAG];
    place(aliasing, offset, n, &in, &out);
    load(in, message, n);
    aead_seal_cpu(ONE_PASS, key, nonce, aad, aad_len, in, n, out, tag);
    compared++;
    if (memcmp(out, sealed, n) != 0 || memcmp(tag, sealed_tag, AEAD_TAG) != 0) {
        report("the seal differs from the two-pass seal", n, offset, aliasing);
    } else if (!outside_kept(in, out, n)) {
        report("the seal wrote outside its output", n, offset, aliasing);
    }
}

// The open of the sealed bytes, and of the same bytes under a tag with
// one bit changed.
static void check_open(size_t n, size_t aad_len, size_t offset, shape aliasing) {
    uint8_t *in;
    uint8_t *out;
    place(aliasing, offset, n, &in, &out);
    load(in, sealed, n);
    compared++;
    if (!aead_open_cpu(ONE_PASS, key, nonce, aad, aad_len, in, n, sealed_tag, out) ||
        memcmp(out, message, n) != 0) {
        report("the open differs from the message", n, offset, aliasing);
    } else if (!outside_kept(in, out, n)) {
        report("the open wrote outside its output", n, offset, aliasing);
    }
    uint8_t bad[AEAD_TAG];
    memcpy(bad, sealed_tag, AEAD_TAG);
    bad[rng_next() % AEAD_TAG] ^= (uint8_t)(1U << (rng_next() % 8));
    load(in, sealed, n);
    compared++;
    if (aead_open_cpu(ONE_PASS, key, nonce, aad, aad_len, in, n, bad, out)) {
        report("the open took a changed tag", n, offset, aliasing);
        return;
    }
    // Below AEAD_AVX2_MIN the two-pass open runs and writes nothing.
    for (size_t i = 0; n >= AEAD_AVX2_MIN && i < n; i++) {
        if (out[i] != 0) {
            report("the open left plaintext after a changed tag", n, offset, aliasing);
            return;
        }
    }
}

static void check_length(size_t n, size_t aad_len, size_t offset) {
    rng_fill(message, n);
    aead_seal_cpu(TWO_PASS, key, nonce, aad, aad_len, message, n, sealed, sealed_tag);
    for (shape aliasing = SEPARATE; aliasing <= BELOW; aliasing++) {
        check_seal(n, aad_len, offset, aliasing);
        check_open(n, aad_len, offset, aliasing);
    }
}

static void run_cases(void) {
    rng_fill(key, sizeof key);
    rng_fill(nonce, sizeof nonce);
    rng_fill(aad, sizeof aad);
    for (size_t n = 0; n <= LENGTH_MAX; n++) {
        check_length(n, n % (AAD_MAX + 1), 7 * n % ALIGN_MAX);
    }
    static const size_t edges[] = {1023, 1536, 1537, 2047, 2048, 2049, 2559, 2560, LENGTH_MAX};
    for (size_t offset = 0; offset < ALIGN_MAX; offset++) {
        for (size_t n = AEAD_AVX2_MIN; n < AEAD_AVX2_MIN + 512; n++) {
            check_length(n, (n + offset) % (AAD_MAX + 1), offset);
        }
        for (size_t i = 0; i < sizeof edges / sizeof edges[0]; i++) {
            check_length(edges[i], offset % (AAD_MAX + 1), offset);
        }
    }
    static const size_t records[] = {RECORD, RECORD + 1};
    for (size_t i = 0; i < 2; i++) {
        for (size_t offset = 0; offset < ALIGN_MAX; offset++) {
            check_length(records[i], SHIFT, offset);
        }
    }
}

#include "aead_avx2_equiv_residue.h"

int main(void) {
    if (!x86_cpu_has_avx2()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "aead avx2 equivalence: this CPU lacks AVX2, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            return 1;
        }
        printf("aead avx2 equivalence: SKIP the one pass: this CPU lacks AVX2\n");
        return 0;
    }
    run_cases();
    run_residue();
    run_avx2_registers();
    if (failures != 0) {
        (void)fprintf(stderr, "aead avx2 equivalence: %lu of %lu checks failed\n", failures,
                      compared);
        return 1;
    }
    printf("aead avx2 equivalence: %lu checks agree between the one pass and the two-pass "
           "AEAD\n",
           compared);
    return 0;
}

#else

int main(void) {
    printf("aead avx2 equivalence: SKIP the one pass: it exists in an x86-64 host object "
           "alone\n");
    return 0;
}

#endif
