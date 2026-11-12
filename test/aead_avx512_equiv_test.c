// aead_avx512.c's one-pass ChaCha20-Poly1305 against the two-pass AEAD: the
// same key, nonce, associated data and input give the same output and the
// same tag, byte for byte (docs/decisions.md 226). The two-pass AEAD runs
// under ch_cfg.cpu CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY, which
// names chacha20_vector.c's keystream and the vector Poly1305, and
// bin/chacha20_equiv_test and bin/poly1305_equiv_test hold those paths to
// the portable loops.
//
// The one pass runs in two forms:
//
//   - its own text over the lane models, test/chacha20_avx512_model_lanes.h
//     and test/poly1305_ifma_model_lanes.h (test/aead_avx512_model.c), on
//     every machine, from a poly1305 keyed as aead.c keys it, with the tag
//     finished as aead.c finishes it;
//   - the instructions, through aead_seal_cpu and aead_open_cpu under the
//     same value with CH_CPU_AVX512_IFMA, as a record calls them, on a CPU
//     with AVX-512 IFMA.
//
// Every case checks the output bytes and the tag or the open's verdict, and
// the instructions' cases check that no byte outside the output changed,
// in each aliasing shape aead.h allows: a separate output, the output on
// the input, and the output below the input, as rec_open decrypts over its
// 5-byte header. The inputs, in order:
//
//   - every length from 0 to LENGTH_MAX, five passes of sixteen blocks, each
//     at one alignment past a 64-byte boundary, 7 times the length modulo
//     64, with 0 to 20 bytes of associated data;
//   - every length of the first one-pass pass that absorbs, 2,048 to 3,071
//     bytes, and the edges of the passes and rows after it, at every
//     alignment;
//   - a 16 KiB record with its content type byte, 16,385 bytes, and 16
//     KiB, at every alignment;
//   - for each length above, the open of a ciphertext with one bit of its
//     tag changed, which returns 0, and on the one pass leaves zeros where
//     the plaintext was.
//
// The model's cases run the lengths from AEAD_AVX512_MIN to LENGTH_MAX at
// one alignment, the edges and the two records, in the same three shapes.
//
// On a CPU with AVX-512 IFMA the binary then searches the stack below a
// seal and an open for the key's eight words side by side and for r^2 to
// r^16, and reads zmm0 to zmm31 and k1 to k7 back as zero after each entry
// (test/aead_avx512_equiv_residue.h). A CPU without AVX-512 IFMA skips
// those cases, unless CH_REQUIRE_AVX512_IFMA or CH_REQUIRE_AVX512 is 1, as
// the nightly's SDE runs and test/avx512-run.sh set them.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "aead_avx512.h"
#include "ch_assert.h"
#include "cpu_cfg.h"
#include "ct.h"
#include "widemul.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define TWO_PASS (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)
#define ONE_PASS (TWO_PASS | CH_CPU_AVX512_IFMA)

#define LENGTH_MAX ((size_t)5120)
#define ALIGN_MAX ((size_t)64)
#define AAD_MAX ((size_t)20)
#define RECORD ((size_t)16384)
// The record layer opens a record 5 bytes below its ciphertext.
#define SHIFT ((size_t)5)
#define GUARD ((size_t)64)
#define GUARD_BYTE 0xa5
// A separate output sits GUARD bytes past the input, and the start moves
// up to 63 bytes to a 64-byte boundary.
#define BUFFER (2 * (RECORD + 1) + 2 * ALIGN_MAX + SHIFT + 3 * GUARD)

// test/aead_avx512_model.c: the entries over the lane models.
void aead_avx512_model_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                            poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct);
void aead_avx512_model_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                            poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt);

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
        (void)fprintf(stderr, "aead avx512 equivalence: %s: %zu bytes at offset %zu, %s\n", what, n,
                      offset, shape_names[aliasing]);
    }
}

// Where the input and the output of a case sit in buffer, after GUARD
// bytes and offset bytes past a 64-byte boundary.
static void place(shape aliasing, size_t offset, size_t n, uint8_t **in, uint8_t **out) {
    uint8_t *base = buffer + GUARD + offset;
    base += (size_t)(-(uintptr_t)buffer % ALIGN_MAX);
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

// aead.c's MAC around the model's entries: the Poly1305 key, the
// associated data and its padding before, and the ciphertext's padding, the
// lengths and the tag after, under the native multiply.
static const uint8_t ZEROS[16] = {0};

static void model_start(poly1305 *p, size_t aad_len) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305_init(p, otk);
    ct_wipe(otk, sizeof otk);
    widemul_poly1305_update(WIDEMUL_CONSTANT_TIME, p, aad, aad_len);
    widemul_poly1305_update(WIDEMUL_CONSTANT_TIME, p, ZEROS, (16 - (aad_len % 16)) % 16);
}

static void model_end(poly1305 *p, size_t aad_len, size_t n, uint8_t tag[AEAD_TAG]) {
    widemul_poly1305_update(WIDEMUL_CONSTANT_TIME, p, ZEROS, (16 - (n % 16)) % 16);
    uint8_t lengths[16];
    for (int i = 0; i < 8; i++) {
        lengths[i] = (uint8_t)((uint64_t)aad_len >> (8 * i));
        lengths[8 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    }
    widemul_poly1305_update(WIDEMUL_CONSTANT_TIME, p, lengths, 16);
    widemul_poly1305_final(WIDEMUL_CONSTANT_TIME, p, tag);
}

static void check_model(size_t n, size_t aad_len, size_t offset, shape aliasing) {
    uint8_t *in;
    uint8_t *out;
    uint8_t tag[AEAD_TAG];
    poly1305 p;
    place(aliasing, offset, n, &in, &out);
    load(in, message, n);
    model_start(&p, aad_len);
    aead_avx512_model_seal(key, nonce, &p, in, n, out);
    model_end(&p, aad_len, n, tag);
    compared++;
    if (memcmp(out, sealed, n) != 0 || memcmp(tag, sealed_tag, AEAD_TAG) != 0) {
        report("the model's seal differs from the two-pass seal", n, offset, aliasing);
    }
    load(in, sealed, n);
    model_start(&p, aad_len);
    aead_avx512_model_open(key, nonce, &p, in, n, out);
    model_end(&p, aad_len, n, tag);
    compared++;
    if (memcmp(out, message, n) != 0 || memcmp(tag, sealed_tag, AEAD_TAG) != 0) {
        report("the model's open differs from the message", n, offset, aliasing);
    }
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
    // Below AEAD_AVX512_MIN the two-pass open runs and writes nothing.
    for (size_t i = 0; n >= AEAD_AVX512_MIN && i < n; i++) {
        if (out[i] != 0) {
            report("the open left plaintext after a changed tag", n, offset, aliasing);
            return;
        }
    }
}

static int run_instructions;

static void check_length(size_t n, size_t aad_len, size_t offset) {
    rng_fill(message, n);
    aead_seal_cpu(TWO_PASS, key, nonce, aad, aad_len, message, n, sealed, sealed_tag);
    for (shape aliasing = SEPARATE; aliasing <= BELOW; aliasing++) {
        if (run_instructions) {
            check_seal(n, aad_len, offset, aliasing);
            check_open(n, aad_len, offset, aliasing);
        } else if (n >= AEAD_AVX512_MIN) {
            check_model(n, aad_len, offset, aliasing);
        }
    }
}

// The edges of the passes and rows past the first pass that absorbs: a
// rest of 0, 1, 256 and 257 bytes, where the rest takes a row pass or a
// pass of sixteen blocks.
static const size_t edges[] = {2048, 2049, 2303, 2304, 2305, 3071, 3072, 3073,
                               3328, 3329, 4095, 4096, 4097, 4352, 4353, LENGTH_MAX};

static void run_cases(void) {
    rng_fill(key, sizeof key);
    rng_fill(nonce, sizeof nonce);
    rng_fill(aad, sizeof aad);
    for (size_t n = 0; n <= LENGTH_MAX; n++) {
        check_length(n, n % (AAD_MAX + 1), 7 * n % ALIGN_MAX);
    }
    for (size_t offset = 0; offset < ALIGN_MAX; offset++) {
        for (size_t n = AEAD_AVX512_MIN; run_instructions && n < AEAD_AVX512_MIN + 1024; n++) {
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

#if defined(CH_AEAD_AVX512) && defined(__x86_64__)
#include "aead_avx512_equiv_residue.h"
#endif

int main(void) {
    // The model on every machine.
    run_cases();
    if (failures != 0) {
        (void)fprintf(stderr, "aead avx512 equivalence: %lu of %lu checks of the model failed\n",
                      failures, compared);
        return 1;
    }
    unsigned long model_checks = compared;
#if defined(CH_AEAD_AVX512) && defined(__x86_64__)
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required() || x86_avx512_required()) {
            (void)fprintf(stderr, "aead avx512 equivalence: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA or CH_REQUIRE_AVX512 is 1\n");
            return 1;
        }
        printf("aead avx512 equivalence: %lu checks of the model agree with the two-pass AEAD; "
               "SKIP the instructions: this CPU lacks AVX-512 IFMA\n",
               model_checks);
        return 0;
    }
    run_instructions = 1;
    rng_state = UINT64_C(0x9e3779b97f4a7c15);
    run_cases();
    run_residue();
    if (failures != 0) {
        (void)fprintf(stderr, "aead avx512 equivalence: %lu of %lu checks failed\n", failures,
                      compared);
        return 1;
    }
    printf("aead avx512 equivalence: %lu checks of the model and %lu of the instructions agree "
           "with the two-pass AEAD\n",
           model_checks, compared - model_checks);
#else
    printf("aead avx512 equivalence: %lu checks of the model agree with the two-pass AEAD; SKIP "
           "the instructions: they exist in an x86-64 host object alone\n",
           model_checks);
#endif
    return 0;
}
