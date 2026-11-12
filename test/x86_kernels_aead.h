// The one-pass ChaCha20-Poly1305 rows of bin/x86_kernels_test
// (docs/decisions.md 199 and 226). A seal or an open of AEAD_AVX2_MIN bytes
// or more runs aead_avx2.c's entry once where the value holds CH_CPU_AVX2
// and CH_CPU_CONSTANT_TIME_MULTIPLY and not CH_CPU_AVX512_IFMA, and one of
// AEAD_AVX512_MIN bytes or more runs aead_avx512.c's entry once where the
// value holds CH_CPU_AVX512_IFMA and the multiply bit. Either then calls
// neither keystream kernel nor either Poly1305 kernel. Under every other
// value and length it runs the two-pass AEAD, with the kernels
// test/x86_kernels_test.c's check_chacha20 names. An open under a wrong
// tag runs the one pass too, and returns 0 with zeros where the plaintext
// was. A record of the same length runs the same calls.
//
// Included by test/x86_kernels_test.c alone, after its calls_are, CHECK
// and names_ functions.
#ifndef CH_TEST_X86_KERNELS_AEAD_H
#define CH_TEST_X86_KERNELS_AEAD_H

#include "aead_avx2.h"
#include "aead_avx512.h"

// Two passes of eight blocks and 37 bytes: the shortest AVX2 one-pass
// length with a pass that absorbs, and a last pass that ends inside a row.
#define LONG_PAYLOAD (AEAD_AVX2_MIN + 37)
// Two passes of sixteen blocks and 37 bytes: the same for the AVX-512 one
// pass, whose last bytes take a row pass beside the last whole pass.
#define LONGER_PAYLOAD (AEAD_AVX512_MIN + 37)

// The one pass a value runs n bytes on: 512 for aead_avx512.c's, 256 for
// aead_avx2.c's, and 0 for the two passes.
static int one_pass_of(uint32_t cpu, size_t n) {
    if (names_poly1305_ifma(cpu) != 0) {
        return n >= AEAD_AVX512_MIN ? 512 : 0;
    }
    return names_poly1305_avx2(cpu) != 0 && n >= AEAD_AVX2_MIN ? 256 : 0;
}

// The calls into the two one-pass entries: aead_avx512.c's seal and open,
// then aead_avx2.c's.
typedef struct {
    unsigned long seals_512;
    unsigned long opens_512;
    unsigned long seals_256;
    unsigned long opens_256;
} one_pass_calls;

// The one-pass calls since the last reset. It resets the four counts.
static one_pass_calls take_one_pass_calls(void) {
    one_pass_calls calls = {x86_aead_avx512_seal_calls, x86_aead_avx512_open_calls,
                            x86_aead_avx2_seal_calls, x86_aead_avx2_open_calls};
    x86_aead_avx512_seal_calls = 0;
    x86_aead_avx512_open_calls = 0;
    x86_aead_avx2_seal_calls = 0;
    x86_aead_avx2_open_calls = 0;
    return calls;
}

// The one-pass calls of one seal or one open on the pass one names: one
// call into that pass's entry, and none where one is 0.
static one_pass_calls one_pass_calls_of(int one, int seal) {
    unsigned long on_512 = one == 512 ? 1 : 0;
    unsigned long on_256 = one == 256 ? 1 : 0;
    one_pass_calls want = {0, 0, 0, 0};
    if (seal) {
        want.seals_512 = on_512;
        want.seals_256 = on_256;
    } else {
        want.opens_512 = on_512;
        want.opens_256 = on_256;
    }
    return want;
}

// Whether the calls since the last reset are the one pass's, or the
// two-pass AEAD's where the value names no one pass for n bytes, and
// resets them.
static int aead_calls_are(uint32_t cpu, size_t n, int seal, int keystream) {
    int one = one_pass_of(cpu, n);
    one_pass_calls got = take_one_pass_calls();
    one_pass_calls want = one_pass_calls_of(one, seal);
    if (got.seals_512 != want.seals_512 || got.opens_512 != want.opens_512 ||
        got.seals_256 != want.seals_256 || got.opens_256 != want.opens_256) {
        (void)fprintf(stderr,
                      "calls: AVX-512 one-pass seal %lu, open %lu, AVX2 one-pass seal %lu, open "
                      "%lu; want %lu, %lu, %lu, %lu\n",
                      got.seals_512, got.opens_512, got.seals_256, got.opens_256, want.seals_512,
                      want.opens_512, want.seals_256, want.opens_256);
        reset_calls();
        return 0;
    }
    unsigned long two = one != 0 ? 0 : 1;
    unsigned long avx2 = keystream ? two * names_chacha20_avx2(cpu) : 0;
    unsigned long avx512 = keystream ? two * names_chacha20_avx512(cpu) : 0;
    return calls_are(avx512, avx2, two * names_poly1305_ifma(cpu), two * names_poly1305_avx2(cpu),
                     0, 0, 0);
}

static void check_aead_length(uint32_t cpu, size_t n) {
    static uint8_t message[LONGER_PAYLOAD];
    static uint8_t want[LONGER_PAYLOAD];
    static uint8_t got[LONGER_PAYLOAD];
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[5];
    uint8_t want_tag[AEAD_TAG];
    uint8_t got_tag[AEAD_TAG];
    fill(message, n, 0x55);
    fill(key, sizeof key, 0x11);
    fill(nonce, sizeof nonce, 0x22);
    fill(aad, sizeof aad, 0x33);
    aead_seal(widemul_of_cpu(cpu), key, nonce, aad, sizeof aad, message, n, want, want_tag);
    CHECK(aead_calls_are(0, n, 1, 1));
    aead_seal_cpu(cpu, key, nonce, aad, sizeof aad, message, n, got, got_tag);
    CHECK(aead_calls_are(cpu, n, 1, 1));
    CHECK(memcmp(got, want, n) == 0 && memcmp(got_tag, want_tag, AEAD_TAG) == 0);
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, want, n, want_tag, got) == 1);
    CHECK(aead_calls_are(cpu, n, 0, 1));
    CHECK(memcmp(got, message, n) == 0);
    // A wrong tag: the one pass decrypts while it absorbs and wipes what
    // it wrote, and the two-pass AEAD runs no keystream.
    want_tag[0] ^= 1;
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, want, n, want_tag, got) == 0);
    CHECK(aead_calls_are(cpu, n, 0, one_pass_of(cpu, n) != 0));
    int zeros = 1;
    for (size_t i = 0; one_pass_of(cpu, n) != 0 && i < n; i++) {
        zeros &= got[i] == 0;
    }
    CHECK(zeros);
}

static void check_aead_one_pass(uint32_t cpu) {
    check_aead_length(cpu, LONG_PAYLOAD);
    check_aead_length(cpu, LONGER_PAYLOAD);
}

#endif
