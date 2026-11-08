// The one-pass ChaCha20-Poly1305 row of bin/x86_kernels_test
// (docs/decisions.md 199). A seal or an open of AEAD_AVX2_MIN bytes or more
// runs aead_avx2.c's entry once where the value holds CH_CPU_AVX2 and
// CH_CPU_CONSTANT_TIME_MULTIPLY and not CH_CPU_AVX512_IFMA, and then calls
// neither chacha20_avx2_xor nor poly1305_avx2_blocks_native. Under every
// other value it runs the two-pass AEAD, with the kernels
// test/x86_kernels_test.c's check_chacha20 names. An open under a wrong
// tag runs the one pass too, and returns 0 with zeros where the plaintext
// was. A record of the same length runs the same calls.
//
// Included by test/x86_kernels_test.c alone, after its calls_are, CHECK
// and names_ functions.
#ifndef CH_TEST_X86_KERNELS_AEAD_H
#define CH_TEST_X86_KERNELS_AEAD_H

#include "aead_avx2.h"

// Two passes of eight blocks and 37 bytes: the shortest one-pass length
// with a pass that absorbs, and a last pass that ends inside a row.
#define LONG_PAYLOAD (AEAD_AVX2_MIN + 37)

static unsigned long names_one_pass(uint32_t cpu) {
    return names_poly1305_avx2(cpu);
}

// Whether the calls since the last reset are the one pass's, or the
// two-pass AEAD's where the value names no one pass, and resets them.
static int aead_calls_are(uint32_t cpu, int seal, int keystream) {
    unsigned long one = names_one_pass(cpu);
    unsigned long seals = x86_aead_avx2_seal_calls;
    unsigned long opens = x86_aead_avx2_open_calls;
    x86_aead_avx2_seal_calls = 0;
    x86_aead_avx2_open_calls = 0;
    if (seals != (seal ? one : 0) || opens != (seal ? 0 : one)) {
        (void)fprintf(stderr, "calls: one-pass seal %lu, open %lu; want %lu, %lu\n", seals, opens,
                      seal ? one : 0, seal ? 0 : one);
        reset_calls();
        return 0;
    }
    unsigned long two = one ? 0 : 1;
    unsigned long avx2 = keystream ? two * names_chacha20_avx2(cpu) : 0;
    unsigned long avx512 = keystream ? two * names_chacha20_avx512(cpu) : 0;
    return calls_are(avx512, avx2, two * names_poly1305_ifma(cpu), two * names_poly1305_avx2(cpu),
                     0, 0, 0);
}

static void check_aead_one_pass(uint32_t cpu) {
    static uint8_t message[LONG_PAYLOAD];
    static uint8_t want[LONG_PAYLOAD];
    static uint8_t got[LONG_PAYLOAD];
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[5];
    uint8_t want_tag[AEAD_TAG];
    uint8_t got_tag[AEAD_TAG];
    fill(message, sizeof message, 0x55);
    fill(key, sizeof key, 0x11);
    fill(nonce, sizeof nonce, 0x22);
    fill(aad, sizeof aad, 0x33);
    aead_seal(widemul_of_cpu(cpu), key, nonce, aad, sizeof aad, message, LONG_PAYLOAD, want,
              want_tag);
    CHECK(aead_calls_are(0, 1, 1));
    aead_seal_cpu(cpu, key, nonce, aad, sizeof aad, message, LONG_PAYLOAD, got, got_tag);
    CHECK(aead_calls_are(cpu, 1, 1));
    CHECK(memcmp(got, want, LONG_PAYLOAD) == 0 && memcmp(got_tag, want_tag, AEAD_TAG) == 0);
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, want, LONG_PAYLOAD, want_tag, got) == 1);
    CHECK(aead_calls_are(cpu, 0, 1));
    CHECK(memcmp(got, message, LONG_PAYLOAD) == 0);
    // A wrong tag: the one pass decrypts while it absorbs and wipes what
    // it wrote, and the two-pass AEAD runs no keystream.
    want_tag[0] ^= 1;
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, want, LONG_PAYLOAD, want_tag, got) == 0);
    CHECK(aead_calls_are(cpu, 0, names_one_pass(cpu) != 0));
    int zeros = 1;
    for (size_t i = 0; names_one_pass(cpu) != 0 && i < LONG_PAYLOAD; i++) {
        zeros &= got[i] == 0;
    }
    CHECK(zeros);
}

#endif
