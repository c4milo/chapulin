// What aead_avx2.c's one pass leaves behind, for
// test/aead_avx2_equiv_test.c alone, which declares the generator, the
// failure count and the buffers this file uses.
//
// run_residue makes one seal and one open of RESIDUE_LENGTH bytes through
// aead_seal_cpu and aead_open_cpu, copies the stack below its caller as
// deep as RESIDUE_BYTES after each, and looks in the copy, at every byte
// offset, for the key's eight words side by side, as the input words of a
// pass hold them, for r's two 64-bit limbs side by side, as the key of
// poly1305_wide.h's step holds them, and for r^2 to r^8 as five words 4 or
// 32 bytes apart, as poly1305_avx2.c's struct of powers and an AVX2
// multiplier hold them. The calls wipe all three before they return. The search finds no key word
// alone, for the reason test/chacha20_equiv_residue.h gives.
//
// run_avx2_registers sets every bit of ymm0 to ymm15, calls each entry,
// and requires every bit of the sixteen registers zero after it, since
// they held the key's words, the keystream and the powers of r
// (test/avx2_registers.h).
#ifndef CH_AEAD_AVX2_EQUIV_RESIDUE_H
#define CH_AEAD_AVX2_EQUIV_RESIDUE_H

#include "avx2_registers.h"
#include "poly1305_wide.h"

#define RESIDUE_LENGTH ((size_t)4096 + 37)
#define RESIDUE_BYTES 8192
#define RESIDUE_POWERS 7
#define WORD_MASK_26 0x3ffffffU

static uint8_t residue_copy[RESIDUE_BYTES];

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static __attribute__((noinline)) void residue_seal(void) {
    aead_seal_cpu(ONE_PASS, key, nonce, aad, SHIFT, message, RESIDUE_LENGTH, sealed, sealed_tag);
}

static __attribute__((noinline)) int residue_open(void) {
    return aead_open_cpu(ONE_PASS, key, nonce, aad, SHIFT, sealed, RESIDUE_LENGTH, sealed_tag,
                         buffer);
}

// The one pass's entries called alone, from a poly1305 keyed as aead.c keys
// it, so that no call after them writes over their dead frames before the
// copy: aead.c's tag runs after them, and its frames reach the stack the
// entries left.
static __attribute__((noinline)) void residue_entry(int seal) {
    static poly1305 state;
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305_init(&state, otk);
    if (seal) {
        aead_avx2_seal(key, nonce, &state, message, RESIDUE_LENGTH, sealed);
    } else {
        aead_avx2_open(key, nonce, &state, sealed, RESIDUE_LENGTH, buffer);
    }
}

// value carried and reduced modulo 2^130 - 5 to its one form below it.
static void residue_reduce(const uint64_t in[5], uint32_t out[5]) {
    uint64_t d[5];
    memcpy(d, in, sizeof d);
    for (int round = 0; round < 3; round++) {
        for (size_t i = 0; i < 4; i++) {
            d[i + 1] += d[i] >> 26;
            d[i] &= WORD_MASK_26;
        }
        d[0] += (d[4] >> 26) * 5;
        d[4] &= WORD_MASK_26;
    }
    // value + 5 at or past 2^130 means value is at or past 2^130 - 5.
    uint64_t g[5];
    g[0] = d[0] + 5;
    for (size_t i = 0; i < 4; i++) {
        g[i + 1] = d[i + 1] + (g[i] >> 26);
        g[i] &= WORD_MASK_26;
    }
    int past = (g[4] >> 26) != 0;
    for (size_t i = 0; i < 5; i++) {
        out[i] = (uint32_t)(past ? (g[i] & WORD_MASK_26) : d[i]);
    }
}

static void residue_multiply(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
    uint64_t d[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 5; j++) {
            uint64_t product = (uint64_t)a[i] * b[j];
            // A product past word 4 is past 2^130, which is 5 modulo
            // 2^130 - 5.
            d[(i + j) % 5] += i + j < 5 ? product : 5 * product;
        }
    }
    residue_reduce(d, out);
}

// Whether the copy holds power as five words stride bytes apart.
static int residue_holds(const uint32_t power[5], size_t stride) {
    for (size_t at = 0; at + 4 * stride + 4 <= RESIDUE_BYTES; at++) {
        uint64_t words[5];
        int small = 1;
        for (size_t i = 0; i < 5; i++) {
            uint32_t word;
            memcpy(&word, &residue_copy[at + i * stride], sizeof word);
            small &= word < (UINT32_C(1) << 27);
            words[i] = word;
        }
        uint32_t value[5];
        residue_reduce(words, value);
        if (small && memcmp(value, power, sizeof value) == 0) {
            return 1;
        }
    }
    return 0;
}

// r from the Poly1305 key of key and nonce, clamped, in five words.
static void residue_r(uint32_t r[5]) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305 p;
    poly1305_init(&p, otk);
    memcpy(r, p.r, sizeof p.r);
}

static void residue_search(const char *call) {
    compared++;
    for (size_t at = 0; at + AEAD_KEY <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], key, AEAD_KEY) == 0) {
            failures++;
            (void)fprintf(stderr,
                          "aead avx2 equivalence: residue: the stack below %s holds the key "
                          "at byte %zu of the copy\n",
                          call, at);
            return;
        }
    }
    uint32_t r[5];
    uint32_t power[5];
    residue_r(r);
    poly1305_wide_key limbs;
    poly1305_wide_key_of(&limbs, r);
    const uint64_t pair[2] = {limbs.r0, limbs.r1};
    for (size_t at = 0; at + sizeof pair <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], pair, sizeof pair) == 0) {
            failures++;
            (void)fprintf(stderr,
                          "aead avx2 equivalence: residue: the stack below %s holds r's two "
                          "limbs at byte %zu of the copy\n",
                          call, at);
            return;
        }
    }
    memcpy(power, r, sizeof power);
    static const size_t strides[2] = {4, 32};
    for (size_t k = 2; k < 2 + RESIDUE_POWERS; k++) {
        residue_multiply(power, r, power);
        for (size_t s = 0; s < 2; s++) {
            if (residue_holds(power, strides[s])) {
                failures++;
                (void)fprintf(stderr,
                              "aead avx2 equivalence: residue: the stack below %s holds r^%zu, "
                              "one word every %zu bytes\n",
                              call, k, strides[s]);
                return;
            }
        }
    }
}

static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        printf("aead avx2 equivalence: SKIP the stack residue: %s\n", unsearched);
        return;
    }
    rng_fill(key, sizeof key);
    rng_fill(nonce, sizeof nonce);
    rng_fill(message, RESIDUE_LENGTH);
    residue_seal();
    residue_snapshot();
    residue_search("the seal");
    if (!residue_open()) {
        failures++;
        (void)fprintf(stderr, "aead avx2 equivalence: residue: the open refused the seal\n");
    }
    residue_snapshot();
    residue_search("the open");
    residue_entry(1);
    residue_snapshot();
    residue_search("aead_avx2_seal");
    residue_entry(0);
    residue_snapshot();
    residue_search("aead_avx2_open");
}

// One entry's registers after a call over n bytes. The call takes a
// poly1305 that holds the associated data, as aead.c's does.
static void registers_after(avx2_function entry, const char *name, size_t n) {
    static poly1305 state;
    uint8_t otk[CHACHA20_BLOCK];
    size_t at = 0;
    chacha20_block(key, nonce, 0, otk);
    poly1305_init(&state, otk);
    avx2_call c = {
        entry,
        {(uintptr_t)key, (uintptr_t)nonce, (uintptr_t)&state, (uintptr_t)message, n,
          (uintptr_t)sealed}
    };
    avx2_set_call_store(&c, 0);
    compared++;
    if (!avx2_registers_hold(0, &at)) {
        failures++;
        (void)fprintf(stderr,
                      "aead avx2 equivalence: registers: ymm%zu word %zu holds 0x%016llx after "
                      "%s over %zu bytes\n",
                      at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS,
                      (unsigned long long)avx2_register_word(at), name, n);
    }
}

static void run_avx2_registers(void) {
    size_t at = 0;
    avx2_call c = {
        NULL, {0, 0, 0, 0, 0, 0}
    };
    avx2_set_call_store(&c, 0);
    compared++;
    if (!avx2_registers_hold(UINT64_MAX, &at)) {
        failures++;
        (void)fprintf(stderr,
                      "aead avx2 equivalence: registers: the block of assembly left "
                      "ymm%zu word %zu unset, so it tests nothing\n",
                      at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS);
        return;
    }
#ifdef TEST_ADDRESS_SANITIZER
    printf("aead avx2 equivalence: SKIP the registers after the one pass: this binary runs under "
           "AddressSanitizer, whose code at the entry's return writes a vector register after "
           "VZEROALL\n");
    return;
#endif
    static const size_t lengths[] = {AEAD_AVX2_MIN, RESIDUE_LENGTH};
    for (size_t i = 0; i < 2; i++) {
        registers_after((avx2_function)aead_avx2_seal, "aead_avx2_seal", lengths[i]);
        registers_after((avx2_function)aead_avx2_open, "aead_avx2_open", lengths[i]);
    }
}

#endif
