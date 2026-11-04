// GHASH for gcm_avx512_kernel.c, four elements to a 512-bit register on VPCLMULQDQ: the element
// layout, the products of a register of blocks and a register of powers, the reduction, the
// powers of the hash subkey, one step's GHASH in the slots between AES rounds, the last group,
// the associated data and the lengths block (docs/decisions.md 130).
//
// Only gcm_avx512_kernel.c includes this file, between the attribute push that turns its
// instructions on and its pop, so every function here carries that target, and nothing here is
// an entry of the object.
//
// The functions a step's rounds call carry always_inline, so that a step's GHASH and AES rounds
// lie in one function and the order of their instructions is the compiler's to interleave.
//
// Element layout. A block reversed byte for byte and read as a 128-bit little-endian integer
// holds SP 800-38D's x^0 coefficient in bit 127 and x^127 in bit 0. Every element here sits in
// that order, one per 128-bit lane, with its low 64-bit word in the lane's low half.
// ghash_vector.h keeps the two words the other way round, so this file computes its own powers
// and reads none of that header's.
//
// Products. Each power is H^k times x^-1, so the carry-less product of a reversed block and a
// power is the reversed 256-bit product of the block and H^k (ghash_vector.h states why). A
// register of four blocks meets a register of four powers in four VPCLMULQDQ: the low words'
// product, the high words' product and the two cross products, which add into the middle sum.
// A group adds the products of every register in it before it reduces.
//
// Reduction. With low the sum of the low words' products, high the sum of the high words' and
// middle the sum of the cross products, the two folds by 0xc200000000000000 that ghash_vector.h
// runs come to
//   c1 = clmul(word 0 of low, 0xc200000000000000)
//   t1 = low + swap(middle + c1)
//   c2 = clmul(word 1 of t1, 0xc200000000000000)
//   result = high + t1 + c2
// in each lane, where swap exchanges a lane's two words and + is exclusive-or, and the four
// lanes then add into one element.
//
// Timing. No line here branches on a value the key decides or indexes memory with one: the
// branches read lengths, a power's index and loop indices, and the byte shuffles take constant
// orders.
#ifndef CH_GCM_AVX512_GHASH_H
#define CH_GCM_AVX512_GHASH_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// The bytes of one 512-bit register, four blocks.
#define REGISTER_BYTES ((size_t)64)
// A whole step: eight registers, 32 blocks, 512 bytes, one GHASH reduction.
#define STEP_REGISTERS 8
#define STEP_BLOCKS ((size_t)32)
#define STEP_BYTES ((size_t)512)
// The last group holds up to 32 blocks and the lengths block, so up to nine registers.
#define GROUP_REGISTERS_MAX 9

// The powers, H^k times x^-1, highest first: power k sits in slot 36 - k, so H^33 is in slot 3,
// H^32 in slot 4, which starts a 64-byte line, and H^1 in slot 35. Slots 36 to 39 hold zeros. A
// register load at slot 36 - top gives H^top to H^(top - 3) in lanes 0 to 3, with zeros past
// H^1. 33 is the highest power a group meets: a seal whose text ends on a whole step hashes that
// step and the lengths block as one group.
#define POWER_SLOTS 40

typedef struct {
    _Alignas(64) __m128i powers[POWER_SLOTS];
} gcm_avx512_powers;

static inline __attribute__((always_inline)) size_t power_slot(size_t k) {
    return POWER_SLOTS - 4 - k;
}

// ---------------------------------------------------------------- elements

static inline __attribute__((always_inline)) __m512i reverse_lanes(__m512i v) {
    const __m512i order =
        _mm512_broadcast_i32x4(_mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
    return _mm512_shuffle_epi8(v, order);
}

static inline __attribute__((always_inline)) __m128i reverse_block(__m128i v) {
    return _mm_shuffle_epi8(v, _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
}

// a + b + c in GF(2): VPTERNLOGQ with the truth table of a three-way exclusive-or.
static inline __attribute__((always_inline)) __m512i add_three(__m512i a, __m512i b, __m512i c) {
    return _mm512_ternarylogic_epi64(a, b, c, 0x96);
}

// Each lane's two 64-bit words exchanged.
static inline __attribute__((always_inline)) __m512i swap_words(__m512i v) {
    return _mm512_shuffle_epi32(v, (_MM_PERM_ENUM)0x4e);
}

// 0xc200000000000000 in the low word of every lane.
static inline __attribute__((always_inline)) __m512i reduction_word(void) {
    return _mm512_broadcast_i32x4(_mm_set_epi64x(0, (long long)0xc200000000000000ULL));
}

// The sums of a group's products in each lane.
typedef struct {
    __m512i low;
    __m512i high;
    __m512i middle;
} hash_sums;

// The reduction at the top of the file, in each lane.
static inline __attribute__((always_inline)) __m512i reduce_lanes(__m512i low, __m512i high,
                                                                  __m512i middle) {
    const __m512i word = reduction_word();
    __m512i c1 = _mm512_clmulepi64_epi128(low, word, 0x00);
    __m512i t1 = _mm512_xor_si512(low, swap_words(_mm512_xor_si512(middle, c1)));
    __m512i c2 = _mm512_clmulepi64_epi128(t1, word, 0x01);
    return add_three(high, t1, c2);
}

// The four lanes of v added into one element.
static inline __attribute__((always_inline)) __m128i sum_lanes(__m512i v) {
    __m256i half = _mm256_xor_si256(_mm512_castsi512_si256(v), _mm512_extracti64x4_epi64(v, 1));
    return _mm_xor_si128(_mm256_castsi256_si128(half), _mm256_extracti128_si256(half, 1));
}

// a times b in each lane, for two powers: the product carries x^-1 once.
static inline __attribute__((always_inline)) __m512i multiply_lanes(__m512i a, __m512i b) {
    __m512i low = _mm512_clmulepi64_epi128(a, b, 0x00);
    __m512i high = _mm512_clmulepi64_epi128(a, b, 0x11);
    __m512i middle = _mm512_xor_si512(_mm512_clmulepi64_epi128(a, b, 0x01),
                                      _mm512_clmulepi64_epi128(a, b, 0x10));
    return reduce_lanes(low, high, middle);
}

// The same for one element, on the 128-bit instruction.
static inline __attribute__((always_inline)) __m128i multiply_block(__m128i a, __m128i b) {
    const __m128i word = _mm_set_epi64x(0, (long long)0xc200000000000000ULL);
    __m128i low = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i high = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i middle =
        _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x01), _mm_clmulepi64_si128(a, b, 0x10));
    __m128i c1 = _mm_clmulepi64_si128(low, word, 0x00);
    __m128i t1 = _mm_xor_si128(low, _mm_shuffle_epi32(_mm_xor_si128(middle, c1), 0x4e));
    __m128i c2 = _mm_clmulepi64_si128(t1, word, 0x01);
    return _mm_xor_si128(_mm_xor_si128(high, t1), c2);
}

// v times x^-1: v shifted up one bit, with x^-1, which reads 0xc2000000...01 in this order,
// added when bit 127 moved out. The arithmetic shift of the top 32-bit word, copied into all
// four, makes the mask, so no branch reads the bit.
static inline __attribute__((always_inline)) __m128i times_inverse_x(__m128i v) {
    __m128i carries = _mm_srli_epi64(v, 63);
    __m128i shifted = _mm_or_si128(_mm_slli_epi64(v, 1), _mm_slli_si128(carries, 8));
    __m128i mask = _mm_srai_epi32(_mm_shuffle_epi32(v, 0xff), 31);
    __m128i inverse_x = _mm_set_epi64x((long long)0xc200000000000000ULL, 1);
    return _mm_xor_si128(shifted, _mm_and_si128(mask, inverse_x));
}

static inline __attribute__((always_inline)) __m512i lanes_of(__m128i lane0, __m128i lane1,
                                                              __m128i lane2, __m128i lane3) {
    __m256i low = _mm256_set_m128i(lane1, lane0);
    __m256i high = _mm256_set_m128i(lane3, lane2);
    return _mm512_inserti64x4(_mm512_castsi256_si512(low), high, 1);
}

// ---------------------------------------------------------------- powers

// H^top to H^(top - 3) in lanes 0 to 3, read through a volatile lvalue, so that no compiler
// keeps a power in a register across a step and the powers stay in the one object the entry's
// wipe reaches.
static inline __attribute__((always_inline)) __m512i power_register(const gcm_avx512_powers *s,
                                                                    size_t top) {
    const volatile __m512i_u *p =
        (const volatile __m512i_u *)(const volatile void *)&s->powers[power_slot(top)];
    return *p;
}

static inline __attribute__((always_inline)) void store_power_register(gcm_avx512_powers *s,
                                                                       size_t top, __m512i v) {
    _mm512_storeu_si512((void *)&s->powers[power_slot(top)], v);
}

// The powers a call's groups meet, H^1 to at least H^top, 1 <= top <= 33, from first_power,
// which is H times x^-1. Each round multiplies the registers of the round before by the highest
// power so far, so the multiplies for H^33 wait on each other five deep.
static inline __attribute__((always_inline)) void compute_powers(gcm_avx512_powers *s,
                                                                 __m128i first_power, size_t top) {
    _mm512_storeu_si512((void *)&s->powers[power_slot(0)], _mm512_setzero_si512());
    if (top < 2) {
        _mm_storeu_si128(&s->powers[power_slot(1)], first_power);
        return;
    }
    __m128i second = multiply_block(first_power, first_power);
    __m128i third = multiply_block(second, first_power);
    __m128i fourth = multiply_block(second, second);
    __m512i up_to_4 = lanes_of(fourth, third, second, first_power);
    store_power_register(s, 4, up_to_4);
    if (top <= 4) {
        return;
    }
    __m512i up_to_8 = multiply_lanes(up_to_4, _mm512_broadcast_i32x4(fourth));
    store_power_register(s, 8, up_to_8);
    if (top <= 8) {
        return;
    }
    __m512i eighth = _mm512_broadcast_i32x4(_mm512_castsi512_si128(up_to_8));
    __m512i up_to_12 = multiply_lanes(up_to_4, eighth);
    __m512i up_to_16 = multiply_lanes(up_to_8, eighth);
    store_power_register(s, 12, up_to_12);
    store_power_register(s, 16, up_to_16);
    if (top <= 16) {
        return;
    }
    __m512i sixteenth = _mm512_broadcast_i32x4(_mm512_castsi512_si128(up_to_16));
    __m512i up_to_32 = multiply_lanes(up_to_16, sixteenth);
    store_power_register(s, 20, multiply_lanes(up_to_4, sixteenth));
    store_power_register(s, 24, multiply_lanes(up_to_8, sixteenth));
    store_power_register(s, 28, multiply_lanes(up_to_12, sixteenth));
    store_power_register(s, 32, up_to_32);
    if (top <= 32) {
        return;
    }
    _mm_storeu_si128(&s->powers[power_slot(33)],
                     multiply_block(_mm512_castsi512_si128(up_to_32), first_power));
}

// ---------------------------------------------------------------- GHASH

// The products of the reversed blocks x with the powers p, added into h or, where start is set,
// starting it. start is a constant at each call, so its branch leaves the compiled code.
static inline __attribute__((always_inline)) void add_products(hash_sums *h, int start, __m512i x,
                                                               __m512i p) {
    __m512i low = _mm512_clmulepi64_epi128(x, p, 0x00);
    __m512i high = _mm512_clmulepi64_epi128(x, p, 0x11);
    __m512i cross_a = _mm512_clmulepi64_epi128(x, p, 0x01);
    __m512i cross_b = _mm512_clmulepi64_epi128(x, p, 0x10);
    if (start) {
        h->low = low;
        h->high = high;
        h->middle = _mm512_xor_si512(cross_a, cross_b);
        return;
    }
    h->low = _mm512_xor_si512(h->low, low);
    h->high = _mm512_xor_si512(h->high, high);
    h->middle = add_three(h->middle, cross_a, cross_b);
}

// Four blocks of text at p, read through a volatile lvalue, so that the read stays between the
// volatile reads of the powers around it: gcc 13 otherwise read all eight registers of a step at
// its start, and the registers they held pushed a product into a stack slot of its own.
static inline __attribute__((always_inline)) __m512i text_register(const uint8_t *p) {
    const volatile __m512i_u *v = (const volatile __m512i_u *)(const volatile void *)p;
    return *v;
}

// One slot of a whole step's GHASH, the work that runs after AES round i: rounds 1 to 7 take the
// products of register i of the 32 blocks at data, round 8 those of register 0, which waits on
// the accumulator, and round 9 reduces. The accumulator joins the first block, and register r
// meets H^(32 - 4r) to H^(29 - 4r). Rounds 10 to 13 of AES-256 hash nothing. i is a constant
// at each call once the round loop unrolls, so the branches leave the compiled code.
static inline __attribute__((always_inline)) void
hash_slot(hash_sums *h, const gcm_avx512_powers *s, const uint8_t *data, size_t i, __m128i *acc) {
    if (i >= 1 && i < STEP_REGISTERS) {
        __m512i x = reverse_lanes(text_register(&data[i * REGISTER_BYTES]));
        add_products(h, i == 1, x, power_register(s, STEP_BLOCKS - 4 * i));
    } else if (i == STEP_REGISTERS) {
        __m512i x =
            _mm512_xor_si512(reverse_lanes(text_register(data)), _mm512_zextsi128_si512(*acc));
        add_products(h, 0, x, power_register(s, STEP_BLOCKS));
    } else if (i == STEP_REGISTERS + 1) {
        *acc = sum_lanes(reduce_lanes(h->low, h->high, h->middle));
    }
}

// GHASH over one whole step at data from acc, with no AES round between its slots.
static inline __attribute__((always_inline)) __m128i hash_step(const gcm_avx512_powers *s,
                                                               const uint8_t *data, __m128i acc) {
    hash_sums h;
#pragma GCC unroll 9
    for (size_t i = 1; i <= STEP_REGISTERS + 1; i++) {
        hash_slot(&h, s, data, i, &acc);
    }
    return acc;
}

// GHASH over blocks blocks held in data, in the order of the text with every byte past it zero,
// and then the lengths block, as one group from acc. blocks is at most 32, so the group fills at
// most nine registers, and its first register meets H^(blocks + 1).
static inline __attribute__((always_inline)) __m128i
hash_last_group(const gcm_avx512_powers *s, __m128i acc, const __m512i data[GROUP_REGISTERS_MAX],
                size_t blocks, __m128i lengths) {
    size_t total = blocks + 1;
    size_t registers = (total + 3) / 4;
    size_t lengths_register = blocks / 4;
    __mmask16 lengths_lane = (__mmask16)(0xfU << (4 * (blocks % 4)));
    hash_sums h;
#pragma GCC unroll 9
    for (size_t r = 0; r < GROUP_REGISTERS_MAX; r++) {
        if (r < registers) {
            __m512i x = data[r];
            if (r == lengths_register) {
                x = _mm512_mask_broadcast_i32x4(x, lengths_lane, lengths);
            }
            x = reverse_lanes(x);
            if (r == 0) {
                x = _mm512_xor_si512(x, _mm512_zextsi128_si512(acc));
            }
            add_products(&h, r == 0, x, power_register(s, total - 4 * r));
        }
    }
    return sum_lanes(reduce_lanes(h.low, h.high, h.middle));
}

// GHASH over the associated data from zero, a block at a time, with the last block padded with
// zeros: the byte mask loads the bytes the last block holds and no byte past them.
static inline __attribute__((always_inline)) __m128i hash_associated_data(__m128i first_power,
                                                                          const uint8_t *aad,
                                                                          size_t aad_len) {
    __m128i acc = _mm_setzero_si128();
    for (size_t off = 0; off < aad_len; off += AES_BLOCK) {
        size_t take = aad_len - off < AES_BLOCK ? aad_len - off : AES_BLOCK;
        __mmask64 mask = ((__mmask64)1 << take) - 1U;
        __m128i block = _mm512_castsi512_si128(_mm512_maskz_loadu_epi8(mask, &aad[off]));
        acc = multiply_block(_mm_xor_si128(acc, reverse_block(block)), first_power);
    }
    return acc;
}

// SP 800-38D's lengths block: the bit lengths of the associated data and the text, each 64 bits
// big-endian, as the block's bytes.
static inline __attribute__((always_inline)) __m128i lengths_block(size_t aad_len, size_t n) {
    uint64_t aad_bits = __builtin_bswap64((uint64_t)aad_len * 8U);
    uint64_t text_bits = __builtin_bswap64((uint64_t)n * 8U);
    return _mm_set_epi64x((long long)text_bits, (long long)aad_bits);
}

#endif // CH_CPU_RUNTIME && __x86_64__
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
