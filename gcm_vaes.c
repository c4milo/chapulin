// An x86-64 host object's AES-GCM: gcm_hw.c's three loops on 256-bit
// registers, two blocks to a register. gcm_vaes.h states the contracts.
// The loops keep gcm_hw.c's order: counter mode, the seal's counter mode
// and GHASH over the ciphertext written before, and the open's GHASH ahead
// of its counter mode. Each runs its AES rounds a step at a time, two of
// gcm_hw.h's passes, sixteen blocks in eight registers, and hashes a step a
// pass at a time.
//
// Why a step is two passes. VAESENC runs a round on two blocks, and the
// next round of the same register waits on it, so the rounds of one pass,
// four registers, left the AES units idle between rounds. Eight registers
// keep them busy, and fit beside the round key in AVX2's sixteen
// (docs/decisions.md 90). GHASH keeps its pass of eight blocks, so its
// powers and its reduction are ghash_vector.h's.
//
// The instructions. VAESENC and VAESENCLAST run one AES round on each
// 128-bit half of a register under the round key in the same half, so a
// round key loaded into both halves runs two blocks at once. VPCLMULQDQ
// computes one carry-less product of two 64-bit words in each half, with
// the same immediate picking the words in both. Each half computes what
// AESENC, AESENCLAST and PCLMULQDQ compute on a 128-bit register, which
// is how Intel's manual defines them.
//
// GHASH over a pass. ghash_vector.h multiplies each of a pass's eight
// blocks by a power of the hash subkey with three carry-less products in
// Karatsuba's form, adds the products of all eight, and reduces once.
// Here each register holds two of the blocks and the two powers they
// meet, so one VPCLMULQDQ computes a product for both, and a pass takes 12
// for its products where ghash_vector.h takes 24. The two halves of each
// sum are then added into one 128-bit sum, which is the sum
// ghash_vector.h forms, and its reduction runs on that sum unchanged. The
// powers are ghash_vector.h's, computed by its ghash_compute_powers and
// then paired, so both paths multiply by the same values.
//
// Timing. No line here branches on an operand or indexes memory with one.
// The branches read the round count and the block count. The byte
// shuffles (VPSHUFB) take constant orders, so which byte moves where
// depends on nothing the cipher computes. Whether VAESENC and VPCLMULQDQ
// take the same time whatever their operands are is the claim the
// caller's CH_CPU_CONSTANT_TIME_AES bit makes for the AES instructions and
// the carry-less multiply at every width (docs/decisions.md 89), and
// gcm_vaes.h's gcm_use_vaes runs these kernels only where that bit and
// CH_CPU_VAES are set.
//
// Every value the seal computes from the key sits in one gcm_vaes_state,
// wiped once when the call ends, as gcm_hw.c's gcm_hw_state is. Counter
// mode keeps its keystream in an array it wipes the same way.
//
// CBMC cannot read an intrinsic, so test/aes_equiv_test.c and
// test/ghash_equiv_test.c hold these kernels to gcm.c's one-block counter
// loop and portable GHASH byte for byte, on a CPU that has the
// instructions.
#include "gcm_vaes.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stddef.h>
#include <string.h>

#include "ct.h"
#include "gcm_hw.h"
// ghash_vector.h comes before the target attribute below, so its
// functions keep the target they declare for themselves. These functions
// call them, and a function may inline one whose instructions are a
// subset of its own.
#include "ghash_vector.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns on AES-NI, PCLMULQDQ, AVX2, VAES and
// VPCLMULQDQ, and no function outside it does. clang applies it through
// one attribute push; gcc's target pragma sets it for each function
// defined after it, until the pop. gcm.c calls these functions, through
// gcm_vaes.h's three entries, only where the bits a key's schedule
// records say the CPU has them.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("aes,pclmul,avx2,vaes,vpclmulqdq"))),           \
                             apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("aes,pclmul,avx2,vaes,vpclmulqdq")
#endif

// Two blocks in one register: the block that comes first in the data in
// the low 128 bits, the next in the high 128 bits. A pass of
// GCM_HW_PASS_BLOCKS blocks is PASS_PAIRS registers, and a step of
// STEP_PASSES passes is STEP_PAIRS registers. Each loop over a step's
// registers carries #pragma GCC unroll 8, for the reason gcm_hw.c gives:
// gcc keeps an array that a rolled loop indexes in memory.
typedef __m256i state_pair;
#define PASS_PAIRS (GCM_HW_PASS_BLOCKS / 2)
#define STEP_PASSES 2
#define STEP_PAIRS ((size_t)STEP_PASSES * PASS_PAIRS)
#define STEP_BLOCKS ((size_t)STEP_PASSES * GCM_HW_PASS_BLOCKS)
#define PAIR_BYTES ((size_t)2 * AES_BLOCK)
#define PASS_BYTES ((size_t)GCM_HW_PASS_BLOCKS * AES_BLOCK)
_Static_assert(STEP_PAIRS == 8, "each #pragma GCC unroll 8 below writes STEP_PAIRS out");

// Two blocks move between memory and a register through memcpy, so no
// load assumes the caller's buffer is aligned.
static state_pair load_state(const uint8_t p[PAIR_BYTES]) {
    state_pair v;
    memcpy(&v, p, PAIR_BYTES);
    return v;
}

static void store_state(uint8_t p[PAIR_BYTES], state_pair v) {
    memcpy(p, &v, PAIR_BYTES);
}

// Round key i of the schedule in both halves of a register.
static state_pair round_key_in_both_halves(const uint8_t *round_keys, size_t i) {
    __m128i key;
    memcpy(&key, &round_keys[i * AES_BLOCK], AES_BLOCK);
    return _mm256_broadcastsi128_si256(key);
}

// gcm_hw.c's three steps of a pass, as its x86-64 arm runs them, over a
// step's registers: VAESENC is a whole round with its AddRoundKey at the
// end, so the first AddRoundKey is written out, round i takes round key
// i + 1, and the last round drops MixColumns.
static void step_start(state_pair states[STEP_PAIRS], const uint8_t *round_keys) {
    state_pair first = round_key_in_both_halves(round_keys, 0);
#pragma GCC unroll 8
    for (size_t b = 0; b < STEP_PAIRS; b++) {
        states[b] = _mm256_xor_si256(states[b], first);
    }
}

static void step_round(state_pair states[STEP_PAIRS], const uint8_t *round_keys, size_t i) {
    state_pair key = round_key_in_both_halves(round_keys, i + 1);
#pragma GCC unroll 8
    for (size_t b = 0; b < STEP_PAIRS; b++) {
        states[b] = _mm256_aesenc_epi128(states[b], key);
    }
}

static void step_final(state_pair states[STEP_PAIRS], const uint8_t *round_keys, size_t rounds) {
    state_pair last = round_key_in_both_halves(round_keys, rounds);
#pragma GCC unroll 8
    for (size_t b = 0; b < STEP_PAIRS; b++) {
        states[b] = _mm256_aesenclast_epi128(states[b], last);
    }
}

// Every round of a step with nothing between them, marked inline for the
// reason gcm_hw.c's cipher_pass is.
static inline void cipher_step(state_pair states[STEP_PAIRS], const uint8_t *round_keys,
                               size_t rounds) {
    step_start(states, round_keys);
    for (size_t i = 0; i + 1 < rounds; i++) {
        step_round(states, round_keys, i);
    }
    step_final(states, round_keys, rounds);
}

// The counter block's first twelve bytes, with zeros where the count goes,
// in reverse byte order and in both halves. Reversed, the count's four
// bytes, which SP 800-38D §6.2 writes big-endian in bytes 12 to 15, sit
// in the lowest 32-bit lane of each half as a number, so a 32-bit add
// there is inc32: it wraps modulo 2^32 and never reaches the other
// twelve bytes.
static state_pair counter_prefix(const uint8_t counter[AES_BLOCK]) {
    const __m128i reverse = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    uint8_t prefix_bytes[AES_BLOCK] = {0};
    memcpy(prefix_bytes, counter, AES_BLOCK - 4);
    __m128i prefix;
    memcpy(&prefix, prefix_bytes, AES_BLOCK);
    return _mm256_broadcastsi128_si256(_mm_shuffle_epi8(prefix, reverse));
}

static uint32_t counter_count(const uint8_t counter[AES_BLOCK]) {
    return ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16) |
           ((uint32_t)counter[14] << 8) | counter[15];
}

// counter's last four bytes = count, big-endian.
static void set_counter_count(uint8_t counter[AES_BLOCK], uint32_t count) {
    counter[12] = (uint8_t)(count >> 24);
    counter[13] = (uint8_t)(count >> 16);
    counter[14] = (uint8_t)(count >> 8);
    counter[15] = (uint8_t)count;
}

// The step's counter blocks, first to first + 15, into states: block 2b
// in the low half of states[b] and block 2b + 1 in its high half. Each
// count is added to the reversed prefix in its lowest lane, and one byte
// shuffle puts each half's sixteen bytes back in order. The AVX2 calls
// take a lane's word as an int; the casts keep its 32 bits, which is how
// gcc and clang define the conversion of a value above INT_MAX.
static void fill_counters(state_pair states[STEP_PAIRS], state_pair prefix, uint32_t first) {
    const state_pair reverse =
        _mm256_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11,
                         10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const state_pair two = _mm256_setr_epi32(2, 0, 0, 0, 2, 0, 0, 0);
    state_pair counts = _mm256_add_epi32(
        prefix, _mm256_setr_epi32((int)first, 0, 0, 0, (int)(first + 1U), 0, 0, 0));
#pragma GCC unroll 8
    for (size_t b = 0; b < STEP_PAIRS; b++) {
        states[b] = _mm256_shuffle_epi8(counts, reverse);
        counts = _mm256_add_epi32(counts, two);
    }
}

// Each block of out is the block of in at the same place exclusive-ored
// with the step's keystream, a register at a time, and the last block
// alone through the low half of its register when take is odd. A
// register's input is read before its output is written, and an output
// register ends before the next input register begins when out is at or
// below in.
static void xor_step(const state_pair keystream[STEP_PAIRS], const uint8_t *in, size_t take,
                     uint8_t *out) {
    size_t pairs = take / 2;
#pragma GCC unroll 8
    for (size_t b = 0; b < pairs; b++) {
        store_state(&out[b * PAIR_BYTES],
                    _mm256_xor_si256(load_state(&in[b * PAIR_BYTES]), keystream[b]));
    }
    if (2 * pairs < take) {
        __m128i data;
        memcpy(&data, &in[pairs * PAIR_BYTES], AES_BLOCK);
        __m128i result = _mm_xor_si128(data, _mm256_castsi256_si128(keystream[pairs]));
        memcpy(&out[pairs * PAIR_BYTES], &result, AES_BLOCK);
    }
}

// xor_step over the first pairs registers of a step, 4 for one pass or 8
// for two, with each register's output written back over its keystream
// too, for the reason gcm_hw.c's xor_pass_in_place gives. The registers
// past pairs keep the keystream of blocks no pass of this call holds, and
// the wipe at the end of the call clears them.
static inline void xor_step_in_place(state_pair states[STEP_PAIRS], size_t pairs, const uint8_t *in,
                                     uint8_t *out) {
#pragma GCC unroll 8
    for (size_t b = 0; b < STEP_PAIRS; b++) {
        if (b < pairs) {
            states[b] = _mm256_xor_si256(load_state(&in[b * PAIR_BYTES]), states[b]);
            store_state(&out[b * PAIR_BYTES], states[b]);
        }
    }
}

// Two powers of the hash subkey, one per half, and each half's two words
// added in both its lanes: the operands the products of a pair of blocks
// take, computed once for every pass.
typedef struct {
    __m256i power;
    __m256i halves_added;
} pass_hash_power;

// What GHASH over a pass computes from the hash subkey: ghash_vector.h's
// state, which holds the subkey, the accumulator, the sums before the
// reduction and the eight powers, and the four pairs of those powers.
// pairs[j] holds the powers blocks 2j and 2j + 1 of a pass meet:
// H^(8 - 2j) * x^-1 in its low half and H^(7 - 2j) * x^-1 in its high
// half.
typedef struct {
    ghash_state single;
    pass_hash_power pairs[GHASH_PASS_BLOCKS / 2];
} pass_hash_state;

// What the seal computes from the key, in one object for one wipe: the
// GHASH state and the step's counter blocks, which the rounds turn into
// its keystream and the exclusive-or into its output.
typedef struct {
    pass_hash_state hash;
    state_pair keystream[STEP_PAIRS];
} gcm_vaes_state;

// The three products of a pair of blocks and a pair of powers, each
// still in two halves, summed over the pairs of a pass.
typedef struct {
    __m256i low;
    __m256i high;
    __m256i middle;
} pass_hash_sums;

// Two blocks as two elements, each in the order ghash_vector.h holds an
// element: one byte shuffle reverses the eight bytes of each 64-bit half,
// as ghash_load_block does for one block.
static __m256i load_pair(const uint8_t data[PAIR_BYTES]) {
    const __m256i order = _mm256_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7,
                                           6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
    return _mm256_shuffle_epi8(load_state(data), order);
}

// v's two words added, in both lanes of each half: _mm256_shuffle_epi32
// with 0x4e exchanges the two 64-bit lanes of each half.
static __m256i pair_halves_added(__m256i v) {
    return _mm256_xor_si256(v, _mm256_shuffle_epi32(v, 0x4e));
}

// pairs[j]'s power and halves added, read through a volatile lvalue for
// the reason ghash_power_at gives, so no compiler holds the powers in
// registers across a pass and copies them to stack slots the wipe does
// not clear.
static __m256i pair_power_at(const pass_hash_state *s, size_t j) {
    const volatile __m256i *power = &s->pairs[j].power;
    return *power;
}

static __m256i pair_halves_at(const pass_hash_state *s, size_t j) {
    const volatile __m256i *halves = &s->pairs[j].halves_added;
    return *halves;
}

// sums = the three products of the pair x and pairs[j], or sums += them,
// each half as ghash_start_sums computes one element's.
static inline void pair_start_sums(const pass_hash_state *s, pass_hash_sums *sums, __m256i x,
                                   size_t j) {
    __m256i power = pair_power_at(s, j);
    sums->low = _mm256_clmulepi64_epi128(x, power, 0x11);
    sums->high = _mm256_clmulepi64_epi128(x, power, 0x00);
    sums->middle = _mm256_clmulepi64_epi128(pair_halves_added(x), pair_halves_at(s, j), 0x00);
}

static inline void pair_add_products(const pass_hash_state *s, pass_hash_sums *sums, __m256i x,
                                     size_t j) {
    pass_hash_sums products;
    pair_start_sums(s, &products, x, j);
    sums->low = _mm256_xor_si256(sums->low, products.low);
    sums->high = _mm256_xor_si256(sums->high, products.high);
    sums->middle = _mm256_xor_si256(sums->middle, products.middle);
}

// The two halves of v added: one 128-bit sum.
static __m128i halves_summed(__m256i v) {
    return _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256(v, 1));
}

// s ready for passes: the subkey and the accumulator from their bytes,
// ghash_vector.h's eight powers, and the four pairs of them.
static void pass_hash_start(pass_hash_state *s, const uint8_t subkey[AES_BLOCK],
                            const uint8_t acc[AES_BLOCK]) {
    s->single.subkey = ghash_load_block(subkey);
    s->single.acc = ghash_load_block(acc);
    ghash_compute_powers(&s->single, GHASH_PASS_BLOCKS);
    for (size_t j = 0; j < GHASH_PASS_BLOCKS / 2; j++) {
        __m256i power = _mm256_set_m128i(s->single.powers[GHASH_PASS_BLOCKS - 2 - 2 * j].power,
                                         s->single.powers[GHASH_PASS_BLOCKS - 1 - 2 * j].power);
        s->pairs[j].power = power;
        s->pairs[j].halves_added = pair_halves_added(power);
    }
}

// ghash_hash_pass over the GHASH_PASS_BLOCKS blocks at data, in pairs:
// the accumulator joins the first block, in the low half of the first
// pair, whose products are added last because they alone wait on the
// last pass's reduction. The halves of each sum are added into
// ghash_vector.h's sums in s, and its reduction gives the accumulator.
static inline void pass_hash(pass_hash_state *s, const uint8_t *data) {
    pass_hash_sums sums;
    pair_start_sums(s, &sums, load_pair(&data[PAIR_BYTES]), 1);
    pair_add_products(s, &sums, load_pair(&data[2 * PAIR_BYTES]), 2);
    pair_add_products(s, &sums, load_pair(&data[3 * PAIR_BYTES]), 3);
    __m256i acc = _mm256_set_m128i(_mm_setzero_si128(), s->single.acc);
    pair_add_products(s, &sums, _mm256_xor_si256(load_pair(data), acc), 0);
    s->single.sums.low = halves_summed(sums.low);
    s->single.sums.high = halves_summed(sums.high);
    s->single.sums.middle = halves_summed(sums.middle);
    s->single.acc = ghash_reduce(&s->single.sums);
}

// The passes a step that starts at pass p covers: two, or one when it is
// the call's last and the passes are odd.
static size_t step_passes(size_t passes, size_t p) {
    return passes - p < STEP_PASSES ? passes - p : STEP_PASSES;
}

void gcm_counter_blocks_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                             const uint8_t *in, size_t blocks, uint8_t *out) {
    if (blocks == 0) {
        return;
    }
    state_pair prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    // keystream holds a step's counter blocks and then their keystream, as
    // in gcm_hw.c's loop, and one wipe after the loop clears it.
    state_pair keystream[STEP_PAIRS];
    size_t done = 0;
    while (done < blocks) {
        fill_counters(keystream, prefix, count + (uint32_t)done + 1U);
        cipher_step(keystream, round_keys, rounds);
        size_t take = blocks - done < STEP_BLOCKS ? blocks - done : STEP_BLOCKS;
        xor_step(keystream, &in[done * AES_BLOCK], take, &out[done * AES_BLOCK]);
        done += take;
    }
    set_counter_count(counter, count + (uint32_t)blocks);
    ct_wipe(keystream, sizeof keystream);
}

void gcm_seal_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out) {
    if (passes == 0) {
        return;
    }
    gcm_vaes_state s;
    pass_hash_start(&s.hash, subkey, acc);
    state_pair prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    for (size_t p = 0; p < passes; p += STEP_PASSES) {
        size_t at = p * PASS_BYTES;
        fill_counters(s.keystream, prefix, count + (uint32_t)(p * GCM_HW_PASS_BLOCKS) + 1U);
        cipher_step(s.keystream, round_keys, rounds);
        xor_step_in_place(s.keystream, step_passes(passes, p) * PASS_PAIRS, &in[at], &out[at]);
        // The ciphertext the step before wrote, which nothing in this step
        // waits on. Only a call's last step holds fewer than two passes.
        if (p > 0) {
            pass_hash(&s.hash, &out[at - 2 * PASS_BYTES]);
            pass_hash(&s.hash, &out[at - PASS_BYTES]);
        }
    }
    // The last step's passes, one or two.
    for (size_t p = (passes - 1) / STEP_PASSES * STEP_PASSES; p < passes; p++) {
        pass_hash(&s.hash, &out[p * PASS_BYTES]);
    }
    ghash_store_block(acc, s.hash.single.acc);
    set_counter_count(counter, count + (uint32_t)(passes * GCM_HW_PASS_BLOCKS));
    ct_wipe(&s, sizeof s);
}

// gcm_hw.c's open loop a step at a time: iteration k decrypts step k - 1
// and then hashes step k, each in an if of its own, for the reasons
// gcm_hw.c gives. A step's plaintext is written at or below its
// ciphertext and ends before the next step's ciphertext begins, so every
// block is hashed before a plaintext byte is written to its address.
void gcm_open_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out) {
    if (passes == 0) {
        return;
    }
    gcm_vaes_state s;
    pass_hash_start(&s.hash, subkey, acc);
    state_pair prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    size_t steps = (passes + STEP_PASSES - 1) / STEP_PASSES;
    for (size_t k = 0; k <= steps; k++) {
        if (k > 0) {
            size_t p = (k - 1) * STEP_PASSES;
            size_t at = p * PASS_BYTES;
            fill_counters(s.keystream, prefix, count + (uint32_t)(p * GCM_HW_PASS_BLOCKS) + 1U);
            cipher_step(s.keystream, round_keys, rounds);
            xor_step_in_place(s.keystream, step_passes(passes, p) * PASS_PAIRS, &in[at], &out[at]);
        }
        if (k < steps) {
            size_t p = k * STEP_PASSES;
            pass_hash(&s.hash, &in[p * PASS_BYTES]);
            if (p + 1 < passes) {
                pass_hash(&s.hash, &in[(p + 1) * PASS_BYTES]);
            }
        }
    }
    ghash_store_block(acc, s.hash.single.acc);
    set_counter_count(counter, count + (uint32_t)(passes * GCM_HW_PASS_BLOCKS));
    ct_wipe(&s, sizeof s);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
