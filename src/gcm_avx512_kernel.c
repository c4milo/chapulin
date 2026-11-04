// AES-GCM's whole seal and whole open for a 96-bit IV, four blocks to a 512-bit register.
// gcm_avx512_kernel.h states the contracts, and docs/decisions.md 130 says why the kernel exists.
//
// What one call does, in order:
//   1. One AES pass over one register whose lanes hold the zero block, the first counter block
//      J0 and the counter block of the first block past the last whole step. It gives the hash
//      subkey H, the tag's mask E(K, J0) and the keystream a last block of 1 to 16 bytes takes.
//   2. H times x^-1, GHASH over the associated data, and the powers of H the groups meet, up to
//      H^33 (gcm_avx512_ghash.h).
//   3. The whole steps. A step is 32 blocks in eight registers. The seal runs a step's AES
//      rounds and, between them, GHASH over the ciphertext of the step before. The open runs
//      GHASH over a step's ciphertext between the rounds of the same step, so it reads every
//      block of the step before it writes the step's plaintext. GHASH reduces once per step.
//   4. The bytes past the last whole step, through byte masks, and GHASH over them and the
//      lengths block in one group.
//   5. The tag, which the open writes to want for gcm.c to compare.
// gcm_avx512.c's entry then wipes the stack below its own frame, which holds this file's frames,
// and every vector register and k1 to k7.
//
// Counters. A register of counter blocks is kept with each block reversed byte for byte, so that
// a block's count sits in its lane's low 32-bit word and a 32-bit add there is SP 800-38D's
// inc32: it wraps modulo 2^32 and carries nothing into the IV. A byte shuffle with a constant
// order turns the register back before each step's rounds.
//
// The bytes past the last whole step. A byte mask loads and stores the bytes of the text and no
// byte past them. Each register's address is computed only where the register holds a byte of
// the text (load_rest_register, store_rest_register), so no pointer here points past a buffer.
//
// Timing. No line branches on a value the key decides or indexes memory with one. The branches
// read the round count, the lengths and loop indices, and the byte shuffles take constant
// orders. CH_CPU_CONSTANT_TIME_AES is the caller's statement that VAESENC and VPCLMULQDQ take the
// same time whatever their operands, at every width, and gcm_use_avx512 requires it.
//
// Secrets. The powers of H sit in one gcm_avx512_powers in the kernel's frame, read through
// volatile lvalues. Round keys, keystream, H, E(K, J0) and the GHASH sums stay in registers, or
// in stack slots the compiler picks. The entry's wipe of GCM_AVX512_BELOW_LEN bytes covers both.
//
// CBMC cannot read an intrinsic, so no harness compiles this file. bin/gcm_avx512_equiv_test
// holds it to gcm.c's path on gcm_hw.c byte for byte on a CPU with the instructions, and the host
// Wycheproof binary and bin/quic_test_hw run the published vectors on it.
#include "gcm_avx512_kernel.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

// Every function from here to the pop at the end of this file carries the target attribute that
// turns on AES-NI, PCLMULQDQ, AVX2, AVX-512F, AVX-512BW, VAES and VPCLMULQDQ, and no function
// outside it does. clang applies it through one attribute push; gcc's target pragma sets it for
// each function defined after it, until the pop. gcm_avx512.c calls these functions only where
// the bits a key's schedule records say the CPU has them.
#ifdef __clang__
#pragma clang attribute push(                                                                      \
    __attribute__((target("aes,pclmul,avx2,avx512f,avx512bw,vaes,vpclmulqdq"))),                   \
    apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("aes,pclmul,avx2,avx512f,avx512bw,vaes,vpclmulqdq")
#endif

#include "gcm_avx512_ghash.h"

// ---------------------------------------------------------------- AES

static inline __attribute__((always_inline)) __m512i round_key(const uint8_t *round_keys,
                                                               size_t i) {
    return _mm512_broadcast_i32x4(
        _mm_loadu_si128((const __m128i *)(const void *)&round_keys[i * AES_BLOCK]));
}

// The first count registers of state, each with key added: the first AddRoundKey.
static inline __attribute__((always_inline)) void add_round_key(__m512i state[STEP_REGISTERS],
                                                                size_t count, __m512i key) {
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        state[r] = _mm512_xor_si512(state[r], key);
    }
}

// One AES round under key on the first count registers of state.
static inline __attribute__((always_inline)) void run_round(__m512i state[STEP_REGISTERS],
                                                            size_t count, __m512i key) {
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        state[r] = _mm512_aesenc_epi128(state[r], key);
    }
}

// One register through every round.
static inline __attribute__((always_inline)) __m512i cipher_register(const uint8_t *round_keys,
                                                                     size_t rounds, __m512i v) {
    v = _mm512_xor_si512(v, round_key(round_keys, 0));
#pragma GCC unroll 13
    for (size_t i = 1; i < rounds; i++) {
        v = _mm512_aesenc_epi128(v, round_key(round_keys, i));
    }
    return _mm512_aesenclast_epi128(v, round_key(round_keys, rounds));
}

// count registers of the counter blocks that follow, from reversed, which then holds the counter
// blocks past them.
static inline __attribute__((always_inline)) void next_counters(__m512i state[STEP_REGISTERS],
                                                                __m512i *reversed, size_t count) {
    const __m512i four = _mm512_broadcast_i32x4(_mm_setr_epi32(4, 0, 0, 0));
    __m512i v = *reversed;
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        state[r] = reverse_lanes(v);
        v = _mm512_add_epi32(v, four);
    }
    *reversed = v;
}

// The register step 1 of the file comment encrypts: the zero block, J0 (the nonce and a count of
// 1), the counter block of text block index (a count of index + 2) and a zero block. reversed
// gets the counter blocks of text blocks 0 to 3. index is the first block past the last whole
// step, so it is below 2^28 for every length gcm.h admits, and the uint32_t sum wraps as inc32
// does if it ever is not.
static inline __attribute__((always_inline)) __m512i first_blocks(const uint8_t nonce[AES_IV],
                                                                  size_t index, __m512i *reversed) {
    __m128i iv = _mm512_castsi512_si128(_mm512_maskz_loadu_epi8(0xfffU, nonce));
    __m512i ivs = _mm512_broadcast_i32x4(iv);
    uint32_t tail = __builtin_bswap32((uint32_t)index + 2U);
    __m512i counts =
        _mm512_setr_epi32(0, 0, 0, 0, 0, 0, 0, 0x01000000, 0, 0, 0, (int)tail, 0, 0, 0, 0);
    *reversed = _mm512_add_epi32(reverse_lanes(ivs),
                                 _mm512_setr_epi32(2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0));
    return _mm512_maskz_or_epi32(0x0ff0, ivs, counts);
}

// ---------------------------------------------------------------- the bytes past the last step

// The bytes register r holds of a run of len bytes, as a byte mask. Requires r * REGISTER_BYTES
// below len, so the register holds at least one byte.
static inline __attribute__((always_inline)) __mmask64 register_mask(size_t len, size_t r) {
    size_t held = len - r * REGISTER_BYTES;
    if (held >= REGISTER_BYTES) {
        return ~(__mmask64)0;
    }
    return ((__mmask64)1 << held) - 1U;
}

// Register r of the len bytes at base + offset, with every byte past them zero. The address of
// the register is computed only where it holds a byte of the run.
static inline __attribute__((always_inline)) __m512i load_rest_register(const uint8_t *base,
                                                                        size_t offset, size_t len,
                                                                        size_t r) {
    if (len <= r * REGISTER_BYTES) {
        return _mm512_setzero_si512();
    }
    return _mm512_maskz_loadu_epi8(register_mask(len, r), &base[offset + r * REGISTER_BYTES]);
}

// v's bytes that fall in register r of the len bytes at base + offset, written there, and none
// past them. The address is computed only where the register holds a byte of the run.
static inline __attribute__((always_inline)) void
store_rest_register(uint8_t *base, size_t offset, size_t len, size_t r, __m512i v) {
    if (len <= r * REGISTER_BYTES) {
        return;
    }
    _mm512_mask_storeu_epi8(&base[offset + r * REGISTER_BYTES], register_mask(len, r), v);
}

// v with every byte past register r's share of a run of len bytes zero.
static inline __attribute__((always_inline)) __m512i rest_bytes(size_t len, size_t r, __m512i v) {
    if (len <= r * REGISTER_BYTES) {
        return _mm512_setzero_si512();
    }
    return _mm512_maskz_mov_epi8(register_mask(len, r), v);
}

// The keystream of count registers of counter blocks from reversed.
static inline __attribute__((always_inline)) void rest_keystream(const uint8_t *round_keys,
                                                                 size_t rounds, __m512i *reversed,
                                                                 __m512i state[STEP_REGISTERS],
                                                                 size_t count) {
    next_counters(state, reversed, count);
    add_round_key(state, count, round_key(round_keys, 0));
#pragma GCC unroll 13
    for (size_t i = 1; i < rounds; i++) {
        run_round(state, count, round_key(round_keys, i));
    }
    __m512i last = round_key(round_keys, rounds);
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        state[r] = _mm512_aesenclast_epi128(state[r], last);
    }
}

// ---------------------------------------------------------------- the seal

// One whole step of the seal: counter mode over the 32 blocks at in into out, with GHASH over the
// 32 blocks at hashed between the rounds when hash is set. hash is a constant at each call.
static inline __attribute__((always_inline)) void
seal_step(const uint8_t *round_keys, size_t rounds, __m512i *reversed, const uint8_t *in,
          uint8_t *out, const gcm_avx512_powers *s, int hash, const uint8_t *hashed, __m128i *acc) {
    __m512i state[STEP_REGISTERS];
    hash_sums h;
    next_counters(state, reversed, STEP_REGISTERS);
    add_round_key(state, STEP_REGISTERS, round_key(round_keys, 0));
#pragma GCC unroll 13
    for (size_t i = 1; i < rounds; i++) {
        run_round(state, STEP_REGISTERS, round_key(round_keys, i));
        if (hash) {
            hash_slot(&h, s, hashed, i, acc);
        }
    }
    __m512i last = round_key(round_keys, rounds);
#pragma GCC unroll 8
    for (size_t r = 0; r < STEP_REGISTERS; r++) {
        __m512i x = _mm512_loadu_si512((const void *)&in[r * REGISTER_BYTES]);
        _mm512_storeu_si512((void *)&out[r * REGISTER_BYTES],
                            _mm512_aesenclast_epi128(state[r], _mm512_xor_si512(last, x)));
    }
}

// The steps of the seal, each hashing the step before between its rounds. acc then holds GHASH
// over the associated data and every step but the last.
static inline __attribute__((always_inline)) void
seal_steps(const uint8_t *round_keys, size_t rounds, __m512i *reversed, const uint8_t *pt,
           uint8_t *ct, size_t steps, const gcm_avx512_powers *s, __m128i *acc) {
    seal_step(round_keys, rounds, reversed, pt, ct, s, 0, ct, acc);
    for (size_t j = 1; j < steps; j++) {
        seal_step(round_keys, rounds, reversed, &pt[j * STEP_BYTES], &ct[j * STEP_BYTES], s, 1,
                  &ct[(j - 1) * STEP_BYTES], acc);
    }
}

// Counter mode over the len bytes past the last whole step at pt + offset into ct + offset, on
// count registers, and data gets the ciphertext with every byte past len zero. count is a
// constant at each call, so the loops unroll and state stays in registers.
static inline __attribute__((always_inline)) void
seal_rest_on(const uint8_t *round_keys, size_t rounds, __m512i *reversed, const uint8_t *pt,
             size_t offset, size_t len, uint8_t *ct, __m512i data[GROUP_REGISTERS_MAX],
             size_t count) {
    __m512i state[STEP_REGISTERS];
    rest_keystream(round_keys, rounds, reversed, state, count);
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        __m512i c = _mm512_xor_si512(state[r], load_rest_register(pt, offset, len, r));
        store_rest_register(ct, offset, len, r, c);
        data[r] = rest_bytes(len, r, c);
    }
}

// The len bytes past the last whole step, 1 <= len < STEP_BYTES, on two, four or eight
// registers. A run of one block takes the keystream step 1 computed in lane 2 of first.
static inline __attribute__((always_inline)) void seal_rest(const uint8_t *round_keys,
                                                            size_t rounds, __m512i *reversed,
                                                            __m512i first, const uint8_t *pt,
                                                            size_t offset, size_t len, uint8_t *ct,
                                                            __m512i data[GROUP_REGISTERS_MAX]) {
    if (len <= AES_BLOCK) {
        __m512i keystream = _mm512_castsi128_si512(_mm512_extracti32x4_epi32(first, 2));
        __m512i c = _mm512_xor_si512(keystream, load_rest_register(pt, offset, len, 0));
        store_rest_register(ct, offset, len, 0, c);
        data[0] = rest_bytes(len, 0, c);
        return;
    }
    size_t registers = (len + REGISTER_BYTES - 1) / REGISTER_BYTES;
    if (registers <= 2) {
        seal_rest_on(round_keys, rounds, reversed, pt, offset, len, ct, data, 2);
    } else if (registers <= 4) {
        seal_rest_on(round_keys, rounds, reversed, pt, offset, len, ct, data, 4);
    } else {
        seal_rest_on(round_keys, rounds, reversed, pt, offset, len, ct, data, STEP_REGISTERS);
    }
}

// The registers of the seal's last group, beside the lengths block: the last whole step's
// ciphertext when nothing follows it, and otherwise the bytes past it, after GHASH over the last
// whole step into acc.
static inline __attribute__((always_inline)) void
seal_last_group(const uint8_t *round_keys, size_t rounds, __m512i *reversed, __m512i first,
                const uint8_t *pt, size_t n, uint8_t *ct, const gcm_avx512_powers *s, __m128i *acc,
                __m512i data[GROUP_REGISTERS_MAX]) {
    size_t steps = n / STEP_BYTES;
    size_t rest = n - steps * STEP_BYTES;
    if (steps > 0 && rest == 0) {
        const uint8_t *last = &ct[(steps - 1) * STEP_BYTES];
#pragma GCC unroll 8
        for (size_t r = 0; r < STEP_REGISTERS; r++) {
            data[r] = _mm512_loadu_si512((const void *)&last[r * REGISTER_BYTES]);
        }
        return;
    }
    if (steps > 0) {
        *acc = hash_step(s, &ct[(steps - 1) * STEP_BYTES], *acc);
    }
    if (rest > 0) {
        seal_rest(round_keys, rounds, reversed, first, pt, steps * STEP_BYTES, rest, ct, data);
    }
}

// The highest power of H a call's groups meet: H^(blocks + 1) for the last group of blocks
// blocks and the lengths block, and at least H^32 where a whole step runs.
static inline __attribute__((always_inline)) size_t powers_needed(size_t steps, size_t blocks) {
    size_t top = blocks + 1;
    return steps > 0 && top < STEP_BLOCKS ? STEP_BLOCKS : top;
}

// The seal's part of the file comment's steps 1 to 5 at one round count.
static inline __attribute__((always_inline)) void
seal_body(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV], const uint8_t *aad,
          size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AES_BLOCK]) {
    gcm_avx512_powers s;
    size_t steps = n / STEP_BYTES;
    size_t rest = n - steps * STEP_BYTES;
    __m512i reversed;
    __m512i first =
        cipher_register(round_keys, rounds, first_blocks(nonce, steps * STEP_BLOCKS, &reversed));
    __m128i first_power = times_inverse_x(reverse_block(_mm512_castsi512_si128(first)));
    __m128i acc = hash_associated_data(first_power, aad, aad_len);
    size_t blocks = steps > 0 && rest == 0 ? STEP_BLOCKS : (rest + AES_BLOCK - 1) / AES_BLOCK;
    compute_powers(&s, first_power, powers_needed(steps, blocks));
    if (steps > 0) {
        seal_steps(round_keys, rounds, &reversed, pt, ct, steps, &s, &acc);
    }
    __m512i data[GROUP_REGISTERS_MAX];
#pragma GCC unroll 9
    for (size_t r = 0; r < GROUP_REGISTERS_MAX; r++) {
        data[r] = _mm512_setzero_si512();
    }
    seal_last_group(round_keys, rounds, &reversed, first, pt, n, ct, &s, &acc, data);
    acc = hash_last_group(&s, acc, data, blocks, lengths_block(aad_len, n));
    __m128i mask = _mm512_extracti32x4_epi32(first, 1);
    _mm_storeu_si128((__m128i *)(void *)tag, _mm_xor_si128(reverse_block(acc), mask));
}

void gcm_avx512_seal_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    seal_body(round_keys, AES_128_ROUNDS, nonce, aad, aad_len, pt, n, ct, tag);
}

#ifdef CH_AES_256
void gcm_avx512_seal_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    seal_body(round_keys, AES_256_ROUNDS, nonce, aad, aad_len, pt, n, ct, tag);
}
#endif

// ---------------------------------------------------------------- the open

// One whole step of the open: GHASH over the 32 blocks at in between the rounds, then counter
// mode over them into out. Every register of in is read before the step writes out.
static inline __attribute__((always_inline)) void
open_step(const uint8_t *round_keys, size_t rounds, __m512i *reversed, const uint8_t *in,
          uint8_t *out, const gcm_avx512_powers *s, __m128i *acc) {
    __m512i state[STEP_REGISTERS];
    hash_sums h;
    next_counters(state, reversed, STEP_REGISTERS);
    add_round_key(state, STEP_REGISTERS, round_key(round_keys, 0));
#pragma GCC unroll 13
    for (size_t i = 1; i < rounds; i++) {
        run_round(state, STEP_REGISTERS, round_key(round_keys, i));
        hash_slot(&h, s, in, i, acc);
    }
    __m512i last = round_key(round_keys, rounds);
#pragma GCC unroll 8
    for (size_t r = 0; r < STEP_REGISTERS; r++) {
        __m512i x = _mm512_loadu_si512((const void *)&in[r * REGISTER_BYTES]);
        _mm512_storeu_si512((void *)&out[r * REGISTER_BYTES],
                            _mm512_aesenclast_epi128(state[r], _mm512_xor_si512(last, x)));
    }
}

// Counter mode over the ciphertext in data, the len bytes past the last whole step, into
// pt + offset, on count registers. count is a constant at each call.
static inline __attribute__((always_inline)) void
open_rest_on(const uint8_t *round_keys, size_t rounds, __m512i *reversed,
             const __m512i data[GROUP_REGISTERS_MAX], size_t len, uint8_t *pt, size_t offset,
             size_t count) {
    __m512i state[STEP_REGISTERS];
    rest_keystream(round_keys, rounds, reversed, state, count);
#pragma GCC unroll 8
    for (size_t r = 0; r < count; r++) {
        store_rest_register(pt, offset, len, r, _mm512_xor_si512(state[r], data[r]));
    }
}

// The len bytes past the last whole step, 1 <= len < STEP_BYTES, on two, four or eight
// registers. A run of one block takes the keystream in lane 2 of first.
static inline __attribute__((always_inline)) void
open_rest(const uint8_t *round_keys, size_t rounds, __m512i *reversed, __m512i first,
          const __m512i data[GROUP_REGISTERS_MAX], size_t len, uint8_t *pt, size_t offset) {
    if (len <= AES_BLOCK) {
        __m512i keystream = _mm512_castsi128_si512(_mm512_extracti32x4_epi32(first, 2));
        store_rest_register(pt, offset, len, 0, _mm512_xor_si512(keystream, data[0]));
        return;
    }
    size_t registers = (len + REGISTER_BYTES - 1) / REGISTER_BYTES;
    if (registers <= 2) {
        open_rest_on(round_keys, rounds, reversed, data, len, pt, offset, 2);
    } else if (registers <= 4) {
        open_rest_on(round_keys, rounds, reversed, data, len, pt, offset, 4);
    } else {
        open_rest_on(round_keys, rounds, reversed, data, len, pt, offset, STEP_REGISTERS);
    }
}

// The open's part of the file comment's steps 1 to 5 at one round count. The ciphertext past the
// last whole step is read into data before any of its plaintext is written.
static inline __attribute__((always_inline)) void
open_body(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV], const uint8_t *aad,
          size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt, uint8_t want[AES_BLOCK]) {
    gcm_avx512_powers s;
    size_t steps = n / STEP_BYTES;
    size_t rest = n - steps * STEP_BYTES;
    size_t blocks = (rest + AES_BLOCK - 1) / AES_BLOCK;
    __m512i reversed;
    __m512i first =
        cipher_register(round_keys, rounds, first_blocks(nonce, steps * STEP_BLOCKS, &reversed));
    __m128i first_power = times_inverse_x(reverse_block(_mm512_castsi512_si128(first)));
    __m128i acc = hash_associated_data(first_power, aad, aad_len);
    compute_powers(&s, first_power, powers_needed(steps, blocks));
    for (size_t j = 0; j < steps; j++) {
        open_step(round_keys, rounds, &reversed, &ct[j * STEP_BYTES], &pt[j * STEP_BYTES], &s,
                  &acc);
    }
    __m512i data[GROUP_REGISTERS_MAX];
#pragma GCC unroll 9
    for (size_t r = 0; r < GROUP_REGISTERS_MAX; r++) {
        data[r] = load_rest_register(ct, steps * STEP_BYTES, rest, r);
    }
    acc = hash_last_group(&s, acc, data, blocks, lengths_block(aad_len, n));
    if (rest > 0) {
        open_rest(round_keys, rounds, &reversed, first, data, rest, pt, steps * STEP_BYTES);
    }
    __m128i mask = _mm512_extracti32x4_epi32(first, 1);
    _mm_storeu_si128((__m128i *)(void *)want, _mm_xor_si128(reverse_block(acc), mask));
}

void gcm_avx512_open_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    open_body(round_keys, AES_128_ROUNDS, nonce, aad, aad_len, ct, n, pt, want);
}

#ifdef CH_AES_256
void gcm_avx512_open_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    open_body(round_keys, AES_256_ROUNDS, nonce, aad, aad_len, ct, n, pt, want);
}
#endif

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
