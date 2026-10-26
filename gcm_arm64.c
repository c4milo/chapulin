// AES-GCM's whole seal and whole open on arm64, in a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) that carries AES and targets arm64.
// gcm_arm64.h states the contracts; this file implements them and nothing
// else. On x86-64 it compiles to nothing.
//
// Why a whole AEAD. A TLS record expands its key, seals or opens, and
// wipes the key, and gcm.c's steps each compute the hash subkey's powers
// they need and wipe them again. On a Neoverse N2 those steps took about
// 100 ns of a 1 KiB record beside the passes (docs/decisions.md 158). Here
// one batch of AES rounds computes the hash subkey H, the first counter
// block's keystream and, for a short text, all of its keystream; one set
// of powers of H serves the associated data, the text and the lengths
// block; and one wipe clears what the call computed.
//
// Why assembly. A pass is 8 blocks of counter mode and GHASH over 8 blocks
// of ciphertext. A Neoverse N2 runs the AES, PMULL and vector instructions
// on two vector pipes, and a pass takes as long as the instructions it
// sends to them. gcm_hw.c's C passes, under gcc 13 and clang 23, sent
// about 175 vector instructions a pass and kept the two pipes busy 85% of
// the time: 4.11 µs for the passes of a 16 KiB record under clang, where
// OpenSSL 3.6.4 took 3.72 µs for the whole AEAD. Each change to the C,
// such as counters from a vector add or the middle products of two blocks
// from one register, moved the compilers' code by 2% to 6%, and neither
// compiler kept an order between the AES rounds and the products. So the
// passes are inline assembly, in gcm_arm64_passes.h, which states them,
// and C does the rest.
//
// The steps of one call, for a 96-bit IV (SP 800-38D §7.1 and §7.2):
//
//   1. One batch of AES rounds over the zero block, the first counter
//      block J0 and, when the text after its whole passes has at most
//      BATCH_TEXT_BLOCKS blocks, every counter block of that rest.
//   2. The powers of H that the longest run of GHASH blocks below takes.
//   3. GHASH over the associated data, then the text's whole passes on the
//      assembly, then the rest of the text, then the lengths block. The
//      blocks outside the passes wait in a buffer of up to 8 blocks, and
//      each full buffer takes one reduction.
//   4. The tag: GHASH's value exclusive-ored with J0's keystream.
//
// The seal's first pass has no ciphertext before it to hash, so it runs
// counter mode alone, and the last pass's ciphertext is hashed after the
// loop. The open hashes each pass's ciphertext in the pass that decrypts
// it.
//
// Two copies. gcm_arm64_eor3.c compiles this file once more with
// GCM_ARM64_EOR3, which turns on FEAT_SHA3's EOR3 in the assembly and
// gives the entries the _eor3 names (gcm_arm64.h).
//
// Timing. The branches read the lengths, the round count and the copy's
// constants, never a byte of a key, a text or a tag. Every index is a
// count those fix. aes_hw.c states what the AES instructions can and
// cannot claim, and the caller's CH_CPU_CONSTANT_TIME_AES bit is the
// statement for them and for PMULL.
//
// CBMC cannot read an intrinsic or assembly, so the proofs stay on
// gcm.c's portable AEAD, and test/ghash_equiv_test.c and
// test/aes_equiv_test.c hold this file to it byte for byte.
#include "gcm_arm64.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include <stddef.h>
#include <string.h>

#include "ct.h"
#include "ghash_vector.h"

// Every function from here to the pop at the end of this file carries
// "+aes", which the AES and PMULL instructions need, as ghash_vector.h's
// functions carry it, and "+sha3" as well in the copy that runs EOR3.
#ifdef __clang__
#ifdef GCM_ARM64_EOR3
#pragma clang attribute push(__attribute__((target("+aes,+sha3"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef GCM_ARM64_EOR3
#pragma GCC target("+aes+sha3")
#else
#pragma GCC target("+aes")
#endif
#endif

#include "gcm_arm64_passes.h"

#ifdef GCM_ARM64_EOR3
#define GCM_ARM64_SEAL gcm_seal_arm64_eor3
#define GCM_ARM64_OPEN gcm_open_arm64_eor3
#else
#define GCM_ARM64_SEAL gcm_seal_arm64
#define GCM_ARM64_OPEN gcm_open_arm64
#endif

// The blocks one batch of AES rounds runs, and of those the text blocks
// step 1's batch can take beside the zero block and J0.
#define BATCH_BLOCKS 8
#define BATCH_TEXT_BLOCKS (BATCH_BLOCKS - 2)

// What a call computes from the key: J0's keystream, the batch's blocks,
// which hold counter blocks and then their keystream, the blocks waiting
// for GHASH, the GHASH state with its powers, which comes last so that a
// wipe can stop after the last power the call computed, and the passes'
// state, which a call wipes when it ran passes.
typedef struct {
    uint8_t mask[AES_BLOCK];
    uint8_t batch[BATCH_BLOCKS][AES_BLOCK];
    uint8_t staged[GHASH_PASS_BLOCKS][AES_BLOCK];
    size_t staged_count;
    size_t powers;
    ghash_state ghash;
    gcm_arm64_passes passes;
} aead_state;

// FIPS 197 §5.1 on the 8 blocks of batch in place, under round keys for
// rounds rounds: AESE and AESMC for each round but the last, which drops
// MixColumns and adds the last round key with an exclusive-or.
static void cipher_batch(const uint8_t *round_keys, size_t rounds,
                         uint8_t batch[BATCH_BLOCKS][AES_BLOCK]) {
    uint8x16_t states[BATCH_BLOCKS];
#pragma GCC unroll 8
    for (size_t b = 0; b < BATCH_BLOCKS; b++) {
        states[b] = vld1q_u8(batch[b]);
    }
    for (size_t i = 0; i + 1 < rounds; i++) {
        uint8x16_t key = vld1q_u8(&round_keys[i * AES_BLOCK]);
#pragma GCC unroll 8
        for (size_t b = 0; b < BATCH_BLOCKS; b++) {
            states[b] = vaesmcq_u8(vaeseq_u8(states[b], key));
        }
    }
    uint8x16_t key = vld1q_u8(&round_keys[(rounds - 1) * AES_BLOCK]);
    uint8x16_t last = vld1q_u8(&round_keys[rounds * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < BATCH_BLOCKS; b++) {
        vst1q_u8(batch[b], veorq_u8(vaeseq_u8(states[b], key), last));
    }
}

// block = the counter block with the twelve bytes of nonce and count in
// its last four bytes, big-endian (SP 800-38D §7.1 step 2 and §6.2).
static void counter_block(uint8_t block[AES_BLOCK], const uint8_t nonce[AES_IV], uint32_t count) {
    memcpy(block, nonce, AES_IV);
    block[12] = (uint8_t)(count >> 24);
    block[13] = (uint8_t)(count >> 16);
    block[14] = (uint8_t)(count >> 8);
    block[15] = (uint8_t)count;
}

// The len bytes at bytes, len at most AES_BLOCK, as the next block for
// GHASH, padded with zeros on the right (SP 800-38D §6.4). A full buffer
// takes one pass of GHASH and one reduction.
static void stage_block(aead_state *s, const uint8_t *bytes, size_t len) {
    uint8_t *block = s->staged[s->staged_count];
    memset(block, 0, AES_BLOCK);
    memcpy(block, bytes, len);
    s->staged_count++;
    if (s->staged_count == GHASH_PASS_BLOCKS) {
        ghash_hash_pass(&s->ghash, &s->staged[0][0]);
        s->staged_count = 0;
    }
}

// GHASH over every block the buffer holds, with one reduction.
static void stage_flush(aead_state *s) {
    if (s->staged_count > 0) {
        ghash_hash_blocks(&s->ghash, &s->staged[0][0], s->staged_count);
        s->staged_count = 0;
    }
}

// Every block of n bytes at bytes, the last padded, into the buffer.
static void stage_bytes(aead_state *s, const uint8_t *bytes, size_t n) {
    for (size_t at = 0; at < n; at += AES_BLOCK) {
        stage_block(s, &bytes[at], n - at < AES_BLOCK ? n - at : AES_BLOCK);
    }
}

// a * b, two elements that each carry x^-1, as ghash_vector.h's powers do:
// the product of two powers of H is the power of their exponents' sum, and
// carries x^-1 once, because the multiply adds one x back. The three
// products and the reduction are ghash_start_sums's and ghash_reduce's,
// on values in registers.
static inline ghash_vector multiply_powers(ghash_vector a, ghash_vector b) {
    ghash_sums sums;
    sums.low = ghash_multiply_lane1(a, b);
    sums.high = ghash_multiply_lane0(a, b);
    sums.middle = ghash_multiply_lane0(ghash_halves_added(a), ghash_halves_added(b));
    return ghash_reduce(&sums);
}

// g->powers[i] = H^(i + 1) * x^-1 for i below count, which is 1, 2, 4 or
// 8, from g->subkey, as ghash_compute_powers writes them, in fewer steps
// that wait on each other: H^2 from H, then H^3 and H^4 from those two,
// then H^5 to H^8 from H^4 and the four before it. Each power stays in a
// register for the products after it, where ghash_compute_powers reads it
// back from g.
static void compute_powers(ghash_state *g, size_t count) {
    ghash_vector p1 = ghash_swap_halves(ghash_times_inverse_x(ghash_swap_halves(g->subkey)));
    ghash_set_power(g, 0, p1);
    if (count < 2) {
        return;
    }
    ghash_vector p2 = multiply_powers(p1, p1);
    ghash_set_power(g, 1, p2);
    if (count < 4) {
        return;
    }
    ghash_vector p3 = multiply_powers(p2, p1);
    ghash_vector p4 = multiply_powers(p2, p2);
    ghash_set_power(g, 2, p3);
    ghash_set_power(g, 3, p4);
    if (count < GHASH_PASS_BLOCKS) {
        return;
    }
    ghash_set_power(g, 4, multiply_powers(p4, p1));
    ghash_set_power(g, 5, multiply_powers(p4, p2));
    ghash_set_power(g, 6, multiply_powers(p4, p3));
    ghash_set_power(g, 7, multiply_powers(p4, p4));
}

// The passes' packed halves for the 8 powers in s's GHASH state, and
// when paired is set, the passes' high powers, H^9 to H^16 times x^-1,
// each H^8 times one of the 8, and their packed halves.
static void pack_powers(aead_state *s, int paired) {
    passes_pack_set(s->passes.packed, s->ghash.powers);
    if (!paired) {
        return;
    }
    ghash_vector eighth = s->ghash.powers[GHASH_PASS_BLOCKS - 1].power;
    for (size_t i = 0; i < GHASH_PASS_BLOCKS; i++) {
        ghash_vector power = multiply_powers(eighth, s->ghash.powers[i].power);
        s->passes.high[i].power = power;
        s->passes.high[i].halves_added = ghash_halves_added(power);
    }
    passes_pack_set(s->passes.packed_high, s->passes.high);
}

static size_t blocks_of(size_t n) {
    return n / AES_BLOCK + (n % AES_BLOCK != 0);
}

// Steps 1 and 2, and GHASH over the associated data: s's mask holds J0's
// keystream, and when keystream_in_batch is set, batch[2 + i] holds the
// keystream of block i of the rest of the text, rest bytes after its whole
// passes, whose first block takes count first. The powers cover blocks,
// the longest run of GHASH blocks with one reduction before the caller
// computes more.
static void aead_start(aead_state *s, const uint8_t *round_keys, size_t rounds,
                       const uint8_t nonce[AES_IV], const uint8_t *aad, size_t aad_len,
                       size_t blocks, uint32_t first, size_t rest, int keystream_in_batch) {
    memset(s->batch, 0, sizeof s->batch);
    counter_block(s->batch[1], nonce, 1U);
    if (keystream_in_batch) {
        for (size_t i = 0; i < blocks_of(rest); i++) {
            counter_block(s->batch[2 + i], nonce, first + (uint32_t)i);
        }
    }
    cipher_batch(round_keys, rounds, s->batch);
    memcpy(s->mask, s->batch[1], AES_BLOCK);
    s->ghash.subkey = ghash_load_block(s->batch[0]);
    s->ghash.acc = vdupq_n_u64(0);
    // compute_powers computes 1, 2, 4 or 8.
    s->powers = 1;
    while (s->powers < blocks && s->powers < GHASH_PASS_BLOCKS) {
        s->powers *= 2;
    }
    compute_powers(&s->ghash, s->powers);
    s->staged_count = 0;
    stage_bytes(s, aad, aad_len);
}

// The keystream of the rest of the text, rest bytes from count first, in
// batch[0] up: step 1's batch when it took the text, or a batch of its own.
static void rest_keystream(aead_state *s, const uint8_t *round_keys, size_t rounds,
                           const uint8_t nonce[AES_IV], uint32_t first, size_t rest,
                           int keystream_in_batch) {
    if (keystream_in_batch) {
        memmove(s->batch[0], s->batch[2], blocks_of(rest) * AES_BLOCK);
        return;
    }
    for (size_t i = 0; i < blocks_of(rest); i++) {
        counter_block(s->batch[i], nonce, first + (uint32_t)i);
    }
    cipher_batch(round_keys, rounds, s->batch);
}

// Step 3's last block and step 4: the lengths in bits, then the tag, and
// the wipe of everything the call computed. passes_len counts the bytes of
// s's passes state the call wrote values computed from the key into.
static void aead_finish(aead_state *s, size_t aad_len, size_t n, size_t passes_len,
                        uint8_t tag[AES_BLOCK]) {
    // Each length's eight bytes, most significant first (cpu_cfg.h: a host
    // object is little-endian).
    uint64_t bits[2] = {__builtin_bswap64((uint64_t)aad_len * 8U),
                        __builtin_bswap64((uint64_t)n * 8U)};
    stage_block(s, (const uint8_t *)bits, AES_BLOCK);
    stage_flush(s);
    // GHASH's value is an element; ghash_store_block's byte reversal makes
    // it bytes, and the mask is added to them.
    ghash_vector hashed = s->ghash.acc;
    vst1q_u8(tag, veorq_u8(vrev64q_u8(vreinterpretq_u8_u64(hashed)), vld1q_u8(s->mask)));
    ct_wipe(s, offsetof(aead_state, ghash) + offsetof(ghash_state, powers) +
                   s->powers * sizeof(ghash_power));
    if (passes_len > 0) {
        ct_wipe(&s->passes, passes_len);
    }
}

void GCM_ARM64_SEAL(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                    uint8_t tag[AES_BLOCK]) {
    aead_state s;
    size_t passes = n / GCM_ARM64_PASS_BYTES;
    size_t done = passes * GCM_ARM64_PASS_BYTES;
    size_t rest = n - done;
    uint32_t first = passes_count(2U, passes, 0);
    int keystream_in_batch = blocks_of(rest) <= BATCH_TEXT_BLOCKS;
    size_t passes_len = 0;
    // With whole passes, the powers the associated data takes now, and the
    // 8 the passes take after the first pass, which takes none.
    size_t blocks = passes > 0 ? blocks_of(aad_len) : blocks_of(aad_len) + blocks_of(n) + 1;
    aead_start(&s, round_keys, rounds, nonce, aad, aad_len, blocks, first, rest,
               keystream_in_batch);
    if (passes > 0) {
        stage_flush(&s);
        passes_counters(&s.passes, round_keys, nonce, 2U);
        pass_args args;
        pass_cursor at;
        passes_begin(&args, &at, &s.passes, &s.ghash, round_keys, 2U, pt, ct);
        passes_counter_pass(&args, &at, rounds);
        s.powers = GHASH_PASS_BLOCKS;
        compute_powers(&s.ghash, s.powers);
        int paired = passes >= GCM_ARM64_PAIRED_PASSES;
        pack_powers(&s, paired);
        passes_run(&s.ghash, &args, &at, rounds, 1, paired, passes - 1);
        passes_len = passes_secret_len(paired);
    }
    if (rest > 0) {
        rest_keystream(&s, round_keys, rounds, nonce, first, rest, keystream_in_batch);
        for (size_t i = 0; i < rest; i++) {
            ct[done + i] = (uint8_t)(pt[done + i] ^ s.batch[i / AES_BLOCK][i % AES_BLOCK]);
        }
        stage_bytes(&s, &ct[done], rest);
    }
    aead_finish(&s, aad_len, n, passes_len, tag);
}

// stage_bytes copies each block of the rest of the ciphertext into the
// buffer before any plaintext byte of the rest is written, and the buffer
// keeps the copies until aead_finish hashes them. A plaintext byte at
// done + i is written after the ciphertext bytes up to done + i are read,
// so pt == ct and pt below ct work.
void GCM_ARM64_OPEN(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                    uint8_t want[AES_BLOCK]) {
    aead_state s;
    size_t passes = n / GCM_ARM64_PASS_BYTES;
    size_t done = passes * GCM_ARM64_PASS_BYTES;
    size_t rest = n - done;
    uint32_t first = passes_count(2U, passes, 0);
    int keystream_in_batch = blocks_of(rest) <= BATCH_TEXT_BLOCKS;
    size_t passes_len = 0;
    aead_start(&s, round_keys, rounds, nonce, aad, aad_len, blocks_of(aad_len) + blocks_of(n) + 1,
               first, rest, keystream_in_batch);
    if (passes > 0) {
        stage_flush(&s);
        passes_counters(&s.passes, round_keys, nonce, 2U);
        int paired = passes >= GCM_ARM64_PAIRED_PASSES;
        pack_powers(&s, paired);
        pass_args args;
        pass_cursor at;
        passes_begin(&args, &at, &s.passes, &s.ghash, round_keys, 2U, ct, pt);
        passes_run(&s.ghash, &args, &at, rounds, 0, paired, passes);
        passes_len = passes_secret_len(paired);
    }
    if (rest > 0) {
        stage_bytes(&s, &ct[done], rest);
        rest_keystream(&s, round_keys, rounds, nonce, first, rest, keystream_in_batch);
        for (size_t i = 0; i < rest; i++) {
            pt[done + i] = (uint8_t)(ct[done + i] ^ s.batch[i / AES_BLOCK][i % AES_BLOCK]);
        }
    }
    aead_finish(&s, aad_len, n, passes_len, want);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __aarch64__
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
