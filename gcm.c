// AEAD_AES_128_GCM, AEAD_AES_256_GCM and the GHASH under them, NIST SP
// 800-38D. gcm.h states every contract; this file implements them
// and nothing else. The two AEADs differ in the forward cipher alone, and
// aes_encrypt_schedule picks that by the schedule's round count, so every
// body below serves both.
//
// The forward cipher comes from aes.c, and INV-26 in
// docs/invariants.md bounds which keys it is given: the Initial keys,
// which anyone who sees a Destination Connection ID can derive (RFC 9001
// §5.2), the Retry key the RFC prints (§5.8), and in a -DCH_SUITE_AES_GCM
// build the traffic keys of the two AES-GCM cipher suites.
//
// Every local computed from the key is wiped: the hash subkey, the
// running multiple in the GF(2^128) multiply, the keystream, the tag mask
// and the tag this call expected. A public key does not need it; the
// suite build runs these same bodies under a traffic key, and one body
// serves both. ct.h refuses that build outside a host object and
// AES=extern, and a host object runs every traffic key on the
// instructions (aes.h), so no table in this tree sits underneath it.
//
// GHASH has two bodies, the portable multiply and ghash_hw.c's on the
// carry-less multiply. gcm_ghash.h holds the first and says which of the
// two a schedule runs in each object.
//
// Counter mode, the seal and the open have one body with one more step
// in a host object. A schedule the AES instructions run takes
// counter mode's whole blocks through gcm_hw.c, which runs several blocks
// at once, and the seal's and the open's whole passes of eight blocks
// through gcm_hw.c's loops that run counter mode and GHASH over the
// ciphertext together; the loop that every other schedule runs block by
// block takes what is left. On x86-64 a schedule whose description of the
// CPU passes gcm_use_avx512 runs its whole seal, or its whole open up to
// the comparison, in one call on gcm_avx512.c instead (docs/decisions.md
// 130). Everything else here is one body in every object.
//
// The open decrypts while it hashes, in every object, and compares
// the tag once it has written the plaintext. On a mismatch it wipes the
// n bytes it wrote before it returns, so a failed call returns no
// plaintext byte (gcm.h, docs/decisions.md entry 85).
//
// Only the 96-bit IV exists here. SP 800-38D §7.1 takes the first
// counter block straight from a 96-bit IV, and hashes any other IV
// length with GHASH first. QUIC produces no other length, so the second
// arm has no caller and no code.
#include "gcm.h"

#include "aes_public_key.h"
#ifdef CH_SUITE_AES_GCM
#include "aes_traffic_key.h"
#endif

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <string.h>

#include "ct.h"
#ifdef CH_CPU_RUNTIME
#include "ch_assert.h"
#include "gcm_avx512.h"
#include "gcm_hw.h"
#include "gcm_vaes.h"
#endif
// After aes_public_key.h, which gives aes_key_schedule the body its
// functions read.
#include "gcm_ghash.h"

// The block of zeros SP 800-38D §7.1 step 1 encrypts to get the hash
// subkey H.
static const uint8_t ZERO_BLOCK[AES_BLOCK] = {0};

// SP 800-38D §6.4's last block holds the two lengths in bits, each as a
// 64-bit big-endian value. The bytes are written one at a time, so this
// does not assume host endianness. A byte count multiplied by 8 is
// computed in uint64_t, which is wide enough for every length this tree
// passes and wraps rather than overflows if one ever is not.
static void write_length_bits(uint8_t out[8], size_t len) {
    uint64_t bits = (uint64_t)len * 8U;
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(bits >> (8 * (7 - i)));
    }
}

// GHASH's state through one AEAD call: the hash subkey H and the
// accumulator, both functions of the key, so hash_finish wipes them.
typedef struct {
    uint8_t subkey[AES_BLOCK];
    uint8_t acc[AES_BLOCK];
} gcm_hash;

// SP 800-38D §7.1 step 1: the hash subkey H is the forward cipher of a
// block of zeros. Then GHASH over the associated data, from zero.
static void hash_start(const aes_key_schedule *k, gcm_hash *h, const uint8_t *aad, size_t aad_len) {
    aes_encrypt_schedule(k, ZERO_BLOCK, h->subkey);
    memset(h->acc, 0, AES_BLOCK);
    ghash_data(k, h->acc, h->subkey, aad, aad_len);
}

// GHASH's last block, the two lengths, and out = the GHASH value. h is
// wiped.
static void hash_finish(const aes_key_schedule *k, gcm_hash *h, size_t aad_len, size_t n,
                        uint8_t out[AES_BLOCK]) {
    uint8_t lengths[AES_BLOCK];
    write_length_bits(lengths, aad_len);
    write_length_bits(&lengths[8], n);
    for (size_t i = 0; i < AES_BLOCK; i++) {
        h->acc[i] = (uint8_t)(h->acc[i] ^ lengths[i]);
    }
    ghash_multiply(k, h->acc, h->subkey);
    memcpy(out, h->acc, AES_BLOCK);
    ct_wipe(h, sizeof *h);
}

static void ghash_schedule(const aes_key_schedule *k, const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t n, uint8_t out[AES_BLOCK]) {
    gcm_hash h;
    hash_start(k, &h, aad, aad_len);
    ghash_data(k, h.acc, h.subkey, ct, n);
    hash_finish(k, &h, aad_len, n, out);
}

// SP 800-38D §7.1 step 2: for a 96-bit IV the first counter block is the
// IV followed by 31 zero bits and a one.
static void first_counter_block(uint8_t counter[AES_BLOCK], const uint8_t nonce[AES_IV]) {
    memcpy(counter, nonce, AES_IV);
    counter[AES_IV] = 0;
    counter[AES_IV + 1] = 0;
    counter[AES_IV + 2] = 0;
    counter[AES_IV + 3] = 1;
}

// SP 800-38D §6.2, inc32: the rightmost 32 bits of the block increase by
// one and the 96 bits before them stay. The carry runs through the four
// bytes without a branch, and the bytes are read and written one at a
// time, so this does not assume host endianness.
static void increment_counter(uint8_t counter[AES_BLOCK]) {
    unsigned carry = 1;
    for (size_t i = AES_BLOCK; i > AES_BLOCK - 4; i--) {
        unsigned sum = (unsigned)counter[i - 1] + carry;
        counter[i - 1] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

#ifdef CH_CPU_RUNTIME
// The round count gcm_hw.c's entries take beside k's round keys. A
// schedule the table expanded never reaches them: every caller below
// checks on_instructions first, and the assertion holds that, because the
// table has no entry that runs several blocks. The round count is the
// suite's, as in aes_encrypt_schedule.
static size_t instruction_rounds(const aes_key_schedule *k) {
#ifdef CH_AES_TWO_CIPHERS
    CH_ASSERT(on_instructions(k));
#endif
#ifdef CH_AES_256
    return k->rounds;
#else
    (void)k;
    return AES_128_ROUNDS;
#endif
}

// The whole blocks of counter_mode's input on the AES instructions, which
// run several blocks at once, on the path the description of the CPU that
// k records names (gcm_counter_blocks_cpu, gcm_vaes.h), and the bytes they
// covered. A schedule the table runs, which only a QUIC host object
// holds, covers none, and counter_mode runs all its blocks one at a time.
static size_t counter_mode_whole_blocks(const aes_key_schedule *k, uint8_t counter[AES_BLOCK],
                                        const uint8_t *in, size_t n, uint8_t *out) {
#ifdef CH_AES_TWO_CIPHERS
    if (!on_instructions(k)) {
        return 0;
    }
#endif
    size_t blocks = n / AES_BLOCK;
    gcm_counter_blocks_cpu(k->cpu, k->round_keys, instruction_rounds(k), counter, in, blocks, out);
    return blocks * AES_BLOCK;
}

// The whole passes of GCM_HW_PASS_BLOCKS blocks on the AES instructions:
// counter mode and GHASH over the ciphertext in one loop, from h's
// accumulator, gcm_seal_passes_cpu when seal is set and
// gcm_open_passes_cpu when it is not, each on the path k's description of
// the CPU names (gcm_vaes.h), and the bytes they covered. A schedule the
// table runs covers none. seal is the caller's own constant, so its
// branch reads no data.
static size_t whole_passes(const aes_key_schedule *k, int seal, uint8_t counter[AES_BLOCK],
                           gcm_hash *h, const uint8_t *in, size_t n, uint8_t *out) {
#ifdef CH_AES_TWO_CIPHERS
    if (!on_instructions(k)) {
        return 0;
    }
#endif
    size_t pass_bytes = (size_t)GCM_HW_PASS_BLOCKS * AES_BLOCK;
    size_t passes = n / pass_bytes;
    size_t rounds = instruction_rounds(k);
    if (seal) {
        gcm_seal_passes_cpu(k->cpu, k->round_keys, rounds, counter, h->acc, h->subkey, in, passes,
                            out);
    } else {
        gcm_open_passes_cpu(k->cpu, k->round_keys, rounds, counter, h->acc, h->subkey, in, passes,
                            out);
    }
    return passes * pass_bytes;
}
#endif

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// Whether k's whole AEAD runs on gcm_avx512.c: k runs on the AES
// instructions, and the two bytes of the description of the CPU it records
// pass gcm_use_avx512 (aes_schedule.h).
static int runs_avx512(const aes_key_schedule *k) {
#ifdef CH_AES_TWO_CIPHERS
    if (!on_instructions(k)) {
        return 0;
    }
#endif
    return gcm_use_avx512((uint32_t)k->cpu | (uint32_t)k->cpu_high << 8);
}
#endif

// SP 800-38D §6.5, GCTR, over the blocks after the first counter block:
// each input block is exclusive-ored with the forward cipher of the
// counter, and the counter increases before every block. The caller
// passes the first counter block, so the first cipher call here runs on
// inc32 of it, which is what §7.1 step 3 asks for. On the AES
// instructions the whole blocks run first, several at a time, and the loop
// below runs the last partial block.
//
// One byte of out is written after the byte of in at the same index is
// read, so in == out works and so does out below in.
static void counter_mode(const aes_key_schedule *k, uint8_t counter[AES_BLOCK], const uint8_t *in,
                         size_t n, uint8_t *out) {
    size_t off = 0;
#ifdef CH_CPU_RUNTIME
    off = counter_mode_whole_blocks(k, counter, in, n, out);
#endif
    // One buffer for every block, wiped once at the end rather than once
    // per block: the last block's keystream is the only one still in the
    // frame when this returns, and a wipe inside the loop would run per
    // block for no further gain.
    uint8_t keystream[AES_BLOCK];
    while (off < n) {
        increment_counter(counter);
        aes_encrypt_schedule(k, counter, keystream);
        size_t take = n - off < AES_BLOCK ? n - off : AES_BLOCK;
        for (size_t i = 0; i < take; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ keystream[i]);
        }
        off += take;
    }
    ct_wipe(keystream, sizeof keystream);
}

// SP 800-38D §7.1 step 6: the tag is GHASH over the associated data and
// the ciphertext, exclusive-ored with the forward cipher of the first
// counter block. hashed is that GHASH value, and both it and the mask are
// wiped.
static void mask_tag(const aes_key_schedule *k, const uint8_t first_counter[AES_BLOCK],
                     uint8_t hashed[AES_BLOCK], uint8_t tag[GCM_TAG]) {
    uint8_t mask[AES_BLOCK];
    aes_encrypt_schedule(k, first_counter, mask);
    for (size_t i = 0; i < GCM_TAG; i++) {
        tag[i] = (uint8_t)(hashed[i] ^ mask[i]);
    }
    ct_wipe(hashed, AES_BLOCK);
    ct_wipe(mask, sizeof mask);
}

void gcm_ghash(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
               size_t n, uint8_t out[GCM_TAG]) {
    ghash_schedule(&k->key, aad, aad_len, ct, n, out);
}

// The AEAD over an expanded key. The typed entries below unwrap their key
// and call these, so seal and open are written once and the compiler
// still decides which call sites may hold which key (INV-26).
static void seal_schedule(const aes_key_schedule *k, const uint8_t nonce[AES_IV],
                          const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                          uint8_t *ct, uint8_t tag[GCM_TAG]) {
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
    if (runs_avx512(k)) {
        gcm_seal_avx512(k->round_keys, instruction_rounds(k), nonce, aad, aad_len, pt, n, ct, tag);
        return;
    }
#endif
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    // Counter mode advances the block it is given, so it gets a copy and
    // mask_tag still reads the first counter block.
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first_counter, AES_BLOCK);
    gcm_hash h;
    hash_start(k, &h, aad, aad_len);
    // GHASH runs over the ciphertext in order, so the whole passes, which
    // gcm_hw.c hashes as it writes them, come first, and the rest is
    // hashed once counter mode has written it. done is at most n, so the
    // two pointers stay inside the buffers or one past their end.
    size_t done = 0;
#ifdef CH_CPU_RUNTIME
    done = whole_passes(k, 1, counter, &h, pt, n, ct);
#endif
    counter_mode(k, counter, &pt[done], n - done, &ct[done]);
    ghash_data(k, h.acc, h.subkey, &ct[done], n - done);
    uint8_t hashed[AES_BLOCK];
    hash_finish(k, &h, aad_len, n, hashed);
    mask_tag(k, first_counter, hashed, tag);
}

// The open's verdict: want, the tag the ciphertext should carry, against
// tag, the one received. want is wiped. ok is the comparison's verdict,
// which the caller learns anyway, so the branch on it is public. On a
// mismatch the call wipes the n bytes the open wrote, and it wrote nothing
// else at pt.
static int tag_matches(uint8_t want[GCM_TAG], const uint8_t tag[GCM_TAG], uint8_t *pt, size_t n) {
    uint32_t ok = ct_memeq_public(want, tag, GCM_TAG);
    ct_wipe(want, GCM_TAG);
    if (!ok) {
        ct_wipe(pt, n);
        return 0;
    }
    return 1;
}

static int open_schedule(const aes_key_schedule *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                         uint8_t *pt) {
    uint8_t want[GCM_TAG];
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
    if (runs_avx512(k)) {
        gcm_open_avx512(k->round_keys, instruction_rounds(k), nonce, aad, aad_len, ct, n, pt, want);
        return tag_matches(want, tag, pt, n);
    }
#endif
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first_counter, AES_BLOCK);
    gcm_hash h;
    hash_start(k, &h, aad, aad_len);
    // The open decrypts while it hashes, as the seal encrypts while it
    // hashes, and compares the tag after both are done. pt may be ct or sit
    // below it (gcm.h), so a plaintext write can overwrite ciphertext.
    // Each ciphertext byte is therefore hashed before any write to its
    // address: gcm_hw.c's loop hashes each pass before it decrypts it, and
    // here GHASH runs over the rest before counter mode writes it.
    size_t done = 0;
#ifdef CH_CPU_RUNTIME
    done = whole_passes(k, 0, counter, &h, ct, n, pt);
#endif
    ghash_data(k, h.acc, h.subkey, &ct[done], n - done);
    counter_mode(k, counter, &ct[done], n - done, &pt[done]);
    uint8_t hashed[AES_BLOCK];
    hash_finish(k, &h, aad_len, n, hashed);
    mask_tag(k, first_counter, hashed, want);
    return tag_matches(want, tag, pt, n);
}

void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]) {
    seal_schedule(&k->key, nonce, aad, aad_len, pt, n, ct, tag);
}

int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt) {
    return open_schedule(&k->key, nonce, aad, aad_len, ct, n, tag, pt);
}

#ifdef CH_SUITE_AES_GCM
// The same AEAD over a TLS traffic key, AES-128 or AES-256 as its
// schedule's round count says. Its own entry rather than a cast,
// because the type is what keeps a traffic key out of the three public
// call sites and a public key out of the record layer (INV-26).
void gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                      uint8_t tag[GCM_TAG]) {
    seal_schedule(&k->key, nonce, aad, aad_len, pt, n, ct, tag);
}

int gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                     uint8_t *pt) {
    return open_schedule(&k->key, nonce, aad, aad_len, ct, n, tag, pt);
}
#endif // CH_SUITE_AES_GCM

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
