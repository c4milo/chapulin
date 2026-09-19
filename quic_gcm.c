// AEAD_AES_128_GCM and the GHASH under it, NIST SP 800-38D. quic_gcm.h
// states every contract; this file implements them and nothing else.
//
// The forward cipher comes from quic_aes.c, and INV-26 in
// docs/invariants.md bounds which keys reach it: the Initial keys, which
// anyone who sees a Destination Connection ID can derive (RFC 9001
// §5.2), and the Retry key the RFC prints (§5.8). No key from the TLS
// key schedule reaches this file, so nothing here holds a secret byte.
//
// Only the 96-bit IV exists here. SP 800-38D §7.1 takes the first
// counter block straight from a 96-bit IV, and hashes any other IV
// length with GHASH first. QUIC produces no other length, so the second
// arm has no caller and no code.
#include "quic_gcm.h"

#ifdef CH_TRANSPORT_QUIC

#include <string.h>

#include "ct.h"

// The block of zeros SP 800-38D §7.1 step 1 encrypts to get the hash
// subkey H.
static const uint8_t ZERO_BLOCK[AES_BLOCK] = {0};

// The 128 bits of one block, which is how many steps SP 800-38D §6.3's
// Algorithm 1 takes. A size_t, because it counts loop iterations.
#define GCM_BLOCK_BITS ((size_t)8 * AES_BLOCK)

// SP 800-38D §6.3, Algorithm 1: multiply the accumulator by the hash
// subkey in GF(2^128). Bit i of the accumulator, counted from the most
// significant bit of byte 0, decides whether the running multiple is
// added to the product. The multiple moves right one bit each step, and
// the field polynomial adds R = 0xe1 || 0^120 back exactly when the bit
// that moved out was set.
//
// The two masks are arithmetic rather than branches because that is
// shorter to read, not because these bytes are secret. Every byte this
// file touches is public, for the reason the file comment gives.
static void multiply_by_subkey(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    uint8_t product[AES_BLOCK] = {0};
    uint8_t multiple[AES_BLOCK];
    memcpy(multiple, subkey, AES_BLOCK);
    for (size_t bit = 0; bit < GCM_BLOCK_BITS; bit++) {
        unsigned selected_bit = ((unsigned)acc[bit / 8] >> (7 - bit % 8)) & 1U;
        uint8_t selected = (uint8_t)(0U - selected_bit); // 0xff when the bit is set, else 0
        for (size_t i = 0; i < AES_BLOCK; i++) {
            product[i] = (uint8_t)(product[i] ^ (multiple[i] & selected));
        }
        uint8_t reduce = (uint8_t)(0U - ((unsigned)multiple[AES_BLOCK - 1] & 1U));
        for (size_t i = AES_BLOCK - 1; i > 0; i--) {
            multiple[i] = (uint8_t)((multiple[i] >> 1) | (uint8_t)(multiple[i - 1] << 7));
        }
        multiple[0] = (uint8_t)(multiple[0] >> 1);
        multiple[0] = (uint8_t)(multiple[0] ^ (0xe1U & reduce));
    }
    memcpy(acc, product, AES_BLOCK);
}

// SP 800-38D §6.4: add each block of data to the accumulator and
// multiply by the hash subkey. A last block shorter than AES_BLOCK is
// padded with zeros on the right, which is what §6.4's pad does.
static void hash_data(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    size_t off = 0;
    while (off < n) {
        size_t take = n - off < AES_BLOCK ? n - off : AES_BLOCK;
        // Zero first, then the bytes there are, which leaves §6.4's pad
        // on a last block shorter than AES_BLOCK.
        uint8_t block[AES_BLOCK];
        memset(block, 0, AES_BLOCK);
        memcpy(block, data + off, take);
        for (size_t i = 0; i < AES_BLOCK; i++) {
            acc[i] = (uint8_t)(acc[i] ^ block[i]);
        }
        multiply_by_subkey(acc, subkey);
        off += take;
    }
}

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

void gcm_ghash(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
               size_t n, uint8_t out[AES_BLOCK]) {
    // SP 800-38D §7.1 step 1: the hash subkey H is the forward cipher of
    // a block of zeros.
    uint8_t subkey[AES_BLOCK];
    aes_encrypt_block(k, ZERO_BLOCK, subkey);

    memset(out, 0, AES_BLOCK);
    hash_data(out, subkey, aad, aad_len);
    hash_data(out, subkey, ct, n);

    uint8_t lengths[AES_BLOCK];
    write_length_bits(lengths, aad_len);
    write_length_bits(&lengths[8], n);
    for (size_t i = 0; i < AES_BLOCK; i++) {
        out[i] = (uint8_t)(out[i] ^ lengths[i]);
    }
    multiply_by_subkey(out, subkey);
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

// SP 800-38D §6.5, GCTR, over the blocks after the first counter block:
// each input block is exclusive-ored with the forward cipher of the
// counter, and the counter increases before every block. The caller
// passes the first counter block, so the first cipher call here runs on
// inc32 of it, which is what §7.1 step 3 asks for.
//
// One byte of out is written after the byte of in at the same index is
// read, so in == out works and so does out below in.
static void counter_mode(const aes_public_key *k, uint8_t counter[AES_BLOCK], const uint8_t *in,
                         size_t n, uint8_t *out) {
    size_t off = 0;
    while (off < n) {
        increment_counter(counter);
        uint8_t keystream[AES_BLOCK];
        aes_encrypt_block(k, counter, keystream);
        size_t take = n - off < AES_BLOCK ? n - off : AES_BLOCK;
        for (size_t i = 0; i < take; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ keystream[i]);
        }
        off += take;
    }
}

// SP 800-38D §7.1 step 6: the tag is GHASH over the associated data and
// the ciphertext, exclusive-ored with the forward cipher of the first
// counter block.
static void compute_tag(const aes_public_key *k, const uint8_t first_counter[AES_BLOCK],
                        const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                        uint8_t tag[GCM_TAG]) {
    uint8_t hashed[AES_BLOCK];
    gcm_ghash(k, aad, aad_len, ct, n, hashed);
    uint8_t mask[AES_BLOCK];
    aes_encrypt_block(k, first_counter, mask);
    for (size_t i = 0; i < GCM_TAG; i++) {
        tag[i] = (uint8_t)(hashed[i] ^ mask[i]);
    }
}

void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]) {
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    // counter_mode advances the block it is given, so it gets a copy and
    // compute_tag still reads the first counter block.
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first_counter, AES_BLOCK);
    counter_mode(k, counter, pt, n, ct);
    compute_tag(k, first_counter, aad, aad_len, ct, n, tag);
}

int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt) {
    uint8_t first_counter[AES_BLOCK];
    first_counter_block(first_counter, nonce);
    // The tag is computed over the ciphertext and compared before any
    // plaintext byte is written, which is the order aead_open uses and
    // the order the header promises.
    uint8_t want[GCM_TAG];
    compute_tag(k, first_counter, aad, aad_len, ct, n, want);
    uint32_t ok = ct_memeq(want, tag, GCM_TAG);
    if (!ok) {
        return 0;
    }
    // No wipe of want, for the reason aes_public_key_initial gives: every
    // byte this file computes is public, and ct_wipe would tell a reader
    // these bytes are secret.
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first_counter, AES_BLOCK);
    counter_mode(k, counter, ct, n, pt);
    return 1;
}

#endif // CH_TRANSPORT_QUIC
