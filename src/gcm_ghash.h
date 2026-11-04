// GHASH for gcm.c: the portable multiply and the loop over data, SP 800-38D §6.3 and §6.4, and
// which of the two GHASH bodies a schedule runs. gcm.c includes this file once, after
// aes_public_key.h, which gives aes_key_schedule the body the functions below read, and no other
// source includes it. It is a header of its own so that gcm.c stays under the 500 lines
// CLAUDE.md sets: every function here is static and compiles into gcm.c's object.
//
// GHASH has two bodies. A device object, AES=soft or AES=extern, runs the portable multiply
// below, 128 masked steps per block. A TCP host object (-DCH_CPU_RUNTIME, cpu_cfg.h) runs
// ghash_hw.c's, three carry-less products per block and, once per pass of up to eight blocks, a
// reduction on the same instruction, and compiles no portable body. A QUIC host object
// (CH_AES_TWO_CIPHERS, aes.h) compiles both and runs ghash_hw.c's for a schedule the AES
// instructions run and the portable one for a schedule the table runs (aes_schedule.h), so a
// session whose caller did not set CH_CPU_CONSTANT_TIME_AES runs no carry-less multiply either.
// Under an AES=extern suite build the portable multiply runs under a secret hash subkey. Its
// masks keep every subkey bit off a branch and off a memory index, and it multiplies no
// integers, so it needs no statement about the part.
#ifndef CH_GCM_GHASH_H
#define CH_GCM_GHASH_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "ct.h"
#ifdef CH_CPU_RUNTIME
#include "ghash_hw.h"
#endif

// The objects that run every schedule on the AES instructions, and so
// hold ghash_hw.c's GHASH alone: a host object with no table beside the
// instructions, which is a TCP one.
#if defined(CH_CPU_RUNTIME) && !defined(CH_AES_TWO_CIPHERS)
#define GCM_GHASH_CARRYLESS_ALONE
#endif

#ifdef GCM_GHASH_CARRYLESS_ALONE
// ghash_hw.c computes both GHASH steps on the carry-less multiply
// instruction, and the portable bodies under #else are not compiled.
// CBMC cannot read an intrinsic, so the proofs cover the portable bodies
// alone, and test/ghash_equiv_test.c holds each entry below to its
// portable twin byte for byte.
static void multiply_by_subkey(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    gcm_multiply_by_subkey_hw(acc, subkey);
}

static void hash_data(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    gcm_hash_data_hw(acc, subkey, data, n);
}
#else
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
// The two masks are arithmetic rather than branches. Under a public key
// that is only shorter to read; under -DCH_SUITE_AES_GCM the accumulator
// bit and the shifted-out bit are both computed from the hash subkey, and
// then the mask is what keeps them off a branch.
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
    // multiple ends as the hash subkey shifted GCM_BLOCK_BITS times, which
    // is an invertible function of it, so the frame would hand a later
    // caller the subkey itself. product is already in acc and needs no
    // wipe of its own.
    ct_wipe(multiple, sizeof multiple);
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
#endif // GCM_GHASH_CARRYLESS_ALONE

// The GHASH body that runs under k. A QUIC host object holds two (the
// paragraph at the top of this file): the carry-less multiply for a
// schedule on the instructions, and the portable one for a schedule on
// the table, which only QUIC's public keys use. Every other object holds
// one body, and k chooses nothing. k->instructions comes from the
// session's CH_CPU_CONSTANT_TIME_AES bit or is a constant
// (aes_schedule.h), so the branch reads a public value. gcm.c's
// counter_mode, whole passes and whole AEAD read the same predicate.
#ifdef CH_AES_TWO_CIPHERS
static int on_instructions(const aes_key_schedule *k) {
    return k->instructions == AES_ON_INSTRUCTIONS;
}

static void ghash_multiply(const aes_key_schedule *k, uint8_t acc[AES_BLOCK],
                           const uint8_t subkey[AES_BLOCK]) {
    if (on_instructions(k)) {
        gcm_multiply_by_subkey_hw(acc, subkey);
        return;
    }
    multiply_by_subkey(acc, subkey);
}

static void ghash_data(const aes_key_schedule *k, uint8_t acc[AES_BLOCK],
                       const uint8_t subkey[AES_BLOCK], const uint8_t *data, size_t n) {
    if (on_instructions(k)) {
        gcm_hash_data_hw(acc, subkey, data, n);
        return;
    }
    hash_data(acc, subkey, data, n);
}
#else
static void ghash_multiply(const aes_key_schedule *k, uint8_t acc[AES_BLOCK],
                           const uint8_t subkey[AES_BLOCK]) {
    (void)k;
    multiply_by_subkey(acc, subkey);
}

static void ghash_data(const aes_key_schedule *k, uint8_t acc[AES_BLOCK],
                       const uint8_t subkey[AES_BLOCK], const uint8_t *data, size_t n) {
    (void)k;
    hash_data(acc, subkey, data, n);
}
#endif

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
