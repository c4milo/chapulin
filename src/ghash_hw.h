// GHASH on the carry-less multiply instruction: the two steps of
// AEAD_AES_128_GCM that a host object moves out of gcm.c. A host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles ghash_hw.c beside aes_hw.c, and
// gcm.c's multiply_by_subkey and hash_data call the two entries below for
// a schedule the AES instructions run; a device object, AES=soft or
// AES=extern, compiles neither file and runs gcm.c's portable bodies. A
// QUIC host object runs those portable bodies too, for a schedule the
// table runs (aes_schedule.h), so a session whose caller did not set
// CH_CPU_CONSTANT_TIME_AES runs no carry-less multiply.
//
// Two entries rather than one. The multiply alone is what gcm.c
// needs for the block of lengths that ends GHASH, and what
// test/ghash_equiv_test.c compares at the operands most likely to go
// wrong. The loop over data is where GHASH spends its time, and running
// it here lets it multiply up to eight blocks by powers of the subkey it
// computes first, with one reduction for all of them (ghash_hw.c).
//
// A pair of its own rather than more entries in aes_block.h. That
// header is the AES block cipher's contract, and aes.c is the one
// source that calls it; these are the GF(2^128) steps of SP 800-38D, and
// gcm.c is the one source that calls them. One concern per pair.
//
// Both names begin gcm_ so that inv-26-aes-public-keys-only matches a
// call to either from any library source outside gcm.c, and
// `make lint-quic-surface` reads this header for that prefix beside
// aes.h, aes_block.h and gcm.h. Both take the hash subkey
// H, which is the forward cipher of a zero block under the AES key, so
// INV-26 bounds them the way it bounds the AEAD.
#ifndef CH_GHASH_HW_H
#define CH_GHASH_HW_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// SP 800-38D §6.3: acc = acc * subkey in GF(2^128), in the bit order
// SP 800-38D writes a block in: the most significant bit of byte 0 is the
// coefficient of x^0. It is the function gcm.c's multiply_by_subkey
// computes.
//
// Requires: acc points at AES_BLOCK readable and writable bytes and
// subkey at AES_BLOCK readable bytes. Both are read before acc is
// written, so acc == subkey works. Writes AES_BLOCK bytes to acc and
// cannot fail.
void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]);

// SP 800-38D §6.4, over n bytes of data: for each block, add it to acc
// and multiply acc by subkey. A last block shorter than AES_BLOCK is
// padded with zeros on the right. It is the function gcm.c's
// hash_data computes.
//
// Requires: acc and subkey as above; data points at n readable bytes and
// may be NULL when n is 0. Writes AES_BLOCK bytes to acc and cannot fail.
void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n);

#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
