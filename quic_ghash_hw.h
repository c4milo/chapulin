// GHASH on the carry-less multiply instruction: the two steps of
// AEAD_AES_128_GCM that an AES=hw build moves out of quic_gcm.c. Under
// CH_AES_HW, quic_gcm.c's multiply_by_subkey and hash_data call the two
// entries below; under AES=soft and AES=extern they run their own
// portable bodies. The Makefile AES variable picks which, and never both
// in one object: AES=hw compiles quic_ghash_hw.c beside quic_aes_hw.c,
// and the other two values compile neither.
//
// Two entries rather than one. The multiply alone is what quic_gcm.c
// needs for the block of lengths that ends GHASH, and what
// test/ghash_equiv_test.c compares at the operands most likely to go
// wrong. The loop over data is where GHASH spends its time, and running
// it here keeps the accumulator and the subkey in 64-bit words from one
// block to the next rather than reading and writing 32 bytes per block.
//
// A pair of its own rather than more entries in quic_aes_block.h. That
// header is the AES block cipher's contract, and quic_aes.c is the one
// source that calls it; these are the GF(2^128) steps of SP 800-38D, and
// quic_gcm.c is the one source that calls them. One concern per pair.
//
// Both names begin gcm_ so that inv-26-aes-public-keys-only matches a
// call to either from any library source outside quic_gcm.c, and
// `make lint-quic-surface` reads this header for that prefix beside
// quic_aes.h, quic_aes_block.h and quic_gcm.h. Both take the hash subkey
// H, which is the forward cipher of a zero block under the AES key, so
// INV-26 bounds them the way it bounds the AEAD.
#ifndef CH_QUIC_GHASH_HW_H
#define CH_QUIC_GHASH_HW_H
#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)
#ifdef CH_AES_HW

#include <stddef.h>
#include <stdint.h>

#include "quic_aes.h"

// SP 800-38D §6.3: acc = acc * subkey in GF(2^128), in the bit order
// SP 800-38D writes a block in: the most significant bit of byte 0 is the
// coefficient of x^0. It is the function quic_gcm.c's multiply_by_subkey
// computes.
//
// Requires: acc points at AES_BLOCK readable and writable bytes and
// subkey at AES_BLOCK readable bytes. Both are read before acc is
// written, so acc == subkey works. Writes AES_BLOCK bytes to acc and
// cannot fail.
void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]);

// SP 800-38D §6.4, over n bytes of data: for each block, add it to acc
// and multiply acc by subkey. A last block shorter than AES_BLOCK is
// padded with zeros on the right. It is the function quic_gcm.c's
// hash_data computes.
//
// Requires: acc and subkey as above; data points at n readable bytes and
// may be NULL when n is 0. Writes AES_BLOCK bytes to acc and cannot fail.
void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n);

#endif // CH_AES_HW
#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
#endif
