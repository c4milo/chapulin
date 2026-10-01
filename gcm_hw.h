// AES-GCM's work over whole blocks on the AES instructions and the
// carry-less multiply: SP 800-38D §6.5's counter mode, several blocks at a
// time, and the seal's and the open's counter mode and GHASH in one loop.
// gcm.c's counter_mode, seal and open call these entries for a schedule
// the AES instructions run, and run a schedule the table or a peripheral
// runs one block at a time. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h)
// compiles gcm_hw.c beside aes_hw.c and ghash_hw.c, and gcm.c calls it for
// a schedule on the instructions alone (aes_schedule.h).
//
// A pair of its own rather than more entries in aes_block.h or ghash_hw.h.
// aes_block.h is the AES block cipher's contract, and ghash_hw.h is
// GHASH's; counter mode and the loop that runs it beside GHASH are
// SP 800-38D's, and gcm.c is the one source that calls them. The loop
// needs the AES rounds and the carry-less multiply in one function, so
// that the core runs both at once, and one function cannot sit in two
// files. One concern per pair: GCM over whole blocks on the instructions.
//
// Each entry takes the round keys as plain bytes, with the round count,
// AES_128_ROUNDS or AES_256_ROUNDS, beside them: gcm.c unwraps its key and
// passes both, the way aes.c hands aes_block.h's entries round keys. Every
// name begins gcm_, so inv-26-aes-public-keys-only matches a call from any
// library source outside gcm.c, and `make lint-quic-surface` reads this
// header for that prefix beside aes.h, aes_block.h, gcm.h and ghash_hw.h.
// The round keys are a public key's or a traffic key's, so INV-26 bounds
// these entries the way it bounds the AEAD.
#ifndef CH_GCM_HW_H
#define CH_GCM_HW_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// How many blocks a pass of gcm_seal_passes_hw and gcm_open_passes_hw
// covers: the eight counter blocks the AES rounds run together, and the
// eight ciphertext blocks one GHASH reduction covers.
#define GCM_HW_PASS_BLOCKS 8

// SP 800-38D §6.5's GCTR over whole blocks, under round keys expanded for
// rounds rounds: for i from 1 to blocks, block i of out is block i of in
// exclusive-ored with CIPH(inc32^i(counter)). inc32 adds one to the
// counter's last four bytes, read big-endian, modulo 2^32 and leaves the
// first twelve alone (SP 800-38D §6.2), so a counter near 2^32 wraps to
// zero without a carry into the IV bytes. counter then holds
// inc32^blocks of what it held, the counter of the last block, so the
// caller can go on with the block after it.
//
// Requires: round_keys points at (rounds + 1) * AES_BLOCK readable bytes
// that aes_expand_round_keys or aes_expand_round_keys_256 wrote, and
// rounds is AES_128_ROUNDS or AES_256_ROUNDS to match; counter points at
// AES_BLOCK readable and writable bytes; in and out point at
// blocks * AES_BLOCK readable and writable bytes, and may be NULL when
// blocks is 0. in == out is allowed, and so is out below in (out <= in):
// every input byte is read before an output byte is written over it.
// Writes blocks * AES_BLOCK bytes and cannot fail.
void gcm_counter_blocks_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out);

// The seal's counter mode and GHASH over passes * GCM_HW_PASS_BLOCKS whole
// blocks in one loop: out gets gcm_counter_blocks_hw's output over them,
// counter advances as it does there, and acc goes on through SP 800-38D
// §6.4's GHASH under the hash subkey over every block of out, from the
// value acc holds, so that a caller who hashed the associated data into
// acc first holds GHASH over the associated data and these blocks.
//
// Requires: round_keys, rounds and counter as gcm_counter_blocks_hw
// requires them; acc points at AES_BLOCK readable and writable bytes and
// subkey at AES_BLOCK readable bytes, H = CIPH_K(0^128) under the same
// key, neither of them inside in or out; in and out point at
// passes * GCM_HW_PASS_BLOCKS * AES_BLOCK readable and writable bytes, and
// may be NULL when passes is 0, with in == out allowed and no other
// overlap. Writes out, counter and acc, and cannot fail.
void gcm_seal_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);

// The open's GHASH and counter mode over passes * GCM_HW_PASS_BLOCKS whole
// blocks of ciphertext in one loop: acc goes on through GHASH over every
// block of in, as gcm_seal_passes_hw's does over its out, and out gets
// gcm_counter_blocks_hw's output over in, which is the plaintext. It
// checks no tag: the caller compares the tag once GHASH is done and wipes
// out when it does not match (gcm.h).
//
// Requires: what gcm_seal_passes_hw requires, with in == out allowed and
// so is out below in (out <= in), as gcm_counter_blocks_hw admits: each
// pass's ciphertext is hashed before any of its plaintext is written.
// Writes out, counter and acc, and cannot fail.
void gcm_open_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);

#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
