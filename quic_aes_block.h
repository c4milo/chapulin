// The AES-128 key expansion and forward cipher, as two entries over
// plain byte arrays, and the AES-256 pair beside them in a build that
// has AES-256 (CH_AES_256, quic_aes.h). The Makefile AES variable picks
// the one source that defines them: quic_aes_soft.c (AES=soft, the
// default), quic_aes_hw.c (AES=hw, the compiler's AES intrinsics) or
// quic_aes_extern.c (AES=extern, a block function the caller supplies).
// One source per object, the way PIN puts one pinned algorithm in one
// object.
//
// quic_aes.c is the only library source that calls these. It owns both
// key types, derives the RFC 9001 §5.2 keys into an aes_public_key,
// expands a traffic key into an aes_traffic_key, and hands the round keys
// down as bytes.
//
// Bytes rather than an aes_key_schedule, on purpose. aes_schedule.h holds
// the body of that type, and INV-26's first check is that only the two key
// headers include it, so only the sources admitted to one of those can
// declare a key or write a field of one. An implementation source that
// took the struct would have to join them. Taking bytes keeps it out:
// none of the three implementations can build a key object at all,
// whatever it does with the bytes it is handed.
//
// Detection is the compiler's, at build time, and nothing here probes a
// CPU or asks an operating system. quic_aes_hw.c states why.
#ifndef CH_QUIC_AES_BLOCK_H
#define CH_QUIC_AES_BLOCK_H

// All three sources define the same two entries, so two of them in one
// object would not link. This says so at the preprocessor instead, and
// it sits outside the transport guard below so it answers whatever build
// reads this header. The Makefile AES variable cannot produce both
// defines; a firmware tree compiling these sources with its own build
// system can, which is who this line is for.
#if defined(CH_AES_HW) && defined(CH_AES_EXTERN)
#error "CH_AES_HW and CH_AES_EXTERN are exclusive: declare at most one (docs/quic.md)"
#endif

#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)

#include <stdint.h>

#include "quic_aes.h"

// FIPS 197 §5.2, Key Expansion, for Nk = 4: key is the 16-byte AES-128
// key and round_keys gets all AES_ROUND_KEYS round keys, AES_BLOCK bytes
// each, the first of which is the key itself.
//
// AES=extern is the one implementation that writes something else. It
// has no expansion to run, because the caller's block function takes a
// key rather than a schedule, so it stores the 16 key bytes in the first
// block and zeros the rest. quic_aes_extern.c states that and nothing
// outside it reads round_keys as anything but an opaque block.
//
// Requires: key points at AES_128_KEY readable bytes; round_keys points
// at AES_ROUND_KEYS * AES_BLOCK writable bytes. Writes them all and
// cannot fail.
void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]);

// FIPS 197 §5.1, the forward cipher CIPH_K: out = CIPH(in) under the
// round keys aes_expand_round_keys wrote.
//
// Requires: round_keys was written by aes_expand_round_keys; in and out
// point at AES_BLOCK readable and writable bytes. in == out is allowed,
// and every implementation copies the input into a local state first so
// that it works. Writes AES_BLOCK bytes and cannot fail.
void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);

#ifdef CH_AES_256
// FIPS 197 §5.2, Key Expansion, for Nk = 8: key is the 32-byte AES-256
// key and round_keys gets all AES_256_ROUND_KEYS round keys, AES_BLOCK
// bytes each, the first two of which are the key itself. Every eighth
// word takes RotWord, SubWord and the round constant, and the word four
// after it takes SubWord alone, which is the step Nk = 4 does not have.
//
// quic_aes_hw.c defines it in a -DCH_SUITE_AES_GCM build, and
// quic_aes_soft.c defines the software reference under
// -DCH_AES_256_TEST, which only tests and proofs set (quic_aes.h).
// quic_aes_extern.c defines neither: a peripheral hook takes a 16-byte key.
//
// Requires: key points at AES_256_KEY readable bytes; round_keys points
// at AES_256_ROUND_KEYS * AES_BLOCK writable bytes. Writes them all and
// cannot fail.
void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]);

// FIPS 197 §5.1, the forward cipher CIPH_K for Nr = 14: one AddRoundKey,
// thirteen full rounds and a last round without MixColumns, under the
// round keys aes_expand_round_keys_256 wrote.
//
// Requires: round_keys was written by aes_expand_round_keys_256; in and
// out point at AES_BLOCK readable and writable bytes, and in == out is
// allowed. Writes AES_BLOCK bytes and cannot fail.
void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
#endif

#ifdef CH_AES_EXTERN
// The platform hook an AES=extern build leaves for the image to define,
// the way RAND=extern leaves ch_rand_bytes in rand.h. A part with an AES
// peripheral wires this to it and compiles no cipher from this tree.
//
// One forward AES-128 block: out = CIPH_key(in), FIPS 197 §5.1. The key
// is the 16-byte AES-128 key, not a schedule, because a peripheral takes
// a key. An implementation that expands the key itself may cache the
// expansion; this call gives it the same key bytes every time for as
// long as one aes_public_key lives.
//
// Requires: key points at AES_128_KEY readable bytes, in at AES_BLOCK
// readable bytes and out at AES_BLOCK writable bytes. in == out must
// work. The hook must not fail and must not return before out holds the
// whole block, because every caller above it treats the cipher as an
// operation that cannot fail.
//
// A build whose peripheral is not constant time keeps INV-26's bound:
// the keys that reach it are the public ones RFC 9001 fixes.
void ch_aes_block(const uint8_t key[AES_128_KEY], const uint8_t in[AES_BLOCK],
                  uint8_t out[AES_BLOCK]);
#endif

#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
#endif
