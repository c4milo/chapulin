// The AES-128 key expansion and forward cipher, as two entries over
// plain byte arrays, and the AES-256 pair beside them in a build that
// has AES-256 (CH_AES_256, aes.h). In a device object the Makefile AES
// variable picks the one source that defines them: quic_aes_soft.c
// (AES=soft, the default) or aes_extern.c (AES=extern, a block function
// the caller supplies). A host object (-DCH_CPU_RUNTIME, cpu_cfg.h)
// compiles aes_hw.c, the compiler's AES intrinsics turned on for its own
// functions alone, and a QUIC host object holds quic_aes_soft.c beside it
// under the aes_soft_ names below. The session's CH_CPU_CONSTANT_TIME_AES
// bit chooses between the two for each public key (docs/decisions.md 81
// and 89).
//
// aes.c is the only library source that calls these. It owns both
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
// Detection is the caller's, at run time (ch_cfg.cpu). Nothing here
// probes a CPU or asks an operating system. aes_hw.c states why.
#ifndef CH_AES_BLOCK_H
#define CH_AES_BLOCK_H

// aes_hw.c and aes_extern.c define the same entries, so the two in one
// object would not link. This says so at the preprocessor instead, and it
// sits outside the transport guard below so it answers whatever build
// reads this header. The Makefile refuses AES=extern for a host object; a
// firmware tree compiling these sources with its own build system can
// still write both defines, which is who this line is for. The two
// defines that chose the AES instructions when the object was built are
// gone, and a build that still writes one stops here rather than
// compiling the table it would otherwise get.
#if defined(CH_CPU_RUNTIME) && defined(CH_AES_EXTERN)
#error "CH_AES_EXTERN is a device object's AES: a host object holds the AES instructions"
#endif
#if defined(CH_AES_HW) || defined(CH_AES_RUNTIME)
#error "AES=hw and AES=runtime are gone: a host object holds the AES instructions (decision 89)"
#endif

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// FIPS 197 §5.2, Key Expansion, for Nk = 4: key is the 16-byte AES-128
// key and round_keys gets all AES_ROUND_KEYS round keys, AES_BLOCK bytes
// each, the first of which is the key itself.
//
// AES=extern is the one implementation that writes something else. It
// has no expansion to run, because the caller's block function takes a
// key rather than a schedule, so it stores the 16 key bytes in the first
// block and zeros the rest. aes_extern.c states that and nothing
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
// aes_hw.c and aes_extern.c define it in a -DCH_SUITE_AES_GCM build,
// and quic_aes_soft.c defines the software reference under
// -DCH_AES_256_TEST, which only tests and proofs set (aes.h).
// aes_extern.c stores the 32 key bytes in the first two blocks and
// zeros the rest, as its AES-128 entry does with 16.
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

#ifdef CH_AES_TWO_CIPHERS
// The second cipher of a QUIC host object (aes.h). aes_hw.c defines the
// four entries above on the AES instructions, and quic_aes_soft.c defines
// these two on the S-box table, with the contracts of
// aes_expand_round_keys and aes_cipher_block and the same round-key
// layout, so a schedule either one expands reads the same to the other.
// aes.c is their one caller, for a public key alone: the Initial keys of a
// session whose caller did not set CH_CPU_CONSTANT_TIME_AES, and the
// Retry key. A traffic key never runs on them, because
// aes_traffic_key_init records the instructions in its schedule
// (aes_schedule.h).
void aes_soft_expand_round_keys(const uint8_t key[AES_128_KEY],
                                uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]);
void aes_soft_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
#endif

// ch_aes_block, the hook an AES=extern build leaves for the image, is
// declared in aes_extern.h, which a caller includes.
#include "aes_extern.h"

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
