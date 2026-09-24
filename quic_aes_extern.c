// AES=extern: no cipher at all. Both entries forward to ch_aes_block,
// which the image defines, the way a RAND=extern build leaves
// ch_rand_bytes to the image. A part with an AES peripheral wires that
// one function to it and compiles no AES from this tree.
// quic_aes_block.h states both contracts and declares the hook.
//
// A peripheral takes a key, not a FIPS 197 key schedule, so there is no
// expansion to run here. aes_expand_round_keys stores the 16 key bytes
// in the first block of round_keys and zeros the rest, and
// aes_cipher_block hands that first block back as the key. Nothing
// outside this file reads round_keys as anything but an opaque block:
// quic_aes.c writes it only through aes_expand_round_keys and reads it
// only by passing it to aes_cipher_block. The remaining bytes stay in
// the struct because quic_aes_key.h fixes its size for every AES choice,
// so the stack budget INV-19 measures does not move with this one.
//
// This build can be the fastest of the three or the slowest, and this
// tree cannot tell which: what ch_aes_block costs is the peripheral's.
// It is also the one choice whose timing this tree cannot state, so
// INV-26's bound still holds it — the keys that reach it are the public
// ones RFC 9001 fixes.
#include "quic_aes_block.h"

#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)
#ifdef CH_AES_EXTERN

// ch_aes_block takes a 16-byte key, so this file has no AES-256 to offer.
// A suite build, the one that needs AES-256, takes AES=hw (ct.h), and the
// software reference is AES=soft's, so no build reaches this line; it
// stops a tree with its own build system that asks for both.
#ifdef CH_AES_256
#error "AES=extern has no AES-256: ch_aes_block takes a 16-byte key"
#endif

#include <string.h>

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    memcpy(round_keys, key, AES_128_KEY);
    memset(&round_keys[AES_128_KEY], 0, ((size_t)AES_ROUND_KEYS * AES_BLOCK) - AES_128_KEY);
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    ch_aes_block(round_keys, in, out);
}

#endif // CH_AES_EXTERN
#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
