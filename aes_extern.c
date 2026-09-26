// AES=extern: no cipher at all. Every entry forwards to ch_aes_block,
// which the image defines, the way a RAND=extern build leaves
// ch_rand_bytes to the image. A part with an AES peripheral wires that
// one function to it and compiles no AES from this tree.
// aes_block.h states the contracts and declares the hook.
//
// A peripheral takes a key, not a FIPS 197 key schedule, so there is no
// expansion to run here. aes_expand_round_keys stores the 16 key bytes
// in the first block of round_keys and zeros the rest, and
// aes_expand_round_keys_256 stores the 32 key bytes in the first two
// blocks and zeros the rest. aes_cipher_block and aes_cipher_block_256
// pass those bytes back to the hook as the key, with the key length
// each entry names. Nothing outside this file reads round_keys as a
// schedule: aes.c writes it only through the two expansions and reads
// it only by passing it to the two ciphers, and gcm.c reads it only
// through aes.c. The remaining bytes stay in the struct because
// aes_schedule.h fixes its size for every AES choice, so the stack
// budget INV-19 measures does not move with this one.
//
// In a -DCH_SUITE_AES_GCM build round_keys holds a traffic key itself,
// not an expansion of it. record.c and quic_packet.c wipe the whole
// aes_traffic_key on the frame that built it, so the key bytes are
// wiped there the way round keys are under AES=hw. This file keeps no
// copy: it has no local that holds a key byte.
//
// This build can be the fastest of the three or the slowest, and this
// tree cannot tell which: what ch_aes_block costs is the peripheral's.
// Its timing is also the one this tree cannot state at all. A build
// without -DCH_SUITE_AES_GCM passes the hook only the public keys RFC
// 9001 fixes, so INV-26's first bound holds it. A suite build passes it
// traffic keys, and ct.h refuses that build unless it defines
// CH_AES_EXTERN_CONSTANT_TIME, the firmware author's statement that the
// peripheral runs in constant time. Nothing in this tree checks that
// statement (docs/decisions.md entry 68).
#include "aes_block.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_AES_EXTERN

#include <stddef.h>
#include <string.h>

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    memcpy(round_keys, key, AES_128_KEY);
    memset(&round_keys[AES_128_KEY], 0, ((size_t)AES_ROUND_KEYS * AES_BLOCK) - AES_128_KEY);
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    ch_aes_block(round_keys, AES_128_KEY, in, out);
}

#ifdef CH_AES_256
void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    memcpy(round_keys, key, AES_256_KEY);
    memset(&round_keys[AES_256_KEY], 0, ((size_t)AES_256_ROUND_KEYS * AES_BLOCK) - AES_256_KEY);
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    ch_aes_block(round_keys, AES_256_KEY, in, out);
}
#endif // CH_AES_256

#endif // CH_AES_EXTERN
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
