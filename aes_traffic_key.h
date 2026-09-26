// What an aes_traffic_key is made of. aes.h declares the type
// incomplete and declares the entries that take one, and gcm.h
// declares the AEAD over one; this header is the one place the struct has
// a body, so it is the one place a file can declare one, size one or
// write a field of one.
//
// It is the second half of INV-26. The first half is aes_public_key,
// whose every key comes from a salt the RFC prints or a connection ID
// that travels in the clear, so a table lookup indexed by one leaks
// nothing. A traffic key is not public, and naming it aes_public_key
// would make that invariant's own name a lie. So it gets a type whose
// name says what it holds, and the compiler decides which call sites may
// hold which key rather than a reviewer.
//
// Four sources include this header, and tools/quic-footprint.py fails on
// a fifth:
//
//   aes.c          writes aes_traffic_key_init and the block entry
//   gcm.c          reads the round keys out of one to run the AEAD
//   record.c       builds one per record from rec_dir's key bytes
//   quic_packet.c  builds one per QUIC packet from quic_keys' key bytes,
//                  and one per header protection mask from quic_hp_key's
//
// A build that never defines CH_SUITE_AES_GCM compiles none of it, and
// ct.h refuses that define unless the build has hardware AES and asserts
// its timing. That refusal is what keeps a secret key away from the
// AES=soft S-box, which is indexed with the key.
//
// This header includes aes_schedule.h and not aes_public_key.h, so the
// files above can build a traffic key, and record.c cannot build a public
// one.
#ifndef CH_AES_TRAFFIC_KEY_H
#define CH_AES_TRAFFIC_KEY_H
#ifdef CH_SUITE_AES_GCM

#include <stdint.h>

#include "aes.h"
#include "aes_schedule.h"

// One AES-128 or AES-256 key from the TLS key schedule, expanded. It holds
// the round keys and their round count and nothing else: a TLS record's
// nonce is built from the write IV and the sequence number by record.c,
// which keeps the IV in rec_dir, and a record carries no header
// protection.
struct aes_traffic_key {
    aes_key_schedule key;
};

#endif // CH_SUITE_AES_GCM
#endif
