// What an aes_traffic_key is made of. quic_aes.h declares the type
// incomplete and quic_gcm.h declares the two entries that take one; this
// header is the one place the struct has a body, so it is the one place a
// file can declare one, size one or write a field of one.
//
// It is the second half of INV-26. The first half is aes_public_key,
// whose every key comes from a salt the RFC prints or a connection ID
// that travels in the clear, so a table lookup indexed by one leaks
// nothing. A traffic key is not public, and naming it aes_public_key
// would make that invariant's own name a lie. So it gets a type whose
// name says what it holds, and the compiler decides which call sites may
// hold which key rather than a reviewer.
//
// Two sources include this header, and tools/quic-footprint.py fails on a
// third:
//
//   record.c    builds one from the key schedule's traffic secret
//   quic_gcm.c  reads the round keys out of one to run the AEAD
//
// A build that never defines CH_SUITE_AES_GCM compiles none of it, and
// ct.h refuses that define unless the build has hardware AES and asserts
// its timing. That refusal is what keeps a secret key away from the
// AES=soft S-box, which is indexed with the key.
#ifndef CH_AES_TRAFFIC_KEY_H
#define CH_AES_TRAFFIC_KEY_H
#ifdef CH_SUITE_AES_GCM

#include <stdint.h>

#include "quic_aes.h"
#include "quic_aes_key.h"

// One direction of one TLS epoch whose AEAD is AEAD_AES_128_GCM. It
// holds the round keys and nothing else: a TLS record's nonce is built
// from the write IV and the sequence number by record.c, which keeps the
// IV in rec_dir beside this, and a record carries no header protection.
struct aes_traffic_key {
    aes_key_schedule key;
};

#endif // CH_SUITE_AES_GCM
#endif
