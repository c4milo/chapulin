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
// Five sources include this header, and tools/quic-footprint.py fails on
// a sixth:
//
//   aes.c          writes aes_traffic_key_init and the block entry, and in
//                  a host object stores and loads a schedule's bytes
//   gcm.c          reads the round keys out of one to run the AEAD
//   record.c       builds one per record from rec_dir's key bytes, or in
//                  a host object from rec_dir's stored schedule
//   quic_packet.c  builds one per QUIC packet from quic_keys' key bytes,
//                  and one per header protection mask from quic_hp_key's,
//                  or in a host object from their stored schedules
//   srv_ticket.c   builds one per ticket from a PROFILE=cnsa2 server's
//                  ticket_key (docs/decisions.md 162)
//
// A stored schedule is bytes, SUITE_AES_SCHEDULE_LEN of them (suite.h),
// so this body stays out of the headers that hold one, and quic_keys.c
// stores one through aes_traffic_key_store or gcm_traffic_key_store
// without it (docs/decisions.md 160 and 234).
//
// A build that never defines CH_SUITE_AES_GCM compiles none of it, and
// ct.h refuses that define unless the build runs AES on the AES
// instructions or on an AES peripheral and asserts that one's timing.
// That refusal is what keeps a secret key away from the AES=soft S-box,
// which is indexed with the key.
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
// the round keys and their round count: a TLS record's nonce is built
// from the write IV and the sequence number by record.c, which keeps the
// IV in rec_dir, and a record carries no header protection.
//
// In a host object it also holds ghash_powers, which points at the powers
// of the key's hash subkey that the key's owner stores beside the key,
// SUITE_GHASH_POWERS_LEN bytes (suite.h), or is NULL where the owner
// stores none. aes_traffic_key_load writes the pointer,
// aes_traffic_key_init writes NULL, and gcm.c hands it to the AEAD, which
// reads the powers in place. So a frame that holds this struct holds no
// copy of a power, and the wipe of this struct leaves the owner's powers
// (docs/decisions.md 234). The pointer is an address in the session, and
// not secret.
struct aes_traffic_key {
    aes_key_schedule key;
#ifdef CH_CPU_RUNTIME
    const uint8_t *ghash_powers;
#endif
};

#endif // CH_SUITE_AES_GCM
#endif
