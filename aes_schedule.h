// What an aes_key_schedule is made of: one AES key expanded into its
// round keys. quic_aes.h declares the type incomplete; this header is the
// one place it has a body.
//
// It is its own header so that the two key types can share it without
// sharing each other's bodies. quic_aes_key.h builds aes_public_key on it
// and aes_traffic_key.h builds aes_traffic_key on it, and each includes
// this file rather than the other. A file admitted to the traffic key
// therefore cannot declare a public key, and a file admitted to the
// public key cannot declare a traffic key. Before this header existed,
// aes_traffic_key.h included quic_aes_key.h for the schedule, so
// record.c could declare an aes_public_key it had no reason to hold.
//
// Two headers include it, and tools/quic-footprint.py fails on a root
// source that includes it directly or spells the body itself.
#ifndef CH_AES_SCHEDULE_H
#define CH_AES_SCHEDULE_H
#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)

#include <stdint.h>

#include "quic_aes.h"

// FIPS 197 §5.2, Key Expansion. Bytes rather than words, so no step of the
// schedule or the cipher assumes host endianness.
//
// A build without AES-256 holds AES-128's eleven round keys and nothing
// else. A build with it (CH_AES_256, quic_aes.h) holds room for fifteen
// and records which cipher the schedule drives, AES_128_ROUNDS or
// AES_256_ROUNDS, because one aes_encrypt_schedule serves both.
struct aes_key_schedule {
    uint8_t round_keys[AES_SCHEDULE_ROUND_KEYS * AES_BLOCK];
#ifdef CH_AES_256
    uint8_t rounds;
#endif
};

#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
#endif
