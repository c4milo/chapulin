// What an aes_key_schedule is made of: one AES key expanded into its
// round keys. aes.h declares the type incomplete; this header is the
// one place it has a body.
//
// It is its own header so that the two key types can share it without
// sharing each other's bodies. aes_public_key.h builds aes_public_key on it
// and aes_traffic_key.h builds aes_traffic_key on it, and each includes
// this file rather than the other. A file admitted to the traffic key
// therefore cannot declare a public key, and a file admitted to the
// public key cannot declare a traffic key. Before this header existed,
// aes_traffic_key.h included aes_public_key.h for the schedule, so
// record.c could declare an aes_public_key it had no reason to hold.
//
// Two headers include it, and tools/quic-footprint.py fails on a root
// source that includes it directly or spells the body itself.
#ifndef CH_AES_SCHEDULE_H
#define CH_AES_SCHEDULE_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stdint.h>

#include "aes.h"

// FIPS 197 §5.2, Key Expansion. Bytes rather than words, so no step of the
// schedule or the cipher assumes host endianness.
//
// A build without AES-256 holds AES-128's eleven round keys and nothing
// else. A build with it (CH_AES_256, aes.h) holds room for fifteen
// and records which cipher the schedule drives, AES_128_ROUNDS or
// AES_256_ROUNDS, because one aes_encrypt_schedule serves both.
//
// A QUIC host object (CH_AES_TWO_CIPHERS, aes.h) also records which of
// its two ciphers expanded the round keys and runs every block under
// them: AES_ON_INSTRUCTIONS for the instructions, and any other value for
// the table. aes_traffic_key_init writes the first always, the Retry
// constructor AES_ON_TABLE, and the Initial constructor the one the
// session's CH_CPU_CONSTANT_TIME_AES bit names, and no other line writes
// it.
//
// A host object (CH_CPU_RUNTIME, cpu_cfg.h) also records cpu: the low byte
// of the description of the CPU that the schedule's session gave in
// ch_cfg.cpu, which holds every bit an object defines (aes.c asserts it).
// gcm.c reads it to pick gcm_vaes.c's 256-bit kernels for the schedule's
// whole blocks on x86-64, and nothing else reads it. aes_traffic_key_init
// and the Retry constructor write 0, which names no kernel,
// aes_traffic_key_cpu and the Initial constructor write the session's
// value, and no other line writes it. One byte keeps the schedule a run
// of bytes with no padding, as its other fields do.
#ifdef CH_AES_TWO_CIPHERS
#define AES_ON_INSTRUCTIONS 1
#define AES_ON_TABLE 2
#endif
struct aes_key_schedule {
    uint8_t round_keys[AES_SCHEDULE_ROUND_KEYS * AES_BLOCK];
#ifdef CH_AES_256
    uint8_t rounds;
#endif
#ifdef CH_AES_TWO_CIPHERS
    uint8_t instructions;
#endif
#ifdef CH_CPU_RUNTIME
    uint8_t cpu;
#endif
};

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
