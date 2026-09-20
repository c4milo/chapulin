// What an aes_public_key is made of. quic_aes.h declares the type
// incomplete and declares every entry that takes it; this header is the
// one place the struct has a body, so it is the one place a file can
// declare a key, size a key or write a field of a key.
//
// The split is INV-26's first check, and the compiler runs it. A key
// that only the two constructors in quic_aes.c can fill is a key no
// other line can fill with a traffic secret, and that is the whole
// reason this tree admits a table-driven AES at all (docs/invariants.md
// INV-26, docs/decisions.md entry 6).
//
// Three sources include this header, and `make lint-quic-surface` fails
// on a fourth:
//
//   quic_aes.c      writes the two constructors and the cipher
//   quic_initial.c  builds one Initial key per packet on its stack
//   quic_retry.c    builds the §5.8 Retry key on its stack
//
// Nothing stores a key between calls. ch_quic holds the Destination
// Connection ID the derivation reads, in initial_dcid, and derives from
// it at each use, so there is no long-lived key object anywhere in the
// tree. The tests and the proof harnesses include this header too; they
// sit outside the library and the Semgrep rule excludes their
// directories for the same reason.
//
// Only a TRANSPORT=quic build compiles it.
#ifndef CH_QUIC_AES_KEY_H
#define CH_QUIC_AES_KEY_H
#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)

#include <stdint.h>

#include "quic_aes.h"

// One direction of one QUIC encryption level whose AEAD is
// AEAD_AES_128_GCM. quic_aes.h states the three fields, what writes
// them and why every key they ever hold is public.
// One AES-128 key expanded into its round keys (FIPS 197 §5.2, Key
// Expansion). Bytes rather than words, so no step of the schedule or the
// cipher assumes host endianness.
typedef struct aes_key_schedule {
    uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK];
} aes_key_schedule;

struct aes_public_key {
    aes_key_schedule key;
    uint8_t iv[AES_IV];
    aes_key_schedule hp;
};

#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
#endif
