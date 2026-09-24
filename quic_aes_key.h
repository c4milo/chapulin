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
// Four sources include this header, and `make lint-quic-surface` fails
// on a fifth:
//
//   quic_aes.c      writes the two constructors and the cipher
//   quic_initial.c  builds one Initial key per packet on its stack
//   quic_retry.c    builds the §5.8 Retry key on its stack
//   quic_gcm.c      reads the round keys out of one to run the AEAD
//
// Nothing stores a key between calls. ch_quic holds the Destination
// Connection ID the derivation reads, in initial_dcid, and derives from
// it at each use, so there is no long-lived key object anywhere in the
// tree. The tests and the proof harnesses include this header too; they
// sit outside the library and the Semgrep rule excludes their
// directories for the same reason.
//
// aes_traffic_key.h, the other key's body, does not include this header,
// and this header does not include that one: aes_schedule.h holds the
// round keys both are built on, so a file admitted to one key sees no
// body of the other.
#ifndef CH_QUIC_AES_KEY_H
#define CH_QUIC_AES_KEY_H
#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)

#include <stdint.h>

#include "aes_schedule.h"
#include "quic_aes.h"

// One direction of one QUIC encryption level whose AEAD is
// AEAD_AES_128_GCM. quic_aes.h states the three fields, what writes
// them and why every key they ever hold is public.
struct aes_public_key {
    aes_key_schedule key;
    uint8_t iv[AES_IV];
    aes_key_schedule hp;
};

#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
#endif
