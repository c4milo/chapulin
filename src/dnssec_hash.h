// The struct a ch_dnssec_hash's storage holds (dnssec.h, docs/decisions.md 185), and the
// conversion from the storage.
#ifndef CH_DNSSEC_HASH_H
#define CH_DNSSEC_HASH_H

#include <stdint.h>

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

// The hash of an RRSIG's signed data (RFC 4034 section 3.1.8.1), under
// the algorithm the RRSIG names: SHA-256 for algorithms 8 and 13, SHA-384
// for 14, and SHA-512 for 10 and 15. ch_dnssec_digest_init starts it as a
// plain SHA-1, SHA-256 or SHA-384 instead. For 15 it is RFC 8032's hash: SHA-512 of R,
// the key A, and then the signed data.
typedef struct {
    uint8_t algorithm;
    union {
        sha1 sha1_state;
        sha256 sha256_state;
        sha512 sha512_state;
    } state;
} ch_dnssec_hash_priv;

typedef struct ch_dnssec_hash ch_dnssec_hash;

static inline ch_dnssec_hash_priv *dnssec_hash_priv(ch_dnssec_hash *h) {
    return (ch_dnssec_hash_priv *)(void *)h;
}
static inline ch_dnssec_hash *dnssec_hash_public(ch_dnssec_hash_priv *h) {
    return (ch_dnssec_hash *)(void *)h;
}

#endif
