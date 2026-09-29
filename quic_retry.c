// The Retry Integrity Tag of RFC 9001 §5.8. quic_retry.h states the
// contract; this file implements it and nothing else.
//
// §5.8 fixes every input of a version, so this file chooses nothing but
// the version: the key comes from aes_public_key_retry, the nonce is the
// version's constant below, the plaintext is empty, and the associated
// data is the pseudo-packet the caller built. One gcm_seal is the whole
// of minting, and one ct_memeq after it is the whole of checking.
//
// Nothing here is secret. Each version's key is printed in its RFC
// (rfc9001.txt:1499-1500, rfc9369.txt:176-188), the nonce is printed
// beside it, and the pseudo-packet holds bytes that travelled in the
// clear: the Retry packet the server sent, and the connection ID the
// client's own Initial packet carried. That is why INV-26 in
// docs/invariants.md admits the table-driven AES under this call, and why
// no line below wipes anything.
#include "quic_retry.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "aes_public_key.h"
#include "ct.h"
#include "quic_version.h"

// RFC 9001 §5.8's printed nonce for QUIC version 1, 0x461599d35d632bf2239825bb
// (rfc9001.txt:1501-1502). It sits here rather than in the key, because
// aes_public_key_retry leaves the iv field of a Retry key zero: a Retry
// packet carries no packet number, so there is no §5.3 nonce to build.
static const uint8_t RETRY_NONCE_V1[AES_IV] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                               0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

// RFC 9369 §3.3.3's printed nonce for QUIC version 2, 0xd86969bc2d7c6d9990efb04a
// (rfc9369.txt:176-188).
static const uint8_t RETRY_NONCE_V2[AES_IV] = {0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
                                               0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};

// Each version's nonce, at the index quic_version_index gives it: version 1's
// first, version 2's second.
static const uint8_t *const RETRY_NONCES[QUIC_VERSION_COUNT] = {RETRY_NONCE_V1, RETRY_NONCE_V2};

// The nonce version's Retry integrity tag is sealed under. quic_retry_tag
// refuses a version this build does not derive before it asks, so version is
// version 1 or version 2 here.
static const uint8_t *retry_nonce(uint32_t version) {
    return RETRY_NONCES[quic_version_index(version)];
}

int quic_retry_tag(uint32_t version, const uint8_t *pseudo, size_t n, uint8_t tag[GCM_TAG]) {
    if (!quic_version_derived(version)) {
        return CH_EINVAL;
    }
    aes_public_key k;
    aes_public_key_retry(&k, version);
    // The empty plaintext of §5.8, and the empty ciphertext it seals to.
    // gcm.h states both pointers for n readable and n writable
    // bytes and says nothing about a null one, so each gets a real
    // buffer. gcm_seal allows pt == ct, which is the shape here.
    uint8_t empty[1] = {0};
    gcm_seal(&k, retry_nonce(version), pseudo, n, empty, 0, empty, tag);
    return CH_OK;
}

uint8_t quic_retry_ok(uint32_t version, const uint8_t *pseudo, size_t n,
                      const uint8_t tag[GCM_TAG]) {
    // RFC 9001 §5.8 fixes every input for both endpoints, so checking a
    // tag is minting one over the caller's own pseudo-packet and
    // comparing, rather than a second copy of §5.8 written for the
    // receiving side. A version the mint refuses matches no tag.
    uint8_t want[GCM_TAG];
    if (quic_retry_tag(version, pseudo, n, want) != CH_OK) {
        return 0;
    }
    return (uint8_t)ct_memeq(want, tag, GCM_TAG);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
