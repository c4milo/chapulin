// The Retry Integrity Tag of RFC 9001 §5.8. quic_retry.h states the
// contract; this file implements it and nothing else.
//
// §5.8 fixes every input, so this file chooses nothing: the key comes
// from aes_public_key_retry, the nonce is the constant below, the
// plaintext is empty, and the associated data is the pseudo-packet the
// caller built. One gcm_seal is the whole of minting, and one ct_memeq
// after it is the whole of checking.
//
// Nothing here is secret. The key is printed in the RFC
// (rfc9001.txt:1499-1500), the nonce is printed beside it, and the
// pseudo-packet holds bytes that travelled in the clear: the Retry
// packet the server sent, and the connection ID the client's own
// Initial packet carried. That is why INV-26 in docs/invariants.md
// admits the table-driven AES under this call, and why no line below
// wipes anything.
#include "quic_retry.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "ct.h"
#include "quic_aes_key.h"

// RFC 9001 §5.8's printed nonce, 0x461599d35d632bf2239825bb
// (rfc9001.txt:1501-1502). It sits here rather than in the key, because
// aes_public_key_retry leaves the iv field of a Retry key zero: a Retry
// packet carries no packet number, so there is no §5.3 nonce to build.
static const uint8_t RETRY_NONCE[AES_IV] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                            0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

void quic_retry_tag(const uint8_t *pseudo, size_t n, uint8_t tag[GCM_TAG]) {
    aes_public_key k;
    aes_public_key_retry(&k);
    // The empty plaintext of §5.8, and the empty ciphertext it seals to.
    // quic_gcm.h states both pointers for n readable and n writable
    // bytes and says nothing about a null one, so each gets a real
    // buffer. gcm_seal allows pt == ct, which is the shape here.
    uint8_t empty[1] = {0};
    gcm_seal(&k, RETRY_NONCE, pseudo, n, empty, 0, empty, tag);
}

uint8_t quic_retry_ok(const uint8_t *pseudo, size_t n, const uint8_t tag[GCM_TAG]) {
    // RFC 9001 §5.8 fixes every input for both endpoints, so checking a
    // tag is minting one over the caller's own pseudo-packet and
    // comparing, rather than a second copy of §5.8 written for the
    // receiving side.
    uint8_t want[GCM_TAG];
    quic_retry_tag(pseudo, n, want);
    return (uint8_t)ct_memeq(want, tag, GCM_TAG);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
