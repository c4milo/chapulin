// Stub only. quic_gcm.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
#include "quic_gcm.h"

#ifdef CH_TRANSPORT_QUIC

void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)pt;
    (void)n;
    (void)ct;
    (void)tag;
}

int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ct;
    (void)n;
    (void)tag;
    (void)pt;
    // 0 is "the tag did not match" here, not a ch_err: the header states the two values
    // this call answers with.
    return 0;
}

void gcm_ghash(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
               size_t n, uint8_t out[AES_BLOCK]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)aad;
    (void)aad_len;
    (void)ct;
    (void)n;
    (void)out;
}

#endif // CH_TRANSPORT_QUIC
