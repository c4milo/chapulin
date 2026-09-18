// Stub only. quic_aes.h states the contract; no line below implements it.
//
// Every function here carries one CH_QUIC_STUB line, returns a value the header
// documents as a refusal, and writes nothing through its out-parameters. A TRANSPORT=quic
// object therefore links and does nothing, which is what lets the Makefile's TRANSPORT
// axis and every gate that reads it run before the code exists. `make quic-footprint`
// counts the marker and reports stubbed against implemented, and
// bin/quic_stub_test calls each entry and requires the refusal.
// docs/quic.md, "The stubs and the marker", states both rules.
#include "quic_aes.h"

#ifdef CH_TRANSPORT_QUIC

int aes_public_key_initial(aes_public_key *k, const uint8_t *dcid, size_t dcid_len,
                           uint8_t direction) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)dcid;
    (void)dcid_len;
    (void)direction;
    return CH_EINVAL;
}

void aes_public_key_retry(aes_public_key *k) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
}

void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)in;
    (void)out;
}

void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)sample;
    (void)out;
}

#endif // CH_TRANSPORT_QUIC
