// Stub only. quic_keys.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
#include "quic_keys.h"

#ifdef CH_TRANSPORT_QUIC

void quic_keys_init(quic_keys *k, const uint8_t secret[SHA256_LEN]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)secret;
}

void quic_hp_key_init(quic_hp_key *h, const uint8_t secret[SHA256_LEN]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)secret;
}

void quic_keys_update(uint8_t secret[SHA256_LEN], quic_keys *k) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)secret;
    (void)k;
}

#endif // CH_TRANSPORT_QUIC
