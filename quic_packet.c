// Stub only. quic_packet.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
#include "quic_packet.h"

#ifdef CH_TRANSPORT_QUIC

void quic_hp_mask(const quic_hp_key *h, const uint8_t sample[QUIC_HP_SAMPLE_LEN],
                  uint8_t mask[QUIC_HP_MASK_LEN]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)sample;
    (void)mask;
}

void quic_header_protect(uint8_t *pkt, size_t pn_off, size_t pn_len, uint8_t level,
                         const uint8_t mask[QUIC_HP_MASK_LEN]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)pkt;
    (void)pn_off;
    (void)pn_len;
    (void)level;
    (void)mask;
}

size_t quic_header_unprotect(uint8_t *pkt, size_t pn_off, uint8_t level,
                             const uint8_t mask[QUIC_HP_MASK_LEN]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)pkt;
    (void)pn_off;
    (void)level;
    (void)mask;
    // 0 is outside the 1 to QUIC_PN_MAX_LEN range the header documents, so a caller that
    // used it would read no packet number byte.
    return 0;
}

uint64_t quic_pn_read(const uint8_t *pkt, size_t pn_off, size_t pn_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)pkt;
    (void)pn_off;
    (void)pn_len;
    return 0;
}

uint64_t quic_pn_decode(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)largest_pn;
    (void)truncated_pn;
    (void)pn_len;
    return 0;
}

void quic_nonce(const uint8_t iv[AEAD_NONCE], uint64_t pn, uint8_t nonce[AEAD_NONCE]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)iv;
    (void)pn;
    (void)nonce;
}

uint8_t quic_key_set_select(uint8_t key_phase, uint8_t packet_key_phase, uint64_t pn,
                            uint64_t current_phase_lowest_pn) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)key_phase;
    (void)packet_key_phase;
    (void)pn;
    (void)current_phase_lowest_pn;
    // CH_QUIC_KEY_PREVIOUS is the set ch_quic_drop_previous_keys wipes and the one that
    // holds zero bytes until the first key update, so a packet opened against it fails
    // its tag and the caller discards it.
    return CH_QUIC_KEY_PREVIOUS;
}

void quic_keys_select(const quic_keys sets[CH_QUIC_KEY_SETS], uint8_t selected, quic_keys *out) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)sets;
    (void)selected;
    (void)out;
}

int quic_packet_seal(const quic_keys *k, const quic_hp_key *h, uint8_t level, uint64_t pn,
                     size_t pn_len, const uint8_t *hdr, size_t hdr_len, const uint8_t *pt,
                     size_t pt_len, uint8_t *out, size_t cap, size_t *out_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)h;
    (void)level;
    (void)pn;
    (void)pn_len;
    (void)hdr;
    (void)hdr_len;
    (void)pt;
    (void)pt_len;
    (void)out;
    (void)cap;
    (void)out_len;
    return CH_EINVAL;
}

int quic_packet_open_handshake(const quic_keys *k, const quic_hp_key *h, uint8_t *pkt,
                               size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                               size_t *pt_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)k;
    (void)h;
    (void)pkt;
    (void)pkt_len;
    (void)pn_off;
    (void)largest_pn;
    (void)pn;
    (void)pt_len;
    return CH_QUIC_DISCARD;
}

int quic_packet_open_application(const quic_keys sets[CH_QUIC_KEY_SETS], const quic_hp_key *h,
                                 uint8_t key_phase, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                                 uint64_t largest_pn, uint64_t current_phase_lowest_pn,
                                 uint8_t *key_set, uint64_t *pn, size_t *pt_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)sets;
    (void)h;
    (void)key_phase;
    (void)pkt;
    (void)pkt_len;
    (void)pn_off;
    (void)largest_pn;
    (void)current_phase_lowest_pn;
    (void)key_set;
    (void)pn;
    (void)pt_len;
    return CH_QUIC_DISCARD;
}

int quic_integrity_limit_exceeded(uint64_t open_failures) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)open_failures;
    // 1 is "the limit is past", the answer that stops the session. The header documents
    // 1 and 0 here rather than a ch_err.
    return 1;
}

int quic_confidentiality_limit_reached(uint64_t sealed) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)sealed;
    // 1 is "sealing one more packet reaches the limit", the answer that refuses the seal.
    return 1;
}

#endif // CH_TRANSPORT_QUIC
