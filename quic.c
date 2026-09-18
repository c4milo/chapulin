// Stub only. quic.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
//
// These fifteen entries are the mode's public API, so they are the ones a caller can
// reach. Each refuses: no call reports CH_OK, no call writes an out-parameter, and the
// three reporting calls answer a dead session. A stub that could answer CH_OK would hand
// a caller an unprotected packet the day it linked against this object, so the refusal is
// the point and bin/quic_stub_test holds it.
#include "quic.h"

#ifdef CH_TRANSPORT_QUIC

#include "handshake_message.h"

int ch_quic_init(ch_quic *q, const ch_cfg *cfg) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)cfg;
    return CH_EINVAL;
}

int ch_quic_initial_keys(ch_quic *q, const uint8_t *dcid, size_t dcid_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)dcid;
    (void)dcid_len;
    return CH_EINVAL;
}

int ch_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)level;
    (void)p;
    (void)n;
    return CH_EINVAL;
}

int ch_quic_crypto_out(ch_quic *q, uint8_t level, uint8_t *out, size_t cap, size_t *out_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)level;
    (void)out;
    (void)cap;
    (void)out_len;
    return CH_EINVAL;
}

int ch_quic_seal(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                 size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                 size_t *out_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
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

int ch_quic_open(ch_quic *q, uint8_t level, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                 uint64_t largest_pn, uint64_t current_phase_lowest_pn, uint8_t *key_set,
                 uint64_t *pn, size_t *pt_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)level;
    (void)pkt;
    (void)pkt_len;
    (void)pn_off;
    (void)largest_pn;
    (void)current_phase_lowest_pn;
    (void)key_set;
    (void)pn;
    (void)pt_len;
    return CH_EINVAL;
}

uint8_t ch_quic_retry_ok(const ch_quic *q, const uint8_t *pseudo, size_t n,
                         const uint8_t tag[GCM_TAG]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)pseudo;
    (void)n;
    (void)tag;
    // 0 is "the tag did not validate", which RFC 9000 §17.2.5.2 makes the caller discard
    // the Retry packet on. It is not a ch_err.
    return 0;
}

int ch_quic_key_update(ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    return CH_EINVAL;
}

uint8_t ch_quic_key_phase(const ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    // 0 is what the header documents before the 1-RTT keys exist, and no stub installs
    // them.
    return 0;
}

void ch_quic_drop_previous_keys(ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
}

int ch_quic_discard(ch_quic *q, uint8_t level) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    (void)level;
    return CH_EINVAL;
}

uint8_t ch_quic_state(const ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    // CH_ST_FAILED, because no entry here completes a handshake and a caller that read
    // CH_ST_START would wait for one. It is the state that says no call will succeed.
    return CH_ST_FAILED;
}

uint8_t ch_quic_alert(const ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    return ALERT_INTERNAL_ERROR;
}

uint64_t ch_quic_error_code(const ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    // The rule quic.h states, read against what the two calls above answer: the state is
    // CH_ST_FAILED and no step wrote an error code, so the answer is 0x0100 plus the
    // alert (RFC 9001 §4.8).
    return 0x0100 + (uint64_t)ALERT_INTERNAL_ERROR;
}

void ch_quic_close(ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
}

#endif // CH_TRANSPORT_QUIC
