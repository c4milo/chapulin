// Stub only. quic_initial.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
#include "quic_initial.h"

#ifdef CH_TRANSPORT_QUIC

int quic_initial_seal(const uint8_t *dcid, size_t dcid_len, uint64_t pn, size_t pn_len,
                      const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)dcid;
    (void)dcid_len;
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

int quic_initial_open(const uint8_t *dcid, size_t dcid_len, uint8_t *pkt, size_t pkt_len,
                      size_t pn_off, uint64_t largest_pn, uint64_t *pn, size_t *pt_len) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)dcid;
    (void)dcid_len;
    (void)pkt;
    (void)pkt_len;
    (void)pn_off;
    (void)largest_pn;
    (void)pn;
    (void)pt_len;
    return CH_QUIC_DISCARD;
}

#endif // CH_TRANSPORT_QUIC
