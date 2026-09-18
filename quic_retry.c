// Stub only. quic_retry.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
#include "quic_retry.h"

#ifdef CH_TRANSPORT_QUIC

uint8_t quic_retry_ok(const uint8_t *pseudo, size_t n, const uint8_t tag[GCM_TAG]) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)pseudo;
    (void)n;
    (void)tag;
    // 0 is "the tag did not validate", which RFC 9000 §17.2.5.2 makes the caller discard
    // the Retry packet on. It is not a ch_err.
    return 0;
}

#endif // CH_TRANSPORT_QUIC
