// Stub only. quic_step.h states the contract; no line below implements it.
// quic_aes.c states what the CH_QUIC_STUB marker means and which two checks read it.
//
// The six step functions quic_step.h describes are static, so none of them exists yet
// either: a static stub nothing calls would not compile. hsq_advance is the one entry
// this file declares, and it refuses every step.
#include "quic_step.h"

#ifdef CH_TRANSPORT_QUIC

// The two headers whose CH_TRANSPORT_QUIC arms no other translation unit reads. quic.h
// pulls in cfg.h, session.h and handshake_record.h, so those three arms are compiled
// already; handshake_auth.h and handshake_post.h are reached from nowhere, because the
// four QUIC_PENDING sources stay out of this object. Without these two lines their 72
// declarations sit behind a define no compiler, no clang-tidy pass and no cppcheck run
// ever reads. This file is where they belong on their own terms: hsq_advance is the step
// machine that calls hsa_read_certificate, hsa_read_certificate_verify and
// hspost_take_ticket.
#include "handshake_auth.h"
#include "handshake_post.h"

int hsq_advance(ch_quic *q) {
    // CH_QUIC_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)q;
    return CH_EINVAL;
}

#endif // CH_TRANSPORT_QUIC
