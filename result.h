// A short English text for each result code, for a log line. cfg.h defines the codes and
// includes this header after them, and quic_cfg.h the two that a QUIC build adds. Each
// call's header states what a code means for that call; the text here is the meaning that
// every call shares.
//
// It is static inline, so no object exports it and an image of two transports holds no
// second definition to clash with.
#ifndef CH_RESULT_H
#define CH_RESULT_H

// The text for rc: a constant string, never NULL. A code no header of this build defines
// answers "unknown result code".
static inline const char *ch_result_text(int rc) {
    switch (rc) {
    case CH_OK:
        return "success";
    case CH_EIO:
        return "the transport failed or closed";
    case CH_EPROTO:
        return "the peer broke the protocol, or the session cannot take the call";
    case CH_EAUTH:
        return "the peer did not authenticate";
    case CH_ECAP:
        return "a buffer is too small for the bytes it must hold";
    case CH_ECLOSED:
        return "the peer closed the connection";
    case CH_EINVAL:
        return "the configuration or the call was refused, and nothing was sent";
    case CH_RECORD_AGAIN:
        return "no whole record has arrived yet";
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    case CH_QUIC_DISCARD:
        return "the packet did not open; drop it";
    case CH_QUIC_AEAD_LIMIT:
        return "too many packets failed to open; close the connection";
#endif
    default:
        return "unknown result code";
    }
}

#endif
