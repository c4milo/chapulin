// The result codes, and a short English text for each, for a log line. cfg.h includes this
// header, and so does ticket.h, whose ch_ticket_save returns a code. Each call's header states
// what a code means for that call; the text here is the meaning that every call shares.
// ch_result_text is static inline, so no object exports it and an image of two transports
// holds no second definition to clash with.
#ifndef CH_RESULT_H
#define CH_RESULT_H

// CH_MUST_USE marks each public call that returns one of these codes, or a verdict. The code says
// whether the caller can go on, and a caller that drops it can use bytes the call did not write,
// or go on after a check that failed. gcc and clang then warn where a caller drops it, and gcc
// warns through a (void) cast too. Another compiler gets no mark. The mark sits between the return
// type and the name, the one place where Semgrep parses it before a definition and a declaration
// alike (docs/decisions.md 143).
#if defined(__GNUC__) || defined(__clang__)
#define CH_MUST_USE __attribute__((warn_unused_result))
#else
#define CH_MUST_USE
#endif

// The result codes. Each call's header says which it returns and what each
// leaves; INV-13 is the rule across calls. CH_EINVAL is a refusal on entry:
// an init call leaves its session failed until the next init, and every
// other call leaves the session as it was. A call on a session that cannot
// take it, bytes for one that failed or closed, or ch_read and ch_write
// before the handshake completes, answers CH_EPROTO, or CH_EINVAL where its
// header says so, and changes nothing. Every other code leaves the session
// dead, but those a header names as leaving it live: CH_ECAP for a caller's
// own short buffer, CH_RECORD_AGAIN and quic_cfg.h's CH_QUIC_DISCARD.
#define CH_OK 0
#define CH_EIO (-1)     // transport failed or closed under us, or a server's sink refused
#define CH_EPROTO (-2)  // peer broke the protocol, or the session cannot take the call
#define CH_EAUTH (-3)   // authentication failed; session dead
#define CH_ECAP (-4)    // a buffer too small: the caller's own, or one a message must fit
#define CH_ECLOSED (-5) // the peer's close_notify; ch_read returns 0 for it, no call returns this
#define CH_EINVAL (-6)  // configuration or call refused on entry; nothing was sent
// TRANSPORT=tcp-nonblocking's ch_read found no record yet; the session stays
// live (tcp_nonblocking.h, INV-13).
#define CH_RECORD_AGAIN (-9)
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// The code a TCP build adds, which ch_read alone returns. The peer sent one KeyUpdate more than
// CH_KEY_UPDATE_RUN_MAX (session.h) in a row, and the session is dead (docs/decisions.md 138).
#define CH_KEY_UPDATE_LIMIT (-10)
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// The two codes a TRANSPORT=quic-nonblocking build adds, which ch_quic_open alone returns.
// quic_cfg.h states what each means.
#define CH_QUIC_DISCARD (-7)
#define CH_QUIC_AEAD_LIMIT (-8)
#endif

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
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    case CH_KEY_UPDATE_LIMIT:
        return "the peer sent too many KeyUpdates without application data";
#endif
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
