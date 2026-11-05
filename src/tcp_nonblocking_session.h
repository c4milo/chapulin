// The struct a ch_tcp's storage holds (tcp_nonblocking.h, docs/decisions.md 185), and the
// conversions between the two.
#ifndef CH_TCP_NONBLOCKING_SESSION_H
#define CH_TCP_NONBLOCKING_SESSION_H
#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_record.h"
#include "session.h"

// One handshake in progress. It holds everything that survives a return,
// because the driver returns to its caller between messages: the ch_tls a
// blocking build keeps alone, the handshake_state that build holds on
// ch_handshake's stack frame, and the driver's own three fields.
//
// It is not copyable: hs.t points at t, and every entry rewrites that
// pointer to its own &r->t, so a copy cannot leave a dangling pointer
// inside a step.
typedef struct ch_tcp_priv {
    ch_tls_priv t;
    handshake_state hs;
    uint8_t step; // TCP_NONBLOCKING_STEP_*, tcp_nonblocking_step.h
    // Bytes of one finished record staged in t.tx and not yet collected,
    // and how many of them ch_tcp_out has already handed over: a
    // handshake message, or the alert record of a failure. A partial
    // collection is what lets a caller with a small buffer make progress.
    size_t tx_len;
    size_t tx_off;
} ch_tcp_priv;

typedef struct ch_tcp ch_tcp;

// The bodies of the public calls on a ch_tcp, each on the ch_tcp_priv in the caller's storage.
// tcp_entry.c defines the public calls, which convert the pointer once and call these;
// tcp_nonblocking.h and srv_tcp_nonblocking.h state each contract.
int tcp_init(ch_tcp_priv *r, const ch_cfg *cfg);
int tcp_in(ch_tcp_priv *r, uint8_t *p, size_t n, size_t *consumed);
int tcp_out(ch_tcp_priv *r, uint8_t *out, size_t cap, size_t *out_len);
void tcp_close(ch_tcp_priv *r);
int srv_tcp_init(ch_tcp_priv *r, const ch_cfg *cfg);
int srv_tcp_in(ch_tcp_priv *r, uint8_t *p, size_t n, size_t *consumed);

static inline ch_tcp_priv *tcp_priv(ch_tcp *r) {
    return (ch_tcp_priv *)(void *)r;
}
static inline const ch_tcp_priv *tcp_priv_const(const ch_tcp *r) {
    return (const ch_tcp_priv *)(const void *)r;
}
static inline ch_tcp *tcp_public(ch_tcp_priv *r) {
    return (ch_tcp *)(void *)r;
}
static inline const ch_tcp *tcp_public_const(const ch_tcp_priv *r) {
    return (const ch_tcp *)(const void *)r;
}

#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
