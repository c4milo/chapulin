// The public calls of TRANSPORT=tcp-nonblocking that take a ch_tcp (docs/decisions.md 185).
// Each converts the caller's storage to the ch_tcp_priv in it, once, and reads a field or calls
// the body that tcp_nonblocking_session.h declares. tcp_nonblocking.h and srv_tcp_nonblocking.h
// state each contract.
#include "tcp_nonblocking_session.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include "session_convert.h"
#include "srv_tcp_nonblocking.h"
#include "tcp_nonblocking.h"

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
int ch_tcp_init(ch_tcp *r, const ch_cfg *cfg) {
    return tcp_init(tcp_priv(r), cfg);
}

int ch_tcp_in(ch_tcp *r, uint8_t *p, size_t n, size_t *consumed) {
    return tcp_in(tcp_priv(r), p, n, consumed);
}

int ch_tcp_out(ch_tcp *r, uint8_t *out, size_t cap, size_t *out_len) {
    return tcp_out(tcp_priv(r), out, cap, out_len);
}
#endif

#ifdef CH_ROLE_SERVER
int ch_srv_tcp_init(ch_tcp *r, const ch_cfg *cfg) {
    return srv_tcp_init(tcp_priv(r), cfg);
}

int ch_srv_tcp_in(ch_tcp *r, uint8_t *p, size_t n, size_t *consumed) {
    return srv_tcp_in(tcp_priv(r), p, n, consumed);
}
#endif

uint8_t ch_tcp_state(const ch_tcp *r) {
    return tcp_priv_const(r)->t.state;
}

ch_tls *ch_tcp_tls(ch_tcp *r) {
    return tls_public(&tcp_priv(r)->t);
}

void ch_tcp_close(ch_tcp *r) {
    tcp_close(tcp_priv(r));
}

#endif // CH_TRANSPORT_TCP_NONBLOCKING
