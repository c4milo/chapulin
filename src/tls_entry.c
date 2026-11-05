// The public calls of the record transports that take a ch_tls (docs/decisions.md 185), but
// srv.c's ch_srv_accept. Each
// converts the caller's storage to the ch_tls_priv in it, once, and calls the body that
// tls_calls.h declares. The public headers state each contract.
#include "tls_calls.h"

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING

#include "alert.h"
#include "session_convert.h"
#include "tls.h"

#if (!defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)) && !defined(CH_TRANSPORT_TCP_NONBLOCKING)
int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    return tls_connect(tls_priv(t), cfg);
}
#endif

int ch_read(ch_tls *t, uint8_t *p, size_t n) {
    return tls_read(tls_priv(t), p, n);
}

int ch_write(ch_tls *t, const uint8_t *p, size_t n) {
    return tls_write(tls_priv(t), p, n);
}

int ch_write_parts(ch_tls *t, const ch_part *parts, size_t part_count) {
    return tls_write_parts(tls_priv(t), parts, part_count);
}

size_t ch_writable_len(const ch_tls *t, size_t cap) {
    return tls_writable_len(tls_priv_const(t), cap);
}

int ch_fail(ch_tls *t, uint8_t description) {
    return tls_fail(tls_priv(t), description);
}

void ch_close(ch_tls *t) {
    tls_close(tls_priv(t));
}

#ifdef CH_EXPORTER
int ch_export(const ch_tls *t, const char *label, const uint8_t *context, size_t context_len,
              uint8_t *out, size_t out_len) {
    return tls_export(tls_priv_const(t), label, context, context_len, out, out_len);
}
#endif

uint8_t ch_alert_sent(const ch_tls *t) {
    return tls_alert_sent(tls_priv_const(t));
}

uint8_t ch_alert_received(const ch_tls *t) {
    return tls_alert_received(tls_priv_const(t));
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
