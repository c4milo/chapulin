// The bodies of the record transports' public calls on a session (docs/decisions.md 185):
// tls.h's, alert.h's and srv.h's ch_srv_accept, each on the ch_tls_priv in the caller's storage.
// tls_entry.c defines the public calls, and srv.c ch_srv_accept. Each converts its pointer once
// and calls one of these. The public headers state every contract; tls.c, tls_write.c,
// tcp_read.c, tcp_seal.c and srv.c define these.
#ifndef CH_TLS_CALLS_H
#define CH_TLS_CALLS_H
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "session.h"
#include "tls.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"
#endif

int tls_connect(ch_tls_priv *t, const ch_cfg *cfg);
#ifndef CH_TRANSPORT_TCP_NONBLOCKING
int tls_read(ch_tls_priv *t, uint8_t *p, size_t n);
int tls_write(ch_tls_priv *t, const uint8_t *p, size_t n);
int tls_write_parts(ch_tls_priv *t, const ch_part *parts, size_t part_count);
int tls_fail(ch_tls_priv *t, uint8_t description);
void tls_close(ch_tls_priv *t);
#else
int tls_read_in_place(ch_tls_priv *t, uint8_t *p, size_t n, uint8_t *reply, size_t reply_cap,
                      ch_read_result *result);
int tls_seal_in_place(ch_tls_priv *t, uint8_t *buf, size_t cap, size_t n, uint8_t *side,
                      size_t side_cap, ch_seal_result *result);
int tls_close_out(ch_tls_priv *t, uint8_t *out, size_t cap, size_t *out_len);
int tls_fail_out(ch_tls_priv *t, uint8_t description, uint8_t *out, size_t cap, size_t *out_len);
#endif
size_t tls_writable_len(const ch_tls_priv *t, size_t cap);
int tls_export(const ch_tls_priv *t, const char *label, const uint8_t *context, size_t context_len,
               uint8_t *out, size_t out_len);
uint8_t tls_alert_sent(const ch_tls_priv *t);
uint8_t tls_alert_received(const ch_tls_priv *t);
int srv_accept(ch_tls_priv *t, const ch_cfg *cfg);

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
