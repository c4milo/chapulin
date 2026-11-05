// The bodies of the record transports' public calls on a session (docs/decisions.md 185):
// tls.h's, alert.h's and srv.h's ch_srv_accept, each on the ch_tls_priv in the caller's storage.
// tls_entry.c defines the public calls, and srv.c ch_srv_accept. Each converts its pointer once
// and calls one of these. The public headers state every contract; tls.c, tls_write.c and srv.c
// define these.
#ifndef CH_TLS_CALLS_H
#define CH_TLS_CALLS_H
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "session.h"
#include "tls.h"

int tls_connect(ch_tls_priv *t, const ch_cfg *cfg);
int tls_read(ch_tls_priv *t, uint8_t *p, size_t n);
int tls_write(ch_tls_priv *t, const uint8_t *p, size_t n);
int tls_write_parts(ch_tls_priv *t, const ch_part *parts, size_t part_count);
size_t tls_writable_len(const ch_tls_priv *t, size_t cap);
int tls_fail(ch_tls_priv *t, uint8_t description);
void tls_close(ch_tls_priv *t);
int tls_export(const ch_tls_priv *t, const char *label, const uint8_t *context, size_t context_len,
               uint8_t *out, size_t out_len);
uint8_t tls_alert_sent(const ch_tls_priv *t);
uint8_t tls_alert_received(const ch_tls_priv *t);
int srv_accept(ch_tls_priv *t, const ch_cfg *cfg);

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
