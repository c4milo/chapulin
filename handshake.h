// The TLS 1.3 ECDHE-PSK client handshake: one entry point that drives the
// caller's I/O from ClientHello to connected, including one
// HelloRetryRequest round. Everything it learns lands in the ch_tls
// session; every failure wipes and kills the session. It builds the
// first ClientHello before it sends a byte. A hello too long for
// ch_tls.tx would return CH_EINVAL with nothing sent and no alert
// recorded, but no configuration ch_connect accepts makes one (tls.h).
#ifndef CH_HANDSHAKE_H
#define CH_HANDSHAKE_H

#include "session.h"

int ch_handshake(ch_tls *t);

#endif
