// The TLS 1.3 ECDHE-PSK client handshake: one entry point that drives the
// caller's I/O from ClientHello to connected, including one
// HelloRetryRequest round. Everything it learns lands in the ch_tls
// session; every failure wipes and kills the session. It builds the
// first ClientHello before it sends a byte, and a hello too long for
// ch_tls.tx returns CH_EINVAL with nothing sent and no alert recorded,
// the refusal on entry ch_connect makes for a configuration (tls.h).
#ifndef CH_HANDSHAKE_H
#define CH_HANDSHAKE_H

#include "session.h"

int ch_handshake(ch_tls *t);

#endif
