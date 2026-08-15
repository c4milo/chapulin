// The TLS 1.3 ECDHE-PSK client handshake: one entry point that drives the
// caller's I/O from ClientHello to connected, including one
// HelloRetryRequest round. Everything it learns lands in the ms_tls
// session; every failure wipes and kills the session.
#ifndef MS_HANDSHAKE_H
#define MS_HANDSHAKE_H

#include "session.h"

int ms_handshake(ms_tls *t);

#endif
