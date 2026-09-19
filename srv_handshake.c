// Stub only. srv_handshake.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
#include "srv_handshake.h"

#ifdef CH_ROLE_SERVER

int srv_handshake(ch_tls *t) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)t;
    return CH_EPROTO;
}

#endif // CH_ROLE_SERVER
