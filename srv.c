// Stub only. srv.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
//
// These are the two calls a ROLE=server object exports beyond ch_read, ch_write and
// ch_close, so this file is what makes `make lib ROLE=server` produce the export list
// the Makefile's PUBLIC_ROLE names. Both refuse, so a firmware that links this object
// today runs no handshake and never reaches a session it could read from.
#include "srv.h"

#ifdef CH_ROLE_SERVER

int ch_srv_accept(ch_tls *t, const ch_cfg *cfg) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)t;
    (void)cfg;
    return CH_EINVAL;
}

int ch_srv_check(const ch_cfg *cfg) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)cfg;
    return CH_EINVAL;
}

#endif // CH_ROLE_SERVER
