// Stub only. srv_flight.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
//
// The two void handlers refuse by doing nothing, which is what "writes nothing"
// means for a call that reports no code: srv_begin draws no secret and starts no
// transcript, so every handler after it has nothing to work from.
#include "srv_flight.h"

#ifdef CH_ROLE_SERVER

void srv_begin(handshake_state *h) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
}

int srv_read_client_hello(handshake_state *h, client_hello *ch) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    return CH_EPROTO;
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    // CH_EPROTO rather than the CH_OK the header gives a client that is owed no
    // record: a stub that reported success here would be the one path in this file
    // where a refusal looks like a completed step.
    return CH_EPROTO;
}

int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    (void)sel;
    return CH_EPROTO;
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)ch;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_encrypted_extensions(handshake_state *h, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_certificate(handshake_state *h, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    (void)sel;
    return CH_EPROTO;
}

int srv_send_finished(handshake_state *h) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    return CH_EPROTO;
}

int srv_read_client_finished(handshake_state *h) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
    return CH_EPROTO;
}

void srv_complete(handshake_state *h) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)h;
}

#endif // CH_ROLE_SERVER
