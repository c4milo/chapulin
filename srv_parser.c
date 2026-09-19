// Stub only. srv_parser.h states the contract; no line below implements it.
//
// Every function here carries one CH_SRV_STUB line, returns a value its header
// documents as a refusal, and writes nothing through its out-parameters. A ROLE=server
// object therefore links and does nothing, which is what lets the Makefile's ROLE axis
// and every gate that reads it run before the code exists. The marker is the one the
// Makefile greps for: SRV_STUB_SRCS holds the files that still carry it, and a file
// drops out of that list on the commit that deletes its last marker. It is the same
// rule quic_aes.c states for CH_QUIC_STUB, under a second name, because the two axes
// stub independently.
#include "srv_parser.h"

#ifdef CH_ROLE_SERVER

int srv_ext_known(uint16_t type) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)type;
    // 0 says the type is unrecognized, which is the answer that reaches no check.
    return 0;
}

int srv_ext_duplicate(const uint8_t *exts, size_t n) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)exts;
    (void)n;
    // 0 claims no duplicate. The caller that would act on a 1 is itself a stub, so
    // no handshake reaches this answer.
    return 0;
}

int srv_parse_client_hello(const uint8_t *body, size_t n, client_hello *ch,
                           const ch_alpn_protocol *offered, size_t offered_count, uint8_t *alert) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)body;
    (void)n;
    (void)ch;
    (void)offered;
    (void)offered_count;
    (void)alert;
    return CH_EPROTO;
}

#endif // CH_ROLE_SERVER
