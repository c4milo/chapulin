// Contract stubs for srv_kex.h's four entries, which srv_select,
// srv_check_retry_hello, srv_send_server_hello and
// srv_derive_handshake_secrets call. proof/srv_flight_harness.c includes
// this after its own helpers, whose nondet_int and fill_nondet it reads.
// It is a header of its own because that harness sits at the 500-line
// cap, and proof/srv_kex_harness.c proves the real four.
//
// Each stub asserts what srv_kex.h requires of a caller and answers with
// every value srv_kex.h allows: a group this build holds or 0, either
// verdict, and a share or a secret of one of the two lengths the two
// groups fix.
#ifndef CH_SRV_KEX_STUBS_H
#define CH_SRV_KEX_STUBS_H

#include <string.h>

#include "srv_kex.h"

uint16_t srv_kex_group(const client_hello *ch) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "kex_group: hello readable");
    uint16_t group = nondet_u16();
    __CPROVER_assume(group == 0 || group == CH_GROUP_X25519 || group == CH_GROUP_X25519MLKEM768);
    return group;
}

int srv_kex_shared(const client_hello *ch, uint16_t group) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "kex_shared: hello readable");
    (void)group;
    return nondet_u8() & 1;
}

int srv_kex_share(handshake_state *hs, const client_hello *ch, uint16_t group,
                  uint8_t share[SRV_KEX_SHARE_MAX], size_t *share_len) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "kex_share: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(share, SRV_KEX_SHARE_MAX), "kex_share: share writable");
    __CPROVER_assert(__CPROVER_w_ok(share_len, sizeof *share_len), "kex_share: length writable");
    (void)group;
    if ((nondet_u8() & 1) != 0) {
        memset(hs->mlkem_ss, 0, sizeof hs->mlkem_ss);
        return CH_EPROTO;
    }
    // The bytes are not filled: the only reader is the stubbed builder,
    // which asserts they are readable and reads none of them.
    *share_len = (nondet_u8() & 1) ? X25519_LEN : CH_HYBRID_SERVER_SHARE;
    fill_nondet(hs->mlkem_ss, sizeof hs->mlkem_ss);
    return CH_OK;
}

int srv_kex_secret(handshake_state *hs, const client_hello *ch, uint16_t group,
                   uint8_t ikm[SRV_KEX_SECRET_MAX], size_t *ikm_len) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "kex_secret: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(ikm, SRV_KEX_SECRET_MAX), "kex_secret: ikm writable");
    __CPROVER_assert(__CPROVER_w_ok(ikm_len, sizeof *ikm_len), "kex_secret: length writable");
    (void)group;
    memset(hs->priv, 0, sizeof hs->priv);
    memset(hs->pub, 0, sizeof hs->pub);
    memset(hs->mlkem_ss, 0, sizeof hs->mlkem_ss);
    if ((nondet_u8() & 1) != 0) {
        memset(ikm, 0, SRV_KEX_SECRET_MAX);
        return CH_EPROTO;
    }
    *ikm_len = (nondet_u8() & 1) ? X25519_LEN : SRV_KEX_SECRET_MAX;
    fill_nondet(ikm, *ikm_len);
    return CH_OK;
}

#endif
