// The r2 corpus chain as both ends of a TRUST=webpki test use it: a
// server presents the chain and signs with its leaf key, and a client
// verifies it against the chain's anchor, for its hostname, at its clock.
// test/gen_webpki_corpus.py writes all of it into test/webpki_corpus.h:
// the Certificate message over leaf_r2 and int_r2_p256, the root_p384
// anchor, and the leaf key as webpki_corpus_server_priv and
// webpki_corpus_server_pub. Included by test/webpki_resume_test.c, whose
// mock server signs with the key, and by the two ROLE=both loopbacks,
// test/webpki_loop_test.c and test/quic_loop_webpki.h, whose server is
// this tree's own. Include it after buf.h and tls.h.
#ifndef CH_TEST_WEBPKI_R2_CHAIN_H
#define CH_TEST_WEBPKI_R2_CHAIN_H

#include <string.h>

#include "webpki_corpus.h"

// The corpus row this file serves: its anchor, hostname and clock. The
// row's expected verdict is "ok", so a client configured from it accepts
// the chain.
static const webpki_corpus_chain *r2_row(void) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        if (strcmp(webpki_corpus_chains[i].name, "r2") == 0) {
            return &webpki_corpus_chains[i];
        }
    }
    return NULL;
}

// The anchors a client trusts, copied out of a corpus anchor set into the
// type ch_cfg.anchors takes.
static ch_trust_anchor r2_anchors[1];

// Sets what a client needs to verify the r2 chain: its one anchor, which
// root_anchor names (webpki_corpus_anchors_root_p384 accepts the chain,
// webpki_corpus_anchors_impostor_p384 carries the root's Name over another
// key), hostname, and the row's clock. Leaves every other field
// as the caller set it.
static void r2_trust(ch_cfg *cfg, const webpki_corpus_anchor *root_anchor, const char *hostname) {
    const webpki_corpus_chain *row = r2_row();
    r2_anchors[0] = (ch_trust_anchor){root_anchor->name, root_anchor->name_len, root_anchor->spki,
                                      root_anchor->spki_len};
    cfg->anchors = r2_anchors;
    cfg->anchor_count = 1;
    cfg->hostname = (const uint8_t *)hostname;
    cfg->hostname_len = strlen(hostname);
    cfg->now_seconds = row != NULL ? row->now_seconds : 0;
}

#ifdef CH_ROLE_SERVER
// The chain's two certificates, pointing into its Certificate message.
static ch_cert r2_chain[2];

// Provisions id, a server's ecdsa_p256 slot, with the r2 chain and its
// leaf key. The Certificate message is split into its entries through the
// rbuf reader: the 4-byte handshake header, the empty
// certificate_request_context, the 3-byte list length, then per entry a
// 3-byte length, the certificate and an empty extensions vector (RFC 9846
// §4.5.1). Returns 0 when the message does not frame two entries.
static int r2_identity(ch_identity *id) {
    rbuf r;
    rb_init(&r, webpki_corpus_message_r2, sizeof webpki_corpus_message_r2);
    (void)rb_bytes(&r, 4);
    (void)rb_u8(&r);
    size_t list_len = rb_u24(&r);
    size_t count = 0;
    while (rb_left(&r) > 0 && count < 2 && !r.err) {
        size_t len = rb_u24(&r);
        r2_chain[count].der = rb_bytes(&r, len);
        r2_chain[count].len = len;
        (void)rb_bytes(&r, rb_u16(&r));
        count++;
    }
    if (r.err || rb_left(&r) != 0 || count != 2 ||
        list_len + 8 != sizeof webpki_corpus_message_r2) {
        return 0;
    }
    memset(id, 0, sizeof *id);
    id->chain = r2_chain;
    id->chain_count = 2;
    id->priv = webpki_corpus_server_priv;
    id->priv_len = sizeof webpki_corpus_server_priv;
    id->pub = webpki_corpus_server_pub;
    id->pub_len = sizeof webpki_corpus_server_pub;
    return 1;
}
#endif

#endif
