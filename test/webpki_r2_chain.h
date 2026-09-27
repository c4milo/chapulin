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
//
// The loopbacks' server also presents the leaf_over_cert_max chain: the
// r2 chain with leaf_r2_large, a leaf of 5,558 bytes, in place of leaf_r2.
// The walk refuses a leaf over CH_WEBPKI_CERT_MAX, and SPKI pins alone
// take it (docs/decisions.md 65). gen_webpki_corpus.py mints that leaf
// over leaf_p256, the r2 leaf's key, so webpki_corpus_server_priv is the
// private key of both leaves.
#ifndef CH_TEST_WEBPKI_R2_CHAIN_H
#define CH_TEST_WEBPKI_R2_CHAIN_H

#include <string.h>

#include "sha256.h"
#include "webpki.h"
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
// Each chain's two certificates, pointing into its Certificate message:
// the r2 row's, and the leaf_over_cert_max row's.
static ch_cert r2_chain[2];
static ch_cert r2_large_chain[2];

// Splits message, a Certificate message of message_len bytes, into its two
// entries in chain, through the rbuf reader: the 4-byte handshake header,
// the empty certificate_request_context, the 3-byte list length, then per
// entry a 3-byte length, the certificate and an empty extensions vector
// (RFC 9846 §4.5.1). Returns 0 when the message does not frame two
// entries.
static int r2_split(const uint8_t *message, size_t message_len, ch_cert chain[2]) {
    rbuf r;
    rb_init(&r, message, message_len);
    (void)rb_bytes(&r, 4);
    (void)rb_u8(&r);
    size_t list_len = rb_u24(&r);
    size_t count = 0;
    while (rb_left(&r) > 0 && count < 2 && !r.err) {
        size_t len = rb_u24(&r);
        chain[count].der = rb_bytes(&r, len);
        chain[count].len = len;
        (void)rb_bytes(&r, rb_u16(&r));
        count++;
    }
    return !r.err && rb_left(&r) == 0 && count == 2 && list_len + 8 == message_len;
}

// Provisions id, a server's ecdsa_p256 slot, with chain and the r2 leaf
// key, webpki_corpus_server_priv and webpki_corpus_server_pub.
static void r2_key_identity(ch_identity *id, const ch_cert *chain) {
    memset(id, 0, sizeof *id);
    id->chain = chain;
    id->chain_count = 2;
    id->priv = webpki_corpus_server_priv;
    id->priv_len = sizeof webpki_corpus_server_priv;
    id->pub = webpki_corpus_server_pub;
    id->pub_len = sizeof webpki_corpus_server_pub;
}

// Provisions id with the r2 chain and its leaf key. Returns 0 when the
// message does not frame two entries.
static int r2_identity(ch_identity *id) {
    if (!r2_split(webpki_corpus_message_r2, sizeof webpki_corpus_message_r2, r2_chain)) {
        return 0;
    }
    r2_key_identity(id, r2_chain);
    return 1;
}

// Provisions id with the leaf_over_cert_max chain, leaf_r2_large before
// int_r2_p256, and the r2 leaf key. Returns 0 when the message does not
// frame two entries.
static int r2_large_identity(ch_identity *id) {
    if (!r2_split(webpki_corpus_message_leaf_over_cert_max,
                  sizeof webpki_corpus_message_leaf_over_cert_max, r2_large_chain)) {
        return 0;
    }
    r2_key_identity(id, r2_large_chain);
    return 1;
}

// Writes pin, the SHA-256 of leaf_r2_large's SubjectPublicKeyInfo as
// webpki_read_certificate_key reads it. That is the reader SPKI pins alone
// use, and webpki_parse_certificate refuses a certificate this large.
// Returns 0 when the reader refuses the leaf, or when its key is not
// webpki_corpus_server_pub, the public half of the key r2_large_identity
// provisions. r2_large_identity must have split the chain first.
static int r2_large_pin(uint8_t pin[SHA256_LEN]) {
    const ch_cert *cert = &r2_large_chain[0];
    webpki_cert leaf;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (webpki_read_certificate_key(cert->der, cert->len, &leaf, &alert) != CH_OK) {
        return 0;
    }
    if (leaf.spki.key_len != sizeof webpki_corpus_server_pub ||
        memcmp(leaf.spki.key, webpki_corpus_server_pub, sizeof webpki_corpus_server_pub) != 0) {
        return 0;
    }
    sha256_of(leaf.spki_tlv, leaf.spki_tlv_len, pin);
    return 1;
}
#endif

#endif
