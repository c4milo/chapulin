// A PROFILE=cnsa2 server's ML-DSA-87 identity and CertificateVerify.
// srv_mldsa.h states the profile's rules, and srv_auth.h states the
// contract of each call this file defines in place of srv_auth.c.
//
// No line here reads a byte behind ch_identity.priv. This file tests
// priv_len and hands the pointer to mldsa87_sign, so the secret key is
// read inside the signer's five files and nowhere else.
#include "srv_mldsa.h"

// Outside the profile this file holds nothing, and the header below
// declares what every server build declares, so the unit is not empty.
#include "srv_auth.h"

#if defined(CH_ROLE_SERVER) && defined(CH_PROFILE_CNSA2)

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "mldsa.h"
#include "mldsa_signer.h"
#include "rand_draw.h"
#include "srv_out.h"

// The 64 bytes of 0x20 that RFC 9846 section 4.5.2 puts in front of the
// signed content.
#define SRV_MLDSA_PAD_LEN 64

// The context string of a server's CertificateVerify. sizeof keeps the
// terminating NUL, which is the separator byte section 4.5.2 puts after it.
static const char srv_mldsa_context[] = "TLS 1.3, server CertificateVerify";

// The signed content at the profile's one transcript hash, SHA-384: 146
// bytes.
#define SRV_MLDSA_CONTENT_LEN (SRV_MLDSA_PAD_LEN + sizeof srv_mldsa_context + SHA384_LEN)

// True when the caller provisioned the slot: a chain of at least one entry
// and both key pointers set. It reads no byte of either key or the chain.
static int identity_provisioned(const ch_identity *id) {
    return id->chain != NULL && id->chain_count > 0 && id->priv != NULL && id->pub != NULL;
}

// The lengths ch_mldsa_key_from_pem writes, which mldsa87_sign reads
// whatever the slot claims.
static int key_lengths_match(const ch_identity *id) {
    return id->priv_len == MLDSA87_SK_LEN && id->pub_len == MLDSA87_PK_LEN;
}

uint8_t srv_identity_live(const ch_cfg *cfg) {
    return identity_provisioned(&cfg->srv.mldsa87) ? SRV_IDENTITY_MLDSA87 : 0;
}

// The key lengths and the chain. The key's coefficients are mldsa87_sign's
// to judge, which ch_srv_check asks at boot: a test here would sign at
// every init call, a ninth of a millisecond's work for a fact that the
// boot check already settled.
int srv_identities_usable(const ch_cfg *cfg) {
    const ch_identity *id = &cfg->srv.mldsa87;
    return !identity_provisioned(id) || (key_lengths_match(id) && srv_certificate_fits(id));
}

uint16_t srv_select_sigalg(const ch_cfg *cfg, uint8_t offered) {
    if ((offered & SRV_SIGALG_MLDSA87) != 0 && srv_identity_live(cfg) != 0) {
        return SIGALG_MLDSA87;
    }
    return 0;
}

const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg) {
    if (sigalg != SIGALG_MLDSA87 || !identity_provisioned(&cfg->srv.mldsa87)) {
        return NULL;
    }
    return &cfg->srv.mldsa87;
}

// Writes RFC 9846 §4.5.2's content over a SHA-384 transcript hash into
// content, through the writer, and returns its length,
// SRV_MLDSA_CONTENT_LEN.
static size_t signed_content(const uint8_t transcript_hash[SHA384_LEN],
                             uint8_t content[SRV_MLDSA_CONTENT_LEN]) {
    wbuf w;
    wb_init(&w, content, SRV_MLDSA_CONTENT_LEN);
    for (size_t i = 0; i < SRV_MLDSA_PAD_LEN; i++) {
        wb_u8(&w, 0x20);
    }
    wb_bytes(&w, (const uint8_t *)srv_mldsa_context, sizeof srv_mldsa_context);
    wb_bytes(&w, transcript_hash, SHA384_LEN);
    return w.err ? 0 : w.len;
}

// Signs the content over transcript_hash with the identity under rnd drawn
// for this signature alone. Returns mldsa87_sign's verdict, 1 or 0, with
// sig zeroed on 0. The content holds the transcript hash, which is derived
// from secrets, and rnd is the hedge, so both are wiped.
static int sign_content(const ch_cfg *cfg, const ch_identity *id,
                        const uint8_t transcript_hash[SHA384_LEN], uint8_t sig[MLDSA87_SIG_LEN]) {
    uint8_t content[SRV_MLDSA_CONTENT_LEN];
    size_t n = signed_content(transcript_hash, content);
    uint8_t rnd[MLDSA87_RND_LEN];
    rand_draw(cfg, rnd, sizeof rnd);
    int signed_ok =
        n == SRV_MLDSA_CONTENT_LEN &&
        mldsa87_sign(sig, id->priv, id->priv_len, id->pub, id->pub_len, content, n, NULL, 0, rnd);
    ct_wipe(rnd, sizeof rnd);
    ct_wipe(content, sizeof content);
    return signed_ok;
}

int srv_mldsa_send_certificate_verify(handshake_state *h, const selection *sel) {
    const ch_identity *id = srv_identity_for(&h->t->cfg, sel->sigalg);
    if (id == NULL || !key_lengths_match(id) || sel->hash_len != SHA384_LEN) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_EAUTH;
    }
    uint8_t hash[SHA384_LEN];
    (void)hsr_transcript_hash(h, SHA384_LEN, hash);
    uint8_t sig[MLDSA87_SIG_LEN];
    int signed_ok = sign_content(&h->t->cfg, id, hash, sig);
    ct_wipe(hash, sizeof hash);
    if (!signed_ok) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_EAUTH;
    }
    // The message streams as the Certificate does: the head, then the
    // signature, each hashed and sealed a record at a time.
    uint8_t head[SRV_CERT_VERIFY_HEAD_LEN];
    size_t head_len =
        srv_build_certificate_verify_head(head, sizeof head, SIGALG_MLDSA87, sizeof sig);
    if (head_len != SRV_CERT_VERIFY_HEAD_LEN) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    srv_frag f;
    f.h = h;
    f.len = 0;
    f.rc = CH_OK;
    srv_frag_bytes(&f, head, head_len);
    srv_frag_bytes(&f, sig, sizeof sig);
    srv_frag_flush(&f);
    return f.rc;
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    const ch_identity *id = srv_identity_for(cfg, sigalg);
    if (id == NULL || !key_lengths_match(id)) {
        return CH_EINVAL;
    }
    // The content a handshake signs, over a transcript hash of SHA384_LEN
    // zero bytes, so a pass here is evidence about the handshake. The
    // signer checks its own signature, and this check runs the verifier
    // once more on the public key the slot names. Every byte in this frame
    // is public but the content and rnd, which sign_content wipes.
    uint8_t transcript[SHA384_LEN];
    memset(transcript, 0, sizeof transcript);
    uint8_t sig[MLDSA87_SIG_LEN];
    if (!sign_content(cfg, id, transcript, sig)) {
        return CH_EINVAL;
    }
    uint8_t content[SRV_MLDSA_CONTENT_LEN];
    size_t n = signed_content(transcript, content);
    if (n != SRV_MLDSA_CONTENT_LEN ||
        !mldsa87_verify(id->pub, id->pub_len, content, n, NULL, 0, sig, sizeof sig)) {
        return CH_EINVAL;
    }
    return CH_OK;
}

#endif // CH_ROLE_SERVER && CH_PROFILE_CNSA2
