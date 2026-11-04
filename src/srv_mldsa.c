// A server's ML-DSA-87 identity and CertificateVerify, in every object
// that signs ML-DSA-87 (CH_SIGN_MLDSA). srv_mldsa.h states the rules and
// each call's contract. Under PROFILE=cnsa2 this file also defines
// srv_auth.h's calls, in place of srv_auth.c.
//
// No line here reads a byte behind ch_identity.priv. This file tests
// priv_len and hands the pointer to mldsa87_sign_cpu, so the secret key is
// read inside the signer's five files and nowhere else.
#include "srv_mldsa.h"

// In an object that signs no ML-DSA-87 this file holds nothing, and the
// header below declares what every server build declares, so the unit is
// not empty.
#include "srv_auth.h"

#if defined(CH_ROLE_SERVER) && defined(CH_SIGN_MLDSA)

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "mldsa.h"
#include "mldsa_signer.h"
#include "rand_draw.h"
#include "sha512.h"
#include "srv_out.h"

// The 64 bytes of 0x20 that RFC 9846 section 4.5.2 puts in front of the
// signed content.
#define SRV_MLDSA_PAD_LEN 64

// The context string of a server's CertificateVerify. sizeof keeps the
// terminating NUL, which is the separator byte section 4.5.2 puts after it.
static const char srv_mldsa_context[] = "TLS 1.3, server CertificateVerify";

// The longest signed content, over a SHA-384 transcript hash: 146 bytes.
// A SHA-256 suite's content is 130 bytes.
#define SRV_MLDSA_CONTENT_MAX (SRV_MLDSA_PAD_LEN + sizeof srv_mldsa_context + SHA384_LEN)

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

int srv_mldsa_live(const ch_cfg *cfg) {
    return identity_provisioned(&cfg->srv.mldsa87);
}

// The key lengths and the chain. The key's coefficients are mldsa87_sign's
// to judge, which ch_srv_check asks at boot: a test here would sign at
// every init call, a ninth of a millisecond's work for a fact that the
// boot check already settled.
int srv_mldsa_usable(const ch_cfg *cfg) {
    const ch_identity *id = &cfg->srv.mldsa87;
    return !identity_provisioned(id) || (key_lengths_match(id) && srv_certificate_fits(id));
}

// Writes RFC 9846 §4.5.2's content over a transcript hash of hash_len
// bytes, SHA256_LEN or SHA384_LEN, into content through the writer, and
// returns its length, or 0 for any other hash_len.
static size_t signed_content(const uint8_t *transcript_hash, size_t hash_len,
                             uint8_t content[SRV_MLDSA_CONTENT_MAX]) {
    if (hash_len != SHA256_LEN && hash_len != SHA384_LEN) {
        return 0;
    }
    wbuf w;
    wb_init(&w, content, SRV_MLDSA_CONTENT_MAX);
    for (size_t i = 0; i < SRV_MLDSA_PAD_LEN; i++) {
        wb_u8(&w, 0x20);
    }
    wb_bytes(&w, (const uint8_t *)srv_mldsa_context, sizeof srv_mldsa_context);
    // One copy of a constant length for each hash, so the copy's length
    // is never a value the caller passed.
    if (hash_len == SHA384_LEN) {
        wb_bytes(&w, transcript_hash, SHA384_LEN);
    } else {
        wb_bytes(&w, transcript_hash, SHA256_LEN);
    }
    return w.err ? 0 : w.len;
}

// mldsa87_sign and mldsa87_verify on the path the configuration's
// ch_cfg.cpu picks in a host object (mldsa_signer.h, mldsa.h), and on the
// portable code in an object with no such field, which a test build is.
static int sign_with(const ch_cfg *cfg, const ch_identity *id, const uint8_t *content, size_t n,
                     const uint8_t rnd[MLDSA87_RND_LEN], uint8_t sig[MLDSA87_SIG_LEN]) {
#ifdef CH_CPU_RUNTIME
    return mldsa87_sign_cpu(cfg->cpu, sig, id->priv, id->priv_len, id->pub, id->pub_len, content, n,
                            NULL, 0, rnd);
#else
    (void)cfg;
    return mldsa87_sign(sig, id->priv, id->priv_len, id->pub, id->pub_len, content, n, NULL, 0,
                        rnd);
#endif
}

static int verify_with(const ch_cfg *cfg, const ch_identity *id, const uint8_t *content, size_t n,
                       const uint8_t sig[MLDSA87_SIG_LEN]) {
#ifdef CH_CPU_RUNTIME
    return mldsa87_verify_cpu(cfg->cpu, id->pub, id->pub_len, content, n, NULL, 0, sig,
                              MLDSA87_SIG_LEN);
#else
    (void)cfg;
    return mldsa87_verify(id->pub, id->pub_len, content, n, NULL, 0, sig, MLDSA87_SIG_LEN);
#endif
}

// Signs the content over transcript_hash with the identity under rnd drawn
// for this signature alone. Returns the signer's verdict, 1 or 0, with sig
// zeroed on 0, and 0 for a hash_len signed_content refuses. The content
// holds the transcript hash, which is derived from secrets, and rnd is the
// hedge, so both are wiped.
static int sign_content(const ch_cfg *cfg, const ch_identity *id, const uint8_t *transcript_hash,
                        size_t hash_len, uint8_t sig[MLDSA87_SIG_LEN]) {
    uint8_t content[SRV_MLDSA_CONTENT_MAX];
    size_t n = signed_content(transcript_hash, hash_len, content);
    uint8_t rnd[MLDSA87_RND_LEN];
    rand_draw(cfg, rnd, sizeof rnd);
    int signed_ok = n != 0 && sign_with(cfg, id, content, n, rnd, sig);
    ct_wipe(rnd, sizeof rnd);
    ct_wipe(content, sizeof content);
    return signed_ok;
}

int srv_mldsa_send_certificate_verify(handshake_state *h, const selection *sel) {
    const ch_identity *id = &h->t->cfg.srv.mldsa87;
    if (sel->sigalg != SIGALG_MLDSA87 || !identity_provisioned(id) || !key_lengths_match(id) ||
        (sel->hash_len != SHA256_LEN && sel->hash_len != SHA384_LEN)) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_EAUTH;
    }
    uint8_t hash[SHA384_LEN];
    (void)hsr_transcript_hash(h, sel->hash_len, hash);
    uint8_t sig[MLDSA87_SIG_LEN];
    int signed_ok = sign_content(&h->t->cfg, id, hash, sel->hash_len, sig);
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

int srv_mldsa_check(const ch_cfg *cfg) {
    const ch_identity *id = &cfg->srv.mldsa87;
    if (!identity_provisioned(id) || !key_lengths_match(id)) {
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
    if (!sign_content(cfg, id, transcript, sizeof transcript, sig)) {
        return CH_EINVAL;
    }
    uint8_t content[SRV_MLDSA_CONTENT_MAX];
    size_t n = signed_content(transcript, sizeof transcript, content);
    if (n == 0 || !verify_with(cfg, id, content, n, sig)) {
        return CH_EINVAL;
    }
    return CH_OK;
}

#ifdef CH_PROFILE_CNSA2

// The profile's definitions of srv_auth.h's calls, over its one slot.

uint8_t srv_identity_live(const ch_cfg *cfg) {
    return srv_mldsa_live(cfg) ? SRV_IDENTITY_MLDSA87 : 0;
}

int srv_identities_usable(const ch_cfg *cfg) {
    return srv_mldsa_usable(cfg);
}

uint16_t srv_select_sigalg(const ch_cfg *cfg, uint8_t offered) {
    if ((offered & SRV_SIGALG_MLDSA87) != 0 && srv_mldsa_live(cfg)) {
        return SIGALG_MLDSA87;
    }
    return 0;
}

const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg) {
    if (sigalg != SIGALG_MLDSA87 || !srv_mldsa_live(cfg)) {
        return NULL;
    }
    return &cfg->srv.mldsa87;
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    return sigalg == SIGALG_MLDSA87 ? srv_mldsa_check(cfg) : CH_EINVAL;
}

#endif // CH_PROFILE_CNSA2

#endif // CH_ROLE_SERVER && CH_SIGN_MLDSA
