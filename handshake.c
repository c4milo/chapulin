#include "handshake.h"

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "handshake_auth.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "handshake_record.h"
#include "io.h"
#include "keysched.h"
#include "rand.h"
#include "x25519.h"

// Exactly one pinned-mode verifier is linked per build (Makefile PIN).
#ifdef CH_PIN_ECDSA
#include "p256.h"
#else
#include "rsa.h"
#endif
#ifdef CH_TRUST_CA
#include "x509.h"
#endif

// The hello is built whole into the TX staging array (docs/decisions.md
// 22), so the array must hold the largest one this build can emit.
// KEX=pq sizes CH_TX_STAGE to exactly that. The classic build's 529
// bytes do not reach its own 617-byte worst case — a resumption
// carrying a max-size ticket identity that then answers an HRR with a
// max-size cookie fails closed with CH_ECAP — so the check runs where
// it holds rather than being written as a claim that is not true.
#ifdef CH_KEX_PQ
#ifndef __cplusplus
_Static_assert(CH_HELLO_MAX <= CH_TX_STAGE, "the largest ClientHello must fit TX staging");
#endif
#endif

// Builds the ClientHello (echoing an HRR cookie on the retry), computes
// the binder over the transcript-so-far plus the truncated message, and
// sends it as a plaintext handshake record. The hybrid build reaches
// this through send_client_hello below, which expands the stored seed
// and hands the ek slice in.
#ifdef CH_KEX_PQ
static int send_client_hello_ek(handshake_state *h, const uint8_t ek[MLKEM_EK_LEN]) {
#else
static int send_client_hello(handshake_state *h) {
#endif
    ch_tls *t = h->t;
    uint8_t *msg = t->tx + REC_HDR;
    size_t cap = sizeof t->tx - REC_HDR;
    size_t n = hs_build_client_hello(msg, cap, &t->cfg,
#ifdef CH_KEX_PQ
                                     ek,
#endif
                                     h->pub, h->random, h->record_size_limit,
                                     h->cookie_len > 0 ? h->cookie : NULL, h->cookie_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    if (t->cfg.psk != NULL) {
        // PSK binder over the transcript-so-far plus the truncated hello.
        sha256 transcript = t->transcript;
        uint8_t hash[SHA256_LEN];
        sha256_update(&transcript, msg, n - CH_BINDERS_TAIL);
        sha256_final(&transcript, hash);
        ks_verify_data(h->binder_key, hash, msg + n - SHA256_LEN);
    }
    sha256_update(&t->transcript, msg, n);

    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    // The very first record may carry 0x0301 for old middleboxes; every
    // later one, including the post-HRR retry, must say 0x0303 (§5.1).
    t->tx[2] = h->cookie_len > 0 ? 0x03 : 0x01;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    return io_send_all(&t->cfg, t->tx, REC_HDR + n);
}

#ifdef CH_KEX_PQ
// Expands the stored (d, z) seed into the FIPS 203 dk layout and hands
// its ek slice to the builder. The expansion is deterministic, so the
// HRR retry resends the identical share; the dk itself is scratch —
// hybrid_secret re-expands the same way at decapsulation. The 2400-byte
// buffer gets its own frame so it is gone before the handshake reads a
// record; the frame itself is over the classic build's budget, which is
// why KEX=pq carries its own (docs/invariants.md INV-19).
static int send_client_hello(handshake_state *h) {
    uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, h->dz, h->dz + 32);
    int rc = send_client_hello_ek(h, dk + 1152);
    ct_wipe(dk, sizeof dk);
    return rc;
}

// Decapsulates into ikm[0..31] and runs x25519 into ikm[32..63] —
// ML-KEM first, RFC 10024's order despite the group's name. The ct
// pointer reads out of the live ServerHello record; no record read sits
// between the parse and this. Decapsulation cannot fail (a tampered
// ciphertext yields the implicit-reject secret); the x25519 all-zero
// refusal stays, and on it the half-built secret is wiped.
static int hybrid_secret(handshake_state *h, const server_hello_info *info,
                         uint8_t ikm[MLKEM_SS_LEN + X25519_LEN]) {
    uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, h->dz, h->dz + 32);
    mlkem_decaps(ikm, info->server_ct, dk);
    ct_wipe(dk, sizeof dk);
    if (!x25519(ikm + MLKEM_SS_LEN, h->priv, info->server_pub)) {
        ct_wipe(ikm, MLKEM_SS_LEN + X25519_LEN);
        return CH_EPROTO;
    }
    return CH_OK;
}
#endif

// Replaces the transcript after HRR: Hash(message_hash || 00 00 20 ||
// Hash(CH1)) || HRR, per RFC 9846 §4.1.
static void hrr_transcript(handshake_state *h, const uint8_t *raw, size_t raw_len) {
    uint8_t ch1[SHA256_LEN];
    sha256_final(&h->t->transcript, ch1);
    sha256_init(&h->t->transcript);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    sha256_update(&h->t->transcript, synth, 4);
    sha256_update(&h->t->transcript, ch1, SHA256_LEN);
    sha256_update(&h->t->transcript, raw, raw_len);
}

static int read_server_hello(handshake_state *h, server_hello_info *info) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_SERVER_HELLO) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    memset(info, 0, sizeof *info);
    rc = hsp_parse_server_hello(raw + 4, raw_len - 4, info, h->t->cfg.psk != NULL);
    if (rc != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return rc;
    }
    if (info->hrr) {
        hrr_transcript(h, raw, raw_len);
        if (info->cookie_len == 0) {
            // An HRR that changes nothing we offered is illegal.
            h->alert = ALERT_ILLEGAL_PARAMETER;
            return CH_EPROTO;
        }
        memcpy(h->cookie, info->cookie, info->cookie_len);
        h->cookie_len = info->cookie_len;
    } else {
        sha256_update(&h->t->transcript, raw, raw_len);
    }
    return CH_OK;
}

static int expect_finished(handshake_state *h) {
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE || type == HS_CERTIFICATE_REQUEST) {
        // Certificates where none belong: a PSK server that rejected the
        // PSK, or a pinned-key server demanding client auth we cannot do.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    if (type != HS_FINISHED || raw_len != 4 + SHA256_LEN) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    uint8_t want[SHA256_LEN];
    ks_verify_data(h->s_hs, hash, want);
    if (!ct_memeq(want, raw + 4, SHA256_LEN)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, raw_len);
    h->server_finished_ok = 1;
    return CH_OK;
}

static int send_client_finished(handshake_state *h, const uint8_t *hash) {
    ch_tls *t = h->t;
    uint8_t msg[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(h->c_hs, hash, msg + 4);
    sha256_update(&t->transcript, msg, sizeof msg);
    size_t out_len = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, msg, sizeof msg, t->tx, sizeof t->tx, &out_len) != 0) {
        return CH_ECAP;
    }
    return io_send_all(&t->cfg, t->tx, out_len);
}

// ClientHello out, ServerHello in, with at most one HelloRetryRequest
// round; on CH_OK info holds an acceptable non-HRR ServerHello.
static int hello_exchange(handshake_state *h, server_hello_info *info) {
    int rc = send_client_hello(h);
    if (rc != CH_OK) {
        return rc;
    }
    rc = read_server_hello(h, info);
    if (rc != CH_OK) {
        return rc;
    }
    if (info->hrr) {
        rc = send_client_hello(h);
        if (rc != CH_OK) {
            return rc;
        }
        rc = read_server_hello(h, info);
        if (rc != CH_OK) {
            return rc;
        }
        if (info->hrr) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
    }
    if (!info->have_share || (h->t->cfg.psk != NULL && !info->psk_ok)) {
        // No ECDHE share, or a PSK server that ignored our identity and
        // would want certificates we did not pin.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    return CH_OK;
}

static int run(handshake_state *h) {
    ch_tls *t = h->t;
    ch_rand_bytes(h->priv, sizeof h->priv);
    ch_rand_bytes(h->random, sizeof h->random);
#ifdef CH_KEX_PQ
    ch_rand_bytes(h->dz, sizeof h->dz);
#endif
    // run() zeroed h, so a hook that returned without writing leaves
    // every one of them zero, and nothing downstream would notice: the
    // handshake completes and the peer can predict the key. A real draw
    // is all-zero with probability 2^-256, so this checks the
    // integrator's hook against rand.h's contract rather than checking
    // peer input, which is what CH_ASSERT is for. It cannot tell a weak
    // generator from a strong one; nothing here can.
    {
        static const uint8_t unwritten[X25519_LEN] = {0};
        CH_ASSERT(!ct_memeq(h->priv, unwritten, sizeof h->priv));
        CH_ASSERT(!ct_memeq(h->random, unwritten, sizeof h->random));
#ifdef CH_KEX_PQ
        CH_ASSERT(!ct_memeq(h->dz, unwritten, 32));
        CH_ASSERT(!ct_memeq(h->dz + 32, unwritten, 32));
#endif
    }
    x25519_base(h->pub, h->priv);
    if (t->cfg.psk != NULL) {
        ks_early(t->cfg.psk, t->cfg.psk_len, t->cfg.resumption, h->early, h->binder_key);
    } else {
        // No PSK: the early secret extracts from a hash-length zero string
        // (RFC 9846 §7.1) and the binder key is never used.
        static const uint8_t no_psk[SHA256_LEN] = {0};
        ks_early(no_psk, sizeof no_psk, 0, h->early, h->binder_key);
    }
    sha256_init(&t->transcript);

    server_hello_info info;
    int rc = hello_exchange(h, &info);
    if (rc != CH_OK) {
        return rc;
    }

#ifdef CH_KEX_PQ
    uint8_t ecdhe[MLKEM_SS_LEN + X25519_LEN];
    if (hybrid_secret(h, &info, ecdhe) != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
#else
    uint8_t ecdhe[X25519_LEN];
    if (!x25519(ecdhe, h->priv, info.server_pub)) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
#endif
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    ks_handshake(h->early, ecdhe, sizeof ecdhe, hash, h->handshake_secret, h->c_hs, h->s_hs);
    ct_wipe(ecdhe, sizeof ecdhe);
    rec_dir_init(&t->rd, h->s_hs);
    rec_dir_init(&t->wr, h->c_hs);
    h->encrypted = 1;
    t->keys = 1; // alerts encrypt from here on

    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_ENCRYPTED_EXTENSIONS) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    // Seed the default first: the parser overrides it only when it has a
    // more specific alert (unsupported_extension, RFC 9846 §4.3), and
    // that override must survive to the wire.
    h->alert = ALERT_ILLEGAL_PARAMETER;
    rc = hsp_parse_encrypted_exts(raw + 4, raw_len - 4, &t->peer_limit, &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
    sha256_update(&t->transcript, raw, raw_len);

    if (t->cfg.psk == NULL) {
        rc = hsa_server_auth(h);
        if (rc != CH_OK) {
            return rc;
        }
    }
    rc = expect_finished(h);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRUST_CA
    hsa_epoch_commit(h);
#endif

    // Server Finished is in; derive the application schedule, answer with
    // our Finished under the handshake keys, then switch both directions.
    (void)hsr_transcript_hash(h, hash);
    ks_master(h->handshake_secret, hash, h->master, t->wr_secret, t->rd_secret);
    rc = send_client_finished(h, hash);
    if (rc != CH_OK) {
        return rc;
    }
    (void)hsr_transcript_hash(h, hash);
    ks_res_master(h->master, hash, t->res_master);
    rec_dir_init(&t->rd, t->rd_secret);
    rec_dir_init(&t->wr, t->wr_secret);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
    return CH_OK;
}

int ch_handshake(ch_tls *t) {
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = t;
    h.alert = ALERT_DECODE_ERROR;
    size_t room = t->cfg.buf_len - REC_HDR - AEAD_TAG;
    h.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    t->peer_limit = CH_TX_PT;

    int rc = run(&h);
    uint8_t alert = h.alert;
    ct_wipe(&h, sizeof h);
    if (rc != CH_OK) {
        tlsi_fail(t, alert);
    }
    return rc;
}
