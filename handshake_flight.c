// The client's flight handlers, one function per handshake message.
// Both transports compile this file: handshake.c calls these in one
// straight line and quic_step.c calls them one per step, so no protocol
// rule exists twice. Contract in handshake_flight.h.
#include "handshake_flight.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"
#include "keysched.h"
#include "rand.h"
#include "x25519.h"

void hsf_begin(handshake_state *h) {
    ch_tls *t = h->t;
    ch_rand_bytes(h->priv, sizeof h->priv);
    ch_rand_bytes(h->random, sizeof h->random);
#ifdef CH_KEX_PQ
    ch_rand_bytes(h->dz, sizeof h->dz);
#endif
    // The caller zeroed h, so a hook that returned without writing leaves
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
}

// Builds the ClientHello (echoing an HRR cookie on the retry), computes
// the binder over the transcript-so-far plus the truncated message, and
// adds the message to the transcript. The hybrid build calls this
// through hsf_build_client_hello below, which expands the stored seed
// and hands the ek slice in.
#ifdef CH_KEX_PQ
static size_t build_client_hello_ek(handshake_state *h, uint8_t *out, size_t cap,
                                    const uint8_t ek[MLKEM_EK_LEN]) {
#else
static size_t build_client_hello_ek(handshake_state *h, uint8_t *out, size_t cap) {
#endif
    ch_tls *t = h->t;
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 §4.1.3 removes the record layer this extension sizes
    // (rfc9001.txt:462-464), so a QUIC hello sends none and the builder
    // reads the 0 this passes.
    const uint16_t record_size_limit = 0;
#else
    const uint16_t record_size_limit = h->record_size_limit;
#endif
    size_t n = hs_build_client_hello(out, cap, &t->cfg,
#ifdef CH_KEX_PQ
                                     ek,
#endif
                                     h->pub, h->random, record_size_limit,
                                     h->cookie_len > 0 ? h->cookie : NULL, h->cookie_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return 0;
    }
    if (t->cfg.psk != NULL) {
        // PSK binder over the transcript-so-far plus the truncated hello.
        sha256 transcript = t->transcript;
        uint8_t hash[SHA256_LEN];
        sha256_update(&transcript, out, n - CH_BINDERS_TAIL);
        sha256_final(&transcript, hash);
        ks_verify_data(h->binder_key, hash, out + n - SHA256_LEN);
    }
    sha256_update(&t->transcript, out, n);
    return n;
}

#ifdef CH_KEX_PQ
// Expands the stored (d, z) seed into the FIPS 203 dk layout and hands
// its ek slice to the builder. The expansion is deterministic, so the
// HRR retry resends the identical share; the dk itself is scratch —
// hsf_derive_handshake_secrets re-expands the same way at
// decapsulation. The 2400-byte buffer gets its own frame so it is gone
// before the handshake reads a record; the frame itself is over the
// classic build's budget, which is why KEX=pq carries its own
// (docs/invariants.md INV-19).
size_t hsf_build_client_hello(handshake_state *h, uint8_t *out, size_t cap) {
    uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, h->dz, h->dz + 32);
    size_t n = build_client_hello_ek(h, out, cap, dk + 1152);
    ct_wipe(dk, sizeof dk);
    return n;
}

// Decapsulates into ikm[0..31] and runs x25519 into ikm[32..63] —
// ML-KEM first, RFC 10024's order despite the group's name. The ct
// pointer reads out of the live ServerHello bytes; no read of a further
// message sits between the parse and this. Decapsulation cannot fail (a
// tampered ciphertext yields the implicit-reject secret); the x25519
// all-zero refusal stays, and on it the half-built secret is wiped.
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
#else
size_t hsf_build_client_hello(handshake_state *h, uint8_t *out, size_t cap) {
    return build_client_hello_ek(h, out, cap);
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

int hsf_read_server_hello(handshake_state *h, server_hello_info *info) {
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

int hsf_accept_server_hello(handshake_state *h, const server_hello_info *info) {
    // The group of the one key_share the parser accepted, or 0 when the
    // ServerHello carried none: the session reports it either way.
    h->t->group = info->group;
    if (!info->have_share || (h->t->cfg.psk != NULL && !info->psk_ok)) {
        // No ECDHE share, or a PSK server that ignored our identity and
        // would want certificates we did not pin.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
#ifdef CH_KEX_PQ
    // require_pq checks at run time what this build promises: it offers
    // X25519MLKEM768 alone and parse_key_share accepts no other group,
    // so the compare reads the field the parser wrote, never the
    // constant the build offered. The alert is the parser's own for a
    // group the client did not offer. A classic build never runs this:
    // ch_connect refuses the flag there before it sends a byte.
    if (h->t->cfg.require_pq && h->t->group != CH_GROUP_X25519MLKEM768) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
#endif
    return CH_OK;
}

int hsf_derive_handshake_secrets(handshake_state *h, const server_hello_info *info) {
#ifdef CH_KEX_PQ
    uint8_t ecdhe[MLKEM_SS_LEN + X25519_LEN];
    int shared_ok = hybrid_secret(h, info, ecdhe) == CH_OK;
#else
    uint8_t ecdhe[X25519_LEN];
    int shared_ok = x25519(ecdhe, h->priv, info->server_pub) != 0;
#endif
    // The six values the exchange consumed. The TLS driver would wipe
    // them with its frame; the QUIC driver returns to its caller
    // between messages, so that wipe is a round trip away and they die
    // here instead. After this call the retry hello can no longer be
    // built, which is correct: the exchange is over.
    ct_wipe(h->priv, sizeof h->priv);
    ct_wipe(h->pub, sizeof h->pub);
    ct_wipe(h->random, sizeof h->random);
#ifdef CH_KEX_PQ
    ct_wipe(h->dz, sizeof h->dz);
#endif
    if (!shared_ok) {
        ct_wipe(h->early, sizeof h->early);
        ct_wipe(h->binder_key, sizeof h->binder_key);
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    ks_handshake(h->early, ecdhe, sizeof ecdhe, hash, h->handshake_secret, h->c_hs, h->s_hs);
    ct_wipe(ecdhe, sizeof ecdhe);
    ct_wipe(h->early, sizeof h->early);
    ct_wipe(h->binder_key, sizeof h->binder_key);
    return CH_OK;
}

int hsf_read_encrypted_extensions(handshake_state *h) {
    ch_tls *t = h->t;
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_ENCRYPTED_EXTENSIONS) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
#ifdef CH_TRANSPORT_QUIC
    // A QUIC build declares no ch_tls.peer_limit, so the parser writes
    // a local this call drops: RFC 9001 §4.1.3 removes the record layer
    // record_size_limit sizes (rfc9001.txt:462-464).
    uint16_t peer_limit = 0xffff;
    const uint8_t *transport_params = NULL;
    size_t transport_params_len = 0;
#endif
    // Seed the default first: the parser overrides it only when it has a
    // more specific alert (unsupported_extension, RFC 9846 §4.3, and in a
    // TRUST=webpki build decode_error for a server_name that carries
    // data), and that override must survive to the wire.
    h->alert = ALERT_ILLEGAL_PARAMETER;
    rc = hsp_parse_encrypted_exts(
#ifdef CH_TRANSPORT_QUIC
        raw + 4, raw_len - 4, &peer_limit, t->cfg.alpn_protocols, t->cfg.alpn_count,
        &t->alpn_selected, &transport_params, &transport_params_len,
#elif defined(CH_TRUST_WEBPKI)
        raw + 4, raw_len - 4, &t->peer_limit, t->cfg.alpn_protocols, t->cfg.alpn_count,
        &t->alpn_selected,
#else
        raw + 4, raw_len - 4, &t->peer_limit,
#endif
        &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 §8.1 requires ALPN of every QUIC client and makes a
    // handshake that negotiated no protocol a failure
    // (rfc9001.txt:1897-1902). The parser accepts a message with no ALPN
    // extension, so the refusal is here.
    if (t->alpn_selected == CH_ALPN_NONE) {
        h->alert = ALERT_NO_APPLICATION_PROTOCOL;
        return CH_EPROTO;
    }
    // The body belongs to the QUIC version in use and is opaque to TLS
    // (RFC 9001 §8.2, rfc9001.txt:1926-1928), so it goes out unread. The
    // pointer is into cfg.buf and the call happens before anything
    // overwrites it.
    if (t->cfg.on_transport_params != NULL) {
        t->cfg.on_transport_params(t->cfg.io, transport_params, transport_params_len);
    }
#endif
    sha256_update(&t->transcript, raw, raw_len);
    return CH_OK;
}

int hsf_read_finished(handshake_state *h) {
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
    if (type != HS_FINISHED || raw_len != HSF_FINISHED_LEN) {
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

void hsf_complete(handshake_state *h, uint8_t finished[HSF_FINISHED_LEN]) {
    ch_tls *t = h->t;
    // Running the client Finished before the server proved it holds the
    // keys would answer an unauthenticated peer, which is programmer
    // error rather than peer input.
    CH_ASSERT(h->server_finished_ok);
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    ks_master(h->handshake_secret, hash, h->master, t->wr_secret, t->rd_secret);
#ifdef CH_EXPORTER
    // RFC 9846 §7.5 derives the exporter secret from this transcript,
    // the same one the application traffic secrets take, so it is
    // derived here rather than at a point of its own.
    ks_exp_master(h->master, hash, t->exp_master);
#endif
    finished[0] = HS_FINISHED;
    finished[1] = 0;
    finished[2] = 0;
    finished[3] = SHA256_LEN;
    ks_verify_data(h->c_hs, hash, finished + 4);
    sha256_update(&t->transcript, finished, HSF_FINISHED_LEN);
    (void)hsr_transcript_hash(h, hash);
    ks_res_master(h->master, hash, t->res_master);
}
