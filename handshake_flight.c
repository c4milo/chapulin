// The client's flight handlers, one function per handshake message.
// Both transports compile this file: handshake.c calls these in one
// straight line and quic_step.c calls them one per step, so no protocol
// rule exists twice. Contract in handshake_flight.h.
#include "handshake_flight.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"
#include "keylog.h"
#include "keysched.h"
#include "rand.h"
#include "x25519.h"
#ifdef CH_TRUST_WEBPKI
#include "webpki_pin.h"
#endif

// The early secret with no PSK: HKDF-Extract over 32 zero bytes (RFC
// 9846 §7.1, rfc9846.txt:4172-4175). The binder key ks_early also derives
// is never used, so it is wiped here.
static void early_secret_without_psk(uint8_t early[SHA256_LEN]) {
    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t unused_binder_key[SHA256_LEN];
    ks_early(no_psk, sizeof no_psk, 0, early, unused_binder_key);
    ct_wipe(unused_binder_key, sizeof unused_binder_key);
}

void hsf_begin(handshake_state *h) {
    ch_tls *t = h->t;
    ch_rand_bytes(h->priv, sizeof h->priv);
    ch_rand_bytes(h->random, sizeof h->random);
#ifdef CH_KEX_HYBRID
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
#ifdef CH_KEX_HYBRID
        CH_ASSERT(!ct_memeq(h->dz, unwritten, 32));
        CH_ASSERT(!ct_memeq(h->dz + 32, unwritten, 32));
#endif
    }
    x25519_base(h->pub, h->priv);
    if (t->cfg.psk != NULL) {
        ks_early(t->cfg.psk, t->cfg.psk_len, t->cfg.resumption, h->early, h->binder_key);
    } else {
        // No PSK: h->binder_key stays the zero the caller wrote.
        early_secret_without_psk(h->early);
    }
    sha256_init(&t->transcript);
}

// Builds the ClientHello (echoing an HRR cookie on the retry), computes
// the binder over the transcript-so-far plus the truncated message, and
// adds the message to the transcript. A build that offers the hybrid
// calls this through hsf_build_client_hello below, which expands the
// stored seed and hands the ek slice in.
#ifdef CH_KEX_HYBRID
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
#ifdef CH_KEX_HYBRID
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

#ifdef CH_KEX_HYBRID
// Expands the stored (d, z) seed into the FIPS 203 dk layout and hands
// its ek slice to the builder. The expansion is deterministic, so the
// HRR retry resends the identical share; the dk itself is scratch —
// hsf_derive_handshake_secrets re-expands the same way at
// decapsulation. The 2400-byte buffer gets its own frame so it is gone
// before the handshake reads a record; the frame itself is over the
// classic build's budget, which is why a build that offers the hybrid
// carries its own (docs/invariants.md INV-19).
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
// message sits between the parse and this. The seed h->dz is wiped as
// soon as the dk is expanded from it, its last use. Decapsulation cannot
// fail (a tampered ciphertext yields the implicit-reject secret); the
// x25519 all-zero refusal stays, and on it the half-built secret is
// wiped.
static int hybrid_secret(handshake_state *h, const server_hello_info *info,
                         uint8_t ikm[MLKEM_SS_LEN + X25519_LEN]) {
    uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, h->dz, h->dz + 32);
    ct_wipe(h->dz, sizeof h->dz);
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

#ifdef CH_KEX_TWO_GROUPS
// Runs x25519 alone into ikm, for a ServerHello that selected x25519.
// The ML-KEM key pair the hello offered beside it goes unused, so its
// seed h->dz is wiped before the exchange runs rather than kept until
// the handshake ends. Returns CH_EPROTO for the all-zero shared secret,
// with ikm wiped, as hybrid_secret does.
static int x25519_secret(handshake_state *h, const server_hello_info *info,
                         uint8_t ikm[X25519_LEN]) {
    ct_wipe(h->dz, sizeof h->dz);
    if (!x25519(ikm, h->priv, info->server_pub)) {
        ct_wipe(ikm, X25519_LEN);
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

#ifdef CH_SUITE_AES_GCM
// Stores the suite a HelloRetryRequest or ServerHello named. The parser
// accepted it as one this client offered; what is left is RFC 9846
// §4.2.4's rule that the ServerHello repeat the retry's suite
// (rfc9846.txt:1489-1491). Returns CH_EPROTO when it does not, an
// illegal_parameter the caller writes.
static int take_suite(handshake_state *h, const server_hello_info *info) {
    if (!info->hrr && h->suite != 0 && info->suite != h->suite) {
        return CH_EPROTO;
    }
    h->suite = info->suite;
    return CH_OK;
}
#endif

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
#ifdef CH_SUITE_AES_GCM
    if (rc == CH_OK) {
        rc = take_suite(h, info);
    }
#endif
    if (rc != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return rc;
    }
    if (info->hrr) {
        hrr_transcript(h, raw, raw_len);
        // The parser refuses a retry that names a group, because every
        // group the hello lists already has a share in it, so a cookie
        // is the one change a retry can ask this client for. A retry
        // without one changes nothing, which RFC 9846 §4.2.4 makes an
        // illegal_parameter abort (rfc9846.txt:1467-1469).
        if (info->cookie_len == 0) {
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

#ifdef CH_TRUST_WEBPKI
// A ServerHello with no pre_shared_key declined the ticket, and a webpki
// hello offers the certificate path beside it, so the handshake goes on
// as a full one (docs/decisions.md 55): the PSK's early secret and binder
// key die here, and the early secret of no PSK replaces them
// (rfc9846.txt:4182-4185). A pre_shared_key naming any identity but 0 is
// no decline but an illegal_parameter abort (rfc9846.txt:2551-2557).
static int decline_psk(handshake_state *h, const server_hello_info *info) {
    if ((info->seen & HSP_SEEN_PRE_SHARED_KEY) != 0) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    ct_wipe(h->early, sizeof h->early);
    ct_wipe(h->binder_key, sizeof h->binder_key);
    early_secret_without_psk(h->early);
    return CH_OK;
}
#else
// A raw or ca hello offers the ticket alone, with no signature scheme
// beside it, so a server that did not select the ticket has no way to
// authenticate that this build can check, and the handshake fails closed.
static int decline_psk(handshake_state *h, const server_hello_info *info) {
    (void)info;
    h->alert = ALERT_HANDSHAKE_FAILURE;
    return CH_EAUTH;
}
#endif

int hsf_accept_server_hello(handshake_state *h, const server_hello_info *info) {
    // The group of the one key_share the parser accepted, or 0 when the
    // ServerHello carried none: the session reports it either way.
    h->t->group = info->group;
#ifdef CH_SUITE_AES_GCM
    h->t->suite = info->suite;
#endif
    if (!info->have_share) {
        // No ECDHE share: psk_dhe_ke is the one mode this client offers,
        // so there are no keys to continue under.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    int psk_offered = h->t->cfg.psk != NULL;
    if (psk_offered && !info->psk_ok) {
        int rc = decline_psk(h, info);
        if (rc != CH_OK) {
            return rc;
        }
    }
    h->t->psk_selected = (uint8_t)(psk_offered && info->psk_ok);
#ifdef CH_KEX_HYBRID
    // require_pq checks at run time what the hello promised: a raw or ca
    // KEX=pq build offers X25519MLKEM768 alone, and a CH_KEX_TWO_GROUPS
    // build under the flag lists and shares the hybrid alone, though its
    // parser still accepts x25519. The compare reads the field the parser
    // wrote, never the constant the build offered, and the alert is the
    // parser's own for a group the client did not offer (RFC 9846
    // §4.3.8). A classic build never runs this: ch_connect refuses the
    // flag there before it sends a byte.
    if (h->t->cfg.require_pq && h->t->group != CH_GROUP_X25519MLKEM768) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
#endif
    return CH_OK;
}

int hsf_derive_handshake_secrets(handshake_state *h, const server_hello_info *info) {
#ifdef CH_KEX_HYBRID
    uint8_t ecdhe[MLKEM_SS_LEN + X25519_LEN];
    size_t ecdhe_len = sizeof ecdhe;
#ifdef CH_KEX_TWO_GROUPS
    // A ServerHello that selected x25519 runs the classic exchange over
    // the x25519 half of the key pair hsf_begin drew, the value both key
    // shares carried, and the input keying material is its 32 bytes
    // alone.
    int shared_ok;
    if (info->group == CH_GROUP_X25519) {
        ecdhe_len = X25519_LEN;
        shared_ok = x25519_secret(h, info, ecdhe) == CH_OK;
    } else {
        shared_ok = hybrid_secret(h, info, ecdhe) == CH_OK;
    }
#else
    int shared_ok = hybrid_secret(h, info, ecdhe) == CH_OK;
#endif
#else
    uint8_t ecdhe[X25519_LEN];
    size_t ecdhe_len = sizeof ecdhe;
    int shared_ok = x25519(ecdhe, h->priv, info->server_pub) != 0;
#endif
    // The six values the exchange consumed. The TLS driver would wipe
    // them with its frame; the QUIC driver returns to its caller
    // between messages, so that wipe is a round trip away and they die
    // here instead. After this call the retry hello can no longer be
    // built, which is correct: the exchange is over.
#ifdef CH_KEYLOG
    // Kept before the wipe below, which is what the first key log build
    // missed: it logged h->random after this point and filed every line
    // under 32 zero bytes. bin/rec_loop_test compares the random both
    // ends log, so that shape now fails a test.
    memcpy(h->client_random, h->random, sizeof h->client_random);
#endif
    ct_wipe(h->priv, sizeof h->priv);
    ct_wipe(h->pub, sizeof h->pub);
    ct_wipe(h->random, sizeof h->random);
    if (!shared_ok) {
        ct_wipe(h->early, sizeof h->early);
        ct_wipe(h->binder_key, sizeof h->binder_key);
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    ks_handshake(h->early, ecdhe, ecdhe_len, hash, h->handshake_secret, h->c_hs, h->s_hs);
    ct_wipe(ecdhe, sizeof ecdhe);
    ct_wipe(h->early, sizeof h->early);
    ct_wipe(h->binder_key, sizeof h->binder_key);
#ifdef CH_KEYLOG
    ch_keylog(h->t->cfg.io, CH_KEYLOG_CLIENT_HANDSHAKE, h->client_random, h->c_hs);
    ch_keylog(h->t->cfg.io, CH_KEYLOG_SERVER_HANDSHAKE, h->client_random, h->s_hs);
#endif
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
#ifdef CH_TRUST_WEBPKI
    // A server that sends no server_certificate_type sends X.509
    // certificates (RFC 9846 §4.5.1), so that is the type the session
    // reports unless the parser writes the one the server selected.
    // handshake_auth.c reads it to tell a raw key from a chain.
    t->server_cert_type = CH_CERT_TYPE_X509;
#endif
    // Seed the default first: the parser overrides it only when it has a
    // more specific alert (unsupported_extension, RFC 9846 §4.3, and in a
    // TRUST=webpki build decode_error for a server_name or a
    // server_certificate_type of the wrong length), and that override
    // must survive to the wire.
    h->alert = ALERT_ILLEGAL_PARAMETER;
    rc = hsp_parse_encrypted_exts(
#ifdef CH_TRANSPORT_QUIC
        raw + 4, raw_len - 4, &peer_limit, t->cfg.alpn_protocols, t->cfg.alpn_count,
        &t->alpn_selected,
#ifdef CH_TRUST_WEBPKI
        t->cfg.hostname_len > 0, webpki_cert_types_offered(&t->cfg), &t->server_cert_type,
#endif
        &transport_params, &transport_params_len,
#elif defined(CH_TRUST_WEBPKI)
        raw + 4, raw_len - 4, &t->peer_limit, t->cfg.alpn_protocols, t->cfg.alpn_count,
        &t->alpn_selected, t->cfg.hostname_len > 0, webpki_cert_types_offered(&t->cfg),
        &t->server_cert_type,
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
        // Certificates where none belong: a server that selected the PSK
        // (RFC 9846 §2.2), or one demanding client auth we cannot do.
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
#ifdef CH_KEYLOG
    // After ks_master, which wrote this client's write secret into
    // wr_secret and the server's into rd_secret.
    ch_keylog(t->cfg.io, CH_KEYLOG_CLIENT_TRAFFIC, h->client_random, t->wr_secret);
    ch_keylog(t->cfg.io, CH_KEYLOG_SERVER_TRAFFIC, h->client_random, t->rd_secret);
#endif
}
