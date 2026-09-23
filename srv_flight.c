// The server's flight handlers, one function per handshake message.
// srv_flight.h states every contract, every alert and the RFC line
// behind each one, so the comments here say what the header does not:
// how a message is staged and why a step sits where it does. A message
// sent in the clear is staged at t->tx + SRV_OUT_STAGE and goes out through
// srv_out_plain; a protected one is staged on the handler's own
// frame and goes out through srv_out_sealed; the Certificate is the one
// message no frame holds, so srv_frag streams it. srv_out.[ch] owns all
// three and is where the two transports differ.
#include "srv_flight.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "io.h"
#include "keylog.h"
#include "keysched.h"
#include "rand.h"
#include "srv_message.h"
#include "srv_out.h"
#include "x25519.h"

// Holds ch_rand_bytes to rand.h's contract: the caller zeroed what this
// fills, so an all-zero draw is a hook that returned without writing.
static void assert_drawn(const uint8_t *p, size_t n) {
    static const uint8_t unwritten[SRV_RANDOM] = {0};
    CH_ASSERT(n <= sizeof unwritten && !ct_memeq(p, unwritten, n));
}

void srv_begin(handshake_state *h) {
    ch_rand_bytes(h->priv, sizeof h->priv);
    assert_drawn(h->priv, sizeof h->priv);
    x25519_base(h->pub, h->priv);
    sha256_init(&h->t->transcript);
}

// Copies the two values the session keeps past the hello, which sits in
// a buffer the next record overwrites.
static void copy_hello_fields(ch_tls *t, const client_hello *ch) {
    t->session_id_len = ch->session_id_len;
    memcpy(t->session_id, ch->session_id, ch->session_id_len);
    t->sni_len = 0;
    if (ch->server_name == NULL || t->cfg.srv.sni_buf == NULL ||
        ch->server_name_len > t->cfg.srv.sni_cap) {
        return;
    }
    memcpy(t->cfg.srv.sni_buf, ch->server_name, ch->server_name_len);
    t->sni_len = ch->server_name_len;
}

int srv_read_client_hello(handshake_state *h, client_hello *ch) {
    ch_tls *t = h->t;
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        // Only a message past the caller's buffer carries no alert.
        if (rc == CH_ECAP) {
            h->alert = ALERT_INTERNAL_ERROR;
        }
        return rc;
    }
    if (type != HS_CLIENT_HELLO) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    memset(ch, 0, sizeof *ch);
    // The parser overwrites this on every refusal it makes.
    h->alert = ALERT_DECODE_ERROR;
    rc = srv_parse_client_hello(raw + 4, raw_len - 4, ch, t->cfg.alpn_protocols, t->cfg.alpn_count,
                                &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
    sha256_update(&t->transcript, raw, raw_len);
    copy_hello_fields(t, ch);
    if (t->cfg.srv.require_server_name && t->sni_len == 0) {
        // §9.2 permits requiring the extension (rfc9846.txt:4609-4612),
        // and §6.2 describes missing_extension as the answer here.
        h->alert = ALERT_MISSING_EXTENSION;
        return CH_EPROTO;
    }
    return CH_OK;
}

// The scheme this connection signs with: the first in docs/server.md's
// order, ECDSA then RSA-PSS, that the client offered and a slot signs.
static uint16_t select_sigalg(const ch_cfg *cfg, uint8_t offered) {
    uint8_t live = srv_identity_live(cfg);
    if ((offered & SRV_SIGALG_ECDSA_P256) != 0 && (live & SRV_IDENTITY_ECDSA_P256) != 0) {
        return SIGALG_ECDSA_P256_SHA256;
    }
    if ((offered & SRV_SIGALG_RSA_PSS) != 0 && (live & SRV_IDENTITY_RSA_PSS) != 0) {
        return SIGALG_RSA_PSS_RSAE_SHA256;
    }
    return 0;
}

// Whether RFC 7301 §3.2's fatal case holds, term by term in srv_flight.h.
static int alpn_mismatch(const ch_cfg *cfg, const client_hello *ch) {
    return cfg->alpn_count != 0 && (ch->seen & SRV_EXT_ALPN) != 0 &&
           ch->alpn_selected == CH_ALPN_NONE;
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    memset(sel, 0, sizeof *sel);
    h->alert = ALERT_HANDSHAKE_FAILURE;
#ifdef CH_SUITE_AES_GCM
    // ChaCha20-Poly1305 first, and AES-GCM only when the client offers no
    // ChaCha20. Both meet the profile, and the order is not about speed:
    // ChaCha20 is constant time by construction here, while AES is
    // constant time because the build asserted that this part's
    // instructions are (ct.h, INV-26). Preferring the one that needs no
    // assertion costs a client that offers both nothing it asked for.
    if ((ch->suites & SRV_SUITE_CHACHA20_POLY1305) != 0) {
        sel->suite = SUITE_CHACHA20_POLY1305_SHA256;
    } else if ((ch->suites & SRV_SUITE_AES_128_GCM) != 0) {
        sel->suite = SUITE_AES_128_GCM_SHA256;
    } else {
        return CH_EPROTO;
    }
    // Both suites hash with SHA-256, so the key schedule needs no hash
    // agility. TLS_AES_256_GCM_SHA384 would need it, which is one reason
    // this build does not offer it.
    sel->hash_len = SHA256_LEN;
#else
    if ((ch->suites & SRV_SUITE_CHACHA20_POLY1305) == 0) {
        return CH_EPROTO;
    }
    sel->suite = SUITE_CHACHA20_POLY1305_SHA256;
    sel->hash_len = SHA256_LEN;
#endif
    if ((ch->groups & SRV_GROUP_KEX) == 0) {
        return CH_EPROTO;
    }
    sel->group = CH_KEX_GROUP;
    sel->sigalg = select_sigalg(&h->t->cfg, ch->sigalgs);
    if (sel->sigalg == 0) {
        return CH_EPROTO;
    }
    if (alpn_mismatch(&h->t->cfg, ch)) {
        h->alert = ALERT_NO_APPLICATION_PROTOCOL;
        return CH_EPROTO;
    }
    // Both halves of §4.1.1's retry condition: the group is one this
    // build holds, and no KeyShareEntry arrived for it.
    sel->need_retry = (ch->shares & SRV_GROUP_KEX) == 0;
    return CH_OK;
}

// Replaces the transcript with §4.4.1's synthetic construction over the
// first ClientHello and hashes the HelloRetryRequest after it. It is
// handshake_flight.c's hrr_transcript with the server's own bytes in
// raw, a copy docs/server.md owes a move.
static void hrr_transcript(handshake_state *h, const uint8_t *raw, size_t raw_len) {
    sha256 *transcript = &h->t->transcript;
    uint8_t ch1[SHA256_LEN];
    sha256_final(transcript, ch1);
    sha256_init(transcript);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    sha256_update(transcript, synth, sizeof synth);
    sha256_update(transcript, ch1, sizeof ch1);
    sha256_update(transcript, raw, raw_len);
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    // The transcript this build runs is SHA-256, so a selection naming
    // another length would make srv_cookie_mint read past ch1.
    CH_ASSERT(sel->hash_len == SHA256_LEN);
    uint8_t ch1[SHA256_LEN];
    (void)hsr_transcript_hash(h, ch1);
    size_t cookie_len = srv_cookie_mint(t->cfg.srv.cookie_key, sel->suite, sel->group, ch1,
                                        sel->hash_len, ch->frozen, h->cookie, sizeof h->cookie);
    if (cookie_len == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    h->cookie_len = cookie_len;
    uint8_t *msg = t->tx + SRV_OUT_STAGE;
    size_t n = srv_build_hello_retry_request(msg, sizeof t->tx - SRV_OUT_STAGE, sel, ch->session_id,
                                             ch->session_id_len, h->cookie, cookie_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    hrr_transcript(h, msg, n);
    t->hrr_sent = 1;
    return srv_out_plain(h, n);
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 section 8.4 forbids a QUIC client from requesting
    // compatibility mode and makes a ChangeCipherSpec a connection error
    // (rfc9001.txt:1976-1979), so a QUIC server sends none. The call stays
    // in the flight rather than disappearing from it, because the two
    // drivers otherwise read differently for a message neither sends.
    (void)h;
    (void)ch;
    return CH_OK;
#else
    if (ch->session_id_len == 0) {
        return CH_OK;
    }
    uint8_t rec[SRV_CCS_RECORD_LEN];
    size_t n = srv_build_compat_ccs(rec, sizeof rec);
    CH_ASSERT(n == SRV_CCS_RECORD_LEN);
    h->t->compat_ccs = 1;
    return io_send_all(&h->t->cfg, rec, n);
#endif
}

int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel) {
    h->alert = ALERT_ILLEGAL_PARAMETER;
    if (ch->cookie == NULL || (ch->seen & SRV_EXT_EARLY_DATA) != 0) {
        return CH_EPROTO;
    }
    uint16_t suite = 0;
    uint16_t group = 0;
    size_t hash_len = 0;
    uint8_t ch1_hash[SRV_COOKIE_HASH_MAX];
    uint8_t frozen[SHA256_LEN];
    if (srv_cookie_open(h->t->cfg.srv.cookie_key, ch->cookie, ch->cookie_len, &suite, &group,
                        ch1_hash, &hash_len, frozen) != CH_OK) {
        return CH_EPROTO;
    }
    // Compared over all SHA256_LEN bytes, so a client cannot search for a
    // match one byte per round trip.
    if (!ct_memeq(frozen, ch->frozen, sizeof frozen)) {
        return CH_EPROTO;
    }
    if (suite != SUITE_CHACHA20_POLY1305_SHA256 || group != CH_KEX_GROUP) {
        return CH_EPROTO;
    }
    if ((ch->shares & SRV_GROUP_KEX) == 0) {
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EPROTO;
    }
    // sigalg stays as the first hello selected it, because the frozen
    // digest covers signature_algorithms. The transcript needs nothing
    // here: srv_send_hello_retry_request replaced it and hashed the
    // retry, and srv_read_client_hello hashed this hello onto that.
    sel->suite = suite;
    sel->hash_len = (uint8_t)hash_len;
    sel->group = group;
    sel->need_retry = 0;
    return CH_OK;
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    uint8_t random32[SRV_RANDOM];
    ch_rand_bytes(random32, sizeof random32);
    assert_drawn(random32, sizeof random32);
    uint8_t *msg = t->tx + SRV_OUT_STAGE;
    size_t n = srv_build_server_hello(msg, sizeof t->tx - SRV_OUT_STAGE, sel, random32,
                                      ch->session_id, ch->session_id_len, h->pub, sizeof h->pub);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    sha256_update(&t->transcript, msg, n);
    return srv_out_plain(h, n);
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    (void)sel; // the suite fixes the schedule, and this build holds one
    // srv_parser.h refuses a KeyShareEntry for this group at any other
    // length, and this call is reached only after a hello that carried
    // one, so a missing share is a call-order bug and not peer input.
    CH_ASSERT(ch->share != NULL && ch->share_len == CH_KEX_CLIENT_SHARE);
    uint8_t ecdhe[X25519_LEN];
    int shared_ok = x25519(ecdhe, h->priv, ch->share) != 0;
    ct_wipe(h->priv, sizeof h->priv);
    ct_wipe(h->pub, sizeof h->pub);
    if (!shared_ok) {
        ct_wipe(ecdhe, sizeof ecdhe);
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    // No PSK: the early secret extracts from a hash-length zero string
    // (RFC 9846 §7.1) and the binder key is never used.
    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t binder_key[SHA256_LEN];
    ks_early(no_psk, sizeof no_psk, 0, h->early, binder_key);
    ct_wipe(binder_key, sizeof binder_key);

    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    ks_handshake(h->early, ecdhe, sizeof ecdhe, hash, h->handshake_secret, h->c_hs, h->s_hs);
    ct_wipe(ecdhe, sizeof ecdhe);
    ct_wipe(h->early, sizeof h->early);
#ifdef CH_KEYLOG
    memcpy(h->client_random, ch->random, sizeof h->client_random);
    ch_keylog(h->t->cfg.io, CH_KEYLOG_CLIENT_HANDSHAKE, h->client_random, h->c_hs);
    ch_keylog(h->t->cfg.io, CH_KEYLOG_SERVER_HANDSHAKE, h->client_random, h->s_hs);
#endif
    // The client secret protects what this endpoint reads and the server
    // secret what it writes, the reverse of handshake.c:94-95 and the
    // whole of the asymmetry.
#ifdef CH_TRANSPORT_QUIC
    // No record layer to key. The two secrets stay in h->c_hs and h->s_hs
    // and the driver turns them into the Handshake level's packet and
    // header protection keys, which is where quic_step.c's client puts the
    // same step (RFC 9001 section 5.4, rfc9001.txt:1172-1174).
    (void)t;
#else
    rec_dir_init(&t->rd, h->c_hs);
    rec_dir_init(&t->wr, h->s_hs);
    h->encrypted = 1;
    t->keys = 1; // alerts encrypt from here on
#endif
    return CH_OK;
}

int srv_send_encrypted_extensions(handshake_state *h, const selection *sel) {
    ch_tls *t = h->t;
    (void)sel; // this message carries nothing the selection decides
    // The protocol the parser selected out of the caller's list, which
    // srv_handshake.c copied onto the session before this call, or none.
    const ch_alpn_protocol *selected = NULL;
    if (t->alpn_selected != CH_ALPN_NONE) {
        selected = &t->cfg.alpn_protocols[t->alpn_selected];
    }
    uint8_t msg[SRV_ENCRYPTED_EXTENSIONS_MAX];
    // No quic_transport_parameters body on this arm. RFC 9001 §8.2
    // forbids the extension on a transport that is not QUIC
    // (rfc9001.txt:1945-1949), and this arm is the record transport. The
    // QUIC arm below passes the caller's body.
#ifdef CH_TRANSPORT_QUIC
    // RFC 9001 section 4.1.3 removes the record layer record_size_limit
    // sizes, and section 8.2 requires the transport parameters extension
    // in its place (rfc9001.txt:1922-1924). The body is the caller's and
    // travels unread.
    size_t n = srv_build_encrypted_extensions(msg, sizeof msg, 0, selected, t->cfg.transport_params,
                                              t->cfg.transport_params_len);
#else
    size_t n =
        srv_build_encrypted_extensions(msg, sizeof msg, h->record_size_limit, selected, NULL, 0);
#endif
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    sha256_update(&t->transcript, msg, n);
    return srv_out_sealed(h, msg, n);
}

int srv_send_certificate(handshake_state *h, const selection *sel) {
    const ch_identity *id = srv_identity_for(&h->t->cfg, sel->sigalg);
    if (id == NULL) {
        h->alert = ALERT_INTERNAL_ERROR; // ch_srv_check should have caught this at boot
        return CH_EINVAL;
    }
    // One buffer for all three fixed pieces: each is streamed before the
    // next is written, and the head is the longest.
    uint8_t frame[SRV_CERT_HEAD_LEN];
    srv_frag f;
    f.h = h;
    f.len = 0;
    f.rc = CH_OK;
    size_t n = srv_build_certificate_header(frame, sizeof frame, id);
    CH_ASSERT(n == SRV_CERT_HEAD_LEN);
    srv_frag_bytes(&f, frame, n);
    for (uint8_t i = 0; i < id->chain_count; i++) {
        n = srv_build_certificate_entry_prefix(frame, sizeof frame, id->chain[i].len);
        if (n == 0) {
            // A certificate past the three-byte cert_data field names no
            // message this server can write.
            h->alert = ALERT_INTERNAL_ERROR;
            return CH_EINVAL;
        }
        srv_frag_bytes(&f, frame, n);
        srv_frag_bytes(&f, id->chain[i].der, id->chain[i].len);
        n = srv_build_certificate_entry_suffix(frame, sizeof frame);
        CH_ASSERT(n == SRV_CERT_SUFFIX_LEN);
        srv_frag_bytes(&f, frame, n);
    }
    srv_frag_flush(&f);
    return f.rc;
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t sig[SRV_SIG_MAX];
    size_t sig_len = 0;
    // srv_auth.h has the signer write the alert on each refusal, so this
    // handler carries the return code out and sets no alert of its own.
    int rc = srv_sign_certificate_verify(&h->t->cfg, sel->sigalg, hash, sel->hash_len, sig,
                                         sizeof sig, &sig_len, &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
    uint8_t msg[SRV_CERT_VERIFY_MAX];
    size_t n = srv_build_certificate_verify(msg, sizeof msg, sel->sigalg, sig, sig_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    sha256_update(&h->t->transcript, msg, n);
    return srv_out_sealed(h, msg, n);
}

int srv_send_finished(handshake_state *h) {
    ch_tls *t = h->t;
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t verify_data[SHA256_LEN];
    ks_verify_data(h->s_hs, hash, verify_data);
    uint8_t msg[SRV_FINISHED_MAX];
    size_t n = srv_build_finished(msg, sizeof msg, verify_data, sizeof verify_data);
    CH_ASSERT(n == sizeof msg);
    sha256_update(&t->transcript, msg, n);
    int rc = srv_out_sealed(h, msg, n);
    if (rc != CH_OK) {
        return rc;
    }
    // ks_master writes the client secret first, which is what this
    // endpoint reads. Only the write direction advances here: the client
    // Finished still arrives under the handshake key.
    (void)hsr_transcript_hash(h, hash);
    ks_master(h->handshake_secret, hash, h->master, t->rd_secret, t->wr_secret);
#ifdef CH_EXPORTER
    // The client's derivation, mirrored: RFC 9846 §7.5 takes the same
    // transcript the traffic secrets above take.
    ks_exp_master(h->master, hash, t->exp_master);
#endif
#ifdef CH_KEYLOG
    // The reverse of the client's pair: here rd_secret holds the client's
    // application secret and wr_secret this server's.
    ch_keylog(t->cfg.io, CH_KEYLOG_CLIENT_TRAFFIC, h->client_random, t->rd_secret);
    ch_keylog(t->cfg.io, CH_KEYLOG_SERVER_TRAFFIC, h->client_random, t->wr_secret);
#endif
#ifndef CH_TRANSPORT_QUIC
    rec_dir_init(&t->wr, t->wr_secret);
#endif
    return CH_OK;
}

int srv_read_client_finished(handshake_state *h) {
    ch_tls *t = h->t;
    CH_ASSERT(t->hash_len == SHA256_LEN);
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        if (rc == CH_ECAP) {
            h->alert = ALERT_INTERNAL_ERROR;
        }
        return rc;
    }
    if (type != HS_FINISHED || raw_len != (size_t)4 + t->hash_len) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    uint8_t want[SHA256_LEN];
    ks_verify_data(h->c_hs, hash, want);
    if (!ct_memeq(want, raw + 4, sizeof want)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sha256_update(&t->transcript, raw, raw_len);
    return CH_OK;
}

void srv_complete(handshake_state *h) {
    ch_tls *t = h->t;
#ifndef CH_TRANSPORT_QUIC
    // Over QUIC the read direction becomes a 1-RTT packet key set, which
    // the driver installs from t->rd_secret with the other three.
    rec_dir_init(&t->rd, t->rd_secret);
#endif
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
}

#endif // CH_ROLE_SERVER
