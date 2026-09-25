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
#include "keylog.h"
#include "keysched.h"
#include "rand.h"
#include "srv_kex.h"
#include "srv_message.h"
#include "srv_out.h"
#include "srv_resume.h"
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
    transcript_init(&h->t->transcript);
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
    if (ch->truncated_len != 0) {
        // The transcript a binder covers: everything before this message,
        // then this message up to its binders list (rfc9846.txt:2591-2598).
        transcript_hash_after(&t->transcript, SHA256_LEN, raw, 4 + ch->truncated_len,
                              ch->binder_hash);
#ifdef CH_HASH_SHA384
        transcript_hash_after(&t->transcript, SHA384_LEN, raw, 4 + ch->truncated_len,
                              ch->binder_hash_sha384);
#endif
    }
    transcript_update(&t->transcript, raw, raw_len);
    copy_hello_fields(t, ch);
    if (t->cfg.srv.require_server_name && t->sni_len == 0) {
        // §9.2 permits requiring the extension (rfc9846.txt:4609-4612),
        // and §6.2 describes missing_extension as the answer here.
        h->alert = ALERT_MISSING_EXTENSION;
        return CH_EPROTO;
    }
    return CH_OK;
}

// Whether RFC 7301 §3.2's fatal case holds, term by term in srv_flight.h.
static int alpn_mismatch(const ch_cfg *cfg, const client_hello *ch) {
    return cfg->alpn_count != 0 && (ch->seen & SRV_EXT_ALPN) != 0 &&
           ch->alpn_selected == CH_ALPN_NONE;
}

// The default order: ChaCha20, constant time by construction, before
// AES-GCM, constant time because the build asserted this part's
// instructions are (ct.h, INV-26); AES-128-GCM before AES-256-GCM,
// because the handshake proofs cover SHA-256 (docs/decisions.md 58). A
// build without CH_SUITE_AES_GCM holds no AES suite, so srv_suite_bit
// answers 0 for both and the walk below passes over them.
static const uint16_t default_suites[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                          SUITE_AES_256_GCM_SHA384};

// The first suite in cfg.srv.cipher_suites, or in the order above when
// that is unset, that the client offered; 0 when there is none.
static uint16_t select_suite(const ch_cfg *cfg, uint8_t offered) {
#ifdef CH_SUITE_AES_GCM
    if (cfg->srv.cipher_suites != NULL) {
        return srv_first_offered_suite(cfg->srv.cipher_suites, cfg->srv.cipher_suite_count,
                                       offered);
    }
#else
    (void)cfg;
#endif
    return srv_first_offered_suite(default_suites, sizeof default_suites / sizeof default_suites[0],
                                   offered);
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    memset(sel, 0, sizeof *sel);
    h->alert = ALERT_HANDSHAKE_FAILURE;
    sel->suite = select_suite(&h->t->cfg, ch->suites);
    if (sel->suite == 0) {
        return CH_EPROTO;
    }
    sel->hash_len = (uint8_t)suite_hash_len(sel->suite); // rfc9846.txt:4055-4056
    // The hybrid whenever the client listed it, x25519 otherwise
    // (srv_kex.h). A hello that listed neither has no group in common.
    sel->group = srv_kex_group(ch);
    if (sel->group == 0) {
        return CH_EPROTO;
    }
    // A hello with no scheme a slot signs can still resume a ticket, and
    // only srv_select_auth can tell, so only a hello that offers no PSK
    // fails here.
    sel->sigalg = srv_select_sigalg(&h->t->cfg, ch->sigalgs);
    if (sel->sigalg == 0 && (ch->seen & SRV_EXT_PRE_SHARED_KEY) == 0) {
        return CH_EPROTO;
    }
    if (alpn_mismatch(&h->t->cfg, ch)) {
        h->alert = ALERT_NO_APPLICATION_PROTOCOL;
        return CH_EPROTO;
    }
    // Both halves of §4.2.1's retry condition: the group is one this
    // build holds, and no KeyShareEntry arrived for it. A retry defers the
    // ticket to the second hello, whose binders cover the retry.
    sel->need_retry = !srv_kex_shared(ch, sel->group);
    return sel->need_retry ? CH_OK : srv_select_auth(h, ch, sel);
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    uint8_t ch1[SRV_COOKIE_HASH_MAX];
    (void)hsr_transcript_hash(h, sel->hash_len, ch1);
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
    // §4.4.1's synthetic message over the first ClientHello, at the
    // selected suite's hash, and then the retry itself.
    hsr_restart_transcript(h, sel->hash_len, msg, n);
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
    // The driver's own output, never cfg.send: INV-28 holds this record too.
    return srv_out_record(h->t, rec, n);
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
    // srv_cookie_open refused a suite this build does not hold, so the
    // suite needs no second check here: it is whichever one srv_select
    // chose for the first hello, AES-GCM included.
    if (srv_group_bit(group) == 0) {
        return CH_EPROTO;
    }
    if (!srv_kex_shared(ch, group)) {
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EPROTO;
    }
    // The frozen digest covers signature_algorithms, so this is the
    // scheme the first hello selected. The transcript needs nothing here:
    // srv_send_hello_retry_request replaced it and hashed the retry, and
    // srv_read_client_hello hashed this hello onto that.
    sel->suite = suite;
    sel->hash_len = (uint8_t)hash_len;
    sel->group = group;
    sel->sigalg = srv_select_sigalg(&h->t->cfg, ch->sigalgs);
    sel->need_retry = 0;
    return srv_select_auth(h, ch, sel);
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    // The share first: for the hybrid it is an encapsulation that refuses
    // an encapsulation key FIPS 203 §7.2 rejects, and a refused hello
    // needs no random value.
    uint8_t share[SRV_KEX_SHARE_MAX];
    size_t share_len = 0;
    if (srv_kex_share(h, ch, sel->group, share, &share_len) != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    uint8_t random32[SRV_RANDOM];
    ch_rand_bytes(random32, sizeof random32);
    assert_drawn(random32, sizeof random32);
    uint8_t *msg = t->tx + SRV_OUT_STAGE;
    size_t n = srv_build_server_hello(msg, sizeof t->tx - SRV_OUT_STAGE, sel, random32,
                                      ch->session_id, ch->session_id_len, share, share_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    transcript_update(&t->transcript, msg, n);
    return srv_out_plain(h, n);
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    ch_tls *t = h->t;
    // srv_kex_secret wipes the key exchange's inputs on both exits, and
    // ikm itself on the refusal.
    uint8_t ikm[SRV_KEX_SECRET_MAX];
    size_t ikm_len = 0;
    if (srv_kex_secret(h, ch, sel->group, ikm, &ikm_len) != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    // A selected ticket left its early secret in h->early. With none, the
    // early secret extracts from a hash-length zero string (RFC 9846 §7.1)
    // and the binder key is never used.
    size_t hash_len = sel->hash_len;
    if (!sel->psk_selected) {
        static const uint8_t no_psk[HKDF_HASH_MAX] = {0};
        uint8_t binder_key[HKDF_HASH_MAX];
        ks_early(hash_len, no_psk, hash_len, 0, h->early, binder_key);
        ct_wipe(binder_key, sizeof binder_key);
    }

    uint8_t hash[HKDF_HASH_MAX];
    (void)hsr_transcript_hash(h, hash_len, hash);
    ks_handshake(hash_len, h->early, ikm, ikm_len, hash, h->handshake_secret, h->c_hs, h->s_hs);
    ct_wipe(ikm, sizeof ikm);
    ct_wipe(h->early, sizeof h->early);
#ifdef CH_KEYLOG
    memcpy(h->client_random, ch->random, sizeof h->client_random);
    ch_keylog(h->t->cfg.io, CH_KEYLOG_CLIENT_HANDSHAKE, h->client_random, h->c_hs, hash_len);
    ch_keylog(h->t->cfg.io, CH_KEYLOG_SERVER_HANDSHAKE, h->client_random, h->s_hs, hash_len);
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
    REC_DIR_INIT_SUITE(&t->rd, h->c_hs, sel->suite);
    REC_DIR_INIT_SUITE(&t->wr, h->s_hs, sel->suite);
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
    transcript_update(&t->transcript, msg, n);
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
    uint8_t hash[HKDF_HASH_MAX];
    (void)hsr_transcript_hash(h, sel->hash_len, hash);
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
    transcript_update(&h->t->transcript, msg, n);
    return srv_out_sealed(h, msg, n);
}

int srv_send_finished(handshake_state *h) {
    ch_tls *t = h->t;
    size_t hash_len = t->hash_len;
    uint8_t hash[HKDF_HASH_MAX];
    (void)hsr_transcript_hash(h, hash_len, hash);
    uint8_t verify_data[HKDF_HASH_MAX];
    ks_verify_data(hash_len, h->s_hs, hash, verify_data);
    uint8_t msg[SRV_FINISHED_MAX];
    size_t n = srv_build_finished(msg, sizeof msg, verify_data, hash_len);
    CH_ASSERT(n == 4 + hash_len);
    transcript_update(&t->transcript, msg, n);
    int rc = srv_out_sealed(h, msg, n);
    if (rc != CH_OK) {
        return rc;
    }
    // ks_master writes the client secret first, which is what this
    // endpoint reads. Only the write direction advances here: the client
    // Finished still arrives under the handshake key.
    (void)hsr_transcript_hash(h, hash_len, hash);
    ks_master(hash_len, h->handshake_secret, hash, h->master, t->rd_secret, t->wr_secret);
#ifdef CH_EXPORTER
    // The client's derivation, mirrored: RFC 9846 §7.5 takes the same
    // transcript the traffic secrets above take.
    ks_exp_master(hash_len, h->master, hash, t->exp_master);
#endif
#ifdef CH_KEYLOG
    // The reverse of the client's pair: here rd_secret holds the client's
    // application secret and wr_secret this server's.
    ch_keylog(t->cfg.io, CH_KEYLOG_CLIENT_TRAFFIC, h->client_random, t->rd_secret, hash_len);
    ch_keylog(t->cfg.io, CH_KEYLOG_SERVER_TRAFFIC, h->client_random, t->wr_secret, hash_len);
#endif
#ifndef CH_TRANSPORT_QUIC
    REC_DIR_INIT_SUITE(&t->wr, t->wr_secret, t->suite);
#endif
    return CH_OK;
}

int srv_read_client_finished(handshake_state *h) {
    ch_tls *t = h->t;
    size_t hash_len = t->hash_len;
    uint8_t hash[HKDF_HASH_MAX];
    (void)hsr_transcript_hash(h, hash_len, hash);
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
    if (type != HS_FINISHED || raw_len != 4 + hash_len) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    uint8_t want[HKDF_HASH_MAX];
    ks_verify_data(hash_len, h->c_hs, hash, want);
    if (!ct_memeq(want, raw + 4, hash_len)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    transcript_update(&t->transcript, raw, raw_len);
    return CH_OK;
}

void srv_complete(handshake_state *h) {
    ch_tls *t = h->t;
#ifndef CH_TRANSPORT_QUIC
    // Over QUIC the read direction becomes a 1-RTT packet key set, which
    // the driver installs from t->rd_secret with the other three.
    REC_DIR_INIT_SUITE(&t->rd, t->rd_secret, t->suite);
#endif
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
}

#endif // CH_ROLE_SERVER
