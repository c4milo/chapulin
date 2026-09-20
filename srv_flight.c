// The server's flight handlers, one function per handshake message.
// srv_flight.h states every contract, every alert and the RFC line
// behind each one, so the comments here say what the header does not:
// how a message is staged and why a step sits where it does. A message
// sent in the clear is staged at t->tx + REC_HDR and goes out through
// send_plain_record; a protected one is staged on the handler's own
// frame and goes out through send_sealed; the Certificate is the one
// message no frame holds, so frag_writer streams it.
#include "srv_flight.h"

#ifdef CH_ROLE_SERVER

// The hybrid key exchange has no server half here, for two structural
// reasons. handshake_state gives the server's share h->pub, which is
// X25519_LEN bytes against CH_KEX_SERVER_SHARE's 1120 under KEX=pq. And
// that share's ML-KEM half is a ciphertext under the client's
// encapsulation key, which srv_begin has not read where srv_flight.h
// draws the server's secrets. Open question ten leaves the pair open.
#ifdef CH_KEX_PQ
#error "ROLE=server has no KEX=pq half yet (docs/server.md, open question ten); use KEX=x25519"
#endif

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "io.h"
#include "keysched.h"
#include "rand.h"
#include "record.h"
#include "srv_message.h"
#include "x25519.h"

// The lengths srv_message.h fixes and this file stages against: a 4-byte
// header over the scheme, the signature length and a signature of at
// most SRV_SIG_MAX bytes; the header over one verify_data; a header, an
// empty extension block, record_size_limit and ALPN at this API's
// longest name; and a Certificate's head and one entry's suffix.
#define SRV_CERT_VERIFY_MAX (4 + 2 + 2 + SRV_SIG_MAX)
#define SRV_FINISHED_MAX (4 + SHA256_LEN)
#define SRV_ENCRYPTED_EXTENSIONS_MAX (6 + 6 + 7 + CH_ALPN_NAME_MAX)
#define SRV_CERT_HEAD_LEN 8
#define SRV_CERT_SUFFIX_LEN 2

// The largest plaintext one record carries: this build's cap, lowered to
// the client's record_size_limit.
static size_t send_limit(const ch_tls *t) {
    return t->peer_limit < CH_TX_PT ? t->peer_limit : CH_TX_PT;
}

// Sends the n bytes staged at t->tx + REC_HDR as one plaintext handshake
// record. RFC 9846 §5.1 fixes legacy_record_version at 0x0303 here.
static int send_plain_record(handshake_state *h, size_t n) {
    ch_tls *t = h->t;
    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    t->tx[2] = 0x03;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    return io_send_all(&t->cfg, t->tx, REC_HDR + n);
}

// Seals pt as one or more handshake records, each carrying at most
// send_limit bytes. RFC 9846 §5.1 permits a message to span records and
// forbids interleaving another type (rfc9846.txt:3460-3462), which a
// straight-line writer cannot do. pt lies outside t->tx, where rec_seal
// writes.
static int send_sealed(handshake_state *h, const uint8_t *pt, size_t n) {
    ch_tls *t = h->t;
    size_t limit = send_limit(t);
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        size_t out_len = 0;
        if (rec_seal(&t->wr, REC_HANDSHAKE, pt, take, t->tx, sizeof t->tx, &out_len) != 0) {
            h->alert = ALERT_INTERNAL_ERROR;
            return CH_ECAP;
        }
        int rc = io_send_all(&t->cfg, t->tx, out_len);
        if (rc != CH_OK) {
            return rc;
        }
        pt += take;
        n -= take;
    }
    return CH_OK;
}

// A message written in pieces, hashed and sealed a fragment at a time.
// rc is sticky the way wbuf's err is, so the caller reads one code.
typedef struct {
    handshake_state *h;
    size_t len;
    int rc;
    uint8_t buf[CH_TX_PT];
} frag_writer;

// Hashes what the writer holds and sends it as one sealed record.
static void frag_flush(frag_writer *f) {
    if (f->rc != CH_OK || f->len == 0) {
        return;
    }
    sha256_update(&f->h->t->transcript, f->buf, f->len);
    f->rc = send_sealed(f->h, f->buf, f->len);
    f->len = 0;
}

static void frag_bytes(frag_writer *f, const uint8_t *p, size_t n) {
    size_t limit = send_limit(f->h->t);
    while (n > 0 && f->rc == CH_OK) {
        size_t take = n < limit - f->len ? n : limit - f->len;
        memcpy(f->buf + f->len, p, take);
        f->len += take;
        p += take;
        n -= take;
        if (f->len == limit) {
            frag_flush(f);
        }
    }
}

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

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    memset(sel, 0, sizeof *sel);
    h->alert = ALERT_HANDSHAKE_FAILURE;
    if ((ch->suites & SRV_SUITE_CHACHA20_POLY1305) == 0) {
        return CH_EPROTO;
    }
    sel->suite = SUITE_CHACHA20_POLY1305_SHA256;
    sel->hash_len = SHA256_LEN;
    if ((ch->groups & SRV_GROUP_KEX) == 0) {
        return CH_EPROTO;
    }
    sel->group = CH_KEX_GROUP;
    sel->sigalg = select_sigalg(&h->t->cfg, ch->sigalgs);
    if (sel->sigalg == 0) {
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
    uint8_t *msg = t->tx + REC_HDR;
    size_t n = srv_build_hello_retry_request(msg, sizeof t->tx - REC_HDR, sel, ch->session_id,
                                             ch->session_id_len, h->cookie, cookie_len);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    hrr_transcript(h, msg, n);
    t->hrr_sent = 1;
    return send_plain_record(h, n);
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
    if (ch->session_id_len == 0) {
        return CH_OK;
    }
    uint8_t rec[SRV_CCS_RECORD_LEN];
    size_t n = srv_build_compat_ccs(rec, sizeof rec);
    CH_ASSERT(n == SRV_CCS_RECORD_LEN);
    h->t->compat_ccs = 1;
    return io_send_all(&h->t->cfg, rec, n);
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
    uint8_t *msg = t->tx + REC_HDR;
    size_t n = srv_build_server_hello(msg, sizeof t->tx - REC_HDR, sel, random32, ch->session_id,
                                      ch->session_id_len, h->pub, sizeof h->pub);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    sha256_update(&t->transcript, msg, n);
    return send_plain_record(h, n);
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
    // The client secret protects what this endpoint reads and the server
    // secret what it writes, the reverse of handshake.c:309-310 and the
    // whole of the asymmetry.
    rec_dir_init(&t->rd, h->c_hs);
    rec_dir_init(&t->wr, h->s_hs);
    h->encrypted = 1;
    t->keys = 1; // alerts encrypt from here on
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
    size_t n = srv_build_encrypted_extensions(msg, sizeof msg, h->record_size_limit, selected);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    sha256_update(&t->transcript, msg, n);
    return send_sealed(h, msg, n);
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
    frag_writer f;
    f.h = h;
    f.len = 0;
    f.rc = CH_OK;
    size_t n = srv_build_certificate_header(frame, sizeof frame, id);
    CH_ASSERT(n == SRV_CERT_HEAD_LEN);
    frag_bytes(&f, frame, n);
    for (uint8_t i = 0; i < id->chain_count; i++) {
        n = srv_build_certificate_entry_prefix(frame, sizeof frame, id->chain[i].len);
        if (n == 0) {
            // A certificate past the three-byte cert_data field names no
            // message this server can write.
            h->alert = ALERT_INTERNAL_ERROR;
            return CH_EINVAL;
        }
        frag_bytes(&f, frame, n);
        frag_bytes(&f, id->chain[i].der, id->chain[i].len);
        n = srv_build_certificate_entry_suffix(frame, sizeof frame);
        CH_ASSERT(n == SRV_CERT_SUFFIX_LEN);
        frag_bytes(&f, frame, n);
    }
    frag_flush(&f);
    return f.rc;
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t sig[SRV_SIG_MAX];
    size_t sig_len = 0;
    // srv_auth.h has the signer write the alert on both refusals. Nothing
    // wires p256_sign.c or rsa_sign.c into srv_auth.c yet, so every
    // certificate handshake this build runs ends here.
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
    return send_sealed(h, msg, n);
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
    int rc = send_sealed(h, msg, n);
    if (rc != CH_OK) {
        return rc;
    }
    // ks_master writes the client secret first, which is what this
    // endpoint reads. Only the write direction advances here: the client
    // Finished still arrives under the handshake key.
    (void)hsr_transcript_hash(h, hash);
    ks_master(h->handshake_secret, hash, h->master, t->rd_secret, t->wr_secret);
    rec_dir_init(&t->wr, t->wr_secret);
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
    rec_dir_init(&t->rd, t->rd_secret);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
}

#endif // CH_ROLE_SERVER
