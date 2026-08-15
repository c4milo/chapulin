#include "handshake.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "hsmsg.h"
#include "io.h"
#include "keysched.h"
#include "p256.h"
#include "rand.h"
#include "x25519.h"

#define COOKIE_MAX 128

// Everything the handshake needs beyond the session, on one stack frame;
// wiped wholesale when the handshake ends either way.
typedef struct {
    ms_tls *t;
    uint8_t priv[X25519_LEN];
    uint8_t pub[X25519_LEN];
    uint8_t random[32];
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t hs_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    uint8_t cookie[COOKIE_MAX];
    size_t cookielen;
    uint16_t rsl;
    int encrypted;
    uint8_t ccs_seen; // compat-mode CCS records tolerated so far
    uint8_t quiet;    // records that added no handshake bytes
    uint8_t alert;    // what to tell the peer if we abort
} hs;

static const uint8_t hrr_magic[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

// Appends one record's handshake bytes at buf[part..]. Plaintext records
// shed their header in place; protected ones decrypt in place.
static int accept_record(hs *h, size_t part, uint8_t outer, size_t reclen) {
    ms_tls *t = h->t;
    uint8_t *buf = t->cfg.buf;
    if (!h->encrypted) {
        if (outer != REC_HANDSHAKE) {
            return MS_EPROTO;
        }
        memmove(buf + part, buf + part + REC_HDR, reclen - REC_HDR);
        t->pt_len = part + reclen - REC_HDR;
        return MS_OK;
    }
    if (outer != REC_APPDATA) {
        return MS_EPROTO;
    }
    size_t n = 0;
    uint8_t itype = 0;
    if (rec_open(&t->rd, buf + part, reclen, buf + part, t->cfg.buf_len - part, &n, &itype) != 0) {
        h->alert = ALERT_BAD_RECORD_MAC;
        return MS_EAUTH;
    }
    if (itype != REC_HANDSHAKE) {
        return MS_EPROTO;
    }
    t->pt_len = part + n;
    return MS_OK;
}

// Reads records until one carrying handshake bytes lands, decrypting once
// keys are up, and appends its plaintext to the unconsumed bytes already
// in cfg.buf so messages may span records.
static int fetch_record(hs *h) {
    ms_tls *t = h->t;
    if (t->pt_off > 0) {
        memmove(t->cfg.buf, t->cfg.buf + t->pt_off, t->pt_len - t->pt_off);
        t->pt_len -= t->pt_off;
        t->pt_off = 0;
    }
    for (;;) {
        size_t part = t->pt_len;
        uint8_t outer = 0;
        size_t reclen = 0;
        int rc = io_read_record(&t->cfg, t->cfg.buf + part, t->cfg.buf_len - part, &outer, &reclen);
        if (rc != MS_OK) {
            return rc;
        }
        if (outer == REC_CCS) {
            // Middlebox-compat noise, never hashed. RFC 8446 §5: the body
            // must be exactly one 0x01 byte; the count cap keeps a hostile
            // plaintext CCS stream from pinning the handshake forever.
            if (reclen != REC_HDR + 1 || t->cfg.buf[part + REC_HDR] != 1 || ++h->ccs_seen > 4) {
                h->alert = ALERT_UNEXPECTED_MESSAGE;
                return MS_EPROTO;
            }
            continue;
        }
        if (outer == REC_ALERT) {
            return MS_EPROTO; // peer aborted; nothing to salvage
        }
        rc = accept_record(h, part, outer, reclen);
        if (rc != MS_OK) {
            return rc;
        }
        // An empty handshake fragment is legal once in a while, but an
        // endless stream of them must not pin the handshake forever.
        if (t->pt_len == part && ++h->quiet > 32) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return MS_EPROTO;
        }
        return MS_OK;
    }
}

// Yields the next complete handshake message, raw (header included) for
// the transcript. Pointers land in cfg.buf and die at the next call.
static int next_msg(hs *h, uint8_t *type, const uint8_t **raw, size_t *rawlen) {
    ms_tls *t = h->t;
    for (;;) {
        const uint8_t *p = t->cfg.buf + t->pt_off;
        size_t avail = t->pt_len - t->pt_off;
        if (avail >= 4) {
            size_t mlen = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
            if (mlen > 0x4000) {
                return MS_EPROTO; // nothing we accept is this large
            }
            if (avail >= 4 + mlen) {
                *type = p[0];
                *raw = p;
                *rawlen = 4 + mlen;
                t->pt_off += 4 + mlen;
                return MS_OK;
            }
        }
        int rc = fetch_record(h);
        if (rc != MS_OK) {
            return rc;
        }
    }
}

// Builds the ClientHello (echoing an HRR cookie on the retry), computes
// the binder over the transcript-so-far plus the truncated message, and
// sends it as a plaintext handshake record.
static int send_ch(hs *h) {
    ms_tls *t = h->t;
    uint8_t *msg = t->tx + REC_HDR;
    size_t cap = sizeof t->tx - REC_HDR;
    size_t n = hs_build_ch(msg, cap, &t->cfg, h->pub, h->random, h->rsl,
                           h->cookielen > 0 ? h->cookie : NULL, h->cookielen);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return MS_ECAP;
    }
    if (t->cfg.psk != NULL) {
        // PSK binder over the transcript-so-far plus the truncated hello.
        sha256 th = t->transcript;
        uint8_t hash[SHA256_LEN];
        sha256_update(&th, msg, n - CH_BINDERS_TAIL);
        sha256_final(&th, hash);
        ks_verify_data(h->binder_key, hash, msg + n - SHA256_LEN);
    }
    sha256_update(&t->transcript, msg, n);

    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    // The very first record may carry 0x0301 for old middleboxes; every
    // later one, including the post-HRR retry, must say 0x0303 (§5.1).
    t->tx[2] = h->cookielen > 0 ? 0x03 : 0x01;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    return io_send_all(&t->cfg, t->tx, REC_HDR + n);
}

typedef struct {
    int hrr;
    int ver_ok;
    int have_share;
    int psk_ok;
    uint8_t server_pub[X25519_LEN];
    const uint8_t *cookie;
    size_t cookielen;
} sh_info;

static int parse_sh_ext(rbuf *r, sh_info *si, int hrr, int psk_mode) {
    uint16_t ext = rb_u16(r);
    size_t elen = rb_u16(r);
    const uint8_t *ep = rb_bytes(r, elen);
    if (ep == NULL) {
        return MS_EPROTO;
    }
    if (ext == EXT_PRE_SHARED_KEY && !psk_mode) {
        return MS_EPROTO; // selecting a PSK we never offered
    }
    rbuf e;
    rb_init(&e, ep, elen);
    switch (ext) {
    case EXT_SUPPORTED_VERSIONS:
        si->ver_ok = rb_u16(&e) == TLS13;
        break;
    case EXT_KEY_SHARE:
        if (hrr) {
            // We offer only x25519, so an HRR can never legally ask for a
            // different share: selecting ours is redundant (illegal) and
            // selecting another group is unsupported. Both are fatal.
            return MS_EPROTO;
        }
        if (rb_u16(&e) != GROUP_X25519 || rb_u16(&e) != X25519_LEN) {
            return MS_EPROTO;
        }
        {
            const uint8_t *pub = rb_bytes(&e, X25519_LEN);
            if (pub == NULL) {
                return MS_EPROTO;
            }
            memcpy(si->server_pub, pub, X25519_LEN);
            si->have_share = 1;
        }
        break;
    case EXT_PRE_SHARED_KEY:
        si->psk_ok = rb_u16(&e) == 0; // we offered exactly one identity
        break;
    case EXT_COOKIE:
        if (!hrr) {
            return MS_EPROTO;
        }
        si->cookielen = rb_u16(&e);
        si->cookie = rb_bytes(&e, si->cookielen);
        if (si->cookie == NULL || si->cookielen > COOKIE_MAX) {
            return MS_EPROTO;
        }
        break;
    default:
        return MS_EPROTO; // ServerHello may carry nothing else
    }
    return e.err ? MS_EPROTO : MS_OK;
}

static int parse_sh(const uint8_t *body, size_t n, sh_info *si, int psk_mode) {
    rbuf r;
    rb_init(&r, body, n);
    if (rb_u16(&r) != 0x0303) {
        return MS_EPROTO;
    }
    const uint8_t *random = rb_bytes(&r, 32);
    if (random == NULL) {
        return MS_EPROTO;
    }
    si->hrr = memcmp(random, hrr_magic, 32) == 0;
    if (rb_u8(&r) != 0) {
        return MS_EPROTO; // we sent an empty legacy_session_id; the echo must match
    }
    if (rb_u16(&r) != SUITE_CHACHA20_POLY1305_SHA256 || rb_u8(&r) != 0) {
        return MS_EPROTO;
    }
    size_t extlen = rb_u16(&r);
    if (r.err || extlen != rb_left(&r)) {
        return MS_EPROTO;
    }
    while (rb_left(&r) > 0) {
        int rc = parse_sh_ext(&r, si, si->hrr, psk_mode);
        if (rc != MS_OK) {
            return rc;
        }
    }
    return si->ver_ok ? MS_OK : MS_EPROTO;
}

// Encrypted extensions: take the peer's record_size_limit, tolerate
// supported_groups (a server may volunteer it for later connections),
// reject everything else — RFC 8446 §4.2 requires unsupported_extension
// for anything the ClientHello did not offer.
static int parse_ee(hs *h, const uint8_t *body, size_t n) {
    rbuf r;
    rb_init(&r, body, n);
    size_t extlen = rb_u16(&r);
    if (r.err || extlen != rb_left(&r)) {
        return MS_EPROTO;
    }
    while (rb_left(&r) > 0) {
        uint16_t ext = rb_u16(&r);
        size_t elen = rb_u16(&r);
        const uint8_t *ep = rb_bytes(&r, elen);
        if (ep == NULL) {
            return MS_EPROTO;
        }
        if (ext == EXT_RECORD_SIZE_LIMIT) {
            rbuf e;
            rb_init(&e, ep, elen);
            uint16_t lim = rb_u16(&e);
            if (e.err || lim < 64) {
                return MS_EPROTO;
            }
            // The limit covers content plus the inner type byte.
            uint16_t pt = lim - 1;
            if (pt < h->t->peer_limit) {
                h->t->peer_limit = pt;
            }
        } else if (ext != EXT_SUPPORTED_GROUPS) {
            h->alert = ALERT_UNSUPPORTED_EXTENSION;
            return MS_EPROTO;
        }
    }
    return MS_OK;
}

// Replaces the transcript after HRR: Hash(message_hash || 00 00 20 ||
// Hash(CH1)) || HRR, per RFC 8446 §4.4.1.
static void hrr_transcript(hs *h, const uint8_t *raw, size_t rawlen) {
    uint8_t ch1[SHA256_LEN];
    sha256_final(&h->t->transcript, ch1);
    sha256_init(&h->t->transcript);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    sha256_update(&h->t->transcript, synth, 4);
    sha256_update(&h->t->transcript, ch1, SHA256_LEN);
    sha256_update(&h->t->transcript, raw, rawlen);
}

static int read_sh(hs *h, sh_info *si) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != MS_OK) {
        return rc;
    }
    if (type != HS_SERVER_HELLO) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return MS_EPROTO;
    }
    memset(si, 0, sizeof *si);
    rc = parse_sh(raw + 4, rawlen - 4, si, h->t->cfg.psk != NULL);
    if (rc != MS_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return rc;
    }
    if (si->hrr) {
        hrr_transcript(h, raw, rawlen);
        if (si->cookielen == 0) {
            // An HRR that changes nothing we offered is illegal.
            h->alert = ALERT_ILLEGAL_PARAMETER;
            return MS_EPROTO;
        }
        memcpy(h->cookie, si->cookie, si->cookielen);
        h->cookielen = si->cookielen;
    } else {
        sha256_update(&h->t->transcript, raw, rawlen);
    }
    return MS_OK;
}

static int hash_now(hs *h, uint8_t out[SHA256_LEN]);

static int expect_finished(hs *h) {
    uint8_t hash[SHA256_LEN];
    (void)hash_now(h, hash);
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != MS_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE || type == HS_CERTIFICATE_REQUEST) {
        // Certificates where none belong: a PSK server that rejected the
        // PSK, or a pinned-key server demanding client auth we cannot do.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return MS_EAUTH;
    }
    if (type != HS_FINISHED || rawlen != 4 + SHA256_LEN) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return MS_EPROTO;
    }
    uint8_t want[SHA256_LEN];
    ks_verify_data(h->s_hs, hash, want);
    if (!ct_memeq(want, raw + 4, SHA256_LEN)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return MS_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, rawlen);
    return MS_OK;
}

// Pinned-key server authentication (RFC 8446 §4.4.2-4.4.3): accept the
// Certificate message with minimal framing checks — its contents are
// authenticated by the signature, not by parsing — then require a
// CertificateVerify whose ECDSA-P256 signature over the running
// transcript checks out against the provisioned public key.
static int server_auth(hs *h) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != MS_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE_REQUEST) {
        h->alert = ALERT_HANDSHAKE_FAILURE; // no client certificates here
        return MS_EAUTH;
    }
    if (type != HS_CERTIFICATE) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return MS_EPROTO;
    }
    rbuf r;
    rb_init(&r, raw + 4, rawlen - 4);
    if (rb_u8(&r) != 0) {
        h->alert = ALERT_ILLEGAL_PARAMETER; // certificate_request_context
        return MS_EPROTO;
    }
    size_t listlen = rb_u24(&r);
    if (r.err || listlen != rb_left(&r) || listlen == 0) {
        h->alert = ALERT_DECODE_ERROR;
        return MS_EPROTO;
    }
    sha256_update(&h->t->transcript, raw, rawlen);

    uint8_t hash[SHA256_LEN];
    (void)hash_now(h, hash);
    rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != MS_OK) {
        return rc;
    }
    if (type != HS_CERTIFICATE_VERIFY) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return MS_EPROTO;
    }
    rb_init(&r, raw + 4, rawlen - 4);
    if (rb_u16(&r) != SIGALG_ECDSA_P256_SHA256) {
        h->alert = ALERT_HANDSHAKE_FAILURE; // we offered exactly one algorithm
        return MS_EAUTH;
    }
    size_t siglen = rb_u16(&r);
    const uint8_t *sig = rb_bytes(&r, siglen);
    if (sig == NULL || rb_left(&r) != 0) {
        h->alert = ALERT_DECODE_ERROR;
        return MS_EPROTO;
    }

    // Signed content per §4.4.3: 64 spaces, context string, NUL, transcript.
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    uint8_t pad[64];
    for (size_t i = 0; i < sizeof pad; i++) {
        pad[i] = ' ';
    }
    sha256 s;
    sha256_init(&s);
    sha256_update(&s, pad, sizeof pad);
    sha256_update(&s, (const uint8_t *)ctx, sizeof ctx - 1);
    uint8_t nul = 0;
    sha256_update(&s, &nul, 1);
    sha256_update(&s, hash, SHA256_LEN);
    uint8_t signed_hash[SHA256_LEN];
    sha256_final(&s, signed_hash);

    if (!p256_ecdsa_verify(h->t->cfg.server_pubkey, signed_hash, sig, siglen)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return MS_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, rawlen);
    return MS_OK;
}

static int send_client_finished(hs *h, const uint8_t *hash) {
    ms_tls *t = h->t;
    uint8_t msg[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(h->c_hs, hash, msg + 4);
    sha256_update(&t->transcript, msg, sizeof msg);
    size_t outn = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, msg, sizeof msg, t->tx, sizeof t->tx, &outn) != 0) {
        return MS_ECAP;
    }
    return io_send_all(&t->cfg, t->tx, outn);
}

static int hash_now(hs *h, uint8_t out[SHA256_LEN]) {
    sha256 th = h->t->transcript;
    sha256_final(&th, out);
    return MS_OK;
}

// ClientHello out, ServerHello in, with at most one HelloRetryRequest
// round; on MS_OK si holds an acceptable non-HRR ServerHello.
static int hello_exchange(hs *h, sh_info *si) {
    int rc = send_ch(h);
    if (rc != MS_OK) {
        return rc;
    }
    rc = read_sh(h, si);
    if (rc != MS_OK) {
        return rc;
    }
    if (si->hrr) {
        rc = send_ch(h);
        if (rc != MS_OK) {
            return rc;
        }
        rc = read_sh(h, si);
        if (rc != MS_OK) {
            return rc;
        }
        if (si->hrr) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return MS_EPROTO;
        }
    }
    if (!si->have_share || (h->t->cfg.psk != NULL && !si->psk_ok)) {
        // No ECDHE share, or a PSK server that ignored our identity and
        // would want certificates we did not pin.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return MS_EAUTH;
    }
    return MS_OK;
}

static int run(hs *h) {
    ms_tls *t = h->t;
    ms_rand_bytes(h->priv, sizeof h->priv);
    ms_rand_bytes(h->random, sizeof h->random);
    x25519_base(h->pub, h->priv);
    if (t->cfg.psk != NULL) {
        ks_early(t->cfg.psk, t->cfg.psk_len, t->cfg.resumption, h->early, h->binder_key);
    } else {
        // No PSK: the early secret extracts from a hash-length zero string
        // (RFC 8446 §7.1) and the binder key is never used.
        static const uint8_t nopsk[SHA256_LEN] = {0};
        ks_early(nopsk, sizeof nopsk, 0, h->early, h->binder_key);
    }
    sha256_init(&t->transcript);

    sh_info si;
    int rc = hello_exchange(h, &si);
    if (rc != MS_OK) {
        return rc;
    }

    uint8_t ecdhe[X25519_LEN];
    if (!x25519(ecdhe, h->priv, si.server_pub)) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return MS_EPROTO;
    }
    uint8_t hash[SHA256_LEN];
    (void)hash_now(h, hash);
    ks_handshake(h->early, ecdhe, hash, h->hs_secret, h->c_hs, h->s_hs);
    ct_wipe(ecdhe, sizeof ecdhe);
    rec_dir_init(&t->rd, h->s_hs);
    rec_dir_init(&t->wr, h->c_hs);
    h->encrypted = 1;
    t->keys = 1; // alerts encrypt from here on

    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != MS_OK) {
        return rc;
    }
    if (type != HS_ENCRYPTED_EXTENSIONS) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return MS_EPROTO;
    }
    rc = parse_ee(h, raw + 4, rawlen - 4);
    if (rc != MS_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return rc;
    }
    sha256_update(&t->transcript, raw, rawlen);

    if (t->cfg.psk == NULL) {
        rc = server_auth(h);
        if (rc != MS_OK) {
            return rc;
        }
    }
    rc = expect_finished(h);
    if (rc != MS_OK) {
        return rc;
    }

    // Server Finished is in; derive the application schedule, answer with
    // our Finished under the handshake keys, then switch both directions.
    (void)hash_now(h, hash);
    ks_master(h->hs_secret, hash, h->master, t->wr_secret, t->rd_secret);
    rc = send_client_finished(h, hash);
    if (rc != MS_OK) {
        return rc;
    }
    (void)hash_now(h, hash);
    ks_res_master(h->master, hash, t->res_master);
    rec_dir_init(&t->rd, t->rd_secret);
    rec_dir_init(&t->wr, t->wr_secret);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = MS_ST_CONNECTED;
    return MS_OK;
}

int ms_handshake(ms_tls *t) {
    hs h;
    memset(&h, 0, sizeof h);
    h.t = t;
    h.alert = ALERT_DECODE_ERROR;
    size_t room = t->cfg.buf_len - REC_HDR - AEAD_TAG;
    h.rsl = room > 0x4001 ? 0x4001 : (uint16_t)room;
    t->peer_limit = MS_TX_PT;

    int rc = run(&h);
    uint8_t alert = h.alert;
    ct_wipe(&h, sizeof h);
    if (rc != MS_OK) {
        tlsi_fail(t, alert);
    }
    return rc;
}
