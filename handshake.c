#include "handshake.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "hsmsg.h"
#include "hsparse.h"
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

// Everything the handshake needs beyond the session, on one stack frame;
// wiped wholesale when the handshake ends either way.
typedef struct {
    ch_tls *t;
    uint8_t priv[X25519_LEN];
    uint8_t pub[X25519_LEN];
    uint8_t random[32];
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t hs_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    uint8_t cookie[HSP_COOKIE_MAX];
    size_t cookielen;
    uint16_t rsl;
    int encrypted;
    uint8_t ccs_seen; // compat-mode CCS records tolerated so far
    uint8_t quiet;    // records that added no handshake bytes
    uint8_t alert;    // what to tell the peer if we abort
} hs;

// Appends one record's handshake bytes at buf[part..]. Plaintext records
// shed their header in place; protected ones decrypt in place.
static int accept_record(hs *h, size_t part, uint8_t outer, size_t reclen) {
    ch_tls *t = h->t;
    uint8_t *buf = t->cfg.buf;
    if (!h->encrypted) {
        if (outer != REC_HANDSHAKE) {
            return CH_EPROTO;
        }
        memmove(buf + part, buf + part + REC_HDR, reclen - REC_HDR);
        t->pt_len = part + reclen - REC_HDR;
        return CH_OK;
    }
    if (outer != REC_APPDATA) {
        return CH_EPROTO;
    }
    size_t n = 0;
    uint8_t itype = 0;
    if (rec_open(&t->rd, buf + part, reclen, buf + part, t->cfg.buf_len - part, &n, &itype) != 0) {
        h->alert = ALERT_BAD_RECORD_MAC;
        return CH_EAUTH;
    }
    if (itype != REC_HANDSHAKE) {
        return CH_EPROTO;
    }
    t->pt_len = part + n;
    return CH_OK;
}

// Reads records until one carrying handshake bytes lands, decrypting once
// keys are up, and appends its plaintext to the unconsumed bytes already
// in cfg.buf so messages may span records.
static int fetch_record(hs *h) {
    ch_tls *t = h->t;
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
        if (rc != CH_OK) {
            return rc;
        }
        if (outer == REC_CCS) {
            // Middlebox-compat noise, never hashed. RFC 8446 §5: the body
            // must be exactly one 0x01 byte; the count cap keeps a hostile
            // plaintext CCS stream from pinning the handshake forever.
            if (reclen != REC_HDR + 1 || t->cfg.buf[part + REC_HDR] != 1 || ++h->ccs_seen > 4) {
                h->alert = ALERT_UNEXPECTED_MESSAGE;
                return CH_EPROTO;
            }
            continue;
        }
        if (outer == REC_ALERT) {
            return CH_EPROTO; // peer aborted; nothing to salvage
        }
        rc = accept_record(h, part, outer, reclen);
        if (rc != CH_OK) {
            return rc;
        }
        // An empty handshake fragment is legal once in a while, but an
        // endless stream of them must not pin the handshake forever.
        if (t->pt_len == part && ++h->quiet > CH_QUIET_CAP) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
        return CH_OK;
    }
}

// Yields the next complete handshake message, raw (header included) for
// the transcript. Pointers land in cfg.buf and die at the next call.
static int next_msg(hs *h, uint8_t *type, const uint8_t **raw, size_t *rawlen) {
    ch_tls *t = h->t;
    for (;;) {
        const uint8_t *p = t->cfg.buf + t->pt_off;
        size_t avail = t->pt_len - t->pt_off;
        if (avail >= 4) {
            size_t mlen = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
            if (mlen > 0x4000) {
                return CH_EPROTO; // nothing we accept is this large
            }
            if (avail >= 4 + mlen) {
                *type = p[0];
                *raw = p;
                *rawlen = 4 + mlen;
                t->pt_off += 4 + mlen;
                return CH_OK;
            }
        }
        int rc = fetch_record(h);
        if (rc != CH_OK) {
            return rc;
        }
    }
}

// Builds the ClientHello (echoing an HRR cookie on the retry), computes
// the binder over the transcript-so-far plus the truncated message, and
// sends it as a plaintext handshake record.
static int send_ch(hs *h) {
    ch_tls *t = h->t;
    uint8_t *msg = t->tx + REC_HDR;
    size_t cap = sizeof t->tx - REC_HDR;
    size_t n = hs_build_ch(msg, cap, &t->cfg, h->pub, h->random, h->rsl,
                           h->cookielen > 0 ? h->cookie : NULL, h->cookielen);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
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
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_SERVER_HELLO) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    memset(si, 0, sizeof *si);
    rc = hsp_parse_sh(raw + 4, rawlen - 4, si, h->t->cfg.psk != NULL);
    if (rc != CH_OK) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return rc;
    }
    if (si->hrr) {
        hrr_transcript(h, raw, rawlen);
        if (si->cookielen == 0) {
            // An HRR that changes nothing we offered is illegal.
            h->alert = ALERT_ILLEGAL_PARAMETER;
            return CH_EPROTO;
        }
        memcpy(h->cookie, si->cookie, si->cookielen);
        h->cookielen = si->cookielen;
    } else {
        sha256_update(&h->t->transcript, raw, rawlen);
    }
    return CH_OK;
}

static int hash_now(hs *h, uint8_t out[SHA256_LEN]);

static int expect_finished(hs *h) {
    uint8_t hash[SHA256_LEN];
    (void)hash_now(h, hash);
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != CH_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE || type == HS_CERTIFICATE_REQUEST) {
        // Certificates where none belong: a PSK server that rejected the
        // PSK, or a pinned-key server demanding client auth we cannot do.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    if (type != HS_FINISHED || rawlen != 4 + SHA256_LEN) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    uint8_t want[SHA256_LEN];
    ks_verify_data(h->s_hs, hash, want);
    if (!ct_memeq(want, raw + 4, SHA256_LEN)) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, rawlen);
    return CH_OK;
}

// Pinned-key server authentication (RFC 8446 §4.4.2-4.4.3): accept the
// Certificate message with minimal framing checks — its contents are
// authenticated by the signature, not by parsing — then require a
// CertificateVerify whose signature (RSA-PSS by default, ECDSA-P256 under
// CH_PIN_ECDSA) over the running transcript checks out against the
// provisioned public key.
static int server_auth(hs *h) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != CH_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE_REQUEST) {
        h->alert = ALERT_HANDSHAKE_FAILURE; // no client certificates here
        return CH_EAUTH;
    }
    if (type != HS_CERTIFICATE) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    rbuf r;
    rb_init(&r, raw + 4, rawlen - 4);
    if (rb_u8(&r) != 0) {
        h->alert = ALERT_ILLEGAL_PARAMETER; // certificate_request_context
        return CH_EPROTO;
    }
    size_t listlen = rb_u24(&r);
    if (r.err || listlen != rb_left(&r) || listlen == 0) {
        h->alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    sha256_update(&h->t->transcript, raw, rawlen);

    uint8_t hash[SHA256_LEN];
    (void)hash_now(h, hash);
    rc = next_msg(h, &type, &raw, &rawlen);
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_CERTIFICATE_VERIFY) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    rb_init(&r, raw + 4, rawlen - 4);
    if (rb_u16(&r) != CH_PIN_SIGALG) {
        h->alert = ALERT_HANDSHAKE_FAILURE; // we offered exactly one algorithm
        return CH_EAUTH;
    }
    size_t siglen = rb_u16(&r);
    const uint8_t *sig = rb_bytes(&r, siglen);
    if (sig == NULL || rb_left(&r) != 0) {
        h->alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
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

#ifdef CH_PIN_ECDSA
    int sig_ok = p256_ecdsa_verify(h->t->cfg.server_pubkey, signed_hash, sig, siglen);
#else
    int sig_ok = rsa_pss_verify(h->t->cfg.server_pubkey, h->t->cfg.server_pubkey_len, signed_hash,
                                sig, siglen);
#endif
    if (!sig_ok) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, rawlen);
    return CH_OK;
}

static int send_client_finished(hs *h, const uint8_t *hash) {
    ch_tls *t = h->t;
    uint8_t msg[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(h->c_hs, hash, msg + 4);
    sha256_update(&t->transcript, msg, sizeof msg);
    size_t outn = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, msg, sizeof msg, t->tx, sizeof t->tx, &outn) != 0) {
        return CH_ECAP;
    }
    return io_send_all(&t->cfg, t->tx, outn);
}

static int hash_now(hs *h, uint8_t out[SHA256_LEN]) {
    sha256 th = h->t->transcript;
    sha256_final(&th, out);
    return CH_OK;
}

// ClientHello out, ServerHello in, with at most one HelloRetryRequest
// round; on CH_OK si holds an acceptable non-HRR ServerHello.
static int hello_exchange(hs *h, sh_info *si) {
    int rc = send_ch(h);
    if (rc != CH_OK) {
        return rc;
    }
    rc = read_sh(h, si);
    if (rc != CH_OK) {
        return rc;
    }
    if (si->hrr) {
        rc = send_ch(h);
        if (rc != CH_OK) {
            return rc;
        }
        rc = read_sh(h, si);
        if (rc != CH_OK) {
            return rc;
        }
        if (si->hrr) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
    }
    if (!si->have_share || (h->t->cfg.psk != NULL && !si->psk_ok)) {
        // No ECDHE share, or a PSK server that ignored our identity and
        // would want certificates we did not pin.
        h->alert = ALERT_HANDSHAKE_FAILURE;
        return CH_EAUTH;
    }
    return CH_OK;
}

static int run(hs *h) {
    ch_tls *t = h->t;
    ch_rand_bytes(h->priv, sizeof h->priv);
    ch_rand_bytes(h->random, sizeof h->random);
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
    if (rc != CH_OK) {
        return rc;
    }

    uint8_t ecdhe[X25519_LEN];
    if (!x25519(ecdhe, h->priv, si.server_pub)) {
        h->alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
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
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_ENCRYPTED_EXTENSIONS) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    // Seed the default first: the parser overrides it only when it has a
    // more specific alert (unsupported_extension, RFC 8446 §4.2), and
    // that override must survive to the wire.
    h->alert = ALERT_ILLEGAL_PARAMETER;
    rc = hsp_parse_ee(raw + 4, rawlen - 4, &t->peer_limit, &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
    sha256_update(&t->transcript, raw, rawlen);

    if (t->cfg.psk == NULL) {
        rc = server_auth(h);
        if (rc != CH_OK) {
            return rc;
        }
    }
    rc = expect_finished(h);
    if (rc != CH_OK) {
        return rc;
    }

    // Server Finished is in; derive the application schedule, answer with
    // our Finished under the handshake keys, then switch both directions.
    (void)hash_now(h, hash);
    ks_master(h->hs_secret, hash, h->master, t->wr_secret, t->rd_secret);
    rc = send_client_finished(h, hash);
    if (rc != CH_OK) {
        return rc;
    }
    (void)hash_now(h, hash);
    ks_res_master(h->master, hash, t->res_master);
    rec_dir_init(&t->rd, t->rd_secret);
    rec_dir_init(&t->wr, t->wr_secret);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = CH_ST_CONNECTED;
    return CH_OK;
}

int ch_handshake(ch_tls *t) {
    hs h;
    memset(&h, 0, sizeof h);
    h.t = t;
    h.alert = ALERT_DECODE_ERROR;
    size_t room = t->cfg.buf_len - REC_HDR - AEAD_TAG;
    h.rsl = room > 0x4001 ? 0x4001 : (uint16_t)room;
    t->peer_limit = CH_TX_PT;

    int rc = run(&h);
    uint8_t alert = h.alert;
    ct_wipe(&h, sizeof h);
    if (rc != CH_OK) {
        tlsi_fail(t, alert);
    }
    return rc;
}
