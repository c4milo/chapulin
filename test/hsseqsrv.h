// The mock server for the handshake sequence differential: renders one
// letter of a message sequence into one real TLS record on demand, as
// the client's recv drains the queue. Rendering is lazy because the
// retry flight after a HelloRetryRequest depends on the second
// ClientHello. Included by test/hsseq_test.c only, after diffdrv.h
// (for die) and the chapulin headers it uses.
#ifndef CH_HSSEQSRV_H
#define CH_HSSEQSRV_H

// What the server has sent so far, deciding how the next record is
// protected: nothing yet, the handshake flight, or post-Finished.
#define PHASE_CLEAR 0
#define PHASE_HS 1
#define PHASE_APP 2

typedef struct {
    const char *seq;
    size_t len;
    size_t next;     // next letter to render
    uint8_t q[2048]; // rendered records the client has not read yet
    size_t qlen;
    size_t qoff;
    uint8_t ch[2][512]; // captured ClientHello messages, header included
    size_t chlen[2];
    int chs;      // ClientHellos captured
    int absorbed; // ClientHellos folded into the transcript
    int psk;
    int phase;
    sha256 transcript;
    rec_dir wr; // server -> client protection
    uint8_t hs_secret[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN]; // server handshake traffic secret
    uint8_t s_ap[SHA256_LEN]; // server application traffic secret
} mock_srv;

static const uint8_t test_psk[32] = {0x4d};
static const uint8_t srv_scalar[X25519_LEN] = {0x07, 0x5e};
static uint8_t srv_pub[X25519_LEN]; // x25519_base(srv_scalar), once in main

#ifdef CH_PIN_ECDSA
#define TEST_PIN_LEN 64
#else
#define TEST_PIN_LEN 256
#endif
static uint8_t test_pin[TEST_PIN_LEN]; // filled in main; content never verified

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_srv *s = io;
    // Each send call carries exactly one record (io_send_all's contract);
    // only plaintext ClientHellos matter to the mock.
    if (n > REC_HDR && p[0] == REC_HANDSHAKE && p[REC_HDR] == HS_CLIENT_HELLO && s->chs < 2 &&
        n - REC_HDR <= sizeof s->ch[0]) {
        memcpy(s->ch[s->chs], p + REC_HDR, n - REC_HDR);
        s->chlen[s->chs] = n - REC_HDR;
        s->chs++;
    }
    return 0;
}

// Queues one record of the given content type under the current phase:
// plaintext before the ServerHello, sealed under the phase's keys after.
static void push_rec(mock_srv *s, uint8_t type, const uint8_t *body, size_t n) {
    if (s->phase == PHASE_CLEAR) {
        wbuf w;
        wb_init(&w, s->q + s->qlen, sizeof s->q - s->qlen);
        wb_u8(&w, type);
        wb_u16(&w, 0x0303);
        wb_u16(&w, (uint16_t)n);
        wb_bytes(&w, body, n);
        if (w.err) {
            die("mock record queue overflow");
        }
        s->qlen += w.len;
    } else {
        size_t outn = 0;
        if (rec_seal(&s->wr, type, body, n, s->q + s->qlen, sizeof s->q - s->qlen, &outn) != 0) {
            die("mock record seal failed");
        }
        s->qlen += outn;
    }
}

// Folds ClientHellos the client has sent but the transcript has not seen.
static void absorb_ch(mock_srv *s) {
    while (s->absorbed < s->chs) {
        sha256_update(&s->transcript, s->ch[s->absorbed], s->chlen[s->absorbed]);
        s->absorbed++;
    }
}

// Digs the x25519 public key out of the latest captured ClientHello.
static const uint8_t *client_share(const mock_srv *s) {
    rbuf r;
    rb_init(&r, s->ch[s->chs - 1], s->chlen[s->chs - 1]);
    rb_skip(&r, 4 + 2 + 32); // handshake header, version, random
    rb_skip(&r, rb_u8(&r));  // legacy_session_id
    rb_skip(&r, rb_u16(&r)); // cipher_suites
    rb_skip(&r, rb_u8(&r));  // legacy_compression_methods
    (void)rb_u16(&r);        // extensions length
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t ext = rb_u16(&r);
        size_t elen = rb_u16(&r);
        const uint8_t *ep = rb_bytes(&r, elen);
        if (ep == NULL) {
            break;
        }
        if (ext == EXT_KEY_SHARE && elen == 2 + 2 + 2 + X25519_LEN) {
            return ep + 6; // shares length, group, key length, then the key
        }
    }
    die("no x25519 key_share in the captured ClientHello");
    return NULL;
}

static void hash_now(const mock_srv *s, uint8_t out[SHA256_LEN]) {
    sha256 th = s->transcript;
    sha256_final(&th, out);
}

// ServerHello or HelloRetryRequest message, header included. hrr swaps
// the random for the §4.1.3 sentinel and offers a cookie instead of a
// key_share (we offer only x25519, so an HRR never selects a share).
static size_t build_sh(const mock_srv *s, uint8_t *out, size_t cap, int hrr) {
    static const uint8_t cookie[8] = {0xc0, 0x0c, 0x1e};
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    if (hrr) {
        wb_bytes(&w, hsp_hrr_magic, 32);
    } else {
        for (int i = 0; i < 32; i++) {
            wb_u8(&w, 0x42); // any random that is not the HRR sentinel
        }
    }
    wb_u8(&w, 0); // legacy_session_id_echo: we sent an empty session id
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    if (hrr) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, 2 + sizeof cookie);
        wb_u16(&w, sizeof cookie);
        wb_bytes(&w, cookie, sizeof cookie);
    } else {
        wb_u16(&w, EXT_KEY_SHARE);
        wb_u16(&w, 2 + 2 + X25519_LEN);
        wb_u16(&w, GROUP_X25519);
        wb_u16(&w, X25519_LEN);
        wb_bytes(&w, srv_pub, X25519_LEN);
        if (s->psk) {
            wb_u16(&w, EXT_PRE_SHARED_KEY);
            wb_u16(&w, 2);
            wb_u16(&w, 0); // we offered exactly one identity
        }
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    if (w.err) {
        die("mock ServerHello build failed");
    }
    return w.len;
}

// S: on the first flight, hash CH..SH and run the key schedule up to the
// handshake traffic secrets; anywhere later it is just an out-of-order
// message under the current keys, which the client must refuse.
static void render_sh(mock_srv *s) {
    uint8_t msg[128];
    size_t n = build_sh(s, msg, sizeof msg, 0);
    if (s->phase != PHASE_CLEAR) {
        push_rec(s, REC_HANDSHAKE, msg, n);
        return;
    }
    absorb_ch(s);
    sha256_update(&s->transcript, msg, n);
    uint8_t ecdhe[X25519_LEN];
    if (!x25519(ecdhe, srv_scalar, client_share(s))) {
        die("client key share is low order");
    }
    uint8_t early[SHA256_LEN];
    uint8_t binder[SHA256_LEN];
    if (s->psk) {
        ks_early(test_psk, sizeof test_psk, 0, early, binder);
    } else {
        static const uint8_t nopsk[SHA256_LEN] = {0};
        ks_early(nopsk, sizeof nopsk, 0, early, binder);
    }
    uint8_t hash[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    hash_now(s, hash);
    ks_handshake(early, ecdhe, hash, s->hs_secret, c_hs, s->s_hs);
    push_rec(s, REC_HANDSHAKE, msg, n); // plaintext: the phase flips below
    rec_dir_init(&s->wr, s->s_hs);
    s->phase = PHASE_HS;
}

// H: mirror of handshake.c's hrr_transcript on the first flight.
static void render_hrr(mock_srv *s) {
    uint8_t msg[128];
    size_t n = build_sh(s, msg, sizeof msg, 1);
    if (s->phase == PHASE_CLEAR) {
        absorb_ch(s);
        uint8_t ch1[SHA256_LEN];
        sha256_final(&s->transcript, ch1);
        sha256_init(&s->transcript);
        const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
        sha256_update(&s->transcript, synth, 4);
        sha256_update(&s->transcript, ch1, SHA256_LEN);
        sha256_update(&s->transcript, msg, n);
    }
    push_rec(s, REC_HANDSHAKE, msg, n);
}

// F: MAC over the running transcript, then the application schedule —
// records after a first-flight Finished ride the application keys.
static void render_fin(mock_srv *s) {
    uint8_t msg[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    uint8_t hash[SHA256_LEN];
    hash_now(s, hash);
    ks_verify_data(s->s_hs, hash, msg + 4);
    sha256_update(&s->transcript, msg, sizeof msg);
    push_rec(s, REC_HANDSHAKE, msg, sizeof msg);
    if (s->phase == PHASE_HS) {
        uint8_t master[SHA256_LEN];
        uint8_t c_ap[SHA256_LEN];
        hash_now(s, hash);
        ks_master(s->hs_secret, hash, master, c_ap, s->s_ap);
        rec_dir_init(&s->wr, s->s_ap);
        s->phase = PHASE_APP;
    }
}

// N: a well-formed NewSessionTicket (lifetime, age_add, 2-byte nonce,
// 16-byte identity, no extensions).
static void render_nst(mock_srv *s) {
    uint8_t msg[64];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, HS_NEW_SESSION_TICKET);
    size_t m = wb_mark(&w, 3);
    wb_u16(&w, 0);
    wb_u16(&w, 3600); // ticket_lifetime
    wb_u16(&w, 0);
    wb_u16(&w, 7); // ticket_age_add
    wb_u8(&w, 2);
    wb_u16(&w, 0x0102); // ticket_nonce
    wb_u16(&w, 16);
    for (int i = 0; i < 16; i++) {
        wb_u8(&w, (uint8_t)i); // ticket identity
    }
    wb_u16(&w, 0); // extensions
    wb_patch24(&w, m);
    if (w.err) {
        die("mock ticket build failed");
    }
    push_rec(s, REC_HANDSHAKE, msg, w.len);
}

static void render(mock_srv *s, char letter) {
    static const uint8_t ee[6] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};
    // Certificate: empty context, one 8-byte "certificate" (hashed, never
    // parsed), no per-entry extensions.
    static const uint8_t cert[21] = {HS_CERTIFICATE,
                                     0,
                                     0,
                                     17,
                                     0,
                                     0,
                                     0,
                                     13,
                                     0,
                                     0,
                                     8,
                                     'c',
                                     'h',
                                     'a',
                                     'p',
                                     'u',
                                     'l',
                                     'i',
                                     'n',
                                     0,
                                     0};
    static const uint8_t certreq[7] = {HS_CERTIFICATE_REQUEST, 0, 0, 3, 0, 0, 0};
    static const uint8_t keyupd[5] = {HS_KEY_UPDATE, 0, 0, 1, 0}; // update_not_requested
    static const uint8_t close[2] = {1, ALERT_CLOSE_NOTIFY};
    switch (letter) {
    case 'S':
        render_sh(s);
        break;
    case 'H':
        render_hrr(s);
        break;
    case 'E':
        sha256_update(&s->transcript, ee, sizeof ee);
        push_rec(s, REC_HANDSHAKE, ee, sizeof ee);
        break;
    case 'C':
        sha256_update(&s->transcript, cert, sizeof cert);
        push_rec(s, REC_HANDSHAKE, cert, sizeof cert);
        break;
    case 'R':
        push_rec(s, REC_HANDSHAKE, certreq, sizeof certreq);
        break;
    case 'V': {
        // CertificateVerify: the offered algorithm, 64 dummy signature
        // bytes; the stubbed verifier accepts them.
        uint8_t msg[4 + 2 + 2 + 64];
        wbuf w;
        wb_init(&w, msg, sizeof msg);
        wb_u8(&w, HS_CERTIFICATE_VERIFY);
        size_t m = wb_mark(&w, 3);
        wb_u16(&w, CH_PIN_SIGALG);
        wb_u16(&w, 64);
        for (int i = 0; i < 64; i++) {
            wb_u8(&w, 0x5a);
        }
        wb_patch24(&w, m);
        sha256_update(&s->transcript, msg, w.len);
        push_rec(s, REC_HANDSHAKE, msg, w.len);
        break;
    }
    case 'F':
        render_fin(s);
        break;
    case 'N':
        render_nst(s);
        break;
    case 'K':
        push_rec(s, REC_HANDSHAKE, keyupd, sizeof keyupd);
        if (s->phase == PHASE_APP) {
            rec_dir_update(s->s_ap, &s->wr); // the client rekeys its read side
        }
        break;
    case 'A':
        push_rec(s, REC_APPDATA, (const uint8_t *)"hola", 4);
        break;
    case 'L':
        push_rec(s, REC_ALERT, close, sizeof close);
        break;
    default:
        die("letter outside the alphabet");
    }
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_srv *s = io;
    if (s->qoff == s->qlen) {
        if (s->next >= s->len) {
            return -1; // sequence exhausted: transport EOF
        }
        s->qoff = 0;
        s->qlen = 0;
        render(s, s->seq[s->next++]);
    }
    size_t left = s->qlen - s->qoff;
    size_t take = n < left ? n : left;
    memcpy(p, s->q + s->qoff, take);
    s->qoff += take;
    return (int)take;
}

static int seq_spent(const mock_srv *s) {
    return s->next == s->len && s->qoff == s->qlen;
}

#endif
