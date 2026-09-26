// Resumption in a TRUST=webpki client (webpki_ticket.h): a ticket is
// presented only under the hostname and anchors of the session that
// received it, and a server that declines it gets a full handshake in the
// same connection (docs/decisions.md 55). Built twice from this file:
// bin/webpki_resume_test over TRANSPORT=tcp-blocking, and
// bin/webpki_resume_tcp_nonblocking over TRANSPORT=tcp-nonblocking.
//
// The mock server answers a ClientHello the way the test asks. By default
// it selects the offered ticket and sends EncryptedExtensions and Finished
// under keys derived from the PSK the test gives it, so a client that used
// any other PSK fails to open those records. With decline set it sends no
// pre_shared_key, derives its keys from the early secret of no PSK, and
// sends the r2 corpus chain and a CertificateVerify its leaf key signs
// (test/webpki_r2_chain.h): the flight a server that declined the ticket
// owes. With retry set it first answers with a HelloRetryRequest that
// carries a cookie. It checks the binder of every hello it reads. After
// the handshake it sends a NewSessionTicket and an application data
// record.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "keysched.h"
#include "p256_sign.h"
#include "record.h"
#include "test_random.h"
#include "tls.h"
#include "webpki_ticket.h"
#include "x25519.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"
#endif

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#include "hello_exts.h"
#include "webpki_r2_chain.h"

typedef struct {
    uint8_t psk[SHA256_LEN];    // the PSK the server's key schedule starts from
    int decline;                // answer with no pre_shared_key and the certificate flight
    int retry;                  // answer the first hello with a HelloRetryRequest
    uint16_t identity;          // the selected_identity a ServerHello that selects names
    uint8_t hello[CH_TX_STAGE]; // the last ClientHello, header included
    size_t hello_len;
    int hellos;          // how many ClientHellos arrived
    int binders_ok;      // how many of them carried the binder the mock computes
    int certificates;    // how many Certificate messages the mock sent
    sha256 transcript;   // the server's running transcript
    rec_dir from_client; // client -> server, under c_hs, to read an alert
    int keys;            // from_client is keyed
    uint8_t alert;       // description byte of the last alert the client sent
    int sends;
    uint8_t queue[4096];
    size_t queue_len;
    size_t queue_off;
    rec_dir application; // server -> client, under s_ap
} mock_server;

static const uint8_t server_scalar[X25519_LEN] = {0x07, 0x5e};
static const uint8_t retry_cookie[4] = {0xc0, 0x0c, 0x1e, 0x55};

static void push_record(mock_server *s, const uint8_t *msg, size_t n) {
    wbuf w;
    wb_init(&w, s->queue + s->queue_len, sizeof s->queue - s->queue_len);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0303);
    wb_u16(&w, (uint16_t)n);
    wb_bytes(&w, msg, n);
    CHECK(!w.err);
    s->queue_len += w.len;
}

static void push_sealed(mock_server *s, rec_dir *d, uint8_t type, const uint8_t *msg, size_t n) {
    size_t out_len = 0;
    CHECK(rec_seal(d, type, msg, n, s->queue + s->queue_len, sizeof s->queue - s->queue_len,
                   &out_len) == 0);
    s->queue_len += out_len;
}

// Seals one handshake message under d and adds it to the transcript.
static void push_message(mock_server *s, rec_dir *d, const uint8_t *msg, size_t n) {
    push_sealed(s, d, REC_HANDSHAKE, msg, n);
    sha256_update(&s->transcript, msg, n);
}

static void transcript_hash(const sha256 *transcript, uint8_t out[SHA256_LEN]) {
    sha256 snapshot = *transcript;
    sha256_final(&snapshot, out);
}

// Whether the last hello's binder is the one the mock computes from its
// PSK over the transcript so far and the hello up to its binders list
// (RFC 9846 §4.3.11.2). After a HelloRetryRequest that transcript is the
// replaced one, so a retry hello that kept its first binder fails here.
static int binder_matches(const mock_server *s) {
    if (s->hello_len < CH_BINDERS_TAIL(SHA256_LEN)) {
        return 0;
    }
    sha256 transcript = s->transcript;
    sha256_update(&transcript, s->hello, s->hello_len - CH_BINDERS_TAIL(SHA256_LEN));
    uint8_t hash[SHA256_LEN];
    sha256_final(&transcript, hash);
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t want[SHA256_LEN];
    ks_early(SHA256_LEN, s->psk, sizeof s->psk, 1, early, binder_key);
    ks_verify_data(SHA256_LEN, binder_key, hash, want);
    return memcmp(want, s->hello + s->hello_len - SHA256_LEN, SHA256_LEN) == 0;
}

// The x25519 KeyShareEntry of the captured hello, or NULL. The hello
// carries it beside the hybrid one (docs/decisions.md entry 53), and this
// mock is a server without the hybrid, so it selects x25519.
static const uint8_t *client_share(const mock_server *s) {
    size_t len = 0;
    const uint8_t *key = hello_key_share(s->hello, s->hello_len, CH_GROUP_X25519, &len);
    return len == X25519_LEN ? key : NULL;
}

// The ServerHello or the HelloRetryRequest: x25519, or a cookie and no
// group in a retry, which is the one change a retry can ask this client
// for; and pre_shared_key in a ServerHello unless the mock declines.
static size_t build_server_hello(const mock_server *s, uint8_t *msg, size_t cap, int retry,
                                 const uint8_t server_pub[X25519_LEN]) {
    wbuf w;
    wb_init(&w, msg, cap);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, retry ? hsp_hrr_magic[i] : 0x42);
    }
    wb_u8(&w, 0);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    if (retry) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, 2 + sizeof retry_cookie);
        wb_u16(&w, sizeof retry_cookie);
        wb_bytes(&w, retry_cookie, sizeof retry_cookie);
    } else {
        wb_u16(&w, EXT_KEY_SHARE);
        wb_u16(&w, 2 + 2 + X25519_LEN);
        wb_u16(&w, CH_GROUP_X25519);
        wb_u16(&w, X25519_LEN);
        wb_bytes(&w, server_pub, X25519_LEN);
    }
    if (!retry && !s->decline) {
        wb_u16(&w, EXT_PRE_SHARED_KEY);
        wb_u16(&w, 2);
        wb_u16(&w, s->identity);
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);
    return w.err ? 0 : w.len;
}

// The HelloRetryRequest, and the transcript RFC 9846 §4.1 replaces the
// first hello with: message_hash over Hash(ClientHello1), then the retry.
static void answer_retry(mock_server *s) {
    uint8_t msg[64];
    size_t n = build_server_hello(s, msg, sizeof msg, 1, NULL);
    push_record(s, msg, n);
    uint8_t first[SHA256_LEN];
    sha256_final(&s->transcript, first);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    sha256_init(&s->transcript);
    sha256_update(&s->transcript, synth, sizeof synth);
    sha256_update(&s->transcript, first, sizeof first);
    sha256_update(&s->transcript, msg, n);
}

// The Certificate and CertificateVerify of a server that declined the
// ticket: the r2 corpus chain, and an ecdsa_secp256r1_sha256 signature by
// its leaf key over RFC 9846 §4.5.2's content for the transcript so far.
static void push_certificate_flight(mock_server *s, rec_dir *d) {
    push_message(s, d, webpki_corpus_message_r2, sizeof webpki_corpus_message_r2);
    s->certificates++;
    static const char context[] = "TLS 1.3, server CertificateVerify";
    uint8_t hash[SHA256_LEN];
    transcript_hash(&s->transcript, hash);
    uint8_t pad[64];
    memset(pad, ' ', sizeof pad);
    sha256 content;
    sha256_init(&content);
    sha256_update(&content, pad, sizeof pad);
    sha256_update(&content, (const uint8_t *)context, sizeof context); // with its NUL
    sha256_update(&content, hash, sizeof hash);
    uint8_t digest[SHA256_LEN];
    sha256_final(&content, digest);
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    CHECK(p256_sign(webpki_corpus_server_priv, digest, sig, sizeof sig, &sig_len) == 1);
    uint8_t msg[8 + P256_SIG_MAX];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, HS_CERTIFICATE_VERIFY);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, SIGALG_ECDSA_P256_SHA256);
    wb_u16(&w, (uint16_t)sig_len);
    wb_bytes(&w, sig, sig_len);
    wb_patch24(&w, body);
    CHECK(!w.err);
    push_message(s, d, msg, w.len);
}

// The ServerHello, then EncryptedExtensions, the certificate flight when
// the mock declines, and Finished under s_hs. The key schedule starts
// from the ticket's PSK when the ServerHello selected it, and from the
// early secret of no PSK when it did not (RFC 9846 §7.1).
static void answer_hello(mock_server *s) {
    const uint8_t *share = client_share(s);
    CHECK(share != NULL);
    if (share == NULL) {
        return;
    }
    uint8_t ecdhe[X25519_LEN];
    uint8_t server_pub[X25519_LEN];
    CHECK(x25519(ecdhe, server_scalar, share) == 1);
    x25519_base(server_pub, server_scalar);
    uint8_t msg[128];
    size_t n = build_server_hello(s, msg, sizeof msg, 0, server_pub);
    push_record(s, msg, n);
    sha256_update(&s->transcript, msg, n);

    uint8_t hash[SHA256_LEN];
    transcript_hash(&s->transcript, hash);
    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    if (s->decline) {
        ks_early(SHA256_LEN, no_psk, sizeof no_psk, 0, early, binder);
    } else {
        ks_early(SHA256_LEN, s->psk, sizeof s->psk, 1, early, binder);
    }
    ks_handshake(SHA256_LEN, early, ecdhe, sizeof ecdhe, hash, handshake_secret, c_hs, s_hs);
    rec_dir handshake;
    rec_dir_init(&handshake, s_hs);
    rec_dir_init(&s->from_client, c_hs);
    s->keys = 1;

    static const uint8_t encrypted_exts[] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};
    push_message(s, &handshake, encrypted_exts, sizeof encrypted_exts);
    if (s->decline) {
        push_certificate_flight(s, &handshake);
    }
    transcript_hash(&s->transcript, hash);
    uint8_t finished[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(SHA256_LEN, s_hs, hash, finished + 4);
    push_message(s, &handshake, finished, sizeof finished);
    transcript_hash(&s->transcript, hash);
    uint8_t master[SHA256_LEN];
    uint8_t c_ap[SHA256_LEN];
    uint8_t s_ap[SHA256_LEN];
    ks_master(SHA256_LEN, handshake_secret, hash, master, c_ap, s_ap);
    rec_dir_init(&s->application, s_ap);
}

// A plaintext fatal alert, the answer a server sends before it has keys.
static void push_alert(mock_server *s, uint8_t description) {
    uint8_t rec[REC_HDR + 2] = {REC_ALERT, 0x03, 0x03, 0, 2, 2, description};
    CHECK(s->queue_len + sizeof rec <= sizeof s->queue);
    memcpy(s->queue + s->queue_len, rec, sizeof rec);
    s->queue_len += sizeof rec;
}

// Takes one ClientHello: counts its binder when it carries the one the
// mock computes, adds it to the transcript, and answers it. A hello with
// no signature_algorithms gets handshake_failure and nothing else, ticket
// or not, which is how dns.google answered a resuming hello without the
// extension when cocuyo measured it on 2026-09-24 (docs/decisions.md 55):
// that server picks its certificate and scheme before it decides whether
// to resume.
static void take_hello(mock_server *s, const uint8_t *p, size_t n) {
    memcpy(s->hello, p, n);
    s->hello_len = n;
    if (s->hellos == 0) {
        sha256_init(&s->transcript);
    }
    s->hellos++;
    uint16_t schemes[8];
    if (hello_sigalgs(s->hello, s->hello_len, schemes, 8) < 0) {
        push_alert(s, ALERT_HANDSHAKE_FAILURE);
        return;
    }
    s->binders_ok += binder_matches(s);
    sha256_update(&s->transcript, p, n);
    if (s->retry && s->hellos == 1) {
        answer_retry(s);
        return;
    }
    answer_hello(s);
}

// A NewSessionTicket carrying identity "ticket-2", then "ok" as
// application data, both under s_ap.
static void push_ticket(mock_server *s) {
    static const uint8_t identity[8] = {'t', 'i', 'c', 'k', 'e', 't', '-', '2'};
    uint8_t ticket[4 + 22];
    wbuf w;
    wb_init(&w, ticket, sizeof ticket);
    wb_u8(&w, HS_NEW_SESSION_TICKET);
    wb_u24(&w, 22);
    wb_u16(&w, 0);
    wb_u16(&w, 3600); // ticket_lifetime
    wb_u16(&w, 0);
    wb_u16(&w, 7); // ticket_age_add
    wb_u8(&w, 1);  // ticket_nonce
    wb_u8(&w, 0);
    wb_u16(&w, sizeof identity);
    wb_bytes(&w, identity, sizeof identity);
    wb_u16(&w, 0); // extensions
    CHECK(!w.err && w.len == sizeof ticket);
    static const uint8_t ok[2] = {'o', 'k'};
    push_sealed(s, &s->application, REC_HANDSHAKE, ticket, sizeof ticket);
    push_sealed(s, &s->application, REC_APPDATA, ok, sizeof ok);
}

// A plaintext handshake record is a ClientHello: the first one, or the
// retry after a HelloRetryRequest. An alert is kept, in the clear or
// sealed under c_hs, so a test can read which one the client sent.
static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_server *s = io;
    s->sends++;
    int hellos_owed = s->retry ? 2 : 1;
    if (s->hellos < hellos_owed && n > REC_HDR && p[0] == REC_HANDSHAKE &&
        n - REC_HDR <= CH_TX_STAGE) {
        take_hello(s, p + REC_HDR, n - REC_HDR);
        return 0;
    }
    if (n == REC_HDR + 2 && p[0] == REC_ALERT) {
        s->alert = p[REC_HDR + 1];
        return 0;
    }
    uint8_t pt[64];
    size_t pt_len = 0;
    uint8_t type = 0;
    if (s->keys && rec_open(&s->from_client, p, n, pt, sizeof pt, &pt_len, &type) == 0 &&
        type == REC_ALERT && pt_len == 2) {
        s->alert = pt[1];
    }
    return 0;
}

// Hands over what the mock holds. Empty, it returns 0 in a tcp-nonblocking build,
// where that means no record yet (tcp_nonblocking.h), and -1 over
// TRANSPORT=tcp-blocking.
static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_server *s = io;
    size_t left = s->queue_len - s->queue_off;
    if (left == 0) {
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
        return 0;
#else
        return -1;
#endif
    }
    size_t take = n < left ? n : left;
    memcpy(p, s->queue + s->queue_off, take);
    s->queue_off += take;
    return (int)take;
}

// The ticket on_ticket received last, copied out of the callback.
static struct {
    int count;
    uint8_t psk[SHA256_LEN];
    size_t psk_len;
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t binding[SHA256_LEN];
} received;

static void keep_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    received.count++;
    // The mock runs ChaCha20 alone, so every ticket is a SHA-256 one.
    CHECK(ticket->psk_len == SHA256_LEN);
    memcpy(received.psk, ticket->psk, SHA256_LEN);
    received.psk_len = ticket->psk_len;
    memcpy(received.identity, ticket->identity, ticket->identity_len);
    received.identity_len = ticket->identity_len;
    memcpy(received.binding, ticket->binding, SHA256_LEN);
}

#include "webpki_resume_session.h"
// The cases call the two session functions, so they come second.
#include "webpki_resume_cases.h"

// The decline rows read the resume rows' configuration helpers, so they
// come third.
#include "webpki_decline_cases.h"

int main(void) {
    test_binding_known_answer();
    test_ticket_shape();
    test_ticket_names_its_config();
    test_resumed_handshake();
    test_resumed_hello_offers_certificates();
    test_server_declines_ticket();
    test_decline_checks_the_chain();
    test_retry_then_resume_or_decline();
    test_decline_handler();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    (void)printf("webpki_resume_tcp_nonblocking: all checks passed\n");
#else
    (void)printf("webpki_resume_test: all checks passed\n");
#endif
    return 0;
}
