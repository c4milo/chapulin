// Resumption in a TRUST=webpki client (webpki_ticket.h): a ticket is
// presented only under the hostname and anchors of the session that
// received it. Built twice from this file: bin/webpki_resume_test over
// TRANSPORT=tls, and bin/webpki_resume_record over TRANSPORT=record.
//
// The mock server speaks the PSK half of a handshake only. It answers a
// ClientHello with a ServerHello that selects the offered ticket, then
// EncryptedExtensions and Finished under keys derived from the PSK the
// test gives it. A client that used any other PSK fails to open those
// records, so a connected session shows the client resumed with the
// ticket the test presented. After the handshake the mock sends a
// NewSessionTicket and an application data record.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "keysched.h"
#include "record.h"
#include "test_random.h"
#include "tls.h"
#include "webpki_ticket.h"
#include "x25519.h"
#ifdef CH_TRANSPORT_RECORD
#include "rec.h"
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

typedef struct {
    uint8_t psk[SHA256_LEN]; // the PSK the server's key schedule starts from
    int decline;             // answer with no pre_shared_key: the ticket was not selected
    uint8_t hello[CH_TX_STAGE];
    size_t hello_len;
    int sends;
    uint8_t queue[2048];
    size_t queue_len;
    size_t queue_off;
    rec_dir application; // server -> client, under s_ap
} mock_server;

static const uint8_t server_scalar[X25519_LEN] = {0x07, 0x5e};

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

static void transcript_hash(const sha256 *transcript, uint8_t out[SHA256_LEN]) {
    sha256 snapshot = *transcript;
    sha256_final(&snapshot, out);
}

// The x25519 KeyShareEntry of the captured hello, or NULL.
static const uint8_t *client_share(const mock_server *s) {
    size_t len = 0;
    const uint8_t *ext = hello_ext(s->hello, s->hello_len, EXT_KEY_SHARE, &len);
    if (ext == NULL || len != 2 + 2 + 2 + X25519_LEN) {
        return NULL;
    }
    rbuf r;
    rb_init(&r, ext, len);
    (void)rb_u16(&r);
    if (rb_u16(&r) != CH_GROUP_X25519 || rb_u16(&r) != X25519_LEN) {
        return NULL;
    }
    return rb_bytes(&r, X25519_LEN);
}

// The ServerHello, then EncryptedExtensions and Finished under s_hs.
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
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, 0x42);
    }
    wb_u8(&w, 0);
    wb_u16(&w, 0x1303);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + X25519_LEN);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, X25519_LEN);
    wb_bytes(&w, server_pub, sizeof server_pub);
    if (!s->decline) {
        wb_u16(&w, EXT_PRE_SHARED_KEY);
        wb_u16(&w, 2);
        wb_u16(&w, 0); // selected_identity: the one ticket offered
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);
    push_record(s, msg, w.len);

    sha256 transcript;
    sha256_init(&transcript);
    sha256_update(&transcript, s->hello, s->hello_len);
    sha256_update(&transcript, msg, w.len);
    uint8_t hash[SHA256_LEN];
    transcript_hash(&transcript, hash);
    uint8_t early[SHA256_LEN];
    uint8_t binder[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_early(s->psk, sizeof s->psk, 1, early, binder);
    ks_handshake(early, ecdhe, sizeof ecdhe, hash, handshake_secret, c_hs, s_hs);
    rec_dir handshake;
    rec_dir_init(&handshake, s_hs);

    static const uint8_t encrypted_exts[] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};
    push_sealed(s, &handshake, REC_HANDSHAKE, encrypted_exts, sizeof encrypted_exts);
    sha256_update(&transcript, encrypted_exts, sizeof encrypted_exts);
    transcript_hash(&transcript, hash);
    uint8_t finished[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(s_hs, hash, finished + 4);
    push_sealed(s, &handshake, REC_HANDSHAKE, finished, sizeof finished);
    sha256_update(&transcript, finished, sizeof finished);
    transcript_hash(&transcript, hash);
    uint8_t master[SHA256_LEN];
    uint8_t c_ap[SHA256_LEN];
    uint8_t s_ap[SHA256_LEN];
    ks_master(handshake_secret, hash, master, c_ap, s_ap);
    rec_dir_init(&s->application, s_ap);
}

// A NewSessionTicket carrying identity "ticket-2", then "ok" as
// application data, both under s_ap.
static void push_ticket(mock_server *s) {
    static const uint8_t ticket[] = {HS_NEW_SESSION_TICKET,
                                     0,
                                     0,
                                     22,
                                     0,
                                     0,
                                     0x0e,
                                     0x10,
                                     0,
                                     0,
                                     0,
                                     7,
                                     1,
                                     0,
                                     0,
                                     8,
                                     't',
                                     'i',
                                     'c',
                                     'k',
                                     'e',
                                     't',
                                     '-',
                                     '2',
                                     0,
                                     0};
    static const uint8_t ok[2] = {'o', 'k'};
    push_sealed(s, &s->application, REC_HANDSHAKE, ticket, sizeof ticket);
    push_sealed(s, &s->application, REC_APPDATA, ok, sizeof ok);
}

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_server *s = io;
    s->sends++;
    if (s->hello_len == 0 && n > REC_HDR && p[0] == REC_HANDSHAKE && n - REC_HDR <= CH_TX_STAGE) {
        memcpy(s->hello, p + REC_HDR, n - REC_HDR);
        s->hello_len = n - REC_HDR;
        answer_hello(s);
    }
    return 0;
}

// Hands over what the mock holds. Empty, it returns 0 in a record build,
// where that means no record yet (rec.h), and -1 over TRANSPORT=tls.
static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_server *s = io;
    size_t left = s->queue_len - s->queue_off;
    if (left == 0) {
#ifdef CH_TRANSPORT_RECORD
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
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t binding[SHA256_LEN];
} received;

static void keep_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    received.count++;
    memcpy(received.psk, ticket->psk, SHA256_LEN);
    memcpy(received.identity, ticket->identity, ticket->identity_len);
    received.identity_len = ticket->identity_len;
    memcpy(received.binding, ticket->binding, SHA256_LEN);
}

#include "webpki_resume_session.h"
// The cases call the two session functions, so they come second.
#include "webpki_resume_cases.h"

int main(void) {
    test_binding_known_answer();
    test_ticket_shape();
    test_ticket_names_its_config();
    test_resumed_handshake();
    test_server_declines_ticket();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
#ifdef CH_TRANSPORT_RECORD
    (void)printf("webpki_resume_record: all checks passed\n");
#else
    (void)printf("webpki_resume_test: all checks passed\n");
#endif
    return 0;
}
