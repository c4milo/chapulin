// Sequence differential for the handshake state machine (issue #3):
// enumerate every server message sequence up to a depth, render each as
// real TLS records over a mock transport, run the real client, and
// require its accept/reject verdict to equal the Lean model's hsseq
// oracle. One letter per server message: S ServerHello, H
// HelloRetryRequest, E EncryptedExtensions, C Certificate, R
// CertificateRequest, V CertificateVerify, F Finished, N
// NewSessionTicket, K KeyUpdate, A application data, L close_notify.
// The mock server derives real keys from the captured ClientHello, so
// ServerHello, Finished MACs, and record protection are genuine — a
// wrong transcript or schedule shows up as a divergence. Only the
// pinned-mode signature check is stubbed (V means "signature valid").
//
// Domain: this oracle models raw-pin mode. The client here links
// without CH_TRUST_CA, and the spec's `pinned` Mode means a pinned
// server key. TRUST=ca builds run the same message-order state machine
// but replace the server_auth check with certificate verification, and
// no sequence oracle covers that arm — only the e2e run exercises
// CA-mode sequencing. This is an accepted, recorded limitation.
//
// Its own binary with a private main, like drbg_test; the link line is
// the library sources minus p256.c/rsa.c/rsa_mont.c plus the stubs here.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>

#include "buf.h"
#include "ch_assert.h"
#include "diffdrv.h"
#include "hsmsg.h"
#include "hsparse.h"
#include "keysched.h"
#include "p256.h"
#include "record.h"
#include "rsa.h"
#include "testrand.h"
#include "tls.h"
#include "x25519.h"

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

// V renders a CertificateVerify with dummy signature bytes and these
// stubs supply the verdict, so message order and pin-slot selection —
// not signature math — is what runs here. When stub_accept is set, only
// that exact key object verifies (a pointer compare: server_auth passes
// the cfg's own pin pointers through), which is what makes the slot
// tests below mean something. Both verifiers exist so both PIN builds
// link; rsa_test, wycheproof, and the e2e cover the real ones.
static const uint8_t *stub_accept; // NULL accepts any key

int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    (void)n_len;
    (void)msg_hash;
    (void)sig;
    (void)sig_len;
    return stub_accept == NULL || n == stub_accept;
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    (void)msg_hash;
    (void)sig_der;
    (void)sig_len;
    return stub_accept == NULL || pub == stub_accept;
}

#define ALPHABET "SHECRVFNKAL"
#define ALPHA_N 11
#define DEPTH_MAX 8

// The client derives its record_size_limit from the receive buffer, and
// ch_connect refuses a buffer under CH_MIN_RXBUF (cfg.h). The mock's
// over-limit record has to clear the same number, so both sides read it
// from here instead of restating it as a literal.
#if CH_MIN_RXBUF > 1024
#define HSSEQ_RXBUF CH_MIN_RXBUF
#else
#define HSSEQ_RXBUF 1024
#endif

#include "hsseqsrv.h"

// Why the client rejected, for the divergence report: transport
// exhaustion (the sequence ended before the client was satisfied) is a
// different failure than a record the client refused.
static const char *reject_why;

// Runs the real client over one sequence. Accept (1) iff ch_connect
// succeeds and the tail drains with every letter consumed; queue
// exhaustion after full consumption is the normal end, not an error.
static mock_server srv;                 // file scope so tests can read captured alerts
static ch_tls client_session;           // and the accepted pin slot
static uint8_t test_pin2[TEST_PIN_LEN]; // slot B, wired when use_pin2 is set
static int use_pin2;

static void case_config(ch_cfg *cfg, uint8_t *rxbuf, size_t rxlen, int psk) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = rxbuf;
    cfg->buf_len = rxlen;
    cfg->send = mock_send;
    cfg->recv = mock_recv;
    cfg->io = &srv;
    if (psk) {
        cfg->psk = test_psk;
        cfg->psk_len = sizeof test_psk;
        cfg->psk_id = (const uint8_t *)"hsseq";
        cfg->psk_id_len = 5;
        return;
    }
    cfg->server_pubkey = test_pin;
    cfg->server_pubkey_len = sizeof test_pin;
    if (use_pin2) {
        cfg->server_pubkey2 = test_pin2;
        cfg->server_pubkey2_len = sizeof test_pin2;
    }
}

// Drains the post-handshake tail with ch_read: accept (1) iff every
// letter is consumed before close_notify or transport EOF cuts it off.
static int drain_tail(void) {
    for (;;) {
        if (seq_spent(&srv)) {
            return 1; // every letter consumed, session still alive
        }
        uint8_t out[64];
        int got = ch_read(&client_session, out, sizeof out);
        if (got > 0) {
            continue;
        }
        if (got == 0) {
            if (seq_spent(&srv)) {
                return 1; // clean close_notify ended the sequence
            }
            reject_why = "letters left after close_notify";
            return 0;
        }
        if (got == CH_EIO && seq_spent(&srv)) {
            return 1; // the tail drained; only the transport EOF is left
        }
        reject_why = "tail refused a record";
        return 0;
    }
}

static int run_case(const char *letters, size_t n, int psk) {
    memset(&srv, 0, sizeof srv);
    srv.seq = letters;
    srv.len = n;
    srv.psk = psk;
    sha256_init(&srv.transcript);

    static uint8_t rxbuf[HSSEQ_RXBUF];
    ch_cfg cfg;
    case_config(&cfg, rxbuf, sizeof rxbuf, psk);

    reject_why = "accepted";
    int rc = ch_connect(&client_session, &cfg);
    if (rc != CH_OK) {
        reject_why = rc == CH_EIO && seq_spent(&srv) ? "handshake starved (sequence too short)"
                                                     : "handshake refused a record";
        return 0;
    }
    return drain_tail();
}

static long mismatches;

static void check_one(const char *letters, size_t len, int psk) {
    int c = run_case(letters, len, psk);
    const char *why = reject_why;
    char cmd[DEPTH_MAX + 16];
    char reply[16];
    (void)snprintf(cmd, sizeof cmd, "hsseq %s %s", psk ? "psk" : "pinned", len > 0 ? letters : "-");
    query(cmd, reply, sizeof reply);
    comparisons++;
    if (c != (strcmp(reply, "1") == 0)) {
        mismatches++;
        (void)fprintf(stderr, "hsseq mismatch: mode=%s seq=%s C=%d spec=%s (C: %s)\n",
                      psk ? "psk" : "pinned", len > 0 ? letters : "-", c, reply, why);
    }
}

// Every sequence over the alphabet of each length 0..depth, one mode.
static void run_all(int depth, int psk) {
    for (int len = 0; len <= depth; len++) {
        int idx[DEPTH_MAX] = {0};
        for (;;) {
            char letters[DEPTH_MAX + 1];
            for (int i = 0; i < len; i++) {
                letters[i] = ALPHABET[idx[i]];
            }
            letters[len] = 0;
            check_one(letters, (size_t)len, psk);
            int i = len - 1;
            while (i >= 0 && ++idx[i] == ALPHA_N) {
                idx[i] = 0;
                i--;
            }
            if (i < 0) {
                break;
            }
        }
    }
}

int main(void) {
    x25519_base(server_pub, server_scalar);
    memset(test_pin, 2, sizeof test_pin);
    test_pin[TEST_PIN_LEN - 1] = 1; // ch_connect requires an odd RSA pin

    // Direct ordering checks, independent of the model: a skipped
    // Finished or CertificateVerify must fail the pinned handshake, and
    // the legal shapes must pass (so rejects above mean rejection, not a
    // broken mock).
    CHECK(run_case("SECV", 4, 0) == 0);
    CHECK(run_case("SECF", 4, 0) == 0);
    CHECK(run_case("SECVF", 5, 0) == 1);
    CHECK(run_case("HSECVFNKAL", 10, 0) == 1);
    CHECK(run_case("SEF", 3, 1) == 1);
    CHECK(run_case("HSEFNKA", 7, 1) == 1);
    CHECK(run_case("SECVF", 5, 1) == 0); // certificate flight under PSK

    // Pin slot B (issue #6's specified mock test). The stub accepts
    // exactly one key object, so these run the real slot loop: the
    // handshake must succeed by whichever slot holds the accepted key,
    // record which, and fail closed with decrypt_error when neither
    // slot verifies. Slot order must not matter.
    memset(test_pin2, 4, sizeof test_pin2);
    test_pin2[TEST_PIN_LEN - 1] = 3; // odd, like every valid RSA pin
    use_pin2 = 1;
    stub_accept = test_pin;
    CHECK(run_case("SECVF", 5, 0) == 1);
    CHECK(client_session.pin_slot == 1); // 1-based: 1 = slot A, 0 = no pin used
    stub_accept = test_pin2;
    CHECK(run_case("SECVF", 5, 0) == 1); // rotated key: slot B accepts
    CHECK(client_session.pin_slot == 2);
    static const uint8_t third_key[TEST_PIN_LEN] = {0};
    stub_accept = third_key; // a key in neither slot
    CHECK(run_case("SECVF", 5, 0) == 0);
    CHECK(srv.alerts > 0 && srv.last_alert == ALERT_DECRYPT_ERROR);
    use_pin2 = 0;
    stub_accept = test_pin2;
    CHECK(run_case("SECVF", 5, 0) == 0); // no slot B configured: B's key fails
    CHECK(srv.last_alert == ALERT_DECRYPT_ERROR);
    stub_accept = NULL;

    // Malformation -> alert table (issue #11): each mutation bends one
    // field; the table asserts the alert description byte the client
    // puts on the wire. MUT_REC_OVER documents current behavior: an
    // over-limit record fails io_read_record and dies as decode_error
    // (RFC 8449 prefers record_overflow; tracked separately).
    static const struct {
        int mut;
        const char *seq;
        int psk;
        uint8_t alert;
    } alert_cases[] = {
        {MUT_SH_SUITE,   "SEF",   1, ALERT_ILLEGAL_PARAMETER },
        {MUT_SH_VERSION, "SEF",   1, ALERT_ILLEGAL_PARAMETER },
        {MUT_SH_ECHO,    "SEF",   1, ALERT_ILLEGAL_PARAMETER },
        {MUT_CV_ALG,     "SECVF", 0, ALERT_HANDSHAKE_FAILURE },
        {MUT_FIN_MAC,    "SEF",   1, ALERT_DECRYPT_ERROR     },
        {MUT_HS_TYPE,    "SEF",   1, ALERT_UNEXPECTED_MESSAGE},
        {MUT_REC_OVER,   "SEFA",  1, ALERT_DECODE_ERROR      },
        {MUT_NONE,       "SECF",  0, ALERT_UNEXPECTED_MESSAGE}, // CV skipped
        {MUT_NONE,       "SEC",   1, ALERT_HANDSHAKE_FAILURE }, // cert under PSK
        {MUT_NONE,       "SER",   0, ALERT_HANDSHAKE_FAILURE }, // CertificateRequest
        {MUT_NONE,       "SS",    1, ALERT_UNEXPECTED_MESSAGE}, // second ServerHello
        {MUT_NONE,       "HH",    1, ALERT_UNEXPECTED_MESSAGE}, // repeated HRR
    };
    for (size_t i = 0; i < sizeof alert_cases / sizeof alert_cases[0]; i++) {
        mut_mode = alert_cases[i].mut;
        int accepted = run_case(alert_cases[i].seq, strlen(alert_cases[i].seq), alert_cases[i].psk);
        mut_mode = MUT_NONE;
        if (accepted != 0 || srv.alerts == 0 || srv.last_alert != alert_cases[i].alert) {
            failures++;
            (void)fprintf(stderr,
                          "FAIL alert case %zu (mut=%d seq=%s): accepted=%d alerts=%d got=%u"
                          " want=%u\n",
                          i, alert_cases[i].mut, alert_cases[i].seq, accepted, srv.alerts,
                          srv.last_alert, alert_cases[i].alert);
        }
    }

    int depth = 5;
    const char *env = getenv("ENUM_DEPTH");
    if (env != NULL) {
        char *end = NULL;
        long v = strtol(env, &end, 10);
        if (end == env || *end != 0 || v < 0 || v > DEPTH_MAX) {
            die("ENUM_DEPTH must be 0..8");
        }
        depth = (int)v;
    }

    if (access("spec/.lake/build/bin/diffspec", X_OK) == 0) {
        spawn_spec("spec/.lake/build/bin/diffspec");
        struct timespec t0;
        struct timespec t1;
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        run_all(depth, 1);
        run_all(depth, 0);
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        double secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (mismatches > 0) {
            (void)fprintf(stderr, "hsseq_test: %ld mismatch(es) in %ld sequences\n", mismatches,
                          comparisons);
            failures++;
        } else {
            (void)printf("hsseq_test: %ld sequences (depth %d, both modes) in %.1f s, C == spec\n",
                         comparisons, depth, secs);
        }
    } else {
        (void)printf("hsseq_test: spec comparisons skipped (build spec/ first)\n");
    }

    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("hsseq_test: all checks passed\n");
    return 0;
}
