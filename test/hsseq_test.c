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
// stubs supply the "valid" verdict, so message order — not signature
// math — is what runs here. Both verifiers exist so both PIN builds
// link; rsa_test and the e2e cover the real ones.
int rsa_pss_verify(const uint8_t *n, size_t nlen, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t siglen) {
    (void)n;
    (void)nlen;
    (void)msg_hash;
    (void)sig;
    (void)siglen;
    return 1;
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    (void)pub;
    (void)msg_hash;
    (void)sig_der;
    (void)sig_len;
    return 1;
}

#define ALPHABET "SHECRVFNKAL"
#define ALPHA_N 11
#define DEPTH_MAX 8

#include "hsseqsrv.h"

// Why the client rejected, for the divergence report: transport
// exhaustion (the sequence ended before the client was satisfied) is a
// different failure than a record the client refused.
static const char *reject_why;

// Runs the real client over one sequence. Accept (1) iff ch_connect
// succeeds and the tail drains with every letter consumed; queue
// exhaustion after full consumption is the normal end, not an error.
static int run_case(const char *letters, size_t n, int psk) {
    static mock_srv s;
    memset(&s, 0, sizeof s);
    s.seq = letters;
    s.len = n;
    s.psk = psk;
    sha256_init(&s.transcript);

    static uint8_t rxbuf[1024];
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &s;
    if (psk) {
        cfg.psk = test_psk;
        cfg.psk_len = sizeof test_psk;
        cfg.psk_id = (const uint8_t *)"hsseq";
        cfg.psk_id_len = 5;
    } else {
        cfg.server_pubkey = test_pin;
        cfg.server_pubkey_len = sizeof test_pin;
    }

    reject_why = "accepted";
    static ch_tls t;
    int rc = ch_connect(&t, &cfg);
    if (rc != CH_OK) {
        reject_why = rc == CH_EIO && seq_spent(&s) ? "handshake starved (sequence too short)"
                                                   : "handshake refused a record";
        return 0;
    }
    for (;;) {
        if (seq_spent(&s)) {
            return 1; // every letter consumed, session still alive
        }
        uint8_t out[64];
        int got = ch_read(&t, out, sizeof out);
        if (got > 0) {
            continue;
        }
        if (got == 0) {
            if (seq_spent(&s)) {
                return 1; // clean close_notify ended the sequence
            }
            reject_why = "letters left after close_notify";
            return 0;
        }
        if (got == CH_EIO && seq_spent(&s)) {
            return 1; // the tail drained; only the transport EOF is left
        }
        reject_why = "tail refused a record";
        return 0;
    }
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
    x25519_base(srv_pub, srv_scalar);
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
