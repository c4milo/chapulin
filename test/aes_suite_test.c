// TLS_AES_128_GCM_SHA256 in the record layer, against RFC 8448's printed
// bytes. docs/server.md names this binary bin/aes_suite_test.
//
// The vector is RFC 8448 section 3's client handshake traffic secret and
// the record the client sends under it. Starting from the secret rather
// than from an expanded key is deliberate: it puts the key schedule and
// the AEAD both under the same published answer, so a derive that writes
// the wrong length and a seal that runs the wrong cipher each fail here.
//
// RFC 8448 traces RFC 8446, and RFC 9846 revises that document without
// changing the wire (docs/decisions.md entry 4), so its records are still
// the records this code writes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_message.h"
#include "record.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        (void)sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

// rfc8448.txt:290-291, the client handshake traffic secret: the expanded
// value of "tls13 c hs traffic", not the PRK printed above it, which is
// that derivation's input. The same 32 octets appear again at
// rfc8448.txt:668-669 as the PRK the client's Finished MAC key comes
// from, which is what confirms the pairing.
#define C_HS_SECRET_HEX "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
// rfc8448.txt:698-700, the client Finished, and rfc8448.txt:701-704, the
// record it goes out in. 58 = 5 header + 36 plaintext + 1 inner type + 16 tag.
#define FINISHED_HEX "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
#define RECORD_HEX                                                                                 \
    "1703030035"                                                                                   \
    "75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44"                                     \
    "d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"

// The seal: derive from the secret, protect the Finished as the first
// record of that epoch, and compare every byte the RFC prints.
static void test_rfc8448_client_finished_record(void) {
    uint8_t secret[SHA256_LEN];
    static uint8_t pt[36];
    static uint8_t want[58];
    CHECK(unhex(C_HS_SECRET_HEX, secret) == sizeof secret);
    CHECK(unhex(FINISHED_HEX, pt) == sizeof pt);
    CHECK(unhex(RECORD_HEX, want) == sizeof want);

    rec_dir d;
    memset(&d, 0, sizeof d);
    rec_dir_init_suite(&d, secret, SUITE_AES_128_GCM_SHA256);

    static uint8_t out[64];
    size_t out_len = 0;
    CHECK(rec_seal(&d, REC_HANDSHAKE, pt, sizeof pt, out, sizeof out, &out_len) == 0);
    CHECK(out_len == sizeof want);
    CHECK(memcmp(out, want, sizeof want) == 0);
}

// The open: the same record read back by a receiver keyed from the same
// secret, which is the direction a peer runs and the one a wrong key
// length would still pass if only the seal were checked.
static void test_rfc8448_record_opens(void) {
    uint8_t secret[SHA256_LEN];
    static uint8_t rec[58];
    static uint8_t want[36];
    CHECK(unhex(C_HS_SECRET_HEX, secret) == sizeof secret);
    CHECK(unhex(RECORD_HEX, rec) == sizeof rec);
    CHECK(unhex(FINISHED_HEX, want) == sizeof want);

    rec_dir d;
    memset(&d, 0, sizeof d);
    rec_dir_init_suite(&d, secret, SUITE_AES_128_GCM_SHA256);

    static uint8_t pt[64];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&d, rec, sizeof rec, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_HANDSHAKE);
    CHECK(pt_len == sizeof want);
    CHECK(memcmp(pt, want, sizeof want) == 0);
}

// The other suite still runs, keyed the same way, so the dispatch picks
// the AEAD rather than replacing it.
static void test_chacha_still_round_trips(void) {
    uint8_t secret[SHA256_LEN];
    memset(secret, 0x2b, sizeof secret);
    rec_dir w;
    rec_dir r;
    memset(&w, 0, sizeof w);
    memset(&r, 0, sizeof r);
    rec_dir_init_suite(&w, secret, SUITE_CHACHA20_POLY1305_SHA256);
    rec_dir_init_suite(&r, secret, SUITE_CHACHA20_POLY1305_SHA256);

    static const uint8_t msg[5] = {'s', 'a', 'p', 'o', '!'};
    static uint8_t out[64];
    size_t out_len = 0;
    CHECK(rec_seal(&w, REC_APPDATA, msg, sizeof msg, out, sizeof out, &out_len) == 0);
    static uint8_t pt[64];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&r, out, out_len, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_APPDATA);
    CHECK(pt_len == sizeof msg && memcmp(pt, msg, sizeof msg) == 0);
}

int main(void) {
    test_rfc8448_client_finished_record();
    test_rfc8448_record_opens();
    test_chacha_still_round_trips();
    if (failures == 0) {
        (void)printf("aes_suite: RFC 8448's record seals and opens, chacha20 unchanged\n");
    }
    return failures != 0;
}
