// The ROLE=server unit vectors: the messages srv_message.c writes, the
// HelloRetryRequest cookie srv_cookie.c mints and opens, and the ClientHello
// srv_parser.c reads. docs/server.md names this binary bin/srv_test.
//
// Every builder case compares the whole message against bytes written out by
// hand from RFC 9846's message formats, not against a second construction of
// the same fields, so a builder and its vector cannot drift together. The
// cookie has no printed vector -- the format is this tree's own -- so its
// cases are a round trip, a tamper sweep over every byte, and the exact
// boundary pairs CLAUDE.md asks of a length rule. The parser reads one hello
// written out by hand the same way, then one mutant per refusal its header
// lists and the boundary pair of every length rule.
//
// The three cases split into headers because the vectors are long and the
// helpers below are what they read, the same shape test/quic_vectors.c uses.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "rand.h"
#include "srv_cookie.h"
#include "srv_message.h"
#include "srv_parser.h"

// hkdf.c reaches this on a contract breach, and srv_cookie.c calls hkdf.c, so
// this binary links the handler every other test main defines.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// srv_message.c draws the ServerHello random through this hook. A counter,
// not entropy: these cases compare structure and codes rather than bytes,
// and a fixed stream replays a failure exactly. Never a source for
// ch_rand_bytes outside tests.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// The vectors below spell the key_share extension out, so they hold only for
// the classic key exchange. The Makefile builds this binary with no KEX
// define, so a build that ever gains one stops here instead of comparing
// against bytes for the other group.
_Static_assert(CH_KEX_GROUP == CH_GROUP_X25519, "the vectors here spell x25519's code point");
_Static_assert(CH_KEX_SERVER_SHARE == 32, "the vectors here spell a 32-byte server share");
_Static_assert(CH_KEX_CLIENT_SHARE == 32, "the vectors here spell a 32-byte client share");

// One scratch buffer, larger than any message these vectors build. The
// CertificateVerify length case is the one call that needs more, and it
// carries its own buffer.
#define SCRATCH 256
static uint8_t out[SCRATCH];

// Whether the builder wrote exactly want, and said so.
static int built(size_t n, const uint8_t *want, size_t want_len) {
    return n == want_len && memcmp(out, want, want_len) == 0;
}

#include "srv_cookie_tests.h"
#include "srv_message_tests.h"
#include "srv_parser_hello.h"
#include "srv_parser_tests.h"

int main(void) {
    test_server_hello();
    test_hello_retry_request();
    test_compat_ccs();
    test_encrypted_extensions();
    test_certificate();
    test_certificate_verify();
    test_finished();
    test_key_update();
    test_builder_capacity();
    test_cookie_round_trip();
    test_cookie_tamper();
    test_cookie_bounds();
    test_golden_hello();
    test_head();
    test_extension_block();
    test_exact_fill();
    test_required_extensions();
    test_key_share();
    test_pre_shared_key();
    test_alpn();
    test_readers();
    test_frozen_digest();
    test_predicates();
    if (failures == 0) {
        (void)printf("srv: message vectors, cookie round trip and ClientHello parse\n");
    }
    return failures != 0;
}
