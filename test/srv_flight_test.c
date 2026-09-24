// The ROLE=server flight handlers: srv_flight.c driven over srv_message.c,
// srv_cookie.c and srv_auth.c. docs/server.md names this binary
// bin/srv_flight_test.
//
// Its own main, separate from bin/srv_test, for one reason:
// test/srv_flight_tests.h defines srv_parse_client_hello itself, so the
// flight cases drive every answer the parser's contract admits rather than
// only the ones a real hello produces. That definition and srv_parser.c
// cannot link into one object, and the flight handlers are what this binary
// is about.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "rand.h"
#include "srv_auth.h"
#include "srv_cookie.h"
#include "srv_flight.h"
#include "srv_message.h"
#include "srv_parser.h"

// hkdf.c reaches this on a contract breach, and srv_cookie.c calls hkdf.c, so
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// srv_flight.c draws the key exchange scalar and the ServerHello random
// through this hook. A counter, not entropy: the flight cases compare
// structure and codes rather than bytes, and a fixed stream replays a
// failure exactly. Never a source for ch_rand_bytes outside tests.
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

#include "srv_flight_keys_tests.h"
#include "srv_flight_suite_tests.h"
#include "srv_flight_tests.h"
#include "srv_resume_issue_tests.h"
#include "srv_resume_tests.h"

int main(void) {
    test_flight_begin();
    test_flight_select();
#ifdef CH_SUITE_AES_GCM
    test_flight_select_suite();
    test_flight_key_suite();
#endif
    test_flight_alpn();
    test_flight_read_hello();
    test_flight_server_name();
    test_flight_retry();
    test_flight_server_hello();
    test_flight_keys();
    test_flight_auth();
    test_flight_finish();
    test_flight_finished_length();
    test_resume_select();
    test_resume_binder();
    test_resume_order();
    test_retry_zeroed_selection();
    test_resume_after_retry();
    test_resume_binder_hash();
    test_resume_issue();
    if (failures == 0) {
        (void)printf("srv_flight: the flight handlers write and refuse as srv_flight.h states\n");
    }
    return failures != 0;
}
