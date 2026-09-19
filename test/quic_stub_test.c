// Every function of the TRANSPORT=quic mode is a stub today, and this binary holds the two
// rules that make a stubbed mode safe to link: no call reports success, and no call writes
// through an out-parameter.
//
// Why it exists. The Makefile's TRANSPORT axis packages these sources into an object a
// caller can link before one line of the mode is implemented. A stub that answered CH_OK
// would hand that caller an unprotected packet and a handshake that never ran. So each
// stub returns the refusal its header documents, and this binary calls every one of them
// and requires it. `make lint-quic-surface` is what holds "every one": it reads the stub
// names from the CH_QUIC_STUB marker and the names called here from this file, and fails
// on a stub this file never calls. docs/quic.md, "The stubs and the marker", states the
// rules; the test/violations mutant quic-stub-returns-ok makes one stub answer CH_OK and
// requires this binary to fail.
//
// Every buffer and every struct below is filled with POISON before the call and compared
// against POISON after it, so "writes nothing" is measured rather than assumed. A function
// leaves this file when it is implemented, in the commit that implements it, and
// `make quic-footprint` prints how many are left.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "quic.h"
#include "quic_initial.h"
#include "quic_packet.h"

// hkdf.c reaches this on a contract breach, and quic_aes.c calls hkdf.c
// now that it is implemented, so this binary links the handler every
// other test main defines.
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

// The byte no stub may replace. 0xa5 is neither 0 nor 0xff, so a wipe and a fill both show.
#define POISON 0xa5

// One scratch buffer, larger than any packet these calls are handed, filled with POISON and
// checked whole. 64 bytes covers the longest out-parameter below, a sealed packet of a
// 4-byte header, 4 bytes of plaintext and a 16-byte tag.
#define SCRATCH 64

// True when every byte of p is still POISON.
static int untouched(const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        if (b[i] != POISON) {
            return 0;
        }
    }
    return 1;
}

// The two out-parameters most calls share, refilled before each call.
static uint8_t out[SCRATCH];
static size_t out_len;

static void fill_out(void) {
    memset(out, POISON, sizeof out);
    memset(&out_len, POISON, sizeof out_len);
}

static int out_untouched(void) {
    return untouched(out, sizeof out) && untouched(&out_len, sizeof out_len);
}

// quic_aes.c carries no section here. Its four entries are implemented,
// so each one writes and none of them refuses, which is the opposite of
// what this binary measures. bin/quic_test checks them against FIPS 197
// and RFC 9001 Appendix A instead.

// quic_gcm.c carries no section here either. Its three entries are
// implemented, so gcm_seal and gcm_ghash write and gcm_open answers 1 on a
// tag that matches, which is the opposite of what this binary measures.
// bin/quic_test checks them against SP 800-38D and RFC 9001 Appendix A
// instead, and test/quic_gcm_tests.h holds those vectors.

// quic_keys.c carries no section here now. Its three entries are
// implemented, so quic_keys_init and quic_hp_key_init write their whole
// object and quic_keys_update rewrites the secret it is given, which is
// the opposite of what this binary measures. bin/quic_test checks them
// against RFC 9001 Appendix A.5's four printed values instead.

// quic_packet.c carries no section here now. Its thirteen entries are
// implemented, so the mask, nonce and key-set calls write their whole
// output and the seal and open calls answer CH_OK on a packet they can
// protect, which is the opposite of what this binary measures.
// bin/quic_test checks them against RFC 9001 Appendix A.2 and A.5 and
// RFC 9000 Appendix A.3 instead.

// quic_initial.c carries no section here now. Its two entries are
// implemented, so a call with a packet they can seal or open writes the
// packet and reports CH_OK, which is the opposite of what this binary
// measures. bin/quic_test checks them against RFC 9001 Appendix A.2's
// client Initial packet and the refusals their header documents
// instead.
//
// Neither file names an AES type or holds a key here, and that is INV-26
// working rather than an omission. quic_aes.h leaves aes_public_key
// incomplete and this file does not include quic_aes_key.h, so
// `aes_public_key k;` would not compile in it. The Initial entries take
// the Destination Connection ID and derive what they need on their own
// stack.
// quic_retry.c carries no section here now. Its one entry is
// implemented, so quic_retry_ok answers 1 on a Retry packet whose tag
// matches, which is the opposite of what this binary measures.
// bin/quic_test checks it against RFC 9001 Appendix A.4 instead.

// The driver, and the public entries that take or report session state.
static ch_quic q;

static void test_session_entries(void) {
    ch_cfg cfg;
    memset(&q, POISON, sizeof q);
    memset(&cfg, 0, sizeof cfg);

    CHECK(hsq_advance(&q) == CH_EINVAL);
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL);
    CHECK(ch_quic_initial_keys(&q, (const uint8_t *)"cid", 3) == CH_EINVAL);
    CHECK(ch_quic_key_update(&q) == CH_EINVAL);
    CHECK(ch_quic_discard(&q, CH_LEVEL_INITIAL) == CH_EINVAL);
    ch_quic_drop_previous_keys(&q);
    ch_quic_close(&q);
    CHECK(untouched(&q, sizeof q));

    // The three reporting calls answer a session no other call can advance.
    CHECK(ch_quic_state(&q) == CH_ST_FAILED);
    CHECK(ch_quic_alert(&q) == 80); // internal_error, RFC 9846 §6
    CHECK(ch_quic_error_code(&q) == 0x0150);
    CHECK(ch_quic_key_phase(&q) == 0);
}

// The four public entries that move bytes: CRYPTO in and out, seal and open.
static void test_public_bytes(void) {
    uint8_t hdr[8];
    uint8_t pt[8];
    uint8_t tag[GCM_TAG];
    uint64_t pn;
    size_t pt_len;
    uint8_t key_set;
    memset(&q, POISON, sizeof q);
    memset(hdr, POISON, sizeof hdr);
    memset(pt, POISON, sizeof pt);
    memset(tag, POISON, sizeof tag);

    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, pt, sizeof pt) == CH_EINVAL);

    fill_out();
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(out_untouched());

    fill_out();
    CHECK(ch_quic_seal(&q, CH_LEVEL_APPLICATION, 1, QUIC_PN_MAX_LEN, hdr, sizeof hdr, pt, sizeof pt,
                       out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(out_untouched());

    fill_out();
    memset(&pn, POISON, sizeof pn);
    memset(&pt_len, POISON, sizeof pt_len);
    memset(&key_set, POISON, sizeof key_set);
    CHECK(ch_quic_open(&q, CH_LEVEL_APPLICATION, out, sizeof out, 1, 0, 0, &key_set, &pn,
                       &pt_len) == CH_EINVAL);
    CHECK(untouched(out, sizeof out) && untouched(&key_set, sizeof key_set) &&
          untouched(&pn, sizeof pn) && untouched(&pt_len, sizeof pt_len));

    CHECK(ch_quic_retry_ok(&q, hdr, sizeof hdr, tag) == 0);
    CHECK(untouched(&q, sizeof q));
}

int main(void) {
    test_session_entries();
    test_public_bytes();
    if (failures == 0) {
        (void)printf("quic_stub: every stub refuses and writes nothing\n");
    }
    return failures != 0;
}
