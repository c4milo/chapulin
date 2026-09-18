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
#include <string.h>

#include "quic.h"
#include "quic_initial.h"
#include "quic_packet.h"
#include "quic_retry.h"

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

static void test_aes(void) {
    aes_public_key k;
    uint8_t in[AES_BLOCK];
    uint8_t dcid[AES_DCID_MAX];
    memset(&k, POISON, sizeof k);
    memset(in, POISON, sizeof in);
    memset(dcid, POISON, sizeof dcid);

    CHECK(aes_public_key_initial(&k, dcid, sizeof dcid, CH_KEY_READ) == CH_EINVAL);
    CHECK(untouched(&k, sizeof k));
    aes_public_key_retry(&k);
    CHECK(untouched(&k, sizeof k));

    fill_out();
    aes_encrypt_block(&k, in, out);
    CHECK(out_untouched());
    fill_out();
    aes_encrypt_block_hp(&k, in, out);
    CHECK(out_untouched());
}

static void test_gcm(void) {
    aes_public_key k;
    uint8_t nonce[AES_IV];
    uint8_t tag[GCM_TAG];
    uint8_t body[SCRATCH];
    memset(&k, POISON, sizeof k);
    memset(nonce, POISON, sizeof nonce);
    memset(tag, POISON, sizeof tag);
    memset(body, POISON, sizeof body);

    fill_out();
    uint8_t seal_tag[GCM_TAG];
    memset(seal_tag, POISON, sizeof seal_tag);
    gcm_seal(&k, nonce, body, 4, body, 8, out, seal_tag);
    CHECK(untouched(out, sizeof out));
    CHECK(untouched(seal_tag, sizeof seal_tag));

    fill_out();
    CHECK(gcm_open(&k, nonce, body, 4, body, 8, tag, out) == 0);
    CHECK(untouched(out, sizeof out));

    fill_out();
    gcm_ghash(&k, body, 4, body, 8, out);
    CHECK(untouched(out, sizeof out));
}

static void test_keys(void) {
    quic_keys keys;
    quic_hp_key hp;
    uint8_t secret[SHA256_LEN];
    memset(&keys, POISON, sizeof keys);
    memset(&hp, POISON, sizeof hp);
    memset(secret, POISON, sizeof secret);

    quic_keys_init(&keys, secret);
    CHECK(untouched(&keys, sizeof keys));
    quic_hp_key_init(&hp, secret);
    CHECK(untouched(&hp, sizeof hp));
    quic_keys_update(secret, &keys);
    CHECK(untouched(secret, sizeof secret));
    CHECK(untouched(&keys, sizeof keys));
}

// The packet-protection calls that write bytes or report a length.
static void test_packet_pieces(void) {
    quic_hp_key hp;
    quic_keys keys;
    uint8_t sample[QUIC_HP_SAMPLE_LEN];
    uint8_t iv[AEAD_NONCE];
    uint8_t mask[QUIC_HP_MASK_LEN];
    memset(&hp, POISON, sizeof hp);
    memset(&keys, POISON, sizeof keys);
    memset(sample, POISON, sizeof sample);
    memset(iv, POISON, sizeof iv);
    memset(mask, POISON, sizeof mask);

    fill_out();
    quic_hp_mask(&hp, sample, out);
    CHECK(untouched(out, sizeof out));

    fill_out();
    quic_header_protect(out, 1, QUIC_PN_MAX_LEN, CH_LEVEL_APPLICATION, mask);
    CHECK(untouched(out, sizeof out));

    fill_out();
    CHECK(quic_header_unprotect(out, 1, CH_LEVEL_APPLICATION, mask) == 0);
    CHECK(untouched(out, sizeof out));

    CHECK(quic_pn_read(sample, 1, QUIC_PN_MAX_LEN) == 0);
    CHECK(quic_pn_decode(100, 7, QUIC_PN_MAX_LEN) == 0);

    fill_out();
    quic_nonce(iv, 7, out);
    CHECK(untouched(out, sizeof out));

    CHECK(quic_key_set_select(1, 0, 9, 4) == CH_QUIC_KEY_PREVIOUS);

    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, POISON, sizeof sets);
    quic_keys selected;
    memset(&selected, POISON, sizeof selected);
    quic_keys_select(sets, CH_QUIC_KEY_CURRENT, &selected);
    CHECK(untouched(&selected, sizeof selected));
}

// The three packet-protection entries that seal or open, and the two §6.6 limit questions.
static void test_packet_calls(void) {
    quic_hp_key hp;
    quic_keys keys;
    quic_keys sets[CH_QUIC_KEY_SETS];
    uint8_t hdr[8];
    uint8_t pt[8];
    uint64_t pn;
    size_t pt_len;
    uint8_t key_set;
    memset(&hp, POISON, sizeof hp);
    memset(&keys, POISON, sizeof keys);
    memset(sets, POISON, sizeof sets);
    memset(hdr, POISON, sizeof hdr);
    memset(pt, POISON, sizeof pt);

    fill_out();
    CHECK(quic_packet_seal(&keys, &hp, CH_LEVEL_HANDSHAKE, 1, QUIC_PN_MAX_LEN, hdr, sizeof hdr, pt,
                           sizeof pt, out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(out_untouched());

    fill_out();
    memset(&pn, POISON, sizeof pn);
    memset(&pt_len, POISON, sizeof pt_len);
    CHECK(quic_packet_open_handshake(&keys, &hp, out, sizeof out, 1, 0, &pn, &pt_len) ==
          CH_QUIC_DISCARD);
    CHECK(untouched(out, sizeof out) && untouched(&pn, sizeof pn) &&
          untouched(&pt_len, sizeof pt_len));

    fill_out();
    memset(&pn, POISON, sizeof pn);
    memset(&pt_len, POISON, sizeof pt_len);
    memset(&key_set, POISON, sizeof key_set);
    CHECK(quic_packet_open_application(sets, &hp, 0, out, sizeof out, 1, 0, 0, &key_set, &pn,
                                       &pt_len) == CH_QUIC_DISCARD);
    CHECK(untouched(out, sizeof out) && untouched(&key_set, sizeof key_set) &&
          untouched(&pn, sizeof pn) && untouched(&pt_len, sizeof pt_len));

    CHECK(quic_integrity_limit_exceeded(0) == 1);
    CHECK(quic_confidentiality_limit_reached(0) == 1);
}

static void test_initial_and_retry(void) {
    aes_public_key rx;
    aes_public_key tx;
    aes_public_key k;
    uint8_t dcid[AES_DCID_MAX];
    uint8_t hdr[8];
    uint8_t pt[8];
    uint8_t tag[GCM_TAG];
    uint64_t pn;
    size_t pt_len;
    memset(&rx, POISON, sizeof rx);
    memset(&tx, POISON, sizeof tx);
    memset(&k, POISON, sizeof k);
    memset(dcid, POISON, sizeof dcid);
    memset(hdr, POISON, sizeof hdr);
    memset(pt, POISON, sizeof pt);
    memset(tag, POISON, sizeof tag);

    CHECK(quic_initial_keys(&rx, &tx, dcid, sizeof dcid) == CH_EINVAL);
    CHECK(untouched(&rx, sizeof rx) && untouched(&tx, sizeof tx));

    fill_out();
    CHECK(quic_initial_seal(&k, 1, QUIC_PN_MAX_LEN, hdr, sizeof hdr, pt, sizeof pt, out, sizeof out,
                            &out_len) == CH_EINVAL);
    CHECK(out_untouched());

    fill_out();
    memset(&pn, POISON, sizeof pn);
    memset(&pt_len, POISON, sizeof pt_len);
    CHECK(quic_initial_open(&k, out, sizeof out, 1, 0, &pn, &pt_len) == CH_QUIC_DISCARD);
    CHECK(untouched(out, sizeof out) && untouched(&pn, sizeof pn) &&
          untouched(&pt_len, sizeof pt_len));

    CHECK(quic_retry_ok(hdr, sizeof hdr, tag) == 0);
}

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
    test_aes();
    test_gcm();
    test_keys();
    test_packet_pieces();
    test_packet_calls();
    test_initial_and_retry();
    test_session_entries();
    test_public_bytes();
    if (failures == 0) {
        (void)printf("quic_stub: every stub refuses and writes nothing\n");
    }
    return failures != 0;
}
