// TRUST=webpki raw public key differential section (webpki_pin.c's
// webpki_verify_raw_key against spec/Spec/WebpkiPin.lean's verifyRawKey).
//
// The keys are every SubjectPublicKeyInfo test/webpki_corpus.h carries:
// each anchor's, the impostor's included, and each certificate's in every
// corpus and capture row, read under the arm its position names. Each key
// is framed as the one entry of a RawPublicKey CertificateEntry list and
// compared:
//
//   - under a pin on it first, second of two and fourth of four, under a
//     pin on nothing, and under no pin
//   - reframed: a second entry, a trailing byte, an extensions vector of
//     one, two and 0xffff bytes, one byte after the key inside the entry,
//     and the list cut short after each of its first three bytes and one
//     byte before its end
//   - with DIFF_PIN_BYTES single bytes of the list changed, each under a
//     pin on the original key and a pin on the changed entry's bytes, so a
//     change the reader still accepts is compared as accepted
//
// and DIFF_PIN_RANDOM lists of random bytes up to one entry past
// CH_WEBPKI_SPKI_MAX, half of them with a u24 length that frames them.
//
// The reply is "ok <rsa|p256|p384> <key>", or the name of the refusal:
// "rejected", "unsupported_extension", "unsupported_certificate" or
// "unpinned". The four are the pairs of return code and alert the C tells
// apart, and test/webpki_auth_pins.h pins which alert each one is.
//
// Included by test/diff_test.c after diff_driver.h (single translation
// unit). spec/Main.lean serves the op:
//   webpki_raw <pins> <list>
// where <pins> is "-" or hex pins joined by commas.
#ifndef CH_DIFF_WEBPKI_PIN_H
#define CH_DIFF_WEBPKI_PIN_H

// ch_cfg carries the pins only in a TRUST=webpki build, so webpki_pin.c
// compiles only there, as the chain walk does.
#ifdef CH_TRUST_WEBPKI

#include "buf.h"
#include "handshake_message.h"
#include "sha256.h"
#include "webpki.h"
#include "webpki_corpus.h"
#include "webpki_pin.h"

// One list: one entry of up to one byte past the cap, a second entry,
// an extensions vector at its u16 maximum, and a trailing byte.
#define DIFF_PIN_LIST_MAX ((size_t)2 * (CH_WEBPKI_SPKI_MAX + 6) + 0xffff + 8)
#define DIFF_PIN_LINE_MAX ((size_t)2 * DIFF_PIN_LIST_MAX + (size_t)CH_SPKI_PIN_MAX * 65 + 64)
#define DIFF_PIN_REPLY_MAX ((size_t)2 * CH_WEBPKI_KEY_MAX + 32)
// The keys the corpus carries, with room to spare.
#define DIFF_PIN_KEYS_MAX 96
// Single bytes of a list changed, one drawn from each stride.
#define DIFF_PIN_BYTES 24
// Lists of random bytes.
#define DIFF_PIN_RANDOM 400

static long diff_pin_rows;
static long diff_pin_accepted;

static const char *const diff_pin_key_names[4] = {"-", "rsa", "p256", "p384"};

// One DER SubjectPublicKeyInfo, pointing into the corpus header.
typedef struct {
    const uint8_t *der;
    size_t len;
} diff_pin_key;

static diff_pin_key diff_pin_keys[DIFF_PIN_KEYS_MAX];
static size_t diff_pin_key_count;

// A pin no corpus key hashes to.
static const uint8_t diff_pin_nothing[SHA256_LEN] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

// The C side: the key on acceptance, and otherwise the refusal's name.
// A pair of return code and alert outside webpki_pin.h's table stops the
// run, because the spec could not name it.
static void diff_pin_c_reply(const uint8_t *list, size_t list_len, uint8_t (*pins)[SHA256_LEN],
                             size_t pin_count, char *reply, size_t cap) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.spki_pins = (const uint8_t (*)[SHA256_LEN])pins;
    cfg.spki_pin_count = pin_count;
    webpki_leaf_info leaf;
    memset(&leaf, 0xa5, sizeof leaf);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = webpki_verify_raw_key(list, list_len, &cfg, &leaf, &alert);
    if (rc == CH_OK) {
        if (leaf.alg < WEBPKI_KEY_RSA || leaf.alg > WEBPKI_KEY_P384 ||
            leaf.key_len > CH_WEBPKI_KEY_MAX || leaf.path_entries != 0 || leaf.anchor_index != 0) {
            die("webpki_raw: an accepted key outside webpki_pin.h's contract");
        }
        static char key_hex[2 * CH_WEBPKI_KEY_MAX + 1];
        (void)hex_encode(key_hex, leaf.key, leaf.key_len);
        (void)snprintf(reply, cap, "ok %s %s", diff_pin_key_names[leaf.alg], key_hex);
        return;
    }
    if (rc == CH_EAUTH && alert == ALERT_BAD_CERTIFICATE) {
        (void)snprintf(reply, cap, "unpinned");
    } else if (rc == CH_EPROTO && alert == ALERT_BAD_CERTIFICATE) {
        (void)snprintf(reply, cap, "rejected");
    } else if (rc == CH_EPROTO && alert == ALERT_UNSUPPORTED_EXTENSION) {
        (void)snprintf(reply, cap, "unsupported_extension");
    } else if (rc == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE) {
        (void)snprintf(reply, cap, "unsupported_certificate");
    } else {
        die("webpki_raw: a refusal outside webpki_pin.h's table");
    }
}

static void diff_pin_compare(const uint8_t *list, size_t list_len, uint8_t (*pins)[SHA256_LEN],
                             size_t pin_count) {
    static char cmd[DIFF_PIN_LINE_MAX];
    static char want[DIFF_PIN_REPLY_MAX];
    if (list_len > DIFF_PIN_LIST_MAX || pin_count > CH_SPKI_PIN_MAX) {
        die("webpki_raw: a driver case over its bounds");
    }
    int at = snprintf(cmd, sizeof cmd, "webpki_raw ");
    if (pin_count == 0) {
        cmd[at++] = '-';
    }
    for (size_t i = 0; i < pin_count; i++) {
        if (i > 0) {
            cmd[at++] = ',';
        }
        at += (int)hex_encode(cmd + at, pins[i], SHA256_LEN);
    }
    cmd[at++] = ' ';
    (void)hex_encode(cmd + at, list, list_len);
    diff_pin_c_reply(list, list_len, pins, pin_count, want, sizeof want);
    diff_pin_rows++;
    diff_pin_accepted += want[0] == 'o';
    expect(cmd, want);
}

// Records a key once, however many rows carry it.
static void diff_pin_add_key(const uint8_t *der, size_t len) {
    for (size_t i = 0; i < diff_pin_key_count; i++) {
        if (diff_pin_keys[i].len == len && memcmp(diff_pin_keys[i].der, der, len) == 0) {
            return;
        }
    }
    if (diff_pin_key_count == DIFF_PIN_KEYS_MAX) {
        die("webpki_raw: more corpus keys than DIFF_PIN_KEYS_MAX");
    }
    diff_pin_keys[diff_pin_key_count].der = der;
    diff_pin_keys[diff_pin_key_count].len = len;
    diff_pin_key_count++;
}

// A row's anchor keys and certificate keys.
static void diff_pin_row_keys(const webpki_corpus_chain *row) {
    for (size_t i = 0; i < row->anchor_count; i++) {
        diff_pin_add_key(row->anchors[i].spki, row->anchors[i].spki_len);
    }
    rbuf r;
    rb_init(&r, row->message, row->message_len);
    rb_skip(&r, 8); // msg_type, length, empty context, list length
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    for (size_t index = 0;
         webpki_read_entry(&r, CH_WEBPKI_CERT_MAX, &cert, &cert_len, &alert) == CH_OK; index++) {
        webpki_cert parsed;
        if (webpki_parse_certificate(cert, cert_len, index != 0, &parsed, &alert) == CH_OK) {
            diff_pin_add_key(parsed.spki_tlv, parsed.spki_tlv_len);
        }
    }
}

// Frames one entry: a u24 length, data, and a u16 extensions length with
// that many zero bytes.
static void diff_pin_entry(wbuf *w, const uint8_t *data, size_t data_len, size_t extensions_len) {
    wb_u24(w, (uint32_t)data_len);
    wb_bytes(w, data, data_len);
    wb_u16(w, (uint16_t)extensions_len);
    for (size_t i = 0; i < extensions_len; i++) {
        wb_u8(w, 0);
    }
}

// One key under each pin set: on it first, second of two and fourth of
// four, on nothing, and none.
static void diff_pin_sets(const diff_pin_key *key, const uint8_t *list, size_t list_len) {
    uint8_t pins[CH_SPKI_PIN_MAX][SHA256_LEN];
    for (size_t i = 0; i < CH_SPKI_PIN_MAX; i++) {
        memcpy(pins[i], diff_pin_nothing, SHA256_LEN);
        pins[i][0] = (uint8_t)i;
    }
    sha256_of(key->der, key->len, pins[0]);
    diff_pin_compare(list, list_len, pins, 1);
    memcpy(pins[1], pins[0], SHA256_LEN);
    memcpy(pins[0], diff_pin_nothing, SHA256_LEN);
    diff_pin_compare(list, list_len, pins, 2);
    memcpy(pins[CH_SPKI_PIN_MAX - 1], pins[1], SHA256_LEN);
    pins[1][0] ^= 0x01;
    diff_pin_compare(list, list_len, pins, CH_SPKI_PIN_MAX);
    diff_pin_compare(list, list_len, pins, 1);
    diff_pin_compare(list, list_len, pins, 0);
}

// One key reframed each way the framing refuses, under a pin on it.
static void diff_pin_frames(const diff_pin_key *key) {
    static uint8_t list[DIFF_PIN_LIST_MAX];
    static uint8_t longer[CH_WEBPKI_SPKI_MAX + 1];
    uint8_t pins[1][SHA256_LEN];
    sha256_of(key->der, key->len, pins[0]);
    static const size_t extension_lens[3] = {1, 2, 0xffff};
    wbuf w;
    wb_init(&w, list, sizeof list);
    diff_pin_entry(&w, key->der, key->len, 0);
    diff_pin_entry(&w, key->der, key->len, 0);
    diff_pin_compare(list, w.len, pins, 1);
    wb_init(&w, list, sizeof list);
    diff_pin_entry(&w, key->der, key->len, 0);
    wb_u8(&w, 0);
    diff_pin_compare(list, w.len, pins, 1);
    for (size_t i = 0; i < 3; i++) {
        wb_init(&w, list, sizeof list);
        diff_pin_entry(&w, key->der, key->len, extension_lens[i]);
        diff_pin_compare(list, w.len, pins, 1);
    }
    memcpy(longer, key->der, key->len);
    longer[key->len] = 0;
    wb_init(&w, list, sizeof list);
    diff_pin_entry(&w, longer, key->len + 1, 0);
    diff_pin_compare(list, w.len, pins, 1);
    wb_init(&w, list, sizeof list);
    diff_pin_entry(&w, key->der, key->len, 0);
    for (size_t cut = 0; cut < 3; cut++) {
        diff_pin_compare(list, cut, pins, 1);
    }
    diff_pin_compare(list, w.len - 1, pins, 1);
    if (w.err) {
        die("webpki_raw: a reframed list over DIFF_PIN_LIST_MAX");
    }
}

// Single bytes of the one-entry list changed, one drawn from each stride,
// each under a pin on the original key and one on the changed entry.
static void diff_pin_bytes(const diff_pin_key *key) {
    static uint8_t list[CH_WEBPKI_SPKI_MAX + 5];
    uint8_t pins[2][SHA256_LEN];
    wbuf w;
    wb_init(&w, list, sizeof list);
    diff_pin_entry(&w, key->der, key->len, 0);
    size_t list_len = w.len;
    sha256_of(key->der, key->len, pins[0]);
    size_t stride = list_len < DIFF_PIN_BYTES ? 1 : list_len / DIFF_PIN_BYTES;
    for (size_t start = 0; start + stride <= list_len; start += stride) {
        size_t at = start + rng_below(stride);
        uint8_t delta = (uint8_t)(1 + rng_below(255));
        list[at] ^= delta;
        rbuf r;
        rb_init(&r, list, list_len);
        rb_skip(&r, 3);
        sha256_of(rb_bytes(&r, key->len), key->len, pins[1]);
        diff_pin_compare(list, list_len, pins, 1);
        diff_pin_compare(list, list_len, pins + 1, 1);
        list[at] ^= delta;
    }
}

// Lists of random bytes, half with a u24 length that frames them as one
// entry and an empty extensions vector, so the reader and the pins run.
static void diff_pin_random(void) {
    static uint8_t list[CH_WEBPKI_SPKI_MAX + 6];
    uint8_t pins[1][SHA256_LEN];
    for (size_t i = 0; i < DIFF_PIN_RANDOM; i++) {
        size_t list_len = rng_below(sizeof list + 1);
        rng_fill(list, list_len);
        if ((i & 1U) != 0 && list_len >= 5) {
            size_t entry_len = list_len - 5;
            wbuf w;
            wb_init(&w, list, 3);
            wb_u24(&w, (uint32_t)entry_len);
            wb_init(&w, list + 3 + entry_len, 2);
            wb_u16(&w, 0);
            rbuf r;
            rb_init(&r, list, list_len);
            rb_skip(&r, 3);
            sha256_of(rb_bytes(&r, entry_len), entry_len, pins[0]);
        } else {
            rng_fill(pins[0], SHA256_LEN);
        }
        diff_pin_compare(list, list_len, pins, 1);
    }
}

static void diff_webpki_pin(void) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        diff_pin_row_keys(&webpki_corpus_chains[i]);
    }
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        diff_pin_row_keys(&webpki_capture_chains[i]);
    }
    static uint8_t list[CH_WEBPKI_SPKI_MAX + 5];
    for (size_t i = 0; i < diff_pin_key_count; i++) {
        const diff_pin_key *key = &diff_pin_keys[i];
        wbuf w;
        wb_init(&w, list, sizeof list);
        diff_pin_entry(&w, key->der, key->len, 0);
        if (w.err) {
            die("webpki_raw: a corpus key over CH_WEBPKI_SPKI_MAX");
        }
        diff_pin_sets(key, list, w.len);
        diff_pin_frames(key);
        diff_pin_bytes(key);
    }
    diff_pin_random();
    (void)printf("diff: webpki_raw: %zu corpus keys, %ld rows (%ld accepted), C == spec\n",
                 diff_pin_key_count, diff_pin_rows, diff_pin_accepted);
}

#else

static void diff_webpki_pin(void) {
    (void)printf("diff: webpki_raw: skipped, the pins compile under TRUST=webpki only\n");
}

#endif

#endif
