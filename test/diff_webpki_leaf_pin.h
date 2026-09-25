// TRUST=webpki leaf pin differential section: webpki_pin.c's
// webpki_verify_leaf_pin against spec/lean/Spec/WebpkiPin.lean's
// verifyLeafPin, the rule for an X.509 chain under SPKI pins alone
// (docs/decisions.md 65).
//
// Every corpus and capture chain's CertificateEntry list is compared:
//
//   - under a pin on its leaf's key, first and second of two, a pin on its
//     second entry's key, a pin on nothing, and no pin
//   - reframed: the first two entries swapped, a trailing byte, an
//     extensions vector on the last entry, the list one byte short, and
//     one entry past CH_WEBPKI_FLIGHT_ENTRIES
//   - with DIFF_PIN_BYTES single bytes of the list changed, each under the
//     leaf's pin, so a change after the key, which the rule never reads,
//     is compared as accepted
//
// A pin on an entry's key is taken over what webpki_read_certificate_key
// reads, or is a pin on nothing when that reader refuses the entry.
//
// The reply is "ok <rsa|p256|p384> <key>", "unpinned", or "rejected" for
// every CH_EPROTO, as the walk's differential reports them; the
// unit tests in test/webpki_leaf_pins.h pin each alert.
//
// Included by test/diff_webpki_pin.h, whose helpers it reads, under
// CH_TRUST_WEBPKI. spec/lean/Main.lean serves the op:
//   webpki_leaf <pins> <list>
// where <pins> is "-" or hex pins joined by commas.
#ifndef CH_DIFF_WEBPKI_LEAF_PIN_H
#define CH_DIFF_WEBPKI_LEAF_PIN_H

static long diff_leaf_rows;
static long diff_leaf_accepted;

// The C side: the key on acceptance, and otherwise the refusal's name. A
// pair of return code and alert outside webpki_pin.h's table stops the
// run, because the spec could not name it.
static void diff_leaf_c_reply(const uint8_t *list, size_t list_len, uint8_t (*pins)[SHA256_LEN],
                              size_t pin_count, char *reply, size_t cap) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.spki_pins = (const uint8_t *)pins;
    cfg.spki_pin_count = pin_count;
    webpki_leaf_info leaf;
    memset(&leaf, 0xa5, sizeof leaf);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = webpki_verify_leaf_pin(list, list_len, &cfg, &leaf, &alert);
    if (rc == CH_OK) {
        if (leaf.alg < WEBPKI_KEY_RSA || leaf.alg > WEBPKI_KEY_P384 ||
            leaf.key_len > CH_WEBPKI_KEY_MAX || leaf.path_entries != 1 || leaf.anchor_index != 0) {
            die("webpki_leaf: an accepted key outside webpki_pin.h's contract");
        }
        static char key_hex[2 * CH_WEBPKI_KEY_MAX + 1];
        (void)hex_encode(key_hex, leaf.key, leaf.key_len);
        (void)snprintf(reply, cap, "ok %s %s", diff_pin_key_names[leaf.alg], key_hex);
        return;
    }
    if (rc == CH_EAUTH && alert == ALERT_BAD_CERTIFICATE) {
        (void)snprintf(reply, cap, "unpinned");
    } else if (rc == CH_EPROTO &&
               (alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_EXTENSION ||
                alert == ALERT_UNSUPPORTED_CERTIFICATE)) {
        (void)snprintf(reply, cap, "rejected");
    } else {
        die("webpki_leaf: a refusal outside webpki_pin.h's table");
    }
}

static void diff_leaf_compare(const uint8_t *list, size_t list_len, uint8_t (*pins)[SHA256_LEN],
                              size_t pin_count) {
    static char cmd[DIFF_PIN_LINE_MAX];
    static char want[DIFF_PIN_REPLY_MAX];
    diff_pin_command(cmd, "webpki_leaf", list, list_len, pins, pin_count);
    diff_leaf_c_reply(list, list_len, pins, pin_count, want, sizeof want);
    diff_leaf_rows++;
    diff_leaf_accepted += want[0] == 'o';
    expect(cmd, want);
}

// Entry index of list, framed as the walk frames it. Returns 0 when the
// list holds fewer entries or frames none there.
static int diff_leaf_entry(const uint8_t *list, size_t list_len, size_t index, const uint8_t **cert,
                           size_t *cert_len) {
    rbuf r;
    rb_init(&r, list, list_len);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    for (size_t i = 0; i <= index; i++) {
        if (webpki_read_entry(&r, CH_WEBPKI_CERT_MAX, cert, cert_len, &alert) != CH_OK) {
            return 0;
        }
    }
    return 1;
}

// The pin on entry index's key, read only as far as the key, or a pin on
// nothing when there is no such entry or the reader refuses it.
static void diff_leaf_entry_pin(const uint8_t *list, size_t list_len, size_t index,
                                uint8_t pin[SHA256_LEN]) {
    memcpy(pin, diff_pin_nothing, SHA256_LEN);
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (diff_leaf_entry(list, list_len, index, &cert, &cert_len) &&
        webpki_read_certificate_key(cert, cert_len, &parsed, &alert) == CH_OK) {
        sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, pin);
    }
}

// One list under each pin set: on its leaf first and second of two, on
// its second entry, on nothing, and none.
static void diff_leaf_sets(const uint8_t *list, size_t list_len) {
    uint8_t pins[2][SHA256_LEN];
    diff_leaf_entry_pin(list, list_len, 0, pins[0]);
    diff_leaf_compare(list, list_len, pins, 1);
    memcpy(pins[1], pins[0], SHA256_LEN);
    memcpy(pins[0], diff_pin_nothing, SHA256_LEN);
    diff_leaf_compare(list, list_len, pins, 2);
    diff_leaf_entry_pin(list, list_len, 1, pins[0]);
    diff_leaf_compare(list, list_len, pins, 1);
    memcpy(pins[0], diff_pin_nothing, SHA256_LEN);
    diff_leaf_compare(list, list_len, pins, 1);
    diff_leaf_compare(list, list_len, pins, 0);
}

// Every entry of list rewritten into w in the order order names, the last
// one with an extensions vector of extensions_len bytes.
static void diff_leaf_rewrite(wbuf *w, const uint8_t *list, size_t list_len, const size_t *order,
                              size_t count, size_t extensions_len) {
    for (size_t i = 0; i < count; i++) {
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        if (!diff_leaf_entry(list, list_len, order[i], &cert, &cert_len)) {
            die("webpki_leaf: a corpus list that does not frame");
        }
        diff_pin_entry(w, cert, cert_len, i + 1 == count ? extensions_len : 0);
    }
}

// One list reframed each way the framing or the leaf rule treats apart,
// under a pin on its leaf.
static void diff_leaf_frames(const uint8_t *list, size_t list_len) {
    static uint8_t framed[DIFF_PIN_LIST_MAX];
    uint8_t pins[1][SHA256_LEN];
    diff_leaf_entry_pin(list, list_len, 0, pins[0]);
    size_t count = 0;
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    while (count <= CH_WEBPKI_FLIGHT_ENTRIES &&
           diff_leaf_entry(list, list_len, count, &cert, &cert_len)) {
        count++;
    }
    size_t order[CH_WEBPKI_FLIGHT_ENTRIES + 1] = {0};
    wbuf w;
    if (count >= 2) {
        order[0] = 1;
        for (size_t i = 1; i < count; i++) {
            order[i] = i == 1 ? 0 : i;
        }
        wb_init(&w, framed, sizeof framed);
        diff_leaf_rewrite(&w, list, list_len, order, count, 0);
        diff_leaf_compare(framed, w.len, pins, 1);
    }
    for (size_t i = 0; i < count; i++) {
        order[i] = i;
    }
    wb_init(&w, framed, sizeof framed);
    diff_leaf_rewrite(&w, list, list_len, order, count, 1);
    diff_leaf_compare(framed, w.len, pins, 1);
    memcpy(framed, list, list_len);
    framed[list_len] = 0;
    diff_leaf_compare(framed, list_len + 1, pins, 1);
    diff_leaf_compare(list, list_len - 1, pins, 1);
    for (size_t i = 0; i <= CH_WEBPKI_FLIGHT_ENTRIES; i++) {
        order[i] = 0;
    }
    wb_init(&w, framed, sizeof framed);
    diff_leaf_rewrite(&w, list, list_len, order, CH_WEBPKI_FLIGHT_ENTRIES + 1, 0);
    diff_leaf_compare(framed, w.len, pins, 1);
    if (w.err) {
        die("webpki_leaf: a reframed list over DIFF_PIN_LIST_MAX");
    }
}

// Single bytes of the list changed, one drawn from each stride, each
// under a pin on the unchanged leaf's key.
static void diff_leaf_bytes(const uint8_t *list, size_t list_len) {
    static uint8_t changed[DIFF_PIN_LIST_MAX];
    uint8_t pins[1][SHA256_LEN];
    diff_leaf_entry_pin(list, list_len, 0, pins[0]);
    memcpy(changed, list, list_len);
    size_t stride = list_len < DIFF_PIN_BYTES ? 1 : list_len / DIFF_PIN_BYTES;
    for (size_t start = 0; start + stride <= list_len; start += stride) {
        size_t at = start + rng_below(stride);
        uint8_t delta = (uint8_t)(1 + rng_below(255));
        changed[at] ^= delta;
        diff_leaf_compare(changed, list_len, pins, 1);
        changed[at] ^= delta;
    }
}

// One row's CertificateEntry list, the Certificate message after its
// 8-byte header.
static void diff_leaf_row(const webpki_corpus_chain *row) {
    if (row->message_len <= 8 || row->message_len - 8 > DIFF_PIN_LIST_MAX - 1) {
        die("webpki_leaf: a corpus message outside the driver's bounds");
    }
    const uint8_t *list = row->message + 8;
    size_t list_len = row->message_len - 8;
    diff_leaf_sets(list, list_len);
    diff_leaf_frames(list, list_len);
    diff_leaf_bytes(list, list_len);
}

static void diff_webpki_leaf_pin(void) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        diff_leaf_row(&webpki_corpus_chains[i]);
    }
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        diff_leaf_row(&webpki_capture_chains[i]);
    }
    (void)printf("diff: webpki_leaf: %ld rows (%ld accepted), C == spec\n", diff_leaf_rows,
                 diff_leaf_accepted);
}

#endif
