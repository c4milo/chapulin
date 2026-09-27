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
//     entry 0 repeated one past CH_WEBPKI_FLIGHT_ENTRIES and
//     DIFF_LEAF_COPIES times, which pins alone accept because they store
//     no entry after the leaf
//   - with DIFF_PIN_BYTES single bytes of the list changed, each under the
//     leaf's pin, so a change after the key, which the rule never reads,
//     is compared as accepted
//
// The leaf_over_cert_max row's leaf is over the walk's CH_WEBPKI_CERT_MAX,
// which pins alone do not apply. The r2 leaf rebuilt at
// CH_WEBPKI_LEAF_PIN_CERT_MAX bytes, their cap, at one byte more, and at
// one byte past CH_WEBPKI_CERT_MAX is compared as entry 0 and as the
// entry after the r2 leaf.
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

// The longest reframe: the leaf and eight entries after it, the shape of
// the QUIC Interop Runner's amplificationlimit chain.
#define DIFF_LEAF_COPIES 9
_Static_assert(DIFF_LEAF_COPIES > CH_WEBPKI_FLIGHT_ENTRIES + 1,
               "the longest reframe runs past the walk's cap");

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

// Entry index of list, framed as pins alone frame it, each entry up to
// CH_WEBPKI_LEAF_PIN_CERT_MAX bytes. Returns 0 when the list holds fewer
// entries or frames none there.
static int diff_leaf_entry(const uint8_t *list, size_t list_len, size_t index, const uint8_t **cert,
                           size_t *cert_len) {
    rbuf r;
    rb_init(&r, list, list_len);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    for (size_t i = 0; i <= index; i++) {
        if (webpki_read_entry(&r, CH_WEBPKI_LEAF_PIN_CERT_MAX, cert, cert_len, &alert) != CH_OK) {
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
    size_t order[DIFF_LEAF_COPIES] = {0};
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
    memset(order, 0, sizeof order);
    wb_init(&w, framed, sizeof framed);
    diff_leaf_rewrite(&w, list, list_len, order, CH_WEBPKI_FLIGHT_ENTRIES + 1, 0);
    diff_leaf_compare(framed, w.len, pins, 1);
    wb_init(&w, framed, sizeof framed);
    diff_leaf_rewrite(&w, list, list_len, order, DIFF_LEAF_COPIES, 0);
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

// The r2 leaf rebuilt at size bytes, the bytes the spec's r2LeafOfSize
// builds: its TBSCertificate fields through the key, then an extensions
// [3] TLV holding a SEQUENCE of zero bytes, which
// webpki_read_certificate_key frames and does not read, then its
// signatureAlgorithm and signature. Every header it writes takes the
// four-byte form, which holds from 256 zero bytes up.
static size_t diff_leaf_of_size(uint8_t *out, size_t cap, size_t size) {
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (!diff_leaf_entry(webpki_corpus_message_r2 + 8, sizeof webpki_corpus_message_r2 - 8, 0,
                         &leaf, &leaf_len) ||
        webpki_read_certificate_key(leaf, leaf_len, &parsed, &alert) != CH_OK) {
        die("webpki_leaf: the r2 leaf does not read");
    }
    size_t fields_len = (size_t)(parsed.spki_tlv - parsed.tbs) + parsed.spki_tlv_len;
    const uint8_t *tail = parsed.tbs + parsed.tbs_len;
    size_t tail_len = leaf_len - (size_t)(tail - leaf);
    if (size < 16 + fields_len + tail_len + 256 || size > cap) {
        die("webpki_leaf: a rebuilt leaf size outside the driver's bounds");
    }
    size_t zeros = size - 16 - fields_len - tail_len;
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, 0x30);
    wb_u8(&w, 0x82);
    wb_u16(&w, (uint16_t)(size - 4));
    wb_u8(&w, 0x30);
    wb_u8(&w, 0x82);
    wb_u16(&w, (uint16_t)(fields_len + 8 + zeros));
    wb_bytes(&w, parsed.tbs, fields_len);
    wb_u8(&w, 0xa3);
    wb_u8(&w, 0x82);
    wb_u16(&w, (uint16_t)(4 + zeros));
    wb_u8(&w, 0x30);
    wb_u8(&w, 0x82);
    wb_u16(&w, (uint16_t)zeros);
    for (size_t i = 0; i < zeros; i++) {
        wb_u8(&w, 0);
    }
    wb_bytes(&w, tail, tail_len);
    if (w.err || w.len != size) {
        die("webpki_leaf: a rebuilt leaf of the wrong size");
    }
    return w.len;
}

// The r2 leaf rebuilt at each side of the pins-alone cap and one byte
// past the walk's cap, each as entry 0 and as the entry after the r2
// leaf, under the r2 leaf's pin.
static void diff_leaf_sizes(void) {
    static uint8_t big[CH_WEBPKI_LEAF_PIN_CERT_MAX + 1];
    static uint8_t list[DIFF_PIN_LIST_MAX];
    const uint8_t *r2_list = webpki_corpus_message_r2 + 8;
    size_t r2_list_len = sizeof webpki_corpus_message_r2 - 8;
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    uint8_t pins[1][SHA256_LEN];
    diff_leaf_entry_pin(r2_list, r2_list_len, 0, pins[0]);
    if (!diff_leaf_entry(r2_list, r2_list_len, 0, &leaf, &leaf_len)) {
        die("webpki_leaf: the r2 list does not frame");
    }
    static const size_t sizes[3] = {CH_WEBPKI_LEAF_PIN_CERT_MAX, CH_WEBPKI_LEAF_PIN_CERT_MAX + 1,
                                    CH_WEBPKI_CERT_MAX + 1};
    for (size_t i = 0; i < 3; i++) {
        size_t big_len = diff_leaf_of_size(big, sizeof big, sizes[i]);
        wbuf w;
        wb_init(&w, list, sizeof list);
        diff_pin_entry(&w, big, big_len, 0);
        diff_leaf_compare(list, w.len, pins, 1);
        wb_init(&w, list, sizeof list);
        diff_pin_entry(&w, leaf, leaf_len, 0);
        diff_pin_entry(&w, big, big_len, 0);
        diff_leaf_compare(list, w.len, pins, 1);
    }
}

static void diff_webpki_leaf_pin(void) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        diff_leaf_row(&webpki_corpus_chains[i]);
    }
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        diff_leaf_row(&webpki_capture_chains[i]);
    }
    diff_leaf_sizes();
    (void)printf("diff: webpki_leaf: %ld rows (%ld accepted), C == spec\n", diff_leaf_rows,
                 diff_leaf_accepted);
}

#endif
