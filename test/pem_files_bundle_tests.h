// The bundle call, ch_anchors_from_pem: the curl-style bundle file, a
// bundle of 300 roots, the caller's rooms at their boundaries, and the
// text rule. Included by test/pem_files_test.c alone, which declares
// CHECK, the rooms, the file buffer, the corpus helpers and the fixtures
// this file uses.
#ifndef CH_TEST_PEM_FILES_BUNDLE_TESTS_H
#define CH_TEST_PEM_FILES_BUNDLE_TESTS_H

// Whether the anchors verify the corpus or capture chain row, through the
// chain walk a session runs, and the index of the anchor that verified.
static int anchors_verify(const webpki_corpus_chain *row, size_t anchor_count,
                          size_t *anchor_index) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.anchors = anchors;
    cfg.anchor_count = anchor_count;
    cfg.hostname = text(row->hostname);
    cfg.hostname_len = strlen(row->hostname);
    cfg.now_seconds = row->now_seconds;
    webpki_leaf_info leaf;
    memset(&leaf, 0, sizeof leaf);
    uint8_t alert = 0;
    // The list after the message's 4-byte header, 1-byte context and
    // 3-byte list length.
    int rc = webpki_verify_chain(row->message + 8, row->message_len - 8, &cfg, &leaf, &alert);
    *anchor_index = leaf.anchor_index;
    return rc == CH_OK;
}

static const webpki_corpus_chain *corpus_row(const char *name) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof *webpki_corpus_chains; i++) {
        if (strcmp(webpki_corpus_chains[i].name, name) == 0) {
            return &webpki_corpus_chains[i];
        }
    }
    return NULL;
}

// The bundle file decodes to the five published roots and root_p384, in
// its order, each anchor equal to the one webpki_corpus.h extracted. The
// anchors then verify a captured public chain and the corpus r2 chain.
static void test_bundle_file(void) {
    size_t count = 0;
    CHECK(anchors_of(pem_fixture_bundle, sizeof pem_fixture_bundle, &count) == CH_OK);
    CHECK(count == 6);
    for (size_t i = 0; i < 5 && i < count; i++) {
        const webpki_corpus_anchor *want = &webpki_capture_anchors_published_roots[i];
        CHECK(same(anchors[i].name, anchors[i].name_len, want->name, want->name_len));
        CHECK(same(anchors[i].spki, anchors[i].spki_len, want->spki, want->spki_len));
    }
    const webpki_corpus_anchor *p384 = &webpki_corpus_anchors_root_p384[0];
    CHECK(count == 6 && same(anchors[5].name, anchors[5].name_len, p384->name, p384->name_len));
    CHECK(count == 6 && same(anchors[5].spki, anchors[5].spki_len, p384->spki, p384->spki_len));

    const webpki_corpus_chain *r2 = corpus_row("r2");
    size_t index = 0;
    CHECK(anchors_verify(&webpki_capture_chains[0], count, &index));
    CHECK(r2 != NULL && anchors_verify(r2, count, &index) && index == 5);
}

// A bundle of TEST_ENTRIES roots: synthetic roots first, whose Name no
// certificate names, then the bundle file's six. It decodes whole, and its
// last root, root_p384, verifies the r2 chain at index 299, past what one
// byte holds. So a system bundle of 150 roots or more decodes, ch_cfg
// takes it, and the chain walk reads to its last root (docs/decisions.md
// 131).
static void test_full_bundle(void) {
    static uint8_t cert[512];
    static uint8_t block[1024];
    pfd_cert_shape shape = {1, 0, 0, 0};
    size_t cert_len = pfd_cert(cert, sizeof cert, webpki_corpus_server_pub, shape);
    size_t block_len = pem_armor(cert, cert_len, 64, "\n", block);
    const size_t synthetic = TEST_ENTRIES - 6;
    size_t n = repeat_block(block, block_len, synthetic, "# a synthetic root\n");
    CHECK(n != 0 && n + 1 + sizeof pem_fixture_bundle <= sizeof file);
    file[n++] = '\n';
    memcpy(file + n, pem_fixture_bundle, sizeof pem_fixture_bundle);
    n += sizeof pem_fixture_bundle;
    size_t count = 0;
    CHECK(anchors_of(file, n, &count) == CH_OK && count == TEST_ENTRIES);
    const webpki_corpus_chain *r2 = corpus_row("r2");
    size_t index = 0;
    CHECK(r2 != NULL && anchors_verify(r2, count, &index) && index == TEST_ENTRIES - 1);
}

// The caller's entries: anchor_max roots read and one more is refused, and
// an array of no entry takes no bundle.
static void test_bundle_counts(void) {
    corpus_entries le =
        entries_of(webpki_corpus_message_letsencrypt, sizeof webpki_corpus_message_letsencrypt);
    static uint8_t block[1024];
    size_t block_len = pem_armor(le.cert[3], le.len[3], 64, "\n", block);
    size_t count = 0;
    for (size_t max = 1; max <= 13; max += 12) {
        size_t n = repeat_block(block, block_len, max, "# a root\n");
        CHECK(anchors_in(file, n, sizeof bundle_der, max, &count) == CH_OK && count == max);
        n = repeat_block(block, block_len, max + 1, "# a root\n");
        CHECK(anchors_in(file, n, sizeof bundle_der, max, &count) == CH_EINVAL && count == 0);
    }
    size_t n = repeat_block(block, block_len, 1, "");
    CHECK(anchors_in(file, n, sizeof bundle_der, 0, &count) == CH_EINVAL && count == 0);
}

// The caller's DER room: the roots share it, so a room of exactly their
// DER reads, and one byte less is refused. A root past the 3,072 bytes a
// session's chain walk takes in one entry reads too: a root is no entry.
static void test_bundle_room(void) {
    corpus_entries le =
        entries_of(webpki_corpus_message_letsencrypt, sizeof webpki_corpus_message_letsencrypt);
    size_t root_len = le.len[3];
    static uint8_t block[1024];
    size_t block_len = pem_armor(le.cert[3], root_len, 64, "\n", block);
    size_t count = 0;
    for (size_t roots = 1; roots <= 2; roots++) {
        size_t n = repeat_block(block, block_len, roots, "");
        CHECK(anchors_in(file, n, roots * root_len, 2, &count) == CH_OK && count == roots);
        CHECK(anchors_in(file, n, roots * root_len - 1, 2, &count) == CH_EINVAL && count == 0);
    }
    size_t n = cert_block_at(0, 3073);
    CHECK(n != 0 && anchors_in(file, n, 3073, 1, &count) == CH_OK && count == 1);
    CHECK(n != 0 && anchors_in(file, n, 3072, 1, &count) == CH_EINVAL && count == 0);
}

// A bundle skips each line that holds no "-----BEGIN ", and its END lines
// end their lines. A BEGIN line of another label refuses it, and so does
// "-----BEGIN " at any byte but a line's first (docs/decisions.md 131). No
// cap bounds its text: a bundle under more text than a bundle of twelve
// roots once took reads.
static void test_bundle_grammar(void) {
    corpus_entries le =
        entries_of(webpki_corpus_message_letsencrypt, sizeof webpki_corpus_message_letsencrypt);
    static uint8_t block[1024];
    size_t block_len = pem_armor(le.cert[3], le.len[3], 64, "\n", block);
    const struct {
        const char *head, *tail;
        size_t count; // 0: refused
    } rows[] = {
        {"",                                                               "",                             1},
        {"# a comment\n\nRoot\n====\n",                                    "\ntrailing text",              1},
        {"no newline before BEGIN ",                                       "",                             0}, // BEGIN is not at a line start
        {" ",                                                              "",                             0}, // an indented BEGIN line
        {"\xef\xbb\xbf",                                                   "",                             0}, // a UTF-8 byte-order mark
        {"Root -----BEGIN CERTIFICATE-----\n",                             "",                             0}, // a BEGIN line inside a name line
        {"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "",                             0}, // another label
        {"-----BEGIN CERTIFICATE----\n",                                   "",                             0}, // a broken BEGIN line
        {"-----BEGIN \n",                                                  "",                             0}, // a BEGIN line of no label
        {"# blocks open with -----BEGIN \n",                               "",                             0}, // "-----BEGIN " in a comment
        {"",                                                               "# a -----BEGIN X509 CRL-----", 0}, // the same after the block
        {"# blocks open with -----BEGIN\n",                                "",                             1}, // no space after it: text
        {"# -----BEGIN-----\n",                                            "\n# -----BEGINNING\n",         1}, // text
        {"",                                                               "-----END CERTIFICATE-----\n",  1}, // a stray END line is text
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        size_t n = 0;
        memcpy(file + n, rows[i].head, strlen(rows[i].head));
        n += strlen(rows[i].head);
        memcpy(file + n, block, block_len);
        n += block_len;
        memcpy(file + n, rows[i].tail, strlen(rows[i].tail));
        n += strlen(rows[i].tail);
        size_t count = 0;
        int rc = anchors_of(file, n, &count);
        CHECK(rows[i].count ? (rc == CH_OK && count == rows[i].count)
                            : (rc == CH_EINVAL && count == 0));
        if (rows[i].count ? rc != CH_OK : rc != CH_EINVAL) {
            (void)fprintf(stderr, "  bundle grammar row %zu\n", i);
        }
    }
    // An END line with text after it on its own line is refused. So is
    // one that a lone CR follows, which ends no line. So are a block whose
    // body breaks the grammar and a file with no block.
    size_t count = 0;
    size_t n = block_len - 1;
    memcpy(file, block, n);
    memcpy(file + n, " note\n", 6);
    CHECK(anchors_of(file, n + 6, &count) == CH_EINVAL && count == 0);
    memcpy(file + n, "\rnote\n", 6);
    CHECK(anchors_of(file, n + 6, &count) == CH_EINVAL && count == 0);
    memcpy(file + n, "\r\nnote\n", 7);
    CHECK(anchors_of(file, n + 7, &count) == CH_OK && count == 1);
    static const uint8_t broken_body[] = {'M', 'I', 'I', '!'};
    n = pem_wrap_text(broken_body, sizeof broken_body, 64, "\n", file);
    CHECK(anchors_of(file, n, &count) == CH_EINVAL);
    CHECK(anchors_of(text("# nothing here\n"), 15, &count) == CH_EINVAL && count == 0);
    CHECK(anchors_of(file, 0, &count) == CH_EINVAL);

    // A block behind a byte-order mark, an indent or a tab is refused,
    // whichever block it is. The call does not skip a CERTIFICATE block
    // with the text around it.
    const char *const before[] = {"", "\xef\xbb\xbf", "  ", "\t"};
    for (size_t first = 0; first < 2; first++) {
        for (size_t i = 0; i < sizeof before / sizeof *before; i++) {
            n = 0;
            for (size_t b = 0; b < 2; b++) {
                const char *head = b == first ? before[i] : "";
                memcpy(file + n, head, strlen(head));
                n += strlen(head);
                memcpy(file + n, block, block_len);
                n += block_len;
            }
            int rc = anchors_of(file, n, &count);
            CHECK(i == 0 ? (rc == CH_OK && count == 2) : (rc == CH_EINVAL && count == 0));
        }
    }

    // A block under another label refuses the bundle, before or after a
    // root that reads. So no block that opens at a BEGIN line drops out
    // without an error. The rows are OpenSSL's TRUSTED CERTIFICATE, the
    // legacy X509 CERTIFICATE and X.509 CERTIFICATE, and a CRL
    // (docs/decisions.md 131). The same certificate under its own label
    // reads, so the label alone refuses.
    const char *const other_labels[] = {"TRUSTED CERTIFICATE", "X509 CERTIFICATE",
                                        "X.509 CERTIFICATE", "X509 CRL", "CERTIFICATE"};
    const size_t other_count = sizeof other_labels / sizeof *other_labels;
    for (size_t i = 0; i < other_count; i++) {
        int reads = i == other_count - 1;
        for (size_t other_first = 0; other_first < 2; other_first++) {
            n = 0;
            for (size_t b = 0; b < 2; b++) {
                const char *label = b == other_first ? other_labels[i] : "CERTIFICATE";
                size_t root = b == other_first ? 2 : 3;
                n += pem_armor_label(label, le.cert[root], le.len[root], 64, "\n", file + n);
            }
            int rc = anchors_of(file, n, &count);
            CHECK(reads ? (rc == CH_OK && count == 2) : (rc == CH_EINVAL && count == 0));
            if (reads ? rc != CH_OK : rc != CH_EINVAL) {
                (void)fprintf(stderr, "  bundle label %s, first %zu\n", other_labels[i],
                              other_first);
            }
        }
    }

    // A block that is not a certificate refuses the bundle, even beside a
    // root that reads.
    static const uint8_t tiny[] = {0x30, 0x03, 0x02, 0x01, 0x2a};
    n = pem_armor(le.cert[3], le.len[3], 64, "\n", file);
    n += pem_armor(tiny, sizeof tiny, 64, "\n", file + n);
    CHECK(anchors_of(file, n, &count) == CH_EINVAL && count == 0);

    // 96 KiB of comment lines after a root: more than the 74,496 bytes a
    // bundle's text took when a cap bounded it.
    n = pem_armor(le.cert[3], le.len[3], 64, "\n", file);
    for (size_t i = 0; i < 96 * 1024 / 16; i++) {
        memcpy(file + n, "# comment line.\n", 16);
        n += 16;
    }
    CHECK(anchors_of(file, n, &count) == CH_OK && count == 1);
}

// A BEGIN line starts with the 11 bytes "-----BEGIN ", byte for byte. Each
// row writes a root whose first line is the row's line, before or after
// a root that reads. A line that differs inside the 11 bytes is text, and
// so are the root's body and its END line. The call then reads the other
// root alone and returns CH_OK, as OpenSSL reads one root. A line that
// differs after the 11 bytes is a BEGIN line, and refuses the bundle
// (docs/decisions.md 131).
static void test_bundle_first_lines(void) {
    corpus_entries le =
        entries_of(webpki_corpus_message_letsencrypt, sizeof webpki_corpus_message_letsencrypt);
    static uint8_t block[1024];
    size_t block_len = pem_armor(le.cert[3], le.len[3], 64, "\n", block);
    const size_t begin_len = strlen("-----BEGIN CERTIFICATE-----");
    const struct {
        const char *line;
        size_t count; // 0: refused
    } rows[] = {
        {"-----BEGIN CERTIFICATE-----",  2}, // the BEGIN line itself
        {"-----begin CERTIFICATE-----",  1}, // lower case inside the 11 bytes
        {"-----Begin CERTIFICATE-----",  1}, // the same
        {"-----BEGIN\tCERTIFICATE-----", 1}, // a tab for the space
        {"----BEGIN CERTIFICATE-----",   1}, // four dashes
        {"-----BEGIN CERTIFICATE----",   0}, // four dashes at the end
        {"-----BEGIN  CERTIFICATE-----", 0}, // two spaces
        {"-----BEGIN certificate-----",  0}, // a label in lower case
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        for (size_t changed = 0; changed < 2; changed++) {
            size_t n = 0;
            for (size_t b = 0; b < 2; b++) {
                const char *line = b == changed ? rows[i].line : "-----BEGIN CERTIFICATE-----";
                memcpy(file + n, line, strlen(line));
                n += strlen(line);
                memcpy(file + n, block + begin_len, block_len - begin_len);
                n += block_len - begin_len;
            }
            size_t count = 0;
            int rc = anchors_of(file, n, &count);
            CHECK(rows[i].count ? (rc == CH_OK && count == rows[i].count)
                                : (rc == CH_EINVAL && count == 0));
            if (rows[i].count ? rc != CH_OK : rc != CH_EINVAL) {
                (void)fprintf(stderr, "  bundle first line %zu, changed %zu\n", i, changed);
            }
        }
    }
}

#endif
