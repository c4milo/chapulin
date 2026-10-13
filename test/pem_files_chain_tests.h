// The chain call, ch_chain_from_pem. The cases cover these:
//  - the caller's entries, and the 255 certificates a chain holds;
//  - the caller's DER room, which the blocks share;
//  - the outer fields each block must read as;
//  - a text past any cap, and the strict text rule.
// Included by test/pem_files_test.c alone, which declares CHECK, the
// rooms, the file buffer, the chain helpers and the fixtures this file
// uses.
#ifndef CH_TEST_PEM_FILES_CHAIN_TESTS_H
#define CH_TEST_PEM_FILES_CHAIN_TESTS_H

// The caller's entries: chain_max certificates read and one more is
// refused, at twelve and at thirteen, and an array of no entry takes no
// chain. Past the caller's entries, ch_identity's chain_count, a
// uint8_t, holds 255: 255 certificates read and the 256th is refused.
static void test_chain_counts(void) {
    static uint8_t cert[512];
    static uint8_t block[1024];
    pfd_cert_shape shape = {1, 0, 0, 0};
    size_t cert_len = pfd_cert(cert, sizeof cert, webpki_corpus_server_pub, shape);
    size_t block_len = pem_armor(cert, cert_len, 64, "\n", block);
    uint8_t count = 0;
    for (size_t max = 12; max <= 13; max++) {
        size_t n = repeat_block(block, block_len, max, "");
        CHECK(chain_in(file, n, sizeof chain_der, max, &count) == CH_OK && count == max);
        n = repeat_block(block, block_len, max + 1, "");
        CHECK(chain_in(file, n, sizeof chain_der, max, &count) == CH_EINVAL && count == 0);
    }
    size_t n = repeat_block(block, block_len, 1, "");
    CHECK(chain_in(file, n, sizeof chain_der, 0, &count) == CH_EINVAL && count == 0);
    n = repeat_block(block, block_len, 255, "");
    CHECK(n != 0 && chain_in(file, n, sizeof chain_der, TEST_ENTRIES, &count) == CH_OK &&
          count == 255);
    n = repeat_block(block, block_len, 256, "");
    CHECK(n != 0 && chain_in(file, n, sizeof chain_der, TEST_ENTRIES, &count) == CH_EINVAL &&
          count == 0);
}

// The caller's DER room. A chain's blocks share it, so one certificate
// that fills it reads, and two that fill it read. One byte less room is
// refused in each shape. A leaf past the 3,072 bytes that this tree's
// client takes in one entry reads too. The Interop Runner's chain of nine
// needs that: its leaf is 5,515 bytes.
static void test_chain_room(void) {
    uint8_t count = 0;
    size_t n = cert_block_at(0, 5515);
    CHECK(n != 0 && chain_of(file, n, &count) == CH_OK && count == 1 && chain[0].len == 5515);
    n = cert_block_at(0, TEST_CHAIN_DER);
    CHECK(n != 0 && chain_in(file, n, TEST_CHAIN_DER, 1, &count) == CH_OK && count == 1 &&
          chain[0].len == TEST_CHAIN_DER);
    CHECK(n != 0 && chain_in(file, n, TEST_CHAIN_DER - 1, 1, &count) == CH_EINVAL && count == 0);

    const size_t leaf = TEST_CHAIN_DER - 1000;
    n = cert_block_at(0, leaf);
    size_t second = cert_block_at(n, 1000);
    CHECK(n != 0 && second != 0);
    CHECK(chain_in(file, n + second, TEST_CHAIN_DER, 2, &count) == CH_OK && count == 2 &&
          chain[1].len == 1000 && chain[1].der == chain[0].der + leaf);
    CHECK(chain_in(file, n + second, TEST_CHAIN_DER - 1, 2, &count) == CH_EINVAL && count == 0);
}

// A chain's blocks must each read as a certificate's outer fields. A
// block of other DER refuses the chain, whichever place it takes. So does
// a certificate with a byte after it.
static void test_chain_framing(void) {
    static const uint8_t tiny[] = {0x30, 0x03, 0x02, 0x01, 0x2a};
    static uint8_t cert[512];
    pfd_cert_shape shape = {1, 0, 0, 0};
    size_t cert_len = pfd_cert(cert, sizeof cert - 1, webpki_corpus_server_pub, shape);
    uint8_t count = 0;
    for (size_t bad = 0; bad < 2; bad++) {
        size_t n = 0;
        for (size_t b = 0; b < 2; b++) {
            n += b == bad ? pem_armor(tiny, sizeof tiny, 64, "\n", file + n)
                          : pem_armor(cert, cert_len, 64, "\n", file + n);
        }
        CHECK(chain_of(file, n, &count) == CH_EINVAL && count == 0);
    }
    size_t n = pem_armor(cert, cert_len, 64, "\n", file);
    CHECK(chain_of(file, n, &count) == CH_OK && count == 1);
    cert[cert_len] = 0x00;
    n = pem_armor(cert, cert_len + 1, 64, "\n", file);
    CHECK(chain_of(file, n, &count) == CH_EINVAL && count == 0);
}

// No cap bounds a chain's text. The r2 chain followed by 64 KiB of LF
// reads. That is more than the 25,392 bytes that a chain file took when a
// cap bounded it.
static void test_chain_long_text(void) {
    size_t base = sizeof pem_fixture_r2_chain;
    memcpy(file, pem_fixture_r2_chain, base);
    memset(file + base, '\n', 64 * 1024);
    uint8_t count = 0;
    CHECK(chain_of(file, base + 64 * 1024, &count) == CH_OK && count == 2);
}

// A chain file built from the r2 chain's two blocks with sep between
// them and tail after.
static size_t r2_with(const char *head, const char *sep, const char *tail) {
    const uint8_t *chain_text = pem_fixture_r2_chain;
    size_t chain_len = sizeof pem_fixture_r2_chain;
    size_t first_len = find(chain_text, chain_len, "-----END CERTIFICATE-----") +
                       strlen("-----END CERTIFICATE-----");
    size_t second = first_len + find(chain_text + first_len, chain_len - first_len, "-----BEGIN");
    size_t n = 0;
    memcpy(file + n, head, strlen(head));
    n += strlen(head);
    memcpy(file + n, chain_text, first_len);
    n += first_len;
    memcpy(file + n, sep, strlen(sep));
    n += strlen(sep);
    // The second block without its own final LF, so tail is all that follows.
    memcpy(file + n, chain_text + second, chain_len - second - 1);
    n += chain_len - second - 1;
    memcpy(file + n, tail, strlen(tail));
    return n + strlen(tail);
}

// A chain is strict: CR and LF alone outside its blocks, an LF before
// each next BEGIN line, and no text.
static void test_chain_grammar(void) {
    uint8_t count = 0;
    const struct {
        const char *head, *sep, *tail;
        int ok;
    } rows[] = {
        {"",       "\n",       "\n",     1},
        {"",       "\r\n",     "\r\n",   1},
        {"",       "\n\r\n",   "",       1},
        {"",       "\r\n\n",   "\n\n\r", 1},
        {"",       "\n\n\n",   "\r",     1},
        {"\n",     "\n",       "\n",     0}, // a terminator before the first block
        {"note\n", "\n",       "\n",     0}, // text before the first block
        {"",       "",         "\n",     0}, // END and BEGIN on one line
        {"",       "\r",       "\n",     0}, // a lone CR ends no line
        {"",       "\n\r",     "\n",     0}, // the byte before BEGIN is CR
        {"",       "\nnote\n", "\n",     0}, // text between the blocks
        {"",       "\n",       "\nx",    0}, // text after the last block
        {"",       "\n",       " ",      0}, // a space after the last END line
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        size_t n = r2_with(rows[i].head, rows[i].sep, rows[i].tail);
        int rc = chain_of(file, n, &count);
        CHECK(rows[i].ok ? (rc == CH_OK && count == 2) : (rc == CH_EINVAL && count == 0));
        if (rows[i].ok ? rc != CH_OK : rc != CH_EINVAL) {
            (void)fprintf(stderr, "  chain grammar row %zu\n", i);
        }
    }
    CHECK(chain_of(file, 0, &count) == CH_EINVAL && count == 0);
}

#endif
