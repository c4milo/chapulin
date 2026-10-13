// The key call, ch_p256_key_from_pem. The cases cover these:
//  - the r2 leaf's key from the files openssl wrote;
//  - every optional field of both forms;
//  - the keys and leaves the call refuses;
//  - the scalar's range at both ends, and the text cap;
//  - what the call leaves on the stack.
// Included by test/pem_files_test.c alone,
// which declares CHECK, the corpus helpers and the fixtures this file
// uses. test/pem_files_parameters_tests.h holds the EC PARAMETERS block
// and the cpu argument.
#ifndef CH_TEST_PEM_FILES_KEY_TESTS_H
#define CH_TEST_PEM_FILES_KEY_TESTS_H

static uint8_t key_priv[32];
static uint8_t key_pub[64];
static uint8_t key_file[2 * CH_PEM_KEY_TEXT_MAX];
// The cpu value the key cases pass. It is 0 in a device object, which
// defines no bit. In a host object it is the value main sets before each
// pass.
static uint32_t key_cpu;

// The r2 leaf, whose key leaf_p256 is.
static corpus_entries r2_chain_entries(void) {
    return entries_of(webpki_corpus_message_r2, sizeof webpki_corpus_message_r2);
}

// One call with both outputs filled with a byte the call must replace.
static int key_of(const uint8_t *pem, size_t n, const uint8_t *leaf, size_t leaf_len) {
    memset(key_priv, 0x5a, sizeof key_priv);
    memset(key_pub, 0x5a, sizeof key_pub);
    return ch_p256_key_from_pem(key_cpu, pem, n, leaf, leaf_len, key_priv, key_pub);
}

// Whether a refusal zeroed both outputs, as pem_files.h says it does.
static int key_zeroed(void) {
    uint8_t acc = 0;
    for (size_t i = 0; i < sizeof key_priv; i++) {
        acc |= key_priv[i];
    }
    for (size_t i = 0; i < sizeof key_pub; i++) {
        acc |= key_pub[i];
    }
    return acc == 0;
}

static int key_is_r2(void) {
    return memcmp(key_priv, webpki_corpus_server_priv, 32) == 0 &&
           memcmp(key_pub, webpki_corpus_server_pub, 64) == 0;
}

// der armored under label, into key_file.
static size_t key_armor(const char *label, const uint8_t *der, size_t der_len) {
    return pem_armor_label(label, der, der_len, 64, "\n", key_file);
}

// The two files openssl wrote decode to the corpus key. So does every
// shape of optional fields that RFC 5915 admits in both forms, at two
// line widths and both terminators.
static void test_key_files(void) {
    corpus_entries r2 = r2_chain_entries();
    CHECK(key_of(pem_fixture_key_pkcs8, sizeof pem_fixture_key_pkcs8, r2.cert[0], r2.len[0]) ==
              CH_OK &&
          key_is_r2());
    CHECK(key_of(pem_fixture_key_sec1, sizeof pem_fixture_key_sec1, r2.cert[0], r2.len[0]) ==
              CH_OK &&
          key_is_r2());

    uint8_t der[CH_PEM_KEY_DER_MAX + 8];
    for (int curve = 0; curve < 2; curve++) {
        for (int point = 0; point < 2; point++) {
            pfd_key_shape shape = {curve, point, 32, 0, 0};
            size_t n = pfd_pkcs8(der, sizeof der, webpki_corpus_server_priv,
                                 webpki_corpus_server_pub, shape);
            size_t len = pem_armor_label("PRIVATE KEY", der, n, 48, "\r\n", key_file);
            CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_OK && key_is_r2());
            n = pfd_ec_private_key(der, sizeof der, webpki_corpus_server_priv,
                                   webpki_corpus_server_pub, shape);
            len = pem_armor_label("EC PRIVATE KEY", der, n, 7, "\n", key_file);
            // RFC 5915 section 3 requires the curve outside PKCS #8.
            int rc = key_of(key_file, len, r2.cert[0], r2.len[0]);
            CHECK(curve ? (rc == CH_OK && key_is_r2()) : (rc == CH_EINVAL && key_zeroed()));
        }
    }
    // The longest key the grammar admits is exactly CH_PEM_KEY_DER_MAX.
    size_t n = pfd_pkcs8(der, sizeof der, webpki_corpus_server_priv, webpki_corpus_server_pub,
                         pfd_key_full);
    CHECK(n == CH_PEM_KEY_DER_MAX);
}

// Files the call refuses whole: a password, another curve, another
// algorithm; a leaf whose key is not this one, or that is not a
// certificate; and a publicKey field that names another point.
static void test_key_refusals(void) {
    corpus_entries r2 = r2_chain_entries();
    const struct {
        const uint8_t *pem;
        size_t len;
    } refused[] = {
        {pem_fixture_key_encrypted,  sizeof pem_fixture_key_encrypted },
        {pem_fixture_key_p384_pkcs8, sizeof pem_fixture_key_p384_pkcs8},
        {pem_fixture_key_p384_sec1,  sizeof pem_fixture_key_p384_sec1 },
        {pem_fixture_key_rsa_pkcs8,  sizeof pem_fixture_key_rsa_pkcs8 },
    };
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        CHECK(key_of(refused[i].pem, refused[i].len, r2.cert[0], r2.len[0]) == CH_EINVAL &&
              key_zeroed());
    }
    const uint8_t *good = pem_fixture_key_sec1;
    size_t good_len = sizeof pem_fixture_key_sec1;
    CHECK(key_of(good, good_len, r2.cert[1], r2.len[1]) == CH_EINVAL && key_zeroed());
    CHECK(key_of(good, good_len, webpki_corpus_server_pub, 64) == CH_EINVAL && key_zeroed());
    CHECK(key_of(good, good_len, NULL, 0) == CH_EINVAL && key_zeroed());

    static const uint8_t gx_gy[64] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
        0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
        0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
        0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57,
        0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    uint8_t der[CH_PEM_KEY_DER_MAX];
    size_t n = pfd_ec_private_key(der, sizeof der, webpki_corpus_server_priv, gx_gy, pfd_key_full);
    size_t len = key_armor("EC PRIVATE KEY", der, n);
    CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_EINVAL && key_zeroed());
}

// The key grammar. The cases are the PKCS #8 fields the readers refuse,
// a scalar of another length, and a form under the other form's label.
// They include text outside the block, and a second block.
static void test_key_grammar(void) {
    corpus_entries r2 = r2_chain_entries();
    uint8_t der[CH_PEM_KEY_DER_MAX + 8];
    const pfd_key_shape refused[] = {
        {0, 1, 32, 0, 1}, // PrivateKeyInfo version 1
        {0, 1, 32, 1, 0}, // attributes after privateKey
        {0, 1, 31, 0, 0}, // a scalar one byte short
        {0, 1, 33, 0, 0}, // a scalar with a zero byte in front
    };
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        size_t n = pfd_pkcs8(der, sizeof der, webpki_corpus_server_priv, webpki_corpus_server_pub,
                             refused[i]);
        size_t len = key_armor("PRIVATE KEY", der, n);
        CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_EINVAL && key_zeroed());
    }
    size_t n = pfd_pkcs8(der, sizeof der, webpki_corpus_server_priv, webpki_corpus_server_pub,
                         pfd_key_full);
    size_t len = key_armor("EC PRIVATE KEY", der, n);
    CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_EINVAL);
    n = pfd_ec_private_key(der, sizeof der, webpki_corpus_server_priv, webpki_corpus_server_pub,
                           pfd_key_full);
    len = key_armor("PRIVATE KEY", der, n);
    CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_EINVAL);

    // A key file is strict, as a chain is.
    const uint8_t *sec1 = pem_fixture_key_sec1;
    size_t sec1_len = sizeof pem_fixture_key_sec1;
    key_file[0] = '\n';
    memcpy(key_file + 1, sec1, sec1_len);
    CHECK(key_of(key_file, sec1_len + 1, r2.cert[0], r2.len[0]) == CH_EINVAL);
    memcpy(key_file, sec1, sec1_len);
    memcpy(key_file + sec1_len, "\r\n\n", 3);
    CHECK(key_of(key_file, sec1_len + 3, r2.cert[0], r2.len[0]) == CH_OK && key_is_r2());
    key_file[sec1_len] = 'x';
    CHECK(key_of(key_file, sec1_len + 1, r2.cert[0], r2.len[0]) == CH_EINVAL);
    memcpy(key_file + sec1_len, sec1, sec1_len);
    CHECK(key_of(key_file, 2 * sec1_len, r2.cert[0], r2.len[0]) == CH_EINVAL && key_zeroed());
}

// A SEC 1 ECPrivateKey of the corpus leaf's scalar whose fields after
// the scalar are tail, written byte for byte inside its SEQUENCE.
static size_t sec1_with_tail(uint8_t *der, size_t cap, const uint8_t *tail, size_t tail_len) {
    pfd_key_shape bare = {0, 0, 32, 0, 0};
    size_t n =
        pfd_ec_private_key(der, cap, webpki_corpus_server_priv, webpki_corpus_server_pub, bare);
    if (n == 0 || n + tail_len > cap || der[1] + tail_len >= 0x80) {
        return 0;
    }
    der[1] = (uint8_t)(der[1] + tail_len);
    memcpy(der + n, tail, tail_len);
    return n + tail_len;
}

// The fields after the scalar, each written byte for byte. The curve must
// be prime256v1's OID whole. Nothing may follow the curve or the public
// key. A PKCS #8 PrivateKeyInfo whose SEQUENCE claims a byte fewer
// than it holds is refused too. Every refused key is the corpus leaf's
// scalar, so a reader that let one through would return the leaf's key.
static void test_key_fields(void) {
    corpus_entries r2 = r2_chain_entries();
    static const uint8_t prime256v1[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                         0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t secp256k1[] = {0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a};
    static const uint8_t prime192v1[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                         0x48, 0xce, 0x3d, 0x03, 0x01, 0x01};
    static const uint8_t point_head[] = {0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};
    static const uint8_t null_field[] = {0x05, 0x00};
    uint8_t tail[96];
    uint8_t der[CH_PEM_KEY_DER_MAX + 8];
    const struct {
        int curve; // 0: prime256v1, 1: secp256k1, 2: prime192v1
        int point; // 1: the publicKey field after the curve
        int null;  // 1: a NULL field after them
        int ok;
    } rows[] = {
        {0, 0, 0, 1},
        {0, 1, 0, 1},
        {1, 0, 0, 0}, // another curve, its OID five bytes
        {2, 0, 0, 0}, // another curve, its OID eight bytes as prime256v1's is
        {1, 1, 0, 0},
        {0, 0, 1, 0}, // a field after the curve
        {0, 1, 1, 0}, // a field after the public key
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        wbuf w;
        wb_init(&w, tail, sizeof tail);
        if (rows[i].curve == 0) {
            wb_bytes(&w, prime256v1, sizeof prime256v1);
        } else if (rows[i].curve == 1) {
            wb_bytes(&w, secp256k1, sizeof secp256k1);
        } else {
            wb_bytes(&w, prime192v1, sizeof prime192v1);
        }
        if (rows[i].point) {
            wb_bytes(&w, point_head, sizeof point_head);
            wb_bytes(&w, webpki_corpus_server_pub, 64);
        }
        if (rows[i].null) {
            wb_bytes(&w, null_field, sizeof null_field);
        }
        size_t n = sec1_with_tail(der, sizeof der, tail, w.len);
        CHECK(n != 0 && !w.err);
        size_t len = key_armor("EC PRIVATE KEY", der, n);
        int rc = key_of(key_file, len, r2.cert[0], r2.len[0]);
        CHECK(rows[i].ok ? (rc == CH_OK && key_is_r2()) : (rc == CH_EINVAL && key_zeroed()));
        if (rows[i].ok ? rc != CH_OK : rc != CH_EINVAL) {
            (void)fprintf(stderr, "  key field row %zu\n", i);
        }
    }

    // The longest PrivateKeyInfo, 150 bytes, has a 0x81 length of 147. A
    // length of 146 leaves the last byte outside the SEQUENCE.
    size_t n = pfd_pkcs8(der, sizeof der, webpki_corpus_server_priv, webpki_corpus_server_pub,
                         pfd_key_full);
    CHECK(n == CH_PEM_KEY_DER_MAX && der[1] == 0x81 && der[2] == 147);
    size_t len = key_armor("PRIVATE KEY", der, n);
    CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_OK && key_is_r2());
    der[2] = 146;
    len = key_armor("PRIVATE KEY", der, n);
    CHECK(key_of(key_file, len, r2.cert[0], r2.len[0]) == CH_EINVAL && key_zeroed());
}

// The scalar's range, 1 to n - 1, at both ends. A leaf of point G takes
// the scalar 1 and refuses 0. A leaf of -G = (Gx, p - Gy) takes n - 1 and
// refuses n.
static void test_scalar_range(void) {
    static const uint8_t g[64] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                                  0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                                  0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f,
                                  0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
                                  0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                                  0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    static const uint8_t minus_g[64] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
        0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
        0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0xb0, 0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80,
        0x65, 0x71, 0x18, 0x14, 0xb5, 0x83, 0xf0, 0x61, 0xe9, 0xd4, 0x31, 0xcc, 0xa9,
        0x94, 0xce, 0xa1, 0x31, 0x34, 0x49, 0xbf, 0x97, 0xc8, 0x40, 0xae, 0x0a};
    static const uint8_t n_minus_1[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                          0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50};
    uint8_t n_exact[32];
    memcpy(n_exact, n_minus_1, 32);
    n_exact[31] = 0x51;
    uint8_t one[32] = {0};
    one[31] = 1;
    const uint8_t zero[32] = {0};
    const struct {
        const uint8_t *scalar;
        const uint8_t *leaf_point;
        int ok;
    } rows[] = {
        {one,       g,       1},
        {zero,      g,       0},
        {n_minus_1, minus_g, 1},
        {n_exact,   minus_g, 0}
    };
    static uint8_t leaf[512];
    uint8_t der[CH_PEM_KEY_DER_MAX];
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        pfd_cert_shape shape = {1, 0, 0, 0};
        size_t leaf_len = pfd_cert(leaf, sizeof leaf, rows[i].leaf_point, shape);
        pfd_key_shape key = {1, 0, 32, 0, 0};
        size_t n = pfd_ec_private_key(der, sizeof der, rows[i].scalar, rows[i].leaf_point, key);
        size_t len = key_armor("EC PRIVATE KEY", der, n);
        int rc = key_of(key_file, len, leaf, leaf_len);
        CHECK(rows[i].ok ? (rc == CH_OK && memcmp(key_priv, rows[i].scalar, 32) == 0 &&
                            memcmp(key_pub, rows[i].leaf_point, 64) == 0)
                         : (rc == CH_EINVAL && key_zeroed()));
    }
}

// The key file's text cap. CH_PEM_KEY_TEXT_MAX bytes read, and one more
// is refused. The cases are a PKCS #8 file and a SEC 1 file under its EC
// PARAMETERS block, each padded with LF.
static void test_key_text_cap(void) {
    corpus_entries r2 = r2_chain_entries();
    const uint8_t *files[] = {pem_fixture_key_pkcs8, pem_fixture_key_sec1_params};
    const size_t lens[] = {sizeof pem_fixture_key_pkcs8, sizeof pem_fixture_key_sec1_params};
    CHECK(CH_PEM_KEY_TEXT_MAX == 452);
    for (size_t i = 0; i < 2; i++) {
        memcpy(key_file, files[i], lens[i]);
        memset(key_file + lens[i], '\n', CH_PEM_KEY_TEXT_MAX + 1 - lens[i]);
        CHECK(key_of(key_file, CH_PEM_KEY_TEXT_MAX, r2.cert[0], r2.len[0]) == CH_OK && key_is_r2());
        CHECK(key_of(key_file, CH_PEM_KEY_TEXT_MAX + 1, r2.cert[0], r2.len[0]) == CH_EINVAL &&
              key_zeroed());
    }
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

// The bytes the search reads below the caller. Under
// CH_CPU_CONSTANT_TIME_MULTIPLY the key call writes 3,712 bytes deep on
// arm64, through p256_wide_wipe_below's frame (docs/performance.md).
#define KEY_RESIDUE_BYTES 4096
static uint8_t key_residue[KEY_RESIDUE_BYTES];

static __attribute__((noinline)) void key_snapshot(void) {
    volatile uint8_t below[KEY_RESIDUE_BYTES];
    stack_residue_take(below, KEY_RESIDUE_BYTES, key_residue);
}

static __attribute__((noinline)) int key_call(const uint8_t *pem, size_t pem_len,
                                              const uint8_t *leaf, size_t leaf_len) {
    return ch_p256_key_from_pem(key_cpu, pem, pem_len, leaf, leaf_len, key_priv, key_pub);
}

// Whether the copy holds any 8 bytes of the scalar. The search reads the
// big-endian order, as the DER and the decoded copies hold it. It reads
// the reverse order too, as a little-endian word of the integer holds it.
// The reversed scalar is static. On the stack, the next call's snapshot
// would find this function's own copy, as gcc's x86-64 frames left it.
static int residue_holds_scalar(void) {
    static uint8_t reversed[32];
    for (size_t i = 0; i < 32; i++) {
        reversed[i] = webpki_corpus_server_priv[31 - i];
    }
    for (size_t s = 0; s + 8 <= 32; s++) {
        for (size_t i = 0; i + 8 <= KEY_RESIDUE_BYTES; i++) {
            if (memcmp(key_residue + i, webpki_corpus_server_priv + s, 8) == 0 ||
                memcmp(key_residue + i, reversed + s, 8) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

// What a call leaves below its caller: no 8 bytes of the scalar, from
// each form. The search runs on success, and on a refusal that decoded
// the scalar first.
static void test_key_wipes(void) {
    const char *reason = stack_residue_unsearched();
    if (reason != NULL) {
        (void)printf("pem_files_test: the stack is not searched: %s\n", reason);
        return;
    }
    corpus_entries r2 = r2_chain_entries();
    const uint8_t *files[] = {pem_fixture_key_pkcs8, pem_fixture_key_sec1,
                              pem_fixture_key_sec1_params};
    const size_t lens[] = {sizeof pem_fixture_key_pkcs8, sizeof pem_fixture_key_sec1,
                           sizeof pem_fixture_key_sec1_params};
    for (size_t i = 0; i < 3; i++) {
        CHECK(key_call(files[i], lens[i], r2.cert[0], r2.len[0]) == CH_OK);
        key_snapshot();
        CHECK(!residue_holds_scalar());
        CHECK(key_call(files[i], lens[i], r2.cert[1], r2.len[1]) == CH_EINVAL);
        key_snapshot();
        CHECK(!residue_holds_scalar());
    }
}

#endif
