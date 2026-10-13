// The key call's EC PARAMETERS block and its cpu argument
// (docs/decisions.md 131). The cases cover these:
//  - the one shape of the block that a key file may hold, and every other
//    shape, refused;
//  - a key that `openssl ecparam -genkey` wrote;
//  - the cpu values each object takes and refuses.
// Included by test/pem_files_test.c alone, after
// test/pem_files_key_tests.h, whose helpers and buffers this file uses.
#ifndef CH_TEST_PEM_FILES_PARAMETERS_TESTS_H
#define CH_TEST_PEM_FILES_PARAMETERS_TESTS_H

#ifdef CH_CPU_RUNTIME
#include "test_cpu.h"
#endif

// One piece of a key file: bytes and their length.
typedef struct {
    const uint8_t *bytes;
    size_t len;
} key_piece;

// The pieces, one after another, in key_file. Returns the file's length.
static size_t key_join(const key_piece *pieces, size_t count) {
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        memcpy(key_file + n, pieces[i].bytes, pieces[i].len);
        n += pieces[i].len;
    }
    return n;
}

// A fixture's text with its final LF dropped, so the next piece starts
// on the END line's line.
static key_piece without_last_lf(const uint8_t *bytes, size_t len) {
    return (key_piece){bytes, len - 1};
}

// The EC PARAMETERS block above an EC PRIVATE KEY block, as `openssl
// ecparam -genkey` writes it. The block names prime256v1 and comes once,
// before a SEC 1 key. Line breaks that end in LF lie between the blocks.
// The call refuses every other shape:
//  - another curve, an explicit curve, other DER, a second block;
//  - the block before a PKCS #8 key or after the key, the block alone;
//  - any text or a lone CR between the blocks.
static void test_key_parameters(void) {
    corpus_entries r2 = r2_chain_entries();
    const key_piece params = {pem_fixture_params_prime256v1, sizeof pem_fixture_params_prime256v1};
    const key_piece sec1 = {pem_fixture_key_sec1, sizeof pem_fixture_key_sec1};
    const key_piece pkcs8 = {pem_fixture_key_pkcs8, sizeof pem_fixture_key_pkcs8};
    const key_piece p384 = {pem_fixture_params_secp384r1, sizeof pem_fixture_params_secp384r1};
    const key_piece explicit_curve = {pem_fixture_params_explicit,
                                      sizeof pem_fixture_params_explicit};
    const key_piece params_end = without_last_lf(params.bytes, params.len);
    const key_piece lf = {text("\n"), 1};
    const key_piece cr = {text("\r"), 1};
    const key_piece crlf_lf = {text("\r\n\n"), 3};
    const key_piece note = {text("note\n"), 5};
    const struct {
        key_piece pieces[4];
        size_t count;
        int ok;
    } rows[] = {
        {{params, sec1},              2, 1},
        {{params_end, crlf_lf, sec1}, 3, 1}, // blank lines between the blocks
        {{params, lf, sec1},          3, 1},
        {{p384, sec1},                2, 0}, // secp384r1
        {{explicit_curve, sec1},      2, 0}, // the curve's explicit parameters
        {{params, params, sec1},      3, 0}, // a second EC PARAMETERS block
        {{params, pkcs8},             2, 0}, // a PKCS #8 key under the block
        {{sec1, params},              2, 0}, // the block after the key
        {{params},                    1, 0}, // the block alone
        {{params, note, sec1},        3, 0}, // text between the blocks
        {{params_end, sec1},          2, 0}, // END and BEGIN on one line
        {{params_end, cr, sec1},      3, 0}, // a lone CR ends no line
        {{lf, params, sec1},          3, 0}, // a line break before the first block
        {{params, sec1, note},        3, 0}, // text after the key
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        size_t n = key_join(rows[i].pieces, rows[i].count);
        int rc = key_of(key_file, n, r2.cert[0], r2.len[0]);
        CHECK(rows[i].ok ? (rc == CH_OK && key_is_r2()) : (rc == CH_EINVAL && key_zeroed()));
        if (rows[i].ok ? rc != CH_OK : rc != CH_EINVAL) {
            (void)fprintf(stderr, "  key parameters row %zu\n", i);
        }
    }
    // The fixture openssl's output makes, and the same file with CR LF.
    CHECK(key_of(pem_fixture_key_sec1_params, sizeof pem_fixture_key_sec1_params, r2.cert[0],
                 r2.len[0]) == CH_OK &&
          key_is_r2());
    size_t n = 0;
    for (size_t i = 0; i < sizeof pem_fixture_key_sec1_params; i++) {
        if (pem_fixture_key_sec1_params[i] == '\n') {
            key_file[n++] = '\r';
        }
        key_file[n++] = pem_fixture_key_sec1_params[i];
    }
    CHECK(key_of(key_file, n, r2.cert[0], r2.len[0]) == CH_OK && key_is_r2());

    // x509_pem_parameters_are_p256 takes prime256v1's OBJECT IDENTIFIER
    // whole. The rows give it these bodies:
    //  - the OID with a byte after it;
    //  - the OID with a length octet of 7;
    //  - the OID itself, which the call takes;
    //  - the OID without its last byte, 0x07.
    // The last row comes after the row that the call takes. So the room
    // of 10 bytes holds that row's 0x07 in its last byte, and a check of
    // the whole room would find prime256v1 there.
    static const uint8_t trailing[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                       0x3d, 0x03, 0x01, 0x07, 0x00};
    static const uint8_t short_oid[] = {0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01};
    static uint8_t block[128];
    const struct {
        const uint8_t *der;
        size_t len;
    } bodies[] = {
        {trailing,  sizeof trailing    },
        {short_oid, sizeof short_oid   },
        {trailing,  sizeof trailing - 1},
        {trailing,  sizeof trailing - 2},
    };
    for (size_t i = 0; i < sizeof bodies / sizeof *bodies; i++) {
        size_t b = pem_armor_label("EC PARAMETERS", bodies[i].der, bodies[i].len, 64, "\n", block);
        key_piece pieces[2] = {
            {block, b},
            sec1
        };
        n = key_join(pieces, 2);
        int rc = key_of(key_file, n, r2.cert[0], r2.len[0]);
        CHECK(i == 2 ? (rc == CH_OK && key_is_r2()) : (rc == CH_EINVAL && key_zeroed()));
        if (i == 2 ? rc != CH_OK : rc != CH_EINVAL) {
            (void)fprintf(stderr, "  key parameters body %zu\n", i);
        }
        // The check itself. The call's room of 10 bytes refuses a longer
        // DER before the check runs.
        CHECK(x509_pem_parameters_are_p256(bodies[i].der, bodies[i].len) == (i == 2));
    }
}

// A key that `openssl ecparam -name prime256v1 -genkey` wrote, the
// command the QUIC Interop Runner's certs.sh runs. The file holds an EC
// PARAMETERS block, then the key. It decodes to the scalar of the
// ECPrivateKey that `openssl ec` wrote from it. It decodes to the point of
// the SubjectPublicKeyInfo that `openssl ec -pubout` wrote, against a leaf
// that carries that point.
static void test_genkey_file(void) {
    CHECK(sizeof pem_fixture_genkey_sec1 == 121 && sizeof pem_fixture_genkey_spki == 91);
    const uint8_t *scalar = pem_fixture_genkey_sec1 + 7;
    const uint8_t *point = pem_fixture_genkey_spki + 27;
    static uint8_t leaf[512];
    pfd_cert_shape shape = {1, 0, 0, 0};
    size_t leaf_len = pfd_cert(leaf, sizeof leaf, point, shape);
    CHECK(key_of(pem_fixture_genkey, sizeof pem_fixture_genkey, leaf, leaf_len) == CH_OK &&
          memcmp(key_priv, scalar, 32) == 0 && memcmp(key_pub, point, 64) == 0);
}

#ifdef CH_CPU_RUNTIME
// The cpu values a host object takes, as every init call takes them
// (test/test_cpu.h): CH_CPU_PROBED alone and every bit the architecture
// defines. The call refuses these values, with priv and pub zeroed:
//  - 0, and every defined bit but CH_CPU_PROBED;
//  - a bit no architecture defines, and the top bit;
//  - each bit of the other architecture.
// Under TEST_WIDEMUL_COUNTED, the point runs on the wide P-256 files when
// the value holds CH_CPU_CONSTANT_TIME_MULTIPLY. It runs on the files
// under their own names when the value does not, and never on the other
// copy.
static void test_key_cpu(void) {
    corpus_entries r2 = r2_chain_entries();
    uint32_t kept = key_cpu;
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        key_cpu = test_cpu_values[i];
        int rc = key_of(pem_fixture_key_sec1, sizeof pem_fixture_key_sec1, r2.cert[0], r2.len[0]);
        CHECK(test_cpu_taken(i) ? (rc == CH_OK && key_is_r2()) : (rc == CH_EINVAL && key_zeroed()));
    }
#ifdef TEST_WIDEMUL_COUNTED
    for (int stated = 0; stated < 2; stated++) {
        key_cpu = widemul_row_cpu(CH_CPU_PROBED, stated);
        widemul_end_calls calls = {0, 0};
        widemul_take_calls(&calls);
        calls = (widemul_end_calls){0, 0};
        CHECK(key_of(pem_fixture_key_sec1, sizeof pem_fixture_key_sec1, r2.cert[0], r2.len[0]) ==
              CH_OK);
        widemul_take_calls(&calls);
        CHECK(widemul_ran_own_copy(&calls, key_cpu));
    }
#endif
    key_cpu = kept;
}
#else
// A device object defines no bit, so it takes 0 and refuses every other
// value: CH_CPU_PROBED's bit, 1, the top bit and every bit.
static void test_key_cpu(void) {
    corpus_entries r2 = r2_chain_entries();
    const uint32_t refused[] = {1, 0x80000000U, 0xffffffffU};
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        key_cpu = refused[i];
        CHECK(key_of(pem_fixture_key_sec1, sizeof pem_fixture_key_sec1, r2.cert[0], r2.len[0]) ==
                  CH_EINVAL &&
              key_zeroed());
    }
    key_cpu = 0;
    CHECK(key_of(pem_fixture_key_sec1, sizeof pem_fixture_key_sec1, r2.cert[0], r2.len[0]) ==
              CH_OK &&
          key_is_r2());
}
#endif

#endif
