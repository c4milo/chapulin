// Grammar strictness for the provisioning PEM decoder. Every boundary
// gets an exact pair: the last valid encoding passes and the first
// invalid one fails. The certificate under test is the build's own
// generated vector, armoured here rather than embedded as text, so
// these cases survive regeneration by test/gen_x509vectors.py.
//
// Real OpenSSL text is checked in test/e2e.sh instead, against the
// caroot.pem that suite already mints.
#ifndef CH_PEM_TESTS_H
#define CH_PEM_TESTS_H

#include "pem.h"
#include "pem_armor.h"

// A rejection must return CH_EINVAL and leave the length at zero. The
// seed is non-zero so an untouched out-parameter fails rather than
// passing by accident.
static int pemt_rejects(const uint8_t *pem, size_t n) {
    uint8_t der[CH_X509_MAX];
    size_t der_len = 0x5a5a;
    return pem_decode_certificate(pem, n, der, &der_len) == CH_EINVAL && der_len == 0;
}

static int pemt_accepts(const uint8_t *pem, size_t n, const uint8_t *want, size_t want_len) {
    uint8_t der[CH_X509_MAX];
    size_t der_len = 0x5a5a;
    return pem_decode_certificate(pem, n, der, &der_len) == CH_OK && der_len == want_len &&
           memcmp(der, want, want_len) == 0;
}

static void pem_tests_limits(const uint8_t *buf, uint8_t *mut, size_t base, const uint8_t *cert,
                             size_t cert_len);

static void pem_tests(void) {
    static uint8_t buf[CH_PEM_MAX + 64];
    static uint8_t mut[CH_PEM_MAX + 64];
    const uint8_t *cert = good_cert;
    size_t cert_len = good_cert_len;

    // Every line width the grammar admits decodes to the same bytes,
    // under both terminators. 4 is the narrowest the cap budgets for.
    for (size_t i = 0; i < sizeof pem_armor_widths / sizeof *pem_armor_widths; i++) {
        for (int crlf = 0; crlf < 2; crlf++) {
            size_t n = pem_armor(cert, cert_len, pem_armor_widths[i], crlf ? "\r\n" : "\n", buf);
            CHECK(n <= CH_PEM_MAX);
            CHECK(pemt_accepts(buf, n, cert, cert_len));
        }
    }

    // The case the cap is sized for: a certificate at the parser's own
    // ceiling, wrapped at the narrowest width the cap budgets for, with
    // the two-byte terminator. Measured margin is 8 bytes on both arms,
    // because the formula budgets 64 for boundary lines that cost 56 --
    // thin enough that changing either boundary breaks it here.
    static uint8_t ceiling[CH_X509_MAX];
    for (size_t i = 0; i < sizeof ceiling; i++) {
        ceiling[i] = (uint8_t)(i * 7 + 3);
    }
    size_t worst = pem_armor(ceiling, sizeof ceiling, 4, "\r\n", buf);
    // Exactly 8 on both arms: 3136 - 3128 and 1600 - 1592. The formula
    // budgets 64 bytes for boundary lines that cost 56, so a change to
    // either boundary moves this difference, not just the inequality.
    CHECK(CH_PEM_MAX - worst == 8);
    CHECK(pemt_accepts(buf, worst, ceiling, sizeof ceiling));

    size_t base = pem_armor(cert, cert_len, 64, "\n", buf);

    // The END line's own terminator is optional; nothing else after it is.
    CHECK(pemt_accepts(buf, base - 1, cert, cert_len));
    memcpy(mut, buf, base);
    mut[base] = 'x';
    CHECK(pemt_rejects(mut, base + 1));

    // Two blocks: the pin slots are ordered in time and a PEM file's
    // blocks are ordered by hierarchy, so this is unresolvable, not a
    // choice. pem.h carries the argument. A SMALL block, twice, for two
    // reasons: two armoured certificates overflow the buffer on the RSA
    // arm (glibc's fortify caught exactly that in CI), and their total
    // is over CH_PEM_MAX, so the cap would reject the input before the
    // second-block rule was ever exercised.
    {
        static const uint8_t tiny[] = {0x30, 0x03, 0x02, 0x01, 0x2a};
        size_t one = pem_armor(tiny, sizeof tiny, 64, "\n", mut);
        (void)memcpy(mut + one, mut, one);
        CHECK(one * 2 <= CH_PEM_MAX);
        CHECK(pemt_rejects(mut, one * 2));
    }

    // RFC 7468 permits explanatory text before the boundary; this
    // grammar does not.
    mut[0] = 'n';
    memcpy(mut + 1, buf, base);
    CHECK(pemt_rejects(mut, base + 1));

    // One byte wrong in either boundary, and one byte outside the
    // alphabet in the body. 45 and 95 are base64url's two characters.
    const struct {
        size_t off;
        uint8_t val;
    } bad[] = {
        {8,        'X' },
        {base - 6, 'X' },
        {30,       '!' },
        {30,       '-' },
        {30,       '_' },
        {30,       ' ' },
        {30,       '\t'},
        {30,       0   }
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        memcpy(mut, buf, base);
        mut[bad[i].off] = bad[i].val;
        CHECK(pemt_rejects(mut, base));
    }

    // Truncation is rejected everywhere except the optional final
    // terminator, which the pair above already covers.
    int trunc_ok = 1;
    for (size_t t = 0; t + 1 < base; t++) {
        if (!pemt_rejects(buf, t)) {
            trunc_ok = 0;
        }
    }
    CHECK(trunc_ok);

    pem_tests_limits(buf, mut, base, cert, cert_len);
}

// The output-overflow case, the grammar table, the terminator rules
// and the cap. Split out of pem_tests to stay under the
// cognitive-complexity ceiling; the order of the cases is unchanged.
static void pem_tests_limits(const uint8_t *buf, uint8_t *mut, size_t base, const uint8_t *cert,
                             size_t cert_len) {
    // More base64 than the array can hold. CH_PEM_MAX budgets two
    // terminator bytes per four characters, so an input that spends
    // none of that budget on terminators carries far more body than
    // CH_X509_MAX bytes. The body count must close its quantum, or
    // body_ok rejects on that and never consults the writer -- the
    // wbuf's sticky error is the rule under test here.
    {
        size_t room = CH_PEM_MAX - 27 - 1 - 25 - 1;
        size_t body = room & ~(size_t)3; // whole quantums only
        size_t n = 0;
        memcpy(mut, "-----BEGIN CERTIFICATE-----", 27);
        n = 27;
        mut[n++] = '\n';
        for (size_t i = 0; i < body; i++) {
            mut[n++] = (uint8_t)pem_armor_alphabet[i & 63U];
        }
        while (n < CH_PEM_MAX - 25 - 1) {
            mut[n++] = '\n'; // the leftover budget, spent on terminators
        }
        memcpy(mut + n, "-----END CERTIFICATE-----", 25);
        n += 25;
        mut[n++] = '\n';
        CHECK(n == CH_PEM_MAX);
        CHECK(body % 4 == 0);
        CHECK(body / 4 * 3 > CH_X509_MAX);
        CHECK(pemt_rejects(mut, n));
    }

    // An empty body decodes to nothing, which is not a certificate.
    const char empty[] = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    CHECK(pemt_rejects((const uint8_t *)empty, sizeof empty - 1));

    // The cap, exactly: pad with terminators to CH_PEM_MAX and then one
    // past it. The reject happens before any byte is read.
    memcpy(mut, buf, base);
    memset(mut + base, '\n', CH_PEM_MAX + 1 - base);
    CHECK(pemt_accepts(mut, CH_PEM_MAX, cert, cert_len));
    CHECK(pemt_rejects(mut, CH_PEM_MAX + 1));

    // The base64 grammar, stated as cases rather than mutated out of a
    // certificate: each row is one rule, and the accepting rows fix the
    // decoded bytes so a decoder that drifts loose fails here.
    static const struct {
        const char *body;
        const char *want; // NULL means the row must be rejected
    } grammar[] = {
        {"QUJD",  "ABC"}, // a full quantum
        {"QQ==",  "A"  }, // 8 bits, two pads
        {"QUI=",  "AB" }, // 16 bits, one pad
        {"QQ=",   NULL }, // the quantum does not close
        {"QQQ",   NULL }, // three characters, no pad
        {"QQQQQ", NULL }, // five characters
        {"QQ===", NULL }, // three pads
        {"Q===",  NULL }, // a pad at group position 1
        {"A===",  NULL }, // the same, but A decodes to zero, so the
                         // unused-bits rule cannot reject it first
                         // and only pad_ok stands in the way
        {"=QQQ",  NULL }, // a pad at group position 0
        {"Q=QQ",  NULL }, // a pad inside a quantum
        {"QQ==Q", NULL }, // an alphabet character after a pad
        {"QQ=A",  NULL }, // the same, inside the quantum
        {"QR==",  NULL }, // the bits the padding stands for are not zero
        {"QUJ=",  NULL }, // likewise, one pad
        {"QQ--",  NULL }, // base64url is not this alphabet
        {"QQ__",  NULL },
    };
    for (size_t i = 0; i < sizeof grammar / sizeof *grammar; i++) {
        size_t n = 0;
        memcpy(mut, "-----BEGIN CERTIFICATE-----\n", 28);
        n = 28;
        size_t body_len = strlen(grammar[i].body);
        memcpy(mut + n, grammar[i].body, body_len);
        n += body_len;
        memcpy(mut + n, "\n-----END CERTIFICATE-----\n", 27);
        n += 27;
        if (grammar[i].want == NULL) {
            CHECK(pemt_rejects(mut, n));
        } else {
            CHECK(pemt_accepts(mut, n, (const uint8_t *)grammar[i].want, strlen(grammar[i].want)));
        }
    }

    // A space INSERTED into the body. The rows above substitute one,
    // which only shows it is outside the alphabet; inserting shows it
    // is not silently skipped the way CR and LF are.
    for (size_t i = 0; i < 3; i++) {
        static const uint8_t ws[3] = {' ', '\t', '\v'};
        (void)memcpy(mut, buf, 30);
        mut[30] = ws[i];
        (void)memcpy(mut + 31, buf + 30, base - 30);
        CHECK(pemt_rejects(mut, base + 1));
    }

    // A lone CR ends no line: the BEGIN boundary takes LF or CRLF and
    // nothing else, so neither a bare CR nor CR CR LF terminates it.
    memcpy(mut, buf, base);
    mut[27] = '\r';
    CHECK(pemt_rejects(mut, base));
    memcpy(mut, buf, 27);
    mut[27] = '\r';
    mut[28] = '\r';
    mut[29] = '\n';
    memcpy(mut + 30, buf + 28, base - 28);
    CHECK(pemt_rejects(mut, base + 2));
}

#endif
