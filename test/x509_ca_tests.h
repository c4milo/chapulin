// Provisioning walk: which certificates yield a key and which do not.
// The vectors are the build's own generated certificates, armoured by
// pemt_armor so they survive regeneration by test/gen_x509vectors.py.
//
// That the extracted bytes equal what openssl reports is checked in
// test/e2e.sh against a real minted root; these cases check the
// decision and the failure contract.
#ifndef CH_X509_CA_TESTS_H
#define CH_X509_CA_TESTS_H

#include "x509_ca.h"
#include "x509_mutate.h"

// Every rejection must leave the length zero and the key wiped: the
// seed is non-zero so an untouched out-parameter fails the check, and
// x509_read_spki sets its outputs on some failing paths, so the entry
// has to clear them itself.
static int cat_rejects(const uint8_t *pem, size_t n) {
    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];
    size_t key_len = 0x5a5a;
    memset(key, 0xAB, sizeof key);
    if (ch_pubkey_from_pem(pem, n, der, key, &key_len) != CH_EINVAL || key_len != 0) {
        return 0;
    }
    for (size_t i = 0; i < sizeof key; i++) {
        if (key[i] != 0) {
            return 0; // the key must be wiped, not merely unread
        }
    }
    return 1;
}

static int cat_accepts(const uint8_t *pem, size_t n, uint8_t *out, size_t *out_len) {
    static uint8_t der[CH_X509_MAX];
    size_t key_len = 0x5a5a;
    if (ch_pubkey_from_pem(pem, n, der, out, &key_len) != CH_OK) {
        return 0;
    }
    *out_len = key_len;
    return key_len == CH_X509_KEY_MAX;
}

static void x509_ca_tests(void) {
    static uint8_t pem[CH_PEM_MAX + 64];
    static uint8_t key[CH_X509_KEY_MAX];
    size_t key_len = 0;

    // The intermediate is a trust anchor an operator may legitimately
    // pin: docs/ca.md directs devices to pin an intermediate's key
    // when a managed CA signs beyond the fleet. It carries
    // basicConstraints CA:TRUE pathlen:0 and keyUsage keyCertSign.
    size_t n = pem_armor(chain_int, chain_int_len, 64, "\n", pem);
    CHECK(cat_accepts(pem, n, key, &key_len));

    // The leaf is the file an operator pushes by mistake. CA:FALSE.
    n = pem_armor(good_cert, good_cert_len, 64, "\n", pem);
    CHECK(cat_rejects(pem, n));

    // Every line width and terminator reaches the same decision: the
    // decoder is upstream of the walk and must not change it.
    for (size_t i = 0; i < sizeof pem_armor_widths / sizeof *pem_armor_widths; i++) {
        for (int crlf = 0; crlf < 2; crlf++) {
            size_t m =
                pem_armor(chain_int, chain_int_len, pem_armor_widths[i], crlf ? "\r\n" : "\n", pem);
            uint8_t k2[CH_X509_KEY_MAX];
            size_t l2 = 0;
            CHECK(cat_accepts(pem, m, k2, &l2));
            CHECK(l2 == key_len && memcmp(k2, key, key_len) == 0);
        }
    }

    // Not PEM at all, and PEM whose body is not a certificate.
    CHECK(cat_rejects((const uint8_t *)"hello", 5));
    {
        static const uint8_t junk[] = {0x30, 0x03, 0x02, 0x01, 0x00};
        size_t m = pem_armor(junk, sizeof junk, 64, "\n", pem);
        CHECK(cat_rejects(pem, m));
    }

    // Near misses spliced out of the good intermediate. A real
    // certificate differs from a valid one in many ways at once, so it
    // proves little; each mutant below breaks exactly one rule, with
    // every enclosing DER length re-encoded by test/x509_mutate.h.
    {
        static uint8_t mut[X509MUT_CAP];
        const uint8_t *c = chain_int;
        size_t cn = chain_int_len;

        // basicConstraints removed entirely: an anchor must assert it.
        size_t off = find_ext(c, cn, oid_bc);
        size_t m = splice(mut, c, cn, off, tlv_total(c, cn, off), (const uint8_t *)"", 0);
        CHECK(cat_rejects(pem, pem_armor(mut, m, 64, "\n", pem)));

        // keyUsage present, keyCertSign absent: digitalSignature only.
        static const uint8_t ku_sign_only[] = {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
                                               0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
        off = find_ext(c, cn, oid_ku);
        m = splice(mut, c, cn, off, tlv_total(c, cn, off), ku_sign_only, sizeof ku_sign_only);
        CHECK(cat_rejects(pem, pem_armor(mut, m, 64, "\n", pem)));

        // An unrecognized CRITICAL extension. insert_unknown builds a
        // non-critical one, which must still be accepted, so both go
        // here as the pair they are.
        static const uint8_t unknown_critical[] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x63,
                                                   0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
        m = splice(mut, c, cn, first_ext(c, cn), 0, unknown_critical, sizeof unknown_critical);
        CHECK(cat_rejects(pem, pem_armor(mut, m, 64, "\n", pem)));
        m = insert_unknown(mut, c, cn, 0x63);
        {
            uint8_t k3[CH_X509_KEY_MAX];
            size_t l3 = 0;
            CHECK(cat_accepts(pem, pem_armor(mut, m, 64, "\n", pem), k3, &l3));
        }

        // A trailing field INSIDE the TBS. The extensions element is
        // the last TBS field, so the NULL goes after it as a sibling:
        // splicing at the byte past the TBS would instead land between
        // the TBS and the signature algorithm, where the tag check
        // rejects it for the wrong reason.
        static uint8_t grown[X509MUT_CAP];
        static const uint8_t der_null[] = {0x05, 0x00};
        size_t tbs = nth_child(c, cn, 0, 0);
        size_t ext_off = tbs_field(c, cn, 7);
        size_t ext_len = tlv_total(c, cn, ext_off);
        (void)memcpy(grown, c + ext_off, ext_len);
        (void)memcpy(grown + ext_len, der_null, sizeof der_null);
        m = splice(mut, c, cn, ext_off, ext_len, grown, ext_len + sizeof der_null);
        CHECK(cat_rejects(pem, pem_armor(mut, m, 64, "\n", pem)));

        // One byte after the outer SEQUENCE. The closing exact-consume
        // catches this one, so it does not isolate the outer length.
        (void)memcpy(mut, c, cn);
        mut[cn] = 0x00;
        CHECK(cat_rejects(pem, pem_armor(mut, cn + 1, 64, "\n", pem)));

        // The outer SEQUENCE declaring a length shorter than its
        // content, with every byte still present. Only the
        // body_len == rb_left check rejects this: the walk itself
        // consumes the whole buffer and ends exactly at the end.
        (void)memcpy(mut, c, cn);
        CHECK(mut[1] == 0x82); // the vectors are all long-form
        mut[2] = 0x01;
        mut[3] = 0x00;
        CHECK(cat_rejects(pem, pem_armor(mut, cn, 64, "\n", pem)));

        // A certificate that is the TBS and nothing else, re-wrapped
        // so the outer length is correct. Cutting the original after
        // the TBS would leave the outer header declaring the old
        // length, and the outer check would reject it before the
        // signature framing was reached.
        size_t tbs_total = tlv_total(c, cn, tbs);
        size_t h = put_header(mut, 0x30, tbs_total);
        (void)memcpy(mut + h, c + tbs, tbs_total);
        CHECK(cat_rejects(pem, pem_armor(mut, h + tbs_total, 64, "\n", pem)));
    }

    // Truncating the certificate must never yield a key. The armour
    // is rebuilt each time, so the PEM stays well formed and the walk
    // is what rejects.
    int trunc_ok = 1;
    for (size_t t = 0; t < chain_int_len; t++) {
        size_t m = pem_armor(chain_int, t, 64, "\n", pem);
        if (!cat_rejects(pem, m)) {
            trunc_ok = 0;
        }
    }
    CHECK(trunc_ok);
}

#endif
