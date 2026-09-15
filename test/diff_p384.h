// P-384 ECDSA differential section: the Lean spec mints signatures
// (p384_pub, p384_sign) and the C verifier must accept each one and
// reject a copy with one mutated hash byte — the strongest cross-check,
// since the C cannot verify a signature the independent spec produced
// unless both agree on the whole curve. The C side never signs.
//
// Beside the mutated hash, each row also feeds the C verifier one
// mutated signature (a byte flipped in r or in s) and a fixed set of
// degenerate inputs the spec is not asked about: r = 0, s = 0, r and s
// above the group order, a public key off the curve, and a truncated
// DER encoding. Every one of those must be rejected.
//
// r/s cross the pipe as raw 48-byte hex; the DER wrapping the C API
// consumes is built here. Included by test/diff_test.c after diff_driver.h
// (single translation unit). Until the C p384 lands, the section still
// exercises the spec ops against themselves.
//
// spec/Main.lean must serve three ops, shaped like their p256 siblings
// with every 32 replaced by 48 and 64 by 96:
//   p384_pub <d-hex>                          -> X||Y as 192 hex chars
//   p384_sign <d-hex> <k-hex> <hash-hex>      -> "<r-hex> <s-hex>"
//   p384_verify <pub-hex> <hash-hex> <r-hex> <s-hex> -> "1" or "0"
//
// The all-0xff scalar the degenerate rows use exceeds the group order:
//   openssl ecparam -name secp384r1 -param_enc explicit -text -noout
// prints the order as ff..ff c7634d81f4372ddf581a0db248b0a77aecec196accc52973.
#ifndef CH_DIFFP384_H
#define CH_DIFFP384_H

#ifdef __has_include
#if __has_include("p384.h")
#include "p384.h"
#define DIFF_HAVE_P384 1
#endif
#endif

// Byte sizes of one P-384 scalar, hash and coordinate, and of the raw
// uncompressed public point (X||Y).
#define DIFF_P384_SCALAR_LEN 48
#define DIFF_P384_PUB_LEN 96
// One DER INTEGER holding a 48-byte value: tag, length, optional 0x00
// pad, 48 value bytes. The signature SEQUENCE holds two of them plus its
// own tag and length.
#define DIFF_P384_DER_INT_MAX (2 + 1 + DIFF_P384_SCALAR_LEN)
#define DIFF_P384_DER_SIG_MAX (2 + 2 * DIFF_P384_DER_INT_MAX)

#ifdef DIFF_HAVE_P384
// Minimal DER INTEGER: strip leading zero bytes, prepend 0x00 when the
// top bit is set (RFC 5915 / X.690 §8.3).
static size_t p384_der_int(uint8_t *dst, const uint8_t v[DIFF_P384_SCALAR_LEN]) {
    size_t lead = 0;
    while (lead < DIFF_P384_SCALAR_LEN - 1 && v[lead] == 0) {
        lead++;
    }
    size_t n = DIFF_P384_SCALAR_LEN - lead;
    size_t pad = (v[lead] & 0x80) ? 1 : 0;
    dst[0] = 0x02;
    dst[1] = (uint8_t)(n + pad);
    if (pad) {
        dst[2] = 0;
    }
    memcpy(dst + 2 + pad, v + lead, n);
    return 2 + pad + n;
}

// ECDSA-Sig-Value (RFC 5912): SEQUENCE { r INTEGER, s INTEGER }.
static size_t p384_der_sig(uint8_t *dst, const uint8_t r[DIFF_P384_SCALAR_LEN],
                           const uint8_t s[DIFF_P384_SCALAR_LEN]) {
    uint8_t body[2 * DIFF_P384_DER_INT_MAX];
    size_t n = p384_der_int(body, r);
    n += p384_der_int(body + n, s);
    dst[0] = 0x30;
    dst[1] = (uint8_t)n;
    memcpy(dst + 2, body, n);
    return 2 + n;
}

// Runs the C verifier over one (r, s) pair the caller has altered and
// requires a rejection. what names the alteration in the failure report.
static void diff_p384_expect_reject(const uint8_t pub[DIFF_P384_PUB_LEN],
                                    const uint8_t hash[DIFF_P384_SCALAR_LEN],
                                    const uint8_t r[DIFF_P384_SCALAR_LEN],
                                    const uint8_t s[DIFF_P384_SCALAR_LEN], const char *what,
                                    const char *d_hex, const char *k_hex) {
    uint8_t der[DIFF_P384_DER_SIG_MAX];
    size_t der_len = p384_der_sig(der, r, s);
    if (p384_ecdsa_verify(pub, hash, der, der_len) != 0) {
        (void)fprintf(stderr, "diff mismatch: C p384_ecdsa_verify accepted %s\n  d: %s\n  k: %s\n",
                      what, d_hex, k_hex);
        exit(1);
    }
    comparisons++;
}

// The signature-side rejections for one minted row: one byte flipped in
// r, one in s, then the degenerate values. Every value of r or s that
// is 0 or at least the group order n fails the range check of FIPS
// 186-4 §6.4 step 1; all-0xff bytes exceed n without naming n here.
// A public point of all zeros is off the curve (b != 0, so (0, 0) does
// not satisfy y^2 = x^3 - 3x + b). A DER encoding cut one byte short
// must fail the parse before any arithmetic.
static void diff_p384_check_c_reject(const uint8_t pub[DIFF_P384_PUB_LEN],
                                     const uint8_t hash[DIFF_P384_SCALAR_LEN],
                                     const uint8_t r[DIFF_P384_SCALAR_LEN],
                                     const uint8_t s[DIFF_P384_SCALAR_LEN], const char *d_hex,
                                     const char *k_hex) {
    uint8_t alt[DIFF_P384_SCALAR_LEN];

    memcpy(alt, r, sizeof alt);
    alt[rng_below(sizeof alt)] ^= (uint8_t)(1 + rng_below(255));
    diff_p384_expect_reject(pub, hash, alt, s, "a mutated r", d_hex, k_hex);

    memcpy(alt, s, sizeof alt);
    alt[rng_below(sizeof alt)] ^= (uint8_t)(1 + rng_below(255));
    diff_p384_expect_reject(pub, hash, r, alt, "a mutated s", d_hex, k_hex);

    memset(alt, 0, sizeof alt);
    diff_p384_expect_reject(pub, hash, alt, s, "r = 0", d_hex, k_hex);
    diff_p384_expect_reject(pub, hash, r, alt, "s = 0", d_hex, k_hex);

    memset(alt, 0xff, sizeof alt);
    diff_p384_expect_reject(pub, hash, alt, s, "r above the group order", d_hex, k_hex);
    diff_p384_expect_reject(pub, hash, r, alt, "s above the group order", d_hex, k_hex);

    uint8_t zero_pub[DIFF_P384_PUB_LEN];
    memset(zero_pub, 0, sizeof zero_pub);
    diff_p384_expect_reject(zero_pub, hash, r, s, "a public key off the curve", d_hex, k_hex);

    uint8_t der[DIFF_P384_DER_SIG_MAX];
    size_t der_len = p384_der_sig(der, r, s);
    if (p384_ecdsa_verify(pub, hash, der, der_len - 1) != 0) {
        (void)fprintf(stderr,
                      "diff mismatch: C p384_ecdsa_verify accepted a truncated DER signature\n"
                      "  d: %s\n  k: %s\n",
                      d_hex, k_hex);
        exit(1);
    }
    comparisons++;
}

// Runs the C verifier over one minted row: accept the good signature,
// reject the mutated hash, then every signature-side rejection.
static void diff_p384_check_c(const uint8_t pub[DIFF_P384_PUB_LEN],
                              const uint8_t hash[DIFF_P384_SCALAR_LEN],
                              const uint8_t bad[DIFF_P384_SCALAR_LEN],
                              const uint8_t r[DIFF_P384_SCALAR_LEN],
                              const uint8_t s[DIFF_P384_SCALAR_LEN], const char *d_hex,
                              const char *k_hex, const char *hash_hex) {
    uint8_t der[DIFF_P384_DER_SIG_MAX];
    size_t der_len = p384_der_sig(der, r, s);
    if (p384_ecdsa_verify(pub, hash, der, der_len) != 1) {
        (void)fprintf(stderr,
                      "diff mismatch: C p384_ecdsa_verify rejected\n  d: %s\n  k: %s\n  h: %s\n",
                      d_hex, k_hex, hash_hex);
        exit(1);
    }
    if (p384_ecdsa_verify(pub, bad, der, der_len) != 0) {
        (void)fprintf(
            stderr,
            "diff mismatch: C p384_ecdsa_verify accepted a mutated hash\n  d: %s\n  k: %s\n", d_hex,
            k_hex);
        exit(1);
    }
    comparisons += 2;
    diff_p384_check_c_reject(pub, hash, r, s, d_hex, k_hex);
}
#endif

static void diff_p384(void) {
#ifndef DIFF_HAVE_P384
    (void)fprintf(stderr, "diff: p384: spec-only pass, p384.h not present yet\n");
#endif
    for (int i = 0; i < 50; i++) {
        uint8_t d[DIFF_P384_SCALAR_LEN];
        uint8_t k[DIFF_P384_SCALAR_LEN];
        uint8_t hash[DIFF_P384_SCALAR_LEN];
        rng_fill(d, sizeof d);
        rng_fill(k, sizeof k);
        rng_fill(hash, sizeof hash);
        // Clearing the top bit keeps d, k below 2^383 < n (already
        // reduced); a forced low bit rules out zero.
        d[0] &= 0x7f;
        k[0] &= 0x7f;
        d[DIFF_P384_SCALAR_LEN - 1] |= 1;
        k[DIFF_P384_SCALAR_LEN - 1] |= 1;
        char d_hex[2 * DIFF_P384_SCALAR_LEN + 1];
        char k_hex[2 * DIFF_P384_SCALAR_LEN + 1];
        char hash_hex[2 * DIFF_P384_SCALAR_LEN + 1];
        (void)hex_encode(d_hex, d, sizeof d);
        (void)hex_encode(k_hex, k, sizeof k);
        (void)hex_encode(hash_hex, hash, sizeof hash);
        char cmd[768];
        (void)snprintf(cmd, sizeof cmd, "p384_pub %s", d_hex);
        char pub_hex[256];
        query(cmd, pub_hex, sizeof pub_hex);
        uint8_t pub[DIFF_P384_PUB_LEN];
        if (strlen(pub_hex) != (size_t)2 * DIFF_P384_PUB_LEN ||
            !hex_decode(pub, pub_hex, sizeof pub)) {
            die("p384_pub: malformed spec response");
        }
        (void)snprintf(cmd, sizeof cmd, "p384_sign %s %s %s", d_hex, k_hex, hash_hex);
        char sig_hex[256]; // "r-hex s-hex", split in place below
        query(cmd, sig_hex, sizeof sig_hex);
        const size_t r_end = (size_t)2 * DIFF_P384_SCALAR_LEN; // index of the separating space
        if (strlen(sig_hex) != 2 * r_end + 1 || sig_hex[r_end] != ' ') {
            die("p384_sign: malformed spec response");
        }
        sig_hex[r_end] = '\0'; // splits into the r and s hex words
        const char *s_hex = sig_hex + r_end + 1;
        uint8_t r[DIFF_P384_SCALAR_LEN];
        uint8_t s[DIFF_P384_SCALAR_LEN];
        if (!hex_decode(r, sig_hex, sizeof r) || !hex_decode(s, s_hex, sizeof s)) {
            die("p384_sign: malformed spec response");
        }
        // The spec must stand behind its own signature, and drop it
        // when one hash byte flips.
        uint8_t bad[DIFF_P384_SCALAR_LEN];
        memcpy(bad, hash, sizeof bad);
        bad[rng_below(sizeof bad)] ^= (uint8_t)(1 + rng_below(255));
        char bad_hex[2 * DIFF_P384_SCALAR_LEN + 1];
        (void)hex_encode(bad_hex, bad, sizeof bad);
        (void)snprintf(cmd, sizeof cmd, "p384_verify %s %s %s %s", pub_hex, hash_hex, sig_hex,
                       s_hex);
        expect(cmd, "1");
        (void)snprintf(cmd, sizeof cmd, "p384_verify %s %s %s %s", pub_hex, bad_hex, sig_hex,
                       s_hex);
        expect(cmd, "0");
#ifdef DIFF_HAVE_P384
        diff_p384_check_c(pub, hash, bad, r, s, d_hex, k_hex, hash_hex);
#else
        (void)r;
        (void)s;
#endif
    }
}

#endif
