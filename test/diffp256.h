// P-256 ECDSA differential section: the Lean spec mints signatures
// (p256_pub, p256_sign) and the C verifier must accept each one and
// reject a copy with one mutated hash byte — the strongest cross-check,
// since the C cannot verify a signature the independent spec produced
// unless both agree on the whole curve. The C side never signs.
//
// r/s cross the pipe as raw 32-byte hex; the DER wrapping the C API
// consumes is built here. Included by test/diff.c after diffdrv.h
// (single translation unit). Until the C p256 lands, the section still
// exercises the spec ops against themselves.
#ifndef CH_DIFFP256_H
#define CH_DIFFP256_H

#ifdef __has_include
#if __has_include("p256.h")
#include "p256.h"
#define DIFF_HAVE_P256 1
#endif
#endif

#ifdef DIFF_HAVE_P256
// Minimal DER INTEGER: strip leading zero bytes, prepend 0x00 when the
// top bit is set (RFC 5915 / X.690 §8.3).
static size_t p256_der_int(uint8_t *dst, const uint8_t v[32]) {
    size_t lead = 0;
    while (lead < 31 && v[lead] == 0) {
        lead++;
    }
    size_t n = 32 - lead;
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
static size_t p256_der_sig(uint8_t *dst, const uint8_t r[32], const uint8_t s[32]) {
    uint8_t body[70];
    size_t n = p256_der_int(body, r);
    n += p256_der_int(body + n, s);
    dst[0] = 0x30;
    dst[1] = (uint8_t)n;
    memcpy(dst + 2, body, n);
    return 2 + n;
}
#endif

static void diff_p256(void) {
#ifndef DIFF_HAVE_P256
    (void)fprintf(stderr, "diff: p256: spec-only pass, p256.h not present yet\n");
#endif
    for (int i = 0; i < 50; i++) {
        uint8_t d[32];
        uint8_t k[32];
        uint8_t hash[32];
        rng_fill(d, sizeof d);
        rng_fill(k, sizeof k);
        rng_fill(hash, sizeof hash);
        // Clearing the top bit keeps d, k below 2^255 < n (already
        // reduced); a forced low bit rules out zero.
        d[0] &= 0x7f;
        k[0] &= 0x7f;
        d[31] |= 1;
        k[31] |= 1;
        char d_hex[65];
        char k_hex[65];
        char hash_hex[65];
        (void)hex_encode(d_hex, d, sizeof d);
        (void)hex_encode(k_hex, k, sizeof k);
        (void)hex_encode(hash_hex, hash, sizeof hash);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "p256_pub %s", d_hex);
        char pub_hex[256];
        query(cmd, pub_hex, sizeof pub_hex);
        uint8_t pub[64];
        if (strlen(pub_hex) != 128 || !hex_decode(pub, pub_hex, sizeof pub)) {
            die("p256_pub: malformed spec response");
        }
        (void)snprintf(cmd, sizeof cmd, "p256_sign %s %s %s", d_hex, k_hex, hash_hex);
        char sig_hex[256]; // "r-hex s-hex", split in place below
        query(cmd, sig_hex, sizeof sig_hex);
        if (strlen(sig_hex) != 129 || sig_hex[64] != ' ') {
            die("p256_sign: malformed spec response");
        }
        sig_hex[64] = '\0'; // splits into the r and s hex words
        uint8_t r[32];
        uint8_t s[32];
        if (!hex_decode(r, sig_hex, sizeof r) || !hex_decode(s, sig_hex + 65, sizeof s)) {
            die("p256_sign: malformed spec response");
        }
        // The spec must stand behind its own signature, and drop it
        // when one hash byte flips.
        uint8_t bad[32];
        memcpy(bad, hash, sizeof bad);
        bad[rng_below(sizeof bad)] ^= (uint8_t)(1 + rng_below(255));
        char bad_hex[65];
        (void)hex_encode(bad_hex, bad, sizeof bad);
        (void)snprintf(cmd, sizeof cmd, "p256_verify %s %s %s %s", pub_hex, hash_hex, sig_hex,
                       sig_hex + 65);
        expect(cmd, "1");
        (void)snprintf(cmd, sizeof cmd, "p256_verify %s %s %s %s", pub_hex, bad_hex, sig_hex,
                       sig_hex + 65);
        expect(cmd, "0");
#ifdef DIFF_HAVE_P256
        uint8_t der[72];
        size_t der_len = p256_der_sig(der, r, s);
        if (p256_ecdsa_verify(pub, hash, der, der_len) != 1) {
            (void)fprintf(
                stderr, "diff mismatch: C p256_ecdsa_verify rejected\n  d: %s\n  k: %s\n  h: %s\n",
                d_hex, k_hex, hash_hex);
            exit(1);
        }
        if (p256_ecdsa_verify(pub, bad, der, der_len) != 0) {
            (void)fprintf(
                stderr,
                "diff mismatch: C p256_ecdsa_verify accepted a mutated hash\n  d: %s\n  k: %s\n",
                d_hex, k_hex);
            exit(1);
        }
        comparisons += 2;
#else
        (void)r;
        (void)s;
#endif
    }
}

#endif
