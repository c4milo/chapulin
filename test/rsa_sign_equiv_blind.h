// The blinding of the 64-bit signer's exponents (rsa_sign64.h,
// docs/decisions.md 187), for bin/rsa_sign_equiv_test. A signature is the
// same bytes under every blind, so the signatures alone cannot show that
// the blinding ran. This file reads the exponents through
// rsa_sign_equiv_blinded_exponents and holds each to d + r (p - 1),
// computed here a byte at a time, and requires every blind to sign to the
// same bytes. It is included by test/rsa_sign_equiv_test.c, after key,
// failures and compared.
#ifndef CH_TEST_RSA_SIGN_EQUIV_BLIND_H
#define CH_TEST_RSA_SIGN_EQUIV_BLIND_H

// The bytes a blinded exponent takes beyond its prime's: r is 64 bits.
#define BLIND_EXTRA_LEN 8

// e = d + r (p - 1), half_len + BLIND_EXTRA_LEN big-endian bytes, with r
// the 8 bytes at r_bytes read little-endian: the schoolbook product in
// bytes, which shares no step with rsa_sign64.c's words.
static void expected_blinded(uint8_t *e, const uint8_t *d, const uint8_t *p, size_t half_len,
                             const uint8_t *r_bytes) {
    size_t e_len = half_len + BLIND_EXTRA_LEN;
    uint32_t sum[CH_RSA_MODULUS_MAX / 2 + BLIND_EXTRA_LEN] = {0};
    for (size_t i = 0; i < half_len; i++) {
        sum[i] = d[half_len - 1 - i];
    }
    for (size_t i = 0; i < half_len; i++) {
        uint32_t p_byte = p[half_len - 1 - i];
        if (i == 0) {
            p_byte &= 0xfe; // p is odd: p - 1 clears its low bit
        }
        for (size_t j = 0; j < BLIND_EXTRA_LEN; j++) {
            sum[i + j] += p_byte * r_bytes[j];
        }
    }
    uint32_t carry = 0;
    for (size_t i = 0; i < e_len; i++) {
        uint32_t v = sum[i] + carry;
        e[e_len - 1 - i] = (uint8_t)v;
        carry = v >> 8;
    }
}

// Each blind's exponents held to expected_blinded, r_p from the blind's
// first 8 bytes and r_q from its last 8, and each blind's signature held
// to the first one's bytes.
static void run_blinded_exponents(const test_rsa_sign_key *from) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    static const uint8_t blinds[][RSA_BLIND_LEN] = {
        {0},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff},
        {0x3c, 0x5a, 0x01, 0x80, 0x7f, 0x02, 0xc4, 0x99},
        {[8] = 0x01, [15] = 0x80},
        {0x5a, 0x3c, 0x01, 0x80, 0x7f, 0x02, 0xc4, 0x99, 0xa5, 0x0f, 0x10, 0x08, 0xf7, 0x20, 0x4c,
         0x91},
    };
    test_rsa_sign_key_load(&key, from);
    size_t half_len = key.n_len / 2;
    size_t e_len = half_len + BLIND_EXTRA_LEN;
    uint8_t em[CH_RSA_MODULUS_MAX];
    random_message(em);
    uint8_t first_sig[CH_RSA_MODULUS_MAX] = {0};
    for (size_t b = 0; b < sizeof blinds / sizeof blinds[0]; b++) {
        uint8_t e_p[CH_RSA_MODULUS_MAX / 2 + BLIND_EXTRA_LEN];
        uint8_t e_q[CH_RSA_MODULUS_MAX / 2 + BLIND_EXTRA_LEN];
        uint8_t want_p[CH_RSA_MODULUS_MAX / 2 + BLIND_EXTRA_LEN];
        uint8_t want_q[CH_RSA_MODULUS_MAX / 2 + BLIND_EXTRA_LEN];
        rsa_sign_equiv_blinded_exponents(e_p, e_q, &key, half_len, blinds[b]);
        expected_blinded(want_p, key.dp, key.p, half_len, blinds[b]);
        expected_blinded(want_q, key.dq, key.q, half_len, blinds[b] + BLIND_EXTRA_LEN);
        compared++;
        if (memcmp(e_p, want_p, e_len) != 0 || memcmp(e_q, want_q, e_len) != 0) {
            failures++;
            (void)fprintf(stderr, "FAIL blinded exponents: blind %zu at %zu bytes\n", b, key.n_len);
        }
        uint8_t sig[CH_RSA_MODULUS_MAX] = {0};
        int signed_ok = rsa_sign64_sp1(equiv_cpu, &key, em, blinds[b], sig);
        if (b == 0) {
            memcpy(first_sig, sig, key.n_len);
        }
        if (!signed_ok || memcmp(sig, first_sig, key.n_len) != 0) {
            failures++;
            (void)fprintf(stderr, "FAIL blinded signature: blind %zu at %zu bytes\n", b, key.n_len);
        }
    }
}

#endif
