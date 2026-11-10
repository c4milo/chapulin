// P-256's rows of bin/widemul_runtime_test: its operations under a
// session's ch_cfg.cpu, and the field each value runs, on x86-64 and on
// arm64 (docs/decisions.md 171 and 215). test/widemul_runtime_test.c
// includes this file once, after its counts, CHECK, OUT_MAX and
// zero_counts, which the rows read; it sits apart only to keep that file
// under 500 lines.
#ifndef CH_TEST_WIDEMUL_RUNTIME_P256_H
#define CH_TEST_WIDEMUL_RUNTIME_P256_H

#if defined(__x86_64__) || defined(__aarch64__)
// p256_run through the entries that take a session's ch_cfg.cpu, with the
// answer that value gives.
static size_t p256_cpu_run(uint32_t cpu, uint8_t out[OUT_MAX]) {
    uint8_t widemul = widemul_of_cpu(cpu);
    uint8_t draw_a[P256_SCALAR_LEN];
    uint8_t draw_b[P256_SCALAR_LEN];
    uint8_t priv_a[P256_SCALAR_LEN];
    uint8_t priv_b[P256_SCALAR_LEN];
    uint8_t pub_a[P256_POINT_LEN];
    uint8_t pub_b[P256_POINT_LEN];
    uint8_t other[P256_SECRET_LEN];
    uint8_t hash[32];
    memset(draw_a, 0x11, sizeof draw_a);
    memset(draw_b, 0x22, sizeof draw_b);
    memset(hash, 0x5a, sizeof hash);
    CHECK(p256_ecdh_keygen_cpu(cpu, widemul, draw_a, priv_a, pub_a) == 1);
    CHECK(p256_ecdh_keygen_cpu(cpu, widemul, draw_b, priv_b, pub_b) == 1);
    CHECK(p256_ecdh_point_valid_cpu(cpu, widemul, pub_b) == 1);
    CHECK(p256_ecdh_cpu(cpu, widemul, priv_a, pub_b, out) == 1);
    CHECK(p256_ecdh_cpu(cpu, widemul, priv_b, pub_a, other) == 1);
    CHECK(memcmp(out, other, P256_SECRET_LEN) == 0);
    size_t sig_len = 0;
    CHECK(p256_sign_cpu(cpu, priv_a, hash, out + P256_SECRET_LEN, OUT_MAX - P256_SECRET_LEN,
                        &sig_len) == 1);
    return P256_SECRET_LEN + sig_len;
}
#endif

// P-256's operations under a session's ch_cfg.cpu (widemul.h's
// widemul_p256_adx and p256.c's verify_rs), on x86-64, where three fields
// answer: p256_adx.h's copy under the multiply bit with CH_CPU_BMI2_ADX
// beside it, the wide files under the multiply bit alone, and the 32-bit
// files without it, whatever CH_CPU_BMI2_ADX says. The verifier runs the
// copy under CH_CPU_BMI2_ADX alone, and the wide files without it. The rows
// that run the copy need BMI2 and ADX, and a CPU without them skips them,
// unless CH_REQUIRE_BMI2_ADX is 1.
static void check_p256_cpu(void) {
#ifdef __x86_64__
    static const uint32_t multiply = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    static const uint32_t adx_alone = CH_CPU_PROBED | CH_CPU_BMI2_ADX;
    uint8_t want[OUT_MAX];
    uint8_t got[OUT_MAX];
    int failed = failures;
    zero_counts();
    size_t want_len = p256_cpu_run(multiply, want);
    unsigned long wide_calls = widemul_native_calls;
    CHECK(widemul_native_calls > 0 && p256_adx_calls == 0 && widemul_decomposed_calls == 0);
    zero_counts();
    CHECK(p256_cpu_run(adx_alone, got) == want_len && memcmp(got, want, want_len) == 0);
    CHECK(widemul_native_calls == 0 && p256_adx_calls == 0 && widemul_decomposed_calls > 0);
    zero_counts();
    const uint8_t *sig = want + P256_SECRET_LEN;
    size_t sig_len = want_len - P256_SECRET_LEN;
    uint8_t pub[P256_POINT_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t hash[32];
    memset(draw, 0x11, sizeof draw);
    memset(hash, 0x5a, sizeof hash);
    CHECK(p256_ecdh_keygen(WIDEMUL_NOT_STATED, draw, priv, pub) == 1);
    zero_counts();
    CHECK(p256_ecdsa_verify_cpu(multiply, pub + 1, hash, sig, sig_len) == 1);
    CHECK(p256_adx_verify_calls == 0);
    const char *adx_row = "skipped: this CPU lacks BMI2 or ADX";
    if (x86_cpu_has_bmi2_adx()) {
        zero_counts();
        CHECK(p256_cpu_run(multiply | CH_CPU_BMI2_ADX, got) == want_len &&
              memcmp(got, want, want_len) == 0);
        // p256_cpu_run's point operations, which the copy runs: two key
        // pairs of a base multiplication and an affine conversion each, the
        // point check, two exchanges of a decode, a multiplication and an
        // affine conversion each, and the signature's base multiplication,
        // affine conversion and curve check. The signature's five scalar
        // operations run on the wide files.
        CHECK(p256_adx_calls == 14 && widemul_native_calls == wide_calls &&
              widemul_decomposed_calls == 0);
        zero_counts();
        CHECK(p256_ecdsa_verify_cpu(adx_alone, pub + 1, hash, sig, sig_len) == 1);
        CHECK(p256_adx_verify_calls == 1);
        adx_row = "the copy under both bits, and its verifier under CH_CPU_BMI2_ADX";
    } else if (x86_bmi2_adx_required()) {
        failures++;
        (void)fprintf(stderr, "this CPU lacks BMI2 or ADX, and CH_REQUIRE_BMI2_ADX is 1\n");
    }
    zero_counts();
    (void)printf("widemul_runtime: p256 by cpu        the wide files under the multiply bit alone, "
                 "the 32-bit files under CH_CPU_BMI2_ADX alone, %s%s\n",
                 adx_row, failures == failed ? "" : " -- FAILED");
#elif defined(__aarch64__)
    // On arm64 two fields answer: p256_arm64.h's copy under the multiply bit
    // and the 32-bit files without it. The verifier runs the copy in every
    // session (docs/decisions.md 215).
    static const uint32_t multiply = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    static const uint32_t probed = CH_CPU_PROBED;
    uint8_t want[OUT_MAX];
    uint8_t got[OUT_MAX];
    int failed = failures;
    zero_counts();
    size_t want_len = p256_cpu_run(multiply, want);
    // p256_cpu_run's point operations, which the copy runs: two key pairs of
    // a base multiplication and an affine conversion each, the point check,
    // two exchanges of a decode, a multiplication and an affine conversion
    // each, and the signature's base multiplication, affine conversion and
    // curve check. The signature's five scalar operations run on the wide
    // files.
    CHECK(p256_arm64_calls == 14 && widemul_native_calls == 19 && widemul_decomposed_calls == 0);
    zero_counts();
    CHECK(p256_cpu_run(probed, got) == want_len && memcmp(got, want, want_len) == 0);
    CHECK(widemul_native_calls == 0 && p256_arm64_calls == 0 && widemul_decomposed_calls > 0);
    const uint8_t *sig = want + P256_SECRET_LEN;
    size_t sig_len = want_len - P256_SECRET_LEN;
    uint8_t pub[P256_POINT_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t hash[32];
    memset(draw, 0x11, sizeof draw);
    memset(hash, 0x5a, sizeof hash);
    CHECK(p256_ecdh_keygen(WIDEMUL_NOT_STATED, draw, priv, pub) == 1);
    zero_counts();
    CHECK(p256_ecdsa_verify_cpu(probed, pub + 1, hash, sig, sig_len) == 1);
    CHECK(p256_arm64_verify_calls == 1);
    zero_counts();
    CHECK(p256_ecdsa_verify_cpu(multiply, pub + 1, hash, sig, sig_len) == 1);
    CHECK(p256_arm64_verify_calls == 1);
    zero_counts();
    (void)printf("widemul_runtime: p256 by cpu        the arm64 copy under the multiply bit, the "
                 "32-bit files without it, and its verifier under every value%s\n",
                 failures == failed ? "" : " -- FAILED");
#endif
}

#endif
