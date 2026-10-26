// The library's ML-DSA-87 signer, mldsa_signer.c, against answers that
// do not come from it (docs/decisions.md 159):
//  - Decompose and Power2Round at every r in [0, q), against FIPS 204's
//    division form;
//  - the constant-time SampleInBall against the verifier's sampler;
//  - the coefficient functions against 64-bit arithmetic;
//  - key generation and signing byte for byte against the test-only
//    signer, test/mldsa_sign.c, which bin/wycheproof_mldsa_sign_test holds
//    to Wycheproof, over 48 seeds, messages and contexts, hedged and
//    deterministic;
//  - the refusals at their boundaries: a context of 255 bytes signs and
//    one of 256 does not, a key of the wrong length, a key out of range,
//    a public key that is not the key's, and zero rnd, which stops
//    mldsa87_sign with CH_ASSERT. Each refusal leaves sig zeroed.
// The inputs come from SHAKE128 over a counter, so every run reads the
// same bytes.
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "mldsa.h"
#include "mldsa_sign.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_signer.h"
#include "sha3.h"

static int failures;
#define CHECK(c)                                                                                   \
    do {                                                                                           \
        if (!(c)) {                                                                                \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                     \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static jmp_buf assert_return;
static volatile int expect_assert;

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    if (expect_assert) {
        expect_assert = 0;
        longjmp(assert_return, 1);
    }
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// n bytes of SHAKE128(label || counter).
static void fill(uint8_t *out, size_t n, uint32_t label, uint32_t counter) {
    uint8_t in[8];
    for (unsigned b = 0; b < 4; b++) {
        in[b] = (uint8_t)(label >> (8 * b));
        in[4 + b] = (uint8_t)(counter >> (8 * b));
    }
    shake h;
    shake128_init(&h);
    shake_absorb(&h, in, sizeof in);
    shake_squeeze(&h, out, n);
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

// FIPS 204 Algorithm 36 with its division, and Algorithm 35.
static void test_rounding(void) {
    unsigned bad_decompose = 0;
    unsigned bad_power2 = 0;
    for (int32_t r = 0; r < MLD_Q; r++) {
        int32_t low = r % (2 * MLD_GAMMA2);
        if (low > MLD_GAMMA2) {
            low -= 2 * MLD_GAMMA2;
        }
        int32_t want1 = (r - low) / (2 * MLD_GAMMA2);
        int32_t want0 = low;
        if (r - low == MLD_Q - 1) {
            want1 = 0;
            want0 = low - 1;
        }
        int32_t r0 = 0;
        int32_t r1 = mlds_decompose(r, &r0);
        bad_decompose += r1 != want1 || r0 != want0;
        int32_t t0w = r & ((1 << MLD_D) - 1);
        if (t0w > (1 << (MLD_D - 1))) {
            t0w -= 1 << MLD_D;
        }
        int32_t t0 = 0;
        int32_t t1 = mlds_power2round(r, &t0);
        bad_power2 += t0 != t0w || t1 != (r - t0w) >> MLD_D;
    }
    CHECK(bad_decompose == 0);
    CHECK(bad_power2 == 0);
}

// Each coefficient function against int64_t arithmetic, over values that
// include the ends of int32_t.
static void test_coefficients(void) {
    static const int32_t edges[] = {INT32_MIN,
                                    INT32_MIN + 1,
                                    -MLD_Q - 1,
                                    -MLD_Q,
                                    -MLD_Q + 1,
                                    -(MLD_Q - 1) / 2 - 1,
                                    -1,
                                    0,
                                    1,
                                    (MLD_Q - 1) / 2,
                                    (MLD_Q + 1) / 2,
                                    MLD_Q - 1,
                                    MLD_Q,
                                    2 * MLD_Q,
                                    INT32_MAX - 1,
                                    INT32_MAX};
    unsigned bad = 0;
    for (uint32_t n = 0; n < 4000; n++) {
        int32_t a;
        int32_t b;
        if (n < 256) {
            a = edges[n % 16];
            b = edges[n / 16];
        } else {
            uint8_t bytes[8];
            fill(bytes, sizeof bytes, 1, n);
            a = (int32_t)((uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
                          (uint32_t)bytes[3] << 24);
            b = (int32_t)((uint32_t)bytes[4] | (uint32_t)bytes[5] << 8 | (uint32_t)bytes[6] << 16 |
                          (uint32_t)bytes[7] << 24);
        }
        int64_t mod_a = (((int64_t)a % MLD_Q) + MLD_Q) % MLD_Q;
        int32_t r = mlds_reduce32(a);
        bad += (((int64_t)r - mod_a) % MLD_Q != 0) || r > 6291200 || r < -6291200;
        bad += mlds_freeze(a) != mod_a;
        int64_t centered = mod_a > (MLD_Q - 1) / 2 ? mod_a - MLD_Q : mod_a;
        bad += mlds_center(a) != centered;
        // a * b * 2^-32 mod q: 2^-32 mod q is 8265825.
        int64_t mod_b = (((int64_t)b % MLD_Q) + MLD_Q) % MLD_Q;
        int64_t want = mod_a * mod_b % MLD_Q * 8265825 % MLD_Q;
        int32_t got = mlds_mul_reduced(a, b);
        bad += (((int64_t)got - want) % MLD_Q != 0) || got >= MLD_Q || got <= -MLD_Q;
        bad += mlds_at_least(mlds_center(a), MLD_GAMMA2) != (llabs(centered) >= MLD_GAMMA2);
    }
    CHECK(bad == 0);
}

// The masked SampleInBall against the verifier's, which branches.
static void test_sample_in_ball(void) {
    unsigned bad = 0;
    for (uint32_t n = 0; n < 200; n++) {
        uint8_t c_tilde[64];
        fill(c_tilde, sizeof c_tilde, 2, n);
        mld_poly want;
        mld_poly got;
        int placed_want = mld_sample_in_ball(&want, c_tilde);
        uint32_t placed = mlds_sample_in_ball(&got, c_tilde);
        bad += placed != (uint32_t)placed_want || memcmp(&want, &got, sizeof want) != 0;
    }
    CHECK(bad == 0);
}

// The library signer and the test signer over the same inputs.
static void test_against_test_signer(void) {
    static mldsa_test_key key;
    static uint8_t sk[MLDSA87_SK_LEN];
    static uint8_t pk[MLDSA87_PK_LEN];
    unsigned bad = 0;
    for (uint32_t n = 0; n < 48; n++) {
        uint8_t seed[32];
        uint8_t rnd[32];
        uint8_t msg[300];
        uint8_t ctx[255];
        fill(seed, sizeof seed, 3, n);
        fill(rnd, sizeof rnd, 4, n);
        fill(msg, sizeof msg, 5, n);
        fill(ctx, sizeof ctx, 6, n);
        size_t msg_len = ((size_t)n * 37) % sizeof msg;
        size_t ctx_len = n == 0 ? 255 : ((size_t)n * 53) % 256;
        if (n % 4 == 3) {
            memset(rnd, 0, sizeof rnd);
        }
        mldsa_test_keygen(&key, seed);
        CHECK(mldsa87_keygen(sk, pk, seed) == 1);
        bad += memcmp(pk, key.pk, sizeof pk) != 0;
        uint8_t want[MLDSA87_SIG_LEN];
        uint8_t got[MLDSA87_SIG_LEN];
        int want_ok = mldsa_test_sign(&key, msg, msg_len, ctx, ctx_len, rnd, want);
        int got_ok = mldsa87_sign_any_rnd(got, sk, sizeof sk, pk, sizeof pk, msg, msg_len, ctx,
                                          ctx_len, rnd);
        bad += want_ok != 1 || got_ok != 1 || memcmp(want, got, sizeof want) != 0;
        bad += !mldsa87_verify(pk, sizeof pk, msg, msg_len, ctx, ctx_len, got, sizeof got);
    }
    CHECK(bad == 0);
}

static int sign_zero_rnd_asserts(uint8_t *sig, const uint8_t *sk, const uint8_t *pk) {
    static const uint8_t zero[MLDSA87_RND_LEN] = {0};
    if (setjmp(assert_return) != 0) {
        return 1;
    }
    expect_assert = 1;
    (void)mldsa87_sign(sig, sk, MLDSA87_SK_LEN, pk, MLDSA87_PK_LEN, NULL, 0, NULL, 0, zero);
    expect_assert = 0;
    return 0;
}

// Each refusal at its boundary, with sig zeroed.
static void test_refusals(void) {
    static uint8_t sk[MLDSA87_SK_LEN];
    static uint8_t pk[MLDSA87_PK_LEN];
    static uint8_t other_sk[MLDSA87_SK_LEN];
    static uint8_t other_pk[MLDSA87_PK_LEN];
    uint8_t seed[32];
    uint8_t rnd[32];
    uint8_t ctx[256];
    fill(seed, sizeof seed, 7, 0);
    fill(rnd, sizeof rnd, 7, 1);
    fill(ctx, sizeof ctx, 7, 2);
    CHECK(mldsa87_keygen(sk, pk, seed) == 1);
    seed[0] ^= 1;
    CHECK(mldsa87_keygen(other_sk, other_pk, seed) == 1);
    static uint8_t sig[MLDSA87_SIG_LEN];
    CHECK(mldsa87_sign(sig, sk, sizeof sk, pk, sizeof pk, NULL, 0, ctx, 255, rnd) == 1);
    CHECK(mldsa87_verify(pk, sizeof pk, NULL, 0, ctx, 255, sig, sizeof sig) == 1);
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, sk, sizeof sk, pk, sizeof pk, NULL, 0, ctx, 256, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, sk, sizeof sk - 1, pk, sizeof pk, NULL, 0, NULL, 0, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, sk, sizeof sk, pk, sizeof pk + 1, NULL, 0, NULL, 0, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    // The check under pk: a key that is not pk's signs, and the signature
    // fails mldsa87_verify, so the call returns 0 with sig zeroed.
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, other_sk, sizeof other_sk, pk, sizeof pk, NULL, 0, NULL, 0, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    // s1's first 3-bit value at 5, then s2's last at 7: each out of range.
    static uint8_t bad_key[MLDSA87_SK_LEN];
    memcpy(bad_key, sk, sizeof bad_key);
    bad_key[128] = (uint8_t)((bad_key[128] & 0xf8U) | 5U);
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, bad_key, sizeof bad_key, pk, sizeof pk, NULL, 0, NULL, 0, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    memcpy(bad_key, sk, sizeof bad_key);
    bad_key[128 + 15 * 96 - 1] |= 0xe0U;
    memset(sig, 0xa5, sizeof sig);
    CHECK(mldsa87_sign(sig, bad_key, sizeof bad_key, pk, sizeof pk, NULL, 0, NULL, 0, rnd) == 0);
    CHECK(all_zero(sig, sizeof sig));
    // The range check at its edge: every 3-bit value 4, the last in range,
    // reads, and one 5 among them does not.
    uint8_t packed[MLDS_ETA_BYTES];
    mld_poly p;
    for (unsigned i = 0; i < MLDS_ETA_BYTES; i += 3) {
        packed[i] = 0x24;     // 100 100 10
        packed[i + 1] = 0x49; // 0 100 100 1
        packed[i + 2] = 0x92; // 00 100 100
    }
    CHECK(mlds_unpack_eta(&p, packed) == 1 && p.coeffs[0] == -2 && p.coeffs[255] == -2);
    packed[MLDS_ETA_BYTES - 1] = 0xb2; // the last value 5
    CHECK(mlds_unpack_eta(&p, packed) == 0);
    CHECK(sign_zero_rnd_asserts(sig, sk, pk) == 1);
}

// Two hedged signatures of one message differ, and both verify.
static void test_hedge(void) {
    static uint8_t sk[MLDSA87_SK_LEN];
    static uint8_t pk[MLDSA87_PK_LEN];
    static uint8_t first[MLDSA87_SIG_LEN];
    static uint8_t second[MLDSA87_SIG_LEN];
    uint8_t seed[32];
    uint8_t rnd[32];
    fill(seed, sizeof seed, 8, 0);
    CHECK(mldsa87_keygen(sk, pk, seed) == 1);
    const uint8_t msg[] = "CertificateVerify";
    fill(rnd, sizeof rnd, 8, 1);
    CHECK(mldsa87_sign(first, sk, sizeof sk, pk, sizeof pk, msg, sizeof msg, NULL, 0, rnd) == 1);
    fill(rnd, sizeof rnd, 8, 2);
    CHECK(mldsa87_sign(second, sk, sizeof sk, pk, sizeof pk, msg, sizeof msg, NULL, 0, rnd) == 1);
    CHECK(memcmp(first, second, sizeof first) != 0);
    CHECK(mldsa87_verify(pk, sizeof pk, msg, sizeof msg, NULL, 0, first, sizeof first) == 1);
    CHECK(mldsa87_verify(pk, sizeof pk, msg, sizeof msg, NULL, 0, second, sizeof second) == 1);
}

int main(void) {
    test_rounding();
    test_coefficients();
    test_sample_in_ball();
    test_against_test_signer();
    test_refusals();
    test_hedge();
    if (failures != 0) {
        (void)fprintf(stderr, "mldsa signer: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("mldsa signer: rounding at every r, coefficients, SampleInBall, 48 signatures "
                 "equal to the test signer's, refusals, hedge: ok\n");
    return 0;
}
