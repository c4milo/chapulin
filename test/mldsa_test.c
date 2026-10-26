// ML-DSA-87 verification against answers this file computes from FIPS 204
// itself (docs/decisions.md 154):
//
// - The zetas, from zeta = 1753.
// - The coefficient arithmetic: each result is congruent to its FIPS 204
//   value mod q and inside the bound mldsa_poly.h states.
// - The NTT: NTT^-1(NTT(a) o NTT(b)) is the product of a and b mod
//   X^256 + 1, computed here term by term.
// - Decompose and UseHint, for every r in [0, q) and both hints, against
//   Algorithms 36 and 40 written with the % operator.
// - The bit unpacking of t1 and z, the norm bound of z at its edges, and
//   SampleInBall's tau coefficients.
// - Whole signatures under a key whose t1 is 0: A z is then 0 for z = 0,
//   so w1 holds only what the hints give, and this file computes c_tilde
//   from SHAKE256 alone. Each of HintBitUnpack's refusals, a flipped bit,
//   the context's bounds and the two lengths must each fail.
//
// Its own binary, like mlkem_test: the module stays testable without the
// rest of the stack. bin/wycheproof_test holds the published known answers.
#include <stdio.h>
#include <string.h>

#include "mldsa.h"
#include "mldsa_poly.h"
#include "mldsa_zetas.h"
#include "sha3.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static uint64_t rng_state = 0x6d6c2d6473612d38ULL;

static uint64_t next_random(void) {
    rng_state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = rng_state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static int64_t mod_q(int64_t a) {
    int64_t r = a % MLD_Q;
    return r < 0 ? r + MLD_Q : r;
}

static int64_t power_mod_q(int64_t base, unsigned e) {
    int64_t r = 1;
    for (unsigned i = 0; i < e; i++) {
        r = r * base % MLD_Q;
    }
    return r;
}

static unsigned bit_reverse8(unsigned k) {
    unsigned r = 0;
    for (unsigned b = 0; b < 8; b++) {
        r |= ((k >> b) & 1U) << (7 - b);
    }
    return r;
}

// zetas[k] = 1753^bitreverse8(k) * 2^32 mod q, centered, for k = 1..255.
static void test_zetas(void) {
    const int64_t r_mod_q = (int64_t)(((uint64_t)1 << 32) % MLD_Q);
    for (unsigned k = 1; k < 256; k++) {
        int64_t want = power_mod_q(1753, bit_reverse8(k)) * r_mod_q % MLD_Q;
        CHECK(mod_q(MLD_ZETAS[k]) == want);
        CHECK(MLD_ZETAS[k] <= (MLD_Q - 1) / 2 && MLD_ZETAS[k] >= -(MLD_Q - 1) / 2);
    }
}

static int32_t random_int32(void) {
    return (int32_t)(uint32_t)next_random();
}

// 2^32 mod q, the factor a Montgomery reduction divides out.
#define TEST_R_MOD_Q 4193792

static void test_coefficients(void) {
    const int32_t edges[] = {0, 1, -1, MLD_Q, -MLD_Q, INT32_MAX, INT32_MIN, (1 << 22), -(1 << 22)};
    for (unsigned n = 0; n < 200000; n++) {
        int32_t a = n < 9 ? edges[n] : random_int32();
        int32_t b = random_int32();
        int32_t r = mld_reduce32(a);
        CHECK(mod_q(r) == mod_q(a) && r <= 6291200 && r >= -6291200);
        int32_t zeta = MLD_ZETAS[1 + n % 255];
        int32_t product = mld_mul_zeta(zeta, a);
        CHECK(product < MLD_Q && product > -MLD_Q);
        CHECK(mod_q((int64_t)product * TEST_R_MOD_Q) == mod_q((int64_t)zeta * a));
        int32_t reduced = mld_mul_reduced(a, b);
        CHECK(reduced < MLD_Q && reduced > -MLD_Q);
        CHECK(mod_q((int64_t)reduced * TEST_R_MOD_Q) == mod_q(mod_q(a) * mod_q(b)));
    }
}

static void random_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = random_int32();
    }
}

// The product mod X^256 + 1, term by term, of the canonical values.
static void negacyclic_product(int64_t out[MLD_N], const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        out[i] = 0;
    }
    for (unsigned i = 0; i < MLD_N; i++) {
        for (unsigned j = 0; j < MLD_N; j++) {
            int64_t term = mod_q(a->coeffs[i]) * mod_q(b->coeffs[j]) % MLD_Q;
            unsigned at = (i + j) % MLD_N;
            out[at] = mod_q(i + j < MLD_N ? out[at] + term : out[at] - term);
        }
    }
}

// The inverse NTT's 2^32 cancels the product's 2^-32, so the result is
// the ring product itself, from inputs anywhere in int32_t.
static void test_ntt(void) {
    for (unsigned round = 0; round < 8; round++) {
        mld_poly a;
        mld_poly b;
        random_poly(&a);
        random_poly(&b);
        int64_t want[MLD_N];
        negacyclic_product(want, &a, &b);
        mld_poly a_hat = a;
        mld_poly b_hat = b;
        mld_poly_ntt(&a_hat);
        mld_poly_ntt(&b_hat);
        mld_poly product;
        mld_poly_pointwise(&product, &a_hat, &b_hat);
        mld_poly_invntt_tomont(&product);
        int same = 1;
        for (unsigned i = 0; i < MLD_N; i++) {
            same &= mod_q(product.coeffs[i]) == want[i];
            same &= product.coeffs[i] < MLD_Q && product.coeffs[i] > -MLD_Q;
        }
        CHECK(same);
    }
}

// FIPS 204 Algorithms 36 and 40 with the % operator, at 2 * gamma2.
static unsigned use_hint_reference(int64_t r, unsigned hint) {
    const int64_t alpha = (int64_t)2 * MLD_GAMMA2;
    int64_t r0 = r % alpha;
    if (r0 > alpha / 2) {
        r0 -= alpha;
    }
    int64_t r1;
    if (r - r0 == MLD_Q - 1) {
        r1 = 0;
        r0 -= 1;
    } else {
        r1 = (r - r0) / alpha;
    }
    if (hint == 1 && r0 > 0) {
        return (unsigned)((r1 + 1) % 16);
    }
    if (hint == 1) {
        return (unsigned)((r1 + 15) % 16);
    }
    return (unsigned)r1;
}

static void test_use_hint(void) {
    unsigned wrong = 0;
    for (int32_t r = 0; r < MLD_Q; r++) {
        for (unsigned hint = 0; hint < 2; hint++) {
            wrong += mld_use_hint_coefficient(r, hint) != use_hint_reference(r, hint);
            // The same value one q higher and one q lower reduces to r.
            wrong += mld_use_hint_coefficient(r - MLD_Q, hint) != use_hint_reference(r, hint);
        }
    }
    CHECK(wrong == 0);
}

// A packing written bit by bit, the low bit first.
static void pack_bits(uint8_t *out, const uint32_t *values, unsigned count, unsigned width) {
    memset(out, 0, (count * width + 7) / 8);
    for (unsigned i = 0; i < count; i++) {
        for (unsigned b = 0; b < width; b++) {
            unsigned at = i * width + b;
            out[at / 8] |= (uint8_t)(((values[i] >> b) & 1U) << (at % 8));
        }
    }
}

static void test_unpack(void) {
    uint32_t values[MLD_N] = {0};
    uint8_t bytes[MLD_Z_BYTES];
    mld_poly p;
    for (unsigned i = 0; i < MLD_N; i++) {
        values[i] = (uint32_t)next_random() & 0x3ffU;
    }
    pack_bits(bytes, values, MLD_N, 10);
    mld_poly_unpack_t1_shifted(&p, bytes);
    int same = 1;
    for (unsigned i = 0; i < MLD_N; i++) {
        same &= p.coeffs[i] == (int32_t)(values[i] << 13);
    }
    CHECK(same);
    // z = gamma1 - v. The edge coefficients: gamma1 - beta - 1 and its
    // negative are under the bound, gamma1 - beta and its negative are not.
    const int32_t bound = MLD_GAMMA1 - MLD_BETA;
    const int32_t edge[4] = {bound - 1, -(bound - 1), bound, -bound};
    for (unsigned e = 0; e < 4; e++) {
        for (unsigned i = 0; i < MLD_N; i++) {
            int32_t z = i == 77 ? edge[e] : (int32_t)(next_random() % 1000) - 500;
            values[i] = (uint32_t)(MLD_GAMMA1 - z);
        }
        pack_bits(bytes, values, MLD_N, 20);
        CHECK(mld_poly_unpack_z(&p, bytes) == (e < 2));
        CHECK(p.coeffs[77] == edge[e]);
    }
}

static void test_sample_in_ball(void) {
    for (unsigned round = 0; round < 64; round++) {
        uint8_t c_tilde[64];
        for (unsigned i = 0; i < 64; i++) {
            c_tilde[i] = (uint8_t)next_random();
        }
        mld_poly c;
        CHECK(mld_sample_in_ball(&c, c_tilde) == 1);
        unsigned nonzero = 0;
        unsigned other = 0;
        for (unsigned i = 0; i < MLD_N; i++) {
            nonzero += c.coeffs[i] != 0;
            other += c.coeffs[i] != 0 && c.coeffs[i] != 1 && c.coeffs[i] != -1;
        }
        CHECK(nonzero == MLD_TAU && other == 0);
    }
}

// A key whose t1 is 0 under a fixed rho, and a signature with z = 0 and
// the hints of rows 0 and 5. Then w' = 0, and UseHint(1, 0) is 15, since
// r0 = 0 moves r1 = 0 down one step. So w1Encode is 0 but for a nibble of
// 15 at each hinted position.
struct test_signature {
    uint8_t pk[MLDSA87_PK_LEN];
    uint8_t sig[MLDSA87_SIG_LEN];
    uint8_t mu[MLDSA_MU_LEN];
};

#define TEST_HINT_AT (MLDSA87_CTILDE_LEN + MLD_L * MLD_Z_BYTES)

static void shake256_of(uint8_t *out, size_t out_len, const uint8_t *a, size_t a_len,
                        const uint8_t *b, size_t b_len) {
    shake h;
    shake256_init(&h);
    shake_absorb(&h, a, a_len);
    shake_absorb(&h, b, b_len);
    shake_squeeze(&h, out, out_len);
}

// c_tilde = H(mu || w1Encode(w1), 64), where w1 is 15 at each (row,
// position) pair in hinted and 0 elsewhere.
static void set_challenge(struct test_signature *t, const uint8_t hinted[][2], size_t count) {
    uint8_t w1[MLD_K * MLD_W1_BYTES] = {0};
    for (size_t h = 0; h < count; h++) {
        unsigned at = hinted[h][0] * MLD_W1_BYTES + hinted[h][1] / 2U;
        w1[at] |= (uint8_t)(15U << (4 * (hinted[h][1] % 2U)));
    }
    shake256_of(t->sig, MLDSA87_CTILDE_LEN, t->mu, sizeof t->mu, w1, sizeof w1);
}

// The signature of msg under ctx: c_tilde = H(H(H(pk) || 0 || |ctx| ||
// ctx || msg) || w1Encode(w1), 64), with the hints at rows 0 and 5.
static void make_signature(struct test_signature *t, const uint8_t *msg, size_t msg_len,
                           const uint8_t *ctx, size_t ctx_len) {
    memset(t->pk, 0, sizeof t->pk);
    for (unsigned i = 0; i < MLD_RHO_BYTES; i++) {
        t->pk[i] = (uint8_t)(0xa0 + i);
    }
    memset(t->sig, 0, sizeof t->sig);
    // z = 0 packs as gamma1 = 0x80000 in each 20-bit field: bytes 00 00 08 00 80.
    for (unsigned at = MLDSA87_CTILDE_LEN; at < TEST_HINT_AT; at += 5) {
        t->sig[at + 2] = 0x08;
        t->sig[at + 4] = 0x80;
    }
    uint8_t *y = t->sig + TEST_HINT_AT;
    const uint8_t positions[3] = {3, 200, 0}; // row 0: 3 and 200; row 5: 0
    memcpy(y, positions, sizeof positions);
    for (unsigned i = 0; i < MLD_K; i++) {
        y[MLD_OMEGA + i] = i < 5 ? 2 : 3;
    }
    uint8_t tr[64];
    shake256_of(tr, sizeof tr, t->pk, sizeof t->pk, NULL, 0);
    uint8_t m_prime[2 + MLDSA_CONTEXT_MAX + 64];
    m_prime[0] = 0;
    m_prime[1] = (uint8_t)ctx_len;
    if (ctx_len > 0) {
        memcpy(m_prime + 2, ctx, ctx_len);
    }
    memcpy(m_prime + 2 + ctx_len, msg, msg_len);
    shake256_of(t->mu, sizeof t->mu, tr, sizeof tr, m_prime, 2 + ctx_len + msg_len);
    const uint8_t hinted[3][2] = {
        {0, 3  },
        {0, 200},
        {5, 0  }
    };
    set_challenge(t, hinted, 3);
}

static int verify(const struct test_signature *t, const uint8_t *msg, size_t msg_len,
                  const uint8_t *ctx, size_t ctx_len) {
    return mldsa87_verify(t->pk, sizeof t->pk, msg, msg_len, ctx, ctx_len, t->sig, sizeof t->sig);
}

// Each edit to the hint encoding that HintBitUnpack refuses, at y's offset.
static void test_hint_refusals(const struct test_signature *good, const uint8_t *msg,
                               size_t msg_len) {
    static struct test_signature t;
    uint8_t *y = t.sig + TEST_HINT_AT;
    t = *good;
    y[1] = 3; // a repeated position in row 0
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    // The same encoding, with c_tilde made for the hints a decoder that
    // skips the order check reads from it: row 0's 3 once, and row 5's 0.
    const uint8_t read_once[2][2] = {
        {0, 3},
        {5, 0}
    };
    set_challenge(&t, read_once, 2);
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    t = *good;
    y[0] = 200; // row 0's positions out of order
    y[1] = 3;
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    t = *good;
    y[10] = 1; // a nonzero byte after the last run
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    t = *good;
    y[MLD_OMEGA + 3] = 1; // an end below the end before it
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    t = *good;
    y[MLD_OMEGA + 7] = MLD_OMEGA + 1; // an end past omega
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
    t = *good;
    y[MLD_OMEGA + 4] = 3; // row 5's hint moved to row 4: well formed, another w1
    CHECK(verify(&t, msg, msg_len, NULL, 0) == 0);
}

static void test_signatures(void) {
    static struct test_signature t;
    static uint8_t ctx[MLDSA_CONTEXT_MAX + 1];
    const uint8_t msg[5] = {'h', 'e', 'l', 'l', 'o'};
    make_signature(&t, msg, sizeof msg, NULL, 0);
    CHECK(verify(&t, msg, sizeof msg, NULL, 0) == 1);
    uint8_t mu_c_tilde[MLDSA87_CTILDE_LEN];
    uint8_t mu[MLDSA_MU_LEN] = {0};
    CHECK(mldsa87_challenge(mu_c_tilde, t.pk, mu, t.sig) == 1);
    CHECK(verify(&t, msg, sizeof msg - 1, NULL, 0) == 0);
    CHECK(mldsa87_verify(t.pk, MLDSA87_PK_LEN - 1, msg, sizeof msg, NULL, 0, t.sig,
                         MLDSA87_SIG_LEN) == 0);
    CHECK(mldsa87_verify(t.pk, MLDSA87_PK_LEN, msg, sizeof msg, NULL, 0, t.sig,
                         MLDSA87_SIG_LEN - 1) == 0);
    for (unsigned bit = 0; bit < 8 * MLDSA87_CTILDE_LEN; bit += 37) {
        t.sig[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        CHECK(verify(&t, msg, sizeof msg, NULL, 0) == 0);
        t.sig[bit / 8] ^= (uint8_t)(1U << (bit % 8));
    }
    test_hint_refusals(&t, msg, sizeof msg);
    // The context: the longest, 255 bytes, verifies; one byte more is refused.
    for (unsigned i = 0; i < sizeof ctx; i++) {
        ctx[i] = (uint8_t)i;
    }
    make_signature(&t, msg, sizeof msg, ctx, MLDSA_CONTEXT_MAX);
    CHECK(verify(&t, msg, sizeof msg, ctx, MLDSA_CONTEXT_MAX) == 1);
    CHECK(verify(&t, msg, sizeof msg, ctx, MLDSA_CONTEXT_MAX - 1) == 0);
    CHECK(verify(&t, msg, sizeof msg, ctx, MLDSA_CONTEXT_MAX + 1) == 0);
    // A z coefficient at gamma1 - beta, the first value the bound refuses.
    make_signature(&t, msg, sizeof msg, NULL, 0);
    const uint32_t v = MLD_GAMMA1 - (MLD_GAMMA1 - MLD_BETA);
    t.sig[MLDSA87_CTILDE_LEN] = (uint8_t)v;
    t.sig[MLDSA87_CTILDE_LEN + 1] = (uint8_t)(v >> 8);
    t.sig[MLDSA87_CTILDE_LEN + 2] = (uint8_t)(v >> 16);
    CHECK(mldsa87_challenge(mu_c_tilde, t.pk, mu, t.sig) == 0);
}

int main(void) {
    test_zetas();
    test_coefficients();
    test_ntt();
    test_use_hint();
    test_unpack();
    test_sample_in_ball();
    test_signatures();
    if (failures == 0) {
        (void)printf("mldsa-87: all tests passed\n");
    }
    return failures != 0;
}
