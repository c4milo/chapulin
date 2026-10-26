// The test-only ML-DSA-87 signer. Contract in test/mldsa_sign.h. It runs
// the NTT, the products and the samplers of mldsa_poly.c, which the
// verifier runs too, and writes FIPS 204's other steps out here: ExpandS,
// ExpandMask, Power2Round, Decompose, MakeHint and the encodings.
#include "mldsa_sign.h"

#include <string.h>

#include "sha3.h"

#define ETA 2

// a mod q, in [0, q).
static int32_t mod_q(int32_t a) {
    int32_t r = mld_reduce32(a);
    return r < 0 ? r + MLD_Q : r;
}

// a mod± q, in [-(q - 1) / 2, (q - 1) / 2].
static int32_t centered(int32_t a) {
    int32_t r = mod_q(a);
    return r > (MLD_Q - 1) / 2 ? r - MLD_Q : r;
}

static int32_t abs32(int32_t a) {
    return a < 0 ? -a : a;
}

// p = NTT^-1(a o b), with each coefficient centered.
static void product(mld_poly *p, const mld_poly *a_hat, const mld_poly *b_hat) {
    mld_poly_pointwise(p, a_hat, b_hat);
    mld_poly_invntt_tomont(p);
    for (int j = 0; j < MLD_N; j++) {
        p->coeffs[j] = centered(p->coeffs[j]);
    }
}

// Row i of NTT^-1(A o v_hat), with each coefficient in [0, q).
static void matrix_row(mld_poly *row, const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                       const mld_poly v_hat[MLD_L]) {
    mld_poly entry;
    for (unsigned j = 0; j < MLD_L; j++) {
        int ok = mld_sample_ntt(&entry, rho, (uint8_t)j, (uint8_t)i);
        (void)ok; // a bound reached has a probability below 2^-546
        if (j == 0) {
            mld_poly_pointwise(row, &entry, &v_hat[0]);
        } else {
            mld_poly_pointwise_acc(row, &entry, &v_hat[j]);
        }
    }
    mld_poly_invntt_tomont(row);
    for (int j = 0; j < MLD_N; j++) {
        row->coeffs[j] = mod_q(row->coeffs[j]);
    }
}

// FIPS 204 Algorithm 31, RejBoundedPoly, at eta = 2: SHAKE256(rho' || r).
static void sample_bounded(mld_poly *p, const uint8_t rho_prime[64], uint16_t r) {
    uint8_t nonce[2] = {(uint8_t)r, (uint8_t)(r >> 8)};
    shake h;
    shake256_init(&h);
    shake_absorb(&h, rho_prime, 64);
    shake_absorb(&h, nonce, sizeof nonce);
    int j = 0;
    while (j < MLD_N) {
        uint8_t z = 0;
        shake_squeeze(&h, &z, 1);
        const uint8_t halves[2] = {(uint8_t)(z & 15), (uint8_t)(z >> 4)};
        for (int t = 0; t < 2 && j < MLD_N; t++) {
            if (halves[t] < 15) {
                p->coeffs[j++] = ETA - (int32_t)(halves[t] % 5);
            }
        }
    }
}

// Writes the b-bit values v[0..255] to out, low bits first (FIPS 204
// Algorithm 16, SimpleBitPack).
static void pack_bits(uint8_t *out, const uint32_t v[MLD_N], unsigned b) {
    memset(out, 0, (size_t)MLD_N * b / 8);
    for (unsigned j = 0; j < MLD_N; j++) {
        for (unsigned bit = 0; bit < b; bit++) {
            unsigned at = j * b + bit;
            out[at / 8] |= (uint8_t)(((v[j] >> bit) & 1U) << (at % 8));
        }
    }
}

// FIPS 204 Algorithm 35, Power2Round: t = t1 * 2^d + t0.
static void power2round(int32_t t, int32_t *t1, int32_t *t0) {
    int32_t r = mod_q(t);
    int32_t r0 = r & ((1 << MLD_D) - 1);
    if (r0 > (1 << (MLD_D - 1))) {
        r0 -= 1 << MLD_D;
    }
    *t0 = r0;
    *t1 = (r - r0) >> MLD_D;
}

void mldsa_test_keygen(mldsa_test_key *k, const uint8_t seed[32]) {
    uint8_t expanded[128];
    const uint8_t dims[2] = {MLD_K, MLD_L};
    shake h;
    shake256_init(&h);
    shake_absorb(&h, seed, 32);
    shake_absorb(&h, dims, sizeof dims);
    shake_squeeze(&h, expanded, sizeof expanded);
    memcpy(k->rho, expanded, MLD_RHO_BYTES);
    const uint8_t *rho_prime = expanded + 32;
    memcpy(k->key, expanded + 96, 32);
    for (unsigned r = 0; r < MLD_L; r++) {
        sample_bounded(&k->s1_hat[r], rho_prime, (uint16_t)r);
        mld_poly_ntt(&k->s1_hat[r]);
    }
    memcpy(k->pk, k->rho, MLD_RHO_BYTES);
    for (unsigned i = 0; i < MLD_K; i++) {
        mld_poly t;
        mld_poly s2;
        sample_bounded(&s2, rho_prime, (uint16_t)(i + MLD_L));
        matrix_row(&t, k->rho, i, k->s1_hat);
        uint32_t t1[MLD_N];
        for (int j = 0; j < MLD_N; j++) {
            int32_t high = 0;
            power2round(t.coeffs[j] + s2.coeffs[j], &high, &k->t0_hat[i].coeffs[j]);
            t1[j] = (uint32_t)high;
        }
        pack_bits(k->pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES, t1, 10);
        k->s2_hat[i] = s2;
        mld_poly_ntt(&k->s2_hat[i]);
        mld_poly_ntt(&k->t0_hat[i]);
    }
    shake256_init(&h);
    shake_absorb(&h, k->pk, MLDSA87_PK_LEN);
    shake_squeeze(&h, k->tr, sizeof k->tr);
}

// FIPS 204 Algorithm 36, Decompose, at gamma2 = (q - 1) / 32: r = r1 *
// 2 * gamma2 + r0.
static void decompose(int32_t r, int32_t *r1, int32_t *r0) {
    int32_t plus = mod_q(r);
    int32_t low = plus % (2 * MLD_GAMMA2);
    if (low > MLD_GAMMA2) {
        low -= 2 * MLD_GAMMA2;
    }
    if (plus - low == MLD_Q - 1) {
        *r1 = 0;
        *r0 = low - 1;
        return;
    }
    *r1 = (plus - low) / (2 * MLD_GAMMA2);
    *r0 = low;
}

static int32_t high_bits(int32_t r) {
    int32_t r1 = 0;
    int32_t r0 = 0;
    decompose(r, &r1, &r0);
    return r1;
}

// FIPS 204 Algorithm 34, ExpandMask: y[r] from SHAKE256(rho'' || kappa + r)
// at 20 bits a coefficient, as gamma1 minus the packed value.
static void expand_mask(mld_poly y[MLD_L], const uint8_t rho2[64], unsigned kappa) {
    for (unsigned r = 0; r < MLD_L; r++) {
        unsigned nonce = kappa + r;
        uint8_t n2[2] = {(uint8_t)nonce, (uint8_t)(nonce >> 8)};
        uint8_t buf[MLD_Z_BYTES];
        shake h;
        shake256_init(&h);
        shake_absorb(&h, rho2, 64);
        shake_absorb(&h, n2, sizeof n2);
        shake_squeeze(&h, buf, sizeof buf);
        for (unsigned j = 0; j < MLD_N; j++) {
            uint32_t v = 0;
            for (unsigned bit = 0; bit < 20; bit++) {
                unsigned at = j * 20 + bit;
                v |= (uint32_t)((buf[at / 8] >> (at % 8)) & 1U) << bit;
            }
            y[r].coeffs[j] = MLD_GAMMA1 - (int32_t)v;
        }
    }
}

// The working state of one round of the rejection loop.
typedef struct {
    mld_poly z[MLD_L];
    mld_poly w[MLD_K];
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    mld_poly c_hat;
} sign_round;

// The commitment w = A y and the challenge for it (FIPS 204 Algorithm 7,
// steps 11 to 16). Writes y_hat into r->z. Returns 0 when SampleInBall
// stops at its bound.
static int commit(sign_round *r, const mldsa_test_key *k, const uint8_t mu[64],
                  const uint8_t rho2[64], unsigned kappa) {
    expand_mask(r->z, rho2, kappa);
    mld_poly y_hat[MLD_L];
    for (unsigned j = 0; j < MLD_L; j++) {
        y_hat[j] = r->z[j];
        mld_poly_ntt(&y_hat[j]);
    }
    shake h;
    shake256_init(&h);
    shake_absorb(&h, mu, 64);
    for (unsigned i = 0; i < MLD_K; i++) {
        matrix_row(&r->w[i], k->rho, i, y_hat);
        uint32_t w1[MLD_N];
        for (int j = 0; j < MLD_N; j++) {
            w1[j] = (uint32_t)high_bits(r->w[i].coeffs[j]);
        }
        uint8_t packed[MLD_W1_BYTES];
        pack_bits(packed, w1, 4);
        shake_absorb(&h, packed, sizeof packed);
    }
    shake_squeeze(&h, r->c_tilde, sizeof r->c_tilde);
    if (!mld_sample_in_ball(&r->c_hat, r->c_tilde)) {
        return 0;
    }
    mld_poly_ntt(&r->c_hat);
    return 1;
}

// z = y + c s1, and whether every coefficient is under gamma1 - beta.
static int response(sign_round *r, const mldsa_test_key *k) {
    for (unsigned j = 0; j < MLD_L; j++) {
        mld_poly cs1;
        product(&cs1, &r->c_hat, &k->s1_hat[j]);
        for (int n = 0; n < MLD_N; n++) {
            r->z[j].coeffs[n] = centered(r->z[j].coeffs[n] + cs1.coeffs[n]);
            if (abs32(r->z[j].coeffs[n]) >= MLD_GAMMA1 - MLD_BETA) {
                return 0;
            }
        }
    }
    return 1;
}

// The low-bits and ct0 checks and the hints (FIPS 204 Algorithm 7, steps
// 21 to 28), written into hints as HintBitPack writes them. Returns 0 when
// a check rejects the round.
static int hints(const sign_round *r, const mldsa_test_key *k, uint8_t hints_out[MLD_HINT_BYTES]) {
    memset(hints_out, 0, MLD_HINT_BYTES);
    unsigned count = 0;
    for (unsigned i = 0; i < MLD_K; i++) {
        mld_poly cs2;
        mld_poly ct0;
        product(&cs2, &r->c_hat, &k->s2_hat[i]);
        product(&ct0, &r->c_hat, &k->t0_hat[i]);
        for (unsigned n = 0; n < MLD_N; n++) {
            int32_t w_cs2 = r->w[i].coeffs[n] - cs2.coeffs[n];
            int32_t r1 = 0;
            int32_t r0 = 0;
            decompose(w_cs2, &r1, &r0);
            if (abs32(r0) >= MLD_GAMMA2 - MLD_BETA || abs32(ct0.coeffs[n]) >= MLD_GAMMA2) {
                return 0;
            }
            // MakeHint(-ct0, w - cs2 + ct0): whether adding -ct0 moves the
            // high bits of w - cs2 + ct0.
            int32_t base = w_cs2 + ct0.coeffs[n];
            if (high_bits(base) != high_bits(base - ct0.coeffs[n])) {
                if (count == MLD_OMEGA) {
                    return 0;
                }
                hints_out[count++] = (uint8_t)n;
            }
        }
        hints_out[MLD_OMEGA + i] = (uint8_t)count;
    }
    return 1;
}

// sigEncode (FIPS 204 Algorithm 26): c_tilde, z at 20 bits as gamma1 - z,
// then the hints.
static void encode(uint8_t sig[MLDSA87_SIG_LEN], const sign_round *r,
                   const uint8_t hint_bytes[MLD_HINT_BYTES]) {
    memcpy(sig, r->c_tilde, MLDSA87_CTILDE_LEN);
    for (unsigned j = 0; j < MLD_L; j++) {
        uint32_t v[MLD_N];
        for (int n = 0; n < MLD_N; n++) {
            v[n] = (uint32_t)(MLD_GAMMA1 - r->z[j].coeffs[n]);
        }
        pack_bits(sig + MLDSA87_CTILDE_LEN + (size_t)j * MLD_Z_BYTES, v, 20);
    }
    memcpy(sig + MLDSA87_CTILDE_LEN + (size_t)MLD_L * MLD_Z_BYTES, hint_bytes, MLD_HINT_BYTES);
}

int mldsa_test_sign(const mldsa_test_key *k, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                    size_t ctx_len, const uint8_t rnd[32], uint8_t sig[MLDSA87_SIG_LEN]) {
    const uint8_t prefix[2] = {0, (uint8_t)ctx_len};
    uint8_t mu[64];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, k->tr, sizeof k->tr);
    shake_absorb(&h, prefix, sizeof prefix);
    shake_absorb(&h, ctx, ctx_len);
    shake_absorb(&h, msg, msg_len);
    shake_squeeze(&h, mu, sizeof mu);
    return mldsa_test_sign_mu(k, mu, rnd, sig);
}

int mldsa_test_sign_mu(const mldsa_test_key *k, const uint8_t mu[64], const uint8_t rnd[32],
                       uint8_t sig[MLDSA87_SIG_LEN]) {
    uint8_t rho2[64];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, k->key, sizeof k->key);
    shake_absorb(&h, rnd, 32);
    shake_absorb(&h, mu, 64);
    shake_squeeze(&h, rho2, sizeof rho2);
    static sign_round r;
    for (unsigned round = 0; round < 1000; round++) {
        if (!commit(&r, k, mu, rho2, round * MLD_L)) {
            return 0;
        }
        uint8_t hint_bytes[MLD_HINT_BYTES];
        if (response(&r, k) && hints(&r, k, hint_bytes)) {
            encode(sig, &r, hint_bytes);
            return 1;
        }
    }
    return 0;
}
