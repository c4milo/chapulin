// The steps of one round of ML-DSA-87's rejection loop (FIPS 204
// Algorithm 7), and a row of key generation (Algorithm 6). Contract in
// mldsa_sign_steps.h.
//
// In a device object neither s1, s2 nor t0 is held whole in the NTT
// domain. Each step that needs one polynomial of them decodes it from sk
// and transforms it, so a round holds NTT(y) or z, w, NTT(c) and two
// polynomials of work: 18 of them, 18 kB (docs/decisions.md 159). Each
// entry of A is sampled from rho just before its product, as the verifier
// samples it (mldsa.c). A host object's signer runs mlds_expand once for
// each signature, and each step then reads A and the three NTTs from
// st->ex (docs/decisions.md 191).
#include "mldsa_sign_steps.h"

#include "ct.h"
#include "mldsa_avx2.h"
#include "mldsa_sign_poly.h"
#include "sha3.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// The sum mlds_matrix_row computes before its inverse NTT, with the
// row's entries sampled four at a time on the four-way Keccak
// (mldsa_avx2.h). Returns 1, or 0 when an entry stops at its sampling
// bound. The entries are public, so four is not wiped.
static int mlds_matrix_row_avx2(uint32_t cpu, mld_poly *row, const uint8_t rho[MLD_RHO_BYTES],
                                unsigned i, const mld_poly v_hat[MLD_L]) {
    mld_poly four[MLD_AVX2_ENTRIES];
    for (unsigned first = 0; first < MLD_L; first += MLD_AVX2_ENTRIES) {
        unsigned count = MLD_L - first < MLD_AVX2_ENTRIES ? MLD_L - first : MLD_AVX2_ENTRIES;
        if (!mld_sample_ntt_avx2(four, rho, i, first, count)) {
            return 0;
        }
        for (unsigned k = 0; k < count; k++) {
            if (first + k == 0) {
                mlds_pointwise(cpu, row, &four[0], &v_hat[0]);
            } else {
                mlds_pointwise_acc(cpu, row, &four[k], &v_hat[first + k]);
            }
        }
    }
    return 1;
}
#endif // CH_CPU_RUNTIME && __x86_64__

// The sum mlds_matrix_row computes before its inverse NTT, each entry
// sampled into entry.
static int mlds_matrix_row_sum(uint32_t cpu, mld_poly *row, mld_poly *entry,
                               const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                               const mld_poly v_hat[MLD_L]) {
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
    if (cpu & CH_CPU_AVX2) {
        return mlds_matrix_row_avx2(cpu, row, rho, i, v_hat);
    }
#endif
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_sample_ntt_cpu(cpu, entry, rho, (uint8_t)j, (uint8_t)i)) {
            return 0;
        }
        if (j == 0) {
            mlds_pointwise(cpu, row, entry, &v_hat[0]);
        } else {
            mlds_pointwise_acc(cpu, row, entry, &v_hat[j]);
        }
    }
    return 1;
}

int mlds_matrix_row(uint32_t cpu, mld_poly *row, mld_poly *entry, const uint8_t rho[MLD_RHO_BYTES],
                    unsigned i, const mld_poly v_hat[MLD_L]) {
    if (!mlds_matrix_row_sum(cpu, row, entry, rho, i, v_hat)) {
        // Defined values for the caller. Its ct_wipe of its state
        // writes zero to row afterwards as well.
        for (unsigned n = 0; n < MLD_N; n++) {
            row->coeffs[n] = 0;
        }
        return 0;
    }
    mlds_invntt_freeze(cpu, row);
    return 1;
}

#ifdef CH_CPU_RUNTIME
// Row i of A into row, each entry sampled in the NTT domain from rho.
// Returns 1, or 0 when an entry stops at its sampling bound. On x86-64,
// for a cpu that holds CH_CPU_AVX2, the four-way Keccak samples four
// entries into four, and the call copies the count it asked for: the
// sampler's array is four entries long, and row has three past its
// fourth entry. Each entry is public, so four is not wiped.
static int expand_row(uint32_t cpu, mld_poly row[MLD_L], const uint8_t rho[MLD_RHO_BYTES],
                      unsigned i) {
#ifdef __x86_64__
    if (cpu & CH_CPU_AVX2) {
        mld_poly four[MLD_AVX2_ENTRIES];
        for (unsigned first = 0; first < MLD_L; first += MLD_AVX2_ENTRIES) {
            unsigned count = MLD_L - first < MLD_AVX2_ENTRIES ? MLD_L - first : MLD_AVX2_ENTRIES;
            if (!mld_sample_ntt_avx2(four, rho, i, first, count)) {
                return 0;
            }
            for (unsigned k = 0; k < count; k++) {
                row[first + k] = four[k];
            }
        }
        return 1;
    }
#endif
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_sample_ntt_cpu(cpu, &row[j], rho, (uint8_t)j, (uint8_t)i)) {
            return 0;
        }
    }
    return 1;
}

uint32_t mlds_expand(mlds_expanded *ex, uint32_t cpu, const uint8_t sk[MLDSA87_SK_LEN]) {
    uint32_t ok = 1;
    for (unsigned j = 0; j < MLD_L; j++) {
        ok &= mlds_unpack_eta(&ex->key.s1_hat[j], sk + MLDS_SK_S1_AT + (size_t)j * MLDS_ETA_BYTES);
        mlds_ntt(cpu, &ex->key.s1_hat[j]);
    }
    for (unsigned i = 0; i < MLD_K; i++) {
        ok &= mlds_unpack_eta(&ex->key.s2_hat[i], sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES);
        mlds_ntt(cpu, &ex->key.s2_hat[i]);
        mlds_unpack(&ex->key.t0_hat[i], sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, 13,
                    1 << (MLD_D - 1));
        mlds_ntt(cpu, &ex->key.t0_hat[i]);
    }
    for (unsigned i = 0; i < MLD_K; i++) {
        ok &= (uint32_t)expand_row(cpu, ex->a_hat[i], sk, i);
    }
    return ok;
}

// mlds_matrix_row's row i of A y into st->w[i], from the entries in st->ex,
// each product in the order mlds_matrix_row_sum takes them.
static void stored_row(mlds_round *st, unsigned i) {
    mld_poly *row = &st->w[i];
    mlds_pointwise(st->cpu, row, &st->ex->a_hat[i][0], &st->yz[0]);
    for (unsigned j = 1; j < MLD_L; j++) {
        mlds_pointwise_acc(st->cpu, row, &st->ex->a_hat[i][j], &st->yz[j]);
    }
    mlds_invntt_freeze(st->cpu, row);
}
#endif // CH_CPU_RUNTIME

// Row i of w = A y into st->w[i], each coefficient in [0, q): from the
// entries of A in st->ex, or from entries sampled into st->s_hat. Returns
// 1, or 0 when an entry stops at its sampling bound.
static int commit_row(mlds_round *st, const uint8_t *sk, unsigned i) {
#ifdef CH_CPU_RUNTIME
    if (st->ex != NULL) {
        stored_row(st, i);
        return 1;
    }
#endif
    return mlds_matrix_row(st->cpu, &st->w[i], &st->s_hat, sk, i, st->yz);
}

// NTT of the polynomial of sk at part, decoded at bits and offset into
// st->s_hat. Returns st->s_hat.
static const mld_poly *decoded_hat(mlds_round *st, const uint8_t *part, unsigned bits,
                                   int32_t offset) {
    mlds_unpack(&st->s_hat, part, bits, offset);
    mlds_ntt(st->cpu, &st->s_hat);
    return &st->s_hat;
}

// NTT(s1[j]): st->ex's copy, or decoded from sk into st->s_hat.
static const mld_poly *s1_hat(mlds_round *st, const uint8_t *sk, unsigned j) {
#ifdef CH_CPU_RUNTIME
    if (st->ex != NULL) {
        return &st->ex->key.s1_hat[j];
    }
#endif
    (void)mlds_unpack_eta(&st->s_hat, sk + MLDS_SK_S1_AT + (size_t)j * MLDS_ETA_BYTES);
    mlds_ntt(st->cpu, &st->s_hat);
    return &st->s_hat;
}

// NTT(s2[i]): st->ex's copy, or decoded from sk into st->s_hat.
static const mld_poly *s2_hat(mlds_round *st, const uint8_t *sk, unsigned i) {
#ifdef CH_CPU_RUNTIME
    if (st->ex != NULL) {
        return &st->ex->key.s2_hat[i];
    }
#endif
    return decoded_hat(st, sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES, 3, MLDS_ETA);
}

// NTT(t0[i]): st->ex's copy, or decoded from sk into st->s_hat.
static const mld_poly *t0_hat(mlds_round *st, const uint8_t *sk, unsigned i) {
#ifdef CH_CPU_RUNTIME
    if (st->ex != NULL) {
        return &st->ex->key.t0_hat[i];
    }
#endif
    return decoded_hat(st, sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, 13, 1 << (MLD_D - 1));
}

uint32_t mlds_key_in_range(mlds_round *st, const uint8_t sk[MLDSA87_SK_LEN]) {
    uint32_t ok = 1;
    for (unsigned r = 0; r < MLD_L + MLD_K; r++) {
        ok &= mlds_unpack_eta(&st->s_hat, sk + MLDS_SK_S1_AT + (size_t)r * MLDS_ETA_BYTES);
    }
    return ok;
}

int mlds_commit(mlds_round *st, const uint8_t *sk, const uint8_t mu[MLDSA_MU_LEN],
                const uint8_t rho2[64], unsigned kappa) {
    for (unsigned j = 0; j < MLD_L; j++) {
        mlds_expand_mask(st->cpu, &st->yz[j], rho2, (uint16_t)(kappa + j));
        mlds_ntt(st->cpu, &st->yz[j]);
    }
    shake h;
    shake256_init(&h);
    mld_absorb(st->cpu, &h, mu, MLDSA_MU_LEN);
    uint8_t w1[MLD_W1_BYTES];
    int32_t r0 = 0; // the low bits, which w1 does not read
    for (unsigned i = 0; i < MLD_K; i++) {
        if (!commit_row(st, sk, i)) {
            return 0;
        }
        for (unsigned n = 0; n < MLD_N; n++) {
            st->product.coeffs[n] = mlds_decompose(st->w[i].coeffs[n], &r0);
        }
        mlds_pack(w1, &st->product, 4, 0);
        mld_absorb(st->cpu, &h, w1, sizeof w1);
    }
    mld_squeeze(st->cpu, &h, st->c_tilde, sizeof st->c_tilde);
    ct_wipe(&h, sizeof h);
    ct_wipe(w1, sizeof w1);
    uint32_t placed = mlds_sample_in_ball(st->cpu, &st->c_hat, st->c_tilde);
    mlds_ntt(st->cpu, &st->c_hat);
    // SampleInBall at its bound, which ends the call (FIPS 204 Appendix C).
    CT_DECLASSIFY(&placed, sizeof placed);
    return placed == 1;
}

uint32_t mlds_response(mlds_round *st, const uint8_t *sk, const uint8_t rho2[64], unsigned kappa) {
    uint32_t reject = 0;
    for (unsigned j = 0; j < MLD_L; j++) {
        mlds_product(st->cpu, &st->product, &st->c_hat, s1_hat(st, sk, j));
        mlds_expand_mask(st->cpu, &st->yz[j], rho2, (uint16_t)(kappa + j));
        for (unsigned n = 0; n < MLD_N; n++) {
            int32_t z = st->yz[j].coeffs[n] + st->product.coeffs[n];
            st->yz[j].coeffs[n] = z;
            reject |= mlds_at_least(z, MLD_GAMMA1 - MLD_BETA);
        }
    }
    return reject;
}

// c times the polynomial whose NTT is hat, into st->product.
static void times_c(mlds_round *st, const mld_poly *hat) {
    mlds_product(st->cpu, &st->product, &st->c_hat, hat);
}

uint32_t mlds_hint_row(mlds_round *st, const uint8_t *sk, unsigned i, uint32_t *count) {
    uint32_t reject = 0;
    int32_t r0 = 0;
    int32_t unused = 0; // the low bits, which a hint does not read
    times_c(st, s2_hat(st, sk, i));
    for (unsigned n = 0; n < MLD_N; n++) {
        int32_t r = mlds_freeze(st->w[i].coeffs[n] - st->product.coeffs[n]);
        st->w[i].coeffs[n] = r;
        (void)mlds_decompose(r, &r0);
        reject |= mlds_at_least(r0, MLD_GAMMA2 - MLD_BETA);
    }
    times_c(st, t0_hat(st, sk, i));
    for (unsigned n = 0; n < MLD_N; n++) {
        int32_t ct0 = st->product.coeffs[n];
        reject |= mlds_at_least(ct0, MLD_GAMMA2);
        int32_t before = mlds_decompose(st->w[i].coeffs[n], &unused);
        int32_t after = mlds_decompose(mlds_freeze(st->w[i].coeffs[n] + ct0), &unused);
        uint32_t hint = (mlds_mask_eq((uint32_t)before, (uint32_t)after) & 1U) ^ 1U;
        st->hints[i][n / 8] |= (uint8_t)(hint << (n % 8));
        *count += hint;
    }
    return reject;
}

void mlds_encode(uint8_t sig[MLDSA87_SIG_LEN], const mlds_round *st) {
    for (unsigned b = 0; b < MLDSA87_CTILDE_LEN; b++) {
        sig[b] = st->c_tilde[b];
    }
    for (unsigned j = 0; j < MLD_L; j++) {
        mlds_pack(sig + MLDS_SIG_Z_AT + (size_t)j * MLD_Z_BYTES, &st->yz[j], 20, MLD_GAMMA1);
    }
    // The round passed with at most omega hints, so every position fits
    // the omega bytes. The write tests the count all the same, so that no
    // hint past omega writes past them, whatever the round's verdict.
    uint8_t y[MLD_HINT_BYTES] = {0};
    unsigned count = 0;
    for (unsigned i = 0; i < MLD_K; i++) {
        for (unsigned n = 0; n < MLD_N; n++) {
            if ((st->hints[i][n / 8] >> (n % 8)) & 1U) {
                if (count < MLD_OMEGA) {
                    y[count] = (uint8_t)n;
                }
                count++;
            }
        }
        y[MLD_OMEGA + i] = (uint8_t)count;
    }
    for (unsigned b = 0; b < MLD_HINT_BYTES; b++) {
        sig[MLDS_SIG_HINT_AT + b] = y[b];
    }
}

uint32_t mlds_keygen_row(mlds_keygen_state *st, uint8_t *sk, uint8_t *pk, unsigned i) {
    uint32_t ok =
        (uint32_t)mlds_matrix_row(st->cpu, &st->row, &st->entry, st->seeds, i, st->s1_hat);
    ok &= mlds_sample_eta(st->cpu, &st->s2, st->seeds + 32, (uint16_t)(MLD_L + i));
    mlds_pack(sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES, &st->s2, 3, MLDS_ETA);
    // t1 takes row's place and t0 takes s2's, each coefficient once read.
    for (unsigned n = 0; n < MLD_N; n++) {
        int32_t t = mlds_freeze(st->row.coeffs[n] + st->s2.coeffs[n]);
        st->row.coeffs[n] = mlds_power2round(t, &st->s2.coeffs[n]);
    }
    mlds_pack(pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES, &st->row, 10, 0);
    mlds_pack(sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, &st->s2, 13, 1 << (MLD_D - 1));
    return ok;
}
