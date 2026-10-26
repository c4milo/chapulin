// The steps of one round of ML-DSA-87's rejection loop (FIPS 204
// Algorithm 7), and a row of key generation (Algorithm 6). Contract in
// mldsa_sign_steps.h.
//
// Neither s1, s2 nor t0 is held whole in the NTT domain. Each step that
// needs one polynomial of them decodes it from sk and transforms it, so a
// round holds NTT(y) or z, w, NTT(c) and two polynomials of work: 18 of
// them, 18 kB (docs/decisions.md 159). Each entry of A is sampled from rho
// just before its product, as the verifier samples it (mldsa.c).
#include "mldsa_sign_steps.h"

#include "ct.h"
#include "mldsa_sign_poly.h"
#include "sha3.h"

int mlds_matrix_row(mld_poly *row, mld_poly *entry, const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                    const mld_poly v_hat[MLD_L]) {
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_sample_ntt(entry, rho, (uint8_t)j, (uint8_t)i)) {
            // Defined values for the caller. Its ct_wipe of its state
            // writes zero to row afterwards as well.
            for (unsigned n = 0; n < MLD_N; n++) {
                row->coeffs[n] = 0;
            }
            return 0;
        }
        if (j == 0) {
            mlds_poly_pointwise(row, entry, &v_hat[0]);
        } else {
            mlds_poly_pointwise_acc(row, entry, &v_hat[j]);
        }
    }
    mlds_poly_invntt_freeze(row);
    return 1;
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
        mlds_expand_mask(&st->yz[j], rho2, (uint16_t)(kappa + j));
        mlds_poly_ntt(&st->yz[j]);
    }
    shake h;
    shake256_init(&h);
    shake_absorb(&h, mu, MLDSA_MU_LEN);
    uint8_t w1[MLD_W1_BYTES];
    int32_t r0 = 0; // the low bits, which w1 does not read
    for (unsigned i = 0; i < MLD_K; i++) {
        if (!mlds_matrix_row(&st->w[i], &st->s_hat, sk, i, st->yz)) {
            return 0;
        }
        for (unsigned n = 0; n < MLD_N; n++) {
            st->product.coeffs[n] = mlds_decompose(st->w[i].coeffs[n], &r0);
        }
        mlds_pack(w1, &st->product, 4, 0);
        shake_absorb(&h, w1, sizeof w1);
    }
    shake_squeeze(&h, st->c_tilde, sizeof st->c_tilde);
    ct_wipe(&h, sizeof h);
    ct_wipe(w1, sizeof w1);
    uint32_t placed = mlds_sample_in_ball(&st->c_hat, st->c_tilde);
    mlds_poly_ntt(&st->c_hat);
    // SampleInBall at its bound, which ends the call (FIPS 204 Appendix C).
    CT_DECLASSIFY(&placed, sizeof placed);
    return placed == 1;
}

uint32_t mlds_response(mlds_round *st, const uint8_t *sk, const uint8_t rho2[64], unsigned kappa) {
    uint32_t reject = 0;
    for (unsigned j = 0; j < MLD_L; j++) {
        (void)mlds_unpack_eta(&st->s_hat, sk + MLDS_SK_S1_AT + (size_t)j * MLDS_ETA_BYTES);
        mlds_poly_ntt(&st->s_hat);
        mlds_poly_product(&st->product, &st->c_hat, &st->s_hat);
        mlds_expand_mask(&st->yz[j], rho2, (uint16_t)(kappa + j));
        for (unsigned n = 0; n < MLD_N; n++) {
            int32_t z = st->yz[j].coeffs[n] + st->product.coeffs[n];
            st->yz[j].coeffs[n] = z;
            reject |= mlds_at_least(z, MLD_GAMMA1 - MLD_BETA);
        }
    }
    return reject;
}

// c times polynomial r of the part of sk at offset, into st->product.
static void times_c(mlds_round *st, const uint8_t *part, unsigned bits, int32_t offset) {
    mlds_unpack(&st->s_hat, part, bits, offset);
    mlds_poly_ntt(&st->s_hat);
    mlds_poly_product(&st->product, &st->c_hat, &st->s_hat);
}

uint32_t mlds_hint_row(mlds_round *st, const uint8_t *sk, unsigned i, uint32_t *count) {
    uint32_t reject = 0;
    int32_t r0 = 0;
    int32_t unused = 0; // the low bits, which a hint does not read
    times_c(st, sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES, 3, MLDS_ETA);
    for (unsigned n = 0; n < MLD_N; n++) {
        int32_t r = mlds_freeze(st->w[i].coeffs[n] - st->product.coeffs[n]);
        st->w[i].coeffs[n] = r;
        (void)mlds_decompose(r, &r0);
        reject |= mlds_at_least(r0, MLD_GAMMA2 - MLD_BETA);
    }
    times_c(st, sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, 13, 1 << (MLD_D - 1));
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
    uint32_t ok = (uint32_t)mlds_matrix_row(&st->row, &st->entry, st->seeds, i, st->s1_hat);
    ok &= mlds_sample_eta(&st->s2, st->seeds + 32, (uint16_t)(MLD_L + i));
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
