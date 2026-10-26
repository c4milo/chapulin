// The constant-time ring arithmetic of ML-DSA-87 signing. Contract in
// mldsa_sign_poly.h. The transforms are mldsa_poly.c's, layer for layer and
// twiddle for twiddle, with each product on mlds_mul_zeta: the same values
// and the same bounds, so mldsa_poly.c's comments hold here. Each loop's
// count is a constant, and no coefficient decides a branch or an index.
#include "mldsa_sign_poly.h"

#include "mldsa_zetas.h"

static void mlds_poly_reduce(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = mlds_reduce32(p->coeffs[i]);
    }
}

void mlds_poly_ntt(mld_poly *p) {
    int32_t *w = p->coeffs;
    mlds_poly_reduce(p);
    unsigned m = 0;
    for (unsigned len = 128; len >= 1; len >>= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m++;
            int32_t zeta = MLD_ZETAS[m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = mlds_mul_zeta(zeta, w[j + len]);
                w[j + len] = w[j] - t;
                w[j] = w[j] + t;
            }
        }
    }
}

void mlds_poly_invntt_tomont(mld_poly *p) {
    int32_t *w = p->coeffs;
    mlds_poly_reduce(p);
    unsigned m = MLD_N;
    for (unsigned len = 1; len < MLD_N; len <<= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m--;
            int32_t zeta = -MLD_ZETAS[m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = w[j];
                w[j] = t + w[j + len];
                w[j + len] = mlds_mul_zeta(zeta, t - w[j + len]);
            }
        }
    }
    for (unsigned j = 0; j < MLD_N; j++) {
        w[j] = mlds_mul_zeta(41978, w[j]);
    }
}

void mlds_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        r->coeffs[i] = mlds_mul_reduced(a->coeffs[i], b->coeffs[i]);
    }
}

void mlds_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        int32_t product = mlds_mul_reduced(a->coeffs[i], b->coeffs[i]);
        acc->coeffs[i] = mlds_reduce32(acc->coeffs[i]) + product;
    }
}

void mlds_poly_product(mld_poly *r, const mld_poly *a_hat, const mld_poly *b_hat) {
    mlds_poly_pointwise(r, a_hat, b_hat);
    mlds_poly_invntt_tomont(r);
    for (unsigned i = 0; i < MLD_N; i++) {
        r->coeffs[i] = mlds_center(r->coeffs[i]);
    }
}

void mlds_poly_invntt_freeze(mld_poly *p) {
    mlds_poly_invntt_tomont(p);
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = mlds_freeze(p->coeffs[i]);
    }
}
