// mldsa_vector.h's four entries as counts over mldsa_poly.c's loops
// (test/mldsa_vector_count.h). bin/mldsa_runtime_test links this file in
// place of mldsa_vector.c.
#include "mldsa_vector_count.h"

#include "mldsa_vector.h"

mldsa_vector_calls mldsa_vector_counted;

#if MLD_VECTOR

void mld_vector_ntt(mld_poly *p) {
    mldsa_vector_counted.ntt++;
    mld_poly_ntt(p);
}

void mld_vector_invntt_tomont(mld_poly *p) {
    mldsa_vector_counted.invntt++;
    mld_poly_invntt_tomont(p);
}

void mld_vector_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    mldsa_vector_counted.pointwise++;
    mld_poly_pointwise(r, a, b);
}

void mld_vector_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    mldsa_vector_counted.pointwise_acc++;
    mld_poly_pointwise_acc(acc, a, b);
}

#endif
