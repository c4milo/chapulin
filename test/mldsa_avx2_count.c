// mldsa_avx2.h's entry as a count over mld_sample_ntt
// (test/mldsa_avx2_count.h). bin/mldsa_runtime_test links this file in
// place of mldsa_avx2.c and keccak_avx2.c. Its SHAKE calls count apart
// (test/mldsa_sha3_count.h): the library makes none for A on this path.
#include "mldsa_avx2_count.h"

#include "mldsa_avx2.h"
#include "mldsa_sha3_count.h"

mldsa_avx2_calls mldsa_avx2_counted;

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

int mld_sample_ntt_avx2(mld_poly e[MLD_AVX2_ENTRIES], const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                        unsigned first, unsigned count) {
    mldsa_avx2_counted.calls++;
    int sampled = 1;
    mldsa_sha3_counting_apart = 1;
    for (unsigned k = 0; k < count; k++) {
        mldsa_avx2_counted.entries++;
        sampled &= mld_sample_ntt(&e[k], rho, (uint8_t)(first + k), (uint8_t)i);
    }
    mldsa_sha3_counting_apart = 0;
    return sampled;
}

#endif
