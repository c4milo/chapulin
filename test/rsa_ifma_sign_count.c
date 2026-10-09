// rsa_ifma_sign.c's two entries and avx512_wipe.c's one as counts, for
// the binaries that link this file in place of the two
// (test/rsa_ifma_sign_count.h). rsa_ifma_sign_power_pair runs
// rsa_sign64_power once for each prime, which writes the words the kernel
// writes under the same contract, and the two wipes count and do nothing
// else. So rsa_sign64.c runs unchanged, no AVX-512 instruction runs, and a
// binary reads which signatures the library sent to the kernel, and that
// each such signature wiped the stack and the registers after each kernel
// call, on any x86-64 CPU. The entries compile under the condition their
// headers declare them under, so on arm64 this file holds the counts
// alone.
#include "rsa_ifma_sign_count.h"

#include "avx512_wipe.h"
#include "rsa_ifma_sign.h"
#include "rsa_sign64.h"

unsigned long rsa_ifma_sign_pair_calls;
unsigned long rsa_ifma_sign_wipe_calls;
unsigned long avx512_wipe_calls;

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

void rsa_ifma_sign_power_pair(uint64_t *o_p, const uint64_t *base_p, const uint8_t *e_p,
                              const rsa_mont64_modulus *mod_p, uint64_t *o_q,
                              const uint64_t *base_q, const uint8_t *e_q,
                              const rsa_mont64_modulus *mod_q, size_t e_len) {
    rsa_ifma_sign_pair_calls++;
    rsa_sign64_power(o_p, base_p, e_p, e_len, mod_p);
    rsa_sign64_power(o_q, base_q, e_q, e_len, mod_q);
}

void rsa_ifma_sign_wipe_below(void) {
    rsa_ifma_sign_wipe_calls++;
}

void avx512_wipe_registers(void) {
    avx512_wipe_calls++;
}

#endif // CH_CPU_RUNTIME && __x86_64__
