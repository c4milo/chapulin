// Test code only: what bin/rsa_ifma_sign_model_test and
// bin/rsa_ifma_sign_equiv_test read of rsa_ifma_sign.c beside its two
// entries. test/rsa_ifma_sign_entries.c compiles that file in place of the
// library's unit and defines these, over the lane model under
// CH_RSA_IFMA_MODEL and on the instructions otherwise.
#ifndef CH_TEST_RSA_IFMA_SIGN_TEST_H
#define CH_TEST_RSA_IFMA_SIGN_TEST_H

#include <stdint.h>

#include "rsa_mont64.h"

// The counts of rsa_ifma_sign_power_pair's and rsa_ifma_sign_wipe_below's
// calls, rsa_ifma_sign_pair_calls and rsa_ifma_sign_wipe_calls, under the
// names test/rsa_ifma_sign_count.c gives them. These binaries define no
// count of avx512_wipe_registers's calls: over the model rsa_sign64.c
// makes none, and on the instructions the binary links avx512_wipe.c.
#include "rsa_ifma_sign_count.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))
// o = the number in digits, RSA_IFMA_DIGIT_COUNT(mod->words) digits each
// below 2^52, as state_finish writes it from a power: mod->words words
// and the word above them, and one subtraction of mod's modulus under a
// mask. The number must be below twice the modulus.
void rsa_ifma_sign_test_finish(uint64_t *o, const uint64_t *digits, const rsa_mont64_modulus *mod);
#endif

#endif
