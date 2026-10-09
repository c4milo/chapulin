// rsa_ifma_sign.c as the library compiles it, with a count of the calls
// into it and an entry into its static state_finish
// (test/rsa_ifma_sign_test.h). bin/rsa_ifma_sign_model_test and
// bin/rsa_ifma_sign_equiv_test link this unit in place of rsa_ifma_sign.c.
// The first compiles every unit under CH_RSA_IFMA_MODEL, so the kernel
// runs over test/rsa_ifma_model_lanes.h on any host; the second compiles
// it on the instructions, on x86-64 alone.
//
// The file's two entries compile under second names, and the names
// rsa_sign64.c calls count each call and then run them. So the binaries
// read which signatures ran the kernel, and how many times a signature
// wiped the stack below it.
#define rsa_ifma_sign_power_pair rsa_ifma_sign_kernel_power_pair
#define rsa_ifma_sign_wipe_below rsa_ifma_sign_kernel_wipe_below

#include "rsa_ifma_sign.c"

#undef rsa_ifma_sign_power_pair
#undef rsa_ifma_sign_wipe_below

#include "rsa_ifma_sign_test.h"

unsigned long rsa_ifma_sign_pair_calls;
unsigned long rsa_ifma_sign_wipe_calls;

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

void rsa_ifma_sign_power_pair(uint64_t *o_p, const uint64_t *base_p, const uint8_t *e_p,
                              const rsa_mont64_modulus *mod_p, uint64_t *o_q,
                              const uint64_t *base_q, const uint8_t *e_q,
                              const rsa_mont64_modulus *mod_q, size_t e_len) {
    rsa_ifma_sign_pair_calls++;
    rsa_ifma_sign_kernel_power_pair(o_p, base_p, e_p, mod_p, o_q, base_q, e_q, mod_q, e_len);
}

void rsa_ifma_sign_wipe_below(void) {
    rsa_ifma_sign_wipe_calls++;
    rsa_ifma_sign_kernel_wipe_below();
}

// Under the instructions the entry turns AVX-512F and AVX-512 IFMA on for
// itself, as rsa_ifma_sign.c's functions do, so that it can inline
// state_finish.
#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif
#endif

void rsa_ifma_sign_test_finish(uint64_t *o, const uint64_t *digits, const rsa_mont64_modulus *mod) {
    static sign_state state;
    memset(&state, 0, sizeof state);
    state.modulus.digit_count = RSA_IFMA_DIGIT_COUNT(mod->words);
    memcpy(state.power, digits, state.modulus.digit_count * sizeof(uint64_t));
    state_finish(o, &state, mod);
}

#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)
