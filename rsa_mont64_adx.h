// RSA's Montgomery multiplication and square on MULX, ADCX and ADOX, for an
// x86-64 host object (docs/decisions.md 183). rsa_sign64.c runs them in
// place of rsa_mont64.c's for the two exponentiations of a signature, in a
// session whose ch_cfg.cpu holds CH_CPU_BMI2_ADX beside
// CH_CPU_CONSTANT_TIME_MULTIPLY and not the IFMA path's bits. Each writes
// the words rsa_mont64_mont_mul and rsa_mont64_mont_square write, which
// bin/rsa_mont64_adx_equiv_test holds word for word.
//
// The method is separated operand scanning: the product, or the square from
// its cross products, into 2k words, then k reduction rows, each of which
// adds the multiple of m that clears the lowest word left, then one
// subtraction of m chosen by the borrow. rsa_mont64_adx_asm.h holds the five
// operations in assembly, and test/rsa_mont64_adx_model.h the same words in
// portable C, which the proofs and the model test build in their place
// under CH_RSA_MONT64_ADX_MODEL.
//
// Constant time: every loop counts the modulus's public words, no branch and
// no address depends on a word of a, b or the product, and the subtraction
// is chosen by CMOVC, which loads both words. The 2k-word product lives in
// each call's own frame, which lies under rsa_sign64.c's wrappers, and their
// rsa_sign64_wipe_below clears it with the frame (docs/decisions.md 181).
// What no wipe clears: the general registers, which hold the last words
// until another instruction writes them.
#ifndef CH_RSA_MONT64_ADX_H
#define CH_RSA_MONT64_ADX_H

#include <stdint.h>

#include "rsa_mont64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_MONT64_ADX_MODEL))

// o = a * b * R^-1 mod m, R = 2^(64k), for a and b below m and mod->words
// from 2 to RSA_MONT64_WORDS_MAX. o may be a or b.
void rsa_mont64_adx_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                        const rsa_mont64_modulus *mod);

// o = a * a * R^-1 mod m under the same terms. o may be a.
void rsa_mont64_adx_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

#endif

#ifdef CH_CPU_RUNTIME
// The multiplication and square rsa_sign64.c's window runs: this file's under
// adx, in a build that holds them, and rsa_mont64.c's otherwise. adx comes
// from the session's ch_cfg.cpu, which the caller states, so the branch reads
// no secret.
static inline void rsa_mont64_window_mul(int adx, uint64_t *o, const uint64_t *a, const uint64_t *b,
                                         const rsa_mont64_modulus *mod) {
#if defined(__x86_64__) || defined(CH_RSA_MONT64_ADX_MODEL)
    if (adx) {
        rsa_mont64_adx_mul(o, a, b, mod);
        return;
    }
#else
    (void)adx;
#endif
    rsa_mont64_mont_mul(o, a, b, mod);
}

static inline void rsa_mont64_window_square(int adx, uint64_t *o, const uint64_t *a,
                                            const rsa_mont64_modulus *mod) {
#if defined(__x86_64__) || defined(CH_RSA_MONT64_ADX_MODEL)
    if (adx) {
        rsa_mont64_adx_square(o, a, mod);
        return;
    }
#else
    (void)adx;
#endif
    rsa_mont64_mont_square(o, a, mod);
}
#endif

#endif
