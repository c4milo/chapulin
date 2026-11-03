// RSA's Montgomery multiplication and square on MULX, ADCX and ADOX
// (rsa_mont64_adx.h, docs/decisions.md 183). The five operations are
// rsa_mont64_adx_asm.h's, or test/rsa_mont64_adx_model.h's in the model
// build, and this file calls them in order.
#include "rsa_mont64_adx.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_MONT64_ADX_MODEL))

#include <stddef.h>

#include "ch_assert.h"
#include "ct.h"

#ifdef CH_RSA_MONT64_ADX_MODEL
#include "rsa_mont64_adx_model.h"
#else
#include "rsa_mont64_adx_asm.h"
#endif

// The reduction and the subtraction both operations end with: t is the 2k
// words of a product below m * R, and o takes t * R^-1 mod m. Row i adds
// u * m at word i, with u = t[i] * m0inv mod 2^64, which clears t[i]; its
// carry out goes into the top of the next row. After k rows t[k..2k-1] and
// the last carry hold t * R^-1 + a multiple of m, below 2m, and one
// subtraction of m leaves it below m.
static void reduce(uint64_t *o, uint64_t *t, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        // u is the low word of t[i] * m0inv: ct_mul128's, so no product
        // wraps.
        uint64_t u = (uint64_t)ct_mul128(t[i], mod->m0inv);
        carry = adx_row_carry(&t[i], u, mod->m, k, carry);
    }
    adx_final_sub(o, &t[k], carry, mod->m, k);
}

void rsa_mont64_adx_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                        const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    CH_ASSERT(k >= 2 && k <= RSA_MONT64_WORDS_MAX);
    uint64_t t[2 * RSA_MONT64_WORDS_MAX];
    // Row 0 writes t[0..k]. Row i adds a[i] * b at word i and writes its top
    // word t[i + k], which no row before it wrote, so t needs no zeros first.
    adx_row_first(t, a[0], b, k);
    for (size_t i = 1; i < k; i++) {
        adx_row_store_top(&t[i], a[i], b, k);
    }
    reduce(o, t, mod);
}

void rsa_mont64_adx_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    CH_ASSERT(k >= 2 && k <= RSA_MONT64_WORDS_MAX);
    uint64_t t[2 * RSA_MONT64_WORDS_MAX];
    // The cross products a[i] * a[j] with i < j, each once: row i adds
    // a[i] * a[i + 1..k - 1] at word 2i + 1 and writes its top word t[i + k],
    // which no row before it wrote. Word 0 and word 2k - 1 hold no cross
    // product. Doubling them and adding each a[i]^2 at word 2i gives the
    // square.
    t[0] = 0;
    adx_row_first(&t[1], a[0], &a[1], k - 1);
    for (size_t i = 1; i + 1 < k; i++) {
        adx_row_store_top(&t[2 * i + 1], a[i], &a[i + 1], k - 1 - i);
    }
    t[2 * k - 1] = 0;
    adx_double_add_diagonal(t, a, k);
    reduce(o, t, mod);
}

#endif
