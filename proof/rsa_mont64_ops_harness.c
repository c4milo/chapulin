// Proves: every piece of rsa_mont64.c that multiplies nothing reads and
// writes inside its arrays and wraps no unsigned value, at the largest
// limb count the build admits (48 for the device bound of RSA-3072; 64
// for RSA-4096 in the rsa_mont64_ops_webpki variant, which sets
// CH_TRUST_WEBPKI). The wrap check is --unsigned-overflow-check on the
// launch line, so every limb of a subtraction written as a complement
// and a carry is a property.
//
// Marshalling. rsa_mont64_from_bytes and rsa_mont64_to_bytes over any
// byte length from 1 to CH_RSA_MODULUS_MAX and the limb count that
// length takes, (len + 7) / 8, which is the count
// rsa_mont64_modulus_init gives them. A length that is no multiple of 8
// is in that range: half of a 376-byte modulus is 188 bytes.
//
// The mask. mask_of_bit returns all ones or all zeros and nothing else,
// because every select in the file is an AND against it.
//
// The comparison and the subtraction. at_or_above answers one bit for
// any limbs and any top limb. sub_masked, reduce_once and double_mod run
// over any limbs, reduce_once both with its output apart from its input,
// as rsa_mont64_mont_mul calls it, and on it, as double_mod does.
//
// The power of two. power_of_two writes inside its k limbs for every k
// from 1 to the largest count and every bit below 64 * k, which is the
// range rsa_mont64_modulus_init's CH_ASSERT gives it: bits - 1 is below
// 8 * m_len, and 8 * m_len is at most 64 * k.
//
// The sum, the difference and the reduction. rsa_mont64_add and
// rsa_mont64_sub run over any operands and any modulus, with the output
// apart from both operands, on the first and on the second, and
// rsa_mont64_reduce_once with its output apart from its input and on it.
// The difference's second loop adds the modulus back under a mask and
// drops a carry out of the top limb, which is a cast and not a wrap.
//
// What this does not drive: rsa_mont64_mont_mul and rsa_mont64_mul_add,
// which rsa_mont64_mul_harness.c and rsa_mont64_sums_harness.c prove;
// rsa_mont64_modulus_init and rsa_mont64_public whole, which
// rsa_mont64_init_harness.c and rsa_mont64_public_harness.c prove; and
// neg_inverse, whose arithmetic wraps on purpose.
#include "harness.h"

uint64_t nondet_u64(void);

#include "rsa_mont64.c"

static void havoc_limbs(uint64_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        a[i] = nondet_u64();
    }
}

static void prove_marshalling(void) {
    uint8_t b[CH_RSA_MODULUS_MAX];
    uint64_t limbs[RSA_MONT64_LIMBS_MAX];
    size_t len = nondet_size_t();
    __CPROVER_assume(len >= 1 && len <= CH_RSA_MODULUS_MAX);
    size_t count = (len + 7) >> 3;
    fill_nondet(b, sizeof b);
    rsa_mont64_from_bytes(limbs, count, b, len);
    havoc_limbs(limbs, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_to_bytes(b, len, limbs);
}

static void prove_mask(void) {
    uint64_t bit = nondet_u64() & 1;
    uint64_t mask = mask_of_bit(bit);
    __CPROVER_assert(mask == 0 || mask == UINT64_MAX, "mask_of_bit is all ones or all zeros");
    __CPROVER_assert((bit == 1) == (mask == UINT64_MAX), "mask_of_bit follows its bit");
}

static void prove_limb_helpers(void) {
    uint64_t a[RSA_MONT64_LIMBS_MAX];
    uint64_t m[RSA_MONT64_LIMBS_MAX];
    uint64_t o[RSA_MONT64_LIMBS_MAX];

    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(m, RSA_MONT64_LIMBS_MAX);
    uint64_t above = at_or_above(a, nondet_u64(), m, RSA_MONT64_LIMBS_MAX);
    __CPROVER_assert(above <= 1, "at_or_above answers one bit");

    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(m, RSA_MONT64_LIMBS_MAX);
    sub_masked(o, a, m, RSA_MONT64_LIMBS_MAX, mask_of_bit(nondet_u64() & 1));

    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(m, RSA_MONT64_LIMBS_MAX);
    reduce_once(o, a, nondet_u64(), m, RSA_MONT64_LIMBS_MAX);

    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(m, RSA_MONT64_LIMBS_MAX);
    reduce_once(a, a, nondet_u64(), m, RSA_MONT64_LIMBS_MAX);

    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(m, RSA_MONT64_LIMBS_MAX);
    double_mod(a, m, RSA_MONT64_LIMBS_MAX);
}

static void prove_power_of_two(void) {
    uint64_t x[RSA_MONT64_LIMBS_MAX];
    size_t k = nondet_size_t();
    size_t bit = nondet_size_t();
    __CPROVER_assume(k >= 1 && k <= RSA_MONT64_LIMBS_MAX && bit < 64 * k);
    power_of_two(x, k, bit);
}

// A modulus record of the largest limb count, every limb unconstrained.
static void havoc_record(rsa_mont64_modulus *mod) {
    havoc_limbs(mod->m, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(mod->r2, RSA_MONT64_LIMBS_MAX);
    mod->m0inv = nondet_u64();
    mod->limbs = RSA_MONT64_LIMBS_MAX;
}

static void prove_modular(void) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_LIMBS_MAX];
    uint64_t b[RSA_MONT64_LIMBS_MAX];
    uint64_t o[RSA_MONT64_LIMBS_MAX];

    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_add(o, a, b, &mod);
    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_add(a, a, b, &mod);
    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_add(b, a, b, &mod);

    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_sub(o, a, b, &mod);
    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_sub(a, a, b, &mod);
    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    havoc_limbs(b, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_sub(b, a, b, &mod);

    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_reduce_once(o, a, &mod);
    havoc_record(&mod);
    havoc_limbs(a, RSA_MONT64_LIMBS_MAX);
    rsa_mont64_reduce_once(a, a, &mod);
}

int main(void) {
    prove_marshalling();
    prove_mask();
    prove_limb_helpers();
    prove_power_of_two();
    prove_modular();
    return 0;
}
