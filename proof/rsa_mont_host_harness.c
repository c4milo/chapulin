// Proves: rsa_vp1 as a host object compiles it (rsa_mont.c under
// -DCH_CPU_RUNTIME), whole, over any odd modulus bytes and any signature
// bytes at the largest length the build admits (384 bytes; 512 in the
// rsa_mont_host_webpki variant, which sets CH_TRUST_WEBPKI), reads and
// writes inside its arrays and divides by no zero. A modulus whose top
// bit is set takes the division that computes R^2: rsa_mont64_modulus_load,
// the complement of the modulus, and its k steps, each with its quotient
// estimate, its subtraction and its passes that add the modulus back. Any
// other modulus takes rsa_mont64_modulus_init, under every bit length the
// bytes give it.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply. The two
// entries below whose own harnesses prove them, rsa_mont64_modulus_init
// (rsa_mont64_init_harness.c) and rsa_mont64_public
// (rsa_mont64_public_harness.c), are contracts that assert what the real
// entry's CH_ASSERT needs and write where it writes. The modulus is odd
// because rsa.h admits no other: both verifiers refuse an even one or a
// zero one before they call rsa_vp1.
//
// This line runs without --unsigned-overflow-check: the limb above the
// k in a step of the division wraps to zero on purpose when a pass adds
// the modulus back.
//
// What it does not prove: that the limbs the division writes are R^2 mod
// m. bin/rsa_equiv_test holds that against rsa_mont.c's 32-bit arithmetic
// over random moduli, the modulus whose division takes the largest
// estimate, and moduli of every bit length near a limb boundary.
#include "rsa_mont64_stubs.h"

static void stub_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len,
                              size_t bits) {
    __CPROVER_assert(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && bits >= 1 && bits <= 8 * m_len,
                     "rsa_mont64_modulus_init: the lengths its CH_ASSERT admits");
    __CPROVER_assert(__CPROVER_r_ok(m, m_len), "rsa_mont64_modulus_init: the modulus is readable");
    havoc_modulus(mod, (m_len + 7) >> 3);
}

static void stub_public(uint8_t *out, const uint8_t *base, size_t len,
                        const rsa_mont64_modulus *mod) {
    __CPROVER_assert(mod->limbs >= 1 && mod->limbs <= RSA_MONT64_LIMBS_MAX,
                     "rsa_mont64_public: the limb count is inside the arrays");
    __CPROVER_assert(len <= 8 * mod->limbs, "rsa_mont64_public: the length its CH_ASSERT admits");
    __CPROVER_assert(__CPROVER_r_ok(base, len), "rsa_mont64_public: the base is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, len), "rsa_mont64_public: the output is writable");
    fill_nondet(out, len);
}

#define rsa_mont64_modulus_init stub_modulus_init
#define rsa_mont64_public stub_public
#include "rsa_mont.c"

int main(void) {
    uint8_t n[CH_RSA_MODULUS_MAX];
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t em[CH_RSA_MODULUS_MAX];
    fill_nondet(n, sizeof n);
    fill_nondet(sig, sizeof sig);
    __CPROVER_assume((n[sizeof n - 1] & 1) == 1);
    rsa_vp1(n, sizeof n, sig, em);
    return 0;
}
