// Proves: rsa_mont64_modulus_init, whole, over any modulus bytes at the
// largest length the build admits (384 bytes; 512 in the
// rsa_mont64_init_webpki variant, which sets CH_TRUST_WEBPKI) and the bit
// length that length has with its top bit set, reads and writes inside
// its arrays: the byte marshalling, neg_inverse, the power of two it
// starts from, its 2 * limbs + 1 doublings and its five multiplications.
// That is the call a modulus of a real key makes, and the largest length
// is the binding case for every index.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply.
//
// This line runs without --unsigned-overflow-check, because neg_inverse
// computes modulo 2^64 and wraps on purpose. The other sums the call runs
// are rsa_mont64_ops_harness.c's and rsa_mont64_sums_harness.c's, with
// that check on.
//
// What it does not drive: a bit length below the top bit. The loop then
// runs up to 64 * limbs more doublings, 3,072 at this bound, past what
// one formula holds. Each of them is double_mod, which
// rsa_mont64_ops_harness.c proves for any limbs, and the first limb the
// call writes is power_of_two's, which that harness proves for every bit
// the call's CH_ASSERT admits. bin/rsa_equiv_test runs moduli of every
// bit length from 2 up through rsa_vp1.
//
// What it does not prove: that the limbs it writes are R^2 mod m and
// -m^-1 mod 2^64. bin/rsa_equiv_test and the published vectors hold
// those, through every answer that depends on them.
#include "rsa_mont64_stubs.h"

int main(void) {
    uint8_t m[CH_RSA_MODULUS_MAX];
    rsa_mont64_modulus mod;
    fill_nondet(m, sizeof m);
    rsa_mont64_modulus_init(&mod, m, sizeof m, 8 * sizeof m);
    __CPROVER_assert(mod.limbs == RSA_MONT64_LIMBS_MAX,
                     "the largest modulus takes the largest limb count");
    return 0;
}
