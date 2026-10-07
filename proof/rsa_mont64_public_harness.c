// Proves: rsa_mont64_public, whole, over any base bytes, any modulus
// words and any m0inv at the largest length the build admits (384 bytes;
// 512 in the rsa_mont64_public_webpki variant, which sets
// CH_TRUST_WEBPKI), reads and writes inside its arrays: the byte
// marshalling both ways, its eighteen multiplications in the three
// aliasing shapes it calls them in, and its two wipes.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply. The base
// is unconstrained, so the proof covers a base at or above the modulus,
// which rsa_mont64.h says the call takes.
//
// This line runs without --unsigned-overflow-check: the call's own
// statements add nothing, and the sums of the multiplications it makes
// are rsa_mont64_sums_harness.c's.
//
// What it does not prove: that the bytes it writes are base^65537 mod m.
// bin/rsa_equiv_test holds that against rsa_mont.c's 32-bit arithmetic,
// and the published vectors hold it against openssl.
#include "rsa_mont64_stubs.h"

int main(void) {
    uint8_t base[CH_RSA_MODULUS_MAX];
    uint8_t out[CH_RSA_MODULUS_MAX];
    rsa_mont64_modulus mod;
    havoc_modulus(&mod, RSA_MONT64_WORDS_MAX);
    fill_nondet(base, sizeof base);
    rsa_mont64_public(out, base, sizeof base, &mod);
    return 0;
}
