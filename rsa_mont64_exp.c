// RSA's public operation with the key's own exponent, for the DNSSEC
// verification calls: a DNSKEY names its exponent (RFC 3110 section 2),
// where TLS fixes 65537. It runs on rsa_mont64.c's Montgomery
// arithmetic, and rsa_mont64.h states its contract. Every host object
// packages the file, and only one built with -DCH_DNSSEC compiles the
// call; in the others the header below, which declares the host object's
// RSA arithmetic, keeps the unit from being empty.
#include "rsa_mont64.h"

#if defined(CH_CPU_RUNTIME) && defined(CH_DNSSEC)

#include <string.h>

#include "ch_assert.h"
#include "ct.h"

// The bit length of e, which is at least 2 here because e >= 3.
static unsigned bit_length(uint64_t e) {
    unsigned n = 0;
    while (e != 0) {
        n++;
        e >>= 1;
    }
    return n;
}

void rsa_mont64_public_exp(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, uint64_t e) {
    size_t k = mod->words;
    CH_ASSERT(len <= 8 * k && e >= 3 && (e & 1) == 1);
    uint64_t x[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t xr[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t acc[RSA_MONT64_WORDS_MAX] = {0};
    rsa_mont64_from_bytes(x, k, base, len);

    // Left to right over e's bits, the way rsa_mont64_public runs 65537:
    // acc starts at base * R for the top bit, and each lower bit squares
    // it and, where the bit is set, multiplies by base * R. Bit 0 is set,
    // because e is odd, so its square is followed by a product by base
    // itself, outside the domain, which divides by R and leaves base^e.
    rsa_mont64_mont_mul(xr, x, mod->r2, mod);
    memcpy(acc, xr, sizeof acc);
    for (unsigned i = bit_length(e) - 1; i-- > 1;) {
        rsa_mont64_mont_square(acc, acc, mod);
        if (((e >> i) & 1) != 0) {
            rsa_mont64_mont_mul(acc, acc, xr, mod);
        }
    }
    rsa_mont64_mont_square(acc, acc, mod);
    rsa_mont64_mont_mul(acc, x, acc, mod);
    rsa_mont64_to_bytes(out, len, acc);
    ct_wipe(x, sizeof x);
    ct_wipe(xr, sizeof xr);
    ct_wipe(acc, sizeof acc);
}

#endif // CH_CPU_RUNTIME && CH_DNSSEC
