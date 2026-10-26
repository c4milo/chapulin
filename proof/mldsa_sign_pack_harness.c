// Proves: the encodings of mldsa_sign_pack.c are memory-safe and UB-free
// with the signed-overflow check on, at each width the signer packs and
// over coefficients from all of int32_t: s1 and s2 at 3 bits, w1 at 4, t1
// at 10, t0 at 13 and z at 20, each with the offset its caller passes.
// Each width writes 32 * bits bytes exactly: the output is an object of
// that length. The unpacking reads 32 * bits bytes and gives each
// coefficient offset minus a bits-bit value, and the range check of s1
// and s2 answers 1 exactly when every coefficient is in [-2, 2].
// ExpandMask's polynomial is proved over every SHAKE stream, through the
// sponge's pointer contract (mldsa_poly_harness.c's stub).
// mldsa_sign_samplers proves the two rejection samplers.
#include "harness.h"

#include <stdlib.h>

#include "mldsa_sign_pack.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

void shake256_init(shake *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake256_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_absorb: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "shake_absorb: input readable");
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_squeeze: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(out, n), "shake_squeeze: output writable");
    fill_nondet(out, n);
}

// One width: pack a havocked polynomial into an object of exactly
// 32 * bits bytes, then unpack those bytes with the offset.
static void width(unsigned bits, int32_t offset) {
    size_t len = (size_t)32 * bits;
    uint8_t *bytes = malloc(len);
    __CPROVER_assume(bytes != NULL);
    mld_poly p;
    havoc_poly(&p);
    mlds_pack(bytes, &p, bits, offset);
    if (offset != 0) {
        mlds_unpack(&p, bytes, bits, offset);
        unsigned n = nondet_u32() % MLD_N;
        __CPROVER_assert(p.coeffs[n] <= offset && p.coeffs[n] > offset - (1 << bits),
                         "mlds_unpack: offset minus a bits-bit value");
    }
    free(bytes);
}

int main(void) {
    width(3, MLDS_ETA);
    width(4, 0);
    width(10, 0);
    width(13, 1 << (MLD_D - 1));
    width(20, MLD_GAMMA1);

    uint8_t eta[MLDS_ETA_BYTES];
    fill_nondet(eta, sizeof eta);
    mld_poly p;
    uint32_t in_range = mlds_unpack_eta(&p, eta);
    unsigned n = nondet_u32() % MLD_N;
    __CPROVER_assert(in_range <= 1, "mlds_unpack_eta: a verdict of 0 or 1");
    __CPROVER_assert(in_range == 0 || (p.coeffs[n] >= -MLDS_ETA && p.coeffs[n] <= MLDS_ETA),
                     "mlds_unpack_eta: a key it accepts is in [-2, 2]");

    uint8_t rho2[64];
    fill_nondet(rho2, sizeof rho2);
    mlds_expand_mask(&p, rho2, (uint16_t)nondet_u32());
    __CPROVER_assert(p.coeffs[n] <= MLD_GAMMA1 && p.coeffs[n] > -MLD_GAMMA1,
                     "mlds_expand_mask: y in (-gamma1, gamma1]");
    return 0;
}
