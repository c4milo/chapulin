// Proves: every exported function in mlkem_poly.c except the NTT
// transforms and the base multiplication — both samplers, Barrett and
// Montgomery reduction, and the byte and compression codings — is
// memory-safe and UB-free with the signed-overflow check on, over
// polynomials whose coefficients range over ALL of int16, not just the
// reduced values the callers pass. That full range is the point:
// mlkem_harness.c stubs this layer with outputs havocked to arbitrary
// coefficients, and this harness plus the mlkem_ntt, mlkem_invntt_low,
// mlkem_invntt_high, and mlkem_basemul harnesses discharge that stub
// by proving the real functions safe on the same widened domain. It
// also shows the arithmetic cannot trap on out-of-contract values —
// the reductions were sized so no int16 pair overflows an int32
// product. The three
// functions built from chained products prove in their own formulas:
// merged with this one the SAT instance exceeds memory (the one-formula
// attempt was killed at 14 GB), and the inverse NTT proves as two half
// formulas because even alone it returns no verdict in 900 s.
//
// Every call gets freshly havocked operands. Reusing a value the
// previous call wrote would silently shrink the proven domain to that
// call's image — reduced coefficients, just-encoded bytes — and the
// stub-discharge argument above needs the full domain at every call.
//
// The SHAKE sponge behind the samplers is stubbed to arbitrary bytes
// (sha3_harness.c proves the real one), so the rejection sampler is
// proved over every stream, not just real SHAKE128 output; the
// MLK_SAMPLE_GROUPS cap is what makes its loop unwindable.
#include "harness.h"

#include "mlkem_poly.c"

int16_t nondet_i16(void);

// Typed, fixed-index stores: filling through a byte pointer would make
// every store a whole-object update in the SSA, and 2,500 of those are
// what stopped a one-harness version of this proof from converging.
static void fill_poly_nondet(mlk_poly *p) {
    for (unsigned i = 0; i < 256; i++) {
        p->coeffs[i] = nondet_i16();
    }
}

void shake128_init(shake *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake128_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
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

int main(void) {
    mlk_poly a;
    mlk_poly b;
    mlk_poly r;
    mlk_polyvec v;
    uint8_t seed[32];
    uint8_t msg[32];
    uint8_t packed[MLK_POLYVEC_COMP_BYTES]; // largest byte form: 960

    fill_nondet(seed, sizeof seed);
    mlk_sample_ntt(&r, seed, nondet_u8(), nondet_u8());
    mlk_sample_cbd(&r, seed, nondet_u8());

    fill_poly_nondet(&a);
    fill_poly_nondet(&b);
    mlk_poly_add(&r, &a, &b);
    fill_poly_nondet(&a);
    fill_poly_nondet(&b);
    mlk_poly_sub(&r, &a, &b);
    // The KEM layer also calls both with the output aliased to an
    // input — add(out, out, x) in the dot product and key generation,
    // sub(w, v, w) in decryption — so the proof must cover those
    // pointer shapes, not just distinct ones.
    fill_poly_nondet(&a);
    fill_poly_nondet(&b);
    mlk_poly_add(&a, &a, &b);
    fill_poly_nondet(&a);
    fill_poly_nondet(&b);
    mlk_poly_sub(&b, &a, &b);

    fill_poly_nondet(&a);
    mlk_poly_reduce(&a);
    fill_poly_nondet(&a);
    mlk_poly_tomont(&a);

    fill_poly_nondet(&a);
    mlk_poly_tobytes(packed, &a);
    fill_nondet(packed, sizeof packed);
    mlk_poly_frombytes(&r, packed);
    for (unsigned k = 0; k < 3; k++) {
        fill_poly_nondet(&v.vec[k]);
    }
    mlk_polyvec_compress(packed, &v);
    fill_nondet(packed, sizeof packed);
    mlk_polyvec_decompress(&v, packed);
    fill_poly_nondet(&a);
    mlk_poly_compress(packed, &a);
    fill_nondet(packed, sizeof packed);
    mlk_poly_decompress(&r, packed);
    fill_nondet(msg, sizeof msg);
    mlk_poly_frommsg(&r, msg);
    fill_poly_nondet(&b);
    mlk_poly_tomsg(msg, &b);
    return 0;
}
