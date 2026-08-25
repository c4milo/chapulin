// Proves: the ML-KEM layer in mlkem.c — K-PKE assembly, the FIPS 203
// section 7.2 modulus check, and the Fujisaki-Okamoto wrapper with its
// branchless implicit-reject select — is memory-safe and UB-free over
// its whole fixed-size input domains: every seed pair, every hostile
// encapsulation key and message, every hostile decapsulation key and
// ciphertext. ML-KEM's inputs are fixed-size arrays, so the bound IS
// the domain and nothing sits outside it.
//
// The polynomial layer is stubbed to its pointer contracts with every
// output havocked to full-range int16 coefficients — a superset of
// anything the real functions produce. mlkem_poly_harness.c and the
// chained-product harnesses beside it prove the real layer over that
// same full range.
// The SHA-3 sponge is stubbed the same way (sha3_harness.c proves the
// real one), which widens every hash and XOF to an arbitrary function.
// All three calls in one main also proves keygen, encapsulation and
// decapsulation do not interfere through the module (it holds no
// state). The signed-overflow check stays on.
#include "harness.h"

#include "mlkem.c"

int16_t nondet_i16(void);

// Typed, fixed-index stores: filling through a byte pointer would make
// every store a whole-object update in the SSA (see mlkem_poly_harness.c).
static void havoc_poly(mlk_poly *p) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly output writable");
    for (unsigned i = 0; i < 256; i++) {
        p->coeffs[i] = nondet_i16();
    }
}

static void assert_poly_readable(const mlk_poly *p) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "poly input readable");
}

void mlk_poly_ntt(mlk_poly *p) {
    havoc_poly(p);
}

void mlk_poly_invntt(mlk_poly *p) {
    havoc_poly(p);
}

void mlk_poly_basemul(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mlk_poly_add(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mlk_poly_sub(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mlk_poly_reduce(mlk_poly *p) {
    havoc_poly(p);
}

void mlk_poly_tomont(mlk_poly *p) {
    havoc_poly(p);
}

void mlk_poly_tobytes(uint8_t out[MLK_POLY_BYTES], const mlk_poly *p) {
    assert_poly_readable(p);
    __CPROVER_assert(__CPROVER_w_ok(out, MLK_POLY_BYTES), "tobytes output writable");
    fill_nondet(out, MLK_POLY_BYTES);
}

void mlk_poly_frombytes(mlk_poly *p, const uint8_t in[MLK_POLY_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLK_POLY_BYTES), "frombytes input readable");
    havoc_poly(p);
}

void mlk_polyvec_compress(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v) {
    __CPROVER_assert(__CPROVER_r_ok(v, sizeof *v), "compress input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, MLK_POLYVEC_COMP_BYTES), "compress output writable");
    fill_nondet(out, MLK_POLYVEC_COMP_BYTES);
}

void mlk_polyvec_decompress(mlk_polyvec *v, const uint8_t in[MLK_POLYVEC_COMP_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLK_POLYVEC_COMP_BYTES), "decompress input readable");
    __CPROVER_assert(__CPROVER_w_ok(v, sizeof *v), "decompress output writable");
    for (unsigned k = 0; k < 3; k++) {
        havoc_poly(&v->vec[k]);
    }
}

void mlk_poly_compress(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p) {
    assert_poly_readable(p);
    __CPROVER_assert(__CPROVER_w_ok(out, MLK_POLY_COMP_BYTES), "compress output writable");
    fill_nondet(out, MLK_POLY_COMP_BYTES);
}

void mlk_poly_decompress(mlk_poly *p, const uint8_t in[MLK_POLY_COMP_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLK_POLY_COMP_BYTES), "decompress input readable");
    havoc_poly(p);
}

void mlk_poly_frommsg(mlk_poly *p, const uint8_t msg[32]) {
    __CPROVER_assert(__CPROVER_r_ok(msg, 32), "frommsg input readable");
    havoc_poly(p);
}

void mlk_poly_tomsg(uint8_t msg[32], const mlk_poly *p) {
    assert_poly_readable(p);
    __CPROVER_assert(__CPROVER_w_ok(msg, 32), "tomsg output writable");
    fill_nondet(msg, 32);
}

void mlk_sample_ntt(mlk_poly *p, const uint8_t seed[32], uint8_t x0, uint8_t x1) {
    (void)x0;
    (void)x1;
    __CPROVER_assert(__CPROVER_r_ok(seed, 32), "sample seed readable");
    havoc_poly(p);
}

void mlk_sample_cbd(mlk_poly *p, const uint8_t seed[32], uint8_t nonce) {
    (void)nonce;
    __CPROVER_assert(__CPROVER_r_ok(seed, 32), "sample seed readable");
    havoc_poly(p);
}

void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha3_256: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA3_256_LEN), "sha3_256: output writable");
    fill_nondet(out, SHA3_256_LEN);
}

void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha3_512: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA3_512_LEN), "sha3_512: output writable");
    fill_nondet(out, SHA3_512_LEN);
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
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    uint8_t ek[MLKEM_EK_LEN];
    uint8_t dk[MLKEM_DK_LEN];
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];

    fill_nondet(d, sizeof d);
    fill_nondet(z, sizeof z);
    mlkem_keygen_derand(ek, dk, d, z);

    fill_nondet(ek, sizeof ek);
    fill_nondet(m, sizeof m);
    (void)mlkem_encaps_derand(ct, ss, ek, m);

    fill_nondet(dk, sizeof dk);
    fill_nondet(ct, sizeof ct);
    mlkem_decaps(ss, ct, dk);
    return 0;
}
