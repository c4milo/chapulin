// Proves: the verification layer in mldsa.c -- the length and context
// checks, mu's input, HintBitUnpack's checks, the hint runs it hands each
// row, and the order of the polynomial steps -- is memory-safe and
// UB-free over every key and signature of every length up to one byte
// past its own, every message length up to 2^20 bytes and every context
// length up to 256. A key and a signature have one valid length each, so
// that bound is the whole domain of each. A verdict of 1 needs both
// lengths right and a context of 255 bytes or fewer.
//
// The polynomial layer is stubbed to its pointer contracts, with every
// output havocked to any int32_t coefficients and every verdict to either
// answer. mldsa_poly, mldsa_ntt and mldsa_coefficient prove the real layer
// over that range. The hint stub also asserts that the run lies inside the
// signature and holds at most omega positions. The SHAKE sponge is
// stubbed as in mldsa_poly_harness.c, and sha3_harness.c proves the real
// one. ct_memeq is the real one.
#include "harness.h"

#include <stdlib.h>

#include "mldsa.c"

int32_t nondet_i32(void);
int nondet_int(void);

static void havoc_poly(mld_poly *p) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly output writable");
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

static void assert_poly_readable(const mld_poly *p) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "poly input readable");
}

static int nondet_verdict(void) {
    int verdict = nondet_int();
    __CPROVER_assume(verdict == 0 || verdict == 1);
    return verdict;
}

void mld_poly_ntt(mld_poly *p) {
    havoc_poly(p);
}

void mld_poly_invntt_tomont(mld_poly *p) {
    havoc_poly(p);
}

void mld_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mld_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(acc);
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(acc);
}

void mld_poly_sub(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mld_poly_unpack_t1_shifted(mld_poly *p, const uint8_t in[MLD_T1_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLD_T1_BYTES), "t1 input readable");
    havoc_poly(p);
}

int mld_poly_unpack_z(mld_poly *p, const uint8_t in[MLD_Z_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLD_Z_BYTES), "z input readable");
    havoc_poly(p);
    return nondet_verdict();
}

void mld_poly_use_hint(uint8_t out[MLD_W1_BYTES], const mld_poly *w, const uint8_t *hints,
                       size_t hint_count) {
    assert_poly_readable(w);
    __CPROVER_assert(hint_count <= MLD_OMEGA, "use_hint: at most omega positions");
    __CPROVER_assert(hint_count == 0 || __CPROVER_r_ok(hints, hint_count),
                     "use_hint: the run is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, MLD_W1_BYTES), "use_hint: output writable");
    fill_nondet(out, MLD_W1_BYTES);
}

int mld_sample_ntt(mld_poly *p, const uint8_t rho[MLD_RHO_BYTES], uint8_t s, uint8_t r) {
    __CPROVER_assert(__CPROVER_r_ok(rho, MLD_RHO_BYTES), "rho readable");
    __CPROVER_assert(s < MLD_L && r < MLD_K, "A's entry is inside the matrix");
    havoc_poly(p);
    return nondet_verdict();
}

int mld_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]) {
    __CPROVER_assert(__CPROVER_r_ok(c_tilde, 64), "c_tilde readable");
    havoc_poly(c);
    return nondet_verdict();
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
    // Each input is a heap object of exactly its length, whose bytes CBMC
    // leaves unconstrained, so a read past a length fails a bound check.
    size_t pk_len = nondet_size_t();
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(pk_len <= MLDSA87_PK_LEN + 1 && sig_len <= MLDSA87_SIG_LEN + 1);
    uint8_t *pk = malloc(pk_len);
    uint8_t *sig = malloc(sig_len);
    __CPROVER_assume(pk != NULL && sig != NULL);
    size_t msg_len = nondet_size_t();
    __CPROVER_assume(msg_len <= ((size_t)1 << 20));
    uint8_t *msg = malloc(msg_len);
    __CPROVER_assume(msg != NULL);
    size_t ctx_len = nondet_size_t();
    __CPROVER_assume(ctx_len <= MLDSA_CONTEXT_MAX + 1);
    uint8_t *ctx = malloc(ctx_len);
    __CPROVER_assume(ctx != NULL);
    int verdict = mldsa87_verify(pk, pk_len, msg, msg_len, ctx, ctx_len, sig, sig_len);
    __CPROVER_assert(verdict == 0 || verdict == 1, "the verdict is 0 or 1");
    __CPROVER_assert(verdict == 0 || (pk_len == MLDSA87_PK_LEN && sig_len == MLDSA87_SIG_LEN &&
                                      ctx_len <= MLDSA_CONTEXT_MAX),
                     "a wrong length or a long context is refused");
    free(msg);
    free(ctx);
    free(sig);
    free(pk);
    return 0;
}
