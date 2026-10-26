// Proves: mldsa_signer.c's key generation and signing entries are
// memory-safe and UB-free with the signed-overflow check on, over every
// seed, every key and public key of every length up to one byte past its
// own, every message length up to 2^20 bytes, every context length up to
// 256 and every nonzero rnd, and these hold:
//  - mldsa87_keygen returns 0 or 1, and on 0 it leaves sk and pk zero;
//  - mldsa87_sign returns 1 only with both lengths right, a context of
//    255 bytes or fewer, a round that wrote sig, and a verdict of 1 from
//    mldsa87_verify over the signature it returns: no signature leaves
//    unchecked (docs/decisions.md 159);
//  - on 0 it leaves sig zero, whichever check refused it;
//  - the rejection loop runs at most MLDSA87_SIGN_ROUNDS rounds, and each
//    round's kappa is a multiple of l that ExpandMask's 16 bits hold.
//
// The two entries are two formulas: this one signs, and
// mldsa_signer_keygen generates the key.
//
// One round of the loop, a row of key generation, the range check of the
// key, the samplers, the encodings and the NTT are stubbed to the contracts
// that mldsa_sign_round, mldsa_sign_keygen_row, mldsa_sign_commit,
// mldsa_sign_samplers, mldsa_sign_pack and mldsa_sign_ntt prove. mldsa87_verify is stubbed to its
// pointer contract and either verdict, and the mldsa harness proves the real one. The SHAKE sponge
// is stubbed as in mldsa_poly_harness.c.
//
// ct_wipe is the byte loop of proof/ct_wipe_stub.c over sk, pk and sig,
// the byte arrays whose zeros the claims above read. Over every other
// object it asserts that the bytes are writable and havocs them: a byte
// loop over a round's 18,752-byte struct of typed arrays rewrites the
// whole struct at each byte, and the formula of key generation alone
// passed 7.9 GB in 31 s. The tests search the stack for what those wipes
// leave (bin/pem_files_mldsa_test).
#include "harness.h"

#include <stdlib.h>

#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"

int32_t nondet_i32(void);
int nondet_int(void);

#include "mldsa_signer.c"

static uint8_t key_room[MLDSA87_SK_LEN];
static uint8_t pk_room[MLDSA87_PK_LEN];
static uint8_t sig[MLDSA87_SIG_LEN];

void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "ct_wipe: the bytes are writable");
    if (__CPROVER_same_object(p, sig) || __CPROVER_same_object(p, key_room) ||
        __CPROVER_same_object(p, pk_room)) {
        volatile uint8_t *v = (volatile uint8_t *)p;
        for (size_t i = 0; i < n; i++) {
            v[i] = 0;
        }
    } else if (n != 0) {
        __CPROVER_havoc_slice(p, n);
    }
}

static void havoc_range(mld_poly *p, int32_t lo, int32_t hi) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly output writable");
    for (unsigned i = 0; i < MLD_N; i++) {
        int32_t v = nondet_i32();
        __CPROVER_assume(v >= lo && v <= hi);
        p->coeffs[i] = v;
    }
}

static uint32_t nondet_bit(void) {
    return nondet_u32() & 1U;
}

void mlds_poly_ntt(mld_poly *p) {
    havoc_range(p, INT32_MIN, INT32_MAX);
}

uint32_t mlds_sample_eta(mld_poly *p, const uint8_t rho_prime[64], uint16_t nonce) {
    __CPROVER_assert(__CPROVER_r_ok(rho_prime, 64), "mlds_sample_eta: rho' readable");
    __CPROVER_assert(nonce < MLD_L + MLD_K, "mlds_sample_eta: the nonce of s1 or s2");
    havoc_range(p, -MLDS_ETA, MLDS_ETA);
    return nondet_bit();
}

void mlds_pack(uint8_t *out, const mld_poly *p, unsigned bits, int32_t offset) {
    (void)offset;
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "mlds_pack: input readable");
    __CPROVER_assert(bits == 3 || bits == 10 || bits == 13, "mlds_pack: s, t1 or t0");
    __CPROVER_assert(__CPROVER_w_ok(out, (size_t)32 * bits), "mlds_pack: output writable");
    __CPROVER_havoc_slice(out, (size_t)32 * bits);
}

uint32_t mlds_keygen_row(mlds_keygen_state *st, uint8_t *sk, uint8_t *pk, unsigned i) {
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_keygen_row: state writable");
    __CPROVER_assert(i < MLD_K, "mlds_keygen_row: a row of t");
    __CPROVER_assert(
        __CPROVER_w_ok(sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES, MLDS_ETA_BYTES),
        "mlds_keygen_row: s2's bytes writable");
    __CPROVER_assert(__CPROVER_w_ok(sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, MLDS_T0_BYTES),
                     "mlds_keygen_row: t0's bytes writable");
    __CPROVER_assert(__CPROVER_w_ok(pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES, MLD_T1_BYTES),
                     "mlds_keygen_row: t1's bytes writable");
    __CPROVER_havoc_slice(sk + MLDS_SK_S2_AT + (size_t)i * MLDS_ETA_BYTES, MLDS_ETA_BYTES);
    __CPROVER_havoc_slice(sk + MLDS_SK_T0_AT + (size_t)i * MLDS_T0_BYTES, MLDS_T0_BYTES);
    __CPROVER_havoc_slice(pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES, MLD_T1_BYTES);
    return nondet_bit();
}

uint32_t mlds_key_in_range(mlds_round *st, const uint8_t sk[MLDSA87_SK_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_key_in_range: state writable");
    __CPROVER_assert(__CPROVER_r_ok(sk, MLDSA87_SK_LEN), "mlds_key_in_range: sk readable");
    return nondet_bit();
}

static unsigned rounds_run;

int mlds_sign_round(mlds_round *st, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk,
                    const uint8_t mu[MLDSA_MU_LEN], const uint8_t rho2[64], unsigned kappa) {
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_sign_round: state writable");
    __CPROVER_assert(__CPROVER_w_ok(sig, MLDSA87_SIG_LEN), "mlds_sign_round: sig writable");
    __CPROVER_assert(__CPROVER_r_ok(sk, MLDSA87_SK_LEN), "mlds_sign_round: sk readable");
    __CPROVER_assert(__CPROVER_r_ok(mu, MLDSA_MU_LEN), "mlds_sign_round: mu readable");
    __CPROVER_assert(__CPROVER_r_ok(rho2, 64), "mlds_sign_round: rho'' readable");
    __CPROVER_assert(kappa == rounds_run * MLD_L, "mlds_sign_round: kappa steps by l");
    __CPROVER_assert(kappa + MLD_L <= 0x10000, "mlds_sign_round: kappa fits 16 bits");
    rounds_run++;
    // The stub writes no byte of sig: sig holds arbitrary bytes before the
    // call (sign below), which covers every byte a round could leave. A
    // havoc of sig in each of 814 rounds made a formula of 244 M clauses.
    int passed = nondet_int();
    __CPROVER_assume(passed >= -1 && passed <= 1);
    return passed;
}

static int verified;

int mldsa87_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(pk_len == 0 || __CPROVER_r_ok(pk, pk_len), "mldsa87_verify: pk readable");
    __CPROVER_assert(msg_len == 0 || __CPROVER_r_ok(msg, msg_len), "mldsa87_verify: msg readable");
    __CPROVER_assert(ctx_len == 0 || __CPROVER_r_ok(ctx, ctx_len), "mldsa87_verify: ctx readable");
    __CPROVER_assert(__CPROVER_r_ok(sig, sig_len), "mldsa87_verify: sig readable");
    verified = (int)nondet_bit();
    return verified;
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

static void keygen(void) {
    uint8_t seed[MLDSA87_SEED_LEN];
    fill_nondet(seed, sizeof seed);
    int ok = mldsa87_keygen(key_room, pk_room, seed);
    size_t at = nondet_size_t();
    __CPROVER_assume(at < MLDSA87_PK_LEN);
    __CPROVER_assert(ok == 0 || ok == 1, "mldsa87_keygen: 0 or 1");
    __CPROVER_assert(ok == 1 || (key_room[at] == 0 && pk_room[at] == 0),
                     "mldsa87_keygen: a refusal leaves sk and pk zero");
}

static void sign(void) {
    size_t sk_len = nondet_size_t();
    size_t pk_len = nondet_size_t();
    __CPROVER_assume(sk_len <= MLDSA87_SK_LEN + 1 && pk_len <= MLDSA87_PK_LEN + 1);
    uint8_t *sk = malloc(sk_len);
    uint8_t *pk = malloc(pk_len);
    __CPROVER_assume(sk != NULL && pk != NULL);
    size_t msg_len = nondet_size_t();
    __CPROVER_assume(msg_len <= ((size_t)1 << 20));
    uint8_t *msg = malloc(msg_len);
    __CPROVER_assume(msg != NULL);
    size_t ctx_len = nondet_size_t();
    __CPROVER_assume(ctx_len <= MLDSA_CONTEXT_MAX + 1);
    uint8_t *ctx = malloc(ctx_len);
    __CPROVER_assume(ctx != NULL);
    uint8_t rnd[MLDSA87_RND_LEN];
    fill_nondet(rnd, sizeof rnd);
    size_t nonzero = nondet_size_t();
    __CPROVER_assume(nonzero < sizeof rnd && rnd[nonzero] != 0);
    __CPROVER_havoc_object(sig);
    verified = 0;
    rounds_run = 0;
    int ok = mldsa87_sign(sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd);
    size_t at = nondet_size_t();
    __CPROVER_assume(at < sizeof sig);
    __CPROVER_assert(ok == 0 || ok == 1, "mldsa87_sign: 0 or 1");
    __CPROVER_assert(ok == 0 || (sk_len == MLDSA87_SK_LEN && pk_len == MLDSA87_PK_LEN &&
                                 ctx_len <= MLDSA_CONTEXT_MAX),
                     "mldsa87_sign: a wrong length or a long context is refused");
    __CPROVER_assert(ok == 0 || verified == 1, "mldsa87_sign: no signature leaves unchecked");
    __CPROVER_assert(ok == 1 || sig[at] == 0, "mldsa87_sign: a refusal leaves sig zero");
    __CPROVER_assert(rounds_run <= MLDSA87_SIGN_ROUNDS, "mldsa87_sign: at most 814 rounds");
    free(ctx);
    free(msg);
    free(pk);
    free(sk);
}

// Key generation and signing are two formulas: mldsa_signer_keygen's
// harness defines SIGNER_KEYGEN and includes this file.
int main(void) {
#ifdef SIGNER_KEYGEN
    keygen();
#else
    sign();
#endif
    return 0;
}
