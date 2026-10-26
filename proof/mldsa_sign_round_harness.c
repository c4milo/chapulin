// Proves: one round of ML-DSA-87's rejection loop, mlds_sign_round in
// mldsa_sign_round.c, is memory-safe and UB-free with the signed-overflow
// check on, over every answer its steps can give, and these hold:
//  - it writes sig only when it returns 1;
//  - it encodes only a round with at most omega hints, the count the
//    rows' steps added;
//  - it clears every hint bit before the first row, so a bit of an
//    earlier round is never encoded.
//
// The steps are stubbed to their contracts, which mldsa_sign_commit,
// mldsa_sign_response and mldsa_sign_hint_row prove: each verdict is
// either answer, and mlds_hint_row sets any bits of its own row and adds
// their exact count. mlds_encode is stubbed to its pointer contract.
#include "harness.h"

#include "mldsa_sign_round.c"

static uint32_t hints_set;

int mlds_commit(mlds_round *st, const uint8_t *sk, const uint8_t mu[MLDSA_MU_LEN],
                const uint8_t rho2[64], unsigned kappa) {
    (void)kappa;
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_commit: state writable");
    __CPROVER_assert(__CPROVER_r_ok(sk, MLDSA87_SK_LEN), "mlds_commit: sk readable");
    __CPROVER_assert(__CPROVER_r_ok(mu, MLDSA_MU_LEN), "mlds_commit: mu readable");
    __CPROVER_assert(__CPROVER_r_ok(rho2, 64), "mlds_commit: rho'' readable");
    __CPROVER_havoc_object(st);
    return (int)(nondet_u32() & 1U);
}

uint32_t mlds_response(mlds_round *st, const uint8_t *sk, const uint8_t rho2[64], unsigned kappa) {
    (void)kappa;
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_response: state writable");
    __CPROVER_assert(__CPROVER_r_ok(sk, MLDSA87_SK_LEN), "mlds_response: sk readable");
    __CPROVER_assert(__CPROVER_r_ok(rho2, 64), "mlds_response: rho'' readable");
    return nondet_u32() & 1U;
}

uint32_t mlds_hint_row(mlds_round *st, const uint8_t *sk, unsigned i, uint32_t *count) {
    __CPROVER_assert(__CPROVER_w_ok(st, sizeof *st), "mlds_hint_row: state writable");
    __CPROVER_assert(__CPROVER_r_ok(sk, MLDSA87_SK_LEN), "mlds_hint_row: sk readable");
    __CPROVER_assert(i < MLD_K, "mlds_hint_row: a row of the round");
    for (unsigned b = 0; b < MLD_N / 8; b++) {
        __CPROVER_assert(st->hints[i][b] == 0, "mlds_hint_row: the row starts clear");
        uint8_t bits = nondet_u8();
        st->hints[i][b] = bits;
        for (unsigned k = 0; k < 8; k++) {
            *count += (bits >> k) & 1U;
            hints_set += (bits >> k) & 1U;
        }
    }
    return nondet_u32() & 1U;
}

static int encoded;

void mlds_encode(uint8_t sig[MLDSA87_SIG_LEN], const mlds_round *st) {
    __CPROVER_assert(__CPROVER_r_ok(st, sizeof *st), "mlds_encode: state readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, MLDSA87_SIG_LEN), "mlds_encode: sig writable");
    __CPROVER_assert(hints_set <= MLD_OMEGA, "mlds_encode: at most omega hints");
    __CPROVER_havoc_object(sig);
    encoded = 1;
}

static mlds_round st;
static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t sig[MLDSA87_SIG_LEN];

int main(void) {
    uint8_t mu[MLDSA_MU_LEN];
    uint8_t rho2[64];
    __CPROVER_havoc_object(sk);
    __CPROVER_havoc_object(&st);
    unsigned kappa = nondet_u32();
    __CPROVER_assume(kappa % MLD_L == 0 && kappa < MLDSA87_SIGN_ROUNDS * MLD_L);
    int passed = mlds_sign_round(&st, sig, sk, mu, rho2, kappa);
    __CPROVER_assert(passed >= -1 && passed <= 1, "the round answers -1, 0 or 1");
    __CPROVER_assert(passed == 1 || encoded == 0, "a round that does not pass writes no sig");
    __CPROVER_assert(passed != 1 || encoded == 1, "a round that passes writes sig");
    return 0;
}
