// The steps of one round of ML-DSA-87's rejection loop (FIPS 204
// Algorithm 7, steps 11 to 28), and the sampling of a row of A times a
// vector, private to mldsa_sign_round.c and mldsa_signer.c
// (docs/decisions.md 159). Each step sits apart from the round that calls
// them, so that a proof runs each step once at its real bounds and a proof
// of the round replaces the steps with their contracts.
#ifndef CH_MLDSA_SIGN_STEPS_H
#define CH_MLDSA_SIGN_STEPS_H

#include <stdint.h>

#include "mldsa.h"
#include "mldsa_poly.h"
#include "mldsa_sign_pack.h"
#include "mldsa_signer.h"

// Where the parts of sk start (FIPS 204 Algorithm 24, skEncode).
#define MLDS_SK_KEY_AT MLD_RHO_BYTES
#define MLDS_SK_TR_AT (MLDS_SK_KEY_AT + 32)
#define MLDS_SK_S1_AT (MLDS_SK_TR_AT + 64)
#define MLDS_SK_S2_AT (MLDS_SK_S1_AT + MLD_L * MLDS_ETA_BYTES)
#define MLDS_SK_T0_AT (MLDS_SK_S2_AT + MLD_K * MLDS_ETA_BYTES)
// Where the parts of a signature start (FIPS 204 Algorithm 26, sigEncode).
#define MLDS_SIG_Z_AT MLDSA87_CTILDE_LEN
#define MLDS_SIG_HINT_AT (MLDS_SIG_Z_AT + MLD_L * MLD_Z_BYTES)

_Static_assert(MLDSA87_SK_LEN == MLDS_SK_T0_AT + MLD_K * MLDS_T0_BYTES, "FIPS 204 Table 2 sk size");
_Static_assert(MLDSA87_SIG_LEN == MLDS_SIG_HINT_AT + MLD_HINT_BYTES, "FIPS 204 Table 2 sig size");

// The working state of one round of the rejection loop.
typedef struct {
    mld_poly yz[MLD_L]; // NTT(y), then z
    mld_poly w[MLD_K];  // w = A y, then w - c s2, each in [0, q)
    mld_poly c_hat;     // NTT(c)
    mld_poly s_hat;     // one polynomial of s1, s2 or t0, or of A, as each step needs it
    mld_poly product;   // c times that polynomial, or w1
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    uint8_t hints[MLD_K][MLD_N / 8]; // the hint of each coefficient, one bit each
} mlds_round;

// The working state of key generation: NTT(s1), one row of t, one entry
// of A and one polynomial of s2, and the three seeds.
typedef struct {
    mld_poly s1_hat[MLD_L];
    mld_poly row;
    mld_poly entry;
    mld_poly s2;
    uint8_t seeds[128]; // rho, rho' and K (FIPS 204 Algorithm 6, step 1)
} mlds_keygen_state;

// row = NTT^-1(sum over j of A[i][j] o v_hat[j]), each coefficient in
// [0, q), with entry as the room for one entry of A. A is public and v_hat
// is not, so each product is mldsa_sign_poly.c's. Returns 1, or 0 with row
// zeroed when an entry of A stops at its sampling bound, so that key
// generation reads defined values on that path too.
int mlds_matrix_row(mld_poly *row, mld_poly *entry, const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                    const mld_poly v_hat[MLD_L]);

// Returns 1 when every coefficient of s1 and s2 in sk is in [-2, 2], and 0
// otherwise. It writes st->s_hat. A key that fails gives the same answer
// at every call, so the answer is public.
uint32_t mlds_key_in_range(mlds_round *st, const uint8_t sk[MLDSA87_SK_LEN]);

// The commitment w = A y and the challenge for it (FIPS 204 Algorithm 7,
// steps 11 to 17): writes NTT(y) to st->yz, w to st->w with each
// coefficient in [0, q), c-tilde to st->c_tilde and NTT(c) to st->c_hat.
// w1Encode of each row goes into the hash of mu before the next row.
// Returns 1, or 0 when a sampler stops at its bound.
int mlds_commit(mlds_round *st, const uint8_t *sk, const uint8_t mu[MLDSA_MU_LEN],
                const uint8_t rho2[64], unsigned kappa);

// z = y + c s1 into st->yz (FIPS 204 Algorithm 7, steps 18 to 20 and 23),
// with y drawn again from rho''. Each product is exact, under beta in
// absolute value, and so is each sum. Returns 1 when a coefficient of z
// reaches gamma1 - beta, and 0 otherwise.
uint32_t mlds_response(mlds_round *st, const uint8_t *sk, const uint8_t rho2[64], unsigned kappa);

// Row i of the low-bits check, the ct0 check and the hints (FIPS 204
// Algorithm 7, steps 21 to 28), for a w in [0, q). The hint of a
// coefficient is MakeHint(-ct0, w - cs2 + ct0): whether the high bits of
// w - cs2 + ct0 and of w - cs2 differ. Sets the row's hint bits in
// st->hints, which the caller cleared, and adds their count to *count.
// Writes w - cs2 to st->w[i]. Returns 1 when a check rejects the round,
// and 0 otherwise.
uint32_t mlds_hint_row(mlds_round *st, const uint8_t *sk, unsigned i, uint32_t *count);

// sigEncode (FIPS 204 Algorithm 26) of the round that passed: c-tilde, z
// as gamma1 - z at 20 bits, and the hints as HintBitPack writes them. The
// round passed, so every byte here is the signature's, which is public, and
// at most omega hints are set. A hint past omega would write no position,
// so sig takes 4627 bytes and no more for any st.
void mlds_encode(uint8_t sig[MLDSA87_SIG_LEN], const mlds_round *st);

// Row i of t = A s1 + s2, and its two halves (FIPS 204 Algorithm 6, steps
// 4 to 6): t1 into pk and t0 into sk, with s2[i] into sk, from st's seeds
// and NTT(s1). Returns 1, or 0 when a sampler stops at its bound.
uint32_t mlds_keygen_row(mlds_keygen_state *st, uint8_t *sk, uint8_t *pk, unsigned i);

#endif
