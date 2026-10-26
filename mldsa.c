// ML-DSA-87 verification (FIPS 204 Algorithms 3 and 8): the decoding of
// the key and the signature, the hashes, and the order of the polynomial
// steps. mldsa_poly.c holds the arithmetic.
//
// The matrix A is never held whole. Each row of w is A[i] o NTT(z) -
// NTT(c) o NTT(t1[i] * 2^d), and each entry A[i][j] is sampled from rho
// just before its product, so one entry, the sum, NTT(z) and NTT(c) are
// the polynomials alive at once. Each row's w1 bytes go into the hash at
// once, so w1 is never held whole either (docs/decisions.md 154).
#include "mldsa.h"

#include "ct.h"
#include "mldsa_poly.h"
#include "sha3.h"

// Where the parts of a signature start (FIPS 204 Algorithm 27, sigDecode).
#define MLD_SIG_Z_AT MLDSA87_CTILDE_LEN
#define MLD_SIG_HINT_AT (MLD_SIG_Z_AT + MLD_L * MLD_Z_BYTES)

_Static_assert(MLDSA87_PK_LEN == MLD_RHO_BYTES + MLD_K * MLD_T1_BYTES, "FIPS 204 Table 2 pk size");
_Static_assert(MLDSA87_SIG_LEN == MLD_SIG_HINT_AT + MLD_HINT_BYTES, "FIPS 204 Table 2 sig size");

// The checks of FIPS 204 Algorithm 21, HintBitUnpack, on the hint
// encoding y: the first omega bytes are positions, and byte omega + i ends
// row i's run of them. Returns 1 when each end is at least the one before
// and at most omega, the positions in each run increase, and every byte
// after the last run is 0. HintBitUnpack returns its failure symbol for
// any other y.
//
// Position at starts a run when it is 0 or when a row ends at it, so the
// order check skips it. One pass over the omega positions makes the order
// check and the zero check. Each loop's count is a constant, so the CBMC
// formula holds no loop whose count depends on y.
static int mld_hints_well_formed(const uint8_t y[MLD_HINT_BYTES]) {
    uint8_t starts_run[MLD_OMEGA + 1] = {0};
    unsigned last = 0;
    for (unsigned i = 0; i < MLD_K; i++) {
        unsigned end = y[MLD_OMEGA + i];
        if (end < last || end > MLD_OMEGA) {
            return 0;
        }
        starts_run[end] = 1;
        last = end;
    }
    for (unsigned at = 0; at < MLD_OMEGA; at++) {
        if (at >= last) {
            if (y[at] != 0) {
                return 0;
            }
        } else if (at > 0 && !starts_run[at] && y[at - 1] >= y[at]) {
            return 0;
        }
    }
    return 1;
}

// w1Encode of row i of w'_Approx (FIPS 204 Algorithm 8, steps 9 and 10).
// Returns 0 when an entry of A stops at its sampling bound.
static int mld_row_w1(uint8_t w1[MLD_W1_BYTES], unsigned i, const uint8_t pk[MLDSA87_PK_LEN],
                      const uint8_t sig[MLDSA87_SIG_LEN], const mld_poly z_hat[MLD_L],
                      const mld_poly *c_hat) {
    mld_poly entry;
    mld_poly sum;
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_sample_ntt(&entry, pk, (uint8_t)j, (uint8_t)i)) {
            return 0;
        }
        if (j == 0) {
            mld_poly_pointwise(&sum, &entry, &z_hat[0]);
        } else {
            mld_poly_pointwise_acc(&sum, &entry, &z_hat[j]);
        }
    }
    mld_poly_unpack_t1_shifted(&entry, pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES);
    mld_poly_ntt(&entry);
    mld_poly_pointwise(&entry, c_hat, &entry);
    mld_poly_sub(&sum, &sum, &entry);
    mld_poly_invntt_tomont(&sum);
    const uint8_t *y = sig + MLD_SIG_HINT_AT;
    unsigned first = i == 0 ? 0 : y[MLD_OMEGA + i - 1];
    unsigned end = y[MLD_OMEGA + i];
    mld_poly_use_hint(w1, &sum, y + first, end - first);
    return 1;
}

int mldsa87_challenge(uint8_t c_tilde[MLDSA87_CTILDE_LEN], const uint8_t pk[MLDSA87_PK_LEN],
                      const uint8_t mu[MLDSA_MU_LEN], const uint8_t sig[MLDSA87_SIG_LEN]) {
    if (!mld_hints_well_formed(sig + MLD_SIG_HINT_AT)) {
        return 0;
    }
    mld_poly z_hat[MLD_L];
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_poly_unpack_z(&z_hat[j], sig + MLD_SIG_Z_AT + (size_t)j * MLD_Z_BYTES)) {
            return 0;
        }
        mld_poly_ntt(&z_hat[j]);
    }
    mld_poly c_hat;
    if (!mld_sample_in_ball(&c_hat, sig)) {
        return 0;
    }
    mld_poly_ntt(&c_hat);
    shake h;
    shake256_init(&h);
    shake_absorb(&h, mu, MLDSA_MU_LEN);
    for (unsigned i = 0; i < MLD_K; i++) {
        uint8_t w1[MLD_W1_BYTES];
        if (!mld_row_w1(w1, i, pk, sig, z_hat, &c_hat)) {
            return 0;
        }
        shake_absorb(&h, w1, sizeof w1);
    }
    shake_squeeze(&h, c_tilde, MLDSA87_CTILDE_LEN);
    return 1;
}

int mldsa87_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len) {
    if (pk_len != MLDSA87_PK_LEN || sig_len != MLDSA87_SIG_LEN || ctx_len > MLDSA_CONTEXT_MAX) {
        return 0;
    }
    // tr = H(pk, 64), then mu = H(tr || M', 64), where M' is the domain
    // byte 0 for pure ML-DSA, the context's length, the context and the
    // message (FIPS 204 Algorithm 3 step 5, Algorithm 8 steps 6 and 7).
    uint8_t tr[64];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, pk, MLDSA87_PK_LEN);
    shake_squeeze(&h, tr, sizeof tr);
    const uint8_t prefix[2] = {0, (uint8_t)ctx_len};
    uint8_t mu[MLDSA_MU_LEN];
    shake256_init(&h);
    shake_absorb(&h, tr, sizeof tr);
    shake_absorb(&h, prefix, sizeof prefix);
    shake_absorb(&h, ctx, ctx_len);
    shake_absorb(&h, msg, msg_len);
    shake_squeeze(&h, mu, sizeof mu);
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    if (!mldsa87_challenge(c_tilde, pk, mu, sig)) {
        return 0;
    }
    return ct_memeq(c_tilde, sig, MLDSA87_CTILDE_LEN) == 1;
}
