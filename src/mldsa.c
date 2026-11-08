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
#include "mldsa_avx2.h"
#include "mldsa_neon.h"
#include "mldsa_poly.h"
#include "mldsa_vector.h"
#include "sha3.h"

// Where the parts of a signature start (FIPS 204 Algorithm 27, sigDecode).
#define MLD_SIG_Z_AT MLDSA87_CTILDE_LEN
#define MLD_SIG_HINT_AT (MLD_SIG_Z_AT + MLD_L * MLD_Z_BYTES)

_Static_assert(MLDSA87_PK_LEN == MLD_RHO_BYTES + MLD_K * MLD_T1_BYTES, "FIPS 204 Table 2 pk size");
_Static_assert(MLDSA87_SIG_LEN == MLD_SIG_HINT_AT + MLD_HINT_BYTES, "FIPS 204 Table 2 sig size");

// The transforms and the products this object runs, for a session whose
// ch_cfg.cpu is cpu. A host object runs them on mldsa_vector.c's lanes
// where mld_vector_runs takes cpu for public operands: on arm64 in every
// session, and on x86-64 in a session whose cpu holds CH_CPU_AVX2. Every
// input of verification is public, so no other bit picks the lanes. Every
// other call runs mldsa_poly.c's loops, which CBMC proves and which
// bin/mldsa_vector_equiv_test holds the lanes to.
static void mld_ntt(uint32_t cpu, mld_poly *p) {
#if MLD_VECTOR
    if (mld_vector_runs(cpu, 0)) {
        mld_vector_ntt(p);
        return;
    }
#else
    (void)cpu;
#endif
    mld_poly_ntt(p);
}

static void mld_invntt_tomont(uint32_t cpu, mld_poly *p) {
#if MLD_VECTOR
    if (mld_vector_runs(cpu, 0)) {
        mld_vector_invntt_tomont(p);
        return;
    }
#else
    (void)cpu;
#endif
    mld_poly_invntt_tomont(p);
}

static void mld_pointwise(uint32_t cpu, mld_poly *r, const mld_poly *a, const mld_poly *b) {
#if MLD_VECTOR
    if (mld_vector_runs(cpu, 0)) {
        mld_vector_pointwise(r, a, b);
        return;
    }
#else
    (void)cpu;
#endif
    mld_poly_pointwise(r, a, b);
}

static void mld_pointwise_acc(uint32_t cpu, mld_poly *acc, const mld_poly *a, const mld_poly *b) {
#if MLD_VECTOR
    if (mld_vector_runs(cpu, 0)) {
        mld_vector_pointwise_acc(acc, a, b);
        return;
    }
#else
    (void)cpu;
#endif
    mld_poly_pointwise_acc(acc, a, b);
}

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

#ifdef MLD_WIDE_ENTRIES
// The sum mld_row_w1 computes over row i of A, with the row's entries
// sampled several at a time (MLD_WIDE_ENTRIES): on the four-way Keccak
// on x86-64 (mldsa_avx2.h) and on the two-way Keccak on arm64
// (mldsa_neon.h), into room. Returns 1, or 0 when an entry stops at its
// sampling bound.
static int mld_row_sum_wide(uint32_t cpu, mld_poly *sum, mld_poly room[MLD_WIDE_ENTRIES],
                            unsigned i, const uint8_t pk[MLDSA87_PK_LEN],
                            const mld_poly z_hat[MLD_L]) {
    for (unsigned first = 0; first < MLD_L; first += MLD_WIDE_ENTRIES) {
        unsigned count = MLD_L - first < MLD_WIDE_ENTRIES ? MLD_L - first : MLD_WIDE_ENTRIES;
        if (!mld_sample_ntt_wide(cpu, room, pk, i, first, count)) {
            return 0;
        }
        for (unsigned k = 0; k < count; k++) {
            if (first + k == 0) {
                mld_pointwise(cpu, sum, &room[0], &z_hat[0]);
            } else {
                mld_pointwise_acc(cpu, sum, &room[k], &z_hat[first + k]);
            }
        }
    }
    return 1;
}
#endif // MLD_WIDE_ENTRIES

// The entries of A that mld_row_w1's room holds: MLD_WIDE_ENTRIES in a
// host object that samples several at a time, and one everywhere else.
#ifdef MLD_WIDE_ENTRIES
#define MLD_ROW_ROOM MLD_WIDE_ENTRIES
#else
#define MLD_ROW_ROOM 1
#endif

// sum = the sum over j of A[i][j] o z_hat[j], each entry sampled into
// room. Returns 1, or 0 when an entry stops at its sampling bound.
static int mld_row_sum(uint32_t cpu, mld_poly *sum, mld_poly room[MLD_ROW_ROOM], unsigned i,
                       const uint8_t pk[MLDSA87_PK_LEN], const mld_poly z_hat[MLD_L]) {
#ifdef MLD_WIDE_ENTRIES
    if (mld_wide_runs(cpu)) {
        return mld_row_sum_wide(cpu, sum, room, i, pk, z_hat);
    }
#endif
    mld_poly *entry = &room[0];
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_sample_ntt_cpu(cpu, entry, pk, (uint8_t)j, (uint8_t)i)) {
            return 0;
        }
        if (j == 0) {
            mld_pointwise(cpu, sum, entry, &z_hat[0]);
        } else {
            mld_pointwise_acc(cpu, sum, entry, &z_hat[j]);
        }
    }
    return 1;
}

// w1Encode of row i of w'_Approx (FIPS 204 Algorithm 8, steps 9 and 10).
// Returns 0 when an entry of A stops at its sampling bound.
static int mld_row_w1(uint32_t cpu, uint8_t w1[MLD_W1_BYTES], unsigned i,
                      const uint8_t pk[MLDSA87_PK_LEN], const uint8_t sig[MLDSA87_SIG_LEN],
                      const mld_poly z_hat[MLD_L], const mld_poly *c_hat) {
    // The wide sampler's entries share their room with entry, which the
    // row reads after them, so the frame holds one polynomial fewer.
    mld_poly room[MLD_ROW_ROOM];
    mld_poly sum;
    if (!mld_row_sum(cpu, &sum, room, i, pk, z_hat)) {
        return 0;
    }
    mld_poly *entry = &room[0];
    mld_poly_unpack_t1_shifted(entry, pk + MLD_RHO_BYTES + (size_t)i * MLD_T1_BYTES);
    mld_ntt(cpu, entry);
    mld_pointwise(cpu, entry, c_hat, entry);
    mld_poly_sub(&sum, &sum, entry);
    mld_invntt_tomont(cpu, &sum);
    const uint8_t *y = sig + MLD_SIG_HINT_AT;
    unsigned first = i == 0 ? 0 : y[MLD_OMEGA + i - 1];
    unsigned end = y[MLD_OMEGA + i];
    mld_poly_use_hint(w1, &sum, y + first, end - first);
    return 1;
}

// mldsa87_challenge with every hash and every transform on cpu, the
// session's ch_cfg.cpu, or 0 for a call that holds none (mld_absorb,
// mld_ntt).
static int challenge(uint32_t cpu, uint8_t c_tilde[MLDSA87_CTILDE_LEN],
                     const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                     const uint8_t sig[MLDSA87_SIG_LEN]) {
    if (!mld_hints_well_formed(sig + MLD_SIG_HINT_AT)) {
        return 0;
    }
    mld_poly z_hat[MLD_L];
    for (unsigned j = 0; j < MLD_L; j++) {
        if (!mld_poly_unpack_z(&z_hat[j], sig + MLD_SIG_Z_AT + (size_t)j * MLD_Z_BYTES)) {
            return 0;
        }
        mld_ntt(cpu, &z_hat[j]);
    }
    mld_poly c_hat;
    if (!mld_sample_in_ball_cpu(cpu, &c_hat, sig)) {
        return 0;
    }
    mld_ntt(cpu, &c_hat);
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, mu, MLDSA_MU_LEN);
    for (unsigned i = 0; i < MLD_K; i++) {
        uint8_t w1[MLD_W1_BYTES];
        if (!mld_row_w1(cpu, w1, i, pk, sig, z_hat, &c_hat)) {
            return 0;
        }
        mld_absorb(cpu, &h, w1, sizeof w1);
    }
    mld_squeeze(cpu, &h, c_tilde, MLDSA87_CTILDE_LEN);
    return 1;
}

int mldsa87_challenge(uint8_t c_tilde[MLDSA87_CTILDE_LEN], const uint8_t pk[MLDSA87_PK_LEN],
                      const uint8_t mu[MLDSA_MU_LEN], const uint8_t sig[MLDSA87_SIG_LEN]) {
    return challenge(0, c_tilde, pk, mu, sig);
}

// mldsa87_verify with every hash on cpu, as challenge.
static int verify(uint32_t cpu, const uint8_t *pk, size_t pk_len, const uint8_t *msg,
                  size_t msg_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *sig,
                  size_t sig_len) {
    if (pk_len != MLDSA87_PK_LEN || sig_len != MLDSA87_SIG_LEN || ctx_len > MLDSA_CONTEXT_MAX) {
        return 0;
    }
    // tr = H(pk, 64), then mu = H(tr || M', 64), where M' is the domain
    // byte 0 for pure ML-DSA, the context's length, the context and the
    // message (FIPS 204 Algorithm 3 step 5, Algorithm 8 steps 6 and 7).
    uint8_t tr[64];
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, pk, MLDSA87_PK_LEN);
    mld_squeeze(cpu, &h, tr, sizeof tr);
    const uint8_t prefix[2] = {0, (uint8_t)ctx_len};
    uint8_t mu[MLDSA_MU_LEN];
    shake256_init(&h);
    mld_absorb(cpu, &h, tr, sizeof tr);
    mld_absorb(cpu, &h, prefix, sizeof prefix);
    mld_absorb(cpu, &h, ctx, ctx_len);
    mld_absorb(cpu, &h, msg, msg_len);
    mld_squeeze(cpu, &h, mu, sizeof mu);
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    if (!challenge(cpu, c_tilde, pk, mu, sig)) {
        return 0;
    }
    return ct_memeq(c_tilde, sig, MLDSA87_CTILDE_LEN) == 1;
}

int mldsa87_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len) {
    return verify(0, pk, pk_len, msg, msg_len, ctx, ctx_len, sig, sig_len);
}

#ifdef CH_CPU_RUNTIME
int mldsa87_verify_cpu(uint32_t cpu, const uint8_t *pk, size_t pk_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *sig,
                       size_t sig_len) {
    return verify(cpu, pk, pk_len, msg, msg_len, ctx, ctx_len, sig, sig_len);
}

int mldsa87_challenge_cpu(uint32_t cpu, uint8_t c_tilde[MLDSA87_CTILDE_LEN],
                          const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                          const uint8_t sig[MLDSA87_SIG_LEN]) {
    return challenge(cpu, c_tilde, pk, mu, sig);
}
#endif
