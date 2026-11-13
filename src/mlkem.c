// ML-KEM (FIPS 203), at the ranks mlkem.h's mlkem_rank_held names: K-PKE
// (Algorithms 13-15) and the Fujisaki-Okamoto KEM wrapper (Algorithms
// 16-18) around it. Every function takes the rank mlk_rank returned, so
// each loop runs over the first rank polys of a vector.
//
// G = SHA3-512, H = SHA3-256, J = SHAKE256(32), PRF and XOF are SHAKE.
// Every secret stack buffer is wiped before return. The one implicit
// reject select is branchless masked arithmetic over 32 bytes.
#include "mlkem.h"

#include <string.h>

#include "ct.h"
#include "mlkem_neon.h"
#include "mlkem_poly.h"
#include "mlkem_vector.h"
#include "sha3.h"
#include "widemul.h"

// The K-PKE secret key, ByteEncode12 of s-hat, and the t-hat of an ek: the
// rank polys at 384 bytes each.
static size_t mlk_polyvec_bytes(unsigned rank) {
    return (size_t)MLK_POLY_BYTES * rank;
}

// Where FIPS 203's dk = dkpke || ek || H(ek) || z holds each part.
static size_t mlk_dk_ek_at(unsigned rank) {
    return mlk_polyvec_bytes(rank);
}

static size_t mlk_dk_h_at(unsigned rank) {
    return mlk_dk_ek_at(rank) + mlkem_ek_len(rank);
}

static size_t mlk_dk_z_at(unsigned rank) {
    return mlk_dk_h_at(rank) + 32;
}

_Static_assert((size_t)MLK_POLY_BYTES * MLKEM_RANK_768 * 2 + 32 + 32 + 32 == MLKEM_DK_LEN_768,
               "dk holds dkpke, ek, H(ek) and z");
_Static_assert((size_t)MLK_POLY_BYTES * MLKEM_RANK_1024 * 2 + 32 + 32 + 32 == MLKEM_DK_LEN_1024,
               "dk holds dkpke, ek, H(ek) and z");
_Static_assert((size_t)MLK_POLY_BYTES *MLKEM_RANK_768 + 32 == MLKEM_EK_LEN_768,
               "ek holds t-hat and rho");
_Static_assert((size_t)MLK_POLY_BYTES *MLKEM_RANK_1024 + 32 == MLKEM_EK_LEN_1024,
               "ek holds t-hat and rho");
_Static_assert(32 * 10 * MLKEM_RANK_768 + 32 * 4 == MLKEM_CT_LEN_768, "ct holds u and v");
_Static_assert(32 * 11 * MLKEM_RANK_1024 + 32 * 5 == MLKEM_CT_LEN_1024, "ct holds u and v");
_Static_assert(MLKEM_DK_EK_AT == (size_t)MLK_POLY_BYTES * MLKEM_K, "mlkem.h's ek offset");

// The forward and inverse NTT, the base multiplication and the sum this
// object runs.
// A host object runs them on eight lanes at a time (mlkem_vector.h) in
// every session. A device object runs mlkem_poly.c's loops, which CBMC
// proves and which bin/mlkem_vector_equiv_test holds the vector path to.
// mlkem_poly.c compiles to the same code in both objects
// (test/widemul-builds.sh), so the choice is made here.
static void mlk_ntt(mlk_poly *p) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_ntt(p);
#else
    mlk_poly_ntt(p);
#endif
}

static void mlk_invntt(mlk_poly *p) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_invntt(p);
#else
    mlk_poly_invntt(p);
#endif
}

static void mlk_multiply_ntts(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_basemul(r, a, b);
#else
    mlk_poly_basemul(r, a, b);
#endif
}

static void mlk_add(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_add(r, a, b);
#else
    mlk_poly_add(r, a, b);
#endif
}

// The Barrett reduction of every coefficient. A host object runs it on
// eight lanes at a time, whose 16x16 multiplies are those of the NTT
// (docs/decisions.md 232).
static void mlk_reduce(mlk_poly *p) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_reduce(p);
#else
    mlk_poly_reduce(p);
#endif
}

// Decompress_1 of the message into p. A host object runs it on eight lanes
// at a time, one byte of the message a step (docs/decisions.md 232).
static void mlk_frommsg(mlk_poly *p, const uint8_t msg[32]) {
#ifdef CH_CPU_RUNTIME
    mlk_vector_frommsg(p, msg);
#else
    mlk_poly_frommsg(p, msg);
#endif
}

// Compress_du and Compress_dv of a polynomial into the ciphertext under the
// answer widemul. mlkem_avx2.c's copy runs rank 3's on AVX2's 32x32
// products where the answer states the multiply (docs/decisions.md 232).
// The answer and the rank are public.
static void mlk_compress_du(uint8_t widemul, uint8_t *out, const mlk_poly *p, unsigned rank) {
#if defined(CH_MLKEM_AVX2_COPY) && MLK_HOLDS_768
    if (widemul_native(widemul) && rank == MLKEM_RANK_768) {
        mlk_poly_compress_10_avx2(out, p);
        return;
    }
#endif
    widemul_mlk_poly_compress_du(widemul, out, p, rank);
}

static void mlk_compress_dv(uint8_t widemul, uint8_t *out, const mlk_poly *p, unsigned rank) {
#if defined(CH_MLKEM_AVX2_COPY) && MLK_HOLDS_768
    if (widemul_native(widemul) && rank == MLKEM_RANK_768) {
        mlk_poly_compress_4_avx2(out, p);
        return;
    }
#endif
    widemul_mlk_poly_compress(widemul, out, p, rank);
}

// ByteDecode12 of 384 bytes into p: t-hat from an ek and s-hat from a dk.
// mlkem_avx2.c's copy reads 16 fields a step on AVX2 (docs/decisions.md
// 232). Both read the fields as shifts and masks of bytes, with no
// branch, so a secret s-hat takes either.
static void mlk_frombytes(mlk_poly *p, const uint8_t in[MLK_POLY_BYTES]) {
#ifdef CH_MLKEM_AVX2_COPY
    mlk_poly_frombytes_avx2(p, in);
#else
    mlk_poly_frombytes(p, in);
#endif
}

// The noise of nonce into p: SamplePolyCBD_2 of PRF(seed, nonce) (FIPS 203
// Algorithm 8). A device object runs mlk_sample_cbd. A host object
// squeezes the same PRF stream as mlk_sample_cbd and runs the centered
// binomial step on lanes (mlk_vector_noise, docs/decisions.md 225). The
// stream and the sponge hold the secret seed's output, so both are wiped.
static void mlk_noise(mlk_poly *p, const uint8_t seed[32], uint8_t nonce) {
#ifdef CH_CPU_RUNTIME
    shake s;
    uint8_t stream[MLK_CBD_BYTES];
    shake256_init(&s);
    shake_absorb(&s, seed, 32);
    shake_absorb(&s, &nonce, 1);
    shake_squeeze(&s, stream, sizeof stream);
    mlk_vector_noise(p, stream);
    ct_wipe(stream, sizeof stream);
    ct_wipe(&s, sizeof s);
#else
    mlk_sample_cbd(p, seed, nonce);
#endif
}

// out = a o b for the first term of an NTT-domain dot product, and out +=
// a o b for each later one. The result keeps the Montgomery R^-1 factor
// that basemul introduces. prod holds a product with a secret operand, so
// it is wiped.
static void mlk_dot_term(mlk_poly *out, const mlk_poly *a, const mlk_poly *b, unsigned j) {
    mlk_poly prod;
    mlk_multiply_ntts(&prod, a, b);
    if (j == 0) {
        *out = prod;
    } else {
        mlk_add(out, out, &prod);
    }
    ct_wipe(&prod, sizeof prod);
}

// mlkem_avx2.c compiles this file once more for an x86-64 host object,
// whose sessions with CH_CPU_AVX2 sample each row's three entries side by
// side (docs/decisions.md 107). That copy defines CH_MLKEM_AVX2_COPY and
// supplies mlk_matvec_row, so the text between the #ifndef below and its
// #endif is this file's alone.
#ifndef CH_MLKEM_AVX2_COPY
#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)
// The form of the two-way Keccak this copy runs (mlkem_neon.h). mlkem_hw.c compiles this file
// for sessions whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_SHA3 (keccak_hw.h), and so runs the
// form on the SHA-3 instructions. This file under its own names runs plain NEON.
#ifdef CH_KECCAK_HW_H
#define MLK_NEON_CPU CH_CPU_CONSTANT_TIME_SHA3
#else
#define MLK_NEON_CPU 0U
#endif

// out = row i of A o s, or of A^T o s where transposed is 1, as the function below computes
// it, in an arm64 host object (docs/decisions.md 198). The row's entries are sampled two at a
// time on two Keccak states side by side, and an entry left over runs mlk_sample_ntt alone,
// which takes less time than two states with one unread. The entries are public. mlk_dot_term
// wipes each product with the secret vector.
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s, unsigned rank) {
    mlk_poly a[MLK_NEON_ENTRIES];
    for (unsigned j = 0; j < rank; j += MLK_NEON_ENTRIES) {
        unsigned count = MLK_NEON_ENTRIES;
        if (rank - j < MLK_NEON_ENTRIES) {
            uint8_t x0 = transposed ? (uint8_t)i : (uint8_t)j;
            uint8_t x1 = transposed ? (uint8_t)j : (uint8_t)i;
            mlk_sample_ntt(&a[0], seed, x0, x1);
            count = 1;
        } else {
            mlk_sample_pair_neon(a, seed, i, transposed, j, MLK_NEON_CPU);
        }
        for (unsigned k = 0; k < count; k++) {
            mlk_dot_term(out, &a[k], &s->vec[j + k], j + k);
        }
    }
}
#else
// out = row i of A o s, expanding A one entry at a time from the public
// seed. FIPS 203 samples A[i][j] from rho || j || i, so keygen
// (transposed = 0) reads row i of A and encrypt (transposed = 1) reads
// row i of A^T; the index bytes are public, so the choice is not a
// secret-dependent branch. prod holds products of a public matrix entry
// with the secret vector, so it is wiped; a is public.
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s, unsigned rank) {
    mlk_poly a;
    mlk_poly prod;
    for (unsigned j = 0; j < rank; j++) {
        uint8_t x0 = transposed ? (uint8_t)i : (uint8_t)j;
        uint8_t x1 = transposed ? (uint8_t)j : (uint8_t)i;
        mlk_sample_ntt(&a, seed, x0, x1);
        mlk_multiply_ntts(&prod, &a, &s->vec[j]);
        if (j == 0) {
            *out = prod;
        } else {
            mlk_add(out, out, &prod);
        }
    }
    ct_wipe(&prod, sizeof prod);
}
#endif // CH_CPU_RUNTIME && __aarch64__
#endif // CH_MLKEM_AVX2_COPY

// K-PKE.KeyGen (Algorithm 13). Writes ek (t-hat || rho) and the K-PKE
// secret key dkpke (s-hat). sigma and the secret vectors are wiped.
static void mlk_pke_keygen(unsigned rank, uint8_t *ek, uint8_t *dkpke, const uint8_t d[32]) {
    uint8_t gin[33];
    uint8_t g[64];
    mlk_polyvec s;
    mlk_poly e;
    mlk_poly t;
    memcpy(gin, d, 32);
    gin[32] = (uint8_t)rank;
    sha3_512(gin, 33, g); // (rho, sigma) = G(d || k)
    const uint8_t *rho = g;
    const uint8_t *sigma = g + 32;
    // rho is public: ek carries it, and A's rejection sampling branches on
    // the bytes it expands to.
    CT_DECLASSIFY(g, 32);
    for (unsigned i = 0; i < rank; i++) {
        mlk_noise(&s.vec[i], sigma, (uint8_t)i);
        mlk_ntt(&s.vec[i]);
    }
    // Row i of t needs entry i of e alone, so e and t take one poly at a
    // time. Each entry of e comes from its own nonce, so the order of the
    // draws changes no value.
    for (unsigned i = 0; i < rank; i++) {
        mlk_matvec_row(&t, rho, i, 0, &s, rank); // t = A o s (with R^-1)
        mlk_poly_tomont(&t);                     // undo the R^-1
        mlk_noise(&e, sigma, (uint8_t)(rank + i));
        mlk_ntt(&e);
        mlk_add(&t, &t, &e);
        mlk_reduce(&t);
        mlk_poly_tobytes(ek + (size_t)384 * i, &t);
        mlk_poly_tobytes(dkpke + (size_t)384 * i, &s.vec[i]);
    }
    memcpy(ek + mlk_polyvec_bytes(rank), rho, 32);
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    ct_wipe(&s, sizeof s);
    ct_wipe(&e, sizeof e);
}

// K-PKE.Encrypt (Algorithm 14). coins seeds the noise; m is the 32-byte
// message. Writes the mlkem_ct_len(rank)-byte ciphertext. widemul is the
// answer the compression runs under (widemul.h).
static void mlk_pke_encrypt(uint8_t widemul, unsigned rank, uint8_t *ct, const uint8_t *ek,
                            const uint8_t m[32], const uint8_t coins[32]) {
    const uint8_t *rho = ek + mlk_polyvec_bytes(rank);
    mlk_poly t;
    mlk_polyvec r;
    mlk_poly u;
    mlk_poly v;
    mlk_poly noise;
    // v starts as t o r (with R^-1), one term for each entry of r as it is
    // sampled, so t takes one poly at a time.
    for (unsigned i = 0; i < rank; i++) {
        mlk_frombytes(&t, ek + (size_t)384 * i);
        mlk_noise(&r.vec[i], coins, (uint8_t)i);
        mlk_ntt(&r.vec[i]);
        mlk_dot_term(&v, &t, &r.vec[i], i);
    }
    // Entry i of u goes into the ciphertext as soon as it is computed, so u
    // takes one poly at a time.
    for (unsigned i = 0; i < rank; i++) {
        mlk_matvec_row(&u, rho, i, 1, &r, rank); // A^T o r (with R^-1)
        mlk_invntt(&u);                          // inverse NTT absorbs R^-1
        mlk_noise(&noise, coins, (uint8_t)(rank + i));
        mlk_add(&u, &u, &noise); // + e1
        mlk_reduce(&u);
        mlk_compress_du(widemul, ct + mlk_poly_comp_du_bytes(rank) * i, &u, rank);
    }
    mlk_invntt(&v);
    mlk_noise(&noise, coins, (uint8_t)(2 * rank)); // e2
    mlk_add(&v, &v, &noise);
    mlk_frommsg(&noise, m); // Decompress1(m)
    mlk_add(&v, &v, &noise);
    mlk_reduce(&v);
    mlk_compress_dv(widemul, ct + mlk_polyvec_comp_bytes(rank), &v, rank);
    // u and v are published only compressed; the low bits the
    // compression drops depend on the secret noise, so both are wiped.
    ct_wipe(&r, sizeof r);
    ct_wipe(&u, sizeof u);
    ct_wipe(&v, sizeof v);
    ct_wipe(&noise, sizeof noise);
}

// K-PKE.Decrypt (Algorithm 15). Recovers the 32-byte message from a
// ciphertext and the K-PKE secret key, and compresses the message under the
// answer widemul.
static void mlk_pke_decrypt(uint8_t widemul, unsigned rank, uint8_t m[32], const uint8_t *dkpke,
                            const uint8_t *ct) {
    mlk_poly u;
    mlk_poly s;
    mlk_poly v;
    mlk_poly w;
    mlk_poly_decompress(&v, ct + mlk_polyvec_comp_bytes(rank), rank);
    // w = s o NTT(u) (with R^-1), one term for each entry of u and s, so
    // each takes one poly at a time.
    for (unsigned i = 0; i < rank; i++) {
        mlk_poly_decompress_du(&u, ct + mlk_poly_comp_du_bytes(rank) * i, rank);
        mlk_ntt(&u);
        mlk_frombytes(&s, dkpke + (size_t)384 * i);
        mlk_dot_term(&w, &s, &u, i);
    }
    mlk_invntt(&w);           // inverse NTT absorbs R^-1
    mlk_poly_sub(&w, &v, &w); // v - s o u
    mlk_reduce(&w);
    widemul_mlk_poly_tomsg(widemul, m, &w);
    ct_wipe(&s, sizeof s);
    ct_wipe(&w, sizeof w);
}

// FIPS 203 section 7.2 modulus check: every 12-bit field of the encoded
// t-hat must be a valid Z_q element. ByteDecode12 reduces mod q, so a
// field at or above q would not round-trip. Reads only the public ek, so
// the value-dependent branch leaks nothing. Returns nonzero on failure.
// mlkem_avx2.c's copy reads 16 fields a step on AVX2 (docs/decisions.md
// 232).
static int mlk_modulus_check(const uint8_t *ek, unsigned rank) {
    size_t t_bytes = mlk_polyvec_bytes(rank);
#ifdef CH_MLKEM_AVX2_COPY
    return mlk_field_at_or_above_q_avx2(ek, t_bytes);
#else
    for (size_t i = 0; i < t_bytes; i += 3) {
        uint16_t lo = (uint16_t)((ek[i] | ((uint16_t)ek[i + 1] << 8)) & 0xfff);
        uint16_t hi = (uint16_t)(((ek[i + 1] >> 4) | ((uint16_t)ek[i + 2] << 4)) & 0xfff);
        if (lo >= MLKEM_Q || hi >= MLKEM_Q) {
            return 1;
        }
    }
    return 0;
#endif
}

// K_bar = J(z || ct) = SHAKE256(z || ct, 32), the implicit-reject secret.
static void mlk_reject_secret(uint8_t out[32], const uint8_t z[32], const uint8_t *ct,
                              unsigned rank) {
    shake s;
    shake256_init(&s);
    shake_absorb(&s, z, 32);
    shake_absorb(&s, ct, mlkem_ct_len(rank));
    shake_squeeze(&s, out, 32);
    ct_wipe(&s, sizeof s);
}

void mlkem_keygen_dk_rank(unsigned rank, uint8_t *dk, const uint8_t d[32], const uint8_t z[32]) {
    rank = mlk_rank(rank);
    // dk = dkpke || ek || H(ek) || z, the ek written in place at
    // mlk_dk_ek_at: a caller that stores only the (d, z) seed re-expands
    // into one dk-sized buffer and reads the ek out of the slice.
    mlk_pke_keygen(rank, dk + mlk_dk_ek_at(rank), dk, d);
    sha3_256(dk + mlk_dk_ek_at(rank), mlkem_ek_len(rank), dk + mlk_dk_h_at(rank));
    memcpy(dk + mlk_dk_z_at(rank), z, 32);
}

void mlkem_keygen_derand_rank(unsigned rank, uint8_t *ek, uint8_t *dk, const uint8_t d[32],
                              const uint8_t z[32]) {
    rank = mlk_rank(rank);
    mlkem_keygen_dk_rank(rank, dk, d, z);
    memcpy(ek, dk + mlk_dk_ek_at(rank), mlkem_ek_len(rank));
}

int mlkem_encaps_derand_rank(uint8_t widemul, unsigned rank, uint8_t *ct, uint8_t ss[MLKEM_SS_LEN],
                             const uint8_t *ek, const uint8_t m[32]) {
    rank = mlk_rank(rank);
    if (mlk_modulus_check(ek, rank) != 0) {
        return 1;
    }
    uint8_t gin[64]; // m || H(ek)
    uint8_t g[64];   // (K, r)
    memcpy(gin, m, 32);
    sha3_256(ek, mlkem_ek_len(rank), gin + 32);
    sha3_512(gin, 64, g);
    mlk_pke_encrypt(widemul, rank, ct, ek, m, g + 32); // coins = r
    memcpy(ss, g, 32);                                 // shared secret = K
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    return 0;
}

void mlkem_decaps_rank(uint8_t widemul, unsigned rank, uint8_t ss[MLKEM_SS_LEN], const uint8_t *ct,
                       const uint8_t *dk) {
    rank = mlk_rank(rank);
    const uint8_t *dkpke = dk;
    const uint8_t *ek = dk + mlk_dk_ek_at(rank);
    const uint8_t *h = dk + mlk_dk_h_at(rank); // H(ek)
    const uint8_t *z = dk + mlk_dk_z_at(rank);
    size_t ct_len = mlkem_ct_len(rank);
    uint8_t mp[32];
    uint8_t gin[64]; // m' || h
    uint8_t g[64];   // (K', r')
    uint8_t kbar[32];
    uint8_t ct2[MLKEM_CT_LEN_MAX];
    mlk_pke_decrypt(widemul, rank, mp, dkpke, ct);
    memcpy(gin, mp, 32);
    memcpy(gin + 32, h, 32);
    sha3_512(gin, 64, g);
    mlk_reject_secret(kbar, z, ct, rank);
    mlk_pke_encrypt(widemul, rank, ct2, ek, mp, g + 32); // re-encrypt with r'
    // ss = (ct == ct2) ? K' : K_bar, selected in constant time.
    uint32_t eq = ct_memeq(ct, ct2, ct_len);
    uint8_t keep = (uint8_t)(-(uint8_t)eq); // 0xff on match, 0x00 otherwise
    for (unsigned i = 0; i < 32; i++) {
        ss[i] = (uint8_t)((g[i] & keep) | (kbar[i] & (uint8_t)~keep));
    }
    ct_wipe(mp, sizeof mp);
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    ct_wipe(kbar, sizeof kbar);
    ct_wipe(ct2, sizeof ct2);
}

void mlkem_keygen_dk(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]) {
    mlkem_keygen_dk_rank(MLKEM_K, dk, d, z);
}

void mlkem_keygen_derand(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                         const uint8_t z[32]) {
    mlkem_keygen_derand_rank(MLKEM_K, ek, dk, d, z);
}

int mlkem_encaps_derand(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    return mlkem_encaps_derand_rank(widemul, MLKEM_K, ct, ss, ek, m);
}

void mlkem_decaps(uint8_t widemul, uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                  const uint8_t dk[MLKEM_DK_LEN]) {
    mlkem_decaps_rank(widemul, MLKEM_K, ss, ct, dk);
}
