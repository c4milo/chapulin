// ML-KEM (FIPS 203): the post-quantum KEM chapulin offers in the TLS 1.3
// key_share. ML-KEM-768 sits beside x25519 in X25519MLKEM768, and
// ML-KEM-1024 stands alone under PROFILE=cnsa2 (docs/decisions.md 150).
// An object holds one parameter set or both. CH_MLKEM_1024 makes
// ML-KEM-1024 the object's rank, and its absence ML-KEM-768.
// CH_MLKEM_TWO_RANKS adds the other set beside it: the _rank calls then
// take the rank, 3 or 4, at run time (docs/decisions.md 177). Every
// server role outside PROFILE=cnsa2 selects either rank (srv_kex.h,
// docs/decisions.md 179), so CH_ROLE_SERVER sets the define below, and
// no build line has to.
//
// The entry points are derandomized: the caller supplies every random
// byte (d, z, m), because chapulin draws only at the sites INV-4 lists,
// through rand_draw (rand.h). keygen and encaps take their seeds as
// arguments; nothing here draws.
//
// The KEX=pq and TRUST=webpki builds and every server role package mlkem.c,
// mlkem_poly.c and sha3.c; a raw or ca client under KEX=x25519 compiles
// them into test binaries only.
#ifndef CH_MLKEM_H
#define CH_MLKEM_H

#if defined(CH_ROLE_SERVER) && !defined(CH_PROFILE_CNSA2) && !defined(CH_MLKEM_TWO_RANKS)
#define CH_MLKEM_TWO_RANKS
#endif

#include <stddef.h>
#include <stdint.h>

#include "sha3.h"

#define MLKEM_RANK_768 3  // the module rank k of ML-KEM-768
#define MLKEM_RANK_1024 4 // the module rank k of ML-KEM-1024
#define MLKEM_EK_LEN_768 1184
#define MLKEM_DK_LEN_768 2400
#define MLKEM_CT_LEN_768 1088
#define MLKEM_EK_LEN_1024 1568
#define MLKEM_DK_LEN_1024 3168
#define MLKEM_CT_LEN_1024 1568
#ifdef CH_MLKEM_1024
#define MLKEM_K MLKEM_RANK_1024        // the object's module rank
#define MLKEM_EK_LEN MLKEM_EK_LEN_1024 // encapsulation key (public)
#define MLKEM_DK_LEN MLKEM_DK_LEN_1024 // decapsulation key (secret)
#define MLKEM_CT_LEN MLKEM_CT_LEN_1024 // ciphertext
#else
#define MLKEM_K MLKEM_RANK_768        // the object's module rank
#define MLKEM_EK_LEN MLKEM_EK_LEN_768 // encapsulation key (public)
#define MLKEM_DK_LEN MLKEM_DK_LEN_768 // decapsulation key (secret)
#define MLKEM_CT_LEN MLKEM_CT_LEN_768 // ciphertext
#endif
// The largest rank the object runs, which sizes every vector on its stack.
#if defined(CH_MLKEM_TWO_RANKS) || defined(CH_MLKEM_1024)
#define MLKEM_K_MAX MLKEM_RANK_1024
#define MLKEM_EK_LEN_MAX MLKEM_EK_LEN_1024
#define MLKEM_DK_LEN_MAX MLKEM_DK_LEN_1024
#define MLKEM_CT_LEN_MAX MLKEM_CT_LEN_1024
#else
#define MLKEM_K_MAX MLKEM_RANK_768
#define MLKEM_EK_LEN_MAX MLKEM_EK_LEN_768
#define MLKEM_DK_LEN_MAX MLKEM_DK_LEN_768
#define MLKEM_CT_LEN_MAX MLKEM_CT_LEN_768
#endif
#define MLKEM_Q 3329    // field modulus
#define MLKEM_N 256     // polynomial degree
#define MLKEM_SS_LEN 32 // shared secret
// Where dk holds ek: after the K-PKE decryption key, 384 bytes per rank (FIPS 203 Algorithm 16).
#define MLKEM_DK_EK_AT ((size_t)384 * MLKEM_K)

// Whether the object runs ML-KEM at rank: its own rank, and under
// CH_MLKEM_TWO_RANKS the other one too.
static inline int mlkem_rank_held(unsigned rank) {
#ifdef CH_MLKEM_TWO_RANKS
    return rank == MLKEM_RANK_768 || rank == MLKEM_RANK_1024;
#else
    return rank == MLKEM_K;
#endif
}

// The byte lengths of ek, dk and ct at rank 3 or 4 (FIPS 203 Table 3).
static inline size_t mlkem_ek_len(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? MLKEM_EK_LEN_1024 : MLKEM_EK_LEN_768;
}

static inline size_t mlkem_dk_len(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? MLKEM_DK_LEN_1024 : MLKEM_DK_LEN_768;
}

static inline size_t mlkem_ct_len(unsigned rank) {
    return rank == MLKEM_RANK_1024 ? MLKEM_CT_LEN_1024 : MLKEM_CT_LEN_768;
}

// Derives (ek, dk) from a 32-byte d and 32-byte z (FIPS 203 Algorithm
// 16, ML-KEM.KeyGen_internal). d seeds the K-PKE key pair; z is the
// implicit-reject secret, copied into dk. Both functions write the same
// dk; mlkem_keygen_derand also copies the ek out. FIPS 203's dk layout
// carries the ek at dk + MLKEM_K * 384, so a caller that stores only the
// (d, z) seed calls mlkem_keygen_dk and reads its ek there, spending one
// dk-sized buffer instead of two.
void mlkem_keygen_dk(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                         const uint8_t z[32]);

// Encapsulates against a peer ek using a 32-byte message m (FIPS 203
// Algorithm 17, ML-KEM.Encaps_internal). Writes ct[MLKEM_CT_LEN] and ss[32].
// Returns 0 on success, nonzero if ek fails the FIPS 203 section 7.2
// modulus check (a coefficient at or above q). This call and
// mlkem_decaps take first the answer their compression runs under, a
// WIDEMUL_ value (widemul.h); key generation compresses nothing.
int mlkem_encaps_derand(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]);

// Decapsulates ct with dk (FIPS 203 Algorithm 18,
// ML-KEM.Decaps_internal). Always writes a 32-byte ss; on an invalid ct
// it writes the implicit-reject secret, selected in constant time. dk is
// trusted (locally generated), so it carries no modulus check.
void mlkem_decaps(uint8_t widemul, uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                  const uint8_t dk[MLKEM_DK_LEN]);

// The four calls above at the rank the caller names, 3 for ML-KEM-768 or 4
// for ML-KEM-1024. Each array holds the bytes mlkem_ek_len, mlkem_dk_len or
// mlkem_ct_len gives at that rank. The four calls above run these at
// MLKEM_K. Each has the contract of the call it is named for.
//
// Requires: mlkem_rank_held(rank). In an object that holds one rank, the
// call runs MLKEM_K whatever rank holds; under CH_MLKEM_TWO_RANKS it runs
// ML-KEM-1024 for 4 and ML-KEM-768 for any other value. So no rank makes a
// call read or write past the lengths of rank 4.
void mlkem_keygen_dk_rank(unsigned rank, uint8_t *dk, const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand_rank(unsigned rank, uint8_t *ek, uint8_t *dk, const uint8_t d[32],
                              const uint8_t z[32]);
int mlkem_encaps_derand_rank(uint8_t widemul, unsigned rank, uint8_t *ct, uint8_t ss[MLKEM_SS_LEN],
                             const uint8_t *ek, const uint8_t m[32]);
void mlkem_decaps_rank(uint8_t widemul, unsigned rank, uint8_t ss[MLKEM_SS_LEN], const uint8_t *ct,
                       const uint8_t *dk);

#ifdef CH_KECCAK_INSTRUCTIONS
// The eight calls above with every SHA-3 and SHAKE call on arm64's SHA-3
// instructions: mlkem.c and mlkem_poly.c compiled once more under
// keccak_hw.h's names (mlkem_hw.c, mlkem_poly_hw.c, docs/decisions.md 99).
// An arm64 host object that clang compiled holds them beside the four
// eight above (cpu_cfg.h). Each has the contract of the call it is named
// for.
//
// Requires: what that call requires, and a CPU with the instructions
// CH_CPU_CONSTANT_TIME_SHA3 names, which the session's caller states. On a
// CPU without them the first permutation faults.
void mlkem_keygen_dk_hw(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand_hw(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                            const uint8_t z[32]);
int mlkem_encaps_derand_hw(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                           const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]);
void mlkem_decaps_hw(uint8_t widemul, uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                     const uint8_t dk[MLKEM_DK_LEN]);
void mlkem_keygen_dk_rank_hw(unsigned rank, uint8_t *dk, const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand_rank_hw(unsigned rank, uint8_t *ek, uint8_t *dk, const uint8_t d[32],
                                 const uint8_t z[32]);
int mlkem_encaps_derand_rank_hw(uint8_t widemul, unsigned rank, uint8_t *ct,
                                uint8_t ss[MLKEM_SS_LEN], const uint8_t *ek, const uint8_t m[32]);
void mlkem_decaps_rank_hw(uint8_t widemul, unsigned rank, uint8_t ss[MLKEM_SS_LEN],
                          const uint8_t *ct, const uint8_t *dk);
#endif

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#include "cpu_cfg.h"

// The eight calls above with each row of the matrix sampled on four Keccak
// states side by side in AVX2: mlkem.c compiled once more under
// mlkem_avx2.h's names, with mlkem_avx2.c's row sampler (keccak_avx2.h,
// docs/decisions.md 107). An x86-64 host object holds them beside the
// eight above. Each has the contract of the call it is named for.
//
// Requires: what that call requires, and a CPU with AVX2, which the
// session's caller states in CH_CPU_AVX2. On a CPU without it the first
// permutation faults.
void mlkem_keygen_dk_avx2(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand_avx2(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN],
                              const uint8_t d[32], const uint8_t z[32]);
int mlkem_encaps_derand_avx2(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                             const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]);
void mlkem_decaps_avx2(uint8_t widemul, uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                       const uint8_t dk[MLKEM_DK_LEN]);
void mlkem_keygen_dk_rank_avx2(unsigned rank, uint8_t *dk, const uint8_t d[32],
                               const uint8_t z[32]);
void mlkem_keygen_derand_rank_avx2(unsigned rank, uint8_t *ek, uint8_t *dk, const uint8_t d[32],
                                   const uint8_t z[32]);
int mlkem_encaps_derand_rank_avx2(uint8_t widemul, unsigned rank, uint8_t *ct,
                                  uint8_t ss[MLKEM_SS_LEN], const uint8_t *ek, const uint8_t m[32]);
void mlkem_decaps_rank_avx2(uint8_t widemul, unsigned rank, uint8_t ss[MLKEM_SS_LEN],
                            const uint8_t *ct, const uint8_t *dk);
#endif

// A copy on the instructions (keccak_hw.h) or for the AVX2 Keccak
// (mlkem_avx2.h) reads the declarations above and none of the entries
// below, as sha3.h's copy does.
#if !defined(CH_KECCAK_HW_H) && !defined(CH_MLKEM_AVX2_H)
// The three calls a session makes at a rank, each with the session's
// ch_cfg.cpu first (CH_CFG_CPU, cpu.h). Where the object holds Keccak on the
// instructions and cpu holds CH_CPU_CONSTANT_TIME_SHA3, the call runs the
// copy on them. In an x86-64 host object, where cpu holds CH_CPU_AVX2, it
// runs the copy for the AVX2 Keccak. For any other session, and in any
// other object, it runs the _rank call above that it is named for.
#ifdef CH_KECCAK_INSTRUCTIONS
static inline void mlkem_keygen_dk_rank_cpu(uint32_t cpu, unsigned rank, uint8_t *dk,
                                            const uint8_t d[32], const uint8_t z[32]) {
    if (sha3_on_instructions(cpu)) {
        mlkem_keygen_dk_rank_hw(rank, dk, d, z);
        return;
    }
    mlkem_keygen_dk_rank(rank, dk, d, z);
}

static inline int mlkem_encaps_derand_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                               uint8_t *ct, uint8_t ss[MLKEM_SS_LEN],
                                               const uint8_t *ek, const uint8_t m[32]) {
    if (sha3_on_instructions(cpu)) {
        return mlkem_encaps_derand_rank_hw(widemul, rank, ct, ss, ek, m);
    }
    return mlkem_encaps_derand_rank(widemul, rank, ct, ss, ek, m);
}

static inline void mlkem_decaps_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                         uint8_t ss[MLKEM_SS_LEN], const uint8_t *ct,
                                         const uint8_t *dk) {
    if (sha3_on_instructions(cpu)) {
        mlkem_decaps_rank_hw(widemul, rank, ss, ct, dk);
        return;
    }
    mlkem_decaps_rank(widemul, rank, ss, ct, dk);
}
#elif defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// Whether a session samples the matrix on the four-way Keccak: where cpu,
// the session's ch_cfg.cpu, holds CH_CPU_AVX2. The bit states no timing,
// and the path reads public input alone (keccak_avx2.h).
static inline int mlkem_matrix_on_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0;
}

static inline void mlkem_keygen_dk_rank_cpu(uint32_t cpu, unsigned rank, uint8_t *dk,
                                            const uint8_t d[32], const uint8_t z[32]) {
    if (mlkem_matrix_on_avx2(cpu)) {
        mlkem_keygen_dk_rank_avx2(rank, dk, d, z);
        return;
    }
    mlkem_keygen_dk_rank(rank, dk, d, z);
}

static inline int mlkem_encaps_derand_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                               uint8_t *ct, uint8_t ss[MLKEM_SS_LEN],
                                               const uint8_t *ek, const uint8_t m[32]) {
    if (mlkem_matrix_on_avx2(cpu)) {
        return mlkem_encaps_derand_rank_avx2(widemul, rank, ct, ss, ek, m);
    }
    return mlkem_encaps_derand_rank(widemul, rank, ct, ss, ek, m);
}

static inline void mlkem_decaps_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                         uint8_t ss[MLKEM_SS_LEN], const uint8_t *ct,
                                         const uint8_t *dk) {
    if (mlkem_matrix_on_avx2(cpu)) {
        mlkem_decaps_rank_avx2(widemul, rank, ss, ct, dk);
        return;
    }
    mlkem_decaps_rank(widemul, rank, ss, ct, dk);
}
#else
static inline void mlkem_keygen_dk_rank_cpu(uint32_t cpu, unsigned rank, uint8_t *dk,
                                            const uint8_t d[32], const uint8_t z[32]) {
    (void)cpu;
    mlkem_keygen_dk_rank(rank, dk, d, z);
}

static inline int mlkem_encaps_derand_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                               uint8_t *ct, uint8_t ss[MLKEM_SS_LEN],
                                               const uint8_t *ek, const uint8_t m[32]) {
    (void)cpu;
    return mlkem_encaps_derand_rank(widemul, rank, ct, ss, ek, m);
}

static inline void mlkem_decaps_rank_cpu(uint32_t cpu, uint8_t widemul, unsigned rank,
                                         uint8_t ss[MLKEM_SS_LEN], const uint8_t *ct,
                                         const uint8_t *dk) {
    (void)cpu;
    mlkem_decaps_rank(widemul, rank, ss, ct, dk);
}
#endif

// The same three calls at MLKEM_K, the object's rank.
static inline void mlkem_keygen_dk_cpu(uint32_t cpu, uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                                       const uint8_t z[32]) {
    mlkem_keygen_dk_rank_cpu(cpu, MLKEM_K, dk, d, z);
}

static inline int mlkem_encaps_derand_cpu(uint32_t cpu, uint8_t widemul, uint8_t ct[MLKEM_CT_LEN],
                                          uint8_t ss[MLKEM_SS_LEN], const uint8_t ek[MLKEM_EK_LEN],
                                          const uint8_t m[32]) {
    return mlkem_encaps_derand_rank_cpu(cpu, widemul, MLKEM_K, ct, ss, ek, m);
}

static inline void mlkem_decaps_cpu(uint32_t cpu, uint8_t widemul, uint8_t ss[MLKEM_SS_LEN],
                                    const uint8_t ct[MLKEM_CT_LEN],
                                    const uint8_t dk[MLKEM_DK_LEN]) {
    mlkem_decaps_rank_cpu(cpu, widemul, MLKEM_K, ss, ct, dk);
}
#endif // !CH_KECCAK_HW_H && !CH_MLKEM_AVX2_H

#endif
