// ML-KEM-768 (FIPS 203): the post-quantum KEM chapulin offers alongside
// x25519 in the TLS 1.3 key_share. One parameter set, no negotiation.
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

#include <stdint.h>

#include "sha3.h"

#define MLKEM_K 3         // module rank
#define MLKEM_Q 3329      // field modulus
#define MLKEM_N 256       // polynomial degree
#define MLKEM_EK_LEN 1184 // encapsulation key (public)
#define MLKEM_DK_LEN 2400 // decapsulation key (secret)
#define MLKEM_CT_LEN 1088 // ciphertext
#define MLKEM_SS_LEN 32   // shared secret

// Derives (ek, dk) from a 32-byte d and 32-byte z (FIPS 203 Algorithm
// 16, ML-KEM.KeyGen_internal). d seeds the K-PKE key pair; z is the
// implicit-reject secret, copied into dk. Both functions write the same
// dk; mlkem_keygen_derand also copies the ek out. FIPS 203's dk layout
// carries the ek at dk + 1152, so a caller that stores only the (d, z)
// seed calls mlkem_keygen_dk and reads its ek there, spending one
// dk-sized buffer instead of two.
void mlkem_keygen_dk(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]);
void mlkem_keygen_derand(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                         const uint8_t z[32]);

// Encapsulates against a peer ek using a 32-byte message m (FIPS 203
// Algorithm 17, ML-KEM.Encaps_internal). Writes ct[1088] and ss[32].
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

#ifdef CH_KECCAK_INSTRUCTIONS
// The four calls above with every SHA-3 and SHAKE call on arm64's SHA-3
// instructions: mlkem.c and mlkem_poly.c compiled once more under
// keccak_hw.h's names (mlkem_hw.c, mlkem_poly_hw.c, docs/decisions.md 99).
// An arm64 host object that clang compiled holds them beside the four
// above (cpu_cfg.h). Each has the contract of the call it is named for.
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
#endif

// A copy on the instructions (keccak_hw.h) reads the declarations above
// and none of the entries below, as sha3.h's copy does.
#ifndef CH_KECCAK_HW_H
// The three calls a session makes, each with the session's ch_cfg.cpu
// first (CH_CFG_CPU, cpu.h). Where the object holds Keccak on the
// instructions and cpu holds CH_CPU_CONSTANT_TIME_SHA3, the call runs the
// copy on them. For any other session, and in any other object, it runs
// the call above that it is named for.
#ifdef CH_KECCAK_INSTRUCTIONS
static inline void mlkem_keygen_dk_cpu(uint32_t cpu, uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                                       const uint8_t z[32]) {
    if (sha3_on_instructions(cpu)) {
        mlkem_keygen_dk_hw(dk, d, z);
        return;
    }
    mlkem_keygen_dk(dk, d, z);
}

static inline int mlkem_encaps_derand_cpu(uint32_t cpu, uint8_t widemul, uint8_t ct[MLKEM_CT_LEN],
                                          uint8_t ss[MLKEM_SS_LEN], const uint8_t ek[MLKEM_EK_LEN],
                                          const uint8_t m[32]) {
    if (sha3_on_instructions(cpu)) {
        return mlkem_encaps_derand_hw(widemul, ct, ss, ek, m);
    }
    return mlkem_encaps_derand(widemul, ct, ss, ek, m);
}

static inline void mlkem_decaps_cpu(uint32_t cpu, uint8_t widemul, uint8_t ss[MLKEM_SS_LEN],
                                    const uint8_t ct[MLKEM_CT_LEN],
                                    const uint8_t dk[MLKEM_DK_LEN]) {
    if (sha3_on_instructions(cpu)) {
        mlkem_decaps_hw(widemul, ss, ct, dk);
        return;
    }
    mlkem_decaps(widemul, ss, ct, dk);
}
#else
static inline void mlkem_keygen_dk_cpu(uint32_t cpu, uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                                       const uint8_t z[32]) {
    (void)cpu;
    mlkem_keygen_dk(dk, d, z);
}

static inline int mlkem_encaps_derand_cpu(uint32_t cpu, uint8_t widemul, uint8_t ct[MLKEM_CT_LEN],
                                          uint8_t ss[MLKEM_SS_LEN], const uint8_t ek[MLKEM_EK_LEN],
                                          const uint8_t m[32]) {
    (void)cpu;
    return mlkem_encaps_derand(widemul, ct, ss, ek, m);
}

static inline void mlkem_decaps_cpu(uint32_t cpu, uint8_t widemul, uint8_t ss[MLKEM_SS_LEN],
                                    const uint8_t ct[MLKEM_CT_LEN],
                                    const uint8_t dk[MLKEM_DK_LEN]) {
    (void)cpu;
    mlkem_decaps(widemul, ss, ct, dk);
}
#endif
#endif // CH_KECCAK_HW_H

#endif
