// ML-KEM-768 (FIPS 203): the post-quantum KEM chapulin offers alongside
// x25519 in the TLS 1.3 key_share. One parameter set, no negotiation.
//
// The entry points are derandomized: the caller supplies every random
// byte (d, z, m), because randomness in chapulin is consumed only at the
// audited sites in handshake.c (INV-4). keygen and encaps take their
// seeds as arguments; nothing here calls ch_rand_bytes.
//
// The KEX=pq build packages mlkem.c, mlkem_poly.c, and sha3.c into the
// library object; every other build compiles them into test binaries
// only.
#ifndef CH_MLKEM_H
#define CH_MLKEM_H

#include <stdint.h>

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
// modulus check (a coefficient at or above q).
int mlkem_encaps_derand(uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]);

// Decapsulates ct with dk (FIPS 203 Algorithm 18,
// ML-KEM.Decaps_internal). Always writes a 32-byte ss; on an invalid ct
// it writes the implicit-reject secret, selected in constant time. dk is
// trusted (locally generated), so it carries no modulus check.
void mlkem_decaps(uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                  const uint8_t dk[MLKEM_DK_LEN]);

#endif
