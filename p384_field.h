// NIST P-384 field and scalar arithmetic for p384.c: the limb layout,
// the two moduli (the field prime p and the group order n) and the
// modular routines both share. Variable time on purpose — every input
// is public (see p384.h). Elements are 12 little-endian uint32 limbs;
// products and carries live in uint64. This is p256.c's arithmetic at
// 12 limbs instead of 8, split into its own pair so p384.c stays under
// the file budget.
#ifndef CH_P384_FIELD_H
#define CH_P384_FIELD_H

#include <stdint.h>

#define P384_LIMBS 12 // limb: one 32-bit word of a big number; P-384 = 12 limbs
#define P384_LEN 48   // bytes in one coordinate or one scalar

typedef struct {
    uint32_t m[P384_LIMBS];  // the modulus
    uint32_t r2[P384_LIMBS]; // 2^768 mod m, entry ticket to the Montgomery domain
    uint32_t m0inv;          // -m^-1 mod 2^32
} p384_modulus;

// SEC 2 secp384r1: the field prime p and the group order n.
extern const p384_modulus p384_modp;
extern const p384_modulus p384_modn;

// Predicates: pure, no reduction.
int p384_is_zero(const uint32_t a[P384_LIMBS]);
int p384_compare(const uint32_t a[P384_LIMBS], const uint32_t b[P384_LIMBS]);

// 48 big-endian bytes -> 12 little-endian limbs, byte by byte.
void p384_from_bytes(uint32_t o[P384_LIMBS], const uint8_t b[P384_LEN]);

// Plain add and subtract over the limbs; the return value is the carry
// out or the borrow out. o may alias a or b.
uint32_t p384_add_raw(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const uint32_t b[P384_LIMBS]);
uint32_t p384_sub_raw(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const uint32_t b[P384_LIMBS]);

// Modular arithmetic. Inputs below mod->m, results below mod->m; o may
// alias a or b in every routine.
void p384_mod_add(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod);
void p384_mod_sub(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod);
// Montgomery product o = a*b / 2^384 mod m.
void p384_mont_mul(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                   const uint32_t b[P384_LIMBS], const p384_modulus *mod);
// Plain product o = a*b mod m.
void p384_mod_mul(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod);
// o = a^-1 mod m by Fermat; a must be non-zero.
void p384_mod_inverse(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const p384_modulus *mod);

#endif
