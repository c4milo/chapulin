// NIST P-384 field and scalar arithmetic on six 64-bit limbs:
// p384_field.h's routines, one for one, at twice the limb width, every
// product one ct_mul128, the 64x64->128 multiply ct.h defines for a host
// object alone. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it, and
// a device object holds none of it: p384_field.c's 32-bit limbs are what a
// device object runs, and they stay the reference that
// bin/p384_equiv_test compares this file with (docs/decisions.md 97).
//
// Variable time on purpose — every input is public (see p384.h), so the
// multiply's timing needs no statement from anybody. Its caller is
// p384_wide_verify.c, in every session of a host object.
#ifndef CH_P384_WIDE_FIELD_H
#define CH_P384_WIDE_FIELD_H

#include <stdint.h>

#include "p384_field.h" // P384_LEN

#ifdef CH_CPU_RUNTIME

#define P384_WIDE_LIMBS 6 // 64-bit limbs in one 384-bit number

typedef struct {
    uint64_t m[P384_WIDE_LIMBS];  // the modulus
    uint64_t r2[P384_WIDE_LIMBS]; // 2^768 mod m, which moves a number into the Montgomery domain
    uint64_t m0inv;               // -m^-1 mod 2^64
} p384_wide_modulus;

// SEC 2 secp384r1: the field prime p and the group order n.
extern const p384_wide_modulus p384_wide_modp;
extern const p384_wide_modulus p384_wide_modn;

// Predicates: pure, no reduction.
int p384_wide_is_zero(const uint64_t a[P384_WIDE_LIMBS]);
int p384_wide_compare(const uint64_t a[P384_WIDE_LIMBS], const uint64_t b[P384_WIDE_LIMBS]);

// 48 big-endian bytes -> 6 little-endian limbs, byte by byte.
void p384_wide_from_bytes(uint64_t o[P384_WIDE_LIMBS], const uint8_t b[P384_LEN]);

// Plain add and subtract over the limbs; the return value is the carry
// out or the borrow out, 0 or 1. o may alias a or b.
uint64_t p384_wide_add_raw(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                           const uint64_t b[P384_WIDE_LIMBS]);
uint64_t p384_wide_sub_raw(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                           const uint64_t b[P384_WIDE_LIMBS]);

// Modular arithmetic. Inputs below mod->m, results below mod->m; o may
// alias a or b in every routine.
void p384_wide_mod_add(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                       const uint64_t b[P384_WIDE_LIMBS], const p384_wide_modulus *mod);
void p384_wide_mod_sub(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                       const uint64_t b[P384_WIDE_LIMBS], const p384_wide_modulus *mod);
// Montgomery product o = a*b / 2^384 mod m.
void p384_wide_mont_mul(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                        const uint64_t b[P384_WIDE_LIMBS], const p384_wide_modulus *mod);
// Plain product o = a*b mod m.
void p384_wide_mod_mul(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                       const uint64_t b[P384_WIDE_LIMBS], const p384_wide_modulus *mod);
// o = a^-1 mod m by Fermat; a must be non-zero.
void p384_wide_mod_inverse(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                           const p384_wide_modulus *mod);

#endif // CH_CPU_RUNTIME

#endif
