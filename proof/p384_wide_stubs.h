// The contracts the p384_wide_point and p384_wide_digits harnesses replace
// the field's three arithmetic routines with. A harness reads this
// header and then p384_wide_point.c, which calls the contracts under the
// routines' names.
//
// WHAT THE STUBS MODEL: p384_wide_mont_mul, p384_wide_mod_add and
// p384_wide_mod_sub each assert that both operands are below p, the
// contract p384_wide_field.h states for them, and write any words below
// p. So a harness over them proves that p384_wide_point.c hands the field
// nothing but reduced operands, and proves its own memory accesses for
// every value a result can take.
//
// WHAT DISCHARGES THE CONTRACT: proof/p384_wide_field_harness.c runs the
// three routines' real bodies for their memory accesses and their sums.
// That a result is below p is the Montgomery reduction's and the
// conditional subtraction's arithmetic, which no harness proves:
// bin/p384_equiv_test holds each routine to p384_field.c's result.
//
// The predicates, the byte reader and the plain sum run on
// p384_wide_field.c's real bodies, so "below p" here is the comparison
// the code makes. The macros give the three replaced routines' real
// bodies other names while the file is read.
#ifndef CH_P384_WIDE_STUBS_H
#define CH_P384_WIDE_STUBS_H

#include "harness.h"

#include <string.h>

// The field's real bodies under other names for the three routines the
// contracts below replace, and under their own for the rest.
#define p384_wide_mont_mul real_mont_mul
#define p384_wide_mod_add real_mod_add
#define p384_wide_mod_sub real_mod_sub
#include "p384_wide_field.c"
#undef p384_wide_mont_mul
#undef p384_wide_mod_add
#undef p384_wide_mod_sub

uint64_t nondet_u64(void);
int nondet_int(void);

static int below(const uint64_t a[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    return p384_wide_compare(a, mod->m) < 0;
}

// Any words below the modulus.
static void havoc_below(uint64_t o[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    for (size_t i = 0; i < P384_WIDE_WORDS; i++) {
        o[i] = nondet_u64();
    }
    __CPROVER_assume(below(o, mod));
}

// p384_wide_field.h: inputs below mod->m, results below mod->m, and o may
// alias a or b. The two comparisons read all six words of each operand
// and havoc_below writes all six of the result, so cbmc's own pointer
// checks on those accesses hold the three arrays to their length.
static void contract(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                     const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    __CPROVER_assert(mod == &p384_wide_modp, "field stub: the points compute modulo p alone");
    __CPROVER_assert(below(a, mod) && below(b, mod), "field stub: both operands are below p");
    havoc_below(o, mod);
}

void p384_wide_mont_mul(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                        const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    contract(o, a, b, mod);
}

void p384_wide_mod_add(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                       const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    contract(o, a, b, mod);
}

void p384_wide_mod_sub(uint64_t o[P384_WIDE_WORDS], const uint64_t a[P384_WIDE_WORDS],
                       const uint64_t b[P384_WIDE_WORDS], const p384_wide_modulus *mod) {
    contract(o, a, b, mod);
}

#include "p384_wide_point.h"

// Any point an entry of the file can write: three coordinates below p.
static void havoc_point(p384_wide_point *o) {
    havoc_below(o->x, &p384_wide_modp);
    havoc_below(o->y, &p384_wide_modp);
    havoc_below(o->z, &p384_wide_modp);
}

static int point_below(const p384_wide_point *a) {
    return below(a->x, &p384_wide_modp) && below(a->y, &p384_wide_modp) &&
           below(a->z, &p384_wide_modp);
}

#endif
