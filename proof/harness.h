// Shared scaffolding for CBMC proof harnesses. Each harness is a main()
// that drives one module with unconstrained (nondet) inputs, assumes only
// the module's documented contract, and lets CBMC's automatic checks
// (bounds, pointer validity, signed overflow, shifts, division) plus any
// explicit asserts do the rest. Harnesses include the module .c to reach
// statics, like the unit tests do.
#ifndef CH_PROOF_HARNESS_H
#define CH_PROOF_HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

size_t nondet_size_t(void);
uint8_t nondet_u8(void);
int64_t nondet_i64(void);

// An CH_ASSERT firing is a proof failure, and execution stops there.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    __CPROVER_assert(0, "CH_ASSERT fired");
    __CPROVER_assume(0);
}

static void fill_nondet(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = nondet_u8();
    }
}

// The SHA-256 stub five harnesses share. A harness that does not prove
// sha256.c models it as: the contract its callers must honour, asserted,
// and an unconstrained digest. Havocking the context and the output is
// what makes the proof consider every digest the real function could
// return, rather than one CBMC happened to pick — a harness that leaves
// them alone proves less. sha256_harness.c proves the real thing and
// must not include this.
//
#ifdef CH_PROOF_STUB_SHA256
#include "sha256.h"

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
    fill_nondet(out, SHA256_LEN);
}

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_of: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_of: output writable");
    fill_nondet(out, SHA256_LEN);
}
#endif

#endif
