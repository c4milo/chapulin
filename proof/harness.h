// Shared scaffolding for CBMC proof harnesses. Each harness is a main()
// that drives one module with unconstrained (nondet) inputs, assumes only
// the module's documented contract, and lets CBMC's automatic checks
// (bounds, pointer validity, signed overflow, shifts, division) plus any
// explicit asserts do the rest. Harnesses include the module .c to reach
// statics, like the unit tests do.
#ifndef MS_PROOF_HARNESS_H
#define MS_PROOF_HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

size_t nondet_size_t(void);
uint8_t nondet_u8(void);
int64_t nondet_i64(void);

// An MS_ASSERT firing is a proof failure, and execution stops there.
noreturn void ms_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    __CPROVER_assert(0, "MS_ASSERT fired");
    __CPROVER_assume(0);
}

static void fill_nondet(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = nondet_u8();
    }
}

#endif
