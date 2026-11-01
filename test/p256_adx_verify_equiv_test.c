// test/p256_verify_equiv_test.c's cases with the host arm on the x86-64
// field's copy of the wide verifier (p256_adx.h), on its assembly, against
// the 32-bit verifier, on an x86-64 CPU with BMI2 and ADX
// (docs/decisions.md 171).
//
// On another architecture it prints SKIP. On an x86-64 CPU without BMI2 or
// ADX it prints SKIP too, unless CH_REQUIRE_BMI2_ADX is 1, as
// test/p256_adx_equiv_test.c does.
#include <stdint.h>
#include <stdio.h>

#ifdef __x86_64__
#include "x86_kernels_cpu.h"

static int adx_before(void);

#define P256_VERIFY_EQUIV_ADX 1
#define P256_VERIFY_EQUIV_NAME "p256_adx_verify_equiv"
#define P256_VERIFY_EQUIV_BEFORE adx_before
#include "p256_verify_equiv_test.c"

static int adx_before(void) {
    if (x86_cpu_has_bmi2_adx()) {
        return 1;
    }
    if (x86_bmi2_adx_required()) {
        (void)printf("p256_adx_verify_equiv: FAIL: CH_REQUIRE_BMI2_ADX=1 and this CPU lacks BMI2 "
                     "or ADX\n");
        exit(1);
    }
    (void)printf("p256_adx_verify_equiv: SKIP: this CPU lacks BMI2 or ADX\n");
    return 0;
}

#else

#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"

// The signer the binary links names the assertion's handler, which
// test/p256_verify_equiv_test.c defines on x86-64.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(void) {
    (void)printf("p256_adx_verify_equiv: SKIP: not x86-64\n");
    return 0;
}

#endif
