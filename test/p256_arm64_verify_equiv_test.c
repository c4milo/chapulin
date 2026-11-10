// test/p256_verify_equiv_test.c's cases with the host arm on the arm64
// field's copy of the wide verifier (p256_arm64.h), on its assembly, against
// the 32-bit verifier, on arm64 (docs/decisions.md 215).
//
// On another architecture it prints SKIP.
#include <stdint.h>
#include <stdio.h>

#ifdef __aarch64__

#define P256_VERIFY_EQUIV_ARM64 1
#define P256_VERIFY_EQUIV_NAME "p256_arm64_verify_equiv"
#include "p256_verify_equiv_test.c"

#else

#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"

// The signer the binary links names the assertion's handler, which
// test/p256_verify_equiv_test.c defines on arm64.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(void) {
    (void)printf("p256_arm64_verify_equiv: SKIP: not arm64\n");
    return 0;
}

#endif
