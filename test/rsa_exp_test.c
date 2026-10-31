// rsa_mont64_public_exp, the DNSSEC public operation with the key's own
// exponent, against known answers from Python's pow
// (test/gen_rsa_exp_vectors.py), and against rsa_mont64_public at 65537,
// the exponent both compute. The binary builds as a host object with
// CH_DNSSEC at the 512-byte bound.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rsa_exp_vectors.h"
#include "rsa_mont64.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void check(int ok, const char *what, size_t index) {
    if (!ok) {
        printf("FAIL rsa_exp vector %zu: %s\n", index, what);
        failures++;
    }
}

int main(void) {
    size_t count = sizeof rsa_exp_vectors / sizeof rsa_exp_vectors[0];
    for (size_t i = 0; i < count; i++) {
        const rsa_exp_vector *v = &rsa_exp_vectors[i];
        rsa_mont64_modulus mod;
        rsa_mont64_modulus_init(&mod, v->m, v->len, v->bits);
        uint8_t out[CH_RSA_MODULUS_MAX];
        rsa_mont64_public_exp(out, v->base, v->len, &mod, v->e);
        check(memcmp(out, v->out, v->len) == 0, "base^e mod m", i);

        // At e = 65537 both calls compute the same power.
        uint8_t fixed[CH_RSA_MODULUS_MAX];
        rsa_mont64_public_exp(out, v->base, v->len, &mod, 65537);
        rsa_mont64_public(fixed, v->base, v->len, &mod);
        check(memcmp(out, fixed, v->len) == 0, "65537 agrees with rsa_mont64_public", i);
    }
    if (failures != 0) {
        return 1;
    }
    printf("rsa_exp: %zu vectors, base^e mod m and the 65537 cross-check\n", count);
    return 0;
}
