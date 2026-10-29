// x25519_adx.c's ladder, inversion and final reduction over the model of its
// five assembly operations (test/x25519_adx_model.h), against the 16-word
// field, on every host: test/x25519_equiv_test.c's cases with the model as
// the field under test. bin/x25519_adx_equiv_test then holds the assembly to
// the model on a CPU with BMI2 and ADX (docs/decisions.md 165).
#include <stdint.h>

#include "x25519.h"

int x25519_adx_model(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                     const uint8_t point[X25519_LEN]);

#define X25519_EQUIV_FIELD x25519_adx_model
#define X25519_EQUIV_NAME "x25519_adx_model"
#define X25519_EQUIV_WHAT "the radix-2^64 field's model"
#define X25519_EQUIV_LADDER_ONLY 1
#include "x25519_equiv_test.c"
