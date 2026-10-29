// x25519_adx.c compiled over test/x25519_adx_model.h, the five operations in
// portable C, under names that end in _model, so a test binary links it
// beside the assembly build on x86-64 and alone on any other host.
#define CH_X25519_ADX_MODEL 1
#define x25519_adx x25519_adx_model
#define x25519_adx_ladder x25519_adx_model_ladder
#define x25519_adx_test_mul x25519_adx_model_test_mul
#define x25519_adx_test_sqr x25519_adx_model_test_sqr
#define x25519_adx_test_add x25519_adx_model_test_add
#define x25519_adx_test_sub x25519_adx_model_test_sub
#define x25519_adx_test_mul_a24 x25519_adx_model_test_mul_a24
#define x25519_adx_test_reduce x25519_adx_model_test_reduce
#include "x25519_adx.c"
