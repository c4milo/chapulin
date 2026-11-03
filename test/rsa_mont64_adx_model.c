// rsa_mont64_adx.c compiled over test/rsa_mont64_adx_model.h, the five
// operations in portable C, under names that end in _model, so a test binary
// links it beside the assembly build on x86-64 and alone on any other host.
#define CH_RSA_MONT64_ADX_MODEL 1
#define rsa_mont64_adx_mul rsa_mont64_adx_model_mul
#define rsa_mont64_adx_square rsa_mont64_adx_model_square
#include "rsa_mont64_adx.c"
