// rsa_mont64_step's proof once more, on the sum form: the form of
// rsa_mont64.h's step that gcc compiles. See rsa_mont64_step_harness.c for
// what it proves.
#define RSA_MONT64_STEP RSA_MONT64_STEP_SUM
#include "rsa_mont64_step_harness.c"
