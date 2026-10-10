// rsa_mont.c and rsa_avx2.c compiled over the lane model,
// test/rsa_avx2_model_lanes.h, under second names, so that any host runs
// the kernel's own text and one binary can hold it beside the
// instructions. CH_RSA_AVX2_MODEL makes rsa_avx2.c include the model in
// place of rsa_avx2_lanes.h, and makes rsa_mont.c hold rsa_vp1_cpu's
// dispatch to it on any architecture. Only test units define it, and
// test/widemul-builds.sh refuses a library build that names it.
//
// The #defines rename both the definitions and the declarations rsa.h and
// rsa_avx2.h hold, as test/rsa_ifma_model.c renames them. A function the
// two files gain and this list lacks is defined twice in
// bin/rsa_avx2_equiv_test, which links rsa_mont.c under its own names, so
// that binary fails to link. test/rsa_avx2_entries.h then gives the static
// functions the tests call external names with the same prefix.
//
// rsa_mont.c's rsa_vp1_cpu calls rsa_avx2_model_public, which counts the
// call and then runs rsa_avx2.c's rsa_avx2_public, compiled here as
// rsa_avx2_model_kernel_public. So bin/rsa_avx2_model_test reads which
// calls of rsa_vp1_cpu ran the kernel, on every machine. On x86-64 the
// same rsa_vp1_cpu hands a value with CH_CPU_AVX512_IFMA to rsa_ifma.c on
// the instructions, which the binary links and never asks for.
#define CH_RSA_AVX2_MODEL 1

#define rsa_vp1 rsa_avx2_model_vp1
#define rsa_vp1_cpu rsa_avx2_model_vp1_cpu
#define rsa_avx2_public rsa_avx2_model_public

#include "rsa_avx2_test.h"

#include "rsa_mont.c"

#undef rsa_avx2_public
#define rsa_avx2_public rsa_avx2_model_kernel_public

#include "rsa_avx2.c"

unsigned long rsa_avx2_model_public_calls;

void rsa_avx2_model_public(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, const uint64_t *digit_r2) {
    rsa_avx2_model_public_calls++;
    rsa_avx2_model_kernel_public(out, base, len, mod, digit_r2);
}

#define RSA_AVX2_ENTRY(name) rsa_avx2_model_##name
#include "rsa_avx2_entries.h"
