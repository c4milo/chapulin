// rsa_mont.c and rsa_ifma.c compiled over the lane model,
// test/rsa_ifma_model_lanes.h, under second names, so that any host runs
// the kernel's own text and one binary can hold it beside the
// instructions. CH_RSA_IFMA_MODEL makes rsa_ifma.c include the model in
// place of rsa_ifma_lanes.h, and makes rsa_mont.c hold rsa_vp1_cpu's
// dispatch to it on any architecture. Only test units define it, and
// test/widemul-builds.sh refuses a library build that names it.
//
// The #defines rename both the definitions and the declarations rsa.h and
// rsa_ifma.h hold, as test/rsa_mont64_loops.c renames rsa_mont64.c's. A
// function the two files gain and this list lacks is defined twice in
// bin/rsa_ifma_equiv_test, which links rsa_mont.c under its own names, so
// that binary fails to link. test/rsa_ifma_entries.h then gives the
// static functions the tests call external names with the same prefix.
//
// rsa_mont.c's rsa_vp1_cpu calls rsa_ifma_model_public, which counts the
// call and then runs rsa_ifma.c's rsa_ifma_public, compiled here as
// rsa_ifma_model_kernel_public. So bin/rsa_ifma_model_test reads which
// calls of rsa_vp1_cpu ran the kernel, on every machine.
#define CH_RSA_IFMA_MODEL 1

#define rsa_vp1 rsa_ifma_model_vp1
#define rsa_vp1_cpu rsa_ifma_model_vp1_cpu
#define rsa_ifma_public rsa_ifma_model_public

#include "rsa_ifma_test.h"

#include "rsa_mont.c"

#undef rsa_ifma_public
#define rsa_ifma_public rsa_ifma_model_kernel_public

#include "rsa_ifma.c"

unsigned long rsa_ifma_model_public_calls;

void rsa_ifma_model_public(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, const uint64_t *digit_r2) {
    rsa_ifma_model_public_calls++;
    rsa_ifma_model_kernel_public(out, base, len, mod, digit_r2);
}

#define RSA_IFMA_ENTRY(name) rsa_ifma_model_##name
#include "rsa_ifma_entries.h"
