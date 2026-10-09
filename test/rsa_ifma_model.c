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
#define CH_RSA_IFMA_MODEL 1

#define rsa_vp1 rsa_ifma_model_vp1
#define rsa_vp1_cpu rsa_ifma_model_vp1_cpu
#define rsa_ifma_public rsa_ifma_model_public

#include "rsa_ifma_test.h"

#include "rsa_mont.c"

#include "rsa_ifma.c"

#define RSA_IFMA_ENTRY(name) rsa_ifma_model_##name
#include "rsa_ifma_entries.h"
