// rsa_ifma.c on the AVX-512 IFMA instructions, as a host object compiles
// it, with test/rsa_ifma_entries.h after it, which gives the static
// functions bin/rsa_ifma_equiv_test calls the prefix
// rsa_ifma_instructions_. rsa_ifma_public keeps its own name, which
// rsa_mont.c's rsa_vp1_cpu calls, so the binary links this unit in place
// of rsa_ifma.c. The whole unit compiles on x86-64 alone, as rsa_ifma.c
// does.
#include "rsa_ifma_test.h"

#include "rsa_ifma.c"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#define RSA_IFMA_ENTRY(name) rsa_ifma_instructions_##name
#include "rsa_ifma_entries.h"
#endif
