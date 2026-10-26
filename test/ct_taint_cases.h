// The public-key cases of the Valgrind taint lane, which test/ct_taint_keys.c defines.
#ifndef CH_TEST_CT_TAINT_CASES_H
#define CH_TEST_CT_TAINT_CASES_H

#include <stdint.h>

// Runs X25519, P-256 ECDH, the P-256 signers, RSA-PSS signing and ML-KEM under cpu, a
// ch_cfg.cpu value, and returns the count of cases whose public output was wrong.
int ct_taint_public_key_cases(uint32_t cpu);

#endif
