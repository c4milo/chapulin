// keccak_neon.h's entries as counts over keccak_neon.c's own code (test/keccak_neon_count.h).
// bin/mldsa_runtime_test and bin/mlkem_hw_equiv_test link this file in place of keccak_neon.c.
#include "keccak_neon_count.h"

#include <stdint.h>

keccak_neon_calls keccak_neon_counted;

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

// keccak_neon.c under this file's names for its three entries, so the definitions below take
// the library's names. keccak_neon.h's inline entries call the library's names, and so reach
// the counts from every file that includes the header.
#define keccak_neon_permute count_permute_plain
#define keccak_neon_permute_sha3 count_permute_sha3
#define keccak_neon_shake128_absorb count_shake128_absorb
#include "keccak_neon.c"
#undef keccak_neon_permute
#undef keccak_neon_permute_sha3
#undef keccak_neon_shake128_absorb

void keccak_neon_permute(keccak_x2 *s);
void keccak_neon_shake128_absorb(keccak_x2 *s, const uint8_t seed[32], const uint8_t x0[2],
                                 const uint8_t x1[2]);

void keccak_neon_permute(keccak_x2 *s) {
    keccak_neon_counted.plain++;
    count_permute_plain(s);
}

#ifdef CH_KECCAK_INSTRUCTIONS
void keccak_neon_permute_sha3(keccak_x2 *s);

void keccak_neon_permute_sha3(keccak_x2 *s) {
    keccak_neon_counted.sha3++;
    count_permute_plain(s);
}
#endif

void keccak_neon_shake128_absorb(keccak_x2 *s, const uint8_t seed[32], const uint8_t x0[2],
                                 const uint8_t x1[2]) {
    keccak_neon_counted.starts++;
    count_shake128_absorb(s, seed, x0, x1);
}

#endif
