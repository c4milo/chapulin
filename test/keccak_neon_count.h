// The calls bin/mldsa_runtime_test and bin/mlkem_hw_equiv_test count into keccak_neon.c, the
// two-way Keccak of an arm64 host object (docs/decisions.md 198). test/keccak_neon_count.c
// compiles keccak_neon.c with its two permutations renamed, and defines keccak_neon_permute,
// keccak_neon_permute_sha3 and keccak_neon_shake128_absorb as a count and a call. Both counted
// permutations run the plain form, so no SHA-3 instruction runs, and the binaries that link
// the file in keccak_neon.c's place read which form keccak_neon.h's keccak_neon_permute_cpu
// picked under each ch_cfg.cpu value.
//
// The names are this test's alone, as test/mldsa_avx2_count.h's are.
#ifndef CH_TEST_KECCAK_NEON_COUNT_H
#define CH_TEST_KECCAK_NEON_COUNT_H

// How many pairs of streams the library started, and how many permutations of each form it
// ran.
typedef struct {
    unsigned long starts;
    unsigned long plain;
    unsigned long sha3;
} keccak_neon_calls;

extern keccak_neon_calls keccak_neon_counted;

#endif
