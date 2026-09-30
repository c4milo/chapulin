// The calls bin/aes_runtime_test counts into each of an AES=runtime
// object's two ciphers and into its carry-less multiply
// (docs/decisions.md 81). test/aes_runtime_soft.c compiles quic_aes_soft.c
// and test/aes_runtime_hw.c compiles aes_hw.c and ghash_hw.c, each with
// its entries under second names, and each defines the entries aes.c and
// gcm.c call as a count and a call to the entry it renamed. So the
// library sources run unchanged, and the test reads which cipher ran.
//
// The second names are this test's alone, as test/aes_equiv_test.c's
// are: the library object compiles the same three files under their own
// names.
#ifndef CH_TEST_AES_RUNTIME_COUNT_H
#define CH_TEST_AES_RUNTIME_COUNT_H

// Calls into quic_aes_soft.c's two entries, the S-box table.
extern unsigned long aes_runtime_table_calls;
// Calls into aes_hw.c's four entries, the AES instructions.
extern unsigned long aes_runtime_instruction_calls;
// Calls into ghash_hw.c's two entries, the carry-less multiply.
extern unsigned long aes_runtime_clmul_calls;

#endif
