// ghash_hw.c's two entries on both sources of the powers of H
// (docs/decisions.md 234), for bin/ghash_equiv_test. Each function below
// runs its entry twice over the same operands:
//
//   with the hash subkey and no stored powers, so the entry computes the
//   powers it needs, which is the result the caller compares with the
//   portable GHASH;
//   with stored powers and a null subkey, so the entry reads the powers in
//   place and a read of the subkey faults. The stored powers come from
//   test/ghash_powers_soft.h's bit arithmetic, which runs no carry-less
//   multiply.
//
// The two results must be the same bytes. A difference prints the
// operands and counts in stored_mismatches, which the test main reads.
// Included by test/ghash_equiv_test.c only.
#ifndef CH_TEST_GHASH_EQUIV_STORED_H
#define CH_TEST_GHASH_EQUIV_STORED_H

#include <stdio.h>
#include <string.h>

#include "ghash_hw.h"
#include "ghash_powers_soft.h"

static unsigned long stored_mismatches;

static void stored_mismatch(const char *entry, const uint8_t subkey[AES_BLOCK], size_t n) {
    (void)fprintf(stderr, "FAIL %s on stored powers, %zu bytes, subkey ", entry, n);
    for (size_t i = 0; i < AES_BLOCK; i++) {
        (void)fprintf(stderr, "%02x", subkey[i]);
    }
    (void)fprintf(stderr, "\n");
    stored_mismatches++;
}

// acc = acc * subkey. acc may be subkey: the powers are computed before
// the first entry writes acc.
static void multiply_on_both(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    uint8_t powers[GHASH_POWERS_SOFT_LEN];
    uint8_t key[AES_BLOCK];
    uint8_t stored[AES_BLOCK];
    memcpy(key, subkey, AES_BLOCK);
    memcpy(stored, acc, AES_BLOCK);
    // The multiply reads the first power alone (ghash_hw.h).
    ghash_powers_soft_first(powers, key, 1);
    gcm_multiply_by_subkey_hw(acc, subkey, NULL);
    gcm_multiply_by_subkey_hw(stored, NULL, powers);
    if (memcmp(stored, acc, AES_BLOCK) != 0) {
        stored_mismatch("gcm_multiply_by_subkey_hw", key, AES_BLOCK);
    }
}

// acc = GHASH's accumulator after the n bytes at bytes, from acc.
static void hash_data_on_both(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                              const uint8_t *bytes, size_t n) {
    uint8_t powers[GHASH_POWERS_SOFT_LEN];
    uint8_t stored[AES_BLOCK];
    memcpy(stored, acc, AES_BLOCK);
    ghash_powers_soft(powers, subkey);
    gcm_hash_data_hw(acc, subkey, NULL, bytes, n);
    gcm_hash_data_hw(stored, NULL, powers, bytes, n);
    if (memcmp(stored, acc, AES_BLOCK) != 0) {
        stored_mismatch("gcm_hash_data_hw", subkey, n);
    }
}

#endif
