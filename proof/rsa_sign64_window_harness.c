// Proves: the two pieces of rsa_sign64.c that read a secret exponent
// compute what their comments say, read and write inside their arrays,
// and wrap no unsigned value. The wrap check is
// --unsigned-overflow-check on the launch line.
//
// The digit. exponent_digit returns the high half of byte i / 2 for an
// even i and the low half for an odd one, for any exponent bytes and any
// i below twice the largest length the build admits (384 bytes; 512 in
// the rsa_sign64_window_webpki variant, which sets CH_TRUST_WEBPKI). So
// the digits of an exponent, read in order, are its bits in order, and a
// digit is below 16.
//
// The read of the table. For any table, any index below 16, the largest
// prime's limb count and any limbs in the output before the call,
// table_select writes exactly the entry at that index: the proof picks
// any one limb and requires it to be the table's. The read keeps the
// output's own limbs under a zero mask, so what the output held is an
// input of the claim. It does not show that the function reads every entry
// whatever the index is: a read that stops at the entry it wants writes
// the same limbs. A Semgrep rule, inv-16-rsa-table-read, holds that
// (docs/invariants.md INV-16).
//
// The mask. mask_of_bit returns all ones or all zeros and follows its
// bit, because the read of the table is an AND against it.
//
// What this does not drive: rsa_sign64_power, which
// rsa_sign64_power_harness.c proves over contracts of the multiplication,
// and the pieces of a CRT signature, which rsa_sign64_crt_harness.c
// proves the same way.
#include "harness.h"

uint64_t nondet_u64(void);

#include "rsa_sign64.c"

static void prove_mask(void) {
    uint64_t bit = nondet_u64() & 1;
    uint64_t mask = mask_of_bit(bit);
    __CPROVER_assert(mask == 0 || mask == UINT64_MAX, "mask_of_bit is all ones or all zeros");
    __CPROVER_assert((bit == 1) == (mask == UINT64_MAX), "mask_of_bit follows its bit");
}

static void prove_exponent_digit(void) {
    uint8_t e[CH_RSA_MODULUS_MAX];
    fill_nondet(e, sizeof e);
    size_t i = nondet_size_t();
    __CPROVER_assume(i < 2 * sizeof e);
    uint64_t digit = exponent_digit(e, i);
    uint8_t byte = e[i / 2];
    uint64_t want = i % 2 == 0 ? (uint64_t)(byte >> 4) : (uint64_t)(byte & 15);
    __CPROVER_assert(digit == want, "exponent_digit is the half of the byte its index names");
    __CPROVER_assert(digit < TABLE_ENTRIES, "exponent_digit is a table index");
}

static void prove_table_select(void) {
    power_table table;
    uint64_t o[PRIME_LIMBS_MAX];
    for (size_t entry = 0; entry < TABLE_ENTRIES; entry++) {
        for (size_t i = 0; i < PRIME_LIMBS_MAX; i++) {
            table.powers[entry][i] = nondet_u64();
        }
    }
    for (size_t i = 0; i < PRIME_LIMBS_MAX; i++) {
        o[i] = nondet_u64();
    }
    uint64_t index = nondet_u64();
    __CPROVER_assume(index < TABLE_ENTRIES);
    table_select(o, &table, index, PRIME_LIMBS_MAX);
    size_t limb = nondet_size_t();
    __CPROVER_assume(limb < PRIME_LIMBS_MAX);
    __CPROVER_assert(o[limb] == table.powers[index][limb],
                     "table_select writes the entry at its index");
}

int main(void) {
    prove_mask();
    prove_exponent_digit();
    prove_table_select();
    return 0;
}
