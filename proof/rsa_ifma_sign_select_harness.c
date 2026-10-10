// Proves: table_select writes the table's entry at the exponent's digit,
// every lane of it, and nothing else. For any table of sixteen entries,
// any exponent byte, either digit of that byte and every register count a
// build admits, 3 and 4, and 5 under CH_TRUST_WEBPKI in its
// rsa_ifma_sign_select_webpki variant, the first 8 * registers words of
// the output are the words of entry i, where i is the byte's high four bits
// for an even digit index and its low four bits for an odd one, as the
// harness reads them; the words past them keep what they held; table_select
// reads the one exponent byte the index names; and every read and write is
// inside its array.
//
// The lane operations are the model's own, test/rsa_ifma_model_lanes.h,
// which bin/rsa_ifma_equiv_test holds to the instructions on a CPU with
// AVX-512 IFMA. table_select runs no multiplication, so the model's loads,
// broadcasts, ands, adds and stores enter the formula as they are, on 64
// bits a lane. CBMC reads the volatile word the masks pass through as
// ordinary memory, as proof/ct_wipe_harness.c says of ct_wipe.c's
// pointer.
//
// What it does not prove: that the compiler keeps the read free of a
// branch on the digit. inv-16-rsa-ifma-table-read holds the source's
// shape, and make lint-wide-multiply counts the branches each compiler
// writes for the file.
#include "harness.h"

#include "rsa_mont64.h"

#include "rsa_ifma_sign.c"

uint64_t nondet_u64(void);
uint8_t nondet_u8(void);
size_t nondet_size_t(void);

static void prove_registers(size_t registers) {
    static sign_table table;
    uint64_t out[SIGN_LANES_MAX];
    uint64_t before[SIGN_LANES_MAX];
    uint8_t e[2];
    for (size_t entry = 0; entry < TABLE_ENTRIES; entry++) {
        for (size_t j = 0; j < SIGN_LANES_MAX; j++) {
            table.powers[entry][j] = nondet_u64();
        }
    }
    for (size_t j = 0; j < SIGN_LANES_MAX; j++) {
        out[j] = nondet_u64();
        before[j] = out[j];
    }
    e[0] = nondet_u8();
    e[1] = nondet_u8();
    size_t i = nondet_size_t();
    __CPROVER_assume(i < 4);
    table_select(out, &table, e, i, registers);

    uint8_t byte = e[i >> 1];
    size_t digit = (i & 1) == 0 ? (size_t)(byte >> 4) : (size_t)(byte & 15);
    for (size_t j = 0; j < SIGN_LANES_MAX; j++) {
        uint64_t want = j < 8 * registers ? table.powers[digit][j] : before[j];
        __CPROVER_assert(out[j] == want,
                         "the output holds the digit's entry in its registers' lanes, and its "
                         "other words as they were");
    }
}

int main(void) {
#ifdef CH_TRUST_WEBPKI
    prove_registers(5);
#else
    prove_registers(3);
    prove_registers(4);
#endif
    return 0;
}
