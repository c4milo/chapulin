// Proves: the sha512 and sha384 framing — update's block assembly across
// a two-chunk split, and finalize's padding and 128-bit length — is
// memory-safe and UB-free for any message totaling up to 192 bytes:
// enough to cross a block boundary and reach every fill state the
// padding path can see (fill is the message length mod 128, and 0..192
// covers all 128 residues). sha512_compress is stubbed to its contract
// here — it reads one block and writes the eight-word state, asserted,
// with the state havocked through its own type — and
// sha512_compress_harness.c proves the function itself over that whole
// domain, so the stub is discharged. Both hashes run in one formula:
// they share update and finalize, and differ only in the initial value
// and in how many words the last step writes.
//
// The split is what makes this converge. One formula carrying the real
// compression and the sha512 path alone verified at a 15.3 GB peak in
// 1308 s (cbmc 6.11.0 with kissat, this bound), above the nightly
// runner's memory, and the two unrolled 80-round compressions were the
// whole of that cost.
#include "harness.h"

#include "sha512.c"

uint64_t nondet_u64(void);

void sha512_compress(uint64_t h[8], const uint8_t block[SHA512_BLOCK]) {
    __CPROVER_assert(__CPROVER_w_ok(h, 8 * sizeof(uint64_t)), "sha512_compress: state writable");
    __CPROVER_assert(__CPROVER_r_ok(block, SHA512_BLOCK), "sha512_compress: block readable");
    for (size_t i = 0; i < 8; i++) {
        h[i] = nondet_u64();
    }
}

int main(void) {
    uint8_t msg[192];
    size_t n1 = nondet_size_t();
    size_t n2 = nondet_size_t();
    __CPROVER_assume(n1 <= sizeof msg);
    __CPROVER_assume(n2 <= sizeof msg - n1);
    fill_nondet(msg, sizeof msg);

    sha512 s;
    uint8_t out512[SHA512_LEN];
    sha512_init(&s);
    sha512_update(&s, msg, n1);
    sha512_update(&s, msg + n1, n2);
    sha512_final(&s, out512);

    uint8_t out384[SHA384_LEN];
    sha384_init(&s);
    sha512_update(&s, msg, n1);
    sha512_update(&s, msg + n1, n2);
    sha384_final(&s, out384);
    return 0;
}
