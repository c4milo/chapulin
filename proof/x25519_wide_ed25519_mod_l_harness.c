// Proves: one step of reduce_mod_l() in x25519_wide_ed25519.h, from any
// remainder below L and either bit, leaves the remainder below L and wraps
// no unsigned value. reduce_mod_l() starts from 0, which is below L, so by
// induction its 512 steps end below L, and ed25519_verify_hram() reads no
// bit of h above 252. Over the 512 steps in one formula, cbmc gave no
// verdict in 15 minutes. bin/dnssec_test holds the value against
// OpenSSL's and std.crypto's signatures, whose check needs h mod L exact.
#define CH_DNSSEC 1
#include "x25519_wide_stubs.h"

int main(void) {
    uint64_t o[4];
    for (size_t i = 0; i < 4; i++) {
        o[i] = nondet_u64();
    }
    __CPROVER_assume(!at_or_above_l(o));
    uint64_t bit = nondet_u64() & 1;
    reduce_step(o, bit);
    __CPROVER_assert(!at_or_above_l(o), "a step keeps the remainder below L");
    return 0;
}
