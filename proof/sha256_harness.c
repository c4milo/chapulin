// Proves: sha256 init/update/final are memory-safe and UB-free for any
// message delivered in any two-chunk split totaling up to 160 bytes —
// enough to cross two block boundaries and exercise every fill state the
// padding path can see. Wrapping uint32 arithmetic is the algorithm, not
// an accident, so only the UB classes are checked.
#include "harness.h"

#include "sha256.c"

int main(void) {
    uint8_t msg[160];
    uint8_t out[SHA256_LEN];
    size_t n1 = nondet_size_t();
    size_t n2 = nondet_size_t();
    __CPROVER_assume(n1 <= sizeof msg);
    __CPROVER_assume(n2 <= sizeof msg - n1);
    fill_nondet(msg, sizeof msg);

    sha256 s;
    sha256_init(&s);
    sha256_update(&s, msg, n1);
    sha256_update(&s, msg + n1, n2);
    sha256_final(&s, out);
    return 0;
}
