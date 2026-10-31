// Proves: sha1.c, under CH_DNSSEC, is memory safe and free of UB: init,
// one update of any length up to a block, and the final padding, whose
// one-byte updates run the path that fills a partial block. Each reads and
// writes inside the context and the output alone. Its value is not proved:
// bin/dnssec_test holds it to FIPS 180-4's examples, one block and two.
// With two updates of up to two blocks, cbmc gave no verdict in 15
// minutes at 3.4 GB.
#include "harness.h"

#include "sha1.h"

int main(void) {
    sha1 s;
    sha1_init(&s);
    uint8_t in[SHA1_BLOCK];
    fill_nondet(in, sizeof in);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    sha1_update(&s, in, n);
    uint8_t out[SHA1_LEN];
    sha1_final(&s, out);
    return 0;
}
