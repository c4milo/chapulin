// Proves: quic_keys_init, quic_hp_key_init and quic_keys_update read and
// write only inside their buffers and commit no undefined behavior, for
// any traffic secret.
//
// There is no length to vary here. Every buffer in quic_keys.h is a
// fixed-size array and every derivation asks HKDF for a constant number
// of bytes, so the whole input domain is the 32 secret bytes, and this
// harness havocs them. What is left to prove is the framing: that each
// call writes its own object whole and reads nothing past the secret.
//
// quic_keys_update is the one that can get this wrong. It derives the
// next secret, writes it back over the caller's buffer, and re-derives
// the key set from it, so the same 32 bytes are both an input and an
// output of one call. Deriving straight over the caller's buffer would
// read bytes the call had already replaced; the implementation uses a
// local and this harness covers the aliasing that results.
//
// HKDF is a contract stub (proof/aes_stubs.h), which states what
// the composition gives up and where the real function is proven. The
// derivation itself is checked against RFC 9001 Appendix A.5's four
// printed values in test/quic_vectors.c.
#include "harness.h"

#include "aes_stubs.h"

#include "quic_keys.c"

int main(void) {
    uint8_t secret[SHA256_LEN];
    quic_keys k;
    quic_hp_key h;

    fill_nondet(secret, sizeof secret);
    quic_keys_init(&k, secret);

    fill_nondet(secret, sizeof secret);
    quic_hp_key_init(&h, secret);

    // The update reads and rewrites the same secret, then rewrites the
    // key set from it. Both operands are havocked again first, so this
    // call reads no value an earlier call left.
    fill_nondet(secret, sizeof secret);
    fill_nondet((uint8_t *)&k, sizeof k);
    quic_keys_update(secret, &k);
    return 0;
}
