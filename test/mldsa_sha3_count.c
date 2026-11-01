// sha3.c with its two SHAKE entries under other names, and the counts of
// the calls into them (test/mldsa_sha3_count.h). bin/mldsa_runtime_test
// links this file in place of sha3.c and sha3_hw.c.
#include "mldsa_sha3_count.h"

#define shake_absorb counted_shake_absorb
#define shake_squeeze counted_shake_squeeze
#include "sha3.c"
#undef shake_absorb
#undef shake_squeeze

mldsa_sha3_calls mldsa_sha3_counted;

void shake_absorb(shake *s, const uint8_t *in, size_t n);
void shake_squeeze(shake *s, uint8_t *out, size_t n);

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    mldsa_sha3_counted.absorb++;
    counted_shake_absorb(s, in, n);
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    mldsa_sha3_counted.squeeze++;
    counted_shake_squeeze(s, out, n);
}

#ifdef CH_KECCAK_INSTRUCTIONS
void shake_absorb_hw(shake *s, const uint8_t *in, size_t n) {
    mldsa_sha3_counted.absorb_hw++;
    counted_shake_absorb(s, in, n);
}

void shake_squeeze_hw(shake *s, uint8_t *out, size_t n) {
    mldsa_sha3_counted.squeeze_hw++;
    counted_shake_squeeze(s, out, n);
}
#endif
