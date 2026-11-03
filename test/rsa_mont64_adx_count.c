// rsa_mont64_adx.c's two entries as counts, for the binaries that link this
// file in place of it (test/rsa_mont64_adx_count.h). Each counts the call and
// writes rsa_mont64.c's words, which are the words the assembly writes
// (bin/rsa_mont64_adx_test). So rsa_sign64.c runs unchanged, no MULX, ADCX
// or ADOX instruction runs, and a binary reads which signatures the library
// sent to the ADX path, on any x86-64 CPU. The entries compile under the
// condition rsa_mont64_adx.h declares them under, so on arm64 this file
// holds the count alone.
#include "rsa_mont64_adx_count.h"

#include "rsa_mont64_adx.h"

unsigned long rsa_mont64_adx_calls;

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

void rsa_mont64_adx_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                        const rsa_mont64_modulus *mod) {
    rsa_mont64_adx_calls++;
    rsa_mont64_mont_mul(o, a, b, mod);
}

void rsa_mont64_adx_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    rsa_mont64_adx_calls++;
    rsa_mont64_mont_square(o, a, mod);
}

#endif // CH_CPU_RUNTIME && __x86_64__
