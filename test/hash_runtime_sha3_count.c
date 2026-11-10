// A host object's SHA-3 and SHAKE entries for bin/hash_runtime_test, each a count and a call to
// sha3.c's code (test/hash_runtime_count.h). sha3_hw.c's entries compute what sha3.c's compute,
// under the same contracts, so a caller sees what it would see from sha3_hw.c, and the binary
// runs no SHA-3 instruction, ANDN or RORX. sha3.c compiles here under second names for the four
// calls that run the permutation, so this file can define the library's names as the counted
// ones. The _hw names exist where sha3.h declares them: in an arm64 host object that clang
// compiled, and in every x86-64 host object (docs/decisions.md 99 and 217).
#define sha3_256 sha3_256_uncounted
#define sha3_512 sha3_512_uncounted
#define shake_absorb shake_absorb_uncounted
#define shake_squeeze shake_squeeze_uncounted
#include "sha3.c"
#undef sha3_256
#undef sha3_512
#undef shake_absorb
#undef shake_squeeze

#include "hash_runtime_count.h"

hash_calls sha3_portable_calls;
hash_calls sha3_hw_calls;

// sha3.h's declarations of the calls, which the renames above gave the second names. A SHAKE
// absorb counts as an update, a squeeze as a final, and a digest of a whole message as itself.
void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]);
void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]);
void shake_absorb(shake *s, const uint8_t *in, size_t n);
void shake_squeeze(shake *s, uint8_t *out, size_t n);

void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    sha3_portable_calls.whole_messages++;
    sha3_256_uncounted(in, n, out);
}

void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    sha3_portable_calls.whole_messages++;
    sha3_512_uncounted(in, n, out);
}

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    sha3_portable_calls.updates++;
    shake_absorb_uncounted(s, in, n);
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    sha3_portable_calls.finals++;
    shake_squeeze_uncounted(s, out, n);
}

#if defined(CH_KECCAK_INSTRUCTIONS) || defined(__x86_64__)
void sha3_256_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    sha3_hw_calls.whole_messages++;
    sha3_256_uncounted(in, n, out);
}

void sha3_512_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    sha3_hw_calls.whole_messages++;
    sha3_512_uncounted(in, n, out);
}

void shake128_init_hw(shake *s) {
    shake128_init(s);
}

void shake256_init_hw(shake *s) {
    shake256_init(s);
}

void shake_absorb_hw(shake *s, const uint8_t *in, size_t n) {
    sha3_hw_calls.updates++;
    shake_absorb_uncounted(s, in, n);
}

void shake_squeeze_hw(shake *s, uint8_t *out, size_t n) {
    sha3_hw_calls.finals++;
    shake_squeeze_uncounted(s, out, n);
}
#endif
