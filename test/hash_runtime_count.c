// A host object's six SHA-256 entries for bin/hash_runtime_test, each a
// count and a call to sha256.c's code (test/hash_runtime_count.h). The
// three of sha256_hw.c compute the digest the portable three compute, under
// the same contracts, so a caller sees what it would see from the
// instructions, and the binary holds none.
//
// sha256.c compiles here under second names for its three calls that hash,
// so this file can define the library's names as the counted ones. A call
// sha256.c makes to itself, as sha256_final's to sha256_update, stays inside
// those second names and is not counted: the counts are the calls the
// library's other sources made.
#define sha256_update sha256_update_uncounted
#define sha256_final sha256_final_uncounted
#define sha256_of sha256_of_uncounted
#include "sha256.c"
#undef sha256_update
#undef sha256_final
#undef sha256_of

#include "hash_runtime_count.h"

// sha256.h's declarations of the three, which the renames above gave the
// second names.
void sha256_update(sha256 *s, const uint8_t *in, size_t n);
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]);
void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]);

hash_calls sha256_portable_calls;
hash_calls sha256_hw_calls;

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    sha256_portable_calls.updates++;
    sha256_update_uncounted(s, in, n);
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    sha256_portable_calls.finals++;
    sha256_final_uncounted(s, out);
}

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    sha256_portable_calls.whole_messages++;
    sha256_of_uncounted(in, n, out);
}

void sha256_update_hw(sha256 *s, const uint8_t *in, size_t n) {
    sha256_hw_calls.updates++;
    sha256_update_uncounted(s, in, n);
}

void sha256_final_hw(sha256 *s, uint8_t out[SHA256_LEN]) {
    sha256_hw_calls.finals++;
    sha256_final_uncounted(s, out);
}

void sha256_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    sha256_hw_calls.whole_messages++;
    sha256_of_uncounted(in, n, out);
}
