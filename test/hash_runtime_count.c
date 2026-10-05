// A host object's SHA-256 and SHA-512 entries for bin/hash_runtime_test,
// each a count and a call to the portable code
// (test/hash_runtime_count.h). The entries of sha256_hw.c and sha512_hw.c
// compute the digests the portable ones compute, under the same contracts,
// so a caller sees what it would see from the instructions, and the binary
// holds none.
//
// sha256.c and sha512.c compile here under second names for their calls
// that hash, so this file can define the library's names as the counted
// ones. A call either file makes to itself, as sha256_final's to
// sha256_update, stays inside those second names and is not counted: the
// counts are the calls the library's other sources made.
#define sha256_update sha256_update_uncounted
#define sha256_final sha256_final_uncounted
#define sha256_of sha256_of_uncounted
#include "sha256.c"
#undef sha256_update
#undef sha256_final
#undef sha256_of

#define sha512_update sha512_update_uncounted
#define sha512_final sha512_final_uncounted
#define sha384_final sha384_final_uncounted
#define sha512_of sha512_of_uncounted
#define sha384_of sha384_of_uncounted
#include "sha512.c"
#undef sha512_update
#undef sha512_final
#undef sha384_final
#undef sha512_of
#undef sha384_of

#include "hash_runtime_count.h"

// sha256.h's and sha512.h's declarations of the calls, which the renames
// above gave the second names.
void sha256_update(sha256 *s, const uint8_t *in, size_t n);
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]);
void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]);
void sha512_update(sha512 *s, const uint8_t *in, size_t n);
void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]);
void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]);
void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);

hash_calls sha256_portable_calls;
hash_calls sha256_hw_calls;
hash_calls sha512_portable_calls;
hash_calls sha512_hw_calls;

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

void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    sha512_portable_calls.updates++;
    sha512_update_uncounted(s, in, n);
}

void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]) {
    sha512_portable_calls.finals++;
    sha512_final_uncounted(s, out);
}

void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    sha512_portable_calls.finals++;
    sha384_final_uncounted(s, out);
}

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    sha512_portable_calls.whole_messages++;
    sha512_of_uncounted(in, n, out);
}

void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    sha512_portable_calls.whole_messages++;
    sha384_of_uncounted(in, n, out);
}

#ifdef __aarch64__
// sha512_hw.c's five entries, which an arm64 host object alone holds.
void sha512_update_hw(sha512 *s, const uint8_t *in, size_t n) {
    sha512_hw_calls.updates++;
    sha512_update_uncounted(s, in, n);
}

void sha512_final_hw(sha512 *s, uint8_t out[SHA512_LEN]) {
    sha512_hw_calls.finals++;
    sha512_final_uncounted(s, out);
}

void sha384_final_hw(sha512 *s, uint8_t out[SHA384_LEN]) {
    sha512_hw_calls.finals++;
    sha384_final_uncounted(s, out);
}

void sha512_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    sha512_hw_calls.whole_messages++;
    sha512_of_uncounted(in, n, out);
}

void sha384_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    sha512_hw_calls.whole_messages++;
    sha384_of_uncounted(in, n, out);
}
#endif
