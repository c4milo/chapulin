// Proves: pbkdf2_hmac_sha256 (pbkdf2.c) is memory safe and free of UB
// over any password, salt, iteration count and output length of up to
// the harness's bounds, NULL pointers with a length of 0 among them. And
// that it keeps what scram.h states:
// - it answers CH_EINVAL exactly when the iteration count is 0, the
//   output length is 0, or the output length is above
//   CH_PBKDF2_OUT_LEN_MAX, for every value of the three, and it then
//   writes nothing;
// - otherwise it answers CH_OK, and writes no byte past out_len.
//
// SHA-256 is a contract stub of this harness, which holds each call to a
// readable input and a writable state and answers any digest. So the
// proof covers every value the hash could return, and proves nothing
// about the value of the key: bin/scram_test holds that to RFC 7914's
// vectors and to RFC 7677's exchange. The stub writes the state's eight
// words through their own type. harness.h's stub fills the state a byte
// at a time, and the some 40 hash calls of one run then gave cbmc no
// formula in 9 minutes (docs/proofs.md). ct_wipe is
// proof/ct_wipe_stub.c's loop.
//
// Bounds. PASSWORD_MAX is 66 bytes, two past the block that a longer
// password is hashed down to, so both arms of key_start run. OUT_MAX is
// 34, two bytes into a second block, so the block loop runs twice and
// the last block is cut short. The iteration count is up to 3: the
// first PRF, and two of the loop's. No step reads how many came before
// it.
#include "harness.h"

#include "pbkdf2.c"

static void state_havoc(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256: state writable");
    for (size_t i = 0; i < 8; i++) {
        s->h[i] = nondet_u32();
    }
}

void sha256_init(sha256 *s) {
    state_havoc(s);
    s->total_bytes = 0;
    s->fill = 0;
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
    state_havoc(s);
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
    state_havoc(s);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        out[i] = nondet_u8();
    }
}

#define PASSWORD_MAX 66
#define SALT_MAX 3
#define OUT_MAX 34
#define COUNT_MAX 3

static void runs(void) {
    uint8_t password[PASSWORD_MAX];
    uint8_t salt[SALT_MAX];
    uint8_t out[OUT_MAX + 1];
    fill_nondet(password, sizeof password);
    fill_nondet(salt, sizeof salt);
    size_t password_len = nondet_size_t();
    size_t salt_len = nondet_size_t();
    size_t out_len = nondet_size_t();
    uint32_t iteration_count = nondet_u32();
    __CPROVER_assume(password_len <= PASSWORD_MAX && salt_len <= SALT_MAX);
    __CPROVER_assume(out_len <= OUT_MAX && iteration_count <= COUNT_MAX);
    // The byte after the output, which the call must leave.
    uint8_t after = nondet_u8();
    out[out_len] = after;
    const uint8_t *p = password_len == 0 && (nondet_u8() & 1) ? NULL : password;
    const uint8_t *s = salt_len == 0 && (nondet_u8() & 1) ? NULL : salt;

    int rc = pbkdf2_hmac_sha256(p, password_len, s, salt_len, iteration_count, out, out_len);

    __CPROVER_assert(rc == (iteration_count == 0 || out_len == 0 ? CH_EINVAL : CH_OK),
                     "CH_EINVAL exactly for a count of 0 or an output of 0 bytes");
    __CPROVER_assert(out[out_len] == after, "no byte past the output is written");
}

// The refusals over every value, with a NULL output: a call that wrote
// would fail the proof.
static void refuses(void) {
    size_t out_len = nondet_size_t();
    uint32_t iteration_count = nondet_u32();
    __CPROVER_assume(iteration_count == 0 || out_len == 0 || out_len > CH_PBKDF2_OUT_LEN_MAX);
    __CPROVER_assert(pbkdf2_hmac_sha256(NULL, 0, NULL, 0, iteration_count, NULL, out_len) ==
                         CH_EINVAL,
                     "a count of 0, and an output of 0 bytes or above the bound, are refused");
}

int main(void) {
    if (nondet_u8() & 1) {
        runs();
    } else {
        refuses();
    }
    return 0;
}
