// Proves: scram.c's calls are memory safe and free of UB over any inputs
// of up to the harness's bounds, NULL pointers with a length of 0 among
// them. And that they keep what scram.h states:
// - ch_ct_compare answers CH_OK exactly when the n bytes are equal, and
//   CH_EAUTH otherwise, for every n of up to COMPARE_MAX and for NULL
//   pointers at n of 0;
// - ch_sha256 and ch_hmac_sha256 hand the hash no pointer it cannot
//   read, for an input of any length here and for a NULL one of length
//   0. hkdf.c's hmac_sha256 is real;
// - ch_pbkdf2_hmac_sha256, ch_base64_encode and ch_base64_decode pass
//   their arguments on unchanged, and return what the call below them
//   returns.
//
// SHA-256 is harness.h's contract stub, which holds each call to a
// readable input and answers any digest; the sha256 harness proves it.
// pbkdf2_hmac_sha256, base64_encode and base64_decode are stubs that
// record their arguments; the pbkdf2 and base64_codec harnesses prove
// them. ct.c is real, and ct_wipe is proof/ct_wipe_stub.c's loop.
//
// Bounds. COMPARE_MAX is 9 bytes, past one 8-byte word. KEY_MAX is 66,
// two bytes past the block HMAC hashes a longer key down to, so both of
// its arms run.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "base64_codec.h"
#include "pbkdf2.h"
#include "scram.h"

#define COMPARE_MAX 9
#define KEY_MAX 66
#define MESSAGE_MAX 4

typedef struct {
    const uint8_t *a;
    size_t a_len;
    const uint8_t *b;
    size_t b_len;
    uint32_t count;
    uint8_t *out;
    size_t out_len;
    size_t *written;
    int answer;
} call;

static call seen;

static int answered(void) {
    seen.answer = (int)nondet_u8() - 8;
    return seen.answer;
}

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                       size_t salt_len, uint32_t iteration_count, uint8_t *out, size_t out_len) {
    seen = (call){password, password_len, salt, salt_len, iteration_count, out, out_len, NULL, 0};
    return answered();
}

int base64_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                  size_t *text_len) {
    seen = (call){in, in_len, NULL, 0, 1, text, text_cap, text_len, 0};
    return answered();
}

int base64_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                  size_t *out_len) {
    seen = (call){text, text_len, NULL, 0, 2, out, out_cap, out_len, 0};
    return answered();
}

static void compare(void) {
    uint8_t a[COMPARE_MAX];
    uint8_t b[COMPARE_MAX];
    fill_nondet(a, sizeof a);
    fill_nondet(b, sizeof b);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= COMPARE_MAX);
    int equal = 1;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            equal = 0;
        }
    }
    int rc = ch_ct_compare(a, b, n);
    __CPROVER_assert(rc == (equal ? CH_OK : CH_EAUTH), "CH_OK exactly for equal bytes");
    __CPROVER_assert(CH_OK == 0, "0 means equal");
    __CPROVER_assert(ch_ct_compare(NULL, NULL, 0) == CH_OK, "no bytes are equal bytes");
}

static void hashes(void) {
    uint8_t key[KEY_MAX];
    uint8_t message[MESSAGE_MAX];
    uint8_t out[CH_SHA256_LEN];
    fill_nondet(key, sizeof key);
    fill_nondet(message, sizeof message);
    size_t key_len = nondet_size_t();
    size_t message_len = nondet_size_t();
    __CPROVER_assume(key_len <= KEY_MAX && message_len <= MESSAGE_MAX);
    // scram.h permits a NULL pointer for an input of no bytes.
    const uint8_t *k = key_len == 0 && (nondet_u8() & 1) ? NULL : key;
    const uint8_t *m = message_len == 0 && (nondet_u8() & 1) ? NULL : message;
    ch_sha256(m, message_len, out);
    ch_hmac_sha256(k, key_len, m, message_len, out);
}

static void forwards(void) {
    uint8_t in[4];
    uint8_t second[4];
    uint8_t out[4];
    size_t written = 0;
    size_t in_len = nondet_size_t();
    size_t second_len = nondet_size_t();
    size_t out_len = nondet_size_t();
    uint32_t count = nondet_u32();
    int rc = ch_pbkdf2_hmac_sha256(in, in_len, second, second_len, count, out, out_len);
    __CPROVER_assert(seen.a == in && seen.a_len == in_len && seen.b == second &&
                         seen.b_len == second_len && seen.count == count && seen.out == out &&
                         seen.out_len == out_len && rc == seen.answer,
                     "ch_pbkdf2_hmac_sha256 passes its arguments and its answer on");
    rc = ch_base64_encode(in, in_len, out, out_len, &written);
    __CPROVER_assert(seen.count == 1 && seen.a == in && seen.a_len == in_len && seen.out == out &&
                         seen.out_len == out_len && seen.written == &written && rc == seen.answer,
                     "ch_base64_encode passes its arguments and its answer on");
    rc = ch_base64_decode(in, in_len, out, out_len, &written);
    __CPROVER_assert(seen.count == 2 && seen.a == in && seen.a_len == in_len && seen.out == out &&
                         seen.out_len == out_len && seen.written == &written && rc == seen.answer,
                     "ch_base64_decode passes its arguments and its answer on");
}

int main(void) {
    uint8_t part = nondet_u8();
    if (part == 0) {
        compare();
    } else if (part == 1) {
        hashes();
    } else {
        forwards();
    }
    return 0;
}
