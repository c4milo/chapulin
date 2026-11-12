// The DNSSEC Ed25519 check's arm of the differential oracle: reduce_step,
// reduce_mod_l, decode_point and ed25519_verify_hram in
// x25519_wide_ed25519.h, against the same Lean spec process
// test/diff_test.c drives.
// spec/lean/Spec/Ed25519ModL.lean models the first two from the C and
// proves that a step from a remainder below L stays below L and that the
// reduction writes h mod L. spec/lean/Spec/Ed25519Decode.lean models the
// third and proves that each point it returns is the one the key encodes.
// spec/lean/Spec/Ed25519Verify.lean models the check's loop and proves
// that it computes [S]B - [h]A; its verifyR is the whole check.
// spec/lean/Spec/Ed25519Sign.lean models the signer's scalar_reduce and
// scalar_muladd in x25519_wide_ed25519_sign.h, and proves that they write
// h mod L and r + k a mod L.
// These rows are what make those proofs about the C: an error in the
// transcription on either side fails a row.
//
// Its own main, as test/diff_x25519_test.c is: the two functions are
// static in a header that x25519_wide.c includes under CH_DNSSEC alone, so
// this unit includes x25519_wide.c itself.
//
// reduce_step takes each bit from the remainders 0, 1, 2^252 - 1, 2^252,
// (L - 1) / 2, (L + 1) / 2 and L - 1, from random ones below 2^252 and
// from random ones just below L. reduce_mod_l takes the hashes 0,
// 2^512 - 1, L - 1, L, L + 1 and random ones. decode_point takes, with
// each sign bit, the y values 0, 1, p - 1, p, 2^255 - 1 and B's, and
// random keys, about half of which encode a point. ed25519_verify_hram
// takes those keys with random hashes and an S of 0, L - 1, L or a random
// one below L: where the spec names the R the check accepts, the C must
// accept that R and refuse it with its low bit or its sign bit flipped,
// and where the spec refuses, the C must refuse each R it is given,
// the R of the point its loop computes among them. scalar_reduce takes
// reduce_mod_l's hashes. scalar_muladd takes each r and k of 0, 1 and
// L - 1 with each a of 0, 1 and 2^256 - 1, and random r and k below 2^252
// with random a. Seven of eight random
// points are outside the subgroup of prime order, and the check refuses
// their keys (docs/decisions.md 227): the R of the loop's point meets the
// equation under such a key, so that row fails a C with no test of the
// key's order. For each random key that encodes a point P, the check
// takes the key of 8 P too, which is in the subgroup, so the rows that
// accept an R stay.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"

#include "diff_driver.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#if !defined(CH_CPU_RUNTIME) || !defined(CH_DNSSEC) || !defined(CH_JWS)
#error "test/diff_ed25519_test.c diffs the wide field's Ed25519 code: build it with -DCH_CPU_RUNTIME -DCH_DNSSEC -DCH_JWS"
#endif
#include "x25519_wide.c"

// The random remainders and hashes each kind takes.
#define RANDOM_ROWS 200

#define COMMAND_SIZE (64 + 2 * 64)

// The random keys the check takes, of the RANDOM_ROWS keys the decode
// takes.
#define VERIFY_KEYS 50

// words[0..4) as 32 little-endian bytes.
static void words_to_bytes(uint8_t b[32], const uint64_t w[4]) {
    for (size_t i = 0; i < 32; i++) {
        b[i] = (uint8_t)(w[i / 8] >> (8 * (i % 8)));
    }
}

static void diff_step(const uint64_t o[4], uint64_t bit) {
    char cmd[COMMAND_SIZE];
    char want[65];
    uint8_t bytes[32];
    words_to_bytes(bytes, o);
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_reduce_step ");
    at += hex_encode(cmd + at, bytes, 32);
    (void)snprintf(cmd + at, sizeof cmd - at, " %u", (unsigned)bit);
    uint64_t out[4];
    memcpy(out, o, sizeof out);
    reduce_step(out, bit);
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

static void diff_decode(const uint8_t key[32]) {
    char cmd[COMMAND_SIZE];
    char want[129];
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_decode ");
    (void)hex_encode(cmd + at, key, 32);
    fe x;
    fe y;
    if (decode_point(x, y, key)) {
        uint8_t bytes[64];
        pack(bytes, x);
        pack(bytes + 32, y);
        (void)hex_encode(want, bytes, 64);
    } else {
        (void)snprintf(want, sizeof want, "FAIL");
    }
    expect(cmd, want);
}

static void diff_verifies(const uint8_t key[32]);

// key8 = the encoding of 8 P for the point P that key encodes: three
// doublings, then the affine y with x's low bit as bit 255. 8 P is in the
// subgroup of prime order. Returns 0 when key encodes no point.
static int eight_times(uint8_t key8[32], const uint8_t key[32]) {
    fe x;
    fe y;
    if (!decode_point(x, y, key)) {
        return 0;
    }
    edwards_point p = {.z = {1}};
    memcpy(p.x, x, sizeof x);
    memcpy(p.y, y, sizeof y);
    mul(p.t, x, y);
    for (int i = 0; i < 3; i++) {
        double_in_place(&p);
    }
    fe zi;
    invert(zi, p.z);
    mul(x, p.x, zi);
    mul(y, p.y, zi);
    pack(key8, y);
    key8[31] |= (uint8_t)(fe_negative(x) << 7);
    return 1;
}

static void diff_decodes(void) {
    // p - 1 in 32 little-endian bytes; the rows below write the others
    // from it.
    uint8_t minus_one[32];
    memset(minus_one, 0xff, sizeof minus_one);
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    uint8_t keys[6][32] = {{0}};
    keys[1][0] = 1;
    memcpy(keys[2], minus_one, 32);
    memcpy(keys[3], minus_one, 32);
    keys[3][0] = 0xed; // p
    memset(keys[4], 0xff, 32);
    keys[4][31] = 0x7f; // 2^255 - 1
    memset(keys[5], 0x66, 32);
    keys[5][0] = 0x58; // B's y, 4/5
    for (size_t i = 0; i < 6; i++) {
        diff_decode(keys[i]);
        diff_verifies(keys[i]);
        keys[i][31] ^= 0x80;
        diff_decode(keys[i]);
        diff_verifies(keys[i]);
    }
    uint8_t key[32];
    for (int r = 0; r < RANDOM_ROWS; r++) {
        rng_fill(key, sizeof key);
        diff_decode(key);
        if (r < VERIFY_KEYS) {
            diff_verifies(key);
            uint8_t key8[32];
            if (eight_times(key8, key)) {
                diff_verifies(key8);
            }
        }
        key[31] ^= 0x80;
        diff_decode(key);
    }
}

// One request whose reply may be FAIL: query() in test/diff_driver.h
// exits on FAIL. It returns 1 and the reply's bytes in r for an R, and 0
// for FAIL.
static int ask_r(const char *cmd, uint8_t r[32]) {
    char got[80];
    (void)fputs(cmd, to_spec);
    (void)fputc('\n', to_spec);
    (void)fflush(to_spec);
    if (fgets(got, (int)sizeof got, from_spec) == NULL) {
        die("spec process closed the pipe (did spec/lean/.lake/build/bin/diffspec build?)");
    }
    comparisons++;
    char *nl = strchr(got, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    if (strcmp(got, "FAIL") == 0) {
        return 0;
    }
    if (strlen(got) != 64 || !hex_decode(r, got, 32)) {
        (void)fprintf(stderr, "diff spec reply:\n  cmd:  %s\n  spec: %s\n", cmd, got);
        exit(1);
    }
    return 1;
}

static void verdict(int want, const uint8_t key[32], const uint8_t hram[64], const uint8_t r[32],
                    const uint8_t s[32], const char *cmd) {
    uint8_t sig[64];
    memcpy(sig, r, 32);
    memcpy(sig + 32, s, 32);
    if ((ed25519_verify_hram(key, hram, sig) != 0) != want) {
        (void)fprintf(stderr, "diff mismatch:\n  cmd:  %s\n  C %s an R the spec %s\n", cmd,
                      want ? "refused" : "accepted", want ? "accepts" : "refuses");
        exit(1);
    }
}

static void diff_verify(const uint8_t key[32], const uint8_t s[32]) {
    uint8_t hram[64];
    rng_fill(hram, sizeof hram);
    // The key, the hash and S in hex, which both requests take.
    char args[2 * (32 + 64 + 32) + 3];
    size_t at = hex_encode(args, key, 32);
    args[at++] = ' ';
    at += hex_encode(args + at, hram, 64);
    args[at++] = ' ';
    (void)hex_encode(args + at, s, 32);
    char cmd[sizeof args + 32];
    (void)snprintf(cmd, sizeof cmd, "ed25519_verify_r %s", args);
    uint8_t r[32];
    if (ask_r(cmd, r)) {
        verdict(1, key, hram, r, s, cmd);
        r[0] ^= 1;
        verdict(0, key, hram, r, s, cmd);
        r[0] ^= 1;
        r[31] ^= 0x80;
        verdict(0, key, hram, r, s, cmd);
    } else {
        memset(r, 0, sizeof r);
        verdict(0, key, hram, r, s, cmd);
        rng_fill(r, sizeof r);
        verdict(0, key, hram, r, s, cmd);
        // The R the loop computes, which the check must refuse too: it
        // shows a refusal the C does not make.
        (void)snprintf(cmd, sizeof cmd, "ed25519_point_r %s", args);
        if (ask_r(cmd, r)) {
            verdict(0, key, hram, r, s, cmd);
        }
    }
}

// Each key with an S of 0, L - 1, L and a random one below 2^252.
static void diff_verifies(const uint8_t key[32]) {
    uint8_t s[32] = {0};
    diff_verify(key, s);
    words_to_bytes(s, ED25519_L);
    s[0]--;
    diff_verify(key, s);
    s[0]++;
    diff_verify(key, s);
    rng_fill(s, sizeof s);
    s[31] &= 0x0f;
    diff_verify(key, s);
}

static void diff_mod_l(const uint8_t h[64]) {
    char cmd[COMMAND_SIZE];
    char want[65];
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_mod_l ");
    (void)hex_encode(cmd + at, h, 64);
    uint64_t out[4];
    reduce_mod_l(out, h);
    uint8_t bytes[32];
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

// scalar_reduce, the signer's reduction of a 64-byte hash, against the
// model's reduce.
static void diff_sign_reduce(const uint8_t h[64]) {
    char cmd[COMMAND_SIZE];
    char want[65];
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_sign_reduce ");
    (void)hex_encode(cmd + at, h, 64);
    uint64_t out[4];
    scalar_reduce(out, h);
    uint8_t bytes[32];
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

// scalar_muladd, r + k a modulo L, against the model's mulAdd, for r and k
// below L and an a of 32 bytes.
static void diff_muladd(const uint64_t r[4], const uint64_t k[4], const uint8_t a[32]) {
    char cmd[32 + 3 * 65];
    char want[65];
    uint8_t bytes[32];
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "ed25519_sign_muladd ");
    words_to_bytes(bytes, r);
    at += hex_encode(cmd + at, bytes, 32);
    cmd[at++] = ' ';
    words_to_bytes(bytes, k);
    at += hex_encode(cmd + at, bytes, 32);
    cmd[at++] = ' ';
    (void)hex_encode(cmd + at, a, 32);
    uint64_t out[4];
    scalar_muladd(out, r, k, a);
    words_to_bytes(bytes, out);
    (void)hex_encode(want, bytes, 32);
    expect(cmd, want);
}

// L less a, for a below L's word 0, which leaves words 1 to 3 as L's.
static void l_less(uint64_t o[4], uint64_t a) {
    memcpy(o, ED25519_L, 4 * sizeof o[0]);
    o[0] -= a;
}

static void diff_steps(void) {
    static const uint64_t fixed[][4] = {
        {0, 0, 0, 0},
        {1, 0, 0, 0},
        {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0x0fffffffffffffff)},
        {0, 0, 0, UINT64_C(0x1000000000000000)},
    };
    uint64_t o[4];
    for (uint64_t bit = 0; bit < 2; bit++) {
        for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
            diff_step(fixed[i], bit);
        }
        // (L - 1) / 2 and (L + 1) / 2: L is odd, so a shift of L down by
        // one is the first, and the first plus 1 the second.
        for (size_t i = 0; i < 4; i++) {
            o[i] = ED25519_L[i] >> 1 | (i < 3 ? ED25519_L[i + 1] << 63 : 0);
        }
        diff_step(o, bit);
        o[0]++;
        diff_step(o, bit);
        l_less(o, 1);
        diff_step(o, bit);
        for (int r = 0; r < RANDOM_ROWS; r++) {
            for (size_t i = 0; i < 4; i++) {
                o[i] = rng_next();
            }
            o[3] &= UINT64_C(0x0fffffffffffffff);
            diff_step(o, bit);
            l_less(o, 1 + rng_next() % (UINT64_C(1) << 32));
            diff_step(o, bit);
        }
    }
}

// Each r and k of 0, 1 and L - 1 with each a of 0, 1 and 2^256 - 1, then
// random r and k below 2^252 with random a.
static void diff_muladds(void) {
    uint64_t scalars[3][4] = {{0}, {1}};
    l_less(scalars[2], 1);
    uint8_t as[3][32] = {{0}, {1}};
    memset(as[2], 0xff, sizeof as[2]);
    for (size_t r = 0; r < 3; r++) {
        for (size_t k = 0; k < 3; k++) {
            for (size_t a = 0; a < 3; a++) {
                diff_muladd(scalars[r], scalars[k], as[a]);
            }
        }
    }
    for (int row = 0; row < RANDOM_ROWS; row++) {
        uint64_t r[4];
        uint64_t k[4];
        uint8_t a[32];
        for (size_t i = 0; i < 4; i++) {
            r[i] = rng_next();
            k[i] = rng_next();
        }
        r[3] &= UINT64_C(0x0fffffffffffffff);
        k[3] &= UINT64_C(0x0fffffffffffffff);
        rng_fill(a, sizeof a);
        diff_muladd(r, k, a);
    }
}

static void diff_reductions(void) {
    uint8_t h[64] = {0};
    diff_mod_l(h);
    diff_sign_reduce(h);
    memset(h, 0xff, sizeof h);
    diff_mod_l(h);
    diff_sign_reduce(h);
    for (uint64_t delta = 0; delta < 3; delta++) {
        uint64_t l_words[4];
        memcpy(l_words, ED25519_L, sizeof l_words);
        // L - 1, L and L + 1: word 0 of L ends in 0xed, so none carries.
        l_words[0] = l_words[0] - 1 + delta;
        memset(h, 0, sizeof h);
        words_to_bytes(h, l_words);
        diff_mod_l(h);
        diff_sign_reduce(h);
    }
    for (int r = 0; r < RANDOM_ROWS; r++) {
        rng_fill(h, sizeof h);
        diff_mod_l(h);
        diff_sign_reduce(h);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff ed25519: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_steps();
    diff_reductions();
    diff_muladds();
    diff_decodes();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff ed25519: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
