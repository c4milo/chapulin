// ML-DSA-87's arm of the differential oracle: mldsa.c and mldsa_poly.c
// against spec/lean/Spec/MlDsa.lean, over the same Lean spec process
// test/diff_test.c drives (docs/decisions.md 154). Its own main, because
// no other row of bin/diff runs this code.
//
// Three kinds of row, each run on fresh random inputs:
// - mldsa87_challenge: a random key, mu and signature whose hints are well
//   formed and whose z is under gamma1 - beta, so every step of
//   Verify_internal runs on both sides and the 64-byte challenge they
//   recompute must match. Then the same with one hint encoding or one z
//   coefficient out of range, which both sides must refuse.
// - mldsa87_verify on a signature valid by construction: a key whose t1
//   is 0 and a signature whose z is 0, so w1 holds only what the hints
//   give, with a random message and context. Both sides must accept it,
//   and must agree on it with one random bit flipped.
// - mldsa87_verify with a context of 255 and of 256 bytes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "diff_driver.h"
#include "mldsa.h"
#include "mldsa_poly.h"
#include "sha3.h"

#define DIFF_HINT_AT (MLDSA87_CTILDE_LEN + MLD_L * MLD_Z_BYTES)

static char request[2 * (MLDSA87_PK_LEN + MLDSA87_SIG_LEN + 2 * 512) + 64];

// The hex of p, or "-" when n is 0, as the protocol spells an empty string.
static size_t put_hex(char *dst, const uint8_t *p, size_t n) {
    if (n == 0) {
        dst[0] = '-';
        dst[1] = '\0';
        return 1;
    }
    return hex_encode(dst, p, n);
}

// Packs 256 values of width bits, the low bit first.
static void pack_bits(uint8_t *out, const uint32_t *values, unsigned width) {
    memset(out, 0, (size_t)32 * width);
    for (unsigned i = 0; i < MLD_N; i++) {
        for (unsigned b = 0; b < width; b++) {
            unsigned at = i * width + b;
            out[at / 8] |= (uint8_t)(((values[i] >> b) & 1U) << (at % 8));
        }
    }
}

// Random hints, at most omega of them, each row's positions increasing.
static void random_hints(uint8_t y[MLD_HINT_BYTES]) {
    memset(y, 0, MLD_HINT_BYTES);
    unsigned used = 0;
    for (unsigned i = 0; i < MLD_K; i++) {
        unsigned count = (unsigned)rng_below(12);
        if (used + count > MLD_OMEGA) {
            count = MLD_OMEGA - used;
        }
        unsigned position = 0;
        for (unsigned h = 0; h < count && position < MLD_N; h++) {
            position += 1 + (unsigned)rng_below(20);
            if (position >= MLD_N) {
                break;
            }
            y[used] = (uint8_t)position;
            used++;
        }
        y[MLD_OMEGA + i] = (uint8_t)used;
    }
}

// z under gamma1 - beta, with the edge values gamma1 - beta - 1 and its
// negative among them.
static void random_z(uint8_t *out) {
    const uint32_t bound = MLD_GAMMA1 - MLD_BETA;
    uint32_t values[MLD_N];
    for (unsigned j = 0; j < MLD_L; j++) {
        for (unsigned i = 0; i < MLD_N; i++) {
            int32_t z = (int32_t)rng_below(2 * bound - 1) - (int32_t)(bound - 1);
            if (rng_below(64) == 0) {
                z = rng_below(2) ? (int32_t)(bound - 1) : -(int32_t)(bound - 1);
            }
            values[i] = (uint32_t)(MLD_GAMMA1 - z);
        }
        pack_bits(out + (size_t)j * MLD_Z_BYTES, values, 20);
    }
}

static void expect_challenge(const uint8_t *pk, const uint8_t *mu, const uint8_t *sig) {
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    static char want[2 * MLDSA87_CTILDE_LEN + 1];
    if (mldsa87_challenge(c_tilde, pk, mu, sig) == 1) {
        (void)hex_encode(want, c_tilde, sizeof c_tilde);
    } else {
        (void)strcpy(want, "FAIL");
    }
    size_t at = (size_t)snprintf(request, sizeof request, "mldsa87_challenge ");
    at += put_hex(request + at, pk, MLDSA87_PK_LEN);
    request[at++] = ' ';
    at += put_hex(request + at, mu, MLDSA_MU_LEN);
    request[at++] = ' ';
    (void)put_hex(request + at, sig, MLDSA87_SIG_LEN);
    expect(request, want);
}

static void diff_mldsa_challenge(void) {
    static uint8_t pk[MLDSA87_PK_LEN];
    static uint8_t sig[MLDSA87_SIG_LEN];
    uint8_t mu[MLDSA_MU_LEN];
    for (int round = 0; round < 4; round++) {
        rng_fill(pk, sizeof pk);
        rng_fill(mu, sizeof mu);
        rng_fill(sig, MLDSA87_CTILDE_LEN);
        random_z(sig + MLDSA87_CTILDE_LEN);
        random_hints(sig + DIFF_HINT_AT);
        expect_challenge(pk, mu, sig);
        // One position after the last run, which HintBitUnpack refuses.
        uint8_t *y = sig + DIFF_HINT_AT;
        if (y[MLD_OMEGA + MLD_K - 1] < MLD_OMEGA) {
            y[MLD_OMEGA - 1] = 1;
            expect_challenge(pk, mu, sig);
        }
        // A z coefficient at gamma1 - beta: 120 in the first 20 bits.
        random_hints(sig + DIFF_HINT_AT);
        sig[MLDSA87_CTILDE_LEN] = MLD_BETA;
        sig[MLDSA87_CTILDE_LEN + 1] = 0;
        sig[MLDSA87_CTILDE_LEN + 2] &= 0xf0;
        expect_challenge(pk, mu, sig);
    }
}

static void expect_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                          size_t ctx_len, const uint8_t *sig) {
    int ok = mldsa87_verify(pk, MLDSA87_PK_LEN, msg, msg_len, ctx, ctx_len, sig, MLDSA87_SIG_LEN);
    size_t at = (size_t)snprintf(request, sizeof request, "mldsa87_verify ");
    at += put_hex(request + at, pk, MLDSA87_PK_LEN);
    request[at++] = ' ';
    at += put_hex(request + at, msg, msg_len);
    request[at++] = ' ';
    at += put_hex(request + at, ctx, ctx_len);
    request[at++] = ' ';
    (void)put_hex(request + at, sig, MLDSA87_SIG_LEN);
    expect(request, ok ? "1" : "0");
}

static void shake256_into(uint8_t *out, size_t out_len, const uint8_t *a, size_t a_len,
                          const uint8_t *b, size_t b_len) {
    shake h;
    shake256_init(&h);
    shake_absorb(&h, a, a_len);
    shake_absorb(&h, b, b_len);
    shake_squeeze(&h, out, out_len);
}

// A key whose t1 is 0 and a signature with z = 0 and random hints. w' is
// then 0, and UseHint(1, 0) = 15, so w1Encode is 0 but for a nibble of 15
// at each hinted position, and c_tilde follows from SHAKE256 alone.
static void make_signature(uint8_t *pk, uint8_t *sig, const uint8_t *msg, size_t msg_len,
                           const uint8_t *ctx, size_t ctx_len) {
    memset(pk, 0, MLDSA87_PK_LEN);
    rng_fill(pk, MLD_RHO_BYTES);
    memset(sig, 0, MLDSA87_SIG_LEN);
    for (size_t at = MLDSA87_CTILDE_LEN; at < DIFF_HINT_AT; at += 5) {
        sig[at + 2] = 0x08;
        sig[at + 4] = 0x80;
    }
    uint8_t *y = sig + DIFF_HINT_AT;
    random_hints(y);
    uint8_t w1[MLD_K * MLD_W1_BYTES] = {0};
    unsigned first = 0;
    for (unsigned i = 0; i < MLD_K; i++) {
        for (unsigned h = first; h < y[MLD_OMEGA + i]; h++) {
            w1[i * MLD_W1_BYTES + y[h] / 2] |= (uint8_t)(15U << (4 * (y[h] % 2)));
        }
        first = y[MLD_OMEGA + i];
    }
    uint8_t tr[64];
    shake256_into(tr, sizeof tr, pk, MLDSA87_PK_LEN, NULL, 0);
    static uint8_t m_prime[2 + MLDSA_CONTEXT_MAX + 512];
    m_prime[0] = 0;
    m_prime[1] = (uint8_t)ctx_len;
    memcpy(m_prime + 2, ctx, ctx_len);
    memcpy(m_prime + 2 + ctx_len, msg, msg_len);
    uint8_t mu[MLDSA_MU_LEN];
    shake256_into(mu, sizeof mu, tr, sizeof tr, m_prime, 2 + ctx_len + msg_len);
    shake256_into(sig, MLDSA87_CTILDE_LEN, mu, sizeof mu, w1, sizeof w1);
}

static void diff_mldsa_verify(void) {
    static uint8_t pk[MLDSA87_PK_LEN];
    static uint8_t sig[MLDSA87_SIG_LEN];
    uint8_t msg[512];
    uint8_t ctx[MLDSA_CONTEXT_MAX + 1];
    for (int round = 0; round < 4; round++) {
        size_t msg_len = rng_below(sizeof msg + 1);
        size_t ctx_len = rng_below(MLDSA_CONTEXT_MAX + 1);
        rng_fill(msg, msg_len);
        rng_fill(ctx, ctx_len);
        make_signature(pk, sig, msg, msg_len, ctx, ctx_len);
        if (mldsa87_verify(pk, MLDSA87_PK_LEN, msg, msg_len, ctx, ctx_len, sig, MLDSA87_SIG_LEN) !=
            1) {
            die("mldsa87_verify refused a signature valid by construction");
        }
        expect_verify(pk, msg, msg_len, ctx, ctx_len, sig);
        size_t bit = rng_below((size_t)8 * MLDSA87_SIG_LEN);
        sig[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        expect_verify(pk, msg, msg_len, ctx, ctx_len, sig);
    }
    rng_fill(ctx, sizeof ctx);
    make_signature(pk, sig, msg, 0, ctx, MLDSA_CONTEXT_MAX);
    expect_verify(pk, msg, 0, ctx, MLDSA_CONTEXT_MAX, sig);
    expect_verify(pk, msg, 0, ctx, MLDSA_CONTEXT_MAX + 1, sig);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff mldsa-87: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_mldsa_challenge();
    diff_mldsa_verify();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff mldsa-87: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
