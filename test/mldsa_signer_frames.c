// The two frames of ML-DSA-87 signing (docs/decisions.md 191), for
// test/mldsa_signer_test.c:
//  - in a host object, the frame that computes A and the NTTs of the key
//    once against the frame a device object signs on, over 64 keys with
//    two mu and rnd each, the same rounds and the same bytes, and a key
//    out of range refused by both;
//  - in every build, the stack below a signature holds no two
//    coefficients of the NTT of the first and the last polynomial of s1,
//    s2 and t0, which a host object's frame holds for the whole signature
//    and a device object's round holds in turn.
#include "mldsa_signer_frames.h"

#include <stdio.h>
#include <string.h>

#include "ct.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_signer.h"
#include "sha3.h"

static unsigned failures;
#define CHECK(c)                                                                                   \
    do {                                                                                           \
        if (!(c)) {                                                                                \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                     \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// The cpu value the calls run under, which a host build passes on.
static uint32_t frame_cpu;

#ifdef CH_CPU_RUNTIME
#define KEYGEN(...) mldsa87_keygen_cpu(frame_cpu, __VA_ARGS__)
#define SIGN(...) mldsa87_sign_cpu(frame_cpu, __VA_ARGS__)
#else
#define KEYGEN mldsa87_keygen
#define SIGN mldsa87_sign
#endif

// n bytes of SHAKE128(label || counter), labels apart from the main
// test's.
static void fill(uint8_t *out, size_t n, uint32_t label, uint32_t counter) {
    uint8_t in[8];
    for (unsigned b = 0; b < 4; b++) {
        in[b] = (uint8_t)(label >> (8 * b));
        in[4 + b] = (uint8_t)(counter >> (8 * b));
    }
    shake h;
    shake128_init(&h);
    shake_absorb(&h, in, sizeof in);
    shake_squeeze(&h, out, n);
}

#ifdef CH_CPU_RUNTIME
// The host object's frame against the device object's, over one key, mu
// and rnd. Returns 1 when the two give other rounds or other bytes. With
// in_range 1 it also returns 1 when the key gives no signature, and with 0
// when it gives one; -1 expects neither.
static unsigned frames_differ(const uint8_t *sk, const uint8_t *pk, const uint8_t mu[64],
                              const uint8_t rnd[32], int in_range) {
    static uint8_t host[MLDSA87_SIG_LEN];
    static uint8_t device[MLDSA87_SIG_LEN];
    memset(host, 0xa5, sizeof host);
    memset(device, 0x5a, sizeof device);
    unsigned host_rounds = mldsa87_sign_mu_cpu(frame_cpu, host, sk, pk, mu, rnd);
    unsigned device_rounds = mldsa87_sign_mu_device_cpu(frame_cpu, device, sk, pk, mu, rnd);
    return host_rounds != device_rounds || memcmp(host, device, sizeof host) != 0 ||
           (in_range >= 0 && (in_range == 1) != (host_rounds != 0));
}

static void test_expanded_equals_device(void) {
    static uint8_t sk[MLDSA87_SK_LEN];
    static uint8_t pk[MLDSA87_PK_LEN];
    unsigned bad = 0;
    for (uint32_t n = 0; n < 64; n++) {
        uint8_t seed[32];
        uint8_t mu[64];
        uint8_t rnd[32];
        fill(seed, sizeof seed, 9, n);
        CHECK(KEYGEN(sk, pk, seed) == 1);
        for (uint32_t m = 0; m < 2; m++) {
            fill(mu, sizeof mu, 10, 2 * n + m);
            fill(rnd, sizeof rnd, 11, 2 * n + m);
            if (m == 1 && n % 8 == 0) {
                memset(rnd, 0, sizeof rnd);
            }
            bad += frames_differ(sk, pk, mu, rnd, 1);
        }
        // A bit of t0's last value changed: the two frames must still agree,
        // on the rounds and on the bytes, whatever the check under pk says.
        if (n % 16 == 1) {
            sk[MLDSA87_SK_LEN - 1] ^= 0x10;
            bad += frames_differ(sk, pk, mu, rnd, -1);
        }
    }
    // s2's last 3-bit value at 7, out of range: both frames refuse it.
    sk[128 + 15 * 96 - 1] |= 0xe0U;
    uint8_t mu[64] = {1};
    uint8_t rnd[32] = {2};
    bad += frames_differ(sk, pk, mu, rnd, 0);
    CHECK(bad == 0);
}
#endif

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

// The bytes the search reads below the caller: a host object's frame of
// 100 kB and the frames under it, or a device object's of 19 kB.
#define RESIDUE_BYTES 131072
static uint8_t residue[RESIDUE_BYTES];

static __attribute__((noinline)) void snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue);
}

// Whether the copy holds 8 bytes of p's coefficients at any 4-byte step:
// two coefficients of a polynomial the signer held in the NTT domain.
static int residue_holds_poly(const mld_poly *p) {
    const uint8_t *secret = (const uint8_t *)p->coeffs;
    for (size_t s = 0; s + 8 <= (size_t)MLD_N * 4; s += 4) {
        for (size_t i = 0; i + 8 <= RESIDUE_BYTES; i++) {
            if (memcmp(residue + i, secret + s, 8) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static __attribute__((noinline)) int sign_call(uint8_t *sig, const uint8_t *sk, const uint8_t *pk) {
    const uint8_t rnd[MLDSA87_RND_LEN] = {9};
    return SIGN(sig, sk, MLDSA87_SK_LEN, pk, MLDSA87_PK_LEN, NULL, 0, NULL, 0, rnd);
}

// NTT(s1[0]), NTT(s1[6]), NTT(s2[0]), NTT(s2[7]), NTT(t0[0]) and
// NTT(t0[7]) of sk, as the signer computes them, into hat.
static void key_hats(mld_poly hat[6], const uint8_t *sk) {
    static const unsigned at[6] = {128,           128 + 6 * 96,  128 + 7 * 96,
                                   128 + 14 * 96, 128 + 15 * 96, 128 + 15 * 96 + 7 * 416};
    for (unsigned k = 0; k < 6; k++) {
        if (k < 4) {
            mlds_unpack(&hat[k], sk + at[k], 3, 2);
        } else {
            mlds_unpack(&hat[k], sk + at[k], 13, 1 << 12);
        }
        mlds_poly_ntt(&hat[k]);
    }
}

static void test_wipes(void) {
    const char *reason = stack_residue_unsearched();
    if (reason != NULL) {
        (void)printf("mldsa signer: the stack is not searched: %s\n", reason);
        return;
    }
    static uint8_t sk[MLDSA87_SK_LEN];
    static uint8_t pk[MLDSA87_PK_LEN];
    static uint8_t sig[MLDSA87_SIG_LEN];
    static mld_poly hat[6];
    uint8_t seed[32];
    fill(seed, sizeof seed, 12, 0);
    CHECK(KEYGEN(sk, pk, seed) == 1);
    key_hats(hat, sk);
    CHECK(sign_call(sig, sk, pk) == 1);
    snapshot();
    unsigned held = 0;
    for (unsigned k = 0; k < 6; k++) {
        held += (unsigned)residue_holds_poly(&hat[k]);
    }
    CHECK(held == 0);
    ct_wipe(hat, sizeof hat);
}

unsigned mldsa_signer_frame_checks(uint32_t cpu) {
    frame_cpu = cpu;
    failures = 0;
#ifdef CH_CPU_RUNTIME
    test_expanded_equals_device();
#endif
    test_wipes();
    return failures;
}
