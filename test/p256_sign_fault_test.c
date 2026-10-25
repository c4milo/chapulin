// The P-256 signer's two checks against injected faults
// (docs/decisions.md 153). The Makefile builds p256_sign.c with
// CH_P256_SIGN_FAULT_TEST, so the signer calls the two hooks below: one
// on k*G before its affine form, one on s before the scalar check. Each
// case changes one word of a coordinate of k*G, or one word of s, and
// requires both entries to refuse, to leave the caller's buffer and
// length as they were, and to have called the hook once. Without a
// fault, each entry must still write the vector's bytes.
//
// A host binary runs under the ch_cfg.cpu value it is handed
// (test/test_cpu.h), and the Makefile hands it one value with the
// multiply bit and one without, so the wide field's check and the 32-bit
// one each see every fault.
// p256_sign.h declares the two hooks under this define, which the
// Makefile also passes to p256_sign.c.
#ifndef CH_P256_SIGN_FAULT_TEST
#define CH_P256_SIGN_FAULT_TEST 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_sign.h"
#include "p256_sign_vectors.h"
#include "test_widemul.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "CH_ASSERT %s at %s:%d\n", cond, file, line);
    exit(2);
}

// The fault each case injects.
typedef enum {
    FAULT_NONE,
    FAULT_POINT_X,
    FAULT_POINT_Y,
    FAULT_POINT_Z,
    FAULT_S,
} fault_kind;

static fault_kind fault = FAULT_NONE;
// The word each fault changes, and how many times each hook ran.
static size_t fault_word = 0;
static int point_hook_calls = 0;
static int scalar_hook_calls = 0;

void p256_sign_fault_point(p256_point *point) {
    point_hook_calls++;
    if (fault == FAULT_POINT_X) {
        point->x.word[fault_word] ^= 0x00010000U;
    } else if (fault == FAULT_POINT_Y) {
        point->y.word[fault_word] ^= 0x00010000U;
    } else if (fault == FAULT_POINT_Z) {
        point->z.word[fault_word] ^= 0x00010000U;
    }
}

void p256_sign_fault_scalar(p256_scalar *s) {
    scalar_hook_calls++;
    if (fault == FAULT_S) {
        s->word[fault_word] ^= 0x00000100U;
    }
}

#ifdef CH_CPU_RUNTIME
#define SIGN_DETERMINISTIC(v, sig, len)                                                            \
    p256_sign_cpu(test_cpu, (v)->priv, (v)->msg_hash, (sig), P256_SIG_MAX, (len))
#define SIGN_HEDGED(v, sig, len)                                                                   \
    p256_sign_hedged_cpu(test_cpu, (v)->priv, (v)->msg_hash, (v)->noise, (sig), P256_SIG_MAX, (len))
#else
#define SIGN_DETERMINISTIC(v, sig, len)                                                            \
    p256_sign(TEST_WIDEMUL, (v)->priv, (v)->msg_hash, (sig), P256_SIG_MAX, (len))
#define SIGN_HEDGED(v, sig, len)                                                                   \
    p256_sign_hedged(TEST_WIDEMUL, (v)->priv, (v)->msg_hash, (v)->noise, (sig), P256_SIG_MAX, (len))
#endif

// One entry under the current fault: returns what it returned, and
// requires the hooks to have run once and, on a refusal, the outputs to
// be as they were.
static int sign_once(int hedged, const p256_hedged_vector *h, const p256_sign_vector *v,
                     uint8_t sig[P256_SIG_MAX], size_t *sig_len) {
    uint8_t before[P256_SIG_MAX];
    memset(sig, 0xaa, P256_SIG_MAX);
    memcpy(before, sig, sizeof before);
    *sig_len = 0x5a5a;
    point_hook_calls = 0;
    scalar_hook_calls = 0;
    int rc = hedged ? SIGN_HEDGED(h, sig, sig_len) : SIGN_DETERMINISTIC(v, sig, sig_len);
    CHECK(point_hook_calls == 1 && scalar_hook_calls == 1);
    if (rc != 1) {
        CHECK(memcmp(sig, before, sizeof before) == 0);
        CHECK(*sig_len == 0x5a5a);
    }
    return rc;
}

// Without a fault, both entries write the vectors' bytes, so the hooks
// change nothing on their own.
static void test_no_fault(void) {
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    fault = FAULT_NONE;
    const p256_sign_vector *v = &p256_sign_vectors[0];
    const p256_hedged_vector *h = &p256_hedged_vectors[0];
    CHECK(sign_once(0, h, v, sig, &sig_len) == 1);
    CHECK(sig_len == v->sig_len && memcmp(sig, v->sig, sig_len) == 0);
    CHECK(sign_once(1, h, v, sig, &sig_len) == 1);
    CHECK(sig_len == h->sig_len && memcmp(sig, h->sig, sig_len) == 0);
}

// One word of one coordinate of k*G changed: the affine point is off the
// curve, and the on-curve check refuses it. One word of s changed: s*k
// is not z + r*d, and the scalar check refuses it. Each fault runs at
// three words of each value and through both entries.
static void test_faults(void) {
    static const fault_kind kinds[] = {FAULT_POINT_X, FAULT_POINT_Y, FAULT_POINT_Z, FAULT_S};
    static const size_t words[] = {0, 3, P256_FE_WORDS - 1};
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
        for (size_t w = 0; w < sizeof words / sizeof words[0]; w++) {
            fault = kinds[k];
            fault_word = words[w];
            for (int hedged = 0; hedged < 2; hedged++) {
                CHECK(sign_once(hedged, &p256_hedged_vectors[1], &p256_sign_vectors[1], sig,
                                &sig_len) == 0);
            }
        }
    }
    fault = FAULT_NONE;
}

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    test_no_fault();
    test_faults();
    if (failures == 0) {
        (void)printf("p256_sign_fault: every fault in k*G and in s refused, the buffer kept\n");
    }
    return failures != 0;
}
