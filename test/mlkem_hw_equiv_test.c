// bin/mlkem_hw_equiv_test: holds mlkem_hw.c and mlkem_poly_hw.c, ML-KEM-768
// with its SHA-3 and SHAKE calls on arm64's SHA-3 instructions, to mlkem.c
// and mlkem_poly.c, the code CBMC proves (docs/decisions.md 99). A copy is
// its file's own text compiled once more under keccak_hw.h's names, so
// this binary checks that the renames sent every call to the path they
// name and that the two paths write the same bytes.
//
// For random seeds it compares, on the two paths and under each answer a
// compression runs under (widemul.h): the encapsulation key and the
// decapsulation key; the ciphertext and the shared secret; the secret a
// decapsulation recovers; and the secret a decapsulation writes for a
// ciphertext with one bit changed, which is FIPS 203's implicit rejection.
// It also runs the three calls a session makes, under a ch_cfg.cpu value
// with and without CH_CPU_CONSTANT_TIME_SHA3.
//
// An object holds the instructions where clang compiled it for arm64
// (CH_KECCAK_INSTRUCTIONS, cpu_cfg.h). In any other object this binary says
// so and passes, and on a CPU without the instructions it skips. Under
// CH_REQUIRE_HASH_INSTRUCTIONS=1 it fails in either case instead
// (test/hash_instructions_cpu.h), so a run that must test the instructions
// cannot pass by testing nothing.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_instructions_cpu.h"
#include "mlkem.h"

#ifndef CH_CPU_RUNTIME
#error "bin/mlkem_hw_equiv_test links a host object's ML-KEM sources: -DCH_CPU_RUNTIME"
#endif

#ifndef CH_KECCAK_INSTRUCTIONS

int main(void) {
    if (hash_instructions_required()) {
        (void)fprintf(stderr,
                      "mlkem instructions equivalence: this object holds no Keccak on the "
                      "SHA-3 instructions (cpu_cfg.h), and CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
        return 1;
    }
    (void)printf("SKIP mlkem instructions equivalence: this object holds no Keccak on the SHA-3 "
                 "instructions (cpu_cfg.h)\n");
    return 0;
}

#else

// xorshift64 from a fixed seed, so a run replays the same cases.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        out[i] = (uint8_t)(rng_state >> 32);
    }
}

static unsigned long compared = 0;
static int failures = 0;

static void expect_same(const char *what, int at, const void *ours, const void *theirs, size_t n) {
    compared++;
    if (memcmp(ours, theirs, n) != 0) {
        failures++;
        (void)fprintf(stderr, "mlkem instructions equivalence: case %d: %s differ\n", at, what);
    }
}

#define CASES 200
// The two answers a compression runs under, widemul.h's WIDEMUL_CONSTANT_TIME
// and WIDEMUL_NOT_STATED, which this file cannot include: it reads ch_cfg.
#define ANSWER_NATIVE 1
#define ANSWER_DECOMPOSED 2
#define CPU_WITH_SHA3 (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_SHA3)

static uint8_t ek[2][MLKEM_EK_LEN];
static uint8_t dk[2][MLKEM_DK_LEN];
static uint8_t ct[2][MLKEM_CT_LEN];
static uint8_t ss[2][MLKEM_SS_LEN];
static uint8_t back[2][MLKEM_SS_LEN];

// Every third case changes one bit of its ciphertext, in a byte that moves on from case to
// case. Counters name the case and the byte: INV-23 keeps the division and modulo operators
// out of every file named for ML-KEM, this one too.
static int tampered_next = 0;
static size_t tampered_byte = 0;

// One case on the two paths: index 0 is mlkem.c and index 1 is its copy.
static void one_case(int at) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    uint8_t widemul = (at & 1) != 0 ? ANSWER_NATIVE : ANSWER_DECOMPOSED;
    rng_bytes(d, sizeof d);
    rng_bytes(z, sizeof z);
    rng_bytes(m, sizeof m);
    mlkem_keygen_derand(ek[0], dk[0], d, z);
    mlkem_keygen_derand_hw(ek[1], dk[1], d, z);
    expect_same("the encapsulation keys", at, ek[1], ek[0], MLKEM_EK_LEN);
    expect_same("the decapsulation keys", at, dk[1], dk[0], MLKEM_DK_LEN);
    int refused = mlkem_encaps_derand(widemul, ct[0], ss[0], ek[0], m);
    int refused_hw = mlkem_encaps_derand_hw(widemul, ct[1], ss[1], ek[1], m);
    expect_same("the two verdicts on the key", at, &refused_hw, &refused, sizeof refused);
    expect_same("the ciphertexts", at, ct[1], ct[0], MLKEM_CT_LEN);
    expect_same("the shared secrets", at, ss[1], ss[0], MLKEM_SS_LEN);
    if (at == tampered_next) {
        // One bit of the ciphertext changed: both paths reject it the same way.
        ct[0][tampered_byte] ^= 1;
        ct[1][tampered_byte] ^= 1;
        tampered_next += 3;
        tampered_byte += 5;
        if (tampered_byte >= MLKEM_CT_LEN) {
            tampered_byte = 0;
        }
    }
    mlkem_decaps(widemul, back[0], ct[0], dk[0]);
    mlkem_decaps_hw(widemul, back[1], ct[1], dk[1]);
    expect_same("the secrets a decapsulation writes", at, back[1], back[0], MLKEM_SS_LEN);

    // The three calls a session makes, under each kind of ch_cfg.cpu.
    mlkem_keygen_dk_cpu(CPU_WITH_SHA3, dk[1], d, z);
    expect_same("mlkem_keygen_dk_cpu with the bit and mlkem.c", at, dk[1], dk[0], MLKEM_DK_LEN);
    mlkem_keygen_dk_cpu(CH_CPU_PROBED, dk[1], d, z);
    expect_same("mlkem_keygen_dk_cpu without the bit and mlkem.c", at, dk[1], dk[0], MLKEM_DK_LEN);
    (void)mlkem_encaps_derand(widemul, ct[0], ss[0], ek[0], m);
    (void)mlkem_encaps_derand_cpu(CPU_WITH_SHA3, widemul, ct[1], ss[1], ek[0], m);
    expect_same("mlkem_encaps_derand_cpu's ciphertext and mlkem.c's", at, ct[1], ct[0],
                MLKEM_CT_LEN);
    mlkem_decaps_cpu(CPU_WITH_SHA3, widemul, back[1], ct[0], dk[0]);
    expect_same("mlkem_decaps_cpu's secret and the encapsulated one", at, back[1], ss[0],
                MLKEM_SS_LEN);
}

int main(void) {
    if (!cpu_has_sha3_instructions()) {
        if (hash_instructions_required()) {
            (void)fprintf(stderr, "mlkem instructions equivalence: this CPU lacks the SHA-3 "
                                  "instructions, and CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            return 1;
        }
        (void)printf("SKIP mlkem instructions equivalence: this CPU lacks the SHA-3 "
                     "instructions\n");
        return 0;
    }
    for (int at = 0; at < CASES; at++) {
        one_case(at);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "mlkem instructions equivalence: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("mlkem instructions equivalence: %lu values agree with mlkem.c\n", compared);
    return 0;
}

#endif // CH_KECCAK_INSTRUCTIONS
