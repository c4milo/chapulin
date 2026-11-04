// SHA-3 and SHAKE (FIPS 202). The fixed-length digests are one-shot;
// the SHAKE XOFs absorb then squeeze through a context, because ML-KEM
// squeezes an open-ended stream from one absorbed seed (matrix
// expansion never knows its output length up front).
//
// The KEX=pq build packages this with mlkem.c, which squeezes both its
// matrix expansion and its noise from here. Every other build compiles
// it into test binaries only, the way the unselected PIN algorithm
// stays tested without shipping.
#ifndef CH_SHA3_H
#define CH_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define SHA3_256_LEN 32
#define SHA3_512_LEN 64

// Sponge rates in bytes: 200-byte state minus twice the capacity.
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

typedef struct {
    uint64_t lane[25];
    size_t rate;   // bytes absorbed or squeezed per permutation
    size_t pos;    // bytes into the current rate block
    int squeezing; // 0 while absorbing; 1 once the first squeeze ran
} shake;

// The one-shots wipe their internal sponge state before returning, so
// they are safe on secret input as-is.
void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]);
void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]);

void shake128_init(shake *s);
void shake256_init(shake *s);
// Absorb more message bytes. Never call after shake_squeeze on the same
// context: the sponge has been padded, and later input would land in
// squeezed state. Re-init to start a new message.
void shake_absorb(shake *s, const uint8_t *in, size_t n);
// Squeeze the next n output bytes. The first call pads and closes the
// message; later calls continue the same output stream, so squeezing
// n then m bytes equals the first n+m bytes of one squeeze. Does not
// wipe — callers absorbing secrets wipe the context themselves.
void shake_squeeze(shake *s, uint8_t *out, size_t n);

#if defined(CH_CPU_RUNTIME) && !defined(__cplusplus)
#include "cpu_cfg.h"

#ifdef CH_KECCAK_INSTRUCTIONS
// The six calls above with Keccak-f[1600] on arm64's SHA-3 instructions (sha3_hw.c,
// docs/decisions.md 99). An arm64 host object that clang compiled (cpu_cfg.h) holds them beside
// sha3.c's, which stay the reference: CBMC proves the portable code, and
// bin/sha3_hw_equiv_test holds these to it. Each has the contract of the call it is named for,
// on the same context type, and the two paths keep the same state in it, so a context may
// take a call from one path and the next from the other.
//
// Requires: what the portable call requires, and a CPU with the instructions
// CH_CPU_CONSTANT_TIME_SHA3 names, which the session's caller states. On a CPU without them
// the first permutation faults.
void sha3_256_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]);
void sha3_512_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]);
void shake128_init_hw(shake *s);
void shake256_init_hw(shake *s);
void shake_absorb_hw(shake *s, const uint8_t *in, size_t n);
void shake_squeeze_hw(shake *s, uint8_t *out, size_t n);
#endif

// A copy on the instructions (keccak_hw.h) reads the declarations above and none of the
// entries below, as sha512.h's copies do.
#ifndef CH_KECCAK_HW_H
#ifdef CH_KECCAK_INSTRUCTIONS
// Whether a session's Keccak runs on the instructions: where cpu, the session's ch_cfg.cpu,
// holds CH_CPU_CONSTANT_TIME_SHA3, which the caller sets from its own probe and its own
// statement of the instructions' timing.
static inline int sha3_on_instructions(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_SHA3) != 0;
}

// The four calls above that run the permutation, for one session of a host object: each
// takes the session's ch_cfg.cpu first, under the same contract, and branches once on
// sha3_on_instructions. shake128_init and shake256_init write zeros and take no description
// of the CPU.
static inline void sha3_256_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                uint8_t out[SHA3_256_LEN]) {
    if (sha3_on_instructions(cpu)) {
        sha3_256_hw(in, n, out);
        return;
    }
    sha3_256(in, n, out);
}

static inline void sha3_512_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                uint8_t out[SHA3_512_LEN]) {
    if (sha3_on_instructions(cpu)) {
        sha3_512_hw(in, n, out);
        return;
    }
    sha3_512(in, n, out);
}

static inline void shake_absorb_cpu(uint32_t cpu, shake *s, const uint8_t *in, size_t n) {
    if (sha3_on_instructions(cpu)) {
        shake_absorb_hw(s, in, n);
        return;
    }
    shake_absorb(s, in, n);
}

static inline void shake_squeeze_cpu(uint32_t cpu, shake *s, uint8_t *out, size_t n) {
    if (sha3_on_instructions(cpu)) {
        shake_squeeze_hw(s, out, n);
        return;
    }
    shake_squeeze(s, out, n);
}
#else
// An object that holds sha3.c alone: one for x86-64, whose CPUs have no SHA-3 instructions and
// whose cpu_cfg.h refuses CH_CPU_CONSTANT_TIME_SHA3, or one for arm64 that a compiler other
// than clang built (cpu_cfg.h, docs/decisions.md 99). The answer is no for every value, and
// each entry runs the portable call.
static inline int sha3_on_instructions(uint32_t cpu) {
    (void)cpu;
    return 0;
}

static inline void sha3_256_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                uint8_t out[SHA3_256_LEN]) {
    (void)cpu;
    sha3_256(in, n, out);
}

static inline void sha3_512_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                uint8_t out[SHA3_512_LEN]) {
    (void)cpu;
    sha3_512(in, n, out);
}

static inline void shake_absorb_cpu(uint32_t cpu, shake *s, const uint8_t *in, size_t n) {
    (void)cpu;
    shake_absorb(s, in, n);
}

static inline void shake_squeeze_cpu(uint32_t cpu, shake *s, uint8_t *out, size_t n) {
    (void)cpu;
    shake_squeeze(s, out, n);
}
#endif
#endif
#endif

#endif
