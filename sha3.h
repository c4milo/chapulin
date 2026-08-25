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

#endif
