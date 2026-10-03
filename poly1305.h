// Poly1305 one-time authenticator (RFC 8439 §2.5). 26-bit limbs with
// 64-bit products — portable C11, constant time: no branches or memory
// indices depend on the key or the message.
#ifndef CH_POLY1305_H
#define CH_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define POLY1305_KEY 32
#define POLY1305_TAG 16

typedef struct {
    uint32_t r[5];   // clamped key half, multiplier
    uint32_t h[5];   // accumulator
    uint32_t pad[4]; // key half added at the end
    uint8_t block[16];
    size_t fill;
} poly1305;

void poly1305_init(poly1305 *p, const uint8_t key[POLY1305_KEY]);
void poly1305_update(poly1305 *p, const uint8_t *in, size_t n);
// Writes the tag and wipes the context.
void poly1305_final(poly1305 *p, uint8_t tag[POLY1305_TAG]);

#ifdef CH_CPU_RUNTIME
// The native copies of the entries above that are built on the widening multiply,
// which a host object holds beside them (poly1305_native.c, widemul_native.h) and
// widemul.h's dispatchers call for WIDEMUL_CONSTANT_TIME.
void poly1305_update_native(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_final_native(poly1305 *p, uint8_t tag[POLY1305_TAG]);
#endif

#endif
