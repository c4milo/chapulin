// The entries test/poly1305_ifma_model.c gives the AVX-512 IFMA Poly1305
// compiled over the lane model, for bin/poly1305_equiv_test and
// bin/diff_poly1305_ifma. Each runs the kernel's own text on any host.
#ifndef CH_TEST_POLY1305_IFMA_MODEL_H
#define CH_TEST_POLY1305_IFMA_MODEL_H

#include <stddef.h>
#include <stdint.h>

#include "poly1305.h"

// POLY1305_IFMA_GROUP and POLY1305_IFMA_MIN, which poly1305_ifma.h names
// only where the kernel exists.
extern const size_t poly1305_ifma_model_group;
extern const size_t poly1305_ifma_model_min;

// poly1305_init and poly1305_final, poly1305.c's under second names.
void poly1305_ifma_model_init(poly1305 *p, const uint8_t key[POLY1305_KEY]);
void poly1305_ifma_model_final(poly1305 *p, uint8_t tag[POLY1305_TAG]);
// poly1305_update_ifma: an update whose whole groups of POLY1305_IFMA_MIN
// bytes or more run on the model's kernel, and the rest on poly1305.c's
// loop.
void poly1305_ifma_model_update(poly1305 *p, const uint8_t *in, size_t n);
// poly1305_ifma_blocks: the kernel's entry.
void poly1305_ifma_model_blocks(poly1305 *p, const uint8_t *m, size_t n);

// A register's eight lanes as numbers: digit[i][l] is digit i of lane l. A
// struct, so that a pointer to a const one takes a plain one in C11.
typedef struct {
    uint64_t digit[3][8];
} poly1305_ifma_model_register;

// One group of sixteen blocks on the eight lanes: group_sums and carry, the
// loop body of poly1305_ifma_blocks, from the lanes' digits h, the 256 bytes
// at m, and the digits of the two multipliers.
void poly1305_ifma_model_group_step(poly1305_ifma_model_register *out,
                                    const poly1305_ifma_model_register *h, const uint8_t *m,
                                    const poly1305_ifma_model_register *first,
                                    const poly1305_ifma_model_register *second);
// compute_powers from r's five 26-bit words: the digits of last_first,
// last_second, by_16 and by_8, in that order.
void poly1305_ifma_model_powers(poly1305_ifma_model_register out[4], const uint32_t r[5]);

#endif
