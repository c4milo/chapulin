// Constant-time byte operations. Everything in the stack that touches
// secret bytes compares through ct_memeq and wipes through ct_wipe; no
// secret ever decides a branch or a memory index anywhere else either.
#ifndef MS_CT_H
#define MS_CT_H

#include <stddef.h>
#include <stdint.h>

// 1 if a[0..n) == b[0..n), 0 otherwise. Time depends only on n.
uint32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n);

// Zeroizes p[0..n) through a volatile pointer so the store survives
// dead-store elimination.
void ct_wipe(void *p, size_t n);

#endif
