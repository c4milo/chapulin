#include "ct.h"

uint32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint32_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint32_t)(a[i] ^ b[i]);
    }
    // Folds any nonzero diff down to 0, zero to 1, without a branch.
    return (uint32_t)1 & ((diff - 1) >> 8);
}

void ct_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        v[i] = 0;
    }
}
