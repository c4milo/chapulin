// Proves: poly1305 init/update/final are memory-safe and UB-free for any
// key and any message delivered in any three-chunk split totaling up to
// 80 bytes — five blocks' worth, crossing the buffered-block path in every
// alignment. The 64-bit limb products cannot overflow: h and r limbs are
// bounded by construction and CBMC checks every multiply and add.
#include "harness.h"

#include "poly1305.c"

int main(void) {
    uint8_t key[POLY1305_KEY];
    uint8_t msg[80];
    uint8_t tag[POLY1305_TAG];
    fill_nondet(key, sizeof key);
    fill_nondet(msg, sizeof msg);

    size_t n1 = nondet_size_t();
    size_t n2 = nondet_size_t();
    size_t n3 = nondet_size_t();
    __CPROVER_assume(n1 <= sizeof msg);
    __CPROVER_assume(n2 <= sizeof msg - n1);
    __CPROVER_assume(n3 <= sizeof msg - n1 - n2);

    poly1305 p;
    poly1305_init(&p, key);
    poly1305_update(&p, msg, n1);
    poly1305_update(&p, msg + n1, n2);
    poly1305_update(&p, msg + n1 + n2, n3);
    poly1305_final(&p, tag);
    return 0;
}
