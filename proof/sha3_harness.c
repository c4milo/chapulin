// Proves: the four SHA-3 modes are memory-safe and UB-free for any
// one-call message up to 200 bytes and any one-call XOF output up to
// 400 bytes, always from a fresh context. 200 passes every rate (72,
// 136, 168) and 400 passes two output blocks of either XOF rate, so
// whole-block absorbs, whole-block squeezes, tails, and every pad
// position run. The split-call streaming states are
// sha3_stream_harness.c's, which assumes an arbitrary context directly
// instead of producing it through prior calls. Keccak's lane
// arithmetic wraps by design, so only the UB classes are checked.
#include "harness.h"

#include "sha3.c"

int main(void) {
    uint8_t msg[200];
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    fill_nondet(msg, sizeof msg);

    uint8_t d32[SHA3_256_LEN];
    sha3_256(msg, n, d32);
    uint8_t d64[SHA3_512_LEN];
    sha3_512(msg, n, d64);

    uint8_t out[400];
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len <= sizeof out);

    shake s;
    shake128_init(&s);
    shake_absorb(&s, msg, n);
    shake_squeeze(&s, out, out_len);

    shake256_init(&s);
    shake_absorb(&s, msg, n);
    shake_squeeze(&s, out, out_len);
    return 0;
}
