// The x86-64 X25519 field: the RFC 7748 Montgomery ladder over 2^255-19 on
// four 64-bit words, its products on MULX and its sums on ADCX and ADOX. An
// x86-64 host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it beside
// x25519_wide.c's field, and widemul.h runs a shared secret on it for a
// session whose ch_cfg.cpu holds CH_CPU_BMI2_ADX beside
// CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 165). A public key runs
// on x25519_wide.c's table in every such session.
#ifndef CH_X25519_ADX_H
#define CH_X25519_ADX_H

#include <stdint.h>

#include "x25519.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_X25519_ADX_MODEL))
// x25519 (x25519.h) on this field, under the same contract. x25519_adx.c
// compiles it from x25519.c, so the clamp and the all-zero check are that
// file's for all three fields.
int x25519_adx(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
               const uint8_t point[X25519_LEN]);

// out = the u-coordinate of clamped * point, for a scalar x25519.c has
// already clamped. It reports nothing: whether out is all zero is
// x25519_adx()'s return value (INV-3), decided after this returns.
void x25519_adx_ladder(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN],
                       const uint8_t point[X25519_LEN]);

#ifdef CH_X25519_ADX_TEST
// x25519_adx.c's five operations on four words under 2^256, and its final
// reduction to the value under p, for bin/x25519_adx_equiv_test alone.
void x25519_adx_test_mul(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_test_sqr(uint64_t o[4], const uint64_t a[4]);
void x25519_adx_test_add(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_test_sub(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]);
void x25519_adx_test_mul_a24(uint64_t o[4], const uint64_t a[4]);
void x25519_adx_test_reduce(uint64_t a[4]);
#endif
#endif

#endif
