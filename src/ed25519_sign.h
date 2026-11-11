// Ed25519 signing (RFC 8032 section 5.1.6), for a JWS under EdDSA (RFC
// 8037) under CH_JWS: ch_jws_sign calls it (jws.h). Its body is
// x25519_wide_ed25519_sign.h, which x25519_wide.c includes, because it
// runs on that file's radix-2^51 field, its table of multiples of the
// base point and its Edwards points.
#ifndef CH_ED25519_SIGN_H
#define CH_ED25519_SIGN_H

#include <stddef.h>
#include <stdint.h>

#if defined(CH_JWS) && defined(CH_CPU_RUNTIME)
// Writes the Ed25519 signature of the msg_len bytes at msg under seed to
// sig: R then S, 32 bytes each. seed is the 32-byte private key of RFC
// 8032 section 5.1.5, which the call hashes to the scalar and the prefix.
// The signature is a function of seed and msg, and the call draws nothing.
// msg may be NULL when msg_len is 0.
//
// The seed, the scalar, the prefix and the nonce r are secret. The field
// arithmetic is the wide field's, whose 64-bit products run in constant
// time only on a CPU whose caller states CH_CPU_CONSTANT_TIME_MULTIPLY, so
// the caller makes this call only under that bit. The arithmetic modulo
// L adds, subtracts and shifts, and selects by mask. No branch and no
// memory index reads a secret, and the call wipes each copy it makes.
//
// Before it writes sig, the call verifies the signature under the public
// key it computed, with ed25519_verify_hram. Returns 1 with sig written.
// Returns 0 when that check failed, and then sig holds zeros.
int ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len, uint8_t sig[64]);
#endif

#endif
