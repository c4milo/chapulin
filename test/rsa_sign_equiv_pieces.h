// The three pieces of rsa_sign64.c that test/rsa_sign_equiv_pieces.c
// gives bin/rsa_sign_equiv_test a call for: its reduction of the message
// modulo a prime, its recombination and its blinded exponents, which are
// static in the file.
#ifndef CH_TEST_RSA_SIGN_EQUIV_PIECES_H
#define CH_TEST_RSA_SIGN_EQUIV_PIECES_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"
#include "rsa_sign.h"

// rsa_sign64.c's message_mod_prime.
void rsa_sign_equiv_reduction(uint64_t *o, const uint64_t *em, size_t em_words,
                              const rsa_mont64_modulus *mod);

// rsa_sign64.c's crt_combine.
void rsa_sign_equiv_recombination(uint64_t *s, uint64_t *m1, uint64_t *m2, const uint8_t *qinv,
                                  size_t half_len, const rsa_mont64_modulus *mod_p,
                                  const rsa_mont64_modulus *mod_q);

// rsa_sign64.c's blinded_exponents: e_p and e_q, half_len + 8 bytes each.
void rsa_sign_equiv_blinded_exponents(uint8_t *e_p, uint8_t *e_q, const ch_rsa_priv *k,
                                      size_t half_len, const uint8_t blind[RSA_BLIND_LEN]);

#endif
