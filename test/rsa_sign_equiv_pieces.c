// rsa_sign64.c's reduction and recombination, which are static there, as
// two calls bin/rsa_sign_equiv_test can make on their own.
//
// Why this exists: inside rsa_sign64_sp1 the frame of each piece is
// written over by the calls that follow it, so the stack after a
// signature cannot show whether a piece wiped what it held. Called on its
// own, a piece's frame is the last one written, and
// test/rsa_sign_equiv_residue.h looks in it.
//
// This unit compiles rsa_sign64.c once more, under the binary's flags, and
// gives its four entries second names, because the binary links
// rsa_sign64.c itself too. The source is the same lines, so a wipe that
// file loses is lost here.
#define rsa_sign64_key_ok rsa_sign64_key_ok_pieces
#define rsa_sign64_power rsa_sign64_power_pieces
#define rsa_sign64_pss rsa_sign64_pss_pieces
#define rsa_sign64_sp1 rsa_sign64_sp1_pieces

#include "rsa_sign64.c"

#include "rsa_sign_equiv_pieces.h"

void rsa_sign_equiv_reduction(uint64_t *o, const uint64_t *em, size_t em_words,
                              const rsa_mont64_modulus *mod) {
    message_mod_prime(o, em, em_words, mod);
}

void rsa_sign_equiv_recombination(uint64_t *s, uint64_t *m1, uint64_t *m2, const uint8_t *qinv,
                                  size_t half_len, const rsa_mont64_modulus *mod_p,
                                  const rsa_mont64_modulus *mod_q) {
    crt_combine(s, m1, m2, qinv, half_len, mod_p, mod_q);
}
