// Proves mlkem_harness.c's claims at ML-KEM-1024: its launch line passes
// -DCH_MLKEM_1024, so mlkem.c's K-PKE, modulus check and Fujisaki-Okamoto
// wrapper run at K = 4 over their whole fixed-size input domains, a
// 1568-byte ek and ciphertext and a 3168-byte dk (docs/decisions.md 150).
// One object holds one parameter set, so each set takes a formula of its
// own.
#ifndef CH_MLKEM_1024
#error "mlkem_1024_harness proves the -DCH_MLKEM_1024 build"
#endif
#include "mlkem_harness.c"
