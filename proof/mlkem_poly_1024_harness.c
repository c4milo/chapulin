// Proves mlkem_poly_harness.c's claims at ML-KEM-1024: its launch line
// passes -DCH_MLKEM_1024, so mlkem_poly.c's compression runs at du = 11
// and dv = 5 over four polynomials (docs/decisions.md 150). The NTT, its
// inverse and the base multiplication do not depend on the parameter set,
// so their four harnesses cover both.
#ifndef CH_MLKEM_1024
#error "mlkem_poly_1024_harness proves the -DCH_MLKEM_1024 build"
#endif
#include "mlkem_poly_harness.c"
