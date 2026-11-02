// Proves mlkem_poly_harness.c's claims on an object that runs both ranks:
// its launch line passes -DCH_MLKEM_TWO_RANKS, so mlkem_poly.c holds the
// compression at du = 10 and 11 and dv = 4 and 5, and the harness's free
// rank value reaches both (docs/decisions.md 177).
#ifndef CH_MLKEM_TWO_RANKS
#error "mlkem_poly_two_ranks_harness proves the -DCH_MLKEM_TWO_RANKS build"
#endif
#include "mlkem_poly_harness.c"
