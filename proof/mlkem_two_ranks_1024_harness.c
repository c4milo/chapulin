// Proves mlkem_harness.c's claims on an object that runs both ranks, at
// rank 4: its launch line passes -DCH_MLKEM_TWO_RANKS, so each call takes
// the rank at run time, and every vector holds four polynomials
// (docs/decisions.md 177). Each rank takes a formula of its own: a free
// rank made every offset into dk and the ciphertext symbolic, and cbmc
// passed its 40-minute limit.
#ifndef CH_MLKEM_TWO_RANKS
#error "mlkem_two_ranks_1024_harness proves the -DCH_MLKEM_TWO_RANKS build"
#endif
#define MLKEM_HARNESS_RANK 4
#include "mlkem_harness.c"
