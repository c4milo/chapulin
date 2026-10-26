// The first row of the mldsa_sign_hint_row proof: the same harness with
// HINT_ROW 0, so the two formulas hold the rows at both ends of sk's s2
// and t0. Every other row reads between them, by the same offsets times
// its index. A proof name is one launch line, so the row gets its own
// file.
#define HINT_ROW 0
#include "mldsa_sign_hint_row_harness.c"
