// The first row of the mldsa_sign_keygen_row proof: the same harness with
// KEYGEN_ROW 0, so the two formulas hold the rows at both ends of sk's s2
// and t0 and of pk's t1. A proof name is one launch line, so the row gets
// its own file.
#define KEYGEN_ROW 0
#include "mldsa_sign_keygen_row_harness.c"
