// poly1305_vector.c compiled once more, on the native widening multiply and under the names
// widemul_native.h gives: the copy a WIDEMUL=runtime object runs for the answer
// CH_WIDEMUL_CONSTANT_TIME (widemul.h, docs/decisions.md 87).
#include "widemul_native.h"

// After the renames, so they apply to every declaration the source includes.
#include "poly1305_vector.c"
