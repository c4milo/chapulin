// x25519.c compiled once more, on the native widening multiply and under the names
// widemul_native.h gives: the copy a host object runs for the answer WIDEMUL_CONSTANT_TIME
// (widemul.h, docs/decisions.md 87 and 89).
#include "widemul_native.h"

// After the renames, so they apply to every declaration the source includes.
#include "x25519.c"
