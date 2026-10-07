// poly1305_avx2.c compiled once more, on the native widening multiply and under the names
// widemul_native.h gives: the copy an x86-64 host object runs for a session whose ch_cfg.cpu
// holds CH_CPU_AVX2 under the answer WIDEMUL_CONSTANT_TIME (widemul.h, docs/decisions.md 110).
#include "widemul_native.h"

// After the renames, so they apply to every declaration the source includes.
#include "poly1305_avx2.c"
