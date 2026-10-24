// Proves: ct_wipe.c with the 4-byte word of a 32-bit target meets the
// contract proof/ct_wipe_harness.c states, under the same bounds. The
// harnesses run on a 64-bit host, where the compiler defines
// __SIZEOF_INT128__, so this file removes that macro before ct_wipe.c
// reads it, and ct_wipe.c then takes uint32_t as its word, as it does on
// the Cortex-M3, mips32r2 and rv32 targets. n up to 64 gives up to 16
// words (docs/decisions.md 144).
#undef __SIZEOF_INT128__

#include "ct_wipe_harness.c"
