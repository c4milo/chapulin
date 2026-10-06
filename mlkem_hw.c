// mlkem.c compiled once more, with its SHA-3 and SHAKE calls on arm64's SHA-3 instructions and
// under the names keccak_hw.h gives: the copy a host object runs for a session whose ch_cfg.cpu
// holds CH_CPU_CONSTANT_TIME_SHA3 (mlkem.h, docs/decisions.md 99). An object holds the
// instructions where clang compiled it for arm64 (CH_KECCAK_INSTRUCTIONS, cpu_cfg.h), and in
// any other object this file holds nothing: <stdint.h> is here so that it is a translation
// unit still.
#include <stdint.h>

#include "cpu_cfg.h"

#ifdef CH_KECCAK_INSTRUCTIONS
#include "keccak_hw.h"

// After the renames, so they apply to every declaration the source includes. mlkem.h declares
// each _hw name this copy defines for the callers that read it, so a definition here that
// differs from that declaration stops the compile.
#include "mlkem.c"
#endif
