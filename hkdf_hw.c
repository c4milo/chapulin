// hkdf.c compiled once more, with its hashes on the CPU's instructions and under the names
// hash_hw.h gives: the copy a host object runs for a session whose ch_cfg.cpu names the
// instructions of the hash a call runs (hkdf.h, docs/decisions.md 93).
#include "hash_hw.h"

// After the renames, so they apply to every declaration the source includes. hkdf.h declares
// each _hw name this copy defines for the callers that read it, so a definition here that
// differs from that declaration stops the compile.
#include "hkdf.c"
