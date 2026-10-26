// gcm_arm64.c compiled once more with GCM_ARM64_EOR3: the passes add three
// values with EOR3, FEAT_SHA3's three-way exclusive-or, in place of each
// pair of EORs, and the entries take the names gcm_arm64.h gives this
// copy, gcm_seal_arm64_eor3 and gcm_open_arm64_eor3. gcm_arm64.h's
// gcm_use_eor3 picks them for a session whose ch_cfg.cpu holds
// CH_CPU_CONSTANT_TIME_SHA3 beside CH_CPU_CONSTANT_TIME_AES. That bit
// states that the CPU has FEAT_SHA3, whose instructions cpu_cfg.h names,
// EOR3 among them, and that they run in constant time on it. On x86-64
// this file compiles to nothing, as gcm_arm64.c does.
#define GCM_ARM64_EOR3

#include "gcm_arm64.c"
