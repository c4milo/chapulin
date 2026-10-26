// gcm_arm64_eor3.c's two entries under the second names
// test/aes_runtime_hw.c's counting entries call, in a unit apart from
// gcm_arm64.c's, whose file-local names they share. gcm_arm64_eor3.c
// calls gcm_counter_blocks_hw, which test/aes_runtime_hw.c defines as a
// counting entry, so the call counts as an instruction call. On a target
// other than arm64 this unit compiles to nothing but its includes.
#define gcm_seal_arm64_eor3 instruction_seal_arm64_eor3
#define gcm_open_arm64_eor3 instruction_open_arm64_eor3

#include "gcm_arm64_eor3.c"
