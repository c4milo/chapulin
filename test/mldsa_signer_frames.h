// The checks of ML-DSA-87's two signing frames, which
// test/mldsa_signer_frames.c states (docs/decisions.md 191).
#ifndef CH_TEST_MLDSA_SIGNER_FRAMES_H
#define CH_TEST_MLDSA_SIGNER_FRAMES_H

#include <stdint.h>

// Runs the checks under cpu, the ch_cfg.cpu value of a host build, which
// every other build ignores. Returns the count of checks that failed.
unsigned mldsa_signer_frame_checks(uint32_t cpu);

#endif
