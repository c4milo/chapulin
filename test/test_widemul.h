// The answer a test hands each call built on ct.h's widening multiply (widemul.h). A host binary
// (-DCH_CPU_RUNTIME) derives it from test_cpu, the ch_cfg.cpu value the binary runs under
// (test/test_cpu.h), as widemul_answer derives a session's: the Makefile runs each such binary
// with CH_CPU_CONSTANT_TIME_MULTIPLY and without it, so its vectors run on both copies. Every
// other binary hands on the answer its build states, WIDEMUL_BUILD_ANSWER, which is what the
// library's own sessions pass.
#ifndef CH_TEST_WIDEMUL_H
#define CH_TEST_WIDEMUL_H

#include <stdint.h>

#include "test_cpu.h"
#include "widemul.h"

#ifdef CH_CPU_RUNTIME
// The answer test_cpu gives.
static inline uint8_t test_widemul_answer(void) {
    return (test_cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 ? WIDEMUL_CONSTANT_TIME
                                                           : WIDEMUL_NOT_STATED;
}
#define TEST_WIDEMUL test_widemul_answer()
#else
#define TEST_WIDEMUL WIDEMUL_BUILD_ANSWER
#endif

#endif
