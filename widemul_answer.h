// The answer an operation built on ct.h's widening multiply runs under, which widemul.h's
// dispatchers and widemul_p256.h's read: the two WIDEMUL_ values, the answer a session's
// ch_cfg.cpu gives, and in a device object the answer its build states (docs/decisions.md 87 and
// 89). widemul.h includes this file, and so does widemul_p256.h, which widemul.h includes at its
// end.
#ifndef CH_WIDEMUL_ANSWER_H
#define CH_WIDEMUL_ANSWER_H

#include <stdint.h>

#include "cfg.h"
#include "ct.h"

// The two answers an operation built on the multiply runs under. WIDEMUL_CONSTANT_TIME says the
// multiply runs in constant time on this CPU, in the mode the session's thread runs in, and takes
// the native multiply, 32x32->64 and 64x64->128 alike. WIDEMUL_NOT_STATED says nothing states
// that, and takes ct.h's 16x16
// decomposition. A host object's session runs under the first when its caller set
// CH_CPU_CONSTANT_TIME_MULTIPLY in ch_cfg.cpu, and under the second when it did not
// (widemul_answer). A device object runs every operation under the one its build states,
// WIDEMUL_BUILD_ANSWER.
#define WIDEMUL_CONSTANT_TIME 1
#define WIDEMUL_NOT_STATED 2

#ifdef CH_CPU_RUNTIME

// The answer a description of the CPU gives: WIDEMUL_CONSTANT_TIME when cpu, a session's
// ch_cfg.cpu, holds CH_CPU_CONSTANT_TIME_MULTIPLY, and WIDEMUL_NOT_STATED when it does not. A
// wiped record direction's 0 gives the second.
static inline uint8_t widemul_of_cpu(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 ? WIDEMUL_CONSTANT_TIME : WIDEMUL_NOT_STATED;
}

// The answer the operations of a session configured by cfg run under: the one its ch_cfg.cpu
// gives. Every init call and ch_srv_check have accepted the value by then (cpu_bits_ok, cpu.h).
static inline uint8_t widemul_answer(const ch_cfg *cfg) {
    return widemul_of_cpu(cfg->cpu);
}

// Whether an operation under the answer widemul runs the native copy: for
// WIDEMUL_CONSTANT_TIME alone, so every other byte takes the decomposition.
static inline int widemul_native(uint8_t widemul) {
    return widemul == WIDEMUL_CONSTANT_TIME;
}

#else // !CH_CPU_RUNTIME

// The answer every operation of a device object runs under: the one its build states, which
// ct.h reads from CH_NATIVE_WIDEMUL and CH_CT_WIDEMUL.
#ifdef CH_WIDEMUL_NATIVE
#define WIDEMUL_BUILD_ANSWER WIDEMUL_CONSTANT_TIME
#else
#define WIDEMUL_BUILD_ANSWER WIDEMUL_NOT_STATED
#endif

// The answer the operations of a session configured by cfg run under: the build's.
static inline uint8_t widemul_answer(const ch_cfg *cfg) {
    (void)cfg;
    return WIDEMUL_BUILD_ANSWER;
}

#endif // CH_CPU_RUNTIME

#endif
