// The answer a test hands each call built on ct.h's widening multiply
// (widemul.h): TEST_WIDEMUL, a CH_WIDEMUL_ value. A WIDEMUL=runtime binary
// names it with -DTEST_WIDEMUL, and the Makefile builds each such test once
// per answer, so its vectors run on both copies. Every other binary hands
// on the answer its build states, WIDEMUL_BUILD_ANSWER, which is what the
// library's own sessions pass.
#ifndef CH_TEST_WIDEMUL_H
#define CH_TEST_WIDEMUL_H

#include "widemul.h"

#ifndef TEST_WIDEMUL
#ifdef CH_WIDEMUL_RUNTIME
#error "a WIDEMUL=runtime test binary names its answer with -DTEST_WIDEMUL"
#endif
#define TEST_WIDEMUL WIDEMUL_BUILD_ANSWER
#endif

// Gives a configuration a test builds the answer TEST_WIDEMUL, which a
// WIDEMUL=runtime object requires of every init call (cpu_cfg.h), and does
// nothing in any other object, whose ch_cfg has no such field.
#ifdef CH_WIDEMUL_RUNTIME
#define TEST_WIDEMUL_CFG(cfg) ((cfg).widemul = TEST_WIDEMUL)
#else
#define TEST_WIDEMUL_CFG(cfg) ((void)(cfg))
#endif

#endif
