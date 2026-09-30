// The answer a test hands each call built on ct.h's widening multiply
// (widemul.h): TEST_WIDEMUL, a CH_WIDEMUL_ value. A binary may name it with
// -DTEST_WIDEMUL; every other binary hands on the answer its build states,
// WIDEMUL_BUILD_ANSWER, which is what the library's own sessions pass.
#ifndef CH_TEST_WIDEMUL_H
#define CH_TEST_WIDEMUL_H

#include "widemul.h"

#ifndef TEST_WIDEMUL
#define TEST_WIDEMUL WIDEMUL_BUILD_ANSWER
#endif

#endif
