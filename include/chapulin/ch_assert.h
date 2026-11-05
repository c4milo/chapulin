// Always-on assertions for programmer-error invariants — states that cannot
// happen unless the code is wrong. Operational errors (bad peer input, short
// buffers, I/O failures) keep returning ch_err codes; CH_ASSERT is never for
// those. The host implementation prints and aborts; a device maps
// ch_assert_fail to its fault handler, and the failure domain is the
// session, not the board.
#ifndef CH_ASSERT_H
#define CH_ASSERT_H

#include <stdnoreturn.h>

noreturn void ch_assert_fail(const char *cond, const char *file, int line);

#define CH_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            ch_assert_fail(#cond, __FILE__, __LINE__);                                             \
        }                                                                                          \
    } while (0)

#endif
