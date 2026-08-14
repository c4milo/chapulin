// Always-on assertions for programmer-error invariants — states that cannot
// happen unless the code is wrong. Operational errors (bad peer input, short
// buffers, I/O failures) keep returning ms_err codes; MS_ASSERT is never for
// those. The host implementation prints and aborts; a device maps
// ms_assert_fail to its fault handler, and the failure domain is the
// session, not the board.
#ifndef MS_ASSERT_H
#define MS_ASSERT_H

#include <stdnoreturn.h>

noreturn void ms_assert_fail(const char *cond, const char *file, int line);

#define MS_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            ms_assert_fail(#cond, __FILE__, __LINE__);                                             \
        }                                                                                          \
    } while (0)

#endif
