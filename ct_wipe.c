// ct_wipe, which ct.h declares. It sits in a file of its own so that the
// proofs can link proof/ct_wipe_stub.c in its place (docs/decisions.md 91).
#include <string.h>

#include "ct.h"

// ct_wipe calls the libc's memset through this pointer. The pointer is a
// volatile object, so the compiler must load it every time ct_wipe runs
// (C11 5.1.2.3p6), and it cannot tell from the code which function the
// load returns. So it cannot delete the call, and it cannot treat the call
// as a memset whose stores no later read needs, even where it inlines
// ct_wipe into a caller whose buffer ends right after the call, as
// link-time optimization does. memset itself is compiled apart from every
// caller, so it writes each byte. docs/decisions.md 91 lists the compilers
// and targets whose output was read.
static void *(*const volatile ct_memset)(void *, int, size_t) = memset;

void ct_wipe(void *p, size_t n) {
    // C11 7.24.1p2 asks memset for a valid pointer even when n is 0, and a
    // caller with nothing to wipe may hold a null one.
    if (n != 0) {
        ct_memset(p, 0, n);
    }
}
