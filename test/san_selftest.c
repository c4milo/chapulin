// The sanitizer lane's canary: a deliberate out-of-bounds read that
// must make an ASan/UBSan build abort. make san-selftest runs it and
// fails if the process exits cleanly, proving the sanitizer is armed
// in this build rather than silently disabled. Never part of any
// other target and never linted as library code.
#include <stdio.h>

int main(void) {
    volatile int canary[4] = {1, 2, 3, 4};
    volatile int i = 4; // one past the end, hidden from constant folding
    printf("%d\n", canary[i]);
    return 0;
}
