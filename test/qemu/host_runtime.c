// Host twin of the M3 runtime: same two hooks over the host libc, so
// m3_kat.c builds unchanged for both and the outputs can be diffed.
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>

void plat_write(const char *s) {
    (void)fputs(s, stdout);
}

void plat_exit(int code) {
    exit(code);
}
