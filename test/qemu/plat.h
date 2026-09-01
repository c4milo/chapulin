// The contract between a smoke image's runtime and its test program:
// the runtime supplies console output and exit, and the program calls
// them. m3_runtime.c fills it with semihosting, host_runtime.c with
// stdio, so the same test source runs on both.
#ifndef PLAT_H
#define PLAT_H

void plat_write(const char *s);
void plat_exit(int code);

#endif
