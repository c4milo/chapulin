// The <string.h> of the Cortex-M3 build in test/qemu-m3.sh. That build
// compiles with -nostdlibinc and links no libc, so it has no libc header,
// and ct_wipe.c includes <string.h> for memset. This header declares the
// routines test/qemu/m3_runtime.c defines and nothing else. m3_runtime.c
// includes it too, so a declaration that differs from its definition
// stops the build. The host build of the same sources takes the host's
// own header.
#ifndef CH_TEST_QEMU_LIBC_STRING_H
#define CH_TEST_QEMU_LIBC_STRING_H

#include <stddef.h>

void *memcpy(void *d, const void *s, size_t n);
void *memmove(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

#endif
