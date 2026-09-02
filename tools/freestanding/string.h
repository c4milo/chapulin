// The <string.h> the codegen gates compile against.
//
// lint-wide-multiply and lint-runtime-symbols compile every secret-touching
// source with clang for a bare target (thumbv7m-none-eabi, mips-linux-musl,
// riscv32-unknown-elf), and a bare clang has its own <stdint.h> and
// <stddef.h> but no libc headers. The handshake sources reach for
// <string.h>, so without this file the gates could not build them, and a
// module the gate does not build is a module the gate does not measure.
// These are the five prototypes the library uses, with their C11 types, so
// what the gate compiles is what a libc's own header declares. The gcc
// specs never see it: a gcc driver comes with its libc's headers.
//
// Not part of the library. Nothing in the packaged object includes it.
#ifndef CH_FREESTANDING_STRING_H
#define CH_FREESTANDING_STRING_H

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

#endif
