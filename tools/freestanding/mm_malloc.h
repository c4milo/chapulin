// The <mm_malloc.h> lint-frame-align and lint-wide-multiply's two 64-bit
// specs compile against.
//
// clang's <immintrin.h> includes <mm_malloc.h> in a hosted compile, and
// clang's own copy of that header includes <stdlib.h>, which a clang with
// no libc headers lacks. Both lints compile a host object's sources hosted,
// because -ffreestanding changes their code: it implies -fno-builtin, and
// under that clang keeps keccak_avx2.c's 25 lanes in an array on the stack
// and aligns the frame for the array, which the object `make lib` builds
// does not do (docs/decisions.md 124 and 126). This directory comes before
// clang's own on the include path, so the compile reads this file. The
// sources allocate nothing, so it declares nothing. A compile with
// -ffreestanding never includes it.
//
// Not part of the library. Nothing in the packaged object includes it.
#ifndef CH_FREESTANDING_MM_MALLOC_H
#define CH_FREESTANDING_MM_MALLOC_H
#endif
