// The two marks of the Valgrind taint lane (docs/decisions.md 155, INV-60).
//
// CT_SECRET(p, n) tells Memcheck that the n bytes at p are undefined. Memcheck then reports
// each conditional jump and each memory address that an undefined value decides, so a branch
// or a table index on a secret shows as an error. CT_PUBLIC(p, n) tells it that the n bytes
// at p are defined again: a test calls it on an output that the protocol publishes, or on a
// verdict that the caller sees, before it compares or prints the value.
//
// The marks are Valgrind client requests. A binary compiled with -DCH_CT_TAINT includes
// <valgrind/memcheck.h>, and each mark is a short sequence of instructions that does nothing
// outside Valgrind. Without the define each mark expands to nothing. No library source
// includes this header, and the packaged object's rule refuses the define (Makefile, LIB_DEF).
#ifndef CH_TEST_CT_TAINT_H
#define CH_TEST_CT_TAINT_H

#ifdef CH_CT_TAINT
#include <valgrind/memcheck.h>
#define CT_SECRET(p, n) ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#define CT_PUBLIC(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
// 1 when the binary runs under Valgrind, which is the only place the marks do anything.
#define CT_UNDER_VALGRIND() (RUNNING_ON_VALGRIND != 0)
#else
#define CT_SECRET(p, n) ((void)(p), (void)(n))
#define CT_PUBLIC(p, n) ((void)(p), (void)(n))
#define CT_UNDER_VALGRIND() 0
#endif

#endif
