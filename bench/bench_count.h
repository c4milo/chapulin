// The two requests a benchmark's --count option puts around the one
// operation it counts (docs/decisions.md 235). BENCH_COUNT_START starts
// the count, and BENCH_COUNT_STOP ends it under a label.
//
// -DBENCH_CALLGRIND: valgrind's callgrind zeroes its counts and dumps them
// under the label, so one process counts every row (bench/insn-host.sh).
//
// -DBENCH_SDE: Intel SDE counts between two SSC marks, a move of an
// immediate into ebx and the bytes 64 67 90, which bench/insn-sde.sh names
// as -start_ssc_mark 111 and -stop_ssc_mark 222. SDE adds the counts of
// every region, so one process counts one row, which --only names. The
// label stays in the program's output alone.
//
// A build with neither defines BENCH_COUNTS as 0, and its programs take no
// --count.
#ifndef CH_BENCH_COUNT_H
#define CH_BENCH_COUNT_H

#if defined(BENCH_CALLGRIND)
#include <valgrind/callgrind.h>
#define BENCH_COUNTS 1
#define BENCH_COUNT_START() CALLGRIND_ZERO_STATS
#define BENCH_COUNT_STOP(label) CALLGRIND_DUMP_STATS_AT(label)
#elif defined(BENCH_SDE)
#define BENCH_COUNTS 1
#define BENCH_COUNT_START()                                                                        \
    __asm__ volatile("movl $0x111, %%ebx\n\t.byte 0x64, 0x67, 0x90" ::: "ebx")
#define BENCH_COUNT_STOP(label)                                                                    \
    do {                                                                                           \
        (void)(label);                                                                             \
        __asm__ volatile("movl $0x222, %%ebx\n\t.byte 0x64, 0x67, 0x90" ::: "ebx");                \
    } while (0)
#else
#define BENCH_COUNTS 0
#endif

#endif
