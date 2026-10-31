// The tcp_nonblocking harness's ch_record_in part, over a stub of
// tcp_nonblocking_advance. The record loop around the real step table
// took most of that formula's 292 s, so the step table and the input loop
// are proved apart, the way quic_step and quic_driver are: the stub
// states tcp_nonblocking_step.h's contract, and the tcp_nonblocking
// harness proves it of the real table.
#define CH_PROOF_STEP_STUB
#include "tcp_nonblocking_harness.c"
