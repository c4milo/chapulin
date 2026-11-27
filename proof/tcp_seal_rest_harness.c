// Proves proof/tcp_seal_harness.c's claims on ch_writable_len, ch_close_out
// and ch_fail_out (tcp_seal.c) in a formula of their own: that harness's
// main runs them under CH_PROOF_SEAL_REST, which this file sets, and the
// seal alone otherwise. ch_writable_len's answer is held to the most
// plaintext whose records fit cap, at any record limit and any cap of 11
// bits.
#define CH_PROOF_SEAL_REST
#include "tcp_seal_harness.c"
