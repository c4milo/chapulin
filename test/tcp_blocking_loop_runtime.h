// The row of the CH_CPU_CONSTANT_TIME_AES bit in the blocking loop
// (docs/decisions.md 81 and 89): test/tcp_blocking_loop_test.c built as
// bin/tcp_blocking_loop_aes, a ROLE=both SUITE=aesgcm host object whose
// client half is the raw client, so ch_connect runs the raw and ca
// configuration rules (tls.c) and ch_srv_accept the server's (srv.c).
// Every other case of that file runs in the same binary with both ends
// stating the AES instructions, TEST_CPU in a suite build
// (test/test_cpu.h), and test/tcp_blocking_loop_cpu.h holds the values
// both calls refuse.
//
// What the row holds: a whole handshake runs with both ends stating the
// probe's bit alone.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_RUNTIME_H
#define CH_TEST_TCP_BLOCKING_LOOP_RUNTIME_H
#if defined(CH_CPU_RUNTIME) && defined(CH_SUITE_AES_GCM)

static void test_runtime_answers(void) {
    // A whole handshake with both ends stating no AES instructions: the
    // raw client offers ChaCha20 alone in every build, and the server's
    // default order without the bit holds nothing else.
    blocking_cpu = CH_CPU_PROBED;
    client_reads_flight(0, 0);
    blocking_cpu = TEST_CPU;
}

#endif // CH_CPU_RUNTIME && CH_SUITE_AES_GCM
#endif
