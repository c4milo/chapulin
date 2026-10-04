// The ChaCha20 and ChaCha20-Poly1305 calls a test makes as one session of its object makes them.
// A host binary (-DCH_CPU_RUNTIME) calls the entries that take a session's ch_cfg.cpu, with
// test_cpu, the value the binary runs under (test/test_cpu.h): the Makefile runs it once for each
// set of bits that changes a path, so the same vectors run the keystream on the 128-bit path and,
// on x86-64 under CH_CPU_AVX2, on the AVX2 kernel, and Poly1305 on each copy. Every other binary
// calls the entries its object holds, under the answer its build states (test/test_widemul.h).
//
// test/unit_test.c keeps RFC 8439's §2.4.2 and §2.8.2 vectors on chacha20_xor, aead_seal and
// aead_open themselves, which a host object holds beside these entries, for a server's ticket.
#ifndef CH_TEST_AEAD_H
#define CH_TEST_AEAD_H

#include "aead.h"
#include "chacha20.h"
#include "test_cpu.h"
#include "test_widemul.h"

#ifdef CH_CPU_RUNTIME
#define TEST_CHACHA20_XOR(...) chacha20_xor_cpu(test_cpu, __VA_ARGS__)
#define TEST_AEAD_SEAL(...) aead_seal_cpu(test_cpu, __VA_ARGS__)
#define TEST_AEAD_OPEN(...) aead_open_cpu(test_cpu, __VA_ARGS__)
#else
#define TEST_CHACHA20_XOR(...) chacha20_xor(__VA_ARGS__)
#define TEST_AEAD_SEAL(...) aead_seal(TEST_WIDEMUL, __VA_ARGS__)
#define TEST_AEAD_OPEN(...) aead_open(TEST_WIDEMUL, __VA_ARGS__)
#endif

#endif
