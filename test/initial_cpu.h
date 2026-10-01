// The ch_cfg.cpu a QUIC host object's Initial calls take in the test binaries that call them
// directly (docs/decisions.md 89). In a QUIC host object, aes_public_key_initial,
// quic_initial_seal and quic_initial_open take the session's ch_cfg.cpu first, and the key runs on
// the AES instructions when the value holds CH_CPU_CONSTANT_TIME_AES and on the table when it does
// not (aes.h). The vector files call every build's shorter form, so the three macros below put
// test_initial_cpu in that place: a host binary sets it and runs the same vectors on each cipher.
// Every other build declares the shorter calls, and this header leaves them alone.
//
// A function-like macro named for the function it calls is not expanded again inside its own
// expansion (C11 6.10.3.4), so each macro calls the function it names. A file includes this header
// after aes.h and quic_initial.h, so their declarations keep their own text.
#ifndef CH_TEST_INITIAL_CPU_H
#define CH_TEST_INITIAL_CPU_H

#include <stdint.h>

#include "aes.h"
#include "quic_initial.h"

#ifdef CH_AES_TWO_CIPHERS
// The value the next Initial key is built under: the AES instructions stated unless the binary
// sets the probe's bit alone.
static uint32_t test_initial_cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES;

#define aes_public_key_initial(k, ...) aes_public_key_initial((k), test_initial_cpu, __VA_ARGS__)
#define quic_initial_seal(...) quic_initial_seal(test_initial_cpu, __VA_ARGS__)
#define quic_initial_open(...) quic_initial_open(test_initial_cpu, __VA_ARGS__)
#endif

#endif
