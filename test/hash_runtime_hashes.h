// bin/hash_runtime_test's rows of the hash headers' own entries: sha256.h's, sha512.h's and
// sha3.h's that take a session's ch_cfg.cpu. test/hash_runtime_test.c alone includes this file,
// after it defines input, output, INPUT and OUTPUT.
#ifndef CH_TEST_HASH_RUNTIME_HASHES_H
#define CH_TEST_HASH_RUNTIME_HASHES_H

#include "sha256.h"
#include "sha3.h"
#include "sha512.h"

// sha256.h's entries.
static void row_sha256_update_final(uint32_t cpu) {
    sha256 s;
    sha256_init(&s);
    sha256_update_cpu(cpu, &s, input, 70);
    sha256_update_cpu(cpu, &s, input + 70, INPUT - 70);
    sha256_final_cpu(cpu, &s, output);
}

static void row_sha256_of(uint32_t cpu) {
    sha256_of_cpu(cpu, input, INPUT, output);
}

// sha512.h's entries: SHA-512 and SHA-384, each streamed and in one call.
static void row_sha512_update_final(uint32_t cpu) {
    sha512 s;
    sha512_init(&s);
    sha512_update_cpu(cpu, &s, input, 70);
    sha512_update_cpu(cpu, &s, input + 70, INPUT - 70);
    sha512_final_cpu(cpu, &s, output);
}

static void row_sha384_update_final(uint32_t cpu) {
    sha512 s;
    sha384_init(&s);
    sha512_update_cpu(cpu, &s, input, INPUT);
    sha384_final_cpu(cpu, &s, output);
}

static void row_sha512_of(uint32_t cpu) {
    sha512_of_cpu(cpu, input, INPUT, output);
}

static void row_sha384_of(uint32_t cpu) {
    sha384_of_cpu(cpu, input, INPUT, output);
}

// sha3.h's entries: SHA3-256 and SHA3-512 in one call, and SHAKE256 absorbed and squeezed in two
// pieces each. SHAKE's init takes no value.
static void row_sha3_256(uint32_t cpu) {
    sha3_256_cpu(cpu, input, INPUT, output);
}

static void row_sha3_512(uint32_t cpu) {
    sha3_512_cpu(cpu, input, INPUT, output);
}

static void row_shake(uint32_t cpu) {
    shake s;
    shake256_init(&s);
    shake_absorb_cpu(cpu, &s, input, 70);
    shake_absorb_cpu(cpu, &s, input + 70, INPUT - 70);
    shake_squeeze_cpu(cpu, &s, output, 100);
    shake_squeeze_cpu(cpu, &s, output + 100, OUTPUT - 100);
}

#endif
