// SHA-512 and SHA-384 (FIPS 180-4). Streaming, the shape sha256.h has:
// a certificate's TBSCertificate is hashed as the reader walks it, never
// buffered whole. One context type serves both hashes, because SHA-384
// is SHA-512 run from its own initial value with the first 48 bytes of
// the result kept (FIPS 180-4 §5.3.4 and §6.5). sha512_update absorbs
// for either; only init and final know which hash is running.
//
// Two builds package this file. A TRUST=webpki object hashes public
// bytes with it: a certificate's TBS bytes for the ecdsa-with-SHA384
// and sha384WithRSAEncryption signatures a public chain carries, and
// the CertificateVerify signed content. A SUITE=aesgcm object runs
// TLS_AES_256_GCM_SHA384's key schedule on it, through hkdf.c's
// hmac_sha384 and the handshake transcript, so there it hashes secrets:
// HMAC keys and the PSK. That is why sha512.c and sha512_compress.c sit
// in the Makefile's WIDEMUL_CEILING and BRANCH_SRCS, where a compiler
// that puts a branch on a word shows as a count that grew. Every other
// build compiles SHA-256 alone.
#ifndef CH_SHA512_H
#define CH_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_LEN 64
#define SHA384_LEN 48
#define SHA512_BLOCK 128

typedef struct {
    uint64_t h[8];
    uint64_t total_bytes; // total message bytes absorbed
    uint8_t block[SHA512_BLOCK];
    size_t fill; // bytes pending in block
} sha512;

void sha512_init(sha512 *s);
void sha384_init(sha512 *s);
void sha512_update(sha512 *s, const uint8_t *in, size_t n);
// Finalizes into out. s is spent; re-init to reuse. Does not wipe, the
// way sha256_final does not: a caller that hashed a secret wipes the
// context itself, as hmac_sha384 does.
void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]);
// The SHA-384 digest: the same finalization, keeping the first 48 of
// the 64 result bytes (FIPS 180-4 §6.5 step 3). Only meaningful after
// sha384_init.
void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]);

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);

#if defined(CH_CPU_RUNTIME) && !defined(__cplusplus)
#include "cpu_cfg.h"

#ifdef __aarch64__
// The five calls above that hash, on arm64's SHA-512 instructions (sha512_hw.c,
// docs/decisions.md 93). An arm64 host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds them beside
// sha512.c's and sha512_compress.c's, which stay the reference: CBMC proves the portable code,
// and bin/sha2_equiv_test holds these to it. Each has the contract of the call it is named for,
// on the same context type. sha512_init and sha384_init start a context for either path, and
// the two paths keep the same state in it, so a context may take an update from one and its
// final from the other. sha512_of_hw and sha384_of_hw also wipe the context they hash in.
//
// Requires: what the portable call requires, and a CPU with the instructions
// CH_CPU_CONSTANT_TIME_SHA512 names, which the session's caller states. On a CPU without them
// the first one faults.
void sha512_update_hw(sha512 *s, const uint8_t *in, size_t n);
void sha512_final_hw(sha512 *s, uint8_t out[SHA512_LEN]);
void sha384_final_hw(sha512 *s, uint8_t out[SHA384_LEN]);
void sha512_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);
#endif

// A copy on the instructions (hash_hw.h) reads the declarations above and none of the entries
// below, as in sha256.h.
#ifndef CH_HASH_HW_H
#ifdef __aarch64__
// Whether a session's SHA-512 and SHA-384 run on the instructions: where cpu, the session's
// ch_cfg.cpu, holds CH_CPU_CONSTANT_TIME_SHA512, which the caller sets from its own probe and
// its own statement of the instructions' timing.
static inline int sha512_on_instructions(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_SHA512) != 0;
}

// The five calls above that hash, for one session of a host object: each takes the session's
// ch_cfg.cpu first, under the same contract, and branches once on sha512_on_instructions, as
// sha256.h's entries do. sha512_init and sha384_init take no description of the CPU.
static inline void sha512_update_cpu(uint32_t cpu, sha512 *s, const uint8_t *in, size_t n) {
    if (sha512_on_instructions(cpu)) {
        sha512_update_hw(s, in, n);
        return;
    }
    sha512_update(s, in, n);
}

static inline void sha512_final_cpu(uint32_t cpu, sha512 *s, uint8_t out[SHA512_LEN]) {
    if (sha512_on_instructions(cpu)) {
        sha512_final_hw(s, out);
        return;
    }
    sha512_final(s, out);
}

static inline void sha384_final_cpu(uint32_t cpu, sha512 *s, uint8_t out[SHA384_LEN]) {
    if (sha512_on_instructions(cpu)) {
        sha384_final_hw(s, out);
        return;
    }
    sha384_final(s, out);
}

static inline void sha512_of_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                 uint8_t out[SHA512_LEN]) {
    if (sha512_on_instructions(cpu)) {
        sha512_of_hw(in, n, out);
        return;
    }
    sha512_of(in, n, out);
}

static inline void sha384_of_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                 uint8_t out[SHA384_LEN]) {
    if (sha512_on_instructions(cpu)) {
        sha384_of_hw(in, n, out);
        return;
    }
    sha384_of(in, n, out);
}
#else
// No x86-64 CPU this tree targets has SHA-512 instructions, and cpu_cfg.h refuses
// CH_CPU_CONSTANT_TIME_SHA512 there, so an x86-64 object holds sha512.c alone: the answer is no
// for every value, and each entry runs the portable call.
static inline int sha512_on_instructions(uint32_t cpu) {
    (void)cpu;
    return 0;
}

static inline void sha512_update_cpu(uint32_t cpu, sha512 *s, const uint8_t *in, size_t n) {
    (void)cpu;
    sha512_update(s, in, n);
}

static inline void sha512_final_cpu(uint32_t cpu, sha512 *s, uint8_t out[SHA512_LEN]) {
    (void)cpu;
    sha512_final(s, out);
}

static inline void sha384_final_cpu(uint32_t cpu, sha512 *s, uint8_t out[SHA384_LEN]) {
    (void)cpu;
    sha384_final(s, out);
}

static inline void sha512_of_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                 uint8_t out[SHA512_LEN]) {
    (void)cpu;
    sha512_of(in, n, out);
}

static inline void sha384_of_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                 uint8_t out[SHA384_LEN]) {
    (void)cpu;
    sha384_of(in, n, out);
}
#endif
#endif
#endif

#endif
