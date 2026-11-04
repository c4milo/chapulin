// SHA-256 (FIPS 180-4). Streaming, because the handshake transcript hash
// absorbs messages as they cross the wire; no message is ever buffered
// whole for hashing.
#ifndef CH_SHA256_H
#define CH_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32
#define SHA256_BLOCK 64

typedef struct {
    uint32_t h[8];
    uint64_t total_bytes; // total message bytes absorbed
    uint8_t block[SHA256_BLOCK];
    size_t fill; // bytes pending in block
} sha256;

void sha256_init(sha256 *s);
void sha256_update(sha256 *s, const uint8_t *in, size_t n);
// Finalizes into out[32]. s is spent; re-init to reuse. Does not wipe —
// callers hashing secrets wipe the context themselves.
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]);

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]);

#if defined(CH_CPU_RUNTIME) && !defined(__cplusplus)
#include "cpu_cfg.h"

// The three calls above that hash, on the CPU's SHA-256 instructions (sha256_hw.c,
// docs/decisions.md 93). A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds them beside
// sha256.c's, which stay the reference: CBMC proves the portable code, and bin/sha2_equiv_test
// holds these to it. Each has the contract of the call it is named for, on the same context
// type. sha256_init starts a context for either path, and the two paths keep the same state in
// it, so a context may take an update from one and its final from the other. sha256_of_hw also
// wipes the context it hashes in.
//
// Requires: what the portable call requires, and a CPU with the instructions
// CH_CPU_CONSTANT_TIME_SHA256 names, which the session's caller states. On a CPU without them
// the first one faults.
void sha256_update_hw(sha256 *s, const uint8_t *in, size_t n);
void sha256_final_hw(sha256 *s, uint8_t out[SHA256_LEN]);
void sha256_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]);

// A copy on the instructions (hash_hw.h) reads the declarations above and none of the entries
// below: every hash call it makes is already one on the instructions.
#ifndef CH_HASH_HW_H
// Whether a session's SHA-256 runs on the instructions: where cpu, the session's ch_cfg.cpu,
// holds CH_CPU_CONSTANT_TIME_SHA256, which the caller sets from its own probe and its own
// statement of the instructions' timing. chapulin probes no CPU.
static inline int sha256_on_instructions(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_SHA256) != 0;
}

// sha256_update, sha256_final and sha256_of for one session of a host object: each takes the
// session's ch_cfg.cpu first, under the same contract. A hash call holds no session, so a
// caller that holds one passes its description of the CPU in an argument: no global holds the
// value, and no hash context does. A caller with no session's value calls the names above,
// which run the portable code in every object. An entry branches once, on a value the caller
// chose and which is not secret, and calls through no function pointer. sha512.h, hkdf.h,
// keysched.h and transcript.h each end with their own entries in the same form
// (docs/decisions.md 93). The library builds as C, so C++ sees none of them. sha256_init writes
// the initial value alone and takes no description of the CPU.
static inline void sha256_update_cpu(uint32_t cpu, sha256 *s, const uint8_t *in, size_t n) {
    if (sha256_on_instructions(cpu)) {
        sha256_update_hw(s, in, n);
        return;
    }
    sha256_update(s, in, n);
}

static inline void sha256_final_cpu(uint32_t cpu, sha256 *s, uint8_t out[SHA256_LEN]) {
    if (sha256_on_instructions(cpu)) {
        sha256_final_hw(s, out);
        return;
    }
    sha256_final(s, out);
}

static inline void sha256_of_cpu(uint32_t cpu, const uint8_t *in, size_t n,
                                 uint8_t out[SHA256_LEN]) {
    if (sha256_on_instructions(cpu)) {
        sha256_of_hw(in, n, out);
        return;
    }
    sha256_of(in, n, out);
}
#endif
#endif

#endif
