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
// sha256_update and sha256_final for one session of a host object (-DCH_CPU_RUNTIME,
// cpu_cfg.h): each takes the session's ch_cfg.cpu first, under the same contract. A hash call
// holds no session, so a caller that holds one passes its description of the CPU in an
// argument: no global holds the value, and no hash context does. A caller with no session's
// value calls the names above, which run the portable code in every object. sha512.h, hkdf.h,
// keysched.h and transcript.h each end with their own calls in the same form
// (docs/decisions.md 93). The library builds as C, so C++ sees none of them.
//
// No object holds SHA-256 on the CPU's instructions yet, so both run the portable call whatever
// cpu says. sha256_init writes the initial value alone and takes no description of the CPU.
static inline void sha256_update_cpu(uint32_t cpu, sha256 *s, const uint8_t *in, size_t n) {
    (void)cpu;
    sha256_update(s, in, n);
}

static inline void sha256_final_cpu(uint32_t cpu, sha256 *s, uint8_t out[SHA256_LEN]) {
    (void)cpu;
    sha256_final(s, out);
}
#endif

#endif
