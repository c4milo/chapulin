// SHA-512 and SHA-384 (FIPS 180-4): the two initial values, and the five calls that hash
// (sha512.h), in two arms.
//
// The second arm is a device object's, and the reference: update, the padding and the digest
// move one byte at a time, in the loops proof/sha512_harness.c proves, around
// sha512_compress.c's compression function.
//
// A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles the first arm in its place, in every
// session, because the arm is plain C that reads no table and no caller has to state anything
// about the CPU (docs/decisions.md 127). It copies with memcpy, writes the length and the digest
// as whole words, compresses on sha512_compress_blocks.c, and wipes the stack below each
// compression call. bin/sha2_equiv_test compiles both arms into one binary and requires the
// same contexts and the same digests from them.
//
// sha512_hw.c compiles the first arm once more for an x86-64 host object, under the _hw names
// hash_hw.h gives the five calls, for a session whose ch_cfg.cpu holds CH_CPU_AVX2
// (docs/decisions.md 128). That copy defines CH_SHA512_AVX2_COPY. It differs from this file in
// two places, each under that define: it compresses on sha512_avx2.c's kernel, and it holds no
// initial value and no init call, which both paths take from this file.
#include "sha512.h"

#ifndef CH_SHA512_AVX2_COPY
// FIPS 180-4 §5.3.5: the SHA-512 initial value, the first 64 bits of the
// fractional parts of the square roots of the first eight primes.
static const uint64_t IV512[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
                                  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

// FIPS 180-4 §5.3.4: the SHA-384 initial value, the same bits of the
// ninth through sixteenth primes.
static const uint64_t IV384[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                                  0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                                  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

// Straight-line, the shape sha256_init has: with no loop the static
// analyzer inlines it and carries fill = 0 into update, where the tail
// copy's index is otherwise unknown to it.
static void init_from(sha512 *s, const uint64_t iv[8]) {
    s->h[0] = iv[0];
    s->h[1] = iv[1];
    s->h[2] = iv[2];
    s->h[3] = iv[3];
    s->h[4] = iv[4];
    s->h[5] = iv[5];
    s->h[6] = iv[6];
    s->h[7] = iv[7];
    s->total_bytes = 0;
    s->fill = 0;
}

void sha512_init(sha512 *s) {
    init_from(s, IV512);
}

void sha384_init(sha512 *s) {
    init_from(s, IV384);
}
#endif // CH_SHA512_AVX2_COPY

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ct.h"

// The compression function this arm calls and the bytes of stack it wipes below each call:
// sha512_compress_blocks.c's, and in sha512_hw.c's copy sha512_avx2.c's kernel, which has the
// same contract and a frame of its own length.
#ifdef CH_SHA512_AVX2_COPY
#include "sha512_avx2.h"
#define COMPRESS_BLOCKS sha512_avx2_compress_blocks
#define COMPRESS_BLOCKS_BELOW_LEN SHA512_AVX2_BELOW_LEN
#else
#include "sha512_compress_blocks.h"
#define COMPRESS_BLOCKS sha512_compress_blocks
#define COMPRESS_BLOCKS_BELOW_LEN SHA512_COMPRESS_BLOCKS_BELOW_LEN
#endif

// SHA-384 is the hash of TLS_AES_256_GCM_SHA384's key schedule, so this arm reads HMAC keys and
// traffic secrets. The compression function leaves words of its message schedule in its frame,
// and whichever registers its compiler wrote to stack slots of its own, which no ct_wipe can
// name. So each call of it below is followed by a wipe of the stack it used, in
// p256_wide_wipe.c's form.
//
// The frame of this function is the array. ct_wipe is compiled apart from it and takes the
// array's address, so the compiler keeps the array in memory and cannot delete the call.
static void wipe_frame(void) {
    uint8_t below[COMPRESS_BLOCKS_BELOW_LEN];
    ct_wipe(below, sizeof below);
}

// compress_blocks calls wipe_frame through this pointer, which is a volatile object
// (docs/decisions.md 91). So the compiler cannot tell which function the call runs and cannot
// compile it into the caller, where the array would join the caller's frame and lie above the
// frame it is there to wipe.
static void (*const volatile wipe_frame_call)(void) = wipe_frame;

// The compression function over blocks whole blocks at p, and the wipe of the stack it used.
// The compression function is another source's, so its frame lay right under the frame of the
// function this one is compiled into, where wipe_frame's array lies next.
static void compress_blocks(uint64_t h[8], const uint8_t *p, size_t blocks) {
    COMPRESS_BLOCKS(h, p, blocks);
    wipe_frame_call();
}

// One word, most significant byte first, into the eight bytes at out. gcc and clang compile the
// eight stores to a byte swap and one 8-byte store on a little-endian target.
static inline void store_word(uint64_t v, uint8_t out[8]) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    // No byte to take: in may be NULL, which no step below may offset or copy from.
    if (n == 0) {
        return;
    }
    s->total_bytes += n;
    if (s->fill > 0) {
        size_t take = SHA512_BLOCK - s->fill;
        if (take > n) {
            take = n;
        }
        memcpy(s->block + s->fill, in, take);
        s->fill += take;
        in += take;
        n -= take;
        if (s->fill < SHA512_BLOCK) {
            return;
        }
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    size_t whole = n / SHA512_BLOCK;
    if (whole > 0) {
        compress_blocks(s->h, in, whole);
        in += whole * SHA512_BLOCK;
        n -= whole * SHA512_BLOCK;
    }
    memcpy(s->block, in, n);
    s->fill = n;
}

// FIPS 180-4 §5.1.2: the 1 bit, zeros to 112 mod 128, then the message bit length as a 128-bit
// big-endian integer, written into the pending block as the second arm's finalize writes it.
static void finalize(sha512 *s) {
    uint64_t high = s->total_bytes >> 61;
    uint64_t low = s->total_bytes << 3;
    s->block[s->fill++] = 0x80;
    if (s->fill > SHA512_BLOCK - 16) {
        memset(s->block + s->fill, 0, SHA512_BLOCK - s->fill);
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    memset(s->block + s->fill, 0, SHA512_BLOCK - 16 - s->fill);
    store_word(high, s->block + SHA512_BLOCK - 16);
    store_word(low, s->block + SHA512_BLOCK - 8);
    compress_blocks(s->h, s->block, 1);
    s->fill = 0;
}

// The first count words of h, each most significant byte first, into out.
static void store_digest(const uint64_t *h, size_t count, uint8_t *out) {
    for (size_t i = 0; i < count; i++) {
        store_word(h[i], out + 8 * i);
    }
}

void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]) {
    finalize(s);
    store_digest(s->h, 8, out);
}

void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    finalize(s);
    store_digest(s->h, 6, out);
}

// The context is on this frame, so the call wipes it: the state after the last block and the
// bytes of that block. sha512_final leaves a caller's context as it is (sha512.h).
void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    sha512 s;
    sha512_init(&s);
    sha512_update(&s, in, n);
    sha512_final(&s, out);
    ct_wipe(&s, sizeof s);
}

void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    sha512 s;
    sha384_init(&s);
    sha512_update(&s, in, n);
    sha384_final(&s, out);
    ct_wipe(&s, sizeof s);
}

#else // !CH_CPU_RUNTIME

#include "sha512_compress.h"

static void store_be64(uint64_t v, uint8_t out[8]) {
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    s->total_bytes += n;
    if (s->fill > 0) {
        while (n > 0 && s->fill < SHA512_BLOCK) {
            s->block[s->fill++] = *in++;
            n--;
        }
        if (s->fill == SHA512_BLOCK) {
            sha512_compress(s->h, s->block);
            s->fill = 0;
        }
    }
    while (n >= SHA512_BLOCK) {
        sha512_compress(s->h, in);
        in += SHA512_BLOCK;
        n -= SHA512_BLOCK;
    }
    while (n > 0) {
        s->block[s->fill++] = *in++;
        n--;
    }
}

// FIPS 180-4 §5.1.2: the 1 bit, zeros to 112 mod 128, then the message
// bit length as a 128-bit big-endian integer. total_bytes * 8 is that
// integer exactly: the high word takes the three bits the shift pushes
// out, so no count of bytes a size_t can hold is ever truncated.
//
// The padding is written straight into the pending block: two loops
// bounded by the block and at most two compressions. sha256.c routes
// its padding through update one byte at a time instead; here that
// shape nested up to 127 update calls, each unrolling update's three
// loops, and the framing proof took seven hours to close. Written flat
// it is the same bytes and a formula the fast tier holds
// (docs/proofs.md: keep harness-reachable loop structure concrete).
static void finalize(sha512 *s) {
    uint64_t high = s->total_bytes >> 61;
    uint64_t low = s->total_bytes << 3;
    s->block[s->fill++] = 0x80;
    if (s->fill > SHA512_BLOCK - 16) {
        while (s->fill < SHA512_BLOCK) {
            s->block[s->fill++] = 0;
        }
        sha512_compress(s->h, s->block);
        s->fill = 0;
    }
    while (s->fill < SHA512_BLOCK - 16) {
        s->block[s->fill++] = 0;
    }
    store_be64(high, s->block + SHA512_BLOCK - 16);
    store_be64(low, s->block + SHA512_BLOCK - 8);
    sha512_compress(s->h, s->block);
    s->fill = 0;
}

void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]) {
    finalize(s);
    for (size_t i = 0; i < 8; i++) {
        store_be64(s->h[i], out + 8 * i);
    }
}

void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    finalize(s);
    for (size_t i = 0; i < 6; i++) {
        store_be64(s->h[i], out + 8 * i);
    }
}

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    sha512 s;
    sha512_init(&s);
    sha512_update(&s, in, n);
    sha512_final(&s, out);
}

void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    sha512 s;
    sha384_init(&s);
    sha512_update(&s, in, n);
    sha384_final(&s, out);
}

#endif // CH_CPU_RUNTIME
