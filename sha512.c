#include "sha512.h"

#include "sha512_compress.h"

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

static void store_be64(uint64_t v, uint8_t out[8]) {
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

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
