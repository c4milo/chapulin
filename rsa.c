// RSA-PSS verification (RFC 8017 8.1.2 / 9.1.2): recover the encoded
// message with RSAVP1, then run EMSA-PSS-VERIFY over it. Fixed to
// rsa_pss_rsae_sha256 — SHA-256, MGF1-SHA256, salt length 32. Every input
// is public, so the code is straight-line and variable time (see rsa.h).
#include "rsa.h"

#include <string.h>

#include "ct.h"
#include "sha256.h"

#define HLEN 32    // SHA-256 output
#define SLEN 32    // salt length, fixed
#define MAXLEN 384 // RSA-3072 modulus, the largest accepted

// 1 if the len-byte big-endian a >= b. Both operands are public.
static int ge_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return a[i] > b[i];
        }
    }
    return 1; // equal
}

// Bit length of the big-endian modulus n, i.e. the position of its top set
// bit. Returns 0 only for n == 0, which the caller has already rejected.
static size_t modulus_bits(const uint8_t *n, size_t nlen) {
    size_t bits = 8 * nlen;
    size_t i = 0;
    while (i < nlen && n[i] == 0) {
        bits -= 8;
        i++;
    }
    if (i == nlen) {
        return 0;
    }
    uint8_t top = n[i];
    while (!(top & 0x80)) {
        bits--;
        top = (uint8_t)(top << 1);
    }
    return bits;
}

// MGF1 (RFC 8017 B.2.1) with SHA-256: mask[0..len) is the leftmost len
// bytes of Hash(seed || counter) blocks, counter a 4-byte big-endian
// index that starts at 0.
static void mgf1(const uint8_t *seed, size_t seedlen, uint8_t *mask, size_t len) {
    size_t off = 0;
    uint32_t counter = 0;
    while (off < len) {
        uint8_t cb[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                         (uint8_t)(counter >> 8), (uint8_t)counter};
        uint8_t digest[SHA256_LEN];
        sha256 h;
        sha256_init(&h);
        sha256_update(&h, seed, seedlen);
        sha256_update(&h, cb, sizeof cb);
        sha256_final(&h, digest);
        size_t take = len - off < SHA256_LEN ? len - off : SHA256_LEN;
        memcpy(mask + off, digest, take);
        off += take;
        counter++;
    }
}

// EMSA-PSS-VERIFY (RFC 8017 9.1.2) over the emLen-byte EM with emBits as
// the maximal bit length. Returns 1 on a match, 0 on any decode failure.
static int emsa_pss_verify(const uint8_t msg_hash[32], const uint8_t *em, size_t emlen,
                           size_t embits) {
    if (emlen < HLEN + SLEN + 2 || em[emlen - 1] != 0xbc) {
        return 0;
    }
    size_t dblen = emlen - HLEN - 1;
    const uint8_t *maskeddb = em;
    const uint8_t *hh = em + dblen; // H, HLEN bytes

    // The leftmost 8*emLen - emBits bits of maskedDB must be zero.
    unsigned zerobits = (unsigned)(8 * emlen - embits);
    uint8_t topmask = (uint8_t)(0xFF << (8 - zerobits));
    if (maskeddb[0] & topmask) {
        return 0;
    }

    // DB = maskedDB XOR MGF1(H); then clear the same leftmost bits.
    uint8_t db[MAXLEN];
    mgf1(hh, HLEN, db, dblen);
    for (size_t i = 0; i < dblen; i++) {
        db[i] ^= maskeddb[i];
    }
    db[0] &= (uint8_t)~topmask;

    // DB must be PS (zeros) || 0x01 || salt, PS filling the front.
    size_t pslen = emlen - SLEN - HLEN - 2;
    for (size_t i = 0; i < pslen; i++) {
        if (db[i] != 0) {
            return 0;
        }
    }
    if (db[pslen] != 0x01) {
        return 0;
    }
    const uint8_t *salt = db + pslen + 1; // last SLEN bytes of DB

    // H' = Hash(0x00 * 8 || msg_hash || salt); accept iff H' == H.
    static const uint8_t zeros8[8] = {0};
    uint8_t hprime[SHA256_LEN];
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, zeros8, sizeof zeros8);
    sha256_update(&h, msg_hash, HLEN);
    sha256_update(&h, salt, SLEN);
    sha256_final(&h, hprime);
    return (int)ct_memeq(hprime, hh, HLEN);
}

int rsa_pss_verify(const uint8_t *n, size_t nlen, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t siglen) {
    if (nlen < 256 || nlen > MAXLEN || nlen % 8 != 0 || siglen != nlen) {
        return 0;
    }
    // Reject a signature numerically >= the modulus (covers s == n and
    // s == n + 1). Both are nlen big-endian bytes, so compare directly.
    if (ge_bytes(sig, n, nlen)) {
        return 0;
    }

    uint8_t em[MAXLEN];
    rsa_vp1(n, nlen, sig, em);

    // emBits = modBits - 1; emLen = ceil(emBits / 8). For an openssl
    // modulus the top bit is set, so emLen == nlen, but compute both
    // generally and require the I2OSP-dropped leading bytes to be zero.
    size_t embits = modulus_bits(n, nlen) - 1;
    size_t emlen = (embits + 7) / 8;
    size_t off = nlen - emlen;
    for (size_t i = 0; i < off; i++) {
        if (em[i] != 0) {
            return 0; // integer too large for emLen
        }
    }
    return emsa_pss_verify(msg_hash, em + off, emlen, embits);
}
