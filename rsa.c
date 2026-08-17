// RSA-PSS verification (RFC 8017 8.1.2 / 9.1.2): recover the encoded
// message with RSAVP1, then run EMSA-PSS-VERIFY over it. Fixed to
// rsa_pss_rsae_sha256 — SHA-256, MGF1-SHA256, salt length 32. Every input
// is public, so the code is straight-line and variable time (see rsa.h).
#include "rsa.h"

#include <string.h>

#include "ct.h"
#include "sha256.h"

#define HLEN 32         // SHA-256 output
#define SLEN 32         // salt length, fixed
#define MODULUS_MAX 384 // RSA-3072 modulus, the largest accepted

// 1 if the len-byte big-endian a >= b. Both operands are public.
static int greater_or_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return a[i] > b[i];
        }
    }
    return 1; // equal
}

// Bit length of the big-endian modulus n, i.e. the position of its top set
// bit. Returns 0 only for n == 0, which the caller has already rejected.
static size_t modulus_bits(const uint8_t *n, size_t n_len) {
    size_t bits = 8 * n_len;
    size_t i = 0;
    while (i < n_len && n[i] == 0) {
        bits -= 8;
        i++;
    }
    if (i == n_len) {
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
static void mgf1(const uint8_t *seed, size_t seed_len, uint8_t *mask, size_t len) {
    size_t off = 0;
    uint32_t counter = 0;
    while (off < len) {
        uint8_t counter_bytes[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                                    (uint8_t)(counter >> 8), (uint8_t)counter};
        uint8_t digest[SHA256_LEN];
        sha256 h;
        sha256_init(&h);
        sha256_update(&h, seed, seed_len);
        sha256_update(&h, counter_bytes, sizeof counter_bytes);
        sha256_final(&h, digest);
        size_t take = len - off < SHA256_LEN ? len - off : SHA256_LEN;
        memcpy(mask + off, digest, take);
        off += take;
        counter++;
    }
}

// EMSA-PSS-VERIFY (RFC 8017 9.1.2) over the emLen-byte EM with emBits as
// the maximal bit length. Returns 1 on a match, 0 on any decode failure.
static int emsa_pss_verify(const uint8_t msg_hash[32], const uint8_t *em, size_t em_len,
                           size_t em_bits) {
    if (em_len < HLEN + SLEN + 2 || em[em_len - 1] != 0xbc) {
        return 0;
    }
    size_t db_len = em_len - HLEN - 1;
    const uint8_t *masked_db = em;
    const uint8_t *hh = em + db_len; // H, HLEN bytes

    // The leftmost 8*emLen - emBits bits of maskedDB must be zero.
    unsigned zero_bits = (unsigned)(8 * em_len - em_bits);
    uint8_t top_mask = (uint8_t)(0xFF << (8 - zero_bits));
    if (masked_db[0] & top_mask) {
        return 0;
    }

    // DB = maskedDB XOR MGF1(H); then clear the same leftmost bits.
    uint8_t db[MODULUS_MAX];
    mgf1(hh, HLEN, db, db_len);
    for (size_t i = 0; i < db_len; i++) {
        db[i] ^= masked_db[i];
    }
    db[0] &= (uint8_t)~top_mask;

    // DB must be PS (zeros) || 0x01 || salt, PS filling the front.
    size_t ps_len = em_len - SLEN - HLEN - 2;
    for (size_t i = 0; i < ps_len; i++) {
        if (db[i] != 0) {
            return 0;
        }
    }
    if (db[ps_len] != 0x01) {
        return 0;
    }
    const uint8_t *salt = db + ps_len + 1; // last SLEN bytes of DB

    // H' = Hash(0x00 * 8 || msg_hash || salt); accept iff H' == H.
    static const uint8_t zeros8[8] = {0};
    uint8_t h_prime[SHA256_LEN];
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, zeros8, sizeof zeros8);
    sha256_update(&h, msg_hash, HLEN);
    sha256_update(&h, salt, SLEN);
    sha256_final(&h, h_prime);
    return (int)ct_memeq(h_prime, hh, HLEN);
}

int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    if (n_len < 256 || n_len > MODULUS_MAX || n_len % 8 != 0 || sig_len != n_len) {
        return 0;
    }
    // Reject a signature numerically >= the modulus (covers s == n and
    // s == n + 1). Both are n_len big-endian bytes, so compare directly.
    if (greater_or_equal(sig, n, n_len)) {
        return 0;
    }

    uint8_t em[MODULUS_MAX];
    rsa_vp1(n, n_len, sig, em);

    // emBits = modBits - 1; emLen = ceil(emBits / 8). For an openssl
    // modulus the top bit is set, so emLen == n_len, but compute both
    // generally and require the I2OSP-dropped leading bytes to be zero.
    size_t em_bits = modulus_bits(n, n_len) - 1;
    size_t em_len = (em_bits + 7) / 8;
    size_t off = n_len - em_len;
    for (size_t i = 0; i < off; i++) {
        if (em[i] != 0) {
            return 0; // integer too large for emLen
        }
    }
    return emsa_pss_verify(msg_hash, em + off, em_len, em_bits);
}
