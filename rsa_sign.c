// RSA-PSS signing: EMSA-PSS-ENCODE (RFC 8017 9.1.1) over public bytes,
// then RSASP1 (RFC 8017 5.2.1) over a Montgomery ladder that is constant
// time in the private exponent. rsa_sign.h states what that claim covers
// and what it does not.
//
// Limbs are little-endian uint32 and every product is a uint64 built by
// ct.h's ct_widemul, the shape p256.c and rsa_mont.c use. What differs
// from rsa_mont.c is every place a value decides something: the
// conditional subtracts and the ladder swap are mask arithmetic, never an
// if.
//
// What that produces, read from the assembly make lint-wide-multiply
// compiles: mont_mul, which handles every secret intermediate, emits five
// loop back-edges and nothing else on each of the three clang targets.
// The file branches on three values that are not loop counters, and all
// three are public: mgf1 takes the smaller of the remaining mask length
// and 32, mont_r2 subtracts the modulus, which is public and is the only
// caller of cond_sub, and rsa_pss_sign asserts that the drawn salt is
// not all zero, which the signature publishes anyway.
#include "rsa_sign.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "rand.h"
#include "sha256.h"

#define HLEN 32 // SHA-256 output
#define SLEN 32 // salt length, fixed by rsa_pss_rsae_sha256

// One 32-bit limb per 4 bytes of modulus: RSA-3072 is 96 limbs, RSA-4096
// is 128. The count follows the one bound rsa.h defines, as rsa_mont.c's
// does, so both files size their arrays from the same number.
#define LIMBS_MAX (CH_RSA_MODULUS_MAX / 4)

// The limb count divides the byte bound, and the byte bound is the one
// rsa_pss_sign's n_len check enforces.
_Static_assert(CH_RSA_MODULUS_MAX % 8 == 0 && CH_RSA_MODULUS_MAX >= 256,
               "CH_RSA_MODULUS_MAX must be a multiple of 8 and at least 256");

// All ones when bit is 1, all zeros when bit is 0. The mask comes from
// moving the bit to the top and spreading it down with an arithmetic
// shift, the form x25519.c's cswap uses: written as 0 - bit, gcc sees a
// negated 0-or-1 value and rewrites `x & -bit` as `x * bit` (match.pd),
// which is a multiply by a secret bit
// (https://github.com/c4milo/chapulin/issues/106).
static uint32_t mask_of_bit(uint32_t bit) {
    return (uint32_t)((int32_t)(bit << 31) >> 31);
}

// k big-endian bytes -> k little-endian limbs, most significant limb
// first in the byte string.
static void limbs_from_bytes(uint32_t *o, const uint8_t *b, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        o[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) |
               (uint32_t)b[j + 3];
    }
}

// k little-endian limbs -> big-endian bytes.
static void limbs_to_bytes(uint8_t *b, const uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        b[j] = (uint8_t)(a[i] >> 24);
        b[j + 1] = (uint8_t)(a[i] >> 16);
        b[j + 2] = (uint8_t)(a[i] >> 8);
        b[j + 3] = (uint8_t)a[i];
    }
}

// The borrow out of a - b over k limbs, with the difference discarded.
// Every limb is read whatever the values are, so this answers "is a below
// b" without a comparison that could branch.
static uint32_t sub_borrow(const uint32_t *a, const uint32_t *b, size_t k) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        borrow = (uint32_t)((v >> 32) & 1);
    }
    return borrow;
}

// a -= b & mask over k limbs. mask is all ones or all zeros, so this is
// either the whole subtraction or a subtraction of zero, and both take
// the same time and touch the same limbs.
static void sub_masked(uint32_t *a, const uint32_t *b, size_t k, uint32_t mask) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - (b[i] & mask) - borrow;
        a[i] = (uint32_t)v;
        borrow = (uint32_t)((v >> 32) & 1);
    }
}

// 1 when the k+1 limb value top:a is below b, and 0 otherwise. b has no
// limb above k, so the top step subtracts only the borrow the low limbs
// produced, and its own borrow answers the whole comparison. Subtracting
// rather than comparing is what keeps a limb off the control path: a
// compare here is what clang turns into a predicated move.
static uint32_t below(const uint32_t *a, const uint32_t *b, size_t k, uint32_t top) {
    uint32_t borrow = sub_borrow(a, b, k);
    return (uint32_t)(((uint64_t)top - borrow) >> 32) & 1;
}

// r -= m when the k+1 limb value extra:r is at or above m. extra is the
// bit the caller shifted out above r's top limb. The choice is a mask.
static void cond_sub(uint32_t *r, const uint32_t *m, size_t k, uint32_t extra) {
    sub_masked(r, m, k, ~mask_of_bit(below(r, m, k, extra)));
}

// Exchanges a and b when mask is all ones, leaves them when it is all
// zeros. Both arrays are written either way.
static void cswap_limbs(uint32_t *a, uint32_t *b, size_t k, uint32_t mask) {
    for (size_t i = 0; i < k; i++) {
        uint32_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

// -m^-1 mod 2^32 by Newton iteration. m0 is odd, so x doubles its correct
// low bits each step and five steps cover all 32.
static uint32_t mont_m0inv(uint32_t m0) {
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) {
        x *= 2U - m0 * x;
    }
    return 0U - x;
}

// r2 = 2^(64k) mod m, the value that moves a number into the Montgomery
// domain. Start at 1 and double 64k times; the value before each double
// is below m, so one conditional subtract restores that.
static void mont_r2(uint32_t *r2, const uint32_t *m, size_t k) {
    memset(r2, 0, k * sizeof(uint32_t));
    r2[0] = 1;
    for (size_t i = 0; i < 64 * k; i++) {
        uint32_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            uint32_t shifted = (r2[j] << 1) | carry;
            carry = r2[j] >> 31;
            r2[j] = shifted;
        }
        cond_sub(r2, m, k, carry);
    }
}

// Montgomery product o = a*b / 2^(32k) mod m (CIOS, Koc et al.). Inputs
// below m, result below m; o may alias a or b, because o is written only
// after both are read in full. Each round adds one limb of a into t,
// adds a multiple of m to make t's low limb zero, and shifts down one
// limb.
static void mont_mul(uint32_t *o, const uint32_t *a, const uint32_t *b, const uint32_t *m,
                     uint32_t m0inv, size_t k) {
    uint32_t t[LIMBS_MAX + 2];
    memset(t, 0, (k + 2) * sizeof(uint32_t));
    for (size_t i = 0; i < k; i++) {
        uint64_t c = 0;
        for (size_t j = 0; j < k; j++) {
            uint64_t v = ct_widemul(a[i], b[j]) + t[j] + c;
            t[j] = (uint32_t)v;
            c = v >> 32;
        }
        uint64_t v = (uint64_t)t[k] + c;
        t[k] = (uint32_t)v;
        t[k + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * m0inv;
        c = (ct_widemul(u, m[0]) + t[0]) >> 32;
        for (size_t j = 1; j < k; j++) {
            v = ct_widemul(u, m[j]) + t[j] + c;
            t[j - 1] = (uint32_t)v;
            c = v >> 32;
        }
        v = (uint64_t)t[k] + c;
        t[k - 1] = (uint32_t)v;
        t[k] = t[k + 1] + (uint32_t)(v >> 32);
        t[k + 1] = 0;
    }
    // t is below 2m, so one subtraction brings it below m. t[k] carries
    // what did not fit in the low limbs, and below() reads it as the top
    // limb of the comparison.
    memcpy(o, t, k * sizeof(uint32_t));
    sub_masked(o, m, k, ~mask_of_bit(below(t, m, k, t[k])));
    ct_wipe(t, (k + 2) * sizeof(uint32_t));
}

void rsa_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    CH_ASSERT(k->n_len >= 256 && k->n_len <= CH_RSA_MODULUS_MAX && k->n_len % 4 == 0);
    size_t limbs = k->n_len / 4;
    // Zeroed at declaration, as rsa_mont.c's are: the limbs above
    // `limbs` are never read, and starting them at zero is what lets a
    // reader, and clang's analyzer, see that without following the
    // length.
    uint32_t m[LIMBS_MAX] = {0};
    uint32_t r2[LIMBS_MAX] = {0};
    uint32_t x1[LIMBS_MAX] = {0}; // the running 1 of the ladder
    uint32_t x2[LIMBS_MAX] = {0}; // the running base
    limbs_from_bytes(m, k->n, limbs);
    uint32_t m0inv = mont_m0inv(m[0]);
    mont_r2(r2, m, limbs);

    // x1 starts at 1 and x2 at em, both moved into the Montgomery domain
    // by one multiplication with r2.
    memset(x1, 0, limbs * sizeof(uint32_t));
    x1[0] = 1;
    mont_mul(x1, x1, r2, m, m0inv, limbs);
    limbs_from_bytes(x2, em, limbs);
    mont_mul(x2, x2, r2, m, m0inv, limbs);

    // The ladder (Montgomery powering ladder): one multiplication and one
    // squaring per exponent bit, over every one of the 8 * n_len bit
    // positions, leading zeros included. The trip count is a function of
    // n_len alone, so it carries nothing about d, and the swap that reads
    // a bit of d selects with a mask.
    for (size_t i = 8 * k->n_len; i-- > 0;) {
        uint32_t bit = ((uint32_t)k->d[k->n_len - 1 - (i >> 3)] >> (i & 7)) & 1;
        uint32_t mask = mask_of_bit(bit);
        cswap_limbs(x1, x2, limbs, mask);
        mont_mul(x2, x1, x2, m, m0inv, limbs);
        mont_mul(x1, x1, x1, m, m0inv, limbs);
        cswap_limbs(x1, x2, limbs, mask);
    }

    // One multiplication by 1 leaves the Montgomery domain.
    memset(x2, 0, limbs * sizeof(uint32_t));
    x2[0] = 1;
    mont_mul(x1, x1, x2, m, m0inv, limbs);
    limbs_to_bytes(sig, x1, limbs);
    ct_wipe(x1, sizeof x1);
    ct_wipe(x2, sizeof x2);
}

// MGF1 (RFC 8017 B.2.1) with SHA-256: mask[0..len) is the leftmost len
// bytes of Hash(seed || counter) blocks, counter a 4-byte big-endian
// index that starts at 0. The verifier holds its own copy of this, static
// to that file; the two arms of the build are separate objects.
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

// EMSA-PSS-ENCODE (RFC 8017 9.1.1) into the em_len-byte em, with a fresh
// 32-byte salt. rsa_pss_sign has already established em_len >= HLEN +
// SLEN + 2. Every byte here ends up inside the signature, so none of it
// is secret and none of it steers anything; the salt is wiped because the
// caller's stack outlives the signature.
static void emsa_pss_encode(const uint8_t msg_hash[32], uint8_t *em, size_t em_len) {
    uint8_t salt[SLEN];
    ch_rand_bytes(salt, sizeof salt);
    // Every draw site INV-4 lists carries this check. A hook that returns
    // without writing leaves the salt zero, every signature over one
    // message becomes the same bytes, and nothing downstream notices. A
    // real draw is all-zero with probability 2^-256, so this checks the
    // integrator's hook against rand.h's contract, which is what
    // CH_ASSERT is for.
    {
        static const uint8_t unwritten[SLEN] = {0};
        CH_ASSERT(!ct_memeq(salt, unwritten, sizeof salt));
    }

    // H = Hash(0x00 * 8 || msg_hash || salt) sits between DB and the
    // trailer byte.
    static const uint8_t zeros8[8] = {0};
    size_t db_len = em_len - HLEN - 1;
    uint8_t *hh = em + db_len;
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, zeros8, sizeof zeros8);
    sha256_update(&h, msg_hash, HLEN);
    sha256_update(&h, salt, SLEN);
    sha256_final(&h, hh);
    em[em_len - 1] = 0xbc;

    // DB = PS (zeros) || 0x01 || salt, masked with MGF1(H).
    size_t ps_len = em_len - SLEN - HLEN - 2;
    memset(em, 0, ps_len);
    em[ps_len] = 0x01;
    memcpy(em + ps_len + 1, salt, SLEN);
    uint8_t mask[CH_RSA_MODULUS_MAX];
    mgf1(hh, HLEN, mask, db_len);
    for (size_t i = 0; i < db_len; i++) {
        em[i] ^= mask[i];
    }

    // emBits is 8 * em_len - 1 here, so exactly one leading bit is
    // cleared. That keeps EM below 2^(8*em_len - 1), which is at or below
    // the modulus, so RSASP1's input is in range by construction.
    em[0] &= 0x7f;
    ct_wipe(salt, sizeof salt);
}

int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32], uint8_t *sig, size_t cap,
                 size_t *sig_len) {
    if (k->n_len < 256 || k->n_len > CH_RSA_MODULUS_MAX || k->n_len % 8 != 0) {
        return 0;
    }
    // Montgomery arithmetic needs an odd modulus, and this file's encoder
    // needs a modulus whose top bit is set: that makes emLen exactly
    // n_len and emBits exactly 8 * n_len - 1, which is the shape every
    // RSA key generator produces. The verifier admits a shorter modulus
    // because a peer's key comes from elsewhere; a server's own key is
    // refused here rather than signed with.
    if ((k->n[k->n_len - 1] & 1) == 0 || (k->n[0] & 0x80) == 0) {
        return 0;
    }
    if (cap < k->n_len) {
        return 0;
    }

    uint8_t em[CH_RSA_MODULUS_MAX];
    emsa_pss_encode(msg_hash, em, k->n_len);
    rsa_sp1(k, em, sig);
    ct_wipe(em, sizeof em);
    *sig_len = k->n_len;
    return 1;
}
