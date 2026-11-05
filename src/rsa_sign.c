// RSA-PSS signing: EMSA-PSS-ENCODE (RFC 8017 9.1.1) over public bytes,
// then RSASP1 (RFC 8017 5.2.1) over a Montgomery ladder that is constant
// time in the private exponent. rsa_sign.h states what that claim covers
// and what it does not.
//
// Words are little-endian uint32 and every product is a uint64 built by
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
// caller of cond_sub, and rsa_pss_sign asserts that the salt its caller
// drew is not all zero, which the signature publishes anyway.
#include "rsa_sign.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "sha256.h"

#define HLEN 32               // SHA-256 output
#define SLEN RSA_PSS_SALT_LEN // salt length, fixed by rsa_pss_rsae_sha256

// A device object compiles this file once, with the ladder below. A host
// object compiles it a second time inside rsa_sign64.c, which defines
// CH_RSA_SIGN64 and renames the entry: that copy holds no exponentiation
// of its own and calls rsa_sign64.c's (docs/decisions.md 95). The test
// of cap and the PSS encoder sit after the ladder, so one line decides
// each whichever signer runs, and the entry names each signer's key test
// and private operation where it calls them.
#ifdef CH_RSA_SIGN64
#include "rsa_sign64.h"
#else

// One 32-bit word per 4 bytes of modulus: RSA-3072 is 96 words, RSA-4096
// is 128. The count follows the one bound rsa.h defines, as rsa_mont.c's
// does, so both files size their arrays from the same number.
#define WORDS_MAX (CH_RSA_MODULUS_MAX / 4)

// The word count divides the byte bound, and the byte bound is the one
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

// k big-endian bytes -> k little-endian words, most significant word
// first in the byte string.
static void words_from_bytes(uint32_t *o, const uint8_t *b, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        o[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) |
               (uint32_t)b[j + 3];
    }
}

// k little-endian words -> big-endian bytes.
static void words_to_bytes(uint8_t *b, const uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        b[j] = (uint8_t)(a[i] >> 24);
        b[j + 1] = (uint8_t)(a[i] >> 16);
        b[j + 2] = (uint8_t)(a[i] >> 8);
        b[j + 3] = (uint8_t)a[i];
    }
}

// The borrow out of a - b over k words, with the difference discarded.
// Every word is read whatever the values are, so this answers "is a below
// b" without a comparison that could branch.
static uint32_t sub_borrow(const uint32_t *a, const uint32_t *b, size_t k) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        borrow = (uint32_t)((v >> 32) & 1);
    }
    return borrow;
}

// a -= b & mask over k words. mask is all ones or all zeros, so this is
// either the whole subtraction or a subtraction of zero, and both take
// the same time and touch the same words.
static void sub_masked(uint32_t *a, const uint32_t *b, size_t k, uint32_t mask) {
    uint32_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - (b[i] & mask) - borrow;
        a[i] = (uint32_t)v;
        borrow = (uint32_t)((v >> 32) & 1);
    }
}

// 1 when the k+1 word value top:a is below b, and 0 otherwise. b has no
// word above k, so the top step subtracts only the borrow the low words
// produced, and its own borrow answers the whole comparison. Subtracting
// rather than comparing is what keeps a word off the control path: a
// compare here is what clang turns into a predicated move.
static uint32_t below(const uint32_t *a, const uint32_t *b, size_t k, uint32_t top) {
    uint32_t borrow = sub_borrow(a, b, k);
    return (uint32_t)(((uint64_t)top - borrow) >> 32) & 1;
}

// r -= m when the k+1 word value extra:r is at or above m. extra is the
// bit the caller shifted out above r's top word. The choice is a mask.
static void cond_sub(uint32_t *r, const uint32_t *m, size_t k, uint32_t extra) {
    sub_masked(r, m, k, ~mask_of_bit(below(r, m, k, extra)));
}

// Exchanges a and b when mask is all ones, leaves them when it is all
// zeros. Both arrays are written either way.
static void cswap_words(uint32_t *a, uint32_t *b, size_t k, uint32_t mask) {
    for (size_t i = 0; i < k; i++) {
        uint32_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

// The words a blinded exponent takes beyond the modulus's. r is 64 bits
// and 65537 is 17 bits, so d + r (65537 d - 1) is below 2^(32 k + 82),
// and 3 words more than d hold it.
#define BLIND_WORDS 3
#define EXPONENT_WORDS_MAX (WORDS_MAX + BLIND_WORDS)

// a += b over k words when mask is all ones, and a += 0 when it is all
// zeros. The carry out of the top word is dropped: each caller sizes a so
// that the sum fits.
static void add_masked(uint32_t *a, const uint32_t *b, size_t k, uint32_t mask) {
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t sum = (uint64_t)a[i] + (b[i] & mask) + carry;
        a[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

// a <<= 1 over k words. The top bit is dropped, as add_masked drops its
// carry.
static void shift_left_one(uint32_t *a, size_t k) {
    uint32_t spill = 0;
    for (size_t i = 0; i < k; i++) {
        uint32_t next = a[i] >> 31;
        a[i] = (a[i] << 1) | spill;
        spill = next;
    }
}

// t = 65537 t - 1 over words + 1 words, the top word zero on entry.
// 65537 t is t + (t << 16). Each word of t << 16 joins the low half of
// t_i with the high half of t_(i-1), and the sum adds two words and a
// carry. Written as one 64-bit sum of t_i 2^16 + t_i, the step became a
// widening multiply by 65537 under clang, which a Cortex-M3 runs in a
// time its operand decides (lint-wide-multiply). A key's d is 1 or more,
// so no borrow leaves the top word. The borrow of the subtraction is bit
// 31 of ~t_i AND the difference, which is set only for t_i = 0 and a borrow
// of 1. Written as bit 63 of a 64-bit difference, it became an IT block on
// a word of t under gcc for the Cortex-M3.
static void scale_minus_one(uint32_t *t, size_t words) {
    uint32_t previous = 0; // t_(i-1), before this step wrote it
    uint32_t carry = 0;
    for (size_t i = 0; i <= words; i++) {
        uint32_t shifted = (t[i] << 16) | (previous >> 16);
        previous = t[i];
        uint64_t sum = (uint64_t)t[i] + shifted + carry;
        t[i] = (uint32_t)sum;
        carry = (uint32_t)(sum >> 32);
    }
    uint32_t borrow = 1;
    for (size_t i = 0; i <= words; i++) {
        uint32_t difference = t[i] - borrow;
        borrow = (~t[i] & difference) >> 31;
        t[i] = difference;
    }
}

// One pass of the product r t, by one bit of r from the top down:
// exponent = 2 exponent + bit t, where mask is all ones for a bit of 1 and
// all zeros for a bit of 0. The mask selects t by AND, never by a choice.
static void blind_pass(uint32_t *exponent, const uint32_t *t, size_t exponent_words,
                       uint32_t mask) {
    shift_left_one(exponent, exponent_words);
    add_masked(exponent, t, exponent_words, mask);
}

// exponent = d + r (65537 d - 1) over words + BLIND_WORDS words, with r
// the first RSA_LADDER_BLIND_LEN bytes of blind read as a little-endian
// number. 65537 d
// - 1 is a multiple of lambda(n), so m^exponent = m^d mod n for every m
// (rsa_sign.h, spec/lean/Spec/RsaBlind.lean). A fresh r for each
// signature gives the ladder a different exponent each time. No step runs
// a multiply, and no branch or index depends on d or r.
static void blinded_exponent(uint32_t *exponent, const uint8_t *d, size_t words,
                             const uint8_t blind[RSA_BLIND_LEN]) {
    size_t exponent_words = words + BLIND_WORDS;
    uint32_t t[EXPONENT_WORDS_MAX] = {0};
    words_from_bytes(t, d, words);
    scale_minus_one(t, words);

    // exponent = r t, after 64 passes from r's top bit down. Each pass's
    // mask is read back from a volatile object. A compiler that knows a
    // mask is all ones or zero may write the masked add as a choice on r's
    // bit, and clang for the Cortex-M3 wrote it as a conditional move in an
    // IT block (docs/decisions.md 125 and 186). What a volatile read returns
    // the compiler cannot know. The last store leaves no bit of r there.
    memset(exponent, 0, exponent_words * sizeof(uint32_t));
    volatile uint32_t opaque = 0;
    for (size_t j = (size_t)8 * RSA_LADDER_BLIND_LEN; j-- > 0;) {
        opaque = mask_of_bit(((uint32_t)blind[j >> 3] >> (j & 7)) & 1);
        blind_pass(exponent, t, exponent_words, opaque);
    }
    opaque = 0;

    // exponent += d.
    memset(t, 0, sizeof t);
    words_from_bytes(t, d, words);
    add_masked(exponent, t, exponent_words, UINT32_MAX);
    ct_wipe(t, sizeof t);
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
// after both are read in full. Each round adds one word of a into t,
// adds a multiple of m to make t's low word zero, and shifts down one
// word.
static void mont_mul(uint32_t *o, const uint32_t *a, const uint32_t *b, const uint32_t *m,
                     uint32_t m0inv, size_t k) {
    uint32_t t[WORDS_MAX + 2];
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
    // what did not fit in the low words, and below() reads it as the top
    // word of the comparison.
    memcpy(o, t, k * sizeof(uint32_t));
    sub_masked(o, m, k, ~mask_of_bit(below(t, m, k, t[k])));
    ct_wipe(t, (k + 2) * sizeof(uint32_t));
}

#ifdef CH_RSA_SIGN_TEST
_Static_assert(RSA_SIGN_BLIND_WORDS == BLIND_WORDS, "rsa_sign.h's test word count");
void rsa_sign_blinded_exponent(uint32_t *exponent, const uint8_t *d, size_t n_len,
                               const uint8_t blind[RSA_BLIND_LEN]) {
    CH_ASSERT(n_len >= 4 && n_len <= CH_RSA_MODULUS_MAX && n_len % 4 == 0);
    blinded_exponent(exponent, d, n_len / 4, blind);
}
#endif

void rsa_sp1(const ch_rsa_priv *k, const uint8_t *em, const uint8_t blind[RSA_BLIND_LEN],
             uint8_t *sig) {
    CH_ASSERT(k->n_len >= 256 && k->n_len <= CH_RSA_MODULUS_MAX && k->n_len % 4 == 0);
    size_t words = k->n_len / 4;
    // Zeroed at declaration, as rsa_mont.c's are: the words above
    // `words` are never read, and starting them at zero is what lets a
    // reader, and clang's analyzer, see that without following the
    // length.
    uint32_t m[WORDS_MAX] = {0};
    uint32_t r2[WORDS_MAX] = {0};
    uint32_t x1[WORDS_MAX] = {0}; // the running 1 of the ladder
    uint32_t x2[WORDS_MAX] = {0}; // the running base
    uint32_t exponent[EXPONENT_WORDS_MAX] = {0};
    size_t exponent_words = words + BLIND_WORDS;
    blinded_exponent(exponent, k->d, words, blind);
    words_from_bytes(m, k->n, words);
    uint32_t m0inv = mont_m0inv(m[0]);
    mont_r2(r2, m, words);

    // x1 starts at 1 and x2 at em, both moved into the Montgomery domain
    // by one multiplication with r2.
    memset(x1, 0, words * sizeof(uint32_t));
    x1[0] = 1;
    mont_mul(x1, x1, r2, m, m0inv, words);
    words_from_bytes(x2, em, words);
    mont_mul(x2, x2, r2, m, m0inv, words);

    // The ladder (Montgomery powering ladder): one multiplication and one
    // squaring per exponent bit, over every one of the 32 * exponent_words
    // bit positions of the blinded exponent, leading zeros included. The
    // trip count is a function of n_len alone, so it carries nothing about
    // d or r, and the swap that reads a bit selects with a mask.
    for (size_t i = 32 * exponent_words; i-- > 0;) {
        uint32_t bit = (exponent[i >> 5] >> (i & 31)) & 1;
        uint32_t mask = mask_of_bit(bit);
        cswap_words(x1, x2, words, mask);
        mont_mul(x2, x1, x2, m, m0inv, words);
        mont_mul(x1, x1, x1, m, m0inv, words);
        cswap_words(x1, x2, words, mask);
    }

    // One multiplication by 1 leaves the Montgomery domain.
    memset(x2, 0, words * sizeof(uint32_t));
    x2[0] = 1;
    mont_mul(x1, x1, x2, m, m0inv, words);
    words_to_bytes(sig, x1, words);
    ct_wipe(x1, sizeof x1);
    ct_wipe(x2, sizeof x2);
    ct_wipe(exponent, sizeof exponent);
}
#endif // CH_RSA_SIGN64

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

// EMSA-PSS-ENCODE (RFC 8017 9.1.1) into the em_len-byte em, with the
// SLEN-byte salt the caller drew. rsa_pss_sign has already established
// em_len >= HLEN + SLEN + 2. Every byte here ends up inside the
// signature, so none of it is secret and none of it steers anything.
static void emsa_pss_encode(const uint8_t msg_hash[32], const uint8_t salt[SLEN], uint8_t *em,
                            size_t em_len) {
    // INV-4's check on the salt draw, which the caller makes (srv_auth.c).
    // A source that returns without writing leaves the salt zero, every
    // signature over one message becomes the same bytes, and nothing
    // downstream notices. A real draw is all-zero with probability 2^-256,
    // so this checks the integrator's source against rand.h's contract,
    // which is what CH_ASSERT is for.
    {
        static const uint8_t unwritten[SLEN] = {0};
        CH_ASSERT(!ct_memeq_public(salt, unwritten, SLEN));
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
}

// The entry. The 64-bit signer's takes the session's ch_cfg.cpu first,
// which its private operation reads, under a name of its own, which
// rsa_sign64.c renames rsa_sign64_pss (rsa_sign64.h); the ladder's takes
// none.
#ifdef CH_RSA_SIGN64
int rsa_pss_sign_cpu(uint32_t cpu, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                     const uint8_t salt[RSA_PSS_SALT_LEN], const uint8_t blind[RSA_BLIND_LEN],
                     uint8_t *sig, size_t cap, size_t *sig_len)
#else
int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 const uint8_t salt[RSA_PSS_SALT_LEN], const uint8_t blind[RSA_BLIND_LEN],
                 uint8_t *sig, size_t cap, size_t *sig_len)
#endif
{
    // The length bound, an odd modulus and its top bit: rsa_sign.h says
    // why each one. The 64-bit signer's test adds that the key's primes
    // multiply to its modulus (rsa_sign64.h).
#ifdef CH_RSA_SIGN64
    // The verdict on the primes is the one a server's configuration check
    // reports, so it is public.
    int key_ok = rsa_sign64_key_ok(k);
    CT_DECLASSIFY(&key_ok, sizeof key_ok);
    if (!key_ok) {
        return 0;
    }
#else
    if (!rsa_pss_sign_key_ok(k)) {
        return 0;
    }
#endif
    if (cap < k->n_len) {
        return 0;
    }

    uint8_t em[CH_RSA_MODULUS_MAX];
    emsa_pss_encode(msg_hash, salt, em, k->n_len);
#ifdef CH_RSA_SIGN64
    // The 64-bit signer returns 0 for a signature that failed its check,
    // and has written no byte of it. The ladder has no check to fail.
    int written = rsa_sign64_sp1(cpu, k, em, blind, sig);
    ct_wipe(em, sizeof em);
    if (!written) {
        return 0;
    }
#else
    rsa_sp1(k, em, blind, sig);
    ct_wipe(em, sizeof em);
#endif
    *sig_len = k->n_len;
    return 1;
}
