// ECDSA P-256 signing (see p256_sign.h for the contracts, the
// constant-time claim and the one stated narrowing against RFC 6979).
// Four things live here and nothing else: the RFC 6979 nonce generator
// with its hedged form, the scalar operations that make s, the two checks
// of a signature, and the copy of a signature that passed them. The DER
// writer is p256_sign_der.h's. The arithmetic is p256_scalar.c's and
// p256_point.c's.
#include "p256_sign.h"

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_sign_der.h"
#include "sha256.h"
#include "widemul.h"

// How many RFC 6979 candidates the generator produces before the signer
// gives up. A candidate fails only when it lands at or above the group
// order, which happens with probability about 2^-32 because n is within
// 2^224 of 2^256, or when it lands on zero, which is 2^-256. Four
// independent failures is below 2^-128, so the give-up path is
// unreachable in practice and exists to fail closed rather than to loop.
// Every candidate is generated whatever the earlier ones were, so the
// cost of a signature does not depend on how many of them were usable.
#define NONCE_CANDIDATES 4

// The RFC 6979 §3.2 HMAC_DRBG state. K and V are each one SHA-256 output.
// inner and outer are HMAC_K's two midstates (RFC 2104 §4): SHA-256 after
// the one block of K XOR ipad, and after the one block of K XOR opad.
// generator_key writes them each time K changes, and each HMAC under that
// K starts from copies of them. So an HMAC compresses its message and the
// inner hash, and never the two pad blocks again. The midstates derive
// from K, which the private key derives, so derive_nonce wipes them with
// K and V.
typedef struct {
    uint8_t k[SHA256_LEN];
    uint8_t v[SHA256_LEN];
    sha256 inner;
    sha256 outer;
} nonce_generator;

// sha256_update and sha256_final on the path cpu picks. cpu is the
// ch_cfg.cpu value p256_sign_cpu takes, and 0 from p256_sign. In a host
// object the calls go to sha256.h's entries: on the SHA-256 instructions
// when cpu holds CH_CPU_CONSTANT_TIME_SHA256, and on the portable code
// when it does not, as 0 does not. A device object holds one SHA-256, so
// there the macros discard cpu and call sha256.c.
#ifdef CH_CPU_RUNTIME
#define GENERATOR_UPDATE(cpu, s, in, n) sha256_update_cpu((cpu), (s), (in), (n))
#define GENERATOR_FINAL(cpu, s, out) sha256_final_cpu((cpu), (s), (out))
#else
#define GENERATOR_UPDATE(cpu, s, in, n) ((void)(cpu), sha256_update((s), (in), (n)))
#define GENERATOR_FINAL(cpu, s, out) ((void)(cpu), sha256_final((s), (out)))
#endif

// The RFC 2104 pad bytes.
#define GENERATOR_IPAD 0x36
#define GENERATOR_OPAD 0x5c

// Writes g->inner and g->outer from g->k. K is SHA256_LEN bytes, shorter
// than a block, so the HMAC key is K followed by zero bytes (RFC 2104
// §2). Each midstate costs one compression, on the path cpu picks.
static void generator_key(uint32_t cpu, nonce_generator *g) {
    uint8_t pad[SHA256_BLOCK];
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        uint8_t key_byte = i < SHA256_LEN ? g->k[i] : 0;
        pad[i] = (uint8_t)(key_byte ^ GENERATOR_IPAD);
    }
    sha256_init(&g->inner);
    GENERATOR_UPDATE(cpu, &g->inner, pad, SHA256_BLOCK);
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        uint8_t key_byte = i < SHA256_LEN ? g->k[i] : 0;
        pad[i] = (uint8_t)(key_byte ^ GENERATOR_OPAD);
    }
    sha256_init(&g->outer);
    GENERATOR_UPDATE(cpu, &g->outer, pad, SHA256_BLOCK);
    ct_wipe(pad, sizeof pad);
}

// One HMAC-SHA-256 of the generator, keyed with K: the same bytes as
// hkdf.h's hmac_sha256 over g->k, from the midstates generator_key wrote
// for the current K. out may not alias msg. The two hashes run on the
// path cpu picks (GENERATOR_UPDATE, GENERATOR_FINAL).
static void generator_hmac(uint32_t cpu, const nonce_generator *g, const uint8_t *msg,
                           size_t msg_len, uint8_t out[SHA256_LEN]) {
    sha256 s = g->inner;
    GENERATOR_UPDATE(cpu, &s, msg, msg_len);
    GENERATOR_FINAL(cpu, &s, out);
    s = g->outer;
    GENERATOR_UPDATE(cpu, &s, out, SHA256_LEN);
    GENERATOR_FINAL(cpu, &s, out);
    ct_wipe(&s, sizeof s);
}

// The zero bytes the hedged form puts after the noise and after the
// private scalar (draft-irtf-cfrg-det-sigs-with-noise-05 section 4). The
// first count ends V, the separator, the noise and the zeros at the end of
// the second block: 32 + 1 + 32 + 63 is 128. The second ends the private
// scalar and the zeros at the end of the third block: 32 + 32 is 64. So
// the private scalar starts a block of its own, after the noise changed
// the state.
#define HEDGED_NOISE_PAD (2 * SHA256_BLOCK - SHA256_LEN - 1 - P256_NOISE_LEN)
#define HEDGED_KEY_PAD (SHA256_BLOCK - P256_PRIV_LEN)

// The longest tail generator_tail writes: the noise, its zeros, the
// private scalar, its zeros and the reduced message hash, which the draft
// calls provided_data. RFC 6979's tail is the private scalar and the
// reduced message hash alone.
#define GENERATOR_TAIL_MAX                                                                         \
    (P256_NOISE_LEN + HEDGED_NOISE_PAD + P256_PRIV_LEN + HEDGED_KEY_PAD + P256_SCALAR_LEN)

// The longest message the generator hashes: V, one separator byte and the
// longest tail (RFC 6979 §3.2 steps d and f, and the draft's steps d and
// f).
#define GENERATOR_INPUT_MAX (SHA256_LEN + 1 + GENERATOR_TAIL_MAX)

// K = HMAC_K(V || separator || tail), then V = HMAC_K(V). With the tail
// generator_tail writes, this is RFC 6979 §3.2 step d with separator 0x00
// and step f with 0x01, or the hedged form's steps d and f. Step h step
// 3's update is the same shape with no tail, which the caller asks for by
// passing tail_len 0. The new K gets its midstates
// before the second HMAC, which it keys. Each HMAC runs on the path cpu
// picks (generator_hmac).
static void generator_update(uint32_t cpu, nonce_generator *g, uint8_t separator,
                             const uint8_t *tail, size_t tail_len) {
    uint8_t input[GENERATOR_INPUT_MAX];
    uint8_t next[SHA256_LEN];
    wbuf w;
    wb_init(&w, input, sizeof input);
    wb_bytes(&w, g->v, SHA256_LEN);
    wb_u8(&w, separator);
    if (tail_len > 0) {
        wb_bytes(&w, tail, tail_len);
    }
    // GENERATOR_INPUT_MAX is the longest input either caller builds, so
    // an overrun here means the constant and the callers disagree.
    CH_ASSERT(w.err == 0);
    // Each HMAC writes a separate buffer and is copied over the state
    // afterwards, because generator_hmac's output may not alias its
    // message.
    generator_hmac(cpu, g, input, w.len, next);
    memcpy(g->k, next, SHA256_LEN);
    generator_key(cpu, g);
    generator_hmac(cpu, g, g->v, SHA256_LEN, next);
    memcpy(g->v, next, SHA256_LEN);
    ct_wipe(input, sizeof input);
    ct_wipe(next, sizeof next);
}

// The tail of steps d and f into tail, and its length into *tail_len.
// With noise NULL it is RFC 6979's: priv || z_octets. With noise it is
// the hedged form's: noise || zeros || priv || zeros || z_octets
// (HEDGED_NOISE_PAD, HEDGED_KEY_PAD). The test of noise reads the pointer
// the entry passed, never a byte of the noise.
static void generator_tail(uint8_t tail[GENERATOR_TAIL_MAX], size_t *tail_len,
                           const uint8_t priv[P256_PRIV_LEN],
                           const uint8_t z_octets[P256_SCALAR_LEN], const uint8_t *noise) {
    static const uint8_t zeros[HEDGED_NOISE_PAD] = {0};
    wbuf w;
    wb_init(&w, tail, GENERATOR_TAIL_MAX);
    if (noise != NULL) {
        wb_bytes(&w, noise, P256_NOISE_LEN);
        wb_bytes(&w, zeros, HEDGED_NOISE_PAD);
    }
    wb_bytes(&w, priv, P256_PRIV_LEN);
    if (noise != NULL) {
        wb_bytes(&w, zeros, HEDGED_KEY_PAD);
    }
    wb_bytes(&w, z_octets, P256_SCALAR_LEN);
    // GENERATOR_TAIL_MAX is the hedged tail's length, so an overrun here
    // means the constant and this function disagree.
    CH_ASSERT(w.err == 0);
    *tail_len = w.len;
}

// RFC 6979 §3.2 steps a through g, or with noise the hedged form's, whose
// steps d and f take the longer tail (generator_tail). z_octets is
// bits2octets(h1), which for this curve is the 32 bytes of the message
// hash reduced mod n, because qlen, hlen and the octet length are all the
// same here.
static void generator_init(uint32_t cpu, nonce_generator *g, const uint8_t priv[P256_PRIV_LEN],
                           const uint8_t z_octets[P256_SCALAR_LEN], const uint8_t *noise) {
    uint8_t tail[GENERATOR_TAIL_MAX];
    size_t tail_len = 0;
    generator_tail(tail, &tail_len, priv, z_octets, noise);
    memset(g->v, 0x01, SHA256_LEN);
    memset(g->k, 0x00, SHA256_LEN);
    generator_key(cpu, g);
    generator_update(cpu, g, 0x00, tail, tail_len);
    generator_update(cpu, g, 0x01, tail, tail_len);
    ct_wipe(tail, sizeof tail);
}

// One candidate, RFC 6979 §3.2 step h steps 1 and 2. qlen and the hash
// length are both 256 bits here, so T is exactly one HMAC output and the
// loop the RFC writes runs once.
static void generator_next(uint32_t cpu, nonce_generator *g, p256_scalar *candidate) {
    uint8_t next[SHA256_LEN];
    generator_hmac(cpu, g, g->v, SHA256_LEN, next);
    memcpy(g->v, next, SHA256_LEN);
    p256_scalar_from_bytes(candidate, g->v);
    ct_wipe(next, sizeof next);
}

// The nonce: the first candidate in [1, n-1], chosen with masks. Every
// candidate is generated and every generator update runs, whatever the
// earlier candidates were, so the sequence of candidates is exactly the
// RFC's and the cost is the same for every key and message. Returns all
// ones when some candidate was usable and zero when none was. Every HMAC
// runs on the path cpu picks (generator_hmac). The wipe of g covers K, V
// and the two midstates. noise is NULL for RFC 6979, and P256_NOISE_LEN
// bytes for the hedged form (generator_tail).
static uint32_t derive_nonce(uint32_t cpu, p256_scalar *k, const uint8_t priv[P256_PRIV_LEN],
                             const uint8_t z_octets[P256_SCALAR_LEN], const uint8_t *noise) {
    nonce_generator g;
    p256_scalar candidate;
    uint32_t found = 0;

    generator_init(cpu, &g, priv, z_octets, noise);
    *k = p256_scalar_zero;
    for (int i = 0; i < NONCE_CANDIDATES; i++) {
        generator_next(cpu, &g, &candidate);
        uint32_t usable = p256_scalar_reduced_mask(&candidate) & ~p256_scalar_zero_mask(&candidate);
        p256_scalar_cmov(k, &candidate, usable & ~found);
        found |= usable;
        // RFC 6979 §3.2 step h step 3's update, run whether or not the
        // candidate was taken. The candidates a conditional update would
        // produce are the same ones, because the update depends on the
        // generator state and never on the verdict.
        generator_update(cpu, &g, 0x00, NULL, 0);
    }
    ct_wipe(&candidate, sizeof candidate);
    ct_wipe(&g, sizeof g);
    CT_DECLASSIFY(&found, sizeof found);
    return found;
}

// s = k^-1 * (z + r*d) mod n, every step through p256_scalar.c, each
// multiply under the answer widemul (widemul.h).
static void signature_scalar(uint8_t widemul, p256_scalar *s, const p256_scalar *k,
                             const p256_scalar *d, const p256_scalar *z, const p256_scalar *r) {
    p256_scalar k_inverse;
    p256_scalar product;

    widemul_p256_scalar_mul(widemul, &product, r, d);
    p256_scalar_add(&product, z, &product);
    widemul_p256_scalar_inverse(widemul, &k_inverse, k);
    widemul_p256_scalar_mul(widemul, s, &k_inverse, &product);

    ct_wipe(&k_inverse, sizeof k_inverse);
    ct_wipe(&product, sizeof product);
}

// The fault hooks of test/p256_sign_fault_test.c (p256_sign.h), which
// every other build compiles to nothing.
#ifdef CH_P256_SIGN_FAULT_TEST
#define FAULT_POINT(point) p256_sign_fault_point(point)
#define FAULT_SCALAR(s) p256_sign_fault_scalar(s)
#else
#define FAULT_POINT(point) ((void)(point))
#define FAULT_SCALAR(s) ((void)(s))
#endif

// The scalar check: all ones when s*k = z + r*d mod n, zero otherwise.
// It multiplies r by d again rather than read signature_scalar's product,
// so a fault in either multiply or in the inverse of k gives a mismatch.
// Every step is constant time (widemul.h, p256_scalar.h), because k and d
// are secret: both sides are below n, so their bytes are the same exactly
// when the scalars are, and ct_memeq compares them. Every value is wiped.
static uint32_t scalar_check(uint8_t widemul, const p256_scalar *s, const p256_scalar *k,
                             const p256_scalar *d, const p256_scalar *z, const p256_scalar *r) {
    p256_scalar lhs;
    p256_scalar rhs;
    uint8_t lhs_bytes[P256_SCALAR_LEN];
    uint8_t rhs_bytes[P256_SCALAR_LEN];
    widemul_p256_scalar_mul(widemul, &lhs, s, k);
    widemul_p256_scalar_mul(widemul, &rhs, r, d);
    p256_scalar_add(&rhs, z, &rhs);
    p256_scalar_to_bytes(lhs_bytes, &lhs);
    p256_scalar_to_bytes(rhs_bytes, &rhs);
    // ct_memeq answers 1 or 0, and 0 - 1 is all ones.
    uint32_t equal = 0U - ct_memeq(lhs_bytes, rhs_bytes, P256_SCALAR_LEN);
    ct_wipe(&lhs, sizeof lhs);
    ct_wipe(&rhs, sizeof rhs);
    ct_wipe(lhs_bytes, sizeof lhs_bytes);
    ct_wipe(rhs_bytes, sizeof rhs_bytes);
    return equal;
}

// r and s for one nonce, as the DER writer's 32-byte values, and the two
// checks (docs/decisions.md 153). Returns all ones when k*G is finite and
// on the curve, s*k = z + r*d mod n, and neither r nor s is zero (the one
// narrowing of RFC 6979, p256_sign.h); zero otherwise. Every step runs
// whatever the answers are, and masks combine them, so no branch reads
// k*G, k or d. The caller writes r and s only on all ones.
static uint32_t compute_signature(uint8_t widemul, const p256_scalar *k, const p256_scalar *d,
                                  const p256_scalar *z, uint8_t r_bytes[P256_SCALAR_LEN],
                                  uint8_t s_bytes[P256_SCALAR_LEN]) {
    p256_point point;
    p256_scalar r;
    p256_scalar s;
    uint8_t x_bytes[P256_FE_LEN];
    uint8_t y_bytes[P256_FE_LEN];

    widemul_p256_point_base_mul(widemul, &point, k);
    FAULT_POINT(&point);
    // k is in [1, n-1], so k*G is never the point at infinity. The mask is
    // read anyway, so a faulted multiplication that reached infinity gives
    // no signature.
    uint32_t finite = widemul_p256_point_affine(widemul, x_bytes, y_bytes, &point);
    // The on-curve check, before r is taken from x.
    uint32_t on_curve = widemul_p256_point_on_curve(widemul, x_bytes, y_bytes);
    p256_scalar_from_bytes(&r, x_bytes);
    p256_scalar_reduce(&r, &r);
    signature_scalar(widemul, &s, k, d, z, &r);
    FAULT_SCALAR(&s);
    uint32_t consistent = scalar_check(widemul, &s, k, d, z, &r);
    p256_scalar_to_bytes(r_bytes, &r);
    p256_scalar_to_bytes(s_bytes, &s);
    uint32_t usable =
        finite & on_curve & consistent & ~p256_scalar_zero_mask(&r) & ~p256_scalar_zero_mask(&s);

    ct_wipe(&s, sizeof s);
    ct_wipe(&point, sizeof point);
    ct_wipe(x_bytes, sizeof x_bytes);
    ct_wipe(y_bytes, sizeof y_bytes);
    return usable;
}

int p256_sign_key_ok(const uint8_t priv[P256_PRIV_LEN]) {
    p256_scalar d;
    p256_scalar_from_bytes(&d, priv);
    uint32_t usable = p256_scalar_reduced_mask(&d) & ~p256_scalar_zero_mask(&d);
    ct_wipe(&d, sizeof d);
    CT_DECLASSIFY(&usable, sizeof usable);
    return usable != 0;
}

// sig = the DER of r and s when checked is all ones and the DER fits cap,
// and no byte of sig otherwise; returns 1 when it wrote. This is the one
// place the file writes a signature, and proof/p256_sign_harness.c proves
// that sig and *sig_len keep what they held unless both checks passed.
// The verdict is what the caller sees, so the branch on it tells no more.
// The DER writer branches on the leading bytes of r and s, so it runs only
// after the verdict, on a pair that goes on the wire: a pair that a check
// refused is never encoded (docs/decisions.md 155). The DER goes to an
// array of this function's own first, which is wiped.
static int write_if_checked(uint32_t checked, const uint8_t r[P256_SCALAR_LEN],
                            const uint8_t s[P256_SCALAR_LEN], uint8_t *sig, size_t cap,
                            size_t *sig_len) {
    CT_DECLASSIFY(&checked, sizeof checked);
    if (checked == 0) {
        return 0;
    }
    CT_DECLASSIFY(r, P256_SCALAR_LEN);
    CT_DECLASSIFY(s, P256_SCALAR_LEN);
    uint8_t candidate[P256_SIG_MAX];
    size_t candidate_len = 0;
    // The array holds the longest signature, so write_signature never refuses.
    int rc =
        write_signature(candidate, sizeof candidate, &candidate_len, r, s) && candidate_len <= cap;
    if (rc) {
        memcpy(sig, candidate, candidate_len);
        *sig_len = candidate_len;
    }
    ct_wipe(candidate, sizeof candidate);
    return rc;
}

// p256_sign's contract, with the multiplies under widemul and the nonce
// generator's HMACs on the path cpu picks (generator_hmac). noise is NULL
// for the RFC 6979 nonce and P256_NOISE_LEN bytes for the hedged one
// (derive_nonce). r and s are encoded and copied to sig only after both
// checks passed (write_if_checked), and are wiped on either verdict: a
// pair that failed is what a fault made of the nonce or of the key.
static int sign_digest(uint8_t widemul, uint32_t cpu, const uint8_t priv[P256_PRIV_LEN],
                       const uint8_t msg_hash[32], const uint8_t *noise, uint8_t *sig, size_t cap,
                       size_t *sig_len) {
    p256_scalar d;
    p256_scalar z;
    p256_scalar k;
    uint8_t z_octets[P256_SCALAR_LEN];
    uint8_t r_bytes[P256_SCALAR_LEN];
    uint8_t s_bytes[P256_SCALAR_LEN];
    int rc = 0;

    // The key must be in [1, n-1]. This branch reads the configured key,
    // which p256_sign.h states under "Not covered, second".
    if (!p256_sign_key_ok(priv)) {
        return 0;
    }
    p256_scalar_from_bytes(&d, priv);

    // z = bits2int(msg_hash) mod n. bits2int is the plain big-endian
    // integer here, because the hash and the group order are both 256
    // bits wide, so no left shift of the RFC 6979 section 2.3.2 kind
    // applies.
    p256_scalar_from_bytes(&z, msg_hash);
    p256_scalar_reduce(&z, &z);
    p256_scalar_to_bytes(z_octets, &z);

    if (derive_nonce(cpu, &k, priv, z_octets, noise)) {
        uint32_t checked = compute_signature(widemul, &k, &d, &z, r_bytes, s_bytes);
        rc = write_if_checked(checked, r_bytes, s_bytes, sig, cap, sig_len);
    }

    ct_wipe(&d, sizeof d);
    ct_wipe(&z, sizeof z);
    ct_wipe(&k, sizeof k);
    ct_wipe(z_octets, sizeof z_octets);
    // r and s go on the wire when the checks pass, but a pair that a fault
    // changed must not stay on the stack, so both are wiped.
    ct_wipe(r_bytes, sizeof r_bytes);
    ct_wipe(s_bytes, sizeof s_bytes);
    return rc;
}

// p256_sign_hedged's contract, with the multiplies under widemul and the
// nonce generator's HMACs on the path cpu picks.
static int sign_hedged(uint8_t widemul, uint32_t cpu, const uint8_t priv[P256_PRIV_LEN],
                       const uint8_t msg_hash[32], const uint8_t noise[P256_NOISE_LEN],
                       uint8_t *sig, size_t cap, size_t *sig_len) {
    // INV-4's check on the noise draw, which the caller makes (srv_auth.c). A source that
    // returns without writing leaves the noise zero, and then every signature over one message is
    // the same bytes again. A real draw is all zero with probability 2^-256, so this checks the
    // integrator's source against rand.h's contract, which is what CH_ASSERT is for. ct_memeq
    // reads every byte, and its one verdict goes to the assertion.
    {
        static const uint8_t unwritten[P256_NOISE_LEN] = {0};
        CH_ASSERT(!ct_memeq_public(noise, unwritten, P256_NOISE_LEN));
    }
    return sign_digest(widemul, cpu, priv, msg_hash, noise, sig, cap, sig_len);
}

int p256_sign(uint8_t widemul, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
              uint8_t *sig, size_t cap, size_t *sig_len) {
    return sign_digest(widemul, 0, priv, msg_hash, NULL, sig, cap, sig_len);
}

int p256_sign_hedged(uint8_t widemul, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
                     const uint8_t noise[P256_NOISE_LEN], uint8_t *sig, size_t cap,
                     size_t *sig_len) {
    return sign_hedged(widemul, 0, priv, msg_hash, noise, sig, cap, sig_len);
}

#ifdef CH_CPU_RUNTIME
int p256_sign_cpu(uint32_t cpu, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
                  uint8_t *sig, size_t cap, size_t *sig_len) {
    return sign_digest(widemul_of_cpu(cpu), cpu, priv, msg_hash, NULL, sig, cap, sig_len);
}

int p256_sign_hedged_cpu(uint32_t cpu, const uint8_t priv[P256_PRIV_LEN],
                         const uint8_t msg_hash[32], const uint8_t noise[P256_NOISE_LEN],
                         uint8_t *sig, size_t cap, size_t *sig_len) {
    return sign_hedged(widemul_of_cpu(cpu), cpu, priv, msg_hash, noise, sig, cap, sig_len);
}
#endif
