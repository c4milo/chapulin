// ECDSA P-256 signing (see p256_sign.h for the contracts, the
// constant-time claim and the one stated narrowing against RFC 6979).
// Three things live here and nothing else: the RFC 6979 nonce generator,
// the four scalar operations that make s, and the DER writer. The
// arithmetic is p256_scalar.c's and p256_point.c's.
#include "p256_sign.h"

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "hkdf.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "sha256.h"

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
typedef struct {
    uint8_t k[SHA256_LEN];
    uint8_t v[SHA256_LEN];
} nonce_generator;

// The longest message the generator hashes: V, one separator byte, the
// private scalar and the reduced message hash (RFC 6979 §3.2 steps d
// and f).
#define GENERATOR_INPUT_MAX (SHA256_LEN + 1 + P256_PRIV_LEN + P256_SCALAR_LEN)

// K = HMAC_K(V || separator || priv || z), then V = HMAC_K(V). This is
// RFC 6979 §3.2 step d with separator 0x00 and step f with 0x01; step h
// step 3's update is the same shape with no priv and no z, which the
// caller asks for by passing tail_len 0.
static void generator_update(nonce_generator *g, uint8_t separator, const uint8_t *tail,
                             size_t tail_len) {
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
    // afterwards. hmac_sha256 happens to tolerate an output that aliases
    // its key or its message, but nothing in hkdf.h promises that, and a
    // generator that depended on it would break silently.
    hmac_sha256(g->k, SHA256_LEN, input, w.len, next);
    memcpy(g->k, next, SHA256_LEN);
    hmac_sha256(g->k, SHA256_LEN, g->v, SHA256_LEN, next);
    memcpy(g->v, next, SHA256_LEN);
    ct_wipe(input, sizeof input);
    ct_wipe(next, sizeof next);
}

// RFC 6979 §3.2 steps a through g. z_octets is bits2octets(h1), which
// for this curve is the 32 bytes of the message hash reduced mod n,
// because qlen, hlen and the octet length are all the same here.
static void generator_init(nonce_generator *g, const uint8_t priv[P256_PRIV_LEN],
                           const uint8_t z_octets[P256_SCALAR_LEN]) {
    uint8_t tail[P256_PRIV_LEN + P256_SCALAR_LEN];
    memcpy(tail, priv, P256_PRIV_LEN);
    memcpy(tail + P256_PRIV_LEN, z_octets, P256_SCALAR_LEN);
    memset(g->v, 0x01, SHA256_LEN);
    memset(g->k, 0x00, SHA256_LEN);
    generator_update(g, 0x00, tail, sizeof tail);
    generator_update(g, 0x01, tail, sizeof tail);
    ct_wipe(tail, sizeof tail);
}

// One candidate, RFC 6979 §3.2 step h steps 1 and 2. qlen and the hash
// length are both 256 bits here, so T is exactly one HMAC output and the
// loop the RFC writes runs once.
static void generator_next(nonce_generator *g, p256_scalar *candidate) {
    uint8_t next[SHA256_LEN];
    hmac_sha256(g->k, SHA256_LEN, g->v, SHA256_LEN, next);
    memcpy(g->v, next, SHA256_LEN);
    p256_scalar_from_bytes(candidate, g->v);
    ct_wipe(next, sizeof next);
}

// The nonce: the first candidate in [1, n-1], chosen with masks. Every
// candidate is generated and every generator update runs, whatever the
// earlier candidates were, so the sequence of candidates is exactly the
// RFC's and the cost is the same for every key and message. Returns all
// ones when some candidate was usable and zero when none was.
static uint32_t derive_nonce(p256_scalar *k, const uint8_t priv[P256_PRIV_LEN],
                             const uint8_t z_octets[P256_SCALAR_LEN]) {
    nonce_generator g;
    p256_scalar candidate;
    uint32_t found = 0;

    generator_init(&g, priv, z_octets);
    *k = p256_scalar_zero;
    for (int i = 0; i < NONCE_CANDIDATES; i++) {
        generator_next(&g, &candidate);
        uint32_t usable = p256_scalar_reduced_mask(&candidate) & ~p256_scalar_zero_mask(&candidate);
        p256_scalar_cmov(k, &candidate, usable & ~found);
        found |= usable;
        // RFC 6979 §3.2 step h step 3's update, run whether or not the
        // candidate was taken. The candidates a conditional update would
        // produce are the same ones, because the update depends on the
        // generator state and never on the verdict.
        generator_update(&g, 0x00, NULL, 0);
    }
    ct_wipe(&candidate, sizeof candidate);
    ct_wipe(&g, sizeof g);
    return found;
}

// One DER INTEGER holding a 32-byte big-endian scalar, minimal-length
// per X.690 §8.3: leading zero bytes are dropped, and one zero byte is
// written back when the top bit of the first content byte is set. The
// value is r or s, both of which go on the wire, so reading their bytes
// here leaks nothing that the signature does not already carry.
static void write_integer(wbuf *w, const uint8_t value[P256_SCALAR_LEN]) {
    size_t lead = 0;
    while (lead < P256_SCALAR_LEN - 1 && value[lead] == 0) {
        lead++;
    }
    size_t content_len = P256_SCALAR_LEN - lead;
    int pad = (value[lead] & 0x80) != 0;
    wb_u8(w, 0x02);
    wb_u8(w, (uint8_t)(content_len + (size_t)pad));
    if (pad) {
        wb_u8(w, 0x00);
    }
    wb_bytes(w, value + lead, content_len);
}

// SEQUENCE { INTEGER r, INTEGER s }. The body is at most 70 bytes, so
// its length always fits the short form and no definite-long header is
// written. Returns 1 when the whole structure fit in cap.
static int write_signature(uint8_t *sig, size_t cap, size_t *sig_len,
                           const uint8_t r[P256_SCALAR_LEN], const uint8_t s[P256_SCALAR_LEN]) {
    uint8_t body[P256_SIG_MAX];
    wbuf inner;
    wbuf outer;

    wb_init(&inner, body, sizeof body);
    write_integer(&inner, r);
    write_integer(&inner, s);
    if (inner.err) {
        return 0;
    }
    wb_init(&outer, sig, cap);
    wb_u8(&outer, 0x30);
    wb_u8(&outer, (uint8_t)inner.len);
    wb_bytes(&outer, body, inner.len);
    if (outer.err) {
        return 0;
    }
    *sig_len = outer.len;
    return 1;
}

// s = k^-1 * (z + r*d) mod n, every step through p256_scalar.c.
static void signature_scalar(p256_scalar *s, const p256_scalar *k, const p256_scalar *d,
                             const p256_scalar *z, const p256_scalar *r) {
    p256_scalar k_inverse;
    p256_scalar product;

    p256_scalar_mul(&product, r, d);
    p256_scalar_add(&product, z, &product);
    p256_scalar_inverse(&k_inverse, k);
    p256_scalar_mul(s, &k_inverse, &product);

    ct_wipe(&k_inverse, sizeof k_inverse);
    ct_wipe(&product, sizeof product);
}

// r and s for one nonce, as the 32 big-endian bytes the DER writer
// takes. Returns 1 when both are usable and 0 when either came out zero,
// which p256_sign.h states is the one place this file narrows RFC 6979.
static int compute_signature(const p256_scalar *k, const p256_scalar *d, const p256_scalar *z,
                             uint8_t r_bytes[P256_SCALAR_LEN], uint8_t s_bytes[P256_SCALAR_LEN]) {
    p256_point point;
    p256_scalar r = p256_scalar_zero;
    p256_scalar s = p256_scalar_zero;
    uint8_t x_bytes[P256_FE_LEN];
    int rc = 0;

    p256_point_base_mul(&point, k);
    // The point is k*G for a k in [1, n-1], so it is never the point at
    // infinity and the mask is always all ones. Reading it anyway keeps a
    // faulted multiplication from producing a signature over bytes that
    // are not a coordinate.
    if (p256_point_affine_x(x_bytes, &point)) {
        p256_scalar_from_bytes(&r, x_bytes);
        p256_scalar_reduce(&r, &r);
        signature_scalar(&s, k, d, z, &r);
        p256_scalar_to_bytes(r_bytes, &r);
        p256_scalar_to_bytes(s_bytes, &s);
        // r and s are public: they go on the wire. A zero in either is
        // below 2^-127.
        rc = !p256_scalar_zero_mask(&r) && !p256_scalar_zero_mask(&s);
    }

    ct_wipe(&s, sizeof s);
    ct_wipe(&point, sizeof point);
    return rc;
}

int p256_sign(const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32], uint8_t *sig,
              size_t cap, size_t *sig_len) {
    p256_scalar d;
    p256_scalar z;
    p256_scalar k;
    uint8_t z_octets[P256_SCALAR_LEN];
    uint8_t r_bytes[P256_SCALAR_LEN];
    uint8_t s_bytes[P256_SCALAR_LEN];
    int rc = 0;

    // The key must be in [1, n-1]. This branch reads the configured key,
    // which p256_sign.h states under "Not covered, second".
    p256_scalar_from_bytes(&d, priv);
    if (!(p256_scalar_reduced_mask(&d) & ~p256_scalar_zero_mask(&d))) {
        ct_wipe(&d, sizeof d);
        return 0;
    }

    // z = bits2int(msg_hash) mod n. bits2int is the plain big-endian
    // integer here, because the hash and the group order are both 256
    // bits wide, so no left shift of the RFC 6979 section 2.3.2 kind
    // applies.
    p256_scalar_from_bytes(&z, msg_hash);
    p256_scalar_reduce(&z, &z);
    p256_scalar_to_bytes(z_octets, &z);

    if (derive_nonce(&k, priv, z_octets) && compute_signature(&k, &d, &z, r_bytes, s_bytes)) {
        rc = write_signature(sig, cap, sig_len, r_bytes, s_bytes);
    }

    ct_wipe(&d, sizeof d);
    ct_wipe(&z, sizeof z);
    ct_wipe(&k, sizeof k);
    ct_wipe(z_octets, sizeof z_octets);
    ct_wipe(s_bytes, sizeof s_bytes);
    return rc;
}
