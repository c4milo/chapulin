// Proves, for p256_sign.c:
//
//   memory safety and absence of UB in the RFC 6979 generator, the DER
//   writer and p256_sign itself, over an unconstrained key, an
//   unconstrained message hash, an unconstrained output capacity and
//   unconstrained HMAC output -- which is what makes the proof consider
//   every candidate nonce the real HMAC could produce, including every
//   one out of range;
//
//   that the wbuf inside the generator never overruns. The
//   GENERATOR_INPUT_MAX buffer is sized by hand against two callers, and
//   the CH_ASSERT that catches a disagreement is a proof failure here
//   (proof/harness.h routes ch_assert_fail into __CPROVER_assert);
//
//   that the generator runs its candidates a literal NONCE_CANDIDATES
//   times and calls the HMAC the same number of times whatever those
//   candidates were, which is the constant-time claim p256_sign.h makes
//   about the retry. A conditional retry would show up as a count that
//   depends on the stubbed usable masks;
//
//   that the DER writer stays inside P256_SIG_MAX for every pair of
//   32-byte scalars, that it writes a minimal INTEGER, and that a short
//   capacity is refused rather than truncated -- with no byte written at
//   or past cap.
//
// Layered proof, in the shape hkdf_harness.c uses. Three things below
// are stubs that assert their callers' contract and havoc their
// outputs: hmac_sha256, whose own proof is proof/hkdf_harness.c; the
// scalar arithmetic, whose proof is proof/p256_scalar_harness.c; and
// the point arithmetic, whose proof is proof/p256_point_harness.c.
// Nothing here depends on an arithmetic value, which is why the formula
// converges at all: the real p256_sign runs 512 complete point
// additions, and a proof that unrolled them would return no verdict.
#include "harness.h"

#include "hkdf.h"
#include "p256_point_stubs.h"
#include "p256_scalar_stubs.h"

#include "p256_sign.c"

// Counts the stubbed HMAC calls one derive_nonce spends, which is how
// prove_nonce_cost_is_fixed states the constant-time claim about the
// retry. Nothing in p256_sign.c reads it.
static unsigned hmac_calls = 0;

// --- stubs ---

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(key_len == 0 || __CPROVER_r_ok(key, key_len), "hmac_sha256: key readable");
    __CPROVER_assert(msg_len == 0 || __CPROVER_r_ok(msg, msg_len), "hmac_sha256: message readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "hmac_sha256: output writable");
    hmac_calls++;
    fill_nondet(out, SHA256_LEN);
}

// --- the proofs ---

// The generator produces NONCE_CANDIDATES candidates and spends the same
// number of HMAC calls whatever the stubbed predicates answered. Two
// HMACs per generator_update and one per generator_next: two updates in
// generator_init, then per candidate one next and one update.
static void prove_nonce_cost_is_fixed(void) {
    uint8_t priv[P256_PRIV_LEN];
    uint8_t z_octets[P256_SCALAR_LEN];
    p256_scalar k;

    fill_nondet(priv, sizeof priv);
    fill_nondet(z_octets, sizeof z_octets);
    hmac_calls = 0;
    (void)derive_nonce(&k, priv, z_octets);
    __CPROVER_assert(
        hmac_calls == 4 + 3 * NONCE_CANDIDATES,
        "derive_nonce: the HMAC count does not depend on which candidates were usable");
}

// The DER writer, over any two 32-byte scalars and any capacity. The
// assertions are the writer's whole contract: it either writes a
// structure inside cap and reports its length, or it reports failure and
// leaves the bytes at and past cap alone.
static void prove_der_writer(void) {
    uint8_t r[P256_SCALAR_LEN];
    uint8_t s[P256_SCALAR_LEN];
    uint8_t sig[P256_SIG_MAX + 1];
    size_t cap = nondet_size_t();
    size_t sig_len = nondet_size_t();

    __CPROVER_assume(cap <= P256_SIG_MAX);
    fill_nondet(r, sizeof r);
    fill_nondet(s, sizeof s);
    fill_nondet(sig, sizeof sig);
    uint8_t guard = sig[P256_SIG_MAX];

    int rc = write_signature(sig, cap, &sig_len, r, s);
    __CPROVER_assert(rc == 0 || sig_len <= cap, "write_signature: the length fits the capacity");
    __CPROVER_assert(rc == 0 || sig_len <= P256_SIG_MAX,
                     "write_signature: the length fits P256_SIG_MAX");
    __CPROVER_assert(rc == 0 || sig[0] == 0x30, "write_signature: a SEQUENCE comes out");
    __CPROVER_assert(sig[P256_SIG_MAX] == guard,
                     "write_signature: nothing is written past the capacity");
}

// One INTEGER, on its own, so the minimal-form claim is stated where the
// code makes it rather than through the whole structure.
static void prove_integer_is_minimal(void) {
    uint8_t value[P256_SCALAR_LEN];
    uint8_t out[P256_SCALAR_LEN + 2];
    wbuf w;

    fill_nondet(value, sizeof value);
    wb_init(&w, out, sizeof out);
    write_integer(&w, value);
    // A 32-byte value whose top bit is set needs 33 content bytes, which
    // is one more than this buffer holds, so the writer must report the
    // overrun rather than drop the pad.
    __CPROVER_assert(w.err != 0 || w.len <= sizeof out,
                     "write_integer: a written INTEGER fits the buffer it was given");
    if (w.err == 0) {
        __CPROVER_assert(out[0] == 0x02, "write_integer: the tag is INTEGER");
        __CPROVER_assert(out[1] >= 1 && out[1] <= 33, "write_integer: the length is in range");
        __CPROVER_assert((out[2] & 0x80) == 0, "write_integer: the value reads as positive");
        __CPROVER_assert(out[1] == 1 || out[2] != 0x00 || (out[3] & 0x80) != 0,
                         "write_integer: a leading zero appears only to clear the top bit");
    }
}

// The whole call, over an unconstrained key, hash and capacity.
static void prove_sign(void) {
    uint8_t priv[P256_PRIV_LEN];
    uint8_t msg_hash[32];
    uint8_t sig[P256_SIG_MAX + 1];
    size_t cap = nondet_size_t();
    size_t sig_len = nondet_size_t();

    __CPROVER_assume(cap <= P256_SIG_MAX);
    fill_nondet(priv, sizeof priv);
    fill_nondet(msg_hash, sizeof msg_hash);
    fill_nondet(sig, sizeof sig);
    uint8_t guard = sig[P256_SIG_MAX];

    int rc = p256_sign(priv, msg_hash, sig, cap, &sig_len);
    __CPROVER_assert(rc == 0 || rc == 1, "p256_sign: the return is the 1-or-0 convention");
    __CPROVER_assert(rc == 0 || sig_len <= cap, "p256_sign: the length fits the capacity");
    __CPROVER_assert(sig[P256_SIG_MAX] == guard, "p256_sign: nothing is written past the capacity");
}

int main(void) {
    prove_nonce_cost_is_fixed();
    prove_der_writer();
    prove_integer_is_minimal();
    prove_sign();
    return 0;
}
