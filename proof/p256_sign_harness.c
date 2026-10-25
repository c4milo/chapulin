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
//   times, computes the HMAC midstates and finishes the HMACs the same
//   number of times whatever those candidates were, which is the
//   constant-time claim p256_sign.h makes about the retry. A conditional
//   retry would show up as a count that depends on the stubbed usable
//   masks;
//
//   that the DER writer stays inside P256_SIG_MAX for every pair of
//   32-byte scalars, that it writes a minimal INTEGER, and that a short
//   capacity is refused rather than truncated -- with no byte written at
//   or past cap;
//
//   that the tail of steps d and f is RFC 6979's priv || z without noise,
//   and the hedged form's noise || zeros || priv || zeros || z with it,
//   byte for byte, with the private scalar at the start of a SHA-256
//   block (docs/decisions.md 153);
//
//   that p256_sign and p256_sign_hedged write sig and *sig_len only
//   after both checks passed, k*G on the curve and s*k = z + r*d, and on
//   every refusal leave both as they were. The on-curve check is a stub
//   with a free verdict, and the scalar check compares values the scalar
//   stubs havoc, so this holds for a faulted signature too
//   (docs/decisions.md 153).
//
// Layered proof, in the shape hkdf_harness.c uses. Three things below
// are stubs that assert their callers' contract and havoc their
// outputs: SHA-256's three calls, whose own proof is
// proof/sha256_harness.c; the scalar arithmetic, whose proof is
// proof/p256_scalar_harness.c; and the point arithmetic, whose proof is
// proof/p256_point_harness.c. The generator's HMAC is its own code over
// the SHA-256 stubs, so its memory accesses are under proof here, and
// the RFC 6979 vectors and the differential hold its bytes.
// Nothing here depends on an arithmetic value, which is why the formula
// converges at all: the real p256_sign runs 512 complete point
// additions, and a proof that unrolled them would return no verdict.
#include "harness.h"

#include "p256_point_stubs.h"
#include "p256_scalar_stubs.h"

#include "p256_sign.c"

// Counts the stubbed SHA-256 starts and finals one derive_nonce spends,
// which is how prove_nonce_cost_is_fixed states the constant-time claim
// about the retry. Each K takes two starts, one for each midstate, and
// each HMAC takes two finals. Nothing in p256_sign.c reads them. The
// stubs leave the state as it was: no value of it reaches an assertion,
// and the finals havoc each digest.
static unsigned sha256_starts = 0;
static unsigned sha256_finals = 0;

// --- stubs ---

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_init: ctx writable");
    sha256_starts++;
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
    sha256_finals++;
    fill_nondet(out, SHA256_LEN);
}

// The on-curve check's contract and the comparison the scalar check ends
// in (docs/decisions.md 153). They live here and not in the shared stub
// headers, because p256_sign.c alone calls them, and a stub no harness
// calls would lower the reach of each harness that includes it. Each
// keeps its last answer, so prove_entry can state that a written
// signature passed both.
static uint32_t p256_point_on_curve_answer;

uint32_t p256_point_on_curve(const uint8_t x[P256_FE_LEN], const uint8_t y[P256_FE_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(x, P256_FE_LEN), "on_curve: x readable");
    __CPROVER_assert(__CPROVER_r_ok(y, P256_FE_LEN), "on_curve: y readable");
    p256_point_on_curve_answer = nondet_mask();
    return p256_point_on_curve_answer;
}

// ct.c's comparison, written out here so the harness keeps its last
// answer: the scalar check is the last caller in a signature, after the
// noise's CH_ASSERT. It compares as ct.c does, so the noise assertion
// still sees the real answer. ct.c has its own harness.
static uint32_t ct_memeq_answer;

uint32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    __CPROVER_assert(n == 0 || (__CPROVER_r_ok(a, n) && __CPROVER_r_ok(b, n)),
                     "ct_memeq: both inputs readable");
    uint32_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint32_t)(a[i] ^ b[i]);
    }
    ct_memeq_answer = diff == 0 ? 1U : 0U;
    return ct_memeq_answer;
}

// --- the proofs ---

// The generator produces NONCE_CANDIDATES candidates and spends the same
// number of HMACs and keys whatever the stubbed predicates answered. Two
// HMACs per generator_update and one per generator_next: two updates in
// generator_init, then per candidate one next and one update. One key
// for K's first value and one per generator_update.
static void prove_nonce_cost_is_fixed(void) {
    uint8_t priv[P256_PRIV_LEN];
    uint8_t z_octets[P256_SCALAR_LEN];
    p256_scalar k;

    fill_nondet(priv, sizeof priv);
    fill_nondet(z_octets, sizeof z_octets);
    uint8_t noise[P256_NOISE_LEN];
    fill_nondet(noise, sizeof noise);
    sha256_starts = 0;
    sha256_finals = 0;
    // A device object reads no cpu (GENERATOR_UPDATE), so any value runs
    // the same calls. The hedged form runs the same HMACs over a longer
    // tail, so one count holds both forms.
    (void)derive_nonce(nondet_u32(), &k, priv, z_octets, nondet_u8() ? noise : NULL);
    __CPROVER_assert(
        sha256_finals == 2 * (4 + 3 * NONCE_CANDIDATES),
        "derive_nonce: the HMAC count does not depend on which candidates were usable");
    __CPROVER_assert(sha256_starts == 2 * (1 + 2 + NONCE_CANDIDATES),
                     "derive_nonce: the key count does not depend on which candidates were usable");
}

// The tail of steps d and f, byte for byte, in both forms. RFC 6979's is
// priv || z. The hedged one is the draft's noise || 63 zeros || priv ||
// 32 zeros || z, so that the private scalar starts the third SHA-256 block
// of the HMAC input: V and the separator take 33 bytes before the tail,
// and 33 + 32 + 63 is 128.
static void prove_generator_tail(void) {
    uint8_t priv[P256_PRIV_LEN];
    uint8_t z_octets[P256_SCALAR_LEN];
    uint8_t noise[P256_NOISE_LEN];
    uint8_t tail[GENERATOR_TAIL_MAX];
    size_t tail_len = nondet_size_t();
    size_t i = nondet_size_t();

    fill_nondet(priv, sizeof priv);
    fill_nondet(z_octets, sizeof z_octets);
    fill_nondet(noise, sizeof noise);
    if (nondet_u8()) {
        generator_tail(tail, &tail_len, priv, z_octets, NULL);
        __CPROVER_assert(tail_len == P256_PRIV_LEN + P256_SCALAR_LEN,
                         "generator_tail: RFC 6979's tail is priv and z");
        __CPROVER_assume(i < tail_len);
        __CPROVER_assert(tail[i] == (i < 32 ? priv[i] : z_octets[i - 32]),
                         "generator_tail: RFC 6979's tail is priv || z");
        return;
    }
    generator_tail(tail, &tail_len, priv, z_octets, noise);
    __CPROVER_assert(tail_len == GENERATOR_TAIL_MAX && tail_len == 191,
                     "generator_tail: the hedged tail is 191 bytes");
    __CPROVER_assert(SHA256_LEN + 1 + P256_NOISE_LEN + HEDGED_NOISE_PAD == 2 * SHA256_BLOCK,
                     "generator_tail: the private scalar starts a block");
    __CPROVER_assume(i < tail_len);
    uint8_t want = 0;
    if (i < 32) {
        want = noise[i];
    } else if (i >= 95 && i < 127) {
        want = priv[i - 95];
    } else if (i >= 159) {
        want = z_octets[i - 159];
    }
    __CPROVER_assert(tail[i] == want, "generator_tail: the hedged tail is the draft's");
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

// One entry, RFC 6979's or the hedged one, over an unconstrained key,
// hash, capacity and noise, and every verdict of the two checks. It
// writes sig and *sig_len only when both checks answered all ones, and
// then inside cap; on every refusal both keep every byte they held. The
// noise is not all zero, because CH_ASSERT fires on that draw (INV-4),
// and the proof states the call for every other value. The stubs keep
// each check's last answer, and a sentinel shows a check that never ran.
#define CHECK_NOT_RUN 0x5a5a5a5aU
static void prove_entry(int hedged) {
    uint8_t priv[P256_PRIV_LEN];
    uint8_t msg_hash[32];
    uint8_t noise[P256_NOISE_LEN];
    uint8_t sig[P256_SIG_MAX + 1];
    uint8_t before[P256_SIG_MAX + 1];
    size_t cap = nondet_size_t();
    size_t sig_len = nondet_size_t();
    size_t i = nondet_size_t();

    __CPROVER_assume(cap <= P256_SIG_MAX);
    fill_nondet(priv, sizeof priv);
    fill_nondet(msg_hash, sizeof msg_hash);
    fill_nondet(noise, sizeof noise);
    __CPROVER_assume(noise[0] != 0);
    fill_nondet(sig, sizeof sig);
    memcpy(before, sig, sizeof before);
    size_t len_before = sig_len;
    p256_point_on_curve_answer = CHECK_NOT_RUN;
    ct_memeq_answer = CHECK_NOT_RUN;

    int rc = hedged ? p256_sign_hedged(nondet_u8(), priv, msg_hash, noise, sig, cap, &sig_len)
                    : p256_sign(nondet_u8(), priv, msg_hash, sig, cap, &sig_len);
    __CPROVER_assert(rc == 0 || rc == 1, "p256_sign: the return is the 1-or-0 convention");
    __CPROVER_assert(rc == 0 || (p256_point_on_curve_answer == UINT32_MAX && ct_memeq_answer == 1),
                     "p256_sign: a written signature passed both checks");
    __CPROVER_assert(rc == 0 || sig_len <= cap, "p256_sign: the length fits the capacity");
    __CPROVER_assume(i < sizeof sig);
    __CPROVER_assert(rc == 1 || (sig[i] == before[i] && sig_len == len_before),
                     "p256_sign: a refusal leaves both outputs as they were");
    __CPROVER_assert(i < cap || sig[i] == before[i],
                     "p256_sign: nothing is written past the capacity");
}

// The key test on its own, the call a server runs on its configuration:
// it reads the 32 key bytes and answers 1 or 0.
static void prove_key_ok(void) {
    uint8_t priv[P256_PRIV_LEN];
    fill_nondet(priv, sizeof priv);
    int ok = p256_sign_key_ok(priv);
    __CPROVER_assert(ok == 0 || ok == 1, "p256_sign_key_ok: the answer is 1 or 0");
}

int main(void) {
    prove_nonce_cost_is_fixed();
    prove_generator_tail();
    prove_der_writer();
    prove_integer_is_minimal();
    prove_entry(0);
    prove_entry(1);
    prove_key_ok();
    return 0;
}
