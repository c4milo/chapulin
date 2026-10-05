// What rsa_sign64_sp1 and rsa_sign64_key_ok leave on the stack, for
// bin/rsa_sign_equiv_test.
//
// Included by test/rsa_sign_equiv_test.c only, which declares the key,
// random_message and the failure and comparison counts this file uses.
#ifndef CH_RSA_SIGN_EQUIV_RESIDUE_H
#define CH_RSA_SIGN_EQUIV_RESIDUE_H

// A signature holds the two primes' records, the message reduced modulo
// each, two tables of sixteen powers, the entry each last step read, the
// two halves of the signature, the factor that joins them, the candidate
// and the power its check raises it to, and wipes each before it returns.
// Its frames are dead after the return, but their bytes stay in memory
// below this binary's own frames until another call writes over them. Any
// one of those values with the message is enough to factor the modulus,
// and so is a candidate that failed its check.
//
// A run makes one call, residue_snapshot copies the stack below its
// caller as deep as RESIDUE_BYTES, where the dead frames lay, and the
// run looks in the copy for two limbs side by side of each value the call
// held, at every byte offset. So an array left behind is found, whole or
// in part. The values are computed only after the copy, and they stay in
// this file's own dead frames, so a run takes a copy before its call too:
// stack_residue_take writes zeros over what it copies, which removes what
// the run before left there. A run that starts with a limb of 0 or 1 is
// not looked for: memory holds those for other reasons.
//
// A signature's own frame is the last one written when it returns, and
// the frames of what it called are not: the exponentiation's frame is
// written over by the recombination and the check, and the reduction's by
// the exponentiation. So the stack after a signature cannot show whether
// one of those wiped what it held, and three more runs call each on its
// own: the reduction and the recombination through
// test/rsa_sign_equiv_pieces.c, where rsa_sign64.c's static functions are
// compiled a second time, and rsa_sign64_power itself.
//
// Seven runs for each key:
//
//   - a signature. It looks for everything computed from the key, and for
//     the encoded message, which is also what the check's power is when
//     the check passes. The signature itself is public and is not looked
//     for.
//   - a signature under a key with one bit of dp changed, which the check
//     refuses. It looks for the same values, and for the candidate that
//     failed, as limbs and as bytes, and the power the check raised it
//     to.
//   - the key test. It looks for the two primes.
//   - the key test under a key with one bit of q changed, which it
//     refuses. It looks for the primes and for the limbs of their product
//     that are not the modulus's, which with the modulus give p.
//   - the reduction of the message modulo p. It looks for R^3 and for the
//     two products it adds.
//   - the exponentiation modulo p. It looks for the sixteen powers, one
//     of which is the entry the last step read, and for the power itself,
//     which the last multiplication's running sum held.
//   - the recombination. It looks for qinv, the difference of the halves
//     and the factor that joins them.
//
// One limb alone is not a finding here, because no wipe written in C can
// name where a compiler keeps one: a register a callee saves, or a slot of
// the compiler's own. CH_RSA_RESIDUE_LIMBS=1 looks for one all the same,
// which is how the slot rsa_mont64_mont_mul's volatile reads removed was
// found (docs/decisions.md 95). What that run finds depends on the
// compiler, so check does not hold it.
//
// The runs hold a claim about optimized code alone, and
// test/rsa_sign_equiv_test.c makes none in a binary built without
// optimization or under AddressSanitizer (test/stack_residue.c). A
// compiler that was not asked to optimize keeps every local in its frame,
// a limb of a running sum beside its carry among them, and the wipes name
// arrays and no such local: built at -O0, a run finds two limbs of a
// signature's half below a signature.
#define RESIDUE_BYTES 32768
#define PRIME_LIMBS (RSA_MONT64_LIMBS_MAX / 2 + 1)

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_em[CH_RSA_MODULUS_MAX];
static uint8_t residue_sig[CH_RSA_MODULUS_MAX];
static int residue_signed;
static int residue_admitted;
// The call the current run made, for a finding's text.
static const char *residue_callee;

static __attribute__((noinline)) void residue_sign(void) {
    residue_signed = rsa_sign64_sp1(&key, residue_em, residue_sig);
}

static __attribute__((noinline)) void residue_key_test(void) {
    residue_admitted = rsa_sign64_key_ok(&key);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// How many limbs side by side count as a value left behind: 2, unless
// CH_RSA_RESIDUE_LIMBS names another count from 1 to 8.
static size_t residue_run = 2;

static void residue_run_from_env(void) {
    const char *text = getenv("CH_RSA_RESIDUE_LIMBS");
    if (text != NULL && text[0] >= '1' && text[0] <= '8' && text[1] == 0) {
        residue_run = (size_t)(text[0] - '0');
    }
}

// Whether the copy holds residue_run limbs of the count that are side by
// side in limbs, at any byte offset. It reports the first run it finds, by
// its first limb and its offset from the copy's end, which is how far
// below this file's frames it lay.
static int residue_holds(const char *what, const uint64_t *limbs, size_t count) {
    size_t run_bytes = residue_run * sizeof(uint64_t);
    for (size_t i = 0; i + residue_run <= count; i++) {
        if (limbs[i] <= 1) {
            continue;
        }
        for (size_t at = 0; at + run_bytes <= RESIDUE_BYTES; at++) {
            if (memcmp(&residue_copy[at], &limbs[i], run_bytes) == 0) {
                failures++;
                (void)fprintf(stderr,
                              "FAIL residue: the stack below %s still holds %zu limb(s) of %s "
                              "from limb %zu, %zu bytes down\n",
                              residue_callee, residue_run, what, i, RESIDUE_BYTES - at);
                return 1;
            }
        }
    }
    return 0;
}

// residue_holds for a value the call held as bytes: the same search over
// the bytes in the order memory has them, eight at a time.
static int residue_holds_bytes(const char *what, const uint8_t *bytes, size_t len) {
    uint64_t chunks[CH_RSA_MODULUS_MAX / 8];
    memcpy(chunks, bytes, len);
    return residue_holds(what, chunks, len / 8);
}

// The message in the Montgomery domain of one prime, as rsa_sign64.c's
// message_mod_prime computes it: the high limbs times R^3 and the low
// limbs times R^2, added modulo the prime. It looks for R^3 and for the
// two products on the way, each of which is a public number reduced
// modulo the prime. Returns 1 when it found any.
static int residue_of_base(const char *name, uint64_t *base, const rsa_mont64_modulus *mod) {
    size_t k = mod->limbs;
    size_t em_limbs = key.n_len / 8;
    uint64_t em[RSA_MONT64_LIMBS_MAX];
    uint64_t high[PRIME_LIMBS] = {0};
    uint64_t r3[PRIME_LIMBS];
    char what[64];
    rsa_mont64_from_bytes(em, em_limbs, residue_em, key.n_len);
    for (size_t i = k; i < em_limbs; i++) {
        high[i - k] = em[i];
    }
    rsa_mont64_mont_mul(r3, mod->r2, mod->r2, mod);
    rsa_mont64_mont_mul(high, high, r3, mod);
    rsa_mont64_mont_mul(base, em, mod->r2, mod);
    (void)snprintf(what, sizeof what, "R^3 modulo %s", name);
    int found = residue_holds(what, r3, k);
    (void)snprintf(what, sizeof what, "the message's high limbs modulo %s", name);
    found = found || residue_holds(what, high, k);
    (void)snprintf(what, sizeof what, "the message's low limbs modulo %s", name);
    found = found || residue_holds(what, base, k);
    rsa_mont64_add(base, base, high, mod);
    return found;
}

// Looks for the sixteen powers of base that rsa_sign64_power's table
// holds, the first of which is 1 in the domain. Returns 1 when it found
// any.
static int residue_of_table(const char *name, const uint64_t *base, const rsa_mont64_modulus *mod) {
    uint64_t power[PRIME_LIMBS];
    uint64_t one[PRIME_LIMBS] = {1};
    char what[64];
    rsa_mont64_mont_mul(power, one, mod->r2, mod);
    for (int entry = 0; entry < 16; entry++) {
        (void)snprintf(what, sizeof what, "entry %d of the table modulo %s", entry, name);
        if (residue_holds(what, power, mod->limbs)) {
            return 1;
        }
        rsa_mont64_mont_mul(power, power, base, mod);
    }
    return 0;
}

// Looks for one prime's share of what a signature held: the prime, R^2
// modulo it, the message in its domain, the sixteen powers and the half
// of the signature, which half takes. Returns 1 when it found any.
static int residue_of_prime(const char *name, const uint8_t *prime, const uint8_t *exponent,
                            uint64_t *half) {
    size_t half_len = key.n_len / 2;
    rsa_mont64_modulus mod;
    uint64_t base[PRIME_LIMBS];
    char what[64];
    rsa_mont64_modulus_init(&mod, prime, half_len, 8 * half_len);
    (void)snprintf(what, sizeof what, "the prime %s", name);
    if (residue_holds(what, mod.m, mod.limbs)) {
        return 1;
    }
    (void)snprintf(what, sizeof what, "R^2 modulo %s", name);
    if (residue_holds(what, mod.r2, mod.limbs) || residue_of_base(name, base, &mod) ||
        residue_of_table(name, base, &mod)) {
        return 1;
    }
    rsa_sign64_power(half, base, exponent, half_len, &mod);
    (void)snprintf(what, sizeof what, "the half of the signature modulo %s", name);
    return residue_holds(what, half, mod.limbs);
}

// Looks for what the recombination held, from the two halves in their
// domains: qinv, the second half out of q's domain, the difference of the
// halves and Garner's factor. candidate takes the value the signer then
// checked, key.n_len bytes, and s its limbs. Returns 1 when it found any.
static int residue_of_recombination(uint64_t *m1, uint64_t *m2, uint64_t *s, uint8_t *candidate) {
    size_t half_len = key.n_len / 2;
    size_t limbs = (half_len + 7) / 8;
    uint64_t qinv[PRIME_LIMBS];
    uint64_t reduced[PRIME_LIMBS];
    uint64_t one[PRIME_LIMBS] = {1};
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    rsa_mont64_modulus_init(&mod_p, key.p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&mod_q, key.q, half_len, 8 * half_len);
    rsa_mont64_from_bytes(qinv, limbs, key.qinv, half_len);
    rsa_mont64_mont_mul(m2, one, m2, &mod_q);
    if (residue_holds("qinv", qinv, limbs) || residue_holds("the plain half modulo q", m2, limbs)) {
        return 1;
    }
    rsa_mont64_reduce_once(reduced, m2, &mod_p);
    rsa_mont64_mont_mul(reduced, reduced, mod_p.r2, &mod_p);
    rsa_mont64_sub(m1, m1, reduced, &mod_p);
    if (residue_holds("the difference of the halves", m1, limbs)) {
        return 1;
    }
    rsa_mont64_mont_mul(reduced, qinv, m1, &mod_p);
    rsa_mont64_mul_add(s, mod_q.m, reduced, m2, limbs);
    rsa_mont64_to_bytes(candidate, key.n_len, s);
    return residue_holds("the factor that joins the halves", reduced, limbs);
}

// Looks for the encoded message, as the limbs the signer reads it into
// and the check's public operation ends on when the check passes, and as
// the bytes the check compares. Returns 1 when it found either.
static int residue_of_message(void) {
    uint64_t em[RSA_MONT64_LIMBS_MAX];
    rsa_mont64_from_bytes(em, key.n_len / 8, residue_em, key.n_len);
    return residue_holds("the encoded message", em, key.n_len / 8) ||
           residue_holds_bytes("the encoded message's bytes", residue_em, key.n_len);
}

// Looks for a candidate that failed its check: its limbs, its bytes, and
// the power the check raised it to, as bytes and as limbs. Returns 1 when
// it found any.
static int residue_of_refused(const uint64_t *s, const uint8_t *candidate) {
    size_t limbs = (key.n_len / 2 + 7) / 8;
    rsa_mont64_modulus mod;
    uint8_t power[CH_RSA_MODULUS_MAX];
    uint64_t power_limbs[RSA_MONT64_LIMBS_MAX];
    rsa_mont64_modulus_init(&mod, key.n, key.n_len, 8 * key.n_len);
    rsa_mont64_public(power, candidate, key.n_len, &mod);
    rsa_mont64_from_bytes(power_limbs, key.n_len / 8, power, key.n_len);
    return residue_holds("the candidate that failed its check", s, 2 * limbs) ||
           residue_holds_bytes("the bytes of the candidate that failed", candidate, key.n_len) ||
           residue_holds_bytes("the bytes of the failed candidate's power", power, key.n_len) ||
           residue_holds("the failed candidate's power", power_limbs, key.n_len / 8);
}

// One signature under the vector key, or under that key with the lowest
// bit of dp changed when fault is 1, which makes the half modulo p wrong
// and the check refuse the candidate.
static void run_residue(const test_rsa_sign_key *from, int fault) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    test_rsa_sign_key_load(&key, from);
    key.dp[key.n_len / 2 - 1] ^= (uint8_t)fault;
    random_message(residue_em);
    residue_callee = fault ? "a refused rsa_sign64_sp1" : "rsa_sign64_sp1";
    residue_snapshot();
    residue_sign();
    residue_snapshot();
    if (residue_signed == fault) {
        failures++;
        (void)fprintf(stderr, "FAIL residue: %s\n",
                      fault ? "the 64-bit signer signed under a key with a wrong dp"
                            : "the 64-bit signer refused its own signature");
        return;
    }

    uint64_t m1[PRIME_LIMBS];
    uint64_t m2[PRIME_LIMBS];
    uint64_t s[2 * PRIME_LIMBS];
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    if (residue_of_prime("p", key.p, key.dp, m1) || residue_of_prime("q", key.q, key.dq, m2) ||
        residue_of_recombination(m1, m2, s, candidate) || residue_of_message()) {
        return;
    }
    // The values above are this file's own arithmetic. It is the
    // signer's when the candidate it ends on is the signature the signer
    // wrote, and only then are the values the ones the call held.
    if (!fault && memcmp(candidate, residue_sig, key.n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL residue: the values looked for are not the signer's\n");
        return;
    }
    if (fault && residue_of_refused(s, candidate)) {
        return;
    }
    compared++;
}

// The key test under the vector key, or under that key with one bit of q
// changed when fault is 1, which the test refuses.
static void run_key_test_residue(const test_rsa_sign_key *from, int fault) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    size_t half_len = from->n_len / 2;
    size_t limbs = (half_len + 7) / 8;
    test_rsa_sign_key_load(&key, from);
    key.q[half_len - 1] ^= (uint8_t)(2 * fault);
    residue_callee = fault ? "a refusing rsa_sign64_key_ok" : "rsa_sign64_key_ok";
    residue_snapshot();
    residue_key_test();
    residue_snapshot();
    if (residue_admitted == fault) {
        failures++;
        (void)fprintf(stderr, "FAIL residue: the key test %s\n",
                      fault ? "admitted primes that do not multiply to the modulus"
                            : "refused a vector key");
        return;
    }

    uint64_t p[PRIME_LIMBS];
    uint64_t q[PRIME_LIMBS];
    uint64_t zero[PRIME_LIMBS] = {0};
    uint64_t product[2 * PRIME_LIMBS];
    rsa_mont64_from_bytes(p, limbs, key.p, half_len);
    rsa_mont64_from_bytes(q, limbs, key.q, half_len);
    rsa_mont64_mul_add(product, p, q, zero, limbs);
    if (residue_holds("the prime p", p, limbs) || residue_holds("the prime q", q, limbs)) {
        return;
    }
    // The changed bit is the second lowest of q, so the product is the
    // modulus and twice p, more or less: it differs from the modulus in
    // its low limbs, and its limbs above those are the modulus's, which
    // the key test has no reason to wipe. So the search ends at the last
    // limb that differs.
    uint64_t n[2 * PRIME_LIMBS];
    size_t differing = 0;
    rsa_mont64_from_bytes(n, 2 * limbs, key.n, key.n_len);
    for (size_t i = 0; i < 2 * limbs; i++) {
        if (product[i] != n[i]) {
            differing = i + 1;
        }
    }
    if (fault && residue_holds("the product of the primes", product, differing)) {
        return;
    }
    compared++;
}

// What a piece's call reads and writes. They are static, so the stack
// holds none of them when the call starts.
static rsa_mont64_modulus piece_mod_p;
static rsa_mont64_modulus piece_mod_q;
static uint64_t piece_em[RSA_MONT64_LIMBS_MAX];
static uint64_t piece_m1[PRIME_LIMBS];
static uint64_t piece_m2[PRIME_LIMBS];
static uint64_t piece_s[2 * PRIME_LIMBS];

static __attribute__((noinline)) void residue_reduction(void) {
    rsa_sign_equiv_reduction(piece_m1, piece_em, key.n_len / 8, &piece_mod_p);
}

static __attribute__((noinline)) void residue_power(void) {
    rsa_sign64_power(piece_m1, piece_m1, key.dp, key.n_len / 2, &piece_mod_p);
}

static __attribute__((noinline)) void residue_recombination(void) {
    rsa_sign_equiv_recombination(piece_s, piece_m1, piece_m2, key.qinv, key.n_len / 2, &piece_mod_p,
                                 &piece_mod_q);
}

// Whether a piece wrote what this file's own arithmetic gives, which is
// what makes the values a run looked for the ones the piece held.
static int piece_wrote(const char *piece, const uint64_t *got, const uint64_t *want, size_t limbs) {
    if (memcmp(got, want, limbs * sizeof(uint64_t)) == 0) {
        return 1;
    }
    failures++;
    (void)fprintf(stderr, "FAIL residue: the values looked for are not %s's\n", piece);
    return 0;
}

// The reduction modulo p, the exponentiation modulo p and the
// recombination under the vector key, each called on its own.
static void run_pieces_residue(const test_rsa_sign_key *from) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    size_t half_len = from->n_len / 2;
    size_t limbs = (half_len + 7) / 8;
    test_rsa_sign_key_load(&key, from);
    random_message(residue_em);
    rsa_mont64_modulus_init(&piece_mod_p, key.p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&piece_mod_q, key.q, half_len, 8 * half_len);
    rsa_mont64_from_bytes(piece_em, key.n_len / 8, residue_em, key.n_len);

    uint64_t base[PRIME_LIMBS];
    residue_callee = "the reduction modulo a prime";
    residue_snapshot();
    residue_reduction();
    residue_snapshot();
    if (residue_of_base("p", base, &piece_mod_p) ||
        !piece_wrote("the reduction", piece_m1, base, limbs)) {
        return;
    }

    residue_callee = "rsa_sign64_power";
    residue_snapshot();
    residue_power();
    residue_snapshot();
    if (residue_of_table("p", base, &piece_mod_p) || residue_holds("the power", piece_m1, limbs)) {
        return;
    }

    // The half modulo q, by the same two calls, and a copy of each half
    // for this file's own recombination, which writes over them.
    uint64_t m1[PRIME_LIMBS];
    uint64_t m2[PRIME_LIMBS];
    uint64_t s[2 * PRIME_LIMBS];
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    rsa_sign_equiv_reduction(piece_m2, piece_em, key.n_len / 8, &piece_mod_q);
    rsa_sign64_power(piece_m2, piece_m2, key.dq, half_len, &piece_mod_q);
    memcpy(m1, piece_m1, sizeof m1);
    memcpy(m2, piece_m2, sizeof m2);
    residue_callee = "the recombination";
    residue_snapshot();
    residue_recombination();
    residue_snapshot();
    if (residue_of_recombination(m1, m2, s, candidate) ||
        !piece_wrote("the recombination", piece_s, s, 2 * limbs)) {
        return;
    }
    compared++;
}

#endif
