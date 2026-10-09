// Whether the stack a call leaves depends on a secret, for
// bin/rsa_sign_equiv_test.
//
// Included by test/rsa_sign_equiv_test.c after
// test/rsa_sign_equiv_residue.h, whose key, messages, pieces and copy of
// the stack it uses.
//
// The runs of rsa_sign_equiv_residue.h look for values they can compute,
// two words side by side. A value shorter than a word they cannot look
// for, and a compiler can leave one: under clang for arm64 the first form
// of rsa_sign64.c's table read left the four bits of the exponent that the
// last step read, in a register the next multiplication saved in its
// frame (docs/decisions.md 95).
//
// A run here makes one call under two inputs that differ in a secret and
// in nothing a caller sees: the same lengths, the same public values and
// the same verdict. It copies the stack after each call and requires the
// two copies equal, byte for byte. A byte that differs is a value computed
// from the secret that the call left behind, of any length, in an array,
// in a slot the compiler picked or in a register a callee saved.
//
// Two copies are equal only when nothing else differs between the two
// calls, so:
//
//   - differential_step makes every call, so each returns to one address
//     and runs at one depth.
//   - Everything a run changes between its calls is static.
//     differential_step and differential_turns compute nothing that
//     depends on the turn, so the registers a callee saves hold the same
//     values at each call.
//   - The call runs once before the two that count, so what a first call
//     does once in a process is done before them.
//
// The runs, for each key:
//
//   - the exponentiation modulo p under dp and under dq;
//   - the exponentiation under dp of two bases;
//   - a signature under the key and under the key with its two primes
//     exchanged, which has the same modulus and the same signature, and
//     no integer of the Chinese remainder theorem where the key has it;
//   - a signature of two messages;
//   - a signature under two keys that each have one bit of dp and one of
//     dq changed, which the check refuses;
//   - the key test under the key and under the key with its primes
//     exchanged;
//   - the key test under two keys that each have one bit of q changed,
//     which it refuses;
//   - the reduction of one message modulo p and modulo q;
//   - the recombination under the key and under the key with its primes
//     exchanged.
//
// What a run cannot see is a register no callee saves: such a register
// holds what the last arithmetic left in it, and it is in no frame.
#ifndef CH_RSA_SIGN_EQUIV_DIFFERENTIAL_H
#define CH_RSA_SIGN_EQUIV_DIFFERENTIAL_H

// The bytes at the top of a copy that the comparison leaves out, because
// the call did not write them. residue_snapshot has a frame of 32 kB, and
// on Darwin a function with a frame over a page first calls the system's
// stack probe, which stores two registers in the 16 bytes under the stack
// pointer, where the top of the copied array then lies. No callee saves
// those two registers, so they hold what the last arithmetic left there:
// with these bytes compared, the run over the reduction differed in a
// carry of the reduction's last sum.
#define DIFFERENTIAL_PROBE_BYTES 16

// The run under way: what writes the statics its call reads for a turn,
// the call, and the verdict both of its calls must return, which
// differential_verdict points at. A call that returns nothing has no
// verdict.
static void (*differential_set)(void);
static void (*differential_call)(void);
static const int *differential_verdict;
static int differential_expect;
static int differential_verdicts_held;

// The stack after the second call of a run and after its third.
static uint8_t differential_copies[2][RESIDUE_BYTES];
// The turn a run is on: 0 for the call that does not count, then 1 and 2.
// It is volatile so that every use reads memory, and no register a callee
// saves holds a value computed from it at a call.
static volatile size_t differential_turn;

// What the runs of one key read: the vector key, that key with its primes
// exchanged, two messages, the records of p and of q, each message modulo
// p in p's domain, and the two halves of the first message's signature,
// each in its prime's domain.
static const test_rsa_sign_key *differential_from;
static ch_rsa_priv differential_exchanged;
static uint8_t differential_messages[2][CH_RSA_MODULUS_MAX];
static rsa_mont64_modulus differential_records[2];
static uint64_t differential_bases[2][PRIME_WORDS];
static uint64_t differential_halves[2][PRIME_WORDS];

// Whether the turn is the one that takes a run's second input.
static int differential_second(void) {
    return differential_turn == 2;
}

// Keeps the copy the turn took, and whether the call returned the verdict
// the run expects, and moves to the next turn. The first two turns write
// one copy, so the turn that does not count leaves nothing.
static __attribute__((noinline)) void differential_keep(void) {
    size_t turn = differential_turn;
    memcpy(differential_copies[turn / 2], residue_copy, RESIDUE_BYTES);
    if (differential_verdict != NULL && *differential_verdict != differential_expect) {
        differential_verdicts_held = 0;
    }
    differential_turn = turn + 1;
}

// One turn of a run: the statics for the turn, the call between two copies
// of the stack, and the second copy kept. The first copy writes zeros over
// what the lines before it left.
static __attribute__((noinline)) void differential_step(void) {
    differential_set();
    residue_snapshot();
    differential_call();
    residue_snapshot();
    differential_keep();
}

// The three turns of a run. It is three calls and no loop, so that no
// counter sits in a register across them, and it writes the turn after the
// last so that the compiler cannot make that call a jump, which would run
// it at another depth.
static __attribute__((noinline)) void differential_turns(void) {
    differential_step();
    differential_step();
    differential_step();
    differential_turn = 0;
}

// One run: call under what set writes in each turn, and one stack after
// both turns that count. what names the call and its two inputs in a
// finding.
static void differential_pair(const char *what, void (*set)(void), void (*call)(void),
                              const int *verdict, int expect) {
    differential_set = set;
    differential_call = call;
    differential_verdict = verdict;
    differential_expect = expect;
    differential_verdicts_held = 1;
    differential_turn = 0;
    differential_turns();
    if (!differential_verdicts_held) {
        failures++;
        (void)fprintf(stderr, "FAIL differential: %s: a call did not return %d\n", what, expect);
        return;
    }
    size_t differing = 0;
    size_t deepest = 0;
    for (size_t at = RESIDUE_BYTES - DIFFERENTIAL_PROBE_BYTES; at-- > 0;) {
        if (differential_copies[0][at] != differential_copies[1][at]) {
            deepest = at;
            differing++;
        }
    }
    if (differing != 0) {
        failures++;
        (void)fprintf(stderr,
                      "FAIL differential: the stack below %s differs in %zu byte(s), the deepest "
                      "%zu bytes down, %02x and %02x\n",
                      what, differing, RESIDUE_BYTES - deepest, differential_copies[0][deepest],
                      differential_copies[1][deepest]);
        return;
    }
    compared++;
}

// key = the vector key, or that key with its primes exchanged.
static void differential_load(int exchanged) {
    if (exchanged) {
        key = differential_exchanged;
    } else {
        test_rsa_sign_key_load(&key, differential_from);
    }
}

// The exponentiation's statics: the base, the record of p, and in key.dp
// the exponent, which residue_power reads there.
static void differential_power_inputs(size_t base, int exponent_dq) {
    size_t half_len = differential_from->n_len / 2;
    differential_load(0);
    if (exponent_dq) {
        memcpy(key.dp, key.dq, half_len);
    }
    piece_mod_p = differential_records[0];
    memcpy(piece_m1, differential_bases[base], sizeof piece_m1);
}

static void differential_set_exponents(void) {
    differential_power_inputs(0, differential_second());
}

static void differential_set_bases(void) {
    differential_power_inputs((size_t)differential_second(), 0);
}

static void differential_set_exchanged(void) {
    differential_load(differential_second());
    memcpy(residue_em, differential_messages[0], sizeof residue_em);
}

static void differential_set_messages(void) {
    differential_load(0);
    memcpy(residue_em, differential_messages[differential_second()], sizeof residue_em);
}

// A key with one bit of dp and one bit of dq changed, and no bit the same
// in the two turns.
static void differential_set_refused(void) {
    size_t last = differential_from->n_len / 2 - 1;
    differential_load(0);
    key.dp[last] ^= differential_second() ? 0x08 : 0x02;
    key.dq[last] ^= differential_second() ? 0x20 : 0x04;
    memcpy(residue_em, differential_messages[0], sizeof residue_em);
}

// A key with one bit of q changed, another in each turn. Neither is the
// lowest, so q stays odd.
static void differential_set_wrong_primes(void) {
    differential_load(0);
    key.q[differential_from->n_len / 2 - 1] ^= differential_second() ? 0x04 : 0x02;
}

// The reduction's statics: the first message's words, and the record of p
// or of q where the reduction reads p's.
static void differential_set_reduction(void) {
    differential_load(0);
    rsa_mont64_from_bytes(piece_em, differential_from->n_len / 8, differential_messages[0],
                          differential_from->n_len);
    piece_mod_p = differential_records[differential_second()];
}

// The recombination's statics: the two halves, the two records and the
// key, whose qinv it reads, each with the primes exchanged in the second
// turn. The recombination writes over both halves, so each turn sets them.
static void differential_set_recombination(void) {
    size_t second = (size_t)differential_second();
    differential_load((int)second);
    piece_mod_p = differential_records[second];
    piece_mod_q = differential_records[1 - second];
    memcpy(piece_m1, differential_halves[second], sizeof piece_m1);
    memcpy(piece_m2, differential_halves[1 - second], sizeof piece_m2);
}

// differential_exchanged = the key in key with p and q exchanged, dp and dq
// with them, and p^-1 mod q where the key has q^-1 mod p. q is prime, so
// that inverse is p^(q - 2) mod q, which rsa_sign64_power computes from p
// reduced modulo q. The loop subtracts 2 from q's bytes, and borrows from
// the bytes above the last one when that byte is 1.
static void differential_exchange(void) {
    size_t half_len = key.n_len / 2;
    size_t words = (half_len + 7) / 8;
    const rsa_mont64_modulus *mod_q = &differential_records[1];
    uint8_t exponent[CH_RSA_MODULUS_MAX / 2];
    uint64_t p[PRIME_WORDS];
    uint64_t one[PRIME_WORDS] = {1};
    memcpy(exponent, key.q, half_len);
    unsigned take = 2;
    for (size_t i = half_len; i-- > 0;) {
        unsigned byte = exponent[i];
        exponent[i] = (uint8_t)(byte - take);
        take = byte < take;
    }
    rsa_mont64_from_bytes(p, words, key.p, half_len);
    rsa_mont64_reduce_once(p, p, mod_q);
    rsa_mont64_mont_mul(p, p, mod_q->r2, mod_q);
    rsa_sign64_power(p, p, exponent, half_len, mod_q);
    rsa_mont64_mont_mul(p, one, p, mod_q);

    differential_exchanged = key;
    memcpy(differential_exchanged.p, key.q, half_len);
    memcpy(differential_exchanged.q, key.p, half_len);
    memcpy(differential_exchanged.dp, key.dq, half_len);
    memcpy(differential_exchanged.dq, key.dp, half_len);
    rsa_mont64_to_bytes(differential_exchanged.qinv, half_len, p);
}

// Writes what the runs of one key read. Returns 0 when the key with its
// primes exchanged does not sign the first message as the key does, which
// would make that key no input for a run.
static int differential_prepare(const test_rsa_sign_key *from) {
    size_t half_len = from->n_len / 2;
    size_t em_words = from->n_len / 8;
    uint8_t sig[CH_RSA_MODULUS_MAX];
    differential_from = from;
    test_rsa_sign_key_load(&key, from);
    rsa_mont64_modulus_init(&differential_records[0], key.p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&differential_records[1], key.q, half_len, 8 * half_len);
    // Each message modulo p. The second pass leaves the first message's
    // words in piece_em, which the half modulo q below reads.
    for (size_t i = 2; i-- > 0;) {
        random_message(differential_messages[i]);
        rsa_mont64_from_bytes(piece_em, em_words, differential_messages[i], from->n_len);
        rsa_sign_equiv_reduction(differential_bases[i], piece_em, em_words,
                                 &differential_records[0]);
    }
    rsa_sign64_power(differential_halves[0], differential_bases[0], key.dp, half_len,
                     &differential_records[0]);
    rsa_sign_equiv_reduction(differential_halves[1], piece_em, em_words, &differential_records[1]);
    rsa_sign64_power(differential_halves[1], differential_halves[1], key.dq, half_len,
                     &differential_records[1]);

    differential_exchange();
    int signed_both =
        rsa_sign64_sp1(equiv_cpu, &key, differential_messages[0], sig) &&
        rsa_sign64_sp1(equiv_cpu, &differential_exchanged, differential_messages[0], residue_sig);
    return signed_both && memcmp(sig, residue_sig, from->n_len) == 0;
}

static void run_differential(const test_rsa_sign_key *from) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    if (!differential_prepare(from)) {
        failures++;
        (void)fprintf(stderr, "FAIL differential: the key with its primes exchanged does not sign "
                              "as the key does\n");
        return;
    }
    differential_pair("rsa_sign64_power under two exponents", differential_set_exponents,
                      residue_power, NULL, 0);
    differential_pair("rsa_sign64_power of two bases", differential_set_bases, residue_power, NULL,
                      0);
    differential_pair("rsa_sign64_sp1 under a key and under it with its primes exchanged",
                      differential_set_exchanged, residue_sign, &residue_signed, 1);
    differential_pair("rsa_sign64_sp1 of two messages", differential_set_messages, residue_sign,
                      &residue_signed, 1);
    differential_pair("a refused rsa_sign64_sp1 under two wrong keys", differential_set_refused,
                      residue_sign, &residue_signed, 0);
    differential_pair("rsa_sign64_key_ok under a key and under it with its primes exchanged",
                      differential_set_exchanged, residue_key_test, &residue_admitted, 1);
    differential_pair("a refusing rsa_sign64_key_ok under two wrong keys",
                      differential_set_wrong_primes, residue_key_test, &residue_admitted, 0);
    differential_pair("the reduction modulo two primes", differential_set_reduction,
                      residue_reduction, NULL, 0);
    differential_pair("the recombination under a key and under it with its primes exchanged",
                      differential_set_recombination, residue_recombination, NULL, 0);
}

#endif
