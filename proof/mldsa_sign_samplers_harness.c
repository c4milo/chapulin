// Proves: the steps of mldsa_sign_pack.c's two masked samplers are
// memory-safe and UB-free with the signed-overflow check on, and each
// matches its model:
//  - eta_entry, RejBoundedPoly's entry, for every half-byte z and every
//    count of 15s from 0 to 961: a z under 15 gives an entry that holds
//    2 - (z mod 5) plus 2, the kept bit and the count, and leaves the
//    count; a 15 gives 0 and adds 1 to the count. That is
//    Spec.MlDsaEta.start (spec/lean/Spec/MlDsaEta.lean).
//  - eta_choose, for every two entries eta_entry can write or 0, and every
//    bit from 0 to 9: the entry above when its move has the bit, else the
//    entry here when its move does not, else 0, whenever the two are not
//    both chosen. That is Spec.MlDsaEta.choose, and pass_never_both proves
//    the two are never both chosen in a run, where the C's OR of two
//    masked entries would differ from the model.
//  - the ten passes of eta_pass in order, bits 0 to 9, as
//    mlds_eta_from_stream runs them, over every array of 962 entries, and
//    in mldsa_sign_samplers_padded over the padded form's 962 entries and 30
//    zero entries (docs/decisions.md 200): every read and write stays in
//    the array. A pass whose bit is nondeterministic makes every index
//    symbolic, and cbmc passed 14.5 GB after 46 minutes on that formula
//    (docs/decisions.md 176).
//  - ball_step, for every position j from the stream, every i from 196
//    to 256 and every polynomial and sign word: i grows by at most 1 and
//    stays at most 256, and each coefficient is the one before, the one at
//    j, or +1 or -1.
// Spec.MlDsaEta.etaFromStream_eq proves that the passes over the entries
// give RejBoundedPoly's loop, and bin/diff_mldsa holds
// mlds_eta_from_stream to Spec.MlDsa.rejBoundedStream (docs/decisions.md
// 176). The loop that drives ball_step runs MLD_BALL_BYTES - 8 steps of a
// 256-position scan, and cbmc passed 7.8 GB in symbolic execution on a
// formula of it (docs/decisions.md 159). bin/mldsa_signer_test holds
// mlds_sample_in_ball to the verifier's sampler value for value.
#include "harness.h"

#include "mldsa_sign_pack.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned n = 0; n < MLD_N; n++) {
        p->coeffs[n] = nondet_i32();
    }
}

uint16_t nondet_u16(void);

static void eta_entry_step(void) {
    uint32_t z = nondet_u32() & 15U;
    uint32_t rejected = nondet_u32();
    __CPROVER_assume(rejected < MLDS_ETA_HALVES);
    uint32_t start = rejected;
    uint32_t entry = eta_entry(z, &rejected);
    if (z < 15) {
        __CPROVER_assert(rejected == start, "eta_entry: a kept half-byte leaves the count");
        __CPROVER_assert((entry & 7U) == 4U - z % 5U, "eta_entry: the value plus eta");
        __CPROVER_assert((entry & MLDS_ETA_KEPT) != 0, "eta_entry: the kept bit");
        __CPROVER_assert(entry >> MLDS_ETA_MOVE_AT == start, "eta_entry: the move is the count");
    } else {
        __CPROVER_assert(rejected == start + 1, "eta_entry: a 15 adds 1 to the count");
        __CPROVER_assert(entry == 0, "eta_entry: a 15 writes no entry");
    }
}

// An entry eta_entry can write: 0, or a value under 5, the kept bit and a
// move under 962.
static uint32_t nondet_entry(void) {
    uint32_t entry = nondet_u16();
    uint32_t kept = entry & MLDS_ETA_KEPT;
    __CPROVER_assume(entry == 0 || (kept != 0 && (entry & 7U) < 5U &&
                                    entry >> MLDS_ETA_MOVE_AT < MLDS_ETA_HALVES));
    return entry;
}

static void eta_choose_step(void) {
    uint32_t here = nondet_entry();
    uint32_t above = nondet_entry();
    unsigned bit = nondet_u32() % MLDS_ETA_PASSES;
    unsigned at = MLDS_ETA_MOVE_AT + bit;
    int moves = above != 0 && ((above >> at) & 1U) != 0;
    int stays = here != 0 && ((here >> at) & 1U) == 0;
    __CPROVER_assume(!(moves && stays));
    uint32_t got = eta_choose(1U, here, above, bit);
    uint32_t want = moves ? above : stays ? here : 0U;
    __CPROVER_assert(got == want, "eta_choose: Spec.MlDsaEta.choose");
}

static void eta_pass_step(void) {
    uint16_t entries[MLDS_ETA_ROOM] = {0};
    for (unsigned i = 0; i < MLDS_ETA_HALVES; i++) {
        entries[i] = nondet_u16();
    }
    for (unsigned bit = 0; bit < MLDS_ETA_PASSES; bit++) {
        eta_pass(entries, bit);
    }
}

static void ball(void) {
    mld_poly c;
    mld_poly before;
    havoc_poly(&c);
    before = c;
    uint32_t i = nondet_u32();
    __CPROVER_assume(i >= MLD_N - MLD_TAU && i <= MLD_N);
    uint32_t j = nondet_u8();
    sign_bits signs = {nondet_u32(), nondet_u32()};
    uint32_t start = i;
    ball_step(&c, &i, j, &signs);
    __CPROVER_assert(i <= MLD_N && i - start <= 1, "ball_step: i grows by at most 1");
    unsigned n = nondet_u32() % MLD_N;
    __CPROVER_assert(c.coeffs[n] == before.coeffs[n] || c.coeffs[n] == before.coeffs[j] ||
                         c.coeffs[n] == 1 || c.coeffs[n] == -1,
                     "ball_step: a coefficient is kept, moved, or a sign");
}

int main(void) {
    eta_entry_step();
    eta_choose_step();
    eta_pass_step();
    ball();
    return 0;
}
