// The encodings, the roundings and the samplers of ML-DSA-87 signing.
// Contract in mldsa_sign_pack.h.
#include "mldsa_sign_pack.h"

#include "ct.h"
#include "sha3.h"

void mlds_pack(uint8_t *out, const mld_poly *p, unsigned bits, int32_t offset) {
    uint32_t value_mask = (1U << bits) - 1U;
    uint32_t acc = 0;
    unsigned have = 0;
    size_t at = 0;
    for (unsigned i = 0; i < MLD_N; i++) {
        uint32_t value = (uint32_t)p->coeffs[i];
        if (offset != 0) {
            value = (uint32_t)offset - value;
        }
        acc |= (value & value_mask) << have;
        have += bits;
        while (have >= 8) {
            out[at++] = (uint8_t)acc;
            acc >>= 8;
            have -= 8;
        }
    }
}

void mlds_unpack(mld_poly *p, const uint8_t *in, unsigned bits, int32_t offset) {
    uint32_t value_mask = (1U << bits) - 1U;
    uint32_t acc = 0;
    unsigned have = 0;
    size_t at = 0;
    for (unsigned i = 0; i < MLD_N; i++) {
        while (have < bits) {
            acc |= (uint32_t)in[at++] << have;
            have += 8;
        }
        p->coeffs[i] = offset - (int32_t)(acc & value_mask);
        acc >>= bits;
        have -= bits;
    }
}

// A 3-bit value v gives eta - v, and a v over 2 * eta sets the high bit of
// 2 * eta - v.
uint32_t mlds_unpack_eta(mld_poly *p, const uint8_t in[MLDS_ETA_BYTES]) {
    mlds_unpack(p, in, 3, MLDS_ETA);
    uint32_t over = 0;
    for (unsigned i = 0; i < MLD_N; i++) {
        over |= (uint32_t)(MLDS_ETA + p->coeffs[i]) >> 31;
    }
    return over ^ 1U;
}

// Writes v to every coefficient of p at position at when keep is all ones,
// and leaves p as it was when keep is 0. Every coefficient is read and
// written, so the addresses do not show at.
static void store_at(mld_poly *p, uint32_t at, int32_t v, uint32_t keep) {
    for (uint32_t n = 0; n < MLD_N; n++) {
        uint32_t m = mlds_mask_eq(n, at) & keep;
        p->coeffs[n] = (int32_t)mlds_select(m, (uint32_t)p->coeffs[n], (uint32_t)v);
    }
}

// The coefficient at position at, read by mask over every coefficient.
static int32_t load_at(const mld_poly *p, uint32_t at) {
    uint32_t v = 0;
    for (uint32_t n = 0; n < MLD_N; n++) {
        v |= mlds_mask_eq(n, at) & (uint32_t)p->coeffs[n];
    }
    return (int32_t)v;
}

// The half-bytes RejBoundedPoly reads, and the passes that move each kept one
// to its position: a kept half-byte moves down by the count of rejected ones
// before it, under 2^MLDS_ETA_PASSES.
#define MLDS_ETA_HALVES (2U * MLDS_ETA_STREAM_BYTES)
#define MLDS_ETA_PASSES 10U
_Static_assert(MLDS_ETA_HALVES <= (1U << MLDS_ETA_PASSES), "every move fits the passes");

// The form of the passes. MLDS_ETA_PADDED is 1 in a host object and 0 in a
// device object; a harness may set it. In the padded form a pass writes
// MLDS_ETA_SPAN positions, MLDS_ETA_HALVES rounded up to a multiple of 16,
// and its first loop ends at a multiple of 16, so the counts of both loops
// are multiples of 16. The array then holds MLDS_ETA_ROOM entries, and those
// from MLDS_ETA_HALVES up stay 0, so a read past the entries reads 0 and
// stays in the array. gcc 13 at -O2 makes vector code only of a loop of such
// a count, with a step it knows: it left the loops of decision 176's form in
// scalar code, and they took 65% of a key generation on an x86-64 host
// (docs/decisions.md 200). The device form is decision 176's: its array
// holds the entries alone, and no pass reads past them.
#ifndef MLDS_ETA_PADDED
#ifdef CH_CPU_RUNTIME
#define MLDS_ETA_PADDED 1
#else
#define MLDS_ETA_PADDED 0
#endif
#endif
#if MLDS_ETA_PADDED
#define MLDS_ETA_SPAN 976U
#define MLDS_ETA_ROOM (MLDS_ETA_SPAN + 16U)
// The end of the positions the first loop of the pass of step s writes, plus
// s: the first multiple of 16 at or above MLDS_ETA_HALVES - s, plus s.
#define MLDS_ETA_READ_END(s) ((((MLDS_ETA_HALVES - (s)) + 15U) & ~15U) + (s))
_Static_assert(MLDS_ETA_SPAN % 16U == 0 && MLDS_ETA_SPAN >= MLDS_ETA_HALVES &&
                   MLDS_ETA_SPAN - MLDS_ETA_HALVES < 16U,
               "the span is the halves rounded up to a multiple of 16");
_Static_assert(MLDS_ETA_HALVES + 15U <= MLDS_ETA_ROOM, "every read stays in the array");
#else
#define MLDS_ETA_SPAN MLDS_ETA_HALVES
#define MLDS_ETA_ROOM MLDS_ETA_HALVES
#define MLDS_ETA_READ_END(s) MLDS_ETA_HALVES
#endif

// An entry: bits 0 to 2 hold the value plus eta, bit 3 is 1 for a kept
// half-byte, and bits 4 up hold its move. An entry of 0 holds nothing.
#define MLDS_ETA_KEPT 8U
#define MLDS_ETA_MOVE_AT 4U

// FIPS 204 Algorithm 15, CoeffFromHalfByte, at eta = 2: a half-byte z under
// 15 gives 2 - (z mod 5). For z in 0..15, (z * 205) >> 10 is z / 5 rounded
// down. Returns z's entry, and adds 1 to *rejected when z is 15.
static uint16_t eta_entry(uint32_t z, uint32_t *rejected) {
    uint32_t keep = (uint32_t)((int32_t)(z - 15U) >> 31);
    uint32_t value = (uint32_t)MLDS_ETA - (z - 5U * ((z * 205U) >> 10)) + (uint32_t)MLDS_ETA;
    uint32_t entry = (value | MLDS_ETA_KEPT | (*rejected << MLDS_ETA_MOVE_AT)) & keep;
    *rejected += keep + 1U;
    return (uint16_t)entry;
}

// The entry at a position after the pass, from the entry there and the one
// 2^bit above it. one is 1, read from a volatile object, so the compiler
// cannot know that a masked bit is 0 or 1. clang for Cortex-M3 wrote 0 minus
// a bit it could see as a predicated instruction on that bit
// (docs/decisions.md 125).
static uint16_t eta_choose(uint32_t one, uint32_t here, uint32_t above, unsigned bit) {
    unsigned at = MLDS_ETA_MOVE_AT + bit;
    uint32_t moves = 0U - ((above >> at) & (above >> 3) & one);
    uint32_t stays = 0U - (((here >> at) ^ one) & (here >> 3) & one);
    return (uint16_t)((above & moves) | (here & stays));
}

// One pass: every kept entry whose move holds bit `bit` goes down by 2^bit,
// and every other kept entry stays. Each move is the count of rejected
// entries before its entry, so no two kept entries meet at one position
// (docs/decisions.md 176). Each position is written from a mask, and the
// loops run in increasing order, so a read at p + step sees the entry before
// this pass. Once p + step reaches MLDS_ETA_READ_END(step), it is
// MLDS_ETA_HALVES or more, where no entry is kept, so the entry above is 0.
static inline void eta_pass(uint16_t entries[MLDS_ETA_ROOM], unsigned bit) {
    volatile uint32_t opaque = 1;
    uint32_t one = opaque;
    uint32_t step = 1U << bit;
    uint32_t p = 0;
    for (; p + step < MLDS_ETA_READ_END(step); p++) {
        entries[p] = eta_choose(one, entries[p], entries[p + step], bit);
    }
    for (; p < MLDS_ETA_SPAN; p++) {
        entries[p] = eta_choose(one, entries[p], 0U, bit);
    }
}

uint32_t mlds_eta_from_stream(mld_poly *p, const uint8_t stream[MLDS_ETA_STREAM_BYTES]) {
    uint16_t entries[MLDS_ETA_ROOM];
    uint32_t rejected = 0;
    for (size_t at = 0; at < MLDS_ETA_STREAM_BYTES; at++) {
        entries[2 * at] = eta_entry(stream[at] & 15U, &rejected);
        entries[2 * at + 1] = eta_entry((uint32_t)stream[at] >> 4, &rejected);
    }
    for (uint32_t at = MLDS_ETA_HALVES; at < MLDS_ETA_ROOM; at++) {
        entries[at] = 0;
    }
    // The padded form writes the ten passes out, so each pass's step is a
    // constant. gcc 13 makes no vector code of a pass whose step it does
    // not know. A device object keeps the loop.
#if MLDS_ETA_PADDED
#pragma GCC unroll 10
#endif
    for (unsigned bit = 0; bit < MLDS_ETA_PASSES; bit++) {
        eta_pass(entries, bit);
    }
    for (unsigned n = 0; n < MLD_N; n++) {
        p->coeffs[n] = (int32_t)(entries[n] & 7U) - MLDS_ETA;
    }
    ct_wipe(entries, sizeof entries);
    uint32_t kept = MLDS_ETA_HALVES - rejected;
    return ((MLD_N - 1U - kept) >> 31) & 1U;
}

uint32_t mlds_sample_eta(uint32_t cpu, mld_poly *p, const uint8_t rho_prime[64], uint16_t nonce) {
    const uint8_t index[2] = {(uint8_t)nonce, (uint8_t)(nonce >> 8)};
    uint8_t stream[MLDS_ETA_STREAM_BYTES];
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, rho_prime, 64);
    mld_absorb(cpu, &h, index, sizeof index);
    mld_squeeze(cpu, &h, stream, sizeof stream);
    ct_wipe(&h, sizeof h);
    uint32_t ok = mlds_eta_from_stream(p, stream);
    ct_wipe(stream, sizeof stream);
    return ok;
}

void mlds_expand_mask(uint32_t cpu, mld_poly *p, const uint8_t rho2[64], uint16_t nonce) {
    const uint8_t index[2] = {(uint8_t)nonce, (uint8_t)(nonce >> 8)};
    uint8_t stream[MLDS_MASK_BYTES];
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, rho2, 64);
    mld_absorb(cpu, &h, index, sizeof index);
    mld_squeeze(cpu, &h, stream, sizeof stream);
    ct_wipe(&h, sizeof h);
    mlds_unpack(p, stream, 20, MLD_GAMMA1);
    ct_wipe(stream, sizeof stream);
}

// The 64 sign bits, held as two words so that each step shifts by a
// constant and chooses the shifted pair by mask.
typedef struct {
    uint32_t low;
    uint32_t high;
} sign_bits;

// One step of SampleInBall's loop: position j from the stream, taken when
// active, which is j <= i while i is under 256. Then c[i] takes c[j], and
// c[j] takes the next sign: +1 for a 0 bit and -1 for a 1 bit. j's write
// comes after i's, so j = i leaves the sign there, as in FIPS 204.
static void ball_step(mld_poly *c, uint32_t *i, uint32_t j, sign_bits *signs) {
    uint32_t active = 0U - (((*i - MLD_N) >> 31) & (((*i - j) >> 31) ^ 1U));
    int32_t moved = load_at(c, j);
    int32_t sign = 1 - 2 * (int32_t)(signs->low & 1U);
    store_at(c, *i, moved, active);
    store_at(c, j, sign, active);
    uint32_t low = (signs->low >> 1) | (signs->high << 31);
    signs->low = mlds_select(active, signs->low, low);
    signs->high = mlds_select(active, signs->high, signs->high >> 1);
    *i += active & 1U;
}

uint32_t mlds_sample_in_ball(uint32_t cpu, mld_poly *c, const uint8_t c_tilde[64]) {
    uint8_t stream[MLD_BALL_BYTES];
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, c_tilde, 64);
    mld_squeeze(cpu, &h, stream, sizeof stream);
    ct_wipe(&h, sizeof h);
    sign_bits signs = {0, 0};
    for (unsigned b = 0; b < 4; b++) {
        signs.low |= (uint32_t)stream[b] << (8 * b);
        signs.high |= (uint32_t)stream[b + 4] << (8 * b);
    }
    for (unsigned n = 0; n < MLD_N; n++) {
        c->coeffs[n] = 0;
    }
    uint32_t i = MLD_N - MLD_TAU;
    for (size_t at = 8; at < sizeof stream; at++) {
        ball_step(c, &i, stream[at], &signs);
    }
    ct_wipe(stream, sizeof stream);
    ct_wipe(&signs, sizeof signs);
    return mlds_mask_eq(i, MLD_N) & 1U;
}
