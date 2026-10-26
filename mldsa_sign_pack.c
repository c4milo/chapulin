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

// FIPS 204 Algorithm 15, CoeffFromHalfByte, at eta = 2: a half-byte z under
// 15 gives 2 - (z mod 5). For z in 0..15, (z * 205) >> 10 is z / 5 rounded
// down. Writes the value at position *count when z is under 15 and p is not
// full, and counts it.
static void keep_half_byte(mld_poly *p, uint32_t *count, uint32_t z) {
    uint32_t keep = 0U - (((z - 15U) >> 31) & ((*count - MLD_N) >> 31));
    int32_t v = MLDS_ETA - (int32_t)(z - 5U * ((z * 205U) >> 10));
    store_at(p, *count, v, keep);
    *count += keep & 1U;
}

uint32_t mlds_sample_eta(mld_poly *p, const uint8_t rho_prime[64], uint16_t nonce) {
    const uint8_t index[2] = {(uint8_t)nonce, (uint8_t)(nonce >> 8)};
    uint8_t stream[MLDS_ETA_STREAM_BYTES];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, rho_prime, 64);
    shake_absorb(&h, index, sizeof index);
    shake_squeeze(&h, stream, sizeof stream);
    ct_wipe(&h, sizeof h);
    for (unsigned n = 0; n < MLD_N; n++) {
        p->coeffs[n] = 0;
    }
    uint32_t count = 0;
    for (size_t at = 0; at < sizeof stream; at++) {
        keep_half_byte(p, &count, stream[at] & 15U);
        keep_half_byte(p, &count, (uint32_t)stream[at] >> 4);
    }
    ct_wipe(stream, sizeof stream);
    return mlds_mask_eq(count, MLD_N) & 1U;
}

void mlds_expand_mask(mld_poly *p, const uint8_t rho2[64], uint16_t nonce) {
    const uint8_t index[2] = {(uint8_t)nonce, (uint8_t)(nonce >> 8)};
    uint8_t stream[MLDS_MASK_BYTES];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, rho2, 64);
    shake_absorb(&h, index, sizeof index);
    shake_squeeze(&h, stream, sizeof stream);
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

uint32_t mlds_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]) {
    uint8_t stream[MLD_BALL_BYTES];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, c_tilde, 64);
    shake_squeeze(&h, stream, sizeof stream);
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
