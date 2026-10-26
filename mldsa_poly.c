// The polynomial layer of ML-DSA-87 verification: the NTT and its
// inverse, the products in the NTT domain, the unpacking of t1 and z, the
// hints, and the two samplers (FIPS 204 sections 7.1 to 7.6). The zetas in
// mldsa_zetas.h are FIPS 204's twiddle factors in the Montgomery domain,
// so a product with one leaves no 2^-32 factor. Every input is public.
#include "mldsa_poly.h"

#include "mldsa_zetas.h"
#include "sha3.h"

static void mld_poly_reduce(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = mld_reduce32(p->coeffs[i]);
    }
}

// Cooley-Tukey, eight layers, the span halving from 128 to 1. The inputs
// are under 6291200 after the reduction, and each layer adds a product
// under q, so the output is under 6291200 + 8q, below 2^27.
void mld_poly_ntt(mld_poly *p) {
    int32_t *w = p->coeffs;
    mld_poly_reduce(p);
    unsigned m = 0;
    for (unsigned len = 128; len >= 1; len >>= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m++;
            int32_t zeta = MLD_ZETAS[m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = mld_mul_zeta(zeta, w[j + len]);
                w[j + len] = w[j] - t;
                w[j] = w[j] + t;
            }
        }
    }
}

// Gentleman-Sande, eight layers, the span doubling from 1 to 256, with
// FIPS 204's negated twiddles. The inputs are under 6291200 after the
// reduction. A sum doubles its bound each layer, so after eight it is
// under 256 * 6291200, below 2^31. A difference is multiplied by a twiddle,
// and so is under q. The last pass multiplies by 41978 = 2^64 / 256 mod q:
// the 1/256 of eight layers, and 2^32 more than the product's 2^-32 takes.
void mld_poly_invntt_tomont(mld_poly *p) {
    int32_t *w = p->coeffs;
    mld_poly_reduce(p);
    unsigned m = MLD_N;
    for (unsigned len = 1; len < MLD_N; len <<= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m--;
            int32_t zeta = -MLD_ZETAS[m];
            for (unsigned j = start; j < start + len; j++) {
                int32_t t = w[j];
                w[j] = t + w[j + len];
                w[j + len] = mld_mul_zeta(zeta, t - w[j + len]);
            }
        }
    }
    for (unsigned j = 0; j < MLD_N; j++) {
        w[j] = mld_mul_zeta(41978, w[j]);
    }
}

void mld_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        r->coeffs[i] = mld_mul_reduced(a->coeffs[i], b->coeffs[i]);
    }
}

// The reduced sum is under 6291200 + q, below 2^24.
void mld_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        int32_t product = mld_mul_reduced(a->coeffs[i], b->coeffs[i]);
        acc->coeffs[i] = mld_reduce32(acc->coeffs[i]) + product;
    }
}

void mld_poly_sub(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i++) {
        int32_t subtrahend = mld_reduce32(b->coeffs[i]);
        r->coeffs[i] = mld_reduce32(a->coeffs[i]) - subtrahend;
    }
}

// Four 10-bit coefficients from each five bytes, the low bits first.
void mld_poly_unpack_t1_shifted(mld_poly *p, const uint8_t in[MLD_T1_BYTES]) {
    for (size_t i = 0; i < MLD_N / 4; i++) {
        const uint8_t *b = in + 5 * i;
        uint32_t c0 = ((uint32_t)b[0] | (uint32_t)b[1] << 8) & 0x3ffU;
        uint32_t c1 = ((uint32_t)b[1] >> 2 | (uint32_t)b[2] << 6) & 0x3ffU;
        uint32_t c2 = ((uint32_t)b[2] >> 4 | (uint32_t)b[3] << 4) & 0x3ffU;
        uint32_t c3 = ((uint32_t)b[3] >> 6 | (uint32_t)b[4] << 2) & 0x3ffU;
        p->coeffs[4 * i] = (int32_t)(c0 << MLD_D);
        p->coeffs[4 * i + 1] = (int32_t)(c1 << MLD_D);
        p->coeffs[4 * i + 2] = (int32_t)(c2 << MLD_D);
        p->coeffs[4 * i + 3] = (int32_t)(c3 << MLD_D);
    }
}

// Two 20-bit values from each five bytes, the low bits first. Each
// coefficient is gamma1 minus its value, in -2^19 + 1 .. 2^19.
int mld_poly_unpack_z(mld_poly *p, const uint8_t in[MLD_Z_BYTES]) {
    const int32_t bound = MLD_GAMMA1 - MLD_BETA;
    int under = 1;
    for (size_t i = 0; i < MLD_N / 2; i++) {
        const uint8_t *b = in + 5 * i;
        uint32_t v0 = ((uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16) & 0xfffffU;
        uint32_t v1 = ((uint32_t)b[2] >> 4 | (uint32_t)b[3] << 4 | (uint32_t)b[4] << 12) & 0xfffffU;
        int32_t z0 = MLD_GAMMA1 - (int32_t)v0;
        int32_t z1 = MLD_GAMMA1 - (int32_t)v1;
        p->coeffs[2 * i] = z0;
        p->coeffs[2 * i + 1] = z1;
        if (z0 >= bound || z0 <= -bound || z1 >= bound || z1 <= -bound) {
            under = 0;
        }
    }
    return under;
}

// The hint of coefficient c is 1 when the next position in the list is c.
// The list's positions increase, so one pass over the coefficients reads
// it whole. A list out of order leaves its later positions unread, and
// mldsa.c refuses such a list before it calls this.
void mld_poly_use_hint(uint8_t out[MLD_W1_BYTES], const mld_poly *w, const uint8_t *hints,
                       size_t hint_count) {
    size_t next = 0;
    for (unsigned i = 0; i < MLD_W1_BYTES; i++) {
        uint32_t nibble[2];
        for (unsigned half = 0; half < 2; half++) {
            unsigned c = 2 * i + half;
            uint32_t hint = 0;
            if (next < hint_count && hints[next] == c) {
                hint = 1;
                next++;
            }
            nibble[half] = mld_use_hint_coefficient(w->coeffs[c], hint);
        }
        out[i] = (uint8_t)(nibble[0] | nibble[1] << 4);
    }
}

unsigned mld_sample_groups(mld_poly *p, unsigned j, const uint8_t *buf, size_t groups) {
    for (size_t group = 0; group < groups && j < MLD_N; group++) {
        const uint8_t *b = buf + 3 * group;
        uint32_t candidate = (uint32_t)b[0] | (uint32_t)b[1] << 8 | ((uint32_t)b[2] & 0x7fU) << 16;
        if (candidate < MLD_Q) {
            p->coeffs[j] = (int32_t)candidate;
            j++;
        }
    }
    return j;
}

int mld_sample_ntt(mld_poly *p, const uint8_t rho[MLD_RHO_BYTES], uint8_t s, uint8_t r) {
    const uint8_t index[2] = {s, r};
    uint8_t block[SHAKE128_RATE];
    shake xof;
    shake128_init(&xof);
    shake_absorb(&xof, rho, MLD_RHO_BYTES);
    shake_absorb(&xof, index, sizeof index);
    unsigned j = 0;
    for (unsigned n = 0; n < MLD_SAMPLE_BLOCKS && j < MLD_N; n++) {
        shake_squeeze(&xof, block, sizeof block);
        j = mld_sample_groups(p, j, block, MLD_SAMPLE_BLOCK_GROUPS);
    }
    return j == MLD_N;
}

// The first 8 bytes give 64 sign bits, the low bit first, and the sampler
// uses the first tau. Each later byte is a position j, kept when j <= i.
// Then c[i] takes c[j], and c[j] takes the next sign.
int mld_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]) {
    uint8_t stream[MLD_BALL_BYTES];
    shake xof;
    shake256_init(&xof);
    shake_absorb(&xof, c_tilde, 64);
    shake_squeeze(&xof, stream, sizeof stream);
    uint64_t signs = 0;
    for (unsigned b = 0; b < 8; b++) {
        signs |= (uint64_t)stream[b] << (8 * b);
    }
    for (unsigned n = 0; n < MLD_N; n++) {
        c->coeffs[n] = 0;
    }
    unsigned i = MLD_N - MLD_TAU;
    for (unsigned at = 8; at < MLD_BALL_BYTES && i < MLD_N; at++) {
        unsigned j = stream[at];
        if (j > i) {
            continue;
        }
        c->coeffs[i] = c->coeffs[j];
        c->coeffs[j] = 1 - 2 * (int32_t)(signs & 1U);
        signs >>= 1;
        i++;
    }
    return i == MLD_N;
}
