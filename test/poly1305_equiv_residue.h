// What poly1305_vector_blocks leaves on the stack. The call computes r^2,
// r^3 and r^4, keeps them and the two multipliers built from them in one
// struct on its frame, and wipes that struct once when it returns. The
// frame is dead after the return, but its bytes stay in memory below this
// binary's own frames until another call writes over them.
//
// residue_call makes one call over RESIDUE_GROUPS groups, residue_snapshot
// copies the stack below its caller as deep as RESIDUE_BYTES, where the
// dead frame lay, and run_residue looks in the copy for r^2, r^3 and r^4
// in each layout the call holds a power in:
//
//   five uint32_t limbs side by side, as the struct holds each power;
//   one limb in every 8 bytes, as a NEON multiplier holds a lane's power;
//   one limb in every 16 bytes, as an SSE2 multiplier holds it.
//
// Five words match a power when each is below 2^27 and together they hold
// its value modulo 2^130 - 5, so a power in another carry form matches
// too. The powers are computed only after the copy, so this file's own
// frames cannot hold them first.
//
// Included by test/poly1305_equiv_test.c only, which declares the
// generator, reduced, report and the failure count this file uses.
#ifndef CH_POLY1305_EQUIV_RESIDUE_H
#define CH_POLY1305_EQUIV_RESIDUE_H

#define RESIDUE_GROUPS 4
#define RESIDUE_BYTES 4096

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_key[POLY1305_KEY];
static uint8_t residue_data[RESIDUE_GROUPS * POLY1305_VECTOR_GROUP];

static __attribute__((noinline)) void residue_call(void) {
    poly1305 p;
    poly1305_init(&p, residue_key);
    poly1305_vector_blocks(&p, residue_data, sizeof residue_data);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// out = a * b modulo 2^130 - 5, reduced, for limbs of at most 2^26.
static void residue_multiply(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
    uint64_t d[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 5; j++) {
            uint64_t product = (uint64_t)a[i] * b[j];
            // A product past limb 4 is past 2^130, which is 5 modulo
            // 2^130 - 5.
            if (i + j < 5) {
                d[i + j] += product;
            } else {
                d[i + j - 5] += 5 * product;
            }
        }
    }
    for (size_t i = 0; i < 4; i++) {
        d[i + 1] += d[i] >> 26;
        d[i] &= LIMB_MASK;
    }
    d[0] += (d[4] >> 26) * 5;
    d[4] &= LIMB_MASK;
    d[1] += d[0] >> 26;
    d[0] &= LIMB_MASK;
    uint32_t limbs[5];
    for (size_t i = 0; i < 5; i++) {
        limbs[i] = (uint32_t)d[i];
    }
    reduced(limbs, out);
}

// Whether the copy holds the power as five words stride bytes apart, at
// any byte offset.
static int residue_holds(const uint32_t power[5], size_t stride) {
    for (size_t at = 0; at + 4 * stride + 4 <= RESIDUE_BYTES; at++) {
        uint32_t limbs[5];
        int below_2_27 = 1;
        for (size_t i = 0; i < 5; i++) {
            memcpy(&limbs[i], &residue_copy[at + i * stride], sizeof limbs[i]);
            below_2_27 &= limbs[i] < (UINT32_C(1) << 27);
        }
        uint32_t value[5];
        reduced(limbs, value);
        if (below_2_27 && memcmp(value, power, sizeof value) == 0) {
            return 1;
        }
    }
    return 0;
}

static void run_residue(void) {
    rng_fill(residue_key, sizeof residue_key);
    rng_fill(residue_data, sizeof residue_data);
    residue_call();
    residue_snapshot();
    poly1305 p;
    poly1305_init(&p, residue_key);
    uint32_t power[3][5];
    residue_multiply(p.r, p.r, power[0]);
    residue_multiply(power[0], p.r, power[1]);
    residue_multiply(power[0], power[0], power[2]);
    static const size_t strides[3] = {4, 8, 16};
    for (size_t k = 0; k < 3; k++) {
        for (size_t s = 0; s < 3; s++) {
            if (residue_holds(power[k], strides[s])) {
                char what[96];
                (void)snprintf(
                    what, sizeof what,
                    "the stack below the call still holds r^%zu, one limb every %zu bytes", k + 2,
                    strides[s]);
                report("residue", what, sizeof residue_data, 0, 0);
                return;
            }
        }
    }
}

#endif
