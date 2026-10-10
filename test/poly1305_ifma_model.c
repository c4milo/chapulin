// poly1305.c and poly1305_ifma.c compiled over the lane model,
// test/poly1305_ifma_model_lanes.h, under second names, so that any host
// runs the AVX-512 IFMA kernel's own text and one binary can hold it beside
// the instructions. CH_POLY1305_IFMA_MODEL makes poly1305_ifma.c include
// the model in place of poly1305_ifma_lanes.h and makes poly1305_ifma.h
// declare the kernel on any architecture, so poly1305.c's whole_blocks
// hands an IFMA update's whole groups to it. Only test units define it, and
// test/widemul-builds.sh refuses a library build that names it.
//
// The unit defines CH_CPU_RUNTIME, for ct.h's 64x64->128 multiply, which
// the model's two multiplications run on, and compiles no native copy:
// poly1305.c's loop runs on the 16x16 decomposition, and its vector paths
// stay out, as they need the native copy. A binary that links it passes
// neither define on its command line. The #defines rename every function
// the two files define outside the unit.
#define CH_CPU_RUNTIME
#define CH_POLY1305_IFMA_MODEL 1

#define poly1305_init poly1305_ifma_model_init
#define poly1305_update poly1305_ifma_model_update_loop
#define poly1305_final poly1305_ifma_model_final
#define poly1305_update_ifma poly1305_ifma_model_update
#define poly1305_ifma_blocks poly1305_ifma_model_blocks

#include "poly1305.c"

#include "poly1305_ifma.c"

#include "poly1305_ifma_model.h"

const size_t poly1305_ifma_model_group = POLY1305_IFMA_GROUP;
const size_t poly1305_ifma_model_min = POLY1305_IFMA_MIN;

// Digit i of every lane of in.
static lanes lanes_of(const poly1305_ifma_model_register *in, size_t i) {
    lanes out;
    for (int l = 0; l < 8; l++) {
        out.lane[l] = in->digit[i][l];
    }
    return out;
}

static void store_lanes(poly1305_ifma_model_register *out, const lanes h[3]) {
    for (size_t i = 0; i < 3; i++) {
        for (int l = 0; l < 8; l++) {
            out->digit[i][l] = h[i].lane[l];
        }
    }
}

static void multiplier_of(multiplier *by, const poly1305_ifma_model_register *digits) {
    by->r0 = lanes_of(digits, 0);
    by->r1 = lanes_of(digits, 1);
    by->r2 = lanes_of(digits, 2);
    multiplier_complete(by);
}

void poly1305_ifma_model_group_step(poly1305_ifma_model_register *out,
                                    const poly1305_ifma_model_register *h_in, const uint8_t *m,
                                    const poly1305_ifma_model_register *first_in,
                                    const poly1305_ifma_model_register *second_in) {
    multiplier first;
    multiplier second;
    multiplier_of(&first, first_in);
    multiplier_of(&second, second_in);
    lanes h[3] = {lanes_of(h_in, 0), lanes_of(h_in, 1), lanes_of(h_in, 2)};
    lanes lo[3];
    lanes hi[3];
    group_sums(lo, hi, h, m, &first, &second);
    carry(h, lo, hi);
    store_lanes(out, h);
}

void poly1305_ifma_model_powers(poly1305_ifma_model_register out[4], const uint32_t r[5]) {
    powers of_r;
    compute_powers(&of_r, r);
    const multiplier *const take[4] = {&of_r.last_first, &of_r.last_second, &of_r.by_16,
                                       &of_r.by_8};
    for (size_t k = 0; k < 4; k++) {
        const lanes digits[3] = {take[k]->r0, take[k]->r1, take[k]->r2};
        store_lanes(&out[k], digits);
    }
}
