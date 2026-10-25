// The wide field's arm of the differential oracle: the x25519 rows of
// test/diff_x25519.h, run against the same Lean spec process test/diff_test.c
// drives, over x25519_wide.c. The Makefile builds it as a host object's
// source, with -DCH_CPU_RUNTIME, and the two renames below send the rows'
// calls to the radix-2^51 field's entries here, where bin/diff runs them on
// the 16-word field.
//
// Its own main rather than a second build of test/diff_test.c, because the
// field changes nothing else that binary compares: every other row would
// run the same code twice. spec/lean/Spec/X25519.lean computes over Nat
// with a reduction mod p after every operation, so it states no word
// representation and serves both fields unchanged.
//
// The rows draw fresh random inputs on every call, so each is run ten times:
// 1,000 scalar multiplications of a random point and 500 of the base point.
// One more row runs x25519_wide_ladder on 1,000 scalars that no clamp has
// touched against the Lean ladder on the same bits, the one row whose
// scalars can set bit 0 (docs/decisions.md 152).
//
// The binary includes x25519_wide.c rather than linking it, to reach the key
// generation's formulas in x25519_wide_edwards.h, and three more rows hold
// them to spec/lean/Spec/X25519Edwards.lean, element for element over ZMod p:
// add_entry and to_extended, double_point and to_extended, and to_u. That
// module proves the formulas compute the Edwards addition law and that the
// map to curve25519 adds, so these rows are what make the proofs about the
// C. Each runs 2,000 times on random field elements, the addition also on
// entries select_entry takes from the table at random digits, and the
// elements 0 and 1 stand in for a random one at random.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

#include "diff_driver.h"

// A build without the define declares no wide field, so it could only diff
// the 16-word field a second time and report success for the wrong one.
#ifndef CH_CPU_RUNTIME
#error "test/diff_x25519_test.c diffs the wide X25519 field: build it with -DCH_CPU_RUNTIME"
#endif
// After x25519.h's declarations, so the renames change the rows' calls and
// no declaration.
#include "x25519_wide.c"
#define x25519 x25519_wide
#define x25519_base x25519_wide_base

#include "diff_x25519.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A field element as both sides read it: 32 random bytes through unpack and
// pack, so below p, and its words under 2^51. One time in eight it is 0 or 1.
static void draw_element(fe out) {
    uint8_t bytes[X25519_LEN];
    rng_fill(bytes, sizeof bytes);
    if ((bytes[1] & 7) == 0) {
        uint8_t small = bytes[2] & 1;
        memset(bytes, 0, sizeof bytes);
        bytes[0] = small;
    }
    unpack(out, bytes);
    pack(bytes, out);
    unpack(out, bytes);
}

// The elements' 32 bytes each, in hex, after a space each.
static void append_elements(char *cmd, size_t cmd_len, const uint64_t *const elements[],
                            size_t count) {
    size_t used = strlen(cmd);
    for (size_t i = 0; i < count; i++) {
        uint8_t bytes[X25519_LEN];
        char hex[2 * X25519_LEN + 1];
        pack(bytes, elements[i]);
        (void)hex_encode(hex, bytes, sizeof bytes);
        int written = snprintf(cmd + used, cmd_len - used, " %s", hex);
        if (written < 0 || (size_t)written >= cmd_len - used) {
            die("x25519_edwards: a row does not fit its buffer");
        }
        used += (size_t)written;
    }
}

static void draw_point(edwards_point *p) {
    draw_element(p->x);
    draw_element(p->y);
    draw_element(p->z);
    draw_element(p->t);
}

static void expect_point(const char *cmd, const edwards_point *p) {
    char want[4 * (2 * X25519_LEN + 1) + 1] = "";
    const uint64_t *const out[] = {p->x, p->y, p->z, p->t};
    append_elements(want, sizeof want, out, 4);
    expect(cmd, want + 1);
}

static void diff_edwards_add(void) {
    edwards_point a;
    edwards_entry b;
    edwards_sum s;
    edwards_point o;
    memset(&b, 0, sizeof b);
    draw_point(&a);
    uint8_t pick[2];
    rng_fill(pick, sizeof pick);
    if (pick[0] & 1) {
        select_entry(&b, X25519_WIDE_TABLE[pick[1] & 31], (int64_t)(pick[0] >> 1) % 17 - 8);
    } else {
        draw_element(b.y_plus_x);
        draw_element(b.y_minus_x);
        draw_element(b.xy2d);
    }
    add_entry(&s, &a, &b);
    to_extended(&o, &s);
    char cmd[1024] = "x25519_edwards_add";
    const uint64_t *const in[] = {a.x, a.y, a.z, a.t, b.y_plus_x, b.y_minus_x, b.xy2d};
    append_elements(cmd, sizeof cmd, in, 7);
    expect_point(cmd, &o);
}

static void diff_edwards_double(void) {
    edwards_point a;
    edwards_sum s;
    edwards_point o;
    draw_point(&a);
    double_point(&s, &a);
    to_extended(&o, &s);
    char cmd[1024] = "x25519_edwards_double";
    const uint64_t *const in[] = {a.x, a.y, a.z, a.t};
    append_elements(cmd, sizeof cmd, in, 4);
    expect_point(cmd, &o);
}

static void diff_edwards_u(void) {
    edwards_point a;
    uint8_t u[X25519_LEN];
    char want[2 * X25519_LEN + 1];
    draw_point(&a);
    to_u(u, &a);
    (void)hex_encode(want, u, sizeof u);
    char cmd[1024] = "x25519_edwards_u";
    const uint64_t *const in[] = {a.x, a.y, a.z, a.t};
    append_elements(cmd, sizeof cmd, in, 4);
    expect(cmd, want);
}

// x25519_wide_ladder on a scalar that no clamp has touched, against the Lean
// ladder on the same bits. A clamped scalar's bit 0 is 0, and x25519_wide()
// passes no other, so this row is what runs the ladder's last cswap with bit
// 1: about half of the random scalars here set bit 0.
static void diff_ladder(void) {
    uint8_t scalar[X25519_LEN];
    uint8_t point[X25519_LEN];
    uint8_t out[X25519_LEN];
    rng_fill(scalar, sizeof scalar);
    rng_fill(point, sizeof point);
    x25519_wide_ladder(out, scalar, point);
    char key_hex[2 * X25519_LEN + 1];
    char point_hex[2 * X25519_LEN + 1];
    char want[2 * X25519_LEN + 1];
    (void)hex_encode(key_hex, scalar, sizeof scalar);
    (void)hex_encode(point_hex, point, sizeof point);
    (void)hex_encode(want, out, sizeof out);
    char cmd[512];
    (void)snprintf(cmd, sizeof cmd, "x25519_ladder %s %s", key_hex, point_hex);
    expect(cmd, want);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff x25519 wide: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (int round = 0; round < 10; round++) {
        diff_x25519();
        diff_x25519_base();
    }
    for (int i = 0; i < 1000; i++) {
        diff_ladder();
    }
    for (int i = 0; i < 2000; i++) {
        diff_edwards_add();
        diff_edwards_double();
        diff_edwards_u();
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff x25519 wide: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
