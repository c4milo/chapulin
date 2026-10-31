// Proves: to_entry() of x25519_wide_ed25519.h, under CH_DNSSEC, from a
// point whose words are below 2^51, writes an entry whose words are below
// 2^51 and wraps no unsigned value (--unsigned-overflow-check). That is the
// form x25519_wide_edwards's harness takes for an entry, and decode_point()
// writes such a point: it reduces x and y to canonical words.
// ed25519_verify_hram() runs double_point() and add_entry() on these
// entries and on the identity, the inductive step x25519_wide_edwards
// proves, so its loop of 253 steps stays inside INV-34's bounds by
// induction. x25519_wide_invert and x25519_wide_tail prove the invert, mul
// and pack that end it, and x25519_wide_ed25519_mod_l proves the scalar's
// reduction.
//
// Not proved by a line of its own: decode_point(). Its chain of squarings
// and products to z^((p - 5) / 8) is mul() and sqr() alone, whose bounds
// x25519_wide_mul and x25519_wide_sqr prove for any operand under 2^54, and
// every add() and sub() in it takes a result of those or of reduce(). With
// to_entry() and the reduction in one formula, cbmc gave no verdict in 25
// minutes. bin/dnssec_test and the Zig API's test run it on OpenSSL's and
// std.crypto's keys, on a key whose y is p, and on a small-order key.
//
// The multiply is the contract in proof/x25519_wide_stubs.h, which
// x25519_wide_mul128 discharges on the real ct_mul128.
#define CH_DNSSEC 1
#include "x25519_wide_stubs.h"

#define CANONICAL ((uint64_t)1 << 51)

int main(void) {
    fe px;
    fe py;
    for (size_t i = 0; i < 5; i++) {
        px[i] = nondet_u64() >> 13;
        py[i] = nondet_u64() >> 13;
    }
    edwards_entry e;
    to_entry(&e, px, py);
    for (size_t i = 0; i < 5; i++) {
        __CPROVER_assert(e.y_plus_x[i] < CANONICAL && e.y_minus_x[i] < CANONICAL &&
                             e.xy2d[i] < CANONICAL,
                         "an entry has canonical words");
    }
    return 0;
}
