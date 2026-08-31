// Proves: the per-character pieces of pem.c, over unconstrained inputs
// at full generality, with no loop over the input.
//
// This is the induction step that lets proof/pem_harness.c run at a
// reduced cap. Two facts split that way:
//
//   1. Memory safety does not depend on the character count. pem.c does
//      no raw buffer arithmetic -- every read goes through rb_u8 or
//      rb_bytes and every write through wb_u8, and buf.c's arithmetic
//      is length-generic by construction (buf_harness checks it at 64
//      bytes, a bound on that harness rather than on the code). The only pointer arithmetic in
//      the file is `end_line + 1` on a static array with compile-time
//      constants.
//   2. The accounting invariant is preserved one character at a time.
//      base64_step is proved here from an ARBITRARY state satisfying
//      nbits in {0,2,4,6}, so it holds after any number of characters,
//      not just the number the driver's bound admits. That is what
//      makes the driver's --undefined-shift-check verdict on
//      `1U << nbits` in body_ok carry to the shipped cap.
//
// base64_value is proved equivalent to RFC 4648 section 4's table rather
// than to itself: the reference below is the alphabet as the RFC prints
// it, searched linearly, so the five range compares have to agree with
// it on all 256 bytes.
#include "harness.h"

#include "pem.c"

uint32_t nondet_u32(void);

// RFC 4648 section 4, as a table. Concrete, so the search is 64 constant
// compares against one symbolic byte.
static uint32_t ref_base64_value(uint8_t c) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (uint32_t i = 0; i < 64; i++) {
        if ((uint8_t)table[i] == c) {
            return i;
        }
    }
    return BASE64_INVALID;
}

static int nbits_ok(uint32_t n) {
    return n == 0 || n == 2 || n == 4 || n == 6;
}

int main(void) {
    // 1. The alphabet, on every byte.
    uint8_t c = nondet_u8();
    __CPROVER_assert(base64_value(c) == ref_base64_value(c),
                     "base64_value is RFC 4648 section 4's table");

    // 2. pad_ok over an arbitrary state: exactly the rule, no UB.
    base64_state p;
    p.acc = nondet_u32();
    p.nbits = nondet_u32();
    p.pos = nondet_u32();
    p.npad = nondet_u32();
    p.seen = nondet_u32();
    int ok = pad_ok(&p);
    __CPROVER_assert(ok == (p.npad < 2 && (p.pos == 2 || p.pos == 3)),
                     "pad_ok is the RFC 4648 section 3.5 rule");

    // 3. The induction step. From ANY state the loop can hold, one
    //    character leaves a state the loop can hold. The driver
    //    establishes the base case (nbits 0) at its own bound.
    base64_state s;
    s.acc = nondet_u32();
    s.nbits = nondet_u32();
    s.pos = nondet_u32();
    s.npad = nondet_u32();
    s.seen = nondet_u32();
    __CPROVER_assume(nbits_ok(s.nbits));
    // The state the loop can actually hold: pos is a mod-4 counter and
    // npad never passes 2, both enforced by base64_step itself.
    __CPROVER_assume(s.pos < 4 && s.npad <= 2);

    uint8_t out[8];
    wbuf w;
    wb_init(&w, out, sizeof out);
    // Havoc the writer's own position too, so the step is proved against
    // a full writer as well as an empty one.
    w.len = nondet_size_t();
    __CPROVER_assume(w.len <= w.cap);

    uint8_t step_c = nondet_u8();
    int rc = base64_step(&s, &w, step_c);
    __CPROVER_assert(rc == 0 || rc == 1, "base64_step returns a flag");
    __CPROVER_assert(nbits_ok(s.nbits), "base64_step preserves nbits in {0,2,4,6}");
    __CPROVER_assert(s.pos < 4 && s.npad <= 2, "base64_step preserves the counter ranges");

    // 4. body_ok over any state the invariant admits: the shift in
    //    `1U << nbits` is in range and nothing else is UB.
    base64_state f;
    f.acc = nondet_u32();
    f.nbits = nondet_u32();
    f.pos = nondet_u32();
    f.npad = nondet_u32();
    f.seen = nondet_u32();
    __CPROVER_assume(nbits_ok(f.nbits));
    (void)body_ok(&w, &f);

    // 5. read_eol over an unconstrained short input.
    uint8_t eol[4];
    fill_nondet(eol, sizeof eol);
    size_t eol_len = nondet_size_t();
    __CPROVER_assume(eol_len <= sizeof eol);
    rbuf r;
    rb_init(&r, eol, eol_len);
    (void)read_eol(&r);

    // 6. match_bytes against both boundaries, at every input length.
    uint8_t line[32];
    fill_nondet(line, sizeof line);
    size_t line_len = nondet_size_t();
    __CPROVER_assume(line_len <= sizeof line);
    rbuf m;
    rb_init(&m, line, line_len);
    (void)match_bytes(&m, begin_line, sizeof begin_line);
    rb_init(&m, line, line_len);
    (void)match_bytes(&m, end_line + 1, sizeof end_line - 1);
    return 0;
}
