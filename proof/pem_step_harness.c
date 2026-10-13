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
//      the file is `end_prefix + 1` on a static array with compile-time
//      constants, and the index into the four-entry label table, which
//      pem_read_block's CH_ASSERT holds below PEM_LABEL_COUNT.
//   2. The accounting invariant is preserved one character at a time.
//      base64_step is proved here from an ARBITRARY state satisfying
//      nbits in {0,2,4,6}, so it holds after any number of characters,
//      not just the number the driver's bound admits. That is what
//      makes the driver's --undefined-shift-check verdict on
//      `1U << nbits` in body_ok carry to the shipped cap.
//
// base64_step takes a byte's class, which base64.c's base64_class gives
// and proof/base64_harness.c proves equal to RFC 4648 section 4's table
// on all 256 bytes. The step below takes any byte as the class, every
// class base64_class gives and more.
#include "harness.h"

#include "pem.c"

uint32_t nondet_u32(void);

static int nbits_ok(uint32_t n) {
    return n == 0 || n == 2 || n == 4 || n == 6;
}

int main(void) {
    // 1. pad_ok over an arbitrary state: exactly the rule, no UB.
    base64_state p;
    p.acc = nondet_u32();
    p.nbits = nondet_u32();
    p.pos = nondet_u32();
    p.npad = nondet_u32();
    p.seen = nondet_u32();
    int ok = pad_ok(&p);
    __CPROVER_assert(ok == (p.npad < 2 && (p.pos == 2 || p.pos == 3)),
                     "pad_ok is the RFC 4648 section 3.5 rule");

    // 2. The induction step. From ANY state the loop can hold, one
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

    uint8_t step_class = nondet_u8();
    int rc = base64_step(&s, &w, step_class);
    __CPROVER_assert(rc == 0 || rc == 1, "base64_step returns a flag");
    __CPROVER_assert(rc == 0 || step_class < 64 || step_class == BASE64_PAD,
                     "base64_step accepts an alphabet value or a pad, and no other class");
    __CPROVER_assert(nbits_ok(s.nbits), "base64_step preserves nbits in {0,2,4,6}");
    __CPROVER_assert(s.pos < 4 && s.npad <= 2, "base64_step preserves the counter ranges");

    // 3. body_ok over any state the invariant admits: the shift in
    //    `1U << nbits` is in range and nothing else is UB.
    base64_state f;
    f.acc = nondet_u32();
    f.nbits = nondet_u32();
    f.pos = nondet_u32();
    f.npad = nondet_u32();
    f.seen = nondet_u32();
    __CPROVER_assume(nbits_ok(f.nbits));
    (void)body_ok(&w, &f);

    // 4. read_eol over an unconstrained short input.
    uint8_t eol[4];
    fill_nondet(eol, sizeof eol);
    size_t eol_len = nondet_size_t();
    __CPROVER_assume(eol_len <= sizeof eol);
    rbuf r;
    rb_init(&r, eol, eol_len);
    (void)read_eol(&r);

    // 5. match_line against both boundaries of every label, at every
    //    input length, and pem_begins_boundary, which reads a copy. It
    //    answers 1 exactly when the line opens with the 11 bytes of
    //    "-----BEGIN ", whatever follows them.
    uint8_t line[32];
    fill_nondet(line, sizeof line);
    size_t line_len = nondet_size_t();
    __CPROVER_assume(line_len <= sizeof line);
    uint8_t label = nondet_u8();
    __CPROVER_assume(label < PEM_LABEL_COUNT);
    rbuf m;
    rb_init(&m, line, line_len);
    (void)match_line(&m, begin_prefix, sizeof begin_prefix, label);
    rb_init(&m, line, line_len);
    (void)match_line(&m, end_prefix + 1, sizeof end_prefix - 1, label);
    rb_init(&m, line, line_len);
    int begins = pem_begins_boundary(&m);
    __CPROVER_assert(m.off == 0 && m.err == 0, "pem_begins_boundary: the reader does not move");
    int opens = line_len >= sizeof begin_prefix;
    for (size_t i = 0; opens && i < sizeof begin_prefix; i++) {
        opens = line[i] == begin_prefix[i];
    }
    __CPROVER_assert(begins == opens, "pem_begins_boundary: 1 exactly at the 11 bytes");
    return 0;
}
