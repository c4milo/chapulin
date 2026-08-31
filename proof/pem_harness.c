// Proves: pem_decode_certificate is memory-safe and UB-free, and
// honours its whole contract -- CH_OK yields a length inside the
// caller's array, and every rejection yields zero.
//
// CONCRETE at the SHIPPED caps: CH_X509_MAX and CH_PEM_MAX are the
// build's own, real rbuf and wbuf via buf.c, real ct_memeq via ct.c,
// nothing stubbed.
//
// What is bounded is the INPUT LENGTH, not the configuration.
// CH_PROOF_PEM_LEN is measured and proof/run.sh's launch line records
// it. A decoder is a per-character state machine over symbolic bytes,
// the shape bounded model checking pays most for: cost measured at
// roughly the 4.7th power of the length, so the shipped 3136-byte cap
// is out of reach by orders of magnitude and claiming it would be a
// launch line that never converged.
//
// Two facts carry the verdict past that length, and neither is an
// appeal to similarity:
//
//   1. Memory safety does not depend on the character count. pem.c
//      does no raw buffer arithmetic -- every read goes through rb_u8
//      or rb_bytes, every write through wb_u8, and buf.c's own
//      arithmetic is length-generic by construction (proof/buf_harness.c
//      checks it at 64 bytes, which is a bound on that harness, not on
//      the code). The only pointer arithmetic in pem.c is
//      `end_line + 1` on a static array with compile-time constants.
//   2. The accounting invariant is preserved one character at a time,
//      and proof/pem_step_harness.c proves that step from an ARBITRARY
//      state rather than from the states this bound reaches. Induction
//      over that step is what makes the shift in body_ok defined
//      at any length.
//
// What is therefore NOT proved here: that some character count above
// CH_PROOF_PEM_LEN drives the boundary sequence itself into a state
// this bound never reaches. The README's verification section says so.
#include "harness.h"

#include "pem.c"

// 64, not lower. The shortest accepting input is 58 bytes -- the two
// boundary lines, their terminators and one base64 quantum -- so at 56
// the CH_OK arm is unreachable and its assertion passes vacuously while
// the run still prints VERIFICATION SUCCESSFUL. Confirmed by asserting
// 0 in that arm: SUCCESS at 56, and a counterexample at 64 and above.
#ifndef CH_PROOF_PEM_LEN
#define CH_PROOF_PEM_LEN 64
#endif

int main(void) {
    uint8_t pem[CH_PROOF_PEM_LEN + 1];
    fill_nondet(pem, sizeof pem);

    uint8_t der[CH_X509_MAX];
    size_t der_len = nondet_size_t();

    // The proof proper, over every input up to the measured length.
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= CH_PROOF_PEM_LEN);
    int rc = pem_decode_certificate(pem, pem_len, der, &der_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "pem_decode_certificate: two codes only");
    if (rc == CH_OK) {
        // The wbuf's sticky error is what holds this, so the assert is
        // a real check on it rather than a restatement.
        __CPROVER_assert(der_len > 0 && der_len <= CH_X509_MAX,
                         "CH_OK: a non-empty length inside the caller's array");
    } else {
        __CPROVER_assert(der_len == 0, "CH_EINVAL: the length is zero");
    }

    // The over-cap arm, at the real cap. The length deliberately runs
    // past this buffer: a caller with a larger buffer is the shape
    // that reaches this arm, and the point is that the cap check
    // returns before any byte is read. Bounding over_len by sizeof pem
    // instead would make the assume unsatisfiable -- CH_PEM_MAX is
    // 3136 and this buffer is CH_PROOF_PEM_LEN + 1 -- and both
    // assertions below would pass vacuously.
    size_t over_len = nondet_size_t();
    __CPROVER_assume(over_len > CH_PEM_MAX);
    size_t over_der_len = nondet_size_t();
    __CPROVER_assert(pem_decode_certificate(pem, over_len, der, &over_der_len) == CH_EINVAL,
                     "over CH_PEM_MAX: rejected");
    __CPROVER_assert(over_der_len == 0, "over CH_PEM_MAX: the length is zero");
    return 0;
}
