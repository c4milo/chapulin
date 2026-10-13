// Proves: pem_decode_one is memory-safe and UB-free for the three labels
// of a key file: PRIVATE KEY, EC PRIVATE KEY and EC PARAMETERS. It
// honours its contract. On 1 the writer holds a non-empty DER inside its
// room, with its sticky error clear. On 0 or 1 the reader never runs past
// the input.
//
// proof/pem_harness.c drives the CERTIFICATE label through
// pem_decode_certificate. This one drives the other three through
// pem_decode_one, into a writer of one of two rooms:
//  - CH_PEM_KEY_DER_MAX bytes, the room pem_files.c's key reader gives
//    the key;
//  - CH_PEM_PARAMETERS_DER_MAX bytes, the room it gives an EC PARAMETERS
//    block. It reads that block through pem_read_block, the call that
//    pem_decode_one makes first.
// The label and the room are nondet, so every compare against each
// boundary is in the formula.
//
// Bounded at CH_PROOF_PEM_LEN for pem_harness.c's reason. The same two
// facts carry the verdict past it: pem.c does no raw buffer arithmetic,
// and proof/pem_step_harness.c proves the per-character step from an
// arbitrary state. 64 covers the longest label. An EC PRIVATE KEY
// block's BEGIN line is 30 bytes and its END line 28, and the END line
// needs no terminator. So the shortest input that the decoder accepts is
// 63 bytes: the BEGIN line, its terminator, one quantum and the END line.
#include "harness.h"

#include "pem.c"

#ifndef CH_PROOF_PEM_LEN
#define CH_PROOF_PEM_LEN 64
#endif

int main(void) {
    uint8_t pem[CH_PROOF_PEM_LEN + 1];
    fill_nondet(pem, sizeof pem);
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= CH_PROOF_PEM_LEN);
    uint8_t label = nondet_u8();
    __CPROVER_assume(label == PEM_LABEL_PRIVATE_KEY || label == PEM_LABEL_EC_PRIVATE_KEY ||
                     label == PEM_LABEL_EC_PARAMETERS);

    uint8_t der[CH_PEM_KEY_DER_MAX];
    size_t room = nondet_u8() & 1 ? sizeof der : CH_PEM_PARAMETERS_DER_MAX;
    wbuf w;
    wb_init(&w, der, room);
    int ok = pem_decode_one(pem, pem_len, label, &w);
    __CPROVER_assert(ok == 0 || ok == 1, "pem_decode_one: a flag");
    if (ok) {
        __CPROVER_assert(w.len > 0 && w.len <= room && !w.err,
                         "1: a non-empty DER inside the writer's room");
    }
    return 0;
}
