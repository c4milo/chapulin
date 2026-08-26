// Proves the revocation epoch's two rules, which nothing else checks:
// epoch_check's verdict always matches the status it reports, and
// hsa_epoch_commit never lowers the stored epoch. The second is what
// makes revocation work at all -- a commit that moved backwards would
// let a replayed certificate undo a bump.
//
// Narrow on purpose. The CA arm's whole driver does not converge
// (#37), so this proves the arm's own arithmetic and leaves the
// record reading to handshake_psk and handshake_pin.
#define CH_TRUST_CA 1
#define CH_PROOF_PIN 1
#define CH_PROOF_STUB_SHA256

#include <string.h>

#include "harness.h"

#include "handshake_auth.c"

static int epoch_store_nondet(void *io, uint32_t value) {
    (void)io;
    (void)value;
    return (int)nondet_u8();
}

static int epoch_load_nondet(void *io, uint32_t *out) {
    (void)io;
    *out = (uint32_t)nondet_size_t();
    return (int)nondet_u8();
}

int main(void) {
    ch_tls t;
    handshake_state h;
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;

    // Both epochs are on the lattice by the time they reach here:
    // ch_connect refuses a stored value above CH_EPOCH_MAX (tls.c), and a
    // leaf's epoch comes from the certificate parser, which bounds it the
    // same way. Without that domain, t->epoch + CH_EPOCH_BOUND overflows
    // and the harness reports a wrap no caller can produce.
    size_t stored = nondet_size_t();
    size_t leaf_epoch = nondet_size_t();
    __CPROVER_assume(stored <= CH_EPOCH_MAX);
    __CPROVER_assume(leaf_epoch <= CH_EPOCH_MAX);
    t.epoch = (uint32_t)stored;
    t.cfg.epoch_store = epoch_store_nondet;
    t.cfg.epoch_load = nondet_u8() ? epoch_load_nondet : NULL;
    h.leaf.epoch = (uint32_t)leaf_epoch;
    h.leaf.epoch_ok = nondet_u8();
    h.alert = nondet_u8();

    int rc = epoch_check(&h);
    // The verdict and the status are one decision reported twice; a
    // caller that trusts one and not the other reads a lie.
    if (t.cfg.epoch_load != NULL) {
        if (rc == CH_OK) {
            __CPROVER_assert(t.epoch_status == CH_EPOCH_MATCHED || t.epoch_status == CH_EPOCH_AHEAD,
                             "epoch: accepted means matched or ahead");
            __CPROVER_assert(!h.leaf.epoch_ok || h.leaf.epoch >= t.epoch,
                             "epoch: accepted never sits below the stored epoch");
        } else {
            __CPROVER_assert(t.epoch_status == CH_EPOCH_UNTRUSTED ||
                                 t.epoch_status == CH_EPOCH_REVOKED,
                             "epoch: refused means untrusted or revoked");
        }
    }

    // The commit's own contract: run() calls it only after Finished.
    h.server_finished_ok = 1;
    uint32_t before = t.epoch;
    hsa_epoch_commit(&h);
    __CPROVER_assert(t.epoch >= before, "epoch: a commit never lowers the stored epoch");
    __CPROVER_assert(t.epoch == before || (h.leaf.epoch_ok && t.epoch == h.leaf.epoch),
                     "epoch: a raised epoch is the leaf's own, and the leaf carried one");
    return 0;
}
