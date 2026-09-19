// Proves: quic_initial_seal and quic_initial_open read and write only
// inside their buffers, commit no undefined behavior, and answer one of
// the codes their header documents, over unconstrained lengths at the
// module's real bounds.
//
// What the harness drives. Every length is symbolic: the Destination
// Connection ID length is unconstrained, so both sides of RFC 9000
// §17.2's cap run; the packet number length is unconstrained, so both
// sides of RFC 9001 §5.4.2's 1-to-4 range run; and the header, payload,
// capacity and packet lengths run from zero to the buffers below. The
// packet number itself is unconstrained. The bound that is not a length
// is CH_QUIC_DCID_MAX, which the harness allocates exactly.
//
// The buffer sizes are the smallest that reach both answers. A packet
// has to hold pn_off plus QUIC_PN_MAX_LEN plus QUIC_HP_SAMPLE_LEN bytes
// before §5.4.2 admits it, which is 24 bytes at pn_off 4, so 28 bytes of
// packet leaves room either side of that bound. The seal's output buffer
// holds a whole packet of the header and payload below.
//
// Two properties beside memory safety. First, a refusal writes neither
// output: the harness poisons the output buffer, calls, and compares.
// That is the promise both entries make, and the reason every length
// check runs before the first write. Second, a successful open reports a
// plaintext length inside the packet it was handed.
//
// The eight calls quic_initial.c makes are contract stubs
// (proof/quic_initial_stubs.h), which states what the composition gives
// up and where each one is proven.
#include "harness.h"

#include "quic_initial_stubs.h"

#include "quic_initial.c"

#ifndef CH_PROOF_HDR_MAX
#define CH_PROOF_HDR_MAX 6
#endif
#ifndef CH_PROOF_PT_MAX
#define CH_PROOF_PT_MAX 6
#endif
#ifndef CH_PROOF_PKT_MAX
#define CH_PROOF_PKT_MAX 28
#endif

#define PROOF_OUT_MAX (CH_PROOF_HDR_MAX + CH_PROOF_PT_MAX + GCM_TAG)

// The byte a refusal may not replace, the one test/srv_stub_test.c
// uses for the same question.
#define PROOF_POISON 0xa5

int main(void) {
    uint8_t dcid[CH_QUIC_DCID_MAX];
    uint8_t hdr[CH_PROOF_HDR_MAX];
    uint8_t pt[CH_PROOF_PT_MAX];
    uint8_t out[PROOF_OUT_MAX];

    fill_nondet(dcid, sizeof dcid);
    fill_nondet(hdr, sizeof hdr);
    fill_nondet(pt, sizeof pt);

    // Unconstrained: the refusals above CH_QUIC_DCID_MAX and outside 1
    // to QUIC_PN_MAX_LEN are what the call answers there, and the stub
    // reads no connection ID byte past the cap.
    size_t dcid_len = nondet_size_t();
    size_t pn_len = nondet_size_t();
    uint64_t pn = nondet_u64();

    size_t hdr_len = nondet_size_t();
    size_t pt_len = nondet_size_t();
    size_t cap = nondet_size_t();
    __CPROVER_assume(hdr_len <= sizeof hdr);
    __CPROVER_assume(pt_len <= sizeof pt);
    __CPROVER_assume(cap <= sizeof out);

    for (size_t i = 0; i < sizeof out; i++) {
        out[i] = PROOF_POISON;
    }
    size_t out_len = PROOF_POISON;
    int rc =
        quic_initial_seal(dcid, dcid_len, pn, pn_len, hdr, hdr_len, pt, pt_len, out, cap, &out_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL,
                     "seal: one of the three documented codes");
    if (rc != CH_OK) {
        // A refusal writes neither the packet nor its length.
        __CPROVER_assert(out_len == (size_t)PROOF_POISON, "seal: a refusal writes no length");
        for (size_t i = 0; i < sizeof out; i++) {
            __CPROVER_assert(out[i] == PROOF_POISON, "seal: a refusal writes no packet byte");
        }
    } else {
        __CPROVER_assert(out_len == hdr_len + pt_len + GCM_TAG,
                         "seal: the whole packet is the header, the payload and the tag");
        __CPROVER_assert(out_len <= cap, "seal: the packet fits the buffer it was given");
    }

    // The open side, over its own packet and its own lengths. pkt is
    // havocked again, so nothing here reads a byte the seal left.
    uint8_t pkt[CH_PROOF_PKT_MAX];
    fill_nondet(pkt, sizeof pkt);
    size_t pkt_len = nondet_size_t();
    size_t pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= sizeof pkt);
    __CPROVER_assume(pn_off <= sizeof pkt);
    // RFC 9000 §17.1 bounds a packet number, and quic_initial.h takes
    // largest_pn as one the caller processed.
    uint64_t largest_pn = nondet_u64();
    __CPROVER_assume(largest_pn < (UINT64_C(1) << 62));

    uint64_t got_pn = PROOF_POISON;
    size_t got_pt_len = PROOF_POISON;
    dcid_len = nondet_size_t();
    rc = quic_initial_open(dcid, dcid_len, pkt, pkt_len, pn_off, largest_pn, &got_pn, &got_pt_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_QUIC_DISCARD || rc == CH_EINVAL,
                     "open: one of the three documented codes");
    if (rc == CH_OK) {
        __CPROVER_assert(got_pt_len <= pkt_len, "open: the plaintext is inside the packet");
        __CPROVER_assert(got_pn < (UINT64_C(1) << 62), "open: the packet number is in range");
    } else {
        __CPROVER_assert(got_pn == (uint64_t)PROOF_POISON, "open: a refusal reports no number");
        __CPROVER_assert(got_pt_len == (size_t)PROOF_POISON, "open: a refusal reports no length");
    }
    return 0;
}
