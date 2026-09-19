// quic_initial.c against RFC 9001 Appendix A.2, in its own header for the
// reason test/quic_gcm_tests.h and test/quic_packet_tests.h are: the
// Initial vectors are long and test/quic_vectors.c holds the helpers they
// read. It uses the helpers and CHECK from that file and is included
// after them.
#ifndef CH_QUIC_INITIAL_TESTS_H
#define CH_QUIC_INITIAL_TESTS_H

// The A.2 header, its packet number and the packet it seals into: 22
// header bytes, 1162 payload bytes and the tag (rfc9001.txt:2394-2402).
#define A2_HDR_LEN 22
#define A2_PN_LEN 4
#define A2_PN 2
#define A2_PACKET (A2_HDR_LEN + A2_PAYLOAD + GCM_TAG)

static void test_appendix_a2_seal(void) {
    uint8_t hdr[A2_HDR_LEN];
    CHECK(unhex("c300000001088394c8f03e5157080000449e00000002", hdr) == sizeof hdr);

    // The payload is the CRYPTO frame followed by PADDING frames, and a
    // PADDING frame is a zero byte (RFC 9000 §19.1).
    static uint8_t pt[A2_PAYLOAD];
    memset(pt, 0, sizeof pt);
    memcpy(pt, A2_CRYPTO_FRAME, sizeof A2_CRYPTO_FRAME);

    static uint8_t out[A2_PACKET];
    size_t out_len = 0;
    CHECK(quic_initial_seal(APPENDIX_DCID, sizeof APPENDIX_DCID, A2_PN, A2_PN_LEN, hdr, sizeof hdr,
                            pt, sizeof pt, out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof out);
    // The first ciphertext block, which is also the sample the RFC
    // names (rfc9001.txt:2407-2411), and the tag the packet ends with.
    CHECK(eq_hex(&out[A2_HDR_LEN], "d1b1c98dd7689fb8ec11d242b123dc9b"));
    CHECK(eq_hex(&out[A2_HDR_LEN + A2_PAYLOAD], "e221af44860018ab0856972e194cd934"));
}

// The byte a refusal may not replace, the one test/srv_stub_test.c
// uses: 0xa5 is neither 0 nor 0xff, so a wipe and a fill both show.
#define INITIAL_POISON 0xa5

static uint8_t initial_out[64];
static size_t initial_out_len;

static void poison_initial_out(void) {
    memset(initial_out, INITIAL_POISON, sizeof initial_out);
    memset(&initial_out_len, INITIAL_POISON, sizeof initial_out_len);
}

// True when the call wrote neither the buffer nor the length.
static int initial_out_untouched(void) {
    uint8_t poisoned[sizeof initial_out];
    memset(poisoned, INITIAL_POISON, sizeof poisoned);
    return memcmp(initial_out, poisoned, sizeof initial_out) == 0 &&
           memcmp(&initial_out_len, poisoned, sizeof initial_out_len) == 0;
}

// Every refusal quic_initial_seal documents, one input at a time, with
// the output buffer poisoned so "writes nothing" is measured.
static void test_initial_seal_refusals(void) {
    uint8_t dcid[CH_QUIC_DCID_MAX + 1];
    uint8_t hdr[8];
    uint8_t pt[8];
    memset(dcid, 0x5a, sizeof dcid);
    memset(hdr, 0x11, sizeof hdr);
    memset(pt, 0x22, sizeof pt);
    const size_t whole = sizeof hdr + sizeof pt + GCM_TAG;

    // A Destination Connection ID one byte over RFC 9000 §17.2's cap.
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, sizeof dcid, 1, A2_PN_LEN, hdr, sizeof hdr, pt, sizeof pt,
                            initial_out, whole, &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // A packet number length outside 1 to QUIC_PN_MAX_LEN, both sides.
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, 8, 1, 0, hdr, sizeof hdr, pt, sizeof pt, initial_out, whole,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, 8, 1, QUIC_PN_MAX_LEN + 1, hdr, sizeof hdr, pt, sizeof pt,
                            initial_out, whole, &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // A header shorter than the packet number field it is said to end
    // with.
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, 8, 1, 3, hdr, 2, pt, sizeof pt, initial_out, whole,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // One byte short of the packet, and the packet exactly.
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, 8, 1, A2_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, initial_out,
                            whole - 1, &initial_out_len) == CH_ECAP);
    CHECK(initial_out_untouched());
    CHECK(quic_initial_seal(dcid, 8, 1, A2_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, initial_out,
                            whole, &initial_out_len) == CH_OK);
    CHECK(initial_out_len == whole);

    // RFC 9001 §5.4.2's own boundary: the packet number and the payload
    // together must reach QUIC_PN_MAX_LEN bytes, or the sample falls
    // outside the packet (rfc9001.txt:1283-1286). 4 seals, 3 refuses.
    CHECK(quic_initial_seal(dcid, 8, 1, 1, hdr, 1, pt, 3, initial_out, 1 + 3 + GCM_TAG,
                            &initial_out_len) == CH_OK);
    CHECK(initial_out_len == 1 + 3 + GCM_TAG);
    poison_initial_out();
    CHECK(quic_initial_seal(dcid, 8, 1, 1, hdr, 1, pt, 2, initial_out, 1 + 2 + GCM_TAG,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());
}

// The two refusals quic_initial_open reaches before the AEAD. The tag
// arm and the successful open need quic_packet.c's header protection
// removal, so they arrive with that file.
static void test_initial_open_refusals(void) {
    uint8_t dcid[CH_QUIC_DCID_MAX + 1];
    memset(dcid, 0x5a, sizeof dcid);
    uint8_t pkt[64];
    uint8_t before[sizeof pkt];
    memset(pkt, 0x33, sizeof pkt);
    memcpy(before, pkt, sizeof before);
    const size_t pn_off = 5;
    // The shortest packet §5.4.2 admits: the packet number field at its
    // longest, and a whole sample after it (rfc9001.txt:1280-1281).
    const size_t sampled = pn_off + QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN;
    uint64_t pn = 0;
    size_t pt_len = 0;

    CHECK(quic_initial_open(dcid, sizeof dcid, pkt, sampled, pn_off, 0, &pn, &pt_len) == CH_EINVAL);
    CHECK(memcmp(pkt, before, sizeof before) == 0);
    CHECK(pn == 0 && pt_len == 0);

    CHECK(quic_initial_open(dcid, 8, pkt, sampled - 1, pn_off, 0, &pn, &pt_len) == CH_QUIC_DISCARD);
    CHECK(memcmp(pkt, before, sizeof before) == 0);
    CHECK(pn == 0 && pt_len == 0);
}

#endif
