// quic_initial.c against RFC 9001 Appendix A.2 and Appendix A.3, in its
// own header for the reason test/quic_gcm_tests.h and
// test/quic_packet_tests.h are: the Initial vectors are long and
// test/quic_vectors.c holds the helpers they read. It uses the helpers and
// CHECK from that file and is included after them.
#ifndef CH_QUIC_INITIAL_TESTS_H
#define CH_QUIC_INITIAL_TESTS_H

// The A.2 header, its packet number and the packet it seals into: 22
// header bytes, 1162 payload bytes and the tag (rfc9001.txt:2394-2402).
#define A2_HDR_LEN 22
#define A2_PN_LEN 4
#define A2_PN 2
#define A2_PACKET (A2_HDR_LEN + A2_PAYLOAD + GCM_TAG)

// Appendix A.2's unprotected payload: the CRYPTO frame the RFC prints,
// followed by PADDING frames, and a PADDING frame is a zero byte (RFC
// 9000 §19.1). Two tests build it, so it is written once.
static void a2_payload(uint8_t pt[A2_PAYLOAD]) {
    memset(pt, 0, A2_PAYLOAD);
    memcpy(pt, A2_CRYPTO_FRAME, sizeof A2_CRYPTO_FRAME);
}

// Appendix A.2's client Initial packet, sealed by the client entry
// (rfc9001.txt:2388-2401). test_appendix_a2_seal holds what it writes
// against the bytes the RFC prints, and test_initial_endpoint_reads
// hands it to the server entry to open.
static void a2_seal(uint8_t out[A2_PACKET], size_t *out_len) {
    uint8_t hdr[A2_HDR_LEN];
    CHECK(unhex("c300000001088394c8f03e5157080000449e00000002", hdr) == sizeof hdr);
    static uint8_t pt[A2_PAYLOAD];
    a2_payload(pt);
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, APPENDIX_DCID, sizeof APPENDIX_DCID, A2_PN,
                            A2_PN_LEN, hdr, sizeof hdr, pt, A2_PAYLOAD, out, A2_PACKET,
                            out_len) == CH_OK);
}

static void test_appendix_a2_seal(void) {
    static uint8_t out[A2_PACKET];
    size_t out_len = 0;
    a2_seal(out, &out_len);
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
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, sizeof dcid, 1, A2_PN_LEN, hdr,
                            sizeof hdr, pt, sizeof pt, initial_out, whole,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // A packet number length outside 1 to QUIC_PN_MAX_LEN, both sides.
    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, 0, hdr, sizeof hdr, pt, sizeof pt,
                            initial_out, whole, &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());
    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, QUIC_PN_MAX_LEN + 1, hdr,
                            sizeof hdr, pt, sizeof pt, initial_out, whole,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // A header shorter than the packet number field it is said to end
    // with.
    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, 3, hdr, 2, pt, sizeof pt,
                            initial_out, whole, &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    // One byte short of the packet, and the packet exactly.
    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, A2_PN_LEN, hdr, sizeof hdr, pt,
                            sizeof pt, initial_out, whole - 1, &initial_out_len) == CH_ECAP);
    CHECK(initial_out_untouched());
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, A2_PN_LEN, hdr, sizeof hdr, pt,
                            sizeof pt, initial_out, whole, &initial_out_len) == CH_OK);
    CHECK(initial_out_len == whole);

    // RFC 9001 §5.4.2's own boundary: the packet number and the payload
    // together must reach QUIC_PN_MAX_LEN bytes, or the sample falls
    // outside the packet (rfc9001.txt:1283-1286). 4 seals, 3 refuses.
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, 1, hdr, 1, pt, 3, initial_out,
                            1 + 3 + GCM_TAG, &initial_out_len) == CH_OK);
    CHECK(initial_out_len == 1 + 3 + GCM_TAG);
    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, 1, 1, hdr, 1, pt, 2, initial_out,
                            1 + 2 + GCM_TAG, &initial_out_len) == CH_EINVAL);
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

    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_CLIENT, dcid, sizeof dcid, pkt, sampled, pn_off, 0,
                            &pn, &pt_len) == CH_EINVAL);
    CHECK(memcmp(pkt, before, sizeof before) == 0);
    CHECK(pn == 0 && pt_len == 0);

    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_CLIENT, dcid, 8, pkt, sampled - 1, pn_off, 0, &pn,
                            &pt_len) == CH_QUIC_DISCARD);
    CHECK(memcmp(pkt, before, sizeof before) == 0);
    CHECK(pn == 0 && pt_len == 0);
}

// RFC 9001 Appendix A.3's server Initial packet: the payload the server
// sends (rfc9001.txt:2462-2468), the header it sends it under, with a
// 2-byte packet number encoding the number 1 (rfc9001.txt:2470-2473), and
// the protected packet the two produce (rfc9001.txt:2482-2488). The
// Length field 0x4075 is 117, which is the 2 packet number bytes, the 99
// payload bytes and the 16-byte tag.
#define A3_HDR_LEN 20
#define A3_PN_LEN 2
#define A3_PN 1
#define A3_PAYLOAD 99
#define A3_PACKET (A3_HDR_LEN + A3_PAYLOAD + GCM_TAG)
#define A3_HDR_HEX "c1000000010008f067a5502a4262b50040750001"
#define A3_PAYLOAD_HEX                                                                             \
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"                             \
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"                             \
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"                             \
    "020304"
#define A3_PACKET_HEX                                                                              \
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"                             \
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"                             \
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"                             \
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"                             \
    "2158407dd074ee"

// The packet number offset both A.3 calls pass: the header ends with its
// packet number field, so the field starts A3_PN_LEN bytes before the end
// of the header (rfc9001.txt:1141-1143).
#define A3_PN_OFF (A3_HDR_LEN - A3_PN_LEN)

// Appendix A.3's server Initial packet, against the bytes the RFC prints.
// The client seals A.2 under "client in" and the server seals this one
// under "server in", so this is what holds quic_initial_seal's other
// endpoint to a published vector rather than to the client's answer.
static void test_appendix_a3_seal(void) {
    uint8_t hdr[A3_HDR_LEN];
    static uint8_t pt[A3_PAYLOAD];
    static uint8_t want[A3_PACKET];
    CHECK(unhex(A3_HDR_HEX, hdr) == sizeof hdr);
    CHECK(unhex(A3_PAYLOAD_HEX, pt) == sizeof pt);
    CHECK(unhex(A3_PACKET_HEX, want) == sizeof want);

    static uint8_t out[A3_PACKET];
    size_t out_len = 0;
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, APPENDIX_DCID, sizeof APPENDIX_DCID, A3_PN,
                            A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, out, sizeof out,
                            &out_len) == CH_OK);
    CHECK(out_len == sizeof out);
    // Every byte, header protection included, because quic_packet.c
    // applies the mask and Appendix A.3 prints the result.
    CHECK(memcmp(out, want, sizeof want) == 0);
}

// Which endpoint reads which packet. RFC 9001 §5.2 gives each endpoint
// its own Initial secret, so each opens what the other sealed and neither
// opens its own. Four calls: the client opens A.3's server packet, the
// server opens A.2's client packet, and each refuses the packet it wrote.
// The two packets themselves are held against the RFC by
// test_appendix_a3_seal and test_appendix_a2_seal, so a wrong mapping
// here cannot hide behind a wrong packet.
static void test_initial_endpoint_reads(void) {
    uint8_t hdr[A3_HDR_LEN];
    static uint8_t pt[A3_PAYLOAD];
    CHECK(unhex(A3_HDR_HEX, hdr) == sizeof hdr);
    CHECK(unhex(A3_PAYLOAD_HEX, pt) == sizeof pt);

    // quic_initial_open works in place, so each call gets its own copy.
    static uint8_t a3[A3_PACKET];
    static uint8_t a3_again[A3_PACKET];
    size_t a3_len = 0;
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, APPENDIX_DCID, sizeof APPENDIX_DCID, A3_PN,
                            A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, a3, sizeof a3,
                            &a3_len) == CH_OK);
    memcpy(a3_again, a3, sizeof a3);

    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_CLIENT, APPENDIX_DCID, sizeof APPENDIX_DCID, a3,
                            a3_len, A3_PN_OFF, 0, &pn, &pt_len) == CH_OK);
    CHECK(pn == A3_PN);
    CHECK(pt_len == A3_PAYLOAD);
    CHECK(memcmp(&a3[A3_HDR_LEN], pt, A3_PAYLOAD) == 0);
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER, APPENDIX_DCID, sizeof APPENDIX_DCID, a3_again,
                            a3_len, A3_PN_OFF, 0, &pn, &pt_len) == CH_QUIC_DISCARD);

    static uint8_t a2[A2_PACKET];
    static uint8_t a2_again[A2_PACKET];
    static uint8_t a2_pt[A2_PAYLOAD];
    size_t a2_len = 0;
    a2_seal(a2, &a2_len);
    memcpy(a2_again, a2, sizeof a2);
    a2_payload(a2_pt);

    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER, APPENDIX_DCID, sizeof APPENDIX_DCID, a2,
                            a2_len, A2_HDR_LEN - A2_PN_LEN, 0, &pn, &pt_len) == CH_OK);
    CHECK(pn == A2_PN);
    CHECK(pt_len == A2_PAYLOAD);
    CHECK(memcmp(&a2[A2_HDR_LEN], a2_pt, A2_PAYLOAD) == 0);
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_CLIENT, APPENDIX_DCID, sizeof APPENDIX_DCID, a2_again,
                            a2_len, A2_HDR_LEN - A2_PN_LEN, 0, &pn, &pt_len) == CH_QUIC_DISCARD);
}

// The endpoint refusal both entries state: a value that is neither cfg.h
// name derives no key and writes nothing. CH_QUIC_ENDPOINT_SERVER + 1 is
// the first such value.
static void test_initial_endpoint_refusals(void) {
    uint8_t dcid[8];
    uint8_t hdr[8];
    uint8_t pt[8];
    memset(dcid, 0x5a, sizeof dcid);
    memset(hdr, 0x11, sizeof hdr);
    memset(pt, 0x22, sizeof pt);
    const size_t whole = sizeof hdr + sizeof pt + GCM_TAG;

    poison_initial_out();
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER + 1, dcid, sizeof dcid, 1, A2_PN_LEN, hdr,
                            sizeof hdr, pt, sizeof pt, initial_out, whole,
                            &initial_out_len) == CH_EINVAL);
    CHECK(initial_out_untouched());

    uint8_t pkt[64];
    uint8_t before[sizeof pkt];
    memset(pkt, 0x33, sizeof pkt);
    memcpy(before, pkt, sizeof before);
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER + 1, dcid, sizeof dcid, pkt, sizeof pkt, 5, 0,
                            &pn, &pt_len) == CH_EINVAL);
    CHECK(memcmp(pkt, before, sizeof before) == 0);
    CHECK(pn == 0 && pt_len == 0);
}

#endif
