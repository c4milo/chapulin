// quic_packet.c against RFC 9001 Appendix A and RFC 9000 Appendix A.3,
// in its own header for the reason test/gcm_tests.h is one: the
// packet vectors are long and test/quic_vectors.c holds the helpers they
// read. It uses unhex, eq_hex and CHECK from that file and is included
// after them.
//
// Every value below is printed by a standard. Where no standard prints
// one -- the ends of the pn_len range, the two header protection widths
// with a first mask byte that tells them apart, and the packet number
// decoder's two window edges -- the case is constructed over a printed
// key, sample or mask, and the comment says so.
#ifndef CH_QUIC_PACKET_TESTS_H
#define CH_QUIC_PACKET_TESTS_H

// RFC 9001 Appendix A.5's application write secret (rfc9001.txt:2509-2511).
// The three derivations it feeds are checked in test_appendix_a5_keys;
// here they key a whole packet.
#define A5_SECRET "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"

// Appendix A.5's packet number, 654360564, encoded in 3 bytes as 49140
// (rfc9001.txt:2535-2540).
#define A5_PN 654360564
#define A5_PN_LEN 3

static void a5_keys(quic_keys *k, quic_hp_key *h) {
    uint8_t secret[SHA256_LEN];
    (void)unhex(A5_SECRET, secret);
    quic_keys_init(k, secret);
    quic_hp_key_init(h, secret);
}

// RFC 9001 Appendix A.5's whole 1-RTT packet, sealed and opened again
// (rfc9001.txt:2529-2555). It is the shortest packet §5.4.2 admits: a
// 3-byte packet number and a 1-byte payload come to exactly
// QUIC_PN_MAX_LEN, so the 16-byte sample ends on the packet's last byte.
static void test_appendix_a5_packet(void) {
    quic_keys k;
    quic_hp_key h;
    uint8_t hdr[4];
    uint8_t pt[1];
    uint8_t nonce[AEAD_NONCE];
    uint8_t out[32];
    size_t out_len = 0;
    a5_keys(&k, &h);
    (void)unhex("4200bff4", hdr);
    (void)unhex("01", pt);

    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr, sizeof hdr, pt,
                           sizeof pt, out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == 21);
    CHECK(eq_hex(out, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

    // The §5.3 nonce the RFC prints beside that packet (rfc9001.txt:2542).
    quic_nonce(k.iv, A5_PN, nonce);
    CHECK(eq_hex(nonce, "e0459b3474bdd0e46d417eb0"));

    // The same packet opened. Byte 0's Key Phase bit is 0 and the stored
    // phase is 0, so §6.5 picks the current set; the other two sets hold
    // zero bytes, which is what ch_quic_drop_previous_keys leaves, and a
    // wrong selection would fail the tag.
    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, 0, sizeof sets);
    memcpy(&sets[CH_QUIC_KEY_CURRENT], &k, sizeof k);
    uint8_t key_set = 0xff;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_packet_open_application(sets, &h, 0, out, out_len, 1, A5_PN - 1, 0, &key_set, &pn,
                                       &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_CURRENT);
    CHECK(pn == A5_PN);
    CHECK(pt_len == 1);
    CHECK(eq_hex(out, "4200bff4"));
    CHECK(out[4] == 0x01);
}

// RFC 9001 §5.4.1's mask rule at the three widths the RFC prints a
// vector for, in both directions. Appendix A.2 is a long header with a
// 4-byte packet number (rfc9001.txt:2404-2417), Appendix A.3 a long
// header with a 2-byte one, where mask[3] and mask[4] go unused
// (rfc9001.txt:2465-2477), and Appendix A.5 a short header with a
// 3-byte one (rfc9001.txt:2546-2548).
static void test_appendix_header_protection(void) {
    uint8_t pkt[32];
    uint8_t mask[QUIC_HP_MASK_LEN];

    memset(pkt, 0xa5, sizeof pkt);
    size_t n = unhex("c300000001088394c8f03e5157080000449e00000002", pkt);
    (void)unhex("437b9aec36", mask);
    quic_header_protect(pkt, n - 4, 4, CH_LEVEL_INITIAL, mask);
    CHECK(eq_hex(pkt, "c000000001088394c8f03e5157080000449e7b9aec34"));
    CHECK(quic_header_unprotect(pkt, n - 4, CH_LEVEL_INITIAL, mask) == 4);
    CHECK(eq_hex(pkt, "c300000001088394c8f03e5157080000449e00000002"));

    memset(pkt, 0xa5, sizeof pkt);
    n = unhex("c1000000010008f067a5502a4262b50040750001", pkt);
    (void)unhex("2ec0d8356a", mask);
    quic_header_protect(pkt, n - 2, 2, CH_LEVEL_INITIAL, mask);
    CHECK(eq_hex(pkt, "cf000000010008f067a5502a4262b5004075c0d9"));
    // A 2-byte packet number leaves mask[3] and mask[4] over, and
    // §5.4.1 leaves them unused, so the two bytes past this header keep
    // the value they had.
    CHECK(pkt[n] == 0xa5 && pkt[n + 1] == 0xa5);
    CHECK(quic_header_unprotect(pkt, n - 2, CH_LEVEL_INITIAL, mask) == 2);
    CHECK(eq_hex(pkt, "c1000000010008f067a5502a4262b50040750001"));

    memset(pkt, 0xa5, sizeof pkt);
    n = unhex("4200bff4", pkt);
    (void)unhex("aefefe7d03", mask);
    quic_header_protect(pkt, n - A5_PN_LEN, A5_PN_LEN, CH_LEVEL_APPLICATION, mask);
    CHECK(eq_hex(pkt, "4cfe4189"));
    CHECK(pkt[n] == 0xa5);
    CHECK(quic_header_unprotect(pkt, n - A5_PN_LEN, CH_LEVEL_APPLICATION, mask) == A5_PN_LEN);
    CHECK(eq_hex(pkt, "4200bff4"));
}

// The ends of the pn_len range and the two first-byte widths, which no
// RFC vector reaches. The packet number cases run Appendix A.5's mask
// over Appendix A.5's header: one byte used leaves mask[2] through
// mask[4] over, and four used leave none. The width case needs a first
// mask byte whose bit 4 is set, which neither printed mask has, so it
// uses 0xff: that bit is the whole difference between QUIC_HP_BITS_LONG
// and QUIC_HP_BITS_SHORT.
static void test_header_protection_edges(void) {
    uint8_t pkt[8];
    uint8_t mask[QUIC_HP_MASK_LEN];
    (void)unhex("aefefe7d03", mask);

    memset(pkt, 0xa5, sizeof pkt);
    (void)unhex("4200bff4", pkt);
    quic_header_protect(pkt, 1, 1, CH_LEVEL_APPLICATION, mask);
    CHECK(eq_hex(pkt, "4cfebff4"));

    memset(pkt, 0xa5, sizeof pkt);
    (void)unhex("4200bff4", pkt);
    quic_header_protect(pkt, 1, QUIC_PN_MAX_LEN, CH_LEVEL_APPLICATION, mask);
    CHECK(eq_hex(pkt, "4cfe4189a6"));

    (void)unhex("ff000000ff", mask);
    memset(pkt, 0xa5, sizeof pkt);
    (void)unhex("4200bff4", pkt);
    quic_header_protect(pkt, 1, 1, CH_LEVEL_HANDSHAKE, mask);
    CHECK(pkt[0] == (0x42 ^ QUIC_HP_BITS_LONG));
    memset(pkt, 0xa5, sizeof pkt);
    (void)unhex("4200bff4", pkt);
    quic_header_protect(pkt, 1, 1, CH_LEVEL_APPLICATION, mask);
    CHECK(pkt[0] == (0x42 ^ QUIC_HP_BITS_SHORT));
}

// The packet number field: RFC 9000 §17.1 reads the first pn_len bytes
// in network byte order (rfc9000.txt:4897-4899), so every length reads
// from the same offset and stops sooner.
static void test_pn_read(void) {
    uint8_t pkt[8];
    memset(pkt, 0xa5, sizeof pkt);
    (void)unhex("0011223344", pkt);
    CHECK(quic_pn_read(pkt, 1, 1) == UINT64_C(0x11));
    CHECK(quic_pn_read(pkt, 1, 2) == UINT64_C(0x1122));
    CHECK(quic_pn_read(pkt, 1, 3) == UINT64_C(0x112233));
    CHECK(quic_pn_read(pkt, 1, QUIC_PN_MAX_LEN) == UINT64_C(0x11223344));
}

// RFC 9000 Appendix A.3's DecodePacketNumber (rfc9000.txt:8358-8381).
// The first case is the example the appendix prints. The rest are
// constructed, because it prints only that one: both window edges at a
// 1-byte encoding, taken from both sides, and the underflow Figure 47
// guards against, where expected_pn is below pn_hwin.
static void test_pn_decode(void) {
    CHECK(quic_pn_decode(UINT64_C(0xa82f30ea), UINT64_C(0x9b32), 2) == UINT64_C(0xa82f9b32));
    CHECK(quic_pn_decode(A5_PN - 1, UINT64_C(49140), A5_PN_LEN) == A5_PN);

    // largest_pn 1000 makes expected_pn 1001, pn_win 256 and pn_hwin
    // 128, so candidate_pn is 768 + truncated_pn. Figure 47 adds a
    // window while candidate_pn + pn_hwin is at most expected_pn: 105
    // is the last truncated value that holds and 106 the first that
    // does not.
    CHECK(quic_pn_decode(1000, 105, 1) == 1129);
    CHECK(quic_pn_decode(1000, 106, 1) == 874);

    // largest_pn 1100 makes expected_pn 1101 and candidate_pn
    // 1024 + truncated_pn. Figure 47 takes a window away once
    // candidate_pn passes expected_pn + pn_hwin, which is 1229: 205 is
    // the last truncated value that does not and 206 the first that
    // does.
    CHECK(quic_pn_decode(1100, 205, 1) == 1229);
    CHECK(quic_pn_decode(1100, 206, 1) == 974);

    // expected_pn is 1 here, below pn_hwin. Figure 47's first guard
    // subtracts pn_hwin from it, and a build that let that subtraction
    // wrap would add a window to every packet at the start of a
    // connection.
    CHECK(quic_pn_decode(0, 0, 1) == 0);
    CHECK(quic_pn_decode(0, 5, 1) == 5);
}

// RFC 9001 §6.5's receive key set rule (rfc9001.txt:1735-1743) and the
// copy that carries it out, with current_phase_lowest_pn at 40 in every
// differing-phase case so the two sides of it are exact.
static void test_key_set_rule(void) {
    CHECK(quic_key_set_select(1, 1, 9, 40) == CH_QUIC_KEY_CURRENT);
    CHECK(quic_key_set_select(0, 0, 99, 40) == CH_QUIC_KEY_CURRENT);
    CHECK(quic_key_set_select(1, 0, 39, 40) == CH_QUIC_KEY_PREVIOUS);
    CHECK(quic_key_set_select(1, 0, 40, 40) == CH_QUIC_KEY_NEXT);
    CHECK(quic_key_set_select(0, 1, 41, 40) == CH_QUIC_KEY_NEXT);

    quic_keys sets[CH_QUIC_KEY_SETS];
    quic_keys got;
    for (size_t s = 0; s < CH_QUIC_KEY_SETS; s++) {
        memset(&sets[s], (int)s + 1, sizeof sets[s]);
    }
    for (size_t s = 0; s < CH_QUIC_KEY_SETS; s++) {
        quic_keys_select(sets, (uint8_t)s, &got);
        CHECK(memcmp(&got, &sets[s], sizeof got) == 0);
    }
    // A name outside the three leaves zero, and zero keys open no
    // packet, so a caller that lost track fails closed.
    static const quic_keys zero = {{0}, {0}};
    quic_keys_select(sets, CH_QUIC_KEY_SETS, &got);
    CHECK(memcmp(&got, &zero, sizeof got) == 0);
}

// quic_packet_seal's three refusals, each measured against a call that
// differs from it in one value. §5.4.2 needs the encoded packet number
// and the payload to come to QUIC_PN_MAX_LEN bytes
// (rfc9001.txt:1283-1286), and the argument checks run before the
// capacity check.
static void test_seal_refusals(void) {
    quic_keys k;
    quic_hp_key h;
    uint8_t hdr[4];
    uint8_t pt[1];
    uint8_t out[32];
    size_t out_len = 0;
    a5_keys(&k, &h);
    (void)unhex("4200bff4", hdr);
    (void)unhex("01", pt);

    // pn_len + pt_len == QUIC_PN_MAX_LEN seals and one less refuses.
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, QUIC_PN_MAX_LEN, hdr, sizeof hdr,
                           pt, 0, out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof hdr + AEAD_TAG);
    memset(out, 0xa5, sizeof out);
    out_len = 0;
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr, sizeof hdr, pt, 0,
                           out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(out[0] == 0xa5 && out_len == 0);

    // The lengths the header calls invalid.
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, 0, hdr, sizeof hdr, pt, sizeof pt,
                           out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, QUIC_PN_MAX_LEN + 1, hdr,
                           sizeof hdr, pt, sizeof pt, out, sizeof out, &out_len) == CH_EINVAL);
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr, 2, pt, sizeof pt,
                           out, sizeof out, &out_len) == CH_EINVAL);

    // The capacity boundary: the exact size seals and one byte less
    // refuses with nothing written.
    size_t whole = sizeof hdr + sizeof pt + AEAD_TAG;
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr, sizeof hdr, pt,
                           sizeof pt, out, whole, &out_len) == CH_OK);
    memset(out, 0xa5, sizeof out);
    out_len = 0;
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr, sizeof hdr, pt,
                           sizeof pt, out, whole - 1, &out_len) == CH_ECAP);
    CHECK(out[0] == 0xa5 && out_len == 0);

    // A call wrong in both ways answers the argument check.
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, A5_PN, 0, hdr, sizeof hdr, pt, sizeof pt,
                           out, 0, &out_len) == CH_EINVAL);
}

// The two grounds the open calls discard on, over Appendix A.5's packet.
// §5.4.2 discards a packet that cannot hold a complete sample before it
// reads one (rfc9001.txt:1280-1281), and §5.5 discards one whose tag
// does not match (rfc9001.txt:1373-1376).
static void test_open_discards(void) {
    quic_keys k;
    quic_hp_key h;
    uint8_t packet[21];
    uint8_t pkt[21];
    uint64_t pn = 0xdead;
    size_t pt_len = 0xbeef;
    uint8_t key_set = 0xff;
    quic_keys sets[CH_QUIC_KEY_SETS];
    a5_keys(&k, &h);
    memset(sets, 0, sizeof sets);
    memcpy(&sets[CH_QUIC_KEY_CURRENT], &k, sizeof k);
    (void)unhex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb", packet);

    // pn_off + QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN is 21 here, so the
    // whole packet is the last length that opens and one byte less is
    // the first that discards, untouched.
    memcpy(pkt, packet, sizeof pkt);
    CHECK(quic_packet_open_application(sets, &h, 0, pkt, sizeof pkt - 1, 1, A5_PN - 1, 0, &key_set,
                                       &pn, &pt_len) == CH_QUIC_DISCARD);
    CHECK(memcmp(pkt, packet, sizeof pkt) == 0);
    CHECK(pn == 0xdead && pt_len == 0xbeef && key_set == 0xff);

    // A packet whose tag does not match. Flipping the last byte leaves
    // the header and the sample alone, so the discard is the AEAD's.
    memcpy(pkt, packet, sizeof pkt);
    pkt[sizeof pkt - 1] ^= 1;
    CHECK(quic_packet_open_application(sets, &h, 0, pkt, sizeof pkt, 1, A5_PN - 1, 0, &key_set, &pn,
                                       &pt_len) == CH_QUIC_DISCARD);
    CHECK(pn == 0xdead && pt_len == 0xbeef && key_set == 0xff);

    // The same §5.4.2 discard on the Handshake path, which has one key
    // set and no Key Phase bit.
    memcpy(pkt, packet, sizeof pkt);
    CHECK(quic_packet_open_handshake(&k, &h, pkt, sizeof pkt - 1, 1, A5_PN - 1, &pn, &pt_len) ==
          CH_QUIC_DISCARD);
    CHECK(memcmp(pkt, packet, sizeof pkt) == 0);
    CHECK(pn == 0xdead && pt_len == 0xbeef);
}

// Appendix A.5's packet is a vector for quic_packet_open_handshake too.
// Its mask byte is 0xae, whose bit 4 is clear, and that bit is the whole
// difference between QUIC_HP_BITS_LONG and QUIC_HP_BITS_SHORT, so the
// long-header width uncovers the same header. What this checks is the
// rest: one key set instead of three, and the same packet number
// recovery and packet protection removal.
static void test_handshake_open(void) {
    quic_keys k;
    quic_hp_key h;
    uint8_t pkt[21];
    uint64_t pn = 0;
    size_t pt_len = 0;
    a5_keys(&k, &h);
    (void)unhex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb", pkt);

    CHECK(quic_packet_open_handshake(&k, &h, pkt, sizeof pkt, 1, A5_PN - 1, &pn, &pt_len) == CH_OK);
    CHECK(pn == A5_PN);
    CHECK(pt_len == 1);
    CHECK(eq_hex(pkt, "4200bff4"));
    CHECK(pkt[4] == 0x01);
}

// RFC 9001 §6.6's two limits, each at the count on either side of it
// (rfc9001.txt:1801-1803, rfc9001.txt:1823-1827).
static void test_aead_limits(void) {
    CHECK(quic_integrity_limit_exceeded(QUIC_INTEGRITY_LIMIT) == 0);
    CHECK(quic_integrity_limit_exceeded(QUIC_INTEGRITY_LIMIT + 1) == 1);
    CHECK(quic_confidentiality_limit_reached(QUIC_CONFIDENTIALITY_LIMIT - 2) == 0);
    CHECK(quic_confidentiality_limit_reached(QUIC_CONFIDENTIALITY_LIMIT - 1) == 1);
}

#endif
