// Contract stubs for the calls quic.c makes below itself, so
// quic_driver_harness proves the driver's own framing -- the input
// loop, the level rules, the counters and the wipes -- rather than
// re-deriving the flight handlers and the packet protection inside one
// formula. Same shape and same reason as proof/quic_initial_stubs.h.
//
// WHAT THESE MODEL, and therefore what the harness still proves:
//
//   hsf_begin                 a writable handshake_state whose back
//                             pointer is written.
//   hsf_build_client_hello    a message length up to the caller's cap,
//                             or 0 with ALERT_INTERNAL_ERROR, which is
//                             what handshake_flight.h states.
//   quic_initial_seal,        CH_EINVAL past CH_QUIC_DCID_MAX without
//   quic_initial_open         reading the connection ID, which is what
//                             quic_initial.h states; otherwise as the
//                             two quic_packet calls below.
//   quic_packet_seal          CH_EINVAL, CH_ECAP below the whole packet,
//                             or that many written bytes and CH_OK.
//   quic_packet_open_*        CH_QUIC_DISCARD, or CH_OK with a
//                             plaintext inside the packet and, at 1-RTT,
//                             a key set that is a named index.
//   quic_retry_ok             1 or 0, over a readable pseudo-packet.
//   quic_keys_update          the secret and the set rewritten.
//   the two §6.6 questions    quic_packet.c's own arithmetic, repeated
//                             so the limit paths are inside the formula.
//
// Each one asserts the contract its own header states for a caller:
// every buffer readable or writable at the length passed, the level one
// quic_packet.c runs, and the outputs valid. quic.c is their only
// caller, so these stubs are where its argument discipline is checked.
//
// WHAT THIS NO LONGER PROVES: that those calls meet their contracts.
// handshake_psk and handshake_pin prove the two flight handlers,
// quic_initial, quic_packet and quic_retry prove the packet calls, and
// quic_keys proves the key update.
#ifndef CH_PROOF_QUIC_DRIVER_STUBS_H
#define CH_PROOF_QUIC_DRIVER_STUBS_H

// The two flight handlers ch_quic_init calls.
void hsf_begin(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "begin: state writable");
    __CPROVER_assert(h->t != NULL, "begin: back pointer written");
}

size_t hsf_build_client_hello(handshake_state *h, uint8_t *out, size_t cap) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "hello: state writable");
    size_t n = nondet_size_t();
    // CH_PROOF_TX for the reason the file header gives: the staged
    // message is copied by length and never read by content.
    __CPROVER_assume(n <= cap && n <= CH_PROOF_TX);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return 0;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, n), "hello: staging writable");
    fill_nondet(out, n);
    return n;
}

// The two Initial calls take the stored Destination Connection ID
// rather than a key (quic_initial.h), and refuse a length past
// CH_QUIC_DCID_MAX before they read a byte.
static int dcid_ok(const uint8_t *dcid, size_t dcid_len) {
    if (dcid_len > CH_QUIC_DCID_MAX) {
        return 0;
    }
    __CPROVER_assert(dcid_len == 0 || __CPROVER_r_ok(dcid, dcid_len), "initial: dcid readable");
    return 1;
}

static int seal_result(const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                       uint8_t *out, size_t cap, size_t *out_len) {
    __CPROVER_assert(hdr_len == 0 || __CPROVER_r_ok(hdr, hdr_len), "seal: header readable");
    __CPROVER_assert(pt_len == 0 || __CPROVER_r_ok(pt, pt_len), "seal: plaintext readable");
    __CPROVER_assert(out_len != NULL, "seal: length output valid");
    uint8_t choice = nondet_u8();
    if (choice == 0) {
        return CH_EINVAL;
    }
    if (choice == 1 || cap < hdr_len + pt_len + GCM_TAG) {
        return CH_ECAP;
    }
    size_t n = hdr_len + pt_len + GCM_TAG;
    __CPROVER_assert(__CPROVER_w_ok(out, n), "seal: output writable");
    fill_nondet(out, n);
    *out_len = n;
    return CH_OK;
}

int quic_initial_seal(const uint8_t *dcid, size_t dcid_len, uint64_t pn, size_t pn_len,
                      const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    if (!dcid_ok(dcid, dcid_len)) {
        return CH_EINVAL;
    }
    (void)pn;
    (void)pn_len;
    return seal_result(hdr, hdr_len, pt, pt_len, out, cap, out_len);
}

int quic_packet_seal(const quic_keys *k, const quic_hp_key *h, uint8_t level, uint64_t pn,
                     size_t pn_len, const uint8_t *hdr, size_t hdr_len, const uint8_t *pt,
                     size_t pt_len, uint8_t *out, size_t cap, size_t *out_len) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(h, sizeof *h), "seal: header key readable");
    __CPROVER_assert(level == CH_LEVEL_HANDSHAKE || level == CH_LEVEL_APPLICATION,
                     "seal: quic_packet.c runs neither Initial nor a level above 1-RTT");
    (void)pn;
    (void)pn_len;
    return seal_result(hdr, hdr_len, pt, pt_len, out, cap, out_len);
}

// The open calls answer CH_OK or CH_QUIC_DISCARD and nothing else.
// quic.c refuses the §5.4.2 length itself, so a discard from here is
// always the tag mismatch it counts.
static int open_result(uint8_t *pkt, size_t pkt_len, size_t pn_off, uint64_t *pn, size_t *pt_len) {
    __CPROVER_assert(pkt_len == 0 || __CPROVER_w_ok(pkt, pkt_len), "open: packet writable");
    __CPROVER_assert(pn_off <= pkt_len, "open: packet number offset inside the packet");
    __CPROVER_assert(pn != NULL && pt_len != NULL, "open: outputs valid");
    if (nondet_u8() & 1) {
        return CH_QUIC_DISCARD;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= pkt_len);
    *pn = nondet_u64();
    *pt_len = n;
    return CH_OK;
}

int quic_initial_open(const uint8_t *dcid, size_t dcid_len, uint8_t *pkt, size_t pkt_len,
                      size_t pn_off, uint64_t largest_pn, uint64_t *pn, size_t *pt_len) {
    if (!dcid_ok(dcid, dcid_len)) {
        return CH_EINVAL;
    }
    (void)largest_pn;
    return open_result(pkt, pkt_len, pn_off, pn, pt_len);
}

int quic_packet_open_handshake(const quic_keys *k, const quic_hp_key *h, uint8_t *pkt,
                               size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                               size_t *pt_len) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(h, sizeof *h), "open: header key readable");
    (void)largest_pn;
    return open_result(pkt, pkt_len, pn_off, pn, pt_len);
}

int quic_packet_open_application(const quic_keys sets[CH_QUIC_KEY_SETS], const quic_hp_key *h,
                                 uint8_t key_phase, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                                 uint64_t largest_pn, uint64_t current_phase_lowest_pn,
                                 uint8_t *key_set, uint64_t *pn, size_t *pt_len) {
    __CPROVER_assert(__CPROVER_r_ok(sets, CH_QUIC_KEY_SETS * sizeof *sets), "open: sets readable");
    __CPROVER_assert(__CPROVER_r_ok(h, sizeof *h), "open: header key readable");
    __CPROVER_assert(key_phase <= 1, "open: the key phase is one bit");
    (void)largest_pn;
    (void)current_phase_lowest_pn;
    int rc = open_result(pkt, pkt_len, pn_off, pn, pt_len);
    if (rc == CH_OK) {
        uint8_t set = nondet_u8();
        __CPROVER_assume(set < CH_QUIC_KEY_SETS);
        *key_set = set;
    }
    return rc;
}

int quic_integrity_limit_exceeded(uint64_t open_failures) {
    return open_failures > QUIC_INTEGRITY_LIMIT;
}

int quic_confidentiality_limit_reached(uint64_t sealed) {
    return sealed + 1 >= QUIC_CONFIDENTIALITY_LIMIT;
}

uint8_t quic_retry_ok(const uint8_t *pseudo, size_t n, const uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pseudo, n), "retry: pseudo-packet readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, GCM_TAG), "retry: tag readable");
    return nondet_u8() & 1;
}

void quic_keys_update(uint8_t secret[SHA256_LEN], quic_keys *k) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "update: secret writable");
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "update: set writable");
    fill_nondet(secret, SHA256_LEN);
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
}

#endif
