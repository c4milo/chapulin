// The packet calls' half of proof/quic_driver_harness.c: ch_quic_seal,
// ch_quic_open, ch_quic_retry_ok and ch_quic_seal_close over any saved
// state and any caller argument, the QUIC version among them. It sits in
// its own file because the harness holds a file under 500 lines, and the
// harness includes it after q, cfg and the helpers these read:
// havoc_session's saved state, WRITE_BITS, write_keys_zero and
// zero_bytes. It is one formula with the harness, not a second proof.
#ifndef CH_PROOF_QUIC_DRIVER_PACKETS_H
#define CH_PROOF_QUIC_DRIVER_PACKETS_H

// Whether a packet at level may carry version, written from RFC 9369
// section 4.1 rather than from quic.c: the negotiated version at every
// level, and the original version at the Initial level too.
static int version_admitted(uint8_t level, uint32_t version) {
    return version == q.t.quic_negotiated_version ||
           (level == CH_LEVEL_INITIAL && version == q.t.cfg.quic_original_version);
}

static void drive_packets(void) {
    uint8_t pkt[CH_PROOF_RXBUF];
    uint8_t out[CH_PROOF_RXBUF + 4 + GCM_TAG];
    uint8_t hdr[4];
    uint8_t tag[GCM_TAG];
    size_t out_len = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint8_t key_set = 0;
    fill_nondet(pkt, sizeof pkt);
    fill_nondet(hdr, sizeof hdr);
    fill_nondet(tag, sizeof tag);

    uint8_t level = nondet_u8();
    uint32_t version = nondet_u32();
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);
    uint64_t was_sealed = q.initial_sealed;
    int live = q.t.state != CH_ST_CLOSED && q.t.state != CH_ST_FAILED;
    int rc = ch_quic_seal(&q, level, version, nondet_u64(), nondet_size_t(), hdr, sizeof hdr, pkt,
                          sizeof pkt, out, cap, &out_len);
    __CPROVER_assert(rc == CH_OK || q.initial_sealed == was_sealed,
                     "RFC 9001 6.6: a seal that did not happen counts nowhere");
    __CPROVER_assert(rc == CH_EINVAL || live,
                     "a dead session seals only through ch_quic_seal_close");
    __CPROVER_assert(version_admitted(level, version) || rc == CH_EINVAL,
                     "RFC 9369 4.1: a packet in a version its level does not admit is refused");

    level = nondet_u8();
    version = nondet_u32();
    size_t pkt_len = nondet_size_t();
    size_t pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= sizeof pkt && pn_off <= pkt_len);
    uint8_t was_state = q.t.state;
    uint64_t was_failures = q.open_failures;
    uint8_t was_ready = q.levels_ready;
    int admitted = version_admitted(level, version);
    rc = ch_quic_open(&q, level, version, pkt, pkt_len, pn_off, nondet_u64(), nondet_u64(),
                      &key_set, &pn, &pt_len);
    __CPROVER_assert(rc == CH_EINVAL || live, "a dead session opens no packet");
    if (!admitted) {
        __CPROVER_assert(rc == CH_EINVAL && q.open_failures == was_failures &&
                             q.levels_ready == was_ready && q.t.state == was_state,
                         "RFC 9369 4.1: a packet in another version is refused and counts nowhere");
    }
    // The same quic_fail drive_crypto_in's failures run, so this checks
    // the bits it leaves and assert_dead there checks the bytes: a second
    // assert_dead here took the formula from 0.97 to 1.54 GB.
    if (rc == CH_QUIC_AEAD_LIMIT) {
        __CPROVER_assert(q.levels_ready == (uint8_t)(was_ready & WRITE_BITS),
                         "the integrity limit keeps exactly the write bits it found");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(key_set < CH_QUIC_KEY_SETS, "the set that opened it is a named index");
        __CPROVER_assert(pt_len <= pkt_len, "the plaintext is inside the packet");
        __CPROVER_assert(level != CH_LEVEL_APPLICATION || was_state == CH_ST_CONNECTED,
                         "RFC 9001 5.7: no 1-RTT packet before the handshake completes");
    }
    if (pn_off > pkt_len || pkt_len - pn_off < QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN) {
        __CPROVER_assert(q.open_failures == was_failures,
                         "RFC 9001 5.4.2: a packet too short to sample counts nowhere");
    }
    uint32_t retry_version = nondet_u32();
    __CPROVER_assert(ch_quic_retry_ok(&q, retry_version, pkt, sizeof pkt, tag) == 0 ||
                         retry_version == q.t.cfg.quic_original_version,
                     "RFC 9369 4.1: a Retry in any version but the original fails");
    __CPROVER_assert(ch_quic_negotiated_version(&q) == q.t.quic_negotiated_version,
                     "the negotiated version is the field's");
    (void)ch_quic_key_update(&q);
    ch_quic_drop_previous_keys(&q);
    (void)ch_quic_discard(&q, nondet_u8());
    (void)ch_quic_key_phase(&q);
    (void)ch_quic_alert(&q);
    (void)ch_quic_state(&q);
    (void)ch_quic_error_code(&q);
}

// ch_quic_seal_close over any saved state. It seals only for a failed
// session at a level whose write bit is set; that one seal wipes the
// level's write keys and clears its bit and no other, a second call at
// that level is refused, and no call changes the session state.
static void drive_close(void) {
    uint8_t pt[CH_PROOF_RXBUF];
    uint8_t out[CH_PROOF_RXBUF + 4 + GCM_TAG];
    uint8_t hdr[4];
    size_t out_len = 0;
    fill_nondet(pt, sizeof pt);
    fill_nondet(hdr, sizeof hdr);
    uint8_t level = nondet_u8();
    size_t cap = nondet_size_t();
    size_t pt_len = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out && pt_len <= sizeof pt);
    uint8_t was_state = q.t.state;
    uint8_t was_ready = q.levels_ready;
    uint32_t version = nondet_u32();
    int admitted = version_admitted(level, version);
    int rc = ch_quic_seal_close(&q, level, version, nondet_u64(), nondet_size_t(), hdr, sizeof hdr,
                                pt, pt_len, out, cap, &out_len);
    __CPROVER_assert(q.t.state == was_state, "a close changes no session state");
    if (rc != CH_OK) {
        __CPROVER_assert(rc == CH_EINVAL || rc == CH_ECAP, "a refused close has two codes");
        __CPROVER_assert(q.levels_ready == was_ready, "a refused close clears no bit");
        return;
    }
    __CPROVER_assert(was_state == CH_ST_FAILED, "only a failed session seals a close");
    __CPROVER_assert(admitted, "a close goes out only in a version its level admits");
    __CPROVER_assert(level <= CH_LEVEL_APPLICATION &&
                         (was_ready & CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE)) != 0,
                     "a close goes out only at a level whose write bit was set");
    __CPROVER_assert(q.levels_ready ==
                         (uint8_t)(was_ready & (uint8_t)~CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE)),
                     "the close clears that level's write bit and no other bit");
    __CPROVER_assert(write_keys_zero(level), "the close wipes that level's write keys");
    __CPROVER_assert(out_len == sizeof hdr + pt_len + GCM_TAG, "the close is one whole packet");
    fill_nondet(pt, sizeof pt);
    fill_nondet(hdr, sizeof hdr);
    cap = nondet_size_t();
    pt_len = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out && pt_len <= sizeof pt);
    rc = ch_quic_seal_close(&q, level, nondet_u32(), nondet_u64(), nondet_size_t(), hdr, sizeof hdr,
                            pt, pt_len, out, cap, &out_len);
    __CPROVER_assert(rc == CH_EINVAL, "a second close at the same level is refused");
}

#endif
