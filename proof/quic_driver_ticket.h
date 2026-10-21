// The ticket half of proof/quic_driver_harness.c: a saved ticket that
// ch_quic_init can be handed, and the rules an accepted ticket meets. It
// sits in its own file because the harness holds a file under 500 lines.
// The harness includes it after q, cfg and the trust_answer of
// proof/quic_driver_stubs.h, which these read. It is one formula with the
// harness, not a second proof.
#ifndef CH_PROOF_QUIC_DRIVER_TICKET_H
#define CH_PROOF_QUIC_DRIVER_TICKET_H

// The ticket ch_quic_init can be handed.
static ch_saved_ticket saved;

// The ticket fields the rules read, each stored through its own type. No
// rule and no stub reads the PSK or the identity bytes, so they stay zero.
static void havoc_ticket(void) {
    saved.ticket.psk_len = nondet_size_t();
    saved.ticket.identity_len = nondet_size_t();
    saved.ticket.lifetime_s = nondet_u32();
    saved.ticket.quic_version = nondet_u32();
}

// What quic.h and handshake_post.h require of a ticket ch_quic_init
// accepts: the trust check held, a PSK of a hash length this build holds,
// an identity a ClientHello holds, a lifetime of 1 second or more, an age
// inside that lifetime and inside 7 days, and the original version. The
// session offers the ticket's PSK and identity, and no pin.
static void assert_ticket_accepted(void) {
    __CPROVER_assert(trust_answer == 1, "an accepted ticket passed the trust check");
    __CPROVER_assert(saved.ticket.psk_len == SHA256_LEN || saved.ticket.psk_len == HKDF_HASH_MAX,
                     "an accepted ticket's PSK is a hash length");
    __CPROVER_assert(saved.ticket.identity_len >= 1 &&
                         saved.ticket.identity_len <= CH_TICKET_ID_MAX,
                     "an accepted ticket's identity fits a ClientHello");
    __CPROVER_assert(saved.ticket.lifetime_s != 0 &&
                         cfg.ticket_age_ms <= (uint64_t)saved.ticket.lifetime_s * 1000U &&
                         cfg.ticket_age_ms <= (uint64_t)CH_TICKET_LIFETIME_MAX * 1000U,
                     "an accepted ticket is inside its lifetime and 7 days");
    __CPROVER_assert(saved.ticket.quic_version == cfg.quic_original_version,
                     "an accepted ticket comes from the original version");
    __CPROVER_assert(q.t.cfg.psk == saved.ticket.psk && q.t.cfg.psk_len == saved.ticket.psk_len &&
                         q.t.cfg.psk_id == saved.identity &&
                         q.t.cfg.psk_id_len == saved.ticket.identity_len,
                     "the session offers the ticket's PSK and identity");
    __CPROVER_assert(q.t.cfg.server_pubkey == NULL && q.t.cfg.server_pubkey2 == NULL,
                     "the session offers the ticket alone, with no pin");
}

#endif
