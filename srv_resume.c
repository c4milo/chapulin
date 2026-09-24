// Resumption on the server: the ticket a ClientHello resumes, and the
// NewSessionTicket a connection ends its handshake with. srv_resume.h
// states both contracts, what a ticket binds and why. Reading goes
// through the rbuf reader (buf.h), so no step here does raw buffer
// arithmetic.
#include "srv_resume.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "keysched.h"
#include "rand.h"
#include "srv_out.h"

// The four-byte obfuscated_ticket_age each PskIdentity ends with (RFC
// 9846 §4.3.11). This server reads none of it: srv_resume.h says why.
#define OBFUSCATED_AGE_LEN 4

// The bytes of ticket_age_add in a NewSessionTicket.
#define TICKET_AGE_ADD_LEN 4

// Whether this configuration can judge a ticket: a key to open it with
// and a clock to date it by. Both issuing and accepting ask it.
static int tickets_on(const ch_srv_cfg *srv) {
    return srv->ticket_key != NULL && srv->now_seconds != 0;
}

// Whether the client offered a PSK this server may select: pre_shared_key,
// and psk_dhe_ke among its modes.
static int ticket_offered(const client_hello *ch) {
    return (ch->seen & SRV_EXT_PRE_SHARED_KEY) != 0 && (ch->psk_modes & SRV_PSK_DHE_KE) != 0;
}

// Whether now_seconds lies inside the ticket's lifetime: not before
// auth_seconds, and at most SRV_TICKET_LIFETIME seconds after it. The
// first comparison is what keeps the subtraction from wrapping.
static int ticket_fresh(uint64_t auth_seconds, uint64_t now_seconds) {
    return now_seconds >= auth_seconds && now_seconds - auth_seconds <= SRV_TICKET_LIFETIME;
}

// Whether a ticket's suite is one this build holds. Every such suite
// hashes with SHA-256, so the ticket resumes under any of them, which is
// RFC 9846 §4.7.1's KDF hash rule (rfc9846.txt:3219-3220).
static int ticket_suite_held(uint16_t suite) {
#ifdef CH_SUITE_AES_GCM
    if (suite == SUITE_AES_128_GCM_SHA256) {
        return 1;
    }
#endif
    return suite == SUITE_CHACHA20_POLY1305_SHA256;
}

// Whether the ticket names the protocol this connection selected, as an
// index into cfg.alpn_protocols or CH_ALPN_NONE. Protocol names are
// public; ct_memeq is the compare INV-16 admits in a library source.
static int ticket_alpn_matches(const srv_ticket_contents *c, const ch_cfg *cfg,
                               uint8_t alpn_selected) {
    if (alpn_selected == CH_ALPN_NONE) {
        return c->alpn_len == 0;
    }
    const ch_alpn_protocol *p = &cfg->alpn_protocols[alpn_selected];
    return c->alpn_len == p->name_len && ct_memeq(c->alpn, p->name, p->name_len);
}

// Whether an opened ticket may resume this handshake: every test
// srv_resume.h lists after the open.
static int ticket_holds(const srv_ticket_contents *c, const ch_cfg *cfg, const client_hello *ch,
                        const selection *sel) {
    return ticket_fresh(c->auth_seconds, cfg->srv.now_seconds) && ticket_suite_held(c->suite) &&
           sel->hash_len == SHA256_LEN && ticket_alpn_matches(c, cfg, ch->alpn_selected);
}

// Walks the client's identities in its order and stops at the first
// ticket that opens and holds, writing its index and what it carried.
// The parser held the list to its syntax, so the walk only reads it.
// Returns 1 when one was found, and 0 with *c wiped when none was.
static int find_ticket(const ch_cfg *cfg, const client_hello *ch, const selection *sel,
                       uint16_t *index, srv_ticket_contents *c) {
    rbuf r;
    rb_init(&r, ch->psk_identities, ch->psk_identities_len);
    for (uint16_t i = 0; rb_left(&r) > 0; i++) {
        size_t identity_len = rb_u16(&r);
        const uint8_t *identity = rb_bytes(&r, identity_len);
        rb_skip(&r, OBFUSCATED_AGE_LEN);
        if (r.err) {
            break;
        }
        // The length travels in the clear, so an identity of any other
        // length is passed over without running the AEAD.
        if (identity_len == SRV_TICKET_LEN &&
            srv_ticket_open(cfg->srv.ticket_key, identity, identity_len, c) == CH_OK &&
            ticket_holds(c, cfg, ch, sel)) {
            *index = i;
            return 1;
        }
    }
    ct_wipe(c, sizeof *c);
    return 0;
}

// The binder at index in the client's binders list, which holds one entry
// per identity in the same order (rfc9846.txt:2501-2502), and its length.
// Returns NULL when the list ends before index.
static const uint8_t *binder_at(const client_hello *ch, uint16_t index, size_t *binder_len) {
    rbuf r;
    rb_init(&r, ch->psk_binders, ch->psk_binders_len);
    for (uint16_t i = 0; rb_left(&r) > 0; i++) {
        size_t len = rb_u8(&r);
        const uint8_t *binder = rb_bytes(&r, len);
        if (r.err) {
            return NULL;
        }
        if (i == index) {
            *binder_len = len;
            return binder;
        }
    }
    return NULL;
}

// Derives the early secret from the ticket's PSK into h->early and checks
// the client's binder at index against the one that secret gives
// (RFC 9846 §4.3.11.2). The binder key dies here either way. Returns 1
// when the binder compared equal.
static int binder_matches(handshake_state *h, const client_hello *ch, const uint8_t psk[SHA256_LEN],
                          uint16_t index) {
    ks_early(SHA256_LEN, psk, SHA256_LEN, 1, h->early, h->binder_key);
    uint8_t want[SHA256_LEN];
    ks_verify_data(SHA256_LEN, h->binder_key, ch->binder_hash, want);
    ct_wipe(h->binder_key, sizeof h->binder_key);
    size_t binder_len = 0;
    const uint8_t *binder = binder_at(ch, index, &binder_len);
    // The length and the presence are public: the client sent both.
    uint32_t equal = 0;
    if (binder != NULL && binder_len == SHA256_LEN) {
        equal = ct_memeq(want, binder, SHA256_LEN);
    }
    ct_wipe(want, sizeof want);
    return equal != 0;
}

// Selects a ticket out of the hello, or none. The only refusal is a
// binder that did not match the ticket the server selected.
static int select_ticket(handshake_state *h, const client_hello *ch, selection *sel) {
    srv_ticket_contents c;
    uint16_t index = 0;
    if (!find_ticket(&h->t->cfg, ch, sel, &index, &c)) {
        return CH_OK;
    }
    int matched = binder_matches(h, ch, c.psk, index);
    uint64_t auth_seconds = c.auth_seconds;
    ct_wipe(&c, sizeof c);
    if (!matched) {
        ct_wipe(h->early, sizeof h->early);
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sel->psk_selected = 1;
    sel->psk_identity = index;
    // No CertificateVerify goes out, so no scheme is selected, even when
    // the hello offered schemes beside the ticket, as OpenSSL's s_client
    // does. ch_tls.sigalg then reports 0 for every resumed session.
    sel->sigalg = 0;
    h->ticket_auth_seconds = auth_seconds;
    return CH_OK;
}

int srv_select_auth(handshake_state *h, const client_hello *ch, selection *sel) {
    sel->psk_selected = 0;
    sel->psk_identity = 0;
    if (tickets_on(&h->t->cfg.srv) && ticket_offered(ch)) {
        int rc = select_ticket(h, ch, sel);
        if (rc != CH_OK) {
            return rc;
        }
    }
    if (sel->psk_selected || sel->sigalg != 0) {
        return CH_OK;
    }
    // Neither path can authenticate this server. A hello with no
    // signature_algorithms asked for no certificate at all, and one that
    // carried the extension named no scheme a provisioned identity signs.
    h->alert = (ch->seen & SRV_EXT_SIGNATURE_ALGORITHMS) == 0 ? ALERT_MISSING_EXTENSION
                                                              : ALERT_HANDSHAKE_FAILURE;
    return CH_EPROTO;
}

// The ALPN protocol this connection negotiated, copied into the ticket
// contents: the name at t->alpn_selected, or none.
static void ticket_alpn(const ch_tls *t, srv_ticket_contents *c) {
    c->alpn_len = 0;
    if (t->alpn_selected == CH_ALPN_NONE) {
        return;
    }
    const ch_alpn_protocol *p = &t->cfg.alpn_protocols[t->alpn_selected];
    // srv_config_ok held every offered name to CH_ALPN_NAME_MAX bytes.
    CH_ASSERT(p->name_len <= CH_ALPN_NAME_MAX);
    c->alpn_len = (uint8_t)p->name_len;
    memcpy(c->alpn, p->name, p->name_len);
}

// The three values one ticket draws: the AEAD nonce, ticket_age_add and
// ticket_nonce, in that order, from one ch_rand_bytes call.
#define TICKET_DRAW_LEN (AEAD_NONCE + TICKET_AGE_ADD_LEN + SRV_TICKET_NONCE_LEN)

// Seals one ticket and writes the NewSessionTicket that carries it into
// msg. lifetime and auth_seconds are the caller's; drawn is the draw
// above. Returns the message length, or 0 when a builder refused.
static size_t build_ticket_message(handshake_state *h, uint64_t auth_seconds, uint32_t lifetime,
                                   const uint8_t drawn[TICKET_DRAW_LEN], uint8_t *msg, size_t cap) {
    ch_tls *t = h->t;
    rbuf r;
    rb_init(&r, drawn, TICKET_DRAW_LEN);
    const uint8_t *nonce = rb_bytes(&r, AEAD_NONCE);
    uint32_t hi = rb_u24(&r); // u32 read as u24+u8 to keep the reads sequenced
    uint32_t age_add = (hi << 8) | rb_u8(&r);
    const uint8_t *ticket_nonce = rb_bytes(&r, SRV_TICKET_NONCE_LEN);
    CH_ASSERT(r.err == 0 && rb_left(&r) == 0);

    // The resumption secret over the transcript through the client
    // Finished (rfc9846.txt:4157-4159), and the ticket's PSK from it.
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    uint8_t res_master[SHA256_LEN];
    ks_res_master(SHA256_LEN, h->master, hash, res_master);
    srv_ticket_contents c;
    memset(&c, 0, sizeof c);
    c.auth_seconds = auth_seconds;
    c.suite = t->suite;
    ticket_alpn(t, &c);
    ks_res_psk(SHA256_LEN, res_master, ticket_nonce, SRV_TICKET_NONCE_LEN, c.psk);
    ct_wipe(res_master, sizeof res_master);

    uint8_t ticket[SRV_TICKET_LEN];
    size_t ticket_len = srv_ticket_seal(t->cfg.srv.ticket_key, nonce, &c, ticket, sizeof ticket);
    ct_wipe(&c, sizeof c);
    if (ticket_len == 0) {
        return 0;
    }
    return srv_build_new_session_ticket(msg, cap, lifetime, age_add, ticket_nonce,
                                        SRV_TICKET_NONCE_LEN, ticket, ticket_len);
}

int srv_send_new_session_ticket(handshake_state *h) {
    ch_tls *t = h->t;
    const ch_srv_cfg *srv = &t->cfg.srv;
    if (!tickets_on(srv)) {
        return CH_OK;
    }
    // A full handshake proved the certificate now. A resumed one proved
    // nothing new, so its ticket keeps the instant the resumed ticket
    // carried, and srv_select_auth admitted that ticket only inside the
    // lifetime, which keeps the subtraction below from wrapping.
    uint64_t now = srv->now_seconds;
    uint64_t auth_seconds = t->psk_selected ? h->ticket_auth_seconds : now;
    CH_ASSERT(ticket_fresh(auth_seconds, now));
    uint64_t spent = now - auth_seconds;
    if (spent >= SRV_TICKET_LIFETIME) {
        // Nothing is left to give: a lifetime of 0 tells the client to
        // discard the ticket at once (rfc9846.txt:3258-3259).
        return CH_OK;
    }
    uint32_t lifetime = (uint32_t)(SRV_TICKET_LIFETIME - spent);

    // ch_rand_bytes writes every byte it is given, so an all-zero draw is
    // a hook that returned without writing: programmer error, which
    // CH_ASSERT is for, as srv_flight.c holds its own two draws.
    static const uint8_t unwritten[TICKET_DRAW_LEN] = {0};
    uint8_t drawn[TICKET_DRAW_LEN] = {0};
    ch_rand_bytes(drawn, sizeof drawn);
    CH_ASSERT(!ct_memeq(drawn, unwritten, sizeof drawn));

    uint8_t msg[SRV_NEW_SESSION_TICKET_MAX];
    size_t n = build_ticket_message(h, auth_seconds, lifetime, drawn, msg, sizeof msg);
    ct_wipe(drawn, sizeof drawn);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    return srv_out_sealed(h, msg, n);
}

#endif // CH_ROLE_SERVER
