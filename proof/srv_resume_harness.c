// Proves: srv_select_auth and srv_send_new_session_ticket (srv_resume.c)
// are memory safe and free of UB over an unconstrained ClientHello offer
// and configuration, and answer only what srv_resume.h states.
//
// The properties. The identities and binders lists are any bytes of any
// length up to the bounds below, so the two walks run over every framing,
// a truncated one included, and never read past either list. The ticket
// key is set or NULL, the clock any value, the offered modes and the seen
// mask any value, the ALPN selection any index the parser could report,
// and the selection's suite, hash length and scheme any value.
// srv_select_auth answers CH_OK, CH_EAUTH with decrypt_error, or CH_EPROTO
// with missing_extension or handshake_failure; a CH_OK names an
// authentication path, a ticket or a scheme; a selected ticket's index
// names an entry inside the list. srv_send_new_session_ticket answers CH_OK, CH_EIO
// or CH_ECAP, sends at most once, and sends only with a key and a clock.
//
// The bounds. IDS_MAX holds one whole ticket identity, SRV_TICKET_LEN bytes
// behind its two length bytes and before its four age bytes, plus a
// second short entry, so the walk can both open a ticket and pass an
// identity over. BINDERS_MAX holds one 32-byte binder and the start of a
// second, so the binder walk can find an entry of the right length, one of
// the wrong length and an index the list does not hold. Both
// are the harness's, not the build's: a real list runs to the ClientHello's
// size, and the walks read it through the same rbuf calls at any length.
//
// What is a stub. srv_ticket_open and srv_ticket_seal have their own
// harness, and here they answer either way over any contents with alpn_len
// held to their contract. ks_early, ks_verify_data, ks_res_master,
// ks_res_psk and hsr_transcript_hash write unconstrained secrets and
// hashes, so the binder compare runs over every value it could see; the
// key schedule is proven in keysched's harness. srv_build_new_session_ticket
// is srv_message's, and srv_out_sealed reports success or a failed send.
// ct.c and buf.c are real, so the constant-time compare and the wipes
// are the code that ships.
#include "harness.h"

#include <string.h>

#include "handshake_record.h"
#include "keysched.h"
#include "srv_message.h"
#include "srv_out.h"
#include "srv_resume.h"

int nondet_int(void);
uint16_t nondet_u16(void);
uint64_t nondet_u64(void);

#define IDS_MAX (2 + SRV_TICKET_LEN + 4 + 7)
#define BINDERS_MAX (1 + SHA256_LEN + 2)

// How many identities the stubbed open was asked about, so the harness can
// say that a selected ticket is one the walk opened.
static uint16_t opened;

int srv_ticket_open(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t *ticket, size_t n,
                    srv_ticket_contents *c) {
    __CPROVER_assert(__CPROVER_r_ok(key, SRV_TICKET_KEY_LEN), "open: key readable");
    __CPROVER_assert(n == SRV_TICKET_LEN, "open: only a ticket-length identity is opened");
    __CPROVER_assert(__CPROVER_r_ok(ticket, n), "open: identity readable");
    __CPROVER_assert(__CPROVER_w_ok(c, sizeof *c), "open: contents writable");
    opened++;
    memset(c, 0, sizeof *c);
    if (nondet_int()) {
        return CH_EAUTH;
    }
    c->auth_seconds = nondet_u64();
    c->suite = nondet_u16();
    c->alpn_len = nondet_u8();
    __CPROVER_assume(c->alpn_len <= CH_ALPN_NAME_MAX);
    fill_nondet(c->alpn, sizeof c->alpn);
    fill_nondet(c->psk, sizeof c->psk);
    return CH_OK;
}

size_t srv_ticket_seal(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t nonce[AEAD_NONCE],
                       const srv_ticket_contents *c, uint8_t *out, size_t cap) {
    __CPROVER_assert(__CPROVER_r_ok(key, SRV_TICKET_KEY_LEN), "seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "seal: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(c, sizeof *c), "seal: contents readable");
    __CPROVER_assert(c->alpn_len <= CH_ALPN_NAME_MAX, "seal: the name fits its field");
    if (cap < SRV_TICKET_LEN || nondet_int()) {
        return 0;
    }
    fill_nondet(out, SRV_TICKET_LEN);
    return SRV_TICKET_LEN;
}

void ks_early(const uint8_t *psk, size_t psk_len, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(psk, psk_len), "early: psk readable");
    __CPROVER_assert(resumption == 1, "early: a ticket's PSK takes the resumption label");
    fill_nondet(early, SHA256_LEN);
    fill_nondet(binder_key, SHA256_LEN);
}

void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(key, SHA256_LEN), "verify_data: key readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "verify_data: hash readable");
    fill_nondet(out, SHA256_LEN);
}

void ks_res_master(const uint8_t master[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                   uint8_t res_master[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(master, SHA256_LEN), "res_master: master readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "res_master: hash readable");
    fill_nondet(res_master, SHA256_LEN);
}

void ks_res_psk(const uint8_t res_master[SHA256_LEN], const uint8_t *nonce, size_t nonce_len,
                uint8_t psk[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(res_master, SHA256_LEN), "res_psk: secret readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, nonce_len), "res_psk: nonce readable");
    fill_nondet(psk, SHA256_LEN);
}

int hsr_transcript_hash(handshake_state *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(s, sizeof *s), "transcript: state readable");
    fill_nondet(out, SHA256_LEN);
    return CH_OK;
}

size_t srv_build_new_session_ticket(uint8_t *out, size_t cap, uint32_t lifetime, uint32_t age_add,
                                    const uint8_t *nonce, size_t nonce_len, const uint8_t *ticket,
                                    size_t ticket_len) {
    (void)age_add;
    __CPROVER_assert(lifetime >= 1 && lifetime <= SRV_TICKET_LIFETIME,
                     "ticket: a lifetime RFC 9846 admits and this build issues");
    __CPROVER_assert(__CPROVER_r_ok(nonce, nonce_len), "ticket: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(ticket, ticket_len), "ticket: ticket readable");
    if (nondet_int()) {
        return 0;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= cap);
    __CPROVER_assert(__CPROVER_w_ok(out, n), "ticket: message writable");
    return n;
}

static unsigned sends;

int srv_out_sealed(handshake_state *h, const uint8_t *pt, size_t n) {
    __CPROVER_assert(__CPROVER_r_ok(h, sizeof *h), "sealed: state readable");
    __CPROVER_assert(n > 0 && __CPROVER_r_ok(pt, n), "sealed: message readable");
    sends++;
    return nondet_int() ? CH_OK : CH_EIO;
}

// The hook's contract (rand.h): it writes every byte, so a draw is never
// all zero, which srv_resume.c asserts.
void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(p, n), "rand: output writable");
    fill_nondet(p, n);
    __CPROVER_assume(p[0] != 0);
}

#include "srv_resume.c"

static ch_tls t;
static handshake_state h;
static client_hello ch;
static selection sel;
static uint8_t identities[IDS_MAX];
static uint8_t binders[BINDERS_MAX];
static uint8_t ticket_key[SRV_TICKET_KEY_LEN];
static uint8_t names[2][CH_ALPN_NAME_MAX];
static ch_alpn_protocol protocols[2];

// The configuration and the session both calls read, every field through
// its own type. The ALPN list holds two names of any length the
// configuration rules admit.
static void fill_session(void) {
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    fill_nondet(ticket_key, sizeof ticket_key);
    t.cfg.srv.ticket_key = nondet_int() ? ticket_key : NULL;
    t.cfg.srv.now_seconds = nondet_u64();
    fill_nondet(names[0], sizeof names[0]);
    fill_nondet(names[1], sizeof names[1]);
    for (size_t i = 0; i < 2; i++) {
        protocols[i].name = names[i];
        protocols[i].name_len = nondet_size_t();
        __CPROVER_assume(protocols[i].name_len >= 1 && protocols[i].name_len <= CH_ALPN_NAME_MAX);
    }
    t.cfg.alpn_protocols = protocols;
    t.cfg.alpn_count = 2;
    t.alpn_selected = nondet_u8();
    __CPROVER_assume(t.alpn_selected < 2 || t.alpn_selected == CH_ALPN_NONE);
    t.suite = nondet_u16();
    t.psk_selected = nondet_u8();
    h.ticket_auth_seconds = nondet_u64();
}

static void prove_select(void) {
    fill_session();
    fill_nondet(identities, sizeof identities);
    fill_nondet(binders, sizeof binders);
    memset(&ch, 0, sizeof ch);
    ch.psk_identities = identities;
    ch.psk_identities_len = nondet_size_t();
    __CPROVER_assume(ch.psk_identities_len <= IDS_MAX);
    ch.psk_binders = binders;
    ch.psk_binders_len = nondet_size_t();
    __CPROVER_assume(ch.psk_binders_len <= BINDERS_MAX);
    ch.seen = nondet_u16();
    ch.psk_modes = nondet_u8();
    ch.alpn_selected = nondet_u8();
    __CPROVER_assume(ch.alpn_selected < 2 || ch.alpn_selected == CH_ALPN_NONE);
    fill_nondet(ch.binder_hash, sizeof ch.binder_hash);
    memset(&sel, 0, sizeof sel);
    sel.suite = nondet_u16();
    sel.hash_len = nondet_u8();
    sel.sigalg = nondet_u16();
    opened = 0;

    int rc = srv_select_auth(&h, &ch, &sel);

    __CPROVER_assert(rc == CH_OK || rc == CH_EAUTH || rc == CH_EPROTO,
                     "select answers one of its three codes");
    if (rc == CH_OK) {
        __CPROVER_assert(sel.psk_selected || sel.sigalg != 0,
                         "a handshake has a way to authenticate");
        // Every entry the walk passed over took at least six bytes, a
        // length, an empty identity and an age, and the selected one takes
        // a whole ticket's, so its index names an entry inside the list.
        __CPROVER_assert(!sel.psk_selected ||
                             (size_t)sel.psk_identity * 6 + 2 + SRV_TICKET_LEN + 4 <=
                                 ch.psk_identities_len,
                         "a selected ticket's index names an entry inside the list");
        __CPROVER_assert(!sel.psk_selected || opened > 0, "a selected ticket was opened");
        __CPROVER_assert(!sel.psk_selected || sel.sigalg == 0,
                         "a selected ticket leaves no scheme for a CertificateVerify");
    }
    if (rc == CH_EAUTH) {
        __CPROVER_assert(h.alert == ALERT_DECRYPT_ERROR && sel.psk_selected == 0,
                         "a binder refusal is decrypt_error and selects nothing");
    }
    if (rc == CH_EPROTO) {
        __CPROVER_assert(h.alert == ALERT_MISSING_EXTENSION || h.alert == ALERT_HANDSHAKE_FAILURE,
                         "no authentication path is one of the two alerts");
    }
    if (sel.psk_selected) {
        __CPROVER_assert(t.cfg.srv.ticket_key != NULL && t.cfg.srv.now_seconds != 0,
                         "a ticket is selected only with a key and a clock");
        __CPROVER_assert((ch.psk_modes & SRV_PSK_DHE_KE) != 0, "only under psk_dhe_ke");
    }
}

static void prove_issue(void) {
    fill_session();
    // srv_select_auth admitted a resumed handshake's ticket inside its
    // lifetime, which is the contract srv_resume.c asserts.
    if (t.psk_selected) {
        __CPROVER_assume(t.cfg.srv.now_seconds >= h.ticket_auth_seconds &&
                         t.cfg.srv.now_seconds - h.ticket_auth_seconds <= SRV_TICKET_LIFETIME);
    }
    sends = 0;

    int rc = srv_send_new_session_ticket(&h);

    __CPROVER_assert(rc == CH_OK || rc == CH_EIO || rc == CH_ECAP,
                     "issue answers one of its three codes");
    __CPROVER_assert(sends <= 1, "one ticket per connection");
    if (t.cfg.srv.ticket_key == NULL || t.cfg.srv.now_seconds == 0) {
        __CPROVER_assert(sends == 0 && rc == CH_OK, "no key or no clock issues nothing");
    }
    if (rc == CH_ECAP) {
        __CPROVER_assert(h.alert == ALERT_INTERNAL_ERROR, "a builder refusal is internal_error");
    }
}

int main(void) {
    prove_select();
    prove_issue();
    return 0;
}
