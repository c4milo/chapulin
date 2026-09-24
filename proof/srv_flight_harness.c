// Proves: the fifteen srv_flight.h handlers are memory safe and free of
// UB over an unconstrained ClientHello, selection and session, and that
// every refusal but a failed send leaves h->alert holding a description
// somebody wrote.
//
// The layering is proof/srv_accept_harness.c's, turned around. There the
// driver was real and these fifteen were contract stubs; here they are
// real and everything they call is one: the parser, the nine builders,
// the cookie, srv_auth.h's and srv_resume.h's entries, the record reader,
// the key schedule, the record layer and the I/O shim. Each stub asserts
// what its header requires of a caller and havocs what its header says
// it writes. ct.c is real, because the wipes and the two constant-time
// comparisons are this file's own steps.
//
// What the alert assertion means. The chain that holds srv_flight.h's failure
// rule runs through four callees whose headers promise the same thing:
// hsr_next_msg, srv_parse_client_hello, srv_select_auth and
// srv_sign_certificate_verify each write the description they chose. So the
// stubs write one on every refusal, and the assertion below reads a byte no
// handler and no stub writes.
//
// Three bounds are the harness's, not the build's: CHAIN_MAX entries in a
// chain, DER_MAX bytes in a certificate and LIMIT_MAX for the peer's record
// limit. The first two bound a walk over the caller's flash; the third bounds
// the fragment loop, and a larger limit runs it fewer times, not more.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "io.h"
#include "keysched.h"
#include "record.h"
#include "srv_flight.h"
#include "x25519.h"

int nondet_int(void);
uint16_t nondet_u16(void);

// The alert byte no handler and no stub writes.
#define ALERT_UNWRITTEN 0xff

#define MSG_MAX 16   // the longest message the record reader yields
#define NAME_MAX 8   // the longest server_name a hello carries here
#define DER_MAX 8    // the longest certificate in the chain below
#define CHAIN_MAX 2  // the longest chain an identity holds here
#define LIMIT_MAX 16 // the largest record limit the peer asks for

static ch_tls t;
static handshake_state h;
static client_hello hello;
static selection sel;
static uint8_t message[MSG_MAX];
static uint8_t name_bytes[NAME_MAX];
static uint8_t cookie_bytes[SRV_COOKIE_MAX];
static uint8_t share_bytes[CH_KEX_CLIENT_SHARE];
static uint8_t sni_area[NAME_MAX];
static uint8_t der_bytes[CHAIN_MAX][DER_MAX];
static ch_cert chain[CHAIN_MAX];
static ch_identity identity;
static uint8_t rxbuf[MSG_MAX];

// One return code out of the set a callee's header names.
static int nondet_rc(int allow_eio, int allow_eauth) {
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_ECAP || rc == CH_EINVAL ||
                     (allow_eio && rc == CH_EIO) || (allow_eauth && rc == CH_EAUTH));
    return rc;
}

// What a callee whose header promises a description would write.
static void write_alert(uint8_t *alert) {
    *alert = nondet_u8();
    __CPROVER_assume(*alert != ALERT_UNWRITTEN);
}

void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "rand: output writable");
    fill_nondet(p, n);
    // rand.h's contract: an all-zero draw is a hook that returned
    // without writing, which the handlers catch with CH_ASSERT.
    __CPROVER_assume(n == 0 || p[0] != 0);
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN], const uint8_t point[32]) {
    __CPROVER_assert(__CPROVER_w_ok(out, X25519_LEN), "x25519: output writable");
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x25519: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(point, X25519_LEN), "x25519: point readable");
    fill_nondet(out, X25519_LEN);
    return nondet_int();
}

void x25519_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(out, X25519_LEN), "x25519_base: output writable");
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x25519_base: scalar readable");
    fill_nondet(out, X25519_LEN);
}

void ks_early(const uint8_t *psk, size_t psk_len, int resumption, uint8_t early[SHA256_LEN],
              uint8_t binder_key[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(psk, psk_len), "ks_early: psk readable");
    (void)resumption;
    fill_nondet(early, SHA256_LEN);
    fill_nondet(binder_key, SHA256_LEN);
}

void ks_handshake(const uint8_t early[SHA256_LEN], const uint8_t *ecdhe, size_t ecdhe_len,
                  const uint8_t transcript[SHA256_LEN], uint8_t handshake_secret[SHA256_LEN],
                  uint8_t c_hs[SHA256_LEN], uint8_t s_hs[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(early, SHA256_LEN), "ks_handshake: early readable");
    __CPROVER_assert(__CPROVER_r_ok(ecdhe, ecdhe_len), "ks_handshake: shared secret readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks_handshake: transcript readable");
    fill_nondet(handshake_secret, SHA256_LEN);
    fill_nondet(c_hs, SHA256_LEN);
    fill_nondet(s_hs, SHA256_LEN);
}

void ks_verify_data(const uint8_t key[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
                    uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(key, SHA256_LEN), "verify_data: key readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "verify_data: transcript readable");
    fill_nondet(out, SHA256_LEN);
}

void ks_master(const uint8_t handshake_secret[SHA256_LEN], const uint8_t transcript[SHA256_LEN],
               uint8_t master[SHA256_LEN], uint8_t c_ap[SHA256_LEN], uint8_t s_ap[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(handshake_secret, SHA256_LEN), "ks_master: secret readable");
    __CPROVER_assert(__CPROVER_r_ok(transcript, SHA256_LEN), "ks_master: transcript readable");
    fill_nondet(master, SHA256_LEN);
    fill_nondet(c_ap, SHA256_LEN);
    fill_nondet(s_ap, SHA256_LEN);
}

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "rec_dir_init: direction writable");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "rec_dir_init: secret readable");
    fill_nondet((uint8_t *)d, sizeof *d);
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)type;
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "seal: direction writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: plaintext readable");
    size_t total = REC_HDR + n + 1 + AEAD_TAG;
    if (total > cap) {
        return -1;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, total), "seal: output writable");
    *out_len = total;
    return 0;
}

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg != NULL, "send: cfg valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: bytes readable");
    return (nondet_u8() & 1) ? CH_OK : CH_EIO;
}

int hsr_next_msg(handshake_state *s, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "next_msg: state writable");
    int rc = nondet_rc(1, 1);
    __CPROVER_assume(rc != CH_EINVAL);
    if (rc != CH_OK) {
        // handshake_record.h has the reader choose the description for
        // every code it reports but CH_ECAP, which the caller answers.
        if (rc != CH_ECAP) {
            write_alert(&s->alert);
        }
        return rc;
    }
    fill_nondet(message, sizeof message);
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 4 && n <= sizeof message);
    *type = nondet_u8();
    *raw = message;
    *raw_len = n;
    return CH_OK;
}

int hsr_transcript_hash(handshake_state *s, uint8_t out[SHA256_LEN]) {
    (void)s;
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "transcript hash: output writable");
    fill_nondet(out, SHA256_LEN);
    return CH_OK;
}

// Everything srv_parse_client_hello writes, each member through its own
// type.
static void fill_hello(client_hello *ch) {
    fill_nondet(ch->random, sizeof ch->random);
    fill_nondet(ch->session_id, sizeof ch->session_id);
    ch->session_id_len = nondet_u8();
    __CPROVER_assume(ch->session_id_len <= SRV_SESSION_ID_MAX);
    ch->suites = nondet_u8();
    ch->groups = nondet_u8();
    ch->shares = nondet_u8();
    ch->sigalgs = nondet_u8();
    // srv_parser.h refuses a share for this group at any other length.
    ch->share = (nondet_u8() & 1) ? share_bytes : NULL;
    ch->share_len = CH_KEX_CLIENT_SHARE;
    ch->cookie = (nondet_u8() & 1) ? cookie_bytes : NULL;
    ch->cookie_len = nondet_size_t();
    __CPROVER_assume(ch->cookie_len <= sizeof cookie_bytes);
    ch->server_name = (nondet_u8() & 1) ? name_bytes : NULL;
    ch->server_name_len = nondet_size_t();
    __CPROVER_assume(ch->server_name_len <= sizeof name_bytes);
    ch->alpn_selected = nondet_u8();
    ch->record_size_limit = nondet_u16();
    ch->psk_modes = nondet_u8();
    ch->truncated_len = nondet_size_t();
    ch->seen = nondet_u16();
    fill_nondet(ch->frozen, sizeof ch->frozen);
}

int srv_parse_client_hello(const uint8_t *body, size_t n, client_hello *ch,
                           const ch_alpn_protocol *offered, size_t offered_count, uint8_t *alert) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "parse: body readable");
    __CPROVER_assert(__CPROVER_w_ok(ch, sizeof *ch), "parse: hello writable");
    (void)offered;
    (void)offered_count;
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO);
    if (rc != CH_OK) {
        write_alert(alert);
        return rc;
    }
    fill_hello(ch);
    return CH_OK;
}

// The nine builders, each reporting srv_message.h's one return
// convention: a length that fits the buffer it was given, or 0.
static size_t nondet_built(uint8_t *out, size_t cap) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= cap && n <= MSG_MAX);
    __CPROVER_assert(cap == 0 || __CPROVER_w_ok(out, cap), "build: output writable");
    if (nondet_u8() & 1) {
        return 0;
    }
    return n;
}

size_t srv_build_server_hello(uint8_t *out, size_t cap, const selection *s,
                              const uint8_t random32[SRV_RANDOM], const uint8_t *session_id,
                              size_t session_id_len, const uint8_t *share, size_t share_len) {
    __CPROVER_assert(__CPROVER_r_ok(s, sizeof *s), "server hello: selection readable");
    __CPROVER_assert(__CPROVER_r_ok(random32, SRV_RANDOM), "server hello: random readable");
    __CPROVER_assert(session_id_len == 0 || __CPROVER_r_ok(session_id, session_id_len),
                     "server hello: session id readable");
    __CPROVER_assert(__CPROVER_r_ok(share, share_len), "server hello: share readable");
    return nondet_built(out, cap);
}

size_t srv_build_hello_retry_request(uint8_t *out, size_t cap, const selection *s,
                                     const uint8_t *session_id, size_t session_id_len,
                                     const uint8_t *cookie, size_t cookie_len) {
    __CPROVER_assert(__CPROVER_r_ok(s, sizeof *s), "retry: selection readable");
    __CPROVER_assert(session_id_len == 0 || __CPROVER_r_ok(session_id, session_id_len),
                     "retry: session id readable");
    __CPROVER_assert(__CPROVER_r_ok(cookie, cookie_len), "retry: cookie readable");
    return nondet_built(out, cap);
}

size_t srv_build_compat_ccs(uint8_t *out, size_t cap) {
    __CPROVER_assert(__CPROVER_w_ok(out, cap), "ccs: output writable");
    // srv_message.h fixes this record at six bytes.
    return cap >= SRV_CCS_RECORD_LEN ? (size_t)SRV_CCS_RECORD_LEN : 0;
}

size_t srv_build_encrypted_extensions(uint8_t *out, size_t cap, uint16_t record_size_limit,
                                      const ch_alpn_protocol *selected,
                                      const uint8_t *transport_params,
                                      size_t transport_params_len) {
    (void)record_size_limit;
    __CPROVER_assert(selected == NULL || __CPROVER_r_ok(selected, sizeof *selected),
                     "ee: protocol readable");
    __CPROVER_assert(transport_params == NULL && transport_params_len == 0, "ee: no QUIC body");
    return nondet_built(out, cap);
}

size_t srv_build_certificate_header(uint8_t *out, size_t cap, const ch_identity *id) {
    __CPROVER_assert(__CPROVER_r_ok(id, sizeof *id), "certificate head: identity readable");
    __CPROVER_assert(__CPROVER_w_ok(out, cap), "certificate head: output writable");
    return cap >= 8 ? (size_t)8 : 0; // srv_message.h fixes the head at eight bytes
}

size_t srv_build_certificate_entry_prefix(uint8_t *out, size_t cap, size_t cert_len) {
    __CPROVER_assert(__CPROVER_w_ok(out, cap), "certificate entry: output writable");
    // srv_message.h: three fixed bytes, and 0 past the cert_data field.
    return (cert_len > 0xFFFFFFu || cap < 3) ? (size_t)0 : (size_t)3;
}

size_t srv_build_certificate_entry_suffix(uint8_t *out, size_t cap) {
    __CPROVER_assert(__CPROVER_w_ok(out, cap), "certificate suffix: output writable");
    return cap >= 2 ? (size_t)2 : 0;
}

size_t srv_build_certificate_verify(uint8_t *out, size_t cap, uint16_t sigalg, const uint8_t *sig,
                                    size_t sig_len) {
    (void)sigalg;
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len),
                     "cert verify: signature readable");
    return nondet_built(out, cap);
}

size_t srv_build_finished(uint8_t *out, size_t cap, const uint8_t *verify_data, size_t hash_len) {
    __CPROVER_assert(__CPROVER_r_ok(verify_data, hash_len), "finished: verify_data readable");
    __CPROVER_assert(__CPROVER_w_ok(out, cap), "finished: output writable");
    // srv_message.h fixes it at the header and one verify_data.
    return cap >= 4 + hash_len ? 4 + hash_len : 0;
}

size_t srv_cookie_mint(const uint8_t key[SRV_COOKIE_KEY_LEN], uint16_t suite, uint16_t group,
                       const uint8_t *ch1_hash, size_t hash_len, const uint8_t frozen[SHA256_LEN],
                       uint8_t *out, size_t cap) {
    (void)suite;
    (void)group;
    __CPROVER_assert(__CPROVER_r_ok(key, SRV_COOKIE_KEY_LEN), "mint: key readable");
    __CPROVER_assert(__CPROVER_r_ok(ch1_hash, hash_len), "mint: transcript hash readable");
    __CPROVER_assert(__CPROVER_r_ok(frozen, SHA256_LEN), "mint: frozen digest readable");
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= cap && n <= SRV_COOKIE_MAX);
    __CPROVER_assert(cap == 0 || __CPROVER_w_ok(out, cap), "mint: output writable");
    if (nondet_u8() & 1) {
        return 0;
    }
    fill_nondet(out, n);
    return n;
}

int srv_cookie_open(const uint8_t key[SRV_COOKIE_KEY_LEN], const uint8_t *cookie, size_t n,
                    uint16_t *suite, uint16_t *group, uint8_t *ch1_hash, size_t *hash_len,
                    uint8_t frozen[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(key, SRV_COOKIE_KEY_LEN), "open: key readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(cookie, n), "open: cookie readable");
    __CPROVER_assert(__CPROVER_w_ok(ch1_hash, SRV_COOKIE_HASH_MAX), "open: hash writable");
    if (nondet_u8() & 1) {
        return CH_EPROTO;
    }
    *suite = nondet_u16();
    *group = nondet_u16();
    size_t len = nondet_size_t();
    __CPROVER_assume(len >= SHA256_LEN && len <= SRV_COOKIE_HASH_MAX);
    *hash_len = len;
    fill_nondet(ch1_hash, len);
    fill_nondet(frozen, SHA256_LEN);
    return CH_OK;
}

uint8_t srv_identity_live(const ch_cfg *cfg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "identity_live: cfg readable");
    return nondet_u8();
}

#include "srv_select_stubs.h"
const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "identity_for: cfg readable");
    (void)sigalg;
    return (nondet_u8() & 1) ? &identity : NULL;
}

int srv_sign_certificate_verify(const ch_cfg *cfg, uint16_t sigalg, const uint8_t *transcript_hash,
                                size_t hash_len, uint8_t *sig, size_t cap, size_t *sig_len,
                                uint8_t *alert) {
    (void)cfg;
    (void)sigalg;
    __CPROVER_assert(__CPROVER_r_ok(transcript_hash, hash_len), "sign: transcript readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, cap), "sign: signature buffer writable");
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EINVAL || rc == CH_ECAP);
    if (rc != CH_OK) {
        write_alert(alert);
        return rc;
    }
    // The bytes are not filled: the only reader is the stubbed builder
    // above, and a fill over SRV_SIG_MAX costs 384 loop iterations.
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= cap);
    *sig_len = n;
    return CH_OK;
}

#include "srv_flight.c"

// The session and the handshake state as srv_handshake.c seeds them,
// with every field a handler reads havocked through its own type.
static void fresh(void) {
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    h.alert = ALERT_UNWRITTEN;
    h.record_size_limit = nondet_u16();
    t.cfg.buf = rxbuf;
    t.cfg.buf_len = sizeof rxbuf;
    t.cfg.srv.cookie_key = cookie_bytes;
    t.cfg.srv.sni_buf = (nondet_u8() & 1) ? sni_area : NULL;
    t.cfg.srv.sni_cap = nondet_size_t();
    __CPROVER_assume(t.cfg.srv.sni_cap <= sizeof sni_area);
    t.cfg.srv.require_server_name = nondet_u8();
    t.alpn_selected = CH_ALPN_NONE;
    t.hash_len = SHA256_LEN;
    // store_selection writes peer_limit only from a nonzero
    // record_size_limit, so the fragment loops below never see 0.
    t.peer_limit = nondet_u16();
    __CPROVER_assume(t.peer_limit >= 1 && t.peer_limit <= LIMIT_MAX);
    fill_nondet(h.priv, sizeof h.priv);
    fill_nondet(h.pub, sizeof h.pub);
    fill_nondet(h.c_hs, sizeof h.c_hs);
    fill_nondet(h.s_hs, sizeof h.s_hs);
    fill_nondet(h.handshake_secret, sizeof h.handshake_secret);
    fill_hello(&hello);
    sel.suite = nondet_u16();
    sel.hash_len = SHA256_LEN; // this build's one transcript hash
    sel.group = nondet_u16();
    sel.sigalg = nondet_u16();
    sel.need_retry = nondet_u8();
    sel.psk_selected = nondet_u8();
}

// srv_flight.h's failure rule, read off the byte nothing else writes.
// CH_EIO is outside it: a send that did not happen has no peer to tell,
// so no handler chooses a description for one and the driver's seed is
// what tlsi_fail passes. The client's handlers propagate hsr_next_msg's
// CH_EIO the same way.
static void refusal_wrote_alert(int rc) {
    if (rc != CH_OK && rc != CH_EIO) {
        __CPROVER_assert(h.alert != ALERT_UNWRITTEN,
                         "a handler that refuses writes the alert it chose");
    }
}

int main(void) {
    for (size_t i = 0; i < CHAIN_MAX; i++) {
        fill_nondet(der_bytes[i], DER_MAX);
        chain[i].der = der_bytes[i];
        chain[i].len = nondet_size_t();
        __CPROVER_assume(chain[i].len <= DER_MAX);
    }
    identity.chain = chain;
    identity.chain_count = nondet_u8();
    __CPROVER_assume(identity.chain_count <= CHAIN_MAX);

    fresh();
    srv_begin(&h);

    fresh();
    refusal_wrote_alert(srv_read_client_hello(&h, &hello));

    fresh();
    refusal_wrote_alert(srv_select(&h, &hello, &sel));

    fresh();
    refusal_wrote_alert(srv_send_hello_retry_request(&h, &hello, &sel));

    fresh();
    refusal_wrote_alert(srv_send_compat_ccs(&h, &hello));

    fresh();
    int rc = srv_check_retry_hello(&h, &hello, &sel);
    refusal_wrote_alert(rc);
    if (rc == CH_OK) {
        // The driver's one retry rests on this.
        __CPROVER_assert(sel.need_retry == 0, "a checked retry hello asks for no second retry");
    }

    fresh();
    refusal_wrote_alert(srv_send_server_hello(&h, &hello, &sel));

    fresh();
    __CPROVER_assume(hello.share != NULL);
    rc = srv_derive_handshake_secrets(&h, &hello, &sel);
    refusal_wrote_alert(rc);
    {
        // The exchange is over on both exits.
        static const uint8_t gone[X25519_LEN] = {0};
        __CPROVER_assert(ct_memeq(h.priv, gone, sizeof h.priv) != 0, "the scalar is wiped");
        __CPROVER_assert(ct_memeq(h.pub, gone, sizeof h.pub) != 0, "the public value is wiped");
    }

    fresh();
    refusal_wrote_alert(srv_send_encrypted_extensions(&h, &sel));

    fresh();
    refusal_wrote_alert(srv_send_certificate(&h, &sel));

    fresh();
    refusal_wrote_alert(srv_send_certificate_verify(&h, &sel));

    fresh();
    refusal_wrote_alert(srv_send_finished(&h));

    fresh();
    refusal_wrote_alert(srv_read_client_finished(&h));

    fresh();
    srv_complete(&h);
    __CPROVER_assert(t.state == CH_ST_CONNECTED, "the flight ends connected");
    return 0;
}
