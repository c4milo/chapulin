// Proves: handle_post_handshake and handle_ticket — the parsers that run over
// decrypted post-handshake bytes (NewSessionTicket and KeyUpdate) — are
// memory-safe and UB-free against ANY plaintext up to 128 bytes, and
// report a consumed length no larger than the input, that no ticket
// with a ticket_lifetime of 0 is handed to on_ticket, that a KeyUpdate
// rekeys only as the last message of the input, which RFC 9846 §5.1
// requires of the message before a key change, and that the parser
// writes two alerts, each only on a failure: decode_error for a message
// that does not parse (§6) and illegal_parameter for a request_update
// neither 0 nor 1 (§4.7.3). This is the last attacker-facing parser; a
// peer that reaches a connected session feeds it arbitrary decrypted
// bytes.
//
// It also proves the trust code of a raw or ca ticket memory-safe
// (docs/decisions.md 142): ticket_trust under a presented ticket, an
// external PSK or either pin slot, and hspost_trust_holds over pins and a
// PSK of up to 16 bytes, each of them set or unset. SHA-256 is a stub
// that asserts its contract.
//
// It also proves the run limit and the answer (docs/decisions.md 138),
// from any key_update_run, any key_update_owed and any send_epochs. The
// parser seals and sends nothing, so a request is answered by ch_write
// alone. Each rekey moves the read direction and adds one to
// key_update_run. A KeyUpdate after a run of CH_KEY_UPDATE_RUN_MAX
// returns CH_KEY_UPDATE_LIMIT with the caller's unexpected_message, and
// rekeys nothing. The limit refuses only a KeyUpdate that the other
// refusals admit: one byte long, with request_update 0 or 1, and the last
// five bytes of the input. key_update_owed changes only to 1, and only on
// a rekey below the sender's epoch cap.
//
// The full ch_read driver that calls this (record reading,
// cross-record reassembly, ch_write, ch_close) does not converge as one
// CBMC formula; its integration is covered by test/e2e.sh, the
// mock-transport unit tests, and fuzz/fuzz_handshake_post.c. Here the record I/O,
// crypto, and key schedule are stubs asserting their proven contracts,
// so what is under proof is the parser's own arithmetic. buf.c and ct.c
// are real.
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "io.h"
#include "keysched.h"
#include "record.h"
#include "session.h"

// The parser sends nothing: a KeyUpdate that asks for an answer sets
// key_update_owed, and ch_write sends the answer (tls_write.c).
int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    __CPROVER_assert(0, "send unreachable: the parser sends nothing");
    return CH_EIO;
}

int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer,
                   size_t *record_len) {
    (void)cfg;
    (void)buf;
    (void)cap;
    (void)outer;
    (void)record_len;
    // read_post_handshake never runs here; the harness drives handle_post_handshake on a
    // whole buffer that leaves no partial trailing message.
    __CPROVER_assert(0, "io_read_record unreachable from handle_post_handshake");
    return CH_EIO;
}

uint64_t nondet_u64(void);

// Typed stores: a byte-pointer fill through a member pointer makes
// every store a whole-object update of the enclosing struct in the
// SSA (docs/proofs.md).
static void fill_rec_dir_nondet(rec_dir *d) {
    fill_nondet(d->key, sizeof d->key);
    fill_nondet(d->iv, sizeof d->iv);
    d->seq = nondet_u64();
}

// The session under proof, which the rekey stub compares a direction with.
static ch_tls session;

// How many directions a KeyUpdate rekeyed, so main can tell whether one
// ran. The harness's own counter; it models nothing in the code.
static unsigned rekeys;

// A rekey here moves the read direction alone: the write direction moves
// when ch_write sends a KeyUpdate, which this parser never does.
void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "upd: secret writable");
    __CPROVER_assert(d == &session.rd && secret == session.rd_secret,
                     "upd: the read direction alone");
    rekeys++;
    fill_nondet(secret, SHA256_LEN);
    fill_rec_dir_nondet(d);
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)d;
    (void)type;
    (void)pt;
    (void)n;
    (void)out;
    (void)cap;
    (void)out_len;
    __CPROVER_assert(0, "seal unreachable: the parser seals nothing");
    return -1;
}

void ks_res_psk(size_t hash_len, const uint8_t *res_master, const uint8_t *nonce, size_t nonce_len,
                uint8_t *psk) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == HKDF_HASH_MAX,
                     "ks_res_psk: hash_len names a hash this build holds");
    __CPROVER_assert(__CPROVER_r_ok(res_master, hash_len), "res: master readable");
    __CPROVER_assert(nonce_len == 0 || __CPROVER_r_ok(nonce, nonce_len), "res: nonce readable");
    fill_nondet(psk, hash_len);
}

// The hash a raw or ca ticket's trust_hash takes (handshake_post.c's
// hspost_trust_hash): every byte it is handed is readable, and the digest
// lands in 32 writable bytes.
void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256: state writable");
}
void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256: state writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256: input readable");
}
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256: state writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256: digest writable");
    fill_nondet(out, SHA256_LEN);
}

// These exist so handshake_post.c links; handle_post_handshake never
// calls them.
void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    (void)secret;
    __CPROVER_assert(0, "rec_dir_init unreachable");
    fill_rec_dir_nondet(d);
}
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *pt_len,
             uint8_t *type) {
    (void)d;
    (void)rec;
    (void)n;
    (void)pt;
    (void)cap;
    (void)pt_len;
    (void)type;
    __CPROVER_assert(0, "rec_open unreachable");
    return -1;
}
int ch_handshake(ch_tls *t) {
    (void)t;
    __CPROVER_assert(0, "ch_handshake unreachable");
    return CH_EPROTO;
}

// Every pointer the driver hands the application must be readable, and no
// ticket it hands over has a lifetime of 0, which RFC 9846 §4.7.1 says to
// discard at once and every client entry refuses in a kept ticket.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    __CPROVER_assert(ticket->lifetime_s != 0, "cb: no ticket with a lifetime of 0");
    __CPROVER_assert(__CPROVER_r_ok(ticket->psk, sizeof ticket->psk), "cb: psk readable");
    __CPROVER_assert(ticket->identity_len == 0 ||
                         __CPROVER_r_ok(ticket->identity, ticket->identity_len),
                     "cb: identity readable");
}

#include "handshake_post.c"

// The trust a ticket can name (handshake_post.c's ticket_trust): two pin
// slots and an external PSK of up to 16 bytes each, and a presented ticket
// of any trust_hash.
static uint8_t pin_a[16];
static uint8_t pin_b[16];
static uint8_t external_psk[16];
static ch_saved_ticket presented;

// bytes, filled with any value, or NULL, an unset slot, under any length
// up to cap.
static const uint8_t *nondet_slot(uint8_t *bytes, size_t cap, size_t *len) {
    fill_nondet(bytes, cap);
    *len = nondet_size_t();
    __CPROVER_assume(*len <= cap);
    return (nondet_u8() & 1) ? bytes : NULL;
}

// What a connected session holds when a ticket arrives. A session that
// presented no ticket and holds no PSK authenticated by a pin, so
// ch_tls.pin_slot is 1 or 2 and that slot is set.
static void havoc_trust(void) {
    session.cfg.server_pubkey = nondet_slot(pin_a, sizeof pin_a, &session.cfg.server_pubkey_len);
    session.cfg.server_pubkey2 = nondet_slot(pin_b, sizeof pin_b, &session.cfg.server_pubkey2_len);
    session.cfg.psk = nondet_slot(external_psk, sizeof external_psk, &session.cfg.psk_len);
    fill_nondet(presented.ticket.trust_hash, sizeof presented.ticket.trust_hash);
    session.cfg.ticket = (nondet_u8() & 1) ? &presented : NULL;
    session.pin_slot = nondet_u8();
    if (session.cfg.ticket == NULL && session.cfg.psk == NULL) {
        __CPROVER_assume(session.pin_slot == 1
                             ? session.cfg.server_pubkey != NULL
                             : session.pin_slot == 2 && session.cfg.server_pubkey2 != NULL);
    }
}

int main(void) {
    memset(&session, 0, sizeof session);
    uint8_t buf[128];
    session.cfg.buf = buf;
    session.cfg.buf_len = sizeof buf;
    if (nondet_u8() & 1) {
        session.cfg.on_ticket = on_ticket;
    }
    fill_nondet(session.rd_secret, sizeof session.rd_secret);
    fill_nondet(session.wr_secret, sizeof session.wr_secret);
    fill_nondet(session.res_master, sizeof session.res_master);
    fill_rec_dir_nondet(&session.wr);
    fill_rec_dir_nondet(&session.rd);
    // Any epoch count, so both sides of the §4.7.3 sender cap are proven,
    // and any run and owed answer, so both sides of the run limit are.
    session.send_epochs = nondet_u64();
    session.key_update_run = nondet_u8();
    session.key_update_owed = nondet_u8() & 1;
    havoc_trust();
    uint8_t run_before = session.key_update_run;
    uint8_t owed_before = session.key_update_owed;

    uint8_t pt[128];
    fill_nondet(pt, sizeof pt);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    size_t used = nondet_size_t();
    // What hspost_read sets before it calls the parser.
    uint8_t alert = ALERT_UNEXPECTED_MESSAGE;
    int rc = handle_post_handshake(&session, pt, n, &used, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO || rc == CH_KEY_UPDATE_LIMIT,
                     "the parser succeeds, refuses the peer's bytes, or meets the run limit");
    // The parser writes two alerts, each only on a failure: decode_error
    // for a KeyUpdate body that is not one byte or a NewSessionTicket whose
    // fields do not fill it (RFC 9846 §6), and illegal_parameter for a
    // KeyUpdate whose request_update is neither 0 nor 1 (§4.7.3). Every
    // other refusal keeps the caller's, the run limit's among them.
    __CPROVER_assert(
        alert == ALERT_UNEXPECTED_MESSAGE ||
            ((alert == ALERT_DECODE_ERROR || alert == ALERT_ILLEGAL_PARAMETER) && rc == CH_EPROTO),
        "only a refused length or request_update writes an alert");
    // One KeyUpdate at most, as the last message of the input, and each
    // rekey is one more of the run, which the limit admitted.
    __CPROVER_assert(rekeys <= 1, "one rekey at most");
    __CPROVER_assert(rekeys == 0 ? session.key_update_run == run_before
                                 : run_before < CH_KEY_UPDATE_RUN_MAX &&
                                       session.key_update_run == run_before + 1,
                     "a rekey adds one to a run below the limit");
    __CPROVER_assert(rc != CH_KEY_UPDATE_LIMIT ||
                         (rekeys == 0 && run_before >= CH_KEY_UPDATE_RUN_MAX),
                     "the run limit refuses before the rekey, and only at a full run");
    // The refusals of INV-14 and INV-39 come first, so the KeyUpdate the
    // limit refuses is one that each of them admits: a body of one byte
    // that holds 0 or 1, and nothing after it in the input.
    __CPROVER_assert(rc != CH_KEY_UPDATE_LIMIT ||
                         (n >= 5 && pt[n - 5] == HS_KEY_UPDATE && pt[n - 4] == 0 &&
                          pt[n - 3] == 0 && pt[n - 2] == 1 && pt[n - 1] <= 1),
                     "the run limit refuses only a KeyUpdate the other refusals admit");
    __CPROVER_assert(session.key_update_owed == owed_before ||
                         (session.key_update_owed == 1 && rekeys == 1 &&
                          session.send_epochs < HSPOST_SEND_EPOCHS_MAX),
                     "an answer is owed only after a rekey below the sender's cap");
    if (rc == CH_OK) {
        __CPROVER_assert(used <= n, "consumed no more than the input");
        // pt[0..n) ends where the newest record ends, so a KeyUpdate that
        // rekeyed a direction was the last message of its record (RFC
        // 9846 §5.1).
        __CPROVER_assert(rekeys == 0 || used == n, "a KeyUpdate ends the input");
    }
    // The check every client entry runs on a presented ticket, over the
    // same slots, any of them unset: it reads each set slot for its length
    // alone, and answers 0 or 1.
    int held = hspost_trust_holds(&session.cfg, &presented.ticket);
    __CPROVER_assert(held == 0 || held == 1, "the trust check answers 0 or 1");
    return 0;
}
