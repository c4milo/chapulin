// Proves: every builder in srv_message.c writes only inside the caller's
// buffer, for any capacity, and reports a length that fits the buffer it was
// given.
//
// Three properties, over unconstrained inputs at each builder's real bound.
// Memory safety and absence of UB, which is what the automatic checks
// discharge. The return contract srv_message.h states once for all of them:
// zero, or a length that fits cap. And the three refusals a builder makes on
// something other than cap -- a cert_data length past the three-byte field, a
// request_update that is neither of its two legal values, and a
// transport-parameters body past CH_TRANSPORT_PARAMS_MAX.
//
// The wbuf writer is real, not stubbed: refusing to overflow is its contract,
// and the point here is that each builder uses it correctly. Every operand is
// havocked again before the call that reads it, so no call inherits a value
// an earlier path constrained.
#include "harness.h"

#include <string.h>

uint16_t nondet_u16(void);

// For SRV_COOKIE_MAX alone: srv_build_hello_retry_request takes the bytes
// srv_cookie_mint produced, and that constant is the length bound the caller
// hands it. No call into srv_cookie.c is made here.
#include "srv_cookie.h"

#include "srv_message.c"

// Larger than any message these builders emit under the bounds below, so the
// capacity draw covers both a buffer that is enough and one that is not. The
// largest is the HelloRetryRequest at the longest cookie: 73 bytes of head
// and framing, 12 of supported_versions and key_share, and 123 of cookie.
#define OUT_MAX 256

// The longest signature this harness hands the CertificateVerify builder. The
// builder's only length-dependent step is the wb_bytes that copies it, so a
// short bound covers the copy; the arm above UINT16_MAX below covers the
// refusal, which returns before it reads a byte.
#define SIG_MAX 64

// The longest quic_transport_parameters body this harness hands the
// EncryptedExtensions builder, for the reason SIG_MAX is short: the one
// length-dependent step is the wb_bytes that copies it. The real cap is
// CH_TRANSPORT_PARAMS_MAX (cfg.h), which the second call below draws past to
// reach the refusal, and that arm returns before it reads a byte.
#define PARAMS_MAX 16

// The chain length the certificate cases run at. srv_certificate_message_len
// is the only call that walks it, one addition per entry.
#define CHAIN_MAX 2

// A fresh selection. Every member is drawn through its own type, never by
// filling the struct through a byte pointer, so each holds the whole range
// its type admits.
static selection nondet_selection(void) {
    selection sel;
    sel.suite = nondet_u16();
    sel.hash_len = nondet_u8();
    sel.group = nondet_u16();
    sel.sigalg = nondet_u16();
    sel.need_retry = nondet_u8();
    sel.psk_selected = nondet_u8();
    return sel;
}

static uint8_t out[OUT_MAX];
static uint8_t random32[SRV_RANDOM];
static uint8_t session_id[SRV_SESSION_ID_MAX];
static uint8_t share[CH_KEX_SERVER_SHARE];
static uint8_t cookie[SRV_COOKIE_MAX];
static uint8_t sig[SIG_MAX];
static uint8_t der[16];
static uint8_t params[PARAMS_MAX];

// Any capacity the buffer can hold, drawn fresh for every call.
static size_t nondet_cap(void) {
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);
    return cap;
}

// Any legacy_session_id length RFC 9846 §4.2.2 admits, which is what
// srv_parse_client_hello holds a ClientHello's to.
static size_t nondet_session_id_len(void) {
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= SRV_SESSION_ID_MAX);
    return len;
}

static void prove_hellos(void) {
    selection sel = nondet_selection();
    size_t cap = nondet_cap();
    fill_nondet(random32, sizeof random32);
    fill_nondet(session_id, sizeof session_id);
    fill_nondet(share, sizeof share);
    size_t n = srv_build_server_hello(out, cap, &sel, random32, session_id, nondet_session_id_len(),
                                      share, sizeof share);
    __CPROVER_assert(n <= cap, "a built ServerHello fits the buffer it was given");

    sel = nondet_selection();
    cap = nondet_cap();
    fill_nondet(session_id, sizeof session_id);
    fill_nondet(cookie, sizeof cookie);
    size_t cookie_len = nondet_size_t();
    __CPROVER_assume(cookie_len <= sizeof cookie);
    n = srv_build_hello_retry_request(out, cap, &sel, session_id, nondet_session_id_len(), cookie,
                                      cookie_len);
    __CPROVER_assert(n <= cap, "a built HelloRetryRequest fits the buffer it was given");
}

static void prove_fixed_records(void) {
    size_t cap = nondet_cap();
    size_t n = srv_build_compat_ccs(out, cap);
    __CPROVER_assert(n <= cap, "a built change_cipher_spec fits the buffer it was given");
    // The record's six bytes are fixed, so a capacity that holds them always
    // succeeds and reports exactly that length.
    __CPROVER_assert(cap < SRV_CCS_RECORD_LEN || n == SRV_CCS_RECORD_LEN,
                     "SRV_CCS_RECORD_LEN bytes always suffice for the dummy record");

    cap = nondet_cap();
    uint8_t request_update = nondet_u8();
    n = srv_build_key_update(out, cap, request_update);
    __CPROVER_assert(n <= cap, "a built KeyUpdate fits the buffer it was given");
    __CPROVER_assert(request_update <= 1 || n == 0,
                     "a request_update outside its two legal values is refused");
}

static void prove_encrypted_extensions(void) {
    size_t cap = nondet_cap();
    fill_nondet(sig, sizeof sig);
    ch_alpn_protocol selected;
    selected.name = sig;
    selected.name_len = nondet_size_t();
    __CPROVER_assume(selected.name_len <= CH_ALPN_NAME_MAX);
    fill_nondet(params, sizeof params);
    // Three arms, each drawn on its own: a NULL selection sends no ALPN
    // extension, a limit of 0 sends no record_size_limit, and a NULL body
    // sends no quic_transport_parameters.
    const ch_alpn_protocol *arm = (nondet_u8() & 1) ? &selected : NULL;
    const uint8_t *body = (nondet_u8() & 1) ? params : NULL;
    size_t body_len = nondet_size_t();
    __CPROVER_assume(body_len <= sizeof params);
    size_t n = srv_build_encrypted_extensions(out, cap, nondet_u16(), arm, body, body_len);
    __CPROVER_assert(n <= cap, "a built EncryptedExtensions fits the buffer it was given");

    // The refusal above CH_TRANSPORT_PARAMS_MAX. The builder returns before
    // it reads a byte of the body, so params goes in at a length it does not
    // hold and the call must still read none of it.
    cap = nondet_cap();
    body_len = nondet_size_t();
    __CPROVER_assume(body_len > CH_TRANSPORT_PARAMS_MAX);
    n = srv_build_encrypted_extensions(out, cap, nondet_u16(), NULL, params, body_len);
    __CPROVER_assert(n == 0, "a transport-parameters body past its cap is refused");
}

static void prove_certificate(void) {
    ch_cert chain[CHAIN_MAX];
    for (size_t i = 0; i < CHAIN_MAX; i++) {
        chain[i].der = der;
        chain[i].len = nondet_size_t();
        __CPROVER_assume(chain[i].len <= sizeof der);
    }
    ch_identity id;
    id.chain = chain;
    id.chain_count = nondet_u8();
    __CPROVER_assume(id.chain_count <= CHAIN_MAX);
    id.priv = NULL;
    id.priv_len = 0;
    id.pub = NULL;
    id.pub_len = 0;

    size_t total = srv_certificate_message_len(&id);
    __CPROVER_assert(total >= 8, "a Certificate message is never shorter than its fixed head");

    size_t cap = nondet_cap();
    size_t n = srv_build_certificate_header(out, cap, &id);
    __CPROVER_assert(n <= cap, "a built Certificate header fits the buffer it was given");
    __CPROVER_assert(n == 0 || n == 8, "a written Certificate header is eight bytes");

    cap = nondet_cap();
    size_t cert_len = nondet_size_t();
    n = srv_build_certificate_entry_prefix(out, cap, cert_len);
    __CPROVER_assert(n <= cap, "a built certificate entry prefix fits the buffer it was given");
    __CPROVER_assert(cert_len <= 0xFFFFFFu || n == 0,
                     "a cert_data length past the three-byte field is refused");

    cap = nondet_cap();
    n = srv_build_certificate_entry_suffix(out, cap);
    __CPROVER_assert(n <= cap, "a built certificate entry suffix fits the buffer it was given");
}

static void prove_signed_messages(void) {
    size_t cap = nondet_cap();
    fill_nondet(sig, sizeof sig);
    size_t sig_len = nondet_size_t();
    // The caller owes sig_len readable bytes, which SIG_MAX bounds. The
    // second arm is the refusal above the two-byte field, which the builder
    // answers before it reads the signature, so no readable bytes are owed
    // there.
    __CPROVER_assume(sig_len <= SIG_MAX || sig_len > UINT16_MAX);
    size_t n = srv_build_certificate_verify(out, cap, nondet_u16(), sig, sig_len);
    __CPROVER_assert(n <= cap, "a built CertificateVerify fits the buffer it was given");
    __CPROVER_assert((sig_len != 0 && sig_len <= UINT16_MAX) || n == 0,
                     "a signature length outside the two-byte field is refused");

    cap = nondet_cap();
    fill_nondet(sig, sizeof sig);
    size_t hash_len = nondet_size_t();
    __CPROVER_assume(hash_len <= SIG_MAX);
    n = srv_build_finished(out, cap, sig, hash_len);
    __CPROVER_assert(n <= cap, "a built Finished fits the buffer it was given");
}

int main(void) {
    prove_hellos();
    prove_fixed_records();
    prove_encrypted_extensions();
    prove_certificate();
    prove_signed_messages();
    return 0;
}
