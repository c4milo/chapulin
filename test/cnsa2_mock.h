// The server half of a PROFILE=cnsa2 handshake, for test/cnsa2_test.c
// and test/cnsa2_quic_test.c. It writes plaintext handshake messages and
// the secrets that key them; each test carries the bytes over its own
// transport, records or CRYPTO bytes. It checks the client's SHA-384
// binder and Finished, encapsulates against the client's ML-KEM-1024 key
// and issues one ticket. Under CH_PIN_MLDSA a hello with no PSK gets the
// Certificate the test names and a CertificateVerify that the test-only
// ML-DSA-87 signer signs (test/mldsa_sign.h, docs/decisions.md 157).
// Include it after CHECK, buf.h, keysched.h, mlkem.h, transcript.h and
// test/hello_exts.h. Not a standalone translation unit.
#ifndef CH_CNSA2_MOCK_H
#define CH_CNSA2_MOCK_H

// The binder is SHA384_LEN bytes: the pre_shared_key extension ends in a
// 2-byte list length, a 1-byte binder length and the binder.
#define BINDER_TAIL (2 + 1 + SHA384_LEN)

#ifdef CH_PIN_MLDSA
#include "mldsa_sign.h"
#endif

static const uint8_t external_psk[SHA384_LEN] = {0x5a, 0x01, 0x02};
static const uint8_t external_id[] = {'d', 'e', 'v', 'i', 'c', 'e', '1'};
static const uint8_t ticket_id[] = {'t', 'i', 'c', 'k', 'e', 't', '-', '1'};
static const uint8_t ticket_nonce[2] = {0x00, 0x01};
static const uint8_t server_m[32] = {0x4b, 0x3a};

// The resumption master of the last whole handshake, which the mock of
// the next one reads to check the binder of the ticket.
static uint8_t issued_res_master[SHA384_LEN];

// hello is the ClientHello the mock answers. sh_suite, sh_group and
// ct_trim, when not 0, put a suite, a group or a short ciphertext in the
// ServerHello that the client must refuse.
typedef struct {
    uint8_t hello[CH_TX_STAGE];
    size_t hello_len;
    uint16_t sh_suite;
    uint16_t sh_group;
    size_t ct_trim;
    int binder_ok;
    int resumed; // the hello offered the ticket a mock issued
    int client_finished_ok;
    int pinned; // the hello offered no PSK, so the server authenticates by signature
#ifdef CH_PIN_MLDSA
    const uint8_t *cert_list; // the CertificateEntry list the Certificate carries
    size_t cert_list_len;
    const mldsa_test_key *signer; // the key that signs the CertificateVerify
    uint16_t cv_scheme;           // when not 0, the scheme the CertificateVerify names
    int cv_flip;                  // when not 0, the signature's byte 0 is flipped
    int cv_delta;                 // bytes the signature's length moves by
#endif
    ch_transcript transcript;
    uint8_t handshake_secret[SHA384_LEN];
    uint8_t c_hs[SHA384_LEN];
    uint8_t s_hs[SHA384_LEN];
    uint8_t master[SHA384_LEN];
    uint8_t c_ap[SHA384_LEN];
    uint8_t s_ap[SHA384_LEN];
} cnsa2_mock;

// The PSK the hello's one identity names: the external PSK, or the
// ticket's, which RFC 9846 §4.6.1 derives from the resumption master.
// Returns 0 when the hello names neither.
static int mock_hello_psk(cnsa2_mock *m, uint8_t psk[SHA384_LEN], size_t *psk_len) {
    size_t len = 0;
    const uint8_t *ext = hello_ext(m->hello, m->hello_len, EXT_PRE_SHARED_KEY, &len);
    if (ext == NULL || len < 4) {
        return 0;
    }
    size_t id_len = ((size_t)ext[2] << 8) | ext[3];
    if (len < 4 + id_len) {
        return 0;
    }
    if (id_len == sizeof external_id && memcmp(ext + 4, external_id, id_len) == 0) {
        memcpy(psk, external_psk, sizeof external_psk);
        *psk_len = sizeof external_psk;
        return 1;
    }
    if (id_len == sizeof ticket_id && memcmp(ext + 4, ticket_id, id_len) == 0) {
        ks_res_psk(SHA384_LEN, issued_res_master, ticket_nonce, sizeof ticket_nonce, psk);
        *psk_len = SHA384_LEN;
        m->resumed = 1;
        return 1;
    }
    return 0;
}

// Checks the binder over the truncated hello (RFC 9846 §4.2.11.2) and
// writes the early secret.
static void mock_check_binder(cnsa2_mock *m, uint8_t early[SHA384_LEN]) {
    uint8_t psk[SHA384_LEN];
    size_t psk_len = 0;
    CHECK(mock_hello_psk(m, psk, &psk_len));
    uint8_t binder_key[SHA384_LEN];
    ks_early(SHA384_LEN, psk, psk_len, m->resumed, early, binder_key);
    CHECK(m->hello_len > BINDER_TAIL);
    const uint8_t *tail = m->hello + m->hello_len - BINDER_TAIL;
    CHECK(tail[0] == 0 && tail[1] == 1 + SHA384_LEN && tail[2] == SHA384_LEN);
    uint8_t hash[SHA384_LEN];
    ch_transcript t;
    transcript_init(&t);
    transcript_hash_after(&t, SHA384_LEN, m->hello, m->hello_len - BINDER_TAIL, hash);
    uint8_t want[SHA384_LEN];
    ks_verify_data(SHA384_LEN, binder_key, hash, want);
    m->binder_ok = memcmp(want, tail + 3, SHA384_LEN) == 0;
}

// Writes the ServerHello into out and returns its length, and derives the
// handshake traffic secrets.
static size_t mock_server_hello(cnsa2_mock *m, uint8_t *out, size_t cap) {
    uint8_t early[SHA384_LEN];
    size_t psk_len = 0;
    m->pinned = hello_ext(m->hello, m->hello_len, EXT_PRE_SHARED_KEY, &psk_len) == NULL;
    if (m->pinned) {
        // No PSK: the early secret is Extract(0, 0^48) (RFC 9846 §7.1).
        static const uint8_t zeros[SHA384_LEN];
        uint8_t binder_key[SHA384_LEN];
        ks_early(SHA384_LEN, zeros, sizeof zeros, 0, early, binder_key);
    } else {
        mock_check_binder(m, early);
    }
    size_t ek_len = 0;
    const uint8_t *ek = hello_key_share(m->hello, m->hello_len, CH_GROUP_MLKEM1024, &ek_len);
    CHECK(ek != NULL && ek_len == MLKEM_EK_LEN);
    uint8_t ct[MLKEM_CT_LEN] = {0};
    uint8_t ss[MLKEM_SS_LEN] = {0};
    CHECK(ek != NULL && mlkem_encaps_derand(TEST_WIDEMUL, ct, ss, ek, server_m) == 0);
    size_t ct_len = MLKEM_CT_LEN - m->ct_trim;
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, 0x42);
    }
    wb_u8(&w, 0);
    wb_u16(&w, m->sh_suite != 0 ? m->sh_suite : SUITE_AES_256_GCM_SHA384);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, (uint16_t)(2 + 2 + ct_len));
    wb_u16(&w, m->sh_group != 0 ? m->sh_group : CH_GROUP_MLKEM1024);
    wb_u16(&w, (uint16_t)ct_len);
    wb_bytes(&w, ct, ct_len);
    if (!m->pinned) {
        wb_u16(&w, EXT_PRE_SHARED_KEY);
        wb_u16(&w, 2);
        wb_u16(&w, 0); // the hello's one identity
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);

    transcript_init(&m->transcript);
    transcript_update(&m->transcript, m->hello, m->hello_len);
    transcript_update(&m->transcript, out, w.len);
    uint8_t hash[SHA384_LEN];
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    ks_handshake(SHA384_LEN, early, ss, sizeof ss, hash, m->handshake_secret, m->c_hs, m->s_hs);
    return w.len;
}

#ifdef CH_PIN_MLDSA
// Writes the Certificate and the CertificateVerify after the w->len bytes
// already in w, and adds both to the transcript. The signature covers RFC
// 9846 §4.4.3's content: 64 spaces, the context string with its NUL, and
// the transcript hash through the Certificate.
static void mock_certificate(cnsa2_mock *m, wbuf *w) {
    size_t at = w->len;
    wb_u8(w, HS_CERTIFICATE);
    size_t body = wb_mark(w, 3);
    wb_u8(w, 0); // empty certificate_request_context
    wb_u24(w, (uint32_t)m->cert_list_len);
    wb_bytes(w, m->cert_list, m->cert_list_len);
    wb_patch24(w, body);
    CHECK(!w->err);
    transcript_update(&m->transcript, w->p + at, w->len - at);
    uint8_t hash[SHA384_LEN];
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    static const char context[] = "TLS 1.3, server CertificateVerify";
    uint8_t content[64 + sizeof context + SHA384_LEN];
    memset(content, ' ', 64);
    memcpy(content + 64, context, sizeof context);
    memcpy(content + 64 + sizeof context, hash, sizeof hash);
    static const uint8_t no_rnd[32];
    static uint8_t sig[MLDSA87_SIG_LEN + 1];
    CHECK(mldsa_test_sign(m->signer, content, sizeof content, NULL, 0, no_rnd, sig));
    sig[0] ^= (uint8_t)(m->cv_flip ? 1 : 0);
    long sig_long = (long)MLDSA87_SIG_LEN + m->cv_delta;
    size_t sig_len = (size_t)sig_long;
    at = w->len;
    wb_u8(w, HS_CERTIFICATE_VERIFY);
    wb_u24(w, (uint32_t)(4 + sig_len));
    wb_u16(w, m->cv_scheme != 0 ? m->cv_scheme : SIGALG_MLDSA87);
    wb_u16(w, (uint16_t)sig_len);
    wb_bytes(w, sig, sig_len);
    CHECK(!w->err);
    transcript_update(&m->transcript, w->p + at, w->len - at);
}
#endif

// Writes EncryptedExtensions, whose extension block is the exts_len bytes
// at exts, then the server Finished, into out. Returns their length, and
// derives the application traffic secrets. A pinned handshake puts the
// Certificate and the CertificateVerify between the two.
static size_t mock_server_flight(cnsa2_mock *m, const uint8_t *exts, size_t exts_len, uint8_t *out,
                                 size_t cap) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_ENCRYPTED_EXTENSIONS);
    wb_u24(&w, (uint32_t)(2 + exts_len));
    wb_u16(&w, (uint16_t)exts_len);
    wb_bytes(&w, exts, exts_len);
    CHECK(!w.err);
    transcript_update(&m->transcript, out, w.len);
#ifdef CH_PIN_MLDSA
    if (m->pinned) {
        mock_certificate(m, &w);
    }
#endif
    CHECK(!w.err && w.len + 4 + SHA384_LEN <= cap);
    uint8_t hash[SHA384_LEN];
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    uint8_t *finished = out + w.len;
    finished[0] = HS_FINISHED;
    finished[1] = 0;
    finished[2] = 0;
    finished[3] = SHA384_LEN;
    ks_verify_data(SHA384_LEN, m->s_hs, hash, finished + 4);
    transcript_update(&m->transcript, finished, 4 + SHA384_LEN);
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    ks_master(SHA384_LEN, m->handshake_secret, hash, m->master, m->c_ap, m->s_ap);
    return w.len + 4 + SHA384_LEN;
}

// Checks the client Finished and keeps the resumption master for the
// ticket mock_ticket writes.
static void mock_client_finished(cnsa2_mock *m, const uint8_t *msg, size_t n) {
    uint8_t hash[SHA384_LEN];
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    uint8_t want[SHA384_LEN];
    ks_verify_data(SHA384_LEN, m->c_hs, hash, want);
    m->client_finished_ok =
        n == 4 + SHA384_LEN && msg[0] == HS_FINISHED && memcmp(msg + 4, want, SHA384_LEN) == 0;
    transcript_update(&m->transcript, msg, n);
    transcript_hash_after(&m->transcript, SHA384_LEN, NULL, 0, hash);
    ks_res_master(SHA384_LEN, m->master, hash, issued_res_master);
}

// Writes a NewSessionTicket for ticket_id under ticket_nonce into out and
// returns its length. Call it after mock_client_finished.
static size_t mock_ticket(uint8_t *out, size_t cap) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_NEW_SESSION_TICKET);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0);
    wb_u16(&w, 3600); // ticket_lifetime
    wb_u16(&w, 0x0102);
    wb_u16(&w, 0x0304); // ticket_age_add
    wb_u8(&w, sizeof ticket_nonce);
    wb_bytes(&w, ticket_nonce, sizeof ticket_nonce);
    wb_u16(&w, sizeof ticket_id);
    wb_bytes(&w, ticket_id, sizeof ticket_id);
    wb_u16(&w, 0);
    wb_patch24(&w, body);
    CHECK(!w.err);
    return w.len;
}

#endif
