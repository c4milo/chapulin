// The ML-DSA-87 cases of test/cnsa2_test.c (docs/decisions.md 157), in
// the TRUST=raw-mldsa and TRUST=ca-mldsa builds: the pin's length
// boundary, the hello's one signature scheme, whole handshakes that the
// mock authenticates by an ML-DSA-87 CertificateVerify, the refusals of
// a bad CertificateVerify, the receive floor at the certificate cap, and
// in the CA build the chains of one and two certificates. Include it after
// test/cnsa2_cases.h. Not a standalone translation unit.
#ifndef CH_CNSA2_MLDSA_CASES_H
#define CH_CNSA2_MLDSA_CASES_H

#include "cnsa2_mldsa_fixture.h"

static cert_list served;

// The key a raw build pins and a CA build pins as its CA: the server's
// own key, or the root.
#ifdef CH_TRUST_CA
#define PINNED_KEY (&root_key)
#else
#define PINNED_KEY (&server_key)
#endif

// A pinned config: no PSK, the pin in slot A, and the mock set to answer
// with the server's list and key.
static ch_cfg pinned_cfg(mock_server *s) {
    ch_cfg cfg = valid_cfg(s);
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = PINNED_KEY->pk;
    cfg.server_pubkey_len = MLDSA87_PK_LEN;
    s->m.cert_list = served.bytes;
    s->m.cert_list_len = served.len;
    s->m.signer = &server_key;
    return cfg;
}

// The pin is the whole 2592-byte key in either slot, and one byte fewer
// or more is refused before a byte is sent. A pin beside the PSK is
// refused, and the PSK alone still passes (test_cnsa2_cfg).
static void test_mldsa_cfg(void) {
    static uint8_t long_pin[MLDSA87_PK_LEN + 1];
    mock_server s;
    ch_cfg cfg = pinned_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    cfg = pinned_cfg(&s);
    cfg.server_pubkey_len = MLDSA87_PK_LEN - 1;
    CHECK(refused(&cfg));
    cfg = pinned_cfg(&s);
    cfg.server_pubkey = long_pin;
    cfg.server_pubkey_len = sizeof long_pin;
    CHECK(refused(&cfg));
    cfg = pinned_cfg(&s);
    cfg.server_pubkey2 = stranger_key.pk;
    cfg.server_pubkey2_len = MLDSA87_PK_LEN;
    CHECK(sends_client_hello(&cfg));
    cfg = pinned_cfg(&s);
    cfg.server_pubkey2 = long_pin;
    cfg.server_pubkey2_len = sizeof long_pin;
    CHECK(refused(&cfg));
    cfg = pinned_cfg(&s);
    cfg.psk = external_psk;
    cfg.psk_len = sizeof external_psk;
    cfg.psk_id = external_id;
    cfg.psk_id_len = sizeof external_id;
    CHECK(refused(&cfg));
    // One byte under the floor is refused, and the floor passes.
    cfg = pinned_cfg(&s);
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(refused(&cfg));
}

// A pinned hello offers mldsa87 alone and no PSK.
static void test_mldsa_hello(void) {
    mock_server s;
    ch_cfg cfg = pinned_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    uint16_t schemes[4] = {0};
    CHECK(hello_sigalgs(s.m.hello, s.m.hello_len, schemes, 4) == 1);
    CHECK(schemes[0] == SIGALG_MLDSA87 && SIGALG_MLDSA87 == 0x0906);
    size_t len = 0;
    CHECK(hello_ext(s.m.hello, s.m.hello_len, EXT_PRE_SHARED_KEY, &len) == NULL);
}

// One pinned handshake under cfg and one echoed record. Returns what
// test_connect returned.
static int pinned_handshake(mock_server *s, const ch_cfg *cfg, ch_tls **t) {
    static const uint8_t ping[] = {'p', 'i', 'n', 'g'};
    s->answer = 1;
    tickets = 0;
    int rc = test_connect(t, cfg);
    if (rc != CH_OK) {
        return rc;
    }
    CHECK(s->m.pinned && !s->m.resumed && s->m.client_finished_ok);
    CHECK((*t)->group == CH_GROUP_MLKEM1024 && (*t)->suite == SUITE_AES_256_GCM_SHA384);
    CHECK((*t)->psk_selected == 0);
    CHECK(ch_write(*t, ping, sizeof ping) == CH_OK);
    CHECK(s->echo_len == sizeof ping && memcmp(s->echo, ping, sizeof ping) == 0);
    uint8_t got[16];
    CHECK(ch_read(*t, got, sizeof got) == (int)sizeof ping);
    CHECK(tickets == 1);
    return rc;
}

// A whole handshake under the pin, then one that resumes its ticket with
// the pin still set, and one where slot B holds the key.
static void test_mldsa_handshake(void) {
    mock_server s;
    ch_cfg cfg = pinned_cfg(&s);
    ch_tls *t = NULL;
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_OK);
    CHECK(t->pin_slot == 1);
    ch_close(t);

    cfg = pinned_cfg(&s);
    cfg.ticket = &saved;
    s.answer = 1;
    CHECK(test_connect(&t, &cfg) == CH_OK);
    CHECK(s.m.resumed && s.m.binder_ok && t->psk_selected == 1);
    ch_close(t);

    cfg = pinned_cfg(&s);
    cfg.server_pubkey = stranger_key.pk;
    cfg.server_pubkey2 = PINNED_KEY->pk;
    cfg.server_pubkey2_len = MLDSA87_PK_LEN;
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_OK);
    CHECK(t->pin_slot == 2);
    ch_close(t);
}

// Each bad CertificateVerify fails the handshake with CH_EAUTH: another
// scheme with handshake_failure; a flipped byte, a signature one byte
// short or long, and a signature by another key with decrypt_error.
static void test_mldsa_certificate_verify(void) {
    static const struct {
        uint16_t scheme;
        int flip;
        int delta;
        int stranger;
        uint8_t alert;
    } cases[] = {
        {SIGALG_RSA_PSS_RSAE_SHA256, 0, 0,  0, ALERT_HANDSHAKE_FAILURE},
        {0x0905,                     0, 0,  0, ALERT_HANDSHAKE_FAILURE}, // mldsa65
        {0,                          1, 0,  0, ALERT_DECRYPT_ERROR    },
        {0,                          0, -1, 0, ALERT_DECRYPT_ERROR    },
        {0,                          0, 1,  0, ALERT_DECRYPT_ERROR    },
        {0,                          0, 0,  1, ALERT_DECRYPT_ERROR    },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        mock_server s;
        ch_cfg cfg = pinned_cfg(&s);
        s.m.cv_scheme = cases[i].scheme;
        s.m.cv_flip = cases[i].flip;
        s.m.cv_delta = cases[i].delta;
        if (cases[i].stranger) {
            s.m.signer = &stranger_key;
        }
        ch_tls *t = NULL;
        CHECK(pinned_handshake(&s, &cfg, &t) == CH_EAUTH);
        CHECK(ch_alert_sent(t) == cases[i].alert);
    }
}

// At a receive buffer of CH_MIN_RXBUF, the largest Certificate the floor
// admits completes the handshake: one certificate of CH_X509_MAX bytes in
// a raw build, and two in a CA build. In a raw build a certificate one
// byte larger does not fit and fails with CH_ECAP. The blocking driver
// reads each record into the buffer whole, and the floor's 22 bytes pay
// for the last one's header, type and tag. ch_record_in opens a record
// from the caller's bytes, so there the first certificate that does not
// fit is 22 bytes larger. In a CA build x509.c refuses a certificate over
// CH_X509_MAX with bad_certificate.
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#define RECORD_SLACK 22
#else
#define RECORD_SLACK 0
#endif
static void test_mldsa_floor(void) {
    for (int over = 0; over < 2; over++) {
#ifdef CH_TRUST_CA
        if (over) {
            list_flat(&served, CH_X509_MAX + 1);
        } else {
            list_chain(&served, CH_X509_MAX, 0);
        }
#else
        list_flat(&served, CH_X509_MAX + (size_t)over * (1 + RECORD_SLACK));
#endif
        mock_server s;
        ch_cfg cfg = pinned_cfg(&s);
        CHECK(cfg.buf_len == CH_MIN_RXBUF);
        ch_tls *t = NULL;
        int rc = pinned_handshake(&s, &cfg, &t);
        if (!over) {
            CHECK(rc == CH_OK);
            ch_close(t);
            continue;
        }
#ifdef CH_TRUST_CA
        CHECK(rc == CH_EPROTO && ch_alert_sent(t) == ALERT_BAD_CERTIFICATE);
#else
        CHECK(rc == CH_ECAP);
#endif
    }
}

#ifdef CH_TRUST_CA
// The chain shapes of x509.c's profile under ML-DSA-87: the leaf alone
// under the root, the leaf and its intermediate, and both refusals: a
// third certificate, and a chain whose root nobody pins.
static void test_mldsa_chains(void) {
    list_chain(&served, 0, 0);
    mock_server s;
    ch_cfg cfg = pinned_cfg(&s);
    ch_tls *t = NULL;
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_OK);
    CHECK(t->pin_slot == 1);
    ch_close(t);

    list_chain(&served, 0, 1);
    cfg = pinned_cfg(&s);
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_EPROTO);
    CHECK(ch_alert_sent(t) == ALERT_UNSUPPORTED_CERTIFICATE);

    list_chain(&served, 0, 0);
    cfg = pinned_cfg(&s);
    cfg.server_pubkey = stranger_key.pk;
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_EAUTH);
    CHECK(ch_alert_sent(t) == ALERT_UNKNOWN_CA);

    // The leaf signs with a key other than the one its certificate names.
    list_flat(&served, 0);
    cfg = pinned_cfg(&s);
    s.m.signer = &int_key;
    CHECK(pinned_handshake(&s, &cfg, &t) == CH_EAUTH);
    CHECK(ch_alert_sent(t) == ALERT_DECRYPT_ERROR);
}
#endif

// The two parsers at the sizes ML-DSA-87 brings. A CertificateVerify body
// with mldsa87 and a 4627-byte signature is exact-fill, and one trailing
// byte fails it; every other scheme, ML-DSA-65's among them, is refused
// with handshake_failure. A Certificate body of the CA floor's largest
// list, two entries of CH_X509_MAX bytes, is exact-fill too.
static void test_mldsa_parsers(void) {
    static uint8_t body[4 + MLDSA87_SIG_LEN + 1];
    static const uint16_t schemes[] = {SIGALG_MLDSA87, 0x0905, SIGALG_RSA_PSS_RSAE_SHA256,
                                       SIGALG_ECDSA_P256_SHA256, SIGALG_ECDSA_P384_SHA384};
    for (size_t i = 0; i < sizeof schemes / sizeof schemes[0]; i++) {
        for (int extra = 0; extra < 2; extra++) {
            body[0] = (uint8_t)(schemes[i] >> 8);
            body[1] = (uint8_t)schemes[i];
            body[2] = (uint8_t)(MLDSA87_SIG_LEN >> 8);
            body[3] = (uint8_t)MLDSA87_SIG_LEN;
            const uint8_t *sig = NULL;
            size_t sig_len = 0;
            uint8_t alert = 0;
            int rc = hsp_parse_certificate_verify(body, 4 + MLDSA87_SIG_LEN + (size_t)extra, &sig,
                                                  &sig_len, &alert);
            if (i > 0) {
                CHECK(rc == CH_EAUTH && alert == ALERT_HANDSHAKE_FAILURE);
            } else if (extra) {
                CHECK(rc == CH_EPROTO);
            } else {
                CHECK(rc == CH_OK && sig == body + 4 && sig_len == MLDSA87_SIG_LEN);
            }
        }
    }
    static uint8_t cert_body[1 + 3 + 2 * (CH_X509_MAX + 5) + 1];
    size_t list_len = (size_t)2 * (CH_X509_MAX + 5);
    cert_body[0] = 0;
    cert_body[1] = (uint8_t)(list_len >> 16);
    cert_body[2] = (uint8_t)(list_len >> 8);
    cert_body[3] = (uint8_t)list_len;
    for (int extra = 0; extra < 2; extra++) {
        const uint8_t *list = NULL;
        size_t got = 0;
        uint8_t alert = 0;
        int rc =
            hsp_parse_certificate(cert_body, 4 + list_len + (size_t)extra, &list, &got, &alert);
        CHECK(extra ? rc == CH_EPROTO : rc == CH_OK && got == list_len && list == cert_body + 4);
    }
}

// hsa_signed_content writes the bytes whose SHA-256
// hsa_hash_signed_content writes, which the differential holds to the
// spec, at both transcript hash lengths.
static void test_mldsa_signed_content(void) {
    uint8_t hash[SHA384_LEN];
    for (size_t i = 0; i < sizeof hash; i++) {
        hash[i] = (uint8_t)(i * 7 + 1);
    }
    static const size_t lens[] = {SHA256_LEN, SHA384_LEN};
    for (size_t i = 0; i < 2; i++) {
        uint8_t content[HSA_SIGNED_CONTENT_MAX];
        size_t n = hsa_signed_content(hash, lens[i], content);
        CHECK(n == 64 + 34 + lens[i]);
        uint8_t want[SHA256_LEN];
        uint8_t got[SHA256_LEN];
        hsa_hash_signed_content(SIGALG_RSA_PSS_RSAE_SHA256, hash, lens[i], want);
        sha256_of(content, n, got);
        CHECK(memcmp(want, got, sizeof got) == 0);
    }
}

static void test_cnsa2_mldsa(void) {
    fixture_keys();
    list_flat(&served, 0);
    test_mldsa_cfg();
    test_mldsa_hello();
    test_mldsa_handshake();
    test_mldsa_certificate_verify();
#ifdef CH_TRUST_CA
    test_mldsa_chains();
#endif
    test_mldsa_floor();
    test_mldsa_parsers();
    test_mldsa_signed_content();
}

#endif
