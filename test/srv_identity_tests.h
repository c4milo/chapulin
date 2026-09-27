// The rules a server checks every provisioned identity against before a
// session starts (srv_identities_usable, srv_auth.h), each at its exact
// boundary: the last configuration a rule admits passes and the first it
// refuses fails. Then ch_srv_accept over each first refusal, which must
// return CH_EINVAL having called neither callback, and over each last
// admitted one, which must get past the check and read.
//
// It continues test/srv_auth_test.c, whose key pairs, chain, CHECK and
// provisioning helpers it uses, and is included after them.
#ifndef CH_SRV_IDENTITY_TESTS_H
#define CH_SRV_IDENTITY_TESTS_H

// The P-256 group order n, big-endian (SEC 2 §2.4.2), the first scalar
// p256_sign refuses above zero.
static const uint8_t p256_order[P256_PRIV_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

// The ECDSA scalar a case provisions, and a chain a case sets lengths in.
// Every der names cert_der: the rules read lengths and pointers, and no
// certificate byte.
static uint8_t scalar[P256_PRIV_LEN];
static ch_cert long_chain[2];

// The longest certificate a one-entry chain carries: the handshake
// header's 3-byte length field holds 2^24 - 1, and the message spends 4
// of those bytes on the context and list lengths and 5 on the entry's
// own length and extensions.
#define ONE_CERT_MAX (0xFFFFFFu - 9)

// Both slots provisioned with the real key pairs, which every rule
// admits. Each case changes one field from here.
static void usable_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    provision_ecdsa(cfg);
    provision_rsa(cfg);
}

// One edit that makes a configuration the case's name says, applied to
// usable_config.
typedef struct {
    const char *name;
    void (*edit)(ch_cfg *cfg);
} identity_case;

static void ecdsa_priv_32(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.priv_len = P256_PRIV_LEN;
}
static void ecdsa_priv_33(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.priv_len = P256_PRIV_LEN + 1;
}
static void ecdsa_pub_63(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.pub_len = 63;
}
static void rsa_priv_short(ch_cfg *cfg) {
    cfg->srv.rsa_pss.priv_len = sizeof(ch_rsa_priv) - 1;
}
static void rsa_pub_max(ch_cfg *cfg) {
    cfg->srv.rsa_pss.pub_len = SRV_SIG_MAX;
}
static void rsa_pub_max_plus_one(ch_cfg *cfg) {
    cfg->srv.rsa_pss.pub_len = SRV_SIG_MAX + 1;
}
static void ecdsa_scalar_one(ch_cfg *cfg) {
    memset(scalar, 0, sizeof scalar);
    scalar[P256_PRIV_LEN - 1] = 1;
    cfg->srv.ecdsa_p256.priv = scalar;
}
static void ecdsa_scalar_zero(ch_cfg *cfg) {
    memset(scalar, 0, sizeof scalar);
    cfg->srv.ecdsa_p256.priv = scalar;
}
static void ecdsa_scalar_order_minus_one(ch_cfg *cfg) {
    memcpy(scalar, p256_order, sizeof scalar);
    scalar[P256_PRIV_LEN - 1] = 0x50;
    cfg->srv.ecdsa_p256.priv = scalar;
}
static void ecdsa_scalar_order(ch_cfg *cfg) {
    memcpy(scalar, p256_order, sizeof scalar);
    cfg->srv.ecdsa_p256.priv = scalar;
}
static void rsa_modulus_even(ch_cfg *cfg) {
    (void)cfg;
    rsa_key.n[rsa_key.n_len - 1] &= (uint8_t)~1U;
}
// One certificate at the longest length and one byte past it, then two
// whose lengths sum to the same bound, and the shapes an entry may not
// have: no bytes, and no pointer.
static void one_cert(ch_cfg *cfg, size_t len) {
    long_chain[0].der = cert_der;
    long_chain[0].len = len;
    cfg->srv.rsa_pss.chain = long_chain;
    cfg->srv.rsa_pss.chain_count = 1;
}
static void one_cert_max(ch_cfg *cfg) {
    one_cert(cfg, ONE_CERT_MAX);
}
static void one_cert_past_max(ch_cfg *cfg) {
    one_cert(cfg, ONE_CERT_MAX + 1);
}
static void two_certs(ch_cfg *cfg, size_t second) {
    long_chain[0].der = cert_der;
    long_chain[0].len = ONE_CERT_MAX - 5 - 5;
    long_chain[1].der = cert_der;
    long_chain[1].len = second;
    cfg->srv.ecdsa_p256.chain = long_chain;
    cfg->srv.ecdsa_p256.chain_count = 2;
}
static void two_certs_max(ch_cfg *cfg) {
    two_certs(cfg, 5);
}
static void two_certs_past_max(ch_cfg *cfg) {
    two_certs(cfg, 6);
}
static void cert_one_byte(ch_cfg *cfg) {
    one_cert(cfg, 1);
}
static void cert_empty(ch_cfg *cfg) {
    one_cert(cfg, 0);
}
static void cert_without_bytes(ch_cfg *cfg) {
    one_cert(cfg, sizeof cert_der);
    long_chain[0].der = NULL;
}

// Each rule's last admitted configuration, then its first refused one.
static const identity_case admitted[] = {
    {"an ECDSA private key of 32 bytes",    ecdsa_priv_32               },
    {"an RSA modulus of SRV_SIG_MAX bytes", rsa_pub_max                 },
    {"the ECDSA scalar 1",                  ecdsa_scalar_one            },
    {"the ECDSA scalar n - 1",              ecdsa_scalar_order_minus_one},
    {"one certificate of 2^24 - 10 bytes",  one_cert_max                },
    {"two certificates at the same bound",  two_certs_max               },
    {"one certificate of one byte",         cert_one_byte               },
};
static const identity_case refused[] = {
    {"an ECDSA private key of 33 bytes",         ecdsa_priv_33       },
    {"an ECDSA public key of 63 bytes",          ecdsa_pub_63        },
    {"an RSA private key one byte short",        rsa_priv_short      },
    {"an RSA modulus of SRV_SIG_MAX + 1 bytes",  rsa_pub_max_plus_one},
    {"the ECDSA scalar 0",                       ecdsa_scalar_zero   },
    {"the ECDSA scalar n",                       ecdsa_scalar_order  },
    {"an even RSA modulus",                      rsa_modulus_even    },
    {"one certificate of 2^24 - 9 bytes",        one_cert_past_max   },
    {"two certificates one byte past the bound", two_certs_past_max  },
    {"an empty certificate",                     cert_empty          },
    {"a certificate with no bytes pointer",      cert_without_bytes  },
};

// The callbacks ch_srv_accept is given: each counts its calls, and recv
// fails, so a configuration the check admits ends the handshake at its
// first read, before any flight.
static size_t send_calls;
static size_t recv_calls;

static int count_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    send_calls++;
    return 0;
}

// It poisons what it was handed, so a session that read on anyway would
// read these bytes and not whatever the buffer held.
static int count_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0xEE, n);
    recv_calls++;
    return -1;
}

static uint8_t accept_buf[CH_MIN_RXBUF];
static const uint8_t accept_cookie_key[CH_SRV_COOKIE_KEY_LEN] = {9};

// ch_srv_accept over one case: what it returns, and whether it called
// either callback.
static int accept_case(const identity_case *c) {
    ch_cfg cfg;
    usable_config(&cfg);
    c->edit(&cfg);
    cfg.buf = accept_buf;
    cfg.buf_len = sizeof accept_buf;
    cfg.send = count_send;
    cfg.recv = count_recv;
    cfg.srv.cookie_key = accept_cookie_key;
    send_calls = 0;
    recv_calls = 0;
    ch_tls t;
    int rc = ch_srv_accept(&t, &cfg);
    CHECK(t.state == CH_ST_FAILED);
    return rc;
}

static void test_identity_rules(void) {
    ch_cfg cfg;
    usable_config(&cfg);
    CHECK(srv_identities_usable(&cfg) == 1);

    for (size_t i = 0; i < sizeof admitted / sizeof admitted[0]; i++) {
        usable_config(&cfg);
        admitted[i].edit(&cfg);
        if (srv_identities_usable(&cfg) != 1) {
            (void)fprintf(stderr, "FAIL refused %s\n", admitted[i].name);
            failures++;
        }
        // Past the check, the session reads first, and the failed read
        // is what ends it.
        if (accept_case(&admitted[i]) != CH_EIO || recv_calls == 0) {
            (void)fprintf(stderr, "FAIL ch_srv_accept stopped %s at the check\n", admitted[i].name);
            failures++;
        }
    }
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        usable_config(&cfg);
        refused[i].edit(&cfg);
        if (srv_identities_usable(&cfg) != 0) {
            (void)fprintf(stderr, "FAIL admitted %s\n", refused[i].name);
            failures++;
        }
        if (ch_srv_check(&cfg) != CH_EINVAL) {
            (void)fprintf(stderr, "FAIL ch_srv_check admitted %s\n", refused[i].name);
            failures++;
        }
        if (accept_case(&refused[i]) != CH_EINVAL || send_calls != 0 || recv_calls != 0) {
            (void)fprintf(stderr, "FAIL ch_srv_accept did not refuse %s before any I/O\n",
                          refused[i].name);
            failures++;
        }
    }
}

#endif
