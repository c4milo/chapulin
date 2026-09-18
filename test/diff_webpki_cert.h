// TRUST=webpki certificate parser and extension walk differential
// section (webpki_cert.c and webpki_ext.c against
// spec/Spec/WebpkiCert.lean).
//
// Three sources of certificates, each compared under the leaf arm and
// the issuer arm or under the arm its position names:
//
//   - every certificate of every corpus and capture row
//     (test/webpki_corpus.h), under both arms, whole, cut short, and
//     with one byte after it
//   - single-byte changes of those certificates: every byte once, by a
//     random nonzero delta, for the r2 leaf and its intermediate, the
//     smallest pair, and DIFF_CERT_SAMPLES bytes spread over each other
//     certificate
//   - random extension lists inside the r2 leaf's fixed TBS fields and
//     signature: drawn from a pool of keyUsage, extendedKeyUsage,
//     basicConstraints, subjectAltName and unknown extensions, each
//     critical or not, well-formed and malformed, in random order and
//     count from 0 to CH_WEBPKI_EXT_COUNT_MAX + 2, half of them seeded
//     with one arm's required set so accepted certificates are compared
//     too, one required entry in three swapped for another value of the
//     same extension, one Extension in eight sized at the TLV cap or one
//     past it, and one frame in four carrying a validity that is swapped,
//     empty or in the wrong Time type
//
// The reply carries every range as an offset and a length into the
// certificate, so the C side's pointers are compared, not only its
// verdict. Neither side's alert is compared; test/webpki_cert_test.c
// pins those.
//
// Included by test/diff_test.c after diff_driver.h (single translation
// unit). spec/Main.lean serves the op:
//   webpki_cert <0|1> <cert> -> "ok <tbs off len> <issuer off len> <subject off len>
//                                <not_before> <not_after> <rsa|p256|p384> <key>
//                                <sigalg> <sig off len> <san off len | - 0> <seen>
//                                <is_ca> <path_len | ->" / "ERR webpki_cert reject"
#ifndef CH_DIFF_WEBPKI_CERT_H
#define CH_DIFF_WEBPKI_CERT_H

#include <inttypes.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "webpki_corpus.h"

// Room for one byte past the certificate cap.
#define DIFF_CERT_MAX (CH_WEBPKI_CERT_MAX + 1)
#define DIFF_CERT_LINE_MAX (2 * DIFF_CERT_MAX + 32)
#define DIFF_CERT_REPLY_MAX (2 * CH_WEBPKI_KEY_MAX + 256)
// Bytes changed one at a time in each certificate other than the r2 pair.
#define DIFF_CERT_SAMPLES 48
// Random extension lists.
#define DIFF_CERT_LISTS 3000
// The largest pool extension, the TLV cap plus one byte.
#define DIFF_CERT_EXT_MAX (CH_WEBPKI_EXT_TLV_MAX + 1)
// A random list holds up to CH_WEBPKI_EXT_COUNT_MAX + 2 extensions of at
// most DIFF_CERT_EXT_MAX bytes; a frame adds the r2 leaf's other fields.
#define DIFF_CERT_LIST_MAX ((CH_WEBPKI_EXT_COUNT_MAX + 2) * DIFF_CERT_EXT_MAX)
#define DIFF_CERT_FRAME_MAX (DIFF_CERT_LIST_MAX + 512)

// Set while the r2 message is visited: its two certificates, the
// smallest pair in the corpus, get every byte changed in turn.
static int diff_cert_every_byte;

// Certificates compared, and how many of them the C accepted.
static long diff_cert_rows;
static long diff_cert_accepted;

static const char *const diff_cert_key_names[4] = {"-", "rsa", "p256", "p384"};
static const char *const diff_cert_sigalg_names[5] = {"-", "rsa_sha256", "rsa_sha384",
                                                      "ecdsa_sha256", "ecdsa_sha384"};

// The C side of webpki_cert: the reply the spec gives for the same bytes.
static void diff_cert_c_reply(const uint8_t *cert, size_t n, int is_ca, char *reply, size_t cap) {
    webpki_cert c;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (webpki_parse_certificate(cert, n, is_ca, &c, &alert) != CH_OK) {
        (void)snprintf(reply, cap, "ERR webpki_cert reject");
        return;
    }
    if (c.spki.key_len > CH_WEBPKI_KEY_MAX || c.spki.alg > WEBPKI_KEY_P384 ||
        c.sigalg > WEBPKI_SIG_ECDSA_SHA384) {
        die("webpki_cert: an accepted certificate outside webpki.h's ranges");
    }
    static char key_hex[2 * CH_WEBPKI_KEY_MAX + 1];
    (void)hex_encode(key_hex, c.spki.key, c.spki.key_len);
    char san[48];
    char path_len[16];
    if (c.san != NULL) {
        (void)snprintf(san, sizeof san, "%zu %zu", (size_t)(c.san - cert), c.san_len);
    } else {
        (void)snprintf(san, sizeof san, "- 0");
    }
    if (c.path_len >= 0) {
        (void)snprintf(path_len, sizeof path_len, "%d", c.path_len);
    } else {
        (void)snprintf(path_len, sizeof path_len, "-");
    }
    (void)snprintf(
        reply, cap,
        "ok %zu %zu %zu %zu %zu %zu %" PRIu64 " %" PRIu64 " %s %s %s %zu %zu %s %u %u %s",
        (size_t)(c.tbs - cert), c.tbs_len, (size_t)(c.issuer - cert), c.issuer_len,
        (size_t)(c.subject - cert), c.subject_len, c.not_before, c.not_after,
        diff_cert_key_names[c.spki.alg], key_hex, diff_cert_sigalg_names[c.sigalg],
        (size_t)(c.sig - cert), c.sig_len, san, (unsigned)c.seen, (unsigned)c.is_ca, path_len);
}

static void diff_cert_compare(const uint8_t *cert, size_t n, int is_ca) {
    static char cmd[DIFF_CERT_LINE_MAX];
    static char want[DIFF_CERT_REPLY_MAX];
    if (n > DIFF_CERT_MAX) {
        die("webpki_cert: a driver certificate over DIFF_CERT_MAX");
    }
    int at = snprintf(cmd, sizeof cmd, "webpki_cert %d ", is_ca);
    (void)hex_encode(cmd + at, cert, n);
    diff_cert_c_reply(cert, n, is_ca, want, sizeof want);
    diff_cert_rows++;
    diff_cert_accepted += want[0] == 'o';
    expect(cmd, want);
}

// Calls visit on every certificate of an RFC 9846 §4.5.1 Certificate
// message, with its entry index. The corpus messages are well-formed, so
// a malformed one is a driver bug.
static void diff_cert_entries(const uint8_t *message, size_t message_len,
                              void (*visit)(const uint8_t *, size_t, size_t)) {
    rbuf r;
    rb_init(&r, message, message_len);
    uint8_t msg_type = rb_u8(&r);
    size_t body_len = rb_u24(&r);
    uint8_t context_len = rb_u8(&r);
    size_t list_len = rb_u24(&r);
    if (r.err || msg_type != 11 || body_len != message_len - 4 || context_len != 0 ||
        list_len != rb_left(&r)) {
        die("webpki_cert: a corpus message is not a Certificate message");
    }
    for (size_t index = 0; rb_left(&r) > 0; index++) {
        size_t cert_len = rb_u24(&r);
        const uint8_t *cert = rb_bytes(&r, cert_len);
        uint16_t extensions_len = rb_u16(&r);
        if (cert == NULL || r.err || extensions_len != 0) {
            die("webpki_cert: a corpus entry is malformed");
        }
        visit(cert, cert_len, index);
    }
}

// One corpus certificate: both arms whole, then the arm its position
// names cut short, one byte longer, and with single bytes changed.
static void diff_cert_corpus_entry(const uint8_t *cert, size_t n, size_t index) {
    static uint8_t changed[DIFF_CERT_MAX];
    int arm = index > 0;
    diff_cert_compare(cert, n, 0);
    diff_cert_compare(cert, n, 1);
    diff_cert_compare(cert, rng_below(n), arm);
    memcpy(changed, cert, n);
    changed[n] = (uint8_t)rng_next();
    diff_cert_compare(changed, n + 1, arm);
    // The r2 pair gets every byte; the rest get DIFF_CERT_SAMPLES bytes,
    // one drawn from each stride.
    size_t stride = diff_cert_every_byte || n < DIFF_CERT_SAMPLES ? 1 : n / DIFF_CERT_SAMPLES;
    for (size_t start = 0; start + stride <= n; start += stride) {
        size_t at = start + (stride > 1 ? rng_below(stride) : 0);
        uint8_t delta = (uint8_t)(1 + rng_below(255));
        changed[at] ^= delta;
        diff_cert_compare(changed, n, arm);
        changed[at] ^= delta;
    }
}

// Every distinct message of a table, each once.
static void diff_cert_table(const webpki_corpus_chain *rows, size_t row_count) {
    for (size_t i = 0; i < row_count; i++) {
        int seen_before = 0;
        for (size_t j = 0; j < i; j++) {
            seen_before |= rows[j].message == rows[i].message;
        }
        if (!seen_before) {
            diff_cert_every_byte = rows[i].message == webpki_corpus_message_r2;
            diff_cert_entries(rows[i].message, rows[i].message_len, diff_cert_corpus_entry);
        }
    }
}

// A DER header for len content bytes; returns its size.
static size_t diff_cert_header(uint8_t *out, uint8_t tag, size_t len) {
    out[0] = tag;
    if (len < 0x80) {
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len < 0x100) {
        out[1] = 0x81;
        out[2] = (uint8_t)len;
        return 3;
    }
    out[1] = 0x82;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)len;
    return 4;
}

// Appends a TLV to out at *at.
static void diff_cert_put(uint8_t *out, size_t *at, uint8_t tag, const uint8_t *content,
                          size_t len) {
    *at += diff_cert_header(out + *at, tag, len);
    memcpy(out + *at, content, len);
    *at += len;
}

// One pool entry: an extnID and an extnValue, both as hex.
typedef struct {
    const char *oid;
    const char *value;
} diff_cert_pool_entry;

// keyUsage, extendedKeyUsage, basicConstraints and subjectAltName values
// on both sides of their rules, unknown extensions, and an extnID that
// is not minimal. Two values end their SEQUENCE before the extnValue
// ends and leave a well-formed element after it, so only the rule that
// the SEQUENCE fills the extnValue refuses them.
static const diff_cert_pool_entry diff_cert_pool[] = {
    {"551d0f",           "03020780"                                    },
    {"551d0f",           "03020106"                                    },
    {"551d0f",           "03020520"                                    },
    {"551d0f",           "030205a0"                                    },
    {"551d0f",           "03020781"                                    },
    {"551d0f",           "0303078080"                                  },
    {"551d0f",           "0302030400"                                  },
    {"551d25",           "300a06082b06010505070301"                    },
    {"551d25",           "300a06082b06010505070302"                    },
    {"551d25",           "301406082b0601050507030206082b06010505070301"},
    {"551d25",           "3000"                                        },
    {"551d25",           "300c06082b060105050703010600"                },
    {"551d25",           "300b06082b0601050507030105"                  },
    {"551d25",           "300a06082b060105050703010603551d25"          },
    {"551d13",           "3000"                                        },
    {"551d13",           "30030101ff"                                  },
    {"551d13",           "30060101ff020100"                            },
    {"551d13",           "30070101ff02020080"                          },
    {"551d13",           "30070101ff02027fff"                          },
    {"551d13",           "30080101ff0203008000"                        },
    {"551d13",           "30060101ff0201ff"                            },
    {"551d13",           "30070101ff02020005"                          },
    {"551d13",           "3003010100"                                  },
    {"551d13",           "3003020100"                                  },
    {"551d13",           "30050101ff0500"                              },
    {"551d13",           "30030101ff020100"                            },
    {"551d11",           "3011820f73332e6578616d706c652e74657374"      },
    {"551d11",           "3000"                                        },
    {"551d1e",           "3000"                                        },
    {"551d20",           "300630040602a001"                            },
    {"2b06010505070101", "3000"                                        },
    {"551d800f",         "03020780"                                    },
    {"551d0e",           "041408ee7cfbcd51fcd6ceebe6120ef1657ba018a03e"},
};
#define DIFF_CERT_POOL_COUNT (sizeof diff_cert_pool / sizeof diff_cert_pool[0])

// Decodes a pool hex string into out; returns its byte count.
static size_t diff_cert_hex(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2;
    if (n > cap || !hex_decode(out, hex, n)) {
        die("webpki_cert: malformed pool constant");
    }
    return n;
}

// Appends one Extension TLV built from pool entry index, critical or not.
static void diff_cert_put_pool(uint8_t *list, size_t *at, size_t index, int critical) {
    uint8_t oid[16];
    uint8_t value[64];
    uint8_t body[96];
    size_t oid_len = diff_cert_hex(oid, sizeof oid, diff_cert_pool[index].oid);
    size_t value_len = diff_cert_hex(value, sizeof value, diff_cert_pool[index].value);
    size_t n = 0;
    diff_cert_put(body, &n, 0x06, oid, oid_len);
    if (critical) {
        static const uint8_t true_flag[] = {0x01, 0x01, 0xff};
        memcpy(body + n, true_flag, sizeof true_flag);
        n += sizeof true_flag;
    }
    diff_cert_put(body, &n, 0x04, value, value_len);
    diff_cert_put(list, at, 0x30, body, n);
}

// Appends an unknown non-critical Extension (2.5.29.9) whose whole TLV is
// total bytes, total from 269 up: both its lengths take the long form.
static void diff_cert_put_sized(uint8_t *list, size_t *at, size_t total) {
    static uint8_t body[DIFF_CERT_EXT_MAX];
    static const uint8_t oid[] = {0x55, 0x1d, 0x09};
    static uint8_t filler[DIFF_CERT_EXT_MAX];
    size_t n = 0;
    diff_cert_put(body, &n, 0x06, oid, sizeof oid);
    memset(filler, 0x5a, sizeof filler);
    diff_cert_put(body, &n, 0x04, filler, total - 13);
    diff_cert_put(list, at, 0x30, body, n);
}

// Validity values a frame carries, as Validity SEQUENCE hex: the r2
// leaf's own, the same two Times swapped, notBefore equal to notAfter,
// and a GeneralizedTime for a year UTCTime must carry.
static const char *const diff_cert_validities[] = {
    "301e170d3236303130313030303030305a170d3236313233313233353935395a",
    "301e170d3236313233313233353935395a170d3236303130313030303030305a",
    "301e170d3236303130313030303030305a170d3236303130313030303030305a",
    "3022180f32303236303130313030303030305a180f32303236313233313233353935395a",
};
#define DIFF_CERT_VALIDITY_COUNT (sizeof diff_cert_validities / sizeof diff_cert_validities[0])

// The r2 leaf with its extensions list replaced by list and its
// validity by diff_cert_validities[validity]: the leaf's own TBS fields
// through the SubjectPublicKeyInfo, then [3] { SEQUENCE list }, then its
// signature algorithm and signature. Returns the length.
static size_t diff_cert_frame(uint8_t *out, const uint8_t *list, size_t list_len, size_t validity) {
    static uint8_t tbs[DIFF_CERT_FRAME_MAX];
    static uint8_t wrap[DIFF_CERT_FRAME_MAX];
    static uint8_t body[DIFF_CERT_FRAME_MAX];
    static uint8_t signature[80];
    // test/webpki_corpus.h's r2 leaf: from its version through its issuer,
    // then from its subject through its key.
    size_t tbs_len = diff_cert_hex(
        tbs, 128,
        "a003020102020115300a06082a8648ce3d040302303f310b3009060355040613025553310f300d060355040a"
        "0c06436f72707573311f301d06035504030c16436f7270757320523220496e7465726d656469617465");
    tbs_len += diff_cert_hex(tbs + tbs_len, 64, diff_cert_validities[validity]);
    tbs_len += diff_cert_hex(
        tbs + tbs_len, 128,
        "301a3118301606035504030c0f73332e6578616d706c652e746573743059301306072a8648ce3d020106082a"
        "8648ce3d03010703420004e1a90594ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e3424"
        "0e17cf6a99180c139f17c33bb5307ed09d63d0e1f3db92aa4167deb7682159");
    size_t signature_len = diff_cert_hex(
        signature, sizeof signature,
        "003045022069214df5546bd569e4782a4a99dbacdc4a2907b4b789d654d379259f0231b516022100a0b8056f"
        "940a4067d93263c04773d110ea862daf302d45277c2258926e295aba");
    static const uint8_t sigalg[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                     0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
    size_t wrap_len = 0;
    diff_cert_put(wrap, &wrap_len, 0x30, list, list_len);
    diff_cert_put(tbs, &tbs_len, 0xa3, wrap, wrap_len);
    size_t body_len = 0;
    diff_cert_put(body, &body_len, 0x30, tbs, tbs_len);
    memcpy(body + body_len, sigalg, sizeof sigalg);
    body_len += sizeof sigalg;
    diff_cert_put(body, &body_len, 0x03, signature, signature_len);
    size_t n = 0;
    diff_cert_put(out, &n, 0x30, body, body_len);
    return n;
}

// The pool indices of each arm's required set: keyUsage digitalSignature,
// extendedKeyUsage serverAuth and subjectAltName; keyUsage keyCertSign
// and basicConstraints with cA, which an issuer marks critical. Then the
// pool's unknown extensions, which a list seeded with a required set
// mostly draws its others from, so that some of those lists are accepted.
static const size_t diff_cert_leaf_set[] = {0, 7, 26};
static const size_t diff_cert_issuer_set[] = {1, 16};
static const size_t diff_cert_unknown_set[] = {28, 29, 30, 32};
#define DIFF_CERT_BASIC_CONSTRAINTS_CA 16

// The pool's index range for each of the four read extensions, first and
// last: keyUsage, extendedKeyUsage, basicConstraints, subjectAltName.
static const size_t diff_cert_kinds[4][2] = {
    {0,  6 },
    {7,  13},
    {14, 25},
    {26, 27},
};

// A required entry, or one in three times another value of the same
// extension, so values on both sides of a rule meet an otherwise
// acceptable certificate.
static size_t diff_cert_variant(size_t index) {
    if (rng_below(3) != 0) {
        return index;
    }
    for (size_t k = 0; k < 4; k++) {
        if (index >= diff_cert_kinds[k][0] && index <= diff_cert_kinds[k][1]) {
            return diff_cert_kinds[k][0] +
                   rng_below(diff_cert_kinds[k][1] - diff_cert_kinds[k][0] + 1);
        }
    }
    return index;
}

// One planned Extension: a pool entry, critical or not, or an unknown
// extension sized to total bytes when total is not 0.
typedef struct {
    size_t index;
    int critical;
    size_t total;
} diff_cert_planned;

// Plans one extension other than a required one.
static diff_cert_planned diff_cert_plan_other(int seeded) {
    diff_cert_planned e = {0, (int)rng_below(2), 0};
    if (rng_below(8) == 0) {
        e.total = CH_WEBPKI_EXT_TLV_MAX + rng_below(2);
    } else if (seeded && rng_below(4) != 0) {
        e.index = diff_cert_unknown_set[rng_below(4)];
        e.critical = 0;
    } else {
        e.index = rng_below(DIFF_CERT_POOL_COUNT);
    }
    return e;
}

#define DIFF_CERT_PLAN_MAX (CH_WEBPKI_EXT_COUNT_MAX + 2)

// Plans one random list into plan, in random order: when seeded, the
// arm's required set, then others up to a random count. Returns the count.
static size_t diff_cert_plan(diff_cert_planned plan[DIFF_CERT_PLAN_MAX], int arm, int seeded) {
    size_t count = 0;
    if (seeded) {
        const size_t *set = arm ? diff_cert_issuer_set : diff_cert_leaf_set;
        size_t set_len = arm ? 2 : 3;
        for (size_t i = 0; i < set_len; i++) {
            int critical = set[i] == DIFF_CERT_BASIC_CONSTRAINTS_CA ? arm : (int)rng_below(2);
            plan[count++] = (diff_cert_planned){diff_cert_variant(set[i]), critical, 0};
        }
    }
    size_t total = count + rng_below(DIFF_CERT_PLAN_MAX + 1 - count);
    while (count < total) {
        plan[count++] = diff_cert_plan_other(seeded);
    }
    for (size_t i = count; i > 1; i--) {
        size_t j = rng_below(i);
        diff_cert_planned swap = plan[i - 1];
        plan[i - 1] = plan[j];
        plan[j] = swap;
    }
    return count;
}

// One random extension list, framed and compared under a random arm.
static void diff_cert_random_list(void) {
    static uint8_t list[DIFF_CERT_LIST_MAX];
    static uint8_t cert[DIFF_CERT_FRAME_MAX];
    diff_cert_planned plan[DIFF_CERT_PLAN_MAX];
    int arm = (int)rng_below(2);
    size_t count = diff_cert_plan(plan, arm, rng_below(2) == 0);
    size_t at = 0;
    for (size_t i = 0; i < count; i++) {
        if (plan[i].total != 0) {
            diff_cert_put_sized(list, &at, plan[i].total);
        } else {
            diff_cert_put_pool(list, &at, plan[i].index, plan[i].critical);
        }
    }
    size_t validity = rng_below(4) == 0 ? rng_below(DIFF_CERT_VALIDITY_COUNT) : 0;
    size_t n = diff_cert_frame(cert, list, at, validity);
    if (n > DIFF_CERT_MAX) {
        return; // over the cap: the corpus rows compare that refusal
    }
    diff_cert_compare(cert, n, arm);
}

static void diff_webpki_cert(void) {
    diff_cert_table(webpki_corpus_chains,
                    sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]);
    diff_cert_table(webpki_capture_chains,
                    sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]);
    long corpus_rows = diff_cert_rows;
    long corpus_accepted = diff_cert_accepted;
    for (int i = 0; i < DIFF_CERT_LISTS; i++) {
        diff_cert_random_list();
    }
    (void)printf("diff: webpki_cert: %ld corpus rows (%ld accepted), %ld extension-list rows "
                 "(%ld accepted), C == spec\n",
                 corpus_rows, corpus_accepted, diff_cert_rows - corpus_rows,
                 diff_cert_accepted - corpus_accepted);
}

#endif
