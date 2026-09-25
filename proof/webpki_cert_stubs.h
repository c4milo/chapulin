// The four readers webpki_cert.c hands fields to, as contract stubs that
// assert what the parser passes them and havoc their outputs within
// exactly what their own harnesses prove: webpki_read_sigalg
// (webpki_sigalg: 15 or 12 bytes, one of four values), webpki_read_time
// (webpki_time: 15 or 17 bytes, a packed date in range), webpki_read_spki
// (webpki_spki: at most 550 bytes, the key inside them, one of three
// algorithms) and webpki_read_extensions (webpki_ext: the arm's bits,
// is_ca equal to the arm, path_len from -1 to 32767, san NULL or inside
// the bytes consumed). Each stub may fail at any point, consuming any
// prefix and setting err, as the real readers may. extensions_reads
// counts the calls to the last one, which webpki_cert_key reads to show
// the key reader never calls the extensions reader.
//
// Shared by proof/webpki_cert_harness.c and proof/webpki_cert_key_harness.c,
// each of which includes it after harness.h, buf.h, handshake_message.h and
// webpki.h and before webpki_cert.c.
#ifndef CH_PROOF_WEBPKI_CERT_STUBS_H
#define CH_PROOF_WEBPKI_CERT_STUBS_H

int nondet_int(void);
uint64_t nondet_u64(void);

// webpki_spki's proven bound on an accepted SubjectPublicKeyInfo.
#define SPKI_MAX 550
#define PACKED_MIN UINT64_C(19500101000000)
#define PACKED_MAX UINT64_C(99991231235959)

// A reader failure: any prefix of what remains consumed, err maybe set.
static int havoc_failure(rbuf *r) {
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= rb_left(r));
    rb_skip(r, take);
    if (nondet_u8() & 1) {
        r->err = 1;
    }
    return 0;
}

// The start of a successful read of exactly take bytes, which a reader
// can only start with err clear and take bytes left. Returns a pointer
// to the bytes the read consumes, the base the stub's outputs point into.
static const uint8_t *consume(rbuf *r, size_t take) {
    __CPROVER_assume(!r->err && take <= rb_left(r));
    const uint8_t *start = rb_bytes(r, take);
    __CPROVER_assert(start != NULL, "stub: the consumed bytes are readable");
    return start;
}

int webpki_read_sigalg(rbuf *r, uint8_t *sigalg) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "sigalg stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(sigalg, sizeof *sigalg), "sigalg stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    uint8_t value = nondet_u8();
    __CPROVER_assume(value >= WEBPKI_SIG_RSA_SHA256 && value <= WEBPKI_SIG_ECDSA_SHA384);
    (void)consume(r, value <= WEBPKI_SIG_RSA_SHA384 ? 15U : 12U);
    *sigalg = value;
    return 1;
}

int webpki_read_time(rbuf *r, uint64_t *packed) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "time stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(packed, sizeof *packed), "time stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    uint64_t value = nondet_u64();
    __CPROVER_assume(value >= PACKED_MIN && value <= PACKED_MAX);
    (void)consume(r, (nondet_u8() & 1) ? 15U : 17U);
    *packed = value;
    return 1;
}

int webpki_read_spki(rbuf *r, webpki_spki *out) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "spki stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "spki stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= SPKI_MAX);
    const uint8_t *start = consume(r, take);
    size_t key_off = nondet_size_t();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= take && key_off <= take - key_len);
    uint8_t alg = nondet_u8();
    __CPROVER_assume(alg >= WEBPKI_KEY_RSA && alg <= WEBPKI_KEY_P384);
    out->alg = alg;
    out->key = start + key_off;
    out->key_len = key_len;
    return 1;
}

static size_t extensions_reads;

int webpki_read_extensions(rbuf *t, int is_ca, webpki_cert *out, uint8_t *alert) {
    extensions_reads++;
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "extensions stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "extensions stub: out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "extensions stub: alert writable");
    __CPROVER_assert(is_ca == 0 || is_ca == 1, "extensions stub: the arm is 0 or 1");
    out->seen = nondet_u8();
    out->is_ca = nondet_u8();
    out->path_len = nondet_int();
    out->san = NULL;
    out->san_len = 0;
    if (nondet_u8() & 1) {
        if (nondet_u8() & 1) {
            *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        }
        (void)havoc_failure(t);
        return CH_EPROTO;
    }
    size_t take = nondet_size_t();
    const uint8_t *start = consume(t, take);
    uint8_t required = is_ca ? (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_BASIC_CONSTRAINTS)
                             : (WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_EXT_KEY_USAGE | WEBPKI_EXT_SAN);
    __CPROVER_assume((out->seen & required) == required);
    out->is_ca = (uint8_t)is_ca;
    __CPROVER_assume(out->path_len >= -1 && out->path_len <= 32767);
    __CPROVER_assume(is_ca || out->path_len == -1);
    if (!is_ca || (nondet_u8() & 1)) {
        size_t san_off = nondet_size_t();
        size_t san_len = nondet_size_t();
        __CPROVER_assume(san_len <= take && san_off <= take - san_len);
        out->san = start + san_off;
        out->san_len = san_len;
    }
    return CH_OK;
}

#endif
