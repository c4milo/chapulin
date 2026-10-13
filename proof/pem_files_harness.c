// Proves: the three calls of pem_files.c are memory-safe
// and UB-free over any input and any rooms the caller gives, and honour
// their contracts (pem_files.h):
//
//   - ch_chain_from_pem: CH_OK with 1 to chain_max certificates, each one
//     inside the caller's DER room, back to back in file order, each
//     one's outer fields read; CH_EINVAL with a count of 0;
//   - ch_p256_key_from_pem: CH_OK only for a cpu value the object takes.
//     CH_OK only when the call asked the leaf about the point it returns,
//     and the leaf answered yes. CH_OK only with the point that
//     p256_ecdh_keygen wrote for the scalar, under the multiply answer
//     that cpu gives. CH_EINVAL with priv and pub zero, on every path. An
//     EC PARAMETERS block is read only at the first byte, and only the EC
//     PRIVATE KEY reader follows it;
//   - ch_anchors_from_pem: CH_OK with 1 to anchor_max anchors, each Name
//     and key inside the caller's DER room; CH_EINVAL with a count of 0.
//
// Layered: the readers below these calls are stubs. They assert the
// contracts their headers state, and havoc within what their own
// harnesses prove:
//  - pem_blocks_init, pem_blocks_next and pem_skip_line_breaks
//    (proof/pem_blocks_harness.c);
//  - pem_decode_one and pem_read_block (proof/pem_one_harness.c and
//    pem_harness.c);
//  - the five x509_pem readers (proof/x509_pem_harness.c and
//    x509_pem_key_harness.c);
//  - p256_ecdh_keygen (proof/p256_ecdh_harness.c).
// So the object under proof is the order of the calls' own steps:
//  - the cpu check and the key's text cap;
//  - the count against the caller's entries;
//  - the key file's three shapes and the order of the key's checks;
//  - the wipes.
// buf.c and ct.c are real, and ct_wipe is proof/ct_wipe_stub.c.
//
// Bounded: the caller's entries up to PROOF_ENTRIES and its DER room up
// to PROOF_ROOM bytes. Each pass of a call's loop over the blocks runs the
// same steps, so these sizes stand for any rooms a caller gives. The
// chain's bound of 255 certificates is past them: bin/pem_files_test and
// the differential hold it at 255 and 256. proof/pem_files_host_harness.c
// runs this harness in a host object, where cpu picks the multiply.
#include "harness.h"

#include "buf.h"
#include "cfg.h"
#include "cpu.h"
#include "p256_ecdh.h"
#include "pem.h"
#include "pem_blocks.h"
#include "widemul.h"
#include "x509_pem.h"

int nondet_int(void);
uint32_t nondet_u32(void);

// The caller's entries and DER room, at most.
#define PROOF_ENTRIES 4
#define PROOF_ROOM 16

// pem_blocks.h: PEM_BLOCKS_READ with the DER of 1 byte or more this call
// appended inside der's room, PEM_BLOCKS_END with nothing appended, or
// PEM_BLOCKS_REFUSED.
void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len, uint8_t rule) {
    __CPROVER_assert(__CPROVER_w_ok(b, sizeof *b), "blocks_init: the reader writable");
    __CPROVER_assert(pem_len == 0 || __CPROVER_r_ok(pem, pem_len), "blocks_init: input readable");
    __CPROVER_assert(rule == PEM_TEXT_REFUSED || rule == PEM_TEXT_SKIPPED,
                     "blocks_init: a text rule");
    rb_init(&b->text, pem, pem_len);
    b->rule = rule;
    b->started = 0;
}

int pem_blocks_next(pem_blocks *b, wbuf *der, const uint8_t **block, size_t *block_len) {
    __CPROVER_assert(__CPROVER_w_ok(b, sizeof *b) && __CPROVER_w_ok(der, sizeof *der) &&
                         __CPROVER_w_ok(block, sizeof *block) &&
                         __CPROVER_w_ok(block_len, sizeof *block_len),
                     "blocks_next: arguments writable");
    __CPROVER_assert(der->len <= der->cap && (der->cap == 0 || __CPROVER_w_ok(der->p, der->cap)),
                     "blocks_next: a room the caller placed");
    int pick = nondet_int();
    if (pick == 0) {
        return PEM_BLOCKS_END;
    }
    size_t n = nondet_size_t();
    if (pick == 1 || n < 1 || n > der->cap - der->len) {
        return PEM_BLOCKS_REFUSED;
    }
    *block = der->p + der->len;
    *block_len = n;
    der->len += n;
    b->started = 1;
    return PEM_BLOCKS_READ;
}

// pem_blocks.h: the CR and LF bytes skipped, the reader left at its end or
// at another byte, and the last of them returned.
uint8_t pem_skip_line_breaks(rbuf *r) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "skip: the reader writable");
    size_t gap = nondet_size_t();
    __CPROVER_assume(gap <= rb_left(r));
    rb_skip(r, gap);
    uint8_t last = nondet_u8();
    __CPROVER_assume(gap == 0 ? last == 0 : (last == '\r' || last == '\n'));
    return last;
}

// Where the EC PARAMETERS reader ran, and whether the EC PRIVATE KEY
// reader of pem_decode_one ran after it. parameters_der and
// parameters_len are the DER that pem_read_block wrote: its room and the
// bytes it appended there.
static int parameters_read;
static const uint8_t *parameters_at;
static const uint8_t *parameters_der;
static size_t parameters_len;
static const uint8_t *key_text;

// pem.h: one block of label, the whole input, appended to der.
int pem_decode_one(const uint8_t *pem, size_t pem_len, uint8_t label, wbuf *der) {
    __CPROVER_assert(pem_len == 0 || __CPROVER_r_ok(pem, pem_len), "decode_one: input readable");
    __CPROVER_assert(label == PEM_LABEL_PRIVATE_KEY || label == PEM_LABEL_EC_PRIVATE_KEY,
                     "decode_one: a key label");
    __CPROVER_assert(der->cap == CH_PEM_KEY_DER_MAX && der->len == 0,
                     "decode_one: an empty key room");
    __CPROVER_assert(!parameters_read || label == PEM_LABEL_EC_PRIVATE_KEY,
                     "decode_one: after the parameters, the EC PRIVATE KEY label alone");
    if (parameters_read) {
        key_text = pem;
    }
    fill_nondet(der->p, der->cap);
    if (!nondet_int()) {
        return 0;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= der->cap);
    der->len = n;
    return 1;
}

// pem.h: one block of label at r's position, appended to der. The key
// call reads the EC PARAMETERS label alone through it, into a room of
// CH_PEM_PARAMETERS_DER_MAX bytes.
int pem_read_block(rbuf *r, uint8_t label, wbuf *der) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r) && __CPROVER_w_ok(der, sizeof *der),
                     "read_block: reader and writer writable");
    __CPROVER_assert(label == PEM_LABEL_EC_PARAMETERS, "read_block: the parameters label");
    __CPROVER_assert(der->cap == CH_PEM_PARAMETERS_DER_MAX && der->len == 0,
                     "read_block: an empty parameters room");
    __CPROVER_assert(r->off == 0, "read_block: the parameters at the first byte");
    parameters_read = 1;
    parameters_at = r->p;
    fill_nondet(der->p, der->cap);
    if (!nondet_int()) {
        return 0;
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take >= 1 && take <= rb_left(r));
    rb_skip(r, take);
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= der->cap);
    der->len = n;
    parameters_der = der->p;
    parameters_len = n;
    return 1;
}

// x509_pem.h. The call passes the DER that pem_read_block wrote, and no
// byte of the room past it. An earlier call left any byte past it.
int x509_pem_parameters_are_p256(const uint8_t *der, size_t der_len) {
    __CPROVER_assert(der_len >= 1 && __CPROVER_r_ok(der, der_len), "parameters: DER readable");
    __CPROVER_assert(der == parameters_der && der_len == parameters_len,
                     "parameters: the DER the block wrote");
    return nondet_int() != 0;
}

// How many times the reader of outer fields answered yes since the count was
// last set to zero.
static size_t framed;

// x509_pem.h, as proof/x509_pem_harness.c proves it. Returns 1 with a
// Name and a key of two bytes or more each, inside the certificate, the
// Name first and anywhere in it. Or returns 0.
int x509_pem_read_subject_key(const uint8_t *cert, size_t cert_len, const uint8_t **name,
                              size_t *name_len, const uint8_t **spki, size_t *spki_len) {
    __CPROVER_assert(cert_len == 0 || __CPROVER_r_ok(cert, cert_len), "subject_key: readable");
    __CPROVER_assert(__CPROVER_w_ok(name, sizeof *name) && __CPROVER_w_ok(spki, sizeof *spki) &&
                         __CPROVER_w_ok(name_len, sizeof *name_len) &&
                         __CPROVER_w_ok(spki_len, sizeof *spki_len),
                     "subject_key: outputs writable");
    if (!nondet_int() || cert_len < 4) {
        return 0;
    }
    size_t name_at = nondet_size_t();
    size_t name_size = nondet_size_t();
    size_t spki_at = nondet_size_t();
    size_t spki_size = nondet_size_t();
    __CPROVER_assume(name_size >= 2 && spki_size >= 2 && name_at <= cert_len &&
                     name_size <= cert_len - name_at && spki_at >= name_at + name_size &&
                     spki_at <= cert_len && spki_size <= cert_len - spki_at);
    *name = cert + name_at;
    *name_len = name_size;
    *spki = cert + spki_at;
    *spki_len = spki_size;
    framed++;
    return 1;
}

// What the leaf check was asked, and what it answered.
static const uint8_t *asked_point;
static int answered;

int x509_pem_spki_is_p256(const uint8_t *spki, size_t spki_len, const uint8_t point[64]) {
    __CPROVER_assert(spki_len == 0 || __CPROVER_r_ok(spki, spki_len), "spki_is_p256: readable");
    __CPROVER_assert(__CPROVER_r_ok(point, 64), "spki_is_p256: point readable");
    asked_point = point;
    answered = nondet_int() != 0;
    return answered;
}

static int stub_key_reader(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                           const uint8_t **point) {
    __CPROVER_assert(der_len >= 1 && __CPROVER_r_ok(der, der_len), "key reader: DER readable");
    __CPROVER_assert(__CPROVER_w_ok(scalar, 32), "key reader: scalar writable");
    if (!nondet_int()) {
        return 0;
    }
    fill_nondet(scalar, 32);
    *point = NULL;
    if (nondet_int() && der_len >= 64) {
        size_t at = nondet_size_t();
        __CPROVER_assume(at <= der_len - 64);
        *point = der + at;
    }
    return 1;
}

int x509_pem_read_pkcs8(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                        const uint8_t **point) {
    __CPROVER_assert(!parameters_read, "pkcs8: never after the parameters");
    return stub_key_reader(der, der_len, scalar, point);
}

int x509_pem_read_sec1(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                       const uint8_t **point) {
    return stub_key_reader(der, der_len, scalar, point);
}

// Whether this object takes cpu, cpu.h's rule written out. A host object
// takes CH_CPU_PROBED and no bit the architecture leaves undefined. A
// device object takes 0 alone.
static int cpu_taken(uint32_t cpu) {
#ifdef CH_CPU_RUNTIME
    return (cpu & CH_CPU_PROBED) != 0 && (cpu & ~(uint32_t)CH_CPU_DEFINED) == 0;
#else
    return cpu == 0;
#endif
}

// The point keygen wrote, X then Y, to compare with what the call returns,
// the call's cpu value, and the multiply answer that value gives.
static uint8_t keygen_xy[64];
static int keygen_ran;
static uint32_t call_cpu;
static uint8_t expected_widemul;

// p256_ecdh.h: 1 with priv the draw and pub its point, or 0 with both
// zeroed.
int p256_ecdh_keygen(uint8_t widemul, const uint8_t draw[P256_SCALAR_LEN],
                     uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_POINT_LEN]) {
    __CPROVER_assert(cpu_taken(call_cpu), "keygen: only under a cpu value the object takes");
    __CPROVER_assert(widemul == expected_widemul, "keygen: the answer cpu gives");
    __CPROVER_assert(__CPROVER_r_ok(draw, P256_SCALAR_LEN), "keygen: draw readable");
    __CPROVER_assert(__CPROVER_w_ok(priv, P256_SCALAR_LEN) && __CPROVER_w_ok(pub, P256_POINT_LEN),
                     "keygen: outputs writable");
    if (!nondet_int()) {
        for (size_t i = 0; i < P256_SCALAR_LEN; i++) {
            priv[i] = 0;
        }
        for (size_t i = 0; i < P256_POINT_LEN; i++) {
            pub[i] = 0;
        }
        return 0;
    }
    for (size_t i = 0; i < P256_SCALAR_LEN; i++) {
        priv[i] = draw[i];
    }
    pub[0] = 0x04;
    for (size_t i = 0; i < 64; i++) {
        pub[1 + i] = nondet_u8();
        keygen_xy[i] = pub[1 + i];
    }
    keygen_ran = 1;
    return 1;
}

#include "pem_files.c"

static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

static uint8_t pem[8];
static uint8_t chain_der[PROOF_ROOM];
static uint8_t bundle_der[PROOF_ROOM];

static void prove_chain(void) {
    ch_cert chain[PROOF_ENTRIES];
    size_t der_len = nondet_size_t();
    size_t chain_max = nondet_size_t();
    __CPROVER_assume(der_len <= sizeof chain_der && chain_max <= PROOF_ENTRIES);
    uint8_t count = nondet_u8();
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem);
    framed = 0;
    int rc = ch_chain_from_pem(pem, pem_len, chain_der, der_len, chain, chain_max, &count);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "chain: two codes");
    if (rc == CH_OK) {
        __CPROVER_assert(count >= 1 && count <= chain_max, "chain: 1 to chain_max certificates");
        __CPROVER_assert(framed == count, "chain: every certificate's outer fields read");
        const uint8_t *next = chain_der;
        for (size_t i = 0; i < PROOF_ENTRIES && i < count; i++) {
            __CPROVER_assert(chain[i].der == next, "chain: back to back, in file order");
            __CPROVER_assert(inside(chain_der, der_len, chain[i].der, chain[i].len) &&
                                 chain[i].len >= 1,
                             "chain: each certificate inside the caller's room");
            next = chain[i].der + chain[i].len;
        }
    } else {
        __CPROVER_assert(count == 0, "chain: a refusal counts 0");
    }
}

static void prove_key(void) {
    uint8_t leaf[16];
    fill_nondet(leaf, sizeof leaf);
    size_t leaf_len = nondet_size_t();
    __CPROVER_assume(leaf_len <= sizeof leaf);
    // Any text up to this array, or one over the cap and past its end,
    // which the call must refuse before the stubs read it.
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem || pem_len > CH_PEM_KEY_TEXT_MAX);
    uint32_t cpu = nondet_u32();
    call_cpu = cpu;
#ifdef CH_CPU_RUNTIME
    expected_widemul =
        (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 ? WIDEMUL_CONSTANT_TIME : WIDEMUL_NOT_STATED;
#else
    expected_widemul = WIDEMUL_BUILD_ANSWER;
#endif
    uint8_t priv[32];
    uint8_t pub[64];
    fill_nondet(priv, sizeof priv);
    fill_nondet(pub, sizeof pub);
    asked_point = NULL;
    answered = 0;
    keygen_ran = 0;
    parameters_read = 0;
    parameters_at = NULL;
    parameters_der = NULL;
    parameters_len = 0;
    key_text = NULL;
    int rc = ch_p256_key_from_pem(cpu, pem, pem_len, leaf, leaf_len, priv, pub);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "key: two codes");
    __CPROVER_assert(!parameters_read || parameters_at == pem,
                     "key: the parameters read from the first byte");
    __CPROVER_assert(key_text == NULL || (key_text >= pem && key_text <= pem + pem_len),
                     "key: the key after the parameters, inside the text");
    if (rc == CH_OK) {
        __CPROVER_assert(cpu_taken(cpu), "key: a cpu value the object takes");
        __CPROVER_assert(pem_len <= CH_PEM_KEY_TEXT_MAX, "key: under the text cap");
        __CPROVER_assert(keygen_ran && answered && asked_point == pub,
                         "key: the leaf answered yes for the point returned");
        for (size_t i = 0; i < 64; i++) {
            __CPROVER_assert(pub[i] == keygen_xy[i], "key: the point is the scalar's");
        }
    } else {
        for (size_t i = 0; i < 32; i++) {
            __CPROVER_assert(priv[i] == 0, "key: a refusal zeroes priv");
        }
        for (size_t i = 0; i < 64; i++) {
            __CPROVER_assert(pub[i] == 0, "key: a refusal zeroes pub");
        }
    }
}

static void prove_anchors(void) {
    ch_trust_anchor anchors[PROOF_ENTRIES];
    size_t der_len = nondet_size_t();
    size_t anchor_max = nondet_size_t();
    __CPROVER_assume(der_len <= sizeof bundle_der && anchor_max <= PROOF_ENTRIES);
    size_t count = nondet_size_t();
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem);
    int rc = ch_anchors_from_pem(pem, pem_len, bundle_der, der_len, anchors, anchor_max, &count);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "anchors: two codes");
    if (rc == CH_OK) {
        __CPROVER_assert(count >= 1 && count <= anchor_max, "anchors: 1 to anchor_max");
        for (size_t i = 0; i < PROOF_ENTRIES && i < count; i++) {
            __CPROVER_assert(inside(bundle_der, der_len, anchors[i].name, anchors[i].name_len) &&
                                 inside(bundle_der, der_len, anchors[i].spki, anchors[i].spki_len),
                             "anchors: each Name and key inside the caller's room");
        }
    } else {
        __CPROVER_assert(count == 0, "anchors: a refusal counts 0");
    }
}

int main(void) {
    fill_nondet(pem, sizeof pem);
    prove_chain();
    prove_key();
    prove_anchors();
    return 0;
}
