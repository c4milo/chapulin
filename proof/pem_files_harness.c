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
//     p256_ecdh_keygen_cpu wrote for the scalar, under the multiply answer
//     that cpu gives. CH_EINVAL with priv and pub zero, on every path.
//     Each key reader runs only on the DER of its shape's key block, in a
//     run of blocks that ended: PKCS #8 after a PRIVATE KEY block alone,
//     SEC 1 after an EC PRIVATE KEY block alone, or after an EC PARAMETERS
//     block that names prime256v1 and an EC PRIVATE KEY block;
//   - ch_anchors_from_pem: CH_OK with 1 to anchor_max anchors, each Name
//     and key inside the caller's DER room; CH_EINVAL with a count of 0.
//
// Layered: the readers below these calls are stubs. They assert the
// contracts their headers state, and havoc within what their own
// harnesses prove:
//  - pem_blocks_init and pem_blocks_next (proof/pem_blocks_harness.c);
//  - the five x509_pem readers (proof/x509_pem_harness.c and
//    x509_pem_key_harness.c);
//  - p256_ecdh_keygen_cpu (proof/p256_ecdh_harness.c).
// So the object under proof is the order of the calls' own steps:
//  - the cpu check;
//  - the label of each block and the count against the caller's entries;
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

// The labels the call under proof may name: CERTIFICATE alone for a chain
// and a bundle, and the three key labels for a key file.
static unsigned allowed_labels;

// What the run under way has read, which each pem_blocks_init clears: the
// labels of the blocks read, the DER of each, whether a call returned
// PEM_BLOCKS_END, and whether a call returned END or REFUSED, after which
// the caller makes no further call.
static size_t run_count;
static uint8_t run_labels[2];
static const uint8_t *run_der[2];
static size_t run_der_len[2];
static int run_ended;
static int run_stopped;

// pem_blocks.h: PEM_BLOCKS_READ with the DER of 1 byte or more this call
// appended inside der's room, PEM_BLOCKS_END with nothing appended, or
// PEM_BLOCKS_REFUSED.
void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len) {
    __CPROVER_assert(__CPROVER_w_ok(b, sizeof *b), "blocks_init: the reader writable");
    __CPROVER_assert(pem_len == 0 || __CPROVER_r_ok(pem, pem_len), "blocks_init: input readable");
    rb_init(&b->text, pem, pem_len);
    b->started = 0;
    run_count = 0;
    run_ended = 0;
    run_stopped = 0;
}

int pem_blocks_next(pem_blocks *b, uint8_t label, wbuf *der, const uint8_t **block,
                    size_t *block_len) {
    __CPROVER_assert(__CPROVER_w_ok(b, sizeof *b) && __CPROVER_w_ok(der, sizeof *der) &&
                         __CPROVER_w_ok(block, sizeof *block) &&
                         __CPROVER_w_ok(block_len, sizeof *block_len),
                     "blocks_next: arguments writable");
    __CPROVER_assert(der->len <= der->cap && (der->cap == 0 || __CPROVER_w_ok(der->p, der->cap)),
                     "blocks_next: a room the caller placed");
    __CPROVER_assert(label < PEM_LABEL_COUNT && (allowed_labels & (1u << label)) != 0,
                     "blocks_next: a label the call reads");
    __CPROVER_assert(!run_stopped, "blocks_next: no call after END or REFUSED");
    int pick = nondet_int();
    if (pick == 0) {
        run_ended = 1;
        run_stopped = 1;
        return PEM_BLOCKS_END;
    }
    size_t n = nondet_size_t();
    if (pick == 1 || n < 1 || n > der->cap - der->len) {
        run_stopped = 1;
        return PEM_BLOCKS_REFUSED;
    }
    *block = der->p + der->len;
    *block_len = n;
    fill_nondet(der->p + der->len, n);
    if (run_count < 2) {
        run_labels[run_count] = label;
        run_der[run_count] = *block;
        run_der_len[run_count] = n;
    }
    run_count++;
    der->len += n;
    b->started = 1;
    return PEM_BLOCKS_READ;
}

// Whether the run that ended read exactly the blocks of labels first and,
// when second is not 0xff, second.
static int run_was(uint8_t first, uint8_t second) {
    if (!run_ended) {
        return 0;
    }
    if (second == 0xff) {
        return run_count == 1 && run_labels[0] == first;
    }
    return run_count == 2 && run_labels[0] == first && run_labels[1] == second;
}

// Whether the parameters check ran on the run's EC PARAMETERS block and
// answered yes.
static int parameters_named_p256;

// x509_pem.h. The call passes the DER of the run's EC PARAMETERS block, in
// its own room, and no byte past it.
int x509_pem_parameters_are_p256(const uint8_t *der, size_t der_len) {
    __CPROVER_assert(run_was(PEM_LABEL_EC_PARAMETERS, PEM_LABEL_EC_PRIVATE_KEY),
                     "parameters: after EC PARAMETERS and EC PRIVATE KEY, and the end");
    __CPROVER_assert(der == run_der[0] && der_len == run_der_len[0],
                     "parameters: the DER the block wrote");
    __CPROVER_assert(der_len <= CH_PEM_PARAMETERS_DER_MAX, "parameters: inside its room");
    parameters_named_p256 = nondet_int() != 0;
    return parameters_named_p256;
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
    __CPROVER_assert(run_was(PEM_LABEL_PRIVATE_KEY, 0xff),
                     "pkcs8: after a PRIVATE KEY block alone, and the end");
    __CPROVER_assert(der == run_der[0] && der_len == run_der_len[0],
                     "pkcs8: the DER of the key block");
    return stub_key_reader(der, der_len, scalar, point);
}

int x509_pem_read_sec1(const uint8_t *der, size_t der_len, uint8_t scalar[32],
                       const uint8_t **point) {
    int alone = run_was(PEM_LABEL_EC_PRIVATE_KEY, 0xff);
    int under = run_was(PEM_LABEL_EC_PARAMETERS, PEM_LABEL_EC_PRIVATE_KEY);
    __CPROVER_assert(alone || (under && parameters_named_p256),
                     "sec1: after an EC PRIVATE KEY block, alone or under prime256v1's parameters");
    size_t key = alone ? 0 : 1;
    __CPROVER_assert(der == run_der[key] && der_len == run_der_len[key],
                     "sec1: the DER of the key block");
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
int p256_ecdh_keygen_cpu(uint32_t cpu, uint8_t widemul, const uint8_t draw[P256_SCALAR_LEN],
                         uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_POINT_LEN]) {
    __CPROVER_assert(cpu_taken(call_cpu), "keygen: only under a cpu value the object takes");
    __CPROVER_assert(cpu == call_cpu, "keygen: the cpu value the key call took");
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
    allowed_labels = 1u << PEM_LABEL_CERTIFICATE;
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
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem);
    allowed_labels = (1u << PEM_LABEL_PRIVATE_KEY) | (1u << PEM_LABEL_EC_PRIVATE_KEY) |
                     (1u << PEM_LABEL_EC_PARAMETERS);
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
    parameters_named_p256 = 0;
    int rc = ch_p256_key_from_pem(cpu, pem, pem_len, leaf, leaf_len, priv, pub);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "key: two codes");
    if (rc == CH_OK) {
        __CPROVER_assert(cpu_taken(cpu), "key: a cpu value the object takes");
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
    allowed_labels = 1u << PEM_LABEL_CERTIFICATE;
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
