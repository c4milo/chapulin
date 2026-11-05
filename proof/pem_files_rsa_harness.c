// Proves: ch_rsa_key_from_pem (pem_files.c) is memory-safe and UB-free
// over any input, and honours its contract (pem_files.h):
//
//   - CH_OK only for a cpu value the object takes, and only after one
//     PRIVATE KEY block alone and the end of the run;
//   - CH_OK only with n_len inside rsa.h's bound, and in a host object
//     with both primes' top bits set in the key;
//   - CH_OK only when the leaf was asked about the key's modulus and
//     answered yes;
//   - CH_OK only when the ladder signed and its signature verified under
//     the key's modulus, and, in a host object under
//     CH_CPU_CONSTANT_TIME_MULTIPLY, when rsa_sign64.c signed and its
//     signature verified too;
//   - CH_EINVAL with every byte of the key zero, on every path.
//
// Layered, as proof/pem_files_harness.c is: the readers below the call
// are stubs that assert the contracts their headers state and havoc
// within what their own harnesses prove. pem_blocks_next and the
// x509_pem readers are proof/pem_blocks_harness.c's and
// proof/x509_pem_rsa_harness.c's. The signers and the verifiers are
// rsa_sign.h's, rsa_sign64.h's and rsa.h's contracts. So the object under
// proof is the order of the call's own steps, the fields each integer
// lands in, and the wipes. buf.c and ct.c are real, and ct_wipe is
// proof/ct_wipe_stub.c.
//
// The DER room is the call's own array, which CBMC treats as holding any
// bytes, so the stub of pem_blocks_next writes none of them.
// proof/pem_files_rsa_host_harness.c runs this harness in a host object.
#include "harness.h"

#include "buf.h"
#include "cfg.h"
#include "cpu.h"
#include "pem.h"
#include "pem_blocks.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "widemul.h"
#include "x509_pem.h"

int nondet_int(void);
uint32_t nondet_u32(void);

// What the run under way has read, which pem_blocks_init clears.
static size_t run_count;
static uint8_t run_label;
static const uint8_t *run_der;
static size_t run_der_len;
static int run_ended;
static int run_stopped;

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
    __CPROVER_assert(label == PEM_LABEL_PRIVATE_KEY, "blocks_next: PRIVATE KEY alone");
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
    if (run_count == 0) {
        run_label = label;
        run_der = *block;
        run_der_len = n;
    }
    run_count++;
    der->len += n;
    b->started = 1;
    return PEM_BLOCKS_READ;
}

// x509_pem.h: 1 with every field inside der, or 0.
int x509_pem_read_rsa_pkcs8(const uint8_t *der, size_t der_len, x509_pem_rsa_key *key) {
    __CPROVER_assert(run_ended && run_count == 1 && run_label == PEM_LABEL_PRIVATE_KEY,
                     "pkcs8: after a PRIVATE KEY block alone, and the end");
    __CPROVER_assert(der == run_der && der_len == run_der_len, "pkcs8: the DER of the key block");
    __CPROVER_assert(__CPROVER_w_ok(key, sizeof *key), "pkcs8: fields writable");
    if (!nondet_int()) {
        return 0;
    }
    x509_pem_integer *fields[] = {&key->n,  &key->d,  &key->p,   &key->q,
                                  &key->dp, &key->dq, &key->qinv};
    for (size_t i = 0; i < 7; i++) {
        size_t at = nondet_size_t();
        size_t len = nondet_size_t();
        __CPROVER_assume(len >= 1 && at <= der_len && len <= der_len - at);
        fields[i]->bytes = der + at;
        fields[i]->len = len;
    }
    return 1;
}

// x509_pem.h: reads out_len bytes of v's value into out. Returns 1 or 0.
// It writes the field's first and last bytes and leaves the rest as they
// were. The call's test of the primes' top bits reads a first byte, and
// rsa_pss_sign_key_ok reads the modulus's first and last. No other step
// reads a byte of a field, and the stubs below read the key by its
// address alone. So the formula holds no loop of a field's length.
int x509_pem_integer_to_bytes(x509_pem_integer v, uint8_t *out, size_t out_len) {
    __CPROVER_assert(v.len >= 1 && __CPROVER_r_ok(v.bytes, v.len), "integer: octets readable");
    __CPROVER_assert(out_len >= 1 && __CPROVER_w_ok(out, out_len), "integer: field writable");
    out[0] = nondet_u8();
    out[out_len - 1] = nondet_u8();
    return nondet_int() != 0;
}

// What the leaf check was asked, and what it answered.
static const uint8_t *asked_n;
static size_t asked_n_len;
static int leaf_answered;

int x509_pem_spki_is_rsa(const uint8_t *spki, size_t spki_len, const uint8_t *n, size_t n_len) {
    __CPROVER_assert(spki_len == 0 || __CPROVER_r_ok(spki, spki_len), "spki_is_rsa: readable");
    __CPROVER_assert(n_len >= 1 && __CPROVER_r_ok(n, n_len), "spki_is_rsa: n readable");
    asked_n = n;
    asked_n_len = n_len;
    leaf_answered = nondet_int() != 0;
    return leaf_answered;
}

int x509_pem_read_subject_key(const uint8_t *cert, size_t cert_len, const uint8_t **name,
                              size_t *name_len, const uint8_t **spki, size_t *spki_len) {
    __CPROVER_assert(cert_len == 0 || __CPROVER_r_ok(cert, cert_len), "subject_key: readable");
    if (!nondet_int() || cert_len < 4) {
        return 0;
    }
    size_t spki_at = nondet_size_t();
    size_t spki_size = nondet_size_t();
    __CPROVER_assume(spki_size >= 2 && spki_at <= cert_len && spki_size <= cert_len - spki_at);
    *name = cert;
    *name_len = 2;
    *spki = cert + spki_at;
    *spki_len = spki_size;
    return 1;
}

static uint32_t call_cpu;
static const ch_rsa_priv *call_key;

// Each signer's signature, by the signer that wrote it: 0 for the ladder,
// 1 for rsa_sign64.c. A verdict is recorded under the signature it read.
static const uint8_t *signed_at[2];
static int verified[2];

static int stub_sign(int signer, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                     const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                     size_t *sig_len) {
    __CPROVER_assert(k == call_key, "sign: the key the call wrote");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32) && __CPROVER_r_ok(salt, RSA_PSS_SALT_LEN),
                     "sign: digest and salt readable");
    __CPROVER_assert(k->n_len >= 1 && k->n_len <= cap && __CPROVER_w_ok(sig, k->n_len),
                     "sign: a room of n_len bytes");
    if (!nondet_int()) {
        return 0;
    }
    *sig_len = k->n_len;
    signed_at[signer] = sig;
    return 1;
}

int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 const uint8_t salt[RSA_PSS_SALT_LEN], const uint8_t blind[RSA_BLIND_LEN],
                 uint8_t *sig, size_t cap, size_t *sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(blind, RSA_BLIND_LEN), "sign: blind readable");
    return stub_sign(0, k, msg_hash, salt, sig, cap, sig_len);
}

#ifdef CH_CPU_RUNTIME
int rsa_sign64_key_ok(const ch_rsa_priv *k) {
    __CPROVER_assert(k == call_key, "sign64 key test: the key the call wrote");
    return nondet_int() != 0;
}

int rsa_sign64_pss(uint32_t cpu, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                   const uint8_t salt[RSA_PSS_SALT_LEN], const uint8_t blind[RSA_BLIND_LEN],
                   uint8_t *sig, size_t cap, size_t *sig_len) {
    __CPROVER_assert(cpu == call_cpu && (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0,
                     "sign64: only under the multiply bit");
    __CPROVER_assert(__CPROVER_r_ok(blind, RSA_BLIND_LEN), "sign64: blind readable");
    return stub_sign(1, k, msg_hash, salt, sig, cap, sig_len);
}
#endif

static int stub_verify(const uint8_t *n, size_t n_len, const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(n == call_key->n && n_len == call_key->n_len, "verify: the key's modulus");
    __CPROVER_assert(sig_len == n_len && __CPROVER_r_ok(sig, sig_len), "verify: one signature");
    int yes = nondet_int() != 0;
    for (int s = 0; s < 2; s++) {
        if (sig == signed_at[s]) {
            verified[s] = yes;
        }
    }
    return yes;
}

int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    (void)msg_hash;
    return stub_verify(n, n_len, sig, sig_len);
}

#ifdef CH_CPU_RUNTIME
int rsa_pss_verify_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t msg_hash[32],
                       const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(cpu == call_cpu, "verify: the call's cpu value");
    (void)msg_hash;
    return stub_verify(n, n_len, sig, sig_len);
}
#endif

#include "pem_files.c"

// Whether this object takes cpu, cpu.h's rule written out.
static int cpu_taken(uint32_t cpu) {
#ifdef CH_CPU_RUNTIME
    return (cpu & CH_CPU_PROBED) != 0 && (cpu & ~(uint32_t)CH_CPU_DEFINED) == 0;
#else
    return cpu == 0;
#endif
}

static int crt_signer_runs(uint32_t cpu) {
#ifdef CH_CPU_RUNTIME
    return (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0;
#else
    (void)cpu;
    return 0;
#endif
}

static uint8_t pem[8];
static uint8_t leaf[16];
static ch_rsa_priv key;

int main(void) {
    fill_nondet(pem, sizeof pem);
    fill_nondet(leaf, sizeof leaf);
    size_t pem_len = nondet_size_t();
    size_t leaf_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem && leaf_len <= sizeof leaf);
    uint32_t cpu = nondet_u32();
    call_cpu = cpu;
    call_key = &key;
    fill_nondet((uint8_t *)&key, sizeof key);
    int rc = ch_rsa_key_from_pem(cpu, pem, pem_len, leaf, leaf_len, &key);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "rsa key: two codes");
    if (rc == CH_OK) {
        __CPROVER_assert(cpu_taken(cpu), "rsa key: a cpu value the object takes");
        __CPROVER_assert(key.n_len >= 256 && key.n_len <= CH_RSA_MODULUS_MAX,
                         "rsa key: n_len inside the bound");
        __CPROVER_assert(leaf_answered && asked_n == key.n && asked_n_len == key.n_len,
                         "rsa key: the leaf answered yes for the key's modulus");
#ifdef CH_CPU_RUNTIME
        __CPROVER_assert((key.p[0] & key.q[0] & 0x80) != 0, "rsa key: both top bits set");
#endif
        __CPROVER_assert(signed_at[0] != NULL && verified[0],
                         "rsa key: the ladder's signature verified");
        __CPROVER_assert(!crt_signer_runs(cpu) || (signed_at[1] != NULL && verified[1]),
                         "rsa key: under the multiply bit, rsa_sign64.c's verified too");
    } else {
        const uint8_t *b = (const uint8_t *)&key;
        for (size_t i = 0; i < sizeof key; i++) {
            __CPROVER_assert(b[i] == 0, "rsa key: a refusal zeroes the key");
        }
    }
    return 0;
}
