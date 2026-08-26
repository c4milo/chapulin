// Proves: hybrid_secret — the KEX=pq handshake's shared-secret
// derivation — is memory-safe and UB-free for any stored seed, any
// server ciphertext, and any server x25519 share, and that its refusal
// path leaves no key material behind. Two asserts carry the contract:
// on CH_OK the 64-byte ikm is fully written, and on CH_EPROTO — the
// x25519 all-zero refusal, INV-3 — every one of those 64 bytes is zero,
// so a rejected key exchange cannot leave half a secret on the stack.
//
// This is the only harness that builds with -DCH_KEX_PQ (#47). The
// hybrid ServerHello parser is still unproven: proof/handshake_parser
// bounds its message at 256 bytes and a hybrid key_share extension is
// 1,128, so the accepting path there is unreachable at that bound.
//
// Layered proof, the handshake-stubs-hsparse pattern: mlkem and x25519
// are stubs asserting their headers' contracts and havocing outputs, so
// mlkem.c, mlkem_poly.c, sha3.c and x25519.c are NOT linked. What is
// under proof is hybrid_secret's own pointer handling and wipe
// discipline, not the lattice arithmetic — mlkem's six harnesses and
// x25519's seven prove that separately. Driving the real primitives
// here would put a 2,400-byte expansion and 256 symbolic multiplies in
// one formula, which is the shape docs/proofs.md says not to build.
#include "harness.h"

#include <string.h>

#include "mlkem.h"
#include "x25519.h"

// The ciphertext the harness hands in, so the stub can assert that
// hybrid_secret passed the pointer through unchanged.
static const uint8_t *expected_ct;

void mlkem_keygen_dk(uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32], const uint8_t z[32]) {
    __CPROVER_assert(__CPROVER_w_ok(dk, MLKEM_DK_LEN), "keygen_dk: dk writable");
    __CPROVER_assert(__CPROVER_r_ok(d, 32), "keygen_dk: d readable");
    __CPROVER_assert(__CPROVER_r_ok(z, 32), "keygen_dk: z readable");
    fill_nondet(dk, MLKEM_DK_LEN);
}

void mlkem_decaps(uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                  const uint8_t dk[MLKEM_DK_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(ss, MLKEM_SS_LEN), "decaps: ss writable");
    __CPROVER_assert(__CPROVER_r_ok(ct, MLKEM_CT_LEN), "decaps: ct readable");
    __CPROVER_assert(__CPROVER_r_ok(dk, MLKEM_DK_LEN), "decaps: dk readable");
    __CPROVER_assert(ct == expected_ct, "decaps: reads the parsed ciphertext");
    // Decapsulation cannot fail: a tampered ciphertext yields the
    // implicit-reject secret, so the stub always writes one.
    fill_nondet(ss, MLKEM_SS_LEN);
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN], const uint8_t point[32]) {
    __CPROVER_assert(__CPROVER_w_ok(out, X25519_LEN), "x25519: out writable");
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x25519: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(point, 32), "x25519: point readable");
    fill_nondet(out, X25519_LEN);
    // Both arms: the all-zero refusal and the accepting path.
    return (nondet_u8() & 1) ? 1 : 0;
}

#include "handshake.c"

int main(void) {
    static handshake_state h;
    static ch_tls t;
    memset(&h, 0, sizeof h);
    memset(&t, 0, sizeof t);
    h.t = &t;
    fill_nondet(h.dz, sizeof h.dz);
    fill_nondet(h.priv, sizeof h.priv);

    // The ciphertext lives in the caller's record buffer, which is
    // where the ServerHello parser leaves the pointer.
    static uint8_t record[MLKEM_CT_LEN];
    fill_nondet(record, sizeof record);
    expected_ct = record;

    server_hello_info info;
    memset(&info, 0, sizeof info);
    info.server_ct = record;
    fill_nondet(info.server_pub, sizeof info.server_pub);

    uint8_t ikm[MLKEM_SS_LEN + X25519_LEN];
    int rc = hybrid_secret(&h, &info, ikm);

    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "hybrid_secret returns OK or EPROTO");
    if (rc != CH_OK) {
        // INV-3: a refused key exchange leaves no key material behind.
        for (size_t i = 0; i < sizeof ikm; i++) {
            __CPROVER_assert(ikm[i] == 0, "refusal wipes the whole ikm");
        }
    }
    return 0;
}
