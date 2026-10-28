// Proves: srv_kex.c's PROFILE=cnsa2 arm (docs/decisions.md 162), over an
// unconstrained offer, reads and writes only inside its buffers, commits no
// undefined behavior, and keeps its four rules:
//  - srv_kex_group answers CH_GROUP_MLKEM1024 exactly when the hello listed
//    it, and 0 otherwise;
//  - srv_kex_shared answers 1 exactly for that group with a share;
//  - srv_kex_share hands the encapsulation the client's whole share and
//    reports MLKEM_CT_LEN bytes, or refuses with h->mlkem_ss zero;
//  - srv_kex_secret writes the encapsulation's shared secret as the whole
//    input keying material, MLKEM_SS_LEN bytes, and wipes h->mlkem_ss.
//
// The encapsulation and the randomness are contract stubs, as srv_kex's own
// harness stubs them: each asserts the buffers the real function reads and
// writes and havocs its outputs. A host object's dispatch can reach the
// encapsulation under three names (mlkem.h), so each is stubbed by the same
// contract. The mlkem harnesses prove the real one.
#include "harness.h"

#include <string.h>

#include "srv_kex.h"

static uint8_t ek_bytes[MLKEM_EK_LEN];
static const uint8_t *encaps_ek;
static uint8_t encaps_ss[MLKEM_SS_LEN];

void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "rand: output writable");
    fill_nondet(p, n);
    __CPROVER_assume(n == 0 || p[0] != 0);
}

static int encaps_contract(uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                           const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    __CPROVER_assert(__CPROVER_w_ok(ct, MLKEM_CT_LEN), "encaps: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(ss, MLKEM_SS_LEN), "encaps: secret writable");
    __CPROVER_assert(__CPROVER_r_ok(ek, MLKEM_EK_LEN), "encaps: key readable");
    __CPROVER_assert(__CPROVER_r_ok(m, 32), "encaps: randomness readable");
    encaps_ek = ek;
    if ((nondet_u8() & 1) != 0) {
        return 1;
    }
    fill_nondet(ss, MLKEM_SS_LEN);
    memcpy(encaps_ss, ss, MLKEM_SS_LEN);
    return 0;
}

int mlkem_encaps_derand(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    (void)widemul;
    return encaps_contract(ct, ss, ek, m);
}

int mlkem_encaps_derand_hw(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                           const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    (void)widemul;
    return encaps_contract(ct, ss, ek, m);
}

int mlkem_encaps_derand_avx2(uint8_t widemul, uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                             const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    (void)widemul;
    return encaps_contract(ct, ss, ek, m);
}

#include "srv_kex.c"

static int zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    static ch_tls t;
    t.cfg.cpu = nondet_u32();
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    srv_kex_begin(&h);

    client_hello ch;
    memset(&ch, 0, sizeof ch);
    ch.groups = nondet_u8();
    ch.shares = nondet_u8();
    __CPROVER_assume((ch.shares & (uint8_t)~ch.groups) == 0);
    ch.mlkem_share = (ch.shares & SRV_GROUP_MLKEM1024) != 0 ? ek_bytes : NULL;
    fill_nondet(ek_bytes, sizeof ek_bytes);

    uint16_t group = srv_kex_group(&ch);
    int listed = (ch.groups & SRV_GROUP_MLKEM1024) != 0;
    __CPROVER_assert(group == (listed ? CH_GROUP_MLKEM1024 : 0),
                     "ML-KEM-1024 is chosen exactly when the hello listed it");
    int shared = srv_kex_shared(&ch, group);
    __CPROVER_assert(shared == (listed && ch.mlkem_share != NULL),
                     "the group is shared exactly when its share arrived");
    if (!shared) {
        return 0;
    }

    uint8_t share[SRV_KEX_SHARE_MAX];
    size_t share_len = 0;
    int rc = srv_kex_share(&h, &ch, group, share, &share_len);
    __CPROVER_assert(encaps_ek == ek_bytes, "the encapsulation reads the client's share");
    if (rc != CH_OK) {
        __CPROVER_assert(rc == CH_EPROTO && zero(h.mlkem_ss, sizeof h.mlkem_ss),
                         "a refused key leaves no shared secret");
        return 0;
    }
    __CPROVER_assert(share_len == MLKEM_CT_LEN, "the share is the ciphertext");

    uint8_t ikm[SRV_KEX_SECRET_MAX];
    size_t ikm_len = 0;
    rc = srv_kex_secret(&h, &ch, group, ikm, &ikm_len);
    __CPROVER_assert(rc == CH_OK && ikm_len == MLKEM_SS_LEN, "the secret is ML-KEM's alone");
    __CPROVER_assert(memcmp(ikm, encaps_ss, MLKEM_SS_LEN) == 0,
                     "the input keying material is the encapsulation's secret");
    __CPROVER_assert(zero(h.mlkem_ss, sizeof h.mlkem_ss), "the shared secret is wiped");
    return 0;
}
