// Stub only. srv_auth.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
//
// Two of these refuse for a second reason that outlives the stub phase: the signers
// they call, p256_sign.c and rsa_sign.c, are not in this tree at all. srv_auth.h
// names both and states what each must hold to.
#include "srv_auth.h"

#ifdef CH_ROLE_SERVER

uint8_t srv_identity_live(const ch_cfg *cfg) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)cfg;
    // 0 says no identity is provisioned, which is the configuration ch_srv_check
    // refuses.
    return 0;
}

const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)cfg;
    (void)sigalg;
    return NULL;
}

void srv_hash_signed_content(uint16_t sigalg, const uint8_t *transcript_hash, size_t hash_len,
                             uint8_t out[SHA256_LEN]) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)sigalg;
    (void)transcript_hash;
    (void)hash_len;
    (void)out;
}

int srv_sign_certificate_verify(const ch_cfg *cfg, uint16_t sigalg, const uint8_t *transcript_hash,
                                size_t hash_len, uint8_t *sig, size_t cap, size_t *sig_len,
                                uint8_t *alert) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)cfg;
    (void)sigalg;
    (void)transcript_hash;
    (void)hash_len;
    (void)sig;
    (void)cap;
    (void)sig_len;
    (void)alert;
    return CH_EINVAL;
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)cfg;
    (void)sigalg;
    return CH_EINVAL;
}

#endif // CH_ROLE_SERVER
