// Stub only. srv_cookie.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
#include "srv_cookie.h"

#ifdef CH_ROLE_SERVER

size_t srv_cookie_mint(const uint8_t key[SRV_COOKIE_KEY_LEN], uint16_t suite, uint16_t group,
                       const uint8_t *ch1_hash, size_t hash_len, const uint8_t frozen[SHA256_LEN],
                       uint8_t *out, size_t cap) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)key;
    (void)suite;
    (void)group;
    (void)ch1_hash;
    (void)hash_len;
    (void)frozen;
    (void)out;
    (void)cap;
    return 0;
}

int srv_cookie_open(const uint8_t key[SRV_COOKIE_KEY_LEN], const uint8_t *cookie, size_t n,
                    uint16_t *suite, uint16_t *group, uint8_t *ch1_hash, size_t *hash_len,
                    uint8_t frozen[SHA256_LEN]) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)key;
    (void)cookie;
    (void)n;
    (void)suite;
    (void)group;
    (void)ch1_hash;
    (void)hash_len;
    (void)frozen;
    return CH_EPROTO;
}

#endif // CH_ROLE_SERVER
