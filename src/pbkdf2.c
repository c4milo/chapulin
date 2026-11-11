// PBKDF2-HMAC-SHA-256. Contract in pbkdf2.h and scram.h. Outside a
// CH_SCRAM build the file holds nothing, and the header's includes keep
// the unit from being empty.
//
// The password is HMAC's key in every one of the iterations. So the file
// hashes the key's two pad blocks once, keeps the two states, and starts
// each HMAC from a copy of them (RFC 2104 section 4 describes the
// saving). An iteration then costs two compressions, the inner hash's
// last and the outer hash's last, in place of four.
#include "pbkdf2.h"

#ifdef CH_SCRAM

#include "ct.h"
#include "scram.h"
#include "sha256.h"

// HMAC's key, as the two hash states that follow its pad blocks: SHA-256
// after K xor ipad, and SHA-256 after K xor opad (RFC 2104 section 2).
typedef struct {
    sha256 inner;
    sha256 outer;
} hmac_key;

// Starts key from the password: a password of up to one block as it is,
// with zero bytes after it, and a longer one hashed first.
static void key_start(hmac_key *key, const uint8_t *password, size_t password_len) {
    uint8_t block[SHA256_BLOCK] = {0};
    if (password_len > SHA256_BLOCK) {
        sha256 s;
        sha256_init(&s);
        sha256_update(&s, password, password_len);
        sha256_final(&s, block);
        ct_wipe(&s, sizeof s);
    } else {
        for (size_t i = 0; i < password_len; i++) {
            block[i] = password[i];
        }
    }
    uint8_t pad[SHA256_BLOCK];
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        pad[i] = block[i] ^ 0x36;
    }
    sha256_init(&key->inner);
    sha256_update(&key->inner, pad, sizeof pad);
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        pad[i] = block[i] ^ 0x5c;
    }
    sha256_init(&key->outer);
    sha256_update(&key->outer, pad, sizeof pad);
    ct_wipe(block, sizeof block);
    ct_wipe(pad, sizeof pad);
}

// out = HMAC(key, first then second). An empty part adds no bytes, and
// its pointer may be NULL. out may be first.
static void prf(const hmac_key *key, const uint8_t *first, size_t first_len,
                const uint8_t *second, size_t second_len, uint8_t out[SHA256_LEN]) {
    sha256 s = key->inner;
    if (first_len != 0) {
        sha256_update(&s, first, first_len);
    }
    if (second_len != 0) {
        sha256_update(&s, second, second_len);
    }
    uint8_t digest[SHA256_LEN];
    sha256_final(&s, digest);
    s = key->outer;
    sha256_update(&s, digest, sizeof digest);
    sha256_final(&s, out);
    ct_wipe(&s, sizeof s);
    ct_wipe(digest, sizeof digest);
}

// One block of the output, T_i of RFC 8018 section 5.2: the XOR of
// iteration_count values, where the first is the PRF of the salt and the
// block's index, and each next one is the PRF of the one before.
static void block_of(const hmac_key *key, const uint8_t *salt, size_t salt_len,
                     uint32_t block_index, uint32_t iteration_count, uint8_t t[SHA256_LEN]) {
    const uint8_t index[4] = {(uint8_t)(block_index >> 24), (uint8_t)(block_index >> 16),
                              (uint8_t)(block_index >> 8), (uint8_t)block_index};
    uint8_t u[SHA256_LEN];
    prf(key, salt, salt_len, index, sizeof index, u);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        t[i] = u[i];
    }
    for (uint32_t iteration = 1; iteration < iteration_count; iteration++) {
        prf(key, u, sizeof u, NULL, 0, u);
        for (size_t i = 0; i < SHA256_LEN; i++) {
            t[i] ^= u[i];
        }
    }
    ct_wipe(u, sizeof u);
}

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                       size_t salt_len, uint32_t iteration_count, uint8_t *out, size_t out_len) {
    if (iteration_count == 0 || out_len == 0 || out_len > CH_PBKDF2_OUT_LEN_MAX) {
        return CH_EINVAL;
    }
    hmac_key key;
    key_start(&key, password, password_len);
    uint8_t t[SHA256_LEN];
    size_t written = 0;
    // The blocks count from 1 (RFC 8018 section 5.2, step 3), and the
    // bound on out_len keeps the count at 65,536 or less.
    uint32_t block_index = 1;
    while (written < out_len) {
        block_of(&key, salt, salt_len, block_index, iteration_count, t);
        size_t n = out_len - written < SHA256_LEN ? out_len - written : SHA256_LEN;
        for (size_t i = 0; i < n; i++) {
            out[written + i] = t[i];
        }
        written += n;
        block_index++;
    }
    ct_wipe(&key, sizeof key);
    ct_wipe(t, sizeof t);
    return CH_OK;
}

#endif // CH_SCRAM
