// The per-byte rows of bench/primitives.c: the hashes and KDFs, ChaCha20
// and the DRBG over it, and Poly1305 with the AEAD it completes. Every
// row reads the same fixed-seed input and times one call the tree makes.
//
// Three groups, split by which build choice moves them. hash and cipher
// call nothing in ct.h's widening multiply, so CH_NATIVE_WIDEMUL
// compiles them to the same code; aead runs Poly1305, whose limb
// products go through ct_widemul, so bench/primitives.sh times it under
// both builds.
#include "aead.h"
#include "chacha20.h"
#include "hkdf.h"
#include "poly1305.h"
#include "primitives.h"
#include "rand.h"
#include "sha256.h"
#include "sha3.h"
#include "sha512.h"

#define MAX_PAYLOAD 16384 // one full TLS record, RFC 9846 §5.1
#define RECORD_AAD_LEN 5  // the record header TLS 1.3 authenticates, RFC 9846 §5.2
#define SEED_LEN 32       // the seed ML-KEM hands SHAKE before it squeezes

// The hash sizes: one block's worth, a 1 KB message, and a full record.
static const size_t HASH_SIZES[] = {64, 1024, MAX_PAYLOAD};
// The cipher sizes: a short record; 1200 bytes, the smallest datagram
// that may carry a QUIC Initial packet (RFC 9000 §14.1); and a full
// record. bench/aead.c times 1350 bytes as well.
static const size_t RECORD_SIZES[] = {64, 1200, MAX_PAYLOAD};
// The DRBG sizes: one 32-byte draw, the size of every draw a handshake
// makes but ML-KEM's, then two long outputs.
static const size_t DRAW_SIZES[] = {32, 1024, MAX_PAYLOAD};
// HKDF-Expand-Label's output: one traffic secret.
static const size_t LABEL_OUTPUT[] = {SHA256_LEN};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static uint8_t input[MAX_PAYLOAD];
static uint8_t output[MAX_PAYLOAD];
static uint8_t sealed[MAX_PAYLOAD];
static uint8_t sealed_tag[AEAD_TAG];
static uint8_t key[AEAD_KEY];
static uint8_t nonce[AEAD_NONCE];
static uint8_t aad[RECORD_AAD_LEN];
static int filled;

static void prepare_inputs(size_t n) {
    (void)n;
    if (!filled) {
        bench_fill(input, sizeof input);
        bench_fill(key, sizeof key);
        bench_fill(nonce, sizeof nonce);
        bench_fill(aad, sizeof aad);
        filled = 1;
    }
}

static void run_sha256(size_t n) {
    uint8_t digest[SHA256_LEN];
    sha256_of(input, n, digest);
    bench_consume(digest, sizeof digest);
}

static void run_sha384(size_t n) {
    uint8_t digest[SHA384_LEN];
    sha384_of(input, n, digest);
    bench_consume(digest, sizeof digest);
}

static void run_sha512(size_t n) {
    uint8_t digest[SHA512_LEN];
    sha512_of(input, n, digest);
    bench_consume(digest, sizeof digest);
}

static void run_sha3_256(size_t n) {
    uint8_t digest[SHA3_256_LEN];
    sha3_256(input, n, digest);
    bench_consume(digest, sizeof digest);
}

// SHAKE the way ML-KEM uses it: absorb a 32-byte seed, then squeeze n
// bytes. The row is per squeezed byte.
static void run_shake128(size_t n) {
    shake s;
    shake128_init(&s);
    shake_absorb(&s, input, SEED_LEN);
    shake_squeeze(&s, output, n);
    bench_consume(&output[n - 1], 1);
}

static void run_shake256(size_t n) {
    shake s;
    shake256_init(&s);
    shake_absorb(&s, input, SEED_LEN);
    shake_squeeze(&s, output, n);
    bench_consume(&output[n - 1], 1);
}

static void run_hmac_sha256(size_t n) {
    uint8_t mac[SHA256_LEN];
    hmac_sha256(key, sizeof key, input, n, mac);
    bench_consume(mac, sizeof mac);
}

// One traffic secret: the label and the 32-byte transcript hash the key
// schedule passes (RFC 9846 §7.1).
static void run_hkdf_expand_label(size_t n) {
    uint8_t secret[SHA256_LEN];
    hkdf_expand_label(SHA256_LEN, key, "c hs traffic", input, SHA256_LEN, secret, n);
    bench_consume(secret, sizeof secret);
}

static void run_chacha20(size_t n) {
    chacha20_xor(key, nonce, 1, input, output, n);
    bench_consume(&output[n - 1], 1);
}

// ch_rand_bytes is drbg.c's here: bench/primitives.c seeds it once.
static void run_drbg(size_t n) {
    ch_rand_bytes(output, n);
    bench_consume(&output[n - 1], 1);
}

static void run_poly1305(size_t n) {
    poly1305 state;
    uint8_t tag[POLY1305_TAG];
    poly1305_init(&state, key);
    poly1305_update(&state, input, n);
    poly1305_final(&state, tag);
    bench_consume(tag, sizeof tag);
}

static void run_seal(size_t n) {
    uint8_t tag[AEAD_TAG];
    aead_seal(key, nonce, aad, sizeof aad, input, n, output, tag);
    bench_consume(tag, sizeof tag);
}

static void prepare_open(size_t n) {
    prepare_inputs(n);
    aead_seal(key, nonce, aad, sizeof aad, input, n, sealed, sealed_tag);
}

static void run_open(size_t n) {
    if (!aead_open(key, nonce, aad, sizeof aad, sealed, n, sealed_tag, output)) {
        bench_fail("aead_open rejected its own seal");
    }
    bench_consume(&output[n - 1], 1);
}

static const bench_row HASH_ROWS[] = {
    {"sha256",            "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_sha256     },
    {"sha384",            "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_sha384     },
    {"sha512",            "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_sha512     },
    {"sha3_256",          "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_sha3_256   },
    {"shake128_squeeze",  "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_shake128   },
    {"shake256_squeeze",  "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_shake256   },
    {"hmac_sha256",       "byte", HASH_SIZES,   COUNT(HASH_SIZES),   prepare_inputs, run_hmac_sha256},
    {"hkdf_expand_label", "op",   LABEL_OUTPUT, COUNT(LABEL_OUTPUT), prepare_inputs,
     run_hkdf_expand_label                                                                          },
};

static const bench_row CIPHER_ROWS[] = {
    {"chacha20", "byte", RECORD_SIZES, COUNT(RECORD_SIZES), prepare_inputs, run_chacha20},
    {"drbg",     "byte", DRAW_SIZES,   COUNT(DRAW_SIZES),   prepare_inputs, run_drbg    },
};

static const bench_row AEAD_ROWS[] = {
    {"poly1305",               "byte", RECORD_SIZES, COUNT(RECORD_SIZES), prepare_inputs, run_poly1305},
    {"chacha20_poly1305_seal", "byte", RECORD_SIZES, COUNT(RECORD_SIZES), prepare_inputs, run_seal    },
    {"chacha20_poly1305_open", "byte", RECORD_SIZES, COUNT(RECORD_SIZES), prepare_open,   run_open    },
};

const bench_group BENCH_HASH = {"hash", HASH_ROWS, COUNT(HASH_ROWS), NULL};
const bench_group BENCH_CIPHER = {"cipher", CIPHER_ROWS, COUNT(CIPHER_ROWS), NULL};
const bench_group BENCH_AEAD = {"aead", AEAD_ROWS, COUNT(AEAD_ROWS), NULL};
