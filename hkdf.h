// HMAC (RFC 2104), HKDF (RFC 5869), and the TLS 1.3 label scheme (RFC 9846
// §7.1), over SHA-256 and, in a build that has it, SHA-384. One file
// because TLS 1.3 uses them as one unit: every key in the protocol is an
// HKDF-Expand-Label of some HKDF-Extract output, and Finished is the lone
// bare-HMAC user.
//
// The hash is the cipher suite's (rfc9846.txt:4055-4056), and every call
// below that the key schedule makes names it by its output length,
// hash_len: SHA256_LEN for TLS_CHACHA20_POLY1305_SHA256 and
// TLS_AES_128_GCM_SHA256, SHA384_LEN for TLS_AES_256_GCM_SHA384. That is
// the Hash.length RFC 9846 §7.1 writes, so one number both picks the hash
// and sizes every secret it produces. hash_len is public: the ServerHello
// names the suite in the clear.
#ifndef CH_HKDF_H
#define CH_HKDF_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

// SHA-384 joins HMAC and HKDF under CH_HASH_SHA384. A -DCH_SUITE_AES_GCM
// build sets it here, because TLS_AES_256_GCM_SHA384 hashes with SHA-384;
// a test binary or a proof harness sets it on its own to run the SHA-384
// vectors on a host with no AES instructions. Every other build compiles
// SHA-256 alone, links no sha512.c, and keeps every secret at 32 bytes.
#if defined(CH_SUITE_AES_GCM) && !defined(CH_HASH_SHA384)
#define CH_HASH_SHA384
#endif

#ifdef CH_HASH_SHA384
#include "sha512.h"
// The longest hash output, and so the longest secret, this build holds.
#define HKDF_HASH_MAX SHA384_LEN
#else
#define HKDF_HASH_MAX SHA256_LEN
#endif

// HMAC-SHA-256. Its callers outside the key schedule fix SHA-256 whatever
// suite runs: the HelloRetryRequest cookie, the QUIC Retry token, the
// webpki ticket binding and RFC 6979's nonce derivation.
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_LEN]);

#ifdef CH_HASH_SHA384
// HMAC-SHA-384: the same construction over SHA-384's 128-byte block.
void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA384_LEN]);
#endif

// HMAC under the hash hash_len names. out gets hash_len bytes.
//
// Requires: hash_len is SHA256_LEN, or SHA384_LEN in a build with
// CH_HASH_SHA384; CH_ASSERT holds it there. key points at key_len readable
// bytes, msg at msg_len, and out at hash_len writable bytes.
void hmac(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
          uint8_t *out);

// HKDF-Extract (RFC 5869 §2.2). prk gets hash_len bytes. A NULL salt is
// hash_len zero bytes, the RFC's default.
void hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                  size_t ikm_len, uint8_t *prk);

// HKDF-Expand (RFC 5869 §2.3). prk holds hash_len bytes; out gets out_len
// bytes, out_len <= 255 * hash_len. The key schedule asks for one hash
// length; an EXPORTER=on build asks for up to CH_EXPORT_MAX through
// ch_export, which is eight blocks.
void hkdf_expand(size_t hash_len, const uint8_t *prk, const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);

// HKDF-Expand-Label(secret, "tls13 " + label, ctx, out_len). label excludes
// the "tls13 " prefix and is at most HKDF_LABEL_MAX bytes.
//
// The default 12 is the longest label TLS 1.3 itself writes. A build may
// raise it, and the EXPORTER axis does: RFC 9846 §7.5 lets the caller
// choose the exporter's label, and RFC 9266's is "EXPORTER-Channel-Binding"
// at 24 bytes. The cap is a build parameter rather than two entry points
// because the only thing that changes is the size of one stack buffer
// below, so a device build that never exports keeps the 12 it had.
#ifndef HKDF_LABEL_MAX
#define HKDF_LABEL_MAX 12
#endif
// The library builds as C, so the two guards always run there; cfg.h
// reaches this header, and chapulin.hpp reaches cfg.h from C++.
#ifndef __cplusplus
_Static_assert(HKDF_LABEL_MAX >= 12, "TLS 1.3's own labels need 12 bytes");
// HkdfLabel's label vector carries a one-byte length that counts the
// "tls13 " prefix too, so the cap has a ceiling as well as a floor.
_Static_assert(HKDF_LABEL_MAX <= 255 - 6, "the label vector's length is one byte, prefix included");
#endif

// The longest info any caller here passes to hkdf_expand, which is the
// one hkdf_expand_label builds: two length bytes, the label vector's own
// length byte, "tls13 ", the label, the context's length byte and a
// transcript hash at the longest hash this build holds. It was written as
// 64 while the label cap was fixed; deriving it is what lets the cap and
// the hash move without a second number to keep in step.
#define HKDF_INFO_MAX (2 + 1 + 6 + HKDF_LABEL_MAX + 1 + HKDF_HASH_MAX)

// secret holds hash_len bytes; ctx_len is at most HKDF_HASH_MAX.
void hkdf_expand_label(size_t hash_len, const uint8_t *secret, const char *label,
                       const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len);

// Derive-Secret(secret, label, transcript-hash): secret, hash and out each
// hold hash_len bytes.
void hkdf_derive_secret(size_t hash_len, const uint8_t *secret, const char *label,
                        const uint8_t *hash, uint8_t *out);

#if defined(CH_CPU_RUNTIME) && !defined(__cplusplus)
// This header's calls in the copy on the CPU's hash instructions (hkdf_hw.c, docs/decisions.md
// 93): hkdf.c compiled once more under the names hash_hw.h gives, with its SHA-256 on
// sha256_hw.c. Each has the contract of the call it is named for, and requires the CPU the
// hash it runs requires on the instructions (sha256.h). hkdf_hw.c reads these declarations
// beside the definitions it compiles, so the compiler holds the two spellings of each name to
// one type.
void hmac_sha256_hw(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[SHA256_LEN]);
void hmac_hw(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg,
             size_t msg_len, uint8_t *out);
void hkdf_extract_hw(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                     size_t ikm_len, uint8_t *prk);
void hkdf_expand_hw(size_t hash_len, const uint8_t *prk, const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);
void hkdf_expand_label_hw(size_t hash_len, const uint8_t *secret, const char *label,
                          const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len);

// A copy on the instructions reads the declarations above and none of the entries below, as in
// sha256.h.
#ifndef CH_HASH_HW_H
// Whether a call of this header or of keysched.h that runs the hash hash_len names runs the
// copy on the instructions: for SHA-256 where sha256_on_instructions says so, and for SHA-384
// where sha512_on_instructions does. hash_len is the suite's, which the ServerHello names in
// the clear. Every call of hkdf.c and keysched.c runs the one hash its hash_len names, so a
// copy that holds two hashes still runs each on its own bit alone: a session that stated one
// hash's instructions and not the other's never runs the other's.
static inline int hash_on_instructions(uint32_t cpu, size_t hash_len) {
#ifdef CH_HASH_SHA384
    if (hash_len == SHA384_LEN) {
        return sha512_on_instructions(cpu);
    }
#endif
    return hash_len == SHA256_LEN && sha256_on_instructions(cpu);
}

// This header's calls for one session of a host object, each with the session's ch_cfg.cpu
// first and under the same contract, as sha256.h's entries are. A session calls hkdf_extract_cpu
// and hkdf_expand_label_cpu, keysched.c makes hkdf_derive_secret's calls, and the other three
// are here for the tests and the bench, which run the published vectors on both copies.
static inline void hmac_sha256_cpu(uint32_t cpu, const uint8_t *key, size_t key_len,
                                   const uint8_t *msg, size_t msg_len, uint8_t out[SHA256_LEN]) {
    if (sha256_on_instructions(cpu)) {
        hmac_sha256_hw(key, key_len, msg, msg_len, out);
        return;
    }
    hmac_sha256(key, key_len, msg, msg_len, out);
}

static inline void hmac_cpu(uint32_t cpu, size_t hash_len, const uint8_t *key, size_t key_len,
                            const uint8_t *msg, size_t msg_len, uint8_t *out) {
    if (hash_on_instructions(cpu, hash_len)) {
        hmac_hw(hash_len, key, key_len, msg, msg_len, out);
        return;
    }
    hmac(hash_len, key, key_len, msg, msg_len, out);
}

static inline void hkdf_extract_cpu(uint32_t cpu, size_t hash_len, const uint8_t *salt,
                                    size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                                    uint8_t *prk) {
    if (hash_on_instructions(cpu, hash_len)) {
        hkdf_extract_hw(hash_len, salt, salt_len, ikm, ikm_len, prk);
        return;
    }
    hkdf_extract(hash_len, salt, salt_len, ikm, ikm_len, prk);
}

static inline void hkdf_expand_cpu(uint32_t cpu, size_t hash_len, const uint8_t *prk,
                                   const uint8_t *info, size_t info_len, uint8_t *out,
                                   size_t out_len) {
    if (hash_on_instructions(cpu, hash_len)) {
        hkdf_expand_hw(hash_len, prk, info, info_len, out, out_len);
        return;
    }
    hkdf_expand(hash_len, prk, info, info_len, out, out_len);
}

static inline void hkdf_expand_label_cpu(uint32_t cpu, size_t hash_len, const uint8_t *secret,
                                         const char *label, const uint8_t *ctx, size_t ctx_len,
                                         uint8_t *out, size_t out_len) {
    if (hash_on_instructions(cpu, hash_len)) {
        hkdf_expand_label_hw(hash_len, secret, label, ctx, ctx_len, out, out_len);
        return;
    }
    hkdf_expand_label(hash_len, secret, label, ctx, ctx_len, out, out_len);
}
#endif
#endif

// The two calls as a source compiled into both objects makes them for a session, with its
// ch_cfg.cpu first. A host object passes the value to the entry above. A device object holds
// one path for each hash, so it calls the portable call and never evaluates cpu: the
// expression may name a field that build does not declare, as AEAD_SEAL_CPU's does (aead.h),
// and the object's compiled code is the call it made before these names existed.
#ifdef CH_CPU_RUNTIME
#define HKDF_EXTRACT_CPU(cpu, ...) hkdf_extract_cpu((cpu), __VA_ARGS__)
#define HKDF_EXPAND_LABEL_CPU(cpu, ...) hkdf_expand_label_cpu((cpu), __VA_ARGS__)
#else
#define HKDF_EXTRACT_CPU(cpu, ...) hkdf_extract(__VA_ARGS__)
#define HKDF_EXPAND_LABEL_CPU(cpu, ...) hkdf_expand_label(__VA_ARGS__)
#endif

#endif
