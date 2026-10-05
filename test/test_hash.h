// The hash, HMAC, HKDF and key schedule calls a test makes as one session of its object makes
// them. A host binary (-DCH_CPU_RUNTIME) calls the entries that take a session's ch_cfg.cpu,
// with test_cpu, the value the binary runs under (test/test_cpu.h): the Makefile runs it once
// for each set of bits that changes a path, so the same published vectors run on the portable
// code and, under a hash's bit, on the CPU's instructions for that hash (docs/decisions.md
// 93). Every other binary calls the portable calls, which are all its object holds. A file
// that uses a macro includes the header of the call it names: sha512.h for the SHA-512 ones
// and keysched.h for the key schedule's.
#ifndef CH_TEST_HASH_H
#define CH_TEST_HASH_H

#include "hkdf.h"
#include "sha256.h"
#include "test_cpu.h"

#ifdef CH_CPU_RUNTIME
#define TEST_SHA256_UPDATE(...) sha256_update_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA256_FINAL(...) sha256_final_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA256_OF(...) sha256_of_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA512_UPDATE(...) sha512_update_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA512_FINAL(...) sha512_final_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA384_FINAL(...) sha384_final_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA512_OF(...) sha512_of_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA384_OF(...) sha384_of_cpu(test_cpu, __VA_ARGS__)
#define TEST_HMAC_SHA256(...) hmac_sha256_cpu(test_cpu, __VA_ARGS__)
#define TEST_HMAC(...) hmac_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXTRACT(...) hkdf_extract_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXPAND(...) hkdf_expand_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXPAND_LABEL(...) hkdf_expand_label_cpu(test_cpu, __VA_ARGS__)
#define TEST_KS_EARLY(...) ks_early_cpu(test_cpu, __VA_ARGS__)
#define TEST_KS_HANDSHAKE(...) ks_handshake_cpu(test_cpu, __VA_ARGS__)
#else
#define TEST_SHA256_UPDATE(...) sha256_update(__VA_ARGS__)
#define TEST_SHA256_FINAL(...) sha256_final(__VA_ARGS__)
#define TEST_SHA256_OF(...) sha256_of(__VA_ARGS__)
#define TEST_SHA512_UPDATE(...) sha512_update(__VA_ARGS__)
#define TEST_SHA512_FINAL(...) sha512_final(__VA_ARGS__)
#define TEST_SHA384_FINAL(...) sha384_final(__VA_ARGS__)
#define TEST_SHA512_OF(...) sha512_of(__VA_ARGS__)
#define TEST_SHA384_OF(...) sha384_of(__VA_ARGS__)
#define TEST_HMAC_SHA256(...) hmac_sha256(__VA_ARGS__)
#define TEST_HMAC(...) hmac(__VA_ARGS__)
#define TEST_HKDF_EXTRACT(...) hkdf_extract(__VA_ARGS__)
#define TEST_HKDF_EXPAND(...) hkdf_expand(__VA_ARGS__)
#define TEST_HKDF_EXPAND_LABEL(...) hkdf_expand_label(__VA_ARGS__)
#define TEST_KS_EARLY(...) ks_early(__VA_ARGS__)
#define TEST_KS_HANDSHAKE(...) ks_handshake(__VA_ARGS__)
#endif

#endif
