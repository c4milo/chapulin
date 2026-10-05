// The hash, HMAC and HKDF calls a test makes as one session of its object makes them. A host
// binary (-DCH_CPU_RUNTIME) calls the entries that take a session's ch_cfg.cpu, with test_cpu,
// the value the binary runs under (test/test_cpu.h): the Makefile runs it once for each set of
// bits that changes a path, so the same published vectors run on the portable code and, under
// a hash's bit, on the CPU's instructions for that hash (docs/decisions.md 93). Every other
// binary calls the portable calls, which are all its object holds.
#ifndef CH_TEST_HASH_H
#define CH_TEST_HASH_H

#include "hkdf.h"
#include "sha256.h"
#include "test_cpu.h"

#ifdef CH_CPU_RUNTIME
#define TEST_SHA256_UPDATE(...) sha256_update_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA256_FINAL(...) sha256_final_cpu(test_cpu, __VA_ARGS__)
#define TEST_SHA256_OF(...) sha256_of_cpu(test_cpu, __VA_ARGS__)
#define TEST_HMAC_SHA256(...) hmac_sha256_cpu(test_cpu, __VA_ARGS__)
#define TEST_HMAC(...) hmac_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXTRACT(...) hkdf_extract_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXPAND(...) hkdf_expand_cpu(test_cpu, __VA_ARGS__)
#define TEST_HKDF_EXPAND_LABEL(...) hkdf_expand_label_cpu(test_cpu, __VA_ARGS__)
#else
#define TEST_SHA256_UPDATE(...) sha256_update(__VA_ARGS__)
#define TEST_SHA256_FINAL(...) sha256_final(__VA_ARGS__)
#define TEST_SHA256_OF(...) sha256_of(__VA_ARGS__)
#define TEST_HMAC_SHA256(...) hmac_sha256(__VA_ARGS__)
#define TEST_HMAC(...) hmac(__VA_ARGS__)
#define TEST_HKDF_EXTRACT(...) hkdf_extract(__VA_ARGS__)
#define TEST_HKDF_EXPAND(...) hkdf_expand(__VA_ARGS__)
#define TEST_HKDF_EXPAND_LABEL(...) hkdf_expand_label(__VA_ARGS__)
#endif

#endif
