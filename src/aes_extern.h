// The AES block function an AES=extern build leaves for the image to
// define, and the one AES call a caller sees. aes_block.h includes this
// header, so the library's sources see the same declaration.
#ifndef CH_AES_EXTERN_H
#define CH_AES_EXTERN_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stddef.h>
#include <stdint.h>

#include "public_sizes.h"

#ifdef CH_AES_EXTERN
// The platform hook an AES=extern build leaves for the image to define,
// the way RAND=extern leaves ch_rand_bytes in rand.h. A part with an AES
// peripheral wires this to it and compiles no cipher from this tree.
//
// One forward AES block: out = CIPH_key(in), FIPS 197 §5.1. key_len is
// AES_128_KEY or AES_256_KEY, and the hook runs AES-128 or AES-256 by
// it. The key is the key itself, not a schedule, because a peripheral
// takes a key. An implementation that expands the key itself may cache
// the expansion: every call made under one aes_key_schedule passes the
// same key bytes and the same key_len, for as long as that schedule
// lives.
//
// Which lengths arrive depends on the build. A build without AES-256
// (CH_AES_256, aes.h) passes 16-byte keys alone. A -DCH_SUITE_AES_GCM
// build also passes 32-byte keys, for TLS_AES_256_GCM_SHA384, so the
// suite build holds the same two suites under every AES value it takes.
// A part whose peripheral has no AES-256 cannot meet this contract, and
// so cannot build SUITE=aesgcm with AES=extern.
//
// Requires: key_len is AES_128_KEY or AES_256_KEY; key points at key_len
// readable bytes, in at AES_BLOCK readable bytes and out at AES_BLOCK
// writable bytes. in == out must work. The hook must not fail and must
// not return before out holds the whole block, because every caller
// above it treats the cipher as an operation that cannot fail.
//
// Timing. A build without -DCH_SUITE_AES_GCM passes only the public keys
// RFC 9001 fixes, so INV-26's first bound holds it: whatever the
// peripheral's timing is, it leaks nothing an observer does not already
// hold. A -DCH_SUITE_AES_GCM build
// passes traffic keys, which are secret, and ct.h refuses that build
// unless it defines CH_AES_EXTERN_CONSTANT_TIME, the firmware author's
// statement, backed by the vendor, that the peripheral behind this hook
// runs in constant time for every key and block. No mechanism in this
// tree can observe a peripheral's timing, so that statement is the
// whole of the claim.
//
// What the hook keeps. This tree wipes its own copies of a traffic key,
// on the frame that built them. Whatever the hook or the peripheral
// keeps after it returns, such as a key register or a cached expansion,
// is the image's to clear.
//
// Threads. This tree calls the hook from whichever thread runs the
// session, and holds no lock around the call, so an image that runs
// sessions on several threads can have calls overlap. A hook over state
// held per thread needs nothing more; a hook over one peripheral that
// every thread shares arbitrates access to it itself.
void ch_aes_block(const uint8_t *key, size_t key_len, const uint8_t in[AES_BLOCK],
                  uint8_t out[AES_BLOCK]);
#endif

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
