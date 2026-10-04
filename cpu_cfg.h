// What a caller states about the CPU a session runs on: the bits of ch_cfg.cpu in a host object.
// cfg.h includes this header.
//
// It sits beside cfg.h for the reason srv_cfg.h does: cfg.h stood at 499 lines
// against the 500-line cap CLAUDE.md sets and make lint-size holds.
#ifndef CH_CPU_CFG_H
#define CH_CPU_CFG_H

// A host object compiles each fast path beside the portable code, and each session picks among
// them at init from ch_cfg.cpu, the caller's description of its CPU (docs/decisions.md 89). A
// build says it is one with -DCH_CPU_RUNTIME. The Makefile and build.zig pass it for a
// TRUST=webpki client, ROLE=server and ROLE=both when the compiler targets a host: arm64 or
// x86-64, NEON or SSE2 on a little-endian core, and unsigned __int128. A raw or ca client builds
// the portable object on every target, and so does every product on any other target. A source
// chooses between a host path and the portable code on CH_CPU_RUNTIME alone, never on an
// architecture macro, so CBMC and a firmware tree's own build get the portable code. Inside a
// host path an architecture macro picks the instruction set, as aes_hw.c picks the Arm or the x86
// AES instructions. This header reads them for two things: to stop a host object for a target
// that fails the test, and to name the bits its architecture defines.
#ifdef CH_CPU_RUNTIME
#if !defined(__aarch64__) && !defined(__x86_64__)
#error "CH_CPU_RUNTIME builds a host object, which targets arm64 or x86-64 (docs/decisions.md 89)"
#endif
#if (!defined(__ARM_NEON) && !defined(__SSE2__)) || !defined(__BYTE_ORDER__) ||                    \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "CH_CPU_RUNTIME builds a host object, which needs NEON or SSE2 on a little-endian core"
#endif
#ifndef __SIZEOF_INT128__
#error "CH_CPU_RUNTIME builds a host object, which needs unsigned __int128"
#endif

// The bits of ch_cfg.cpu. The caller probes the CPU and sets the bits that describe it. chapulin
// probes nothing and writes no CPU state.
//
// CH_CPU_PROBED says the caller wrote the field on purpose. Every init call and ch_srv_check
// return CH_EINVAL, before they send anything, for a value without it, so a configuration that
// never set the field, 0, is refused.
//
// CH_CPU_CONSTANT_TIME_AES says the CPU has the AES and carry-less multiply instructions, and
// states that they run in constant time on it, at every width, in the mode the session's thread
// runs in. Arm's A64 reference lists AESE, AESD, AESMC, AESIMC, PMULL and PMULL2 as
// data-independent-time instructions while PSTATE.DIT is 1. Intel's DOIT list names AESENC,
// AESDEC, AESIMC, AESKEYGENASSIST, PCLMULQDQ, VAESENC and VPCLMULQDQ, which hold on Ice Lake,
// Gracemont and later parts while the operating system has set DOITM. The bit is the caller's
// statement, because the caller probes the CPU and sets the mode, and nothing here can check it.
// A session with the bit runs QUIC's Initial packets and their header protection on the
// instructions, and in a SUITE=aesgcm object it offers and prefers the AES-GCM suites in
// docs/decisions.md 80's order. A session without it runs neither instruction: Initial packets
// take the software AES, whose keys are public (INV-26), the session holds ChaCha20 alone, and
// init refuses a cipher_suites list that names an AES-GCM suite. A Retry tag takes the software
// AES whatever the bit says, and a traffic key never does (docs/decisions.md 81).
//
// CH_CPU_CONSTANT_TIME_MULTIPLY states that the widening multiply runs in constant time on the
// CPU, in that mode: MADD, UMULH, MUL and MULX are on the same two lists. On arm64 that needs a
// core with FEAT_DIT and a thread that has set PSTATE.DIT, and on x86-64 a part on the DOIT list
// and the DOITM policy of its operating system. A session with the bit runs every operation built
// on ct.h's widening multiply on the native multiply, the _native copies widemul.h dispatches
// to, and X25519 on x25519_wide.c's field, whose 64x64->128 multiply the bit states as well. A
// session without it runs them on ct.h's 16x16 decomposition, the files under their own names,
// and X25519 on the 16-limb field (docs/decisions.md 52, 87 and 89).
//
// CH_CPU_AVX2 says the CPU has AVX2 and its operating system saves the 256-bit registers, which a
// probe reads from CPUID and XGETBV, and CH_CPU_VAES that the CPU also has VAES and VPCLMULQDQ on
// those registers. Both are x86-64 bits, and each picks a kernel beside a path every x86-64 CPU
// runs. Neither states a timing. A session whose bit names instructions its CPU lacks faults on
// the first one.
// A session with CH_CPU_AVX2 computes a record's or a packet's ChaCha20 keystream eight blocks a
// pass in 256-bit vectors, and one without it on SSE2 (chacha20.c's use_avx2). A session with
// CH_CPU_VAES and CH_CPU_CONSTANT_TIME_AES runs AES-GCM's whole blocks two to a 256-bit register,
// and one with the AES bit alone on the 128-bit instructions (gcm_vaes.h's gcm_use_vaes): the AES
// bit's statement covers the 256-bit forms, and CH_CPU_VAES without it runs nothing. No bit turns
// the 128-bit vector ChaCha20 off: every arm64 CPU has NEON and every x86-64 CPU SSE2
// (docs/decisions.md 82, 89 and 90).
//
// CH_CPU_DEFINED holds the bits this object defines for its architecture. Every init call and
// ch_srv_check refuse a value with any other bit: CH_CPU_AVX2 or CH_CPU_VAES on arm64, or a bit
// a later release adds. A caller written before such a release leaves the new bit clear and runs
// the slower path. A defined bit for instructions the object never runs, such as
// CH_CPU_CONSTANT_TIME_AES in an object that carries no AES, still describes the CPU, and init
// accepts it.
#define CH_CPU_PROBED 0x01U
#define CH_CPU_CONSTANT_TIME_AES 0x02U
#define CH_CPU_CONSTANT_TIME_MULTIPLY 0x04U
#define CH_CPU_AVX2 0x08U
#define CH_CPU_VAES 0x10U
#ifdef __x86_64__
#define CH_CPU_DEFINED                                                                             \
    (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_AVX2 |      \
     CH_CPU_VAES)
#else
#define CH_CPU_DEFINED (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY)
#endif
#endif // CH_CPU_RUNTIME

#endif
