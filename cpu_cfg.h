// What a caller states about the CPU a session runs on: the bits of ch_cfg.cpu in a host object,
// and the answers the older fields about that CPU take. cfg.h includes this header.
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
// the portable object on every target, and so does every product on any other target. No source
// chooses a path on the architecture macros. This header reads them for two things: to stop a
// host object for a target that fails the test, and to name the bits its architecture defines.
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
//
// CH_CPU_CONSTANT_TIME_MULTIPLY states that the widening multiply runs in constant time on the
// CPU, in that mode: MADD, UMULH, MUL and MULX are on the same two lists. On arm64 that needs a
// core with FEAT_DIT and a thread that has set PSTATE.DIT, and on x86-64 a part on the DOIT list
// and the DOITM policy of its operating system.
//
// CH_CPU_AVX2 says the CPU has AVX2, and CH_CPU_VAES that it has VAES and VPCLMULQDQ on 256-bit
// registers. Both are x86-64 bits.
//
// No path reads the four bits after CH_CPU_PROBED yet: the AES, CHACHA, WIDEMUL and X25519 build
// variables still choose what each object runs, and the commits docs/decisions.md 89 lists move
// each choice to its bit.
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

// The two answers ch_cfg.aes_instructions takes in an AES=runtime object (-DCH_AES_RUNTIME,
// docs/decisions.md 81). 0 is neither, so a configuration that never set the field is
// refused. The object chooses which AES runs, so it needs one it carries: QUIC's public-key
// packets or the AES-GCM suites, and a TCP object without SUITE=aesgcm carries neither.
#ifdef CH_AES_RUNTIME
#define CH_AES_INSTRUCTIONS_PRESENT 1
#define CH_AES_INSTRUCTIONS_ABSENT 2
#if !defined(CH_TRANSPORT_QUIC_NONBLOCKING) && !defined(CH_SUITE_AES_GCM)
#error "AES=runtime chooses an AES this object does not carry: build it for QUIC or SUITE=aesgcm"
#endif
#endif

// The two answers about ct.h's widening multiply. Every operation built on it runs under one of
// them (widemul.h). CH_WIDEMUL_CONSTANT_TIME says the multiply runs in constant time on this CPU,
// in the mode it runs in, and takes the native multiply. CH_WIDEMUL_NOT_STATED says nothing
// states that, and takes ct.h's 16x16 decomposition. An object whose ct.h takes the native
// multiply runs every operation under the first, and any other object under the second, but for
// a WIDEMUL=runtime object (-DCH_WIDEMUL_RUNTIME, docs/decisions.md 87). That object holds both
// multiplies and takes the answer from each session's ch_cfg.widemul. Every init call and
// ch_srv_check return CH_EINVAL for any other value, 0 included, before they send anything.
//
// The answer is about the CPU and the mode the session's thread runs in, and the caller owns
// both. On arm64 the architecture states that its multiplies take a time independent of their
// data only while PSTATE.DIT is 1, on a core that implements FEAT_DIT, so a caller answers
// CH_WIDEMUL_CONSTANT_TIME for a thread that has set DIT. On x86-64 Intel's DOIT list holds on
// Ice Lake, Gracemont and later parts only while the operating system has set DOITM, which code
// in user mode cannot read, so the answer there is the caller's policy (ct.h). chapulin writes
// no CPU state and probes nothing.
#define CH_WIDEMUL_CONSTANT_TIME 1
#define CH_WIDEMUL_NOT_STATED 2

#endif
