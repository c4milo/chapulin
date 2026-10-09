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
// and X25519 on the 16-word field (docs/decisions.md 52, 87 and 89).
//
// CH_CPU_AVX2 says the CPU has AVX2 and its operating system saves the 256-bit registers, which a
// probe reads from CPUID and XGETBV, and CH_CPU_VAES that the CPU also has VAES and VPCLMULQDQ on
// those registers. Both are x86-64 bits, and each picks a kernel beside a path every x86-64 CPU
// runs. Neither states a timing. A session whose bit names instructions its CPU lacks faults on
// the first one.
// A session with CH_CPU_AVX2 computes a record's or a packet's ChaCha20 keystream eight blocks a
// pass in 256-bit vectors, and one without it on SSE2 (chacha20.c's use_avx2). With the bit beside
// CH_CPU_CONSTANT_TIME_MULTIPLY, whose statement covers the kernel's VPMULUDQ, a record's or a
// packet's Poly1305 runs a ciphertext of 512 bytes or more of whole blocks eight blocks at a time
// in four lanes, on poly1305_avx2.c's kernel, and without one of the two bits it takes the path
// that bit leaves (widemul.h's widemul_poly1305_avx2, docs/decisions.md 110). A session with
// CH_CPU_VAES and CH_CPU_CONSTANT_TIME_AES runs AES-GCM's whole blocks two to a 256-bit register,
// and one with the AES bit alone on the 128-bit instructions (gcm_vaes.h's gcm_use_vaes): the AES
// bit's statement covers the 256-bit forms, and CH_CPU_VAES without it runs nothing. No bit turns
// the 128-bit vector ChaCha20 off: every arm64 CPU has NEON and every x86-64 CPU SSE2
// (docs/decisions.md 82, 89 and 90).
//
// CH_CPU_AVX512_IFMA says the CPU has AVX-512F and AVX-512 IFMA, which CPUID leaf 7 reports in
// bits 16 and 21 of EBX, and that its operating system saves the opmask registers and the 512-bit
// registers, which XGETBV reports in bits 5 to 7 of XCR0. A probe reads the IFMA bit itself: a
// CPU can have AVX-512F without IFMA. It is an x86-64 bit for RSA verification, whose inputs are
// all public, so like CH_CPU_AVX2 it states presence alone and no timing. rsa_mont.c's
// rsa_vp1_cpu reads it and sends the verifiers' public operation to rsa_ifma.c for a modulus of
// 2,048 bits or more whose bit length is a multiple of 64, and to rsa_mont64.c for any other.
// x509.c verifies the chain links of TRUST=ca-rsa with rsa_pss_verify, which takes no cpu, so
// they run rsa_mont64.c whatever the bit says. rsa_ifma.c runs the public operation in digits
// of 52 bits, eight to a 512-bit register, on VPMADD52LUQ and VPMADD52HUQ, and writes the bytes
// rsa_mont64.c writes: a session with the bit computes what a session without it computes.
//
// CH_CPU_CONSTANT_TIME_SHA256, CH_CPU_CONSTANT_TIME_SHA512 and CH_CPU_CONSTANT_TIME_SHA3 each say
// the CPU has the instructions of one hash, and state that they run in constant time on it, in
// the mode the session's thread runs in, as CH_CPU_CONSTANT_TIME_AES states for AES: a hash reads
// HMAC keys and traffic secrets (docs/decisions.md 93).
//   - The SHA-256 bit names FEAT_SHA256 on arm64: SHA256H, SHA256H2, SHA256SU0 and SHA256SU1. On
//     x86-64 it names the SHA extensions with SSSE3 and SSE4.1: SHA256RNDS2, SHA256MSG1 and
//     SHA256MSG2, and the PSHUFB, PALIGNR and PBLENDW that order the bytes and the state beside
//     them, so a probe reads all three from CPUID.
//   - The SHA-512 bit names FEAT_SHA512: SHA512H, SHA512H2, SHA512SU0 and SHA512SU1.
//   - The SHA-3 bit names FEAT_SHA3: EOR3, RAX1, XAR and BCAX.
// The last two are arm64 bits: no x86-64 CPU this tree targets has SHA-512 instructions, and
// x86-64 has no Keccak instruction. Arm's list of data-independent-time instructions under
// PSTATE.DIT names all twelve arm64 instructions, and Intel's DOIT list names the six x86-64
// ones. As with the AES bit, the statement is the caller's.
// A session passes its ch_cfg.cpu to every hash call it makes for its transcript, its key
// schedule and its record and packet keys, through the entries that end sha256.h, sha512.h,
// hkdf.h, keysched.h and transcript.h. With CH_CPU_CONSTANT_TIME_SHA256 those entries run SHA-256,
// and HMAC, HKDF and the key schedule over it, on the instructions (sha256_hw.c, hash_hw.h), and
// without it on sha256.c. With CH_CPU_CONSTANT_TIME_SHA512 an arm64 session runs SHA-384, the
// hash of TLS_AES_256_GCM_SHA384, and HMAC, HKDF and the key schedule over it on the SHA-512
// instructions (sha512_hw.c), and without it on sha512.c. Each hash follows its own bit alone. A
// session whose bit names instructions its CPU lacks faults on the first one. With
// CH_CPU_CONSTANT_TIME_SHA3 an arm64 session runs SHA-3, SHAKE and ML-KEM's hashes on the SHA-3
// instructions (sha3_hw.c, keccak_hw.h) where the object holds them, which is where clang
// compiled it (CH_KECCAK_INSTRUCTIONS below), and on sha3.c everywhere else. A hash call that
// takes no value runs the portable code in every object: a certificate's, a signature's and the
// DRBG's are such calls.
//
// CH_CPU_DEFINED holds the bits this object defines for its architecture. Every init call and
// ch_srv_check refuse a value with any other bit: CH_CPU_AVX2, CH_CPU_VAES or CH_CPU_AVX512_IFMA
// on arm64, CH_CPU_CONSTANT_TIME_SHA512 or CH_CPU_CONSTANT_TIME_SHA3 on x86-64, or a bit a later
// release adds. A caller written before such a release leaves the new bit clear and runs the
// slower path. A defined bit for instructions the object never runs, such as
// CH_CPU_CONSTANT_TIME_AES in an object that carries no AES, still describes the CPU, and init
// accepts it. An AES key schedule keeps the low byte of the value, which holds CH_CPU_VAES and
// CH_CPU_CONSTANT_TIME_AES, the two bits gcm_use_vaes reads (aes_schedule.h).
#define CH_CPU_PROBED 0x01U
#define CH_CPU_CONSTANT_TIME_AES 0x02U
#define CH_CPU_CONSTANT_TIME_MULTIPLY 0x04U
#define CH_CPU_AVX2 0x08U
#define CH_CPU_VAES 0x10U
#define CH_CPU_CONSTANT_TIME_SHA256 0x20U
#define CH_CPU_CONSTANT_TIME_SHA512 0x40U
#define CH_CPU_CONSTANT_TIME_SHA3 0x80U
#define CH_CPU_AVX512_IFMA 0x100U
#ifdef __x86_64__
#define CH_CPU_DEFINED                                                                             \
    (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_AVX2 |      \
     CH_CPU_VAES | CH_CPU_CONSTANT_TIME_SHA256 | CH_CPU_AVX512_IFMA)
#else
#define CH_CPU_DEFINED                                                                             \
    (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY |                    \
     CH_CPU_CONSTANT_TIME_SHA256 | CH_CPU_CONSTANT_TIME_SHA512 | CH_CPU_CONSTANT_TIME_SHA3)
#endif

// Whether the object holds Keccak on the SHA-3 instructions, which CH_CPU_CONSTANT_TIME_SHA3
// then picks: an arm64 host object that clang compiled. A round of Keccak-f[1600] keeps 32
// values in arm64's 32 vector registers, and a compiler that needs a 33rd writes a lane of the
// state to a stack slot of its choosing, which no wipe written in C clears. Apple clang 21,
// clang 18 and clang 23 keep all 32 in registers, and gcc 13 does not (sha3_hw.c,
// docs/decisions.md 99). In an object another compiler built, the bit describes the CPU and
// picks nothing.
#if defined(__aarch64__) && defined(__clang__)
#define CH_KECCAK_INSTRUCTIONS
#endif
#endif // CH_CPU_RUNTIME

#endif
