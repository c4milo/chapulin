// What a caller states about the CPU a session runs on: the answers the
// ch_cfg fields about that CPU take. cfg.h includes this header.
//
// It sits beside cfg.h for the reason srv_cfg.h does: cfg.h stood at 499 lines
// against the 500-line cap CLAUDE.md sets and make lint-size holds.
#ifndef CH_CPU_CFG_H
#define CH_CPU_CFG_H

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
// multiply runs every operation under the first, and any other object under the second.
#define CH_WIDEMUL_CONSTANT_TIME 1
#define CH_WIDEMUL_NOT_STATED 2

#endif
