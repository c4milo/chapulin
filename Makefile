CC ?= cc
# -D_DEFAULT_SOURCE: glibc hides POSIX and getrandom under -std=c11 without
# it; macOS ignores it.
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE
# INV-19: -Wvla bans variable frames everywhere; the frame budget is
# enforced per library source by lint-stack, because host test mains
# legitimately keep whole vector tables in their frames.
CFLAGS += -Wvla
STACK_BUDGET := 2560
# A TRUST=webpki object verifies RSA-4096, so rsa_vp1's limb arrays are
# 128 limbs wide instead of 96: measured 3,168 bytes (clang 23 -O2,
# arm64) and 3,128 (Arm GNU gcc 16.2 -O2, Cortex-M3), against 2,400 and
# 2,360 at the device bound. The mode is host-side (docs/webpki.md), so
# its ceiling is 4 kB rather than a device's 2.5 kB; it still catches a
# new buffer. KEX=pq below raises it further.
ifeq ($(TRUST),webpki)
STACK_BUDGET := 4096
endif
# The hybrid build's ceiling is set by ML-KEM's own working memory, not
# by chapulin's plumbing: K-PKE encrypt holds three polynomial vectors
# and two polynomials, 5,632 bytes of coefficients before locals
# (measured 5,744, gcc 13.3 -O2). 6 kB leaves room for compiler
# variation and still catches a new buffer. See docs/invariants.md
# INV-19 and the README's memory table.
ifeq ($(KEX),pq)
STACK_BUDGET := 6144
endif

# cfg.h makes the entropy pattern a declared build choice with no
# default, so every translation unit that sees cfg.h must say which
# pattern its image uses. Every host binary built here supplies its own
# ch_rand_bytes — test/test_random.h for the test mains, an OS-entropy
# shim in the examples, a stub in the fuzz and proof harnesses that
# reach randomness at all — so they declare it once, here. Two recipes are not host binaries and filter it
# back out: the packaged object declares through RAND below, and
# bin/drbg_test links the reference generator instead of supplying a
# hook.
HOST_RAND_DEF := -DCH_RAND_EXTERN
# ct.h has no architecture allowlist, so every build gets the 16x16
# decomposition unless it says otherwise. These binaries run on a development
# machine and hold no secret worth timing, and the decomposition costs solver
# time in the proofs and wall time in the tests, so the host asserts the native
# multiply. It is an assertion about this machine and nothing else: LIB_CFLAGS
# filters it out below, so the packaged object a consumer links keeps the safe
# default for a target neither we nor the compiler knows.
#
# bin/timing overrides it with -DCH_CT_WIDEMUL, because the t-test exists to
# measure the path that ships. ct-widemul-check builds the vector binaries
# with CT_WIDEMUL_CFLAGS, which filters the assertion out and sets
# -DCH_CT_WIDEMUL, so the published answers run over that path once per
# check-slow.
HOST_WIDEMUL_DEF := -DCH_NATIVE_WIDEMUL
CFLAGS += $(HOST_RAND_DEF) $(HOST_WIDEMUL_DEF)
LIB_CFLAGS = $(filter-out $(HOST_RAND_DEF) $(HOST_WIDEMUL_DEF),$(CFLAGS))
# Every tool version comes from one file that CI sources and this include
# reads, so a runner and a development machine resolve the same pins. Before
# it, LLVM_MAJOR below was referenced and never defined here, so the pinned
# candidates expanded to bare `llvm-nm-` and a development machine linted
# with whatever clang-tidy it carried
# A missing file is a hard
# error on purpose: unpinned checks are worse than no checks.
include tools/toolchain.env

# Resolve the pinned major first, then fall back. apt.llvm.org installs the
# versioned names, Homebrew installs a versioned keg, and an unversioned
# binary is the last candidate rather than the first -- taking it first is
# what let LLVM 23 run against a tree pinned to 22. Whichever candidate
# wins, lint-toolchain asserts its version before any linter runs, so a
# machine that resolves the wrong one is told which pin it missed instead of
# reporting the code as broken.
LLVM_BIN := /opt/homebrew/opt/llvm/bin
LLVM_PINNED_BIN := /opt/homebrew/opt/llvm@$(LLVM_MAJOR)/bin
CLANG_TIDY ?= $(shell command -v clang-tidy-$(LLVM_MAJOR) \
                || command -v $(LLVM_PINNED_BIN)/clang-tidy \
                || command -v clang-tidy || command -v $(LLVM_BIN)/clang-tidy)
CLANG_FORMAT ?= $(shell command -v clang-format-$(LLVM_MAJOR) \
                  || command -v $(LLVM_PINNED_BIN)/clang-format \
                  || command -v clang-format || command -v $(LLVM_BIN)/clang-format)
CLANG_RV ?= $(shell command -v clang-$(LLVM_MAJOR) \
              || command -v $(LLVM_PINNED_BIN)/clang \
              || command -v $(LLVM_BIN)/clang || command -v clang)
LLVM_NM ?= $(shell command -v llvm-nm-$(LLVM_MAJOR) \
             || command -v $(LLVM_PINNED_BIN)/llvm-nm \
             || command -v llvm-nm || command -v $(LLVM_BIN)/llvm-nm)
CPPCHECK ?= $(shell command -v cppcheck)
CBMC ?= $(shell command -v cbmc)
CXX ?= c++
LAKE ?= $(shell command -v lake || command -v $(HOME)/.elan/bin/lake)

# On CI a missing tool must fail its gate, not skip it: a workflow edit
# that drops an install step would otherwise disable a check silently.
# Locally the skip stays a convenience. Usage: $(call REQUIRE_ON_CI,name)
REQUIRE_ON_CI = @[ -z "$$CI" ] || { echo "$(1): missing on CI; the gate must not skip"; exit 1; }

# spec/ depends on Mathlib (spec/lakefile.toml), and lake compiles from
# source any dependency whose compiled files it does not find. Mathlib
# takes hours to compile, so every `lake build` below first checks for
# the file `lake exe cache get` downloads and names that command when
# the file is missing. CI runs the command in
# .github/actions/fetch-mathlib. Usage: $(call REQUIRE_MATHLIB,name)
MATHLIB_OLEAN := spec/.lake/packages/mathlib/.lake/build/lib/lean/Mathlib.olean
REQUIRE_MATHLIB = @[ -f $(MATHLIB_OLEAN) ] || { echo "$(1): $(MATHLIB_OLEAN) is missing, and lake would compile Mathlib from source; run 'cd spec && lake exe cache get' once (spec/CONTRACT.md)"; exit 1; }

# A missing linter fails everywhere, CI or not. A lint gate that skips
# is worse than no gate: check exits 0, the run reads green, and the
# finding lands on CI after the push instead of before it. ac3b0d2
# reached main red exactly that way, with cppcheck and semgrep absent
# and their two SKIP lines scrolled off the top of a thirty-minute run.
# Tools outside the lint target keep REQUIRE_ON_CI: skipping a proof or
# a differential locally costs coverage the pushed branch still gets,
# while skipping a linter hides a verdict that was already available.
# Usage: $(call REQUIRE,name,how to install it)
REQUIRE = @echo "$(1): missing, and a linter must not skip. $(2)"; exit 1

SHELLCHECK ?= shellcheck

# Every shell script the repo ships, asked of git rather than listed here:
# a hand-kept list is what let bench/device-ram.sh fall four modules behind
# the build.
SH_SRCS := $(shell git ls-files '*.sh' '.githooks/*')

SRCS := ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c rsa.c rsa_mont.c \
        pem.c x509.c x509_der.c x509_ca.c webpki_time.c webpki_name.c webpki_spki.c webpki_ext.c buf.c record.c keysched.c io.c handshake_message.c handshake_parser.c handshake_record.c session.c \
        handshake_auth.c handshake.c handshake_post.c tls.c softmul.c

HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h p256.h rsa.h ch_assert.h \
        pem.h x509.h x509_der.h x509_ca.h webpki.h buf.h record.h keysched.h io.h handshake_message.h handshake_parser.h handshake_record.h cfg.h session.h handshake_auth.h handshake.h handshake_post.h \
        tls.h rand.h drbg.h sha3.h sha512.h sha512_compress.h p384.h p384_field.h rsa_pkcs1.h mlkem.h mlkem_poly.h \
        handshake_flight.h quic.h quic_aes.h quic_aes_key.h quic_gcm.h quic_initial.h quic_keys.h quic_packet.h quic_retry.h quic_step.h

# The TRANSPORT=quic mode's own sources, named here rather than matched
# by a pattern, for the reason WEBPKI_SRCS is named: an auditor reads
# the object's contents off this line, and an untracked scratch file
# never enters the object. They sit outside SRCS because only one
# transport compiles them; the TRANSPORT axis below names them as its
# add, the way TRUST=webpki names WEBPKI_SRCS.
#
# Every one of them is a stub today: it defines each function its header
# declares and implements none, so a TRANSPORT=quic object links and
# every call refuses. `make quic-footprint` prints how many of the
# mode's functions are stubbed and how many are implemented, and
# bin/quic_stub_test calls each public entry and requires the refusal.
QUIC_SRCS := quic_aes.c quic_gcm.c quic_keys.c quic_packet.c quic_initial.c quic_retry.c \
             quic_step.c quic.c
# Which of them are still stubs, read from the marker rather than from a
# list kept by hand: every stub body holds one `// CH_QUIC_STUB: ` line
# and an implemented body holds none. Two gates carry an exception this
# list bounds, and each retires its own the moment the file it names
# stops matching -- lint-tidy's stub pass, and lib-check's RAND=extern
# import check.
QUIC_STUB_SRCS := $(shell grep -l '^[[:space:]]*// CH_QUIC_STUB: ' $(QUIC_SRCS) 2>/dev/null)
# softmul.c is excluded on purpose. It has to define __mulsi3 and
# __muldi3 -- the names the compiler emits, so they replace the runtime
# library's -- and clang-tidy rejects those as reserved identifiers that
# should have internal linkage. Both are true and neither is fixable: the
# ABI picks the names and external linkage is the whole point. Excluding
# one file keeps bugprone-reserved-identifier and misc-use-internal-linkage
# working everywhere else, which disabling them in .clang-tidy would not.
# clang-format still covers it, and so does lint-runtime-symbols.
LINT_C := $(filter-out softmul.c,$(SRCS)) drbg.c sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c webpki.c mlkem.c mlkem_poly.c test/unit_test.c test/tls_client.c \
          test/diff_test.c test/timing_test.c test/drbg_test.c test/softmul_test.c test/rsa_test.c test/sha3_test.c test/sha512_test.c test/p384_test.c test/rsa_pkcs1_test.c \
          test/webpki_time_test.c test/webpki_name_test.c test/webpki_spki_test.c test/webpki_sigalg_test.c test/webpki_session_test.c test/webpki_cert_test.c test/webpki_chain_test.c \
          test/webpki_auth_test.c \
          test/mlkem_test.c test/handshake_strict_test.c test/handshake_sequence_test.c \
          test/x509_strict_test.c $(QUIC_SRCS) test/quic_stub_test.c test/quic_vectors.c test/diff_quic_test.c $(wildcard examples/*.c)

# Test-local headers: prerequisites for every binary that includes them,
# so a header edit rebuilds the binaries it changes.
TESTH := test/test_random.h test/pem_armor.h test/pem_tests.h test/x509_ca_tests.h test/session_tests.h test/session_post_tests.h \
         test/session_cfg_tests.h test/quic_gcm_tests.h test/p256_tests.h test/diff_driver.h test/diff_aes.h test/diff_gcm.h test/diff_hash.h \
         test/diff_handshake_parser.h test/diff_handshake_certificate.h test/diff_p256.h test/diff_pem.h test/diff_record.h test/diff_rsa.h \
         test/diff_x25519.h test/handshake_sequence_server.h test/rfc8448_vectors.h \
         test/rfc8448_tests.h \
         test/x509_vectors.h test/x509_mutate.h test/x509_chain_tests.h test/x509_epoch.h \
         test/x509_exact_fill.h \
         test/x509_spki.h test/diff_x509.h test/diff_x509_bounds.h test/diff_x509_chain.h \
         test/diff_x509_epoch.h test/diff_x509_mutate.h test/diff_x509_random.h \
         test/diff_x509_signed.h test/diff_sha3.h test/diff_sha512.h test/diff_p384.h test/diff_rsa_pkcs1.h \
         test/rsa_pkcs1_vectors.h test/rsa_wide_vectors.h test/rsa_pkcs1_wide_vectors.h \
         test/diff_webpki.h test/diff_mlkem.h test/mlkem_vectors.h test/webpki_corpus.h test/webpki_sigalg_vectors.h \
         test/diff_webpki_sigalg.h test/hello_exts.h test/webpki_session_cases.h \
         test/handshake_strict_alpn.h \
         test/webpki_cert_mutants.h test/webpki_ext_mutants.h test/diff_webpki_cert.h \
         test/webpki_auth_vectors.h test/rxbuf_floor_tests.h

# Each axis names its value or stops the build. RAND has done this since
# https://github.com/c4milo/chapulin/issues/41; PIN, TRUST and KEX each
# had a bare else, so a misspelled or not-yet-implemented value resolved
# to the default and every gate passed against a build nobody asked for.
# `make check TRUST=webpki` built and passed as TRUST=raw.
#
# Each axis contributes a filter rather than rewriting LIB_SRCS, and one
# assignment below applies them together. Sequential rewrites made the
# packaged source list depend on the order the axes appear in this file.

# Pinned mode verifies one signature algorithm per build: PIN=rsa
# (default, RSA-PSS up to 3072 bits) or PIN=ecdsa (P-256, -DCH_PIN_ECDSA).
# Test binaries compile both modules so both stay tested either way; the
# packaged library object carries only the selected one.
PIN ?= rsa
ifeq ($(PIN),ecdsa)
PIN_DEF := -DCH_PIN_ECDSA
PIN_FILTER := rsa.c rsa_mont.c
else ifeq ($(PIN),rsa)
PIN_DEF :=
PIN_FILTER := p256.c
else
$(error PIN=$(PIN) is not a pinned algorithm; use PIN=rsa or PIN=ecdsa)
endif
# Trust mode: TRUST=raw (default) pins server keys and ships no
# certificate parser; TRUST=ca pins a CA key and includes it;
# TRUST=webpki verifies a public chain against the caller's anchors
# (docs/webpki.md). One mode per packaged object, like PIN.
#
# The webpki sources are the TRUST=webpki object's alone. They are
# listed by name, not matched by a pattern, for two reasons: an auditor
# reads the object's contents off this line, and an untracked scratch
# file in the tree never enters the object. The chain walk lands file by
# file, and each new webpki*.c file joins that object, and stays out of
# the other two, when a change adds it here. lint-trust-separation fails
# while git tracks a root webpki*.c file this list leaves out. A tree
# without webpki.c still builds; the object then fails every handshake
# closed (handshake_auth.c).
WEBPKI_SRCS := webpki_time.c webpki_name.c webpki_spki.c webpki_sigalg.c webpki_ext.c \
                webpki_cert.c webpki.c
# The verifiers and the SHA-384 core a public chain needs. SRCS lists
# x509_der.c, rsa.c, rsa_mont.c and p256.c already; these five it does
# not, because the device objects never package them.
WEBPKI_CHAIN_SRCS := sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c
TRUST ?= raw
ifeq ($(TRUST),ca)
TRUST_DEF := -DCH_TRUST_CA
# Provisioning is a public call only where its parser is linked.
PUBLIC_CA := ch_pubkey_from_pem
TRUST_FILTER := $(WEBPKI_SRCS)
TRUST_ADD :=
else ifeq ($(TRUST),raw)
TRUST_DEF :=
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_der.c x509_ca.c $(WEBPKI_SRCS)
TRUST_ADD :=
else ifeq ($(TRUST),webpki)
TRUST_DEF := -DCH_TRUST_WEBPKI
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_ca.c
TRUST_ADD := $(WEBPKI_CHAIN_SRCS) $(filter-out $(SRCS),$(WEBPKI_SRCS))
# A public chain's links are signed by different algorithm families, so
# this object carries every verifier and PIN selects nothing in it: its
# filter and its define both drop out (CLAUDE.md).
PIN_DEF :=
PIN_FILTER :=
else
$(error TRUST=$(TRUST) is not a trust mode; use TRUST=raw, TRUST=ca or TRUST=webpki)
endif
# Transport: TRANSPORT=tls (default) runs the client over TLS records and
# a socket the caller's I/O callbacks drive; TRANSPORT=quic runs the same
# TLS 1.3 handshake over QUIC's CRYPTO frames and protects QUIC packets
# with the keys it produces (docs/quic.md). One transport per packaged
# object, like PIN and TRUST: the two export different public calls, so
# an object cannot carry both.
#
# The five sources a QUIC object replaces: it compiles none of them
# (docs/quic.md, "What is reused, and what changes").
QUIC_REPLACED := io.c record.c session.c handshake.c tls.c
# The four sources that keep their TLS text and owe a QUIC arm under an
# #ifdef, and that a QUIC object cannot compile until they have one.
# Three of the four do not compile under -DCH_TRANSPORT_QUIC at all,
# because the headers already fork ahead of them: handshake_parser.c
# gets conflicting types for hsp_parse_encrypted_exts, and
# handshake_record.c and handshake_post.c read fields the QUIC arms of
# handshake_record.h and session.h drop. handshake_auth.c compiles
# clean, and it calls hsp_ and hsr_ functions the other three define, so
# a QUIC object that carried it alone would not link. So the object
# leaves all four out for now and no QUIC source reaches a handshake
# message. A name leaves this list in the commit that lands its arm, and
# the list is empty when the mode is whole.
#
# handshake_message.c is not on this list. It compiles clean under
# -DCH_TRANSPORT_QUIC and imports only the wb_ writer from buf.c, which
# this object already packages, so the mode compiles it today and
# quic.c includes its header.
QUIC_PENDING := handshake_parser.c handshake_record.c handshake_auth.c handshake_post.c
TRANSPORT ?= tls
ifeq ($(TRANSPORT),quic)
TRANSPORT_DEF := -DCH_TRANSPORT_QUIC
TRANSPORT_FILTER := $(QUIC_REPLACED) $(QUIC_PENDING)
TRANSPORT_ADD := $(QUIC_SRCS)
PUBLIC_TRANSPORT := ch_quic_init ch_quic_initial_keys ch_quic_crypto_in ch_quic_crypto_out \
                    ch_quic_seal ch_quic_open ch_quic_retry_ok ch_quic_key_update \
                    ch_quic_key_phase ch_quic_drop_previous_keys ch_quic_discard \
                    ch_quic_state ch_quic_alert ch_quic_error_code ch_quic_close
else ifeq ($(TRANSPORT),tls)
TRANSPORT_DEF :=
TRANSPORT_FILTER :=
TRANSPORT_ADD :=
PUBLIC_TRANSPORT := ch_connect ch_read ch_write ch_close
else
$(error TRANSPORT=$(TRANSPORT) is not a transport; use TRANSPORT=tls or TRANSPORT=quic)
endif
# Set while this build's object holds no code that draws randomness:
# handshake.c is the only library source that calls ch_rand_bytes, a
# TRANSPORT=quic object compiles none of it, and the QUIC driver that
# will draw is quic.c, still a stub. lib-check reads it, and asserts the
# object imports nothing rather than announcing that it cannot check:
# this variable is file-granular, because QUIC_STUB_SRCS greps whole
# files, while a marker is per function, so a quic.c whose ch_quic_init
# draws randomness while another function stays a stub would still set
# it. The assertion catches that build and names the line to delete.
QUIC_STUB_RAND := $(if $(filter quic,$(TRANSPORT)),$(filter quic.c,$(QUIC_STUB_SRCS)))
LIB_DEF := $(strip $(PIN_DEF) $(TRUST_DEF) $(TRANSPORT_DEF))
# The one assignment. Every axis above filters or names the sources
# only its value adds; nothing below rewrites.
LIB_SRCS := $(filter-out $(PIN_FILTER) $(TRUST_FILTER) $(TRANSPORT_FILTER),$(SRCS)) \
            $(TRUST_ADD) $(TRANSPORT_ADD)
# Key exchange: KEX=x25519 (default) or KEX=pq (-DCH_KEX_PQ), the
# X25519MLKEM768 hybrid — the ML-KEM and SHA-3 modules join the
# packaged object only there. One mode per object, like PIN and TRUST.
KEX ?= x25519
ifeq ($(KEX),pq)
LIB_DEF += -DCH_KEX_PQ
LIB_SRCS += sha3.c mlkem.c mlkem_poly.c
else ifneq ($(KEX),x25519)
$(error KEX=$(KEX) is not a key exchange; use KEX=x25519 or KEX=pq)
endif
# Entropy pattern, and the one build variable with no default: RAND=extern
# leaves ch_rand_bytes undefined for the image to supply, RAND=drbg packages
# the reference generator and exports ch_drbg_seed so the image seeds it at
# boot. Neither is a default because the choice is the point
# (https://github.com/c4milo/chapulin/issues/41): a weak generator completes
# the handshake and reports success, so the only thing a build can enforce is
# that somebody wrote the choice down. Naming neither reaches cfg.h's #error,
# which is where a firmware tree compiling these sources with its own build
# system meets the same demand.
ifeq ($(RAND),drbg)
LIB_DEF += -DCH_RAND_DRBG
LIB_SRCS += drbg.c
PUBLIC_RAND := ch_drbg_seed
else ifeq ($(RAND),extern)
LIB_DEF += -DCH_RAND_EXTERN
PUBLIC_RAND :=
else ifneq ($(RAND),)
$(error RAND=$(RAND) is not an entropy pattern; use RAND=extern or RAND=drbg)
endif
# CBMC intrinsics don't compile under clang-tidy/cppcheck; harnesses get
# clang-format only. Fuzzers include .c files for statics, same deal.
PROOF_C := $(wildcard proof/*.c) proof/harness.h
FUZZ_C := $(wildcard fuzz/*.c)
# The insn benches' shared driver and vectors: formatted, but outside
# LINT_C -- the drivers compile freestanding for two cross targets, not
# with host flags (the proof-harness precedent).
BENCH_C := $(wildcard bench/*.c bench/*.h)
# The QEMU and FreeRTOS smoke sources. LINT_C's host flags cannot parse
# a freestanding image, so clang-tidy runs them in separate invocations:
# lint-tidy carries a target-flag pass for the test/qemu files, and
# freertos-check lints its two programs against the fetched kernel
# headers. lint-format and lint-cppcheck take the list whole.
QEMU_SMOKE_C := $(wildcard test/qemu/*.c test/qemu/*.h test/freertos/*.c test/freertos/*.h)

# Firmware links bin/chapulin.o: one relocatable object exposing exactly
# the calls PUBLIC names, four under TRANSPORT=tls and fifteen under
# TRANSPORT=quic. Partial linking merges the modules; nmedit
# (macOS) or objcopy (everything else) localizes every other symbol, so
# the library cannot collide with application names. lib-check enforces
# the export list as part of check. Objects live under the variant that
# built them, so switching PIN, TRUST, KEX, RAND or TRANSPORT never
# reuses a stale object. TRANSPORT belongs here for a reason the other
# four share and it sharpens: the two transports link different object
# lists into chapulin.o, so without it a TRANSPORT=tls chapulin.o and a
# TRANSPORT=quic one write to the same path, make 3.81 compares mtimes
# to the second, and the second link reuses the first object -- the
# failure the paragraph below records for RAND.
LIB_VARIANT := $(PIN)-$(TRUST)-$(KEX)-$(RAND)-$(TRANSPORT)
LIB_OBJS := $(LIB_SRCS:%.c=bin/obj/$(LIB_VARIANT)/%.o)

# bench/device-ram.sh sizes the same modules the build packages. It asks
# here rather than keeping its own list, which is how that list fell four
# modules behind the handshake split.
.PHONY: print-lib-srcs
print-lib-srcs:
	@echo $(LIB_SRCS)
.PHONY: print-lib-def
print-lib-def:
	@echo $(LIB_DEF)

# The mode partition, checked from the build variables rather than
# assumed from the ifeq chain above. Each axis value names the sources
# its packaged object must carry and the sources it must not, and the
# defines likewise. A value whose filter stops matching a renamed file,
# or a new value that forgets its filter, fails here rather than in a
# consumer's link. The check reads print-lib-srcs and print-lib-def
# through a recursive make per axis value, so it costs no build; the
# command-line value overrides whatever the outer make was given. The
# PIN and KEX rows name TRUST=raw as well, because PIN selects nothing
# under TRUST=webpki, and `make check TRUST=webpki` would otherwise hand
# that value to their recursions.
# The recursions pass --no-print-directory: GNU make 4 turns on -w for
# a sub-make, and `make ci` runs this lint from one, so its captured
# output would otherwise start with an "Entering directory" line and
# the last name on a list would sit before a newline, not the space the
# match below wants. `make -w lint-trust-separation` reproduces that.
#
# The transport rows read their file list the same way, from git's
# quic*.c at the root, so a QUIC_SRCS that loses a file fails here
# instead of leaving that file out of the object. They name TRANSPORT
# explicitly on both sides, because a `make check TRANSPORT=quic` hands
# its value to every recursion below, and the TRANSPORT=tls row must
# read the transport it names.
#
# The webpki rows read their file lists from nowhere the build reads
# them: the chain verifiers are written out, and the webpki*.c files are
# the ones git tracks at the root. A filter that loses a webpki file
# then fails here instead of passing against its own mistake. The same
# git list is what the TRUST=webpki rows require, so a root webpki*.c
# file that git tracks and WEBPKI_SRCS leaves out fails those rows
# instead of being left out of the object. The lint also fails when git
# names no webpki file at all.
# test/violations/inv05-webpki-source-in-raw.violation drops the webpki
# files from TRUST=raw's filter, and
# test/violations/inv05-webpki-source-unlisted.violation drops one file
# from WEBPKI_SRCS; each requires this lint to fail.
.PHONY: lint-trust-separation
lint-trust-separation:
	@rc=0; \
	check() { \
	  axis=$$1; want=$$2; ban=$$3; wantdef=$$4; bandef=$$5; \
	  srcs=" $$($(MAKE) -s --no-print-directory -f $(firstword $(MAKEFILE_LIST)) print-lib-srcs $$axis) "; \
	  defs=" $$($(MAKE) -s --no-print-directory -f $(firstword $(MAKEFILE_LIST)) print-lib-def $$axis) "; \
	  for f in $$want; do case "$$srcs" in *" $$f "*) ;; *) echo "lint-trust-separation: $$axis must package $$f"; rc=1;; esac; done; \
	  for f in $$ban; do case "$$srcs" in *" $$f "*) echo "lint-trust-separation: $$axis must not package $$f"; rc=1;; esac; done; \
	  for d in $$wantdef; do case "$$defs" in *" $$d "*) ;; *) echo "lint-trust-separation: $$axis must define $$d"; rc=1;; esac; done; \
	  for d in $$bandef; do case "$$defs" in *" $$d "*) echo "lint-trust-separation: $$axis must not define $$d"; rc=1;; esac; done; \
	}; \
	webpki_files=$$(git ls-files 'webpki*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$webpki_files" ] || { echo "lint-trust-separation: git tracks no webpki*.c file at the root, so the webpki rows would check nothing"; rc=1; }; \
	webpki_only="sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c $$webpki_files"; \
	check "TRUST=raw" "" "pem.c x509.c x509_der.c x509_ca.c $$webpki_only" "" "-DCH_TRUST_CA -DCH_TRUST_WEBPKI"; \
	check "TRUST=ca" "pem.c x509.c x509_der.c x509_ca.c" "$$webpki_only" "-DCH_TRUST_CA" "-DCH_TRUST_WEBPKI"; \
	check "TRUST=webpki" "x509_der.c rsa.c rsa_mont.c p256.c $$webpki_only" "pem.c x509.c x509_ca.c" "-DCH_TRUST_WEBPKI" "-DCH_TRUST_CA -DCH_PIN_ECDSA"; \
	check "TRUST=webpki PIN=ecdsa" "x509_der.c rsa.c rsa_mont.c p256.c $$webpki_only" "pem.c x509.c x509_ca.c" "-DCH_TRUST_WEBPKI" "-DCH_TRUST_CA -DCH_PIN_ECDSA"; \
	check "TRUST=raw PIN=rsa" "rsa.c rsa_mont.c" "p256.c" "" "-DCH_PIN_ECDSA"; \
	check "TRUST=raw PIN=ecdsa" "p256.c" "rsa.c rsa_mont.c" "-DCH_PIN_ECDSA" ""; \
	check "TRUST=raw KEX=x25519" "x25519.c" "sha3.c mlkem.c mlkem_poly.c" "" "-DCH_KEX_PQ"; \
	check "TRUST=raw KEX=pq" "x25519.c sha3.c mlkem.c mlkem_poly.c" "" "-DCH_KEX_PQ" ""; \
	quic_files=$$(git ls-files 'quic*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$quic_files" ] || { echo "lint-trust-separation: git tracks no quic*.c file at the root, so the transport rows would check nothing"; rc=1; }; \
	check "TRANSPORT=tls" "io.c record.c session.c handshake.c tls.c" "$$quic_files" "" "-DCH_TRANSPORT_QUIC"; \
	check "TRANSPORT=quic" "$$quic_files" "io.c record.c session.c handshake.c tls.c" "-DCH_TRANSPORT_QUIC" ""; \
	[ $$rc = 0 ] && echo "lint-trust-separation: every axis value packages exactly its own sources and defines"; \
	exit $$rc
# bench/device-ram.sh builds with CLANG_RV, the clang the codegen lints
# use. It asks here for the same reason: a copy of the candidate order
# above would drift, and the numbers it publishes are the compiler's
# (https://github.com/c4milo/chapulin/issues/111).
.PHONY: print-clang-rv
print-clang-rv:
	@echo $(CLANG_RV)
# RAND=drbg packages the generator, so ch_drbg_seed becomes part of the
# API the image calls and lib-check covers it like the transport's own
# calls. PUBLIC_TRANSPORT is the transport's set and replaces the other
# transport's rather than adding to it: lib-check diffs the object's
# exports against this list for exact equality, so a term carrying both
# sets fails every build (docs/decisions.md 28).
PUBLIC := $(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)

bin/obj/$(LIB_VARIANT)/%.o: %.c $(HDRS)
	@mkdir -p bin/obj/$(LIB_VARIANT)
	$(CC) $(LIB_CFLAGS) $(LIB_DEF) -I. -c $< -o $@

# The packaged object is variant-specific but lands at one path, so
# mtimes alone cannot tell which variant built it; the stamp rewrites
# (and so triggers a relink) only when PIN, TRUST, KEX or RAND changed
# since the last build. RAND belongs here because it changes the link
# and the export list even when no object's contents move.

PIN_STAMP := bin/obj/pin-stamp
$(PIN_STAMP): FORCE
	@mkdir -p bin/obj
	@[ "$$(cat $@ 2>/dev/null)" = "$(LIB_VARIANT)" ] || echo "$(LIB_VARIANT)" > $@
.PHONY: FORCE
FORCE:

# The linked object lives under the variant that built it, like the objects
# it is made of. It used to sit at the fixed bin/chapulin.o, and that path
# cannot be kept honest by timestamps: which bytes are correct depends on
# PIN, TRUST, KEX and RAND, not on any file being newer. check links drbg
# and extern back to back, both landed in the same second, make 3.81
# compares mtimes to the second, and the extern pass relinked nothing --
# so the object kept drbg's ch_drbg_seed export and lib-check failed on a
# tree that was correct.
LIB_OBJ := bin/obj/$(LIB_VARIANT)/chapulin.o

$(LIB_OBJ): $(LIB_OBJS) $(PIN_STAMP)
	ld -r -o $@ $(LIB_OBJS)
ifeq ($(shell uname),Darwin)
	printf '_%s\n' $(PUBLIC) > bin/exports.txt
	nmedit -s bin/exports.txt $@
else
	objcopy $(foreach s,$(PUBLIC),-G $(s)) $@
endif

.PHONY: lib lib-check cxx-check
lib: $(LIB_OBJ)
	@cp $(LIB_OBJ) bin/chapulin.o

# The optional C++ wrapper (chapulin.hpp) compiles under -fno-exceptions
# -fno-rtti and links against the packaged library object, the way a
# firmware C++ consumer would use it.
CXXFLAGS ?= -std=c++17 -fno-exceptions -fno-rtti -Wall -Wextra -Wpedantic -Werror
cxx-check: $(LIB_OBJ) chapulin.hpp test/hpp_test.cpp
	@command -v $(CXX) >/dev/null || { \
	  [ -n "$$CI" ] && { echo "$(CXX): missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP cxx-check: no C++ compiler"; exit 0; }
	$(CXX) $(CXXFLAGS) $(LIB_DEF) -D_DEFAULT_SOURCE -I. -c test/hpp_test.cpp -o bin/hpp_test.o
	$(CXX) -o bin/hpp_test bin/hpp_test.o $(LIB_OBJ)
	./bin/hpp_test

lib-check: $(LIB_OBJ)
	@cp $(LIB_OBJ) bin/chapulin.o
	@nm -g $(LIB_OBJ) | awk '$$2 ~ /^[TDSB]$$/ {print $$3}' | sed 's/^_//' | sort > bin/exported.txt
	@printf '%s\n' $(PUBLIC) | sort > bin/expected.txt
	@diff -u bin/expected.txt bin/exported.txt || { \
	  echo "lib-check: exported symbols differ from the public API"; exit 1; }
	@echo "lib-check: $$(wc -l < bin/exported.txt | tr -d ' ') exported symbols, all public API"
# https://github.com/c4milo/chapulin/issues/41 calls the undefined import
# chapulin's strongest randomness property: an image that never wired a
# generator does not link. RAND=drbg trades it away deliberately, so assert
# whichever one this build promised rather than leaving the difference to a
# reader of the Makefile.
ifeq ($(RAND),drbg)
	@if nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qx ch_rand_bytes; then \
	  echo "lib-check: RAND=drbg packages the generator, so ch_rand_bytes must be defined here, not imported"; exit 1; fi
	@echo "lib-check: ch_rand_bytes is defined in the object; the image seeds it with ch_drbg_seed at boot"
else ifneq ($(QUIC_STUB_RAND),)
	@if nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qx ch_rand_bytes; then \
	  echo "lib-check: quic.c still carries a CH_QUIC_STUB marker and this object already imports ch_rand_bytes; drop QUIC_STUB_RAND and let the RAND=extern check run"; exit 1; fi
	@echo "lib-check: quic.c is still a stub, so no source in this object calls ch_rand_bytes and there is no import to check; the RAND=extern check returns with quic.c's implementation"
else
	@if ! nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qx ch_rand_bytes; then \
	  echo "lib-check: RAND=extern must leave ch_rand_bytes undefined, so an image that forgets the hook fails to link"; exit 1; fi
	@echo "lib-check: ch_rand_bytes is undefined in the object; a forgotten hook is a link error"
endif

# The declaration in cfg.h is the whole feature, so check that it fires.
# tls.c is enough to drive it: it includes cfg.h, where the guard lives.
# LIB_CFLAGS is the flag set with the host declaration filtered out, so
# the "neither" arm really names neither.
.PHONY: rand-check
rand-check:
	@set -e; \
	for d in "" "-DCH_RAND_EXTERN -DCH_RAND_DRBG"; do \
	  if $(CC) $(LIB_CFLAGS) $$d -I. -fsyntax-only tls.c 2>/dev/null; then \
	    echo "rand-check: tls.c compiled with [$$d]; the cfg.h guard did not fire"; exit 1; \
	  fi; \
	done; \
	for d in -DCH_RAND_EXTERN -DCH_RAND_DRBG; do \
	  $(CC) $(LIB_CFLAGS) $$d -I. -fsyntax-only tls.c || { \
	    echo "rand-check: tls.c must compile with $$d alone"; exit 1; }; \
	done; \
	echo "rand-check: cfg.h admits exactly one of CH_RAND_EXTERN and CH_RAND_DRBG"

# The reference generator's own vectors. It builds here whatever RAND
# says, because the module is the subject of the test rather than the
# image's choice — so this is the one recipe that declares CH_RAND_DRBG
# on its own. Whether the packaged object also carries drbg.c is RAND's
# business, not this binary's.
bin/drbg_test: test/drbg_test.c drbg.c chacha20.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(LIB_CFLAGS) -DCH_RAND_DRBG -I. -o $@ test/drbg_test.c drbg.c chacha20.c ct.c

# softmul.c only compiles where there is no hardware multiplier, so the
# test forces it on and includes the unit. The host has a multiplier,
# which is what makes the compiler's own `*` an independent oracle.
bin/softmul_test: test/softmul_test.c softmul.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/softmul_test.c

# RSA-PSS verify vectors; its own binary like drbg_test, so the module
# stays testable without the rest of the stack. Built with rsa.h's
# CH_RSA_MODULUS_MAX at 512, the value TRUST=webpki gives it, as
# rsa_pkcs1_test and wycheproof_test are, so the RSA-4096 vectors
# verify; the test adapts to the bound, and bin/unit, which links rsa.c
# at the device bound of 384, checks that the same vectors are refused
# there. The define names the bound rather than the mode: -DCH_TRUST_WEBPKI
# also selects the web PKI ClientHello, EncryptedExtensions and
# CertificateVerify rules, and bin/diff must keep diffing the pinned
# ones (diff-webpki diffs the others).
RSA_WIDE_DEF := -DCH_RSA_MODULUS_MAX=512
bin/rsa_test: test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c

# SHA-3 vectors and the SHAKE streaming contract. Its own binary: sha3.c stays
# out of the packaged object until the ML-KEM build calls it
# (https://github.com/c4milo/chapulin/issues/21).
bin/sha3_test: test/sha3_test.c sha3.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/sha3_test.c sha3.c ct.c

# ML-KEM-768 known answers, the CCTV decaps anchors, and the input checks. Its
# own binary, out of the packaged object like sha3
# (https://github.com/c4milo/chapulin/issues/21).
bin/mlkem_test: test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
# Every function of the TRANSPORT=quic mode refuses and writes nothing while
# it is a stub. Its own binary over the mode's sources under
# -DCH_TRANSPORT_QUIC, the shape bin/sha3_test uses for a mode's own
# sources: bin/unit compiles no QUIC source, because it includes tls.h and
# calls rec_seal, which a -DCH_TRANSPORT_QUIC build does not compile.
# hkdf.c, sha256.c and ct.c join the line because quic_aes.c derives the
# Initial keys through HKDF now that it is implemented. A stub called
# nothing below itself.
bin/quic_stub_test: test/quic_stub_test.c $(QUIC_SRCS) hkdf.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC -I. -o $@ test/quic_stub_test.c $(QUIC_SRCS) hkdf.c sha256.c ct.c
# The mode against its published vectors: FIPS 197 for the AES-128 forward
# cipher and RFC 9001 Appendix A for the Initial keys, the header
# protection masks and the Retry key. Same shape and same reason as
# bin/quic_stub_test above, and docs/quic.md, "Verification owed", names
# both the file and this binary. test/quic_vectors.c compiles quic_aes.c
# rather than linking it, because FIPS 197's vectors fix the key and
# INV-26 keeps the two constructors the only public way to write one, so
# quic_aes.c is not on the line below. A later lane that adds a vector
# section for another quic source links that source here.
bin/quic_test: test/quic_vectors.c quic_gcm.c hkdf.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC -I. -o $@ test/quic_vectors.c quic_gcm.c hkdf.c sha256.c ct.c
# SHA-512 and SHA-384 vectors and the streaming contract. Its own binary,
# out of the packaged object like sha3: only TRUST=webpki links sha512.c.
bin/sha512_test: test/sha512_test.c sha512.c sha512_compress.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/sha512_test.c sha512.c sha512_compress.c
# P-384 ECDSA verification against RFC 6979 A.2.6 and openssl, and PKCS#1
# v1.5 against openssl: their own binaries, out of the packaged object
# like sha3, until TRUST=webpki links them.
bin/p384_test: test/p384_test.c p384.c p384_field.c buf.c sha512.c sha512_compress.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/p384_test.c p384.c p384_field.c buf.c sha512.c sha512_compress.c
bin/rsa_pkcs1_test: test/rsa_pkcs1_test.c rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/rsa_pkcs1_test.c rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c
# The TRUST=webpki date reader and hostname matcher at their boundaries:
# their own binaries, out of the raw and ca objects like sha512, each
# over the DER primitives it reads through.
WEBPKI_TIME_SRC := webpki_time.c x509_der.c buf.c ct.c
WEBPKI_NAME_SRC := webpki_name.c x509_der.c buf.c ct.c
bin/webpki_time_test: test/webpki_time_test.c $(WEBPKI_TIME_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/webpki_time_test.c $(WEBPKI_TIME_SRC)
bin/webpki_name_test: test/webpki_name_test.c $(WEBPKI_NAME_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/webpki_name_test.c $(WEBPKI_NAME_SRC)
# The TRUST=webpki public-key reader and signature dispatch: their own
# binaries, out of the raw and ca objects like sha512. Both build with
# RSA_WIDE_DEF, -DCH_RSA_MODULUS_MAX=512, so the RSA-4096 key is the last
# one the modulus gate admits, as the webpki object will. The dispatch
# binary links every verifier and both hashes it calls.
WEBPKI_SPKI_SRC := webpki_spki.c x509_der.c buf.c ct.c
WEBPKI_SIGALG_SRC := webpki_sigalg.c $(WEBPKI_SPKI_SRC) sha256.c sha512.c sha512_compress.c p256.c \
                     p384.c p384_field.c rsa_pkcs1.c rsa.c rsa_mont.c
bin/webpki_spki_test: test/webpki_spki_test.c $(WEBPKI_SPKI_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/webpki_spki_test.c $(WEBPKI_SPKI_SRC)
bin/webpki_sigalg_test: test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC)
# The TRUST=webpki certificate parser and extension walk: one binary over
# both files, the chain corpus and the boundary mutants. The parser calls
# webpki_read_sigalg, so the binary links the dispatch's sources too, and
# it builds with -DCH_TRUST_WEBPKI (RSA_WIDE_DEF) so the captured RSA-4096
# keys pass the modulus gate.
WEBPKI_CERT_SRC := webpki_cert.c webpki_ext.c webpki_time.c $(WEBPKI_SIGALG_SRC)
bin/webpki_cert_test: test/webpki_cert_test.c $(WEBPKI_CERT_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/webpki_cert_test.c $(WEBPKI_CERT_SRC)
# The TRUST=webpki chain walk: the corpus and the captures through
# webpki_verify_chain, plus the lists that test reframes to reach the
# bounds. It builds with -DCH_TRUST_WEBPKI rather than RSA_WIDE_DEF,
# because ch_cfg declares the anchors, the hostname and the clock only
# there, and that define widens the modulus gate the same way.
WEBPKI_CHAIN_TEST_SRC := webpki.c webpki_name.c $(WEBPKI_CERT_SRC)
bin/webpki_chain_test: test/webpki_chain_test.c $(WEBPKI_CHAIN_TEST_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/webpki_chain_test.c $(WEBPKI_CHAIN_TEST_SRC)

# Parser strictness: drives the ServerHello/EE parsers directly; their
# whole dependency closure is handshake_parser.c + buf.c.
bin/handshake_strict_test: test/handshake_strict_test.c handshake_parser.c buf.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/handshake_strict_test.c handshake_parser.c buf.c

# The TRUST=webpki arms of the same parsers: the empty server_name
# acknowledgement in EncryptedExtensions and the three CertificateVerify
# schemes, with the PKCS#1 v1.5 two refused.
bin/handshake_strict_webpki: test/handshake_strict_test.c handshake_parser.c buf.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/handshake_strict_test.c handshake_parser.c buf.c

# The TRUST=webpki session surface: ch_connect's config rules, the
# ClientHello bytes and the fail-closed handshake, linked over the
# sources that object packages, once per KEX value, because CH_HELLO_MAX
# and CH_TX_STAGE differ between the two.
WEBPKI_TEST_SRCS := $(filter-out pem.c x509.c x509_ca.c,$(SRCS)) $(WEBPKI_CHAIN_SRCS) \
                    $(filter-out $(SRCS),$(WEBPKI_SRCS))
bin/webpki_session_test: test/webpki_session_test.c $(WEBPKI_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/webpki_session_test.c $(WEBPKI_TEST_SRCS)
# The TRUST=webpki CertificateVerify arm: hsa_server_auth over a corpus
# chain and the signatures test/webpki_auth_vectors.h carries, linked
# over the same sources the session test uses, because the flight runs
# through the record reader and the chain walk to reach that arm.
bin/webpki_auth_test: test/webpki_auth_test.c $(WEBPKI_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/webpki_auth_test.c $(WEBPKI_TEST_SRCS)

bin/webpki_session_pq: test/webpki_session_test.c $(WEBPKI_TEST_SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -DCH_KEX_PQ -I. -o $@ test/webpki_session_test.c \
	  $(WEBPKI_TEST_SRCS) sha3.c mlkem.c mlkem_poly.c

# Certificate grammar strictness: one binary per PIN, because the
# profile's grammar is the build's grammar.
X509STRICT_SRC := test/x509_strict_test.c pem.c x509.c x509_der.c x509_ca.c buf.c sha256.c ct.c

# The provisioning tool the e2e suite feeds real openssl armour to.
PEMKEY_SRC := test/pemkey.c pem.c x509.c x509_der.c x509_ca.c buf.c sha256.c ct.c
bin/pemkey: $(PEMKEY_SRC) rsa.c rsa_mont.c $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ $(PEMKEY_SRC) rsa.c rsa_mont.c

bin/pemkey_ecdsa: $(PEMKEY_SRC) p256.c $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -DCH_PIN_ECDSA -I. -o $@ $(PEMKEY_SRC) p256.c
bin/x509strict: $(X509STRICT_SRC) rsa.c rsa_mont.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ $(X509STRICT_SRC) rsa.c rsa_mont.c

bin/x509strict_ecdsa: $(X509STRICT_SRC) p256.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_PIN_ECDSA -I. -o $@ $(X509STRICT_SRC) p256.c

# Sequence differential: every server message sequence to a bounded depth
# (ENUM_DEPTH overrides; the default sweep is ~466k sequences over both modes) against the
# Lean state machine's verdict. Links the stack minus the pinned
# verifiers, which it stubs — V in a sequence means "signature valid".
bin/handshake_sequence_test: test/handshake_sequence_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/handshake_sequence_test.c $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))

bin/unit: test/unit_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/unit_test.c $(SRCS)

# The CA-build unit: the #ifdef CH_TRUST_CA test arms (floor
# derivation, CA slot validation) only execute here.
bin/unit_ca: test/unit_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ test/unit_test.c $(SRCS)

# The hybrid-build variants, like bin/unit_ca for KEX=pq: the #ifdef
# CH_KEX_PQ test arms (share sizes, the receive-buffer floor, the mock
# server's encapsulation) only execute under -DCH_KEX_PQ, which also
# pulls the ML-KEM modules onto the link line (the same additions
# KEX=pq makes to LIB_SRCS). handshake_strict_pq needs no ML-KEM code: the
# parser only reads lengths.
bin/unit_pq: test/unit_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/unit_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c

bin/handshake_sequence_pq: test/handshake_sequence_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/handshake_sequence_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS)) sha3.c mlkem.c mlkem_poly.c

bin/handshake_strict_pq: test/handshake_strict_test.c handshake_parser.c buf.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/handshake_strict_test.c handshake_parser.c buf.c

# The decomposed-multiply variants: bin/unit and bin/mlkem_test compiled
# with the host's CH_NATIVE_WIDEMUL assertion filtered out and
# CH_CT_WIDEMUL on, so the RFC 7748, RFC 8439 and RFC 8448 vectors and
# the FIPS 203 known answers run over the four 16x16 pieces ct.h ships
# rather than the host's one instruction. Every other host binary asserts
# the native multiply, and test/softmul_test.c compares ct_widemul,
# ct_widemul_opaque, ct_widemul_s and ct_mulsmall against the compiler's
# product on their own. So this is the one build where the decomposition
# as poly1305, x25519 and mlkem_poly inline it is checked against a
# published vector (https://github.com/c4milo/chapulin/issues/92).
# ct-widemul-check runs both, then wycheproof-ct-widemul below;
# check-slow calls it.
CT_WIDEMUL_CFLAGS = $(filter-out $(HOST_WIDEMUL_DEF),$(CFLAGS)) -DCH_CT_WIDEMUL
bin/unit_ct_widemul: test/unit_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -o $@ test/unit_test.c $(SRCS)

bin/mlkem_test_ct_widemul: test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -o $@ test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c

.PHONY: ct-widemul-check
ct-widemul-check: bin/unit_ct_widemul bin/mlkem_test_ct_widemul
	./bin/unit_ct_widemul
	./bin/mlkem_test_ct_widemul
	$(MAKE) wycheproof-ct-widemul

bin/tlsclient: test/tls_client.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/tls_client.c $(SRCS)

# The same client compiled for the P-256 pinned mode; e2e runs both
# builds against matching servers.
bin/tlsclient_ecdsa: test/tls_client.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_PIN_ECDSA -I. -o $@ test/tls_client.c $(SRCS)

# The CA-trust clients: the same main under -DCH_TRUST_CA, one per PIN,
# so e2e proves certificate verification against real issued chains.
bin/tlsclient_ca: test/tls_client.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ test/tls_client.c $(SRCS)

bin/tlsclient_ca_ecdsa: test/tls_client.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -DCH_PIN_ECDSA -I. -o $@ test/tls_client.c $(SRCS)

# The web PKI client: the same main under -DCH_TRUST_WEBPKI, over the
# sources that object packages, so e2e proves the chain walk against a
# chain openssl issued and a root the caller configures as an anchor.
bin/tlsclient_webpki: test/tls_client.c $(WEBPKI_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/tls_client.c $(WEBPKI_TEST_SRCS)

# The hybrid-build client: the same main under -DCH_KEX_PQ, with the
# ML-KEM and SHA-3 sources KEX=pq adds to LIB_SRCS; e2e runs it against
# servers that accept only X25519MLKEM768.
bin/tlsclient_pq: test/tls_client.c $(SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/tls_client.c $(SRCS) sha3.c mlkem.c mlkem_poly.c

# Every differential arm builds with RSA_WIDE_DEF, CH_RSA_MODULUS_MAX at
# 512: test/diff_rsa.h and test/diff_rsa_pkcs1.h sample a 4096-bit
# modulus, which rsa.h admits only at that bound, and the spec verifies
# any modulus, so the define is what keeps the two sides' domains equal.
# test/spec_coverage.py passes the same flag.
bin/diff: test/diff_test.c $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/diff_test.c $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c mlkem.c mlkem_poly.c

# Build and run one test binary: make run-unit, make run-webpki_time_test.
# check runs its roster from one recipe, which is the right shape for a
# full run and the wrong one for an inner loop that wants a single
# binary. tools/impact.py emits this form for every binary it selects.
run-%: bin/%
	./bin/$*

.PHONY: check check-slow ci lint lint-tidy lint-format lint-cppcheck lint-docs lint-conflict-markers lint-invariants lint-violation-builds lint-impact lint-fuzz-budget lint-codegen-partition lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-shellcheck lint-bench-numbers lint-spec prove diff fmt clean
# check is the inner loop and holds a one-minute budget, so it runs what
# answers "did I break the build or a contract": the linters, every unit
# and strict-parser binary, the packaged-object export check, and the
# Wycheproof vectors. Measured at about 47 s.
#
# check-slow holds everything whose cost is minutes: the proofs, e2e
# against a real server, the spec differential, the sequence enumerations,
# and the invariant violation builds. The nightly runs it. Splitting on
# duration rather than on importance is deliberate -- nothing here is
# optional, and a change is not finished until check-slow passes too.
check: bin/unit bin/unit_ca bin/unit_pq bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa bin/tlsclient_webpki bin/tlsclient_pq bin/drbg_test bin/softmul_test bin/rsa_test bin/sha3_test bin/sha512_test bin/p384_test bin/rsa_pkcs1_test bin/webpki_time_test bin/webpki_name_test bin/webpki_spki_test bin/webpki_sigalg_test bin/webpki_cert_test bin/webpki_chain_test bin/webpki_auth_test bin/mlkem_test bin/handshake_strict_test bin/handshake_strict_pq bin/handshake_strict_webpki bin/webpki_session_test bin/webpki_session_pq bin/x509strict bin/x509strict_ecdsa bin/quic_stub_test bin/quic_test lint rand-check
	# The packaged object is built once per entropy pattern, because
	# lib-check reads a different export list and a different import
	# list in each. Only the object is built twice: the examples and
	# hpp_test define ch_rand_bytes, so they are extern-pattern programs
	# and build in the extern pass only. The examples compile under the
	# object's defines, so against the drbg object they stop at cfg.h,
	# which rejects two entropy declarations, instead of linking into a
	# binary whose first draw aborts on drbg.c's CH_ASSERT(g_seeded).
	# Pass order does not matter to the fixed paths e2e runs: lib-check
	# and the example targets copy the variant they built into place on
	# every invocation.
	$(MAKE) lib-check RAND=drbg
	$(MAKE) lib-check cxx-check RAND=extern
	# The examples are pinned to TRUST=raw and TRANSPORT=tls, whatever
	# this check was given. psk_client and pinned_client are raw-mode TLS
	# programs: they call ch_connect, ch_write and ch_read, which a
	# TRANSPORT=quic object does not export, and each drives a socket
	# through the I/O callbacks that object has no use for. The fixed
	# paths bin/example_psk and bin/example_pinned are what test/e2e.sh
	# runs: `make check TRUST=webpki` used to leave the webpki-variant
	# copies there, and the next e2e run started a PSK server against a
	# client built for a mode that refuses a PSK.
	$(MAKE) examples-check RAND=extern TRUST=raw TRANSPORT=tls
	# The CA arm packages the provisioning reader and its fifth export;
	# without this leg neither the export list nor the C++ forwarder is
	# checked by anything.
	$(MAKE) lib-check cxx-check RAND=extern TRUST=ca
	# The webpki arm exports the four calls and no provisioning call, and
	# its C++ forwarders are the anchors, hostname and clock setters.
	$(MAKE) lib-check cxx-check RAND=extern TRUST=webpki
	# The QUIC arm exports the fifteen ch_quic_ calls and none of the four
	# TLS ones, so it is the leg that holds PUBLIC_TRANSPORT to a
	# replacement rather than an addition, and the one that compiles
	# chapulin.hpp's Quic class against the object it forwards to.
	$(MAKE) lib-check cxx-check RAND=extern TRANSPORT=quic
	# lint above holds lint-stack at the budget of the build check was
	# given, 2,560 B for a plain `make check`, the target `make ci` runs.
	# This leg compiles the TRUST=webpki object's sources under their own
	# defines against that build's 4,096 B budget (INV-19), which nothing
	# else in check measures. It took 2.0 to 3.1 s in three timed runs.
	$(MAKE) lint-stack TRUST=webpki
	# The QUIC arm compiles the eight QUIC_SRCS, which no other leg
	# compiles at all, against the 2,560 B device budget (INV-19). Every
	# body is a stub today, so the leg costs seconds; it is here so the
	# first real frame the mode lands is measured on the commit that
	# lands it.
	$(MAKE) lint-stack TRANSPORT=quic
	./bin/unit
	./bin/unit_ca
	./bin/unit_pq
	./bin/drbg_test
	./bin/softmul_test
	./bin/rsa_test
	./bin/sha3_test
	./bin/sha512_test
	./bin/p384_test
	./bin/rsa_pkcs1_test
	./bin/webpki_time_test
	./bin/webpki_name_test
	./bin/webpki_spki_test
	./bin/webpki_sigalg_test
	./bin/webpki_cert_test
	./bin/webpki_chain_test
	./bin/webpki_auth_test
	./bin/mlkem_test
	./bin/quic_stub_test
	./bin/quic_test
	./bin/handshake_strict_test
	./bin/handshake_strict_pq
	./bin/handshake_strict_webpki
	./bin/webpki_session_test
	./bin/webpki_session_pq
	./bin/x509strict
	./bin/x509strict_ecdsa
	$(MAKE) wycheproof
	$(MAKE) proof-coverage
	$(MAKE) proof-reach-smoke

# The gates a change can break, and running them. BASE names the
# revision to compare against (default HEAD); `git diff BASE` compares
# it to the working tree, and the tool adds the untracked files, so a
# dirty tree reports what it holds. docs/impact.md says what the
# selection covers and what it deliberately over-selects; it is an
# inner-loop tool, never a landing gate, and check and check-slow stay
# in force before a commit.
#
# TIER drops the gates no tier below it runs: TIER=check keeps what
# `make check` already runs, TIER=slow adds what check-slow adds, and
# the default keeps the nightly-only lanes too. It narrows the plan, so
# it is never what a change is judged by.
.PHONY: impact impact-run
BASE ?= HEAD
TIER ?= nightly
impact:
	@python3 tools/impact.py --base $(BASE) --max-tier=$(TIER)

impact-run:
	@mkdir -p bin
	@python3 tools/impact.py --base $(BASE) --max-tier=$(TIER) --commands > bin/impact.sh
	@set -e; while read -r cmd; do \
	  echo "== $$cmd"; sh -c "$$cmd"; \
	done < bin/impact.sh; \
	echo "impact-run: every selected gate passed"

# What CI runs, decided here rather than in the workflow: the workflow
# calls one target and this file says which tier that means. GitHub sets
# GITHUB_EVENT_NAME; it is empty on a development machine, where ci runs
# both halves.
#
# A pull request gets the one-minute check so review stays fast. A merge to
# main and the nightly get the slow half too, because that is where a
# regression must not survive.
.PHONY: ci
ci:
ifeq ($(GITHUB_EVENT_NAME),pull_request)
	$(MAKE) check
	@echo "ci: pull request, so the slow half is skipped; a merge to main runs it"
else
	$(MAKE) check-slow
endif

# The slow half. bin/handshake_sequence_pq walks the same message ordering
# as its classic sibling; what pq changes is share sizes and secret
# derivation, which handshake_strict_pq, the differential and the e2e pq
# legs cover. ct-widemul-check costs about 7 s, measured, nearly all of it
# three compiles that would come out of check's one-minute budget, so it
# sits here.
.PHONY: check-slow
check-slow: check bin/handshake_sequence_test bin/handshake_sequence_pq bin/pemkey bin/pemkey_ecdsa
	$(MAKE) ct-widemul-check
	./test/qemu-m3.sh
	./test/e2e.sh
	$(MAKE) diff
	./bin/handshake_sequence_test
	$(MAKE) test-invariants-fast
	$(MAKE) prove

# The ECDSA-arm differential: bin/diff compiles the RSA parser, so
# the P-256 certificate rows run against real C only in this variant. The
# nightly lane runs it; the PR lane keeps one diff build.
.PHONY: diff-ecdsa
diff-ecdsa:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff-ecdsa: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff-ecdsa)
	cd spec && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_PIN_ECDSA -I. -o bin/diff_ecdsa test/diff_test.c $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c mlkem.c mlkem_poly.c
	./bin/diff_ecdsa
endif

# The hybrid arm: bin/diff compiles the x25519 key_share parser, so the
# 1120-byte hybrid share only meets real C here. Same lane as
# diff-ecdsa — the nightly runs it, the PR lane keeps one diff build.
.PHONY: diff-pq
diff-pq:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff-pq: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff-pq)
	cd spec && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_KEX_PQ -I. -o bin/diff_pq test/diff_test.c $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c mlkem.c mlkem_poly.c
	./bin/diff_pq
endif

# The web PKI arm: bin/diff compiles the pinned parsers, so the empty
# server_name acknowledgement in EncryptedExtensions and the three
# CertificateVerify schemes run against real C only here. Same lane as
# diff-pq.
# The build links pem.c, x509.c and x509_ca.c too, which the webpki
# object does not package, because test/diff_x509.h drives them.
.PHONY: diff-webpki
diff-webpki:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff-webpki: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff-webpki)
	cd spec && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_TRUST_WEBPKI -I. -o bin/diff_webpki test/diff_test.c $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c webpki.c mlkem.c mlkem_poly.c
	./bin/diff_webpki
endif

# Differential oracle: the Lean spec in spec/ answers over a pipe and
# test/diff_test.c compares every C module against it on random inputs.
diff:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff)
	cd spec && $(LAKE) build
	$(MAKE) bin/diff
	./bin/diff
	$(MAKE) bin/diff_quic
	./bin/diff_quic
endif

# The TRANSPORT=quic arm of the differential. Its own main, because
# test/diff_test.c calls rec_seal and reads the TLS layout of ch_cfg, and
# a -DCH_TRANSPORT_QUIC build compiles neither; test/diff_driver.h holds
# the plumbing both mains share. test/diff_aes.h compiles quic_aes.c, so
# that source is not on the line, for the reason bin/quic_test states.
bin/diff_quic: test/diff_quic_test.c quic_gcm.c hkdf.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC -I. -o $@ test/diff_quic_test.c quic_gcm.c hkdf.c sha256.c ct.c

# The sequence enumerations compare against spec/.lake/build/bin/diffspec,
# and handshake_sequence_test skips the comparison when that binary is
# absent. A caller that runs the binary directly therefore has to build the
# spec first, or a restored cache decides what gets compared.
.PHONY: handshake-sequence handshake-sequence-pq
# Only the oracle build is guarded: the enumeration itself still runs
# without lake, comparing nothing, which is what the binary does alone.
handshake-sequence: bin/handshake_sequence_test
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec comparison: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,handshake-sequence)
	cd spec && $(LAKE) build
endif
	./bin/handshake_sequence_test

handshake-sequence-pq: bin/handshake_sequence_pq
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec comparison: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,handshake-sequence-pq)
	cd spec && $(LAKE) build
endif
	./bin/handshake_sequence_pq

# Line coverage over the library sources, merged across the five host
# test binaries and both PIN builds. Per-pin object dirs share .gcno
# files, so each binary run accumulates counts into the same .gcda set
# and gcovr merges the whole tree into one number. The gate reads that
# one number only — per-file floors invite gaming and churn.
#
# COVERAGE_FLOOR ratchets by hand: it sits at measured-minus-one
# against CI's toolchain (gcc/gcov reads a few tenths lower than local
# llvm-cov), and it moves up in the same diff that adds the tests. A PR
# that lowers the number must either add tests or move the floor down
# in the same diff, with the reason in the commit message.
#
# The recipe below builds two object sets by hand, one per PIN over
# $(SRCS) and one over the webpki sources. Neither names a QUIC source,
# so the eight QUIC_SRCS contribute nothing to this number. That is a
# deferral, not an oversight: every one of the eight is a stub that
# bin/quic_stub_test calls once, so a leg added today would ratchet the
# floor on bodies the next lane deletes. The leg lands in the shape of
# the webpki leg below, with bin/quic_test and bin/quic_driver_test in
# its run list, in the commit that adds those two binaries; that commit
# moves this floor to CI's re-measured reading, the way 3432a5d moved
# it for the webpki leg. docs/quic.md, "What is still open", carries
# the same debt.
COVERAGE_FLOOR := 93
GCOVR ?= $(shell command -v gcovr)
GCOV_TOOL := $(shell $(CC) --version 2>/dev/null | grep -qi clang \
  && echo "$$(xcrun --find llvm-cov 2>/dev/null || command -v llvm-cov) gcov" || echo gcov)
COV_CC = $(CC) --coverage -O0 -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $$def -I.
COV_LIB_OBJS = $(SRCS:%.c=$$d/%.o)
.PHONY: coverage
# What CBMC proves: which sources a running harness compiles, and any
# harness that exists but no launch line starts. A static scan of a
# tenth of a second, so check runs it and a harness added without a
# launch line is caught on the same PR. It reports rather than fails:
# the gaps it finds today are known and tracked. --reach adds a slow
# cbmc pass and stays nightly.
# Reachability at the configured bounds. cbmc --cover location answers
# what a passing verdict cannot: whether the bound is large enough to enter
# the code the harness names. It costs minutes per harness, so the nightly
# runs it (https://github.com/c4milo/chapulin/issues/55).
.PHONY: proof-reach
proof-reach:
	python3 -u proof/coverage.py --reach

.PHONY: proof-coverage
proof-coverage:
	python3 proof/coverage.py

# One cover run through --reach's own code path, on the cheapest gated
# harness (epoch: a third of a second), so check executes the branch the
# nightly runs; 0ab9862 deleted a function on that path and check stayed
# green until the nightly failed. Its own target, not a line of
# proof-coverage, because it needs cbmc and the nightly's spec-coverage
# job runs proof-coverage on a runner without one.
.PHONY: proof-reach-smoke
proof-reach-smoke:
	python3 -u proof/coverage.py --reach --only epoch

# What the Lean spec checks: which spec ops any driver exercises, and
# how much of each shipping source the differential reaches on its own.
# Lean has no line-coverage tool, so the C side is measured instead —
# it answers the question that matters, which is how much of the code
# that ships is checked against an independent model. Slow (an -O0
# instrumented build), so it runs nightly rather than per PR.
.PHONY: spec-coverage
spec-coverage:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec-coverage: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,spec-coverage)
	cd spec && $(LAKE) build
	python3 test/spec_coverage.py
endif

coverage:
ifeq ($(GCOVR),)
	$(call REQUIRE_ON_CI,gcovr)
	@echo "SKIP coverage: gcovr not on PATH (pip install --require-hashes -r tools/coverage-requirements.txt)"
else
	@rm -rf bin/cov bin/coverage.md && mkdir -p bin/cov/html
	@echo "| binary | build | result |" > bin/coverage.md
	@echo "| --- | --- | --- |" >> bin/coverage.md
	@set -e; for pin in rsa ecdsa; do \
	  def=""; [ $$pin = ecdsa ] && def=-DCH_PIN_ECDSA; \
	  d=bin/cov/$$pin; mkdir -p $$d; \
	  for f in $(SRCS) drbg.c; do $(COV_CC) -c $$f -o $$d/$${f%.c}.o; done; \
	  $(COV_CC) test/unit_test.c $(COV_LIB_OBJS) -o $$d/unit; \
	  $(COV_CC) test/drbg_test.c $$d/drbg.o $$d/chacha20.o $$d/ct.o -o $$d/drbg_test; \
	  $(COV_CC) test/rsa_test.c $$d/rsa.o $$d/rsa_mont.o $$d/sha256.o $$d/ct.o -o $$d/rsa_test; \
	  $(COV_CC) test/handshake_strict_test.c $$d/handshake_parser.o $$d/buf.o -o $$d/handshake_strict_test; \
	  verifier="$$d/rsa.o $$d/rsa_mont.o"; if [ $$pin = ecdsa ]; then verifier=$$d/p256.o; fi; \
	  strict_objs=""; for f in $(filter-out test/x509_strict_test.c,$(X509STRICT_SRC)); do \
	    strict_objs="$$strict_objs $$d/$${f%.c}.o"; done; \
	  $(COV_CC) $$def test/x509_strict_test.c $$strict_objs $$verifier -o $$d/x509strict_test; \
	  $(COV_CC) test/handshake_sequence_test.c \
	    $(filter-out $$d/p256.o $$d/rsa.o $$d/rsa_mont.o,$(COV_LIB_OBJS)) -o $$d/handshake_sequence_test; \
	  for b in unit rsa_test handshake_strict_test x509strict_test handshake_sequence_test; do \
	    if ENUM_DEPTH=4 ./$$d/$$b > /dev/null; then \
	      echo "| $$b | $$pin | pass |" >> bin/coverage.md; \
	    else \
	      echo "| $$b | $$pin | FAIL |" >> bin/coverage.md; exit 1; \
	    fi; \
	  done; \
	done
	# The TRUST=webpki leg: one object set under -DCH_TRUST_WEBPKI, which
	# widens the modulus gate the way RSA_WIDE_DEF does, then every
	# binary check runs for the mode, each over the sources its own rule
	# names. The strictness binary here runs the parsers' webpki arms.
	@set -e; d=bin/cov/webpki; def=-DCH_TRUST_WEBPKI; mkdir -p $$d; \
	  for f in $(sort $(WEBPKI_TEST_SRCS) $(WEBPKI_SRCS)); do $(COV_CC) -c $$f -o $$d/$${f%.c}.o; done; \
	  link() { name=$$1; shift; objs=""; for f in "$$@"; do objs="$$objs $$d/$${f%.c}.o"; done; \
	    $(COV_CC) test/$$name.c $$objs -o $$d/$$name; }; \
	  link sha512_test sha512.c sha512_compress.c; \
	  link p384_test p384.c p384_field.c buf.c sha512.c sha512_compress.c; \
	  link rsa_pkcs1_test rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c; \
	  link webpki_time_test $(WEBPKI_TIME_SRC); \
	  link webpki_name_test $(WEBPKI_NAME_SRC); \
	  link webpki_spki_test $(WEBPKI_SPKI_SRC); \
	  link webpki_sigalg_test $(WEBPKI_SIGALG_SRC); \
	  link webpki_cert_test $(WEBPKI_CERT_SRC); \
	  link webpki_chain_test $(WEBPKI_CHAIN_TEST_SRC); \
	  link webpki_session_test $(WEBPKI_TEST_SRCS); \
	  link webpki_auth_test $(WEBPKI_TEST_SRCS); \
	  link handshake_strict_test handshake_parser.c buf.c; \
	  for b in sha512_test p384_test rsa_pkcs1_test webpki_time_test webpki_name_test \
	           webpki_spki_test webpki_sigalg_test webpki_cert_test webpki_chain_test \
	           webpki_session_test webpki_auth_test handshake_strict_test; do \
	    if ./$$d/$$b > /dev/null; then \
	      echo "| $$b | webpki | pass |" >> bin/coverage.md; \
	    else \
	      echo "| $$b | webpki | FAIL |" >> bin/coverage.md; exit 1; \
	    fi; \
	  done
	@echo "" >> bin/coverage.md
	# ENUM_DEPTH=4 above: line coverage saturates well below the check
	# tier's depth 5; the deeper run buys sequences, not lines, and
	# costs minutes at -O0. The filter keeps the report to the root
	# library sources; test mains and generated code stay out.
	# suspicious_hits.warn: the x25519 ladder legitimately racks up
	# billions of hits across both PIN runs; the counter magnitude
	# does not affect line coverage.
	$(GCOVR) --root . bin/cov --filter '^[a-z0-9_]+\.c$$' \
	  --merge-mode-functions=separate \
	  --gcov-executable "$(GCOV_TOOL)" \
	  --gcov-ignore-parse-errors suspicious_hits.warn_once_per_file \
	  --markdown bin/coverage-table.md --html-details bin/cov/html/index.html \
	  --print-summary --json-summary bin/coverage.json --fail-under-line $(COVERAGE_FLOOR) \
	  || { echo "coverage: total line coverage fell below the $(COVERAGE_FLOOR)% floor" >> bin/coverage.md; \
	       cat bin/coverage-table.md >> bin/coverage.md; exit 1; }
	@cat bin/coverage-table.md >> bin/coverage.md
	@echo "" >> bin/coverage.md
	@echo "Floor: $(COVERAGE_FLOOR)% (ratchets by hand; see the comment at COVERAGE_FLOOR)" >> bin/coverage.md
	@echo "coverage: report at bin/cov/html/index.html, summary at bin/coverage.md"
endif

# Wycheproof (C2SP): attack-derived vectors against every primitive.
# Fetched by WYCHEPROOF_COMMIT; tools/toolchain.env carries the reasoning:
# the suite publishes no releases to pin, and a branch head lets two runs
# read different cases. A new attack case is still the alarm we want,
# so the weekly pin bump proposes the newer commit and that pull request
# is where the case first fails. CI fetches fresh every run (bin/ is not
# cached); locally the fetch replaces a checkout that is not the pinned
# commit. Offline with no checkout, the target skips the way lint skips
# absent tools. Every run logs the vector commit.
WYCHEPROOF_DIR := bin/wycheproof
WYCHEPROOF_URL := https://github.com/C2SP/wycheproof

# The fetch, shared by the four targets that build the vectors: the three
# below and the Cortex-M3 lane in test/platforms.mk. One copy, so all four
# check the pin the same way. $(1) names the calling target in the skip and
# failure messages. A shallow fetch of the one commit, as the FreeRTOS
# kernel does, rather than a clone of the branch.
define wycheproof_fetch
if [ "$$(git -C $(WYCHEPROOF_DIR) rev-parse HEAD 2>/dev/null)" != "$(WYCHEPROOF_COMMIT)" ]; then \
	  rm -rf $(WYCHEPROOF_DIR) && mkdir -p $(WYCHEPROOF_DIR) && \
	  git -C $(WYCHEPROOF_DIR) init -q && \
	  git -C $(WYCHEPROOF_DIR) fetch -q --depth 1 $(WYCHEPROOF_URL) $(WYCHEPROOF_COMMIT) && \
	  git -C $(WYCHEPROOF_DIR) -c advice.detachedHead=false checkout -q $(WYCHEPROOF_COMMIT) \
	    || { [ -n "$$CI" ] && { echo "$(1): the wycheproof fetch failed and CI must not skip a gate"; exit 1; }; \
	         echo "SKIP $(1): the fetch of WYCHEPROOF_COMMIT failed; no network, or the pin names no commit"; exit 0; }; \
	fi; \
	[ "$$(git -C $(WYCHEPROOF_DIR) rev-parse HEAD)" = "$(WYCHEPROOF_COMMIT)" ] \
	  || { echo "$(1): the wycheproof checkout is not WYCHEPROOF_COMMIT"; exit 1; }
endef

.PHONY: wycheproof
wycheproof:
	@$(call wycheproof_fetch,wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC -I. -Ibin -o bin/wycheproof_test test/wycheproof_test.c \
	  x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c mlkem.c mlkem_poly.c sha3.c buf.c ct.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c quic_gcm.c && \
	./bin/wycheproof_test

# The web PKI chain fixtures, test/webpki_corpus.h, live in the tree like
# test/rsa_pkcs1_vectors.h; regenerate them by hand. The keys under
# test/webpki_corpus/keys/ and the captures under test/webpki_captures/
# are fixed inputs, so a run over an unchanged tree reproduces the header
# byte for byte. The generator runs the openssl CLI as its oracle and
# opens no network connection.
.PHONY: webpki-corpus
webpki-corpus:
	python3 test/gen_webpki_corpus.py

# The CertificateVerify fixtures over those chains, test/webpki_auth_vectors.h.
# The generator re-mints the same certificates and signs the transcript each
# chain's Certificate message makes, so it runs after webpki-corpus. Its
# RSA-PSS salt is random, so those rows change on every run.
.PHONY: webpki-auth-vectors
webpki-auth-vectors:
	python3 test/gen_webpki_auth_vectors.py

# The same suites over the decomposed multiply, for ct-widemul-check. The
# fetch is the wycheproof target's, so a checkout already at the pinned
# commit is reused and an offline tree skips the same way.
.PHONY: wycheproof-ct-widemul
wycheproof-ct-widemul:
	@$(call wycheproof_fetch,wycheproof-ct-widemul); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(CC) $(CT_WIDEMUL_CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC -I. -Ibin -o bin/wycheproof_test_ct_widemul test/wycheproof_test.c \
	  x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c mlkem.c mlkem_poly.c sha3.c buf.c ct.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c quic_gcm.c && \
	./bin/wycheproof_test_ct_widemul

# Sanitizer lane: the deterministic suites under ASan + UBSan, test
# binaries only — sanitized codegen must never leak into coverage,
# timing, or release objects, so the lane builds into bin/san with its
# own compile lines, like coverage does. O picks the optimization
# level and the output names it, because "passed UBSan" is ambiguous
# without one: -O0 sees code the optimizer would delete, -O2 is what
# ships. -fno-sanitize-recover=all turns any finding into an abort, so
# CI fails on the finding; no suite aborts on purpose (CH_ASSERT never
# fires on the clean tree), so exit status is the pass condition.
# LeakSanitizer joins free on Linux ASan; for a zero-heap library any
# leak is a real bug. Sanitizers are blind to timing: this lane says
# nothing about INV-16, which stays with construction and the t-test.
O ?= 2
SAN_CFLAGS = $(filter-out -O2,$(CFLAGS)) -O$(O) -g \
  -fsanitize=address,undefined -fno-sanitize-recover=all
.PHONY: san-check san-selftest
san-check:
	@rm -rf bin/san && mkdir -p bin/san
	@echo "san-check at -O$(O) with $$($(CC) --version | head -1)"
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/unit test/unit_test.c $(SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/drbg_test test/drbg_test.c drbg.c chacha20.c ct.c
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha3_test test/sha3_test.c sha3.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha512_test test/sha512_test.c sha512.c sha512_compress.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/p384_test test/p384_test.c p384.c p384_field.c buf.c sha512.c sha512_compress.c
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/rsa_pkcs1_test test/rsa_pkcs1_test.c rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/webpki_time_test test/webpki_time_test.c $(WEBPKI_TIME_SRC)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/webpki_name_test test/webpki_name_test.c $(WEBPKI_NAME_SRC)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/webpki_spki_test test/webpki_spki_test.c $(WEBPKI_SPKI_SRC)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/webpki_sigalg_test test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/webpki_cert_test test/webpki_cert_test.c $(WEBPKI_CERT_SRC)
	# The walk, the session it runs inside and the CertificateVerify
	# binding, over the TRUST=webpki object's own source set, so the
	# sanitizers read the chain walk and the webpki ch_connect too.
	$(CC) $(SAN_CFLAGS) -DCH_TRUST_WEBPKI -I. -o bin/san/webpki_chain_test test/webpki_chain_test.c $(WEBPKI_CHAIN_TEST_SRC)
	$(CC) $(SAN_CFLAGS) -DCH_TRUST_WEBPKI -I. -o bin/san/webpki_session_test test/webpki_session_test.c $(WEBPKI_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -DCH_TRUST_WEBPKI -I. -o bin/san/webpki_auth_test test/webpki_auth_test.c $(WEBPKI_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/mlkem_test test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_strict_test test/handshake_strict_test.c handshake_parser.c buf.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/x509strict_test $(X509STRICT_SRC) rsa.c rsa_mont.c
	$(CC) $(SAN_CFLAGS) -DCH_PIN_ECDSA -I. -o bin/san/x509strict_ecdsa $(X509STRICT_SRC) p256.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_sequence_test test/handshake_sequence_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
	@set -e; for b in unit rsa_test sha3_test sha512_test p384_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test webpki_chain_test webpki_session_test webpki_auth_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
	  echo "== $$b (SAN -O$(O))"; ENUM_DEPTH=4 ./bin/san/$$b; done
	@$(call wycheproof_fetch,san wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC -I. -Ibin -o bin/san/wycheproof_test test/wycheproof_test.c \
	  x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c mlkem.c mlkem_poly.c sha3.c buf.c ct.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c quic_gcm.c && \
	echo "== wycheproof_test (SAN -O$(O))" && ./bin/san/wycheproof_test
	$(MAKE) san-selftest

# Proves the sanitizer has teeth on every run, not once in a scratch
# branch: a committed, deliberate out-of-bounds read that must abort.
san-selftest:
	@mkdir -p bin/san
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/selftest test/san_selftest.c
	@if ./bin/san/selftest >/dev/null 2>&1; then \
	  echo "san-selftest: the deliberate violation did not trip the sanitizer"; exit 1; \
	else echo "san-selftest: sanitizer trips as required"; fi

# Big-endian MIPS lane: the byte-exact suites on the deployment ISA.
# Every other test runs on little-endian x86-64; this lane proves no
# host byte order leaked into the wire path or the crypto, and lets the
# vectors meet mips32r2 code generation. CROSS names the toolchain
# prefix and RUNNER the emulator; the same command runs locally and on
# CI:  make cross-check CROSS=mips-linux-gnu- RUNNER=qemu-mips
# Static binaries, so the emulator needs no target sysroot. The suites
# run from bin/cross on purpose: handshake_sequence then skips the Lean-spec
# comparison (the oracle is a host binary), keeping its direct ordering
# and alert tables; depth 3 keeps the emulated enumeration to minutes,
# and the x86 lane owns the deep run.
CROSS ?=
RUNNER ?=
CROSS_EXTRA ?= # extra flags for the cross lane (nightly adds UBSan here)
# The platform test lanes — the native suite roster, the bare-metal
# Cortex-M3 lane and the FreeRTOS lane — live in test/platforms.mk,
# beside the shims and harnesses they build. This file keeps the core
# build, the packaging and the lints.
include test/platforms.mk

.PHONY: cross-check
cross-check:
	@[ -n "$(CROSS)" ] || { echo "cross-check: set CROSS=<toolchain-prefix> (and RUNNER=<emulator>)"; exit 1; }
	@mkdir -p bin/cross
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/unit test/unit_test.c $(SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/drbg_test test/drbg_test.c drbg.c chacha20.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha3_test test/sha3_test.c sha3.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha512_test test/sha512_test.c sha512.c sha512_compress.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/p384_test test/p384_test.c p384.c p384_field.c buf.c sha512.c sha512_compress.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/rsa_pkcs1_test test/rsa_pkcs1_test.c rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/webpki_time_test test/webpki_time_test.c $(WEBPKI_TIME_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/webpki_name_test test/webpki_name_test.c $(WEBPKI_NAME_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_spki_test test/webpki_spki_test.c $(WEBPKI_SPKI_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_sigalg_test test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_cert_test test/webpki_cert_test.c $(WEBPKI_CERT_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/mlkem_test test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_strict_test test/handshake_strict_test.c handshake_parser.c buf.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/x509strict_test $(X509STRICT_SRC) rsa.c rsa_mont.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -DCH_PIN_ECDSA -I. -o bin/cross/x509strict_ecdsa $(X509STRICT_SRC) p256.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_sequence_test test/handshake_sequence_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
	@if [ -d $(WYCHEPROOF_DIR)/.git ] \
	  || git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) 2>/dev/null; then \
	  python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	  $(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC -static -I. -Ibin -o bin/cross/wycheproof_test test/wycheproof_test.c \
	    x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c mlkem.c mlkem_poly.c sha3.c buf.c ct.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c quic_gcm.c; \
	else \
	  [ -n "$$CI" ] && { echo "wycheproof: clone failed and CI must not skip a gate"; exit 1; }; \
	  echo "SKIP cross wycheproof: no checkout and no network"; \
	fi
	@set -e; cd bin/cross; for b in unit rsa_test sha3_test sha512_test p384_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
	  echo "== $$b ($(RUNNER))"; ENUM_DEPTH=3 $(RUNNER) ./$$b; done; \
	if [ -x wycheproof_test ]; then echo "== wycheproof_test ($(RUNNER))"; $(RUNNER) ./wycheproof_test; fi

# Lean spec hygiene: the escape hatches that would quietly weaken the
# proofs are banned from the model (spec/Spec/, Spec.lean) — sorry,
# admit, native_decide, unsafe, axiom declarations, and kernel-limit
# bumps. Main.lean is the IO oracle driver, not the model; its one
# `partial def loop` (a REPL cannot be proven terminating) is the sole
# allowed use. The axiom check then proves the load-bearing theorems
# rest only on Lean's three standard axioms.
SPEC_MODEL := $(wildcard spec/Spec/*.lean) spec/Spec.lean
lint-spec:
ifeq ($(LAKE),)
	$(call REQUIRE,lint-spec,lake is not on PATH — install elan from https://leanprover.github.io)
else
	@rc=0; for f in $(SPEC_MODEL) spec/Main.lean; do \
	  hits=$$(sed 's/--.*//' $$f \
	    | grep -nwE 'sorry|admit|native_decide|unsafe' ; \
	    sed 's/--.*//' $$f | grep -nE '^[[:space:]]*axiom[[:space:]]' ; \
	    sed 's/--.*//' $$f | grep -nE 'set_option[[:space:]]+(maxHeartbeats|maxRecDepth)') ; \
	  [ -z "$$hits" ] || { printf '%s\n' "$$hits" | sed "s|^|$$f:|"; rc=1; }; \
	done; \
	for f in $(SPEC_MODEL); do \
	  hits=$$(sed 's/--.*//' $$f | grep -nwE 'partial'); \
	  [ -z "$$hits" ] || { printf '%s\n' "$$hits" | sed "s|^|$$f:|"; rc=1; }; \
	done; \
	[ $$rc -eq 0 ] || { echo "lint-spec: banned escape hatch in the model"; exit 1; }
	$(call REQUIRE_MATHLIB,lint-spec)
	@cd spec && $(LAKE) build 2>&1 | tee /tmp/lake-build.log \
	  && ! grep -q "warning:" /tmp/lake-build.log \
	  || { echo "lint-spec: lake build warnings are errors here"; exit 1; }
	@cd spec && $(LAKE) env lean AxiomCheck.lean > /tmp/axioms.log 2>&1 \
	  || { cat /tmp/axioms.log; exit 1; }
	@! grep -oE "depends on axioms: \[[^]]*\]" /tmp/axioms.log \
	  | tr ',[]' '\n' | sed 's/.*axioms: //;s/^ *//;s/ *$$//' | grep -v '^$$' \
	  | grep -vxE 'propext|Classical\.choice|Quot\.sound' \
	  || { echo "lint-spec: a theorem in the model depends on a non-standard axiom"; exit 1; }
	@echo "lint-spec: model clean, theorems rest on the standard axioms only"
endif

# Checks and thresholds live in .clang-tidy; every disable carries a reason
# there (fix-or-drop, never NOLINT in code).
lint: lint-toolchain lint-pins lint-proof-cover lint-exact-fill lint-tidy lint-format lint-cppcheck lint-commits lint-docs lint-conflict-markers lint-invariants lint-stack lint-size lint-tracked-ignored lint-matrix lint-nightly-report lint-violation-builds lint-impact lint-fuzz-budget lint-codegen-partition lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-shellcheck lint-bench-numbers lint-spec lint-trust-separation lint-quic-partition lint-quic-surface

# INV-19: bounded stack. The budget is the measured worst library
# frame (rsa_vp1's RSA-3072 limb temporaries, 2,400 bytes) rounded up;
# a frame past it is a build error, not a bench surprise. Each source
# compiles alone so a breach names its file.
# Hand-written C stays under 500 lines (CLAUDE.md): the rule serves
# third-party audit, so it covers what a person reads and skips what a
# generator emits. spec/ is Lean and carries its own reasoning for the
# exemption there.
FILE_LINE_MAX := 500
.PHONY: lint-size
lint-size:
	@rc=0; for f in $$(git ls-files '*.c' '*.h'); do \
	  head -3 $$f | grep -q 'Generated by' && continue; \
	  n=$$(wc -l < $$f | tr -d ' '); \
	  if [ $$n -gt $(FILE_LINE_MAX) ]; then \
	    echo "lint-size: $$f is $$n lines, over $(FILE_LINE_MAX)"; rc=1; \
	  fi; \
	done; \
	[ $$rc -eq 0 ] && echo "lint-size: every hand-written C file under $(FILE_LINE_MAX) lines"; exit $$rc

# .gitignore stops a future `git add`; it does not untrack a file the
# index already holds, so adding a rule for a tracked file needs a
# `git rm --cached` beside it. ac8faeb added the __pycache__/ rule and
# skipped that step, so the commit meant to drop the cache file
# committed a newer copy of it instead. The rules come from the
# repository's own .gitignore files alone, never from a machine's
# global excludes file, so the verdict is the same here and on CI.
.PHONY: lint-tracked-ignored
lint-tracked-ignored:
	@rc=0; for f in $$(git ls-files -i -c --exclude-per-directory=.gitignore); do \
	  echo "lint-tracked-ignored: $$f is tracked but .gitignore excludes it; git rm --cached untracks it"; rc=1; \
	done; \
	[ $$rc -eq 0 ] && echo "lint-tracked-ignored: no tracked file matches an ignore rule"; exit $$rc

# Compiles what THIS build packages, with the defines it packages them
# under: iterating $(SRCS) without $(LIB_DEF) measured the default build
# whatever PIN, TRUST or KEX asked for, so no variant was ever checked.
lint-stack:
	@mkdir -p bin/obj/stack
	@rc=0; for f in $(LIB_SRCS) drbg.c; do \
	  $(CC) $(CFLAGS) $(LIB_DEF) -Wframe-larger-than=$(STACK_BUDGET) -I. -c $$f -o bin/obj/stack/$$f.o || rc=1; \
	done; rm -rf bin/obj/stack; \
	[ $$rc -eq 0 ] && echo "lint-stack: every library frame under $(STACK_BUDGET) B"; exit $$rc

# Every document must be named in the README; an orphaned doc is a doc
# nobody finds. The second and third loops keep the invariants
# doc-to-rules mapping honest in both directions: every INV id the
# rules cite has an entry, and every rule id the doc claims exists.
# Pure shell, so it never skips.
DOCS_MD := $(wildcard docs/*.md) SECURITY.md CONTRIBUTING.md
lint-docs:
	@rc=0; for d in $(DOCS_MD); do \
	  grep -q "$$d" README.md || { echo "lint-docs: README does not name $$d"; rc=1; }; \
	done; \
	for id in $$(grep -o 'INV-[0-9]*' .semgrep/invariants.yml | sort -u); do \
	  grep -q "^### $$id " docs/invariants.md \
	    || { echo "lint-docs: invariants.yml cites $$id, which has no entry in docs/invariants.md"; rc=1; }; \
	done; \
	for rule in $$(grep -o '`inv-[a-z0-9-]*`' docs/invariants.md | tr -d '`' | sort -u); do \
	  grep -q "id: $$rule" .semgrep/invariants.yml \
	    || { echo "lint-docs: docs/invariants.md claims rule $$rule, which invariants.yml does not define"; rc=1; }; \
	done; exit $$rc

SEMGREP ?= $(shell command -v semgrep)
lint-invariants:
ifeq ($(SEMGREP),)
	$(call REQUIRE,semgrep,pip install --require-hashes -r .semgrep/requirements.txt)
else
	# Local rules only and --metrics=off, never --config auto or a
	# registry config: those fetch rules from and upload scan context
	# to semgrep.dev. The version pin lives in .semgrep/requirements.txt
	# with hashes because semgrep carries a large dependency tree and is
	# the only pip package in the security path.
	# Tracked files only: CI builds tools from source inside the
	# workspace, and a dot target would audit their sources too. The
	# violation file is excluded here because semgrep scans explicit
	# targets regardless of --exclude.
	$(SEMGREP) scan --metrics=off --quiet --error \
	  --config .semgrep/invariants.yml $$(git ls-files '*.c' '*.h' ':!.semgrep')
	@$(SEMGREP) --metrics=off --test \
	  --config .semgrep/invariants.yml .semgrep/invariants.c >/dev/null \
	  && echo "lint-invariants: rules clean, tripwires trip"
endif

# Assert the resolved checkers are the pinned ones before any of them runs.
# CI has asserted this since the pins existed; a development machine had no
# equivalent, so an upgraded Homebrew LLVM reported eight new diagnostics in
# x509_der.c and read as the code being broken rather than the checker having
# moved. A version this does
# not recognise is a stop, not a warning: CLAUDE.md forbids adapting code or
# suppressions to an older checker, and the same rule makes a silent newer
# one just as wrong.
.PHONY: lint-toolchain
lint-toolchain:
	@rc=0; \
	 for spec in "clang-tidy:$(CLANG_TIDY):version $(LLVM_MAJOR)\\." \
	             "clang-format:$(CLANG_FORMAT):version $(LLVM_MAJOR)\\." \
	             "clang:$(CLANG_RV):version $(LLVM_MAJOR)\\." \
	             "llvm-nm:$(LLVM_NM):$(LLVM_MAJOR)\\."; do \
	   name=$${spec%%:*}; rest=$${spec#*:}; bin=$${rest%%:*}; want=$${rest#*:}; \
	   if [ -z "$$bin" ]; then \
	     echo "lint-toolchain: $$name is missing; the pin is LLVM $(LLVM_MAJOR) (tools/toolchain.env)"; rc=1; \
	   elif ! "$$bin" --version 2>/dev/null | grep -qE "$$want"; then \
	     echo "lint-toolchain: $$bin is $$("$$bin" --version 2>/dev/null | head -1)"; \
	     echo "lint-toolchain: the pin is LLVM $(LLVM_MAJOR) (tools/toolchain.env). Install it, or bump the pin"; \
	     echo "lint-toolchain: and take the new diagnostics as work -- never adapt the code to an older checker."; rc=1; \
	   fi; \
	 done; \
	 [ $$rc -eq 0 ] && echo "lint-toolchain: every checker is the pinned LLVM $(LLVM_MAJOR)"; exit $$rc

# tools/toolchain.env is the only place a tool version is written, and every
# job that reads one loads it. tools/toolchain-pins.py carries the reasoning
# for both halves.
.PHONY: lint-pins
lint-pins:
	@python3 tools/toolchain-pins.py

# .clang-tidy disables bugprone-signed-bitwise because the signed arithmetic
# here is deliberate and CBMC proves the class the check approximates. That
# argument holds only while every shipped source is proven with the
# signed-overflow class on. tools/proof-cover.py carries the reasoning.
.PHONY: lint-proof-cover
lint-proof-cover:
	@python3 tools/proof-cover.py

# INV-25: a reader that opens a slice must compare what is left in it
# against a length, or a trailing byte inside the container passes
# unread. tools/exact-fill.py
# carries the reasoning and states what the check cannot see.
.PHONY: lint-exact-fill
lint-exact-fill:
	@python3 tools/exact-fill.py

# INV-27: the QUIC mode's partition, read from the preprocessor rather
# than from a list kept by hand. A root file belongs to TRANSPORT=quic
# when it writes no declaration without -DCH_TRANSPORT_QUIC and gains
# something with it. The rule is that every such file is named quic*,
# and that no other root file is one, so `git ls-files 'quic*'` names
# every file the mode owns and a reader sees how much it covers without
# reading the build. tools/quic-partition.py carries the reasoning, the
# flags each run passes and what the check cannot see.
#
# The two lists below are the mode's text outside the prefix, and the
# lint reads them from here.
#
# handshake_flight.[ch] is the one file the QUIC mode adds that both
# transports compile: the TLS driver in handshake.c and the QUIC driver
# in quic_step.c call the same flight handlers, so no protocol rule
# exists twice (docs/quic.md, "The design: one whole message per step").
# It carries no quic prefix on purpose, and QUIC_SHARED names it here so
# a reader sees the exemption rather than reading the missing prefix as
# a mistake. The exemption checks its file rather than skipping it: a
# QUIC_SHARED file that becomes QUIC-only fails this lint too, under the
# message that belongs to it, which says a file both transports compile
# has stopped compiling in a TLS build.
QUIC_SHARED := handshake_flight.c handshake_flight.h
# The shared files that carry a #ifdef CH_TRANSPORT_QUIC arm: the
# configuration, the session struct and the handshake layers the mode
# reuses. Each holds text only a QUIC build compiles, so each is a place
# to look that the prefix does not name, and a file that gains such an
# arm without joining this list fails the lint. A file that stops
# carrying one fails it too, so the list never sends a reader to a file
# that holds nothing.
QUIC_CONDITIONAL := cfg.h session.h handshake_record.h handshake_post.h \
                    handshake_auth.h handshake_parser.h
.PHONY: lint-quic-partition
lint-quic-partition:
	@CC='$(CC)' python3 tools/quic-partition.py

# quic.h and docs/quic.md's interface table must name the same ch_quic_
# entries. A name in one and not the other means the header and its
# design record disagree about the public surface, which is a defect in
# whichever moved last. `make quic-footprint` prints the same comparison
# inside its report; this target is the one that fails, so the report
# reaches no verdict of its own.
.PHONY: lint-quic-surface
lint-quic-surface:
	@python3 tools/quic-footprint.py --check-surface

lint-tidy:
ifeq ($(CLANG_TIDY),)
	$(call REQUIRE,clang-tidy,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	# webpki.c, the three webpki test mains and the webpki example read
	# ch_cfg fields that exist only under -DCH_TRUST_WEBPKI, so this
	# pass, which defines no trust mode, leaves them to the next one.
	# The QUIC sources and their test main are left out for the same
	# reason: every declaration they hold sits behind
	# -DCH_TRANSPORT_QUIC, which this pass does not define, so it would
	# read eight empty translation units. The two passes below read them.
	$(CLANG_TIDY) --quiet $(filter-out webpki.c test/webpki_session_test.c test/webpki_chain_test.c test/webpki_auth_test.c examples/webpki_client.c $(QUIC_SRCS) test/quic_stub_test.c test/quic_vectors.c test/diff_quic_test.c,$(LINT_C)) -- \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -I.
	# The pass above defines no trust mode, so it reads none of the
	# TRUST=webpki arms. This pass parses the sources that carry them or
	# compile against the webpki layout of ch_cfg and handshake_state, and
	# the four tests built under the define, with -DCH_TRUST_WEBPKI, so
	# the cognitive-complexity threshold holds in that build too. The
	# second pass adds -DCH_KEX_PQ for webpki_session_test.c's hybrid arm.
	# Measured with clang-tidy 23.1.1: 2.9 s and 0.2 s.
	$(CLANG_TIDY) --quiet tls.c handshake_parser.c handshake_message.c handshake_auth.c \
	  handshake.c handshake_record.c webpki.c \
	  test/webpki_session_test.c test/webpki_chain_test.c test/webpki_auth_test.c \
	  test/handshake_strict_test.c test/diff_test.c examples/webpki_client.c -- \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI -I.
	$(CLANG_TIDY) --quiet test/webpki_session_test.c -- \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI -DCH_KEX_PQ -I.
	# The QUIC mode, in two passes split by QUIC_STUB_SRCS. This first
	# one reads the sources that are implemented, plus the two test
	# mains, under every check.
	@set -e; done="$(filter-out $(QUIC_STUB_SRCS),$(QUIC_SRCS))"; \
	 [ -z "$$done" ] || $(CLANG_TIDY) --quiet $$done -- \
	   -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC -I.
	$(CLANG_TIDY) --quiet test/quic_stub_test.c test/quic_vectors.c test/diff_quic_test.c -- \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC -I.
	# The second reads the sources that are still stubs, with
	# readability-non-const-parameter off. A stub writes nothing through
	# the out-parameters its header declares writable, so that check
	# reads every one of them as a pointer that could be const -- an
	# answer the header forbids, since making it const would conflict
	# with the declaration. The exception is bounded by QUIC_STUB_SRCS
	# and retires per file: an implemented source drops out of that list
	# and joins the pass above, where the check is on again.
	@set -e; [ -z "$(QUIC_STUB_SRCS)" ] || $(CLANG_TIDY) --quiet \
	   --checks='-readability-non-const-parameter' $(QUIC_STUB_SRCS) -- \
	   -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC -I.
	# The M3 smoke runtimes and the KAT program lint with the target's
	# own flags. Three checks are off, each with its reason:
	# bugprone-reserved-identifier and its two cert aliases, because the
	# linker script and the EABI name _start, __bss_start and
	# __aeabi_*; misc-use-internal-linkage, because reset_handler, main
	# and the mem routines are called by the vector fetch and the
	# compiler's own lowering, which no header reaches; and
	# portability-no-assembler, because semihosting is a bkpt
	# instruction. The FreeRTOS programs need the fetched kernel
	# headers, so freertos-check lints them (test/platforms.mk).
	$(CLANG_TIDY) --quiet \
	  --checks='-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-misc-use-internal-linkage,-portability-no-assembler' \
	  test/qemu/m3_runtime.c test/qemu/m3_start.c test/qemu/m3_kat.c -- \
	  -std=c11 --target=armv7m-none-eabi -ffreestanding -I. -Itest/qemu
	# The host half of the KAT diff is ordinary hosted C; no checks off.
	$(CLANG_TIDY) --quiet test/qemu/host_runtime.c -- -std=c11 -D_DEFAULT_SOURCE -I. -Itest/qemu
endif

lint-format:
ifeq ($(CLANG_FORMAT),)
	$(call REQUIRE,clang-format,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(BENCH_C) $(QEMU_SMOKE_C) $(TESTH)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	$(call REQUIRE,cppcheck,build it at the CPPCHECK_VERSION pinned in .github/workflows/check.yml)
else
	# constParameterCallback: I/O callback signatures are fixed by the
	# ch_cfg contract in tls.h; const-ing an implementation's void *io
	# would need function-pointer casts, which is worse.
	# shiftTooManyBitsSigned: it reports a signed right shift by width-1
	# as undefined, and C11 6.5.7 makes a negative value's right shift
	# implementation-defined, which every compiler chapulin targets
	# defines as arithmetic. That shift is the sign-spread mask ct.h's
	# ct_widemul_s and x25519's cswap build on purpose, the form gcc
	# leaves alone where it rewrote `x & (0 - bit)` as a multiply
	# (https://github.com/c4milo/chapulin/issues/106). The undefined
	# class the check also covers, a left shift out of range, is proven
	# absent by CBMC's --undefined-shift-check on every harness.
	# cfg.h demands a declared entropy pattern, so cppcheck needs one to
	# get past the preprocessor. Passing -D alone would limit it to that
	# single configuration; --force keeps it exploring CH_PIN_ECDSA,
	# CH_TRUST_CA and CH_KEX_PQ the way it did before the declaration
	# existed. Measured at 3.1 s without and 10.4 s with, over 42 files.
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --inline-suppr --suppress=missingIncludeSystem \
	  --suppress=constParameterCallback --suppress=shiftTooManyBitsSigned \
	  $(HOST_RAND_DEF) --force \
	  --error-exitcode=1 --quiet $(LINT_C)
	# The QEMU and FreeRTOS smoke sources, with two suppressions:
	# unusedStructMember, because the hardware, not C, reads the vector
	# table entries; and comparePointers, because __bss_start and
	# __bss_end are one region to the linker and two objects to C.
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --suppress=missingIncludeSystem \
	  --suppress=unusedStructMember --suppress=comparePointers \
	  --error-exitcode=1 --quiet $(filter %.c,$(QEMU_SMOKE_C))
endif

# Dev tooling lives in tools/, so npm installs into tools/node_modules and
# npx cannot resolve commitlint from the repo root. Name the binary and its
# config outright.
COMMITLINT := tools/node_modules/.bin/commitlint --config tools/commitlint.config.mjs

# One-time setup: point git at the committed hooks (commit-msg runs
# commitlint; run npm ci in tools/ first).
.PHONY: hooks lint-commits
hooks:
	git config core.hooksPath .githooks

lint-commits:
ifeq ($(wildcard tools/node_modules/.bin/commitlint),)
	$(call REQUIRE,commitlint,install node then run: npm ci --prefix tools)
else
	$(COMMITLINT) --from=$(shell git rev-list --max-parents=0 HEAD)~0 --to=HEAD \
	  || $(COMMITLINT) --from=HEAD~1 --to=HEAD
endif

# The examples build against the packaged library, the way a consumer
# links them, and e2e.sh then runs them against real servers. Building
# alone catches a changed signature; only running catches a changed
# meaning, and the reviewers found exactly that class of bug in the
# first drafts. Building them is also what stops the API drifting out
# from under the one place a reader learns it from.
#
# psk_client and pinned_client link $(LIB_OBJ), so they are built under
# the variant that built it and compiled under $(LIB_DEF), the defines
# the object was compiled with. session.h sizes ch_tls.tx by CH_KEX_PQ,
# so an example compiled without the object's defines declares a ch_tls
# of another size, and the link still succeeds. The fixed paths e2e.sh
# runs are copies, refreshed on every invocation the way lib refreshes
# bin/chapulin.o, because a timestamp cannot say which variant wrote
# them: `make bin/example_psk RAND=drbg` followed in the same second by
# `make examples-check RAND=extern` relinked nothing, since make 3.81
# compares mtimes to the second, and e2e then ran a drbg-linked example
# that aborted on drbg.c's CH_ASSERT(g_seeded)
# (https://github.com/c4milo/chapulin/issues/89).
EXAMPLE_PSK := bin/obj/$(LIB_VARIANT)/example_psk
EXAMPLE_PINNED := bin/obj/$(LIB_VARIANT)/example_pinned

$(EXAMPLE_PSK): examples/psk_client.c $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LIB_DEF) -I. -o $@ examples/psk_client.c $(LIB_OBJ)

$(EXAMPLE_PINNED): examples/pinned_client.c $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LIB_DEF) -I. -o $@ examples/pinned_client.c $(LIB_OBJ)

# Phony on purpose: the file at each path is whichever variant was copied
# there last, so the copy runs on every invocation instead of when make
# judges the path stale. The paths stay make targets because
# test/violations.py builds and deletes the binaries e2e.sh runs by
# these names.
.PHONY: bin/example_psk bin/example_pinned
bin/example_psk: $(EXAMPLE_PSK)
	@cp $(EXAMPLE_PSK) $@

bin/example_pinned: $(EXAMPLE_PINNED)
	@cp $(EXAMPLE_PINNED) $@

# The CA example needs the CA-trust library, so it links its own copy of
# the sources rather than the packaged raw-pin object.
bin/example_ca: examples/ca_client.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ examples/ca_client.c $(SRCS)

# The web PKI example needs the TRUST=webpki library, so it links its own
# copy of the sources that object packages, under that object's define.
bin/example_webpki: examples/webpki_client.c $(WEBPKI_TEST_SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ examples/webpki_client.c $(WEBPKI_TEST_SRCS)

.PHONY: examples-check
examples-check: bin/example_psk bin/example_pinned bin/example_ca bin/example_webpki
	@echo "examples-check: the PSK and pinned examples link the packaged library; ca_client links the CA-trust sources; webpki_client links the TRUST=webpki sources"


# lint-invariants checks that the code does not violate an invariant.
# This checks that a test notices when it does: each Violation field in
# docs/invariants.md becomes an edit, and some test must object. Too
# slow for check (each one rebuilds and reruns a target), so the nightly
# runs it, in two jobs.
# The violation runner requires each target to PASS on unedited source
# before it trusts the target's verdict on an edit, so every prerequisite
# a violation names must build here. bin/diff execs the Lean oracle at
# run time and nothing else in this target's lane builds it, so the
# recipe runs the lake step itself; the epoch violation drives e2e,
# which needs the CA clients.
# The fast tier: violations backed by the second-scale binaries (unit,
# the strictness parsers, rsa_test, softmul_test, webpki_spki_test,
# webpki_sigalg_test, webpki_cert_test, the decomposed-multiply unit and
# ML-KEM binaries)
# and the codegen gate scripts, so the PR lane runs them. The diff,
# handshake_sequence and e2e-backed violations run in the nightly's
# test-invariants job — each of those targets is slow enough that a
# baseline plus a mutation pass costs real minutes — and the
# proof-backed ones in its test-invariants-proof-backed job.
.PHONY: test-invariants-fast
test-invariants-fast: bin/unit bin/unit_ca bin/x509strict bin/x509strict_ecdsa bin/rsa_test bin/drbg_test bin/handshake_strict_test bin/handshake_strict_webpki bin/webpki_session_test bin/webpki_auth_test bin/softmul_test bin/unit_ct_widemul bin/mlkem_test_ct_widemul bin/webpki_spki_test bin/webpki_sigalg_test bin/webpki_cert_test
	python3 test/violations.py --tier=fast

# Every violation but the proof-backed ones: the fast tier plus the
# handshake_sequence_test, diff and e2e-backed violations that cost
# minutes each. The nightly's test-invariants job runs this.
.PHONY: test-invariants-not-proof-backed
test-invariants-not-proof-backed: bin/unit bin/diff bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP test-invariants-not-proof-backed: lake not on PATH (install elan: https://leanprover.github.io)"
else
	# The examples link the packaged object, and RAND has no default, so
	# they cannot be prerequisites of a target invoked without one. check
	# builds them through the same recursion.
	$(MAKE) RAND=extern bin/example_psk bin/example_pinned bin/example_ca
	$(call REQUIRE_MATHLIB,test-invariants-not-proof-backed)
	cd spec && $(LAKE) build
	python3 test/violations.py --not-proof-backed
endif

# The proof-backed violations, whose target is proof/prove-one.sh running
# one CBMC harness: they need cbmc on PATH, and kissat for the harness to
# verify inside the wrapper's clock. Without cbmc the baseline fails and
# the runner reports ERROR, never caught. Each run is a proof of minutes,
# twice, so the nightly gives the class its own job with its own timeout,
# test-invariants-proof-backed
# (https://github.com/c4milo/chapulin/issues/144). test/violations.py
# reads the class from each catches line, so a new proof-backed
# violation lands here without a Makefile edit.
.PHONY: test-invariants-proof-backed
test-invariants-proof-backed:
	python3 test/violations.py --proof-backed

# The whole set, one class after the other. Two recipe lines rather than
# two prerequisites: the runner edits sources in place, so the classes
# must never run at the same time under make -j.
.PHONY: test-invariants
test-invariants:
	$(MAKE) test-invariants-not-proof-backed
	$(MAKE) test-invariants-proof-backed

# The nightly runs one job per slow proof, from a static matrix. A
# launch line added without a matching matrix entry would simply never
# run in CI, and nothing would say so.
.PHONY: lint-matrix
lint-matrix:
	@a=$$(awk '$$1=="launch" && $$2 ~ /^slow/ {print $$4}' proof/run.sh | sort | tr '\n' ' '); \
	 b=$$(sed -n 's/.*proof: \[\(.*\)\]/\1/p' .github/workflows/nightly.yml \
	      | tr -d ' ' | tr ',' '\n' | sort | tr '\n' ' '); \
	 if [ "$$a" != "$$b" ]; then \
	   echo "lint-matrix: nightly matrix and run.sh slow tier disagree"; \
	   echo "  run.sh:  $$a"; \
	   echo "  nightly: $$b"; \
	   exit 1; \
	 fi; \
	 echo "lint-matrix: nightly runs every slow proof"

# The nightly's report job files an issue only for the jobs in its needs
# list. A job left out of the list runs and goes red, and nothing says
# so: proof-reach ran that way from the day it was added.
# tools/nightly-report.py holds the list equal to the job set.
.PHONY: lint-nightly-report
lint-nightly-report:
	@python3 tools/nightly-report.py

# A violation whose target is a script must name every binary that script
# runs: a script runs no make, so the 'builds' line is the only thing that
# puts them on disk. A name missing there fails quietly, since the baseline
# runs a binary nobody built and that invariant loses its verdict.
.PHONY: lint-violation-builds
lint-violation-builds:
	@python3 test/violations.py --lint-builds

# The impact selection, checked against test/violations/ as its ground
# truth: every violation names a file and the target that objects when
# that file breaks, so the plan for that file must select that target. A
# plan that drops one would let an inner loop miss a failure the tree
# already knows about. It reads files and starts a few make invocations,
# a second or two, so check runs it rather than the slow tier.
# docs/impact.md says what selection is for and what it never replaces.
#
# The checker sits in test/ and its subject sits in tools/. CLAUDE.md
# puts dev tooling in tools/ and keeps a script with the thing it
# operates on; this one reads test/violations/ as its data, so it stays
# beside that data.
.PHONY: lint-impact
lint-impact:
	@python3 test/impact_test.py

# ---------------------------------------------------------------------------
# Codegen gates. Three leaks are instruction selection rather than source, so
# no source-level rule sees them (https://github.com/c4milo/chapulin/issues/53):
# a widening multiply or a division the compiler emits for a secret operand,
# the runtime-library call a core without a multiplier makes for `*`, and a
# conditional branch the compiler chooses for a select the source wrote as
# a mask (https://github.com/c4milo/chapulin/issues/141).
# lint-wide-multiply and lint-runtime-symbols read what the compiler emits.
#
# CODEGEN_SRCS is every source a key, a shared secret, a session secret or
# record plaintext passes through: the chain from ct.c up to tls.c, plus
# drbg.c (the reference generator ships outside the packaged object, but a
# firmware that picks RAND=drbg compiles it) and softmul.c (the multiply
# itself, on a core with none). buf.c is in because the binder and the
# Finished bytes pass through wbuf; its only arithmetic is on lengths, so
# its ceiling is zero like the rest.
#
# WIDEMUL_PUBLIC is every other library source, each with the reason it
# may multiply or divide: its operands are bytes the peer sent in the
# clear.
#   p256.c, rsa.c, rsa_mont.c: public-key verify. Each does three wide
#     multiply-accumulates, measured, over a server or CA public key, a
#     transcript hash and a signature, and the client never signs, so
#     there is no signing entry point to add a secret to.
#   p384.c, p384_field.c, rsa_pkcs1.c: the same verify-only shape for the
#     signatures a public chain carries under TRUST=webpki — a CA's key,
#     a certificate's digest and its signature, every byte from the wire
#     or from the caller's anchor table, and the client never signs.
#   pem.c, x509.c, x509_der.c, x509_ca.c: the certificate readers. The
#     certificate is public too (gcc lowers x509_der.c's decimal date
#     digits to two madd on mips32r2, and nothing there is secret).
#   webpki_spki.c, webpki_sigalg.c: a public chain's keys, signature
#     algorithms and signatures under TRUST=webpki. The reader doubles a
#     coordinate length; the dispatch hashes a certificate's TBS bytes
#     and hands them, a CA's key and the signature to the three verifiers
#     above. Every byte is from the wire or from the caller's anchor
#     table.
#   sha512.c, sha512_compress.c: SHA-384 for the signatures a public chain carries. Every
#     byte it hashes is public — a certificate's TBS bytes, or the
#     CertificateVerify signed content, which is 64 spaces, a context
#     string and the transcript hash — and a hash has no multiply, so
#     the gate would read zero either way. The list says what the file
#     may see, not what it does.
#   webpki_time.c, webpki_name.c: a certificate's dates and names, the
#     caller's clock and the caller's hostname, under TRUST=webpki. The
#     date packer multiplies decimal fields by constants and the clock
#     conversion divides, every operand public.
#   webpki_ext.c, webpki_cert.c: one certificate's fields and extensions
#     under TRUST=webpki. The extension walk multiplies a
#     pathLenConstraint's high octet by 256, and every byte either file
#     reads is from the wire.
#   webpki.c: the chain walk under TRUST=webpki. It multiplies the two
#     high octets of a CertificateEntry's u24 length, and compares
#     Names, dates and depths. A public chain is public: every byte it
#     reads is from the wire or from the caller's anchor table, and it
#     never sees a key, a shared secret or record plaintext.
#   quic_aes.c, quic_gcm.c: the AES-128 forward cipher and AES-128-GCM
#     under TRANSPORT=quic. INV-26 admits exactly three key sources
#     here, and RFC 9001 says every one of them is public: the Initial
#     packet key and header protection key, both expanded from
#     HKDF-Extract over the printed salt and the Destination Connection
#     ID a long header carries in the clear (§5.2), and the 16-byte
#     Retry key the RFC prints (§5.8). No traffic secret keysched.c
#     derives reaches either file.
#   quic_initial.c, quic_retry.c: the Initial packet path and the Retry
#     tag check, the only two library sources INV-26 lets call those
#     entries. They see the same three keys and the packet bytes that
#     travel under them, which RFC 9001 §5 says have neither
#     confidentiality nor integrity protection.
# A secret arriving in any of these is a design change, and this list is
# where it lands. Until https://github.com/c4milo/chapulin/issues/85 the
# gate read four files and the rest went unmeasured.
#
# Both lists are hand-kept, so lint-codegen-partition holds them to a
# partition of the library sources: every source is in exactly one, and
# every entry names a source. Without it a new secret-bearing file was
# measured by neither gate until someone added it
# (https://github.com/c4milo/chapulin/issues/143).
#
# Ceilings are file:count and hold on every spec below unless
# WIDEMUL_CEILING_SPEC names the spec and file. Going over fails. Coming in
# under only prints, because the only non-zero entries are a public
# division whose lowering is a compiler choice and a recorded leak that is
# meant to fall, and zero cannot be undershot, so every other module is
# held exactly.
WIDEMUL_CEILING := ct.c:0 sha256.c:0 sha3.c:1 hkdf.c:0 chacha20.c:0 poly1305.c:0 aead.c:0 \
                   x25519.c:0 mlkem.c:0 mlkem_poly.c:0 buf.c:0 record.c:0 keysched.c:0 io.c:0 \
                   session.c:0 handshake_message.c:0 handshake_parser.c:0 handshake_record.c:0 \
                   handshake_auth.c:0 handshake.c:0 handshake_post.c:0 tls.c:0 drbg.c:0 softmul.c:0 \
                   quic_keys.c:0 quic_packet.c:0 quic_step.c:0 quic.c:0
CODEGEN_SRCS := $(foreach e,$(WIDEMUL_CEILING),$(firstword $(subst :, ,$(e))))
# Per-file defines both gates below add for one file alone, file:defines,
# in the shape WIDEMUL_CEILING_SPEC uses for per-spec ceilings. Each gate
# compiles every CODEGEN_SRCS file under one fixed flag set that names no
# transport, and the four QUIC entries above do not compile without
# -DCH_TRANSPORT_QUIC: CH_LEVEL_*, the ch_quic struct and the new ch_cfg
# fields all sit behind it. Adding the define to the shared line instead
# would break record.c, io.c, session.c, handshake.c and tls.c, which are
# on the same list and compile only without it.
WIDEMUL_DEFINES := quic_keys.c:-DCH_TRANSPORT_QUIC quic_packet.c:-DCH_TRANSPORT_QUIC \
                   quic_step.c:-DCH_TRANSPORT_QUIC quic.c:-DCH_TRANSPORT_QUIC
WIDEMUL_PUBLIC := p256.c rsa.c rsa_mont.c pem.c x509.c x509_der.c x509_ca.c sha512.c sha512_compress.c \
                  p384.c p384_field.c rsa_pkcs1.c webpki_time.c webpki_name.c webpki_spki.c webpki_sigalg.c \
                  webpki_ext.c webpki_cert.c webpki.c \
                  quic_aes.c quic_gcm.c quic_initial.c quic_retry.c

# The library sources are $(SRCS), drbg.c, and every .c file git tracks
# at the repository root. The KEX=pq sources join LIB_SRCS by += rather
# than through SRCS, and every library source is a root file whichever
# build variable lists it, so git's view is the one no Makefile list can
# fall behind (SH_SRCS is the precedent). $(SRCS) stays in the union so a
# file listed before it is tracked fails here rather than on CI.
.PHONY: lint-codegen-partition
lint-codegen-partition:
	@rc=0; \
	 srcs=" $$({ printf '%s\n' $(SRCS) drbg.c; git ls-files '*.c' | grep -v /; } | sort -u | tr '\n' ' ')"; \
	 for f in $$srcs; do \
	   gated=0; public=0; \
	   for g in $(CODEGEN_SRCS); do [ "$$g" = "$$f" ] && gated=1; done; \
	   for p in $(WIDEMUL_PUBLIC); do [ "$$p" = "$$f" ] && public=1; done; \
	   case "$$gated$$public" in \
	     00) echo "lint-codegen-partition: $$f is in neither WIDEMUL_CEILING nor WIDEMUL_PUBLIC, so no codegen gate measures it"; rc=1 ;; \
	     11) echo "lint-codegen-partition: $$f is in both WIDEMUL_CEILING and WIDEMUL_PUBLIC; a source is gated or public, never both"; rc=1 ;; \
	   esac; \
	 done; \
	 for e in $(CODEGEN_SRCS) $(WIDEMUL_PUBLIC); do \
	   case "$$srcs" in *" $$e "*) ;; \
	     *) echo "lint-codegen-partition: $$e is in a gate list and is not a library source"; rc=1 ;; \
	   esac; \
	 done; \
	 [ $$rc -eq 0 ] && echo "lint-codegen-partition: every library source is in exactly one of WIDEMUL_CEILING and WIDEMUL_PUBLIC"; exit $$rc

# The Cortex-M3 has two multiply opcodes: mul is constant-time, umull is
# not -- it returns sooner when both operands are below 65536, and has
# undocumented early exits on zero and powers of two. The 32->64 one has
# been used to extract Curve25519 keys. So a product wider than 32 bits
# reached from a secret is a leak on that part, whatever the source says.
# A division is the same shape on every core here: udiv, div and rem take
# a data-dependent number of cycles (KyberSlash was a division on a
# secret-derived coefficient), and a 64-bit quotient becomes a call into
# the compiler's runtime, which branches on its operands. 64-bit addition
# is fine: it is two 32-bit adds.
#
# ct_widemul and ct_mulsmall in ct.h build a wide product out of 16x16
# pieces, so every secret-touching module is at zero where the compiler
# keeps the pieces apart. sha3's `% 5` over Keccak's public loop counters
# is the one entry that is non-zero by design: clang lowers it to a
# multiply-high, gcc to a hardware division, and no secret is divided, so
# it is recorded rather than fought (writing it as conditional subtraction
# does not help; the optimiser recognises the loop and puts the modulo
# back).
#
# Each spec is name:compiler:machine:flags:tokens:branches.
#   compiler  clang or gcc. clang specs compile under $(CLANG_RV) with
#             -target machine, always, and are part of lint. gcc specs
#             compile under the driver lint-wide-multiply-gcc is given
#             (WIDEMUL_GCC), and a spec runs only when that driver's
#             -dumpmachine starts with machine, so a CI lane runs the spec
#             its toolchain is for and cannot run another's by mistake.
#   flags     comma-separated: the CPU or arch selection the spec measures,
#             and after it an optimisation level when the spec measures
#             one other than -Os. The gate passes -Os before the flags,
#             so a level in the flags wins.
#   tokens    comma-separated. A token without a leading __ is an opcode
#             and counts every instruction whose mnemonic begins with it,
#             so umullne, umulls, umull.w and udiveq count under umull and
#             udiv (a word-boundary match let the condition-code forms
#             through). A token with a leading __ is a runtime routine and
#             counts every call whose target begins with it, which is
#             where a 64-bit division goes on every one of these cores.
#             A prefix can only over-count, and an over-count fails the
#             gate loudly; it cannot let a form through. Assembler
#             directives, the lines that begin with a dot, are dropped
#             before the count: a file that defines a runtime routine
#             names it in .globl, .type and .size, and none of those is
#             a call. softmul.c is that file.
#   branches  comma-separated opcodes, matched as prefixes the same way:
#             the conditional-branch mnemonics of the ISA, one of the
#             BRANCH_OPS lists below. Every file in BRANCH_SRCS holds a
#             recorded count of them per spec.
# The arm list carries the Thumb-2 forms whose product or quotient is
# wider than 32 bits, the DSP ones included, so it holds on an M4 too;
# mips carries the r6 spellings beside the r2 ones for the same reason.
WIDEMUL_OPS_ARM := umull,umlal,umaal,smull,smlal,smlsld,smmul,smmla,smmls,smulw,smlaw,udiv,sdiv,__aeabi_uidiv,__aeabi_idiv,__aeabi_uldiv,__aeabi_ldiv,__udiv,__div,__umod,__mod
WIDEMUL_OPS_MIPS := mult,multu,madd,maddu,msub,msubu,muh,muhu,div,divu,ddiv,ddivu,mod,modu,__udiv,__div,__umod,__mod
WIDEMUL_OPS_RV := mulh,mulhu,mulhsu,div,divu,rem,remu,__udiv,__div,__umod,__mod
# rv32ic has no M extension, so there is no mulh to count: a 64-bit
# product is a call to __muldi3 and a division a call into the __div and
# __mod family, and those names are the whole list. On a chapulin build
# __muldi3 is softmul.c's own constant-time routine, so a count is a
# 64-bit product the decomposition should have kept out, the same finding
# mulh is on rv32imac. __mulsi3 is not listed: it is the 32-to-32
# multiply, which no spec counts as mul either, and poly1305, x25519 and
# mlkem_poly call it once per 16x16 piece. softmul.c's zero holds one
# more thing: gcc at -Os rewrote its masked add into a 64-bit multiply,
# which on this core was a call to __muldi3 from inside __muldi3
# (https://github.com/c4milo/chapulin/issues/107).
WIDEMUL_OPS_RV32I := __muldi3,__udiv,__div,__umod,__mod
# The second count, read from the same assembly: the conditional branches
# each file emits (https://github.com/c4milo/chapulin/issues/141). INV-16
# claims no emitted instruction branches on a secret, and the multiply
# tokens above cannot see one. The compare-carries in ct_widemul_opaque,
# `mid < lh` and `lo < ll`, and the sign masks in ct_widemul_s, cswap
# and poly1305_final are branch-free in C, and each compiler in the table
# lowers them to a predicated instruction, sltu or an arithmetic shift
# today -- by its choice, and no check held it to that choice. This count
# is the check. It cannot tell a branch on a public loop counter from one
# on a limb, so every file in BRANCH_SRCS carries a measured count per
# spec in BRANCH_CEILING, all of them loop control on public counts (a
# block loop, x25519's ladder, poly1305's `n >= 16`, Keccak's round and
# lane counters, softmul's fixed 32 and 64 iterations), and what the gate
# holds is that the count does not grow: a branch a compiler puts on a
# limb lands on top of the recorded ones.
# test/violations/inv16-poly1305-final-sign-branch.violation writes
# poly1305_final's select as an if on the last limb's sign, and the
# count rises by one under every compiler in the table.
# test/violations/inv16-widemul-s-sign-branch.violation writes
# ct_widemul_s's two sign corrections as ifs: clang lowers both back to
# the mask and its count does not move, and every gcc emits two branches
# on the signs where x25519 inlines the routine, so only the gcc specs
# see it -- the split the multiply count found first
# (https://github.com/c4milo/chapulin/issues/106).
#
# arm counts every b<cond> -- both spellings of carry-set and carry-clear,
# and the .w and .n widths through the prefix -- cbz and cbnz, the table
# branches tbb and tbh, and the IT instruction, one per block. A
# predicated instruction takes the same cycles on the Cortex-M3 whether
# or not its condition holds, so an IT block is not a timing leak there;
# it is counted because it is the form clang gives an if on a limb (it
# mi, addmi), and a count that saw only b<cond> would pass that form
# through. Unconditional b, bl, blx and bx do not count. mips counts beq,
# bne and the four compare-with-zero branches, and the prefixes take the
# likely (beql), link (bgezal), assembler (beqz, bnez) and r6 compact
# (beqc, bltc, bgeuc) spellings with them; movz and movn are selects, not
# branches, and do not count. rv32 counts the six base branches and the
# compressed c.beqz and c.bnez, and the prefixes take the assembler's
# beqz, bnez, bgt, ble, bgtu and bleu. No spec counts a jump through a
# register (jr, jalr, a load into pc): it is a return as often as a table
# jump, and no file in BRANCH_SRCS has a switch.
BRANCH_OPS_ARM := beq,bne,bcs,bhs,bcc,blo,bmi,bpl,bvs,bvc,bhi,bls,bge,blt,bgt,ble,cbz,cbnz,tbb,tbh,it
BRANCH_OPS_MIPS := beq,bne,blt,bge,bgt,ble
BRANCH_OPS_RV := beq,bne,blt,bge,bgt,ble,c.beqz,c.bnez
# Both compiler families are measured: CLAUDE.md names gcc-shipping
# firmware trees as the audience, and gcc does not keep the 16x16 pieces
# apart where clang does (https://github.com/c4milo/chapulin/issues/86).
# The five gcc specs are the three CI toolchains: the Arm GNU release
# ARM_GNU_VERSION pins; Ubuntu 24.04's gcc-mips-linux-gnu, which runs
# twice -- at -Os like every other spec, and at -O2, the one compiler and
# level where a secret-bearing file is not at zero
# (https://github.com/c4milo/chapulin/issues/122); and the Bootlin
# riscv32 toolchain RV32_TC_VERSION pins, which runs twice -- rv32imac,
# and rv32ic, the core with no multiplier, where softmul.c compiles.
WIDEMUL_SPECS := \
  m3:clang:thumbv7m-none-eabi:-mcpu=cortex-m3:$(WIDEMUL_OPS_ARM):$(BRANCH_OPS_ARM) \
  mips32r2:clang:mips-linux-musl:-march=mips32r2:$(WIDEMUL_OPS_MIPS):$(BRANCH_OPS_MIPS) \
  rv32imac:clang:riscv32-unknown-elf:-march=rv32imac:$(WIDEMUL_OPS_RV):$(BRANCH_OPS_RV) \
  m3-gcc:gcc:arm-none-eabi:-mcpu=cortex-m3,-mthumb:$(WIDEMUL_OPS_ARM):$(BRANCH_OPS_ARM) \
  mips32r2-gcc:gcc:mips-:-march=mips32r2,-mabi=32:$(WIDEMUL_OPS_MIPS):$(BRANCH_OPS_MIPS) \
  mips32r2-gcc-O2:gcc:mips-:-march=mips32r2,-mabi=32,-O2:$(WIDEMUL_OPS_MIPS):$(BRANCH_OPS_MIPS) \
  rv32imac-gcc:gcc:riscv32-:-march=rv32imac,-mabi=ilp32:$(WIDEMUL_OPS_RV):$(BRANCH_OPS_RV) \
  rv32ic-gcc:gcc:riscv32-:-march=rv32ic,-mabi=ilp32:$(WIDEMUL_OPS_RV32I):$(BRANCH_OPS_RV)
# Per-spec ceilings, spec/file:count, where a spec measures a file above its
# WIDEMUL_CEILING entry. Every number is measured with the spec's compiler
# at its flags, at -Os unless the flags carry another level. The entries
# are sha3.c under each gcc, the public `% 5`, five hardware divisions
# where clang's one multiply-high stood, and poly1305.c under the mips
# gcc at -O2, two madd.
#
# That two is a record, not an allowance. At -O2 the mips gcc inlines
# ct_widemul into poly1305's block, and for two of the 75 `product + x`
# sums the 25 recombinations hand it, its register allocator keeps the
# accumulator in LO and emits madd (mtlo, madd, mflo) where the other 73
# get mul and addu; -O1 gives four. The operands are the same 16-bit
# halves either way. At -Os every gcc keeps ct_widemul out of line, so
# the -Os specs read the recombination once per file and never inlined
# under the block's register pressure; this spec is the one that does.
# The form that hands gcc no such sum costs 38% of AEAD seal and 19% of
# x25519 on mips32r2, so the ladder stays; docs/porting.md has the
# measurements, and the inv16-widemul-compare-carries violation is the
# edit this spec catches and the -Os spec does not
# (https://github.com/c4milo/chapulin/issues/122).
#
# poly1305.c, x25519.c and mlkem_poly.c held non-zero gcc entries once: the
# leak https://github.com/c4milo/chapulin/issues/86 predicted, found the
# first time the gate ran under gcc. arm-none-eabi-gcc fused ct_widemul's
# `(uint64_t)lh + hl` -- a 64-bit sum of two products it could prove narrow
# -- into umlal, and both it and the Bootlin riscv32 gcc rewrote the sign
# mask `x & (0 - bit)` in ct_widemul_s and cswap as `x * bit`, a widening
# multiply by a secret bit. ct.h and x25519.c no longer carry either form
# (https://github.com/c4milo/chapulin/issues/106), every secret-bearing
# file is at zero under every -Os spec, and the
# inv16-widemul-mid-widened violation keeps the first form caught.
#
# rv32ic-gcc counts runtime names, since rv32ic has no multiply or divide
# instruction: the `% 5` is five calls to __modsi3. softmul.c is at zero
# calls to __muldi3 there, which is the point of the spec
# (https://github.com/c4milo/chapulin/issues/107).
WIDEMUL_CEILING_SPEC := m3-gcc/sha3.c:5 mips32r2-gcc/sha3.c:5 mips32r2-gcc-O2/sha3.c:5 \
                        mips32r2-gcc-O2/poly1305.c:2 rv32imac-gcc/sha3.c:5 rv32ic-gcc/sha3.c:5
# The files the branch count covers: the arithmetic under the record
# layer, whose every input is a key, a limb or a block, and whose only
# branches are loop control on public counts. The other CODEGEN_SRCS
# files -- buf.c, record.c, keysched.c, io.c, session.c, the handshake
# files and tls.c -- branch on lengths, types and states the peer sent in
# the clear, several dozen each, so a count there would record the parser
# and move with every feature. The multiply count still covers them; a
# secret reaching their control paths is a design change, not a codegen
# choice, and review holds that line.
BRANCH_SRCS := ct.c sha256.c sha3.c hkdf.c chacha20.c poly1305.c aead.c x25519.c mlkem.c \
               mlkem_poly.c drbg.c softmul.c
# Per-spec branch ceilings, spec/file:count, one for every BRANCH_SRCS
# file under every spec. A spec that lacks one fails, and the gate's own
# output is where a new spec reads its numbers. Every number is measured
# with the spec's compiler at its flags: make lint-wide-multiply for the
# three clang rows, make lint-wide-multiply-gcc for m3-gcc, and
# test/docker-mips.sh and test/docker-riscv32.sh for the other four.
# Going over fails; coming in under prints, and the entry then comes
# down. softmul.c compiles to nothing where a multiplier exists and to
# its two fixed-count loops on rv32ic, which is the one nonzero entry
# for it.
BRANCH_CEILING := \
  m3/ct.c:4 m3/sha256.c:17 m3/sha3.c:50 m3/hkdf.c:13 m3/chacha20.c:9 m3/poly1305.c:19 \
  m3/aead.c:4 m3/x25519.c:34 m3/mlkem.c:14 m3/mlkem_poly.c:43 m3/drbg.c:9 m3/softmul.c:0 \
  mips32r2/ct.c:4 mips32r2/sha256.c:16 mips32r2/sha3.c:29 mips32r2/hkdf.c:10 \
  mips32r2/chacha20.c:7 mips32r2/poly1305.c:18 mips32r2/aead.c:2 mips32r2/x25519.c:31 \
  mips32r2/mlkem.c:13 mips32r2/mlkem_poly.c:36 mips32r2/drbg.c:8 mips32r2/softmul.c:0 \
  rv32imac/ct.c:4 rv32imac/sha256.c:17 rv32imac/sha3.c:38 rv32imac/hkdf.c:14 \
  rv32imac/chacha20.c:8 rv32imac/poly1305.c:18 rv32imac/aead.c:2 rv32imac/x25519.c:31 \
  rv32imac/mlkem.c:14 rv32imac/mlkem_poly.c:36 rv32imac/drbg.c:9 rv32imac/softmul.c:0 \
  m3-gcc/ct.c:2 m3-gcc/sha256.c:12 m3-gcc/sha3.c:24 m3-gcc/hkdf.c:12 m3-gcc/chacha20.c:7 \
  m3-gcc/poly1305.c:14 m3-gcc/aead.c:2 m3-gcc/x25519.c:23 m3-gcc/mlkem.c:14 \
  m3-gcc/mlkem_poly.c:37 m3-gcc/drbg.c:8 m3-gcc/softmul.c:0 \
  mips32r2-gcc/ct.c:2 mips32r2-gcc/sha256.c:12 mips32r2-gcc/sha3.c:21 mips32r2-gcc/hkdf.c:11 \
  mips32r2-gcc/chacha20.c:6 mips32r2-gcc/poly1305.c:14 mips32r2-gcc/aead.c:2 \
  mips32r2-gcc/x25519.c:20 mips32r2-gcc/mlkem.c:14 mips32r2-gcc/mlkem_poly.c:41 \
  mips32r2-gcc/drbg.c:7 mips32r2-gcc/softmul.c:0 \
  mips32r2-gcc-O2/ct.c:4 mips32r2-gcc-O2/sha256.c:23 mips32r2-gcc-O2/sha3.c:31 \
  mips32r2-gcc-O2/hkdf.c:11 mips32r2-gcc-O2/chacha20.c:7 mips32r2-gcc-O2/poly1305.c:21 \
  mips32r2-gcc-O2/aead.c:2 mips32r2-gcc-O2/x25519.c:28 mips32r2-gcc-O2/mlkem.c:18 \
  mips32r2-gcc-O2/mlkem_poly.c:38 mips32r2-gcc-O2/drbg.c:8 mips32r2-gcc-O2/softmul.c:0 \
  rv32imac-gcc/ct.c:2 rv32imac-gcc/sha256.c:15 rv32imac-gcc/sha3.c:26 rv32imac-gcc/hkdf.c:15 \
  rv32imac-gcc/chacha20.c:10 rv32imac-gcc/poly1305.c:15 rv32imac-gcc/aead.c:4 \
  rv32imac-gcc/x25519.c:23 rv32imac-gcc/mlkem.c:20 rv32imac-gcc/mlkem_poly.c:39 \
  rv32imac-gcc/drbg.c:9 rv32imac-gcc/softmul.c:0 \
  rv32ic-gcc/ct.c:2 rv32ic-gcc/sha256.c:15 rv32ic-gcc/sha3.c:26 rv32ic-gcc/hkdf.c:15 \
  rv32ic-gcc/chacha20.c:10 rv32ic-gcc/poly1305.c:15 rv32ic-gcc/aead.c:4 \
  rv32ic-gcc/x25519.c:23 rv32ic-gcc/mlkem.c:20 rv32ic-gcc/mlkem_poly.c:39 \
  rv32ic-gcc/drbg.c:9 rv32ic-gcc/softmul.c:2
WIDEMUL_RUN ?= clang
WIDEMUL_GCC ?= $(M3_CC)
.PHONY: lint-wide-multiply lint-wide-multiply-gcc
lint-wide-multiply:
	@rc=0; ran=""; got=""; \
	 for spec in $(WIDEMUL_SPECS); do \
	   arch=$${spec%%:*}; rest=$${spec#*:}; \
	   compiler=$${rest%%:*}; rest=$${rest#*:}; \
	   machine=$${rest%%:*}; rest=$${rest#*:}; \
	   flags=$$(echo "$${rest%%:*}" | tr ',' ' '); rest=$${rest#*:}; \
	   tokens=$${rest%%:*}; branches=""; \
	   case "$$rest" in *:*) branches=$${rest#*:} ;; esac; \
	   [ "$$compiler" = "$(WIDEMUL_RUN)" ] || continue; \
	   case "$$compiler" in \
	   clang) \
	     [ -n "$(CLANG_RV)" ] || { echo "lint-wide-multiply: clang is missing, and a linter must not skip. It ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env"; exit 1; }; \
	     cc="$(CLANG_RV) -target $$machine -nostdlibinc -Itools/freestanding" ;; \
	   gcc) \
	     [ -n "$(WIDEMUL_GCC)" ] || { echo "lint-wide-multiply: set WIDEMUL_GCC=<the gcc driver you ship>; there is no gcc to measure"; exit 1; }; \
	     got=$$($(WIDEMUL_GCC) -dumpmachine 2>/dev/null) || { echo "lint-wide-multiply: $(WIDEMUL_GCC) does not answer -dumpmachine"; exit 1; }; \
	     case "$$got" in "$$machine"*) ;; *) continue ;; esac; \
	     cc="$(WIDEMUL_GCC)" ;; \
	   *) echo "lint-wide-multiply: spec $$arch names compiler '$$compiler'; it is clang or gcc"; exit 1 ;; \
	   esac; \
	   ops=$$(echo "$$tokens" | tr ',' '\n' | grep -v '^__' | paste -sd '|' -); \
	   calls=$$(echo "$$tokens" | tr ',' '\n' | grep '^__' | paste -sd '|' -); \
	   pattern=""; \
	   [ -z "$$ops" ] || pattern="^[[:space:]]+($$ops)"; \
	   [ -z "$$calls" ] || pattern="$$pattern$${pattern:+|}[[:space:],(]($$calls)"; \
	   [ -n "$$pattern" ] || { echo "lint-wide-multiply: spec $$arch lists no token to count"; exit 1; }; \
	   [ -n "$$branches" ] || { echo "lint-wide-multiply: spec $$arch lists no conditional branch to count; the sixth field is the branch mnemonics of its ISA (BRANCH_OPS_ARM, BRANCH_OPS_MIPS or BRANCH_OPS_RV)"; exit 1; }; \
	   bpattern="^[[:space:]]+($$(echo "$$branches" | tr ',' '\n' | paste -sd '|' -))"; \
	   ran="$$ran$$arch "; table=""; btable=""; \
	   for e in $(WIDEMUL_CEILING); do \
	     f=$${e%%:*}; cap=$${e##*:}; \
	     for o in $(WIDEMUL_CEILING_SPEC); do [ "$${o%%:*}" = "$$arch/$$f" ] && cap=$${o##*:}; done; \
	     extra=""; \
	     for o in $(WIDEMUL_DEFINES); do [ "$${o%%:*}" = "$$f" ] && extra=$$(echo "$${o#*:}" | tr ',' ' '); done; \
	     err=$$(mktemp); \
	     asm=$$($$cc -Os $$flags -std=c11 -ffreestanding -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ $$extra -I. -S $$f -o - 2>"$$err") || { \
	       echo "lint-wide-multiply: $$f does not build for $$arch — a count of zero from a failed compile is not a measurement"; \
	       sed -n '1p' "$$err" | sed 's/^/lint-wide-multiply:   /'; \
	       rm -f "$$err"; rc=1; continue; }; \
	     rm -f "$$err"; \
	     [ -n "$$asm" ] || { echo "lint-wide-multiply: $$f produced no assembly for $$arch"; rc=1; continue; }; \
	     asm=$$(printf '%s\n' "$$asm" | grep -vE '^[[:space:]]*\.'); \
	     n=$$(printf '%s\n' "$$asm" | grep -cE "$$pattern"); \
	     [ "$$n" -eq 0 ] || table="$$table $$f=$$n"; \
	     if [ "$$n" -gt "$$cap" ]; then \
	       echo "lint-wide-multiply: $$f emits $$n wide multiplies or divisions on $$arch, ceiling is $$cap (see https://github.com/c4milo/chapulin/issues/53)"; \
	       printf '%s\n' "$$asm" | grep -E "$$pattern" | head -5 | sed 's/^[[:space:]]*/lint-wide-multiply:   /'; rc=1; \
	     elif [ "$$n" -lt "$$cap" ]; then \
	       echo "lint-wide-multiply: $$f is down to $$n from $$cap on $$arch — lower the ceiling"; \
	     fi; \
	     case " $(BRANCH_SRCS) " in *" $$f "*) ;; *) continue ;; esac; \
	     bcap=""; for o in $(BRANCH_CEILING); do [ "$${o%%:*}" = "$$arch/$$f" ] && bcap=$${o##*:}; done; \
	     b=$$(printf '%s\n' "$$asm" | grep -cE "$$bpattern"); \
	     btable="$$btable $$f=$$b"; \
	     if [ -z "$$bcap" ]; then \
	       echo "lint-wide-multiply: $$f has no branch ceiling for $$arch and emits $$b conditional branches; read them, then record $$arch/$$f:$$b in BRANCH_CEILING"; rc=1; \
	     elif [ "$$b" -gt "$$bcap" ]; then \
	       echo "lint-wide-multiply: $$f emits $$b conditional branches on $$arch, ceiling is $$bcap (see https://github.com/c4milo/chapulin/issues/141)"; \
	       printf '%s\n' "$$asm" | grep -E "$$bpattern" | awk '{print $$1}' | sort | uniq -c | awk '{printf " %s=%s", $$2, $$1} END {print ""}' | sed 's/^/lint-wide-multiply:  /'; rc=1; \
	     elif [ "$$b" -lt "$$bcap" ]; then \
	       echo "lint-wide-multiply: $$f is down to $$b conditional branches from $$bcap on $$arch — lower the ceiling"; \
	     fi; \
	   done; \
	   echo "lint-wide-multiply: $$arch, $$($$cc --version 2>/dev/null | head -1):$${table:- every file at 0}; branches$$btable"; \
	 done; \
	 [ -n "$$ran" ] || { echo "lint-wide-multiply: no $(WIDEMUL_RUN) spec ran$${got:+ — none matches $(WIDEMUL_GCC) ($$got); add one to WIDEMUL_SPECS}"; exit 1; }; \
	 [ $$rc -eq 0 ] && echo "lint-wide-multiply: every module at its recorded ceiling on $$ran"; exit $$rc

# The same gate under the gcc a firmware tree ships. WIDEMUL_GCC is the
# driver: the spec whose machine prefix matches its -dumpmachine runs, and
# no match fails rather than skips. The m3, mips and riscv32 CI jobs each
# run this with their toolchain; locally it defaults to the Arm GNU release
# the m3 lane uses (M3_CC in test/platforms.mk).
lint-wide-multiply-gcc:
	@$(MAKE) --no-print-directory lint-wide-multiply WIDEMUL_RUN=gcc WIDEMUL_GCC="$(WIDEMUL_GCC)"

# A core without the M extension has no hardware multiply, so every `*`
# becomes a libgcc call, and those routines branch on their operands
# (https://github.com/c4milo/chapulin/issues/53). That is a variable-time
# sequence reached from secret data, which INV-23's ban on / and % cannot
# see: it bans source-level division, and this is the compiler emitting a
# routine for multiplication. softmul.c supplies constant-time __mulsi3 and
# __muldi3 under the names the compiler emits, so the branching ones are
# never linked. clang carries the riscv32 target, so this needs no cross
# toolchain.
#
# This gate builds every CODEGEN_SRCS file for rv32ic and holds two things:
# which runtime routines each file pulls, and that softmul.c still defines
# the ones the list admits.
#
# RV_ALLOWED is file:symbols, measured under the pinned clang; a file not
# named pulls nothing. It used to be one list for all files, with softmul's
# definitions subtracted from the union of everything undefined -- so a new
# `*` in aead.c resolved to softmul's __mulsi3 and nothing said so, and a
# new `/` anywhere hid behind sha3's __udivsi3
# (https://github.com/c4milo/chapulin/issues/85). Now a symbol is judged in
# the file that pulls it. sha3's __udivsi3 is Keccak's `% 5` over public
# loop counters, a performance matter rather than a leak.
#
# The four TRANSPORT=quic entries WIDEMUL_CEILING carries -- quic.c,
# quic_keys.c, quic_packet.c and quic_step.c -- get no row: measured
# under the pinned clang for rv32ic with their WIDEMUL_DEFINES entry,
# each pulls nothing. A row for a file that pulls nothing is not free,
# because the loop below prints "no longer pulls" for it on every run.
# The decision is recorded here rather than left to a reader of the
# list's absence, and it is re-measured when these files stop being
# stubs.
RV_ALLOWED := poly1305.c:__mulsi3 x25519.c:__mulsi3 mlkem_poly.c:__mulsi3 sha3.c:__udivsi3
# What softmul.c must define. The __mul* names RV_ALLOWED admits are
# constant-time only because this file supplies them; if it stopped, the
# admitted calls would bind to libgcc's and the allowlist would keep
# passing. So the definitions are asserted, not assumed.
RV_SOFTMUL := __muldi3 __mulsi3
.PHONY: lint-runtime-symbols
lint-runtime-symbols:
ifeq ($(CLANG_RV),)
	$(call REQUIRE,clang,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else ifeq ($(LLVM_NM),)
	$(call REQUIRE,llvm-nm,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	@d=$$(mktemp -d); rc=0; seen=0; \
	 for f in $(CODEGEN_SRCS); do \
	   extra=""; \
	   for o in $(WIDEMUL_DEFINES); do [ "$${o%%:*}" = "$$f" ] && extra=$$(echo "$${o#*:}" | tr ',' ' '); done; \
	   $(CLANG_RV) -target riscv32-unknown-elf -march=rv32ic -mabi=ilp32 -Os -std=c11 -ffreestanding \
	     -nostdlibinc -Itools/freestanding -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ $$extra -I. \
	     -c $$f -o $$d/$${f%.c}.o 2>/dev/null \
	     || { echo "lint-runtime-symbols: $$f does not build for rv32ic"; rc=1; continue; }; \
	   allowed=""; \
	   for e in $(RV_ALLOWED); do [ "$${e%%:*}" = "$$f" ] && allowed=$$(echo "$${e#*:}" | tr ',' ' '); done; \
	   got=$$($(LLVM_NM) -u $$d/$${f%.c}.o 2>/dev/null | grep -oE '__[a-z0-9_]+' | sort -u); \
	   for sym in $$got; do \
	     seen=$$((seen + 1)); \
	     echo "$$allowed" | tr ' ' '\n' | grep -qx "$$sym" \
	       || { echo "lint-runtime-symbols: $$f pulls $$sym on rv32ic, a compiler-runtime dependency RV_ALLOWED does not record for it (see https://github.com/c4milo/chapulin/issues/53)"; rc=1; }; \
	   done; \
	   for sym in $$allowed; do \
	     echo "$$got" | grep -qx "$$sym" \
	       || echo "lint-runtime-symbols: $$f no longer pulls $$sym — drop it from RV_ALLOWED"; \
	   done; \
	 done; \
	 [ "$$seen" -gt 0 ] || { echo "lint-runtime-symbols: read no undefined symbol from any object; llvm-nm or the build failed"; rc=1; }; \
	 def=$$($(LLVM_NM) --defined-only $$d/softmul.o 2>/dev/null | awk '{print $$3}' | grep -E '^__' | sort | tr '\n' ' '); \
	 want=$$(echo $(RV_SOFTMUL) | tr ' ' '\n' | sort | tr '\n' ' '); \
	 [ "$$def" = "$$want" ] \
	   || { echo "lint-runtime-symbols: softmul.c defines '$$def' on rv32ic; RV_SOFTMUL expects '$$want'"; rc=1; }; \
	 rm -rf $$d; \
	 [ $$rc -eq 0 ] && echo "lint-runtime-symbols: on rv32ic each file pulls only the runtime calls RV_ALLOWED records, and softmul.c defines $(RV_SOFTMUL)"; exit $$rc
endif

.PHONY: lint-bench-numbers
lint-bench-numbers:
	@python3 tools/bench-numbers.py

.PHONY: lint-shellcheck
lint-shellcheck:
ifeq ($(shell command -v $(SHELLCHECK) 2>/dev/null),)
	$(call REQUIRE,shellcheck,brew install shellcheck — see the SHELLCHECK_VERSION pin in tools/toolchain.env)
else
	@$(SHELLCHECK) -x -f gcc $(SH_SRCS) \
	  && echo "lint-shellcheck: every shell script clean"
endif

.PHONY: lint-issue-links
lint-issue-links:
	@python3 tools/issue-links.py

# A merge or three-way apply that stops on a conflict writes its markers
# into the file, and when nobody re-reads the file the commit keeps them
# (https://github.com/c4milo/chapulin/issues/130). git writes every
# conflict hunk as a `<<<<<<< label` line, a `=======` line and a
# `>>>>>>> label` line; the diff3 and zdiff3 styles add a `||||||| base`
# line between them, and an empty label (`git merge-file -L ''`) leaves
# the seven characters alone on the line (xdiff/xmerge.c). So matching
# the outer two lines finds every hunk, and the pattern is exactly what
# git writes: seven markers, then a space or the end of the line. The
# `=======` line is not matched on its own, because a bare `=======` is
# also a Markdown setext heading underline; it is a marker only between
# the outer pair, and the outer pair is already caught. -I skips binary
# files: git never merges a binary file three-way, so it never writes
# markers into one.
.PHONY: lint-conflict-markers
lint-conflict-markers:
	@hits=$$(git grep -nIE '^(<<<<<<<|>>>>>>>)( |$$)' -- .); \
	 if [ -n "$$hits" ]; then \
	   printf '%s\n' "$$hits" | sed 's/^/lint-conflict-markers: /'; \
	   echo "lint-conflict-markers: a merge or three-way apply left its markers in a tracked file"; \
	   exit 1; \
	 fi; \
	 echo "lint-conflict-markers: no conflict marker in any tracked file"

# The fuzz job's budget is per target, so adding a target silently
# overruns its timeout. GitHub reports that as cancelled, not failed,
# and a cancelled fuzz job has fuzzed nothing -- which is how two
# nights ran with no fuzzing at all after the fifth target landed.
.PHONY: lint-fuzz-budget
lint-fuzz-budget:
	@n=$$(grep -c '$$(FUZZ_CC) $$(FUZZ_CFLAGS) fuzz/' Makefile); \
	 t=$$(sed -n 's/.*make fuzz .*FUZZ_TIME=\([0-9]*\).*/\1/p' .github/workflows/nightly.yml); \
	 cap=$$(awk '/^  fuzz:/{f=1} f&&/timeout-minutes:/{print $$2; exit}' .github/workflows/nightly.yml); \
	 [ -n "$$t" ] && [ -n "$$cap" ] || { echo "lint-fuzz-budget: cannot read FUZZ_TIME or the job timeout"; exit 1; }; \
	 used=$$(( n * t / 60 )); \
	 if [ "$$used" -ge "$$cap" ]; then \
	   echo "lint-fuzz-budget: $$n targets x $$t s = $$used min, at or over the job's $$cap-minute cap"; \
	   exit 1; \
	 fi; \
	 echo "lint-fuzz-budget: $$n targets x $$t s = $$used min, inside the $$cap-minute cap"

# A commit body citing a hash is only useful while that hash resolves, and
# a history rewrite orphans every one it moved. Nothing warns: the text
# still reads fine, and it fails only for somebody cloning fresh. Matches
# exactly seven hex characters carrying at least one a-f, which is git's
# abbreviation here and keeps job ids and file digests out; an all-digit
# abbreviation would go unchecked, and none exist.
.PHONY: lint-commit-citations
lint-commit-citations:
	@shas=$$(mktemp); git log --format=%H > $$shas; rc=0; \
	 for c in $$(git log --format=%H); do \
	   for t in $$(git log -1 --format=%b $$c | grep -v '^Claude-Session:' \
	       | perl -ne 'while(/(?<![0-9a-fx])\b([0-9a-f]{7})\b/g){my $$h=$$1; print "$$h\n" if $$h =~ /[a-f]/}' \
	       | sort -u); do \
	     grep -q "^$$t" $$shas || { \
	       echo "lint-commit-citations: $$(git log -1 --format=%h $$c) cites $$t, which no commit reaches"; \
	       rc=1; }; \
	   done; \
	 done; rm -f $$shas; \
	 [ $$rc -eq 0 ] && echo "lint-commit-citations: every hash a commit body cites resolves"; exit $$rc

# CBMC proofs: memory safety and absence of UB per module, at the bounds
# each harness documents. The fast tier (seconds to a few minutes) gates
# every check; the SAT heavyweights run as prove-slow in CI and
# before a release. prove-all is both.
.PHONY: prove-slow prove-all
prove:
ifeq ($(CBMC),)
	$(call REQUIRE_ON_CI,cbmc)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh fast
endif

prove-slow:
ifeq ($(CBMC),)
	$(call REQUIRE_ON_CI,cbmc)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh slow
endif

prove-all:
ifeq ($(CBMC),)
	$(call REQUIRE_ON_CI,cbmc)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh all
endif

# One harness by name: make prove-one HARNESS=webpki_time. The wrapper
# proof/prove-one.sh already runs a single launch line with that line's
# flags, bounds, weight and solver, so this names it rather than
# composing a second cbmc command that could drift. tools/impact.py
# emits this form, and test/violations.py calls the script directly.
.PHONY: prove-one
prove-one:
	@[ -n "$(HARNESS)" ] || { echo "prove-one: set HARNESS=<name as proof/run.sh spells it>"; exit 1; }
	./proof/prove-one.sh $(HARNESS)

fmt:
ifneq ($(CLANG_FORMAT),)
	$(CLANG_FORMAT) -i $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(BENCH_C) $(QEMU_SMOKE_C) $(TESTH)
endif

# -DCH_CT_WIDEMUL, because the point is to measure what ships. ct.h resolves
# CH_NATIVE_WIDEMUL on any x86-64 or aarch64 development machine, so without
# this flag the t-test times `(uint64_t)a * b` -- one instruction -- while a
# part with no constant-time widening multiply runs the four 16x16 pieces.
# The path the test existed to check was the one path it never ran.
#
# What this does and does not buy: a t-test on a development machine measures
# whether the C has a data-dependent branch, not whether the target's own
# multiply is uniform. That second question belongs to the silicon and to
# ct.h's comment, not to this binary.
bin/timing: test/timing_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_CT_WIDEMUL -I. -o $@ test/timing_test.c $(SRCS)

# Constant-time check (Welch's t over interleaved input classes). Load-
# sensitive, so it is not part of check; run it on an otherwise idle box.
.PHONY: timing
timing: bin/timing
	./bin/timing

# libFuzzer harnesses for the attacker-facing parsers in fuzz/. Each target
# #includes the translation unit holding its statics, so the .c that
# defines them is left off the link line. Needs a clang with libFuzzer;
# skipped with a message otherwise. New corpus units and crash repros land
# under bin/ (gitignored); fuzz/corpus/* stays read-only seed input.
FUZZ_CC ?= $(shell command -v $(LLVM_BIN)/clang || command -v clang)
FUZZ_CFLAGS := -std=c11 -O1 -g -fsanitize=fuzzer,address -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -I.
FUZZ_TIME ?= 30
FUZZ_RECORD_LINK := record.c ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c
FUZZ_HANDSHAKE_PARSER_LINK := handshake_parser.c buf.c
FUZZ_HANDSHAKE_POST_LINK := handshake.c handshake_parser.c handshake_record.c io.c record.c keysched.c session.c buf.c ct.c \
                    sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c rsa.c rsa_mont.c handshake_message.c \
                    handshake_auth.c
FUZZ_X509_LINK := x509.c x509_der.c buf.c ct.c sha256.c rsa.c rsa_mont.c
# The TRUST=webpki walk and every file under it. -DCH_TRUST_WEBPKI is
# not optional here: ch_cfg declares the anchors, the hostname and the
# clock only there, and it widens the modulus gate to the RSA-4096 a
# public root carries.
FUZZ_WEBPKI_LINK := -DCH_TRUST_WEBPKI webpki.c webpki_cert.c webpki_ext.c webpki_name.c webpki_sigalg.c \
                    webpki_spki.c webpki_time.c x509_der.c buf.c ct.c sha256.c sha512.c \
                    sha512_compress.c p256.c p384.c p384_field.c rsa.c rsa_mont.c rsa_pkcs1.c
FUZZ_HANDSHAKE_RECORD_LINK := handshake_record.c io.c record.c buf.c ct.c sha256.c hkdf.c \
                    chacha20.c poly1305.c aead.c

.PHONY: fuzz
fuzz:
	@set -e; \
	probe='int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){(void)d;(void)n;return 0;}'; \
	tmp=$$(mktemp); \
	if ! printf '%s\n' "$$probe" | $(FUZZ_CC) -fsanitize=fuzzer,address -x c - -o "$$tmp" 2>/dev/null; then \
	  rm -f "$$tmp"; \
	  [ -n "$$CI" ] && { echo "$(FUZZ_CC): missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP fuzz: $(FUZZ_CC) lacks libFuzzer (install llvm: brew install llvm)"; \
	  exit 0; \
	fi; \
	rm -f "$$tmp"; \
	for t in record handshake_parser handshake_record handshake_post x509 webpki; do mkdir -p bin/fuzz/work_$$t; done; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_record.c  $(FUZZ_RECORD_LINK)  -o bin/fuzz/fuzz_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_parser.c $(FUZZ_HANDSHAKE_PARSER_LINK) -o bin/fuzz/fuzz_handshake_parser; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_record.c $(FUZZ_HANDSHAKE_RECORD_LINK) -o bin/fuzz/fuzz_handshake_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_post.c  $(FUZZ_HANDSHAKE_POST_LINK)  -o bin/fuzz/fuzz_handshake_post; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_x509.c    $(FUZZ_X509_LINK)    -o bin/fuzz/fuzz_x509; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_webpki.c $(FUZZ_WEBPKI_LINK) -o bin/fuzz/fuzz_webpki; \
	for t in record handshake_parser handshake_record handshake_post x509 webpki; do \
	  ./bin/fuzz/fuzz_$$t bin/fuzz/work_$$t fuzz/corpus/fuzz_$$t \
	    -artifact_prefix=bin/fuzz/ -max_total_time=$(FUZZ_TIME); \
	done

# CI range lint: only the commits under review when a base exists; on main
# (or with no origin/main) fall back to the full history.
.PHONY: lint-commits-range
lint-commits-range:
	@if git rev-parse -q --verify origin/main >/dev/null && \
	    ! git merge-base --is-ancestor HEAD origin/main; then \
	    $(COMMITLINT) --from origin/main --to HEAD; \
	else \
	    $(COMMITLINT) --from "$$(git rev-list --max-parents=0 HEAD)" --to HEAD; \
	fi

clean:
	rm -rf bin

# What the TRANSPORT=quic mode covers, read from the tree: the files and
# their line counts, the mode's text inside the CH_TRANSPORT_QUIC arms of
# files a TLS build compiles too, the mode's share of the library, how
# many declared functions have a definition, the ch_quic_ surface against
# the interface table in docs/quic.md, and the standards the headers cite
# section by section. It is a report, so it is not in `lint` and not in `check`, and
# it reaches no verdict: it exits 0 on every count it prints, and stops
# with a message only when something it reads is not there. The one
# comparison in it that is a verdict, quic.h against docs/quic.md's
# interface table, runs in `lint` under lint-quic-surface.
.PHONY: quic-footprint
quic-footprint:
	@python3 tools/quic-footprint.py
