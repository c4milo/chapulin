CC ?= cc
# -D_DEFAULT_SOURCE: glibc hides POSIX and getrandom under -std=c11 without
# it; macOS ignores it.
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE
# INV-19: -Wvla bans variable frames everywhere; the frame budget is
# enforced per library source by lint-stack, because host test mains
# legitimately keep whole vector tables in their frames.
CFLAGS += -Wvla
STACK_BUDGET := 2560
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
# measure the path that ships.
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
        pem.c x509.c x509_der.c x509_ca.c buf.c record.c keysched.c io.c handshake_message.c handshake_parser.c handshake_record.c session.c \
        handshake_auth.c handshake.c handshake_post.c tls.c softmul.c

HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h p256.h rsa.h ch_assert.h \
        pem.h x509.h x509_ca.h buf.h record.h keysched.h io.h handshake_message.h handshake_parser.h handshake_record.h cfg.h session.h handshake_auth.h handshake.h handshake_post.h \
        tls.h rand.h drbg.h sha3.h mlkem.h mlkem_poly.h
# softmul.c is excluded on purpose. It has to define __mulsi3 and
# __muldi3 -- the names the compiler emits, so they replace the runtime
# library's -- and clang-tidy rejects those as reserved identifiers that
# should have internal linkage. Both are true and neither is fixable: the
# ABI picks the names and external linkage is the whole point. Excluding
# one file keeps bugprone-reserved-identifier and misc-use-internal-linkage
# working everywhere else, which disabling them in .clang-tidy would not.
# clang-format still covers it, and so does lint-runtime-symbols.
LINT_C := $(filter-out softmul.c,$(SRCS)) drbg.c sha3.c mlkem.c mlkem_poly.c test/unit_test.c test/tls_client.c \
          test/diff_test.c test/timing_test.c test/drbg_test.c test/softmul_test.c test/rsa_test.c test/sha3_test.c \
          test/mlkem_test.c test/handshake_strict_test.c test/handshake_sequence_test.c \
          test/x509_strict_test.c $(wildcard examples/*.c)

# Test-local headers: prerequisites for every binary that includes them,
# so a header edit rebuilds the binaries it changes.
TESTH := test/test_random.h test/pem_armor.h test/pem_tests.h test/x509_ca_tests.h test/session_tests.h test/session_post_tests.h \
         test/session_cfg_tests.h test/p256_tests.h test/diff_driver.h test/diff_hash.h \
         test/diff_handshake_parser.h test/diff_p256.h test/diff_pem.h test/diff_record.h test/diff_rsa.h \
         test/diff_x25519.h test/handshake_sequence_server.h test/rfc8448_vectors.h \
         test/rfc8448_tests.h \
         test/x509_vectors.h test/x509_mutate.h test/x509_chain_tests.h test/x509_epoch.h \
         test/x509_spki.h test/diff_x509.h test/diff_x509_bounds.h test/diff_x509_chain.h \
         test/diff_x509_epoch.h test/diff_x509_mutate.h test/diff_x509_random.h \
         test/diff_x509_signed.h test/diff_sha3.h test/diff_mlkem.h test/mlkem_vectors.h

# Pinned mode verifies one signature algorithm per build: PIN=rsa
# (default, RSA-PSS up to 3072 bits) or PIN=ecdsa (P-256, -DCH_PIN_ECDSA).
# Test binaries compile both modules so both stay tested either way; the
# packaged library object carries only the selected one.
PIN ?= rsa
ifeq ($(PIN),ecdsa)
LIB_DEF := -DCH_PIN_ECDSA
LIB_SRCS := $(filter-out rsa.c rsa_mont.c,$(SRCS))
else
LIB_DEF :=
LIB_SRCS := $(filter-out p256.c,$(SRCS))
endif
# Trust mode: TRUST=raw (default) pins server keys and ships no
# certificate parser; TRUST=ca pins a CA key and includes it. One
# mode per packaged object, like PIN.
TRUST ?= raw
ifeq ($(TRUST),ca)
LIB_DEF += -DCH_TRUST_CA
# Provisioning is a public call only where its parser is linked.
PUBLIC_CA := ch_pubkey_from_pem
else
PUBLIC_CA :=
LIB_SRCS := $(filter-out pem.c x509.c x509_der.c x509_ca.c,$(LIB_SRCS))
endif
# Key exchange: KEX=x25519 (default) or KEX=pq (-DCH_KEX_PQ), the
# X25519MLKEM768 hybrid — the ML-KEM and SHA-3 modules join the
# packaged object only there. One mode per object, like PIN and TRUST.
KEX ?= x25519
ifeq ($(KEX),pq)
LIB_DEF += -DCH_KEX_PQ
LIB_SRCS += sha3.c mlkem.c mlkem_poly.c
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

# Firmware links bin/chapulin.o: one relocatable object exposing exactly
# the four public calls. Partial linking merges the modules; nmedit
# (macOS) or objcopy (everything else) localizes every other symbol, so
# the library cannot collide with application names. lib-check enforces
# the export list as part of check. Objects live under the variant that
# built them, so switching PIN, TRUST, KEX or RAND never reuses a stale
# object.
LIB_VARIANT := $(PIN)-$(TRUST)-$(KEX)-$(RAND)
LIB_OBJS := $(LIB_SRCS:%.c=bin/obj/$(LIB_VARIANT)/%.o)

# bench/device-ram.sh sizes the same modules the build packages. It asks
# here rather than keeping its own list, which is how that list fell four
# modules behind the handshake split.
.PHONY: print-lib-srcs
print-lib-srcs:
	@echo $(LIB_SRCS)
# RAND=drbg packages the generator, so ch_drbg_seed becomes part of the
# API the image calls and lib-check covers it like the other four.
PUBLIC := ch_connect ch_read ch_write ch_close $(PUBLIC_RAND) $(PUBLIC_CA)

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
# stays testable without the rest of the stack.
bin/rsa_test: test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c

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

# Parser strictness: drives the ServerHello/EE parsers directly; their
# whole dependency closure is handshake_parser.c + buf.c.
bin/handshake_strict_test: test/handshake_strict_test.c handshake_parser.c buf.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/handshake_strict_test.c handshake_parser.c buf.c

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

# The hybrid-build client: the same main under -DCH_KEX_PQ, with the
# ML-KEM and SHA-3 sources KEX=pq adds to LIB_SRCS; e2e runs it against
# servers that accept only X25519MLKEM768.
bin/tlsclient_pq: test/tls_client.c $(SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/tls_client.c $(SRCS) sha3.c mlkem.c mlkem_poly.c

bin/diff: test/diff_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/diff_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c

.PHONY: check check-slow ci lint lint-tidy lint-format lint-cppcheck lint-docs lint-invariants lint-violation-builds lint-fuzz-budget lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-shellcheck lint-bench-numbers lint-spec prove diff fmt clean
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
check: bin/unit bin/unit_ca bin/unit_pq bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa bin/tlsclient_pq bin/drbg_test bin/softmul_test bin/rsa_test bin/sha3_test bin/mlkem_test bin/handshake_strict_test bin/handshake_strict_pq bin/x509strict bin/x509strict_ecdsa lint rand-check
	# The packaged object is built once per entropy pattern, because
	# lib-check reads a different export list and a different import
	# list in each. Only the object is built twice: the examples and
	# hpp_test define ch_rand_bytes, so they are extern-pattern programs.
	# Linking one against the drbg object succeeds and produces a binary
	# that cannot run — its own hook is dead code and nothing calls
	# ch_drbg_seed, so the first draw faults on CH_ASSERT(g_seeded).
	# The extern pass therefore runs last, since bin/chapulin.o and the
	# example binaries land at fixed paths and e2e below runs them.
	$(MAKE) lib-check RAND=drbg
	$(MAKE) lib-check cxx-check examples-check RAND=extern
	./bin/unit
	./bin/unit_ca
	./bin/unit_pq
	./bin/drbg_test
	./bin/softmul_test
	./bin/rsa_test
	./bin/sha3_test
	./bin/mlkem_test
	./bin/handshake_strict_test
	./bin/handshake_strict_pq
	./bin/x509strict
	./bin/x509strict_ecdsa
	$(MAKE) wycheproof
	$(MAKE) proof-coverage

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
# legs cover.
.PHONY: check-slow
check-slow: check bin/handshake_sequence_test bin/handshake_sequence_pq bin/pemkey bin/pemkey_ecdsa
	./test/e2e.sh
	$(MAKE) diff
	./bin/handshake_sequence_test
	$(MAKE) test-invariants-fast
	$(MAKE) prove

# The ECDSA-arm differential: bin/diff compiles the RSA parser, so
# the P-256 certificate rows only meet real C in this variant. The
# nightly lane runs it; the PR lane keeps one diff build.
.PHONY: diff-ecdsa
diff-ecdsa:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff-ecdsa: lake not on PATH (install elan: https://leanprover.github.io)"
else
	cd spec && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_PIN_ECDSA -I. -o bin/diff_ecdsa test/diff_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c
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
	cd spec && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o bin/diff_pq test/diff_test.c $(SRCS) sha3.c mlkem.c mlkem_poly.c
	./bin/diff_pq
endif

# Differential oracle: the Lean spec in spec/ answers over a pipe and
# test/diff_test.c compares every C module against it on random inputs.
diff:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff: lake not on PATH (install elan: https://leanprover.github.io)"
else
	cd spec && $(LAKE) build
	$(MAKE) bin/diff
	./bin/diff
endif

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
	cd spec && $(LAKE) build
endif
	./bin/handshake_sequence_test

handshake-sequence-pq: bin/handshake_sequence_pq
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec comparison: lake not on PATH (install elan: https://leanprover.github.io)"
else
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
COVERAGE_FLOOR := 92
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
	python3 proof/coverage.py --reach

.PHONY: proof-coverage
proof-coverage:
	python3 proof/coverage.py

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
	cd spec && $(LAKE) build
	python3 test/spec_coverage.py
endif

coverage:
ifeq ($(GCOVR),)
	$(call REQUIRE_ON_CI,gcovr)
	@echo "SKIP coverage: gcovr not on PATH (pip install gcovr)"
else
	@rm -rf bin/cov bin/coverage.md && mkdir -p bin/cov/html
	@echo "| binary | PIN | result |" > bin/coverage.md
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
	  for b in unit drbg_test rsa_test handshake_strict_test x509strict_test handshake_sequence_test; do \
	    if ENUM_DEPTH=4 ./$$d/$$b > /dev/null; then \
	      echo "| $$b | $$pin | pass |" >> bin/coverage.md; \
	    else \
	      echo "| $$b | $$pin | FAIL |" >> bin/coverage.md; exit 1; \
	    fi; \
	  done; \
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
# Deliberately latest-not-pinned, unlike every other CI input: the
# suite grows by adding attack cases, and a new case failing is exactly
# the alarm we want, as early as C2SP publishes it. An upstream change
# reddening CI is signal, not flake — triage the new case first. CI
# clones fresh every run (bin/ is not cached); locally, rm -rf the
# checkout to refresh. Offline with no checkout, the target skips the
# way lint skips absent tools. Every run logs the vector commit.
WYCHEPROOF_DIR := bin/wycheproof
.PHONY: wycheproof
wycheproof:
	@if [ ! -d $(WYCHEPROOF_DIR)/.git ]; then \
	  git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) \
	    || { [ -n "$$CI" ] && { echo "wycheproof clone failed and CI must not skip a gate"; exit 1; }; \
	         echo "SKIP wycheproof: no checkout and no network"; exit 0; }; \
	fi; \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(CC) $(CFLAGS) -I. -Ibin -o bin/wycheproof_test test/wycheproof_test.c \
	  x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c buf.c ct.c && \
	./bin/wycheproof_test

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
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha3_test test/sha3_test.c sha3.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/mlkem_test test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_strict_test test/handshake_strict_test.c handshake_parser.c buf.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/x509strict_test $(X509STRICT_SRC) rsa.c rsa_mont.c
	$(CC) $(SAN_CFLAGS) -DCH_PIN_ECDSA -I. -o bin/san/x509strict_ecdsa $(X509STRICT_SRC) p256.c
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_sequence_test test/handshake_sequence_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
	@set -e; for b in unit drbg_test rsa_test sha3_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa handshake_sequence_test; do \
	  echo "== $$b (SAN -O$(O))"; ENUM_DEPTH=4 ./bin/san/$$b; done
	@if [ -d $(WYCHEPROOF_DIR)/.git ] \
	  || git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) 2>/dev/null; then \
	  python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	  $(CC) $(SAN_CFLAGS) -I. -Ibin -o bin/san/wycheproof_test test/wycheproof_test.c \
	    x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c buf.c ct.c && \
	  echo "== wycheproof_test (SAN -O$(O))" && ./bin/san/wycheproof_test; \
	else \
	  [ -n "$$CI" ] && { echo "wycheproof: clone failed and CI must not skip a gate"; exit 1; }; \
	  echo "SKIP san wycheproof: no checkout and no network"; \
	fi
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
.PHONY: cross-check
cross-check:
	@[ -n "$(CROSS)" ] || { echo "cross-check: set CROSS=<toolchain-prefix> (and RUNNER=<emulator>)"; exit 1; }
	@mkdir -p bin/cross
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/unit test/unit_test.c $(SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/drbg_test test/drbg_test.c drbg.c chacha20.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha3_test test/sha3_test.c sha3.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/mlkem_test test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_strict_test test/handshake_strict_test.c handshake_parser.c buf.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/x509strict_test $(X509STRICT_SRC) rsa.c rsa_mont.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -DCH_PIN_ECDSA -I. -o bin/cross/x509strict_ecdsa $(X509STRICT_SRC) p256.c
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_sequence_test test/handshake_sequence_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
	@if [ -d $(WYCHEPROOF_DIR)/.git ] \
	  || git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) 2>/dev/null; then \
	  python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	  $(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -Ibin -o bin/cross/wycheproof_test test/wycheproof_test.c \
	    x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c buf.c ct.c; \
	else \
	  [ -n "$$CI" ] && { echo "wycheproof: clone failed and CI must not skip a gate"; exit 1; }; \
	  echo "SKIP cross wycheproof: no checkout and no network"; \
	fi
	@set -e; cd bin/cross; for b in unit drbg_test rsa_test sha3_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa handshake_sequence_test; do \
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
lint: lint-toolchain lint-pins lint-proof-cover lint-tidy lint-format lint-cppcheck lint-commits lint-docs lint-invariants lint-stack lint-size lint-matrix lint-violation-builds lint-fuzz-budget lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-shellcheck lint-bench-numbers lint-spec

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

lint-tidy:
ifeq ($(CLANG_TIDY),)
	$(call REQUIRE,clang-tidy,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	$(CLANG_TIDY) --quiet $(LINT_C) -- -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -I.
endif

lint-format:
ifeq ($(CLANG_FORMAT),)
	$(call REQUIRE,clang-format,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(TESTH)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	$(call REQUIRE,cppcheck,build it at the CPPCHECK_VERSION pinned in .github/workflows/check.yml)
else
	# constParameterCallback: I/O callback signatures are fixed by the
	# ch_cfg contract in tls.h; const-ing an implementation's void *io
	# would need function-pointer casts, which is worse.
	# cfg.h demands a declared entropy pattern, so cppcheck needs one to
	# get past the preprocessor. Passing -D alone would limit it to that
	# single configuration; --force keeps it exploring CH_PIN_ECDSA,
	# CH_TRUST_CA and CH_KEX_PQ the way it did before the declaration
	# existed. Measured at 3.1 s without and 10.4 s with, over 42 files.
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --inline-suppr --suppress=missingIncludeSystem \
	  --suppress=constParameterCallback $(HOST_RAND_DEF) --force \
	  --error-exitcode=1 --quiet $(LINT_C)
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

# The examples build and are linted, but never run: e2e covers live
# behaviour. Building them is what stops the API drifting out from
# under the one place a reader learns it from. ca_client.c needs the
# CA-trust library, so it builds only in that mode.
# The examples build against the packaged library, the way a consumer
# links them, and e2e.sh then runs them against real servers. Building
# alone catches a changed signature; only running catches a changed
# meaning, and the reviewers found exactly that class of bug in the
# first drafts.
bin/example_psk: examples/psk_client.c $(LIB_OBJ)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ examples/psk_client.c $(LIB_OBJ)

bin/example_pinned: examples/pinned_client.c $(LIB_OBJ)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ examples/pinned_client.c $(LIB_OBJ)

# The CA example needs the CA-trust library, so it links its own copy of
# the sources rather than the packaged raw-pin object.
bin/example_ca: examples/ca_client.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ examples/ca_client.c $(SRCS)

.PHONY: examples-check
examples-check: bin/example_psk bin/example_pinned bin/example_ca
	@echo "examples-check: the PSK and pinned examples link the packaged library; ca_client links the CA-trust sources"


# lint-invariants checks that the code does not violate an invariant.
# This checks that a test notices when it does: each Violation field in
# docs/invariants.md becomes an edit, and some test must object. Too
# slow for check (each one rebuilds and reruns a target), so it runs
# nightly.
.PHONY: test-invariants
# The violation runner requires each target to PASS on unedited source
# before it trusts the target's verdict on an edit, so every prerequisite
# a violation names must build here. bin/diff execs the Lean oracle at
# run time and nothing else in this target's lane builds it, so the
# recipe runs the lake step itself; the epoch violation drives e2e,
# which needs the CA clients.
# The fast tier: violations backed by the second-scale binaries (unit,
# the strictness parsers, rsa_test), so the PR lane runs them. The diff,
# handshake_sequence and e2e-backed violations stay in the nightly full run — each of
# those targets is slow enough that a baseline plus a mutation pass costs
# real minutes.
.PHONY: test-invariants-fast
test-invariants-fast: bin/unit bin/unit_ca bin/x509strict bin/x509strict_ecdsa bin/rsa_test bin/drbg_test bin/handshake_strict_test
	python3 test/violations.py --tier=fast

# The whole set, fast tier plus the handshake_sequence_test and e2e-backed
# violations that cost minutes each. Nightly.
test-invariants: bin/unit bin/diff bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP test-invariants: lake not on PATH (install elan: https://leanprover.github.io)"
else
	# The examples link the packaged object, and RAND has no default, so
	# they cannot be prerequisites of a target invoked without one. check
	# builds them through the same recursion.
	$(MAKE) RAND=extern bin/example_psk bin/example_pinned bin/example_ca
	cd spec && $(LAKE) build
	python3 test/violations.py
endif

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

# A violation whose target is a script must name every binary that script
# runs: a script runs no make, so the 'builds' line is the only thing that
# puts them on disk. A name missing there fails quietly, since the baseline
# runs a binary nobody built and that invariant loses its verdict.
.PHONY: lint-violation-builds
lint-violation-builds:
	@python3 test/violations.py --lint-builds

# A core without the M extension has no hardware multiply, so every `*` becomes
# a libgcc call, and those routines branch on their operands
# (https://github.com/c4milo/chapulin/issues/53). That is a variable-time
# sequence reached from secret data, which INV-23's ban on / and % cannot see:
# it bans source-level division, and this is the compiler emitting a routine
# for multiplication.
#
# The list is what rv32ic pulls today, not what is acceptable. It exists so a
# NEW compiler-runtime dependency fails here rather than in a review, and it
# shrinks to empty when https://github.com/c4milo/chapulin/issues/53 is
# resolved. clang carries the riscv32 target, so this needs no cross toolchain.
# The sources that compile freestanding, which is every module that multiplies
# a secret. The rest reach for <string.h>, and a bare-metal riscv32 clang has
# no libc headers; adding a shim to check modules that do no secret arithmetic
# would buy nothing.
RV_SRCS := ct.c sha256.c chacha20.c poly1305.c aead.c x25519.c x509_der.c record.c \
           keysched.c io.c handshake_message.c session.c sha3.c mlkem_poly.c softmul.c
# What is left after softmul.c supplies the multiplies. sha3's division is `%
# 5` on Keccak's loop counters, a public index, so it is a performance matter
# rather than a leak -- https://github.com/c4milo/chapulin/issues/53 separates
# the two.
RV_ALLOWED := __udivsi3

# The Cortex-M3 has two multiply opcodes: mul is constant-time, umull is not --
# it returns sooner when both operands are below 65536, and has undocumented
# early exits on zero and powers of two. The 32->64 one has been used to
# extract Curve25519 keys. So a product wider than 32 bits reached from a
# secret is a leak on that part, whatever the source says
# (https://github.com/c4milo/chapulin/issues/53). 64-bit addition is fine: it
# is two 32-bit adds.
#
# Every module that multiplies a secret is at zero: ct_widemul and
# ct_mulsmall in ct.h build a wide product out of 16x16 pieces, and the
# M3's 32->32 multiply is constant-time. The one left is sha3's `% 5` over
# Keccak's public loop counters, which the compiler emits as a
# multiply-high. Writing it as conditional subtraction does not help --
# the optimiser recognises the loop and puts the modulo back -- and no
# secret is divided, so it is recorded rather than fought.
#
# Going over a ceiling fails. Coming in under one only prints, because the
# single non-zero entry is sha3's modulo over public counters, and whether a
# given compiler build lowers it to a multiply-high is not a security
# property. The entries that matter are zero, and zero cannot be undershot,
# so every secret-touching module is still held exactly.
#
# p256.c and rsa.c are absent because they multiply nothing secret. The
# client verifies signatures and never makes them: p256_ecdsa_verify and
# rsa_pss_verify read a server or CA public key, a transcript hash and a
# signature, all of which the peer already sent in the clear. There is no
# signing entry point in this library to add one to.
# Both targets are checked, not just the M3. mips32r2 is the reference
# part, and a comment claiming the decomposition runs there proves nothing
# on its own -- a compiler that folded the 16x16 pieces back into a mult
# would leave the claim standing and the leak restored. Each spec is
# name:triple:cpu-flag:comma-separated opcodes.
WIDEMUL_SPECS := \
  m3:thumbv7m-none-eabi:-mcpu=cortex-m3:umull,smull,umlal,smlal \
  mips32r2:mips-linux-musl:-march=mips32r2:mult,multu,madd,maddu \
  rv32imac:riscv32-unknown-elf:-march=rv32imac:mulh,mulhu,mulhsu
WIDEMUL_CEILING := poly1305.c:0 mlkem_poly.c:0 x25519.c:0 sha3.c:1
.PHONY: lint-wide-multiply
lint-wide-multiply:
ifeq ($(CLANG_RV),)
	$(call REQUIRE,clang,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	@rc=0; for spec in $(WIDEMUL_SPECS); do \
	  arch=$${spec%%:*}; rest=$${spec#*:}; \
	  triple=$${rest%%:*}; rest=$${rest#*:}; \
	  cpu=$${rest%%:*}; ops=$$(echo "$${rest#*:}" | tr ',' '|'); \
	  for e in $(WIDEMUL_CEILING); do \
	    f=$${e%%:*}; cap=$${e##*:}; \
	    err=$$(mktemp); \
	    asm=$$($(CLANG_RV) -target $$triple $$cpu -Os -std=c11 -ffreestanding -nostdlibinc \
	        -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ -I. -S $$f -o - 2>"$$err") || { \
	      echo "lint-wide-multiply: $$f does not build for $$arch — a count of zero from a failed compile is not a measurement"; \
	      sed -n '1p' "$$err" | sed 's/^/lint-wide-multiply:   /'; \
	      rm -f "$$err"; rc=1; continue; }; \
	    rm -f "$$err"; \
	    [ -n "$$asm" ] || { \
	      echo "lint-wide-multiply: $$f produced no assembly for $$arch"; rc=1; continue; }; \
	    n=$$(printf '%s' "$$asm" | grep -cE "\\b($$ops)\\b"); \
	    if [ "$$n" -gt "$$cap" ]; then \
	      echo "lint-wide-multiply: $$f emits $$n wide multiplies on $$arch, ceiling is $$cap (see https://github.com/c4milo/chapulin/issues/53)"; rc=1; \
	    elif [ "$$n" -lt "$$cap" ]; then \
	      echo "lint-wide-multiply: $$f is down to $$n from $$cap on $$arch — lower the ceiling"; \
	    fi; \
	  done; \
	done; \
	names=$$(for spec in $(WIDEMUL_SPECS); do printf "%s " "$${spec%%:*}"; done); \
	[ $$rc -eq 0 ] && echo "lint-wide-multiply: every module at its recorded ceiling on $$names"; exit $$rc
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

.PHONY: lint-runtime-symbols
lint-runtime-symbols:
ifeq ($(CLANG_RV),)
	$(call REQUIRE,clang,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else ifeq ($(LLVM_NM),)
	$(call REQUIRE,llvm-nm,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	@d=$$(mktemp -d); rc=0; \
	 for f in $(RV_SRCS); do \
	   $(CLANG_RV) -target riscv32-unknown-elf -march=rv32ic -mabi=ilp32 -Os -std=c11 \
	     -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ -I. -c $$f -o $$d/$${f%.c}.o 2>/dev/null \
	     || { echo "lint-runtime-symbols: $$f does not build for rv32ic"; rc=1; }; \
	 done; \
	 $(LLVM_NM) -u $$d/*.o 2>/dev/null | grep -oE '__[a-z0-9]+' | sort -u > $$d/.und; \
	 $(LLVM_NM) --defined-only $$d/*.o 2>/dev/null | awk '{print $$3}' \
	   | grep -E '^__[a-z0-9]+$$' | sort -u > $$d/.def; \
	 got=$$(comm -23 $$d/.und $$d/.def); \
	 [ -s $$d/.und ] || { echo "lint-runtime-symbols: read no symbols; llvm-nm or the build failed"; rc=1; }; \
	 for sym in $$got; do \
	   echo "$(RV_ALLOWED)" | tr ' ' '\n' | grep -qx "$$sym" \
	     || { echo "lint-runtime-symbols: $$sym is a new compiler-runtime dependency (see https://github.com/c4milo/chapulin/issues/53)"; rc=1; }; \
	 done; \
	 rm -rf $$d; \
	 [ $$rc -eq 0 ] && echo "lint-runtime-symbols: rv32ic pulls only the runtime calls https://github.com/c4milo/chapulin/issues/53 records"; exit $$rc
endif

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

fmt:
ifneq ($(CLANG_FORMAT),)
	$(CLANG_FORMAT) -i $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(TESTH)
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
	for t in record handshake_parser handshake_record handshake_post x509; do mkdir -p bin/fuzz/work_$$t; done; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_record.c  $(FUZZ_RECORD_LINK)  -o bin/fuzz/fuzz_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_parser.c $(FUZZ_HANDSHAKE_PARSER_LINK) -o bin/fuzz/fuzz_handshake_parser; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_record.c $(FUZZ_HANDSHAKE_RECORD_LINK) -o bin/fuzz/fuzz_handshake_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_post.c  $(FUZZ_HANDSHAKE_POST_LINK)  -o bin/fuzz/fuzz_handshake_post; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_x509.c    $(FUZZ_X509_LINK)    -o bin/fuzz/fuzz_x509; \
	for t in record handshake_parser handshake_record handshake_post x509; do \
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
