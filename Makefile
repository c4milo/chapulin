CC ?= cc
# -D_DEFAULT_SOURCE: glibc hides POSIX and getrandom under -std=c11 without
# it; macOS ignores it.
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE
# INV-19: -Wvla bans variable frames everywhere; the frame budget is
# enforced per library source by lint-stack, because host test mains
# legitimately keep whole vector tables in their frames.
CFLAGS += -Wvla
STACK_BUDGET := 2560
# A TRUST=webpki object verifies RSA-4096, so rsa_vp1's word arrays are
# 128 words wide instead of 96: measured 3,168 bytes (clang 23 -O2,
# arm64) and 3,128 (Arm GNU gcc 16.2 -O2, Cortex-M3), against 2,400 and
# 2,360 at the device bound. The mode is host-side (docs/webpki.md), so
# its ceiling is 4 kB rather than a device's 2.5 kB; it still catches a
# new buffer. The hybrid ceiling below raises it further, because the
# same object carries ML-KEM in every build.
ifeq ($(TRUST),webpki)
STACK_BUDGET := 4096
endif
# A KEX=pq raw or ca client builds its hello around ML-KEM's 2,400-byte
# decapsulation key, which hsf_build_client_hello holds while it writes
# the encapsulation key into the share: measured 2,640 bytes (clang 23
# -O2, arm64). 3 kB covers it and still catches a new buffer.
ifeq ($(KEX),pq)
STACK_BUDGET := 3072
endif
# ML-KEM's own sources get their own ceiling, set by ML-KEM's working
# memory rather than chapulin's plumbing: K-PKE encrypt holds three
# polynomial vectors and two polynomials, 5,632 bytes of coefficients
# before locals (measured 5,744 with gcc 13.3 -O2, and 6,224 with Apple
# clang 21 and clang 23.1.1 -O2 on arm64). 6.5 kB leaves room for
# compiler variation; 6 kB did not hold clang. The ceiling applies to
# KEX_HYBRID_SRCS alone, so every other file in an object that carries
# ML-KEM (KEX=pq, every TRUST=webpki object since docs/decisions.md 53,
# and every server role since docs/decisions.md 54) keeps the ceiling
# above and a new buffer there still fails. See
# docs/invariants.md INV-19 and docs/performance.md's memory table.
STACK_BUDGET_KEX_HYBRID := 6656
# mlkem_avx2.c compiles mlkem.c's text once more, so it takes the same
# ceiling: gcc 13.3 -O2 on x86-64 gives its K-PKE encrypt and
# decapsulation the frames mlkem.c's take, 5,760 and 5,504 bytes. Its row
# sampler holds the row's three entries, so mlk_matvec_row's frame is
# 2,656 bytes where mlkem.c's is 1,120 (docs/decisions.md 107).
STACK_KEX_HYBRID_COPIES = $(if $(filter mlkem.c,$(KEX_HYBRID_SRCS)),mlkem_avx2.c)
# rsa_sign64.c, the RSA signer a host object runs on 64-bit words, gets
# its own ceiling too, set by what a CRT signature holds at once.
# rsa_sign64_sp1 holds a modulus record for each prime, the message, the
# two halves, the recombined signature and the candidate it checks:
# measured 4,368 bytes at the 384-byte bound and 5,776 at the 512-byte one
# with Apple clang 21 on arm64, and 4,544 and 6,016 with gcc 13.3 on
# x86-64, all at -O2. rsa_sign64_power holds a table of sixteen powers,
# each as long as a prime: 3,408 and 4,496, and 3,328 and 4,416. Only a
# host object holds the file, and docs/decisions.md 95 says why the
# window is sixteen entries. The ceiling applies to that file alone.
STACK_BUDGET_RSA_SIGN64 := 6656
# p256_wide_wipe.c, which only a host object holds, gets its own ceiling
# too: its frame is the array it wipes after each wide P-256 call, and the
# array must reach as deep as the deepest of them. p256_wide_mul writes
# 2,560 bytes below its caller under gcc 13.3 for x86-64 on the 128-bit
# sums, so the array is 3,072 bytes (p256_wide_wipe.h, docs/decisions.md
# 114).
STACK_BUDGET_P256_WIDE_WIPE := 3584

# cfg.h makes the entropy pattern a declared build choice with no
# default, so every translation unit that sees cfg.h must say which
# pattern its image uses. Every host binary built here supplies its own
# ch_rand_bytes — test/test_random.h for the test mains, an OS-entropy
# shim in the examples, a stub in the fuzz and proof harnesses that
# reach randomness at all — so they declare it once, here. Three kinds of
# build filter it back out: the packaged object declares through RAND
# below, every build of test/drbg_test.c links the reference generator
# instead of supplying a hook, so it declares CH_RAND_DRBG, the define
# drbg.h declares ch_drbg_seed under, and the RAND=session builds of the
# loop tests hand each session a source of its own (SESSION_CFLAGS).
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
# The flags of the RAND=session builds of the loop tests, which hand each
# session a source of its own (test/rand_session.h) in place of the host's
# pattern.
SESSION_CFLAGS = $(filter-out $(HOST_RAND_DEF),$(CFLAGS)) -DCH_RAND_SESSION
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
# clang-tidy reads each translation unit on its own, so lint-tidy runs
# one process per file, LINT_JOBS at a time. The order and the count
# change the wall time and nothing else. Each process prints its output
# in one piece when it ends, so two files' findings never interleave.
# Each pass in lint-tidy writes its files and flags as one line of
# TIDY_PASSES, and one tools/tidy-each.py run then checks every pass's
# files from one pool. It skips a file that passed before on the same
# inputs: its key covers the file and every header it includes under the
# pass's flags, the flags, the .clang-tidy files and clang-tidy's
# version, and CLANG_RV lists the includes. The script says what the key
# holds.
LINT_JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
# The files a stamp names when the check it guards reads the Makefile's
# variables or recipes: the Makefile and the two files it includes
# (tools/stamp.py).
STAMP_MAKEFILES := --file Makefile --file tools/toolchain.env --file test/platforms.mk
# The SHA-256 command the recipes that key on content pipe through.
# Linux and recent macOS releases ship sha256sum; older macOS releases
# ship only shasum.
SHA256 := $(if $(shell command -v sha256sum),sha256sum,shasum -a 256)
# $(call TIDY_EACH,files,compiler flags). One lint-tidy runs at a time in
# a tree: TIDY_PASSES is one fixed path.
TIDY_PASSES := bin/tidy-passes.txt
TIDY_EACH = printf '%s\n' '$(strip $(1)) -- $(strip $(2))' >> $(TIDY_PASSES)
CBMC ?= $(shell command -v cbmc)
CXX ?= c++
LAKE ?= $(shell command -v lake || command -v $(HOME)/.elan/bin/lake)
# The Zig build (build.zig) and the localizer it runs; lint-zig-build and
# lint-toolchain read it. CI installs the pinned release on PATH through
# .github/actions/install-zig.
ZIG ?= $(shell command -v zig)

# On CI a missing tool must fail its gate, not skip it: a workflow edit
# that drops an install step would otherwise disable a check silently.
# Locally the skip stays a convenience. Usage: $(call REQUIRE_ON_CI,name)
REQUIRE_ON_CI = @[ -z "$$CI" ] || { echo "$(1): missing on CI; the gate must not skip"; exit 1; }

# spec/ depends on Mathlib (spec/lean/lakefile.toml), and lake compiles from
# source any dependency whose compiled files it does not find. Mathlib
# takes hours to compile, so every `lake build` below first checks for
# the file `lake exe cache get` downloads and names that command when
# the file is missing. CI runs the command in
# .github/actions/fetch-mathlib. Usage: $(call REQUIRE_MATHLIB,name)
MATHLIB_OLEAN := spec/lean/.lake/packages/mathlib/.lake/build/lib/lean/Mathlib.olean
REQUIRE_MATHLIB = @[ -f $(MATHLIB_OLEAN) ] || { echo "$(1): $(MATHLIB_OLEAN) is missing, and lake would compile Mathlib from source; run 'cd spec/lean && lake exe cache get' once (spec/lean/CONTRACT.md)"; exit 1; }

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
# A lint can run without lint-toolchain: a violation's catch script runs
# one lint alone. So a lint that runs a pinned checker checks the version
# itself, first, before it reads a stamp or runs the checker. Another
# version's verdict does not count: clang-tidy 18, for one, rejects
# .clang-tidy, runs none of its checks and exits 0, and another clang's
# code generation moves lint-wide-multiply's recorded counts.
# test/pinned-checkers.sh checks that each such lint fails on another
# version.
# Usage: $(call REQUIRE_PINNED,lint,checker,ERE its --version matches,the pin)
REQUIRE_PINNED = @"$(2)" --version 2>/dev/null | grep -qE '$(3)' || { echo "$(1): $(2) is $$("$(2)" --version 2>/dev/null | head -1), and the pin is $(4) (tools/toolchain.env)"; exit 1; }

SHELLCHECK ?= shellcheck

# Every shell script the repo ships, asked of git rather than listed here:
# a hand-kept list is what let bench/device-ram.sh fall four modules behind
# the build.
# Quiet on stderr because this runs on every make invocation, a build
# included, and a tree exported without .git -- a release tarball -- would
# otherwise print git's "not a repository" before any compile. An empty
# result is not treated as "nothing to check": lint-shellcheck refuses it,
# so a checker that cannot see its inputs reports no verdict rather than
# success.
SH_SRCS := $(shell git ls-files '*.sh' '.githooks/*' 2>/dev/null)

SRCS := ct.c ct_wipe.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c rsa.c rsa_mont.c \
        pem.c x509.c x509_der.c x509_ca.c webpki_time.c webpki_name.c webpki_spki.c webpki_ext.c buf.c record.c keysched.c io.c handshake_message.c handshake_parser.c handshake_parser_ee.c handshake_record.c session.c \
        handshake_auth.c handshake_flight.c handshake.c handshake_post.c tls.c tls_write.c softmul.c build.c

HDRS := ct.h sha256.h hkdf.h chacha20.h chacha20_vector.h chacha20_avx2.h poly1305.h poly1305_vector.h poly1305_avx2.h poly1305_scalar.h aead.h x25519.h x25519_wide.h p256.h rsa.h rsa_mont64.h ch_assert.h \
        pem.h x509.h x509_der.h x509_ca.h webpki.h webpki_cfg.h webpki_pin.h webpki_ticket.h buf.h record.h keysched.h io.h handshake_message.h handshake_parser.h handshake_record.h cfg.h session.h handshake_auth.h handshake.h handshake_post.h \
        tls.h rand.h rand_draw.h drbg.h sha3.h sha512.h sha512_compress.h p384.h p384_field.h p256_field.h p256_scalar.h p256_point.h p256_sign.h p256_ecdh.h rsa_pkcs1.h rsa_sign.h rsa_sign64.h mlkem.h mlkem_poly.h mlkem_vector.h mlkem_lanes.h mlkem_zetas.h mlkem_avx2.h keccak_avx2.h keccak_round_constants.h \
        p256_wide_word.h p256_wide_field.h p256_wide_scalar.h p256_wide_inverse.h p256_wide_point.h \
        p256_wide_mul.h p256_wide_table.h p256_wide_wipe.h p256_wide_verify.h p256_wide_verify_point.h \
        p384_wide_field.h p384_wide_point.h p384_wide_verify.h \
        handshake_flight.h handshake_groups.h quic.h quic_cfg.h quic_session.h quic_version.h quic_config.h quic_initial.h quic_keys.h quic_packet.h quic_retry.h quic_step.h quic_fail.h quic_token.h aes.h aes_block.h aes_public_key.h aes_traffic_key.h aes_schedule.h gcm.h ghash_hw.h ghash_vector.h gcm_hw.h gcm_vaes.h \
        srv_cfg.h srv.h srv_parser.h srv_parser_ext.h srv_message.h srv_cookie.h srv_ticket.h srv_auth.h srv_out.h srv_flight.h srv_resume.h srv_handshake.h srv_quic.h srv_tcp_nonblocking.h srv_kex.h keylog.h \
        tcp_nonblocking.h tcp_nonblocking_frame.h tcp_nonblocking_step.h build.h suite.h transcript.h ticket.h \
        alert.h widemul.h widemul_native.h cpu_cfg.h cpu.h hash_hw.h

# The wide P-256 files and the table of multiples of G the base
# multiplication reads, which a host object holds beside p256_field.c,
# p256_scalar.c and p256_point.c (docs/decisions.md 94): the field and the
# scalar arithmetic on four 64-bit words and the inverse both run
# (docs/decisions.md 115), the points and the two scalar multiplications
# over them, and the wipe of the stack their calls used; and the verifier
# with its own variable-time points (docs/decisions.md 96 and 104). They
# are named once, here, for the object, for the test binaries that link a
# host object's P-256 and for the lints.
P256_WIDE_SRCS := p256_wide_field.c p256_wide_scalar.c p256_wide_inverse.c p256_wide_point.c \
                  p256_wide_mul.c p256_wide_table.c p256_wide_wipe.c p256_wide_verify.c \
                  p256_wide_verify_point.c

# P-384 on six 64-bit words: the field, the points and the verifier over
# them, which a host object holds in place of p384_field.c and of p384.c's
# 32-bit arm (docs/decisions.md 97). They are named once, here, for the
# object, for the test binaries that link a host object's P-384 and for
# the lints.
P384_WIDE_SRCS := p384_wide_field.c p384_wide_point.c p384_wide_verify.c

# The TRANSPORT=quic-nonblocking mode's own sources, named here rather than matched
# by a pattern, for the reason WEBPKI_SRCS is named: an auditor reads
# the object's contents off this line, and an untracked scratch file
# never enters the object. They sit outside SRCS because only one
# transport compiles them; the TRANSPORT axis below names them as its
# add, the way TRUST=webpki names WEBPKI_SRCS.
#
# Every one of them is implemented. `make quic-footprint` reads the tree
# and prints what each file declares and defines, and counts the
# CH_QUIC_STUB marker, which matches nothing now: the two build checks
# that read that marker retired with the last stub (docs/quic.md, "The
# stubs and the marker").
#
# AES implementation. A device object takes the Makefile AES variable:
# AES=soft (default) is the FIPS 197 cipher in C with a 256-byte S-box
# table, and AES=extern leaves ch_aes_block to the image the way
# RAND=extern leaves ch_rand_bytes. One implementation per device object:
# both define the same entries, so the two in one object would not link,
# and AES_IMPL names the one that joins QUIC_SRCS for the portable test
# binaries and AES_ADD below for the object.
#
# A host object (HOST_TARGET below, docs/decisions.md 89) takes no AES
# value. It holds AES_HW_SRCS, the AES instructions and the carry-less
# multiply compiled with no instruction flag: each function in them turns
# the instructions on for itself through the compiler's target attribute,
# so the rest of the object runs on any arm64 or x86-64 CPU. A QUIC host
# object also holds quic_aes_soft.c under names of its own, for the public
# keys of a session whose caller did not set CH_CPU_CONSTANT_TIME_AES; a
# TCP host object has no public key and holds none. The caller's bit
# picks per session (ch_cfg.cpu, cpu_cfg.h). AES=hw and AES=runtime chose
# the instructions when the object was built and are gone.
#
# A TRANSPORT=quic-nonblocking object compiles AES for QUIC Initial
# packets and the Retry tag, and a SUITE=aesgcm object compiles it for the
# two AES-GCM suites over every transport (INV-26). A TCP build without
# the suite compiles no AES, which is why AES_ADD reads the transport and
# the suite: LIB_VARIANT carries AES so two device objects never share a
# path, and aes_block.h refuses a host object's define beside
# -DCH_AES_EXTERN.
#
# Nothing probes a CPU and nothing asks an operating system. aes_hw.c
# states why: the caller probes and states what it found.
# Cipher suite: SUITE=chacha (default) offers TLS_CHACHA20_POLY1305_SHA256
# alone, SUITE=aesgcm offers TLS_AES_128_GCM_SHA256 and
# TLS_AES_256_GCM_SHA384 beside it, over every transport, and meets RFC
# 9846 section 9.1 (docs/decisions.md 58). The second one is a compile
# error unless the build is a host object, whose caller states the AES
# instructions' timing in ch_cfg.cpu, or takes AES=extern and defines
# CH_AES_EXTERN_CONSTANT_TIME, which ct.h checks and INV-26 explains: the
# AES=soft S-box is indexed with the key, and CH_AES_EXTERN_CONSTANT_TIME
# is the build's statement that the peripheral behind ch_aes_block runs
# in constant time (docs/decisions.md 68). The Makefile does not define
# it, because it is a claim about hardware that only the firmware author
# can make.
SUITE ?= chacha
ifeq ($(SUITE),aesgcm)
SUITE_DEF := -DCH_SUITE_AES_GCM
else ifeq ($(SUITE),chacha)
SUITE_DEF :=
else
$(error SUITE=$(SUITE) is not a cipher suite; use SUITE=chacha or SUITE=aesgcm)
endif

# The AES instructions are four sources rather than one: aes_hw.c runs the
# block cipher on the AES instructions, ghash_hw.c runs GHASH's multiply
# on the carry-less multiply instruction, gcm_hw.c runs counter mode over
# whole blocks and the seal's counter mode and GHASH in one loop on both,
# and gcm_vaes.c holds the 256-bit kernels beside gcm_hw.c on x86-64. gcm.c
# calls the middle two in place of its own portable multiply and
# one-block counter loop for a schedule on the instructions. AES_HW_SRCS
# names them once, for AES_ADD below and for every host test binary.
AES_HW_SRCS := aes_hw.c ghash_hw.c gcm_hw.c gcm_vaes.c
# AES-256 outside a suite build, for the test binaries and proof harnesses
# that hold it to FIPS 197 and SP 800-38D on every AES value: on AES=soft
# it compiles the software reference quic_aes_soft.c keeps for that, and
# in a host object the instructions a suite build runs (aes.h). No library
# object takes it: LIB_DEF never names it, lint-trust-separation fails a
# packaged object whose defines carry it, and quic_aes_soft.c holds no
# AES-256 beside the instructions, so the software AES-256 never meets a
# traffic key.
AES_256_TEST_DEF := -DCH_AES_256_TEST
AES ?= soft
ifneq ($(filter hw runtime,$(AES)),)
$(error AES=$(AES) is gone: on arm64 and x86-64 a TRUST=webpki client, ROLE=server and ROLE=both hold the AES instructions and each session picks them from ch_cfg.cpu (docs/decisions.md 89); a device object takes AES=soft or AES=extern)
else ifeq ($(AES),soft)
AES_DEF :=
AES_IMPL := quic_aes_soft.c
else ifeq ($(AES),extern)
AES_DEF := -DCH_AES_EXTERN
AES_IMPL := aes_extern.c
else
$(error AES=$(AES) is not an AES implementation; use AES=soft or AES=extern)
endif
QUIC_SRCS := aes.c $(AES_IMPL) gcm.c quic_keys.c quic_packet.c quic_initial.c \
             quic_retry.c quic_config.c quic_fail.c quic_step.c quic.c
# What SUITE=aesgcm adds to an object: the key expansion and the AEAD,
# which record.c and quic_packet.c call under -DCH_SUITE_AES_GCM, and
# SHA-512's core, which TLS_AES_256_GCM_SHA384's key schedule runs, with
# the AES implementation in AES_ADD below. Without them the object
# imported functions no source in it defined, and lib-check said so. A
# QUIC object already compiles the AES sources through QUIC_SRCS and a
# TRUST=webpki one the SHA-512 core through WEBPKI_SRCS, so LIB_SRCS
# takes out of this list what another axis added.
SUITE_ADD := $(if $(SUITE_DEF),aes.c gcm.c sha512.c sha512_compress.c)
# The implementation sources, named whichever ones this build picks, so a
# check that reads every AES choice does not re-derive the list.
AES_IMPL_SRCS := quic_aes_soft.c $(AES_HW_SRCS) aes_extern.c
# The host test (docs/decisions.md 89). A host object compiles each fast
# path beside the portable code, and each session picks among them at
# init from ch_cfg.cpu, the caller's description of its CPU (cpu_cfg.h). A
# target is a host target when $(CC) passes three probes: it targets arm64
# or x86-64, it targets NEON or SSE2 on a little-endian core, and it has
# unsigned __int128. Every LP64 compiler for the two architectures passes
# all three. A host build passes one define, -DCH_CPU_RUNTIME, and the
# sources choose on it and never on the architecture macros, so every
# proof harness, bench/sram.sh, the test binaries of the portable code and
# a firmware tree's own build compile the code they compiled before.
# CPU_RUNTIME_DEF below gives the define to the products that build a
# host object, and the host test binaries are named only where this
# compiler passes.
HOST_TARGET := $(shell macros=$$($(CC) -dM -E -x c /dev/null 2>/dev/null); \
  printf '%s\n' "$$macros" | grep -qwE '__aarch64__|__x86_64__' && \
  printf '%s\n' "$$macros" | grep -qwE '__ARM_NEON|__SSE2__' && \
  printf '%s\n' "$$macros" | grep -qw '__BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__' && \
  printf '%s\n' "$$macros" | grep -qw '__SIZEOF_INT128__' && echo yes)
# The defines of a host test binary that carries the AES-GCM suites: the
# suite, and the host object's define, which ct.h requires beside it.
HOST_SUITE_DEF := -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME
# What lint-quic-partition needs to preprocess the files that guard
# their body on a second macro. Without it, a file guarded on the
# transport or the suite reads as QUIC-only, and a file guarded on the
# transport and an AES choice reads as empty in both runs. Same shape as
# WIDEMUL_DEFINES, with commas between a file's flags.
COMMA := ,
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
# The defines a SUITE=aesgcm AES=extern build compiles with: it needs no
# flag to turn instructions on, and it states the peripheral's timing.
# The entries join a file's defines with commas and no space, so a space
# does not split an entry into two words.
AES_EXTERN_SUITE_DEF := -DCH_SUITE_AES_GCM -DCH_AES_EXTERN -DCH_AES_EXTERN_CONSTANT_TIME
AES_EXTERN_SUITE_ENTRY := $(subst $(SPACE),$(COMMA),$(AES_EXTERN_SUITE_DEF))
# The defines a SUITE=aesgcm host object compiles with, where this
# compiler passes the host test, and the AES=extern suite build's where
# it does not, because cpu_cfg.h refuses -DCH_CPU_RUNTIME there.
AES_SUITE_ENTRY := $(if $(HOST_TARGET),-DCH_SUITE_AES_GCM$(COMMA)-DCH_CPU_RUNTIME,$(AES_EXTERN_SUITE_ENTRY))
# The AES and GCM sources a SUITE=aesgcm build compiles carry no quic
# prefix because they are not the mode's: that build compiles them over
# every transport, for TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384.
# Judged with that build's defines, both runs read the text the suite
# compiles, so each file reads as shared rather than QUIC-only, which is
# what it is. aes.c and aes.h then still gain their QUIC arms under the
# transport define, which is why QUIC_CONDITIONAL names them.
# aes_extern.c is one of them: a SUITE=aesgcm AES=extern build compiles
# it over every transport, so it is judged with that build's defines.
# quic_aes_soft.c keeps the prefix and gets no entry: only a QUIC build
# compiles it, a TCP suite build refuses it (INV-26), and its body is what
# a build with neither the suite define nor the host object's compiles.
# quic_token.c and quic_token.h guard their body on CH_ROLE_SERVER as well
# as the transport, because only a server mints or checks a Retry token,
# so without the role define both runs would read nothing.
# x509_ca.h declares ch_pubkey_from_pem, whose name carries the
# transport, only under CH_TRUST_CA, so without that define both runs
# would read the same text.
QUIC_EXTRA_DEFINES := aes.c:$(AES_SUITE_ENTRY) aes.h:$(AES_SUITE_ENTRY) \
                      aes_block.h:$(AES_SUITE_ENTRY) aes_public_key.h:$(AES_SUITE_ENTRY) \
                      aes_traffic_key.h:$(AES_SUITE_ENTRY) aes_schedule.h:$(AES_SUITE_ENTRY) \
                      aes_hw.c:$(AES_SUITE_ENTRY) gcm.c:$(AES_SUITE_ENTRY) gcm.h:$(AES_SUITE_ENTRY) \
                      ghash_hw.c:$(AES_SUITE_ENTRY) ghash_hw.h:$(AES_SUITE_ENTRY) \
                      ghash_vector.h:$(AES_SUITE_ENTRY) gcm_hw.c:$(AES_SUITE_ENTRY) \
                      gcm_hw.h:$(AES_SUITE_ENTRY) gcm_vaes.c:$(AES_SUITE_ENTRY) \
                      gcm_vaes.h:$(AES_SUITE_ENTRY) aes_extern.c:$(AES_EXTERN_SUITE_ENTRY) \
                      quic_token.c:-DCH_ROLE_SERVER quic_token.h:-DCH_ROLE_SERVER \
                      x509_ca.h:-DCH_TRUST_CA
# The files this compiler cannot judge, because the build choice they
# need is one it does not offer. aes_hw.c, ghash_hw.c, ghash_vector.h,
# gcm_hw.c and gcm_vaes.c hold their body under -DCH_CPU_RUNTIME, which
# cpu_cfg.h refuses on a compiler that fails the host test, so
# lint-quic-partition skips them there and judges them everywhere else.
QUIC_UNPROBED := $(if $(HOST_TARGET),,aes_hw.c ghash_hw.c ghash_vector.h gcm_hw.c gcm_vaes.c)
# The hash sources of a host object hold their body under the same define
# (docs/decisions.md 93), so the lint skips them on such a compiler too.
QUIC_UNPROBED += $(if $(HOST_TARGET),,sha256_hw.c sha512_hw.c hash_hw.h hkdf_hw.c keysched_hw.c)
# So do Keccak on the SHA-3 instructions and ML-KEM's two copies over it
# (docs/decisions.md 99), and the four-way Keccak and ML-KEM's copy over
# it (107).
QUIC_UNPROBED += $(if $(HOST_TARGET),,sha3_hw.c keccak_hw.h mlkem_hw.c mlkem_poly_hw.c)
QUIC_UNPROBED += $(if $(HOST_TARGET),,keccak_avx2.c mlkem_avx2.h mlkem_avx2.c)

# The ROLE=server mode's own sources, named here for the reason
# QUIC_SRCS and WEBPKI_SRCS are named: an auditor reads the object's
# contents off this line, and an untracked scratch file never enters the
# object. They sit outside SRCS because only one role compiles them; the
# ROLE axis below names them as its add.
#
# One concern per pair, dependencies pointing down: srv_ticket (the
# sealed resumption ticket) below srv_parser (the ClientHello parser)
# below srv_message (the messages a server writes) below srv_cookie (the
# HelloRetryRequest cookie) below srv_auth (which identity signs, and
# what the CertificateVerify covers) below srv_resume (which ticket a
# hello resumes, and the NewSessionTicket a connection ends with) below
# srv_kex (which group, the server's key share and the shared secret)
# below srv_flight (the flight handlers) below srv_handshake (the state
# machine) below srv (the public calls).
#
# None of them is a stub any more. docs/server.md, "Stubs first",
# states the rule they were written under: each file defined every
# function its header declares from its first commit, so a ROLE=server
# object linked before any handler was implemented.
SRV_SRCS := srv_ticket.c srv_parser.c srv_parser_ext.c srv_message.c srv_cookie.c srv_auth.c \
            srv_out.c srv_resume.c srv_kex.c srv_flight.c srv_handshake.c srv.c
# Which of them were still stubs was read from a marker rather than from
# a hand-kept list: every stub body held one `// CH_SRV_STUB: ` line and
# an implemented body held none. SRV_STUB_SRCS read that marker, and two
# checks carried an exception that list bounded: lint-tidy's stub pass,
# and lib-check's RAND=extern import check, for the object that drew no
# randomness while srv_flight.c was a stub. The marker matches nothing
# now, and the list and both exceptions went with the commit that
# implemented the last stub. The TRANSPORT=quic-nonblocking axis retired the same
# machinery under CH_QUIC_STUB.
# The client driver sources a ROLE=server object does not compile: the
# state machine, the peer-certificate flight, the parsers for the
# messages a server sends, and the ClientHello builder. Their server
# counterparts are in SRV_SRCS.
#
# tls.c and tls_write.c are deliberately absent. They define ch_read,
# ch_write and ch_close, which both roles export, so a server object
# compiles them and the split runs inside tls.c under #ifndef
# CH_ROLE_SERVER.
# handshake_flight.c holds the client's flight handlers, which both
# transports compile and a server does not.
CLIENT_REPLACED := handshake.c handshake_auth.c handshake_parser.c handshake_parser_ee.c \
                   handshake_message.c handshake_flight.c
# softmul.c is excluded on purpose. It has to define __mulsi3 and
# __muldi3 -- the names the compiler emits, so they replace the runtime
# library's -- and clang-tidy rejects those as reserved identifiers that
# should have internal linkage. Both are true and neither is fixable: the
# ABI picks the names and external linkage is the whole point. Excluding
# one file keeps bugprone-reserved-identifier and misc-use-internal-linkage
# working everywhere else, which disabling them in .clang-tidy would not.
# clang-format still covers it, and so does lint-runtime-symbols.
# The host object's multiply sources and tests (docs/decisions.md 87 and
# 89), which compile only under -DCH_CPU_RUNTIME: the native copies, the
# counting test and the units that compile the files built on the multiply
# again under counted names. lint-tidy reads them in passes of their own.
WIDEMUL_HOST_LINT_C := poly1305_native.c mlkem_poly_native.c poly1305_vector_native.c \
                          poly1305_avx2_native.c \
                          test/widemul_runtime_test.c test/widemul_runtime_count.c \
                          test/widemul_count_decomposed.c test/widemul_count_decomposed_point.c \
                          test/widemul_count_decomposed_scalar.c test/widemul_count_native.c \
                          test/widemul_count_native_vector.c test/widemul_count_native_avx2.c
# The host object's hash sources and tests (docs/decisions.md 93), which
# compile only under -DCH_CPU_RUNTIME: SHA-256 and SHA-512 on the CPU's
# instructions, the two copies over them, the equivalence test, and the
# counting test with its counting entries. lint-tidy reads them in passes
# of their own.
HASH_HOST_LINT_C := sha256_hw.c sha512_hw.c hkdf_hw.c keysched_hw.c test/sha2_equiv_test.c \
                    sha3_hw.c mlkem_hw.c mlkem_poly_hw.c test/sha3_hw_equiv_test.c \
                    test/mlkem_hw_equiv_test.c \
                    test/hash_runtime_test.c test/hash_runtime_count.c
# RSA's arithmetic on 64-bit words, the signer built on it and their
# equivalence tests (docs/decisions.md 95), which compile only under
# -DCH_CPU_RUNTIME. lint-tidy reads them in a pass of their own.
RSA_HOST_LINT_C := rsa_mont64.c rsa_sign64.c test/rsa_equiv_test.c test/rsa_equiv_portable.c \
                   test/rsa_sign_equiv_test.c test/rsa_sign_equiv_pieces.c test/diff_rsa_sign_test.c
LINT_C := $(filter-out softmul.c,$(SRCS)) handshake_groups.c drbg.c sha3.c sha512.c sha512_compress.c p384.c p384_field.c p256_field.c p256_scalar.c p256_point.c p256_sign.c p256_ecdh.c rsa_pkcs1.c rsa_sign.c webpki_sigalg.c webpki_cert.c webpki.c webpki_ticket.c webpki_pin.c webpki_cfg.c mlkem.c mlkem_poly.c test/unit_test.c test/tls_client.c \
          test/diff_test.c test/timing_test.c test/drbg_test.c test/softmul_test.c test/rsa_test.c test/rsa_sign_test.c test/sha3_test.c test/sha3_equiv_test.c test/sha512_test.c test/hkdf384_test.c test/p384_test.c test/p256_field_test.c test/p256_sign_test.c test/p256_ecdh_test.c test/rsa_pkcs1_test.c \
          test/webpki_time_test.c test/webpki_name_test.c test/webpki_spki_test.c test/webpki_sigalg_test.c test/webpki_session_test.c test/webpki_resume_test.c test/webpki_cert_test.c test/webpki_chain_test.c \
          test/webpki_auth_test.c test/webpki_encrypted_exts_test.c \
          test/mlkem_test.c test/handshake_strict_test.c test/handshake_sequence_test.c \
          test/x509_strict_test.c $(QUIC_SRCS) $(filter-out $(AES_IMPL),$(AES_IMPL_SRCS)) \
          $(SRV_SRCS) test/srv_auth_test.c test/srv_test.c test/srv_flight_test.c test/tls_server.c \
          srv_quic.c quic_token.c srv_tcp_nonblocking.c test/srv_tcp_nonblocking_test.c test/tcp_nonblocking_loop_test.c test/tcp_blocking_loop_test.c test/webpki_loop_test.c test/exporter_test.c tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c \
          test/tcp_blocking_key_limit_test.c \
          test/quic_driver_test.c test/quic_loop_test.c test/quic_vectors.c test/diff_quic_test.c \
          test/aes_equiv_test.c test/aes_equiv_soft.c test/aes_equiv_hw.c test/aes_equiv_vaes.c \
          test/aes_extern_hook.c test/x86_kernels_test.c test/x86_kernels_count.c \
          test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c \
          test/ghash_equiv_test.c test/ghash_equiv_soft.c \
          chacha20_vector.c chacha20_avx2.c test/chacha20_equiv_test.c test/chacha20_equiv_vector.c \
          test/chacha20_equiv_avx2.c x25519_wide.c test/x25519_equiv_test.c \
          $(P256_WIDE_SRCS) test/p256_equiv_test.c test/diff_p256_wide_test.c \
          test/p256_verify_equiv_test.c test/p256_verify_portable.c \
          $(P384_WIDE_SRCS) test/p384_equiv_test.c test/p384_equiv_field.c test/p384_equiv_sign.c \
          test/p384_portable.c \
          $(RSA_HOST_LINT_C) \
          poly1305_vector.c test/poly1305_equiv_test.c test/poly1305_equiv_vector.c test/stack_residue.c \
          poly1305_avx2.c test/poly1305_equiv_avx2.c \
          mlkem_vector.c test/mlkem_vector_equiv_test.c \
          keccak_avx2.c mlkem_avx2.c test/mlkem_avx2_equiv_test.c \
          test/diff_x25519_test.c test/build_test.c test/lib_pair_half.c test/lib_pair_main.c \
          test/entropy_recipe.c test/ticket_epoch_test.c $(WIDEMUL_HOST_LINT_C) $(HASH_HOST_LINT_C) \
          $(wildcard examples/*.c)

# Test-local headers: prerequisites for every binary that includes them,
# so a header edit rebuilds the binaries it changes.
TESTH := test/test_random.h test/test_widemul.h test/test_aead.h test/test_hash.h test/x86_kernels_cpu.h \
         test/hash_instructions_cpu.h test/hash_runtime_count.h test/sha2_equiv_copies.h \
         test/sha2_equiv_residue.h test/sha2_equiv_sha512.h test/sha2_equiv_copies384.h \
         test/sha2_equiv_residue512.h test/quic_vectors_cpu.h test/x86_kernels_count.h test/initial_cpu.h \
         test/aes_equiv_counter.h test/ghash_equiv_residue.h test/ghash_equiv_vaes.h test/pem_armor.h test/pem_tests.h test/x509_ca_tests.h test/session_tests.h test/session_post_tests.h test/session_record_end_tests.h test/session_write_tests.h \
         test/session_alert_tests.h test/session_hello_tests.h \
         test/session_cfg_tests.h test/gcm_tests.h test/quic_initial_tests.h test/quic_packet_tests.h test/p256_tests.h test/p256_field_vectors.h test/p256_sign_vectors.h test/p256_ecdh_vectors.h test/wycheproof_p256.h test/wycheproof_aes_gcm.h test/diff_driver.h test/diff_p256_wide_inverse.h test/diff_aes.h test/diff_gcm.h test/diff_hash.h test/diff_hash384.h \
         test/diff_handshake_parser.h test/diff_encrypted_exts.h test/diff_handshake_certificate.h test/diff_p256.h test/diff_pem.h test/diff_record.h test/diff_rsa.h \
         test/diff_x25519.h test/handshake_sequence_server.h test/rfc8439_tests.h test/rfc8448_vectors.h \
         test/poly1305_equiv_residue.h test/p256_equiv_field.h test/p256_equiv_residue.h \
         test/p256_equiv_table.h test/p256_verify_equiv_joint.h \
         test/rfc8448_tests.h \
         test/x509_vectors.h test/x509_mutate.h test/x509_chain_tests.h test/x509_epoch.h \
         test/x509_exact_fill.h \
         test/x509_spki.h test/diff_x509.h test/diff_x509_bounds.h test/diff_x509_chain.h \
         test/diff_x509_epoch.h test/diff_x509_mutate.h test/diff_x509_random.h \
         test/diff_x509_signed.h test/diff_sha3.h test/diff_sha512.h test/diff_p384.h test/diff_rsa_pkcs1.h \
         test/rsa_pkcs1_vectors.h test/rsa_wide_vectors.h test/rsa_pkcs1_wide_vectors.h \
         test/rsa_sign_vectors.h test/rsa_sign_key.h test/rsa_sign_equiv_residue.h \
         test/rsa_sign_equiv_pieces.h test/rsa_sign_equiv_differential.h \
         test/diff_webpki.h test/diff_mlkem.h test/mlkem_vectors.h test/webpki_corpus.h test/webpki_sigalg_vectors.h \
         test/diff_webpki_sigalg.h test/hello_exts.h test/webpki_session_cases.h test/webpki_groups_cases.h test/webpki_p256_cases.h test/webpki_mock_kex.h test/webpki_suite_cases.h test/tcp_nonblocking_read_tests.h test/tcp_nonblocking_record_end_tests.h test/record_edit.h test/tcp_blocking_retry_tests.h test/tcp_blocking_alert_tests.h test/tcp_nonblocking_resume_tests.h test/tcp_nonblocking_group_tests.h test/tcp_nonblocking_coalesced_tests.h test/tcp_nonblocking_close_tests.h test/tcp_nonblocking_alert_tests.h test/tcp_nonblocking_failure_alert_tests.h test/tcp_nonblocking_frame_tests.h test/quic_loop_raw.h test/quic_loop_close.h test/quic_loop_webpki.h test/quic_loop_pins.h test/webpki_resume_session.h test/webpki_resume_cases.h test/webpki_pins_cases.h test/tls_client_webpki.h \
         test/webpki_decline_cases.h test/webpki_r2_chain.h test/psk_decline_tests.h \
         test/handshake_strict_alpn.h test/handshake_strict_cert_type.h \
         test/webpki_cert_mutants.h test/webpki_cert_key_mutants.h test/webpki_ext_mutants.h test/diff_webpki_cert.h \
         test/webpki_auth_vectors.h test/webpki_auth_pins.h test/webpki_leaf_pins.h test/webpki_chain_path.h \
         test/diff_webpki_chain.h test/diff_webpki_pin.h test/diff_webpki_leaf_pin.h test/rxbuf_floor_tests.h \
         test/srv_message_tests.h test/srv_cookie_tests.h test/srv_ticket_tests.h test/srv_resume_tests.h test/srv_resume_issue_tests.h test/srv_flight_tests.h test/srv_flight_suite_tests.h test/srv_flight_p256_tests.h \
         test/quic_token_tests.h test/quic_retry_tests.h test/quic_version_tests.h test/srv_quic_version_tests.h test/srv_quic_retry_tests.h test/srv_quic_retry_count_tests.h test/srv_quic_retry_vectors.h \
         test/quic_v2_vectors.h test/quic_version2_tests.h test/quic_loop_version.h test/diff_quic.h \
         test/quic_loop_ticket_versions.h \
         test/srv_flight_keys_tests.h test/srv_identity_tests.h test/srv_parser_hello.h test/srv_parser_tests.h test/srv_parser_reader_tests.h \
         test/lib_pair.h test/rand_session.h test/rand_session_cases.h test/tcp_nonblocking_session_tests.h \
         test/tcp_blocking_session_tests.h test/quic_loop_session.h test/key_limit_cases.h \
         test/webpki_loop_order.h test/aes_runtime_count.h test/quic_v1_vectors.h test/quic_loop_runtime.h \
         test/webpki_loop_runtime.h test/tcp_blocking_loop_runtime.h test/widemul_runtime_count.h \
         test/widemul_count_names.h test/tcp_blocking_loop_widemul.h test/tcp_nonblocking_loop_widemul.h \
         test/quic_loop_widemul.h test/webpki_session_widemul.h test/test_cpu.h \
         test/tcp_blocking_loop_cpu.h test/tcp_nonblocking_loop_cpu.h test/quic_loop_cpu.h \
         test/webpki_session_cpu.h

# Each axis names its value or stops the build. RAND has done this since
# https://github.com/c4milo/chapulin/issues/41; PIN, TRUST and KEX each
# had a bare else, so a misspelled or not-yet-implemented value resolved
# to the default and every gate passed against a build nobody asked for.
# `make check TRUST=webpki` built and passed as the default mode.
#
# Each axis contributes a filter rather than rewriting LIB_SRCS, and one
# assignment below applies them together. Sequential rewrites made the
# packaged source list depend on the order the axes appear in this file.

# PIN was an axis until the pinned algorithm became half of a TRUST
# value. A build line that still carries one asked for a specific
# verifier, and ignoring it would hand back an object built around
# another, so it is refused by name.
ifdef PIN
$(error PIN is no longer an axis; the pinned algorithm is half of TRUST: use TRUST=raw-rsa, TRUST=raw-ecdsa, TRUST=ca-rsa or TRUST=ca-ecdsa)
endif
# Trust mode, which also names the pinned key's algorithm: TRUST=raw-rsa
# (default) and TRUST=raw-ecdsa pin server keys and ship no certificate
# parser; TRUST=ca-rsa and TRUST=ca-ecdsa pin a CA key and include it;
# TRUST=webpki verifies a public chain against the caller's anchors
# (docs/webpki.md). One mode per packaged object.
#
# One value names both halves because the algorithm is a choice only
# where a key is pinned. A public chain's links are signed by different
# algorithm families, so a webpki object carries every verifier and has
# no algorithm to name, and a server object carries both for the same
# reason. An axis that selects nothing in two of the builds that read it
# is a suffix, not an axis, and writing it as one means the build that
# asks for a verifier it will not get cannot be spelled.
#
# The rsa suffix is RSA-PSS up to 3072 bits (rsa.[ch]); the ecdsa suffix
# is P-256 (p256.[ch], -DCH_PIN_ECDSA). Test binaries compile both
# modules so both stay tested either way; the packaged library object
# carries only the named one.
#
# One consequence of that choice is invisible from the outside and worth
# reading before picking a mode: only TRUST=webpki gives a client the ALPN
# fields, so a raw or ca client offers no application protocol at all and
# cannot speak anything that selects itself by ALPN, HTTP/2 over TLS among
# them (RFC 9113 section 3.1). That is deliberate. Those modes talk to an
# endpoint whose key the device already pins, so the protocol is settled
# when the key is provisioned, and carrying the fields would cost every
# such hello the 270 bytes cfg.h prices at CH_ALPN_MAX. A device that must
# negotiate a protocol takes TRUST=webpki.
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
                webpki_cert.c webpki.c webpki_ticket.c webpki_pin.c webpki_cfg.c
# The verifiers and the SHA-384 core a public chain needs. SRCS lists
# x509_der.c, rsa.c, rsa_mont.c and p256.c already; these five it does
# not, because the device objects never package them.
WEBPKI_CHAIN_SRCS := sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c
# The constant-time P-256 key exchange: p256_ecdh.c over the arithmetic
# p256_sign.c computes with too. p256.c is the variable-time verifier and
# is not among them. Every server role and every TRUST=webpki client
# carries them (docs/decisions.md 63); the device clients do not.
P256_ECDH_SRCS := p256_ecdh.c p256_point.c p256_scalar.c p256_field.c
# What the TRUST=webpki client adds for its key exchange: the retry to
# secp256r1, the group a ServerHello may then select, and the classic
# secrets (handshake_groups.h), with the P-256 arithmetic under them.
WEBPKI_KEX_SRCS := handshake_groups.c $(P256_ECDH_SRCS)
TRUST ?= raw-rsa
# Provisioning is a public call only where its parser is linked, so
# PUBLIC_CA is set by the two ca arms alone.
ifeq ($(TRUST),raw-rsa)
TRUST_DEF :=
PIN_DEF :=
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_der.c x509_ca.c $(WEBPKI_SRCS)
PIN_FILTER := p256.c
TRUST_ADD :=
else ifeq ($(TRUST),raw-ecdsa)
TRUST_DEF :=
PIN_DEF := -DCH_PIN_ECDSA
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_der.c x509_ca.c $(WEBPKI_SRCS)
PIN_FILTER := rsa.c rsa_mont.c
TRUST_ADD :=
else ifeq ($(TRUST),ca-rsa)
TRUST_DEF := -DCH_TRUST_CA
PIN_DEF :=
PUBLIC_CA := ch_pubkey_from_pem
TRUST_FILTER := $(WEBPKI_SRCS)
PIN_FILTER := p256.c
TRUST_ADD :=
else ifeq ($(TRUST),ca-ecdsa)
TRUST_DEF := -DCH_TRUST_CA
PIN_DEF := -DCH_PIN_ECDSA
PUBLIC_CA := ch_pubkey_from_pem
TRUST_FILTER := $(WEBPKI_SRCS)
PIN_FILTER := rsa.c rsa_mont.c
TRUST_ADD :=
else ifeq ($(TRUST),none)
# The server's value. A server proves its own identity and judges no
# peer certificate, so it reads no certificate parser and names no
# algorithm: ch_srv_check verifies both provisioned identities at boot,
# so the object holds both verifiers and PIN_FILTER stays empty. It
# exists rather than letting a server take the default because a server
# built under raw-rsa is described by a value naming one algorithm the
# object does not honour, and because a recursion that does not name its
# trust value silently inherits one.
TRUST_DEF :=
PIN_DEF :=
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_der.c x509_ca.c $(WEBPKI_SRCS)
PIN_FILTER :=
TRUST_ADD :=
else ifeq ($(TRUST),webpki)
TRUST_DEF := -DCH_TRUST_WEBPKI
# This object carries every verifier, so it names no algorithm and
# filters none out.
PIN_DEF :=
PUBLIC_CA :=
TRUST_FILTER := pem.c x509.c x509_ca.c
PIN_FILTER :=
TRUST_ADD := $(WEBPKI_CHAIN_SRCS) $(filter-out $(SRCS),$(WEBPKI_SRCS)) $(WEBPKI_KEX_SRCS)
else
$(error TRUST=$(TRUST) is not a trust mode; use TRUST=raw-rsa, TRUST=raw-ecdsa, TRUST=ca-rsa, TRUST=ca-ecdsa, TRUST=webpki, or TRUST=none for ROLE=server)
endif
# Transport: TRANSPORT=tcp-blocking (default) runs the client over TLS records and
# a socket the caller's I/O callbacks drive; TRANSPORT=quic-nonblocking runs the same
# TLS 1.3 handshake over QUIC's CRYPTO frames and protects QUIC packets
# with the keys it produces (docs/quic.md). One transport per packaged
# object, like PIN and TRUST: the two export different public calls, so
# an object cannot carry both.
#
# The six sources a QUIC object replaces: it compiles none of them
# (docs/quic.md, "What is reused, and what changes").
QUIC_REPLACED := io.c record.c session.c handshake.c tls.c tls_write.c
# The sources that keep their TLS text, carry a QUIC arm under #ifdef
# CH_TRANSPORT_QUIC_NONBLOCKING, and cannot be compiled into the object until they
# have one. Every arm landed with the driver, so the list is empty and
# the object compiles all of handshake_parser_ee.c, handshake_record.c,
# handshake_auth.c, handshake_post.c and handshake_message.c. The name
# stays because TRANSPORT_FILTER and tools/quic-partition.py read it: a
# source that loses its arm goes back on this list.
QUIC_PENDING :=
# Each value names what TLS runs over and who does the I/O: chapulin
# through blocking callbacks, or the caller (docs/decisions.md 62). The
# old names stop the build rather than pick a transport.
TRANSPORT ?= tcp-blocking
ifneq ($(filter tls record quic,$(TRANSPORT)),)
$(error TRANSPORT=$(TRANSPORT) is renamed: tls is tcp-blocking, record is tcp-nonblocking, quic is quic-nonblocking)
endif
ifeq ($(TRANSPORT),quic-nonblocking)
TRANSPORT_DEF := -DCH_TRANSPORT_QUIC_NONBLOCKING
TRANSPORT_FILTER := $(QUIC_REPLACED) $(QUIC_PENDING)
TRANSPORT_ADD := $(filter-out $(AES_IMPL),$(QUIC_SRCS))
PUBLIC_TRANSPORT := ch_quic_init ch_quic_initial_keys ch_quic_crypto_in ch_quic_crypto_out \
                    ch_quic_switch_version ch_quic_negotiated_version \
                    ch_quic_seal ch_quic_seal_close ch_quic_open ch_quic_retry_ok ch_quic_key_update \
                    ch_quic_key_phase ch_quic_drop_previous_keys ch_quic_discard \
                    ch_quic_state ch_quic_alert ch_quic_error_code ch_quic_close \
                    ch_ticket_obfuscated_age ch_alert_sent ch_alert_received
else ifeq ($(TRANSPORT),tcp-nonblocking)
# The same TLS records, driven by a caller that owns the socket. It
# replaces handshake.c, the blocking driver, and keeps everything under
# it: the flight handlers, the record layer and the post-handshake
# messages are the ones TRANSPORT=tcp-blocking compiles. ch_connect goes with
# handshake.c, and ch_read, ch_write and ch_close stay, because a caller
# that has finished the handshake holds its bytes and its callbacks no
# longer block (tcp_nonblocking.h).
TRANSPORT_DEF := -DCH_TRANSPORT_TCP_NONBLOCKING
TRANSPORT_FILTER := handshake.c
TRANSPORT_ADD := tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c
PUBLIC_TRANSPORT := ch_record_init ch_record_in ch_record_out ch_record_state ch_record_close \
                    ch_record_whole_len ch_read ch_write ch_writable_len ch_close ch_ticket_obfuscated_age \
                    ch_alert_sent ch_alert_received
else ifeq ($(TRANSPORT),tcp-blocking)
TRANSPORT_DEF :=
TRANSPORT_FILTER :=
TRANSPORT_ADD :=
PUBLIC_TRANSPORT := ch_connect ch_read ch_write ch_writable_len ch_close ch_ticket_obfuscated_age \
                    ch_alert_sent ch_alert_received
else
$(error TRANSPORT=$(TRANSPORT) is not a transport; use TRANSPORT=tcp-blocking, TRANSPORT=tcp-nonblocking or TRANSPORT=quic-nonblocking)
endif
# Role: ROLE=client (default) builds the TLS 1.3 client this tree has
# always built; ROLE=server builds a TLS 1.3 server from the same
# primitives, the same record layer and the same key schedule
# (docs/server.md). ROLE=client and ROLE=server each carry one role, and
# a device wants that: it carries one role for the life of the
# deployment, so the flash the other one costs buys it nothing.
#
# ROLE=both is the host-side value and carries the two together. The
# firmware argument does not reach a host library, and two objects are
# not a substitute: each holds the shared half, so linking them into one
# program makes ld report ch_read, ch_write, ch_close and ch_drbg_seed
# defined twice. The roles share ch_tls and every post-handshake call
# (srv.h), so the combined object needs no dispatch and no second name --
# it exports ch_connect and ch_srv_accept beside the calls they share.
#
# This block sits here and not higher because every assignment in it is
# immediate: ROLE_FILTER reads CLIENT_REPLACED, the client arm reads
# PUBLIC_TRANSPORT from the TRANSPORT block above, the server arm
# rewrites the PIN variables the PIN block above set, and LIB_DEF and
# LIB_SRCS below read the result.
ROLE ?= client
ifeq ($(ROLE),server)
# A server proves its own identity, never judges a peer's certificate,
# and carries both verifiers because ch_srv_check verifies both
# provisioned identities at boot. So TRUST names nothing here: neither a
# parser to add nor an algorithm to keep, and every value but the
# default is refused rather than ignored.
#
# A server names TRUST=none and nothing else. Taking the client default
# instead would describe this object with a value naming one algorithm,
# where it holds both; it would also let a recursion that forgets to
# name its trust value inherit one and either build the wrong object or
# stop here, which is what `make check TRUST=raw-ecdsa` did.
#
# The test is the value and not $(origin TRUST): lint-trust-separation's
# recursions inherit every command-line variable through MAKEFLAGS, so an
# origin test would make `make check TRUST=webpki` die in a row that
# names its own value rather than in a build anyone asked for.
ifneq ($(TRUST),none)
$(error ROLE=server judges no peer certificate, so it has no trust mode to choose; use TRUST=none)
endif
ROLE_DEF    := -DCH_ROLE_SERVER
ROLE_FILTER := $(CLIENT_REPLACED)
# The server's own sources and the two signers srv_auth.c calls:
# rsa_sign.c for rsa_pss_rsae_sha256 and p256_sign.c for
# ecdsa_secp256r1_sha256, with the constant-time arithmetic p256_sign.c
# computes over and p256.c does not carry, and p256_ecdh.c over the same
# arithmetic for srv_kex.c's secp256r1 key exchange (docs/decisions.md
# 63). docs/server.md's ROLE_ADD also names aes.c and gcm.c; those two
# do not exist, so this object has no AES and the build offers
# TLS_CHACHA20_POLY1305_SHA256 alone. Each lane adds its own name here
# when it lands.
#
# rsa_sign.c brings the deepest call chain in the object: rsa_pss_sign
# calls rsa_sp1 calls mont_mul, and a device's stack holds all three at
# once. lint-stack passes at the 2,560-byte budget because
# -Wframe-larger-than measures one frame at a time, and docs/server.md
# measures the sum a deployment has to size its stack from.
ROLE_ADD    := $(SRV_SRCS) rsa_sign.c p256_sign.c $(P256_ECDH_SRCS)
ifeq ($(TRANSPORT),quic-nonblocking)
# The server's driver replaces the client's, source for source:
# srv_quic.c is the step table quic_step.c is for a client, and
# srv_handshake.c drives the TLS records this transport does not have.
# quic.c stays, because the packet calls in it read no side and a server
# needs every one; its own client driver is guarded out there. The
# server adds quic_token.c, which mints and checks the Retry token and
# which no client calls.
TRANSPORT_ADD := $(filter-out quic_step.c,$(TRANSPORT_ADD))
ROLE_ADD    := $(filter-out srv_handshake.c,$(ROLE_ADD)) srv_quic.c quic_token.c
# What this object exports: the server's five calls, the boot check, the
# packet calls quic.h declares for either role, and alert.h's two calls,
# which every object exports. Not ch_quic_init, ch_quic_crypto_in,
# ch_quic_crypto_out or ch_quic_switch_version, which are the client's
# driver; not ch_read, ch_write or ch_close, which are record-layer calls
# RFC 9001 section 4.1.3 removes with the record layer.
PUBLIC_ROLE := ch_srv_quic_init ch_srv_quic_crypto_in ch_srv_quic_retry_tag \
               ch_srv_quic_token_mint ch_srv_quic_token_check ch_srv_check \
               ch_quic_initial_keys ch_quic_negotiated_version \
               ch_quic_seal ch_quic_seal_close ch_quic_open ch_quic_retry_ok \
               ch_quic_key_update ch_quic_key_phase ch_quic_drop_previous_keys \
               ch_quic_discard ch_quic_state ch_quic_alert ch_quic_error_code ch_quic_close \
               ch_alert_sent ch_alert_received
else ifeq ($(TRANSPORT),tcp-nonblocking)
# The server's driver replaces the client's, source for source:
# srv_tcp_nonblocking.c is the step table tcp_nonblocking_step.c is for
# a client, and srv_handshake.c is the blocking driver this transport
# exists to avoid. tcp_nonblocking.c stays, because ch_record_state and
# ch_record_close read no side; its own client driver is guarded out
# there. tcp_nonblocking_frame.c stays for the same reason: one inbound
# record reads the same from either side, and a failure's alert record
# is sealed the same way on either side.
TRANSPORT_ADD := $(filter-out tcp_nonblocking_step.c,$(TRANSPORT_ADD))
ROLE_ADD    := $(filter-out srv_handshake.c,$(ROLE_ADD)) srv_tcp_nonblocking.c
# What this object exports: the server's two driver calls, the boot check,
# the two session calls either role uses, the record framing call either
# role uses, the record-layer calls a connected session needs, and
# alert.h's two calls. Not
# ch_record_init, ch_record_in or ch_record_out, which are the client's
# driver, not ch_ticket_obfuscated_age, which only a client presents, and
# not ch_srv_accept, which is the blocking one.
PUBLIC_ROLE := ch_srv_record_init ch_srv_record_in ch_srv_check \
               ch_record_state ch_record_close ch_record_whole_len \
               ch_read ch_write ch_writable_len ch_close ch_alert_sent ch_alert_received
else
PUBLIC_ROLE := ch_srv_accept ch_srv_check ch_read ch_write ch_writable_len ch_close \
               ch_alert_sent ch_alert_received
endif
# PIN_DEF and PIN_FILTER are already empty: the TRUST=none arm this
# block requires sets them, and an empty PIN_FILTER keeps every verifier
# because LIB_SRCS filters out what the filter names. This object wants
# exactly that -- it holds two signing identities and ch_srv_check
# verifies both at boot, so it needs p256_ecdsa_verify and rsa_pss_verify
# in one object. rsa_pkcs1.c is the one verifier a server never needs,
# and no filter has to name it: it reaches a build only through
# TRUST_ADD, which TRUST=none never sets.
else ifeq ($(ROLE),both)
# One object that answers and dials. A host-side consumer is often both
# -- colibri serves HTTP/2 and HTTP/3 and also fetches over them -- and
# two objects cannot be linked into one program: each carries the shared
# half, so ld reports ch_read, ch_write, ch_close and ch_drbg_seed
# defined twice. This arm is the client arm plus the server's sources,
# and it is not for a device: CLAUDE.md's one-role-per-object rule is a
# firmware argument (a device carries one role for the life of the
# deployment), and it stands for ROLE=client and ROLE=server.
#
# The client half needs a trust mode, so TRUST=none is refused here and
# every other value is allowed. srv_cfg.h admits CH_TRUST_* under
# CH_ROLE_BOTH for the same reason.
ifeq ($(TRUST),none)
$(error ROLE=both carries a client, which judges a peer certificate; TRUST=none is ROLE=server only, so use TRUST=raw-rsa, TRUST=raw-ecdsa, TRUST=ca-rsa, TRUST=ca-ecdsa or TRUST=webpki)
endif
# CH_ROLE_SERVER compiles the srv_*.c files and the server arms inside the
# shared sources; CH_ROLE_BOTH keeps the four guards that would otherwise
# drop the client half with it (tls.h, tls.c and quic.c twice).
ROLE_DEF    := -DCH_ROLE_SERVER -DCH_ROLE_BOTH
# Nothing is replaced: ROLE=server filters $(CLIENT_REPLACED) because its
# srv_*.c files stand in for those drivers, and here both sets compile.
ROLE_FILTER :=
ROLE_ADD    := $(SRV_SRCS) rsa_sign.c p256_sign.c $(P256_ECDH_SRCS)
ifeq ($(TRANSPORT),quic-nonblocking)
ROLE_ADD    := $(filter-out srv_handshake.c,$(ROLE_ADD)) srv_quic.c quic_token.c
PUBLIC_ROLE := $(PUBLIC_TRANSPORT) ch_srv_quic_init ch_srv_quic_crypto_in \
               ch_srv_quic_retry_tag ch_srv_quic_token_mint ch_srv_quic_token_check \
               ch_srv_check
else ifeq ($(TRANSPORT),tcp-nonblocking)
# The server's blocking driver goes and its tcp-nonblocking driver takes the
# place, the same swap the quic arm above makes. tcp_nonblocking_step.c
# stays, unlike the ROLE=server arm: this object keeps the client half, so
# both step tables compile and each driver calls its own.
ROLE_ADD    := $(filter-out srv_handshake.c,$(ROLE_ADD)) srv_tcp_nonblocking.c
PUBLIC_ROLE := $(PUBLIC_TRANSPORT) ch_srv_record_init ch_srv_record_in ch_srv_check
else
PUBLIC_ROLE := $(PUBLIC_TRANSPORT) ch_srv_accept ch_srv_check
endif
# Both verifiers, as ROLE=server has: ch_srv_check verifies both
# provisioned identities at boot whatever the client half pins.
PIN_FILTER  :=
else ifeq ($(ROLE),client)
# TRUST=none says "judges no peer certificate", which is the one thing a
# client must do.
ifeq ($(TRUST),none)
$(error TRUST=none is the ROLE=server value; a client judges a peer certificate, so use TRUST=raw-rsa, TRUST=raw-ecdsa, TRUST=ca-rsa, TRUST=ca-ecdsa or TRUST=webpki)
endif
ROLE_DEF    :=
ROLE_FILTER :=
ROLE_ADD    :=
PUBLIC_ROLE := $(PUBLIC_TRANSPORT)
else
$(error ROLE=$(ROLE) is not a role; use ROLE=client, ROLE=server or ROLE=both)
endif
# The product picks the object on a host target (docs/decisions.md 89).
# A device client, ROLE=client with a raw or ca TRUST, builds the
# portable object on every target, so the default `make lib` and the
# examples stay the device object. TRUST=webpki, ROLE=server and
# ROLE=both build the host object where HOST_TARGET above passed. A check
# that packages a server's device object on a development machine sets
# HOST_TARGET empty on its command line: that is the host test's result
# for a device target, and the build then passes no define.
DEVICE_CLIENT := $(filter client-raw-rsa client-raw-ecdsa client-ca-rsa client-ca-ecdsa,$(ROLE)-$(TRUST))
CPU_RUNTIME_DEF := $(if $(HOST_TARGET),$(if $(DEVICE_CLIENT),,-DCH_CPU_RUNTIME))
# A host object takes no AES value: it holds the AES instructions and,
# over QUIC, the table for public keys. The test is $(origin AES), which
# tells the default from a value the command line or the environment
# set, as KEX's below is.
ifneq ($(CPU_RUNTIME_DEF),)
ifneq ($(origin AES),file)
$(error AES=$(AES) chooses a device object's AES, and TRUST=$(TRUST) ROLE=$(ROLE) on this compiler builds a host object, which holds the AES instructions and picks them per session from ch_cfg.cpu (docs/decisions.md 89): drop AES, or set HOST_TARGET empty for the device object)
endif
endif
# The AES implementation the object holds, where it carries AES: over
# QUIC, and under SUITE=aesgcm. A host object holds the instructions,
# and over QUIC the table beside them; a device object holds AES_IMPL.
AES_CARRIED := $(if $(filter quic-nonblocking,$(TRANSPORT)),yes,$(SUITE_DEF))
AES_ADD := $(if $(AES_CARRIED),$(if $(CPU_RUNTIME_DEF),$(AES_HW_SRCS) \
             $(if $(filter quic-nonblocking,$(TRANSPORT)),quic_aes_soft.c),$(AES_IMPL)))
LIB_DEF := $(strip $(PIN_DEF) $(TRUST_DEF) $(TRANSPORT_DEF) $(AES_DEF) $(SUITE_DEF) $(ROLE_DEF) \
             $(CPU_RUNTIME_DEF))
# The one assignment. Every axis above filters or names the sources
# only its value adds; nothing below rewrites. A ROLE=both TRUST=webpki
# object gets the P-256 arithmetic from both its trust mode and its
# role, so the role's copy of a name the trust mode already added is
# dropped: ld -r would otherwise see each of those objects twice.
LIB_SRCS := $(filter-out $(PIN_FILTER) $(TRUST_FILTER) $(TRANSPORT_FILTER) $(ROLE_FILTER),$(SRCS)) \
            $(TRUST_ADD) $(TRANSPORT_ADD) $(filter-out $(TRUST_ADD),$(ROLE_ADD)) \
            $(filter-out $(TRUST_ADD) $(TRANSPORT_ADD) $(ROLE_ADD),$(SUITE_ADD)) $(AES_ADD)
# Key exchange: KEX=x25519 (default) or KEX=pq (-DCH_KEX_PQ), the
# X25519MLKEM768 hybrid. KEX chooses the one group of a raw or ca device
# client and nothing else. The ML-KEM and SHA-3 modules join the packaged
# object under KEX=pq and in every TRUST=webpki object.
#
# Every other build's key exchange is fixed, so a KEX value on its build
# line asks for something it will not get, and it is refused, as
# decision 40 refused a stale PIN. A TRUST=webpki client offers both
# groups in every build, a key share for each, and cfg.h defines what that
# needs from CH_TRUST_WEBPKI alone (docs/decisions.md 53): KEX=x25519
# would ask for an x25519-only hello, and KEX=pq for the one-group hybrid
# hello, which ch_cfg.require_pq gives at run time. A server role's key
# exchange is not a build choice either: it holds X25519MLKEM768 and
# x25519 in every build, prefers the hybrid, and so carries ML-KEM
# whatever KEX says (docs/decisions.md 54). The test is
# $(origin KEX), which tells the default below from a value the command
# line or the environment set, because the default is the one KEX those
# builds can build under.
KEX ?= x25519
ifeq ($(filter x25519 pq,$(KEX)),)
$(error KEX=$(KEX) is not a key exchange; use KEX=x25519 or KEX=pq)
endif
KEX_HYBRID_SRCS := sha3.c mlkem.c mlkem_poly.c
ifeq ($(ROLE)-$(filter raw-rsa raw-ecdsa ca-rsa ca-ecdsa,$(TRUST)),client-$(TRUST))
KEX_VARIANT := $(KEX)
else
ifneq ($(origin KEX),file)
$(error KEX=$(KEX) chooses the group of a raw or ca client, and TRUST=$(TRUST) ROLE=$(ROLE) is not one: a TRUST=webpki client offers X25519MLKEM768 and x25519 in every build, and a server role holds both in every build (docs/decisions.md 53 and 54). Drop KEX, and set ch_cfg.require_pq for the hybrid alone)
endif
# What LIB_VARIANT records for a key exchange KEX does not choose: every
# such build carries both groups, a webpki client because it offers both
# and a server role because it holds both.
KEX_VARIANT := both
endif
ifeq ($(KEX),pq)
LIB_DEF += -DCH_KEX_PQ
endif
ifneq ($(filter pq-% %-webpki,$(KEX)-$(TRUST))$(filter server both,$(ROLE)),)
LIB_SRCS += $(KEX_HYBRID_SRCS)
endif
# The X25519 field, which both KEX values run. Every object holds
# x25519.c's 16 words of 16 bits, whose products are 32x32 multiplies that
# ct.h can build from 16x16 pieces on any core. A host object also holds
# x25519_wide.c, five words of 51 bits whose products are 64x64->128
# multiplies, and widemul.h runs it for a session whose ch_cfg.cpu holds
# CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 52 and 89). The host
# test requires unsigned __int128, the type of those products, which no
# 32-bit target here has.
#
# No variable chooses the field. X25519=wide chose it for a whole object
# until the field moved under the bit, and a build that still passes the
# variable would get the 16-word field with nothing said, so any value of
# it stops the build here.
ifneq ($(origin X25519),undefined)
$(error X25519=$(X25519) is gone: on arm64 and x86-64 a TRUST=webpki client, ROLE=server and ROLE=both hold the wide X25519 field and run it for a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY, and every other object runs the 16-word field (docs/decisions.md 89))
endif
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += x25519_wide.c
endif
# P-256, which a TRUST=webpki client and every server role run. Every
# object that carries it holds p256_field.c, p256_scalar.c and
# p256_point.c, eight words of 32 bits whose products ct.h can build from
# 16x16 pieces on any core. A host object also holds the wide files
# (P256_WIDE_SRCS), four words of 64 bits whose products are 64x64->128
# multiplies, and widemul.h runs them for a session whose ch_cfg.cpu holds
# CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 89 and 94). They are
# P-256's second copy there, as x25519_wide.c is X25519's, so neither
# p256_field.c nor p256_scalar.c has a native copy.
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter p256_point.c,$(LIB_SRCS)),$(P256_WIDE_SRCS))
endif
# RSA's public operation, rsa_vp1, which the two RSA verifiers call. A
# device object runs it on rsa_mont.c's 32-bit words. In a host object
# rsa_mont.c compiles to a call into rsa_mont64.c, the same exponentiation
# on 64-bit words whose products are 64x64->128 multiplies, and every
# session runs it: a modulus and a signature are public, so no bit states
# the multiply's timing for them (docs/decisions.md 95). The file joins
# every host object that holds rsa_mont.c.
RSA_MONT64_SRCS := rsa_mont64.c
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter rsa_mont.c,$(LIB_SRCS)),$(RSA_MONT64_SRCS))
endif
# ECDSA P-384, which a TRUST=webpki client checks a chain's signatures
# with. A device object runs p384.c's 32-bit arm over p384_field.c. In a
# host object p384.c compiles to a call into p384_wide_verify.c, the same
# equation on six 64-bit words over p384_wide_point.c and
# p384_wide_field.c, and p384_field.c compiles to nothing. Every session
# runs it: a key, a hash and a signature are public, so no bit states the
# multiply's timing for them (docs/decisions.md 97). The three files join
# every host object that holds p384.c.
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter p384.c,$(LIB_SRCS)),$(P384_WIDE_SRCS))
endif
# RSA-PSS signing, which a server role runs. A device object signs with
# rsa_sign.c's ladder on 32-bit words. A host object holds that ladder for
# a session that does not state its multiply, and beside it rsa_sign64.c,
# the Chinese remainder theorem on rsa_mont64.c's words with each
# signature checked before it returns, which widemul.h runs for a session
# that does (docs/decisions.md 95). The file joins every host object that
# holds rsa_sign.c, and every such object holds rsa_mont.c for
# ch_srv_check's verifier, so rsa_mont64.c is there for it.
RSA_SIGN64_SRCS := rsa_sign64.c
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter rsa_sign.c,$(LIB_SRCS)),$(RSA_SIGN64_SRCS))
endif
# ML-KEM's NTT. A device object runs mlkem_poly.c's loops. A host object
# also holds mlkem_vector.c, the same transforms on eight 16-bit lanes,
# NEON on arm64 and SSE2 on x86-64, which mlkem.c runs in every session
# (docs/decisions.md 101).
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter mlkem.c,$(LIB_SRCS)),mlkem_vector.c)
endif
# ML-KEM's matrix. An x86-64 host object also holds keccak_avx2.c, Keccak
# on four states at once in AVX2, and mlkem_avx2.c, mlkem.c compiled once
# more with each row's three entries sampled side by side on it, which a
# session runs where its ch_cfg.cpu holds CH_CPU_AVX2 (docs/decisions.md
# 107). Every host object lists both, and on arm64 they hold nothing, as
# chacha20_avx2.c does.
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(if $(filter mlkem.c,$(LIB_SRCS)),keccak_avx2.c mlkem_avx2.c)
endif
# The ChaCha20 keystream, which every build runs
# (https://github.com/c4milo/chapulin/issues/181). A device object runs
# chacha20.c's loop, one 64-byte block at a time in 32-bit words. A host
# object also holds chacha20_vector.c, eight blocks a pass on NEON on
# arm64 and four on SSE2 on x86-64, in 128-bit vectors, which every
# session runs in place of the loop, and chacha20_avx2.c, an AVX2 kernel
# of eight blocks a pass, which a session whose ch_cfg.cpu holds
# CH_CPU_AVX2 runs for its records and packets. The kernel compiles to
# nothing on arm64. docs/decisions.md entries 82, 86, 89 and 90 say why.
#
# No bit turns the 128-bit path off: every arm64 core has NEON and every
# x86-64 core SSE2, and the host test requires one of the two on a
# little-endian core. The path asks for no timing statement of its own,
# where the wide X25519 field asks for the multiply bit: it runs the
# operations chacha20.c runs, adds, exclusive-ors, shifts and lane moves,
# with no multiply, no table and no division, so it rests on what the
# portable loop rests on. The vector Poly1305 does multiply, so a host
# object holds it in Poly1305's native copy alone, which the multiply bit
# picks (below the WIDEMUL axis).
#
# No variable chooses the keystream. CHACHA=vector chose it for a whole
# object until the choice moved to the host test, and a build that still
# passes the variable would get an object it did not name, so any value
# of it stops the build here.
ifneq ($(origin CHACHA),undefined)
$(error CHACHA=$(CHACHA) is gone: on arm64 and x86-64 a TRUST=webpki client, ROLE=server and ROLE=both run the vector ChaCha20 in every session, and every other object runs chacha20.c's loop (docs/decisions.md 89))
endif
# The two vector sources, named once for the object and for the test
# binaries that build a host object's ChaCha20.
CHACHA_VECTOR_SRCS := chacha20_vector.c chacha20_avx2.c
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(CHACHA_VECTOR_SRCS)
endif
# Whether the compiler targets x86-64, whose host object holds the AVX2
# ChaCha20 kernel and the VAES AES-GCM kernels (docs/decisions.md 90).
# There the host binaries that take a ch_cfg.cpu value also run under the
# values below, which name the kernels, and bin/x86_kernels_test counts
# which calls the library sends to a kernel under each value. A binary
# run under a value that names instructions its CPU lacks skips, and
# fails instead under CH_REQUIRE_X86_KERNELS=1 (test/test_cpu.h).
#   0xd   the probe's bit, the multiply bit and CH_CPU_AVX2
#   0xf   those and the AES bit
#   0x1f  those and CH_CPU_VAES: every bit that picks a kernel or a path beside one
X86_KERNEL_PROBE := $(shell $(CC) -dM -E -x c /dev/null 2>/dev/null | grep -qw '__x86_64__' && echo yes)
X86_KERNEL_BINS := $(if $(X86_KERNEL_PROBE),$(if $(HOST_TARGET),bin/x86_kernels_test))
X86_UNIT_CPU := $(if $(X86_KERNEL_PROBE),0xd)
X86_WYCHEPROOF_CPU := $(if $(X86_KERNEL_PROBE),0xf 0x1f)
# The values under which the host binaries that take a ch_cfg.cpu value run
# their hashes on the CPU's hash instructions (docs/decisions.md 93). The
# unit suite runs FIPS 180-4's, RFC 4231's and RFC 5869's vectors and keys
# every record direction under the first, and the Wycheproof host binary
# runs its HMAC and HKDF suites under the second. On arm64 two more values
# add the SHA-512 bit, which an x86-64 object refuses. The two SHA-512
# vector binaries run under the third: FIPS 180-4's SHA-384 and SHA-512
# vectors, RFC 4231's and the TLS_AES_256_GCM_SHA384 key schedule on the
# SHA-512 instructions. The Wycheproof host binary runs once more under
# the fourth, its HMAC-SHA-384 and HKDF-SHA-384 suites on them. The
# SHA-512 values are apart from the SHA-256 ones because a binary run
# under a value that names instructions its CPU lacks skips, and an arm64
# CPU may have FEAT_SHA256 without FEAT_SHA512. Under
# CH_REQUIRE_HASH_INSTRUCTIONS=1 such a binary fails instead
# (test/test_cpu.h).
#   0x25  the probe's bit, the multiply bit and CH_CPU_CONSTANT_TIME_SHA256
#   0x27  those and the AES bit
#   0x65  the first with CH_CPU_CONSTANT_TIME_SHA512, on arm64
#   0x67  the second with it, on arm64
HASH_UNIT_CPU := 0x25
HASH_WYCHEPROOF_CPU := 0x27 $(if $(X86_KERNEL_PROBE),,0x67)
HASH512_UNIT_CPU := $(if $(X86_KERNEL_PROBE),,0x65)
# The exporter of RFC 9846 section 7.5, off by default. EXPORTER=on adds
# ch_export to the public API and 32 bytes to ch_tls, so a device build
# that exports nothing pays neither: docs/performance.md's SRAM numbers
# are the default build's and this axis leaves them alone.
#
# It raises HKDF_LABEL_MAX with it, because the exporter's label is the
# caller's and RFC 9266's is 24 bytes against the 12 TLS 1.3 itself
# writes. hkdf.h states why that is a build parameter rather than a
# second serializer, and tls.c asserts the public cap and hkdf's agree.
# The two defines a build with the exporter carries. Named once, here,
# so the axis, the test binaries and the lint passes that read the
# exporter's sources all pass the same pair.
EXPORTER_DEF := -DCH_EXPORTER -DHKDF_LABEL_MAX=32
EXPORTER ?= off
ifeq ($(EXPORTER),on)
# ch_export lives in tls.c, which a QUIC object does not compile
# (QUIC_REPLACED), so that object could list the call and never define
# it. RFC 9001 keys QUIC from the handshake secrets directly and uses no
# TLS exporter, and the h2 caller this axis exists for runs over
# records; a QUIC exporter is a separate change with its own entry in
# quic.h, not a symbol this axis can promise. keysched.h refuses the
# same pair for a firmware tree that builds these sources its own way.
ifeq ($(TRANSPORT),quic-nonblocking)
$(error EXPORTER=on has no QUIC entry point: ch_export is a record-layer call, so use TRANSPORT=tcp-blocking or TRANSPORT=tcp-nonblocking)
endif
LIB_DEF += $(EXPORTER_DEF)
PUBLIC_EXPORT := ch_export
else ifeq ($(EXPORTER),off)
PUBLIC_EXPORT :=
else
$(error EXPORTER=$(EXPORTER) is not a setting; use EXPORTER=on or EXPORTER=off)
endif
# The key log (keylog.h), off by default. KEYLOG=on hands each traffic
# secret to a hook the image defines, which is the one path by which a
# secret leaves chapulin on purpose, so a device client refuses it: a
# raw or ca trust mode under ROLE=client is a pinned firmware image.
# TRUST=webpki, the server's TRUST=none and ROLE=both are admitted,
# because colibri's interop endpoint logs in both roles and over QUIC.
# keylog.h refuses the same device builds for a tree with its own build
# system. The object exports nothing new; it imports ch_keylog, which
# lib-check admits as a hook because no source here defines it.
#
# `make check KEYLOG=on` is refused at the default ROLE=client
# TRUST=raw-rsa by design, the way `make check TRUST=none` is; the axis
# is checked by its own library builds in check instead.
KEYLOG ?= off
ifeq ($(KEYLOG),on)
ifeq ($(ROLE),client)
ifneq ($(TRUST),webpki)
$(error KEYLOG=on is refused for a device client: use TRUST=webpki, ROLE=server or ROLE=both)
endif
endif
LIB_DEF += -DCH_KEYLOG
else ifneq ($(KEYLOG),off)
$(error KEYLOG=$(KEYLOG) is not a setting; use KEYLOG=on or KEYLOG=off)
endif
# SUITE=aesgcm, refused the same way for a device client. A raw or ca
# client pins the endpoint it talks to and offers ChaCha20 alone, so the
# AES suite would sit in its object unused (docs/decisions.md entry 45).
# A TRUST=webpki client offers both suites, and a server role selects AES
# from a client that offers nothing else. handshake_message.c refuses
# the define for a tree with its own build system.
ifeq ($(SUITE)-$(ROLE),aesgcm-client)
ifneq ($(TRUST),webpki)
$(error SUITE=aesgcm is refused for a device client: use TRUST=webpki, ROLE=server or ROLE=both)
endif
endif
# The widening multiply (ct.h). A host object holds both multiplies, and
# each session's CH_CPU_CONSTANT_TIME_MULTIPLY bit in ch_cfg.cpu picks one
# for every operation built on the multiply (widemul.h, docs/decisions.md
# 87 and 89). Each file built on it that the object carries compiles as a
# WIDEMUL=decomposed device object compiles it. Two of them compile once
# more as their _native.c copies, WIDEMUL_COPIED below; poly1305_vector.c
# and poly1305_avx2.c, whose paths run on the native multiply alone, join
# as their native copies only; and x25519.c, p256_field.c, p256_scalar.c and rsa_sign.c have no
# native copy, because their second copies are the wide files and the
# 64-bit signer above. The builder states nothing about the part, so a
# host object takes no CH_NATIVE_WIDEMUL, and ct.h refuses one beside
# -DCH_CPU_RUNTIME.
#
# A device object takes the WIDEMUL variable. WIDEMUL=decomposed, the
# default, builds every widening product from 16x16 pieces and claims
# nothing about the CPU. WIDEMUL=native defines CH_NATIVE_WIDEMUL in the
# object: the builder states that this part's widening multiply runs in
# constant time, which ct.h says firmware does only with a vendor
# statement. LIB_CFLAGS filters the host test flags out, so no object is
# compiled with them: this is the one supported way to ask for the native
# multiply, and LIB_VARIANT and the object's cc-stamp record the choice.
# A host object takes no WIDEMUL value, as it takes no AES value, and the
# test is $(origin WIDEMUL) for the same reason.
WIDEMUL_COPIED := poly1305.c mlkem_poly.c
# A native copy preprocesses only under -DCH_CPU_RUNTIME, because ct.h
# refuses one anywhere else, so lint-quic-partition judges each with it.
QUIC_EXTRA_DEFINES += $(foreach f,$(WIDEMUL_COPIED),$(f:.c=_native.c):-DCH_CPU_RUNTIME) \
                      poly1305_vector_native.c:-DCH_CPU_RUNTIME poly1305_avx2_native.c:-DCH_CPU_RUNTIME
# The copies on the hash instructions preprocess only under
# -DCH_CPU_RUNTIME too, because hash_hw.h refuses one anywhere else
# (docs/decisions.md 93), and sha256_hw.c holds its body under the define.
QUIC_EXTRA_DEFINES += hash_hw.h:-DCH_CPU_RUNTIME hkdf_hw.c:-DCH_CPU_RUNTIME keysched_hw.c:-DCH_CPU_RUNTIME \
                      sha256_hw.c:-DCH_CPU_RUNTIME sha512_hw.c:-DCH_CPU_RUNTIME \
                      keccak_hw.h:-DCH_CPU_RUNTIME sha3_hw.c:-DCH_CPU_RUNTIME mlkem_hw.c:-DCH_CPU_RUNTIME \
                      mlkem_poly_hw.c:-DCH_CPU_RUNTIME
# So does ML-KEM's copy for the four-way Keccak, whose mlkem_avx2.h refuses
# one anywhere else (docs/decisions.md 107).
QUIC_EXTRA_DEFINES += keccak_avx2.c:-DCH_CPU_RUNTIME mlkem_avx2.h:-DCH_CPU_RUNTIME \
                      mlkem_avx2.c:-DCH_CPU_RUNTIME
# What a host test binary compiles with, and what it links
# (docs/decisions.md 89). HOST_CFLAGS is the test flags without the host's
# CH_NATIVE_WIDEMUL, which ct.h refuses beside -DCH_CPU_RUNTIME, because a
# host object takes the multiply's timing from each session; each rule
# adds -DCH_CPU_RUNTIME, or HOST_SUITE_DEF, which holds it. host_srcs is
# $(1) and what a host object holds beside each of its files: the native
# copy of each that has one, the wide field beside x25519.c and the wide
# P-256 files beside p256_point.c, which widemul.h's dispatchers call, the
# two vector sources beside chacha20.c, the vector Poly1305 and the AVX2
# Poly1305, as their native copies, beside poly1305.c, the 64-bit Montgomery arithmetic beside
# rsa_mont.c, which calls it, the 64-bit signer beside rsa_sign.c, the
# vector NTT and the four-way Keccak's two files beside mlkem.c, and the
# hash sources below beside the files they stand beside.
HOST_CFLAGS = $(filter-out $(HOST_WIDEMUL_DEF),$(CFLAGS))
widemul_native_of = $(patsubst %.c,%_native.c,$(filter $(WIDEMUL_COPIED),$(1)))
# What a host object holds beside its hash files (docs/decisions.md 93):
# sha256_hw.c, SHA-256 on the CPU's SHA-256 instructions, beside sha256.c,
# sha512_hw.c, SHA-512 and SHA-384 on arm64's SHA-512 instructions, beside
# sha512.c, and hkdf.c and keysched.c compiled once more over them, as
# hkdf_hw.c and keysched_hw.c. A session's CH_CPU_CONSTANT_TIME_SHA256 and
# CH_CPU_CONSTANT_TIME_SHA512 bits pick them, and a device object holds
# none. sha512_hw.c has no body on x86-64, which has no such instructions.
# The same for Keccak (docs/decisions.md 99): sha3_hw.c, SHA-3 and SHAKE on
# arm64's SHA-3 instructions, beside sha3.c, and mlkem.c and mlkem_poly.c
# compiled once more over it, as mlkem_hw.c and mlkem_poly_hw.c, which a
# session's CH_CPU_CONSTANT_TIME_SHA3 bit picks. The three have a body
# where clang compiles an arm64 object and none anywhere else (cpu_cfg.h).
hash_hw_of = $(if $(filter sha256.c,$(1)),sha256_hw.c) $(if $(filter sha512.c,$(1)),sha512_hw.c) \
             $(if $(filter hkdf.c,$(1)),hkdf_hw.c) $(if $(filter keysched.c,$(1)),keysched_hw.c) \
             $(if $(filter sha3.c,$(1)),sha3_hw.c) $(if $(filter mlkem.c,$(1)),mlkem_hw.c) \
             $(if $(filter mlkem_poly.c,$(1)),mlkem_poly_hw.c)
host_srcs = $(1) $(call widemul_native_of,$(1)) $(if $(filter x25519.c,$(1)),x25519_wide.c) \
            $(if $(filter p256_point.c p256.c,$(1)),$(P256_WIDE_SRCS)) \
            $(if $(filter p256.c,$(1)),$(filter-out $(1),p256_scalar.c ct_wipe.c)) \
            $(if $(filter p384.c,$(1)),$(P384_WIDE_SRCS)) \
            $(if $(filter chacha20.c,$(1)),$(CHACHA_VECTOR_SRCS)) \
            $(if $(filter poly1305.c,$(1)),poly1305_vector_native.c poly1305_avx2_native.c) \
            $(if $(filter rsa_mont.c,$(1)),$(RSA_MONT64_SRCS)) \
            $(if $(filter rsa_sign.c,$(1)),$(RSA_SIGN64_SRCS)) \
            $(if $(filter mlkem.c,$(1)),mlkem_vector.c keccak_avx2.c mlkem_avx2.c) \
            $(call hash_hw_of,$(1))
WIDEMUL ?= decomposed
ifneq ($(CPU_RUNTIME_DEF),)
ifneq ($(origin WIDEMUL),file)
$(error WIDEMUL=$(WIDEMUL) chooses a device object's multiply, and TRUST=$(TRUST) ROLE=$(ROLE) on this compiler builds a host object, which holds both multiplies and picks one per session from ch_cfg.cpu (docs/decisions.md 89): drop WIDEMUL, or set HOST_TARGET empty for the device object)
endif
LIB_SRCS += $(patsubst %.c,%_native.c,$(filter $(WIDEMUL_COPIED),$(LIB_SRCS)))
else ifeq ($(WIDEMUL),native)
LIB_DEF += -DCH_NATIVE_WIDEMUL
else ifneq ($(WIDEMUL),decomposed)
$(error WIDEMUL=$(WIDEMUL) is not a multiply; use WIDEMUL=decomposed or WIDEMUL=native)
endif
# A host object holds Poly1305's block loop four blocks at a time on the
# vector widening multiply, as poly1305_vector_native.c, which
# poly1305_native.c's loop calls, so a session with the multiply bit runs
# it and no other does. An x86-64 host object holds the AVX2 kernel beside
# it, eight blocks at a time, as poly1305_avx2_native.c, which a session
# with the multiply bit and CH_CPU_AVX2 runs; the file has no body on
# arm64. A device object holds poly1305.c's loop alone, on the multiply
# WIDEMUL names: poly1305_vector.h turns the path on in a host object's
# native copy and nowhere else. docs/decisions.md entries 83, 89 and 110
# say why.
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += poly1305_vector_native.c poly1305_avx2_native.c
endif
# A host object holds SHA-256 on the CPU's instructions and the two copies
# over it (hash_hw_of above); a session's hash bit picks them, and a device
# object holds the portable hash alone. It holds sha512_hw.c only with
# SUITE=aesgcm, whose key schedule and transcript run SHA-384 under a
# session's value. A TRUST=webpki object without the suite hashes
# certificates with sha512.c through calls that take no value, so no call
# in it would run sha512_hw.c, and it leaves the file out.
ifneq ($(CPU_RUNTIME_DEF),)
LIB_SRCS += $(filter-out $(if $(SUITE_DEF),,sha512_hw.c),$(call hash_hw_of,$(LIB_SRCS)))
endif
# The most plaintext one outgoing TLS record carries, cfg.h's CH_TX_PT.
# Empty, the default, leaves cfg.h's 512, which keeps a device's ch_tls
# small. TX_RECORD=N writes -DCH_TX_PT=N into the object, for a host that
# sends bulk data: a 5 MiB upload takes 10,240 records at 512 and 320 at
# 16384. N is a decimal integer from 512 to 16384, the most plaintext RFC
# 9846 section 5.1 lets one record carry, and session.h grows ch_tls.tx to
# hold one sealed record of N bytes (docs/decisions.md 71). A QUIC object
# seals no TLS record, so it refuses the variable, the way the EXPORTER
# axis refuses that transport. cfg.h and session.h refuse the same values
# for a firmware tree that builds these sources its own way, and
# test/tx-record-builds.sh checks all three places at each edge.
TX_RECORD ?=
ifneq ($(TX_RECORD),)
ifeq ($(TRANSPORT),quic-nonblocking)
$(error TX_RECORD=$(TX_RECORD) sizes a TLS record, and TRANSPORT=quic-nonblocking seals none: drop TX_RECORD, or use TRANSPORT=tcp-blocking or TRANSPORT=tcp-nonblocking)
endif
ifneq ($(shell echo '$(TX_RECORD)' | awk '/^[1-9][0-9]*$$/ && $$1 >= 512 && $$1 <= 16384'),$(TX_RECORD))
$(error TX_RECORD=$(TX_RECORD) is not a record size; use a decimal integer from 512 to 16384, or leave TX_RECORD empty for 512)
endif
LIB_DEF += -DCH_TX_PT=$(TX_RECORD)
endif
# Entropy pattern, and the one build variable with no default: RAND=extern
# leaves ch_rand_bytes undefined for the image to supply, RAND=drbg packages
# the reference generator and exports ch_drbg_seed so the image seeds it at
# boot, and ch_rand_bytes so the image can draw the output docs/entropy.md's
# seed file and reseed recipes need (docs/decisions.md 67), and
# RAND=session gives each session a source of its own in ch_cfg.rand_bytes
# and ch_cfg.rand_io, so the object neither defines nor imports
# ch_rand_bytes and packages no drbg.c (docs/decisions.md 77). None is a
# default because the choice is the point
# (https://github.com/c4milo/chapulin/issues/41): a weak generator completes
# the handshake and reports success, so the only thing a build can enforce is
# that somebody wrote the choice down. Naming none reaches cfg.h's #error,
# which is where a firmware tree compiling these sources with its own build
# system meets the same demand.
ifeq ($(RAND),drbg)
LIB_DEF += -DCH_RAND_DRBG
LIB_SRCS += drbg.c
PUBLIC_RAND := ch_drbg_seed ch_rand_bytes
else ifeq ($(RAND),extern)
LIB_DEF += -DCH_RAND_EXTERN
PUBLIC_RAND :=
else ifeq ($(RAND),session)
LIB_DEF += -DCH_RAND_SESSION
PUBLIC_RAND :=
else ifneq ($(RAND),)
$(error RAND=$(RAND) is not an entropy pattern; use RAND=extern, RAND=drbg or RAND=session)
endif
# CBMC intrinsics don't compile under clang-tidy/cppcheck; harnesses get
# clang-format only. Fuzzers include .c files for statics, same deal.
PROOF_C := $(wildcard proof/*.c) $(wildcard proof/*.h)
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
# The objects test/localize-check.sh localizes: formatted, and outside
# LINT_C, because zig compiles them for eleven targets rather than with the
# host flags, and entry.c defines _start.
LOCALIZE_C := $(wildcard test/localize/*.c)

# Firmware links bin/chapulin.o: one relocatable object exposing exactly
# the symbols PUBLIC names: its calls, four under TRANSPORT=tcp-blocking, sixteen
# under TRANSPORT=quic-nonblocking and five under ROLE=server, and in every variant
# one data symbol, the build record, named for the transport:
# ch_build_info_tcp_blocking, ch_build_info_tcp_nonblocking or ch_build_info_quic_nonblocking. Partial linking merges
# the modules; nmedit (macOS) or objcopy (everything else) localizes
# every other symbol, so the library cannot collide with application
# names, and test/lib-pair-check.sh links two objects of different
# transports into one image (docs/decisions.md 61). lib-check enforces
# the export list as part of check. Objects live under the variant that
# built them, so switching PIN, TRUST, KEX, RAND, TRANSPORT or ROLE
# never reuses a stale object. TRANSPORT belongs here for a reason the other
# four share and it sharpens: the two transports link different object
# lists into chapulin.o, so without it a TRANSPORT=tcp-blocking chapulin.o and a
# TRANSPORT=quic-nonblocking one write to the same path, make 3.81 compares mtimes
# to the second, and the second link reuses the first object -- the
# failure the paragraph below records for RAND.
# SUITE belongs here for the same reason: -DCH_SUITE_AES_GCM changes
# record.o and adds three objects, so the two suites must not share a
# directory.
# TX_RECORD belongs here because -DCH_TX_PT can change sizeof(ch_tls) and
# so every object that reads it. It is added only when set, so the default
# object keeps the directory it had.
# The host test's result belongs here because -DCH_CPU_RUNTIME changes
# ch_cfg and every object that reads it, and a check can build a server's
# device object beside its host object. It is added only for a host
# object, for TX_RECORD's reason.
LIB_VARIANT := $(TRUST)-$(KEX_VARIANT)-$(RAND)-$(TRANSPORT)-$(AES)-$(SUITE)-$(ROLE)-$(EXPORTER)-$(KEYLOG)-$(WIDEMUL)$(if $(TX_RECORD),-tx$(TX_RECORD))$(if $(CPU_RUNTIME_DEF),-host)
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
# Both lines from one target, sources first, so one recursive make answers
# lint-trust-separation's row in a fixed order even under -j.
.PHONY: print-lib-lists
print-lib-lists:
	@echo $(LIB_SRCS)
	@echo $(LIB_DEF)
# test/zig-build-check.sh builds make's object under a CFLAGS of its own when
# a configuration states a hardware claim, and starts from these flags, as
# check's lib-check builds start from $(CFLAGS). It and the bench scripts
# ask for the host test's result for the reason check's targets read it:
# yes when this compiler builds a host object, and empty when it does not.
.PHONY: print-lib-cflags print-host-target
print-lib-cflags:
	@echo $(LIB_CFLAGS)
print-host-target:
	@echo $(HOST_TARGET)
# bench/aead.sh and bench/record.sh link the AES instructions' sources from
# here rather than from a list of their own: bench/aead.sh's list once
# lacked gcm_hw.c, and bench.yml's aead job failed to link.
.PHONY: print-aes-hw-srcs
print-aes-hw-srcs:
	@echo $(AES_HW_SRCS)
# bench/primitives.sh builds its handshake program from the sources
# bin/tcp_nonblocking_loop_test links, and asks here rather than
# keeping its own list, for the reason bench/device-ram.sh does.
.PHONY: print-tcp-nonblocking-loop-srcs
print-tcp-nonblocking-loop-srcs:
	@echo $(TCP_NONBLOCKING_LOOP_SRCS)
# bench/primitives.sh builds its host object programs from HOST_SRCS_OF, a
# list it passes, as a host object holds those sources: with the native
# copy of each file that has one and the wide X25519 field (host_srcs).
.PHONY: print-host-srcs
print-host-srcs:
	@echo $(call host_srcs,$(HOST_SRCS_OF))
# test/aes-runtime-qemu.sh builds its binaries for x86-64 and for arm64
# from the sources their rules here link, one list per line:
# bin/quic_loop_aes, bin/webpki_loop_aes, bin/aes_runtime_test beside its
# three test files, bin/quic_test_hw beside test/quic_vectors.c,
# bin/x86_kernels_test beside its two, bin/sha2_equiv_test beside its one,
# the two lists bin/hash_runtime_test links beside its one, of which
# bin/hash_runtime_exporter_test links the first, bin/p256_equiv_test
# beside its one, bin/sha3_hw_equiv_test and bin/mlkem_hw_equiv_test
# beside theirs, bin/mlkem_vector_equiv_test and
# bin/mlkem_avx2_equiv_test beside their one each, and
# bin/poly1305_equiv_test beside its one.
.PHONY: print-aes-runtime-qemu-srcs
print-aes-runtime-qemu-srcs:
	@echo $(call host_srcs,$(QUIC_LOOP_AES_SRCS))
	@echo $(WEBPKI_LOOP_AES_SRCS)
	@echo $(AES_RUNTIME_TEST_SRCS)
	@echo $(QUIC_TEST_HW_SRCS)
	@echo $(X86_KERNELS_TEST_SRCS)
	@echo $(SHA2_EQUIV_TEST_SRCS)
	@echo $(HASH_RUNTIME_TEST_SRCS)
	@echo $(HASH_RUNTIME_QUIC_SRCS)
	@echo $(P256_EQUIV_TEST_SRCS)
	@echo $(SHA3_HW_EQUIV_TEST_SRCS)
	@echo $(MLKEM_HW_EQUIV_TEST_SRCS)
	@echo $(MLKEM_VECTOR_EQUIV_TEST_SRCS)
	@echo $(MLKEM_AVX2_EQUIV_TEST_SRCS)
	@echo $(POLY1305_EQUIV_TEST_SRCS)

# The mode partition, checked from the build variables rather than
# assumed from the ifeq chain above. Each axis value names the sources
# its packaged object must carry and the sources it must not, and the
# defines likewise. A value whose filter stops matching a renamed file,
# or a new value that forgets its filter, fails here rather than in a
# consumer's link. The check reads print-lib-srcs and print-lib-def
# through a recursive make per axis value, so it costs no build; the
# command-line value overrides whatever the outer make was given. The
# The KEX rows name TRUST as well, because `make check TRUST=webpki`
# would otherwise hand that value to their recursions and measure a
# different object than the row names. A TRUST=webpki object carries the
# ML-KEM sources whatever KEX says and never defines CH_KEX_PQ, and the
# last KEX rows require the Makefile to refuse either KEX value for a
# build whose key exchange KEX does not choose: a webpki client, ROLE=both
# and ROLE=server (docs/decisions.md 53).
# The recursions pass --no-print-directory: GNU make 4 turns on -w for
# a sub-make, and `make ci` runs this lint from one, so its captured
# output would otherwise start with an "Entering directory" line and
# the last name on a list would sit before a newline, not the space the
# match below wants. `make -w lint-trust-separation` reproduces that.
#
# The transport rows read their file list the same way, from git's
# quic*.c at the root, so a QUIC_SRCS that loses a file fails here
# instead of leaving that file out of the object. The AES and GCM
# sources a SUITE=aesgcm build compiles carry no quic prefix, because
# that build compiles them over TCP too, so the rows read a second list
# from git's aes*.c, gcm*.c and ghash*.c at the root: the TCP row, which
# builds the default ChaCha20 suite, bans every file on both lists, and
# the QUIC rows require aes.c and gcm.c, what remains of the second list
# once the instructions' four sources and aes_extern.c come out. The three
# AES implementations, quic_aes_soft.c, aes_hw.c and aes_extern.c, come
# out of the two lists and get rows of their own. A device object holds
# exactly one of the table and aes_extern.c, because the two define the
# same entries and a second one would not link, the way the PIN rows hold
# the pinned algorithm to one. A host object holds aes_hw.c, with
# ghash_hw.c, gcm_hw.c and gcm_vaes.c, and in a QUIC object the table
# beside it under names of its own, the one pair docs/decisions.md 81 and
# 89 admit; its rows require them, ban aes_extern.c and require
# -DCH_CPU_RUNTIME, and every device row bans the four and that define,
# because a device object runs gcm.c's portable GHASH and one-block
# counter loop and no second one. A TCP host object without the suite
# holds no AES at all. gcm_vaes.c's 256-bit kernels sit beside gcm_hw.c in
# every object that holds it, and compile to nothing outside x86-64
# (docs/decisions.md 90). A build that names AES=hw or AES=runtime, the
# values that chose the instructions at build time, must be refused, and
# so must a host object that names an AES value. They name TRANSPORT
# explicitly on both sides, because a `make check TRANSPORT=quic-nonblocking` hands
# its value to every recursion below, and the TRANSPORT=tcp-blocking row must
# read the transport it names. The quic rows name EXPORTER=off for the
# same reason in the other direction: the EXPORTER axis refuses
# TRANSPORT=quic-nonblocking by name, so a `make check EXPORTER=on` that handed its
# value to those recursions would die in a row rather than in a build
# anyone asked for.
#
# Two quic*.c files belong to one role. quic_step.c is the client's step
# table, so the QUIC server row bans it. quic_token.c mints and checks
# the Retry token, which only a server does, so it leaves the transport
# rows' list with the AES implementations: the client row bans it and the
# QUIC server row requires it.
#
# The role rows read their file list the same way, from git's srv*.c at
# the root, and they name TRUST and TRANSPORT on both sides because the
# ROLE=server arm stops the build on any other value of the two, and a
# recursion inherits whatever the outer make was given: without
# TRUST=raw-rsa here, `make check TRUST=webpki` would reach that error
# arm. This is
# the check that fails on an axis whose ROLE_FILTER, ROLE_ADD or
# ROLE_DEF never reached LIB_SRCS or LIB_DEF; a partition tool that
# preprocessed the sources could not do it, because a source list is not
# text in a file.
#
# Three of git's srv*.c files are drivers, one per transport:
# srv_handshake.c for TRANSPORT=tcp-blocking, srv_quic.c for TRANSPORT=quic-nonblocking and
# srv_tcp_nonblocking.c for TRANSPORT=tcp-nonblocking. A server object
# carries exactly one of the three, so each role row names its own and
# bans the other two, and srv_shared holds what every server object
# carries whatever the transport. The rows subtracted one driver name
# from the whole git list instead until srv_tcp_nonblocking.c landed and
# made the third: subtraction says which driver a row skips, and a row
# has to say which one it wants.
# srv_shared keeps the property that shape had -- a new srv*.c file that
# is not a driver lands there, so every role row requires it and an arm
# that forgot to add it fails here. Every server row also requires the
# ML-KEM-768 and SHA-3 sources and bans -DCH_KEX_PQ, because a server
# role holds the hybrid in every build and KEX chooses nothing for it
# (docs/decisions.md 54).
#
# The webpki rows read their file lists from nowhere the build reads
# them: the chain verifiers are written out, and the webpki*.c files are
# the ones git tracks at the root. A filter that loses a webpki file
# then fails here instead of passing against its own mistake. The same
# git list is what the TRUST=webpki rows require, so a root webpki*.c
# file that git tracks and WEBPKI_SRCS leaves out fails those rows
# instead of being left out of the object. The lint also fails when git
# names no webpki file at all.
# The SUITE=aesgcm rows hold a suite object to a cipher with no table for
# its traffic keys and to SHA-384, for the host object and for a device
# object on AES=extern, over TCP and over QUIC. The host rows require
# aes_hw.c, ghash_hw.c, gcm_hw.c and gcm_vaes.c and -DCH_CPU_RUNTIME, and
# ban aes_extern.c; the TCP one bans the table too, and the QUIC one holds
# it for the public keys alone (aes_schedule.h). The AES=extern rows set
# HOST_TARGET empty, the result a compiler for a device gives, require
# aes_extern.c and ban the table and the instructions' four sources,
# because that object runs gcm.c's portable GHASH and counter loop. Every
# suite row requires the two SHA-512 files and bans -DCH_AES_256_TEST, the
# define that compiles the software AES-256 for the tests and proofs; the
# QUIC rows ban that define too. A packaged object that carried it would
# hold a software AES-256 no secret key may reach. Every suite row also
# bans -DCH_AES_EXTERN_CONSTANT_TIME: the Makefile never writes it,
# because it is the firmware author's claim about a part
# (docs/decisions.md 68). A host object's claim is the caller's
# CH_CPU_CONSTANT_TIME_AES, made at run time (docs/decisions.md 89).
#
# test/violations/inv05-webpki-source-in-raw.violation drops the webpki
# files from TRUST=raw-rsa's filter, and
# test/violations/inv05-webpki-source-unlisted.violation drops one file
# from WEBPKI_SRCS; each requires this lint to fail.
#
# Every row requires build.c too, because every object exports the build
# record it defines (docs/decisions.md 56), so a filter that drops it
# from one variant fails here rather than in that variant's link.
#
# The ChaCha20 rows hold chacha20_vector.c and chacha20_avx2.c to the host
# object, so a device object carries the portable loop alone, and require
# every value of the CHACHA variable to stop the build, which is gone
# (docs/decisions.md 89). Every row bans -DCH_CHACHA_VECTOR, which no
# source reads.
#
# The hash rows hold sha256_hw.c, hkdf_hw.c and keysched_hw.c to the host
# object, over TCP and over QUIC, beside the three files they stand
# beside, so a device object carries the portable hash alone. They hold
# sha512_hw.c to the host object with SUITE=aesgcm: a host object without
# the suite packages sha512.c for its certificates and no sha512_hw.c
# (docs/decisions.md 93). The Keccak rows hold sha3_hw.c, mlkem_hw.c and
# mlkem_poly_hw.c to the host object beside sha3.c, mlkem.c and
# mlkem_poly.c, so a KEX=pq device object carries the portable Keccak alone
# (docs/decisions.md 99). The same rows hold mlkem_vector.c, the vector
# NTT, to the host object, so a device object carries mlkem_poly.c's loops
# alone (docs/decisions.md 101), and keccak_avx2.c and mlkem_avx2.c, the
# four-way Keccak and ML-KEM's copy over it, so a device object samples its
# matrix on sha3.c alone (docs/decisions.md 107).
#
# The WIDEMUL rows hold -DCH_NATIVE_WIDEMUL to the device object that
# asks for it, and every native copy to the host object: a host row
# requires each copied file beside its _native.c copy, and the vector
# Poly1305 and the AVX2 Poly1305 as their native copies alone, and every
# device row bans the copies. rsa_sign.c has no native copy, and the RSA
# rows hold its second copy. No row packages poly1305_vector.c or
# poly1305_avx2.c under its own name. A host
# object takes no WIDEMUL value, and WIDEMUL=runtime is gone
# (docs/decisions.md 87 and 89).
#
# The X25519 rows hold x25519.c to every object and x25519_wide.c to the
# host object, with no native copy of x25519.c in any, and require every
# value of the X25519 variable to stop the build, which is gone
# (docs/decisions.md 89).
#
# The P-256 rows hold p256_field.c, p256_scalar.c and p256_point.c to
# every object that carries the curve and the wide files to the host
# object, with no native copy of the field or the scalar in any
# (docs/decisions.md 94).
# The RSA rows hold rsa_mont64.c, the 64-bit arithmetic rsa_mont.c calls
# in a host object, to the host object beside rsa_mont.c, and out of every
# device object, and rsa_sign64.c, the signer on those words, to the host
# object that holds rsa_sign.c (docs/decisions.md 95).
#
# The RAND rows hold each entropy pattern to its one define, and drbg.c,
# the reference generator, to the RAND=drbg object alone: a RAND=session
# object packages no generator, because each session names its own source
# (docs/decisions.md 77).
#
# The host rows set the host test's result on their own command line,
# HOST_TARGET=yes or empty, so they read the same on every compiler. On a
# host target the four device clients define no -DCH_CPU_RUNTIME, and a
# TRUST=webpki client, ROLE=server and ROLE=both, raw client half and all,
# define it; on any other target none of the three does
# (docs/decisions.md 89). Each row names ROLE and TRUST, because a
# recursion inherits the outer make's values.
#
# Each row runs as its own background job and prints into a file of its
# own, and the files print in row order once every row has ended, so the
# rows run at once and their lines never interleave. A row prints only
# its failures, so a file that is not empty is a row that failed. Each
# row asks one recursive make for both lists.
#
# The lint reads the Makefile, the files it includes and git's list of
# files, never a file's content, so its stamp covers those files and the
# names git lists (tools/stamp.py). A Makefile change that makes a source
# list depend on what a file holds must add that file to the stamp.
.PHONY: lint-trust-separation lint-trust-separation-run
lint-trust-separation:
	@python3 tools/stamp.py lint-trust-separation --names . $(STAMP_MAKEFILES) \
	  --output '$(CC) --version' \
	  -- $(MAKE) --no-print-directory lint-trust-separation-run
lint-trust-separation-run:
	@rc=0; rows=$$(mktemp -d); n=0; \
	row() { \
	  axis=$$1; want="$$2 build.c"; ban=$$3; wantdef=$$4; bandef=$$5; \
	  lists=$$($(MAKE) -s --no-print-directory -f $(firstword $(MAKEFILE_LIST)) print-lib-lists $$axis); \
	  srcs=" $$(printf '%s\n' "$$lists" | sed -n 1p) "; \
	  defs=" $$(printf '%s\n' "$$lists" | sed -n 2p) "; \
	  for f in $$want; do case "$$srcs" in *" $$f "*) ;; *) echo "lint-trust-separation: $$axis must package $$f";; esac; done; \
	  for f in $$ban; do case "$$srcs" in *" $$f "*) echo "lint-trust-separation: $$axis must not package $$f";; esac; done; \
	  for d in $$wantdef; do case "$$defs" in *" $$d "*) ;; *) echo "lint-trust-separation: $$axis must define $$d";; esac; done; \
	  for d in $$bandef; do case "$$defs" in *" $$d "*) echo "lint-trust-separation: $$axis must not define $$d";; esac; done; \
	}; \
	refused() { \
	  if $(MAKE) -s --no-print-directory -f $(firstword $(MAKEFILE_LIST)) print-lib-def $$1 KEX=$$2 >/dev/null 2>&1; then \
	    echo "lint-trust-separation: $$1 KEX=$$2 must be refused, because KEX does not choose that build's key exchange"; \
	  fi; \
	}; \
	refused_build() { \
	  if $(MAKE) -s --no-print-directory -f $(firstword $(MAKEFILE_LIST)) print-lib-def $$1 >/dev/null 2>&1; then \
	    echo "lint-trust-separation: $$1 must be refused, because $$2"; \
	  fi; \
	}; \
	check() { n=$$((n + 1)); row "$$@" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & }; \
	webpki_files=$$(git ls-files 'webpki*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$webpki_files" ] || { echo "lint-trust-separation: git tracks no webpki*.c file at the root, so the webpki rows would check nothing"; rc=1; }; \
	webpki_only="sha512.c sha512_compress.c p384.c p384_field.c p384_wide_field.c p384_wide_point.c p384_wide_verify.c rsa_pkcs1.c handshake_groups.c p256_ecdh.c p256_point.c p256_scalar.c p256_field.c $$webpki_files"; \
	check "TRUST=raw-rsa" "rsa.c rsa_mont.c" "p256.c pem.c x509.c x509_der.c x509_ca.c $$webpki_only" "" "-DCH_TRUST_CA -DCH_TRUST_WEBPKI -DCH_PIN_ECDSA"; \
	check "TRUST=raw-ecdsa" "p256.c" "rsa.c rsa_mont.c pem.c x509.c x509_der.c x509_ca.c $$webpki_only" "-DCH_PIN_ECDSA" "-DCH_TRUST_CA -DCH_TRUST_WEBPKI"; \
	check "TRUST=ca-rsa" "pem.c x509.c x509_der.c x509_ca.c rsa.c rsa_mont.c" "p256.c $$webpki_only" "-DCH_TRUST_CA" "-DCH_TRUST_WEBPKI -DCH_PIN_ECDSA"; \
	check "TRUST=ca-ecdsa" "pem.c x509.c x509_der.c x509_ca.c p256.c" "rsa.c rsa_mont.c $$webpki_only" "-DCH_TRUST_CA -DCH_PIN_ECDSA" "-DCH_TRUST_WEBPKI"; \
	check "TRUST=webpki" "x509_der.c rsa.c rsa_mont.c p256.c sha3.c mlkem.c mlkem_poly.c $$webpki_only" "pem.c x509.c x509_ca.c" "-DCH_TRUST_WEBPKI" "-DCH_TRUST_CA -DCH_PIN_ECDSA -DCH_KEX_PQ"; \
	check "TRUST=raw-rsa KEX=x25519" "x25519.c" "sha3.c mlkem.c mlkem_poly.c" "" "-DCH_KEX_PQ"; \
	check "TRUST=raw-rsa KEX=pq" "x25519.c sha3.c mlkem.c mlkem_poly.c" "" "-DCH_KEX_PQ" ""; \
	check "TRUST=raw-rsa" "x25519.c" "x25519_wide.c x25519_native.c" "" "-DCH_X25519_WIDE -DCH_NATIVE_MUL128"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "x25519.c x25519_wide.c" "x25519_native.c" "-DCH_CPU_RUNTIME" \
	  "-DCH_X25519_WIDE -DCH_NATIVE_MUL128"; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "x25519.c x25519_wide.c" "x25519_native.c" "-DCH_CPU_RUNTIME" \
	  "-DCH_X25519_WIDE -DCH_NATIVE_MUL128"; \
	check "ROLE=server TRUST=none HOST_TARGET=" "x25519.c" "x25519_wide.c x25519_native.c" "" \
	  "-DCH_X25519_WIDE -DCH_NATIVE_MUL128 -DCH_CPU_RUNTIME"; \
	for value in portable wide; do \
	  for axis in "TRUST=raw-rsa" "ROLE=client TRUST=webpki HOST_TARGET=yes" "ROLE=server TRUST=none HOST_TARGET="; do \
	    n=$$((n + 1)); refused_build "$$axis X25519=$$value" "X25519 is gone: a host object holds the wide field and each session's ch_cfg.cpu picks it" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	  done; \
	done; \
	p256_portable="p256_field.c p256_scalar.c p256_point.c"; \
	p256_gone="p256_field_native.c p256_scalar_native.c"; \
	check "TRUST=raw-rsa" "" "$$p256_portable $(P256_WIDE_SRCS) $$p256_gone" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "$$p256_portable $(P256_WIDE_SRCS)" "$$p256_gone" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "$$p256_portable $(P256_WIDE_SRCS)" "$$p256_gone" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=" "$$p256_portable" "$(P256_WIDE_SRCS) $$p256_gone" "" "-DCH_CPU_RUNTIME"; \
	check "TRUST=raw-rsa" "rsa_mont.c" "rsa_mont64.c" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "p384.c p384_field.c $(P384_WIDE_SRCS)" "" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=client TRUST=webpki HOST_TARGET=" "p384.c p384_field.c" "$(P384_WIDE_SRCS)" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "rsa_mont.c rsa_mont64.c" "" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "rsa_mont.c rsa_mont64.c rsa_sign.c rsa_sign64.c" "" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=client TRUST=webpki HOST_TARGET=" "rsa_mont.c" "rsa_mont64.c rsa_sign64.c" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=server TRUST=none HOST_TARGET=" "rsa_mont.c rsa_sign.c" "rsa_mont64.c rsa_sign64.c" "" "-DCH_CPU_RUNTIME"; \
	check "TRUST=raw-rsa" "chacha20.c" "chacha20_vector.c chacha20_avx2.c poly1305_vector.c poly1305_avx2.c" "" \
	  "-DCH_CHACHA_VECTOR"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "chacha20.c chacha20_vector.c chacha20_avx2.c" \
	  "poly1305_vector.c poly1305_avx2.c" "-DCH_CPU_RUNTIME" "-DCH_CHACHA_VECTOR"; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "chacha20.c chacha20_vector.c chacha20_avx2.c" \
	  "poly1305_vector.c poly1305_avx2.c" "-DCH_CPU_RUNTIME" "-DCH_CHACHA_VECTOR"; \
	check "ROLE=server TRUST=none HOST_TARGET=" "chacha20.c" \
	  "chacha20_vector.c chacha20_avx2.c poly1305_vector.c poly1305_avx2.c" "" \
	  "-DCH_CHACHA_VECTOR -DCH_CPU_RUNTIME"; \
	for value in portable vector; do \
	  for axis in "TRUST=raw-rsa" "ROLE=client TRUST=webpki HOST_TARGET=yes" "ROLE=server TRUST=none HOST_TARGET="; do \
	    n=$$((n + 1)); refused_build "$$axis CHACHA=$$value" "CHACHA is gone: a host object runs the vector ChaCha20 in every session, and a device object the portable loop" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	  done; \
	done; \
	hash_hw="sha256_hw.c hkdf_hw.c keysched_hw.c"; \
	check "TRUST=raw-rsa" "sha256.c hkdf.c keysched.c" "$$hash_hw sha512_hw.c" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "sha256.c hkdf.c keysched.c sha512.c $$hash_hw" "sha512_hw.c" \
	  "-DCH_CPU_RUNTIME" "-DCH_SUITE_AES_GCM"; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "sha256.c hkdf.c keysched.c $$hash_hw" "sha512_hw.c" "-DCH_CPU_RUNTIME" ""; \
	check "TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki EXPORTER=off HOST_TARGET=yes" \
	  "sha256.c hkdf.c keysched.c $$hash_hw" "sha512_hw.c" "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=" "sha256.c hkdf.c keysched.c" "$$hash_hw sha512_hw.c" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=server TRUST=none SUITE=aesgcm HOST_TARGET=yes" "sha512.c sha512_hw.c $$hash_hw" "" \
	  "-DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM" ""; \
	check "TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm EXPORTER=off HOST_TARGET=yes" \
	  "sha512.c sha512_hw.c $$hash_hw" "" "-DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM" ""; \
	check "ROLE=server TRUST=none SUITE=aesgcm AES=extern HOST_TARGET=" "sha512.c" "sha512_hw.c $$hash_hw" \
	  "-DCH_SUITE_AES_GCM" "-DCH_CPU_RUNTIME"; \
	keccak_hw="sha3_hw.c mlkem_hw.c mlkem_poly_hw.c mlkem_vector.c keccak_avx2.c mlkem_avx2.c"; \
	check "TRUST=raw-rsa KEX=pq" "sha3.c mlkem.c mlkem_poly.c" "$$keccak_hw" "" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "sha3.c mlkem.c mlkem_poly.c $$keccak_hw" "" \
	  "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "sha3.c mlkem.c mlkem_poly.c $$keccak_hw" "" \
	  "-DCH_CPU_RUNTIME" ""; \
	check "ROLE=server TRUST=none HOST_TARGET=" "sha3.c mlkem.c mlkem_poly.c" "$$keccak_hw" "" \
	  "-DCH_CPU_RUNTIME"; \
	native_files=$$(git ls-files '*_native.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$native_files" ] || { echo "lint-trust-separation: git tracks no *_native.c file at the root, so the WIDEMUL rows would check nothing"; rc=1; }; \
	check "TRUST=raw-rsa WIDEMUL=decomposed" "poly1305.c" "poly1305_vector.c poly1305_avx2.c $$native_files" "" \
	  "-DCH_NATIVE_WIDEMUL -DCH_CPU_RUNTIME"; \
	check "TRUST=raw-rsa WIDEMUL=native" "poly1305.c" \
	  "chacha20_vector.c chacha20_avx2.c poly1305_vector.c poly1305_avx2.c $$native_files" "-DCH_NATIVE_WIDEMUL" \
	  "-DCH_CHACHA_VECTOR -DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki HOST_TARGET=yes" "poly1305.c poly1305_native.c poly1305_vector_native.c \
	  poly1305_avx2_native.c mlkem_poly.c mlkem_poly_native.c" \
	  "poly1305_vector.c poly1305_avx2.c rsa_sign.c rsa_sign64.c" "-DCH_CPU_RUNTIME" "-DCH_NATIVE_WIDEMUL"; \
	check "ROLE=server TRUST=none HOST_TARGET=yes" "poly1305.c poly1305_native.c poly1305_vector_native.c \
	  poly1305_avx2_native.c mlkem_poly.c mlkem_poly_native.c \
	  rsa_sign.c" "poly1305_vector.c poly1305_avx2.c" "-DCH_CPU_RUNTIME" \
	  "-DCH_NATIVE_WIDEMUL"; \
	check "ROLE=server TRUST=none HOST_TARGET=" "poly1305.c mlkem_poly.c rsa_sign.c" \
	  "poly1305_vector.c poly1305_avx2.c $$native_files" "" "-DCH_NATIVE_WIDEMUL -DCH_CPU_RUNTIME"; \
	check "ROLE=server TRUST=none WIDEMUL=native HOST_TARGET=" "poly1305.c rsa_sign.c" \
	  "poly1305_vector.c poly1305_avx2.c $$native_files" "-DCH_NATIVE_WIDEMUL" "-DCH_CPU_RUNTIME"; \
	for value in decomposed native; do \
	  n=$$((n + 1)); refused_build "ROLE=server TRUST=none HOST_TARGET=yes WIDEMUL=$$value" "a host object holds both multiplies and takes no WIDEMUL value" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	done; \
	n=$$((n + 1)); refused_build "TRUST=raw-rsa WIDEMUL=runtime" \
	  "WIDEMUL=runtime put both multiplies in an object, and a host object holds them now and picks one per session from ch_cfg.cpu (docs/decisions.md 89)" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	check "TRUST=raw-rsa RAND=extern" "" "drbg.c" "-DCH_RAND_EXTERN" "-DCH_RAND_DRBG -DCH_RAND_SESSION"; \
	check "TRUST=raw-rsa RAND=drbg" "drbg.c" "" "-DCH_RAND_DRBG" "-DCH_RAND_EXTERN -DCH_RAND_SESSION"; \
	check "TRUST=raw-rsa RAND=session" "" "drbg.c" "-DCH_RAND_SESSION" "-DCH_RAND_EXTERN -DCH_RAND_DRBG"; \
	for axis in "ROLE=client TRUST=raw-rsa" "ROLE=client TRUST=raw-ecdsa" "ROLE=client TRUST=ca-rsa" "ROLE=client TRUST=ca-ecdsa"; do \
	  check "$$axis HOST_TARGET=yes" "" "" "" "-DCH_CPU_RUNTIME"; \
	done; \
	for axis in "ROLE=client TRUST=webpki" "ROLE=server TRUST=none" "ROLE=both TRUST=raw-rsa" "ROLE=both TRUST=webpki"; do \
	  check "$$axis HOST_TARGET=yes" "" "" "-DCH_CPU_RUNTIME" ""; \
	  check "$$axis HOST_TARGET=" "" "" "" "-DCH_CPU_RUNTIME"; \
	done; \
	for axis in "TRUST=webpki ROLE=client" "TRUST=webpki ROLE=both" "TRUST=none ROLE=server"; do \
	  for k in x25519 pq; do \
	    n=$$((n + 1)); refused "$$axis" $$k > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	  done; \
	done; \
	quic_files=$$(git ls-files 'quic*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$quic_files" ] || { echo "lint-trust-separation: git tracks no quic*.c file at the root, so the transport rows would check nothing"; rc=1; }; \
	quic_always=$$(printf '%s\n' $$quic_files | grep -vxF -e quic_aes_soft.c -e quic_token.c | tr '\n' ' '); \
	aes_files=$$(git ls-files 'aes*.c' 'gcm*.c' 'ghash*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$aes_files" ] || { echo "lint-trust-separation: git tracks no aes*.c, gcm*.c or ghash*.c file at the root, so the AES rows would check nothing"; rc=1; }; \
	instructions="aes_hw.c ghash_hw.c gcm_hw.c gcm_vaes.c"; \
	aes_always=$$(printf '%s\n' $$aes_files | grep -vxF -e aes_hw.c -e ghash_hw.c -e gcm_hw.c -e gcm_vaes.c -e aes_extern.c | tr '\n' ' '); \
	check "TRANSPORT=tcp-blocking" "io.c record.c session.c handshake.c tls.c tls_write.c" "$$quic_files $$aes_files" "" "-DCH_TRANSPORT_QUIC_NONBLOCKING"; \
	check "TRANSPORT=quic-nonblocking EXPORTER=off" "$$quic_always $$aes_always quic_aes_soft.c" "io.c record.c session.c handshake.c tls.c tls_write.c $$instructions aes_extern.c quic_token.c" "-DCH_TRANSPORT_QUIC_NONBLOCKING" "-DCH_AES_EXTERN -DCH_CPU_RUNTIME -DCH_AES_256_TEST"; \
	check "TRANSPORT=quic-nonblocking AES=soft EXPORTER=off" "quic_aes_soft.c" "$$instructions aes_extern.c" "" "-DCH_AES_EXTERN -DCH_CPU_RUNTIME"; \
	check "TRANSPORT=quic-nonblocking AES=extern EXPORTER=off" "aes_extern.c" "quic_aes_soft.c $$instructions" "-DCH_AES_EXTERN" "-DCH_CPU_RUNTIME"; \
	check "ROLE=client TRUST=webpki TRANSPORT=quic-nonblocking EXPORTER=off HOST_TARGET=yes" "$$quic_always $$aes_always $$instructions quic_aes_soft.c" "aes_extern.c quic_token.c" "-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME" "-DCH_AES_EXTERN -DCH_AES_256_TEST"; \
	check "ROLE=client TRUST=webpki TRANSPORT=tcp-nonblocking HOST_TARGET=yes" "" "$$quic_files $$aes_files" "-DCH_CPU_RUNTIME" "-DCH_SUITE_AES_GCM -DCH_AES_EXTERN"; \
	for value in hw runtime; do \
	  n=$$((n + 1)); refused_build "TRUST=raw-rsa AES=$$value" "AES=$$value chose the AES instructions when the object was built, and each session picks them from ch_cfg.cpu now (docs/decisions.md 89)" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	done; \
	for value in soft extern; do \
	  n=$$((n + 1)); refused_build "ROLE=server TRUST=none HOST_TARGET=yes AES=$$value" "a host object holds the AES instructions and takes no AES value" > "$$rows/$$(printf '%03d' $$n)" 2>&1 & \
	done; \
	srv_files=$$(git ls-files 'srv*.c' | grep -v / | tr '\n' ' '); \
	[ -n "$$srv_files" ] || { echo "lint-trust-separation: git tracks no srv*.c file at the root, so the role rows would check nothing"; rc=1; }; \
	client_only="handshake.c handshake_auth.c handshake_parser.c handshake_parser_ee.c handshake_message.c"; \
	role_crypto="rsa_sign.c p256_sign.c p256_ecdh.c p256_scalar.c p256_point.c p256_field.c"; \
	srv_shared=$$(printf '%s\n' $$srv_files | grep -vxF -e srv_handshake.c -e srv_quic.c -e srv_tcp_nonblocking.c | tr '\n' ' '); \
	check "ROLE=client TRUST=raw-rsa TRANSPORT=tcp-blocking" "$$client_only tls.c tls_write.c" "$$srv_files $$role_crypto" "" "-DCH_ROLE_SERVER"; \
	check "ROLE=both TRUST=webpki TRANSPORT=tcp-blocking" "$$srv_shared srv_handshake.c $$role_crypto tls.c tls_write.c handshake.c handshake_groups.c sha3.c mlkem.c mlkem_poly.c" "srv_quic.c srv_tcp_nonblocking.c" "-DCH_ROLE_SERVER -DCH_ROLE_BOTH" "-DCH_KEX_PQ"; \
	check "ROLE=server TRUST=none TRANSPORT=tcp-blocking" "$$srv_shared srv_handshake.c $$role_crypto tls.c tls_write.c rsa.c rsa_mont.c p256.c sha3.c mlkem.c mlkem_poly.c" "$$client_only srv_quic.c srv_tcp_nonblocking.c" "-DCH_ROLE_SERVER" "-DCH_PIN_ECDSA -DCH_KEX_PQ"; \
	quic_srv=$$(printf '%s\n' $$quic_always | grep -vxF -e quic_step.c | tr '\n' ' '); \
	check "ROLE=server TRUST=none TRANSPORT=quic-nonblocking EXPORTER=off" "$$srv_shared srv_quic.c quic_token.c $$role_crypto $$quic_srv $$aes_always sha3.c mlkem.c mlkem_poly.c" "$$client_only srv_handshake.c srv_tcp_nonblocking.c quic_step.c record.c" "-DCH_ROLE_SERVER -DCH_TRANSPORT_QUIC_NONBLOCKING" "-DCH_PIN_ECDSA -DCH_KEX_PQ"; \
	check "ROLE=server TRUST=none TRANSPORT=tcp-nonblocking" "$$srv_shared srv_tcp_nonblocking.c $$role_crypto tcp_nonblocking.c tcp_nonblocking_frame.c record.c sha3.c mlkem.c mlkem_poly.c" "$$client_only srv_handshake.c srv_quic.c tcp_nonblocking_step.c" "-DCH_ROLE_SERVER -DCH_TRANSPORT_TCP_NONBLOCKING" "-DCH_PIN_ECDSA -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_KEX_PQ"; \
	check "ROLE=server TRUST=none TRANSPORT=tcp-blocking SUITE=aesgcm HOST_TARGET=yes" "aes.c $$instructions gcm.c sha512.c sha512_compress.c" "quic_aes_soft.c aes_extern.c" "-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME" "-DCH_AES_EXTERN -DCH_AES_256_TEST -DCH_AES_EXTERN_CONSTANT_TIME"; \
	check "ROLE=server TRUST=none TRANSPORT=quic-nonblocking SUITE=aesgcm EXPORTER=off HOST_TARGET=yes" "aes.c $$instructions quic_aes_soft.c gcm.c quic_packet.c sha512.c sha512_compress.c" "aes_extern.c record.c" "-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME -DCH_TRANSPORT_QUIC_NONBLOCKING" "-DCH_AES_EXTERN -DCH_AES_256_TEST -DCH_AES_EXTERN_CONSTANT_TIME"; \
	check "ROLE=server TRUST=none TRANSPORT=tcp-blocking SUITE=aesgcm AES=extern HOST_TARGET=" "aes.c aes_extern.c gcm.c sha512.c sha512_compress.c" "quic_aes_soft.c $$instructions" "-DCH_SUITE_AES_GCM -DCH_AES_EXTERN" "-DCH_CPU_RUNTIME -DCH_AES_256_TEST -DCH_AES_EXTERN_CONSTANT_TIME"; \
	check "ROLE=server TRUST=none TRANSPORT=quic-nonblocking SUITE=aesgcm AES=extern EXPORTER=off HOST_TARGET=" "aes.c aes_extern.c gcm.c quic_packet.c sha512.c sha512_compress.c" "quic_aes_soft.c $$instructions record.c" "-DCH_SUITE_AES_GCM -DCH_AES_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING" "-DCH_CPU_RUNTIME -DCH_AES_256_TEST -DCH_AES_EXTERN_CONSTANT_TIME"; \
	wait; \
	for f in "$$rows"/*; do [ -s "$$f" ] && { cat "$$f"; rc=1; }; done; \
	rm -rf "$$rows"; \
	[ $$rc = 0 ] && echo "lint-trust-separation: every axis value packages exactly its own sources and defines"; \
	exit $$rc
# bench/device-ram.sh builds with CLANG_RV, the clang the codegen lints
# use. It asks here for the same reason: a copy of the candidate order
# above would drift, and the numbers it publishes are the compiler's
# (https://github.com/c4milo/chapulin/issues/111).
.PHONY: print-clang-rv
print-clang-rv:
	@echo $(CLANG_RV)
# test/localize-check.sh reads objects with the pinned llvm-nm and the
# tools beside it, and asks here when test/violations.py runs it on its own.
.PHONY: print-llvm-nm
print-llvm-nm:
	@echo $(LLVM_NM)
# RAND=drbg packages the generator, so ch_drbg_seed becomes part of the
# API the image calls and lib-check covers it like the role's own calls.
# PUBLIC_ROLE is one role's set and replaces the other role's rather
# than adding to it: lib-check diffs the object's exports against this
# list for exact equality, so a term carrying both sets fails every
# build (docs/decisions.md 28). A ROLE=client build sets it from
# PUBLIC_TRANSPORT, so the two transports' lists still reach here
# unchanged.
#
# PUBLIC_BUILD is the one export that is data rather than a call: the
# build record build.c defines in every object, which a consumer compares
# against its own headers (build.h, docs/decisions.md 56). No axis
# changes it, so every variant's list names it.
PUBLIC_BUILD := ch_build
# The lists above name each export as its header declares it. Six of
# those names belong to exports that objects of more than one transport
# carry: the build record, the server's boot check, the CA provisioning
# call, the client's ticket age call and the two alert calls. One image
# may link one object of each transport, so each of the six puts the
# object's transport in its symbol name, and build.h, srv.h, x509_ca.h,
# ticket.h and alert.h map the declared name to that symbol name under
# the consumer's own defines (docs/decisions.md 61, 72 and 75). ch_writable_len needs no such name: the
# two TCP transports export it beside ch_write, and decision 61 refuses an
# image of those two objects for ch_read, ch_write and ch_close already.
# PUBLIC holds symbol names, because those are what the link keeps and
# what lib-check reads.
TRANSPORT_NAMED := ch_build ch_srv_check ch_pubkey_from_pem ch_ticket_obfuscated_age \
                   ch_alert_sent ch_alert_received
# A symbol name takes no hyphen, so the suffix is the TRANSPORT value
# with underscores, and the build record's symbol is named for its type,
# ch_build_info: ch_build_info_tcp_blocking, ch_srv_check_tcp_blocking.
TRANSPORT_SUFFIX := $(subst -,_,$(TRANSPORT))
transport_symbol = $(if $(filter ch_build,$(1)),ch_build_info,$(1))_$(TRANSPORT_SUFFIX)
PUBLIC := $(foreach s,$(PUBLIC_ROLE) $(PUBLIC_RAND) $(PUBLIC_CA) $(PUBLIC_EXPORT) $(PUBLIC_BUILD), \
            $(if $(filter $(s),$(TRANSPORT_NAMED)),$(call transport_symbol,$(s)),$(s)))

# LIB_VARIANT names the build variables that pick the sources and the
# defines, and the compiler is not one of them. So `make CC=<cross> lib`
# writes its objects into the directory the host build uses; a later host
# build finds them newer than their sources, reuses them, and ld -r fails
# with "unknown file type" on an object of the wrong architecture. The
# stamp holds the compile command, so a different one rebuilds the objects
# instead of leaving two architectures in one directory.
#
# It sits under the variant because check builds several variants, and a
# single shared stamp would differ at every switch and rebuild all of
# them each time.
CC_STAMP := bin/obj/$(LIB_VARIANT)/cc-stamp
$(CC_STAMP): FORCE
	@mkdir -p bin/obj/$(LIB_VARIANT)
	@[ "$$(cat $@ 2>/dev/null)" = "$(CC) $(LIB_CFLAGS) $(LIB_DEF)" ] \
	  || echo "$(CC) $(LIB_CFLAGS) $(LIB_DEF)" > $@

bin/obj/$(LIB_VARIANT)/%.o: %.c $(HDRS) $(CC_STAMP)
	@mkdir -p bin/obj/$(LIB_VARIANT)
	$(CC) $(LIB_CFLAGS) $(LIB_DEF) -I. -c $< -o $@

# The stamp holds PUBLIC, because the link decides from that list which
# symbols stay global, and an edit to the list changes no source: without
# it, an object linked before a name left PUBLIC would still export it.
# It sits under the variant, beside the object it guards, for the reason
# CC_STAMP does, and because check links several variants at once: one
# stamp for every variant was rewritten by each of them in turn.
#
# A rewritten stamp reads as newer than the object only a second after
# the object was linked, because make 3.81 compares mtimes to the
# second. test/violations.py edits PUBLIC, links, restores it and links
# again in well under a second, and the second link was skipped: the
# object kept the edited export list under a stamp that held the
# restored one, and every later lib-check failed on a correct tree. So a
# stamp whose line differs from this build's forces the link through
# FORCE, whatever the clocks say.
PIN_STAMP := bin/obj/$(LIB_VARIANT)/pin-stamp
PIN_STAMP_LINE := $(LIB_VARIANT) $(strip $(PUBLIC))
PIN_STAMP_FORCE :=
ifneq ($(shell cat $(PIN_STAMP) 2>/dev/null),$(PIN_STAMP_LINE))
PIN_STAMP_FORCE := FORCE
endif
$(PIN_STAMP): FORCE
	@mkdir -p bin/obj/$(LIB_VARIANT)
	@[ "$$(cat $@ 2>/dev/null)" = "$(PIN_STAMP_LINE)" ] || echo "$(PIN_STAMP_LINE)" > $@
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

# The consumer lib-check links against the object to read its build
# record, and the defines of two more consumers, each of which disagrees
# with the object on one axis.
#
# The first moves CH_PIN_ECDSA: it adds the define where the object has
# none and drops it where the object has it. No header refuses the
# define in any build, and it changes no hook and no symbol name, so
# that consumer links and reads a record whose axes differ from its
# headers' in one bit.
#
# The second moves the transport: a TRANSPORT=tcp-blocking object meets a
# tcp-nonblocking consumer, and a tcp-nonblocking or QUIC object meets a
# tcp-blocking one. Its
# headers name another transport's record, which this object does not
# define, so that consumer must fail to link (docs/decisions.md 61).
# BUILD_OTHER_RECORD is the name its link reports missing.
BUILD_TEST := bin/obj/$(LIB_VARIANT)/build_test
ifneq ($(filter -DCH_PIN_ECDSA,$(LIB_DEF)),)
BUILD_PIN_MOVED_DEF := $(filter-out -DCH_PIN_ECDSA,$(LIB_DEF))
else
BUILD_PIN_MOVED_DEF := $(LIB_DEF) -DCH_PIN_ECDSA
endif
ifeq ($(TRANSPORT),tcp-blocking)
BUILD_TRANSPORT_MOVED_DEF := $(LIB_DEF) -DCH_TRANSPORT_TCP_NONBLOCKING
BUILD_OTHER_RECORD := ch_build_info_tcp_nonblocking
else
BUILD_TRANSPORT_MOVED_DEF := $(filter-out -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRANSPORT_TCP_NONBLOCKING,$(LIB_DEF))
BUILD_OTHER_RECORD := ch_build_info_tcp_blocking
endif

# nmedit reads its list from a file, which sits beside the object it
# edits, so two variants linked at once never read each other's list:
# test/zig-build-check.sh builds its objects at once.
$(LIB_OBJ): $(LIB_OBJS) $(PIN_STAMP) $(PIN_STAMP_FORCE)
	ld -r -o $@ $(LIB_OBJS)
ifeq ($(shell uname),Darwin)
	printf '_%s\n' $(PUBLIC) > $(@D)/exports.txt
	nmedit -s $(@D)/exports.txt $@
else
	objcopy $(foreach s,$(PUBLIC),-G $(s)) $@
endif

.PHONY: lib lib-check cxx-check lib-pair-object
lib: $(LIB_OBJ)
	@cp $(LIB_OBJ) bin/chapulin.o

# test/lib-pair-check.sh links two packaged objects into one image, so it
# needs each object at a path of its own rather than lib's copy at
# bin/chapulin.o. This builds the object where lib-check builds it and
# prints three lines: its path, the defines a consumer compiles against
# it under, and the flags.
lib-pair-object: $(LIB_OBJ)
	@echo $(LIB_OBJ)
	@echo $(LIB_DEF)
	@echo $(LIB_CFLAGS)

# The optional C++ wrapper (chapulin.hpp) compiles under -fno-exceptions
# -fno-rtti and links against the packaged library object, the way a
# firmware C++ consumer would use it.
CXXFLAGS ?= -std=c++17 -fno-exceptions -fno-rtti -Wall -Wextra -Wpedantic -Werror
cxx-check: $(LIB_OBJ) chapulin.hpp test/hpp_test.cpp bin/srv_flight_test
	@command -v $(CXX) >/dev/null || { \
	  [ -n "$$CI" ] && { echo "$(CXX): missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP cxx-check: no C++ compiler"; exit 0; }
	$(CXX) $(CXXFLAGS) $(LIB_DEF) -D_DEFAULT_SOURCE -I. -c test/hpp_test.cpp -o bin/obj/$(LIB_VARIANT)/hpp_test.o
	$(CXX) -o bin/obj/$(LIB_VARIANT)/hpp_test bin/obj/$(LIB_VARIANT)/hpp_test.o $(LIB_OBJ)
	./bin/obj/$(LIB_VARIANT)/hpp_test

# nm names a defined symbol by the section it sits in, and the letters
# differ by platform: T for code, D and B for data, S for any other
# section on Mach-O, where the build record's const data sits in __TEXT,__const,
# and R for read-only data on ELF, where it sits in .rodata.
#
# check runs lib-check for several variants at once, so every file it
# writes sits under the variant, and the copy to bin/chapulin.o lands by
# rename: that path holds whole the object of whichever variant finished
# last.
LIB_CHECK_DIR := bin/obj/$(LIB_VARIANT)
lib-check: $(LIB_OBJ)
	@cp $(LIB_OBJ) bin/chapulin.o.$$$$ && mv -f bin/chapulin.o.$$$$ bin/chapulin.o
	@nm -g $(LIB_OBJ) | awk '$$2 ~ /^[TDSBR]$$/ {print $$3}' | sed 's/^_//' | sort > $(LIB_CHECK_DIR)/exported.txt
	@printf '%s\n' $(PUBLIC) | sort > $(LIB_CHECK_DIR)/expected.txt
	@diff -u $(LIB_CHECK_DIR)/expected.txt $(LIB_CHECK_DIR)/exported.txt || { \
	  echo "lib-check: exported symbols differ from the public API"; exit 1; }
	@echo "lib-check: $$(wc -l < $(LIB_CHECK_DIR)/exported.txt | tr -d ' ') exported symbols, all public API"
# https://github.com/c4milo/chapulin/issues/41 calls the undefined import
# chapulin's strongest randomness property: an image that never wired a
# generator does not link. RAND=drbg trades it away deliberately, and
# RAND=session moves the source into each session's ch_cfg, so assert
# whichever one this build promised rather than leaving the difference to a
# reader of the Makefile.
ifeq ($(RAND),drbg)
	@if nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qx ch_rand_bytes; then \
	  echo "lib-check: RAND=drbg packages the generator, so ch_rand_bytes must be defined here, not imported"; exit 1; fi
	@echo "lib-check: ch_rand_bytes is defined and exported by the object; the image seeds it with ch_drbg_seed at boot"
# docs/entropy.md's boot-seed recipe, compiled the way an image compiles
# it and linked against this object. The page once told an integrator to
# call sha256_of, which the object keeps local, and nothing compiled the
# page's code, so the link error went unnoticed
# (https://github.com/c4milo/chapulin/issues/164). The program starts a
# TCP-blocking client and defines no hook but ch_assert_fail, so it runs
# on the objects that carry that client and import no other hook.
ifeq ($(TRANSPORT)-$(ROLE)-$(KEYLOG),tcp-blocking-client-off)
	@$(CC) $(LIB_CFLAGS) $(LIB_DEF) -I. -o bin/obj/$(LIB_VARIANT)/entropy_recipe test/entropy_recipe.c $(LIB_OBJ)
	@bin/obj/$(LIB_VARIANT)/entropy_recipe || { \
	  echo "lib-check: docs/entropy.md's boot-seed recipe links against this object but does not run"; exit 1; }
	@echo "lib-check: docs/entropy.md's boot-seed recipe links against this object, and the handshake it starts draws from the seeded generator"
endif
else ifeq ($(RAND),session)
# The RAND=extern check's counterpart. Every draw calls the session's
# cfg.rand_bytes (rand.h), so the object names neither generator symbol,
# defined, local or imported, and a program that links only RAND=session
# objects defines no entropy hook. build_test.c below is such a program:
# under CH_RAND_SESSION it defines no ch_rand_bytes, so its link fails
# when the object imports one (docs/decisions.md 77).
	@if nm $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'ch_rand_bytes|ch_drbg_seed'; then \
	  echo "lib-check: RAND=session must neither define nor import ch_rand_bytes or ch_drbg_seed, so a program that links only such objects defines no entropy hook"; exit 1; fi
	@echo "lib-check: the object names no ch_rand_bytes and no ch_drbg_seed; every draw calls the session's own source"
else
	@if ! nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qx ch_rand_bytes; then \
	  echo "lib-check: RAND=extern must leave ch_rand_bytes undefined, so an image that forgets the hook fails to link"; exit 1; fi
	@echo "lib-check: ch_rand_bytes is undefined in the object; a forgotten hook is a link error"
endif
# The export list above says what an image may call. This says what the
# object still asks the image for. An undefined symbol that some source in
# this tree defines is not a hook: it is a module this variant left out
# while keeping a caller of it, so the object builds, lib-check passed, and
# the image fails to link. ROLE=server did exactly that, compiling
# ch_connect with no handshake.c under it, and nothing here noticed until a
# consumer tried the link.
#
# ch_rand_bytes is the one hook this tree also defines, in drbg.c, so a
# RAND=extern object imports it on purpose and it is named below. A
# RAND=drbg object defines it, and a RAND=session object must not import
# it, so neither admits it.
# ch_assert_fail and ch_aes_block need no entry: no source here defines
# either, so the rule passes them without being told.
	@set -e; \
	allow=""; \
	[ "$(RAND)" != "extern" ] || allow="ch_rand_bytes"; \
	bad=""; \
	for s in $$(nm -u $(LIB_OBJ) | awk '{print $$NF}' | sed 's/^_//' | sort -u); do \
	  case " $$allow " in *" $$s "*) continue;; esac; \
	  if grep -qE "^[A-Za-z_][A-Za-z0-9_ ]*\**$$s\(" *.c 2>/dev/null; then bad="$$bad $$s"; fi; \
	done; \
	[ -z "$$bad" ] || { echo "lib-check: the object imports$$bad, which this tree defines in a source this variant does not compile"; exit 1; }
	@echo "lib-check: every undefined symbol is a libc call or a caller-supplied hook"
# The build record (build.h, docs/decisions.md 56 and 61), read the way
# a consumer reads it: test/build_test.c compiles against the headers
# and links this object. Compiled under the object's own defines, it
# must read a record equal to what its headers compute and exit 0.
# Compiled with CH_PIN_ECDSA moved, it must read a difference and exit
# 1. It exits 2 when its own header view disagrees with the defines it
# was given, and that fails either run. Compiled with the transport
# moved, it must compile and then fail to link, and the link must name
# the other transport's record. A build.h that gave two transports one
# record name would let that consumer link and read this object's
# record. The three builds add about 0.3 s to each lib-check run.
	@$(CC) $(LIB_CFLAGS) $(LIB_DEF) -I. -o $(BUILD_TEST) test/build_test.c $(LIB_OBJ)
	@$(BUILD_TEST) || { echo "lib-check: the build record disagrees with the headers compiled under this object's own defines"; exit 1; }
	@$(CC) $(LIB_CFLAGS) $(BUILD_PIN_MOVED_DEF) -I. -o $(BUILD_TEST)_pin test/build_test.c $(LIB_OBJ)
	@rc=0; $(BUILD_TEST)_pin > /dev/null || rc=$$?; \
	[ $$rc -eq 1 ] || { echo "lib-check: a consumer compiled with CH_PIN_ECDSA moved must read a different build record, and it exited $$rc"; exit 1; }
	@$(CC) $(LIB_CFLAGS) $(BUILD_TRANSPORT_MOVED_DEF) -I. -c test/build_test.c -o $(BUILD_TEST)_transport.o
	@if $(CC) -o $(BUILD_TEST)_transport $(BUILD_TEST)_transport.o $(LIB_OBJ) 2> $(BUILD_TEST)_transport.err; then \
	  echo "lib-check: a consumer compiled for another transport linked against this object; build.h must give each transport's record its own name"; exit 1; fi
	@grep -q "$(BUILD_OTHER_RECORD)" $(BUILD_TEST)_transport.err || { cat $(BUILD_TEST)_transport.err; \
	  echo "lib-check: a consumer compiled for another transport failed to link without naming $(BUILD_OTHER_RECORD)"; exit 1; }
	@echo "lib-check: the build record matches this object's defines, differs from a consumer's with CH_PIN_ECDSA moved, and is not the record a consumer of another transport names"

# The declaration in cfg.h is the whole feature, so check that it fires.
# tls.c is enough to drive it: it includes cfg.h, where the guard lives.
# LIB_CFLAGS is the flag set with the host declaration filtered out, so
# the "none" arm really names none. Every pair and all three together
# must fail, and each define alone must compile.
.PHONY: rand-check
rand-check:
	@set -e; \
	for d in "" "-DCH_RAND_EXTERN -DCH_RAND_DRBG" "-DCH_RAND_EXTERN -DCH_RAND_SESSION" \
	  "-DCH_RAND_DRBG -DCH_RAND_SESSION" "-DCH_RAND_EXTERN -DCH_RAND_DRBG -DCH_RAND_SESSION"; do \
	  if $(CC) $(LIB_CFLAGS) $$d -I. -fsyntax-only tls.c 2>/dev/null; then \
	    echo "rand-check: tls.c compiled with [$$d]; the cfg.h guard did not fire"; exit 1; \
	  fi; \
	done; \
	for d in -DCH_RAND_EXTERN -DCH_RAND_DRBG -DCH_RAND_SESSION; do \
	  $(CC) $(LIB_CFLAGS) $$d -I. -fsyntax-only tls.c || { \
	    echo "rand-check: tls.c must compile with $$d alone"; exit 1; }; \
	done; \
	echo "rand-check: cfg.h admits exactly one of CH_RAND_EXTERN, CH_RAND_DRBG and CH_RAND_SESSION"

# The reference generator's own vectors. It builds here whatever RAND
# says, because the module is the subject of the test rather than the
# image's choice — so this recipe declares CH_RAND_DRBG on its own, and
# the sanitizer, cross and coverage builds of the same test do too.
# Whether the packaged object also carries drbg.c is RAND's business,
# not this binary's.
#
# The sources a test binary links sit in a variable when another recipe
# builds the same test: san-check, cross-check, m3-check, coverage, the
# CH_CT_WIDEMUL builds and the host object's builds read the variable
# this rule reads, so a source the test comes to need fails check, which
# builds this rule, before it fails one of those recipes.
DRBG_TEST_SRCS := drbg.c chacha20.c sha256.c ct.c ct_wipe.c
bin/drbg_test: test/drbg_test.c $(DRBG_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(LIB_CFLAGS) -DCH_RAND_DRBG -I. -o $@ test/drbg_test.c $(DRBG_TEST_SRCS)

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
RSA_TEST_SRCS := rsa.c rsa_mont.c sha256.c ct.c ct_wipe.c
bin/rsa_test: test/rsa_test.c $(RSA_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/rsa_test.c $(RSA_TEST_SRCS)

# RSA-PSS signing: the known answers, the round trip through the verifier
# and the refusals. Its own binary like bin/rsa_test, at the same
# 512-byte bound so the RSA-4096 vector signs, which is wider than the
# 384-byte bound the ROLE=server object that now packages rsa_sign.c
# builds it at. It links rsa.c for the verifier the round trip checks
# against, which is the same pairing bin/rsa_pkcs1_test uses.
RSA_SIGN_TEST_SRCS := rsa_sign.c rsa.c rsa_mont.c sha256.c ct.c ct_wipe.c
bin/rsa_sign_test: test/rsa_sign_test.c $(RSA_SIGN_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/rsa_sign_test.c $(RSA_SIGN_TEST_SRCS)

# SHA-3 vectors and the SHAKE streaming contract. Its own binary: sha3.c stays
# out of the packaged object until the ML-KEM build calls it
# (https://github.com/c4milo/chapulin/issues/21).
SHA3_TEST_SRCS := sha3.c ct.c ct_wipe.c
bin/sha3_test: test/sha3_test.c $(SHA3_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/sha3_test.c $(SHA3_TEST_SRCS)
# sha3.c against FIPS 202 as the standard writes it, proof/sha3_reference.h:
# the permutation, both digests, and both XOFs through split calls
# (docs/decisions.md 98). The test includes sha3.c itself, to call the
# permutation that file keeps static, so the line links no second copy.
bin/sha3_equiv_test: test/sha3_equiv_test.c $(SHA3_TEST_SRCS) proof/sha3_reference.h $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/sha3_equiv_test.c $(filter-out sha3.c,$(SHA3_TEST_SRCS))

# ML-KEM-768 known answers, the CCTV decaps anchors, and the input checks. Its
# own binary, out of the packaged object like sha3
# (https://github.com/c4milo/chapulin/issues/21).
MLKEM_TEST_SRCS := mlkem.c mlkem_poly.c sha3.c ct.c ct_wipe.c
bin/mlkem_test: test/mlkem_test.c $(MLKEM_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/mlkem_test.c $(MLKEM_TEST_SRCS)
# The TRANSPORT=quic-nonblocking driver through its sixteen public entries: the
# configuration rules, the staged ClientHello, a ServerHello delivered
# over CRYPTO bytes, the level rules RFC 9001 §4.1.3 states, and the one
# CONNECTION_CLOSE per level a failed session seals. Its own
# binary over the whole QUIC object's sources under -DCH_TRANSPORT_QUIC_NONBLOCKING,
# the shape bin/sha3_test uses for a mode's own sources: bin/unit
# compiles no QUIC source, because it includes tls.h and calls rec_seal,
# which a -DCH_TRANSPORT_QUIC_NONBLOCKING build does not compile. It is also the
# build that compiles quic.c for test/quic-builds.sh, the catch target
# of the INV-26 mutants the compiler refuses.
QUIC_DRIVER_SRCS := $(QUIC_SRCS) handshake_message.c handshake_parser.c handshake_parser_ee.c \
                    handshake_record.c handshake_auth.c handshake_post.c handshake_flight.c \
                    keysched.c x25519.c \
                    rsa.c rsa_mont.c hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c ct.c ct_wipe.c
bin/quic_driver_test: test/quic_driver_test.c $(QUIC_DRIVER_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -o $@ test/quic_driver_test.c $(QUIC_DRIVER_SRCS)
# The mode against its published vectors: FIPS 197 for the AES-128 and
# AES-256 forward ciphers, SP 800-38D for both AEADs, and RFC 9001
# Appendix A for the Initial keys, the header protection masks and the
# Retry key. AES_256_TEST_DEF turns on the AES-256 rows, which a library
# object has only under SUITE=aesgcm. Same shape and same reason as
# bin/quic_driver_test above, and docs/quic.md, "Verification owed", names
# both the file and this binary. aes.c and the AES implementation this
# build picked are both on the line: the cipher moved out of aes.c into
# the three sources the AES axis chooses among, and test/quic_vectors.c reaches
# it through aes_block.h's two entries, which take plain bytes rather than
# a key object. A later lane that adds a vector section for another quic source
# links that source here.
bin/quic_test: test/quic_vectors.c aes.c $(AES_IMPL) gcm.c quic_keys.c quic_retry.c quic_initial.c quic_packet.c \
               hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c ct.c ct_wipe.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) $(AES_256_TEST_DEF) -I. -o $@ test/quic_vectors.c aes.c \
	  $(AES_IMPL) gcm.c quic_keys.c quic_retry.c quic_initial.c quic_packet.c hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c ct.c ct_wipe.c
# The same vectors in a QUIC host object (docs/decisions.md 89), which
# holds aes_hw.c's AES instructions and quic_aes_soft.c's table beside
# them. test/quic_vectors.c runs every vector twice there: with
# test_initial_cpu stating the instructions, and with the probe's bit
# alone, which puts the Initial keys on the table (test/initial_cpu.h).
# CBMC cannot read an intrinsic, so the published standards are how the
# instruction path answers for itself: FIPS 197 for the cipher, RFC 9001
# Appendix A for the Initial keys and the header protection masks, SP
# 800-38D for the AEAD, whose GHASH runs on the carry-less multiply under a
# schedule on the instructions. bin/aes_equiv_test and bin/ghash_equiv_test
# are the other half, comparing each instruction path with its software
# twin directly.
#
# Every host test binary compiles as a host object does, with
# -DCH_CPU_RUNTIME and no instruction flag: each function in AES_HW_SRCS
# turns the instructions on for itself. HOST_BINS below names them only
# where HOST_TARGET found a host compiler, and they run where the CPU has
# the AES instructions, as every CI runner's does; test/aes-runtime-qemu.sh
# runs the rows without the AES bit on a CPU that lacks them.
# TLS_AES_128_GCM_SHA256 in the record layer, against RFC 8448's printed
# record, in the TCP host object that carries the suite.
# The server's suite selection, in a build that has two suites to choose
# between. Same cases as bin/srv_flight_test plus the four the second
# suite adds, and test_flight_without_aes, whose server states no AES
# instructions, so one source covers both builds.
# The flight handlers and what they call in the role, without the parser,
# which both flight binaries replace with test/srv_flight_tests.h's own.
SRV_FLIGHT_SRCS := srv_flight.c srv_out.c srv_message.c srv_cookie.c srv_auth.c srv_ticket.c \
                   srv_resume.c srv_kex.c
SRV_FLIGHT_AES_SRCS = $(call host_srcs,$(SRV_FLIGHT_SRCS) $(SRV_FLIGHT_DEPS) $(SRV_SIGNERS) gcm.c aes.c \
                        $(AES_HW_SRCS) sha512.c sha512_compress.c)
bin/srv_flight_test_aes: test/srv_flight_test.c $(SRV_FLIGHT_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_ROLE_SERVER $(HOST_SUITE_DEF) -I. -o $@ test/srv_flight_test.c \
	  $(SRV_FLIGHT_AES_SRCS)

AES_SUITE_TEST_SRCS := $(call host_srcs,record.c gcm.c aes.c $(AES_HW_SRCS) aead.c chacha20.c poly1305.c \
                         hkdf.c sha256.c sha512.c sha512_compress.c ct.c ct_wipe.c buf.c)
bin/aes_suite_test: test/aes_suite_test.c $(AES_SUITE_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) $(HOST_SUITE_DEF) -I. -o $@ test/aes_suite_test.c $(AES_SUITE_TEST_SRCS)

# test/aes-runtime-qemu.sh links QUIC_TEST_HW_SRCS too, for x86-64.
QUIC_TEST_HW_SRCS := $(call host_srcs,aes.c $(AES_HW_SRCS) quic_aes_soft.c gcm.c quic_keys.c quic_retry.c \
                       quic_initial.c quic_packet.c hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c ct.c \
                       ct_wipe.c)
bin/quic_test_hw: test/quic_vectors.c $(QUIC_TEST_HW_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME $(AES_256_TEST_DEF) -I. -o $@ \
	  test/quic_vectors.c $(QUIC_TEST_HW_SRCS)
# The AES instructions against the table over the same inputs, the check
# that holds the instruction path where a proof cannot reach. Both
# implementations are in one binary under two names, which a library
# object may never do and a test binary may, the way the test binaries
# compile both PIN algorithms. test/aes_equiv_soft.c and
# test/aes_equiv_hw.c compile the two sources in under those names, so
# neither is on the line twice; the second defines the host object's
# CH_CPU_RUNTIME itself, so the first compiles quic_aes_soft.c under
# aes_block.h's own names.
# ct_wipe.c is on the line because aes_hw.c wipes its key-schedule word
# and its cipher state through ct_wipe; quic_aes_soft.c wipes nothing and
# links nothing, for the reason its file comment gives.
# test/aes_equiv_vaes.c compiles gcm_vaes.c's kernels, which the counter
# cases run as well on an x86-64 CPU with VAES and VPCLMULQDQ, and which
# gcm_hw.c's entries name on x86-64.
# The line takes HOST_CFLAGS because two of its units define
# CH_CPU_RUNTIME, and ct.h refuses the test flags' CH_NATIVE_WIDEMUL
# beside it. No unit on the line multiplies.
bin/aes_equiv_test: test/aes_equiv_test.c test/aes_equiv_soft.c test/aes_equiv_hw.c test/aes_equiv_vaes.c \
                    quic_aes_soft.c aes_hw.c gcm_hw.c gcm_vaes.c ct.c ct_wipe.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -o $@ test/aes_equiv_test.c \
	  test/aes_equiv_soft.c test/aes_equiv_hw.c test/aes_equiv_vaes.c ct.c ct_wipe.c
# GHASH on the carry-less multiply against gcm.c's portable GHASH, the
# same check for ghash_hw.c: the multiply, the loop over data and the
# whole AEAD. The binary is a QUIC host object, so gcm.c holds both GHASH
# bodies and runs the one a schedule names; test/ghash_equiv_soft.c
# compiles gcm.c a second time under renamed entries, which reach the
# portable multiply and data loop the proofs cover, and the AEAD cases run
# one copy under a schedule on the instructions and the other under one on
# the table. aes.c calls hkdf.c for the Initial key constructor, which is
# why hkdf.c and sha256.c link. test/stack_residue.c copies the stack a
# call left, for the check that the powers of H and a pass's sums are gone
# (test/ghash_equiv_residue.h).
# The wide X25519 field against the 16-word one, both in one binary under
# the names the library gives them, as a host object holds them: x25519.c
# on ct.h's 16x16 decomposition and x25519_wide.c, which compiles x25519.c
# once more for its clamp and all-zero check. The binary is a host
# object's, so HOST_BINS names it. bin/unit_host runs RFC 7748's vectors
# and the unit suite's handshakes on the wide field, with the multiply bit,
# and on the 16-word one, without it.
X25519_EQUIV_TEST_SRCS := x25519.c x25519_wide.c ct.c ct_wipe.c
bin/x25519_equiv_test: test/x25519_equiv_test.c $(X25519_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -o $@ test/x25519_equiv_test.c $(X25519_EQUIV_TEST_SRCS)
# The wide P-256 files against p256_field.c, p256_scalar.c and
# p256_point.c, all in one binary under the names the library gives them,
# as a host object holds them: the files under their own names on ct.h's
# 16x16 decomposition, and the wide files on the 64x64->128 multiply.
# The signer and the key exchange link so that a signature, a key pair and
# a shared secret run under both answers, and p256.c so that the
# independent verifier reads each signature. test/stack_residue.c copies
# the stack a call left, for the check that a scalar's words are gone
# (test/p256_equiv_residue.h), and the copies on the SHA-256 instructions
# link so that one signature's nonce runs on them, as a server's does under
# the SHA-256 bit (p256_sign_cpu). The binary is a host object's, so
# HOST_BINS names it. bin/p256_sign_test_host and bin/p256_ecdh_test_host
# run RFC 6979's vectors and Python's on the wide files, with the multiply
# bit, and on the files under their own names, without it.
P256_EQUIV_TEST_SRCS := p256_sign.c p256_ecdh.c p256_point.c p256_scalar.c p256_field.c $(P256_WIDE_SRCS) \
                        test/p256_verify_portable.c sha256.c hkdf.c $(call hash_hw_of,sha256.c hkdf.c) \
                        buf.c ct.c ct_wipe.c test/stack_residue.c
bin/p256_equiv_test: test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS)
# The same binary on the 128-bit sums, the form of p256_wide_word.h's two
# carry steps that gcc compiles for a machine other than x86-64. The
# binary above runs the form its compiler picks: the builtins under clang
# and the intrinsics under gcc for x86-64. check runs on no machine whose
# compiler picks the sums, so this rule names them (docs/decisions.md 94).
bin/p256_equiv_test_sum: test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DP256_WIDE_CARRY=P256_WIDE_CARRY_SUM -I. -Itest -o $@ \
	  test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS)
# A host object's ECDSA P-256 verifier against the portable one
# (docs/decisions.md 96). The binary compiles as a host object compiles
# its sources, so p256.c is the arm that calls p256_wide_verify.c, and
# test/p256_verify_portable.c compiles the same file's 32-bit arm, a
# device object's, under a second name beside it. The signer and the
# 32-bit point and scalar files link so that the test computes its own
# signatures on an arithmetic that is neither verifier's.
P256_VERIFY_EQUIV_TEST_SRCS := p256.c p256_sign.c p256_point.c p256_scalar.c p256_field.c $(P256_WIDE_SRCS) \
                               sha256.c hkdf.c $(call hash_hw_of,sha256.c hkdf.c) buf.c ct.c ct_wipe.c
P256_VERIFY_EQUIV_TEST_UNITS := test/p256_verify_equiv_test.c test/p256_verify_portable.c
bin/p256_verify_equiv_test: $(P256_VERIFY_EQUIV_TEST_UNITS) $(P256_VERIFY_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ $(P256_VERIFY_EQUIV_TEST_UNITS) \
	  $(P256_VERIFY_EQUIV_TEST_SRCS)
# The same binary on the overflow builtins, the form clang compiles. CI's
# check job and test/docker-check.sh compile with gcc for x86-64, which
# picks the intrinsics, so this rule names the builtins and a machine
# whose compiler is gcc runs them too (docs/decisions.md 94).
bin/p256_equiv_test_builtin: test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DP256_WIDE_CARRY=P256_WIDE_CARRY_BUILTIN -I. -Itest -o $@ \
	  test/p256_equiv_test.c $(P256_EQUIV_TEST_SRCS)
# A host object's RSA arithmetic against the portable code
# (docs/decisions.md 95). The binary compiles as a host object compiles
# its sources, so rsa_mont.c is the arm that calls rsa_mont64.c's 64-bit
# words, and test/rsa_equiv_portable.c compiles the same file's 32-bit
# arm, a device object's, under a second name beside it. It builds at the
# 512-byte bound, so RSA-4096 runs on both.
RSA_EQUIV_TEST_SRCS := rsa_mont.c $(RSA_MONT64_SRCS) ct.c ct_wipe.c
RSA_EQUIV_TEST_UNITS := test/rsa_equiv_test.c test/rsa_equiv_portable.c
bin/rsa_equiv_test: $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o $@ $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS)
# The same binary on each form of rsa_mont64.h's step: the binary above
# runs the form its compiler picks, the compare form under clang and the
# sum form under gcc, and check runs on clang on a Mac and on gcc in CI, so
# these two rules name each form and every machine runs both
# (docs/decisions.md 117).
bin/rsa_equiv_test_compare: $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DRSA_MONT64_STEP=RSA_MONT64_STEP_COMPARE $(RSA_WIDE_DEF) -I. \
	  -o $@ $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS)
bin/rsa_equiv_test_sum: $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DRSA_MONT64_STEP=RSA_MONT64_STEP_SUM $(RSA_WIDE_DEF) -I. \
	  -o $@ $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS)
# The same for the signer: rsa_sign.c is the ladder a host object holds
# for a session that does not state its multiply, the code a device object
# runs, and rsa_sign64.c is the CRT signer on 64-bit words beside it. The
# two link under their own names, as a host object holds them.
# test/stack_residue.c copies the stack a call left, for the check that
# its wipes cover what it held, and test/rsa_sign_equiv_pieces.c compiles
# rsa_sign64.c once more under second names, so that the check can call
# that file's static reduction and recombination on their own.
RSA_SIGN_EQUIV_TEST_SRCS := test/rsa_sign_equiv_pieces.c test/stack_residue.c rsa_sign.c \
                            $(RSA_SIGN64_SRCS) $(RSA_MONT64_SRCS) sha256.c ct.c ct_wipe.c
bin/rsa_sign_equiv_test: test/rsa_sign_equiv_test.c $(RSA_SIGN_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o $@ test/rsa_sign_equiv_test.c $(RSA_SIGN_EQUIV_TEST_SRCS)
# The RSA-PSS verifier's vectors on a host object's rsa_vp1: bin/rsa_test's
# main, built as a host object builds its sources. It takes no ch_cfg.cpu
# value, because no bit picks the public operation. bin/rsa_pkcs1_test_host
# is the same for the PKCS#1 v1.5 verifier, beside bin/rsa_pkcs1_test.
bin/rsa_test_host: test/rsa_test.c $(call host_srcs,$(RSA_TEST_SRCS)) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o $@ test/rsa_test.c $(call host_srcs,$(RSA_TEST_SRCS))
# A host object's ChaCha20 against chacha20.c's loop, the paths in one
# binary under their own names: chacha20.c compiles here without
# -DCH_CPU_RUNTIME, so chacha20_xor is the portable loop, as a device
# object runs it, and test/chacha20_equiv_vector.c compiles
# chacha20_vector.c under the define beside it, and
# test/chacha20_equiv_avx2.c the AVX2 kernel, whose cases run on an
# x86-64 CPU with AVX2. ct_wipe.c is the wipe of the buffer a vector path's
# last bytes pass through. The line takes HOST_CFLAGS for
# bin/aes_equiv_test's reason.
CHACHA20_EQUIV_TEST_SRCS := test/chacha20_equiv_vector.c test/chacha20_equiv_avx2.c chacha20.c ct.c ct_wipe.c
bin/chacha20_equiv_test: test/chacha20_equiv_test.c $(CHACHA20_EQUIV_TEST_SRCS) $(CHACHA_VECTOR_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -I. -o $@ test/chacha20_equiv_test.c $(CHACHA20_EQUIV_TEST_SRCS)
# The vector Poly1305 against poly1305.c's loop, both in one binary:
# poly1305.c compiles here without -DCH_CPU_RUNTIME, the loop alone on the
# 16x16 decomposition, as a device object runs it, and
# test/poly1305_equiv_vector.c compiles a host object's native copy
# beside it, poly1305_native.c with poly1305_vector_native.c, under the
# define. test/poly1305_equiv_avx2.c compiles poly1305_avx2_native.c, the
# AVX2 kernel the copy holds on x86-64, which the binary runs on a CPU
# with AVX2 (docs/decisions.md 110). test/stack_residue.c copies the
# stack a call left, for the check that the powers of r are gone
# (test/poly1305_equiv_residue.h).
POLY1305_EQUIV_TEST_SRCS := test/poly1305_equiv_vector.c test/poly1305_equiv_avx2.c \
                            test/stack_residue.c poly1305.c ct.c ct_wipe.c
bin/poly1305_equiv_test: test/poly1305_equiv_test.c $(POLY1305_EQUIV_TEST_SRCS) poly1305_native.c \
                         poly1305_vector_native.c poly1305_vector.c poly1305_avx2_native.c \
                         poly1305_avx2.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -I. -o $@ test/poly1305_equiv_test.c $(POLY1305_EQUIV_TEST_SRCS)
# A host object's SHA-256 on the CPU's instructions against sha256.c, and
# the copies of hkdf.c and keysched.c over it against the files under
# their own names, all in one binary under the names the library gives
# them, as a host object holds them (docs/decisions.md 93). It defines
# CH_HASH_SHA384 and the exporter so that every call of the two copied
# files compiles. test/stack_residue.c copies the stack a call left, for
# the check that no value the call computed from a block is still there
# (test/sha2_equiv_residue.h). On a CPU without the instructions the
# binary skips.
SHA2_EQUIV_TEST_DEFS := -DCH_CPU_RUNTIME -DCH_HASH_SHA384 $(EXPORTER_DEF)
SHA2_EQUIV_TEST_SRCS := test/stack_residue.c $(call host_srcs,sha256.c hkdf.c keysched.c sha512.c) \
                        sha512_compress.c ct.c ct_wipe.c
bin/sha2_equiv_test: test/sha2_equiv_test.c $(SHA2_EQUIV_TEST_SRCS) hkdf.c keysched.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) $(SHA2_EQUIV_TEST_DEFS) -I. -Itest -o $@ test/sha2_equiv_test.c $(SHA2_EQUIV_TEST_SRCS)
# A host object's Keccak on arm64's SHA-3 instructions against sha3.c, the
# portable code CBMC proves (docs/decisions.md 99). test/stack_residue.c
# copies the stack a call left, for the check that no lane the call
# computed is still there (test/sha3_hw_equiv_residue.h). In an object
# that holds no such path, and on a CPU without the instructions, the
# binary says so and passes.
SHA3_HW_EQUIV_TEST_SRCS := test/stack_residue.c $(call host_srcs,sha3.c) ct.c ct_wipe.c
bin/sha3_hw_equiv_test: test/sha3_hw_equiv_test.c test/sha3_hw_equiv_residue.h \
                        $(SHA3_HW_EQUIV_TEST_SRCS) proof/sha3_reference.h $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/sha3_hw_equiv_test.c $(SHA3_HW_EQUIV_TEST_SRCS)
# ML-KEM's two copies on the SHA-3 instructions against mlkem.c and
# mlkem_poly.c, the code CBMC proves (docs/decisions.md 99): the same
# keys, ciphertexts and secrets on the two paths, and the three calls a
# session makes under each kind of ch_cfg.cpu.
MLKEM_HW_EQUIV_TEST_SRCS := $(call host_srcs,sha3.c mlkem.c mlkem_poly.c) ct.c ct_wipe.c
bin/mlkem_hw_equiv_test: test/mlkem_hw_equiv_test.c $(MLKEM_HW_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/mlkem_hw_equiv_test.c $(MLKEM_HW_EQUIV_TEST_SRCS)
# The vector NTT against mlkem_poly.c's loops, the code CBMC proves
# (docs/decisions.md 101). mlkem_poly.c compiles to the same code in a host
# object as in a device object, so the binary links it under its own names.
MLKEM_VECTOR_EQUIV_TEST_SRCS := mlkem_poly.c mlkem_vector.c $(call host_srcs,sha3.c) ct.c ct_wipe.c
bin/mlkem_vector_equiv_test: test/mlkem_vector_equiv_test.c $(MLKEM_VECTOR_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/mlkem_vector_equiv_test.c \
	  $(MLKEM_VECTOR_EQUIV_TEST_SRCS)
# The four-way Keccak against sha3.c, and ML-KEM's copy over it against
# mlkem.c (docs/decisions.md 107). Both have a body on x86-64 alone; on
# another target the binary says so and passes.
MLKEM_AVX2_EQUIV_TEST_SRCS := $(call host_srcs,sha3.c mlkem.c mlkem_poly.c) ct.c ct_wipe.c
bin/mlkem_avx2_equiv_test: test/mlkem_avx2_equiv_test.c $(MLKEM_AVX2_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/mlkem_avx2_equiv_test.c \
	  $(MLKEM_AVX2_EQUIV_TEST_SRCS)
# Which SHA-256 and which SHA-512 a host object's hash calls run under
# each ch_cfg.cpu value (docs/decisions.md 93). test/hash_runtime_count.c
# defines sha256.c's three calls that hash, sha512.c's five and the same
# calls of sha256_hw.c and sha512_hw.c, each as a count and a call to the
# portable code, and the binary links it in place of the four files.
# So no hash instruction runs, the binary gives one verdict on every CPU,
# and its counts say which path the library chose. The first binary is a
# QUIC object with the suites, whose rows hold a record direction and a
# QUIC level's keys. The second is a TCP object with the suites and the
# exporter, which a QUIC object does not hold, so the two exporter entries
# have a row. Both link the P-256 signer, whose nonce's HMACs follow the
# SHA-256 bit (p256_sign_cpu).
HASH_RUNTIME_COUNTED := sha256.c sha256_hw.c sha512.c sha512_hw.c
HASH_RUNTIME_TEST_SRCS := test/hash_runtime_count.c \
                          $(filter-out $(HASH_RUNTIME_COUNTED),$(call host_srcs,record.c aes.c $(AES_HW_SRCS) \
                          gcm.c aead.c chacha20.c poly1305.c hkdf.c keysched.c sha256.c sha512.c \
                          sha512_compress.c p256_sign.c p256_scalar.c p256_point.c p256_field.c \
                          buf.c ct.c ct_wipe.c))
HASH_RUNTIME_QUIC_SRCS := quic_packet.c quic_keys.c quic_initial.c quic_aes_soft.c
bin/hash_runtime_test: test/hash_runtime_test.c $(HASH_RUNTIME_TEST_SRCS) $(HASH_RUNTIME_QUIC_SRCS) sha256.c \
                       sha512.c hkdf.c keysched.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest -o $@ \
	  test/hash_runtime_test.c $(HASH_RUNTIME_TEST_SRCS) $(HASH_RUNTIME_QUIC_SRCS)
bin/hash_runtime_exporter_test: test/hash_runtime_test.c $(HASH_RUNTIME_TEST_SRCS) sha256.c sha512.c hkdf.c \
                                keysched.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) $(HOST_SUITE_DEF) $(EXPORTER_DEF) -I. -Itest -o $@ test/hash_runtime_test.c \
	  $(HASH_RUNTIME_TEST_SRCS)
# Which calls an x86-64 host object sends to its kernels under each
# ch_cfg.cpu value (docs/decisions.md 89, 90, 107 and 110):
# chacha20_avx2.c's AVX2 ChaCha20 and mlkem_avx2.c's copy of ML-KEM, which
# CH_CPU_AVX2 picks, poly1305_avx2.c's AVX2 Poly1305, which it picks beside
# CH_CPU_CONSTANT_TIME_MULTIPLY, and gcm_vaes.c's three VAES entries, which
# CH_CPU_VAES picks beside CH_CPU_CONSTANT_TIME_AES.
# test/x86_kernels_count.c defines the eight entries, each as a count and
# a call to the entry it stands beside, and the binary links it in place
# of the kernel sources. So no instruction of a kernel runs, the binary
# runs on every x86-64 CPU, and its counts say which path the library
# chose. It holds a TCP object's record layer and a QUIC object's
# packet calls, so it compiles both under the QUIC and suite defines. What
# the kernels compute is held by the equivalence binaries and by the
# vectors the host binaries run under the kernels' bits.
X86_KERNELS_TEST_SRCS := $(filter-out chacha20_avx2.c gcm_vaes.c keccak_avx2.c mlkem_avx2.c poly1305_avx2_native.c, \
                           $(call host_srcs,record.c \
                           quic_packet.c quic_keys.c quic_initial.c aes.c $(AES_HW_SRCS) quic_aes_soft.c gcm.c aead.c \
                           chacha20.c poly1305.c hkdf.c sha256.c sha512.c sha512_compress.c buf.c ct.c ct_wipe.c \
                           mlkem.c mlkem_poly.c sha3.c))
bin/x86_kernels_test: test/x86_kernels_test.c test/x86_kernels_count.c $(X86_KERNELS_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest -o $@ \
	  test/x86_kernels_test.c test/x86_kernels_count.c $(X86_KERNELS_TEST_SRCS)
GHASH_EQUIV_TEST_SRCS := test/ghash_equiv_soft.c test/stack_residue.c gcm.c aes.c $(AES_HW_SRCS) quic_aes_soft.c \
                         $(call host_srcs,hkdf.c sha256.c) ct.c ct_wipe.c
bin/ghash_equiv_test: test/ghash_equiv_test.c $(GHASH_EQUIV_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -I. -o $@ test/ghash_equiv_test.c \
	  $(GHASH_EQUIV_TEST_SRCS)
# The same two rules for the ROLE=server mode, over the role's sources under
# -DCH_ROLE_SERVER. Beside the seven srv sources it links what the implemented
# ones call, which is SRV_BELOW: srv_message.c and srv_cookie.c read and write
# through buf.c, srv_cookie.c calls hkdf.c for the cookie MAC, ct.c for the
# comparison and ct_wipe.c for the wipe, srv_auth.c calls sha256.c for the
# CertificateVerify signed content and ct_wipe.c for the wipes after it, srv.c
# compares ALPN names with ct_memeq, srv_handshake.c wipes its handshake_state
# and fails the session through tlsi_fail, and session.c's alert path pulls the record
# layer, the I/O shim and the key derivation record.c runs with it.
# srv_parser.c reads through buf.c, hashes the frozen fields through sha256.c
# and compares ALPN names with ct_memeq. srv_flight.c adds keysched.c for
# the key schedule and handshake_record.c for the messages it reads, and
# srv_kex.c adds the key exchange: x25519.c, p256_ecdh.c over the P-256
# arithmetic SRV_SIGNERS lists, and the ML-KEM-768 and SHA-3 sources
# every server role carries. No stub is left in the role.
SRV_BELOW := buf.c ct.c ct_wipe.c session.c io.c record.c aead.c chacha20.c poly1305.c hkdf.c sha256.c \
             keysched.c x25519.c p256_ecdh.c handshake_record.c $(KEX_HYBRID_SRCS)
# The two signers srv_auth.c calls, each with the arithmetic it computes
# over, and the two verifiers its boot-time check calls. Every binary
# that links srv_auth.c links these, and so does the ROLE=server object
# through ROLE_ADD.
SRV_SIGNERS := rsa_sign.c rsa.c rsa_mont.c p256_sign.c p256_scalar.c p256_point.c \
               p256_field.c p256.c
bin/srv_auth_test: test/srv_auth_test.c $(SRV_SRCS) $(SRV_BELOW) $(SRV_SIGNERS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -I. -Itest -o $@ test/srv_auth_test.c $(SRV_SRCS) \
	  $(SRV_BELOW) $(SRV_SIGNERS)
# The e2e server: this tree's ROLE=server object behind a TCP socket,
# which test/e2e.sh drives OpenSSL's s_client and this tree's own client
# against, a full handshake and then a resumed one each.
bin/tlsserver: test/tls_server.c $(SRV_SRCS) $(SRV_BELOW) $(SRV_SIGNERS) tls.c tls_write.c \
               handshake_post.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -I. -Itest -o $@ test/tls_server.c $(SRV_SRCS) \
	  $(SRV_BELOW) $(SRV_SIGNERS) tls.c tls_write.c handshake_post.c
# The same server under -DCH_SUITE_AES_GCM in a host object, whose
# sessions state the AES instructions (test/tls_server.c), which
# test/e2e.sh drives with s_client restricted to one suite at a time. A
# compiler that fails the host test builds none of it, and e2e says so.
TLSSERVER_AES_SRCS = $(call host_srcs,$(SRV_SRCS) $(SRV_BELOW) $(SRV_SIGNERS) tls.c tls_write.c \
                       handshake_post.c aes.c $(AES_HW_SRCS) gcm.c sha512.c sha512_compress.c)
bin/tlsserver_aes: test/tls_server.c $(TLSSERVER_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_ROLE_SERVER $(HOST_SUITE_DEF) -I. -Itest -o $@ test/tls_server.c \
	  $(TLSSERVER_AES_SRCS)
# The same server on AES=extern, its AES blocks answered by
# test/aes_extern_hook.c. It needs no AES instruction, so e2e runs it on
# every host.
bin/tlsserver_aes_extern: test/tls_server.c $(SRV_SRCS) $(SRV_BELOW) $(SRV_SIGNERS) tls.c \
                          tls_write.c handshake_post.c aes.c $(AES_EXTERN_DEPS) gcm.c sha512.c \
                          sha512_compress.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER $(AES_EXTERN_SUITE_DEF) -I. -Itest -o $@ test/tls_server.c \
	  $(SRV_SRCS) $(SRV_BELOW) $(SRV_SIGNERS) tls.c tls_write.c handshake_post.c aes.c \
	  $(AES_EXTERN_SRCS) gcm.c sha512.c sha512_compress.c
# The role's unit vectors: the messages srv_message.c writes, the cookie
# srv_cookie.c mints and opens, and the ClientHello srv_parser.c reads. It
# links those sources and their dependencies alone, not the whole role,
# because the builders, the cookie and the parser are pure functions over
# caller buffers and touch no session.
SRV_DEPS := buf.c ct.c ct_wipe.c sha256.c hkdf.c aead.c chacha20.c poly1305.c
# The QUIC server driver end to end: this tree's own ClientHello, built by
# handshake_message.c, through srv_quic.c and out as the flight it pushes.
# It links both sides of the connection on purpose, which no packaged
# object does, so the builder and the parser check each other.
SRV_QUIC_SRCS := srv_quic.c srv_flight.c srv_out.c srv_message.c srv_cookie.c srv_auth.c \
                 srv_ticket.c srv_resume.c srv_kex.c p256_ecdh.c $(KEX_HYBRID_SRCS) \
                 srv_parser.c srv_parser_ext.c srv.c handshake_message.c handshake_record.c \
                 quic_fail.c quic.c quic_keys.c quic_packet.c quic_initial.c quic_retry.c \
                 aes.c quic_aes_soft.c gcm.c quic_config.c buf.c ct.c ct_wipe.c sha256.c \
                 hkdf.c keysched.c x25519.c chacha20.c poly1305.c aead.c rsa_sign.c \
                 p256_sign.c p256_scalar.c p256_point.c p256_field.c p256.c rsa.c rsa_mont.c \
                 quic_token.c
bin/srv_quic_test: test/srv_quic_test.c $(SRV_QUIC_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -o $@ test/srv_quic_test.c \
	  $(SRV_QUIC_SRCS)

# The same main over a ROLE=both TRANSPORT=quic-nonblocking object: the server's QUIC
# sources and the client's, in one binary. A session takes its Initial
# labels from the init call that made it, and only this build can show a
# session taking the wrong ones: a one-role object has one side.
SRV_QUIC_BOTH_SRCS := $(sort $(SRV_QUIC_SRCS) $(QUIC_DRIVER_SRCS))
bin/srv_quic_both_test: test/srv_quic_test.c $(SRV_QUIC_BOTH_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -o $@ \
	  test/srv_quic_test.c $(SRV_QUIC_BOTH_SRCS)

# Both QUIC drivers against each other in one ROLE=both object, the one
# colibri links, once per trust mode colibri builds: TRUST=raw-ecdsa for its
# runner image and TRUST=webpki for its local checks. Each resumes a ticket
# from this tree's server; the webpki build also links the chain verifier
# its full handshake would run, which the resumed one never calls.
bin/quic_loop_test: test/quic_loop_test.c $(SRV_QUIC_BOTH_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PIN_ECDSA -I. -Itest \
	  -o $@ test/quic_loop_test.c $(SRV_QUIC_BOTH_SRCS)
# The raw build under RAND=session (docs/decisions.md 77): every case
# above with the client's source and the server's apart, and
# test/quic_loop_session.h's checks of what each source handed out.
bin/quic_loop_session: test/quic_loop_test.c $(SRV_QUIC_BOTH_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(SESSION_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PIN_ECDSA \
	  -I. -Itest -o $@ test/quic_loop_test.c $(SRV_QUIC_BOTH_SRCS)
QUIC_LOOP_WEBPKI_SRCS := $(sort $(SRV_QUIC_BOTH_SRCS) $(WEBPKI_SRCS) $(WEBPKI_CHAIN_SRCS) x509_der.c \
                                $(KEX_HYBRID_SRCS) $(WEBPKI_KEX_SRCS))
bin/quic_loop_webpki: test/quic_loop_test.c $(QUIC_LOOP_WEBPKI_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI -I. \
	  -Itest -o $@ test/quic_loop_test.c $(QUIC_LOOP_WEBPKI_SRCS)
# The same loop under -DCH_SUITE_AES_GCM in a host object, the object
# colibri links for a suite build: each of the three suites over QUIC, full
# and resumed, with a key update (test/quic_loop_suites.h), with both ends
# stating the AES instructions, and the rows of test/quic_loop_runtime.h,
# which set each end's ch_cfg.cpu with and without the AES bit.
QUIC_LOOP_AES_SRCS := $(filter-out $(AES_IMPL_SRCS),$(QUIC_LOOP_WEBPKI_SRCS)) $(AES_HW_SRCS) quic_aes_soft.c
bin/quic_loop_aes: test/quic_loop_test.c test/quic_loop_suites.h test/quic_loop_runtime.h \
                   $(call host_srcs,$(QUIC_LOOP_AES_SRCS)) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI \
	  $(HOST_SUITE_DEF) -I. -Itest -o $@ test/quic_loop_test.c $(call host_srcs,$(QUIC_LOOP_AES_SRCS))
# QUIC packet and header protection under the two AES-GCM suites against
# an independent computation, the key update and the §6.6 count
# (test/quic_suite_test.c), on the AES instructions of a QUIC host object.
# QUIC_SUITE_TEST_DEVICE_SRCS is the list without a host object's native
# copies, which bin/quic_suite_test_extern, a device object, links.
QUIC_SUITE_TEST_DEVICE_SRCS := quic_packet.c quic_keys.c aes.c $(AES_HW_SRCS) quic_aes_soft.c gcm.c \
                               hkdf.c sha256.c sha512.c sha512_compress.c chacha20.c poly1305.c aead.c buf.c ct.c \
                               ct_wipe.c
QUIC_SUITE_TEST_SRCS := $(call host_srcs,$(QUIC_SUITE_TEST_DEVICE_SRCS))
bin/quic_suite_test: test/quic_suite_test.c $(QUIC_SUITE_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -o $@ test/quic_suite_test.c \
	  $(QUIC_SUITE_TEST_SRCS)

# The AES=extern binaries. An AES=extern object runs every AES block on the
# image's ch_aes_block, so these binaries link test/aes_extern_hook.c as
# that hook: quic_aes_soft.c's FIPS 197 cipher under second names, for
# 16-byte and 32-byte keys, which aborts on any other key length. The
# library code under test is aes_extern.c and everything above it, and
# the vectors and the loops are the ones the host binaries run. The suite
# binaries state CH_AES_EXTERN_CONSTANT_TIME on their own lines, because
# ct.h refuses the suite without it; the part behind the hook is this
# host, and the keys are test keys.
# No binary here needs an AES instruction, so every compiler builds them
# and check runs them on every host. The hook includes quic_aes_soft.c,
# which is why that file is a prerequisite and not on a compile line.
AES_EXTERN_SRCS := aes_extern.c test/aes_extern_hook.c
AES_EXTERN_DEPS := $(AES_EXTERN_SRCS) quic_aes_soft.c
AES_EXTERN_BINS := bin/quic_test_extern bin/aes_suite_test_extern bin/quic_suite_test_extern \
                   bin/webpki_loop_aes_extern bin/quic_loop_aes_extern bin/tcp_blocking_key_limit \
                   bin/webpki_session_aes_extern
# FIPS 197, SP 800-38D and RFC 9001 Appendix A through the hook, AES-256
# included, and what aes_extern.c writes into round_keys at the exact
# bound (test_extern_layout).
bin/quic_test_extern: test/quic_vectors.c aes.c $(AES_EXTERN_DEPS) gcm.c quic_keys.c quic_retry.c \
                      quic_initial.c quic_packet.c hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c \
                      ct.c ct_wipe.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_AES_EXTERN $(AES_256_TEST_DEF) -I. -o $@ \
	  test/quic_vectors.c aes.c $(AES_EXTERN_SRCS) gcm.c quic_keys.c quic_retry.c quic_initial.c \
	  quic_packet.c hkdf.c sha256.c chacha20.c poly1305.c aead.c buf.c ct.c ct_wipe.c
# TLS_AES_128_GCM_SHA256 in the record layer against RFC 8448's printed
# record, as bin/aes_suite_test runs it.
bin/aes_suite_test_extern: test/aes_suite_test.c record.c gcm.c aes.c $(AES_EXTERN_DEPS) aead.c \
                           chacha20.c poly1305.c hkdf.c sha256.c sha512.c sha512_compress.c ct.c ct_wipe.c buf.c \
                           $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(AES_EXTERN_SUITE_DEF) -I. -o $@ test/aes_suite_test.c record.c gcm.c aes.c \
	  $(AES_EXTERN_SRCS) aead.c chacha20.c poly1305.c hkdf.c sha256.c sha512.c sha512_compress.c \
	  ct.c ct_wipe.c buf.c
# QUIC packet and header protection under both AES suites against the
# independent computation bin/quic_suite_test checks, AES-256 included.
bin/quic_suite_test_extern: test/quic_suite_test.c $(filter-out $(AES_IMPL_SRCS),$(QUIC_SUITE_TEST_DEVICE_SRCS)) \
                            $(AES_EXTERN_DEPS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_EXTERN_SUITE_DEF) -I. -o $@ \
	  test/quic_suite_test.c $(filter-out $(AES_IMPL_SRCS),$(QUIC_SUITE_TEST_DEVICE_SRCS)) $(AES_EXTERN_SRCS)
# This tree's client against this tree's server over QUIC, on the
# AES=extern suite object: the rows bin/quic_loop_aes runs, each suite
# full and resumed. Both ends run the same hook, so a loop alone cannot
# tell a wrong cipher from a right one; the vectors above and the
# Wycheproof and e2e tests are what can. The tcp-nonblocking loop on this
# object, bin/webpki_loop_aes_extern, sits below WEBPKI_LOOP_SRCS.
QUIC_LOOP_AES_EXTERN_SRCS := $(filter-out $(AES_IMPL_SRCS),$(QUIC_LOOP_WEBPKI_SRCS)) $(AES_EXTERN_SRCS)
bin/quic_loop_aes_extern: test/quic_loop_test.c test/quic_loop_suites.h $(QUIC_LOOP_AES_EXTERN_SRCS) \
                          quic_aes_soft.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI \
	  $(AES_EXTERN_SUITE_DEF) -I. -Itest -o $@ test/quic_loop_test.c $(QUIC_LOOP_AES_EXTERN_SRCS)

# bin/aes_runtime_test runs RFC 9001 and RFC 9369 Appendix A with the
# CH_CPU_CONSTANT_TIME_AES bit and without it, in a QUIC host object, and
# counts which cipher ran each call, through test/aes_runtime_soft.c and
# test/aes_runtime_hw.c, which compile quic_aes_soft.c, aes_hw.c and
# ghash_hw.c in under counting entries; so those three are prerequisites
# and not on the line (docs/decisions.md 81 and 89). test/aes-runtime-qemu.sh
# builds it for x86-64 and runs its half without the bit on a CPU model
# without AES-NI and PCLMULQDQ.
AES_RUNTIME_TEST_SRCS := $(call host_srcs,aes.c gcm.c gcm_vaes.c quic_initial.c quic_retry.c quic_packet.c \
                           quic_keys.c hkdf.c sha256.c sha512.c sha512_compress.c chacha20.c poly1305.c aead.c \
                           buf.c ct.c ct_wipe.c)
bin/aes_runtime_test: test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c \
                      $(AES_RUNTIME_TEST_SRCS) $(AES_HW_SRCS) quic_aes_soft.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest -o $@ \
	  test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c $(AES_RUNTIME_TEST_SRCS)

# The tcp-nonblocking server driver, over the same flight sources the blocking
# server builds: srv_tcp_nonblocking.c replaces srv_handshake.c and
# tcp_nonblocking_frame.c comes with the transport, and no
# tcp_nonblocking_step.c, which is the client's table.
SRV_TCP_NONBLOCKING_SRCS := $(filter-out srv_handshake.c,$(SRV_SRCS)) srv_tcp_nonblocking.c tcp_nonblocking.c tcp_nonblocking_frame.c $(KEX_HYBRID_SRCS) \
                handshake_message.c handshake_record.c record.c session.c buf.c ct.c ct_wipe.c sha256.c hkdf.c keysched.c \
                x25519.c chacha20.c poly1305.c aead.c io.c rsa_sign.c p256_sign.c p256_ecdh.c \
                p256_scalar.c p256_point.c p256_field.c p256.c rsa.c rsa_mont.c
bin/srv_tcp_nonblocking_test: test/srv_tcp_nonblocking_test.c $(SRV_TCP_NONBLOCKING_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_TRANSPORT_TCP_NONBLOCKING -I. -o $@ test/srv_tcp_nonblocking_test.c \
	  $(SRV_TCP_NONBLOCKING_SRCS)

# Both tcp-nonblocking drivers against each other in one process, under the
# defines of the one object that carries both: ROLE=both
# TRANSPORT=tcp-nonblocking. It is the client half's INV-28 test --
# bin/tlsclient_tcp_nonblocking needs a live server and runs in check-slow,
# so that side's claim was checked once a night. The two filters are the
# ones that arm applies, written the same way here. The list is otherwise
# $(SRCS) whole, like every other test binary, so it also links the
# certificate parsers a raw-rsa object filters out and this program never
# reaches.
TCP_NONBLOCKING_LOOP_SRCS := $(filter-out handshake.c,$(SRCS)) tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c \
                 $(filter-out srv_handshake.c,$(SRV_SRCS)) srv_tcp_nonblocking.c $(KEX_HYBRID_SRCS) \
                 rsa_sign.c p256_sign.c $(P256_ECDH_SRCS)
bin/tcp_nonblocking_loop_test: test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING $(EXPORTER_DEF) -DCH_KEYLOG \
	  -I. -o $@ test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS)
# The same main with the KEX=pq client, which offers X25519MLKEM768 alone,
# so the server's hybrid half runs against this tree's own client for a
# full handshake and a resumed one. The Makefile refuses KEX beside
# ROLE=both for a packaged object, because the server half would ignore it;
# a test binary may set it, because here it chooses only the client's
# group, which is what the case is about.
bin/tcp_nonblocking_loop_pq: test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_KEX_PQ $(EXPORTER_DEF) \
	  -DCH_KEYLOG -I. -o $@ test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS)
# The same KEX=pq main under RAND=session, where each session draws from
# the source its ch_cfg names (docs/decisions.md 77). Every case above runs
# with the client's source and the server's apart, and
# test/tcp_nonblocking_session_tests.h checks what each handed out: the
# draws, a replay from two seeds, the refusals of a configuration with no
# source, and the RSA-PSS salt. KEX=pq is the build whose full handshake
# runs the most draw sites: the ML-KEM seed and the encapsulation
# randomness as well as the scalars, the randoms and the salt.
bin/tcp_nonblocking_loop_session: test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS) $(HDRS) \
                                  $(TESTH)
	@mkdir -p bin
	$(CC) $(SESSION_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_KEX_PQ \
	  $(EXPORTER_DEF) -DCH_KEYLOG -I. -o $@ test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS)
# Each tcp-blocking driver against the other role's flight handlers, which
# the test calls from inside the driver's recv callback, under the defines
# of the one object that carries both blocking drivers: ROLE=both
# TRANSPORT=tcp-blocking. It holds both drivers to RFC 9846 section 5.1's
# record boundary (INV-39), which bin/tcp_nonblocking_loop_test holds for
# the other transport. The list is $(SRCS) and the server's sources, the
# way that test's list is.
TCP_BLOCKING_LOOP_SRCS := $(SRCS) $(SRV_SRCS) $(KEX_HYBRID_SRCS) rsa_sign.c p256_sign.c \
                          $(P256_ECDH_SRCS)
bin/tcp_blocking_loop_test: test/tcp_blocking_loop_test.c $(TCP_BLOCKING_LOOP_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I. -o $@ test/tcp_blocking_loop_test.c \
	  $(TCP_BLOCKING_LOOP_SRCS)
# The same main as a ROLE=both SUITE=aesgcm host object, whose raw client
# half runs tls.c's raw and ca rules: every case above with both ends
# stating the AES instructions, the rows of test/tcp_blocking_loop_cpu.h
# and test/tcp_blocking_loop_runtime.h's row (docs/decisions.md 81 and 89).
TCP_BLOCKING_LOOP_AES_SRCS = $(call host_srcs,$(TCP_BLOCKING_LOOP_SRCS) aes.c $(AES_HW_SRCS) gcm.c sha512.c \
                               sha512_compress.c)
bin/tcp_blocking_loop_aes: test/tcp_blocking_loop_test.c test/tcp_blocking_loop_runtime.h \
                           $(TCP_BLOCKING_LOOP_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH $(HOST_SUITE_DEF) -I. -o $@ \
	  test/tcp_blocking_loop_test.c $(TCP_BLOCKING_LOOP_AES_SRCS)
# The same main under RAND=session (docs/decisions.md 77): every case above
# with the client's source and the server's apart, and
# test/tcp_blocking_session_tests.h's checks of what each source handed out.
bin/tcp_blocking_loop_session: test/tcp_blocking_loop_test.c $(TCP_BLOCKING_LOOP_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(SESSION_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I. -o $@ test/tcp_blocking_loop_test.c \
	  $(TCP_BLOCKING_LOOP_SRCS)
# The AES-GCM key-usage ceiling between the two tcp-blocking sessions of
# the ROLE=both TRUST=webpki SUITE=aesgcm object, on AES=extern so every
# host builds it: ch_connect against the server's flight handlers, then
# test/key_limit_cases.h's writes across the ceiling each way
# (docs/decisions.md 78). bin/webpki_loop_aes runs the same cases over
# tcp-nonblocking.
TCP_BLOCKING_KEY_LIMIT_SRCS := $(sort $(filter-out pem.c x509.c x509_ca.c,$(TCP_BLOCKING_LOOP_SRCS)) \
                                      $(WEBPKI_SRCS) $(WEBPKI_CHAIN_SRCS) $(WEBPKI_KEX_SRCS))
bin/tcp_blocking_key_limit: test/tcp_blocking_key_limit_test.c $(TCP_BLOCKING_KEY_LIMIT_SRCS) aes.c \
                            $(AES_EXTERN_DEPS) gcm.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI $(AES_EXTERN_SUITE_DEF) -I. \
	  -o $@ test/tcp_blocking_key_limit_test.c $(TCP_BLOCKING_KEY_LIMIT_SRCS) aes.c $(AES_EXTERN_SRCS) \
	  gcm.c
# The TRUST=webpki tcp-nonblocking client against this tree's tcp-nonblocking
# server, over
# the ROLE=both TRANSPORT=tcp-nonblocking TRUST=webpki object's sources: the server
# presents the r2 corpus chain with its leaf key, and a server holding
# another ticket key declines the client's ticket (docs/decisions.md 55).
WEBPKI_LOOP_SRCS := $(sort $(filter-out pem.c x509.c x509_ca.c,$(TCP_NONBLOCKING_LOOP_SRCS)) \
                           $(WEBPKI_SRCS) $(WEBPKI_CHAIN_SRCS) $(WEBPKI_KEX_SRCS))
bin/webpki_loop_tcp_nonblocking: test/webpki_loop_test.c $(WEBPKI_LOOP_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_TRUST_WEBPKI \
	  -I. -o $@ test/webpki_loop_test.c $(WEBPKI_LOOP_SRCS)
# The same loop at TX_RECORD=16384, the object stompy links: every row
# above, and test/webpki_loop_tx_record.h's application records of
# CH_TX_PT bytes each way (docs/decisions.md 71). The define is written
# here, as the other loop binaries write theirs, so the binary is the
# same whatever this make was given.
bin/webpki_loop_tx_record: test/webpki_loop_test.c test/webpki_loop_tx_record.h $(WEBPKI_LOOP_SRCS) \
                           $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_TRUST_WEBPKI \
	  -DCH_TX_PT=16384 -I. -o $@ test/webpki_loop_test.c $(WEBPKI_LOOP_SRCS)
# The TX_RECORD axis in one target, for check-lib-tx-record: the range
# and the refusals of the headers, make and build.zig, then the loop above.
.PHONY: tx-record-check
tx-record-check: bin/webpki_loop_tx_record
	+./test/tx-record-builds.sh
	./bin/webpki_loop_tx_record
# The same loop under -DCH_SUITE_AES_GCM in a host object, with both ends
# stating the AES instructions: each of the three suites through a full
# handshake and a resumption, a SHA-384 ticket passed over by a SHA-256
# suite, h3spec's suite offer through the real parser
# (test/webpki_loop_suites.h), each end writing across its AES-GCM write
# key's ceiling (test/key_limit_cases.h), and test/webpki_loop_runtime.h's
# rows, which set each end's ch_cfg.cpu with and without the AES bit. A
# TCP host object holds no table, so the bit chooses the suites alone.
WEBPKI_LOOP_AES_SRCS = $(call host_srcs,$(WEBPKI_LOOP_SRCS) aes.c $(AES_HW_SRCS) gcm.c)
bin/webpki_loop_aes: test/webpki_loop_test.c test/webpki_loop_suites.h test/webpki_loop_runtime.h \
                     $(WEBPKI_LOOP_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_TRUST_WEBPKI \
	  $(HOST_SUITE_DEF) -I. -o $@ test/webpki_loop_test.c $(WEBPKI_LOOP_AES_SRCS)
# The same loop on the AES=extern suite object, the rows bin/webpki_loop_aes
# runs. Both ends run the same hook, so a loop alone cannot tell a wrong
# cipher from a right one; the vectors and the Wycheproof and e2e tests are
# what can. The rule sits below WEBPKI_LOOP_SRCS, because make expands a
# rule's prerequisites where it reads the rule: above it the list was
# empty, and an edit to a library source left this binary as it was.
bin/webpki_loop_aes_extern: test/webpki_loop_test.c test/webpki_loop_suites.h $(WEBPKI_LOOP_SRCS) \
                            aes.c $(AES_EXTERN_DEPS) gcm.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_TRUST_WEBPKI \
	  $(AES_EXTERN_SUITE_DEF) -I. -o $@ test/webpki_loop_test.c $(WEBPKI_LOOP_SRCS) aes.c \
	  $(AES_EXTERN_SRCS) gcm.c
bin/srv_test: test/srv_test.c srv_message.c srv_cookie.c srv_ticket.c srv_parser.c \
              srv_parser_ext.c $(SRV_DEPS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -I. -o $@ test/srv_test.c srv_message.c srv_cookie.c \
	  srv_ticket.c srv_parser.c srv_parser_ext.c $(SRV_DEPS)
# The flight handlers, in their own binary. test/srv_flight_tests.h defines
# srv_parse_client_hello itself, so the flight cases drive every answer the
# parser's contract admits rather than only the ones a real hello produces;
# that definition and srv_parser.c cannot link into one object.
SRV_FLIGHT_DEPS := buf.c ct.c ct_wipe.c sha256.c hkdf.c keysched.c x25519.c p256_ecdh.c handshake_record.c io.c $(KEX_HYBRID_SRCS) \
                   record.c aead.c chacha20.c poly1305.c
bin/srv_flight_test: test/srv_flight_test.c $(SRV_FLIGHT_SRCS) $(SRV_FLIGHT_DEPS) $(SRV_SIGNERS) \
                     $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_ROLE_SERVER -I. -o $@ test/srv_flight_test.c $(SRV_FLIGHT_SRCS) \
	  $(SRV_FLIGHT_DEPS) $(SRV_SIGNERS)
# SHA-512 and SHA-384 vectors and the streaming contract. Its own binary,
# out of the packaged object like sha3: only TRUST=webpki links sha512.c.
SHA512_TEST_SRCS := sha512.c sha512_compress.c
bin/sha512_test: test/sha512_test.c $(SHA512_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/sha512_test.c $(SHA512_TEST_SRCS)
# HMAC-SHA-384 and the SHA-384 key schedule against RFC 4231 and a
# published TLS_AES_256_GCM_SHA384 trace. -DCH_HASH_SHA384 turns SHA-384
# on in hkdf.c without the AES suite, which needs the AES instructions, so
# this runs on every host.
HKDF384_SRCS := hkdf.c keysched.c sha256.c sha512.c sha512_compress.c ct.c ct_wipe.c
bin/hkdf384_test: test/hkdf384_test.c $(HKDF384_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_HASH_SHA384 -I. -o $@ test/hkdf384_test.c $(HKDF384_SRCS)
# P-384 ECDSA verification against RFC 6979 A.2.6 and openssl, and PKCS#1
# v1.5 against openssl: their own binaries, out of the packaged object
# like sha3, until TRUST=webpki links them.
P384_TEST_SRCS := p384.c p384_field.c buf.c sha512.c sha512_compress.c
bin/p384_test: test/p384_test.c $(P384_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/p384_test.c $(P384_TEST_SRCS)
# The same vectors on a host object's verifier, as bin/rsa_test_host runs
# RSA's: p384.c compiles the arm that calls p384_wide_verify.c
# (docs/decisions.md 97). It takes no ch_cfg.cpu value, because no bit
# picks a verifier. ct_wipe.c links for sha512_hw.c, which host_srcs
# writes beside sha512.c and which wipes its working state.
P384_TEST_HOST_SRCS := $(call host_srcs,$(P384_TEST_SRCS)) ct_wipe.c
bin/p384_test_host: test/p384_test.c $(P384_TEST_HOST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -o $@ test/p384_test.c $(P384_TEST_HOST_SRCS)
# A host object's P-384 against the portable files (docs/decisions.md 97):
# the field routine by routine, and then the verifier's verdicts. The
# binary compiles as a host object compiles its sources, so p384.c is the
# arm that calls p384_wide_verify.c and p384_field.c has no body, and
# test/p384_portable.c compiles what a device object holds beside them,
# the verifier under a second name.
P384_EQUIV_TEST_SRCS := p384.c p384_field.c $(P384_WIDE_SRCS) buf.c
P384_EQUIV_TEST_UNITS := test/p384_equiv_test.c test/p384_equiv_field.c test/p384_equiv_sign.c \
                         test/p384_portable.c
bin/p384_equiv_test: $(P384_EQUIV_TEST_UNITS) $(P384_EQUIV_TEST_SRCS) $(HDRS) $(TESTH) \
                     test/p384_equiv.h test/p384_portable.h
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ $(P384_EQUIV_TEST_UNITS) \
	  $(P384_EQUIV_TEST_SRCS)
# The constant-time P-256 field arithmetic, against vectors Python
# computed. Its own binary for the same reason: nothing links
# p256_field.c until the P-256 key exchange lands, and the module is
# testable without the rest of the stack. The CH_CT_WIDEMUL binary beside
# ct-widemul-check below runs the same vectors over ct.h's multiply
# decomposition, the form that ships to a target whose widening multiply
# is variable time (https://github.com/c4milo/chapulin/issues/53).
P256_FIELD_TEST_SRCS := p256_field.c
bin/p256_field_test: test/p256_field_test.c $(P256_FIELD_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/p256_field_test.c $(P256_FIELD_TEST_SRCS)
# Constant-time P-256 ECDH: key pairs, shared secrets, the points it
# refuses and the scalar boundary. Its own binary, like p384_test,
# because only the server roles and the TRUST=webpki client link
# p256_ecdh.c, and bin/unit builds neither.
P256_ECDH_TEST_SRCS := p256_ecdh.c p256_point.c p256_scalar.c p256_field.c ct.c ct_wipe.c
bin/p256_ecdh_test: test/p256_ecdh_test.c $(P256_ECDH_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/p256_ecdh_test.c $(P256_ECDH_TEST_SRCS)
# ECDSA P-256 signing against Python's integers and RFC 6979 A.2.5, and
# every signature checked again by the independent verifier in p256.c.
# Its own binary, out of the packaged object like p384_test: no client
# links a signer, and the module stays testable without the rest of the
# stack. p256.c is on the line as the cross-check, not as a dependency --
# p256_sign.c calls nothing in it, which is the whole point of the file
# (p256_sign.h).
P256_SIGN_SRC := p256_sign.c p256_scalar.c p256_point.c p256_field.c p256.c sha256.c hkdf.c buf.c ct.c ct_wipe.c
bin/p256_sign_test: test/p256_sign_test.c $(P256_SIGN_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -Itest -o $@ test/p256_sign_test.c $(P256_SIGN_SRC)
RSA_PKCS1_TEST_SRCS := rsa_pkcs1.c rsa.c rsa_mont.c sha256.c sha512.c sha512_compress.c ct.c ct_wipe.c
bin/rsa_pkcs1_test: test/rsa_pkcs1_test.c $(RSA_PKCS1_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -I. -o $@ test/rsa_pkcs1_test.c $(RSA_PKCS1_TEST_SRCS)
# The same vectors on a host object's rsa_vp1, as bin/rsa_test_host runs
# the RSA-PSS ones.
bin/rsa_pkcs1_test_host: test/rsa_pkcs1_test.c $(call host_srcs,$(RSA_PKCS1_TEST_SRCS)) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o $@ test/rsa_pkcs1_test.c $(call host_srcs,$(RSA_PKCS1_TEST_SRCS))
# The TRUST=webpki date reader and hostname matcher at their boundaries:
# their own binaries, out of the raw and ca objects like sha512, each
# over the DER primitives it reads through.
WEBPKI_TIME_SRC := webpki_time.c x509_der.c buf.c ct.c ct_wipe.c
WEBPKI_NAME_SRC := webpki_name.c x509_der.c buf.c ct.c ct_wipe.c
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
WEBPKI_SPKI_SRC := webpki_spki.c x509_der.c buf.c ct.c ct_wipe.c
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
# whole dependency closure is handshake_parser.c, handshake_parser_ee.c
# and buf.c.
HANDSHAKE_STRICT_SRCS := handshake_parser.c handshake_parser_ee.c buf.c
bin/handshake_strict_test: test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)

# The TRUST=webpki arms of the same parsers: the server_name
# acknowledgement, the ALPN selection and the server_certificate_type in
# EncryptedExtensions, and the three CertificateVerify schemes, with the
# PKCS#1 v1.5 two refused.
bin/handshake_strict_webpki: test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)

# The TRUST=webpki session surface: ch_connect's config rules, the
# ClientHello bytes and the fail-closed handshake, linked over the
# sources that object packages. Every webpki client offers the hybrid
# (docs/decisions.md 53), so the ML-KEM and SHA-3 sources are on the list
# and there is one build, not one per KEX value.
WEBPKI_TEST_SRCS := $(filter-out pem.c x509.c x509_ca.c,$(SRCS)) $(WEBPKI_CHAIN_SRCS) \
                    $(filter-out $(SRCS),$(WEBPKI_SRCS)) $(KEX_HYBRID_SRCS) $(WEBPKI_KEX_SRCS)
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
# The TRUST=webpki EncryptedExtensions flight handler: what the
# ClientHello asked for reaches the parser, and the certificate type the
# server selected reaches ch_tls.server_cert_type.
bin/webpki_encrypted_exts_test: test/webpki_encrypted_exts_test.c $(WEBPKI_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/webpki_encrypted_exts_test.c $(WEBPKI_TEST_SRCS)

# TRUST=webpki resumption (webpki_ticket.h) over both TCP drivers: the
# blocking one, and TRANSPORT=tcp-nonblocking's, which drops handshake.c for
# tcp_nonblocking.c, tcp_nonblocking_frame.c and tcp_nonblocking_step.c.
# The mock server signs the CertificateVerify of a declined ticket with the
# r2 corpus leaf key, so both binaries link the P-256 signer beside the
# client. The arithmetic under it is in WEBPKI_TEST_SRCS already, because
# the client's secp256r1 key exchange computes over it too.
P256_SIGN_SRCS := p256_sign.c
bin/webpki_resume_test: test/webpki_resume_test.c $(WEBPKI_TEST_SRCS) $(P256_SIGN_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -I. -o $@ test/webpki_resume_test.c $(WEBPKI_TEST_SRCS) \
	  $(P256_SIGN_SRCS)
WEBPKI_TCP_NONBLOCKING_SRCS := $(filter-out handshake.c,$(WEBPKI_TEST_SRCS)) tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c
bin/webpki_resume_tcp_nonblocking: test/webpki_resume_test.c $(WEBPKI_TCP_NONBLOCKING_SRCS) $(P256_SIGN_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI -DCH_TRANSPORT_TCP_NONBLOCKING -I. -o $@ test/webpki_resume_test.c \
	  $(WEBPKI_TCP_NONBLOCKING_SRCS) $(P256_SIGN_SRCS)

# The same main in the client that offers all three cipher suites
# (docs/decisions.md entries 45 and 58), so the mock can select either
# AES-GCM suite. The suite define needs a host object, so this binary
# builds only where HOST_TARGET found a host compiler, like
# bin/aes_suite_test. Its client states the AES instructions, so its hello
# lists the AES-first order, and the rows of test/webpki_suite_cases.h
# that clear the bit offer ChaCha20 alone and refuse a list that names an
# AES-GCM suite (docs/decisions.md 81 and 89).
WEBPKI_TEST_AES_SRCS = $(call host_srcs,$(WEBPKI_TEST_SRCS) aes.c $(AES_HW_SRCS) gcm.c)
bin/webpki_session_aes: test/webpki_session_test.c $(WEBPKI_TEST_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRUST_WEBPKI $(HOST_SUITE_DEF) -I. -o $@ test/webpki_session_test.c \
	  $(WEBPKI_TEST_AES_SRCS)
# The same main on the AES=extern suite object, through
# test/aes_extern_hook.c, on every host. Its ClientHello lists ChaCha20
# first where bin/webpki_session_aes lists AES-256-GCM first
# (docs/decisions.md 80). The rule sits below WEBPKI_TEST_SRCS for the
# reason bin/webpki_loop_aes_extern's does.
bin/webpki_session_aes_extern: test/webpki_session_test.c $(WEBPKI_TEST_SRCS) aes.c $(AES_EXTERN_DEPS) \
                               gcm.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI $(AES_EXTERN_SUITE_DEF) -I. -o $@ test/webpki_session_test.c \
	  $(WEBPKI_TEST_SRCS) aes.c $(AES_EXTERN_SRCS) gcm.c

# Certificate grammar strictness: one binary per PIN, because the
# profile's grammar is the build's grammar.
X509STRICT_SRC := test/x509_strict_test.c pem.c x509.c x509_der.c x509_ca.c buf.c sha256.c ct.c ct_wipe.c

# The provisioning tool the e2e suite feeds real openssl armour to.
PEMKEY_SRC := test/pemkey.c pem.c x509.c x509_der.c x509_ca.c buf.c sha256.c ct.c ct_wipe.c
bin/pemkey: $(PEMKEY_SRC) rsa.c rsa_mont.c $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -I. -o $@ $(PEMKEY_SRC) rsa.c rsa_mont.c

bin/pemkey_ecdsa: $(PEMKEY_SRC) p256.c $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -DCH_PIN_ECDSA -I. -o $@ $(PEMKEY_SRC) p256.c
X509STRICT_RSA_SRCS := $(X509STRICT_SRC) rsa.c rsa_mont.c
X509STRICT_ECDSA_SRCS := $(X509STRICT_SRC) p256.c
bin/x509strict: $(X509STRICT_RSA_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ $(X509STRICT_RSA_SRCS)

bin/x509strict_ecdsa: $(X509STRICT_ECDSA_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_PIN_ECDSA -I. -o $@ $(X509STRICT_ECDSA_SRCS)

# Sequence differential: every server message sequence to a bounded depth
# (ENUM_DEPTH overrides; the default sweep is ~466k sequences over both modes) against the
# Lean state machine's verdict. Links the stack minus the pinned
# verifiers, which it stubs — V in a sequence means "signature valid".
# `--shard K/N` checks the sequences whose index is K mod N, and
# test/handshake_sequence_shards.sh runs one shard per core.
HANDSHAKE_SEQUENCE_SRCS = $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
bin/handshake_sequence_test: test/handshake_sequence_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/handshake_sequence_test.c $(HANDSHAKE_SEQUENCE_SRCS)

bin/unit: test/unit_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/unit_test.c $(SRCS)

# The exporter, which no other binary compiles: EXPORTER=off is the
# default, so ks_exporter and ch_export exist only under these defines.
# It links $(SRCS) because ch_export sits in tls.c, and it is the one
# binary that checks the public call's refusals.
bin/exporter_test: test/exporter_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(EXPORTER_DEF) -I. -o $@ test/exporter_test.c $(SRCS)

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

bin/handshake_strict_pq: test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_KEX_PQ -I. -o $@ test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)

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
# ci-slow calls it.
CT_WIDEMUL_CFLAGS = $(filter-out $(HOST_WIDEMUL_DEF),$(CFLAGS)) -DCH_CT_WIDEMUL
bin/unit_ct_widemul: test/unit_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -o $@ test/unit_test.c $(SRCS)

bin/mlkem_test_ct_widemul: test/mlkem_test.c $(MLKEM_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -o $@ test/mlkem_test.c $(MLKEM_TEST_SRCS)
# The signer multiplies through ct_widemul in three files -- the field,
# the scalar arithmetic and, through them, every point addition -- so its
# vectors run over both forms for the reason the two above do.
bin/p256_sign_test_ct_widemul: test/p256_sign_test.c $(P256_SIGN_SRC) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -Itest -o $@ test/p256_sign_test.c $(P256_SIGN_SRC)

# p256_field.c multiplies through ct_widemul too, so its vectors run over
# both forms for the reason the two above do.
bin/p256_field_test_ct_widemul: test/p256_field_test.c $(P256_FIELD_TEST_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CT_WIDEMUL_CFLAGS) -I. -o $@ test/p256_field_test.c $(P256_FIELD_TEST_SRCS)

.PHONY: ct-widemul-check
ct-widemul-check: bin/unit_ct_widemul bin/mlkem_test_ct_widemul bin/p256_field_test_ct_widemul bin/p256_sign_test_ct_widemul
	./bin/unit_ct_widemul
	./bin/mlkem_test_ct_widemul
	./bin/p256_field_test_ct_widemul
	./bin/p256_sign_test_ct_widemul
	$(MAKE) wycheproof-ct-widemul

# The host object's multiply (docs/decisions.md 87 and 89). Its binaries
# compile as a host object compiles its sources: -DCH_CPU_RUNTIME, without
# the host test flags' CH_NATIVE_WIDEMUL, which ct.h refuses beside it
# (HOST_CFLAGS), and each file built on the multiply the binary links both
# under its own name and as its native copy, with the vector ChaCha20 and
# the vector Poly1305 a host object holds (host_srcs).
#
# The unit, ML-KEM, P-256 and RSA signing vectors, each one host binary
# that takes the ch_cfg.cpu value it runs under as its argument
# (test/test_cpu.h): its main hands the answer that value gives to every
# call built on the multiply and the value to every configuration it
# builds (test/test_widemul.h), and HOST_VECTOR_CPU runs it with
# CH_CPU_CONSTANT_TIME_MULTIPLY and without it, so the same vectors run
# through widemul.h's dispatchers on the native copies and then on the
# decomposition. The host Wycheproof test below does the same.
# bin/widemul_runtime_test counts which copy each operation ran. On
# x86-64 the unit suite runs once more, under X86_UNIT_CPU, which names
# AVX2: RFC 8439's vectors and every record the suite seals and opens
# then run ChaCha20 on the AVX2 kernel (test/test_aead.h). On both
# architectures it runs once more under HASH_UNIT_CPU, which names the
# SHA-256 instructions: FIPS 180-4's, RFC 4231's and RFC 5869's vectors and
# every record direction the suite keys then hash on them
# (test/test_hash.h).
HOST_VECTOR_CPU := 0x5 0x1
# $(1) the binary's stem, $(2) its main, $(3) the library sources it
# links, $(4) its own flags.
define HOST_VECTOR_BIN
bin/$(1)_host: $(2) $(3) $$(call host_srcs,$(3)) $$(HDRS) $$(TESTH)
	@mkdir -p bin
	$$(CC) $$(HOST_CFLAGS) -DCH_CPU_RUNTIME $(4) -I. -Itest -o $$@ $(2) $$(call host_srcs,$(3))
endef
HOST_VECTOR_TESTS := unit mlkem_test p256_ecdh_test p256_sign_test rsa_sign_test sha512_test hkdf384_test
$(eval $(call HOST_VECTOR_BIN,unit,test/unit_test.c,$(SRCS),))
$(eval $(call HOST_VECTOR_BIN,mlkem_test,test/mlkem_test.c,$(MLKEM_TEST_SRCS),))
$(eval $(call HOST_VECTOR_BIN,p256_ecdh_test,test/p256_ecdh_test.c,$(P256_ECDH_TEST_SRCS),))
$(eval $(call HOST_VECTOR_BIN,p256_sign_test,test/p256_sign_test.c,$(P256_SIGN_SRC),))
$(eval $(call HOST_VECTOR_BIN,rsa_sign_test,test/rsa_sign_test.c,$(RSA_SIGN_TEST_SRCS),$(RSA_WIDE_DEF)))
# FIPS 180-4's SHA-384 and SHA-512 vectors, RFC 4231's HMAC-SHA-384 and
# the TLS_AES_256_GCM_SHA384 key schedule, as a host object's session runs
# them: under HASH512_UNIT_CPU beside the two values every vector binary
# takes, which on arm64 names the SHA-512 instructions. sha512_hw.c wipes
# what it computes, so the first links ct_wipe.c beside the hash.
$(eval $(call HOST_VECTOR_BIN,sha512_test,test/sha512_test.c,$(SHA512_TEST_SRCS) ct_wipe.c,))
$(eval $(call HOST_VECTOR_BIN,hkdf384_test,test/hkdf384_test.c,$(HKDF384_SRCS),-DCH_HASH_SHA384))
# The counting test: the files whose entries widemul.h dispatches to again
# under the second names of test/widemul_count_names.h, in the
# test/widemul_count_*.c units, in place of the files, their native copies,
# the wide X25519 field and the three wide P-256 files that hold a
# dispatched entry, and the stubs that count each call
# (test/widemul_runtime_count.h). WIDEMUL_COUNTED names what the units
# replace on a link line. p256_field.c, p256_wide_field.c, the inverse both
# wide moduli call, the table of multiples of G and the verifier's points
# hold no dispatched entry, so a counting binary links them as they are
# (WIDEMUL_COUNT_FIELDS).
WIDEMUL_COUNT_UNITS := test/widemul_count_decomposed.c test/widemul_count_decomposed_point.c \
                       test/widemul_count_decomposed_scalar.c test/widemul_count_native.c \
                       test/widemul_count_native_vector.c test/widemul_count_native_avx2.c \
                       test/widemul_count_wide.c \
                       test/widemul_count_wide_p256.c test/widemul_count_sign64.c
WIDEMUL_COUNTED := $(WIDEMUL_COPIED) x25519.c p256_scalar.c p256_point.c rsa_sign.c
WIDEMUL_COUNT_FIELDS := p256_field.c p256_wide_field.c p256_wide_inverse.c p256_wide_table.c \
                        p256_wide_wipe.c p256_wide_verify_point.c
WIDEMUL_COUNT_SRCS := aead.c chacha20.c $(CHACHA_VECTOR_SRCS) hkdf.c sha256.c $(call hash_hw_of,hkdf.c sha256.c) \
                      ct.c ct_wipe.c buf.c record.c mlkem.c mlkem_vector.c keccak_avx2.c mlkem_avx2.c \
                      sha3.c p256.c p256_ecdh.c p256_sign.c rsa.c rsa_mont.c $(RSA_MONT64_SRCS) \
                      $(WIDEMUL_COUNT_FIELDS)
bin/widemul_runtime_test: test/widemul_runtime_test.c test/widemul_runtime_count.c $(WIDEMUL_COUNT_UNITS) \
                          $(WIDEMUL_COUNT_SRCS) $(WIDEMUL_COUNTED) x25519_wide.c poly1305_vector.c poly1305_avx2.c \
                          $(P256_WIDE_SRCS) $(RSA_SIGN64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/widemul_runtime_test.c test/widemul_runtime_count.c \
	  $(WIDEMUL_COUNT_UNITS) $(WIDEMUL_COUNT_SRCS)
# The host object's loop and session binaries (docs/decisions.md 89), each
# built as a host object builds its sources, on the same counting copies:
# the sources a loop links, with the files built on the multiply replaced by the count
# units and their stubs, and the two vector ChaCha20 sources, the vector
# NTT and the hash sources a host object holds beside its own added
# (widemul_counted), which each says with
# -DTEST_WIDEMUL_COUNTED, so a whole handshake reads which copy each end
# ran. Every case of each runs with both ends
# describing the CPU as TEST_CPU (test/test_cpu.h), which holds
# CH_CPU_CONSTANT_TIME_MULTIPLY. Its test/*_cpu.h rows hold ch_cfg.cpu's
# refusals at ch_connect, ch_record_init, ch_quic_init, ch_srv_accept,
# ch_srv_record_init, ch_srv_quic_init and ch_srv_check, and its
# test/*_widemul.h rows set each end's multiply bit. cpu_cfg.h refuses the
# define on a compiler that fails the host test, so the binaries are named
# only where HOST_TARGET found one, and check-skips says when it did not.
widemul_counted = $(filter-out $(WIDEMUL_COUNTED) $(WIDEMUL_COUNT_FIELDS),$(1)) $(WIDEMUL_COUNT_FIELDS) \
                  $(WIDEMUL_COUNT_UNITS) test/widemul_runtime_count.c $(CHACHA_VECTOR_SRCS) \
                  $(if $(filter rsa_mont.c,$(1)),$(RSA_MONT64_SRCS)) \
                  $(if $(filter p384.c,$(1)),$(P384_WIDE_SRCS)) \
                  $(if $(filter mlkem.c,$(1)),mlkem_vector.c keccak_avx2.c mlkem_avx2.c) \
                  $(call hash_hw_of,$(1))
bin/tcp_blocking_loop_host: test/tcp_blocking_loop_test.c $(TCP_BLOCKING_LOOP_SRCS) $(WIDEMUL_COUNT_UNITS) \
                            test/widemul_runtime_count.c $(RSA_MONT64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I. -Itest -o $@ \
	  test/tcp_blocking_loop_test.c $(call widemul_counted,$(TCP_BLOCKING_LOOP_SRCS))
bin/tcp_nonblocking_loop_host: test/tcp_nonblocking_loop_test.c $(TCP_NONBLOCKING_LOOP_SRCS) \
                               $(WIDEMUL_COUNT_UNITS) test/widemul_runtime_count.c $(RSA_MONT64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING \
	  $(EXPORTER_DEF) -DCH_KEYLOG -I. -Itest -o $@ test/tcp_nonblocking_loop_test.c \
	  $(call widemul_counted,$(TCP_NONBLOCKING_LOOP_SRCS))
bin/quic_loop_host: test/quic_loop_test.c $(QUIC_LOOP_AES_SRCS) $(WIDEMUL_COUNT_UNITS) \
                    test/widemul_runtime_count.c $(RSA_MONT64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING \
	  -DCH_TRUST_WEBPKI -I. -Itest -o $@ test/quic_loop_test.c $(call widemul_counted,$(QUIC_LOOP_AES_SRCS))
bin/webpki_session_host: test/webpki_session_test.c $(WEBPKI_TEST_SRCS) $(WIDEMUL_COUNT_UNITS) \
                         test/widemul_runtime_count.c $(RSA_MONT64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_TRUST_WEBPKI -I. -Itest -o $@ test/webpki_session_test.c \
	  $(call widemul_counted,$(WEBPKI_TEST_SRCS))
# The binaries of the host object's AES are named here with them: the
# vectors, the two equivalence tests, the two ciphers' counts, and each
# suite's record, QUIC, flight, session and loop tests, whose rows run with
# the CH_CPU_CONSTANT_TIME_AES bit and without it. So are the two
# equivalence tests of the host object's ChaCha20 and its vector Poly1305,
# and the equivalence test and the two counting tests of its SHA-256 on the
# CPU's instructions.
HOST_BINS := $(if $(HOST_TARGET),bin/tcp_blocking_loop_host bin/tcp_nonblocking_loop_host bin/quic_loop_host \
                                 bin/webpki_session_host bin/widemul_runtime_test bin/x25519_equiv_test \
                                 bin/p256_equiv_test bin/p256_equiv_test_sum bin/p256_equiv_test_builtin \
                                 bin/p256_verify_equiv_test bin/p384_equiv_test bin/p384_test_host \
                                 bin/chacha20_equiv_test bin/poly1305_equiv_test \
                                 bin/sha2_equiv_test bin/sha3_hw_equiv_test bin/mlkem_hw_equiv_test \
                                 bin/mlkem_vector_equiv_test bin/mlkem_avx2_equiv_test bin/hash_runtime_test \
                                 bin/hash_runtime_exporter_test \
                                 bin/rsa_equiv_test bin/rsa_equiv_test_compare bin/rsa_equiv_test_sum \
                                 bin/rsa_sign_equiv_test bin/rsa_test_host bin/rsa_pkcs1_test_host \
                                 bin/quic_test_hw bin/aes_equiv_test bin/ghash_equiv_test \
                                 bin/aes_runtime_test bin/aes_suite_test bin/quic_suite_test bin/srv_flight_test_aes \
                                 bin/webpki_session_aes bin/webpki_loop_aes bin/quic_loop_aes bin/tcp_blocking_loop_aes)
# The vector binaries, which check runs once for each value of
# HOST_VECTOR_CPU through a check-run- target of their own.
HOST_VECTOR_BINS := $(if $(HOST_TARGET),$(foreach t,$(HOST_VECTOR_TESTS),bin/$(t)_host))

# The TRANSPORT=tcp-nonblocking client, which owns its socket and lets chapulin
# touch none of it. test/e2e.sh runs it against the same PSK server
# bin/tlsclient uses, so the two drivers are compared over one wire.
TCP_NONBLOCKING_SRCS := $(filter-out handshake.c,$(SRCS)) tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c
bin/tlsclient_tcp_nonblocking: test/tcp_nonblocking_client.c $(TCP_NONBLOCKING_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_TCP_NONBLOCKING -I. -o $@ test/tcp_nonblocking_client.c $(TCP_NONBLOCKING_SRCS)

# The CA build's ticket epoch rule at the two non-blocking client entries,
# ch_record_init and ch_quic_init, from one main. No other test binary
# builds either transport under -DCH_TRUST_CA, and bin/unit_ca holds
# ch_connect to the same boundary. The QUIC one adds x509.c and
# x509_der.c, the CA chain verifier handshake_auth.c calls in that mode,
# which QUIC_DRIVER_SRCS leaves out.
bin/ticket_epoch_tcp_nonblocking: test/ticket_epoch_test.c $(TCP_NONBLOCKING_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -DCH_TRANSPORT_TCP_NONBLOCKING -I. -o $@ test/ticket_epoch_test.c \
	  $(TCP_NONBLOCKING_SRCS)
bin/ticket_epoch_quic: test/ticket_epoch_test.c $(QUIC_DRIVER_SRCS) x509.c x509_der.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_CA -DCH_TRANSPORT_QUIC_NONBLOCKING -I. -o $@ test/ticket_epoch_test.c \
	  $(QUIC_DRIVER_SRCS) x509.c x509_der.c

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

# The web PKI client that offers both cipher suites (docs/decisions.md
# entry 45). It is a host object whose sessions state the AES
# instructions (test/tls_client.c), so check builds it only where
# HOST_TARGET found a host compiler, and e2e skips its tests, saying so,
# where it is absent.
bin/tlsclient_webpki_aes: test/tls_client.c $(WEBPKI_TEST_AES_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRUST_WEBPKI $(HOST_SUITE_DEF) -I. -o $@ test/tls_client.c \
	  $(WEBPKI_TEST_AES_SRCS)
# The same client on AES=extern, for e2e's tests against OpenSSL, built
# on every host because the hook needs no AES instruction.
bin/tlsclient_webpki_aes_extern: test/tls_client.c $(WEBPKI_TEST_SRCS) aes.c $(AES_EXTERN_DEPS) gcm.c \
                                 $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRUST_WEBPKI $(AES_EXTERN_SUITE_DEF) -I. -o $@ test/tls_client.c \
	  $(WEBPKI_TEST_SRCS) aes.c $(AES_EXTERN_SRCS) gcm.c

# Every differential arm builds with RSA_WIDE_DEF, CH_RSA_MODULUS_MAX at
# 512: test/diff_rsa.h and test/diff_rsa_pkcs1.h sample a 4096-bit
# modulus, which rsa.h admits only at that bound, and the spec verifies
# any modulus, so the define is what keeps the two sides' domains equal.
# test/spec_coverage.py passes the same flag. diff-ecdsa, diff-pq and
# diff-webpki link DIFF_SRCS too, beside what their arm adds, and
# test/spec_coverage.py links it through print-diff-srcs.
DIFF_SRCS := $(SRCS) sha3.c sha512.c sha512_compress.c p384.c p384_field.c rsa_pkcs1.c webpki_sigalg.c webpki_cert.c mlkem.c mlkem_poly.c
.PHONY: print-diff-srcs
print-diff-srcs:
	@echo $(DIFF_SRCS)
bin/diff: test/diff_test.c $(DIFF_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_HASH_SHA384 -I. -o $@ test/diff_test.c $(DIFF_SRCS)

# Build and run one test binary: make run-unit, make run-webpki_time_test.
# check runs every binary on its roster through a check-run- target of
# its own, which holds the output until the run ends; this form prints as
# the binary runs, which suits an inner loop that wants a single binary.
# tools/impact.py emits this form for every binary it selects.
run-%: bin/%
	./bin/$*

.PHONY: check check-slow ci lint lint-tidy lint-format lint-cppcheck lint-docs lint-conflict-markers lint-invariants lint-violation-builds lint-violation-anchors lint-impact lint-fuzz-budget lint-codegen-partition lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-rfcs lint-shellcheck lint-bench-numbers lint-stack-walk lint-spec lint-p256-wide prove diff fmt clean
# check is the inner loop and holds a one-minute budget, so it runs what
# answers "did I break the build or a contract": the linters, every unit
# and strict-parser binary, the packaged-object export check, the
# Wycheproof vectors, and a build, not a run, of each program a bench or
# platform script compiles from a source list of its own.
#
# Every part of it is a prerequisite: the linters, each library build in
# CHECK_LIBRARY_BUILDS, each test binary's run, the Wycheproof vectors and
# the proof scan. So `make -j check` runs them side by side, and check's
# own recipe runs only once every part has passed. A library build or a
# run holds its output in bin/check/<target>.log and prints it whole when
# it ends, so two of them never interleave their lines, and a failure ends
# with a line that names its target. The linters skip what passed before
# on the same inputs (tools/stamp.py), so on an unchanged tree most of the
# time goes to the library builds and the runs.
#
# check-slow holds everything whose cost is minutes: the proofs, e2e
# against a real server, the spec differential, the sequence enumerations,
# and the invariant violation builds. The nightly runs it. Splitting on
# duration rather than on importance is deliberate -- nothing here is
# optional, and a change is not finished until check-slow passes too.
CHECK_BUILDS := bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa bin/tlsclient_webpki \
                $(if $(HOST_TARGET),bin/tlsclient_webpki_aes) bin/tlsclient_pq bin/tlsclient_tcp_nonblocking \
                bin/tlsserver
# The binaries check runs. The host object's are named only where the
# host test passed; check-skips says which were left out.
CHECK_RUN_BINS := unit unit_ca unit_pq drbg_test softmul_test rsa_test rsa_sign_test sha3_test sha3_equiv_test \
                  sha512_test \
                  hkdf384_test p384_test p256_field_test p256_ecdh_test p256_sign_test rsa_pkcs1_test \
                  webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test \
                  webpki_chain_test webpki_auth_test webpki_encrypted_exts_test mlkem_test quic_driver_test \
                  quic_test $(patsubst bin/%,%,$(AES_EXTERN_BINS)) \
                  $(patsubst bin/%,%,$(X86_KERNEL_BINS) $(HOST_BINS)) \
                  srv_auth_test srv_test srv_quic_test srv_quic_both_test srv_tcp_nonblocking_test \
                  tcp_nonblocking_loop_test tcp_nonblocking_loop_pq tcp_blocking_loop_test \
                  quic_loop_test quic_loop_webpki tcp_blocking_loop_session tcp_nonblocking_loop_session \
                  quic_loop_session \
                  webpki_loop_tcp_nonblocking exporter_test srv_flight_test handshake_strict_test \
                  handshake_strict_pq handshake_strict_webpki webpki_session_test webpki_resume_test \
                  webpki_resume_tcp_nonblocking x509strict x509strict_ecdsa \
                  ticket_epoch_tcp_nonblocking ticket_epoch_quic
CHECK_LIBRARY_BUILDS := check-lib-drbg check-lib-session check-lib-session-cxx check-lib-extern check-examples check-lib-ca-rsa check-lib-ca-ecdsa \
              check-lib-webpki check-lib-webpki-tcp-nonblocking check-lib-tx-record \
              check-lib-quic check-lib-quic-webpki-both check-lib-server check-lib-server-tcp-nonblocking \
              check-lib-raw-ecdsa-pq check-lib-exporter check-lib-server-quic-keylog \
              check-lib-server-aes check-lib-server-aes-extern check-lib-quic-aes \
              check-lib-pair \
              check-stack-webpki check-stack-exporter check-stack-quic check-stack-server
CHECK_RUN_HOST_VECTOR := $(patsubst bin/%,check-run-%,$(HOST_VECTOR_BINS))
.PHONY: $(CHECK_LIBRARY_BUILDS) $(addprefix check-run-,$(CHECK_RUN_BINS)) $(CHECK_RUN_HOST_VECTOR) \
        check-chacha-builds check-mlkem-builds check-widemul-builds check-host-builds check-hash-builds \
        check-script-builds check-wycheproof check-skips
check: lint rand-check $(CHECK_BUILDS) $(CHECK_LIBRARY_BUILDS) $(addprefix check-run-,$(CHECK_RUN_BINS)) \
       $(CHECK_RUN_HOST_VECTOR) \
       check-chacha-builds check-mlkem-builds check-widemul-builds check-host-builds check-hash-builds \
       check-script-builds check-wycheproof check-skips proof-coverage proof-reach-smoke
	@echo "check: every lint, library build and test run passed"

# A recipe line that runs a script which calls make itself starts with +,
# as a line that names $(MAKE) is treated without one, so make hands the
# script its jobserver. Without it, GNU make 4.3 under make -j gives the
# script's make no jobserver, and that make warns and prints its
# "Entering directory" lines to stdout even with --no-print-directory, so
# a script that reads a value from make reads those lines too. That is
# how test/x25519-builds.sh, which test/widemul-builds.sh has since taken
# over, failed on CI run 36277795480, the first make -j ci. make 3.81
# prints no such lines, so macOS never shows it.
#
# What a library build or a run ends with: its held output, and on a
# failure one line that names the target and its exit status.
CHECK_REPORT = rc=$$?; cat bin/check/$@.log; \
  [ $$rc -eq 0 ] || echo "check: $@ failed with exit $$rc; bin/check/$@.log holds its output"; exit $$rc

# One target per test binary, written out by $(eval) so that every run
# stays a line of the form ./bin/<name> in make's database, which is
# where tools/impact.py reads which binaries check runs.
define CHECK_RUN
check-run-$(1): bin/$(1)
	@mkdir -p bin/check; ./bin/$(1) > bin/check/$$@.log 2>&1; $$(CHECK_REPORT)
endef
$(foreach b,$(CHECK_RUN_BINS),$(eval $(call CHECK_RUN,$(b))))
# A host vector binary runs once for each ch_cfg.cpu value of
# HOST_VECTOR_CPU, which it takes as its argument (test/test_cpu.h), and
# its target fails when any run does. $(2) names the values a binary runs
# under beside those: the unit suite's, X86_UNIT_CPU on x86-64 and
# HASH_UNIT_CPU, and HASH512_UNIT_CPU for the two SHA-512 vector binaries.
define CHECK_RUN_HOST_VECTOR_BIN
check-run-$(1): bin/$(1)
	@mkdir -p bin/check; : > bin/check/$$@.log; rc=0; \
	for bits in $$(HOST_VECTOR_CPU) $(2); do ./bin/$(1) $$$$bits >> bin/check/$$@.log 2>&1 || rc=$$$$?; done; \
	(exit $$$$rc); $$(CHECK_REPORT)
endef
HASH_VECTOR_HOST := sha512_test_host hkdf384_test_host
$(foreach b,$(patsubst bin/%,%,$(HOST_VECTOR_BINS)),$(eval $(call CHECK_RUN_HOST_VECTOR_BIN,$(b),$(if $(filter unit_host,$(b)),$(X86_UNIT_CPU) $(HASH_UNIT_CPU))$(if $(filter $(HASH_VECTOR_HOST),$(b)),$(HASH512_UNIT_CPU)))))

# The host object's AES runs: the published vectors on the instructions
# and on the table, and each instruction path against its software twin
# over the same inputs -- the block cipher in bin/aes_equiv_test, GHASH in
# bin/ghash_equiv_test. CBMC cannot read an intrinsic, so these are what
# hold those paths (docs/quic.md, "What the AES axis proves"). The
# AES=extern runs are the
# same published vectors, the record layer's RFC 8448 record, the QUIC
# suite computation and both loops, on aes_extern.c over
# test/aes_extern_hook.c; they need no instruction, so they never skip.
# The wide X25519 field's runs are bin/unit_host's, with the multiply bit,
# and bin/x25519_equiv_test's, the field against the 16-word one over the
# same inputs. The host object's ChaCha20 runs are the unit suite and
# Wycheproof under each ch_cfg.cpu value, and each vector path against
# the portable loop over the same inputs. A compiler that fails the host
# test builds none of the host object's binaries, and on CI, whose
# runners all pass it, that skip is a failure.
check-skips:
	@[ -n "$(X86_KERNEL_BINS)" ] || echo "SKIP the x86-64 kernels' counts and the runs under their bits: $(CC) does not target x86-64"
ifeq ($(HOST_BINS),)
	$(call REQUIRE_ON_CI,the host test: arm64 or x86-64 with NEON or SSE2 and unsigned __int128)
	@echo "SKIP the host object's binaries: $(CC) fails the host test (docs/decisions.md 89)"
endif

# chacha20_vector.h's two refusals, a host object's calls to the vector
# ChaCha20 and, in Poly1305's native copy alone, to the vector Poly1305,
# and the x86-64 kernels' instructions in their own files.
check-chacha-builds:
	+@mkdir -p bin/check; ./test/chacha-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# A host object's calls to the vector NTT in place of mlkem_poly.c's loops,
# and a device object's calls to the loops (docs/decisions.md 101).
check-mlkem-builds:
	+@mkdir -p bin/check; ./test/mlkem-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# ct.h's rules for a host object's two multiplies, each file under its
# own names compiled to its decomposed build's code there, the vector
# Poly1305 called from poly1305_native.c alone, the 64x64->128 multiply in
# a host object alone, and the refusals of a WIDEMUL value for a host
# object and of the X25519 variable for every object in make and in
# build.zig (docs/decisions.md 87 and 89).
check-widemul-builds:
	+@mkdir -p bin/check; ZIG='$(ZIG)' ./test/widemul-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# The host test in cpu_cfg.h, the Makefile and build.zig, each against
# this host's compiler and the pinned clang's cross targets that fail one
# probe (docs/decisions.md 89).
check-host-builds:
	+@mkdir -p bin/check; ZIG='$(ZIG)' ./test/host-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# Which object holds a hash on the CPU's instructions and which file holds
# the instructions (docs/decisions.md 93): a device object's hash sources
# call no entry on the instructions, hash_hw.h refuses a copy outside a
# host object, sha256_hw.c compiles for x86-64 and arm64 with no
# instruction flag and holds the SHA-256 instructions, and each copy calls
# the hash on the instructions.
check-hash-builds:
	+@mkdir -p bin/check; ./test/hash-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# The programs the bench and platform scripts compile from source lists of
# their own, built and not run (test/script-builds.sh names them). No
# other part of check builds them, so a call a source gains into a file
# such a list leaves out failed only the script's next run: bench.yml's
# aead job failed to link that way (docs/decisions.md 88). It costs about
# 45 s of CPU and 9 s of wall on an M1 Pro, and it is skipped when it
# passed before on the same inputs: every .c and .h file, the scripts it
# runs, the Makefile, which they read lists and flags from, the
# compiler's version and the system's release (tools/stamp.py).
check-script-builds:
	+@mkdir -p bin/check; python3 tools/stamp.py check-script-builds --content '*.[ch]' \
	  --content 'bench/*.sh' --content test/qemu-m3.sh --content test/script-builds.sh \
	  $(STAMP_MAKEFILES) --output '$(CC) --version' --output 'uname -srm' -- \
	  env CC='$(CC)' ./test/script-builds.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# The Wycheproof tests, then the total docs/verification.md states against
# the vectors they ran. The second is not stamped: an edit to the page
# alone must meet it.
check-wycheproof:
	@mkdir -p bin/check; { $(MAKE) --no-print-directory wycheproof && python3 tools/wycheproof-total.py; } \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)

# The library builds. Each runs lib-check, and some cxx-check, in a
# recursive make for one variant. A variant's objects, its link and every
# file lib-check writes sit under bin/obj/<variant>/, so builds of
# different variants run at once. Two things are shared, and the
# prerequisites below order them: check-lib-extern and check-examples
# build the same variant, which the default configuration of
# test/zig-build-check.sh builds too, so the two wait for lint-zig-build
# and the second waits for the first; and test/lib-pair-check.sh builds
# objects of several of these variants, so it waits for every library
# build. cxx-check needs bin/srv_flight_test, which the builds that run
# it wait for rather than each building it at once.
#
# A lib-check build is skipped when it passed before on the same inputs:
# every file git does not ignore, the C and C++ compilers' versions, the
# system's release, which names the linker and nm, and the make
# variables (tools/stamp.py). check-examples is never skipped, because it
# copies its variant to the fixed paths test/e2e.sh runs, and a skip
# would leave there whatever an earlier build copied.
CHECK_LIBRARY_STAMP = python3 tools/stamp.py $@ --content . --output '$(CC) --version' \
  --output '$(CXX) --version' --output 'ld -v' --output 'uname -srm' --
#
# The packaged object is built once per entropy pattern, because
# lib-check reads a different export list and a different import list in
# each. Only the object is built twice: the examples and hpp_test define
# ch_rand_bytes, so they are extern-pattern programs and build beside the
# RAND=extern object only. The examples compile under the object's defines, so
# against the drbg object they stop at cfg.h, which rejects two entropy
# declarations, instead of linking into a binary whose first draw aborts
# on drbg.c's CH_ASSERT(g_seeded). The order of the builds does not
# matter to the fixed paths e2e runs: the example targets copy the
# variant they built into place on every invocation.
check-lib-drbg:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=drbg > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The pattern where each session names its own source (docs/decisions.md
# 77), on the object that compiles every one of the ten draw sites: a
# client and a server, over the tcp-nonblocking transport colibri's HTTP/2
# side links, with the TRUST=webpki client's P-256 retry. lib-check holds
# it to name no ch_rand_bytes and no ch_drbg_seed, defined or imported,
# and links test/build_test.c, which defines no hook under
# CH_RAND_SESSION. test/lib-check-rand-session.sh runs the same command
# for test/violations/.
check-lib-session:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking \
	  ROLE=both > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# chapulin.hpp's Config::rand_bytes on a RAND=session object.
# test/hpp_test.cpp connects over the tcp-blocking driver alone, so this
# target builds the default configuration, not the tcp-nonblocking one above,
# and lib-check holds this object to the same no-hook rule.
check-lib-session-cxx: bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=session > bin/check/$@.log 2>&1; \
	  $(CHECK_REPORT)
check-lib-extern: lint-zig-build bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=extern > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The examples are pinned to TRUST=raw-rsa and TRANSPORT=tcp-blocking, whatever
# this check was given. psk_client and pinned_client are raw-mode TLS
# programs: they call ch_connect, ch_write and ch_read, which a
# TRANSPORT=quic-nonblocking object does not export, and each drives a socket
# through the I/O callbacks that object has no use for. The fixed
# paths bin/example_psk and bin/example_pinned are what test/e2e.sh
# runs: `make check TRUST=webpki` used to leave the webpki-variant
# copies there, and the next e2e run started a PSK server against a
# client built for a mode that refuses a PSK.
check-examples: lint-zig-build check-lib-extern
	@mkdir -p bin/check; $(MAKE) examples-check RAND=extern TRUST=raw-rsa TRANSPORT=tcp-blocking \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The CA arm packages the provisioning reader and its fifth export;
# without this build neither the export list nor the C++ forwarder is
# checked by anything. Both pinned algorithms run, because the
# forwarder reads a certificate and the verifier that reads it is
# what the algorithm half names: with only the rsa build,
# test/hpp_test.cpp asserted an RSA modulus that a P-256 verifier
# refuses, and no build here noticed.
check-lib-ca-rsa: bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=extern TRUST=ca-rsa > bin/check/$@.log 2>&1; $(CHECK_REPORT)
check-lib-ca-ecdsa: bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=extern TRUST=ca-ecdsa > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The webpki arm exports the four calls and no provisioning call, and
# its C++ forwarders are the anchors, hostname and clock setters.
check-lib-webpki: bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=extern TRUST=webpki > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The same mode over the tcp-nonblocking transport, which is what a public-PKI
# host client on an event loop builds. It is the build that checks the
# tcp-nonblocking export list on the client side at all, and the one that
# catches an unguarded ch_connect: this transport compiles
# ch_record_init and no ch_connect, so a trust mode whose ch_connect
# is not guarded imports the ch_handshake nothing compiled
# (https://github.com/c4milo/chapulin/issues/171). It took 2.4 s cold.
check-lib-webpki-tcp-nonblocking:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# TX_RECORD at its ceiling, on the ROLE=both object stompy links for
# its uploads (docs/decisions.md 71): the export list and build record
# of an object whose ch_tls.tx holds a sealed record of 16,384 bytes,
# its frames against the webpki budget, the axis's range and refusals,
# and records of 16,384 bytes between the object's two drivers. It took
# 13.7 s cold and 7.2 s with everything built, 4 s of that lint-stack.
check-lib-tx-record:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check lint-stack tx-record-check RAND=extern TRUST=webpki \
	  TRANSPORT=tcp-nonblocking ROLE=both TX_RECORD=16384 > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The QUIC arm exports the sixteen ch_quic_ calls and none of the four
# tcp-blocking ones, so it is the build that holds PUBLIC_TRANSPORT to a
# replacement rather than an addition, and the one that compiles
# chapulin.hpp's Quic class against the object it forwards to.
check-lib-quic: bin/srv_flight_test
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check cxx-check RAND=extern TRANSPORT=quic-nonblocking EXPORTER=off \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The object colibri links for its own QUIC checks: the webpki chain
# walk under both roles and the key log. No test here drives a
# TRUST=webpki QUIC client, so this build is what holds the pair to
# compiling: 756ad91 broke it and nothing here saw it.
check-lib-quic-webpki-both:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both \
	  KEYLOG=on EXPORTER=off > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The server arm exports ch_srv_accept and ch_srv_check beside
# ch_read, ch_write and ch_close, and no ch_connect, so it is the build
# that holds PUBLIC_ROLE to a replacement rather than an addition. It
# is lib-check alone: chapulin.hpp has no Server type yet, so
# cxx-check joins this line on the commit that adds one
# (docs/server.md). It is also the only build that packages the two
# signers, so it is where a link error in them shows.
# Names TRUST as well as ROLE: the server arm admits one value, and a
# recursion inherits whatever the outer make was given, so without it
# `make check TRUST=raw-ecdsa` dies in this row rather than in a build
# anyone asked for.
check-lib-server:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern ROLE=server TRUST=none > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The server's tcp-nonblocking transport: srv_tcp_nonblocking.c in place of
# srv_handshake.c, tcp_nonblocking.c and tcp_nonblocking_frame.c
# under it, and nine calls rather than five. lint-trust-separation
# reads that source list and this build links it. A variant that keeps
# a caller and drops the module under it builds and passes the
# export list, which is the failure this target's own comment
# records for ROLE=server. It took 2.7 s cold.
check-lib-server-tcp-nonblocking:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern ROLE=server TRUST=none TRANSPORT=tcp-nonblocking \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The hybrid device client, with the P-256 pin: the one build that links
# ML-KEM into a raw-mode object and the one that packages
# TRUST=raw-ecdsa. KEX=pq sets its CH_TX_STAGE and CH_MIN_RXBUF, and
# lib-check reads both from its build record.
check-lib-raw-ecdsa-pq:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern TRUST=raw-ecdsa KEX=pq > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The exporter axis: the one build that verifies PUBLIC_EXPORT against
# a packaged object, since bin/exporter_test links $(SRCS) directly
# and never reads LIB_SRCS or PUBLIC. It is lib-check alone until
# chapulin.hpp forwards ch_export; cxx-check joins it on that commit.
check-lib-exporter:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern EXPORTER=on > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The key log axis, on the build colibri's interop endpoint links: a
# QUIC server. It proves the object still exports its nineteen calls
# and imports ch_keylog as a hook. EXPORTER=off is named because that
# axis refuses TRANSPORT=quic-nonblocking and a recursion inherits the outer value.
check-lib-server-quic-keylog:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern ROLE=server TRUST=none TRANSPORT=quic-nonblocking \
	  EXPORTER=off KEYLOG=on > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The AES suite, on the server that selects it: a host object
# (docs/decisions.md 89), whose sessions run AES-GCM on the AES
# instructions where the caller sets CH_CPU_CONSTANT_TIME_AES. A compiler
# that fails the host test builds no such object, and the target skips there;
# check-skips fails CI on that skip.
check-lib-server-aes:
ifeq ($(HOST_TARGET),)
	@echo "SKIP lib-check ROLE=server SUITE=aesgcm: $(CC) fails the host test"
else
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern ROLE=server TRUST=none SUITE=aesgcm \
	  > bin/check/$@.log 2>&1; $(CHECK_REPORT)
endif
# The same server on AES=extern, the device object a part with an AES
# peripheral links. HOST_TARGET is empty on its line, the host test's
# result a compiler for that part gives, so the build packages the device
# object on every host. It states CH_AES_EXTERN_CONSTANT_TIME, which ct.h
# requires and the Makefile never writes, and it needs no AES
# instruction. The object imports ch_aes_block from the image, and
# lib-check's import rule passes it because no source here defines it.
check-lib-server-aes-extern:
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern ROLE=server TRUST=none SUITE=aesgcm AES=extern \
	  HOST_TARGET= CFLAGS='$(CFLAGS) -DCH_AES_EXTERN_CONSTANT_TIME' > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The QUIC object colibri links, the ROLE=both TRUST=webpki one with the
# suite, which holds the AES instructions and the table beside them
# (docs/decisions.md 81 and 89). It links only where HOST_TARGET passed.
check-lib-quic-aes:
ifeq ($(HOST_TARGET),)
	@echo "SKIP lib-check SUITE=aesgcm over QUIC: $(CC) fails the host test"
else
	@mkdir -p bin/check; $(CHECK_LIBRARY_STAMP) $(MAKE) lib-check RAND=extern TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki \
	  SUITE=aesgcm KEYLOG=on EXPORTER=off > bin/check/$@.log 2>&1; $(CHECK_REPORT)
endif
# Two objects of different transports in one image (docs/decisions.md
# 61): four pairs that must link and run, and the two the decision
# refuses, whose link must fail on the names both objects export. It
# reuses the objects the targets above built and builds two more. It took
# 5.2 s with every object built and 8 s with those two to build. It is
# skipped when it passed before on the same tree, compiler and system
# (tools/stamp.py).
check-lib-pair: lint-zig-build $(filter check-lib-%,$(filter-out check-lib-pair,$(CHECK_LIBRARY_BUILDS))) check-examples
	+@mkdir -p bin/check; python3 tools/stamp.py lib-pair-check --content . --output '$(CC) --version' \
	  --output 'ld -v' --output 'uname -srm' -- env CC='$(CC)' ./test/lib-pair-check.sh > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# lint above holds lint-stack at the budget of the build check was
# given, 2,560 B for a plain `make check`, the target CI's check job runs.
# This target compiles the TRUST=webpki object's sources under their own
# defines against that build's 4,096 B budget (INV-19), which nothing
# else in check measures. It took 2.0 to 3.1 s in three timed runs.
check-stack-webpki:
	@mkdir -p bin/check; $(MAKE) lint-stack TRUST=webpki > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The EXPORTER axis widens hkdf's info buffer by 20 bytes and adds
# ks_exporter's frame; this holds both to the default budget.
check-stack-exporter:
	@mkdir -p bin/check; $(MAKE) lint-stack EXPORTER=on > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The QUIC arm compiles the QUIC_SRCS, which no other frame-budget
# check compiles, against the 2,560 B device budget (INV-19).
check-stack-quic:
	@mkdir -p bin/check; $(MAKE) lint-stack TRANSPORT=quic-nonblocking EXPORTER=off > bin/check/$@.log 2>&1; $(CHECK_REPORT)
# The server object carries ML-KEM in every build (docs/decisions.md
# 54). This target holds ML-KEM's sources to their 6,656 B ceiling and
# every server source, srv_kex.c and the signers included, to the
# 2,560 B device budget, so a hybrid-sized buffer on a server frame
# fails here (INV-19).
check-stack-server:
	@mkdir -p bin/check; $(MAKE) lint-stack ROLE=server TRUST=none > bin/check/$@.log 2>&1; $(CHECK_REPORT)

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

# What CI runs. .github/workflows/check.yml gives each of four targets a
# job of its own, so the four run at once on four runners, and each job
# runs one target, so the workflow holds no list of steps:
#
#   job      target      events
#   check    check       every one
#   slow     ci-slow     every one but a pull request
#   mutants  ci-mutants  every one but a pull request
#   prove    ci-prove    every one but a pull request
#
# A pull request gets the one-minute check so review stays fast. A merge to
# main and the nightly get the slow half too, because that is where a
# regression must not survive. The workflow holds that rule, in the `if`
# of the three jobs.
#
# A job starts from a checkout with no bin/ and installs only the tools
# its target reads, so each ci- target builds every binary its steps run
# and none assumes that check ran before it. A step a target gains may
# read a tool the job does not install, so the job's install steps change
# in the same commit.
#
# ci and check-slow run the four one after another in one invocation,
# which is how a development machine runs them.
.PHONY: ci
ci:
	$(MAKE) check-slow

# check, then the slow half: the three ci- targets, one after another.
.PHONY: check-slow ci-slow ci-mutants ci-prove
check-slow: check
	$(MAKE) ci-slow
	$(MAKE) ci-mutants
	$(MAKE) ci-prove

# The slow job's target: every step of the slow half but the mutants and
# the proofs.
#
# The prerequisites are what the steps run and do not build. test/e2e.sh
# runs no make, so its binaries are here: CHECK_BUILDS, the two
# provisioning tools, the two SUITE=aesgcm servers and the AES=extern
# webpki client. Its four examples link the packaged object, and RAND has
# no default, so the recipe builds them through the recursion
# check-examples uses. bin/handshake_sequence_pq is built and not run: it
# walks the same message ordering as its classic sibling; what pq changes
# is share sizes and secret derivation, which handshake_strict_pq, the
# differential and the e2e pq tests cover, and the nightly runs it.
#
# check-skips is a prerequisite because diff, test/e2e.sh and the Zig
# roster each leave out the host object's rows under a compiler that
# fails the host test, and on CI that is a failure, here as in check.
#
# ct-widemul-check costs about 7 s, measured, nearly all of it three
# compiles that would come out of check's one-minute budget, so it sits
# here. handshake-sequence builds the spec's oracle before it runs the
# enumeration, which compares nothing where the oracle is absent.
ci-slow: check-skips $(CHECK_BUILDS) bin/handshake_sequence_pq bin/pemkey bin/pemkey_ecdsa \
         $(if $(HOST_TARGET),bin/tlsserver_aes) bin/tlsserver_aes_extern bin/tlsclient_webpki_aes_extern
	$(MAKE) ct-widemul-check
	# check's lint-zig-build holds build.zig to make over the default
	# object, the four colibri links, stompy's and a SUITE=aesgcm
	# record-mode object. This holds it over every lib-check build's
	# configuration too, so every value of every axis meets build.zig.
	# It took 29 s with only those seven objects built.
	+ZIG='$(ZIG)' CC='$(CC)' ./test/zig-build-check.sh --roster
	./test/qemu-m3.sh
	$(MAKE) examples-check RAND=extern TRUST=raw-rsa TRANSPORT=tcp-blocking
	+./test/e2e.sh
	$(MAKE) diff
	$(MAKE) handshake-sequence

# The mutants job's target: the fast tier of test/violations/.
ci-mutants: test-invariants-fast

# The prove job's target: the fast tier of the CBMC proofs.
ci-prove: prove

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
	cd spec/lean && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_PIN_ECDSA -I. -o bin/diff_ecdsa test/diff_test.c $(DIFF_SRCS)
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
	cd spec/lean && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_KEX_PQ -I. -o bin/diff_pq test/diff_test.c $(DIFF_SRCS)
	./bin/diff_pq
endif

# The web PKI arm: bin/diff compiles the pinned parsers, so the empty
# server_name acknowledgement in EncryptedExtensions and the three
# CertificateVerify schemes run against real C only here. Same lane as
# diff-pq. The webpki client lists two groups and sends a share for each
# (docs/decisions.md entry 53), so a ServerHello selecting either one
# meets the model's two-groups token here and nowhere else. It builds a
# second binary under -DCH_SUITE_AES_GCM, the client that offers two
# suites (entry 45), where the AES instructions exist. That binary also
# takes CH_TX_PT=16384, TX_RECORD's ceiling (entry 71), so
# test/diff_writable_len.h compares ch_writable_len at record limits up to
# 2^14 and across an AES-GCM key's KeyUpdate record. No other row reads
# CH_TX_PT.
# The build links pem.c, x509.c and x509_ca.c too, which the webpki
# object does not package, because test/diff_x509.h drives them.
.PHONY: diff-webpki
diff-webpki:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff-webpki: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff-webpki)
	cd spec/lean && $(LAKE) build
	@mkdir -p bin
	$(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_TRUST_WEBPKI -I. -o bin/diff_webpki test/diff_test.c $(DIFF_SRCS) webpki.c webpki_ticket.c webpki_pin.c webpki_cfg.c $(WEBPKI_KEX_SRCS)
	./bin/diff_webpki
ifneq ($(HOST_TARGET),)
	$(CC) $(HOST_CFLAGS) $(RSA_WIDE_DEF) -DCH_TRUST_WEBPKI $(HOST_SUITE_DEF) -DCH_TX_PT=16384 -I. -o bin/diff_webpki_aes test/diff_test.c $(call host_srcs,$(DIFF_SRCS) webpki.c webpki_ticket.c webpki_pin.c webpki_cfg.c $(WEBPKI_KEX_SRCS) aes.c $(AES_HW_SRCS) gcm.c)
	./bin/diff_webpki_aes
else
	@echo "SKIP diff-webpki's SUITE=aesgcm binary: $(CC) fails the host test"
endif
endif

# Differential oracle: the Lean spec in spec/lean/ answers over a pipe and
# test/diff_test.c compares every C module against it on random inputs.
diff:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,diff)
	cd spec/lean && $(LAKE) build
	$(MAKE) bin/diff
	./bin/diff
	$(MAKE) bin/diff_quic
	./bin/diff_quic
ifneq ($(HOST_TARGET),)
	$(MAKE) bin/diff_quic_hw
	./bin/diff_quic_hw
else
	@echo "SKIP diff's host binary: $(CC) fails the host test"
endif
	$(MAKE) bin/diff_quic_extern
	./bin/diff_quic_extern
ifneq ($(HOST_TARGET),)
	$(MAKE) bin/diff_x25519_wide
	./bin/diff_x25519_wide
	$(MAKE) bin/diff_p256_wide
	./bin/diff_p256_wide
	$(MAKE) bin/diff_rsa_sign64
	./bin/diff_rsa_sign64
else
	@echo "SKIP diff's wide X25519 and P-256 binaries: $(CC) fails the host test"
	@echo "SKIP diff's RSA signers' binary: $(CC) fails the host test"
endif
endif

# The wide field's arm: the x25519 rows against spec/lean/Spec/X25519.lean
# with x25519_wide.c's entries answering, built as a host object builds
# that file. Its own main, because the field changes no other row bin/diff
# compares; test/diff_x25519_test.c says so, and why the spec needs no
# second model.
bin/diff_x25519_wide: test/diff_x25519_test.c x25519.c x25519_wide.c ct.c ct_wipe.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -o $@ test/diff_x25519_test.c x25519_wide.c ct.c ct_wipe.c

# The constant-time P-256 arm: a key generation, a signature and a key
# exchange against spec/lean/Spec/P256.lean, under both answers, so the
# wide files and the 32-bit files each answer the spec
# (docs/decisions.md 94), and the wide incomplete additions, the Jacobian
# doubling and the two conversions against spec/lean/Spec/P256WidePoint.lean,
# coordinate for coordinate (docs/decisions.md 111 and 112). Its own main,
# for bin/diff_x25519_wide's reason:
# bin/diff compares the verifier in p256.c and no row of it reads these
# files.
DIFF_P256_WIDE_SRCS := p256_sign.c p256_ecdh.c p256_point.c p256_scalar.c p256_field.c \
                       $(P256_WIDE_SRCS) sha256.c hkdf.c $(call hash_hw_of,sha256.c hkdf.c) buf.c ct.c \
                       ct_wipe.c
bin/diff_p256_wide: test/diff_p256_wide_test.c $(DIFF_P256_WIDE_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o $@ test/diff_p256_wide_test.c $(DIFF_P256_WIDE_SRCS)
# The RSA signers' arm: RSASSA-PSS signatures by spec/lean/Spec/Rsa.lean
# against the two signers a host object holds, the 64-bit one and the
# ladder, built as a host object builds them (docs/decisions.md 95). Its
# own main, because bin/diff is built as a device object's sources and
# holds no 64-bit signer; test/diff_rsa_sign_test.c says why the spec
# needs no second model. It builds at the 512-byte bound, so RSA-4096
# signs.
DIFF_RSA_SIGN_SRCS := rsa_sign.c $(RSA_SIGN64_SRCS) $(RSA_MONT64_SRCS) sha256.c ct.c ct_wipe.c
bin/diff_rsa_sign64: test/diff_rsa_sign_test.c $(DIFF_RSA_SIGN_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o $@ test/diff_rsa_sign_test.c $(DIFF_RSA_SIGN_SRCS)

# The TRANSPORT=quic-nonblocking arm of the differential. Its own main, because
# test/diff_test.c calls rec_seal and reads the TLS layout of ch_cfg, and
# a -DCH_TRANSPORT_QUIC_NONBLOCKING build compiles neither; test/diff_driver.h holds
# the plumbing both mains share. aes.c and the AES implementation are
# on the line for the reason bin/quic_test states. DIFF_QUIC_SRCS is what
# each of the three binaries links beside them: quic_keys.c and
# quic_retry.c, whose version 1 and version 2 rows test/diff_quic.h
# holds, and the HKDF and constant-time sources they call.
DIFF_QUIC_SRCS := quic_keys.c quic_retry.c hkdf.c sha256.c ct.c ct_wipe.c
bin/diff_quic: test/diff_quic_test.c aes.c $(AES_IMPL) gcm.c $(DIFF_QUIC_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) $(AES_256_TEST_DEF) -I. -o $@ test/diff_quic_test.c aes.c $(AES_IMPL) gcm.c $(DIFF_QUIC_SRCS)
# The same main in a QUIC host object, whatever this build's AES value is,
# so the rows in test/diff_aes.h and test/diff_gcm.h run the AES instructions
# and the carry-less multiply GHASH against spec/lean/Spec/Aes.lean and
# spec/lean/Spec/Gcm.lean: each key the rows build names the instructions
# (test/diff_gcm.h, test/initial_cpu.h). bin/diff_quic runs them over the
# build's own AES value, which is AES=soft unless the caller says
# otherwise, and no other differential binary compiles GCM. `diff` builds
# this one only where HOST_TARGET found a host compiler. It is a host
# object's binary, so it links the hash sources such an object holds
# beside hkdf.c and sha256.c, which the entries its key derivations call
# name (docs/decisions.md 93).
DIFF_QUIC_HW_SRCS := aes.c $(AES_HW_SRCS) quic_aes_soft.c gcm.c $(DIFF_QUIC_SRCS) \
                     $(call hash_hw_of,$(DIFF_QUIC_SRCS))
bin/diff_quic_hw: test/diff_quic_test.c $(DIFF_QUIC_HW_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME $(AES_256_TEST_DEF) -I. -o $@ \
	  test/diff_quic_test.c $(DIFF_QUIC_HW_SRCS)
# The same main on AES=extern, with test/aes_extern_hook.c as the hook,
# so the AES and GCM rows, AES-256 among them, run aes_extern.c's
# forwarding against the spec. It needs no instruction, so `diff` builds
# it on every host.
bin/diff_quic_extern: test/diff_quic_test.c aes.c $(AES_EXTERN_DEPS) gcm.c $(DIFF_QUIC_SRCS) $(HDRS) \
                      $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_AES_EXTERN $(AES_256_TEST_DEF) -I. -o $@ \
	  test/diff_quic_test.c aes.c $(AES_EXTERN_SRCS) gcm.c $(DIFF_QUIC_SRCS)

# The sequence enumerations compare against spec/lean/.lake/build/bin/diffspec,
# and handshake_sequence_test skips the comparison when that binary is
# absent. A caller that runs the binary directly therefore has to build the
# spec first, or a restored cache decides what gets compared. Both targets
# run the binary as one shard per core through
# test/handshake_sequence_shards.sh, which fails unless the shards' counts
# add up to the whole enumeration.
.PHONY: handshake-sequence handshake-sequence-pq
# Only the oracle build is guarded: the enumeration itself still runs
# without lake, comparing nothing, which is what the binary does alone.
handshake-sequence: bin/handshake_sequence_test
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec comparison: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,handshake-sequence)
	cd spec/lean && $(LAKE) build
endif
	./test/handshake_sequence_shards.sh ./bin/handshake_sequence_test

handshake-sequence-pq: bin/handshake_sequence_pq
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP spec comparison: lake not on PATH (install elan: https://leanprover.github.io)"
else
	$(call REQUIRE_MATHLIB,handshake-sequence-pq)
	cd spec/lean && $(LAKE) build
endif
	./test/handshake_sequence_shards.sh ./bin/handshake_sequence_pq

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
# so the QUIC_SRCS contribute nothing to this number. That is a
# deferral, not an oversight: the QUIC pass lands in the shape of the
# webpki pass below, with bin/quic_test and bin/quic_driver_test in its run
# list, and that commit moves this floor to CI's re-measured reading,
# the way 3432a5d moved
# it for the webpki pass. docs/quic.md, "What is still open", carries
# the same debt.
COVERAGE_FLOOR := 93
GCOVR ?= $(shell command -v gcovr)
GCOV_TOOL := $(shell $(CC) --version 2>/dev/null | grep -qi clang \
  && echo "$$(xcrun --find llvm-cov 2>/dev/null || command -v llvm-cov) gcov" || echo gcov)
COV_CC = $(CC) --coverage -O0 -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $$def -I.
# drbg.c and test/drbg_test.c compile as bin/drbg_test does, under
# CH_RAND_DRBG in place of the host's pattern.
COV_DRBG_CC = $(filter-out $(HOST_RAND_DEF),$(COV_CC)) -DCH_RAND_DRBG
COV_LIB_OBJS = $(SRCS:%.c=$$d/%.o)
# Each pass compiles every source its links read, and each link reads the
# variable the binary's own rule reads, so a source a test's rule gains
# is compiled and linked here as well. drbg.c compiles on its own line,
# under COV_DRBG_CC.
COV_PIN_SRCS = $(sort $(filter-out test/% drbg.c,$(SRCS) $(DRBG_TEST_SRCS) $(RSA_TEST_SRCS) \
  $(HANDSHAKE_STRICT_SRCS) $(X509STRICT_RSA_SRCS) $(X509STRICT_ECDSA_SRCS)))
COV_WEBPKI_SRCS = $(sort $(WEBPKI_TEST_SRCS) $(WEBPKI_SRCS) $(SHA512_TEST_SRCS) $(P384_TEST_SRCS) \
  $(RSA_PKCS1_TEST_SRCS) $(WEBPKI_TIME_SRC) $(WEBPKI_NAME_SRC) $(WEBPKI_SPKI_SRC) $(WEBPKI_SIGALG_SRC) \
  $(WEBPKI_CERT_SRC) $(WEBPKI_CHAIN_TEST_SRC) $(HANDSHAKE_STRICT_SRCS))
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
	cd spec/lean && $(LAKE) build
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
	  for f in $(COV_PIN_SRCS); do $(COV_CC) -c $$f -o $$d/$${f%.c}.o; done; \
	  $(COV_DRBG_CC) -c drbg.c -o $$d/drbg.o; \
	  $(COV_CC) test/unit_test.c $(COV_LIB_OBJS) -o $$d/unit; \
	  $(COV_DRBG_CC) test/drbg_test.c $(patsubst %.c,$$d/%.o,$(DRBG_TEST_SRCS)) -o $$d/drbg_test; \
	  $(COV_CC) test/rsa_test.c $(patsubst %.c,$$d/%.o,$(RSA_TEST_SRCS)) -o $$d/rsa_test; \
	  $(COV_CC) test/handshake_strict_test.c $(patsubst %.c,$$d/%.o,$(HANDSHAKE_STRICT_SRCS)) \
	    -o $$d/handshake_strict_test; \
	  strict_objs="$(patsubst %.c,$$d/%.o,$(filter-out test/%,$(X509STRICT_RSA_SRCS)))"; \
	  if [ $$pin = ecdsa ]; then \
	    strict_objs="$(patsubst %.c,$$d/%.o,$(filter-out test/%,$(X509STRICT_ECDSA_SRCS)))"; fi; \
	  $(COV_CC) $$def test/x509_strict_test.c $$strict_objs -o $$d/x509strict_test; \
	  $(COV_CC) test/handshake_sequence_test.c \
	    $(patsubst %.c,$$d/%.o,$(HANDSHAKE_SEQUENCE_SRCS)) -o $$d/handshake_sequence_test; \
	  for b in unit rsa_test handshake_strict_test x509strict_test handshake_sequence_test; do \
	    if ENUM_DEPTH=4 ./$$d/$$b > /dev/null; then \
	      echo "| $$b | $$pin | pass |" >> bin/coverage.md; \
	    else \
	      echo "| $$b | $$pin | FAIL |" >> bin/coverage.md; exit 1; \
	    fi; \
	  done; \
	done
	# The TRUST=webpki pass: one object set under -DCH_TRUST_WEBPKI, which
	# widens the modulus gate the way RSA_WIDE_DEF does, then every
	# binary check runs for the mode, each over the sources its own rule
	# names. The strictness binary here runs the parsers' webpki arms.
	@set -e; d=bin/cov/webpki; def=-DCH_TRUST_WEBPKI; mkdir -p $$d; \
	  for f in $(COV_WEBPKI_SRCS); do $(COV_CC) -c $$f -o $$d/$${f%.c}.o; done; \
	  link() { name=$$1; shift; objs=""; for f in "$$@"; do objs="$$objs $$d/$${f%.c}.o"; done; \
	    $(COV_CC) test/$$name.c $$objs -o $$d/$$name; }; \
	  link sha512_test $(SHA512_TEST_SRCS); \
	  link p384_test $(P384_TEST_SRCS); \
	  link rsa_pkcs1_test $(RSA_PKCS1_TEST_SRCS); \
	  link webpki_time_test $(WEBPKI_TIME_SRC); \
	  link webpki_name_test $(WEBPKI_NAME_SRC); \
	  link webpki_spki_test $(WEBPKI_SPKI_SRC); \
	  link webpki_sigalg_test $(WEBPKI_SIGALG_SRC); \
	  link webpki_cert_test $(WEBPKI_CERT_SRC); \
	  link webpki_chain_test $(WEBPKI_CHAIN_TEST_SRC); \
	  link webpki_session_test $(WEBPKI_TEST_SRCS); \
	  link webpki_auth_test $(WEBPKI_TEST_SRCS); \
	  link webpki_encrypted_exts_test $(WEBPKI_TEST_SRCS); \
	  link handshake_strict_test $(HANDSHAKE_STRICT_SRCS); \
	  for b in sha512_test p384_test rsa_pkcs1_test webpki_time_test webpki_name_test \
	           webpki_spki_test webpki_sigalg_test webpki_cert_test webpki_chain_test \
	           webpki_session_test webpki_auth_test webpki_encrypted_exts_test \
	           handshake_strict_test; do \
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

.PHONY: wycheproof wycheproof-default wycheproof-host wycheproof-aes-extern \
        wycheproof-run-default wycheproof-run-host wycheproof-run-aes-extern
wycheproof:
	@$(call wycheproof_fetch,wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(MAKE) --no-print-directory -j4 wycheproof-default wycheproof-host wycheproof-aes-extern
# The three tests build and run at once, each about 3 seconds to
# compile and 6 to run. Each writes its report to a file and prints it
# whole when it ends, so the reports never interleave. None is a target
# to run on its
# own: each reads the bin/wycheproof_vectors.h the target above writes.
#
# A test is skipped when it passed before on the same inputs
# (tools/stamp.py). Its key covers the Makefile, which holds its recipe,
# the compiler's version, the system's release, which names the linker
# and the C library, and the test's compile line run with -E: the flags,
# and every byte of every source and header the compile reads,
# bin/wycheproof_vectors.h among them, so a new vector or a changed
# expectation runs the test again. The binary reads no file, and the host
# test's arguments are in its recipe here. On x86-64 the host test's binary
# also reads its CPU and CH_REQUIRE_X86_KERNELS, to skip or fail a value
# that names instructions the CPU lacks (test/test_cpu.h): every key
# covers that variable, and a stamp never leaves the machine that wrote
# it, so what the binary prints follows from the key.
#
# What every test that builds test/wycheproof_test.c turns on beside its own
# flags: AES-256 for the AES-GCM suite at 256 bits, and SHA-384 in hkdf.c
# for the HKDF-SHA-384 and HMAC-SHA-384 suites. A library object has both
# only under SUITE=aesgcm, which needs a host object or AES=extern, so
# these two are how the other tests run TLS_AES_256_GCM_SHA384's primitives.
WYCHEPROOF_TEST_DEFS := $(AES_256_TEST_DEF) -DCH_HASH_SHA384
WYCHEPROOF_SRCS := x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c \
  mlkem.c mlkem_poly.c sha3.c buf.c ct.c ct_wipe.c sha512.c sha512_compress.c p384.c p384_field.c \
  rsa_pkcs1.c rsa_sign.c aes.c gcm.c p256_sign.c p256_ecdh.c p256_point.c \
  p256_scalar.c p256_field.c
WYCHEPROOF_STAMP_INPUTS = $(STAMP_MAKEFILES) --output '$(CC) --version' --output 'uname -srm'
# Each test's compile line without its output, so the stamp's -E run and
# the compile read the same flags and the same sources.
WYCHEPROOF_DEFAULT = $(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) \
  $(WYCHEPROOF_TEST_DEFS) -I. -Ibin test/wycheproof_test.c $(WYCHEPROOF_SRCS) $(AES_IMPL)
WYCHEPROOF_HOST = $(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING \
  $(WYCHEPROOF_TEST_DEFS) -I. -Ibin test/wycheproof_test.c $(call host_srcs,$(WYCHEPROOF_SRCS)) \
  $(AES_HW_SRCS) quic_aes_soft.c
WYCHEPROOF_AES_EXTERN = $(CC) $(CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_AES_EXTERN \
  $(WYCHEPROOF_TEST_DEFS) -I. -Ibin test/wycheproof_test.c $(WYCHEPROOF_SRCS) $(AES_EXTERN_SRCS)
wycheproof-default:
	@python3 tools/stamp.py wycheproof-default $(WYCHEPROOF_STAMP_INPUTS) \
	  --output '$(WYCHEPROOF_DEFAULT) -E' -- $(MAKE) --no-print-directory wycheproof-run-default
wycheproof-run-default:
	@$(WYCHEPROOF_DEFAULT) -o bin/wycheproof_test && \
	{ ./bin/wycheproof_test > bin/wycheproof_test.log 2>&1; rc=$$?; cat bin/wycheproof_test.log; exit $$rc; }
# The host Wycheproof test (docs/decisions.md 89). New crypto gets its
# Wycheproof suite in every test that builds test/wycheproof_test.c. The AES
# instructions are a second AES-128 in this tree, so the AES-GCM suite
# answers for them too, and a host object holds each file built on the
# widening multiply twice, so each suite of those files answers for both
# copies. The vector ChaCha20 and the vector Poly1305 are a second of
# each, so the ChaCha20-Poly1305 suite answers for them. The binary is a
# QUIC host object, and it
# runs once for each set of ch_cfg.cpu bits that changes a path,
# HOST_WYCHEPROOF_CPU. Without CH_CPU_CONSTANT_TIME_AES its AES-128-GCM
# runs on the table and the portable GHASH, and with it AES-128-GCM and
# AES-256-GCM run on the instructions and the carry-less multiply. Without
# CH_CPU_CONSTANT_TIME_MULTIPLY every call built on the multiply runs the
# file under its own names, on the decomposition, and with it the native
# copy, the vector Poly1305 included, and X25519 the wide field, whose
# 518 cases the x25519 suite then answers for (test/test_widemul.h). On
# x86-64 it runs twice more, under X86_WYCHEPROOF_CPU: with CH_CPU_AVX2
# the ChaCha20-Poly1305 suite runs its keystream on the AVX2 kernel, and
# with CH_CPU_VAES beside the AES bit both AES-GCM suites run their whole
# blocks on the VAES kernels (docs/decisions.md 90). On both
# architectures it runs once more under HASH_WYCHEPROOF_CPU, where the
# HMAC-SHA-256 and HKDF-SHA-256 suites hash on the CPU's SHA-256
# instructions (docs/decisions.md 93). Running the
# whole file each time is what the rule asks for and what keeps this test
# from rotting when a suite is added. A compiler that fails the host test
# skips, the way the fetch above skips offline.
HOST_WYCHEPROOF_CPU := 0x1 0x3 0x5 0x7 $(X86_WYCHEPROOF_CPU) $(HASH_WYCHEPROOF_CPU)
wycheproof-host:
ifeq ($(HOST_TARGET),)
	$(call REQUIRE_ON_CI,wycheproof-host)
	@echo "SKIP the host Wycheproof test: $(CC) fails the host test"
else
	@python3 tools/stamp.py wycheproof-host $(WYCHEPROOF_STAMP_INPUTS) \
	  --output '$(WYCHEPROOF_HOST) -E' -- $(MAKE) --no-print-directory wycheproof-run-host
endif
wycheproof-run-host:
	@set -e; $(WYCHEPROOF_HOST) -o bin/wycheproof_test_host; \
	for bits in $(HOST_WYCHEPROOF_CPU); do \
	  ./bin/wycheproof_test_host $$bits > bin/wycheproof_test_host.log 2>&1 \
	    || { echo "== bin/wycheproof_test_host $$bits failed:"; cat bin/wycheproof_test_host.log; exit 1; }; \
	  echo "== bin/wycheproof_test_host $$bits (host object):"; cat bin/wycheproof_test_host.log; \
	done
# The AES=extern Wycheproof test, for the host one's reason: an AES=extern
# object runs AES-GCM over the image's ch_aes_block, so the AES-GCM suite
# answers for aes_extern.c at both key sizes, with test/aes_extern_hook.c
# as the hook. It needs no AES instruction, so it never skips.
wycheproof-aes-extern:
	@python3 tools/stamp.py wycheproof-aes-extern $(WYCHEPROOF_STAMP_INPUTS) \
	  --output '$(WYCHEPROOF_AES_EXTERN) -E' -- $(MAKE) --no-print-directory wycheproof-run-aes-extern
wycheproof-run-aes-extern:
	@$(WYCHEPROOF_AES_EXTERN) -o bin/wycheproof_test_aes_extern && \
	{ ./bin/wycheproof_test_aes_extern > bin/wycheproof_test_aes_extern.log 2>&1; rc=$$?; \
	  echo "== bin/wycheproof_test_aes_extern (AES=extern):"; cat bin/wycheproof_test_aes_extern.log; exit $$rc; }

# The web PKI chain fixtures, test/webpki_corpus.h, live in the tree like
# test/rsa_pkcs1_vectors.h; regenerate them by hand. The keys under
# test/webpki_corpus/keys/ and the captures under test/webpki_captures/
# are fixed inputs, so a run over an unchanged tree reproduces the header
# byte for byte. The generator runs the openssl CLI as its oracle and
# opens no network connection.
.PHONY: webpki-corpus
webpki-corpus:
	python3 test/gen_webpki_corpus.py

# The ECDSA P-256 signing vectors, test/p256_sign_vectors.h. The
# generator checks every constant p256_scalar.c and p256_point.c carry,
# runs the complete addition formula against an affine reference, and
# reproduces RFC 6979 A.2.5 before it prints anything, so a wrong
# constant fails here rather than in a signature. clang-format runs over
# the result because lint-format covers TESTH: the generator prints
# sixteen bytes to a line and the struct nesting puts that one column
# past the limit.
.PHONY: p256-sign-vectors
p256-sign-vectors:
	python3 test/gen_p256_sign_vectors.py > test/p256_sign_vectors.h
	$(CLANG_FORMAT) -i test/p256_sign_vectors.h

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
	$(CC) $(CT_WIDEMUL_CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) $(WYCHEPROOF_TEST_DEFS) -I. -Ibin -o bin/wycheproof_test_ct_widemul test/wycheproof_test.c \
	  $(WYCHEPROOF_SRCS) $(AES_IMPL) && \
	./bin/wycheproof_test_ct_widemul

# Sanitizer lane: the deterministic suites under ASan + UBSan, test
# binaries only — sanitized codegen must never leak into coverage,
# timing, or release objects, so the lane builds into bin/san with its
# own compile lines, like coverage does. Each line takes its sources from
# the variable the binary's own rule reads, which check builds, so a call
# one source gains into another fails check before it fails this lane.
# O picks the optimization
# level and the output names it, because "passed UBSan" is ambiguous
# without one: -O0 sees code the optimizer would delete, -O2 is what
# ships. -fno-sanitize-recover=all turns any finding into an abort, so
# CI fails on the finding; no suite aborts on purpose (CH_ASSERT never
# fires on the clean tree), so exit status is the pass condition.
# LeakSanitizer joins free on Linux ASan; for a zero-heap library any
# leak is a real bug. Sanitizers are blind to timing: this lane says
# nothing about INV-16, which stays with construction and the t-test.
# -DTEST_ADDRESS_SANITIZER tells test/stack_residue.c that the binary's
# frames are AddressSanitizer's, so a test that searches the stack for
# what a call left skips the search and says so.
O ?= 2
SAN_CFLAGS = $(filter-out -O2,$(CFLAGS)) -O$(O) -g \
  -fsanitize=address,undefined -fno-sanitize-recover=all -DTEST_ADDRESS_SANITIZER
# The same for a host object's binary: without the host test flags'
# CH_NATIVE_WIDEMUL, which ct.h refuses beside -DCH_CPU_RUNTIME.
SAN_HOST_CFLAGS = $(filter-out $(HOST_WIDEMUL_DEF),$(SAN_CFLAGS))
.PHONY: san-check san-selftest
san-check:
	@rm -rf bin/san && mkdir -p bin/san
	@echo "san-check at -O$(O) with $$($(CC) --version | head -1)"
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/unit test/unit_test.c $(SRCS)
	$(CC) $(filter-out $(HOST_RAND_DEF),$(SAN_CFLAGS)) -DCH_RAND_DRBG -I. -o bin/san/drbg_test test/drbg_test.c $(DRBG_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/rsa_test test/rsa_test.c $(RSA_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha3_test test/sha3_test.c $(SHA3_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha3_equiv_test test/sha3_equiv_test.c $(filter-out sha3.c,$(SHA3_TEST_SRCS))
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/sha512_test test/sha512_test.c $(SHA512_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -DCH_HASH_SHA384 -I. -o bin/san/hkdf384_test test/hkdf384_test.c $(HKDF384_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/p384_test test/p384_test.c $(P384_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/p256_field_test test/p256_field_test.c $(P256_FIELD_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/p256_ecdh_test test/p256_ecdh_test.c $(P256_ECDH_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -Itest -o bin/san/p256_sign_test test/p256_sign_test.c $(P256_SIGN_SRC)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/rsa_pkcs1_test test/rsa_pkcs1_test.c $(RSA_PKCS1_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -I. -o bin/san/rsa_sign_test test/rsa_sign_test.c $(RSA_SIGN_TEST_SRCS)
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
	$(CC) $(SAN_CFLAGS) -DCH_TRUST_WEBPKI -I. -o bin/san/webpki_encrypted_exts_test test/webpki_encrypted_exts_test.c $(WEBPKI_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/mlkem_test test/mlkem_test.c $(MLKEM_TEST_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_strict_test test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/x509strict_test $(X509STRICT_RSA_SRCS)
	$(CC) $(SAN_CFLAGS) -DCH_PIN_ECDSA -I. -o bin/san/x509strict_ecdsa $(X509STRICT_ECDSA_SRCS)
	$(CC) $(SAN_CFLAGS) -I. -o bin/san/handshake_sequence_test test/handshake_sequence_test.c \
	  $(HANDSHAKE_SEQUENCE_SRCS)
	@set -e; for b in unit rsa_test rsa_sign_test sha3_test sha3_equiv_test sha512_test hkdf384_test p384_test p256_field_test p256_ecdh_test p256_sign_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test webpki_chain_test webpki_session_test webpki_auth_test webpki_encrypted_exts_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
	  echo "== $$b (SAN -O$(O))"; ENUM_DEPTH=4 ./bin/san/$$b; done
	@$(call wycheproof_fetch,san wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(CC) $(SAN_CFLAGS) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) $(WYCHEPROOF_TEST_DEFS) -I. -Ibin -o bin/san/wycheproof_test test/wycheproof_test.c \
	  $(WYCHEPROOF_SRCS) $(AES_IMPL) && \
	echo "== wycheproof_test (SAN -O$(O))" && ./bin/san/wycheproof_test
	# A host object's paths, where the compiler passes the host test. The
	# four equivalence binaries: the wide X25519 field, the vector
	# ChaCha20 and Poly1305, which run their cases on heap buffers that end
	# where each case ends, so ASan sees a read or a write one byte past
	# them, and RSA's 64-bit arithmetic, whose word arrays sit on the
	# stack; the signer's binary makes no run over the stack here, as the
	# SHA-2 one below makes none. Then the RSA signer's vectors and its
	# faulted keys under each value of HOST_VECTOR_CPU, which run the CRT
	# signer's refusals over keys whose integers do not belong together.
	# Then the Wycheproof
	# suites over the host object with the multiply bit, 0x5, under which
	# the x25519 rows run the wide field, every other row built on the
	# multiply its native copy, the vector Poly1305 among them, and
	# ChaCha20 the vector path; on x86-64 they run once more under each
	# value of X86_WYCHEPROOF_CPU, on the kernels, where the CPU has
	# their instructions. UBSan finds no unsigned wrap,
	# which C does not call undefined; the field's proofs check that class
	# with --unsigned-overflow-check instead. The SHA-2 equivalence binary
	# runs its cases on heap buffers that end where each case ends too, and
	# skips its search of the stack, which AddressSanitizer's frames would
	# not answer (test/stack_residue.c), and so does the Keccak one, which
	# has a path to test where clang builds for arm64. The wide P-256 files'
	# equivalence binary runs without its stack checks
	# (CH_P256_EQUIV_NO_STACK): a sanitizer's redzones make its frames
	# several times the object's, so how deep a sanitized call writes and
	# what it leaves there say nothing of the object. The Wycheproof suites
	# run once more under HASH_WYCHEPROOF_CPU, their HMAC and HKDF on the
	# SHA-256 instructions, where the CPU has them.
	@set -e; if [ -n "$(HOST_TARGET)" ]; then \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -o bin/san/x25519_equiv_test test/x25519_equiv_test.c \
	    $(X25519_EQUIV_TEST_SRCS); \
	  echo "== x25519_equiv_test (SAN -O$(O))"; ./bin/san/x25519_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o bin/san/p256_equiv_test test/p256_equiv_test.c \
	    $(P256_EQUIV_TEST_SRCS); \
	  echo "== p256_equiv_test (SAN -O$(O))"; CH_P256_EQUIV_NO_STACK=1 ./bin/san/p256_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -I. -o bin/san/chacha20_equiv_test test/chacha20_equiv_test.c \
	    $(CHACHA20_EQUIV_TEST_SRCS); \
	  echo "== chacha20_equiv_test (SAN -O$(O))"; ./bin/san/chacha20_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -I. -o bin/san/poly1305_equiv_test test/poly1305_equiv_test.c \
	    $(POLY1305_EQUIV_TEST_SRCS); \
	  echo "== poly1305_equiv_test (SAN -O$(O))"; ./bin/san/poly1305_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) $(SHA2_EQUIV_TEST_DEFS) -I. -Itest -o bin/san/sha2_equiv_test test/sha2_equiv_test.c \
	    $(SHA2_EQUIV_TEST_SRCS); \
	  echo "== sha2_equiv_test (SAN -O$(O))"; ./bin/san/sha2_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o bin/san/sha3_hw_equiv_test test/sha3_hw_equiv_test.c \
	    $(SHA3_HW_EQUIV_TEST_SRCS); \
	  echo "== sha3_hw_equiv_test (SAN -O$(O))"; ./bin/san/sha3_hw_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o bin/san/mlkem_hw_equiv_test test/mlkem_hw_equiv_test.c \
	    $(MLKEM_HW_EQUIV_TEST_SRCS); \
	  echo "== mlkem_hw_equiv_test (SAN -O$(O))"; ./bin/san/mlkem_hw_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o bin/san/mlkem_vector_equiv_test \
	    test/mlkem_vector_equiv_test.c $(MLKEM_VECTOR_EQUIV_TEST_SRCS); \
	  echo "== mlkem_vector_equiv_test (SAN -O$(O))"; ./bin/san/mlkem_vector_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME -I. -Itest -o bin/san/mlkem_avx2_equiv_test \
	    test/mlkem_avx2_equiv_test.c $(MLKEM_AVX2_EQUIV_TEST_SRCS); \
	  echo "== mlkem_avx2_equiv_test (SAN -O$(O))"; ./bin/san/mlkem_avx2_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o bin/san/rsa_equiv_test \
	    $(RSA_EQUIV_TEST_UNITS) $(RSA_EQUIV_TEST_SRCS); \
	  echo "== rsa_equiv_test (SAN -O$(O))"; ./bin/san/rsa_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -o bin/san/rsa_sign_equiv_test \
	    test/rsa_sign_equiv_test.c $(RSA_SIGN_EQUIV_TEST_SRCS); \
	  echo "== rsa_sign_equiv_test (SAN -O$(O))"; ./bin/san/rsa_sign_equiv_test; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -I. -Itest -o bin/san/rsa_sign_test_host \
	    test/rsa_sign_test.c $(call host_srcs,$(RSA_SIGN_TEST_SRCS)); \
	  for bits in $(HOST_VECTOR_CPU); do \
	    echo "== rsa_sign_test_host $$bits (SAN -O$(O))"; ./bin/san/rsa_sign_test_host $$bits; \
	  done; \
	  [ -f bin/wycheproof_vectors.h ] || { echo "SKIP san wycheproof host object: the fetch above skipped"; exit 0; }; \
	  $(CC) $(SAN_HOST_CFLAGS) -DCH_CPU_RUNTIME $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING \
	    $(WYCHEPROOF_TEST_DEFS) -I. -Ibin -o bin/san/wycheproof_test_host test/wycheproof_test.c \
	    $(call host_srcs,$(WYCHEPROOF_SRCS)) $(AES_HW_SRCS) quic_aes_soft.c; \
	  for bits in 0x5 $(X86_WYCHEPROOF_CPU) $(HASH_WYCHEPROOF_CPU); do \
	    echo "== wycheproof_test_host $$bits (SAN -O$(O))"; ./bin/san/wycheproof_test_host $$bits; \
	  done; \
	else \
	  echo "SKIP san host object: $(CC) fails the host test"; \
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
# and the x86 lane owns the deep run. Each line takes its sources from
# the variable the binary's own rule reads, as san-check does.
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
	$(CROSS)gcc $(filter-out $(HOST_RAND_DEF),$(CFLAGS)) -DCH_RAND_DRBG $(CROSS_EXTRA) -static -I. -o bin/cross/drbg_test test/drbg_test.c $(DRBG_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/rsa_test test/rsa_test.c $(RSA_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha3_test test/sha3_test.c $(SHA3_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha3_equiv_test test/sha3_equiv_test.c $(filter-out sha3.c,$(SHA3_TEST_SRCS))
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/sha512_test test/sha512_test.c $(SHA512_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -DCH_HASH_SHA384 -I. -o bin/cross/hkdf384_test test/hkdf384_test.c $(HKDF384_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/p384_test test/p384_test.c $(P384_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/p256_field_test test/p256_field_test.c $(P256_FIELD_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/p256_ecdh_test test/p256_ecdh_test.c $(P256_ECDH_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -Itest -o bin/cross/p256_sign_test test/p256_sign_test.c $(P256_SIGN_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/rsa_pkcs1_test test/rsa_pkcs1_test.c $(RSA_PKCS1_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/webpki_time_test test/webpki_time_test.c $(WEBPKI_TIME_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/webpki_name_test test/webpki_name_test.c $(WEBPKI_NAME_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_spki_test test/webpki_spki_test.c $(WEBPKI_SPKI_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_sigalg_test test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -static -I. -o bin/cross/webpki_cert_test test/webpki_cert_test.c $(WEBPKI_CERT_SRC)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/mlkem_test test/mlkem_test.c $(MLKEM_TEST_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_strict_test test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/x509strict_test $(X509STRICT_RSA_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -DCH_PIN_ECDSA -I. -o bin/cross/x509strict_ecdsa $(X509STRICT_ECDSA_SRCS)
	$(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) -static -I. -o bin/cross/handshake_sequence_test test/handshake_sequence_test.c \
	  $(HANDSHAKE_SEQUENCE_SRCS)
	@if [ -d $(WYCHEPROOF_DIR)/.git ] \
	  || git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) 2>/dev/null; then \
	  python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	  $(CROSS)gcc $(CFLAGS) $(CROSS_EXTRA) $(RSA_WIDE_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(AES_DEF) $(WYCHEPROOF_TEST_DEFS) -static -I. -Ibin -o bin/cross/wycheproof_test test/wycheproof_test.c \
	    $(WYCHEPROOF_SRCS) $(AES_IMPL) ; \
	else \
	  [ -n "$$CI" ] && { echo "wycheproof: clone failed and CI must not skip a gate"; exit 1; }; \
	  echo "SKIP cross wycheproof: no checkout and no network"; \
	fi
	@set -e; cd bin/cross; for b in unit rsa_test sha3_test sha3_equiv_test sha512_test hkdf384_test p384_test p256_field_test p256_ecdh_test p256_sign_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
	  echo "== $$b ($(RUNNER))"; ENUM_DEPTH=3 $(RUNNER) ./$$b; done; \
	if [ -x wycheproof_test ]; then echo "== wycheproof_test ($(RUNNER))"; $(RUNNER) ./wycheproof_test; fi

# Lean spec hygiene: the escape hatches that would quietly weaken the
# proofs are banned from the model (spec/lean/Spec/, Spec.lean) — sorry,
# admit, native_decide, unsafe, axiom declarations, and kernel-limit
# bumps. Main.lean is the IO oracle driver, not the model; its one
# `partial def loop` (a REPL cannot be proven terminating) is the sole
# allowed use. The axiom check then proves the load-bearing theorems
# rest only on Lean's three standard axioms.
SPEC_MODEL := $(wildcard spec/lean/Spec/*.lean) spec/lean/Spec.lean
lint-spec:
ifeq ($(LAKE),)
	$(call REQUIRE,lint-spec,lake is not on PATH — install elan from https://leanprover.github.io)
else
	@rc=0; for f in $(SPEC_MODEL) spec/lean/Main.lean; do \
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
	@cd spec/lean && $(LAKE) build 2>&1 | tee /tmp/lake-build.log \
	  && ! grep -q "warning:" /tmp/lake-build.log \
	  || { echo "lint-spec: lake build warnings are errors here"; exit 1; }
	# The axiom check elaborates against all of Mathlib, about 11 seconds.
	# Its answer depends only on the compiled Spec modules, the check
	# itself, the Lean toolchain and the Mathlib commit, so a run whose
	# hash of those matches bin/spec-axioms.ok, the hash of the last clean
	# run, has nothing new to check. lake has already rebuilt every
	# module whose source changed.
	@key=$$(cat spec/lean/AxiomCheck.lean spec/lean/lean-toolchain spec/lean/lake-manifest.json \
	    spec/lean/.lake/build/lib/lean/Spec.olean spec/lean/.lake/build/lib/lean/Spec/*.olean \
	    | shasum -a 256 | cut -d' ' -f1); \
	if [ "$$(cat bin/spec-axioms.ok 2>/dev/null)" = "$$key" ]; then \
	  echo "lint-spec: model clean; the compiled model is the one the last axiom check passed"; \
	  exit 0; \
	fi; \
	(cd spec/lean && $(LAKE) env lean AxiomCheck.lean) > /tmp/axioms.log 2>&1 \
	  || { cat /tmp/axioms.log; exit 1; }; \
	! grep -oE "depends on axioms: \[[^]]*\]" /tmp/axioms.log \
	  | tr ',[]' '\n' | sed 's/.*axioms: //;s/^ *//;s/ *$$//' | grep -v '^$$' \
	  | grep -vxE 'propext|Classical\.choice|Quot\.sound' \
	  || { echo "lint-spec: a theorem in the model depends on a non-standard axiom"; exit 1; }; \
	mkdir -p bin && echo "$$key" > bin/spec-axioms.ok; \
	echo "lint-spec: model clean, theorems rest on the standard axioms only"
endif

# Checks and thresholds live in .clang-tidy; every disable carries a reason
# there (fix-or-drop, never NOLINT in code).
lint: lint-toolchain lint-pins lint-proof-cover lint-size-floor lint-pinned-checkers lint-rfcs lint-exact-fill lint-analyzers lint-format lint-commits lint-docs lint-conflict-markers lint-invariants lint-stack lint-size lint-tracked-ignored lint-matrix lint-nightly-report lint-violation-builds lint-violation-anchors lint-impact lint-fuzz-budget lint-codegen-partition lint-runtime-symbols lint-wide-multiply lint-commit-citations lint-issue-links lint-shellcheck lint-bench-numbers lint-stack-walk lint-spec lint-trust-separation lint-quic-partition lint-quic-surface lint-zig-build lint-p256-wide

# The Zig build a Zig project depends on (build.zig, docs/decisions.md 69),
# held to make's, and the Zig API its module carries (docs/zig.md). zig
# fmt checks the Zig sources, `zig build test` runs the localizer's unit
# tests, test/localize-check.sh compares the localizer with llvm-objcopy
# -G and nmedit -s over objects of both formats, and
# test/zig-build-check.sh builds the default object, the four colibri
# links, stompy's and a SUITE=aesgcm record-mode object both ways and
# requires the same sources, defines, exports and build record, builds
# test/zig-consumer against each object through the module the package
# exports for it and runs the API's unit tests and, for each ROLE=both
# object, a client and a server through the API, across an AES-GCM write
# key's ceiling under SUITE=aesgcm, then links two Zig objects of
# different transports into one image and runs it. check-slow runs the
# last over every lib-check build's configuration. With every object and
# program built the script takes 5 s on an M-series Mac, 20 to 23 s
# after an edit to cfg.h, and 44 to 45 s with no Zig build
# (docs/decisions.md 73). The SUITE=aesgcm object added 2 to 5 s to the
# second and under 3 s to the others, at load averages of 18 to 37, and
# nothing measurable to make -j8 check after that edit: 79 to 81 s with
# the object and without it, at load averages of 18 to 56.
#
# The two scripts build from every library source and header, the Zig
# sources, the Makefile and git's file list, with zig, $(CC), the LLVM
# tools beside $(LLVM_NM) and the system's linker, so the stamp covers
# every file git does not ignore, those tools' versions and the system's
# release (tools/stamp.py).
ZIG_SRCS := build.zig build.zig.zon $(wildcard chapulin*.zig tools/*.zig test/zig-consumer/*.zig) test/zig-consumer/build.zig.zon
.PHONY: lint-zig-build lint-zig-build-run
lint-zig-build:
ifeq ($(ZIG),)
	$(call REQUIRE,zig,brew install zig -- see the ZIG_VERSION pin in tools/toolchain.env)
else
	@python3 tools/stamp.py lint-zig-build --content . --output '$(ZIG) version' \
	  --output '$(CC) --version' --output '$(LLVM_NM) --version' --output 'uname -srm' \
	  -- $(MAKE) --no-print-directory lint-zig-build-run
endif
lint-zig-build-run:
	@$(ZIG) fmt --check $(ZIG_SRCS) || { echo "lint-zig-build: zig fmt would rewrite the files above"; exit 1; }
	@$(ZIG) build test --summary none --cache-dir bin/zig/root-cache
	+@ZIG='$(ZIG)' CC='$(CC)' LLVM_NM='$(LLVM_NM)' ./test/localize-check.sh
	+@ZIG='$(ZIG)' CC='$(CC)' ./test/zig-build-check.sh

# INV-19: bounded stack. The budget is the measured worst library
# frame (rsa_vp1's RSA-3072 word temporaries, 2,400 bytes) rounded up;
# a frame past it is a build error, not a bench surprise. Each source
# compiles alone so a breach names its file.
# Hand-written C, and the Zig API that forwards to it, stays under 500
# lines (CLAUDE.md): the rule serves third-party audit, so it covers what
# a person reads and skips what a generator emits. spec/ is Lean and
# carries its own reasoning for the exemption there.
# One wc and one awk read every file, rather than three processes per
# file: the file list has grown past four hundred. A file over the limit
# whose first three lines say "Generated by" is a generator's.
FILE_LINE_MAX := 500
.PHONY: lint-size
lint-size:
	@rc=0; \
	generated=$$(git ls-files -z '*.c' '*.h' | xargs -0 awk 'FNR <= 3 && /Generated by/ {print FILENAME}'); \
	over=$$(git ls-files -z '*.c' '*.h' 'chapulin*.zig' | xargs -0 wc -l \
	  | awk -v max=$(FILE_LINE_MAX) '$$2 != "total" && $$1 > max {print $$2 ":" $$1}'); \
	for e in $$over; do \
	  f=$${e%:*}; n=$${e##*:}; \
	  printf '%s\n' "$$generated" | grep -qxF "$$f" && continue; \
	  echo "lint-size: $$f is $$n lines, over $(FILE_LINE_MAX)"; rc=1; \
	done; \
	[ $$rc -eq 0 ] && echo "lint-size: every hand-written C file and the Zig API under $(FILE_LINE_MAX) lines"; exit $$rc

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
#
# check runs this for several builds at once, so each run compiles into
# a directory of its own. A run is skipped when every .c and .h file, the
# Makefile, the compiler's version, the system's release and the make
# variables, which name the build, are what they were when it last
# passed (tools/stamp.py).
# The test flags, less CH_NATIVE_WIDEMUL for a host object, which ct.h
# refuses beside -DCH_CPU_RUNTIME.
STACK_CFLAGS = $(if $(filter -DCH_CPU_RUNTIME,$(LIB_DEF)),$(HOST_CFLAGS),$(CFLAGS))
.PHONY: lint-stack-run
lint-stack:
	@python3 tools/stamp.py lint-stack --content '*.[ch]' $(STAMP_MAKEFILES) \
	  --output '$(CC) --version' --output 'uname -srm' -- $(MAKE) --no-print-directory lint-stack-run
lint-stack-run:
	@mkdir -p bin/obj; objs=$$(mktemp -d bin/obj/stack.XXXXXX); \
	rc=0; for f in $(LIB_SRCS) drbg.c; do \
	  budget=$(STACK_BUDGET); \
	  case " $(KEX_HYBRID_SRCS) $(call hash_hw_of,$(KEX_HYBRID_SRCS)) $(STACK_KEX_HYBRID_COPIES) " in \
	    *" $$f "*) budget=$(STACK_BUDGET_KEX_HYBRID) ;; esac; \
	  case " $(RSA_SIGN64_SRCS) " in *" $$f "*) budget=$(STACK_BUDGET_RSA_SIGN64) ;; esac; \
	  case "$$f" in p256_wide_wipe.c) budget=$(STACK_BUDGET_P256_WIDE_WIPE) ;; esac; \
	  $(CC) $(STACK_CFLAGS) $(LIB_DEF) -Wframe-larger-than=$$budget -I. -c $$f -o $$objs/$$f.o || rc=1; \
	done; rm -rf $$objs; \
	[ $$rc -eq 0 ] && echo "lint-stack: every library frame under $(STACK_BUDGET) B, ML-KEM's under $(STACK_BUDGET_KEX_HYBRID) B, the 64-bit RSA signer's under $(STACK_BUDGET_RSA_SIGN64) B, the wide P-256 stack wipe's under $(STACK_BUDGET_P256_WIDE_WIPE) B"; exit $$rc

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
# Semgrep reads the rules, their tests and the files it scans, so the run
# is skipped when every .c and .h file, .semgrep/, the JSON reader, the
# Makefile, Semgrep's version and the make variables are what they were
# when it last passed (tools/stamp.py).
# SEMGREP_ENABLE_VERSION_CHECK=0 keeps --version from asking semgrep.dev
# for a newer release, which would put a network answer in the key.
lint-invariants:
ifeq ($(SEMGREP),)
	$(call REQUIRE,semgrep,pip install --require-hashes -r .semgrep/requirements.txt)
else
	@python3 tools/stamp.py lint-invariants --content '*.[ch]' --content .semgrep \
	  --file tools/semgrep-parse.py $(STAMP_MAKEFILES) \
	  --output 'SEMGREP_ENABLE_VERSION_CHECK=0 $(SEMGREP) --version' \
	  -- $(MAKE) --no-print-directory lint-invariants-run
endif
.PHONY: lint-invariants-run
lint-invariants-run:
	# Local rules only and --metrics=off, never --config auto or a
	# registry config: those fetch rules from and upload scan context
	# to semgrep.dev. The version pin lives in .semgrep/requirements.txt
	# with hashes because semgrep carries a large dependency tree and is
	# the only pip package in the security path.
	# Tracked files only: CI builds tools from source inside the
	# workspace, and a dot target would audit their sources too. The
	# violation file is excluded here because semgrep scans explicit
	# targets regardless of --exclude.
	# The rule tests run beside the scan: each semgrep start costs about
	# three seconds, and neither run reads what the other writes.
	# Semgrep reports a file it could not parse as a warning and exits 0,
	# and no rule checks that file. tools/semgrep-parse.py reads the
	# scan's JSON and fails on that, and on a partial parse of any file
	# its PARTIAL list does not name. A rule that runs past --timeout
	# skips the file the same way: inv-23 took over the default five
	# seconds on test/mlkem_vectors.h at a load average of 70. So the
	# scan sets no time limit, and its result does not depend on load.
	@mkdir -p bin; rm -f bin/semgrep-scan.json; \
	$(SEMGREP) --metrics=off --test \
	  --config .semgrep/invariants.yml .semgrep/invariants.c > bin/semgrep-test.log 2>&1 & \
	test_pid=$$!; \
	$(SEMGREP) scan --metrics=off --quiet --error --timeout 0 --json-output=bin/semgrep-scan.json \
	  --config .semgrep/invariants.yml $$(git ls-files '*.c' '*.h' ':!.semgrep'); \
	scan_rc=$$?; \
	wait $$test_pid || { cat bin/semgrep-test.log; echo "lint-invariants: a rule missed its tripwire or matched a clean line"; exit 1; }; \
	python3 tools/semgrep-parse.py bin/semgrep-scan.json || exit 1; \
	[ $$scan_rc -eq 0 ] || exit $$scan_rc; \
	echo "lint-invariants: rules clean, tripwires trip, no parse failure outside the PARTIAL list"

# Assert the resolved checkers are the pinned ones before any of them runs.
# CI has asserted this since the pins existed; a development machine had no
# equivalent, so an upgraded Homebrew LLVM reported eight new diagnostics in
# x509_der.c and read as the code being broken rather than the checker having
# moved. A version this does
# not recognise is a stop, not a warning: CLAUDE.md forbids adapting code or
# suppressions to an older checker, and the same rule makes a silent newer
# one just as wrong. lint-tidy, lint-cppcheck, lint-wide-multiply and
# lint-runtime-symbols also check their own checkers (REQUIRE_PINNED),
# because a catch script runs them without this.
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
	 if [ -z "$(ZIG)" ]; then \
	   echo "lint-toolchain: zig is missing; the pin is Zig $(ZIG_VERSION) (tools/toolchain.env)"; rc=1; \
	 elif [ "$$($(ZIG) version 2>/dev/null)" != "$(ZIG_VERSION)" ]; then \
	   echo "lint-toolchain: $(ZIG) is Zig $$($(ZIG) version 2>/dev/null), and the pin is $(ZIG_VERSION) (tools/toolchain.env)"; rc=1; \
	 fi; \
	 [ $$rc -eq 0 ] && echo "lint-toolchain: every checker is the pinned LLVM $(LLVM_MAJOR), and zig is the pinned $(ZIG_VERSION)"; exit $$rc

# tools/toolchain.env is the only place a tool version is written, and every
# job that reads one loads it. tools/toolchain-pins.py carries the reasoning
# for both halves.
.PHONY: lint-pins
lint-pins:
	@python3 tools/toolchain-pins.py

# lint-tidy, lint-cppcheck, lint-wide-multiply and lint-runtime-symbols
# fail on a checker at another version (REQUIRE_PINNED): each gets a
# stand-in that reports an older one and a newer one, and must fail and name
# the pin (test/pinned-checkers.sh). The stand-ins need no LLVM and no
# cppcheck, and the recipe starts with + so the lints the script runs share
# this make's job slots.
.PHONY: lint-pinned-checkers
lint-pinned-checkers:
	+@./test/pinned-checkers.sh

# ct.h's size_t floor: refused at a 16-bit target, compiled at a 32-bit one
# (test/size-floor.sh). CLANG_RV is the clang the codegen lints already use,
# which can target both.
.PHONY: lint-size-floor
lint-size-floor:
	@./test/size-floor.sh "$(CLANG_RV)"

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
# than from a list kept by hand. A root file belongs to TRANSPORT=quic-nonblocking
# when it writes no declaration without -DCH_TRANSPORT_QUIC_NONBLOCKING and gains
# something with it. The rule is that every such file is named quic*,
# and that no other root file is one, so `git ls-files 'quic*'` names
# every file the mode owns and a reader sees how much it covers without
# reading the build. tools/quic-partition.py carries the reasoning, the
# flags each run passes and what the check cannot see.
#
# The two lists below are the mode's text outside the prefix, and the
# lint reads them from here.
#
# handshake_flight.[ch] is the one file the QUIC mode adds that every
# transport compiles: the tcp-blocking driver in handshake.c, the
# tcp-nonblocking driver in tcp_nonblocking_step.c and the QUIC driver in
# quic_step.c call the same flight handlers, so no protocol rule
# exists twice (docs/quic.md, "The design: one whole message per step").
# It carries no quic prefix on purpose, and QUIC_SHARED names it here so
# a reader sees the exemption rather than reading the missing prefix as
# a mistake. The exemption checks its file rather than skipping it: a
# QUIC_SHARED file that becomes QUIC-only fails this lint too, under the
# message that belongs to it, which says a file both transports compile
# has stopped compiling in a TCP build.
QUIC_SHARED := handshake_flight.c handshake_flight.h
# The shared files that carry a #ifdef CH_TRANSPORT_QUIC_NONBLOCKING arm: the
# configuration, the session struct, the handshake layers the mode
# reuses, the build record, which holds sizeof(ch_quic) in a QUIC build
# and 0 in the others, the CA provisioning call, whose symbol name
# x509_ca.h gives the QUIC transport's suffix in a QUIC build
# (docs/decisions.md 61), and the AES key entries, whose QUIC arms
# build the Initial and Retry keys and run header protection, which a
# TLS record does not have. Each holds text only a QUIC build compiles,
# so each is a place to look that the prefix does not name, and a file
# that gains such an arm without joining this list fails the lint. A file
# that stops carrying one fails it too, so the list never sends a reader
# to a file that holds nothing.
QUIC_CONDITIONAL := cfg.h session.h handshake_record.h handshake_post.h \
                    handshake_auth.h handshake_parser.h handshake_message.c \
                    handshake_parser_ee.c handshake_record.c handshake_auth.c \
                    handshake_post.c build.h build.c x509_ca.h x509_ca.c \
                    aes.h aes.c ticket.h alert.h
# A QUIC host object holds two AES ciphers, the instructions and the table
# (CH_AES_TWO_CIPHERS, aes.h), so where this compiler passes the host test
# QUIC_EXTRA_DEFINES judges these three under the host object's suite
# defines, and the transport define adds aes_block.h's two aes_soft_
# entries, aes_schedule.h's record of the cipher and gcm.c's choice of
# GHASH and counter mode by that record. Under any other compiler the
# three are judged under the AES=extern suite build, which holds one
# cipher and no such arm.
QUIC_CONDITIONAL += $(if $(HOST_TARGET),aes_block.h aes_schedule.h gcm.c)
#
# The lint preprocesses every root source and header with $(CC) and reads
# the Makefile and git's file list, so its stamp covers every file git
# does not ignore and the compiler's version (tools/stamp.py).
.PHONY: lint-quic-partition
lint-quic-partition:
	+@python3 tools/stamp.py lint-quic-partition --content . --output '$(CC) --version' \
	  -- env CC='$(CC)' python3 tools/quic-partition.py

# quic.h and docs/quic.md's interface table must name the same ch_quic_
# entries. A name in one and not the other means the header and its
# design record disagree about the public surface, which is a defect in
# whichever moved last. `make quic-footprint` prints the same comparison
# inside its report; this target is the one that fails, so the report
# reaches no verdict of its own.
.PHONY: lint-quic-surface
lint-quic-surface:
	+@python3 tools/quic-footprint.py --check-surface

# The two analyzers write nothing and read nothing the other writes, so
# they run at once, each LINT_JOBS processes wide. Their lines can
# interleave; each finding still names its file. Each skips what passed
# before on the same inputs, so on an unchanged tree neither analyses a
# file.
.PHONY: lint-analyzers
lint-analyzers:
	@$(MAKE) --no-print-directory -j2 lint-tidy lint-cppcheck

# The checks the M3 smoke pass turns off, named once because the list's
# commas would split a $(call) argument. lint-tidy says why each is off.
QEMU_TIDY_CHECKS := -bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-misc-use-internal-linkage,-portability-no-assembler
lint-tidy:
ifeq ($(CLANG_TIDY),)
	$(call REQUIRE,clang-tidy,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	$(call REQUIRE_PINNED,lint-tidy,$(CLANG_TIDY),version $(LLVM_MAJOR)\.,LLVM $(LLVM_MAJOR))
	@mkdir -p bin && : > $(TIDY_PASSES)
	# webpki.c, the three webpki test mains and the webpki example read
	# ch_cfg fields that exist only under -DCH_TRUST_WEBPKI, so this
	# pass, which defines no trust mode, leaves them to the next one.
	# handshake_groups.c guards its whole body on CH_KEX_TWO_GROUPS,
	# which only that define sets, so it goes there too.
	# The QUIC sources and their test main are left out for the same
	# reason: every declaration they hold sits behind
	# -DCH_TRANSPORT_QUIC_NONBLOCKING, which this pass does not define, so it would
	# read eight empty translation units. The two passes below read them.
	# x509_ca.c, drbg.c and the two mains that call ch_drbg_seed get
	# passes of their own too: x509_ca.h declares ch_pubkey_from_pem only
	# under -DCH_TRUST_CA, and drbg.h declares ch_drbg_seed only under
	# -DCH_RAND_DRBG. test/stack_residue.c stays out of every pass: it
	# declares its one call beside the definition, where its callers
	# declare it too, and misc-use-internal-linkage asks a file read alone
	# to make that call static, which its callers' link would refuse.
	@$(call TIDY_EACH,$(filter-out webpki.c webpki_ticket.c webpki_pin.c \
	  webpki_cfg.c handshake_groups.c x509_ca.c drbg.c test/drbg_test.c test/entropy_recipe.c \
	  test/webpki_resume_test.c test/webpki_session_test.c \
	  test/webpki_chain_test.c test/webpki_auth_test.c \
	  test/webpki_encrypted_exts_test.c examples/webpki_client.c $(QUIC_SRCS) \
	  $(AES_IMPL_SRCS) test/quic_driver_test.c test/quic_vectors.c \
	  test/diff_quic_test.c test/aes_equiv_test.c test/aes_equiv_soft.c \
	  test/aes_equiv_hw.c test/aes_extern_hook.c test/ghash_equiv_test.c test/ghash_equiv_soft.c \
	  test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c \
	  $(SRV_SRCS) test/srv_auth_test.c test/srv_test.c test/srv_flight_test.c \
	  test/tls_server.c srv_quic.c quic_token.c srv_tcp_nonblocking.c test/srv_tcp_nonblocking_test.c \
	  test/tcp_nonblocking_loop_test.c test/tcp_blocking_loop_test.c test/webpki_loop_test.c \
	  test/tcp_blocking_key_limit_test.c test/quic_loop_test.c test/ticket_epoch_test.c \
	  test/exporter_test.c tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c x25519_wide.c \
	  test/x25519_equiv_test.c $(P256_WIDE_SRCS) test/p256_equiv_test.c test/hkdf384_test.c \
	  $(P384_WIDE_SRCS) test/p384_equiv_test.c test/p384_equiv_field.c test/p384_equiv_sign.c \
	  test/p384_portable.c \
	  test/diff_x25519_test.c test/diff_p256_wide_test.c chacha20_vector.c test/chacha20_equiv_vector.c \
	  poly1305_vector.c test/poly1305_equiv_vector.c test/stack_residue.c \
	  poly1305_avx2.c test/poly1305_equiv_avx2.c \
	  mlkem_vector.c test/mlkem_vector_equiv_test.c \
	  keccak_avx2.c mlkem_avx2.c test/mlkem_avx2_equiv_test.c \
	  test/x86_kernels_test.c test/x86_kernels_count.c \
	  $(RSA_HOST_LINT_C) $(WIDEMUL_HOST_LINT_C) $(HASH_HOST_LINT_C),$(LINT_C)), \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -I.)
	# The wide X25519 field. x25519_wide.c guards its body on
	# -DCH_CPU_RUNTIME and compiles x25519.c's clamp and all-zero check
	# inside it, so the pass above reads the 16-word field and this one
	# reads the other, with the equivalence test, which calls both, and the
	# differential main, which refuses any other build.
	@$(call TIDY_EACH,x25519_wide.c test/x25519_equiv_test.c test/diff_x25519_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I.)
	# The wide P-256 files, whose bodies sit behind -DCH_CPU_RUNTIME too,
	# with the equivalence test, which calls them and the files under
	# their own names, and the differential main, which refuses any other
	# build. p256.c compiles its other arm under the define, the one that
	# calls p256_wide_verify.c, so the pass above reads the 32-bit arm and
	# this one reads the host arm, with the verifiers' equivalence test.
	# test/p256_verify_portable.c stays out of every pass, for the reason
	# test/aes_equiv_soft.c does below.
	@$(call TIDY_EACH,$(P256_WIDE_SRCS) p256.c test/p256_equiv_test.c test/diff_p256_wide_test.c \
	  test/p256_verify_equiv_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I. -Itest)
	# P-384's 64-bit field, points and verifier (docs/decisions.md
	# 97), whose bodies sit behind -DCH_CPU_RUNTIME, with p384.c, which
	# compiles the arm that calls them under the define, and the three
	# units of the equivalence test that are its own. test/p384_portable.c stays out of every
	# pass, for the reason test/aes_equiv_soft.c does below.
	@$(call TIDY_EACH,$(P384_WIDE_SRCS) p384.c test/p384_equiv_test.c test/p384_equiv_field.c \
	  test/p384_equiv_sign.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I. -Itest)
	# RSA's arithmetic on 64-bit words and the signer built on it
	# (docs/decisions.md 95). rsa_mont64.c and rsa_sign64.c guard their
	# bodies on -DCH_CPU_RUNTIME and rsa_mont.c compiles its other arm
	# under it, so the pass above reads the 32-bit arm and this one reads
	# the 64-bit one, with the two equivalence tests, which call both.
	# rsa_sign64.c ends by compiling rsa_sign.c's encoder, so this pass
	# reads that under the define too. test/rsa_equiv_portable.c stays out
	# of every pass,
	# for the reason test/aes_equiv_soft.c does below. ct.h defines the
	# 64x64->128 multiply with unsigned __int128, so the pass runs only
	# where HOST_TARGET found a host compiler.
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,rsa_mont64.c rsa_mont.c rsa_sign64.c test/rsa_equiv_test.c test/rsa_sign_equiv_test.c \
	  test/rsa_sign_equiv_pieces.c test/diff_rsa_sign_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I.)
	# A host object's ChaCha20. chacha20_vector.c guards its body on
	# -DCH_CPU_RUNTIME, and chacha20.c and aead.c hold the entries that
	# take a session's ch_cfg.cpu under it, so this pass reads the three in
	# the instruction set of the host that runs the lint: NEON on an arm64
	# machine, SSE2 on CI's x86-64 runner. The pass of the native copies
	# below reads the vector Poly1305. test/chacha20_equiv_vector.c,
	# test/poly1305_equiv_vector.c and test/poly1305_equiv_avx2.c stay out
	# of every pass, for the reason test/aes_equiv_soft.c does below.
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,chacha20.c chacha20_vector.c aead.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I.)
	# The x86-64 kernels and the two files that choose them, read for an
	# x86-64 target whatever the host, as the QEMU pass below names its
	# core: chacha20_avx2.c and gcm_vaes.c have no body on any other
	# target, and chacha20.c's use_avx2 and gcm_vaes.h's gcm_use_vaes
	# compile on x86-64 alone, so on an arm64 machine no pass above reads them. The
	# counting test of the kernels joins the second line, whose defines are
	# its binary's. Freestanding, with tools/freestanding's string.h.
	@$(call TIDY_EACH,chacha20_avx2.c chacha20.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -I.)
	@$(call TIDY_EACH,gcm_vaes.c gcm.c test/x86_kernels_count.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest)
	# The AVX2 Poly1305 (docs/decisions.md 110) as its native copy, which
	# has a body on x86-64 alone, with poly1305.c's native copy, whose x86-64
	# arm holds the update that calls it, and aead.c, whose MAC calls it
	# through widemul.h's x86-64 arm.
	@$(call TIDY_EACH,poly1305_avx2_native.c poly1305_native.c aead.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -I.)
	# A host object's ML-KEM NTT (docs/decisions.md 101). mlkem_vector.c
	# holds one arm for each architecture, so two passes read it for a named
	# target whatever the host, as the passes above read the kernels, with
	# mlkem.c, whose host arm calls it. Its equivalence test follows with
	# the Keccak test mains below.
	@$(call TIDY_EACH,mlkem_vector.c mlkem.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -I.)
	@$(call TIDY_EACH,mlkem_vector.c mlkem.c, \
	  -std=c11 --target=aarch64-none-elf -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -I.)
	# The four-way Keccak and ML-KEM's copy over it (docs/decisions.md
	# 107), which have a body on x86-64 alone, read for an x86-64 target
	# whatever the host, as the kernels' passes above are. mlkem_avx2.c
	# compiles mlkem.c's text, so the pass reads the copy's arms too. Their
	# equivalence test follows with the Keccak test mains below.
	@$(call TIDY_EACH,keccak_avx2.c mlkem_avx2.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -I.)
	# A host object's SHA-256 and SHA-512 on the CPU's instructions
	# (docs/decisions.md 93). sha256_hw.c holds one arm for each
	# architecture, so two passes read it for a named target whatever the
	# host, as the pass above reads the kernels: x86-64 and arm64,
	# freestanding. The arm64 pass reads sha512_hw.c too, which has no body
	# on x86-64. The two copies and the
	# files they copy follow under the host's own target with the defines
	# the equivalence test's binary takes, so the pass reads the entries
	# that end sha256.h, hkdf.h and keysched.h too, and then the two test
	# mains under their binaries' defines. test/hash_runtime_count.c stays
	# out of every pass, for the reason test/aes_equiv_soft.c does below.
	# sha3_hw.c and ML-KEM's two copies have a body for arm64 under clang
	# alone (docs/decisions.md 99), which the arm64 pass's target gives
	# them, and the two Keccak test mains follow under the host's own target.
	@$(call TIDY_EACH,sha256_hw.c, \
	  -std=c11 --target=x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -I.)
	@$(call TIDY_EACH,sha256_hw.c sha512_hw.c, \
	  -std=c11 --target=aarch64-none-elf -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -I.)
	@$(call TIDY_EACH,sha3_hw.c mlkem_hw.c mlkem_poly_hw.c, \
	  -std=c11 --target=aarch64-none-elf -ffreestanding -nostdlibinc -Itools/freestanding \
	  -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -I.)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,hkdf.c keysched.c hkdf_hw.c keysched_hw.c test/sha2_equiv_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $(SHA2_EQUIV_TEST_DEFS) -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/sha3_hw_equiv_test.c test/mlkem_hw_equiv_test.c test/mlkem_vector_equiv_test.c \
	    test/mlkem_avx2_equiv_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/hash_runtime_test.c record.c quic_keys.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest)
	# The pass above defines no trust mode, so it reads none of the
	# TRUST=webpki arms. This pass parses the sources that carry them or
	# compile against the webpki layout of ch_cfg and handshake_state, and
	# the four tests built under the define, with -DCH_TRUST_WEBPKI, so
	# the cognitive-complexity threshold holds in that build too. That
	# build offers the hybrid (docs/decisions.md 53), so the pass reads
	# webpki_session_test.c's hybrid arm too. Measured with clang-tidy
	# 23.1.1: 2.9 s.
	@$(call TIDY_EACH,tls.c handshake_parser.c handshake_parser_ee.c \
	  handshake_message.c handshake_auth.c handshake.c handshake_record.c handshake_flight.c \
	  handshake_groups.c webpki.c webpki_ticket.c webpki_pin.c webpki_cfg.c \
	  test/webpki_session_test.c test/webpki_chain_test.c test/webpki_auth_test.c \
	  test/webpki_encrypted_exts_test.c test/handshake_strict_test.c \
	  test/diff_test.c examples/webpki_client.c test/webpki_resume_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI -I.)
	# The CA mode's provisioning call, under -DCH_TRUST_CA: every object
	# that packages x509_ca.c compiles with that define, and x509_ca.h
	# declares ch_pubkey_from_pem only under it.
	@$(call TIDY_EACH,x509_ca.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_CA -I.)
	# The reference generator, its test main and docs/entropy.md's recipe,
	# under -DCH_RAND_DRBG in place of the host's pattern, as bin/drbg_test
	# builds: drbg.h declares ch_drbg_seed only under that define.
	@$(call TIDY_EACH,drbg.c test/drbg_test.c test/entropy_recipe.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_DRBG -I.)
	# RAND=session, in place of the host's pattern: the draw sites and the
	# configuration checks read rand.h's session arm and ch_cfg's two
	# fields only under -DCH_RAND_SESSION, and so do the three loop tests
	# built under it, whose fixture is test/rand_session.h. Each file takes
	# the role, trust mode or transport its body sits behind.
	@$(call TIDY_EACH,tls.c handshake_flight.c srv_flight.c srv_kex.c srv_resume.c srv_auth.c srv.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I.)
	@$(call TIDY_EACH,handshake_groups.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_TRUST_WEBPKI -I.)
	@$(call TIDY_EACH,quic_config.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/tcp_nonblocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_KEX_PQ $(EXPORTER_DEF) -DCH_KEYLOG -I.)
	@$(call TIDY_EACH,test/tcp_blocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I.)
	@$(call TIDY_EACH,test/quic_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_SESSION -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PIN_ECDSA -I. -Itest)
	# The QUIC mode: its sources and its three test mains, under every
	# check.
	@$(call TIDY_EACH,$(QUIC_SRCS), \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/quic_driver_test.c test/quic_vectors.c \
	  test/diff_quic_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	# The AES implementation this build did not pick, read under the suite
	# build's defines, the text that holds its AES-256 pair as well as the
	# AES-128 one. The pass above already read what $(AES_IMPL) names.
	@$(call TIDY_EACH,$(filter-out $(AES_IMPL),aes_extern.c), \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $(AES_EXTERN_SUITE_DEF) -I.)
	# test/aes_equiv_test.c alone: the two wrappers beside it compile a
	# library source in under a renamed symbol, so linting them would
	# report that source's findings a second time under a name no file
	# on disk carries. test/aes_extern_hook.c stays out for the same
	# reason: it compiles quic_aes_soft.c in under renamed entries.
	@$(call TIDY_EACH,test/aes_equiv_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	# The host object's AES (docs/decisions.md 81 and 89), in the builds of
	# the binaries that run it, where HOST_TARGET found a host compiler:
	# the instructions' four sources and gcm.c's arm for them, which compile
	# only under -DCH_CPU_RUNTIME; the QUIC object that holds both ciphers,
	# with its test mains and loop; the TCP object, which holds the
	# instructions alone, with the client and server rules; and the four
	# test mains built on the TCP objects, the blocking loop's raw client
	# among them. No line takes an instruction flag, because the
	# instructions' functions turn them on for themselves.
	# test/ghash_equiv_test.c joins alone, for the reason
	# test/aes_equiv_test.c does above, and test/aes_runtime_soft.c and
	# test/aes_runtime_hw.c stay out for the same reason.
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,$(AES_HW_SRCS) aes.c quic_aes_soft.c gcm.c quic_initial.c quic.c quic_config.c \
	  srv_flight.c srv.c webpki_cfg.c test/aes_runtime_test.c test/quic_loop_test.c test/ghash_equiv_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI \
	  -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/quic_vectors.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME \
	  $(AES_256_TEST_DEF) -I.)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/x86_kernels_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_QUIC_NONBLOCKING $(HOST_SUITE_DEF) -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,$(AES_HW_SRCS) aes.c gcm.c tls.c test/webpki_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI \
	  -DCH_TRANSPORT_TCP_NONBLOCKING $(HOST_SUITE_DEF) -I.)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/webpki_session_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI $(HOST_SUITE_DEF) -I.)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/srv_flight_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER $(HOST_SUITE_DEF) -I.)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,test/tcp_blocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH $(HOST_SUITE_DEF) -I.)
	# The host object's multiply (docs/decisions.md 87 and 89): the native
	# copies, which ct.h refuses outside -DCH_CPU_RUNTIME; the answer the
	# record directions hold, which compiles only under it; and the vector
	# tests and the counting test, built under it. The count units stay
	# out, for the reason test/aes_equiv_soft.c does below.
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,$(WIDEMUL_COPIED:.c=_native.c) poly1305_vector_native.c record.c \
	  test/widemul_runtime_test.c test/widemul_runtime_count.c test/unit_test.c test/mlkem_test.c \
	  test/p256_ecdh_test.c test/p256_sign_test.c test/rsa_sign_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -I. -Itest)
	# A host object (docs/decisions.md 89): the rule every init call and
	# ch_srv_check apply to ch_cfg.cpu, which compiles only under
	# -DCH_CPU_RUNTIME, in each role, trust mode and transport that has it,
	# and the host binaries' rows and the files that set the field, built
	# under the same define. The loop and session mains take
	# -DTEST_WIDEMUL_COUNTED, as their host binaries do, so their rows of
	# the multiply bit are read too. cpu_cfg.h refuses the define on a
	# compiler that fails the host test, so the passes run only where
	# HOST_TARGET found one.
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,tls.c srv.c test/tcp_blocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER \
	  -DCH_ROLE_BOTH -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,tls.c test/webpki_session_test.c examples/webpki_client.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_TRUST_WEBPKI \
	  -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,tcp_nonblocking.c srv_tcp_nonblocking.c test/tcp_nonblocking_loop_test.c \
	  test/lib_pair_half.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER \
	  -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING $(EXPORTER_DEF) -DCH_KEYLOG -I. -Itest)
	@set -e; [ -z "$(HOST_BINS)" ] || \
	  $(call TIDY_EACH,quic_config.c test/quic_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER \
	  -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI -I. -Itest)
	# The server role gets its own pass: every declaration these files
	# hold sits behind -DCH_ROLE_SERVER, so the pass above would read
	# seven empty translation units.
	@$(call TIDY_EACH,$(SRV_SRCS) test/srv_auth_test.c test/srv_test.c \
	  test/srv_flight_test.c test/tls_server.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -I.)
	# The tcp-nonblocking transport's client driver, behind -DCH_TRANSPORT_TCP_NONBLOCKING,
	# and the build record's arm for that transport.
	@$(call TIDY_EACH,tcp_nonblocking.c tcp_nonblocking_frame.c tcp_nonblocking_step.c build.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRANSPORT_TCP_NONBLOCKING -I.)
	# Each server driver with the transport it is written for. Neither
	# reads a declaration the role pass above sets, because both sit
	# behind a transport define as well as the role. quic_token.c, the
	# QUIC server's Retry token, sits behind the same two defines, and so
	# do the build record's QUIC and server arms.
	@$(call TIDY_EACH,srv_quic.c quic_token.c build.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	@$(call TIDY_EACH,srv_tcp_nonblocking.c test/srv_tcp_nonblocking_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_TRANSPORT_TCP_NONBLOCKING -I.)
	# The loopback drives both drivers, so it is the one source that needs
	# CH_ROLE_BOTH as well: srv_cfg.h and tls.h keep the client half only
	# under that define.
	@$(call TIDY_EACH,test/tcp_nonblocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING $(EXPORTER_DEF) -DCH_KEYLOG -I.)
	@$(call TIDY_EACH,test/tcp_nonblocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_KEX_PQ $(EXPORTER_DEF) -DCH_KEYLOG -I.)
	# The blocking loopback, under the ROLE=both TRANSPORT=tcp-blocking
	# defines its object takes.
	@$(call TIDY_EACH,test/tcp_blocking_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I.)
	# The QUIC loopback, once per trust mode it is built in, because each
	# includes a different half.
	@$(call TIDY_EACH,test/quic_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_PIN_ECDSA -I. -Itest)
	@$(call TIDY_EACH,test/quic_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI -I. -Itest)
	# The TRUST=webpki record loopback, under the defines its object takes.
	@$(call TIDY_EACH,test/webpki_loop_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_TRUST_WEBPKI -I.)
	# The AES-GCM key-usage ceiling (docs/decisions.md 78): tls_write.c's
	# KeyUpdate step and record.c's refusal compile only under
	# -DCH_SUITE_AES_GCM, and so do the tcp-blocking loop that writes
	# across the ceiling with test/key_limit_cases.h and the AES-GCM rows
	# of test/diff_writable_len.h, which bin/diff_webpki_aes runs. The
	# AES=extern defines name a suite build no instruction flag has to
	# turn on.
	@$(call TIDY_EACH,tls_write.c record.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $(AES_EXTERN_SUITE_DEF) -I.)
	@$(call TIDY_EACH,test/tcp_blocking_key_limit_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI $(AES_EXTERN_SUITE_DEF) -I.)
	@$(call TIDY_EACH,test/diff_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI $(AES_EXTERN_SUITE_DEF) -I.)
	# The ticket epoch test, once per non-blocking transport it is built
	# for, under the CA mode it refuses to build without.
	@$(call TIDY_EACH,test/ticket_epoch_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_CA -DCH_TRANSPORT_TCP_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/ticket_epoch_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_CA -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	# The four ch_keylog call sites, which no other pass compiles: the
	# hook exists only under CH_KEYLOG, and keylog.h refuses that define
	# without a server role, so this pass names ROLE=both's pair.
	@$(call TIDY_EACH,handshake_flight.c srv_flight.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_KEYLOG -I.)
	# SHA-384 in the key schedule, behind -DCH_HASH_SHA384: hmac_sha384,
	# the dispatcher's second arm and keysched.c's SHA-384 constants and
	# context hash compile only there, and so do the SHA-384 rows of the
	# differential and test/hkdf384_test.c. The exporter's defines ride
	# along, so ks_exporter's SHA-384 arm is read too.
	@$(call TIDY_EACH,hkdf.c keysched.c test/hkdf384_test.c test/diff_test.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_HASH_SHA384 $(EXPORTER_DEF) -I.)
	# The exporter, behind its own axis: without these defines tls.h
	# declares no ch_export and keysched.h no ks_exporter, so this pass
	# would read a file with nothing in it.
	@$(call TIDY_EACH,test/exporter_test.c tls.c keysched.c hkdf.c \
	  handshake_flight.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $(EXPORTER_DEF) -I.)
	@$(call TIDY_EACH,srv_flight.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) $(EXPORTER_DEF) -DCH_ROLE_SERVER -I.)
	# test/lib_pair_half.c, under the defines of the objects
	# test/lib-pair-check.sh compiles it for. The first pass above reads
	# its TRANSPORT=tcp-blocking client; these read the tcp-nonblocking client with the
	# webpki configuration, the QUIC client with the CA provisioning call
	# and the boot check, and the two server-only drivers. The last reads
	# the image's key log hook, which only a KEYLOG=on pair compiles.
	@$(call TIDY_EACH,test/lib_pair_half.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_WEBPKI -DCH_TRANSPORT_TCP_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/lib_pair_half.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_TRUST_CA -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_ROLE_SERVER -DCH_ROLE_BOTH -I.)
	@$(call TIDY_EACH,test/lib_pair_half.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_TRANSPORT_TCP_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/lib_pair_half.c, \
	  -std=c11 -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -DCH_ROLE_SERVER -DCH_TRANSPORT_QUIC_NONBLOCKING -I.)
	@$(call TIDY_EACH,test/lib_pair_main.c, \
	  -std=c11 -D_DEFAULT_SOURCE -DLIB_PAIR_TCP_BLOCKING -DLIB_PAIR_TCP_NONBLOCKING -DLIB_PAIR_QUIC_NONBLOCKING -DLIB_PAIR_KEYLOG -I.)
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
	@$(call TIDY_EACH,--tidy-arg --checks=$(QEMU_TIDY_CHECKS) \
	  test/qemu/m3_runtime.c test/qemu/m3_start.c test/qemu/m3_kat.c, \
	  -std=c11 --target=armv7m-none-eabi -ffreestanding -DCH_RAND_EXTERN -I. -Itest/qemu)
	# The host half of the KAT diff is ordinary hosted C; no checks off.
	@$(call TIDY_EACH,test/qemu/host_runtime.c,-std=c11 -D_DEFAULT_SOURCE -I. -Itest/qemu)
	# Every pass above wrote one line; this checks them all from one pool.
	+@CLANG_TIDY='$(CLANG_TIDY)' CLANG='$(CLANG_RV)' LINT_JOBS=$(LINT_JOBS) \
	  python3 tools/tidy-each.py --passes $(TIDY_PASSES)
endif

# clang-format reads the files it is given and the .clang-format files
# above them, so the run is skipped when every file git does not ignore
# and clang-format's version are what they were when it last passed
# (tools/stamp.py).
lint-format:
ifeq ($(CLANG_FORMAT),)
	$(call REQUIRE,clang-format,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	@python3 tools/stamp.py lint-format --content . --output '$(CLANG_FORMAT) --version' \
	  -- $(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(BENCH_C) \
	  $(QEMU_SMOKE_C) $(TESTH) $(LOCALIZE_C)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	$(call REQUIRE,cppcheck,build it at the CPPCHECK_VERSION pinned in tools/toolchain.env)
else
	$(call REQUIRE_PINNED,lint-cppcheck,$(CPPCHECK),^Cppcheck $(subst .,\.,$(CPPCHECK_VERSION))$$,Cppcheck $(CPPCHECK_VERSION))
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
	#
	# The run is skipped when every .c and .h file, the Makefile,
	# cppcheck's version and the make variables are what they were when
	# it last passed (tools/stamp.py). When it does run,
	# lint-cppcheck-run analyses again only what changed.
	@python3 tools/stamp.py lint-cppcheck --content '*.[ch]' $(STAMP_MAKEFILES) \
	  --output '$(CPPCHECK) --version' -- $(MAKE) --no-print-directory lint-cppcheck-run
endif

# cppcheck keeps each file's analysis, its findings and its whole-program
# summary, in a build directory, and analyses a file again only when a
# hash over its tokens, the tokens of every header it includes, its
# defines, cppcheck's version and its suppressions changes. The
# whole-program pass reads every file's summary on every run, so a
# finding that spans two files still sees both. A build directory serves
# one command line: its name is a hash of the flags and the file list,
# so a run under other flags starts from an empty one.
#
# The files go to cppcheck by absolute path, and --relative-paths prints
# them relative again. cppcheck 2.22 finds a file's entry in the build
# directory's files.txt by suffix (getAnalyzerInfoFileFromFilesTxt in
# lib/analyzerinfo.cpp), so given relative paths, handshake_record.c,
# srv_handshake.c and srv_quic.c read and write the entries of record.c,
# handshake.c and quic.c, and the whole-program pass loses one of each
# pair. No absolute path in the tree ends with another. With each file
# in its own entry, -j keeps the whole-program checks, so the files are
# analysed LINT_JOBS at a time. A caller that passes NULL to a callee in
# another file that dereferences it is reported on the first run, on a
# run that analyses only the caller, and on one that analyses only the
# callee.
CPPCHECK_FLAGS := --std=c11 --enable=warning,style,performance,portability \
  --inline-suppr --suppress=missingIncludeSystem \
  --suppress=constParameterCallback --suppress=shiftTooManyBitsSigned \
  $(HOST_RAND_DEF) --force --error-exitcode=1 --quiet
# A host object's native copies, and the units that compile them again
# under counted names, define CH_WIDEMUL_NATIVE_COPY, which ct.h refuses
# outside -DCH_CPU_RUNTIME. In cppcheck's base configuration that #error
# is the whole file, so they get a run of their own under that define,
# with a build directory of its own (docs/decisions.md 87 and 89).
# Poly1305's native copy holds the vector path, whose header refuses a
# target without NEON or SSE2 on a little-endian core, and cppcheck
# defines no compiler macro, so the run states SSE2 and the byte order as
# a host compiler does. --force then reads the NEON arm as well.
#
# The two copies on the hash instructions join that run for the same
# reason: hash_hw.h refuses a copy outside -DCH_CPU_RUNTIME, so in the
# base configuration its #error is the whole file (docs/decisions.md 93).
# In a host object sha256.h includes cpu_cfg.h, for the bit its entries
# read, and cpu_cfg.h refuses a target that is not arm64 or x86-64 or
# that has no unsigned __int128. So the run states x86-64 and the type's
# size too, as an x86-64 compiler does: without them the configuration
# the run names is one cpu_cfg.h refuses, and cppcheck 2.22 reports that
# #error for every file that includes sha256.h on its second run over a
# build directory, though not on its first.
WIDEMUL_NATIVE_COPY_DEFS := -DCH_CPU_RUNTIME -D__x86_64__ -D__SIZEOF_INT128__=16 -D__SSE2__ \
                            -D__BYTE_ORDER__=__ORDER_LITTLE_ENDIAN__
WIDEMUL_NATIVE_COPY_C := poly1305_native.c mlkem_poly_native.c \
                         poly1305_vector_native.c poly1305_avx2_native.c \
                         test/widemul_count_native.c test/widemul_count_native_vector.c \
                         test/widemul_count_native_avx2.c \
                         hkdf_hw.c keysched_hw.c
CPPCHECK_C = $(filter-out $(WIDEMUL_NATIVE_COPY_C),$(LINT_C))
.PHONY: lint-cppcheck-run
lint-cppcheck-run:
	@build=bin/cppcheck/$$(printf '%s\n' '$(CPPCHECK_FLAGS) $(CPPCHECK_C)' | $(SHA256) | cut -c1-16); \
	mkdir -p $$build; \
	$(CPPCHECK) $(CPPCHECK_FLAGS) --cppcheck-build-dir=$$build -j$(LINT_JOBS) \
	  --relative-paths=$(CURDIR) $(addprefix $(CURDIR)/,$(CPPCHECK_C))
	@build=bin/cppcheck/$$(printf '%s\n' '$(CPPCHECK_FLAGS) $(WIDEMUL_NATIVE_COPY_DEFS) $(WIDEMUL_NATIVE_COPY_C)' \
	  | $(SHA256) | cut -c1-16); \
	mkdir -p $$build; \
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(WIDEMUL_NATIVE_COPY_DEFS) --cppcheck-build-dir=$$build -j$(LINT_JOBS) \
	  --relative-paths=$(CURDIR) $(addprefix $(CURDIR)/,$(WIDEMUL_NATIVE_COPY_C))
	# The QEMU and FreeRTOS smoke sources, with two suppressions:
	# unusedStructMember, because the hardware, not C, reads the vector
	# table entries; and comparePointers, because __bss_start and
	# __bss_end are one region to the linker and two objects to C.
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --suppress=missingIncludeSystem \
	  --suppress=unusedStructMember --suppress=comparePointers \
	  --error-exitcode=1 --quiet $(filter %.c,$(QEMU_SMOKE_C))

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
# copy of the sources that object packages, under that object's defines:
# -DCH_TRUST_WEBPKI, and where HOST_TARGET makes that object a host
# object, -DCH_CPU_RUNTIME, no CH_NATIVE_WIDEMUL and the native copies
# beside the files built on the multiply.
EXAMPLE_WEBPKI_SRCS := $(if $(HOST_TARGET),$(call host_srcs,$(WEBPKI_TEST_SRCS)),$(WEBPKI_TEST_SRCS))
bin/example_webpki: examples/webpki_client.c $(EXAMPLE_WEBPKI_SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(if $(HOST_TARGET),$(HOST_CFLAGS) -DCH_CPU_RUNTIME,$(CFLAGS)) -DCH_TRUST_WEBPKI -I. -o $@ \
	  examples/webpki_client.c $(EXAMPLE_WEBPKI_SRCS)

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
#
# The fast tier and the not-proof-backed class run one violation per
# worker, half as many workers as cores. With --jobs above 1,
# test/violations.py runs each violation in a copy of the tree under
# bin/violations/, one copy per worker, and never edits the working tree;
# its docstring says what a copy holds. The fast tier took 13 minutes one
# violation at a time in CI's check job on a 4-core runner (run
# 36228452875). Half the cores, because many catch targets run parallel
# jobs of their own (semgrep, zig, the clang lint specs): on a 10-core Mac
# the fast tier took 1,158 s with one worker, 393 s with five and 489 s
# with ten.
VIOLATION_JOBS ?= $(shell n=$$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2); echo $$(( n > 1 ? n / 2 : 1 )))
.PHONY: test-invariants-fast
test-invariants-fast: bin/unit bin/unit_ca bin/x509strict bin/x509strict_ecdsa bin/rsa_test bin/drbg_test bin/handshake_strict_test bin/handshake_strict_webpki bin/webpki_session_test bin/webpki_resume_test bin/webpki_resume_tcp_nonblocking bin/webpki_auth_test bin/webpki_encrypted_exts_test bin/softmul_test bin/unit_ct_widemul bin/mlkem_test_ct_widemul bin/webpki_spki_test bin/webpki_sigalg_test bin/webpki_cert_test bin/x25519_equiv_test bin/rsa_equiv_test bin/rsa_sign_equiv_test bin/rsa_sign_test_host
	+python3 test/violations.py --tier=fast --jobs $(VIOLATION_JOBS)

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
	cd spec/lean && $(LAKE) build
	+python3 test/violations.py --not-proof-backed --jobs $(VIOLATION_JOBS)
endif

# The proof-backed violations, whose target is proof/prove-one.sh running
# one CBMC harness: they need cbmc on PATH, and kissat for the harness to
# verify inside the wrapper's clock. Without cbmc the baseline fails and
# the runner reports ERROR, never caught. Each run is a proof of minutes,
# twice, so the nightly gives the class its own job with its own timeout,
# test-invariants-proof-backed
# (https://github.com/c4milo/chapulin/issues/144). test/violations.py
# reads the class from each catches line, so a new proof-backed
# violation lands here without a Makefile edit. The class runs one
# violation at a time, in the working tree: proof/run.sh admits each
# proof against the whole machine's memory, so two at once could
# exhaust it.
.PHONY: test-invariants-proof-backed
test-invariants-proof-backed:
	+python3 test/violations.py --proof-backed

# The whole set, one class after the other. Two recipe lines rather than
# two prerequisites: the proof-backed class edits sources in the working
# tree, and the other class copies the working tree when it starts, so
# a copy made during a proof-backed edit would hold that edit. The
# classes must never run at the same time under make -j.
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
	+@python3 test/violations.py --lint-builds

# Every violation's edit still matches its file exactly once. The runner
# reports a stale edit too, but only after building that edit's target,
# which is minutes away and lives in check-slow; matching the text costs
# no build, so it belongs here. Three edits went stale in one day without
# this: two when a header's guard gained a condition, and one when five
# TRUST arms came to write the same filter line and an edit naming that
# line alone matched three of them.
.PHONY: lint-violation-anchors
lint-violation-anchors:
	+@python3 test/violations.py --lint-anchors

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
#
# The test reads the Makefile through make, the harnesses and the files
# they include, the violations, the scripts and git's view of the tree,
# so its stamp covers every file git does not ignore, with git's, make's
# and Python's versions (tools/stamp.py).
.PHONY: lint-impact
lint-impact:
	+@python3 tools/stamp.py lint-impact --content . --output 'git --version' \
	  --output 'make --version' --output 'python3 --version' -- python3 test/impact_test.py

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
# record plaintext passes through: the chain from ct.c and ct_wipe.c up to tls.c, plus
# drbg.c (the reference generator ships outside the packaged object, but a
# firmware that picks RAND=drbg compiles it) and softmul.c (the multiply
# itself, on a core with none). buf.c is in because the binder and the
# Finished bytes pass through wbuf; its only arithmetic is on lengths, so
# its ceiling is zero like the rest. aes.c, aes_extern.c and gcm.c
# are in because a -DCH_SUITE_AES_GCM build passes them a traffic key,
# and quic_aes_soft.c is in beside them, a table cipher whose ceiling was
# written down before any suite build existed (INV-26 in
# docs/invariants.md).
# its ceiling is zero like the rest. p256_field.c is in for the plainest
# reason: a P-256 private scalar and an ECDSA nonce are its operands, which
# is why it exists beside the verify-only p256.c rather than inside it.
# quic_token.c is in because the Retry token key, which the caller holds
# secret, passes through it on its way to hmac_sha256; it multiplies
# nothing, so its ceiling is zero.
#
# WIDEMUL_PUBLIC is every other library source, each with the reason it
# may multiply or divide: its operands are bytes the peer sent in the
# clear.
#   p256.c, rsa.c, rsa_mont.c: public-key verify. Each does three wide
#     multiply-accumulates, measured, over a server or CA public key, a
#     transcript hash and a signature, and the client never signs, so
#     there is no signing entry point to add a secret to.
#   p384.c, p384_field.c, p384_wide_field.c, p384_wide_point.c,
#     p384_wide_verify.c, rsa_pkcs1.c: the same verify-only shape for the
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
#   webpki_cfg.c: the configuration rules under TRUST=webpki. It reads
#     the caller's configuration alone and compares ALPN names.
#   webpki_pin.c: SPKI pins and RFC 7250 raw public keys under
#     TRUST=webpki. It hashes a server's public key and compares the
#     hash with the caller's pins, which are hashes of public keys too.
#   aes_hw.c: the AES forward cipher on the AES instructions, in a host
#     object (-DCH_CPU_RUNTIME). It is the one AES source left on this
#     list: aes.c, quic_aes_soft.c, aes_extern.c and gcm.c take a
#     ceiling above, and this file cannot, because every spec below
#     targets a core that fails the host test, where cpu_cfg.h stops the
#     file's define. INV-26 admits three public keys to it, the Initial
#     packet key and header protection key, both expanded from
#     HKDF-Extract over the printed salt and the Destination Connection
#     ID a long header carries in the clear (RFC 9001 §5.2), and the
#     16-byte Retry key the RFC prints (§5.8), and in a SUITE=aesgcm
#     object the traffic keys, which a session runs on it only under its
#     caller's CH_CPU_CONSTANT_TIME_AES (docs/decisions.md 89).
#     test/aes_equiv_test.c and the Wycheproof AES-GCM suite in the host
#     Wycheproof test check it instead, and neither measures timing
#     (docs/quic.md, "What the AES axis proves").
#   ghash_hw.c: GHASH's multiply on the carry-less multiply
#     instruction, in a host object, in place of gcm.c's portable one for
#     a schedule on the AES instructions. It sits here for aes_hw.c's
#     reason: every spec below targets a core that fails the host test.
#     Its multiply is branchless and reads no table, and the hash subkey
#     it takes is the forward cipher of a zero block under a key aes_hw.c
#     takes. test/ghash_equiv_test.c and the Wycheproof AES-GCM suite in
#     the host Wycheproof test check it instead, and neither measures timing.
#   gcm_hw.c: counter mode over whole blocks and the seal's counter mode
#     and GHASH in one loop, on the AES instructions and the carry-less
#     multiply, in a host object. It sits here for aes_hw.c's reason, and
#     takes the keys aes_hw.c and ghash_hw.c take. Its branches read the
#     round count and the block count alone. test/aes_equiv_test.c,
#     test/ghash_equiv_test.c and the Wycheproof AES-GCM suite in the
#     host Wycheproof test check it instead, and none of them measures timing.
#   gcm_vaes.c: gcm_hw.c's three loops on x86-64's 256-bit VAES and
#     VPCLMULQDQ, in every host object on x86-64. It sits here for
#     gcm_hw.c's reason and takes the keys gcm_hw.c takes: the 32-bit
#     specs compile it to nothing, and the x86-64 spec measures no file
#     in this list. Its branches read the round count and the block count
#     alone. bin/aes_equiv_test, bin/ghash_equiv_test, bin/quic_test_hw
#     and the host Wycheproof test check it on a CPU that has the
#     instructions, and none of them measures timing.
#   srv_parser.c, srv_parser_ext.c, srv_message.c, srv_cookie.c,
#     srv_ticket.c, srv_auth.c, srv_resume.c, srv_kex.c, srv_flight.c,
#     srv_handshake.c, srv.c: the ROLE=server protocol files. They are
#     parsers and builders, and the transcript hash, the verify_data, the
#     cookie MAC, the ticket's PSK, the binder and the key exchange's
#     shared secrets pass through them, so they take a ceiling here.
#     They take no conditional-branch count, for the reason BRANCH_SRCS
#     gives below: they branch on lengths, types and states the peer
#     sent in the clear.
#   quic_initial.c, quic_retry.c: the Initial packet path and the Retry
#     tag check, the only two library sources INV-26 lets call those
#     entries. They see the same three keys and the packet bytes that
#     travel under them, which RFC 9001 §5 says have neither
#     confidentiality nor integrity protection.
#   build.c: the build record, one const struct of sizes and bounds the
#     compiler computes (docs/decisions.md 56). It defines no function,
#     so a gate would count nothing in it, and no byte of it depends on
#     a key or a peer.
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
# under only prints, because the only non-zero entries are one public
# division whose lowering is a compiler choice and a recorded leak that is
# meant to fall, and zero cannot be undershot, so every other module is
# held exactly. The division is tls_write.c's in ch_writable_len, the
# caller's buffer length by the length of a record (docs/decisions.md 72).
WIDEMUL_CEILING := ct.c:0 ct_wipe.c:0 sha256.c:0 sha3.c:0 hkdf.c:0 chacha20.c:0 poly1305.c:0 aead.c:0 \
                   x25519.c:0 p256_field.c:0 mlkem.c:0 mlkem_poly.c:0 buf.c:0 record.c:0 keysched.c:0 io.c:0 \
                   session.c:0 handshake_message.c:0 handshake_parser.c:0 handshake_parser_ee.c:0 handshake_record.c:0 \
                   handshake_auth.c:0 handshake_flight.c:0 handshake.c:0 handshake_post.c:0 \
                   tls.c:0 tls_write.c:1 drbg.c:0 softmul.c:0 tcp_nonblocking.c:0 tcp_nonblocking_frame.c:0 \
                   tcp_nonblocking_step.c:0 \
                   quic_keys.c:0 quic_packet.c:0 quic_config.c:0 quic_step.c:0 quic.c:0 \
                   quic_fail.c:0 srv_quic.c:0 quic_token.c:0 srv_tcp_nonblocking.c:0 \
                   aes.c:0 quic_aes_soft.c:0 aes_extern.c:0 gcm.c:0 \
                   srv_parser.c:0 srv_parser_ext.c:0 srv_message.c:0 srv_cookie.c:0 \
                   srv_ticket.c:0 srv_resume.c:0 srv_kex.c:0 \
                   srv_auth.c:0 srv_out.c:0 srv_flight.c:0 srv_handshake.c:0 srv.c:0 rsa_sign.c:0 \
                   p256_scalar.c:0 p256_point.c:0 p256_sign.c:0 p256_ecdh.c:0 webpki_ticket.c:0 \
                   sha512.c:0 sha512_compress.c:0 handshake_groups.c:0
# The wide X25519 field, x25519_wide.c, is one of three secret-bearing sources
# no spec in WIDEMUL_SPECS can compile: its products are unsigned __int128,
# which no 32-bit target has, and it compiles only in a host object, which
# cpu_cfg.h refuses on every one of them. WIDE64_SPECS below measure it
# instead, on 64-bit targets, and this list is what they compile,
# file:ceiling as above. Its multiply is the 64x64->128 instruction the
# session's multiply bit states, so that spec's tokens are
# the divisions and the 128-bit runtime calls, and the ceiling is zero.
# The others are a host object's vector paths, chacha20_vector.c,
# chacha20_avx2.c, poly1305_vector.c and mlkem_vector.c: they need NEON,
# SSE2 or AVX2, which no 32-bit spec targets, and the arm64 and x86-64
# specs have. chacha20_avx2.c compiles to nothing on arm64 and, under its
# own target attribute, to the AVX2 kernel on x86-64 (docs/decisions.md
# 90). chacha20_vector.c and chacha20_avx2.c multiply nothing.
# mlkem_vector.c multiplies 16-bit lanes alone, which these specs do not
# count, and divides nothing (docs/decisions.md 101). keccak_avx2.c and
# mlkem_avx2.c, the four-way Keccak and ML-KEM's copy over it, compile to
# nothing on arm64, and on x86-64 the first multiplies nothing and the
# second holds mlkem.c's text, whose products these specs count no more
# than mlkem_vector.c's (docs/decisions.md 107).
# poly1305_vector.c compiles to nothing under its own name: a host object
# holds it as poly1305_vector_native.c alone, and the entry here holds
# that, because the file would compile to its four branches if
# poly1305_vector.h turned the path on outside the native copy. So the
# four ceilings are zero too. poly1305_avx2.c, the AVX2 Poly1305, is
# the same under its own name on both specs, and its native copy has a
# body on x86-64 alone (docs/decisions.md 110).
#
# A host object's native copies join this list (docs/decisions.md 87 and
# 89). A host object targets arm64 or x86-64, so no 32-bit spec compiles a
# copy, and the 64-bit specs are the targets the copies run on. What they
# hold for a copy is its branch count, as for the vector paths.
# poly1305_vector_native.c and poly1305_avx2_native.c multiply on the
# 32x32->64 widening multiply, scalar and vector, that the session's
# multiply bit states, which these specs count no more than
# x25519_wide.c's; they divide nothing and call no runtime routine.
#
# A host object's hash sources join it too (docs/decisions.md 93):
# sha256_hw.c, whose SHA-256 instructions no 32-bit spec targets and which
# compiles under its own target attribute on both 64-bit specs,
# sha512_hw.c, which does the same on arm64 and has no body on x86-64, and
# hkdf_hw.c and keysched_hw.c, the copies of hkdf.c and keysched.c over
# them, which hash_hw.h refuses outside a host object. They multiply and
# divide nothing, and what the specs hold for each is its branch count.
#
# The wide P-256 files join it for x25519_wide.c's reason
# (docs/decisions.md 94): their products are unsigned __int128, and they
# compile only in a host object. They divide nothing and call no runtime
# routine, so their ceilings are zero.
# rsa_mont64.c, RSA's Montgomery arithmetic on 64-bit words, joins it for
# x25519_wide.c's reasons (docs/decisions.md 95): its products are
# unsigned __int128 and its body sits behind -DCH_CPU_RUNTIME. Its
# multiply is the same 64x64->128 instruction, so its tokens are the
# divisions and the 128-bit runtime calls too, and its ceiling is zero.
# rsa_sign64.c, the signer on those words, multiplies only through
# rsa_mont64.c and joins on the same terms.
WIDE64_CEILING := x25519_wide.c:0 chacha20_vector.c:0 chacha20_avx2.c:0 poly1305_vector.c:0 \
                  poly1305_avx2.c:0 poly1305_native.c:0 mlkem_poly_native.c:0 \
                  poly1305_vector_native.c:0 poly1305_avx2_native.c:0 \
                  sha256_hw.c:0 sha512_hw.c:0 hkdf_hw.c:0 keysched_hw.c:0 rsa_mont64.c:0 rsa_sign64.c:0 \
                  sha3_hw.c:0 mlkem_hw.c:0 mlkem_poly_hw.c:0 mlkem_vector.c:0 \
                  keccak_avx2.c:0 mlkem_avx2.c:0 \
                  $(addsuffix :0,$(P256_WIDE_SRCS))
# The sources the 32-bit specs compile, which lint-runtime-symbols compiles
# for rv32ic too, and the whole codegen list, which lint-codegen-partition
# holds to a partition of the library sources.
CODEGEN32_SRCS := $(foreach e,$(WIDEMUL_CEILING),$(firstword $(subst :, ,$(e))))
CODEGEN_SRCS := $(CODEGEN32_SRCS) $(foreach e,$(WIDE64_CEILING),$(firstword $(subst :, ,$(e))))
# Per-file defines both gates below add for one file alone, file:defines,
# in the shape WIDEMUL_CEILING_SPEC uses for per-spec ceilings. Each gate
# compiles every CODEGEN_SRCS file under one fixed flag set that names no
# transport and no role, and two groups of entries above hold nothing
# without their own define. The QUIC entries need
# -DCH_TRANSPORT_QUIC_NONBLOCKING: CH_LEVEL_*, the ch_quic struct and the QUIC
# ch_cfg fields all sit behind it, and the four AES entries guard their
# whole body on it. aes_extern.c takes the SUITE=aesgcm AES=extern
# defines instead: its body sits behind -DCH_AES_EXTERN, and the suite
# define adds the AES-256 pair a suite object compiles, so the count
# reads the text that carries a traffic key and not an empty file. The
# server entries need -DCH_ROLE_SERVER
# for the same reason, and preprocess to an empty file without it;
# srv_quic.c and quic_token.c need both defines. webpki_ticket.c needs
# -DCH_TRUST_WEBPKI, because the ch_cfg hostname and anchor fields it
# hashes exist only under that define, and handshake_groups.c needs it
# because its body sits behind CH_KEX_TWO_GROUPS, which that define sets.
# chacha20_vector.c and chacha20_avx2.c need -DCH_CPU_RUNTIME, because
# their whole bodies sit behind that define, and poly1305_vector.c takes
# it to be read as a host object would compile it under its own name.
# Adding any of the three to the shared line would break record.c, io.c,
# session.c, handshake.c and tls.c, which are on the same list and
# compile only without the transport and role defines, and
# quic_aes_soft.c, which preprocesses to an empty file under
# -DCH_AES_EXTERN.
# The native copies of a host object need -DCH_CPU_RUNTIME, because ct.h
# refuses a native copy anywhere else, and x25519_wide.c, rsa_mont64.c and
# rsa_sign64.c need it because their whole bodies sit behind that define.
# sha256_hw.c needs it for that reason too, and hkdf_hw.c and keysched_hw.c
# because hash_hw.h refuses a copy without it; the two copies take
# -DCH_HASH_SHA384 as hkdf.c and keysched.c do, so the count reads both
# hashes' arms.
WIDEMUL_NATIVE_DEFINES := -DCH_CPU_RUNTIME
# webpki_ticket.c and handshake_groups.c carry -UCH_KEX_PQ because the codegen lints compile every
# source with -DCH_KEX_PQ and cfg.h refuses it beside -DCH_TRUST_WEBPKI: that
# client offers both groups in every build (docs/decisions.md 53). The server
# entries need no such flag. -DCH_KEX_PQ chooses a client's group, and a
# server source holds both groups whatever it says (docs/decisions.md 54).
WIDEMUL_DEFINES := quic_keys.c:-DCH_TRANSPORT_QUIC_NONBLOCKING quic_packet.c:-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   quic_config.c:-DCH_TRANSPORT_QUIC_NONBLOCKING quic_step.c:-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   quic.c:-DCH_TRANSPORT_QUIC_NONBLOCKING quic_fail.c:-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   srv_quic.c:-DCH_ROLE_SERVER$(COMMA)-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   quic_token.c:-DCH_ROLE_SERVER$(COMMA)-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   aes.c:-DCH_TRANSPORT_QUIC_NONBLOCKING quic_aes_soft.c:-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   aes_extern.c:$(AES_EXTERN_SUITE_ENTRY) \
                   gcm.c:-DCH_TRANSPORT_QUIC_NONBLOCKING \
                   srv_parser.c:-DCH_ROLE_SERVER srv_parser_ext.c:-DCH_ROLE_SERVER \
                   srv_message.c:-DCH_ROLE_SERVER \
                   srv_cookie.c:-DCH_ROLE_SERVER srv_auth.c:-DCH_ROLE_SERVER \
                   srv_ticket.c:-DCH_ROLE_SERVER \
                   srv_resume.c:-DCH_ROLE_SERVER srv_out.c:-DCH_ROLE_SERVER \
                   srv_kex.c:-DCH_ROLE_SERVER srv_flight.c:-DCH_ROLE_SERVER \
                   srv_handshake.c:-DCH_ROLE_SERVER \
                   srv.c:-DCH_ROLE_SERVER webpki_ticket.c:-DCH_TRUST_WEBPKI$(COMMA)-UCH_KEX_PQ \
                   hkdf.c:-DCH_HASH_SHA384 keysched.c:-DCH_HASH_SHA384 \
                   handshake_groups.c:-DCH_TRUST_WEBPKI$(COMMA)-UCH_KEX_PQ \
                   chacha20_vector.c:-DCH_CPU_RUNTIME chacha20_avx2.c:-DCH_CPU_RUNTIME \
                   poly1305_vector.c:-DCH_CPU_RUNTIME poly1305_avx2.c:-DCH_CPU_RUNTIME \
                   x25519_wide.c:-DCH_CPU_RUNTIME rsa_mont64.c:-DCH_CPU_RUNTIME \
                   $(addsuffix :-DCH_CPU_RUNTIME,$(P256_WIDE_SRCS)) \
                   rsa_sign64.c:-DCH_CPU_RUNTIME \
                   $(foreach f,$(WIDEMUL_COPIED),$(f:.c=_native.c):$(WIDEMUL_NATIVE_DEFINES)) \
                   poly1305_vector_native.c:$(WIDEMUL_NATIVE_DEFINES) \
                   poly1305_avx2_native.c:$(WIDEMUL_NATIVE_DEFINES) \
                   sha256_hw.c:-DCH_CPU_RUNTIME sha512_hw.c:-DCH_CPU_RUNTIME \
                   sha3_hw.c:-DCH_CPU_RUNTIME mlkem_hw.c:-DCH_CPU_RUNTIME mlkem_poly_hw.c:-DCH_CPU_RUNTIME \
                   keccak_avx2.c:-DCH_CPU_RUNTIME mlkem_avx2.c:-DCH_CPU_RUNTIME \
                   mlkem_vector.c:-DCH_CPU_RUNTIME \
                   hkdf_hw.c:-DCH_CPU_RUNTIME$(COMMA)-DCH_HASH_SHA384 \
                   keysched_hw.c:-DCH_CPU_RUNTIME$(COMMA)-DCH_HASH_SHA384
WIDEMUL_PUBLIC := p256.c rsa.c rsa_mont.c pem.c x509.c x509_der.c x509_ca.c \
                  p384.c p384_field.c $(P384_WIDE_SRCS) rsa_pkcs1.c webpki_time.c webpki_name.c webpki_spki.c \
                  webpki_sigalg.c \
                  webpki_ext.c webpki_cert.c webpki.c webpki_pin.c webpki_cfg.c \
                  aes_hw.c ghash_hw.c gcm_hw.c gcm_vaes.c quic_initial.c quic_retry.c build.c

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
	     00) echo "lint-codegen-partition: $$f is in none of WIDEMUL_CEILING, WIDE64_CEILING and WIDEMUL_PUBLIC, so no codegen gate measures it"; rc=1 ;; \
	     11) echo "lint-codegen-partition: $$f is in a ceiling list and in WIDEMUL_PUBLIC; a source is gated or public, never both"; rc=1 ;; \
	   esac; \
	 done; \
	 for e in $(CODEGEN_SRCS) $(WIDEMUL_PUBLIC); do \
	   case "$$srcs" in *" $$e "*) ;; \
	     *) echo "lint-codegen-partition: $$e is in a gate list and is not a library source"; rc=1 ;; \
	   esac; \
	 done; \
	 [ $$rc -eq 0 ] && echo "lint-codegen-partition: every library source is in exactly one of WIDEMUL_CEILING, WIDE64_CEILING and WIDEMUL_PUBLIC"; exit $$rc

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
# keeps the pieces apart.
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
# on a word, so every file in BRANCH_SRCS carries a measured count per
# spec in BRANCH_CEILING, all of them loop control on public counts (a
# block loop, x25519's ladder, poly1305's `n >= 16`, Keccak's round and
# lane counters, softmul's fixed 32 and 64 iterations), and what the gate
# holds is that the count does not grow: a branch a compiler puts on a
# word lands on top of the recorded ones.
#
# rsa_sign.c's count is loop control over word counts, plus three sites
# that are not loop control and are all on public values: MGF1 takes the
# smaller of the remaining mask length and 32; mont_r2's conditional
# subtract runs on the modulus, which is public, and is the only caller
# of cond_sub; and rsa_pss_sign asserts that the drawn salt is not all
# zero (INV-4), which the signature publishes anyway. mont_mul, which
# handles every secret intermediate, emits five loop back-edges and
# nothing else under each of the three clang specs, read at -Os from the
# assembly the gate itself compiles.
# test/violations/inv16-poly1305-final-sign-branch.violation writes
# poly1305_final's select as an if on the last word's sign, and the
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
# it is counted because it is the form clang gives an if on a word (it
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
# The two 64-bit specs, which compile WIDE64_CEILING's files and nothing else,
# under the pinned clang, each file with the defines WIDEMUL_DEFINES gives
# it. Their multiply tokens are the divisions and the 128-bit runtime calls: a
# 64x64->128 multiply is the instruction the wide field is built on, and
# the session's multiply bit is the statement about its timing, so counting it
# would hold nothing. What these specs hold is the branch count, which is the
# field's claim that no instruction branches on a word or a scalar bit: every
# branch x25519_wide.c emits under both is loop control over a public count
# -- the 255 ladder steps, the five words, the 40 bytes ct_wipe clears, the
# eight bytes load_le64 reads, and sqr_times' count -- and cswap and pack's
# conditional subtraction stay masks. x25519.c's clamp and all-zero check,
# which the file compiles inside it, add no branch under either spec.
# arm64 counts b.<cond>, spelled out so
# the dot cannot match bl, and cbz, cbnz, tbz and tbnz. x86-64 counts every
# j<cond>, by prefixes that cannot match jmp. A compiler run that emits
# either family's multiply by a word as a call to __multi3 fails the zero.
# No gcc spec measures the field: no CI lane runs a 64-bit gcc through
# lint-wide-multiply-gcc, and a spec nothing runs would pass unread.
#
# rsa_mont64.c's 43 under both specs were read the same way, function by
# function. Thirty are loop control over a word count, a byte count,
# the doublings rsa_mont64_modulus_init counts from its bits argument, its
# five squarings, the public exponent's sixteen and neg_inverse's six
# steps, and the tests that skip a loop of no iterations. Four are the
# three CH_ASSERTs on the public lengths the entries take:
# rsa_mont64_modulus_load, which rsa_mont.c calls for a public modulus,
# checks its length itself (docs/decisions.md 103). rsa_mont64_mont_square
# has the other nine, each on a word count or a row's index: the test for
# no words, the loop that writes twice the operand, the tests for row 0
# and for row 1, whose part below its square is empty, that part's loop,
# the tests for a row with words past its square and past the word above
# it, their loop, and the loop over rows (docs/decisions.md 106). The
# comparison and the subtraction that end a multiplication stay a carry
# and a mask: reduce_once's three are its two loops and the test for no
# words. The sum, the difference
# and the plain product a CRT signature joins its halves with add nine,
# all loops over words: the difference adds the modulus back under a mask.
#
# rsa_sign64.c's 26 under the arm64 spec and 27 under the x86-64 one were
# read the same way. The x86-64 spec's one more is rsa_sign64_sp1's
# CH_ASSERT on the key's public length, two tests there and one
# conditional compare under the arm64 spec.
# rsa_sign64_power's seven are loop control: the table's
# entries, the exponent's digits, whose count comes from its length in
# bytes, the four squarings, the sixteen entries a read of the table
# visits and their words, and its CH_ASSERT on the word count.
# message_mod_prime's are its loops over the message's words. rsa_sign64_key_ok's four
# are rsa_pss_sign_key_ok's three on the modulus's length and two of its
# bits and the loop that compares the product with the modulus; the
# verdict it returns is a flag and no branch. rsa_sign64_sp1's are its
# CH_ASSERT on the key's public length, the loop of the recombination,
# and one on whether the signature passed its check, which the caller
# sees as the return value. rsa_sign64_pss's seven are rsa_sign.c's,
# which that file compiles from: the key test, the test of cap, the salt
# assertion, mgf1's loop and the private operation's verdict. The digit
# that picks a table entry becomes a mask and no branch. The count does
# not hold that by itself: a read of the table that stops at the entry it
# wants compiles to the same counts, so inv-16-rsa-table-read holds it
# (test/violations/inv16-rsa-sign64-table-read-stops-early.violation).
WIDE64_OPS_ARM64 := udiv,sdiv,__udivti3,__divti3,__umodti3,__modti3,__multi3
WIDE64_OPS_X86 := div,idiv,__udivti3,__divti3,__umodti3,__modti3,__multi3
BRANCH_OPS_ARM64 := b.eq,b.ne,b.cs,b.hs,b.cc,b.lo,b.mi,b.pl,b.vs,b.vc,b.hi,b.ls,b.ge,b.lt,b.gt,b.le,cbz,cbnz,tbz,tbnz
BRANCH_OPS_X86 := ja,jb,jc,je,jg,jl,jn,jo,jp,jr,js,jz
WIDE64_SPECS := \
  arm64:clang:aarch64-none-elf:-march=armv8-a:$(WIDE64_OPS_ARM64):$(BRANCH_OPS_ARM64) \
  x86-64:clang:x86_64-unknown-linux-gnu:-march=x86-64:$(WIDE64_OPS_X86):$(BRANCH_OPS_X86)
WIDE64_SPEC_NAMES := $(foreach s,$(WIDE64_SPECS),$(firstword $(subst :, ,$(s))))
# Per-spec ceilings, spec/file:count, where a spec measures a file above its
# WIDEMUL_CEILING entry. Every number is measured with the spec's compiler
# at its flags, at -Os unless the flags carry another level. The entries
# are poly1305.c and p256_scalar.c under the mips gcc at -O2, two madd
# each.
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
# p256_scalar.c reads two madd under that same spec, and unlike
# poly1305's its operands are readable straight from the assembly. Both
# come from one call, mont_mul's `ct_widemul(t[0], N0_INV)`, and both are
# the ladder's middle products: `madd $3,$13` multiplies `srl
# $3,$19,16`, a word's high half, by `li $13,0xbc4f`, N0_INV's low
# half, and `madd $31,$24` multiplies `andi $31,$19,0xffff` by `li
# $24,0xee00`, N0_INV's high half. gcc holds both halves of the constant,
# so it puts `hl + (ll >> 16)` and `(t & 0xFFFF) + lh` in the
# multiplier's accumulator instead of mul and addu. Every operand is 16
# bits, the file's other 13 products stay on mul, and the
# p256-scalar-widemul-native violation is the edit this entry catches.
#
# rv32ic-gcc counts runtime names, since rv32ic has no multiply or divide
# instruction: the `% 5` is five calls to __modsi3. softmul.c is at zero
# calls to __muldi3 there, which is the point of the spec
# (https://github.com/c4milo/chapulin/issues/107).
#
# tls_write.c reads two divu under the -O2 spec, from ch_writable_len's one
# division of the caller's cap by a record's length. gcc copies the
# function body into both arms of the smaller-of in
# record_plaintext_max: one arm divides by peer_limit + 22 and the
# other by CH_TX_PT + 22, so each path still runs one division, and
# every operand is a public length. Measured with Ubuntu 24.04's
# mips-linux-gnu-gcc 12.4.0 under this spec's flags; CI run 36285635999
# failed on it.
# A host object's native copies (docs/decisions.md 87 and 89) have their
# own branch ceilings, in the table below, which BRANCH_CEILING takes in
# whole. The copy differs from the file under its own names in the
# multiply alone, which is straight-line code, so its branches are the
# file's own loop control, and each was read against the file's on the
# 64-bit specs, whose targets a host object is for. poly1305_native.c's 19
# are the 18 it held before every host object carried the vector path, and
# the byte count n against POLY1305_VECTOR_MIN, which hands an update's
# whole groups to that path; n is public. On x86-64 it holds a 20th, in
# poly1305_update_avx2's copy of the update: n against POLY1305_AVX2_MIN,
# which hands the whole groups to the AVX2 kernel (docs/decisions.md 110).
# poly1305_vector_native.c's 4 are the vector path's, and
# poly1305_avx2_native.c's 4 the AVX2 kernel's, read below. No 32-bit spec compiles a copy: a host object
# targets arm64 or x86-64, so the 96 entries the eight 32-bit specs held
# for WIDEMUL=runtime's copies went with that value.
#
# p256_scalar.c joined BRANCH_SRCS when it had a native copy, because the
# branch count held both copies of every file built on the multiply, and
# it stays beside p256_field.c now that the wide files are the second copy
# of both (docs/decisions.md 94). Its branches were read under each spec:
# loop back edges over the eight words and the 256 rounds of
# p256_scalar_inverse, whose exponent n-2 is a build constant, the same
# shape as p256_field.c's.
WIDEMUL_NATIVE_BRANCH_CEILING := \
  arm64/poly1305_native.c:19 arm64/mlkem_poly_native.c:35 \
  x86-64/poly1305_native.c:20 \
  x86-64/mlkem_poly_native.c:36 \
  arm64/poly1305_vector_native.c:4 x86-64/poly1305_vector_native.c:4 \
  arm64/poly1305_avx2_native.c:0 x86-64/poly1305_avx2_native.c:4
# A host object's hash sources on the CPU's instructions (docs/decisions.md
# 93), under the two 64-bit specs, which are the targets they run on. Each
# branch was read under both. sha256_hw.c's eight are the same on arm64 and
# x86-64: in sha256_update_hw the tests of the byte count, of the bytes a
# context holds, of a block it then fills and of the whole blocks left; in
# compress_blocks the loop over the blocks and the loop over twelve groups
# of four rounds; and in sha256_final_hw the test of where the padding
# ends and the loop that writes the eight digest words. Every one reads a
# length or a count, which is public, and none reads a message byte or a
# state word. hkdf_hw.c's sixteen are hkdf.c's under -DCH_HASH_SHA384: each
# HMAC's test of the key length against a block and its two pad loops, the
# dispatcher's two tests of hash_len, hkdf_expand's three contract checks
# and its output loop, and hkdf_expand_label's three contract checks and
# its test of an empty context. keysched_hw.c is calls in a straight line.
# sha512_hw.c's twelve on arm64 are sha512_update_hw's four tests, the
# ones sha256_hw.c's update makes; in compress_blocks the loop over the
# blocks, the loop over five groups of sixteen rounds and its test for
# the first group, which takes the block's own words; finalize's test of
# where the padding ends; and the two loops that write the digest's words
# and their bytes, once in each final. Every one reads a length or a
# count. On x86-64 the file has no body and no branch.
# sha3_hw.c's 31 on arm64 (docs/decisions.md 99): 25 are sha3.c's sponge
# compiled once more, seven each in block_xor and block_bytes, five in
# absorb with absorb_whole_blocks's count of the blocks, three in squeeze,
# the loop that zeroes the state in each init, and shake_squeeze's test of
# whether the padding ran. Each reads a length, a position in the block or
# the rate. permute_blocks has the other six: the loop over the blocks,
# four tests of how many lanes of the message a block takes, and the loop
# over the 24 rounds. None reads a lane or a message byte.
# mlkem_hw.c's 15 and mlkem_poly_hw.c's 37 are the branches of mlkem.c and
# mlkem_poly.c, the same text under keccak_hw.h's names: by function, the
# counts mlkem_poly_native.c has on this spec, and one more in each of
# mlk_poly_compress and mlk_poly_tomsg, whose multiply is ct.h's
# decomposition here. On x86-64 the three files have no body and no branch.
HASH_HW_BRANCH_CEILING := \
  arm64/sha256_hw.c:8 x86-64/sha256_hw.c:8 arm64/hkdf_hw.c:16 x86-64/hkdf_hw.c:16 \
  arm64/keysched_hw.c:0 x86-64/keysched_hw.c:0 arm64/sha512_hw.c:12 x86-64/sha512_hw.c:0 \
  arm64/sha3_hw.c:31 x86-64/sha3_hw.c:0 arm64/mlkem_hw.c:15 x86-64/mlkem_hw.c:0 \
  arm64/mlkem_poly_hw.c:37 x86-64/mlkem_poly_hw.c:0
# The wide P-256 files, under the two 64-bit specs alone, for the reason
# WIDE64_CEILING gives. Their branches were read before they were
# recorded, and the counts are the same on both specs but for
# p256_wide_inverse.c's. Every one closes a loop over a public count or
# tests a public value, and none reads a word or a bit of a secret.
#   p256_wide_field.c's 6: the four words in each of the two copies to and
#     from p256_field.h's element, and the four words and the eight bytes of
#     each in the two marshalling routines. The add, the subtract, the
#     multiply, the inverse's one product and the three predicates are
#     straight line.
#   p256_wide_scalar.c has none: the Montgomery product and the copies are
#     straight line.
#   p256_wide_inverse.c's 14 on arm64 and 17 on x86-64 (docs/decisions.md
#     115 and 116): the 17 rounds, the 31 steps of each, the shifts of the
#     approximations' ladder, whose count halves from 32 to 1, and loops
#     over the four or five words of a value: in the start of the rounds,
#     in the approximations, and in each combination's products, sums,
#     negations and shifts. p256_wide_inverse_public runs the rounds in a
#     loop of its own and ends it on a test of a's words, which it computes
#     from a public y. x86-64 keeps three of the word loops that arm64
#     unrolls: the start of the rounds in each entry, and one in
#     combine_modular.
#   p256_wide_point.c's 3: the leading byte and the range of a peer's
#     point in p256_wide_point_from_bytes, both public, and whether the
#     caller of p256_wide_point_affine asked for Y.
#   p256_wide_mul.c's 13: the windows each multiplication adds after its
#     first, 42 of the table's and 63 of a point's, the 32 entries a table
#     scan reads, whose words sit in vectors with no loop of their own, the
#     eight multiples a point's scan reads and the four words of each of a
#     multiple's three coordinates, the seven multiples p256_wide_mul
#     computes, the four doublings between windows, twice: once in the loop
#     over windows 62 to 1 and once before window 0, which adds outside it
#     (docs/decisions.md 112), and in window_digit the loop over a digit's
#     bits, the test of a bit's position against 255 and the test for the
#     top window, whose digit is positive, which read a window's number and
#     a loop counter.
#   p256_wide_table.c is constants and p256_wide_wipe.c one call: neither
#     holds a branch.
#   p256_wide_verify.c's 5: the range checks of r and of s, the second
#     test inside the range check, the decoder's verdict on the key and the
#     infinity test of the sum. Every one reads a signature, a key or a
#     hash, which are public (docs/decisions.md 96).
#   p256_wide_verify_point.c's 22, the verifier's points, which are
#     variable time on purpose (docs/decisions.md 104): on arm64, 4 in
#     signed_digits (its loop over the bit positions, the positions a digit
#     passes over, the test of a bit against the carry and the narrower
#     window at the top), 4 in point_add (either operand at infinity, and
#     the two tests for equal points and for negatives), 4 in
#     p256_wide_jacobian_x_is_r (the first comparison, the carry out of r +
#     n, the test of r + n against p and the loop of that sum), and 10 in
#     p256_wide_jacobian_double_mul, which holds the loop over the digits,
#     the tests of each scalar's digit and of its sign, and the doubling
#     and the mixed addition the compiler put inside it with their tests of
#     infinity, of equal points and of negatives. Every one reads a digit
#     of u1 or u2, a coordinate of a point computed from the key, or r, and
#     all of them are public.
P256_WIDE_BRANCH_CEILING := \
  arm64/p256_wide_field.c:6 x86-64/p256_wide_field.c:6 \
  arm64/p256_wide_scalar.c:0 x86-64/p256_wide_scalar.c:0 \
  arm64/p256_wide_inverse.c:14 x86-64/p256_wide_inverse.c:17 \
  arm64/p256_wide_point.c:3 x86-64/p256_wide_point.c:3 \
  arm64/p256_wide_mul.c:13 x86-64/p256_wide_mul.c:13 \
  arm64/p256_wide_table.c:0 x86-64/p256_wide_table.c:0 \
  arm64/p256_wide_wipe.c:0 x86-64/p256_wide_wipe.c:0 \
  arm64/p256_wide_verify.c:5 x86-64/p256_wide_verify.c:5 \
  arm64/p256_wide_verify_point.c:22 x86-64/p256_wide_verify_point.c:22
P256_SCALAR_BRANCH_CEILING := \
  m3/p256_scalar.c:15 mips32r2/p256_scalar.c:14 rv32imac/p256_scalar.c:14 m3-gcc/p256_scalar.c:12 \
  mips32r2-gcc/p256_scalar.c:12 mips32r2-gcc-O2/p256_scalar.c:14 rv32imac-gcc/p256_scalar.c:18 rv32ic-gcc/p256_scalar.c:18
WIDEMUL_CEILING_SPEC := mips32r2-gcc-O2/poly1305.c:2 mips32r2-gcc-O2/p256_scalar.c:2 \
                        mips32r2-gcc-O2/tls_write.c:2
# The files the branch count covers: the arithmetic under the record
# layer, whose every input is a key, a word or a block. Almost every
# branch they hold is loop control on a public count; the two exceptions
# are aead_open's and gcm_open's `if (!ok)` on the tag comparison, where
# ct_memeq has already run in constant time and whether the packet
# authenticates is what the caller is told anyway. The other CODEGEN_SRCS
# files -- buf.c, record.c, keysched.c, io.c, session.c, the handshake
# files and tls.c -- branch on lengths, types and states the peer sent in
# the clear, several dozen each, so a count there would record the parser
# and move with every feature. The multiply count still covers them; a
# secret reaching their control paths is a design change, not a codegen
# choice, and review holds that line.
#
# aes.c, quic_aes_soft.c, aes_extern.c and gcm.c joined the
# list on the commit that wrote the -DCH_SUITE_AES_GCM rules into ct.h,
# for the build whose AES key is a traffic secret. INV-26 said what that
# build would owe -- these files sat in WIDEMUL_PUBLIC, so no codegen
# gate compiled them and no count held their masked selects to a
# branchless lowering. gcm.c's multiply_by_subkey is the select that
# matters: under a secret key the accumulator bit and the shifted-out bit
# are both derived from the hash subkey, and the two 0xff masks are what
# keep them off a branch, exactly as poly1305_final's are. aes_hw.c
# is not here and cannot be: it is an #error under every spec below,
# because no spec's target has the AES instructions.
# test/aes_equiv_test.c and the Wycheproof AES-GCM suite on the host
# object check it instead (docs/quic.md, "What the AES axis proves").
#
# aes.c's counts did not move when QUIC version 2's salt, Retry key and
# labels joined version 1's (docs/decisions.md 79). Each is read from a
# two-entry table at quic_version_index, the 0 or 1 a comparison of the
# version yields, and every compiler in the table writes that comparison
# without a branch. A comparison per constant cost m3 five more and
# rv32imac three more under the pinned clang. All eight specs were read
# after the change.
#
# sha512.c and sha512_compress.c joined when TLS_AES_256_GCM_SHA384 put
# SHA-384 under the key schedule: hmac_sha384 hashes HMAC keys and the
# transcript through them, so they left WIDEMUL_PUBLIC for WIDEMUL_CEILING
# at 0 and this list. Their branches were read under every spec: the
# compression function's four are the back edges of its sixteen-word load,
# its eighty rounds and its message schedule, and the streaming half's are
# loops over the caller's length and the pad, which are public. hkdf.c is
# measured under -DCH_HASH_SHA384 (WIDEMUL_DEFINES), the build a suite
# object compiles, and its count rose by six to twelve with it. The new
# branches were read too: hmac_sha384's key-length test and its two pad
# loops, the dispatcher's test of hash_len, and hkdf_expand's CH_ASSERT on
# hash_len. hash_len is the suite's, which the ServerHello names in the
# clear, and none of them reads a key byte.
BRANCH_SRCS := ct.c ct_wipe.c sha256.c sha3.c hkdf.c chacha20.c poly1305.c aead.c x25519.c mlkem.c \
               mlkem_poly.c drbg.c softmul.c rsa_sign.c aes.c quic_aes_soft.c \
               aes_extern.c gcm.c p256_field.c x25519_wide.c chacha20_vector.c chacha20_avx2.c poly1305_vector.c \
               sha512.c \
               sha512_compress.c p256_scalar.c poly1305_native.c mlkem_poly_native.c \
               poly1305_vector_native.c poly1305_avx2.c poly1305_avx2_native.c \
               sha256_hw.c sha512_hw.c hkdf_hw.c keysched_hw.c rsa_mont64.c rsa_sign64.c $(P256_WIDE_SRCS) \
               sha3_hw.c mlkem_hw.c mlkem_poly_hw.c mlkem_vector.c keccak_avx2.c mlkem_avx2.c
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
#
# p256_field.c's entries were read before they were recorded, which is
# what the gate's message asks for. Every branch it emits is a loop back
# edge over a literal count -- eight words, thirty-two bytes, 256 rounds
# -- except one: p256_fe_inv tests a bit of p-2, a build constant, so the
# test is the same on every call and no operand reaches it. The two arm
# numbers also count IT and ITE, which BRANCH_OPS_ARM lists: both
# compilers write the masked select in reduce_once and the mask in
# p256_fe_zero_mask as predicated moves, which is the gate's good case
# rather than its bad one -- a predicated move is the select staying off
# the control path.
#
# sha3.c's entry under the mips gcc at -O2 rose from 31 to 36, and its
# other seven fell, when block_xor and block_bytes took the byte loops
# out of absorb and squeeze and the round lost its loops
# (docs/decisions.md 98). Each of the two has three loops, and at -O2
# this gcc tests a loop's condition before its first pass as well as
# after each one. The branches were read. More than half are in
# block_xor and block_bytes, each a compare of the byte count with the
# length or of a byte's place in its lane with zero. The rest are in
# absorb, squeeze and the entries that inline them, on the block's fill,
# the bytes left, the rate, the squeezing flag and the round counter.
# keccak_round holds none: it is straight-line. No branch reads a lane
# or a message byte. The entry fell to 33 when absorb's loop over whole
# blocks moved into absorb_whole_blocks (docs/decisions.md 99).
#
# mlkem_poly.c's entry, and its native and _hw copies', rose by two on
# every spec when mlk_sample_ntt took the stream eight three-byte groups a
# squeeze: the loop over a chunk's groups adds its own test and a second
# test of the coefficients written against 256. The mips gcc at -O2 adds
# a third, the test before the loop's first pass. Each reads a counter,
# and the stream the loop parses is the public matrix's.
#
# sha3.c's entries under the Arm GNU gcc and the two riscv32 gcc entries
# rose by one, from 21 to 22 and from 22 to 23, when absorb's loop over
# whole blocks moved into absorb_whole_blocks, which sha3_hw.c replaces
# (docs/decisions.md 99). At -Os both gccs then inline absorb into its two
# callers, where they kept one copy out of line before: shake_absorb holds
# absorb's four branches, on the block's fill, the bytes it takes, a full
# block and the bytes left against the rate, and keccak holds the last of
# them again, because its block starts empty. The branches were read.
# None reads a lane or a message byte.
#
# x25519.c's two riscv32 gcc entries rose from 23 to 24 when the clamp
# moved into clamp_and_ladder(), which the wide field shares. Both branches
# that function adds were read: a bne that closes the 32-byte copy loop,
# and a beq that tests the stack-protector canary this toolchain adds to a
# function holding an array. ladder() lost the copy loop's branch, so the
# net is the canary. Neither reads the scalar.
#
# drbg.c's two riscv32 gcc entries rose from 9 to 10 when ch_drbg_seed began
# to hash the seed (docs/decisions.md 66). Both branches the function now
# holds were read: a bgtu that tests seed_len against CH_DRBG_SEED_MIN for
# CH_ASSERT, a length the caller chose, and a beq that tests the
# stack-protector canary this toolchain adds to a function holding an
# array, here the SHA-256 context. The 32-byte copy loop and its bne are
# gone. Neither reads a seed byte.
#
# gcm.c's two riscv32 gcc entries rose from 22 to 23 when the one-pass
# open split compute_tag and ghash_schedule into hash_start, hash_finish
# and mask_tag (docs/decisions.md 85). Their branches moved into
# hash_finish and mask_tag. The one new branch was read: a beq that
# tests the stack-protector canary this toolchain adds to a function
# holding an array, here gcm_ghash, which now keeps the gcm_hash state
# on its own frame. It reads no key, subkey or data byte.
#
# chacha20_avx2.c's x86-64 entry was read the same way, and it has no body
# on arm64. Its 23 close the ten double rounds or test the byte count n:
# six in chacha20_avx2_xor, n against the bytes of a pass, the pass loop's
# back edge, n against zero, whether n ends inside a row of 32 bytes,
# those last 1 to 31 bytes against zero and their loop, and in pass the
# round loop and one test for each of the 16 rows, the row count against
# the limit's whole rows. No branch reads a lane value.
#
# chacha20_vector.c's two entries were read before they were recorded.
# Every branch on both targets closes a loop over a public count or tests
# the byte count n: n against the bytes of a pass, the ten double rounds,
# n against zero, whether n ends inside a row, the loop over those last 1
# to 15 bytes, and for each row of 16 bytes whether the limit of the pass
# covers it. They rose from 12 to 40 on arm64 and to 23 on x86-64 when a
# pass began to XOR its rows from registers and test each row against the
# limit, and an arm64 pass to hold two groups (docs/decisions.md 86): 31
# and 16 of them are those row tests, and one on arm64 tests whether the
# limit covers the second group. No branch reads a lane value.
#
# The vector Poly1305's two entries were read the same way, in
# poly1305_vector_native.c, the one name a host object compiles the path
# under. All four branches on each target test the byte count n: the
# CH_ASSERT at the entry, n against zero and n modulo 64, and the group
# loop's entry and back edge, n against 64. The powers of r and both
# carries are straight line. poly1305_vector.c under its own name holds
# none, because it compiles to nothing there. The AVX2 Poly1305's x86-64
# entry was read the same way, in poly1305_avx2_native.c, and it has no
# body on arm64 or under its own name: its four test n at the entry's
# CH_ASSERT, n against zero and n modulo 128, and the group loop's entry
# and back edge, n against 128 (docs/decisions.md 110).
#
# The vector NTT's two entries were read the same way (docs/decisions.md
# 101). Each transform holds four loops, and each of eight of the nine
# branches on each target closes one: the 8 steps over the layers of span
# 128 and 64, the 4 blocks and their 2 steps over the layers of span 32
# and 16, and the 16 blocks of the last three layers, in each direction.
# The ninth closes the base multiplication's loop over its 16 blocks.
# Every count is a constant, and no branch reads a lane value.
#
# The four-way Keccak and ML-KEM's copy over it were read the same way
# (docs/decisions.md 107), on x86-64, the one target where they have a
# body. Each of keccak_avx2.c's 7 closes a loop whose count is a constant:
# the permutation's loops over the 25 lanes in, the 24 rounds and the 25
# lanes out, the start's loops that zero the four states and write each
# one's seed, and the loop over the 21 lanes a block's bytes come from.
# mlkem_avx2.c's 28 are mlkem.c's text under the copy's names, 13 of them,
# and the row sampler's 15, which mlk_matvec_row holds inlined. Those test
# the loop over the three streams' blocks, each entry's count of
# coefficients, the clamp on the last block's groups, and in
# mlk_sample_groups's loop each candidate against q. The candidates come
# from the public seed, and no branch reads a secret.
BRANCH_CEILING := \
  m3/ct.c:2 m3/ct_wipe.c:1 m3/sha256.c:17 m3/sha3.c:38 m3/hkdf.c:19 m3/chacha20.c:9 m3/poly1305.c:19 \
  m3/aead.c:4 m3/x25519.c:34 m3/p256_field.c:24 m3/mlkem.c:14 m3/mlkem_poly.c:45 m3/drbg.c:9 \
  m3/softmul.c:0 m3/aes.c:3 m3/quic_aes_soft.c:12 m3/aes_extern.c:0 \
  m3/gcm.c:22 m3/rsa_sign.c:29 mips32r2/ct.c:2 mips32r2/ct_wipe.c:1 mips32r2/sha256.c:16 mips32r2/sha3.c:25 \
  mips32r2/hkdf.c:16 mips32r2/chacha20.c:7 mips32r2/poly1305.c:18 mips32r2/aead.c:2 \
  mips32r2/x25519.c:31 mips32r2/p256_field.c:21 mips32r2/mlkem.c:13 mips32r2/mlkem_poly.c:38 \
  mips32r2/drbg.c:8 mips32r2/softmul.c:0 mips32r2/aes.c:2 mips32r2/quic_aes_soft.c:12 \
  mips32r2/aes_extern.c:0 mips32r2/gcm.c:16 mips32r2/rsa_sign.c:27 rv32imac/ct.c:2 rv32imac/ct_wipe.c:1 \
  rv32imac/sha256.c:17 rv32imac/sha3.c:32 rv32imac/hkdf.c:18 rv32imac/chacha20.c:8 \
  rv32imac/poly1305.c:18 rv32imac/aead.c:2 rv32imac/x25519.c:31 rv32imac/p256_field.c:21 \
  rv32imac/mlkem.c:14 rv32imac/mlkem_poly.c:38 rv32imac/drbg.c:9 rv32imac/softmul.c:0 \
  rv32imac/aes.c:3 rv32imac/quic_aes_soft.c:12 rv32imac/aes_extern.c:0 \
  rv32imac/gcm.c:20 rv32imac/rsa_sign.c:27 m3-gcc/ct.c:1 m3-gcc/ct_wipe.c:1 m3-gcc/sha256.c:12 \
  m3-gcc/sha3.c:22 m3-gcc/hkdf.c:19 m3-gcc/chacha20.c:7 m3-gcc/poly1305.c:14 m3-gcc/aead.c:2 \
  m3-gcc/x25519.c:23 m3-gcc/p256_field.c:14 m3-gcc/mlkem.c:14 m3-gcc/mlkem_poly.c:39 \
  m3-gcc/drbg.c:8 m3-gcc/softmul.c:0 m3-gcc/aes.c:3 m3-gcc/quic_aes_soft.c:9 \
  m3-gcc/aes_extern.c:0 m3-gcc/gcm.c:15 m3-gcc/rsa_sign.c:26 mips32r2-gcc/ct.c:1 mips32r2-gcc/ct_wipe.c:1 \
  mips32r2-gcc/sha256.c:12 mips32r2-gcc/sha3.c:18 mips32r2-gcc/hkdf.c:18 \
  mips32r2-gcc/chacha20.c:6 mips32r2-gcc/poly1305.c:14 mips32r2-gcc/aead.c:2 \
  mips32r2-gcc/x25519.c:20 mips32r2-gcc/p256_field.c:13 mips32r2-gcc/mlkem.c:14 \
  mips32r2-gcc/mlkem_poly.c:43 mips32r2-gcc/drbg.c:7 mips32r2-gcc/softmul.c:0 \
  mips32r2-gcc/aes.c:3 mips32r2-gcc/quic_aes_soft.c:9 mips32r2-gcc/aes_extern.c:0 \
  mips32r2-gcc/gcm.c:13 mips32r2-gcc/rsa_sign.c:23 \
  mips32r2-gcc-O2/ct.c:2 mips32r2-gcc-O2/ct_wipe.c:1 mips32r2-gcc-O2/sha256.c:23 mips32r2-gcc-O2/sha3.c:33 \
  mips32r2-gcc-O2/hkdf.c:23 mips32r2-gcc-O2/chacha20.c:7 mips32r2-gcc-O2/poly1305.c:21 \
  mips32r2-gcc-O2/aead.c:2 mips32r2-gcc-O2/x25519.c:28 mips32r2-gcc-O2/p256_field.c:24 \
  mips32r2-gcc-O2/mlkem.c:18 \
  mips32r2-gcc-O2/mlkem_poly.c:41 mips32r2-gcc-O2/drbg.c:8 mips32r2-gcc-O2/softmul.c:0 \
  rv32imac-gcc/ct.c:1 rv32imac-gcc/ct_wipe.c:1 rv32imac-gcc/sha256.c:15 rv32imac-gcc/sha3.c:23 rv32imac-gcc/hkdf.c:23 \
  rv32imac-gcc/chacha20.c:10 rv32imac-gcc/poly1305.c:15 rv32imac-gcc/aead.c:4 \
  rv32imac-gcc/x25519.c:24 rv32imac-gcc/p256_field.c:20 rv32imac-gcc/mlkem.c:20 \
  rv32imac-gcc/mlkem_poly.c:41 rv32imac-gcc/drbg.c:10 rv32imac-gcc/softmul.c:0 \
  rv32imac-gcc/aes.c:4 rv32imac-gcc/quic_aes_soft.c:12 rv32imac-gcc/aes_extern.c:0 \
  rv32imac-gcc/gcm.c:23 rv32imac-gcc/rsa_sign.c:27 rv32ic-gcc/ct.c:1 rv32ic-gcc/ct_wipe.c:1 \
  rv32ic-gcc/sha256.c:15 rv32ic-gcc/sha3.c:23 rv32ic-gcc/hkdf.c:23 rv32ic-gcc/chacha20.c:10 \
  rv32ic-gcc/poly1305.c:15 rv32ic-gcc/aead.c:4 rv32ic-gcc/x25519.c:24 \
  rv32ic-gcc/p256_field.c:20 rv32ic-gcc/mlkem.c:20 rv32ic-gcc/mlkem_poly.c:41 \
  rv32ic-gcc/drbg.c:10 rv32ic-gcc/softmul.c:2 rv32ic-gcc/aes.c:4 \
  rv32ic-gcc/quic_aes_soft.c:12 rv32ic-gcc/aes_extern.c:0 rv32ic-gcc/gcm.c:23 \
  rv32ic-gcc/rsa_sign.c:27 mips32r2-gcc-O2/aes.c:3 mips32r2-gcc-O2/quic_aes_soft.c:12 \
  mips32r2-gcc-O2/aes_extern.c:0 mips32r2-gcc-O2/gcm.c:16 \
  mips32r2-gcc-O2/rsa_sign.c:26 \
  m3/sha512.c:24 m3/sha512_compress.c:4 mips32r2/sha512.c:20 mips32r2/sha512_compress.c:4 \
  rv32imac/sha512.c:23 rv32imac/sha512_compress.c:4 m3-gcc/sha512.c:12 \
  m3-gcc/sha512_compress.c:4 mips32r2-gcc/sha512.c:12 mips32r2-gcc/sha512_compress.c:4 \
  mips32r2-gcc-O2/sha512.c:27 mips32r2-gcc-O2/sha512_compress.c:4 rv32imac-gcc/sha512.c:14 \
  rv32imac-gcc/sha512_compress.c:5 rv32ic-gcc/sha512.c:14 rv32ic-gcc/sha512_compress.c:5 \
  arm64/x25519_wide.c:16 x86-64/x25519_wide.c:20 arm64/chacha20_vector.c:40 x86-64/chacha20_vector.c:23 \
  arm64/chacha20_avx2.c:0 x86-64/chacha20_avx2.c:23 \
  arm64/poly1305_vector.c:0 x86-64/poly1305_vector.c:0 \
  arm64/poly1305_avx2.c:0 x86-64/poly1305_avx2.c:0 \
  arm64/rsa_mont64.c:43 x86-64/rsa_mont64.c:43 \
  arm64/rsa_sign64.c:26 x86-64/rsa_sign64.c:27 \
  arm64/mlkem_vector.c:9 x86-64/mlkem_vector.c:9 \
  arm64/keccak_avx2.c:0 x86-64/keccak_avx2.c:7 arm64/mlkem_avx2.c:0 x86-64/mlkem_avx2.c:28 \
  $(WIDEMUL_NATIVE_BRANCH_CEILING) $(P256_SCALAR_BRANCH_CEILING) $(HASH_HW_BRANCH_CEILING) \
  $(P256_WIDE_BRANCH_CEILING)
WIDEMUL_RUN ?= clang
WIDEMUL_GCC ?= $(M3_CC)
.PHONY: lint-wide-multiply lint-wide-multiply-gcc lint-wide-multiply-run
# The clang specs, one sub-make each, all at once. Each compiles every
# WIDEMUL_CEILING file for its own target and prints its own verdict, so
# running them together changes the wall time and nothing else. A spec is
# skipped when every .c and .h file, the freestanding headers, the
# Makefile, clang's version and the make variables are what they were
# when it last passed (tools/stamp.py).
WIDEMUL_CLANG = $(foreach s,$(WIDEMUL_SPECS) $(WIDE64_SPECS),$(if $(filter clang,$(word 2,$(subst :, ,$(s)))),$(firstword $(subst :, ,$(s)))))
lint-wide-multiply:
ifeq ($(CLANG_RV),)
	$(call REQUIRE,clang,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	$(call REQUIRE_PINNED,lint-wide-multiply,$(CLANG_RV),version $(LLVM_MAJOR)\.,LLVM $(LLVM_MAJOR))
	@$(MAKE) --no-print-directory -j$(words $(WIDEMUL_CLANG)) \
	  $(addprefix lint-wide-multiply-spec-,$(WIDEMUL_CLANG))
endif
lint-wide-multiply-spec-%:
	@python3 tools/stamp.py lint-wide-multiply-$* --content '*.[ch]' --content tools/freestanding \
	  $(STAMP_MAKEFILES) --output '$(CLANG_RV) --version' \
	  -- $(MAKE) --no-print-directory lint-wide-multiply-run WIDEMUL_RUN=clang WIDEMUL_ONLY=$*
# WIDEMUL_ONLY, when set, names the one spec to run.
#
# Each compile's assembly is kept in bin/stamps/asm/, in a file named by a
# SHA-256 over the compiler's --version, the compile line, and the source
# preprocessed under that line, which is every byte the compile reads. A
# compile whose key names a kept file reads the assembly from it instead
# of compiling again. The counts and the verdicts are computed from the
# assembly on every run, so a ceiling edited here applies at once.
# CHECK_NO_STAMPS=1 compiles every file and keeps nothing.
lint-wide-multiply-run:
	@rc=0; ran=""; got=""; \
	 for spec in $(WIDEMUL_SPECS) $(WIDE64_SPECS); do \
	   arch=$${spec%%:*}; rest=$${spec#*:}; \
	   compiler=$${rest%%:*}; rest=$${rest#*:}; \
	   machine=$${rest%%:*}; rest=$${rest#*:}; \
	   flags=$$(echo "$${rest%%:*}" | tr ',' ' '); rest=$${rest#*:}; \
	   tokens=$${rest%%:*}; branches=""; \
	   case "$$rest" in *:*) branches=$${rest#*:} ;; esac; \
	   [ "$$compiler" = "$(WIDEMUL_RUN)" ] || continue; \
	   [ -z "$(WIDEMUL_ONLY)" ] || [ "$$arch" = "$(WIDEMUL_ONLY)" ] || continue; \
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
	   ccid=$$($$cc --version 2>&1); \
	   ops=$$(echo "$$tokens" | tr ',' '\n' | grep -v '^__' | paste -sd '|' -); \
	   calls=$$(echo "$$tokens" | tr ',' '\n' | grep '^__' | paste -sd '|' -); \
	   pattern=""; \
	   [ -z "$$ops" ] || pattern="^[[:space:]]+($$ops)"; \
	   [ -z "$$calls" ] || pattern="$$pattern$${pattern:+|}[[:space:],(]($$calls)"; \
	   [ -n "$$pattern" ] || { echo "lint-wide-multiply: spec $$arch lists no token to count"; exit 1; }; \
	   [ -n "$$branches" ] || { echo "lint-wide-multiply: spec $$arch lists no conditional branch to count; the sixth field is the branch mnemonics of its ISA (BRANCH_OPS_ARM, BRANCH_OPS_MIPS or BRANCH_OPS_RV)"; exit 1; }; \
	   bpattern="^[[:space:]]+($$(echo "$$branches" | tr ',' '\n' | paste -sd '|' -))"; \
	   ran="$$ran$$arch "; table=""; btable=""; \
	   files="$(WIDEMUL_CEILING)"; \
	   case " $(WIDE64_SPEC_NAMES) " in *" $$arch "*) files="$(WIDE64_CEILING)" ;; esac; \
	   for e in $$files; do \
	     f=$${e%%:*}; cap=$${e##*:}; \
	     for o in $(WIDEMUL_CEILING_SPEC); do [ "$${o%%:*}" = "$$arch/$$f" ] && cap=$${o##*:}; done; \
	     extra=""; \
	     for o in $(WIDEMUL_DEFINES); do [ "$${o%%:*}" = "$$f" ] && extra=$$(echo "$${o#*:}" | tr ',' ' '); done; \
	     args="-Os $$flags -std=c11 -ffreestanding -D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ $$extra -I."; \
	     key=$$( { printf '%s\n' "$$ccid" "$$cc $$args $$f"; $$cc $$args -E $$f 2>&1; echo "status $$?"; } \
	       | $(SHA256) | cut -d' ' -f1); \
	     memo=bin/stamps/asm/$$key.s; \
	     err=$$(mktemp); \
	     if [ "$${CHECK_NO_STAMPS:-0}" = 0 ] && [ -f "$$memo" ]; then asm=$$(cat "$$memo"); \
	     else \
	       asm=$$($$cc $$args -S $$f -o - 2>"$$err") || { \
	         echo "lint-wide-multiply: $$f does not build for $$arch — a count of zero from a failed compile is not a measurement"; \
	         sed -n '1p' "$$err" | sed 's/^/lint-wide-multiply:   /'; \
	         rm -f "$$err"; rc=1; continue; }; \
	       [ "$${CHECK_NO_STAMPS:-0}" != 0 ] || { mkdir -p bin/stamps/asm; \
	         printf '%s\n' "$$asm" > "$$memo.$$$$" && mv "$$memo.$$$$" "$$memo"; }; \
	     fi; \
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
	@$(MAKE) --no-print-directory lint-wide-multiply-run WIDEMUL_RUN=gcc WIDEMUL_GCC="$(WIDEMUL_GCC)"

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
# This gate builds every CODEGEN32_SRCS file for rv32ic and holds two things:
# which runtime routines each file pulls, and that softmul.c still defines
# the ones the list admits. x25519_wide.c is the one CODEGEN_SRCS file it
# leaves out, because rv32ic has no unsigned __int128 to build it with.
#
# RV_ALLOWED is file:symbols, measured under the pinned clang; a file not
# named pulls nothing. It used to be one list for all files, with softmul's
# definitions subtracted from the union of everything undefined -- so a new
# `*` in aead.c resolved to softmul's __mulsi3 and nothing said so, and a
# new `/` anywhere hid behind sha3's __udivsi3
# (https://github.com/c4milo/chapulin/issues/85). Now a symbol is judged in
# the file that pulls it. tls_write.c's __udivsi3 is ch_writable_len's
# one division, the caller's buffer length by the length of a record,
# both public (docs/decisions.md 72); its __mulsi3 is the
# same call's count of whole records times their plaintext, which
# softmul.c supplies in constant time like every other.
#
# The eight QUIC and AES entries WIDEMUL_CEILING carries -- quic.c,
# quic_keys.c, quic_packet.c, quic_step.c, aes.c, quic_aes_soft.c,
# aes_extern.c and gcm.c -- get no row: measured under the
# pinned clang for rv32ic with their WIDEMUL_DEFINES entry, each pulls
# nothing. A row for a file that pulls nothing is not free,
# because the loop below prints "no longer pulls" for it on every run.
# The decision is recorded here rather than left to a reader of the
# list's absence, and it is re-measured when the stubs among these
# files are implemented.
#
# A host object's native copies are not here: CODEGEN32_SRCS holds none,
# because no rv32ic object holds one (docs/decisions.md 89).
RV_ALLOWED := poly1305.c:__mulsi3 x25519.c:__mulsi3 mlkem_poly.c:__mulsi3 \
              rsa_sign.c:__mulsi3 p256_field.c:__mulsi3 p256_scalar.c:__mulsi3 \
              tls_write.c:__mulsi3,__udivsi3
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
	$(call REQUIRE_PINNED,lint-runtime-symbols,$(CLANG_RV),version $(LLVM_MAJOR)\.,LLVM $(LLVM_MAJOR))
	$(call REQUIRE_PINNED,lint-runtime-symbols,$(LLVM_NM),version $(LLVM_MAJOR)\.,LLVM $(LLVM_MAJOR))
	@python3 tools/stamp.py lint-runtime-symbols --content '*.[ch]' --content tools/freestanding \
	  $(STAMP_MAKEFILES) --output '$(CLANG_RV) --version' --output '$(LLVM_NM) --version' \
	  -- $(MAKE) --no-print-directory lint-runtime-symbols-run
endif
# The run is skipped when every .c and .h file, the freestanding headers,
# the Makefile, clang's and llvm-nm's versions and the make variables are
# what they were when it last passed (tools/stamp.py).
.PHONY: lint-runtime-symbols-run
lint-runtime-symbols-run:
	@d=$$(mktemp -d); rc=0; seen=0; \
	 for f in $(CODEGEN32_SRCS); do \
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

.PHONY: lint-bench-numbers
lint-bench-numbers:
	@python3 tools/bench-numbers.py

# The constants of the wide P-256 files and the table of multiples of G
# (docs/decisions.md 94). tools/p256_wide.py recomputes each constant from
# SEC 2's definition of the curve and compares it with the words the
# source carries, so a wrong word fails here and names its file. The same
# script writes p256_wide_table.c, and the second line fails when the
# checked-in file is not what the script prints: a hand edit of the table,
# or an edit of the script without its output. The recipe names the files
# the script reads, which is how make impact selects it for them.
# tools/p256-wide-carry.py then reads which form of p256_wide_word.h's two
# carry steps each compiler reads: the builtins as clang reads the header,
# and as gcc reads it the intrinsics for x86-64 and the 128-bit sums for
# arm64. gcc expands a builtin to a jump on a word's carry, and no lane runs
# a 64-bit gcc through lint-wide-multiply, so this is the check that fails
# when gcc reads one. The script runs clang's preprocessor and no more of
# it, and the text it reads is the header's own, so it asks for no pinned
# version.
lint-p256-wide:
	@python3 tools/p256_wide.py check p256_wide_field.h p256_wide_field.c p256_wide_scalar.c \
	  p256_wide_point.c p256_wide_inverse.c spec/lean/Spec/P256WideInverse.lean
	@python3 tools/p256_wide.py table | cmp -s - p256_wide_table.c \
	  || { echo "lint-p256-wide: p256_wide_table.c is not what tools/p256_wide.py table prints;" \
	       "regenerate it with: python3 tools/p256_wide.py table > p256_wide_table.c"; exit 1; }
	@echo "lint-p256-wide: p256_wide_table.c is what tools/p256_wide.py table prints"
ifeq ($(CLANG_RV),)
	$(call REQUIRE,clang,it ships with llvm — see the LLVM_MAJOR pin in tools/toolchain.env)
else
	@python3 tools/p256-wide-carry.py "$(CLANG_RV)" p256_wide_word.h
endif

# bench/stack.py, which computes the peaks docs/performance.md states,
# reads the call graph from the relocations objdump prints under each call
# and jump. test/stack_walk.py compiles a fixture for arm64 and x86-64
# Mach-O with the pinned clang and reads it with the pinned llvm-nm and
# llvm-objdump, which read Mach-O on any host. The walk must follow a jump
# at a function's first instruction, which it once dropped, count the
# return address an x86-64 call pushes, keep apart two static functions
# of one name in two objects, which it once merged, and name the calls it
# counts no frame for. The check also requires the script to compile the
# sources and the defines print-lib-lists prints for the build it walks,
# and no other root source.
.PHONY: lint-stack-walk
lint-stack-walk:
	@CLANG=$(CLANG_RV) STACK_NM=$(LLVM_NM) STACK_OBJDUMP=$(subst llvm-nm,llvm-objdump,$(LLVM_NM)) \
	  python3 test/stack_walk.py bench/stack.py

# shellcheck -x follows each script's source lines, so the run is skipped
# only when every file git does not ignore and shellcheck's version are
# what they were when it last passed (tools/stamp.py).
.PHONY: lint-shellcheck
lint-shellcheck:
ifeq ($(shell command -v $(SHELLCHECK) 2>/dev/null),)
	$(call REQUIRE,shellcheck,brew install shellcheck — see the SHELLCHECK_VERSION pin in tools/toolchain.env)
else
	@[ -n "$(SH_SRCS)" ] || { \
	  echo "lint-shellcheck: no scripts to check; git ls-files found none, so this is an export without .git rather than a clean tree"; \
	  exit 1; }
	@python3 tools/stamp.py lint-shellcheck --content . --output '$(SHELLCHECK) --version' \
	  -- $(SHELLCHECK) -x -f gcc $(SH_SRCS) \
	  && echo "lint-shellcheck: every shell script clean"
endif

# Every RFC this tree cites by line number, carried in docs/rfcs/ so a
# reader can check a citation without leaving the repository. Line numbers
# are only meaningful against exact bytes, so SHA256SUMS records them and
# this target refuses a file that drifted from the hash.
#
# The second half is what makes vendoring worth its megabyte: a citation
# to an RFC the tree does not carry fails here, so a new citation brings
# its document with it instead of pointing at a file only its author had.
# It reads the files git lists, tracked or untracked but not ignored, so
# the RFC citations in tools/node_modules' own documentation are not the
# tree's.
.PHONY: lint-rfcs
lint-rfcs:
	@cd docs/rfcs && $(SHA256) -c SHA256SUMS >/dev/null \
	  || { echo "lint-rfcs: a vendored RFC does not match SHA256SUMS; line citations are measured against those bytes"; exit 1; }
	@rc=0; \
	cited=$$(git ls-files -z --cached --others --exclude-standard -- '*.c' '*.h' '*.md' '*.sh' \
	  | xargs -0 grep -hoE 'rfc[0-9]{3,5}\.txt' | sort -u); \
	[ -n "$$cited" ] || { echo "lint-rfcs: no citation found at all, so this target would check nothing"; exit 1; }; \
	for f in $$cited; do \
	  [ -f "docs/rfcs/$$f" ] || { echo "lint-rfcs: the tree cites $$f by line number and docs/rfcs/ does not carry it"; rc=1; }; \
	done; \
	[ $$rc -eq 0 ] || exit $$rc; \
	echo "lint-rfcs: $$(printf '%s\n' $$cited | wc -l | tr -d ' ') cited RFCs, all vendored and matching their hashes"

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
	@python3 tools/commit-citations.py

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
	+./proof/run.sh fast
endif

prove-slow:
ifeq ($(CBMC),)
	$(call REQUIRE_ON_CI,cbmc)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	+./proof/run.sh slow
endif

prove-all:
ifeq ($(CBMC),)
	$(call REQUIRE_ON_CI,cbmc)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	+./proof/run.sh all
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
#
# Every timing binary links -lm: the t-test calls sqrt, which glibc keeps in
# libm and macOS's libc holds itself.
bin/timing: test/timing_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_CT_WIDEMUL -I. -o $@ test/timing_test.c $(SRCS) -lm
# The same t-test over the wide X25519 field, built as a host object builds
# its sources, with -DTEST_X25519_WIDE so that the x25519 row calls the
# field's entry. What this binary measures is whether the caller's multiply
# bit would be true on this host: whether the ladder's time moves with the
# scalar while the 64x64->128 multiply runs in the mode the host runs it
# in. It cannot say what another part does, which is ct.h's point.
bin/timing_x25519_wide: test/timing_test.c $(call host_srcs,$(SRCS)) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CT_WIDEMUL -DCH_CPU_RUNTIME -DTEST_X25519_WIDE -I. -o $@ test/timing_test.c \
	  $(call host_srcs,$(SRCS)) -lm
# The same t-test over the wide P-256 files and the table of multiples of
# G (docs/decisions.md 94), with -DTEST_P256_WIDE: a key generation, a key
# exchange and a signature under the constant-time answer, each a fixed
# scalar against fresh random ones. The sources are the equivalence
# binary's, less the stack helper it alone calls.
P256_TIMING_SRCS := $(filter-out test/stack_residue.c,$(P256_EQUIV_TEST_SRCS))
bin/timing_p256_wide: test/timing_test.c $(P256_TIMING_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CPU_RUNTIME -DTEST_P256_WIDE -I. -o $@ test/timing_test.c $(P256_TIMING_SRCS) -lm

# The same t-test over the host object's RSA arithmetic, with
# -DTEST_RSA_SIGN64 so that the binary runs that file's two rows: the
# 64-bit Montgomery multiplication over operands that do and do not need
# its last subtraction, and the windowed exponentiation over an exponent of
# zeros and random ones (docs/decisions.md 95). Like the wide field's, it
# measures this host in the mode it runs the multiply in.
bin/timing_rsa_sign64: test/timing_test.c $(call host_srcs,$(SRCS)) rsa_sign.c $(RSA_SIGN64_SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(HOST_CFLAGS) -DCH_CT_WIDEMUL -DCH_CPU_RUNTIME -DTEST_RSA_SIGN64 -I. -o $@ test/timing_test.c \
	  $(call host_srcs,$(SRCS)) rsa_sign.c $(RSA_SIGN64_SRCS) -lm

# Constant-time check (Welch's t over interleaved input classes). Load-
# sensitive, so it is not part of check; run it on an otherwise idle box.
.PHONY: timing
timing: bin/timing $(if $(HOST_TARGET),bin/timing_x25519_wide bin/timing_p256_wide bin/timing_rsa_sign64)
	./bin/timing
ifneq ($(HOST_TARGET),)
	./bin/timing_x25519_wide
	./bin/timing_p256_wide
	./bin/timing_rsa_sign64
else
	@echo "SKIP timing of the wide X25519 field, the wide P-256 files and RSA on 64-bit words: $(CC) fails the host test"
endif

# libFuzzer harnesses for the attacker-facing parsers in fuzz/. Each target
# #includes the translation unit holding its statics, so the .c that
# defines them is left off the link line. Needs a clang with libFuzzer;
# skipped with a message otherwise. New corpus units and crash repros land
# under bin/ (gitignored); fuzz/corpus/* stays read-only seed input.
FUZZ_CC ?= $(shell command -v $(LLVM_BIN)/clang || command -v clang)
FUZZ_CFLAGS := -std=c11 -O1 -g -fsanitize=fuzzer,address -D_DEFAULT_SOURCE $(HOST_RAND_DEF) -I.
FUZZ_TIME ?= 30
FUZZ_RECORD_LINK := record.c ct.c ct_wipe.c sha256.c hkdf.c chacha20.c poly1305.c aead.c
FUZZ_HANDSHAKE_PARSER_LINK := handshake_parser.c handshake_parser_ee.c buf.c
# handshake_post.c needs handshake.c, and handshake.c needs most of the
# client, so this list is SRCS less the file the harness includes. A
# hand-kept list lost the link when 33978f6 moved the flight handlers
# into handshake_flight.c; SRCS gains every such file.
FUZZ_HANDSHAKE_POST_LINK := $(filter-out handshake_post.c,$(SRCS))
FUZZ_X509_LINK := x509.c x509_der.c buf.c ct.c ct_wipe.c sha256.c rsa.c rsa_mont.c
# The TRUST=webpki walk and every file under it. -DCH_TRUST_WEBPKI is
# not optional here: ch_cfg declares the anchors, the hostname and the
# clock only there, and it widens the modulus gate to the RSA-4096 a
# public root carries.
FUZZ_WEBPKI_LINK := -DCH_TRUST_WEBPKI webpki.c webpki_cert.c webpki_ext.c webpki_name.c webpki_sigalg.c \
                    webpki_spki.c webpki_time.c x509_der.c buf.c ct.c ct_wipe.c sha256.c sha512.c \
                    sha512_compress.c p256.c p384.c p384_field.c rsa.c rsa_mont.c rsa_pkcs1.c
# The two rules SPKI pins run (webpki_pin.c), on a raw public key and on a
# chain under pins alone, over the walk's files, which hold their entry
# framing (webpki.c), the raw key's reader (webpki_spki.c) and the leaf's
# key reader (webpki_cert.c).
FUZZ_WEBPKI_PIN_LINK := $(FUZZ_WEBPKI_LINK) webpki_pin.c
FUZZ_HANDSHAKE_RECORD_LINK := handshake_record.c io.c record.c buf.c ct.c ct_wipe.c sha256.c hkdf.c \
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
	for t in record handshake_parser handshake_record handshake_post x509 webpki webpki_leaf_pin \
	    webpki_raw_key; do \
	  mkdir -p bin/fuzz/work_$$t; \
	done; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_record.c  $(FUZZ_RECORD_LINK)  -o bin/fuzz/fuzz_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_parser.c $(FUZZ_HANDSHAKE_PARSER_LINK) -o bin/fuzz/fuzz_handshake_parser; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_record.c $(FUZZ_HANDSHAKE_RECORD_LINK) -o bin/fuzz/fuzz_handshake_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_handshake_post.c  $(FUZZ_HANDSHAKE_POST_LINK)  -o bin/fuzz/fuzz_handshake_post; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_x509.c    $(FUZZ_X509_LINK)    -o bin/fuzz/fuzz_x509; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_webpki.c $(FUZZ_WEBPKI_LINK) -o bin/fuzz/fuzz_webpki; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_webpki_leaf_pin.c $(FUZZ_WEBPKI_PIN_LINK) \
	  -o bin/fuzz/fuzz_webpki_leaf_pin; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_webpki_raw_key.c $(FUZZ_WEBPKI_PIN_LINK) \
	  -o bin/fuzz/fuzz_webpki_raw_key; \
	for t in record handshake_parser handshake_record handshake_post x509 webpki webpki_leaf_pin \
	    webpki_raw_key; do \
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

# What the TRANSPORT=quic-nonblocking mode covers, read from the tree: the files and
# their line counts, the mode's text inside the CH_TRANSPORT_QUIC_NONBLOCKING arms of
# files a TCP build compiles too, the mode's share of the library, how
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

# ChaCha20-Poly1305 against AES-128-GCM, timed per byte on this machine,
# with each AEAD split into its cipher and its hash, under AES=soft and in
# a host object. bench/aead.sh states what it builds and writes
# bench/results-aead-<arch>.csv. It is a measurement, so `check` does not
# run it: its numbers belong to the machine that ran them, and a run
# takes about half a minute. `bench/aead.sh --quick` builds every variant
# and writes nothing, which is the form for an emulated machine, and
# check-script-builds runs `bench/aead.sh --build`, which builds every
# variant and runs none.
# .github/workflows/bench.yml runs the full form on an x86-64 runner when
# someone starts it by hand.
.PHONY: bench-aead
bench-aead:
	CC='$(CC)' bench/aead.sh

# One TLS record's protection, split into its stages and timed on this
# machine: rec_seal and rec_open, the AEAD entries record.c calls, and each
# AEAD's stages, for AES-128-GCM and AES-256-GCM in a host object and for
# ChaCha20-Poly1305, with the OpenSSL test/e2e.sh takes and Zig's
# std.crypto beside them. bench/record.sh builds with the flags make lib uses,
# where the host test passes, states what it builds, and writes
# bench/results-record-<os>-<arch>-<compiler>.csv, which docs/performance.md
# reads. `check` does not run it, for the reason it does not run
# bench-aead, and a run takes about a minute. `bench/record.sh --quick`
# runs every row once and writes nothing, and check-script-builds runs
# `bench/record.sh --build`, which builds every binary and runs none.
.PHONY: bench-record
bench-record:
	CC='$(CC)' bench/record.sh

# Every primitive the tree ships, per byte or per operation, and whole
# handshakes between this tree's client and server, on this machine, in a
# host object under the ch_cfg.cpu value a caller on this CPU states and
# under CH_CPU_PROBED alone, with `openssl speed` beside each primitive
# OpenSSL has. bench/primitives.sh states what it builds and writes
# bench/results-primitives-<os>-<arch>-<compiler>.csv and the handshake
# call counts beside it. docs/performance.md, "chapulin beside OpenSSL",
# renders its table from those files and bench-record's,
# tools/bench_scoreboard.py prints the table a run gives, and
# bench/notes-primitives.md reads the other rows.
# `check` does not run it, for the reason it does not run bench-aead, and
# a run took 8 min 41 s on an M1 Pro. `bench/primitives.sh --quick` builds
# every program, checks every known answer and writes nothing, and
# check-script-builds runs `bench/primitives.sh --build`, which builds
# every program and runs none.
.PHONY: bench-primitives
bench-primitives:
	CC='$(CC)' bench/primitives.sh

# The sources bench/insn-m3.sh, bench/insn-mips.sh and bench/insn-rv32.sh
# link beside bench/insn_driver.c to count each operation's instructions
# on a device core, and the defines every one of their builds takes: the
# extern entropy pattern, which cfg.h requires a build to declare and the
# driver never draws from. The three scripts read both from here, sources
# first, and test/script-builds.sh, which check runs, builds the driver
# from the same two lines with this host's compiler. So a call one of
# these sources gains into a file the list leaves out, or a define a
# header comes to require, fails check (docs/decisions.md 88).
INSN_SRCS := ct.c ct_wipe.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c rsa.c rsa_mont.c \
             buf.c keysched.c record.c sha3.c mlkem.c mlkem_poly.c
INSN_DEF := -DCH_RAND_EXTERN
.PHONY: print-insn-lists
print-insn-lists:
	@echo $(INSN_SRCS)
	@echo $(INSN_DEF)
