CC ?= cc
# -D_DEFAULT_SOURCE: glibc hides POSIX and getrandom under -std=c11 without
# it; macOS ignores it.
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE
# INV-19: -Wvla bans variable frames everywhere; the frame budget is
# enforced per library source by lint-stack, because host test mains
# legitimately keep whole vector tables in their frames.
CFLAGS += -Wvla
STACK_BUDGET := 2560
LLVM_BIN := /opt/homebrew/opt/llvm/bin
CLANG_TIDY ?= $(shell command -v clang-tidy || command -v $(LLVM_BIN)/clang-tidy)
CLANG_FORMAT ?= $(shell command -v clang-format || command -v $(LLVM_BIN)/clang-format)
CPPCHECK ?= $(shell command -v cppcheck)
CBMC ?= $(shell command -v cbmc)
CXX ?= c++
LAKE ?= $(shell command -v lake || command -v $(HOME)/.elan/bin/lake)

# On CI a missing tool must fail its gate, not skip it: a workflow edit
# that drops an install step would otherwise disable a check silently.
# Locally the skip stays a convenience. Usage: $(call REQUIRE_ON_CI,name)
REQUIRE_ON_CI = @[ -z "$$CI" ] || { echo "$(1): missing on CI; the gate must not skip"; exit 1; }

SRCS := ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c rsa.c rsa_mont.c \
        buf.c record.c keysched.c io.c hsmsg.c hsparse.c session.c handshake.c tls.c
HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h p256.h rsa.h ch_assert.h \
        buf.h record.h keysched.h io.h hsmsg.h hsparse.h cfg.h session.h handshake.h tls.h \
        rand.h drbg.h
LINT_C := $(SRCS) drbg.c test/unit.c test/tlsclient.c test/diff.c test/timing.c \
          test/drbg_test.c test/rsa_test.c test/hsstrict_test.c test/hsseq_test.c

# Test-local headers: prerequisites for every binary that includes them,
# so a header edit rebuilds the binaries it changes.
TESTH := test/testrand.h test/session_tests.h test/diffdrv.h test/diffp256.h \
         test/diffrsa.h test/hsseqsrv.h test/rfc8448_vectors.h test/rfc8448_tests.h

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
# CBMC intrinsics don't compile under clang-tidy/cppcheck; harnesses get
# clang-format only. Fuzzers include .c files for statics, same deal.
PROOF_C := $(wildcard proof/*.c) proof/harness.h
FUZZ_C := $(wildcard fuzz/*.c)

# Firmware links bin/chapulin.o: one relocatable object exposing exactly
# the four public calls. Partial linking merges the modules; nmedit
# (macOS) or objcopy (everything else) localizes every other symbol, so
# the library cannot collide with application names. lib-check enforces
# the export list as part of check. Objects live under the PIN they were
# built for, so switching PIN never reuses a stale object.
LIB_OBJS := $(LIB_SRCS:%.c=bin/obj/$(PIN)/%.o)
PUBLIC := ch_connect ch_read ch_write ch_close

bin/obj/$(PIN)/%.o: %.c $(HDRS)
	@mkdir -p bin/obj/$(PIN)
	$(CC) $(CFLAGS) $(LIB_DEF) -I. -c $< -o $@

# The packaged object is PIN-specific but lands at one path, so mtimes
# alone cannot tell which PIN built it; the stamp rewrites (and so
# triggers a relink) only when PIN changed since the last build.
PIN_STAMP := bin/obj/pin-stamp
$(PIN_STAMP): FORCE
	@mkdir -p bin/obj
	@[ "$$(cat $@ 2>/dev/null)" = "$(PIN)" ] || echo "$(PIN)" > $@
.PHONY: FORCE
FORCE:

bin/chapulin.o: $(LIB_OBJS) $(PIN_STAMP)
	ld -r -o $@ $(LIB_OBJS)
ifeq ($(shell uname),Darwin)
	printf '_%s\n' $(PUBLIC) > bin/exports.txt
	nmedit -s bin/exports.txt $@
else
	objcopy $(foreach s,$(PUBLIC),-G $(s)) $@
endif

.PHONY: lib lib-check cxx-check
lib: bin/chapulin.o

# The optional C++ wrapper (chapulin.hpp) compiles under -fno-exceptions
# -fno-rtti and links against the packaged library object, the way a
# firmware C++ consumer would use it.
CXXFLAGS ?= -std=c++17 -fno-exceptions -fno-rtti -Wall -Wextra -Wpedantic -Werror
cxx-check: bin/chapulin.o chapulin.hpp test/hpp_test.cpp
	@command -v $(CXX) >/dev/null || { \
	  [ -n "$$CI" ] && { echo "$(CXX): missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP cxx-check: no C++ compiler"; exit 0; }
	$(CXX) $(CXXFLAGS) $(LIB_DEF) -D_DEFAULT_SOURCE -I. -c test/hpp_test.cpp -o bin/hpp_test.o
	$(CXX) -o bin/hpp_test bin/hpp_test.o bin/chapulin.o
	./bin/hpp_test

lib-check: bin/chapulin.o
	@nm -g bin/chapulin.o | awk '$$2 ~ /^[TDSB]$$/ {print $$3}' | sed 's/^_//' | sort > bin/exported.txt
	@printf '%s\n' $(PUBLIC) | sort > bin/expected.txt
	@diff -u bin/expected.txt bin/exported.txt || { \
	  echo "lib-check: exported symbols differ from the public API"; exit 1; }
	@echo "lib-check: $$(wc -l < bin/exported.txt | tr -d ' ') exported symbols, all public API"

# The reference generator ships as source but stays out of the packaged
# object: it implements the ch_rand_bytes import, which firmware with a
# real RNG provides itself and the test binaries provide themselves.
bin/drbg_test: test/drbg_test.c drbg.c chacha20.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/drbg_test.c drbg.c chacha20.c ct.c

# RSA-PSS verify vectors; its own binary like drbg_test, so the module
# stays testable without the rest of the stack.
bin/rsa_test: test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c

# Parser strictness: drives the ServerHello/EE parsers directly; their
# whole dependency closure is hsparse.c + buf.c.
bin/hsstrict_test: test/hsstrict_test.c hsparse.c buf.c $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/hsstrict_test.c hsparse.c buf.c

# Sequence differential: every server message sequence to a bounded depth
# (ENUM_DEPTH overrides; 5 is ~354k sequences over both modes) against the
# Lean state machine's verdict. Links the stack minus the pinned
# verifiers, which it stubs — V in a sequence means "signature valid".
bin/hsseq_test: test/hsseq_test.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/hsseq_test.c $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))

bin/unit: test/unit.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/unit.c $(SRCS)

bin/tlsclient: test/tlsclient.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/tlsclient.c $(SRCS)

# The same client compiled for the P-256 pinned mode; e2e runs both
# builds against matching servers.
bin/tlsclient_ecdsa: test/tlsclient.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -DCH_PIN_ECDSA -I. -o $@ test/tlsclient.c $(SRCS)

bin/diff: test/diff.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/diff.c $(SRCS)

.PHONY: check lint lint-tidy lint-format lint-cppcheck lint-docs lint-invariants lint-spec prove diff fmt clean
check: bin/unit bin/tlsclient bin/tlsclient_ecdsa bin/drbg_test bin/rsa_test bin/hsstrict_test bin/hsseq_test lint lib-check cxx-check
	./bin/unit
	./bin/drbg_test
	./bin/rsa_test
	./bin/hsstrict_test
	$(MAKE) wycheproof
	./test/e2e.sh
	$(MAKE) diff
	./bin/hsseq_test
	$(MAKE) prove

# Differential oracle: the Lean spec in spec/ answers over a pipe and
# test/diff.c compares every C module against it on random inputs.
diff:
ifeq ($(LAKE),)
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP diff: lake not on PATH (install elan: https://leanprover.github.io)"
else
	cd spec && $(LAKE) build
	$(MAKE) bin/diff
	./bin/diff
endif

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
COV_CC = $(CC) --coverage -O0 -std=c11 -D_DEFAULT_SOURCE $$def -I.
COV_LIB_OBJS = $(SRCS:%.c=$$d/%.o)
.PHONY: coverage
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
	  $(COV_CC) test/unit.c $(COV_LIB_OBJS) -o $$d/unit; \
	  $(COV_CC) test/drbg_test.c $$d/drbg.o $$d/chacha20.o $$d/ct.o -o $$d/drbg_test; \
	  $(COV_CC) test/rsa_test.c $$d/rsa.o $$d/rsa_mont.o $$d/sha256.o $$d/ct.o -o $$d/rsa_test; \
	  $(COV_CC) test/hsstrict_test.c $$d/hsparse.o $$d/buf.o -o $$d/hsstrict_test; \
	  $(COV_CC) test/hsseq_test.c \
	    $(filter-out $$d/p256.o $$d/rsa.o $$d/rsa_mont.o,$(COV_LIB_OBJS)) -o $$d/hsseq_test; \
	  for b in unit drbg_test rsa_test hsstrict_test hsseq_test; do \
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

# Big-endian MIPS lane: the byte-exact suites on the deployment ISA.
# Every other test runs on little-endian x86-64; this lane proves no
# host byte order leaked into the wire path or the crypto, and lets the
# vectors meet mips32r2 code generation. CROSS names the toolchain
# prefix and RUNNER the emulator; the same command runs locally and on
# CI:  make cross-check CROSS=mips-linux-gnu- RUNNER=qemu-mips
# Static binaries, so the emulator needs no target sysroot. The suites
# run from bin/cross on purpose: hsseq then skips the Lean-spec
# comparison (the oracle is a host binary), keeping its direct ordering
# and alert tables; depth 3 keeps the emulated enumeration to minutes,
# and the x86 lane owns the deep run.
CROSS ?=
RUNNER ?=
.PHONY: cross-check
cross-check:
	@[ -n "$(CROSS)" ] || { echo "cross-check: set CROSS=<toolchain-prefix> (and RUNNER=<emulator>)"; exit 1; }
	@mkdir -p bin/cross
	$(CROSS)gcc $(CFLAGS) -static -I. -o bin/cross/unit test/unit.c $(SRCS)
	$(CROSS)gcc $(CFLAGS) -static -I. -o bin/cross/drbg_test test/drbg_test.c drbg.c chacha20.c ct.c
	$(CROSS)gcc $(CFLAGS) -static -I. -o bin/cross/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(CROSS)gcc $(CFLAGS) -static -I. -o bin/cross/hsstrict_test test/hsstrict_test.c hsparse.c buf.c
	$(CROSS)gcc $(CFLAGS) -static -I. -o bin/cross/hsseq_test test/hsseq_test.c \
	  $(filter-out p256.c rsa.c rsa_mont.c,$(SRCS))
	@if [ -d $(WYCHEPROOF_DIR)/.git ] \
	  || git clone --quiet --depth 1 https://github.com/C2SP/wycheproof $(WYCHEPROOF_DIR) 2>/dev/null; then \
	  python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	  $(CROSS)gcc $(CFLAGS) -static -I. -Ibin -o bin/cross/wycheproof_test test/wycheproof_test.c \
	    x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c buf.c ct.c; \
	else \
	  [ -n "$$CI" ] && { echo "wycheproof: clone failed and CI must not skip a gate"; exit 1; }; \
	  echo "SKIP cross wycheproof: no checkout and no network"; \
	fi
	@set -e; cd bin/cross; for b in unit drbg_test rsa_test hsstrict_test hsseq_test; do \
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
	$(call REQUIRE_ON_CI,lake)
	@echo "SKIP lint-spec: lake not on PATH (install elan: https://leanprover.github.io)"
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
	  || { echo "lint-spec: a load-bearing theorem depends on a non-standard axiom"; exit 1; }
	@echo "lint-spec: model clean, theorems rest on the standard axioms only"
endif

# Checks and thresholds live in .clang-tidy; every disable carries a reason
# there (fix-or-drop, never NOLINT in code).
lint: lint-tidy lint-format lint-cppcheck lint-commits lint-docs lint-invariants lint-stack lint-spec

# INV-19: bounded stack. The budget is the measured worst library
# frame (rsa_vp1's RSA-3072 limb temporaries, 2,400 bytes) rounded up;
# a frame past it is a build error, not a bench surprise. Each source
# compiles alone so a breach names its file.
lint-stack:
	@mkdir -p bin/obj/stack
	@rc=0; for f in $(SRCS) drbg.c; do \
	  $(CC) $(CFLAGS) -Wframe-larger-than=$(STACK_BUDGET) -I. -c $$f -o bin/obj/stack/$$f.o || rc=1; \
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
	$(call REQUIRE_ON_CI,semgrep)
	@echo "SKIP semgrep: not on PATH (pip install --require-hashes -r .semgrep/requirements.txt)"
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

lint-tidy:
ifeq ($(CLANG_TIDY),)
	$(call REQUIRE_ON_CI,clang-tidy)
	@echo "SKIP clang-tidy: not on PATH (ships with llvm)"
else
	$(CLANG_TIDY) --quiet $(LINT_C) -- -std=c11 -D_DEFAULT_SOURCE -I.
endif

lint-format:
ifeq ($(CLANG_FORMAT),)
	$(call REQUIRE_ON_CI,clang-format)
	@echo "SKIP clang-format: not on PATH (ships with llvm)"
else
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) $(TESTH)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	$(call REQUIRE_ON_CI,cppcheck)
	@echo "SKIP cppcheck: not on PATH (install cppcheck)"
else
	# constParameterCallback: I/O callback signatures are fixed by the
	# ch_cfg contract in tls.h; const-ing an implementation's void *io
	# would need function-pointer casts, which is worse.
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --inline-suppr --suppress=missingIncludeSystem \
	  --suppress=constParameterCallback \
	  --error-exitcode=1 --quiet $(LINT_C)
endif

# One-time setup: point git at the committed hooks (commit-msg runs
# commitlint; npm install first).
.PHONY: hooks lint-commits
hooks:
	git config core.hooksPath .githooks

lint-commits:
ifeq ($(shell command -v npx),)
	$(call REQUIRE_ON_CI,npx)
	@echo "SKIP commitlint: npx not on PATH (install node)"
else
	npx --no-install commitlint --from=$(shell git rev-list --max-parents=0 HEAD)~0 --to=HEAD \
	  || npx --no-install commitlint --from=HEAD~1 --to=HEAD
endif

# CBMC proofs: memory safety and absence of UB per module, at the bounds
# each harness documents. The fast tier (seconds to a few minutes) gates
# every check; the four SAT heavyweights run as prove-slow in CI and
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

bin/timing: test/timing.c $(SRCS) $(HDRS) $(TESTH)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/timing.c $(SRCS)

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
FUZZ_CFLAGS := -std=c11 -O1 -g -fsanitize=fuzzer,address -D_DEFAULT_SOURCE -I.
FUZZ_TIME ?= 30
FUZZ_RECORD_LINK := record.c ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c
FUZZ_HSPARSE_LINK := hsparse.c buf.c
FUZZ_POSTHS_LINK := handshake.c hsparse.c io.c record.c keysched.c session.c buf.c ct.c \
                    sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c rsa.c rsa_mont.c hsmsg.c

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
	for t in record hsparse posths; do mkdir -p bin/fuzz/work_$$t; done; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_record.c  $(FUZZ_RECORD_LINK)  -o bin/fuzz/fuzz_record; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_hsparse.c $(FUZZ_HSPARSE_LINK) -o bin/fuzz/fuzz_hsparse; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) fuzz/fuzz_posths.c  $(FUZZ_POSTHS_LINK)  -o bin/fuzz/fuzz_posths; \
	for t in record hsparse posths; do \
	  ./bin/fuzz/fuzz_$$t bin/fuzz/work_$$t fuzz/corpus/fuzz_$$t \
	    -artifact_prefix=bin/fuzz/ -max_total_time=$(FUZZ_TIME); \
	done

# CI range lint: only the commits under review when a base exists; on main
# (or with no origin/main) fall back to the full history.
.PHONY: lint-commits-range
lint-commits-range:
	@if git rev-parse -q --verify origin/main >/dev/null && \
	    ! git merge-base --is-ancestor HEAD origin/main; then \
	    npx --no-install commitlint --from origin/main --to HEAD; \
	else \
	    npx --no-install commitlint --from "$$(git rev-list --max-parents=0 HEAD)" --to HEAD; \
	fi

clean:
	rm -rf bin
