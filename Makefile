CC ?= cc
# -D_DEFAULT_SOURCE: glibc hides POSIX and getrandom under -std=c11 without
# it; macOS ignores it.
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE
LLVM_BIN := /opt/homebrew/opt/llvm/bin
CLANG_TIDY ?= $(shell command -v clang-tidy || command -v $(LLVM_BIN)/clang-tidy)
CLANG_FORMAT ?= $(shell command -v clang-format || command -v $(LLVM_BIN)/clang-format)
CPPCHECK ?= $(shell command -v cppcheck)
CBMC ?= $(shell command -v cbmc)
LAKE ?= $(shell command -v lake || command -v $(HOME)/.elan/bin/lake)

SRCS := ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c \
        buf.c record.c keysched.c io.c hsmsg.c session.c handshake.c tls.c
HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h p256.h ch_assert.h \
        buf.h record.h keysched.h io.h hsmsg.h cfg.h session.h handshake.h tls.h rand.h
LINT_C := $(SRCS) test/unit.c test/tlsclient.c test/diff.c test/timing.c
# CBMC intrinsics don't compile under clang-tidy/cppcheck; harnesses get
# clang-format only. Fuzzers include .c files for statics, same deal.
PROOF_C := $(wildcard proof/*.c) proof/harness.h
FUZZ_C := $(wildcard fuzz/*.c)

bin/unit: test/unit.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/unit.c $(SRCS)

bin/tlsclient: test/tlsclient.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/tlsclient.c $(SRCS)

bin/diff: test/diff.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/diff.c $(SRCS)

.PHONY: check lint lint-tidy lint-format lint-cppcheck prove diff fmt clean
check: bin/unit bin/tlsclient lint
	./bin/unit
	./test/e2e.sh
	$(MAKE) diff
	$(MAKE) prove

# Differential oracle: the Lean spec in spec/ answers over a pipe and
# test/diff.c compares every C module against it on random inputs.
diff:
ifeq ($(LAKE),)
	@echo "SKIP diff: lake not on PATH (install elan: https://leanprover.github.io)"
else
	cd spec && $(LAKE) build
	$(MAKE) bin/diff
	./bin/diff
endif

# Checks and thresholds live in .clang-tidy; every disable carries a reason
# there (fix-or-drop, never NOLINT in code).
lint: lint-tidy lint-format lint-cppcheck lint-commits

lint-tidy:
ifeq ($(CLANG_TIDY),)
	@echo "SKIP clang-tidy: not on PATH (ships with llvm)"
else
	$(CLANG_TIDY) --quiet $(LINT_C) -- -std=c11 -D_DEFAULT_SOURCE -I.
endif

lint-format:
ifeq ($(CLANG_FORMAT),)
	@echo "SKIP clang-format: not on PATH (ships with llvm)"
else
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) test/testrand.h test/diffdrv.h test/diffp256.h
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
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
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh fast
endif

prove-slow:
ifeq ($(CBMC),)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh slow
endif

prove-all:
ifeq ($(CBMC),)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh all
endif

fmt:
ifneq ($(CLANG_FORMAT),)
	$(CLANG_FORMAT) -i $(LINT_C) $(HDRS) $(PROOF_C) $(FUZZ_C) test/testrand.h test/diffdrv.h test/diffp256.h
endif

bin/timing: test/timing.c $(SRCS) $(HDRS)
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
FUZZ_HSPARSE_LINK := buf.c ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c \
                     x25519.c record.c keysched.c hsmsg.c
FUZZ_POSTHS_LINK := handshake.c io.c record.c keysched.c session.c buf.c ct.c \
                    sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c hsmsg.c

.PHONY: fuzz
fuzz:
	@set -e; \
	probe='int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){(void)d;(void)n;return 0;}'; \
	tmp=$$(mktemp); \
	if ! printf '%s\n' "$$probe" | $(FUZZ_CC) -fsanitize=fuzzer,address -x c - -o "$$tmp" 2>/dev/null; then \
	  rm -f "$$tmp"; \
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
