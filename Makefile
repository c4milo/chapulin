CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2
LLVM_BIN := /opt/homebrew/opt/llvm/bin
CLANG_TIDY ?= $(shell command -v clang-tidy || command -v $(LLVM_BIN)/clang-tidy)
CLANG_FORMAT ?= $(shell command -v clang-format || command -v $(LLVM_BIN)/clang-format)
CPPCHECK ?= $(shell command -v cppcheck)
CBMC ?= $(shell command -v cbmc)
LAKE ?= $(shell command -v lake || command -v $(HOME)/.elan/bin/lake)

SRCS := ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c \
        buf.c record.c keysched.c io.c hsmsg.c session.c handshake.c tls.c
HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h ms_assert.h \
        buf.h record.h keysched.h io.h hsmsg.h cfg.h session.h handshake.h tls.h rand.h
LINT_C := $(SRCS) test/unit.c test/tlsclient.c test/diff.c
# CBMC intrinsics don't compile under clang-tidy/cppcheck; harnesses get
# clang-format only.
PROOF_C := $(wildcard proof/*.c) proof/harness.h

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
	$(CLANG_TIDY) --quiet $(LINT_C) -- -std=c11 -I.
endif

lint-format:
ifeq ($(CLANG_FORMAT),)
	@echo "SKIP clang-format: not on PATH (ships with llvm)"
else
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS) $(PROOF_C)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	@echo "SKIP cppcheck: not on PATH (install cppcheck)"
else
	# constParameterCallback: I/O callback signatures are fixed by the
	# ms_cfg contract in tls.h; const-ing an implementation's void *io
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
# each harness documents. proof/run.sh fails on the first violated claim.
prove:
ifeq ($(CBMC),)
	@echo "SKIP cbmc: not on PATH (brew install cbmc)"
else
	./proof/run.sh
endif

fmt:
ifneq ($(CLANG_FORMAT),)
	$(CLANG_FORMAT) -i $(LINT_C) $(HDRS) $(PROOF_C)
endif

clean:
	rm -rf bin
