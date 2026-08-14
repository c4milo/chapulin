CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -Werror -std=c11 -O2
LLVM_BIN := /opt/homebrew/opt/llvm/bin
CLANG_TIDY ?= $(shell command -v clang-tidy || command -v $(LLVM_BIN)/clang-tidy)
CLANG_FORMAT ?= $(shell command -v clang-format || command -v $(LLVM_BIN)/clang-format)
CPPCHECK ?= $(shell command -v cppcheck)
CBMC ?= $(shell command -v cbmc)

SRCS := ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c
HDRS := ct.h sha256.h hkdf.h chacha20.h poly1305.h aead.h x25519.h ms_assert.h
LINT_C := $(SRCS) test/unit.c

bin/unit: test/unit.c $(SRCS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -I. -o $@ test/unit.c $(SRCS)

.PHONY: check lint lint-tidy lint-format lint-cppcheck prove fmt clean
check: bin/unit lint
	./bin/unit
	$(MAKE) prove

# Checks and thresholds live in .clang-tidy; every disable carries a reason
# there (fix-or-drop, never NOLINT in code).
lint: lint-tidy lint-format lint-cppcheck

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
	$(CLANG_FORMAT) --dry-run --Werror $(LINT_C) $(HDRS)
endif

lint-cppcheck:
ifeq ($(CPPCHECK),)
	@echo "SKIP cppcheck: not on PATH (install cppcheck)"
else
	$(CPPCHECK) --std=c11 --enable=warning,style,performance,portability \
	  --inline-suppr --suppress=missingIncludeSystem \
	  --error-exitcode=1 --quiet $(LINT_C)
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
	$(CLANG_FORMAT) -i $(LINT_C) $(HDRS)
endif

clean:
	rm -rf bin
