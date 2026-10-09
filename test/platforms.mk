# The platform test lanes: the native suite roster for parity jobs,
# the bare-metal Cortex-M3 lane, and the FreeRTOS lane. Included by the
# root Makefile; everything here builds test images and runs them, and
# none of it is part of the library build.

# Prefer the Arm GNU toolchain release the CI pin names (the macOS cask
# installs it under /Applications, off PATH) over whatever PATH carries:
# Homebrew's arm-none-eabi-gcc formula is a bare compiler without
# newlib's rdimon.specs, and it shadows the cask when both exist.
M3_CC ?= $(shell command -v \
  /Applications/ArmGNUToolchain/$(ARM_GNU_VERSION)/arm-none-eabi/bin/arm-none-eabi-gcc \
  || command -v arm-none-eabi-gcc)
M3_QEMU ?= $(shell command -v qemu-system-arm)
M3_FLAGS = -mcpu=cortex-m3 -mthumb --specs=rdimon.specs $(CFLAGS) \
           -Wl,--no-warn-rwx-segments -T test/qemu/m3_semi.ld test/qemu/m3_start.c
M3_RUN = $(M3_QEMU) -M mps2-an385 -cpu cortex-m3 -nographic -semihosting -kernel
FREERTOS_KERNEL_DIR ?= bin/freertos-kernel
FREERTOS_TCP_DIR ?= bin/freertos-plus-tcp
# The sources this device build links: every source in SRCS except the
# webpki chain verifier, which reads a clock and a hostname the device
# does not have. Derived from SRCS rather than retyped, because a copy
# drifts: this list was written out by hand and never gained
# handshake_flight.c when that file was split out of handshake.c, so the
# link failed on eight hsf_ symbols until the count was compared.
FREERTOS_SRCS = $(filter-out webpki_%.c,$(SRCS))

# Every deterministic suite, built and run natively — the tests-only
# half of check, for platform-parity jobs (linux arm64 today) where
# re-building the whole lint toolchain buys nothing. The roster is
# check's own prerequisite list.
.PHONY: suite-check
suite-check: bin/unit bin/unit_ca bin/unit_pq bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa bin/tlsclient_pq bin/drbg_test bin/softmul_test bin/rsa_test bin/sha3_test bin/sha512_test bin/p384_test bin/rsa_pkcs1_test bin/webpki_time_test bin/webpki_name_test bin/webpki_spki_test bin/webpki_sigalg_test bin/webpki_cert_test bin/mlkem_test bin/handshake_strict_test bin/handshake_strict_pq bin/x509strict bin/x509strict_ecdsa $(X86_KERNEL_BINS) \
             $(HOST_BINS) $(HOST_VECTOR_BINS)
	@set -e; for b in unit unit_ca unit_pq drbg_test softmul_test rsa_test sha3_test sha512_test p384_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test mlkem_test \
	  handshake_strict_test handshake_strict_pq x509strict x509strict_ecdsa; do \
	  echo "== $$b (native)"; ./bin/$$b; done
	@set -e; for b in $(notdir $(X86_KERNEL_BINS) $(HOST_BINS)); do echo "== $$b (host object)"; ./bin/$$b; done
	@set -e; for b in $(notdir $(HOST_VECTOR_BINS)); do for bits in $(HOST_VECTOR_CPU); do \
	  echo "== $$b $$bits (host object)"; ./bin/$$b $$bits; done; done
	@set -e; for b in $(if $(HOST_VECTOR_BINS),$(X86_VECTOR_HOST)); do for bits in $(X86_UNIT_CPU); do \
	  echo "== $$b $$bits (host object)"; ./bin/$$b $$bits; done; done
	@set -e; for bits in $(if $(HOST_VECTOR_BINS),$(HASH_UNIT_CPU)); do \
	  echo "== unit_host $$bits (host object)"; ./bin/unit_host $$bits; done
	@set -e; for b in $(if $(HOST_VECTOR_BINS),$(HASH_VECTOR_HOST)); do for bits in $(HASH512_UNIT_CPU); do \
	  echo "== $$b $$bits (host object)"; ./bin/$$b $$bits; done; done
	$(MAKE) wycheproof


# The x86-64 kernels, for CI's x86-64-kernels job: chacha20_avx2.c's AVX2
# ChaCha20 and gcm_vaes.c's VAES and VPCLMULQDQ kernels
# (docs/decisions.md 90), keccak_avx2.c's four-way Keccak, on which
# mlkem_avx2.c samples ML-KEM's matrix (107), and poly1305_avx2.c's AVX2
# Poly1305 (110). Every x86-64 host object carries them, built
# with no instruction flag, and a session runs one where its ch_cfg.cpu
# names it. The equivalence binaries call the kernels directly,
# bin/quic_test_hw and bin/ghash_equiv_test run a pass of their vectors
# and cases on the VAES kernels, and bin/unit_host and the host Wycheproof
# test run under the values that name a kernel (X86_UNIT_CPU,
# X86_WYCHEPROOF_CPU). Each skips a kernel on a CPU without its
# instructions, in check and everywhere else; this target runs them under
# CH_REQUIRE_X86_KERNELS=1, so on such a CPU it fails instead, after
# x86-64-kernels-cpu names the CPU. bin/x86_kernels_test, which counts
# the calls into the kernels and runs none of their instructions, runs
# here too. AVX-512 IFMA, which the values with CH_CPU_AVX512_IFMA name,
# is absent from some of the job's runners, so CH_REQUIRE_X86_KERNELS=1
# leaves those values skipping there (test/x86_kernels_cpu.h).
#
# The same job holds sha256_hw.c's x86-64 arm on the SHA extensions
# (docs/decisions.md 93), which a CPU with the kernels' instructions has:
# bin/sha2_equiv_test, bin/unit_host under HASH_UNIT_CPU and the host Wycheproof
# test run under CH_REQUIRE_HASH_INSTRUCTIONS=1, so a CPU without the
# extensions fails them too.
X86_KERNEL_RUNS := chacha20_equiv_test aes_equiv_test ghash_equiv_test quic_test_hw x86_kernels_test \
                   mlkem_avx2_equiv_test poly1305_equiv_test
.PHONY: x86-64-kernels-check x86-64-kernels-cpu
x86-64-kernels-check: x86-64-kernels-cpu $(addprefix bin/,$(X86_KERNEL_RUNS)) \
                      $(addprefix bin/,$(X86_VECTOR_HOST)) bin/sha2_equiv_test
	@[ -n "$(X86_KERNEL_BINS)" ] || \
	  { echo "x86-64-kernels-check: $(CC) does not build a host object for x86-64"; exit 1; }
	@set -e; for b in $(X86_KERNEL_RUNS); do \
	  echo "== $$b (the x86-64 kernels required)"; CH_REQUIRE_X86_KERNELS=1 ./bin/$$b; done
	@set -e; for b in $(X86_VECTOR_HOST); do for bits in $(X86_UNIT_CPU); do \
	  echo "== $$b $$bits (the x86-64 kernels required)"; CH_REQUIRE_X86_KERNELS=1 ./bin/$$b $$bits; done; done
	@echo "== sha2_equiv_test (the SHA extensions required)"; CH_REQUIRE_HASH_INSTRUCTIONS=1 ./bin/sha2_equiv_test
	@set -e; for bits in $(HASH_UNIT_CPU); do \
	  echo "== unit_host $$bits (the SHA extensions required)"; CH_REQUIRE_HASH_INSTRUCTIONS=1 ./bin/unit_host $$bits; done
	CH_REQUIRE_X86_KERNELS=1 CH_REQUIRE_HASH_INSTRUCTIONS=1 $(MAKE) --no-print-directory wycheproof

# Keccak on arm64's SHA-3 instructions, which sha3_hw.c holds under clang
# alone (docs/decisions.md 99). A job whose compiler is gcc builds the file
# with no body, so suite-check there runs none of it. This target builds
# the two equivalence tests with KECCAK_CC, the pinned clang unless the
# caller names another, and runs them under CH_REQUIRE_HASH_INSTRUCTIONS=1,
# so a CPU without FEAT_SHA3 fails it, and so does a compiler under which
# the object holds no such path. It removes the two binaries before and
# after: make would take one that another compiler built for the one the
# next goal wants.
KECCAK_CC ?= $(CLANG_RV)
KECCAK_INSTRUCTION_RUNS := sha3_hw_equiv_test mlkem_hw_equiv_test
.PHONY: keccak-instructions-check
keccak-instructions-check:
	@rm -f $(addprefix bin/,$(KECCAK_INSTRUCTION_RUNS))
	@$(MAKE) --no-print-directory CC=$(KECCAK_CC) $(addprefix bin/,$(KECCAK_INSTRUCTION_RUNS))
	@set -e; for b in $(KECCAK_INSTRUCTION_RUNS); do \
	  echo "== $$b ($(KECCAK_CC), FEAT_SHA3 required)"; CH_REQUIRE_HASH_INSTRUCTIONS=1 ./bin/$$b; done
	@rm -f $(addprefix bin/,$(KECCAK_INSTRUCTION_RUNS))

# Whether this machine's CPU has what the x86-64 kernels and sha256_hw.c
# run: AES-NI, PCLMULQDQ, AVX2, VAES and VPCLMULQDQ, and the SHA
# extensions with SSSE3 and SSE4.1, read from /proc/cpuinfo. It names the
# CPU, and fails where one is missing.
x86-64-kernels-cpu:
	@[ -r /proc/cpuinfo ] || { echo "x86-64-kernels-cpu: no /proc/cpuinfo; this target runs on Linux x86-64"; exit 1; }
	@cpu=$$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1); \
	for f in aes pclmulqdq avx2 vaes vpclmulqdq sha_ni ssse3 sse4_1; do grep -qw "$$f" /proc/cpuinfo || \
	  { echo "x86-64-kernels-cpu: $$cpu lacks $$f"; exit 1; }; done; \
	echo "x86-64-kernels-cpu: $$cpu has AES-NI, PCLMULQDQ, AVX2, VAES, VPCLMULQDQ, the SHA extensions, SSSE3 and SSE4.1"

# test/aes-runtime-qemu.sh: bin/aes_runtime_test and the two suite loop
# binaries, host objects, built for x86-64 and run under qemu-x86_64 on a
# CPU model with AES-NI and PCLMULQDQ turned off. Their rows without the
# CH_CPU_CONSTANT_TIME_AES bit must pass there, and the rows with it and
# bin/quic_test_hw's vectors must die of SIGILL. It does the same for
# CH_CPU_CONSTANT_TIME_SHA256 on a model without the SHA extensions, and
# runs bin/sha2_equiv_test on the model that has them. Linux only, with
# qemu-user; X86_CC names a cross compiler on a host of another
# architecture (docs/decisions.md 81, 89 and 93). CI's
# mips job runs it, and test/docker-aes-runtime-qemu.sh runs it in a
# container on any host with docker.
.PHONY: aes-runtime-qemu
aes-runtime-qemu:
	./test/aes-runtime-qemu.sh

# test/aes-runtime-disasm.sh: three host objects, built with this host's
# compiler and disassembled, hold the AES and carry-less multiply
# instructions in aes_hw.c's, ghash_hw.c's, gcm_hw.c's and gcm_vaes.c's
# functions and nowhere else, and the SHA-256 instructions in
# sha256_hw.c's. CI's arm64 job runs it, because no QEMU arm64 model can
# turn the AES or the SHA-256 extension off (docs/decisions.md 81 and
# 93). The recipe starts with + so the builds the script runs take this
# make's job slots.
.PHONY: aes-runtime-disasm
aes-runtime-disasm:
	+./test/aes-runtime-disasm.sh

# The Cortex-M3 lane: the cross-check suite roster, built with the Arm
# GNU toolchain (newlib + rdimon semihosting) and run one binary at a
# time on QEMU's MPS2-AN385 — the same core lint-wide-multiply checks by
# disassembly, executing instead of being read. drbg_test is one of two
# roster differences from the mips lane: it drives a diffspec child
# over pipe/dup2, which bare metal has no words for, and
# handshake_sequence_test forks the same child; every Linux lane runs
# both. Each line takes its sources from the variable the binary's own
# rule in the Makefile reads, as san-check does.
.PHONY: m3-check
m3-check:
	@[ -n "$(M3_CC)" ] || { \
	  [ -n "$$CI" ] && { echo "m3-check: arm-none-eabi-gcc missing on CI; the check must not skip"; exit 1; }; \
	  echo "SKIP m3-check: no arm-none-eabi-gcc (see ARM_GNU_VERSION in tools/toolchain.env)"; exit 0; }
	@[ -n "$(M3_QEMU)" ] || { \
	  [ -n "$$CI" ] && { echo "m3-check: qemu-system-arm missing on CI; the check must not skip"; exit 1; }; \
	  echo "SKIP m3-check: no qemu-system-arm"; exit 0; }
	@mkdir -p bin/m3
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/unit test/unit_test.c $(SRCS)
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -I. -o bin/m3/rsa_test test/rsa_test.c $(RSA_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/sha3_test test/sha3_test.c $(SHA3_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/sha512_test test/sha512_test.c $(SHA512_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/p384_test test/p384_test.c $(P384_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/p256_ecdh_test test/p256_ecdh_test.c $(P256_ECDH_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -I. -o bin/m3/rsa_pkcs1_test test/rsa_pkcs1_test.c $(RSA_PKCS1_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/webpki_time_test test/webpki_time_test.c $(WEBPKI_TIME_SRC)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/webpki_name_test test/webpki_name_test.c $(WEBPKI_NAME_SRC)
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -I. -o bin/m3/webpki_spki_test test/webpki_spki_test.c $(WEBPKI_SPKI_SRC)
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -I. -o bin/m3/webpki_sigalg_test test/webpki_sigalg_test.c $(WEBPKI_SIGALG_SRC)
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -I. -o bin/m3/webpki_cert_test test/webpki_cert_test.c $(WEBPKI_CERT_SRC)
	$(M3_CC) $(M3_FLAGS) -I. -Itest -o bin/m3/p256_sign_test test/p256_sign_test.c $(P256_SIGN_SRC)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/mlkem_test test/mlkem_test.c $(MLKEM_TEST_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/handshake_strict_test test/handshake_strict_test.c $(HANDSHAKE_STRICT_SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/x509strict_test $(X509STRICT_RSA_SRCS)
	$(M3_CC) $(M3_FLAGS) -DCH_PIN_ECDSA -I. -o bin/m3/x509strict_ecdsa $(X509STRICT_ECDSA_SRCS)
	# No QUIC transport is defined here, so test/wycheproof_test.c runs no
	# AES-GCM suite and the line leaves aes.c and gcm.c out.
	@$(call wycheproof_fetch,m3 wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(M3_CC) $(M3_FLAGS) $(RSA_WIDE_DEF) -DCH_HASH_SHA384 -I. -Ibin -o bin/m3/wycheproof_test test/wycheproof_test.c \
	  $(filter-out aes.c gcm.c,$(WYCHEPROOF_SRCS))
	@set -e; for b in unit rsa_test sha3_test sha512_test p384_test p256_ecdh_test p256_sign_test rsa_pkcs1_test webpki_time_test webpki_name_test webpki_spki_test webpki_sigalg_test webpki_cert_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
	  echo "== $$b (m3/qemu)"; $(M3_RUN) bin/m3/$$b; done; \
	if [ -x bin/m3/wycheproof_test ]; then echo "== wycheproof_test (m3/qemu)"; $(M3_RUN) bin/m3/wycheproof_test; fi



# The FreeRTOS lane, two rungs. The pinned kernel boots with two
# statically allocated tasks that must interleave before PASS — the
# scheduler, SysTick and PendSV proven. Then a task completes a
# TLS 1.3 handshake through FreeRTOS+TCP to a live openssl s_server,
# application data verified (test/qemu-freertos-tls.sh owns the server).
# Kernel and Plus-TCP arrive by commit hash — tools/toolchain.env says
# why never by ref — into gitignored checkouts, reused when at the pin.
.PHONY: freertos-check
freertos-check:
	@[ -n "$(M3_CC)" ] || { \
	  [ -n "$$CI" ] && { echo "freertos-check: arm-none-eabi-gcc missing on CI; the check must not skip"; exit 1; }; \
	  echo "SKIP freertos-check: no arm-none-eabi-gcc (see ARM_GNU_VERSION in tools/toolchain.env)"; exit 0; }
	@[ -n "$(M3_QEMU)" ] || { \
	  [ -n "$$CI" ] && { echo "freertos-check: qemu-system-arm missing on CI; the check must not skip"; exit 1; }; \
	  echo "SKIP freertos-check: no qemu-system-arm"; exit 0; }
	@if [ "$$(git -C $(FREERTOS_KERNEL_DIR) rev-parse HEAD 2>/dev/null)" != "$(FREERTOS_KERNEL_COMMIT)" ]; then \
	  rm -rf $(FREERTOS_KERNEL_DIR); mkdir -p $(FREERTOS_KERNEL_DIR); \
	  git -C $(FREERTOS_KERNEL_DIR) init -q; \
	  git -C $(FREERTOS_KERNEL_DIR) fetch -q --depth 1 \
	    https://github.com/FreeRTOS/FreeRTOS-Kernel.git $(FREERTOS_KERNEL_COMMIT); \
	  git -C $(FREERTOS_KERNEL_DIR) -c advice.detachedHead=false checkout -q $(FREERTOS_KERNEL_COMMIT); \
	fi
	@[ "$$(git -C $(FREERTOS_KERNEL_DIR) rev-parse HEAD)" = "$(FREERTOS_KERNEL_COMMIT)" ] \
	  || { echo "freertos-check: kernel checkout is not the pinned commit"; exit 1; }
	@mkdir -p bin/freertos
	$(M3_CC) -mcpu=cortex-m3 -mthumb -Os -std=c11 -ffreestanding -nostdlib \
	  -Wall -Wextra -Wpedantic -Werror -Wl,--no-warn-rwx-segments -Wl,--entry=reset_handler \
	  -Itest/freertos -I$(FREERTOS_KERNEL_DIR)/include -I$(FREERTOS_KERNEL_DIR)/portable/GCC/ARM_CM3 \
	  -T test/qemu/m3.ld -o bin/freertos/boot_test test/freertos/boot_test.c \
	  $(FREERTOS_KERNEL_DIR)/tasks.c $(FREERTOS_KERNEL_DIR)/list.c \
	  $(FREERTOS_KERNEL_DIR)/portable/GCC/ARM_CM3/port.c $(FREERTOS_KERNEL_DIR)/portable/MemMang/heap_4.c
	@echo "== freertos boot_test (m3/qemu)"; \
	 $(M3_RUN) bin/freertos/boot_test
	@if [ "$$(git -C $(FREERTOS_TCP_DIR) rev-parse HEAD 2>/dev/null)" != "$(FREERTOS_PLUS_TCP_COMMIT)" ]; then \
	  rm -rf $(FREERTOS_TCP_DIR); mkdir -p $(FREERTOS_TCP_DIR); \
	  git -C $(FREERTOS_TCP_DIR) init -q; \
	  git -C $(FREERTOS_TCP_DIR) fetch -q --depth 1 \
	    https://github.com/FreeRTOS/FreeRTOS-Plus-TCP.git $(FREERTOS_PLUS_TCP_COMMIT); \
	  git -C $(FREERTOS_TCP_DIR) -c advice.detachedHead=false checkout -q $(FREERTOS_PLUS_TCP_COMMIT); \
	fi
	@[ "$$(git -C $(FREERTOS_TCP_DIR) rev-parse HEAD)" = "$(FREERTOS_PLUS_TCP_COMMIT)" ] \
	  || { echo "freertos-check: Plus-TCP checkout is not the pinned commit"; exit 1; }
	# Both test programs go through clang-tidy with the lane's flags and
	# headers ($(M3_CC) supplies the newlib include path). Beyond
	# lint-tidy's three freestanding drops (reserved identifiers,
	# internal linkage, assembler -- the reasons live in the root
	# Makefile), two more are off here: performance-no-int-to-ptr,
	# because the NVIC and the ethernet MMIO live at integer addresses,
	# and misc-header-include-cycle, because the cycles are in the
	# vendor's own headers.
	@if [ -n "$(CLANG_TIDY)" ]; then \
	  $(CLANG_TIDY) --quiet --header-filter='test/freertos/.*' \
	    --checks='-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-misc-use-internal-linkage,-portability-no-assembler,-performance-no-int-to-ptr,-misc-header-include-cycle' \
	    test/freertos/boot_test.c test/freertos/tls_test.c -- \
	    -std=c11 --target=armv7m-none-eabi -ffreestanding -DCH_RAND_EXTERN \
	    -isystem "$$($(M3_CC) -print-sysroot)/include" \
	    -I. -Itest/freertos \
	    -I$(FREERTOS_KERNEL_DIR)/include -I$(FREERTOS_KERNEL_DIR)/portable/GCC/ARM_CM3 \
	    -I$(FREERTOS_TCP_DIR)/source/include -I$(FREERTOS_TCP_DIR)/source/portable/Compiler/GCC \
	    -I$(FREERTOS_TCP_DIR)/source/portable/NetworkInterface/MPS2_AN385/ether_lan9118; \
	elif [ -n "$$CI" ]; then \
	  echo "freertos-check: clang-tidy missing on CI; the lint must not skip"; exit 1; \
	else echo "SKIP freertos tidy: no clang-tidy (see LLVM_MAJOR in tools/toolchain.env)"; fi
	$(M3_CC) -mcpu=cortex-m3 -mthumb -Os -std=c11 -ffreestanding -nostdlib \
	  -Wall -Wextra -Wl,--no-warn-rwx-segments -Wl,--entry=reset_handler \
	  -DCH_RAND_EXTERN \
	  -Itest/freertos -I$(FREERTOS_KERNEL_DIR)/include -I$(FREERTOS_KERNEL_DIR)/portable/GCC/ARM_CM3 \
	  -I$(FREERTOS_TCP_DIR)/source/include -I$(FREERTOS_TCP_DIR)/source/portable/Compiler/GCC \
	  -I$(FREERTOS_TCP_DIR)/source/portable/NetworkInterface/MPS2_AN385/ether_lan9118 -I. \
	  -T test/qemu/m3.ld -o bin/freertos/tls_test test/freertos/tls_test.c \
	  $(FREERTOS_KERNEL_DIR)/tasks.c $(FREERTOS_KERNEL_DIR)/list.c $(FREERTOS_KERNEL_DIR)/queue.c \
	  $(FREERTOS_KERNEL_DIR)/event_groups.c $(FREERTOS_KERNEL_DIR)/portable/GCC/ARM_CM3/port.c \
	  $(FREERTOS_KERNEL_DIR)/portable/MemMang/heap_4.c \
	  $(addprefix $(FREERTOS_TCP_DIR)/source/,FreeRTOS_IP.c FreeRTOS_IP_Timers.c FreeRTOS_IP_Utils.c \
	    FreeRTOS_ARP.c FreeRTOS_ICMP.c FreeRTOS_Sockets.c FreeRTOS_Stream_Buffer.c FreeRTOS_TCP_IP.c \
	    FreeRTOS_TCP_Reception.c FreeRTOS_TCP_State_Handling.c FreeRTOS_TCP_Transmission.c \
	    FreeRTOS_TCP_Utils.c FreeRTOS_TCP_WIN.c FreeRTOS_UDP_IP.c FreeRTOS_IPv4.c FreeRTOS_IPv4_Utils.c \
	    FreeRTOS_IPv4_Sockets.c FreeRTOS_TCP_IP_IPv4.c FreeRTOS_TCP_Transmission_IPv4.c \
	    FreeRTOS_TCP_State_Handling_IPv4.c FreeRTOS_TCP_Utils_IPv4.c FreeRTOS_UDP_IPv4.c \
	    FreeRTOS_Routing.c portable/BufferManagement/BufferAllocation_2.c \
	    portable/NetworkInterface/MPS2_AN385/NetworkInterface.c \
	    portable/NetworkInterface/MPS2_AN385/ether_lan9118/smsc9220_eth_drv.c) \
	  $(FREERTOS_SRCS)
	QEMU="$(M3_QEMU)" ./test/qemu-freertos-tls.sh bin/freertos/tls_test

