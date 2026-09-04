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

# Every deterministic suite, built and run natively — the tests-only
# half of check, for platform-parity jobs (linux arm64 today) where
# re-building the whole lint toolchain buys nothing. The roster is
# check's own prerequisite list.
.PHONY: suite-check
suite-check: bin/unit bin/unit_ca bin/unit_pq bin/tlsclient bin/tlsclient_ecdsa bin/tlsclient_ca bin/tlsclient_ca_ecdsa bin/tlsclient_pq bin/drbg_test bin/softmul_test bin/rsa_test bin/sha3_test bin/mlkem_test bin/handshake_strict_test bin/handshake_strict_pq bin/x509strict bin/x509strict_ecdsa
	@set -e; for b in unit unit_ca unit_pq drbg_test softmul_test rsa_test sha3_test mlkem_test \
	  handshake_strict_test handshake_strict_pq x509strict x509strict_ecdsa; do \
	  echo "== $$b (native)"; ./bin/$$b; done
	$(MAKE) wycheproof



# The Cortex-M3 lane: the cross-check suite roster, built with the Arm
# GNU toolchain (newlib + rdimon semihosting) and run one binary at a
# time on QEMU's MPS2-AN385 — the same core lint-wide-multiply gates by
# disassembly, executing instead of being read. drbg_test is one of two
# roster differences from the mips lane: it drives a diffspec child
# over pipe/dup2, which bare metal has no words for, and
# handshake_sequence_test forks the same child; every Linux lane runs
# both.
.PHONY: m3-check
m3-check:
	@[ -n "$(M3_CC)" ] || { \
	  [ -n "$$CI" ] && { echo "m3-check: arm-none-eabi-gcc missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP m3-check: no arm-none-eabi-gcc (see ARM_GNU_VERSION in tools/toolchain.env)"; exit 0; }
	@[ -n "$(M3_QEMU)" ] || { \
	  [ -n "$$CI" ] && { echo "m3-check: qemu-system-arm missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP m3-check: no qemu-system-arm"; exit 0; }
	@mkdir -p bin/m3
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/unit test/unit_test.c $(SRCS)
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/rsa_test test/rsa_test.c rsa.c rsa_mont.c sha256.c ct.c
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/sha3_test test/sha3_test.c sha3.c ct.c
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/mlkem_test test/mlkem_test.c mlkem.c mlkem_poly.c sha3.c ct.c
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/handshake_strict_test test/handshake_strict_test.c handshake_parser.c buf.c
	$(M3_CC) $(M3_FLAGS) -I. -o bin/m3/x509strict_test $(X509STRICT_SRC) rsa.c rsa_mont.c
	$(M3_CC) $(M3_FLAGS) -DCH_PIN_ECDSA -I. -o bin/m3/x509strict_ecdsa $(X509STRICT_SRC) p256.c
	@$(call wycheproof_fetch,m3 wycheproof); \
	python3 test/gen_wycheproof.py $(WYCHEPROOF_DIR) bin/wycheproof_vectors.h && \
	$(M3_CC) $(M3_FLAGS) -I. -Ibin -o bin/m3/wycheproof_test test/wycheproof_test.c \
	  x25519.c chacha20.c poly1305.c aead.c hkdf.c sha256.c p256.c rsa.c rsa_mont.c mlkem.c mlkem_poly.c sha3.c buf.c ct.c
	@set -e; for b in unit rsa_test sha3_test mlkem_test handshake_strict_test x509strict_test x509strict_ecdsa; do \
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
	  [ -n "$$CI" ] && { echo "freertos-check: arm-none-eabi-gcc missing on CI; the gate must not skip"; exit 1; }; \
	  echo "SKIP freertos-check: no arm-none-eabi-gcc (see ARM_GNU_VERSION in tools/toolchain.env)"; exit 0; }
	@[ -n "$(M3_QEMU)" ] || { \
	  [ -n "$$CI" ] && { echo "freertos-check: qemu-system-arm missing on CI; the gate must not skip"; exit 1; }; \
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
	  ct.c sha256.c hkdf.c chacha20.c poly1305.c aead.c x25519.c pem.c x509.c x509_der.c x509_ca.c \
	  buf.c record.c keysched.c io.c handshake_message.c handshake_parser.c handshake_record.c \
	  session.c handshake_auth.c handshake.c handshake_post.c tls.c softmul.c rsa.c rsa_mont.c p256.c
	QEMU="$(M3_QEMU)" ./test/qemu-freertos-tls.sh bin/freertos/tls_test

