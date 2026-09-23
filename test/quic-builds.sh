#!/usr/bin/env bash
# The catch target for the INV-26 violations the compiler refuses rather
# than a lint. test/violations.py runs a script by path with no
# arguments and reads its exit status, and a make target is not a path,
# so this is the path.
#
# bin/quic_driver_test compiles every QUIC_SRCS file and the handshake
# sources the driver calls, so it is the target that fails when a QUIC
# source stops compiling. INV-26 turns a whole class of edit into that
# failure: ch_quic stores no aes_public_key, quic_aes.h leaves the type
# incomplete, and only quic_aes.c, quic_initial.c and quic_retry.c
# include quic_aes_key.h, so a write to a field of a key anywhere else
# names a member that does not exist.
#
# test/violations.py counts a build failure under a 'builds' line as
# unguarded rather than caught, because an edit that will not compile
# proves nothing about the tests. A script target builds nothing of its
# own, so here the compiler's refusal is the script's exit status and
# the verdict reads correctly.
#
# It carries a second check for the same reason: ct.h refuses
# -DCH_SUITE_AES_GCM unless the build also takes AES=hw and asserts
# CH_NATIVE_AES, and an #error is a compiler refusal rather than a lint.
# INV-26 states what that build would hand AES and why the AES=soft S-box
# may not be underneath it.
cd "$(dirname "$0")/.." || exit 1

make -s bin/quic_driver_test || exit 1

# One translation unit that reads ct.h and nothing else, so what passes or
# fails is the preprocessor rule and not some later compile error.
tu=$(mktemp -t chapulin_cfg_XXXXXX).c
trap 'rm -f "$tu" "${tu%.c}"' EXIT
echo '#include "ct.h"' > "$tu"
cc=${CC:-cc}

# The suite build that states both: it compiles.
if ! "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES "$tu"; then
    echo "quic-builds: -DCH_SUITE_AES_GCM with AES=hw and CH_NATIVE_AES must compile" >&2
    exit 1
fi

# The suite build that takes whatever AES the axis defaulted to: it does not.
if "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM without CH_AES_HW compiled; ct.h must refuse it" >&2
    exit 1
fi

# The two refusals are checked one at a time, so a build that dropped one
# of them cannot hide behind the other. First the vendor statement without
# the instructions.
if "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_NATIVE_AES "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM without CH_AES_HW compiled; ct.h must refuse it" >&2
    exit 1
fi

# Then the instructions with nobody asserting their timing.
if "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_AES_HW "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM without CH_NATIVE_AES compiled; ct.h must refuse it" >&2
    exit 1
fi

# The suite over QUIC: quic_packet.c refuses the pair, because it runs
# ChaCha20-Poly1305 alone and RFC 9001 section 5.3 makes the packet AEAD
# the suite TLS negotiated. The same file compiles under QUIC without the
# suite, so what fails is that refusal and not a missing define.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC \
    -DCH_AES_HW -DCH_NATIVE_AES quic_packet.c; then
    echo "quic-builds: quic_packet.c under QUIC without the suite must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC \
    -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES quic_packet.c 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM with CH_TRANSPORT_QUIC compiled; quic_packet.c must refuse it" >&2
    exit 1
fi
