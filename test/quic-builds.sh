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
# fails is the preprocessor rule and not some later compile error. The
# second name is the object the GHASH check below reads.
tu=$(mktemp -t chapulin_cfg_XXXXXX).c
gcm_obj=$(mktemp -t chapulin_gcm_XXXXXX).o
trap 'rm -f "$tu" "${tu%.c}" "$gcm_obj" "${gcm_obj%.o}"' EXIT
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

# The suite over QUIC: quic_packet.c protects Handshake and 1-RTT packets
# and their headers with the suite TLS negotiated (RFC 9001 sections 5.3
# and 5.4.3), so under -DCH_SUITE_AES_GCM it hands AES traffic keys. It
# compiles with AES=hw and CH_NATIVE_AES, and without the vendor
# statement ct.h refuses it, as it refuses every suite build: the file
# itself, not only ct.h's own translation unit above, is what is checked.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES quic_packet.c; then
    echo "quic-builds: quic_packet.c under the suite with AES=hw and CH_NATIVE_AES must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM -DCH_AES_HW quic_packet.c 2>/dev/null; then
    echo "quic-builds: a QUIC suite build without CH_NATIVE_AES compiled; ct.h must refuse it" >&2
    exit 1
fi

# The AES=soft cipher under the suite define: quic_aes_soft.c refuses it
# itself, beside ct.h's refusal, because its S-box is indexed with the key
# and a suite build hands AES a traffic key. The file reads no ct.h, so
# this is the one line that stops a tree with its own build system from
# pairing them. Without the suite the same file compiles, AES-256
# reference included, so what fails is the refusal and nothing else.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_AES_256_TEST \
    quic_aes_soft.c; then
    echo "quic-builds: quic_aes_soft.c with its AES-256 reference must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM \
    -DCH_NATIVE_AES quic_aes_soft.c 2>/dev/null; then
    echo "quic-builds: quic_aes_soft.c under -DCH_SUITE_AES_GCM compiled; it must refuse the suite" >&2
    exit 1
fi

# The suite in a raw or ca client: handshake_message.c refuses it, because
# that client offers ChaCha20 alone (docs/decisions.md entry 45). The
# same flags compile for a TRUST=webpki client, which offers both suites,
# and for a build with a server role, whose server selects AES.
suite_flags=(-std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_AES_HW -DCH_NATIVE_AES)
if "$cc" "${suite_flags[@]}" handshake_message.c 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM in a raw client compiled; handshake_message.c must refuse it" >&2
    exit 1
fi
for role in -DCH_TRUST_WEBPKI -DCH_ROLE_SERVER; do
    if ! "$cc" "${suite_flags[@]}" "$role" handshake_message.c; then
        echo "quic-builds: handshake_message.c with the suite and $role must compile" >&2
        exit 1
    fi
done

# AES=hw's GHASH. quic_gcm.c compiled with -DCH_AES_HW must call the two
# entries quic_ghash_hw.c defines, and compiled without it must call
# neither. The first half is what refuses an AES=hw object that runs the
# portable multiply under the AES=hw name: quic_ghash_hw.c would still
# link and define two functions nobody calls, and bin/ghash_equiv_test
# would still pass, because the portable GHASH computes the same bytes.
# quic_gcm.c names no intrinsic, so it compiles here without the flags
# that turn the instructions on. nm lists an object's undefined symbols,
# and the match is anchored at the end of the line because a Mach-O
# object prefixes each name with an underscore.
ghash_calls() { # $@ = extra flags: the quic_ghash_hw.c entries quic_gcm.c calls, on one line
    "$cc" -std=c11 -I. -c -o "$gcm_obj" -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING "$@" quic_gcm.c ||
        return 1
    nm -u "$gcm_obj" | grep -oE 'gcm_(multiply_by_subkey|hash_data)_hw$' | sort -u | tr '\n' ' '
}
if ! hw_calls=$(ghash_calls -DCH_AES_HW); then
    echo "quic-builds: quic_gcm.c under -DCH_AES_HW must compile" >&2
    exit 1
fi
if [ "$hw_calls" != "gcm_hash_data_hw gcm_multiply_by_subkey_hw " ]; then
    echo "quic-builds: quic_gcm.c under -DCH_AES_HW calls [$hw_calls] of quic_ghash_hw.c;" \
        "it must call gcm_multiply_by_subkey_hw and gcm_hash_data_hw" >&2
    exit 1
fi
if ! soft_calls=$(ghash_calls); then
    echo "quic-builds: quic_gcm.c without -DCH_AES_HW must compile" >&2
    exit 1
fi
if [ -n "$soft_calls" ]; then
    echo "quic-builds: quic_gcm.c without -DCH_AES_HW calls $soft_calls;" \
        "only an AES=hw object carries quic_ghash_hw.c" >&2
    exit 1
fi
