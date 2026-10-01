#!/usr/bin/env bash
# The catch target for the INV-26 violations the compiler refuses rather
# than a lint. test/violations.py runs a script by path with no
# arguments and reads its exit status, and a make target is not a path,
# so this is the path.
#
# bin/quic_driver_test compiles every QUIC_SRCS file and the handshake
# sources the driver calls, so it is the target that fails when a QUIC
# source stops compiling. INV-26 turns a whole class of edit into that
# failure: ch_quic stores no aes_public_key, aes.h leaves the type
# incomplete, and only aes.c, quic_initial.c and quic_retry.c
# include aes_public_key.h, so a write to a field of a key anywhere else
# names a member that does not exist.
#
# test/violations.py counts a build failure under a 'builds' line as
# unguarded rather than caught, because an edit that will not compile
# proves nothing about the tests. A script target builds nothing of its
# own, so here the compiler's refusal is the script's exit status and
# the verdict reads correctly.
#
# It carries a second check for the same reason: ct.h refuses
# -DCH_SUITE_AES_GCM unless the build is a host object (-DCH_CPU_RUNTIME),
# whose caller states the AES instructions' timing in ch_cfg.cpu, or takes
# AES=extern and asserts CH_AES_EXTERN_CONSTANT_TIME, and an #error is a
# compiler refusal rather than a lint. INV-26 states what that build would
# hand AES and why the AES=soft S-box may not be underneath it.
cd "$(dirname "$0")/.." || exit 1

make -s bin/quic_driver_test || exit 1

# One translation unit that reads ct.h and nothing else, so what passes or
# fails is the preprocessor rule and not some later compile error. The
# second name is the object the GHASH check below reads.
tu=$(mktemp -t chapulin_cfg_XXXXXX).c
gcm_obj=$(mktemp -t chapulin_gcm_XXXXXX).o
trap 'rm -f "$tu" "$tu.s" "${tu%.c}" "$gcm_obj" "${gcm_obj%.o}"' EXIT
echo '#include "ct.h"' > "$tu"
cc=${CC:-cc}

# The suite in a host object: it compiles, on this host compiler.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME "$tu"; then
    echo "quic-builds: -DCH_SUITE_AES_GCM in a host object must compile" >&2
    exit 1
fi

# The suite build that takes the AES=soft table a device object defaults
# to: it does not.
if "$cc" -std=c11 -I. -fsyntax-only -DCH_SUITE_AES_GCM "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM on AES=soft compiled; ct.h must refuse it" >&2
    exit 1
fi

# CH_NATIVE_AES, the build's statement before docs/decisions.md 89, stops
# every build that still writes it, a host suite build among them.
for defs in "-DCH_NATIVE_AES" "-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME -DCH_NATIVE_AES"; do
    # shellcheck disable=SC2086 # one define per word
    if "$cc" -std=c11 -I. -fsyntax-only $defs "$tu" 2>/dev/null; then
        echo "quic-builds: $defs compiled; ct.h must refuse CH_NATIVE_AES" >&2
        exit 1
    fi
done

# The suite on AES=extern: the image's ch_aes_block gets the traffic keys,
# so the build states the peripheral's timing with
# CH_AES_EXTERN_CONSTANT_TIME (docs/decisions.md 68). With it the build
# compiles. Without it ct.h refuses the build. The extern statement
# without AES=extern is the AES=soft build, which no statement admits.
if ! "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_AES_EXTERN -DCH_AES_EXTERN_CONSTANT_TIME "$tu"; then
    echo "quic-builds: -DCH_SUITE_AES_GCM with AES=extern and CH_AES_EXTERN_CONSTANT_TIME must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_AES_EXTERN "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM on AES=extern without CH_AES_EXTERN_CONSTANT_TIME compiled;" \
        "ct.h must refuse it" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only \
    -DCH_SUITE_AES_GCM -DCH_AES_EXTERN_CONSTANT_TIME "$tu" 2>/dev/null; then
    echo "quic-builds: -DCH_SUITE_AES_GCM on AES=soft compiled with CH_AES_EXTERN_CONSTANT_TIME;" \
        "ct.h must refuse it" >&2
    exit 1
fi

# The suite over QUIC: quic_packet.c protects Handshake and 1-RTT packets
# and their headers with the suite TLS negotiated (RFC 9001 sections 5.3
# and 5.4.3), so under -DCH_SUITE_AES_GCM it hands AES traffic keys. It
# compiles in a host object, and on the AES=soft table ct.h refuses it, as
# it refuses every suite build: the file itself, not only ct.h's own
# translation unit above, is what is checked.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME quic_packet.c; then
    echo "quic-builds: quic_packet.c under the suite in a host object must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM quic_packet.c 2>/dev/null; then
    echo "quic-builds: a QUIC suite build on AES=soft compiled; ct.h must refuse it" >&2
    exit 1
fi
# The same pair on AES=extern, where the image's ch_aes_block gets those
# keys.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM -DCH_AES_EXTERN -DCH_AES_EXTERN_CONSTANT_TIME quic_packet.c; then
    echo "quic-builds: quic_packet.c under the suite with AES=extern and CH_AES_EXTERN_CONSTANT_TIME" \
        "must compile" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_TRANSPORT_QUIC_NONBLOCKING \
    -DCH_SUITE_AES_GCM -DCH_AES_EXTERN quic_packet.c 2>/dev/null; then
    echo "quic-builds: a QUIC suite build on AES=extern without CH_AES_EXTERN_CONSTANT_TIME compiled;" \
        "ct.h must refuse it" >&2
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
    quic_aes_soft.c 2>/dev/null; then
    echo "quic-builds: quic_aes_soft.c under -DCH_SUITE_AES_GCM compiled; it must refuse the suite" >&2
    exit 1
fi

# The suite in a raw or ca client: handshake_message.c refuses it, because
# that client offers ChaCha20 alone (docs/decisions.md entry 45). The
# same flags compile for a TRUST=webpki client, which offers both suites,
# and for a build with a server role, whose server selects AES.
suite_flags=(-std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME)
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

# The defines that chose the AES instructions when the object was built
# are gone, and aes_block.h stops a build that still writes one rather
# than compile the table in its place. A host object beside AES=extern is
# refused there too: aes_hw.c and aes_extern.c define the same entries. A
# host object compiles over QUIC and under the suite.
block_tu() { # $@ = defines: compiles one file that reads cfg.h and aes_block.h
    printf '#include "cfg.h"\n#include "aes_block.h"\n' > "$tu"
    "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN "$@" "$tu"
}
for gone in -DCH_AES_HW -DCH_AES_RUNTIME; do
    if block_tu -DCH_TRANSPORT_QUIC_NONBLOCKING "$gone" 2>/dev/null; then
        echo "quic-builds: $gone compiled; aes_block.h must refuse it" >&2
        exit 1
    fi
done
if block_tu -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_AES_EXTERN 2>/dev/null; then
    echo "quic-builds: a host object beside AES=extern compiled; aes_block.h must refuse it" >&2
    exit 1
fi
if ! block_tu -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME ||
    ! block_tu -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME; then
    echo "quic-builds: a host object over QUIC and under the suite must compile" >&2
    exit 1
fi

# The table beside the instructions. quic_aes_soft.c compiles in a QUIC
# host object, with the suite and without it, where it defines the two
# aes_soft_ entries and neither of aes_block.h's own, which aes_hw.c holds
# there, and no AES-256. A TCP suite host object holds no table, and the
# file refuses the suite there as it does on AES=soft.
for defs in "-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME" \
    "-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM"; do
    # shellcheck disable=SC2086 # one define per word
    if ! "$cc" -std=c11 -I. -c -o "$gcm_obj" -DCH_RAND_EXTERN $defs quic_aes_soft.c; then
        echo "quic-builds: quic_aes_soft.c in a QUIC host object under $defs must compile" >&2
        exit 1
    fi
    soft_defs=$(nm -g "$gcm_obj" | awk '$2 == "T" {print $3}' | sed 's/^_//' | sort | tr '\n' ' ')
    if [ "$soft_defs" != "aes_soft_cipher_block aes_soft_expand_round_keys " ]; then
        echo "quic-builds: quic_aes_soft.c under $defs defines [$soft_defs];" \
            "it must define aes_soft_cipher_block and aes_soft_expand_round_keys alone" >&2
        exit 1
    fi
done
if "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME \
    quic_aes_soft.c 2>/dev/null; then
    echo "quic-builds: quic_aes_soft.c in a TCP suite host object compiled; it must refuse the suite" >&2
    exit 1
fi

# The host object's GHASH and counter mode. gcm.c must call the two
# entries ghash_hw.c defines and the three gcm_hw.c defines, counter mode
# over whole blocks several at a time and the seal's and the open's
# counter mode and GHASH in one loop, in each host object: a QUIC one,
# which holds the table too and runs a schedule on the cipher it records,
# with and without the suite, and the TCP suite one, which holds no table
# and runs every schedule on the instructions. Compiled for a device
# object it must call none of them. The first half is what refuses a host
# object that runs the portable multiply, the one-block counter loop or
# the two-pass seal on a schedule the instructions run: the instruction
# entries would still link, and bin/ghash_equiv_test would still pass,
# because the portable paths compute the same bytes.
# gcm.c names no intrinsic, so it compiles here without the flags
# that turn the instructions on. It compiles at -O2, as make lib compiles
# it, because gcc at -O0 still emits a static function that nothing
# calls, and the calls inside it with it. nm lists an object's undefined
# symbols, and the match is anchored at the end of the line because a
# Mach-O object prefixes each name with an underscore.
hw_entries='gcm_(multiply_by_subkey|hash_data|counter_blocks|seal_passes|open_passes)_hw$'
hw_want="gcm_counter_blocks_hw gcm_hash_data_hw gcm_multiply_by_subkey_hw gcm_open_passes_hw gcm_seal_passes_hw "
ghash_calls() { # $@ = defines: the instruction entries gcm.c calls, on one line
    "$cc" -std=c11 -O2 -I. -c -o "$gcm_obj" -DCH_RAND_EXTERN "$@" gcm.c || return 1
    nm -u "$gcm_obj" | grep -oE "$hw_entries" | sort -u | tr '\n' ' '
}
for defs in "-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME" \
    "-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM" \
    "-DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM"; do
    # shellcheck disable=SC2086 # one define per word
    if ! host_calls=$(ghash_calls $defs); then
        echo "quic-builds: gcm.c under $defs must compile" >&2
        exit 1
    fi
    if [ "$host_calls" != "$hw_want" ]; then
        echo "quic-builds: gcm.c under $defs calls [$host_calls] of the instruction entries;" \
            "it must call [$hw_want]" >&2
        exit 1
    fi
done
if ! soft_calls=$(ghash_calls -DCH_TRANSPORT_QUIC_NONBLOCKING); then
    echo "quic-builds: gcm.c in a device QUIC object must compile" >&2
    exit 1
fi
if [ -n "$soft_calls" ]; then
    echo "quic-builds: gcm.c in a device QUIC object calls $soft_calls;" \
        "only a host object carries ghash_hw.c and gcm_hw.c" >&2
    exit 1
fi

# gcm_vaes.c's kernels (docs/decisions.md 90), asked of the pinned clang
# for x86-64 and arm64 targets whatever the host, freestanding, as
# test/chacha-builds.sh asks its cross questions, with no flag beyond the
# host object's define:
#
#   - for x86-64, gcm_vaes.c must define the three kernels and run 256-bit
#     VAESENC and VPCLMULQDQ, which its target attribute turns on, while
#     gcm_hw.c holds no 256-bit register, so the rest of the object runs on
#     any x86-64 CPU with AES-NI and PCLMULQDQ;
#   - gcm_hw.c must call none of the kernels while use_vaes answers 0, so
#     no object runs them before the caller's CH_CPU_VAES bit can say the
#     CPU has them;
#   - for arm64, gcm_vaes.c must define nothing.
clang_rv=$(make -s --no-print-directory print-clang-rv)
if [ -z "$clang_rv" ]; then
    echo "quic-builds: no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env" >&2
    exit 1
fi
cross_gcm() { # $1 = target, $2 = source; writes $gcm_obj and $tu.s
    local target=$1 source=$2
    "$clang_rv" -target "$target" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME -c "$source" -o "$gcm_obj" || exit 1
    "$clang_rv" -target "$target" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_RAND_EXTERN -DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME -S "$source" -o "$tu.s" || exit 1
}
vaes_kernels="gcm_counter_blocks_vaes gcm_open_passes_vaes gcm_seal_passes_vaes "
cross_gcm x86_64-unknown-linux-gnu gcm_vaes.c
defined=$(nm "$gcm_obj" | awk '$2 == "T" {print $3}' | sed 's/^_//' | grep _vaes | sort | tr '\n' ' ')
if [ "$defined" != "$vaes_kernels" ] ||
    ! grep -qE 'vaesenc[[:space:]]+%ymm' "$tu.s" || ! grep -qE 'vpclmulqdq[[:space:]].*%ymm' "$tu.s"; then
    echo "quic-builds: gcm_vaes.c for x86-64 defines [$defined]; it must define" \
        "[$vaes_kernels] on 256-bit VAESENC and VPCLMULQDQ" >&2
    exit 1
fi
cross_gcm x86_64-unknown-linux-gnu gcm_hw.c
if grep -q '%ymm' "$tu.s"; then
    echo "quic-builds: gcm_hw.c for x86-64 holds a 256-bit instruction; only gcm_vaes.c may" >&2
    exit 1
fi
if nm -u "$gcm_obj" | grep -q '_vaes$'; then
    echo "quic-builds: gcm_hw.c for x86-64 calls a VAES kernel while use_vaes answers 0" >&2
    exit 1
fi
cross_gcm aarch64-none-elf gcm_vaes.c
if nm "$gcm_obj" | grep -q '_vaes$'; then
    echo "quic-builds: gcm_vaes.c for arm64 defines a kernel; it has a body on x86-64 alone" >&2
    exit 1
fi
