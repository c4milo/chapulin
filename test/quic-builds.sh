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
cd "$(dirname "$0")/.." || exit 1
exec make -s bin/quic_driver_test
