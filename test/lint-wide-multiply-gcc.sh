#!/usr/bin/env bash
# The catch target for the violations only gcc's codegen shows. gcc fused
# ct.h's 16x16 pieces back into a widening multiply where clang kept them
# apart (https://github.com/c4milo/chapulin/issues/106), so the clang check
# test/lint-wide-multiply.sh runs passes the mutant that puts that form
# back. This runs the same check under the gcc lint-wide-multiply-gcc
# resolves -- the Arm GNU release M3_CC names -- over the source on disk,
# which is the edited source while a violation is applied; a nonzero exit
# is lint-wide-multiply-gcc objecting, and a missing gcc is a failure, not a
# skip.
cd "$(dirname "$0")/.." || exit 1
exec make -s lint-wide-multiply-gcc
