#!/usr/bin/env bash
# The catch target for the TRUST=webpki frame-budget violation in
# test/violations/. test/violations.py runs a script by path with no
# arguments and reads its exit status, and a make target is not a path,
# so this is the path. It runs the lint over the sources on disk, which
# are the edited sources while a violation is applied; a nonzero exit is
# the lint objecting.
#
# The TRUST=webpki object packages sources the default object filters
# out -- p256.c under an rsa mode, and the five chain verifiers -- so this
# is the one frame-budget check that compiles them. This runs the command
# make check's check-stack-webpki target runs, and tools/impact.py runs
# that target for a source the object packages; the two have to stay the
# same command, and test/impact_test.py compares them.
cd "$(dirname "$0")/.." || exit 1
exec make -s lint-stack TRUST=webpki
