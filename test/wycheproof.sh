#!/usr/bin/env bash
# The catch target for the Wycheproof violations in test/violations/.
# test/violations.py runs a script by path with no arguments and reads its
# exit status, and a make target is not a path, so this is the path. It
# regenerates the vectors and runs every Wycheproof test over the sources
# on disk, which are the edited sources while a violation is applied; a
# nonzero exit is a test objecting. A test is skipped when it passed
# before on the same inputs, so a violation here shows that the skip still
# sees the edit.
cd "$(dirname "$0")/.." || exit 1
exec make -s wycheproof
