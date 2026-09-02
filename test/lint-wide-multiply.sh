#!/usr/bin/env bash
# The catch target for the lint-wide-multiply violations in test/violations/.
# test/violations.py runs a script by path with no arguments and reads its
# exit status, and a make target is not a path, so this is the path. It
# runs the gate over the source on disk, which is the edited source while a
# violation is applied; a nonzero exit is the gate objecting.
cd "$(dirname "$0")/.." || exit 1
exec make -s lint-wide-multiply
