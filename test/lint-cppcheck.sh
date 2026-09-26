#!/usr/bin/env bash
# The catch target for the lint-cppcheck violations in test/violations/.
# test/violations.py runs a script by path with no arguments and reads its
# exit status, and a make target is not a path, so this is the path. It
# runs cppcheck over the sources on disk, which are the edited sources
# while a violation is applied; a nonzero exit is cppcheck objecting.
# cppcheck analyses again only the files that changed and reads the rest
# from its build directory, so a violation here shows that a finding
# spanning two files still appears when only one of them changed.
cd "$(dirname "$0")/.." || exit 1
exec make -s lint-cppcheck
