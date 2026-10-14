#!/usr/bin/env bash
# The catch target for the lint-bench-numbers violation in test/violations/.
# test/violations.py runs a script by path with no arguments and reads its
# exit status, and a make target is not a path, so this is the path. It
# runs the lint over the documents on disk, which are the edited documents
# while a violation is applied; a nonzero exit is the lint objecting.
cd "$(dirname "$0")/.." || exit 1
exec make -s lint-bench-numbers
