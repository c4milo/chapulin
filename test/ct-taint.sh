#!/bin/sh
# The taint lane as a violation's catch target (test/violations.py): make
# ct-taint, which runs bin/ct_taint_test under Valgrind's Memcheck once for
# each ch_cfg.cpu value that picks a path on this machine (docs/decisions.md
# 155, INV-60). It exits nonzero when Memcheck reports a branch or a memory
# address that a secret decides. Without Valgrind it prints SKIP and exits
# 0, which test/violations.py counts as unguarded, and on CI it fails.
cd "$(dirname "$0")/.." || exit 1
exec make -s ct-taint
