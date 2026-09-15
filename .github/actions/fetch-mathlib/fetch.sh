#!/bin/bash
# Run from spec/: clone the packages lake-manifest.json pins and download
# Mathlib's compiled files. The last line checks for the one file the
# Makefile's REQUIRE_MATHLIB reads, so a download that produced nothing
# fails here, by name, rather than as an hours-long Mathlib compile.
set -euo pipefail

lake exe cache get
olean=.lake/packages/mathlib/.lake/build/lib/lean/Mathlib.olean
[ -f "$olean" ] || { echo "fetch-mathlib: lake exe cache get left no $olean"; exit 1; }
