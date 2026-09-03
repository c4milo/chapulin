#!/usr/bin/env bash
# Runs one CBMC harness through proof/run.sh's own launch and exits
# nonzero unless it verifies, so a test/violations/*.violation can name
# a proof as the test that must object to its edit:
#
#     catches: proof/prove-one.sh x25519_tail
#
# run.sh already runs a single harness when PROVE_ONLY names it, with
# the launch line's flags, unwind bounds, weight and solver, so this
# wraps that call rather than composing a second cbmc command line that
# could drift from the first.
#
# Contract:
#   $1 is the harness name as its launch line in run.sh spells it
#   (x25519_step, not proof/x25519_step_harness.c). run.sh exits 1 when
#   no launch line matches, so a misspelt name fails instead of passing.
#
#   Exit 0 when run.sh reports VERIFICATION SUCCESSFUL, or finds the
#   verdict cached. The cache key hashes the preprocessed sources, so an
#   edited x25519.c never reuses a verdict proven on the unedited one.
#
#   Exit nonzero when a property fails, a callee has no body, the solver
#   dies under run.sh's address-space cap, or cbmc is not installed.
#
#   Exit 124, coreutils timeout's number, when the run passes
#   PROVE_WALL_SECONDS (default 3600) of wall clock with no verdict.
#   run.sh has no clock of its own -- CI's job timeout is its budget --
#   and a mutant that stops a formula converging would otherwise hold
#   test/violations.py until the nightly job's timeout cancels it, and
#   every other violation's verdict with it. The runner counts 124 as
#   ERROR, never caught: a formula that did not converge refuted
#   nothing (https://github.com/c4milo/chapulin/issues/144). The
#   slowest run measured
#   under this wrapper is x25519_step refuting its mutant: 829 s under
#   kissat on a 10-core development machine, against 513 s for the
#   proof itself (proof/run.sh), and a CI runner is slower.
#
#   CBMC, PROVE_SOLVER, PROVE_NO_CACHE and PROVE_JOBS pass through to
#   run.sh unchanged.
#
# test/violations.py runs the target on the unedited source first and
# requires exit 0 before it trusts the verdict on an edit, so a machine
# without cbmc reports ERROR for the violation, never caught.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

if [ $# -ne 1 ]; then
    echo "usage: proof/prove-one.sh <harness>" >&2
    exit 2
fi
name="$1"
budget="${PROVE_WALL_SECONDS:-3600}"

# set -m gives each background job its own process group, so one signal
# reaches run.sh, the subshell it forks the checker in, cbmc and the
# solver together. A plain kill would stop run.sh and leave the solver
# running to its own end.
set -m
PROVE_ONLY="$name" ./proof/run.sh all &
run_pid=$!
(
    sleep "$budget"
    kill -TERM -- "-$run_pid" 2>/dev/null
) &
watchdog_pid=$!
wait "$run_pid"
rc=$?
if kill -0 "$watchdog_pid" 2>/dev/null; then
    # run.sh finished on its own; the watchdog is still asleep.
    kill -TERM -- "-$watchdog_pid" 2>/dev/null
else
    echo "prove-one: $name returned no verdict in $budget s; the last lines of its log:"
    tail -3 "proof/results/$name.log" 2>/dev/null
    rc=124
fi
exit "$rc"
