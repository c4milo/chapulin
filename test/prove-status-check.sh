#!/usr/bin/env bash
# Checks that proof/run.sh reports each harness's own verdict when wait
# and kill -0 answer for another process (INV-75). bash 5.2 forgets the
# status of a job that ended once a new child of the shell takes the
# job's process id. The kernel gives an id out again sooner where pid_max
# is low, 32768 in a container, and a run of the fast tier forks
# thousands of children. wait then answers 127 or the new child's
# status, and kill -0 answers for the new child.
#
# This check runs proof/run.sh's own code: every line above its first
# launch line, and its report loop from the line FAIL=0 to its end. It
# writes three launch lines of its own between them, and before those it
# defines wait and kill as shell functions, which bash calls in place of
# the builtins. wait answers STATUS_WAIT_ANSWER once the job ends, and
# kill -0 finds every process alive, as a reused process id makes it.
# A stand-in for cbmc gives each harness a verdict by its name:
#   - status_pass verifies and exits 0;
#   - status_crash prints VERIFICATION SUCCESSFUL and exits 1, as a cbmc
#     that dies after its verdict does;
#   - status_fail refutes a property and exits 10;
#   - status_killed prints VERIFICATION SUCCESSFUL and kills its job
#     before the job writes its status, as a signal can.
# Before each run the check writes a status of 0 for status_killed, as
# an earlier run of the same name leaves one. Under each of the two
# answers, 127 and 0, the run must report status_pass verified and the
# other three FAILED, exit 1, and end in STATUS_SECONDS seconds. An
# admission loop that counts an ended job as alive waits for it until
# that time.
#
# What this does not check: that bash forgets a status at all, which
# needs a reused process id, and the launch lines and cache of the real
# run, which the stand-in cbmc never reads.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

STATUS_SECONDS=30

work=$(mktemp -d "${TMPDIR:-/tmp}/prove-status.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/proof"

first=$(grep -n '^launch ' proof/run.sh | head -1 | cut -d: -f1)
report=$(grep -n '^FAIL=0$' proof/run.sh | head -1 | cut -d: -f1)
if [ -z "$first" ] || [ -z "$report" ] || [ "$first" -ge "$report" ]; then
    echo "prove-status: proof/run.sh has no launch line before a FAIL=0 line"
    exit 1
fi

{
    head -n $((first - 1)) proof/run.sh
    cat <<'EOF'
wait() {
    builtin wait "$@" 2>/dev/null
    return "$STATUS_WAIT_ANSWER"
}
kill() {
    if [ "$1" = -0 ]; then
        return 0
    fi
    builtin kill "$@"
}
launch fast full status_pass 2 ""
launch fast full status_crash 2 ""
launch fast full status_fail 2 ""
launch fast full status_killed 2 ""
EOF
    tail -n +"$report" proof/run.sh
} > "$work/proof/run.sh"

cat > "$work/cbmc" <<'EOF'
#!/usr/bin/env bash
# The check's stand-in for cbmc: a verdict for each harness by its name.
case "${1:-}" in
--version)
    echo "cbmc stand-in"
    exit 0
    ;;
*/status_pass_harness.c)
    echo "** 0 of 1 failed (1 iterations)"
    echo "VERIFICATION SUCCESSFUL"
    exit 0
    ;;
*/status_crash_harness.c)
    echo "** 0 of 1 failed (1 iterations)"
    echo "VERIFICATION SUCCESSFUL"
    exit 1
    ;;
*/status_fail_harness.c)
    echo "** 1 of 1 failed (1 iterations)"
    echo "VERIFICATION FAILED"
    exit 10
    ;;
*/status_killed_harness.c)
    echo "** 0 of 1 failed (1 iterations)"
    echo "VERIFICATION SUCCESSFUL"
    kill -KILL "$PPID"
    exit 0
    ;;
esac
echo "cbmc stand-in: no verdict for $*" >&2
exit 2
EOF
chmod +x "$work/cbmc"

# Runs the copy with wait answering $1, and requires the four verdicts.
# set -m gives the run a process group of its own, so the time limit
# stops the run and every job it started. The verdicts are on standard
# output. bash writes its notice of the killed job to standard error,
# where it would split a verdict's line.
check_answer() {
    local answer="$1" out="$work/out-$1" seconds=0 rc
    mkdir -p "$work/proof/results"
    echo 0 > "$work/proof/results/status_killed.rc"
    set -m
    STATUS_WAIT_ANSWER="$answer" CBMC="$work/cbmc" PROVE_NO_CACHE=1 PROVE_JOBS=1 \
        PROVE_SOLVER=builtin bash "$work/proof/run.sh" fast > "$out" 2> "$out.err" &
    local pid=$!
    set +m
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$seconds" -ge "$STATUS_SECONDS" ]; then
            kill -TERM -- "-$pid" 2>/dev/null
            echo "prove-status: with wait answering $answer, run.sh did not end in" \
                "$STATUS_SECONDS s; it counts an ended job as alive"
            return 1
        fi
        sleep 1
        seconds=$((seconds + 1))
    done
    wait "$pid"
    rc=$?
    local bad=0
    if ! grep -q '^status_pass  *\*\* 0 of 1 failed' "$out"; then
        echo "prove-status: with wait answering $answer, status_pass is not verified"
        bad=1
    fi
    if ! grep -q '^status_crash  *FAILED' "$out"; then
        echo "prove-status: with wait answering $answer, status_crash is not FAILED"
        bad=1
    fi
    if ! grep -q '^status_fail  *FAILED' "$out"; then
        echo "prove-status: with wait answering $answer, status_fail is not FAILED"
        bad=1
    fi
    if ! grep -q '^status_killed *FAILED' "$out"; then
        echo "prove-status: with wait answering $answer, status_killed is not FAILED"
        bad=1
    fi
    if [ "$rc" -ne 1 ]; then
        echo "prove-status: with wait answering $answer, run.sh exited $rc, not 1"
        bad=1
    fi
    if [ "$bad" -ne 0 ]; then
        sed 's/^/  /' "$out" "$out.err"
    fi
    return "$bad"
}

status=0
check_answer 127 || status=1
check_answer 0 || status=1
if [ "$status" -eq 0 ]; then
    echo "prove-status: run.sh reports each job's own verdict when wait answers 127 or 0" \
        "and kill -0 finds every process alive"
fi
exit "$status"
