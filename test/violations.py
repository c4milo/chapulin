#!/usr/bin/env python3
"""Checks that the suite fails when an invariant is broken.

Run from the repository root: python3 test/violations.py [name ...]

docs/invariants.md says what must never break, and each entry there
carries a Violation field describing what a breaking change looks like.
This turns those descriptions into edits and checks that some test
actually objects. A test suite that passes on broken code is not
guarding the invariant, whatever its name says.

make lint-invariants checks that the code does not violate an
invariant. This checks that a test notices when it does.

Each violation lives in test/violations/<name>.violation:

    invariant: INV-10
    file: record.c
    catches: unit
    builds: bin/unit          (optional; required when catches is a script,
                               which builds nothing of its own)
    reason: one line on what breaks
    --- old
    <text to find, exactly once>
    --- new
    <text to replace it with>

The runner applies the edit, builds the named target, runs it, and
requires a NONZERO exit. Three outcomes:

  caught     the target failed, so the invariant is guarded
  unguarded  the target passed on broken code — a coverage hole
  STALE      the old text is gone, so the violation no longer applies

STALE is a failure too. A violation that silently stops matching is
worse than none, because it reports success forever.
"""

import os
import pathlib
import subprocess
import time
import sys

# Each violation rebuilds and reruns its target, worth watching in
# real time, so flush per line rather than buffering until exit.
sys.stdout.reconfigure(line_buffering=True)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIOLATIONS = ROOT / "test" / "violations"


def parse(path):
    head, old, new, where = {}, [], [], "head"
    for line in path.read_text().splitlines():
        if line.strip() == "--- old":
            where = "old"
        elif line.strip() == "--- new":
            where = "new"
        elif where == "head":
            if line.strip() and not line.startswith("#"):
                key, _, value = line.partition(":")
                head[key.strip()] = value.strip()
        elif where == "old":
            old.append(line)
        else:
            new.append(line)
    for key in ("invariant", "file", "catches", "reason"):
        if key not in head:
            sys.exit(f"{path.name}: missing '{key}'")
    return head, "\n".join(old).strip("\n"), "\n".join(new).strip("\n")


def tail(output, lines=5):
    """The last few non-blank lines of a failed step's output, indented
    to sit under the ERROR line that quotes them."""
    kept = [l for l in (output or "").splitlines() if l.strip()][-lines:]
    return "".join(f"           {l}\n" for l in kept)


def run(name):
    """Apply one violation, build and run its target, restore, report."""
    path = VIOLATIONS / f"{name}.violation"
    head, old, new = parse(path)
    target = ROOT / head["file"]
    original = target.read_text()

    if original.count(old) != 1:
        print(f"  STALE    {name}: its 'old' text appears "
              f"{original.count(old)} times in {head['file']}, expected 1")
        return "stale"

    # A "catches" with a slash is a script run as-is; otherwise it names
    # a binary under bin/. Either way the target must be built from the
    # source under test; a script that builds nothing of its own
    # (test/e2e.sh runs no make) needs a 'builds' line saying what to.
    target_is_script = "/" in head["catches"]
    binary = head["catches"] if target_is_script else f"bin/{head['catches']}"
    builds = head.get("builds", "" if target_is_script else binary).split()
    if target_is_script and not builds:
        print(f"  STALE    {name}: a script target needs a 'builds' line "
              f"naming what to rebuild from the edited source")
        return "stale"

    def rebuild_and_run():
        """Rebuild the prerequisites from the source on disk now, then run
        the target. Returns (built_ok, run_returncode, output), where
        output is the failed step's stderr (stdout when stderr is
        empty) — the baseline error quotes it, because the target's
        own message otherwise never reaches the log.

        make decides staleness by whole-second mtimes, and a prior
        violation's edit-then-restore plus this one's edit can all land in
        one tick — leaving a binary make thinks is current but that was
        built from other source. So the edited file's mtime is pushed a
        minute into the future before each build: make then always sees
        it as newer than any binary and rebuilds, and the verdict depends
        on the source rather than on build-cache timing. A minute ahead of
        the object files, not deleting them, keeps the rebuild
        incremental — a delete would recompile every source each time."""
        future = time.time() + 60
        os.utime(target, (future, future))
        if builds:
            b = subprocess.run(["make", *builds], cwd=ROOT,
                               capture_output=True, text=True)
            if b.returncode != 0:
                return False, None, b.stderr or b.stdout
        r = subprocess.run([binary], cwd=ROOT, capture_output=True, text=True)
        return True, r.returncode, r.stderr or r.stdout

    # Baseline: the target must PASS on unedited source in this
    # environment before its verdict on an edit means anything. Without
    # it, a target that fails for an unrelated reason — a missing binary,
    # an absent oracle — makes the edit look caught when it was never
    # compiled in. "Break X, expect failure" says nothing unless X
    # demonstrably passes first.
    base_built, base_rc, base_output = rebuild_and_run()
    if not base_built:
        print(f"  ERROR    {name}: {' '.join(builds)} does not build on clean "
              f"source; cannot establish a baseline")
        print(tail(base_output), end="")
        return "error"
    if base_rc != 0:
        print(f"  ERROR    {name}: {head['catches']} fails on unedited source "
              f"(exit {base_rc}); its verdict on an edit would be meaningless")
        print(tail(base_output), end="")
        return "error"

    try:
        target.write_text(original.replace(old, new, 1))
        built, rc, _ = rebuild_and_run()
        if not built:
            # An edit that will not compile proves nothing about the
            # tests, so say that rather than counting it as caught.
            print(f"  unguarded {name}: {head['file']} no longer compiles; "
                  f"write an edit that builds")
            return "unguarded"
    finally:
        target.write_text(original)
        target.touch()
        # The mutation build future-dated the source, so the binaries it
        # produced sit AHEAD of the restored source's mtime and make
        # would keep them forever — a later `make check` then runs a
        # binary built from the mutant. Delete them so the next build
        # starts from the restored source. (This is how a poisoned
        # bin/rsa_test once failed a full check an hour after the
        # violation run that made it.)
        for b in builds:
            if b.startswith("bin/"):
                (ROOT / b).unlink(missing_ok=True)
        if not target_is_script and binary.startswith("bin/"):
            (ROOT / binary).unlink(missing_ok=True)

    if rc != 0:
        print(f"  caught   {name} [{head['invariant']}] by {head['catches']}")
        return "caught"
    print(f"  unguarded {name} [{head['invariant']}]: {head['catches']} passed "
          f"on broken code")
    print(f"           {head['reason']}")
    return "unguarded"


# The fast tier for the PR lane is the targets that run in seconds: the
# unit suite, the strictness parsers, rsa_test. Left out are the ones
# whose single run is expensive — the exhaustive handshake enumeration
# (minutes), the end-to-end suite (needs live servers), and the
# differential (each run drives ~6000 oracle comparisons, so a baseline
# and a mutation pass together are ~30s per violation). The tier follows
# the target, so no per-violation field drifts from what the check runs.
FAST_TARGETS = {"unit", "unit_ca", "x509strict", "x509strict_ecdsa",
                "rsa_test", "drbg_test", "handshake_strict_test"}


def catches_of(name):
    return parse(VIOLATIONS / f"{name}.violation")[0]["catches"]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    tier = next((a[len("--tier="):] for a in sys.argv[1:]
                 if a.startswith("--tier=")), None)
    names = args or sorted(p.stem for p in VIOLATIONS.glob("*.violation"))
    if tier == "fast":
        names = [n for n in names if catches_of(n) in FAST_TARGETS]
    elif tier == "slow":
        names = [n for n in names if catches_of(n) not in FAST_TARGETS]
    elif tier is not None:
        sys.exit(f"test-invariants: unknown --tier={tier} (want fast or slow)")
    if not names:
        sys.exit("test-invariants: nothing in test/violations/")
    print(f"test-invariants: {len(names)} violations to check")
    tally = {"caught": 0, "unguarded": 0, "stale": 0, "error": 0}
    for name in names:
        tally[run(name)] += 1
    print(f"test-invariants: {tally['caught']} caught, "
          f"{tally['unguarded']} unguarded, {tally['stale']} stale, "
          f"{tally['error']} error")
    if tally["unguarded"] or tally["stale"] or tally["error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
