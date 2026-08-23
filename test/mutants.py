#!/usr/bin/env python3
"""Checks that the suite fails when an invariant is broken.

Run from the repository root: python3 test/mutants.py [name ...]

docs/invariants.md says what must never break, and each entry there
carries a Violation field describing what a breaking change looks like.
This turns those descriptions into edits and checks that some test
actually objects. A test suite that passes on broken code is not
guarding the invariant, whatever its name says.

Each mutant lives in test/mutants/<name>.mut:

    invariant: INV-10
    file: record.c
    catches: unit
    reason: one line on what breaks
    --- old
    <text to find, exactly once>
    --- new
    <text to replace it with>

The runner applies the edit, builds the named target, runs it, and
requires a NONZERO exit. Three outcomes:

  caught     the target failed, so the invariant is guarded
  SURVIVED   the target passed on broken code — a coverage hole
  STALE      the old text is gone, so the mutant no longer applies

STALE is a failure too. A mutant that silently stops matching is worse
than none, because it reports success forever.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "test" / "mutants"


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


def run(name):
    """Apply one mutant, build and run its target, restore, report."""
    path = MUTANTS / f"{name}.mut"
    head, old, new = parse(path)
    target = ROOT / head["file"]
    original = target.read_text()

    if original.count(old) != 1:
        print(f"  STALE    {name}: its 'old' text appears "
              f"{original.count(old)} times in {head['file']}, expected 1")
        return "stale"

    try:
        target.write_text(original.replace(old, new, 1))
        # Touch so make rebuilds: an edit inside the same second as the
        # last build otherwise leaves the binary alone.
        target.touch()
        # A "catches" with a slash is a script to run as-is; otherwise
        # it names a binary under bin/ that make builds first.
        target_is_script = "/" in head["catches"]
        binary = head["catches"] if target_is_script else f"bin/{head['catches']}"
        if not target_is_script:
            built = subprocess.run(["make", binary], cwd=ROOT,
                                   capture_output=True, text=True)
            if built.returncode != 0:
                # A mutant that will not compile proves nothing about the
                # tests, so say that rather than counting it as caught.
                print(f"  SURVIVED {name}: {head['file']} no longer compiles; "
                      f"write an edit that builds")
                return "survived"
        ran = subprocess.run([binary], cwd=ROOT, capture_output=True, text=True)
    finally:
        target.write_text(original)
        target.touch()

    if ran.returncode != 0:
        print(f"  caught   {name} [{head['invariant']}] by {head['catches']}")
        return "caught"
    print(f"  SURVIVED {name} [{head['invariant']}]: {head['catches']} passed "
          f"on broken code")
    print(f"           {head['reason']}")
    return "survived"


def main():
    names = sys.argv[1:] or sorted(p.stem for p in MUTANTS.glob("*.mut"))
    if not names:
        sys.exit("mutants: no mutants in test/mutants/")
    print(f"mutants: {len(names)} to check")
    tally = {"caught": 0, "survived": 0, "stale": 0}
    for name in names:
        tally[run(name)] += 1
    print(f"mutants: {tally['caught']} caught, {tally['survived']} survived, "
          f"{tally['stale']} stale")
    if tally["survived"] or tally["stale"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
