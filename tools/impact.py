#!/usr/bin/env python3
"""Selects the gates a set of changed files can break.

Run from the repository root:

    python3 tools/impact.py [--base REV] [--max-tier T] [--json]
                            [--commands] [path ...]

With paths, those are the changed files. Without them, `git diff
--name-only` against REV (default HEAD) supplies them, together with the
untracked files, so a dirty tree reports what it holds.

The output is a plan: one command per line, grouped, each with the
reason it is in the plan and the tier that already runs it. --commands
prints the commands alone, in the order to run them, and --json prints
the whole plan with the gates each command covers. --max-tier drops the
gates no tier below it runs, so a plan can be compared against the tier
it stands in for.

`make impact` prints the plan and `make impact-run` runs it. The slow
tier costs about half an hour, and most of that is proofs and
differential runs a one-file change cannot break, so the plan exists to
run the part it can.

The rule is over-select, never miss. Every ambiguity resolves toward
running more: a source no list in the tree names selects every gate and
says which path did it, a variable reference inside a make function
expands to its whole value rather than to what the function would keep,
and a root header selects every gate because every test binary lists
every root header as a prerequisite. A plan that runs a gate it did not
have to costs minutes. A plan that drops a gate that would have failed
lets a bad commit land, which is worse than running everything.
Selection is an inner-loop tool and never a landing gate: `make check`
before a commit and `make check-slow` before calling a change done both
stay in force (CLAUDE.md), and CI and the nightly run everything.
docs/impact.md states this.

The tool is four modules, one concern each:

  tools/impact_read.py    reads the mapping out of the tree: the make
                          database, proof/run.sh, test/violations/, the
                          gate wrapper scripts
  tools/impact_map.py     holds it: what each gate compiles, which tier
                          runs it, what each packaged object carries,
                          and which paths no selection may narrow
  tools/impact_select.py  chooses the commands one changed path gates
  tools/impact.py         this file: the command line that runs them

Nothing lists a source. The mapping decays if the Makefile, the launch
lines or the violations stop naming theirs — a Makefile that hid a
source list behind a variable the recipe never names would leave a gate
unselected, which is why a Makefile edit itself selects everything.
"""


import json
import sys

from impact_map import Mapping, TIERS
from impact_read import run
from impact_select import plan


GROUP_ORDER = ["everything", "lint", "tests", "modes", "codegen",
               "differential", "proofs", "violations"]


def render(entries):
    lines = []
    for group in GROUP_ORDER:
        rows = [e for e in entries if e.group == group]
        if not rows:
            continue
        lines.append(f"# {group}")
        # A note carries no command; it says why the group is here.
        notes = [e for e in rows if e.command.startswith("#")]
        rows = [e for e in rows if not e.command.startswith("#")]
        for e in notes:
            lines.append(f"  {e.command}")
        # Pad to the widest command, but never past 46 columns: one long
        # build line would otherwise push every reason off the screen.
        width = min(max([len(e.command) for e in rows], default=0), 46)
        for e in rows:
            lines.append(f"  [{e.tier:<7}] {e.command.ljust(width)}  # {e.reason}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def changed_paths(base):
    """Every path the working tree changed against base, plus every
    untracked file. An inner loop runs on a dirty tree, so a plan read
    from the commit alone would miss the file being edited.

    `git diff <base>` compares base to the working tree, so it already
    carries the staged and unstaged changes; only untracked files need
    the second command. --exclude-standard leaves build output and the
    fetched checkouts .gitignore names out of the plan."""
    paths = set()
    for args in (("git", "diff", "--name-only", base),
                 ("git", "ls-files", "--others", "--exclude-standard")):
        r = run(*args)
        if r.returncode != 0:
            sys.exit(f"impact: {' '.join(args)} failed: {r.stderr.strip()}")
        paths |= {p for p in r.stdout.split("\n") if p}
    return sorted(paths)


def main(argv):
    base = "HEAD"
    form = "plan"
    max_tier = "nightly"
    paths = []
    rest = list(argv)
    while rest:
        arg = rest.pop(0)
        if arg == "--base":
            if not rest:
                sys.exit("impact: --base needs a revision")
            base = rest.pop(0)
        elif arg.startswith("--base="):
            base = arg.split("=", 1)[1]
        elif arg.startswith("--max-tier="):
            max_tier = arg.split("=", 1)[1]
            if max_tier not in TIERS:
                sys.exit(f"impact: --max-tier wants one of {', '.join(TIERS)}")
        elif arg in ("--json", "--commands"):
            form = arg[2:]
        elif arg.startswith("--"):
            sys.exit(f"impact: unknown option {arg}")
        else:
            paths.append(arg)

    mapping = Mapping()
    if not paths:
        paths = changed_paths(base)
    if not paths:
        # --commands is read by a shell, so an empty plan has to be no
        # lines at all: a note on stdout would run as a command.
        if form == "plan":
            print(f"impact: nothing changed against {base}, so the plan "
                  f"is empty")
        elif form == "json":
            print(json.dumps({"changed": [], "plan": []}, indent=2))
        return 0
    entries = plan(paths, mapping)
    # --max-tier drops the gates no tier below it runs, which is how a
    # selected set is compared against the tier it stands in for. It
    # narrows the plan, so it is never the default.
    keep = TIERS[: TIERS.index(max_tier) + 1]
    entries = [e for e in entries
               if e.tier in keep or e.command.startswith("#")]
    if form == "json":
        print(json.dumps({"changed": sorted(set(paths)),
                          "plan": [e.as_dict() for e in entries]}, indent=2))
        return 0
    if form == "commands":
        # Group order, so the lints answer before the builds: a run that
        # stops early should stop on the cheapest verdict available.
        for group in GROUP_ORDER:
            for entry in entries:
                if entry.group == group and not entry.command.startswith("#"):
                    print(entry.command)
        return 0
    print(f"# impact: {len(paths)} changed path(s), "
          f"{len([e for e in entries if not e.command.startswith('#')])} "
          f"command(s) to run")
    print(render(entries), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
