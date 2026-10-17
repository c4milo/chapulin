#!/usr/bin/env python3
"""Check that each sharded CI job runs every part of its set once.

A job that runs a set in N parts passes "$SHARD/N" to VIOLATION_SHARD
(test/violations.py --shard) or to REACH_SHARD (proof/coverage.py
--shard), and its matrix lists the values of SHARD. A list that leaves out
a value never runs that part, and the job stays green on the parts that
it ran. So for each workflow job this check requires:

- a job with a shard matrix passes "$SHARD/N" in a step;
- the matrix's shard list is 1 to N, each value once;
- each step that reads $SHARD sets it from matrix.shard.

Then it calls each tool's own shard function for K from 1 to N, and
requires that each name of the set goes to exactly one part. For
test/violations.py that holds for every selection its class and tier
options make, since a Makefile target passes one of them.

Run through `make lint-matrix`.
"""

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
TOOLS = {"VIOLATION_SHARD": "test/violations.py",
         "REACH_SHARD": "proof/coverage.py"}
PASSES = re.compile(r'\b(' + "|".join(TOOLS) + r')="\$SHARD/([0-9]+)"')
MATRIX = re.compile(r"^\s+shard:\s*\[([^\]]*)\]\s*(#.*)?$", re.M)
READS = re.compile(r"\$\{?SHARD\b")
SETS = re.compile(r"^\s+SHARD:\s*\$\{\{\s*matrix\.shard\s*\}\}\s*$", re.M)
# The selections test/violations.py makes. A Makefile target passes one.
VIOLATION_SELECTIONS = ([], ["--tier=fast"], ["--tier=slow"],
                        ["--proof-backed"], ["--not-proof-backed"])


def load(rel, name):
    """The module at rel, loaded by path: tools/, test/ and proof/ are
    no packages, and two of the file names carry a hyphen."""
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def steps_of(body):
    """The text of each step in a job's body, split at each `- ` line
    whose indent is the first step's."""
    lines = body.split("\n")
    starts = [i for i, l in enumerate(lines) if re.match(r"^\s+- \w", l)]
    if not starts:
        return []
    indent = len(lines[starts[0]]) - len(lines[starts[0]].lstrip())
    starts = [i for i in starts
              if len(lines[i]) - len(lines[i].lstrip()) == indent]
    return ["\n".join(lines[a:b]) for a, b in zip(starts, starts[1:] + [len(lines)])]


def job_problems(rel, name, body):
    """What is wrong with one job's shards, and the (tool, N) pairs that
    the job runs."""
    out, runs = [], set()
    matrix = MATRIX.search(body)
    passes = {(TOOLS[var], int(n)) for var, n in PASSES.findall(body)}
    if not matrix and not passes:
        return out, runs
    where = f"{rel}: {name}"
    if not passes:
        return [f"{where} has a shard matrix and passes no \"$SHARD/N\", so "
                "each of its jobs runs the whole set"], runs
    if not matrix:
        return [f"{where} passes \"$SHARD/N\" and has no shard matrix"], runs
    counts = {n for _, n in passes}
    if len(counts) != 1:
        return [f"{where} passes more than one N: {sorted(counts)}"], runs
    count = counts.pop()
    values = [v.strip() for v in matrix.group(1).split(",") if v.strip()]
    if values != [str(k) for k in range(1, count + 1)]:
        out.append(f"{where} lists shards [{', '.join(values)}] and passes "
                   f"\"$SHARD/{count}\"; the list must be 1 to {count}")
    for step in steps_of(body):
        if READS.search(step) and not SETS.search(step):
            first = step.strip().split("\n")[0]
            out.append(f"{where}: the step `{first}` reads $SHARD and does not "
                       "set it from matrix.shard")
    return out, passes


def partition_problems(label, whole, parts):
    """Where parts, a list of name lists, fail to split whole: a name in
    no part or in two, a name no part should hold, or an empty part."""
    out = []
    seen = {}
    for k, part in enumerate(parts, 1):
        if not part:
            out.append(f"{label}: part {k} of {len(parts)} is empty")
        for name in part:
            if name in seen:
                out.append(f"{label}: {name} is in parts {seen[name]} and {k}")
            seen.setdefault(name, k)
    for name in sorted(set(whole) - set(seen)):
        out.append(f"{label}: {name} is in no part of {len(parts)}")
    for name in sorted(set(seen) - set(whole)):
        out.append(f"{label}: part {seen[name]} holds {name}, which the "
                   "whole set does not")
    return out


def violation_parts(violations, selection, count):
    """The whole selection and its count parts, through
    test/violations.py's own select(). A part that select() refuses as
    empty is an empty list."""
    def chosen(argv):
        try:
            return violations.select(argv)
        except SystemExit:
            return []
    return chosen(selection), [chosen(selection + [f"--shard={k}/{count}"])
                               for k in range(1, count + 1)]


def main():
    pins = load("tools/toolchain-pins.py", "toolchain_pins")
    problems, runs = [], set()
    for path in WORKFLOWS:
        rel = path.relative_to(ROOT)
        for name, _, body in pins.split_jobs(path.read_text()):
            found, passes = job_problems(rel, name, body)
            problems += found
            runs |= passes
    for tool, count in sorted(runs):
        if tool == "test/violations.py":
            violations = load(tool, "violations")
            for selection in VIOLATION_SELECTIONS:
                whole, parts = violation_parts(violations, selection, count)
                label = f"{tool} {' '.join(selection) or '(every violation)'}"
                problems += partition_problems(label, whole, parts)
        else:
            coverage = load(tool, "coverage")
            launched = coverage.launch_lines()
            problems += partition_problems(
                tool, coverage.reach_names(launched),
                [coverage.reach_names(launched, shard=(k, count))
                 for k in range(1, count + 1)])
    for problem in problems:
        print(f"lint-matrix: {problem}")
    if problems:
        return 1
    print("lint-matrix: each sharded job runs every part once, and the parts "
          "split their sets: " + ", ".join(f"{tool} in {n}" for tool, n in sorted(runs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
