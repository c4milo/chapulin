#!/usr/bin/env python3
"""Check that each sharded CI job runs every part of its set once.

A job that runs a set in N parts passes "$SHARD/N" to VIOLATION_SHARD
(test/violations.py --shard) or to REACH_SHARD (proof/coverage.py
--shard), and its matrix lists the values of SHARD. A list that leaves out
a value never runs that part, and the job stays green on the parts that
it ran. So for each workflow job this check requires:

- a job with a shard matrix passes "$SHARD/N" in a step;
- the matrix's shard list is 1 to N, each value once;
- each step that reads $SHARD sets it from matrix.shard;
- the make target of that step passes the variable to the tool as
  --shard, in its own recipe or in the recipe of a phony target that it
  depends on;
- a job that needs a sharded job calls always() in its own `if:`, so it
  runs when a part fails or runs out of time.

Then it calls each tool's own shard function for K from 1 to N, and
requires that each name goes to exactly one part. It does this for the
sets that the tools select today, and for lists of every length from N to
3N, because a function that drops the last names of a set fails only on
a set whose size N does not divide. For test/violations.py the check
covers every selection that its class and tier options make, since a
Makefile target passes one of them.

Then it writes a part of the reach table for each shard of
proof/coverage.py, as the proof-reach jobs do, and calls the function of
--merge. With every part it must return 0. With one part absent it must
return 1 and give each harness of that part a row that says so.

Then it holds the cells that each part writes for a cover run that
gives no number. It calls proof/coverage.py's reach_table with a stand-in
for cbmc, which returns the stderr texts that cbmc wrote on the nightly
runner. Each cause needs its own cell and log line, and a harness with a
floor fails on each cause (LABEL_CASES).

Last, it runs proof/coverage.py's main over the same stand-in. A
proof-reach job reads the exit status of main, not the table. A floored
harness that gives no number, or a number under its floor, needs exit 1
(EXIT_CASES).

Run through `make lint-matrix`.
"""

import contextlib
import importlib.util
import io
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
TOOLS = {"VIOLATION_SHARD": "test/violations.py",
         "REACH_SHARD": "proof/coverage.py"}
PASSES = re.compile(r'\b(' + "|".join(TOOLS) + r')="\$SHARD/([0-9]+)"')
MATRIX = re.compile(r"^\s+shard:\s*\[([^\]]*)\]\s*(#.*)?$", re.M)
READS = re.compile(r"\$\{?SHARD\b")
SETS = re.compile(r"^\s+SHARD:\s*\$\{\{\s*matrix\.shard\s*\}\}\s*$", re.M)
# The target of a `make` command in a step's run text: the first word
# after `make` and its options that is no variable assignment.
MAKE_TARGET = re.compile(r"\bmake\s+(?:-\S+\s+)*([a-z][a-z0-9-]*)(?=\s|$)")
# A Makefile rule's first line: its targets, then a colon that starts no
# `:=` assignment, then its prerequisites.
RULE = re.compile(r"^([A-Za-z0-9_./%-]+(?:[ \t]+[A-Za-z0-9_./%-]+)*)[ \t]*::?(?!=)(.*)$")
DIRECTIVE = re.compile(r"^(ifeq|ifneq|ifdef|ifndef|else|endif)\b")
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


def indent_of(line):
    return len(line) - len(line.lstrip())


def steps_of(body):
    """The text of each step in a job's body, split at each `- ` line
    whose indent is the first step's."""
    lines = body.split("\n")
    starts = [i for i, l in enumerate(lines) if re.match(r"^\s+- \w", l)]
    if not starts:
        return []
    indent = indent_of(lines[starts[0]])
    starts = [i for i in starts if indent_of(lines[i]) == indent]
    return ["\n".join(lines[a:b]) for a, b in zip(starts, starts[1:] + [len(lines)])]


def job_key(body, key):
    """The value of one of the job's own keys, with the lines under it,
    or None when the job has no such key. A key of a step sits deeper
    and is not read. Comment lines are left out."""
    lines = body.split("\n")[1:]
    keys = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
    if not keys:
        return None
    indent = indent_of(keys[0])
    for i, line in enumerate(lines):
        if indent_of(line) != indent or not line.lstrip().startswith(f"{key}:"):
            continue
        text = [line.lstrip()[len(key) + 1:]]
        for more in lines[i + 1:]:
            if more.strip() and indent_of(more) <= indent:
                break
            if not more.lstrip().startswith("#"):
                text.append(more.strip())
        return " ".join(t for t in text if t.strip()).strip()
    return None


def needs_of(body):
    """The job ids that a job's `needs:` names: one id, or a flow list
    [a, b] over one line or more. An empty list when it has no needs."""
    text = job_key(body, "needs")
    if text is None:
        return []
    text = text.split("#", 1)[0].strip().strip("[]")
    return [item.strip().strip("\"'") for item in text.split(",") if item.strip()]


def makefile_rules():
    """Target -> (prerequisites, recipe) for each rule of the Makefile,
    and the set of phony targets. recipe holds the rule's command lines
    with each backslash continuation joined, and leaves out the shell
    comments. A conditional directive such as ifeq does not end a
    recipe, and a blank line or a comment line does not either.

    This reads the text and not make's database (`make -qp`), which
    tools/impact_read.py reads. The database keeps one arm of each ifeq,
    and test-invariants-not-proof-backed runs its tool only in the arm
    for a machine with lake. `make -n` cannot stand in either: it runs
    each recipe line that starts with '+'."""
    joined = []
    for line in (ROOT / "Makefile").read_text().split("\n"):
        if joined and joined[-1].endswith("\\"):
            joined[-1] = joined[-1][:-1] + " " + line.strip()
        else:
            joined.append(line)
    rules, current = {}, None
    for line in joined:
        if line.startswith("\t") and current is not None:
            command = line.strip().lstrip("@+-").strip()
            if not command.startswith("#"):
                rules[current][1].append(command)
            continue
        if current is not None and (not line.strip() or line.startswith("#")
                                    or DIRECTIVE.match(line)):
            continue
        current = None
        match = RULE.match(line)
        if not match:
            continue
        prerequisites = match.group(2).split(";", 1)[0].split()
        for target in match.group(1).split():
            rules.setdefault(target, ([], []))[0].extend(prerequisites)
        current = match.group(1).split()[0]
    phony = set(rules.get(".PHONY", ([], []))[0])
    return rules, phony


def recipe_passes(rules, phony, target, tool, variable):
    """Whether make target runs tool with --shard=$(variable): in its own
    recipe, or in the recipe of a phony target that it depends on. A
    phony prerequisite is a step of the target, and a file prerequisite
    is an input of it, so only the phony ones are followed."""
    flag = f"--shard=$({variable})"
    seen, todo = set(), [target]
    while todo:
        name = todo.pop()
        if name in seen or name not in rules:
            continue
        seen.add(name)
        prerequisites, recipe = rules[name]
        if any(tool in command and flag in command for command in recipe):
            return True
        todo += [p for p in prerequisites if p in phony]
    return False


def recipe_problems(where, body, makefile):
    """Where a step that passes "$SHARD/N" runs a make target whose
    recipe does not pass the variable on as the tool's --shard. Then
    each job of the matrix runs the whole set."""
    rules, phony = makefile
    out = []
    for step in steps_of(body):
        found = PASSES.search(step)
        if not found:
            continue
        variable = found.group(1)
        command = step.split("run:", 1)[-1]
        target = MAKE_TARGET.search(command)
        if not target:
            out.append(f"{where} passes {variable}=\"$SHARD/N\" in a step that "
                       "runs no make target")
            continue
        if not recipe_passes(rules, phony, target.group(1), TOOLS[variable], variable):
            out.append(f"{where}: make {target.group(1)} does not pass "
                       f"--shard=$({variable}) to {TOOLS[variable]}, so each "
                       "job of the matrix runs the whole set")
    return out


def job_problems(rel, name, body, makefile):
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
    out += recipe_problems(where, body, makefile)
    return out, passes


def needs_problems(rel, jobs):
    """Where a job needs a sharded job and its own `if:` does not call
    always(). Without it the job is skipped when a part fails or runs
    out of time, and those are the nights when it has to run."""
    sharded = {name for name, body in jobs.items() if MATRIX.search(body)}
    out = []
    for name, body in jobs.items():
        needed = sorted(sharded & set(needs_of(body)))
        condition = job_key(body, "if") or ""
        if needed and not re.search(r"\balways\(\)", condition):
            out.append(f"{rel}: {name} needs the sharded {', '.join(needed)} "
                       "and its if: does not call always(), so it does not run "
                       "when a part fails or runs out of time")
    return out


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


def length_problems(label, part_of, count):
    """Where part_of(names, k) does not split a list of every length from
    count to 3 * count into count parts."""
    out = []
    for length in range(count, 3 * count + 1):
        names = [f"name{i:04d}" for i in range(length)]
        out += partition_problems(f"{label} over {length} names", names,
                                  [part_of(names, k) for k in range(1, count + 1)])
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


def write_parts(coverage, directory, parts, cells, missing):
    """Write the report of each shard but the one numbered missing under
    directory, each in a directory of its own, as download-artifact puts
    the proof-reach jobs' reports."""
    count = len(parts)
    for k, part in enumerate(parts, 1):
        if k == missing:
            continue
        lines = coverage.reach_intro((k, count)) + coverage.TABLE_HEAD
        lines += [f"| `{name}` | {cells[name]} |" for name in part]
        place = directory / f"proof-reach-part-{k}"
        place.mkdir(parents=True)
        (place / coverage.REPORT.name).write_text("\n".join(lines) + "\n")


def merged_rows(coverage, directory, runs):
    """What --merge's function returns for the parts under directory,
    and the rows of the table that it writes."""
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            result = coverage.merge_reports(directory, runs)
    except SystemExit as stop:
        return f"an exit with {stop.code!r}", {}
    return result, dict(coverage.REACH_ROW.findall(coverage.REPORT.read_text()))


def row_problems(label, rows, parts, cells, missing):
    """Where a merged table's rows differ from the parts: a harness of
    the part numbered missing needs a row that says its part did not
    report, and each other harness needs the cell of its part."""
    out = []
    for k, part in enumerate(parts, 1):
        for name in part:
            cell = rows.get(name)
            if k == missing and not (cell or "").startswith("**no report**"):
                out.append(f"{label} gives {name} the row {cell!r}, which "
                           "does not say that its part did not report")
            elif k != missing and cell != cells[name]:
                out.append(f"{label} gives {name} the row {cell!r}, not its "
                           f"part's {cells[name]!r}")
    return out


def merge_problems(coverage, count):
    """Where proof/coverage.py's merge of count parts gives the wrong
    verdict or the wrong rows: with every part, or with each part
    absent. The report goes to a temporary directory under bin/, so
    bin/proof-coverage.md, which other checks write, stays as it is."""
    runs = coverage.launch_lines()
    parts = [coverage.reach_names(runs, shard=(k, count)) for k in range(1, count + 1)]
    cells = {name: f"{50 + k}.0% ({k}/9)"
             for k, part in enumerate(parts, 1) for name in part}
    out = []
    report = coverage.REPORT
    (ROOT / "bin").mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=ROOT / "bin") as tmp:
            coverage.REPORT = Path(tmp) / report.name
            for missing in [None] + list(range(1, count + 1)):
                directory = Path(tmp) / f"without-{missing}"
                write_parts(coverage, directory, parts, cells, missing)
                result, rows = merged_rows(coverage, directory, runs)
                label = f"proof/coverage.py --merge without part {missing} of {count}"
                want = 1
                if missing is None:
                    label = f"proof/coverage.py --merge of all {count} parts"
                    want = 0
                if result != want:
                    out.append(f"{label} returns {result}, not {want}")
                out += row_problems(label, rows, parts, cells, missing)
    finally:
        coverage.REPORT = report
    return out


class Case:
    """One cover run that the stand-in for cbmc gives reach_table: what
    cbmc wrote and its exit status, and the cell the table must give it.
    returncode None stands for a run that its budget stops. floored gives
    the harness a floor of 50%, and number says that the run gives a
    number. flags are the launch line's flags, and floor_bits and budget
    are the fields of the harness's line in reach-floors.txt."""

    def __init__(self, name, stderr, cell, *, returncode=6, stdout="",
                 floored=True, number=False, flags=(), floor_bits=None,
                 budget=None):
        self.name, self.stderr, self.cell = name, stderr, cell
        self.returncode, self.stdout = returncode, stdout
        self.floored, self.number = floored, number
        self.flags, self.floor_bits, self.budget = flags, floor_bits, budget


# The lines that start the stderr of each cover run. The rsa_mont64
# harnesses got the second warning twice.
COVER_WARNINGS = [
    "--cover is incompatible with --unwinding-assertions, so "
    "unwinding-assertions will be defaulted to false",
    "**** WARNING: Use --unwinding-assertions to obtain sound verification "
    "results"]
RSA_WARNINGS = COVER_WARNINGS + COVER_WARNINGS[1:]
OBJECT_LIMIT = ("too many addressed objects: maximum number of objects is set "
                "to 2^n={} (with n={}); use the `--object-bits n` option to "
                "increase the maximum number")
# The nightly runner's address-space cap, which label_problems gives
# reach_table in place of the cap of this machine.
LABEL_CAP = 13 * 1024 ** 3
MEMORY_CELL = "out of memory under the 13 GiB address-space cap"
# Each way a cover run gives no number, and the cell for each. The texts
# of the first four and of "objects" are what cbmc 6.11.0 wrote on the
# nightly runner in run 39056264441, line for line. Until this check,
# reach_table said "not measured" for "objects" and for the two cases
# whose lines cbmc cut short.
LABEL_CASES = [
    # rsa_mont64_mul on MiniSat.
    Case("memory_whole", RSA_WARNINGS + [
        "SAT checker ran out of memory",
        "Solver ran out of memory during propositional reduction.",
        "Try reducing the problem size or increasing available memory.",
        "Out of memory"], MEMORY_CELL),
    # rsa_mont64_mul on CaDiCaL.
    Case("memory_cadical", RSA_WARNINGS + [
        "Solver ran out of memory during propositional reduction.",
        "Try reducing the problem size or increasing available memory.",
        "Out of memory"], MEMORY_CELL),
    # rsa_mont64_mul_webpki on MiniSat: cbmc cut three lines short.
    Case("memory_cut", RSA_WARNINGS + [
        "SAT checker ran", "Solver ran out ", "Try reducing th",
        "Out of memory"], MEMORY_CELL),
    # rsa_mont64_public_webpki on MiniSat: cbmc cut two lines short.
    Case("memory_cut_public", RSA_WARNINGS + [
        "Solver ran out ", "Try reducing th", "Out of memory"], MEMORY_CELL),
    # hello_build under a 12 GB cap on 2026-09-02: a summary of zero after
    # the memory line, and exit 0 (proof/coverage.py, reach_memory_cap).
    Case("memory_covered", ["Solver ran out of memory"], MEMORY_CELL,
         returncode=0, stdout="** 0 of 182 covered (0.0%)\n"),
    # What libstdc++ writes when std::bad_alloc ends a process, which then
    # stops on SIGABRT.
    Case("memory_abort", [
        "terminate called after throwing an instance of 'std::bad_alloc'",
        "  what():  std::bad_alloc"], MEMORY_CELL, returncode=-6),
    # rsa_avx2_chain on either solver, with no --object-bits.
    Case("objects", COVER_WARNINGS + [
        "Ignoring block 21 location 824 product_group (missing source location)",
        "Ignoring block 22 location 832 product_group (missing source location)",
        OBJECT_LIMIT.format(256, 8)],
         "too many addressed objects at --object-bits 8; add object_bits=N to "
         "its line in proof/reach-floors.txt"),
    Case("objects_floor_bits", [OBJECT_LIMIT.format(1024, 10)],
         "too many addressed objects at --object-bits 10; raise object_bits "
         "on its line in proof/reach-floors.txt", floor_bits=10),
    Case("objects_launch_bits", [OBJECT_LIMIT.format(512, 9)],
         "too many addressed objects at --object-bits 9; raise --object-bits "
         "on its launch line in proof/run.sh", flags=("--object-bits", "9")),
    Case("signal", [], "killed by SIGKILL", returncode=-9),
    Case("unmeasured", COVER_WARNINGS + ["a line that names no cause"],
         "not measured, exit 6"),
    Case("timeout", [], "timed out at 60 s", returncode=None, budget=60),
    # With no floor, a run that gives no number fails nothing.
    Case("memory_no_floor", ["Out of memory"], MEMORY_CELL, floored=False),
    Case("number", COVER_WARNINGS, "52.2% (121/232) (floor 50.0%)",
         returncode=0, stdout="** 121 of 232 covered (52.2%)\n", number=True),
]


def stand_in_cbmc(cases):
    """A stand-in for subprocess.run that returns, for the cover command
    of each case's harness, what that case says cbmc wrote."""
    def run(command, **_options):
        case = cases[Path(command[1]).name[:-len("_harness.c")]]
        if case.returncode is None:
            raise subprocess.TimeoutExpired(command, case.budget)
        stderr = "".join(f"{line}\n" for line in case.stderr)
        return subprocess.CompletedProcess(command, case.returncode,
                                           case.stdout, stderr)
    return run


@contextlib.contextmanager
def stand_ins(coverage, cases, floors):
    """Inside the with block, proof/coverage.py runs the stand-in for
    cbmc over cases, reads floors as its floor lines and takes LABEL_CAP
    as its cap. It reads cbmc, the floors file and the cap through three
    module names, and the block replaces them."""
    saved = coverage.subprocess, coverage.floor_lines, coverage.reach_memory_cap
    coverage.subprocess = types.SimpleNamespace(
        run=stand_in_cbmc(cases), TimeoutExpired=subprocess.TimeoutExpired)
    coverage.floor_lines = lambda: floors
    coverage.reach_memory_cap = lambda: LABEL_CAP
    try:
        yield
    finally:
        coverage.subprocess, coverage.floor_lines, coverage.reach_memory_cap = saved


def labelled_table(coverage):
    """reach_table's rows, its log lines and its failed floors for the
    cases of LABEL_CASES."""
    cases = {case.name: case for case in LABEL_CASES}
    runs = {case.name: ("fast", 1, set(), "", list(case.flags))
            for case in LABEL_CASES}
    floors = [(case.name, 50.0, case.budget, None, case.floor_bits)
              for case in LABEL_CASES if case.floored]
    output = io.StringIO()
    with stand_ins(coverage, cases, floors), contextlib.redirect_stdout(output):
        table, _dead, fell, _stale = coverage.reach_table(runs, sorted(cases))
    rows = dict(coverage.REACH_ROW.findall("\n".join(table)))
    return rows, output.getvalue().splitlines(), {name: got for name, got, _ in fell}


def label_problems(coverage):
    """Where reach_table gives a case of LABEL_CASES the wrong cell, no
    log line that starts with its cell, or the wrong verdict on its
    floor."""
    rows, log, failed = labelled_table(coverage)
    out = []
    for case in LABEL_CASES:
        where = f"proof/coverage.py reach_table: {case.name}"
        if rows.get(case.name) != case.cell:
            out.append(f"{where} gets the cell {rows.get(case.name)!r}, not "
                       f"{case.cell!r}")
        start = f"proof-reach: {case.name} {case.cell}"
        if not case.number and not any(line.startswith(start) for line in log):
            out.append(f"{where} gets no log line that starts with {start!r}")
        fails = case.floored and not case.number
        if fails and failed.get(case.name) != case.cell:
            out.append(f"{where} has a floor and gives no number, and the check "
                       f"does not fail it with its cell")
        if not fails and case.name in failed:
            out.append(f"{where} fails the check, and it has no floor or gives "
                       "a number")
    return out


# The harness that exit_problems names to proof/coverage.py's main. main
# measures only a harness with a launch line and a harness file, and
# make proof-reach-smoke measures this one.
EXIT_HARNESS = "epoch"
# The cover runs that exit_problems gives main for EXIT_HARNESS, and the
# exit status that main must return for each. reach_table lists a failed
# floor for a run that its budget stops, for a run that gives no number
# and for a number under the floor. main must fail on each of the three.
EXIT_CASES = [
    (Case("exit_memory", ["Out of memory"], MEMORY_CELL), 1),
    (Case("exit_timeout", [], "timed out at 60 s", returncode=None,
          budget=60), 1),
    (Case("exit_below_floor", COVER_WARNINGS,
          "40.0% (40/100) **below its 50.0% floor**", returncode=0,
          stdout="** 40 of 100 covered (40.0%)\n", number=True), 1),
    (Case("exit_number", COVER_WARNINGS, "52.2% (121/232) (floor 50.0%)",
          returncode=0, stdout="** 121 of 232 covered (52.2%)\n",
          number=True), 0),
    (Case("exit_no_floor", ["Out of memory"], MEMORY_CELL, floored=False), 0),
]


def main_status(coverage, case):
    """What proof/coverage.py's main returns for --reach --only
    EXIT_HARNESS when the stand-in for cbmc gives case, the cell that
    its report gives the harness, and its log. main returns None for a
    pass, and this gives 0 for it. The report goes to a temporary
    directory under bin/, so bin/proof-coverage.md stays as it is."""
    floors = [(EXIT_HARNESS, 50.0, case.budget, None, None)] if case.floored else []
    saved = sys.argv, coverage.shutil, coverage.REPORT
    output = io.StringIO()
    (ROOT / "bin").mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(dir=ROOT / "bin") as tmp, \
                stand_ins(coverage, {EXIT_HARNESS: case}, floors), \
                contextlib.redirect_stdout(output):
            sys.argv = ["proof/coverage.py", "--reach", "--only", EXIT_HARNESS]
            # main stops when cbmc is not on PATH, and the stand-in
            # needs no cbmc.
            coverage.shutil = types.SimpleNamespace(which=lambda tool: tool)
            coverage.REPORT = Path(tmp) / saved[2].name
            try:
                status = coverage.main()
            except SystemExit as stop:
                status = f"an exit with {stop.code!r}"
            report = coverage.REPORT.read_text() if coverage.REPORT.exists() else ""
    finally:
        sys.argv, coverage.shutil, coverage.REPORT = saved
    rows = dict(coverage.REACH_ROW.findall(report))
    return (0 if status is None else status), rows.get(EXIT_HARNESS), \
        output.getvalue().splitlines()


def exit_problems(coverage):
    """Where proof/coverage.py's main gives a case of EXIT_CASES the
    wrong exit status, or its report gives the case the wrong cell.
    A proof-reach job reads the exit status of main, not the table, so
    a failed floor that main does not read fails nothing."""
    out = []
    for case, want in EXIT_CASES:
        status, cell, log = main_status(coverage, case)
        where = f"proof/coverage.py main: {case.name}"
        if status != want:
            # The lines that can give main a reason to fail: the verdict
            # on the harness, and each problem of docs/verification.md.
            said = [line for line in log if line.startswith(
                (f"proof-coverage: {EXIT_HARNESS} ", "proof-coverage: docs/"))]
            out.append(f"{where} returns {status!r}, not {want}; main printed "
                       f"{said!r}")
        if cell != case.cell:
            out.append(f"{where} gets the cell {cell!r}, not {case.cell!r}")
    return out


def tool_problems(tool, count):
    """Where the tool's shard function does not split its sets into count
    parts, and for proof/coverage.py, where its merge of the parts is
    wrong."""
    if tool == "test/violations.py":
        violations = load(tool, "violations")
        problems = length_problems(
            f"{tool} shard_of", lambda names, k:
            violations.shard_of([f"--shard={k}/{count}"], names), count)
        for selection in VIOLATION_SELECTIONS:
            whole, parts = violation_parts(violations, selection, count)
            label = f"{tool} {' '.join(selection) or '(every violation)'}"
            problems += partition_problems(label, whole, parts)
        return problems
    coverage = load(tool, "coverage")
    launched = coverage.launch_lines()
    problems = length_problems(
        f"{tool} shard_part", lambda names, k:
        coverage.shard_part(names, (k, count)), count)
    problems += partition_problems(
        tool, coverage.reach_names(launched),
        [coverage.reach_names(launched, shard=(k, count))
         for k in range(1, count + 1)])
    return problems + merge_problems(coverage, count)


def main():
    pins = load("tools/toolchain-pins.py", "toolchain_pins")
    makefile = makefile_rules()
    problems, runs = [], set()
    for path in WORKFLOWS:
        rel = path.relative_to(ROOT)
        jobs = {}
        for name, _, body in pins.split_jobs(path.read_text()):
            jobs[name] = body
            found, passes = job_problems(rel, name, body, makefile)
            problems += found
            runs |= passes
        problems += needs_problems(rel, jobs)
    for tool, count in sorted(runs):
        problems += tool_problems(tool, count)
    coverage = load("proof/coverage.py", "coverage")
    problems += label_problems(coverage) + exit_problems(coverage)
    for problem in problems:
        print(f"lint-matrix: {problem}")
    if problems:
        return 1
    print("lint-matrix: each sharded job runs every part once, the parts "
          "split their sets, and the reach parts merge: "
          + ", ".join(f"{tool} in {n}" for tool, n in sorted(runs))
          + f"; the reach table names the cause in {len(LABEL_CASES)} cases, "
          f"and main's exit status follows the floor in {len(EXIT_CASES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
