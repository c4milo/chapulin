#!/usr/bin/env python3
"""Reports which code CBMC actually proves.

Run from the repository root: python3 proof/coverage.py

CBMC does not sample inputs, it proves over all of them at a bound, so
line coverage is the wrong question. Two things can go wrong instead,
and both are silent:

1. A module has no harness, so nothing is proven about it.
2. A harness exists but never runs, because no launch line in
   proof/run.sh starts it and no other harness includes it. It passes
   review and proves nothing.
3. A harness runs and returns no verdict, because the solver runs out
   of time or memory. It has a launch line, so this report lists it
   exactly like one that passed. The tier column is the only hint:
   a slow row's verdict comes from the nightly, not from this run.

A fourth failure needs CBMC itself: a harness whose unwind bound is too
small to reach the interesting code still reports success. Pass
--reach to measure that with `cbmc --cover location`; it is slow, so
it stays off by default.

    --reach              add the reachability table, one cover run per
                         harness
    --only HARNESS       with --reach, measure this harness alone
                         (repeatable)
    --shard=K/N          with --reach, measure the Kth harness in name
                         order and every Nth after it, as
                         test/violations.py --shard takes violations, so
                         N jobs with K from 1 to N measure each harness
                         once
    --merge DIR          join the shards' reports under DIR into one
                         table; run no cbmc

Writes bin/proof-coverage.md and prints a summary. It also reads
docs/verification.md back against proof/run.sh and fails where the two
disagree; see doc_problems().
"""

import argparse
import functools
import pathlib
import re
import resource
import shlex
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT = ROOT / "bin" / "proof-coverage.md"
DOC = ROOT / "docs" / "verification.md"

# Sources that ship in the library. A file here with no harness is a
# gap; a file absent from here is not library code.
LIB = sorted(p.name for p in ROOT.glob("*.c"))


def launch_lines():
    """Harness name -> (tier, unwind, linked sources, unwindset, defines).

    The unwindset and the -D flags are part of the bound: --reach has to
    measure under the same ones run.sh proves under, or a loop that the
    launch line unwinds far enough looks unreachable and the reachability
    number says nothing about the real proof."""
    text = (ROOT / "proof" / "run.sh").read_text()
    # One physical line per launch. This parser, tools/impact_read.py and
    # tools/proof-cover.py read a launch line to its end of line, so a
    # flag after a backslash continuation is dropped without an error:
    # four suite harnesses lost -DCH_NATIVE_AES that way, and two of them
    # then failed to parse under the cover command and reported not
    # measured.
    continued = re.findall(r"^launch \S+ \w+ (\S+) .*\\$", text, re.M)
    if continued:
        sys.exit(f"proof-coverage: proof/run.sh continues the launch line of "
                 f"{', '.join(continued)} with a backslash; keep each launch "
                 f"on one line, because the scripts that read them read one")
    runs = {}
    for m in re.finditer(r'^launch (\S+) (\w+) (\S+) (\d+) "([^"]*)"(.*)$', text, re.M):
        tier, _mode, name, unwind, unwindset, rest = m.groups()
        # A linked source is a path from the root: a shipped source, or a
        # stub in proof/ such as proof/ct_wipe_stub.c.
        linked = re.findall(r"\b([a-z0-9_/]+\.c)\b", rest)
        # Every flag the launch line carries, -D, -I and otherwise: a launch
        # line that needs --object-bits to prove needs it to cover too,
        # or cbmc stops with "too many addressed objects" and the harness
        # reports not measured -- which is how handshake_record's floor
        # went unenforced (https://github.com/c4milo/chapulin/issues/57).
        # The rsa_ifma lines' -Itest finds the lane model their sources
        # include, so the cover command cannot compile them without it.
        defines = re.findall(r"(-[DI]\S+)", rest)
        options = re.findall(r"(--[a-z-]+ \S+)", rest)
        flags = defines + [w for opt in options for w in opt.split()]
        runs[name] = (tier, int(unwind), set(linked), unwindset, flags)
    return runs


def launch_defines():
    """The -D flags run.sh's launch() adds to every harness, in order.

    Read from run.sh, not kept as a second list here. run.sh is the one
    statement of what each proof compiles: a launch line carries the
    flags one harness needs, and launch() adds the ones every harness
    shares. A copy here drifted once: it named -DCH_RAND_EXTERN and left
    out -DCH_NATIVE_WIDEMUL, which 6552715 added to launch(). From then
    on the nightly measured poly1305 on the 16x16 decomposition in ct.h
    and held it to a floor recorded on the native multiply its proof
    compiles (https://github.com/c4milo/chapulin/issues/113). A flag file
    both scripts read would end the drift too, but it would separate
    each flag from the launch() comment that says why it is there, and
    this script already reads run.sh for the launch lines.

    ctwidemul needs no exception: launch() passes it -DCH_NATIVE_WIDEMUL
    like every other harness, and its source defines CH_CT_WIDEMUL,
    which ct.h lets win. The cover command copies that, not a rule."""
    text = (ROOT / "proof" / "run.sh").read_text()
    m = re.search(r"local args=\((.*?)\)", text, re.S)
    defines = re.findall(r"(-D\S+)", m.group(1)) if m else []
    if not defines:
        sys.exit("proof-coverage: no -D flag found in run.sh's launch() "
                 "`local args=(...)`; update launch_defines()")
    return defines


def included_harnesses():
    """Harness stems that another harness includes. A shared body has no
    launch line of its own and is not dormant: it runs through whichever
    harness includes it."""
    shared = set()
    for path in (ROOT / "proof").glob("*_harness.c"):
        for inc in re.findall(r'#include "([a-z0-9_]+)_harness\.c"', path.read_text()):
            shared.add(inc)
    return shared


def harness_includes(path, seen=None):
    """Library sources a harness pulls in with #include, following a
    harness that wraps a sibling (the PIN variants do this)."""
    seen = seen or set()
    if path in seen or not path.exists():
        return set()
    seen.add(path)
    found = set()
    for inc in re.findall(r'#include "([a-z0-9_]+\.c)"', path.read_text()):
        if inc.endswith("_harness.c"):
            found |= harness_includes(ROOT / "proof" / inc, seen)
        else:
            found.add(inc)
    return found


def doc_problems(runs, uncovered):
    """Where docs/verification.md disagrees with proof/run.sh and with
    this report. The page is written by hand: its count of covered
    sources said twelve uncovered when there were eleven, it said three
    harnesses ran without the signed-overflow check when five did, and
    ten launched harnesses had no entry. Each check below reads one of
    those statements back."""
    text = DOC.read_text()
    run_sh = (ROOT / "proof" / "run.sh").read_text()
    out = []

    m = re.search(r"^(\d+) of the (\d+) C sources", text, re.M)
    want = (len(LIB) - len(uncovered), len(LIB))
    if m is None:
        out.append("has no sentence opening \"N of the M C sources\"")
    elif (int(m.group(1)), int(m.group(2))) != want:
        out.append(f"says {m.group(1)} of the {m.group(2)} sources are covered; "
                   f"this report counts {want[0]} of {want[1]}")
    m = re.search(r"^The other (\d+) sources", text, re.M)
    if m is None or int(m.group(1)) != len(uncovered):
        out.append(f"must say \"The other {len(uncovered)} sources\" before its "
                   f"table of sources with no launched harness")

    # The first cell of each row of that table names its sources.
    section = re.search(r"^### Sources with no launched harness$(.*?)^#", text, re.M | re.S)
    listed = set()
    for cell in re.findall(r"^\| (`[^|]*)\|", section.group(1) if section else "", re.M):
        listed |= set(re.findall(r"`([a-z0-9_]+\.c)`", cell))
    for src in sorted(set(uncovered) - listed):
        out.append(f"leaves {src} out of the table of sources with no launched harness")
    for src in sorted(listed - set(uncovered)):
        out.append(f"lists {src} as having no launched harness, but one covers it")

    noovf = set(re.findall(r"^launch \S+ noovf (\S+) ", run_sh, re.M))
    m = re.search(r"run without that check:(.*?)\(see", text, re.S)
    named = set(re.findall(r"`([a-z0-9_]+)`", m.group(1))) if m else set()
    if named != noovf:
        out.append("names " + (", ".join(sorted(named)) or "no harness") +
                   " as run without the signed-overflow check; proof/run.sh "
                   "launches " + ", ".join(sorted(noovf)) + " with noovf")

    # Every entry opens with a line such as
    # - **Harnesses:** `sha512` (slow), `sha512_compress` (fast)
    entries = {}
    for line in re.findall(r"^- \*\*Harness(?:es)?:\*\* (.*)$", text, re.M):
        for name, tier in re.findall(r"`([a-z0-9_]+)` \(([a-z ]+)\)", line):
            entries[name] = tier
    for name, run in sorted(runs.items()):
        tier = run[0].split(":")[0]
        if name not in entries:
            out.append(f"has no entry for {name}, which proof/run.sh launches")
        elif entries[name] != tier:
            out.append(f"gives {name} the {entries[name]} tier; proof/run.sh "
                       f"launches it in the {tier} tier")
    for name, tier in sorted(entries.items()):
        if name in runs:
            continue
        if tier != "no launch line":
            out.append(f"gives {name} the {tier} tier, but proof/run.sh does not launch it")
        elif not (ROOT / "proof" / f"{name}_harness.c").exists():
            out.append(f"names {name}, but proof/{name}_harness.c does not exist")
    return out


def shard_option(value):
    """(K, N) from a --shard value, which is K/N with 1 <= K <= N."""
    match = re.fullmatch(r"([0-9]+)/([0-9]+)", value)
    if not match or not 1 <= int(match.group(1)) <= int(match.group(2)):
        raise argparse.ArgumentTypeError(
            f"--shard takes K/N with 1 <= K <= N, not {value!r}")
    return int(match.group(1)), int(match.group(2))


def shard_part(names, shard):
    """The Kth of names and every Nth after it, for shard (K, N). That is
    what test/violations.py --shard keeps of the violations, so the N
    parts with K from 1 to N hold each name once, and names next to each
    other go to different parts. tools/shard-matrix.py holds this to that
    over lists of every length from N to 3N."""
    k, n = shard
    return names[k - 1::n]


def reach_names(runs, only=frozenset(), shard=None):
    """The harnesses a --reach run measures, in name order: each launched
    harness whose file exists, or each one that `only` names. shard,
    (K, N), keeps the part that shard_part gives."""
    names = [name for name in sorted(runs)
             if (ROOT / "proof" / f"{name}_harness.c").exists()
             and (not only or name in only)]
    if shard is None:
        return names
    return shard_part(names, shard)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reach", action="store_true",
                    help="measure reachability with cbmc --cover location (slow)")
    ap.add_argument("--only", action="append", default=[], metavar="HARNESS",
                    help="with --reach, measure just this harness (repeatable) "
                         "under the cover command; this is how one floor "
                         "gets re-measured by hand. A harness the floors file "
                         "lists as carrying no floor runs when named here.")
    ap.add_argument("--shard", type=shard_option, metavar="K/N",
                    help="with --reach, measure the Kth harness in name order "
                         "and every Nth after it; the nightly's proof-reach "
                         "jobs run K from 1 to N")
    ap.add_argument("--merge", metavar="DIR",
                    help="join the reports that the shards of a --reach run "
                         "wrote under DIR into one table; runs no cbmc")
    args = ap.parse_args()
    if args.merge is not None:
        if args.reach or args.only or args.shard:
            sys.exit("proof-coverage: --merge reads the shards' reports and "
                     "measures nothing, so it takes no --reach, --only or "
                     "--shard")
        return merge_reports(pathlib.Path(args.merge), launch_lines())
    if args.shard and not args.reach:
        sys.exit("proof-coverage: --shard chooses what --reach measures; "
                 "add --reach")
    # A missing cbmc is a setup error, not a measurement: without this
    # the nightly's spec-coverage job, which installs no cbmc, died in a
    # traceback, and a stub on PATH would read as 0.0% under a floor.
    if args.reach and shutil.which("cbmc") is None:
        sys.exit("proof-reach: cbmc is not on PATH; the reach measurement "
                 "runs it, so install it or drop --reach")

    runs = launch_lines()
    for name in args.only:
        if name not in runs:
            sys.exit(f"proof-coverage: --only {name} matches no launch line "
                     "in proof/run.sh")
    measured = reach_names(runs, set(args.only), args.shard) if args.reach else []
    if args.reach and not measured:
        # An empty selection measures nothing, and a job that measured
        # nothing must not pass as if it measured its share.
        sys.exit("proof-reach: the --only and --shard selection holds no "
                 "harness to measure")
    shared = included_harnesses()
    proven = {}   # library file -> harnesses that compile it and run
    dormant = []  # harness with no launch line and no harness including it
    for path in sorted((ROOT / "proof").glob("*_harness.c")):
        name = path.name[: -len("_harness.c")]
        # What CBMC compiles: what the harness includes, plus what the
        # launch line links. Everything in that closure is checked for
        # memory safety on the paths the harness drives, so all of it
        # counts as covered.
        closure = harness_includes(path)
        if name not in runs:
            if name not in shared:
                dormant.append((name, ", ".join(sorted(closure)) or "self-contained"))
            continue
        closure |= runs[name][2]
        for src in closure:
            proven.setdefault(src, []).append(name)

    lines = ["## What CBMC proves", "",
             "CBMC proves over every input at a bound, so this counts",
             "harnesses and whether they run, not lines executed.", "",
             "### Library sources", "",
             "| file | proven by | tier |", "| --- | --- | --- |"]
    uncovered = []
    for src in LIB:
        names = proven.get(src, [])
        if not names:
            uncovered.append(src)
            lines.append(f"| `{src}` | **no harness** | — |")
            continue
        tiers = ",".join(sorted({runs[n][0].split(":")[0] for n in names}))
        lines.append(f"| `{src}` | {', '.join(sorted(names))} | {tiers} |")
    lines += ["", f"{len(LIB) - len(uncovered)} of {len(LIB)} sources are "
                  f"compiled into a harness with a launch line. Everything",
              "CBMC compiles is checked for memory safety and undefined",
              "behaviour on the paths the harness drives; a source listed",
              "here against its own harness is also proven against its",
              "contract.", "",
              "A fast row's verdict comes from `make check-slow`, which runs",
              "the fast tier through `make prove`; CI runs that on every push",
              "to main and not on a pull request, which gets `make check` and",
              "no proof job. A slow row carries the verdict of the last",
              "nightly job that finished, not of this commit. A harness",
              "that starts and returns no verdict proves nothing, and this",
              "table cannot tell that apart from one that passed — for the",
              "slow rows, read the nightly.", ""]
    if uncovered:
        lines.append("No harness: " + ", ".join(f"`{s}`" for s in uncovered) + ".")
        lines.append("")

    if dormant:
        lines += ["### Harnesses that never run", "",
                  "These compile and pass review but no launch line in",
                  "proof/run.sh starts them, so they prove nothing.", "",
                  "| harness | subject |", "| --- | --- |"]
        for name, subject in sorted(dormant):
            lines.append(f"| `{name}` | `{subject or 'unknown'}` |")
        lines.append("")

    reach_dead, reach_fell, reach_stale = [], [], []
    if args.reach:
        reach_lines, reach_dead, reach_fell, reach_stale = reach_table(
            runs, measured, set(args.only), args.shard)
        lines += reach_lines

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n")
    print(f"proof-coverage: {len(LIB) - len(uncovered)}/{len(LIB)} sources in a "
          f"launched harness, {len(dormant)} dormant -> {REPORT.relative_to(ROOT)}")
    if uncovered:
        print("proof-coverage: no harness for " + ", ".join(uncovered))
    for name, _ in sorted(dormant):
        print(f"proof-coverage: {name} has no launch line")
    for name in reach_dead:
        print(f"proof-coverage: {name} reaches no code at its bound; the "
              f"proof passes without entering what it names")
    for name, got, floor in reach_fell:
        # got is a percentage, or the words for why there is none: a run
        # that returned no number is a failed check too, and saying "0.0%"
        # for it sent a reader after the bound instead of the runner.
        if isinstance(got, str):
            print(f"proof-coverage: {name} {got}, so its recorded {floor}% "
                  f"floor was not measured; the check fails until it is")
            continue
        print(f"proof-coverage: {name} reaches {got}% of its locations, under "
              f"its recorded {floor}% floor; the bound no longer enters what "
              f"the harness names")
    for name in reach_stale:
        print(f"proof-coverage: {name}'s launch line bounds a loop its goto "
              f"model does not have; run.sh fails the proof the same way")
    doc = doc_problems(runs, uncovered)
    for problem in doc:
        print(f"proof-coverage: {DOC.relative_to(ROOT)} {problem}")
    if reach_dead or reach_fell or reach_stale or doc:
        return 1


# The SAT solvers a floor line can name in a solver= field. A cover run
# whose line names none runs on cbmc's default solver, MiniSat 2.
#
# run.sh proves under kissat through --external-sat-solver, and cbmc
# 6.11.0 refuses that flag with --cover. A cover run asks the solver
# about one formula again for each set of goals that stays open, so cbmc
# needs a solver that keeps the formula between those calls. For an
# external solver it stops with "the chosen solver does not support
# incremental solving". CaDiCaL is in the pinned cbmc release, and it
# keeps the formula.
#
# A goal is covered when the path to it is satisfiable, and each solver
# decides that for the same formula. So the solver changes the time and
# the memory of a cover run, not its count. On the nightly runner on
# 2026-10-17, CaDiCaL printed MiniSat's count for each of the 201
# harnesses where both solvers printed a number.
#
# MiniSat returned no number for rsa_mont_host, rsa_mont_power,
# rsa_mont_power_avx2 and their webpki variants: in 3000 s, and in 2800 s
# without its simplifier. Its first query did not return. Their proofs
# take MiniSat 14 s to 71 s on that runner, because the two formulas ask
# different questions. rsa_mont_power's proof formula holds 21.8 million
# clauses, and simplification leaves 84 of its 271,704 checks, which the
# solver refutes in under a millisecond. Its cover formula holds 28.3
# million clauses and 48,033 goal instances: the unwound loops copy the
# 336 goals that the reach table counts. The first query asks for one
# path to any of them. CaDiCaL finds that path in 1.8 s and measures the
# harness in 31 s. It measures the other five in 28 s to 118 s, and
# sha512_compress_blocks_advancing, where MiniSat stopped at 1800 s, in
# 1 s.
#
# CaDiCaL is not the default, because it takes more time or memory on
# some harnesses. It ran out of memory at 12.2 GB on rsa_ifma_sign_power,
# which MiniSat measures in 994 s. It took 1707 s on webpki_ext_walk,
# where MiniSat takes 744 s.
REACH_SOLVERS = ("cadical",)

# A floor line's object_bits=N field adds --object-bits N to the cover
# command of that harness alone. cbmc writes an object's number in the
# top bits of each pointer, 8 by default, so a formula can hold about 256
# objects. A formula with more stops with "too many addressed objects".
# On the nightly runner on 2026-10-17, the three rsa_avx2_chain cover
# runs stopped that way, while their proofs need no such flag (run
# 39056264441). With N bits for the number, 64 - N bits remain for the
# offset in an object. The objects of those three harnesses are a few
# kilobytes, far below what 54 offset bits address. So for them the field
# changes the encoding of a pointer and no goal's answer. A launch line
# that passes --object-bits gives it to its cover command already, so its
# floor line cannot name the field too.
REACH_DEFAULT_OBJECT_BITS = 8


def floor_lines():
    """(harness, floor, budget, solver, object_bits) for every line of
    reach-floors.txt. budget is the cover run's own wall-clock limit in
    seconds, from an optional budget=SECONDS field, or None when the line
    carries none and REACH_BUDGET_S applies. solver is the cover run's SAT
    solver, from an optional solver=NAME field that names one of
    REACH_SOLVERS, or None when the line carries none and cbmc's default
    solver applies. object_bits is the cover run's --object-bits, from an
    optional object_bits=N field, or None when the line carries none."""
    path = ROOT / "proof" / "reach-floors.txt"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, pct, *extra = line.split()
        budget = None
        solver = None
        object_bits = None
        for field in extra:
            key, _, value = field.partition("=")
            if key == "budget":
                budget = int(value)
            elif key == "solver" and value in REACH_SOLVERS:
                solver = value
            elif (key == "object_bits" and value.isdigit()
                  and int(value) > REACH_DEFAULT_OBJECT_BITS):
                object_bits = int(value)
            else:
                sys.exit(f"proof-coverage: reach-floors.txt gives {name} the field "
                         f"{field!r}; a line is name, percent and the optional fields "
                         f"budget=SECONDS, solver={'|'.join(REACH_SOLVERS)} and "
                         f"object_bits=N, with N above cbmc's default of "
                         f"{REACH_DEFAULT_OBJECT_BITS}")
        entries.append((name, float(pct), budget, solver, object_bits))
    return entries


def reach_floors():
    """Harness -> the lowest reach share it is allowed to report."""
    return {name: pct for name, pct, _, _, _ in floor_lines()}


def reach_budgets():
    """Harness -> its cover run's wall-clock limit in seconds, for the
    harnesses whose line names one."""
    return {name: budget for name, _, budget, _, _ in floor_lines() if budget is not None}


def reach_solvers():
    """Harness -> its cover run's SAT solver, for the harnesses whose line
    names one."""
    return {name: solver for name, _, _, solver, _ in floor_lines() if solver is not None}


def reach_object_bits():
    """Harness -> its cover run's --object-bits, for the harnesses whose
    line names one."""
    return {name: bits for name, _, _, _, bits in floor_lines() if bits is not None}


def reach_not_gated():
    """The harnesses reach-floors.txt lists as carrying no floor: cover
    does not converge on them, so the nightly does not run them. The list
    is the indented comment block under the file's "No floor" heading."""
    path = ROOT / "proof" / "reach-floors.txt"
    names = set()
    if not path.exists():
        return names
    for line in path.read_text().splitlines():
        m = re.fullmatch(r"#\s{3}([a-z0-9_]+)", line)
        if m:
            names.add(m.group(1))
    return names


# What one cover run gets, in seconds. The number is measured, and the
# measurement is here because the 900 s it replaces was not: hello_build
# converged in 278 s, 281 s and 287 s on the nightly runner (runs
# 33715874614, 33717153636 and 33851067664) and once timed out at 900 s
# (run 33731054741), under the same command, the same sources and the same
# cbmc 6.11.0. Three of those four sit inside 1.6% of each other, so the
# 900 s excursion is not the spread of a noisy measurement.
#
# That run was not a slow one. Its other 19 converging harnesses each
# finished within 17% of their own fastest time, median 1.01x, so a loaded
# runner does not explain it. The same command on a development machine ran
# six times, 175 s to 195 s, and peaked at 12.2 GB. A harness holding three
# quarters of a 16 GB runner has a wall time set by the memory free during
# its own window, which a whole-run average cannot see.
#
# So the budget carries margin over the swing, not over the median: 1800 s
# is about 6x what hello_build takes on the runner when it converges. The
# other half of the fix is in reach-floors.txt, which now names the three
# mlkem cover runs that return no verdict at this budget either, so raising
# the number does not double what they spend.
#
# This buys margin; it does not shrink the formula that needs it. A cover
# run holding 12.2 GB of a 16 GB runner will move like this again, and one
# budget still cannot serve both a 310 s harness and pem's 1665 s. Both are
# https://github.com/c4milo/chapulin/issues/163. The second half has its
# answer: a floor line may carry budget=SECONDS, and that harness's cover
# run gets that limit instead of this one (reach-floors.txt says which,
# and why). The first half, the formula's memory, was the cover command
# leaving out --slice-formula (reach_command says why it is there now). In
# an ubuntu 24.04 amd64 container with the pinned cbmc, hello_build's
# cover run without it passed 13 GB in 43 s, and with it the run takes
# 2 s and 76 MB. On arm64 macOS both commands reach 143 of 185 locations,
# the runner's 77.3%.
REACH_BUDGET_S = 1800

# Each cover run gets the address-space cap run.sh gives a lone proof: the
# memory available when the check starts, in whole GiB, less one. On the
# nightly runner that is 13 GiB, since run.sh's prove-slow log there names
# an 8 GB budget, the available 14 GiB less 6. The largest sliced cover
# runs, the x25519 harnesses', peak at 4.9 GB resident and 6.0 GB of
# address space in an ubuntu 24.04 amd64 container.
#
# A 12 GB cap was tried after the 2026-09-02 runner death, and 0ab9862
# dropped it: under it cbmc printed "Solver ran out of memory" and then
# "0 of 182 covered" with exit 0 for hello_build, which needed more, and
# the check took the 0 as a number. reach_table now reads that message and
# reports "over memory", and with --slice-formula hello_build needs 76 MB.
# Without a cap, only the no-floor list kept a cover run from using up the
# runner's memory, and a harness missing from that list ended the job
# before it wrote the table: hello_build_suite did that on three nightly
# runs from 2026-09-30. Under a cap, its unsliced command stops with
# "Solver ran out of memory during propositional reduction" and exit 6.
def reach_memory_cap():
    """The cover run's address-space cap in bytes. None where the machine
    has no /proc/meminfo, as on macOS, which ignores the limit (run.sh's
    comment on ulimit -v), or reports 2 GiB or less available, a machine
    run.sh does not size its cap from either."""
    try:
        meminfo = pathlib.Path("/proc/meminfo").read_text()
    except OSError:
        return None
    m = re.search(r"^MemAvailable:\s+(\d+) kB$", meminfo, re.M)
    if not m:
        return None
    available_gib = int(m.group(1)) // 1024 ** 2
    if available_gib <= 2:
        return None
    return (available_gib - 1) * 1024 ** 3


def cap_address_space(cap):
    """Set the calling process's address-space limit to cap bytes, or to
    its hard limit if that is lower. reach_table runs it in each cbmc
    child before exec."""
    _, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        cap = min(cap, hard)
    resource.setrlimit(resource.RLIMIT_AS, (cap, hard))


def reach_command(name, runs, shared_defines, solver=None, object_bits=None):
    """The cover command for one harness: what its launch line links and
    bounds, then the defines launch() adds, in run.sh's order, and the SAT
    solver and the --object-bits its floor line names, if it names them
    (REACH_SOLVERS, REACH_DEFAULT_OBJECT_BITS).

    --slice-formula is the flag run.sh's BASE passes every proof. A cover
    goal is covered when the path to it is satisfiable, and the slicer
    keeps every assumption, branch condition and path guard, so no goal
    changes its answer. What it drops is each assignment that none of
    them reads, such as the bytes a builder copies into its output.
    Without it, hello_build_suite's cover run held 13 GB when a 13 GB
    container stopped it 52 s in, still converting the formula, and the
    nightly runner died on it three times; with it, the run takes 6 s and
    0.13 GB. Both readings come from an ubuntu 24.04 amd64 container with
    the pinned cbmc (https://github.com/c4milo/chapulin/issues/163)."""
    _tier, unwind, linked, unwindset, defines = runs[name]
    cmd = ["cbmc", str(ROOT / "proof" / f"{name}_harness.c")]
    cmd += [str(ROOT / src) for src in sorted(linked)]
    cmd += [*defines, *shared_defines, "-I", str(ROOT),
            "--cover", "location", "--slice-formula", "--unwind", str(unwind)]
    if unwindset:
        cmd += ["--unwindset", unwindset]
    if solver:
        cmd += ["--sat-solver", solver]
    if object_bits is not None:
        if "--object-bits" in defines:
            sys.exit(f"proof-coverage: {name}'s launch line passes --object-bits, "
                     "and its line in reach-floors.txt names object_bits too; "
                     "keep the launch line's")
        cmd += ["--object-bits", str(object_bits)]
    return cmd


# cbmc's three warnings, on stderr, for an --unwindset id that bounds no
# single loop: "does not match any loop" when the function has no such
# loop, "for non-existent function" when the goto model has no such
# function, "is ambiguous" when more than one loop matches. run.sh fails
# a proof on any of them; the cover command reads the same unwindset, so
# a floor must not be measured under one either
# (https://github.com/c4milo/chapulin/issues/136).
STALE_UNWINDSET = re.compile(
    r"^loop identifier (\S+) (?:for non-existent function )?provided with unwindset",
    re.M)


REACH_TITLE = "Reachability at the configured bounds"
# The heading of a shard's part. --merge reads the shard and the count
# back from it, so each part names the harnesses that it measures.
PART_HEADING = re.compile(
    r"^### " + REACH_TITLE + r", shard ([0-9]+) of ([0-9]+)$", re.M)
# One row of the reach table: the harness and the cell beside it.
REACH_ROW = re.compile(r"^\| `([a-z0-9_]+)` \| (.*) \|$", re.M)
# A cell of a harness that reached none of its locations.
DEAD_CELL = re.compile(r"^[0-9.]+% \(0/[1-9][0-9]*\)")


def reach_intro(shard=None):
    """The reach table's heading and the text above its rows. A shard's
    heading names the shard and the count."""
    title = REACH_TITLE
    if shard is not None:
        title += f", shard {shard[0]} of {shard[1]}"
    lines = [f"### {title}", "",
             "`cbmc --cover location`: the share of program locations the",
             "harness can reach. A low number means the unwind bound stops",
             "short of the code the harness claims to prove.", ""]
    if shard is not None:
        k, n = shard
        lines += [f"This part holds shard {k} of {n} (`--shard={k}/{n}`): the",
                  f"harnesses at positions {k}, {k + n}, {k + 2 * n} and so on "
                  "in name order.", ""]
    return lines


TABLE_HEAD = ["| harness | locations reached |", "| --- | --- |"]


def dead_line(dead):
    """The line under the table that names the harnesses that reach
    nothing, or no line when there are none."""
    if not dead:
        return []
    return ["**Reaches nothing at its bound:** " +
            ", ".join(f"`{n}`" for n in dead) + ".", ""]


def reach_table(runs, names, only=frozenset(), shard=None):
    """Per harness in names, the share of its goto locations CBMC can
    reach at the configured bound. A low number means the bound stops
    the proof short of the code it claims to cover. A non-empty `only`
    lets a harness the floors file lists as carrying no floor run.
    shard, (K, N), names the part of the harnesses that names holds."""
    dead = []
    fell = []
    stale = []
    floors = reach_floors()
    budgets = reach_budgets()
    solvers = reach_solvers()
    object_bits = reach_object_bits()
    not_gated = reach_not_gated()
    shared_defines = launch_defines()
    cap = reach_memory_cap()
    limit = functools.partial(cap_address_space, cap) if cap else None
    out = reach_intro(shard) + TABLE_HEAD
    for name in names:
        if name in not_gated and name not in only:
            out.append(f"| `{name}` | no floor: cover does not converge "
                       "(proof/reach-floors.txt) |")
            print(f"proof-reach: {name} carries no floor, skipped", flush=True)
            continue
        cmd = reach_command(name, runs, shared_defines, solvers.get(name),
                            object_bits.get(name))
        # The log carries the exact command, so a floor can be re-measured
        # by hand under the flags the cover command used and not a
        # reconstruction.
        print(f"proof-reach: {name} command: {shlex.join(cmd)}", flush=True)
        budget = budgets.get(name, REACH_BUDGET_S)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=budget,
                                 preexec_fn=limit)
        except subprocess.TimeoutExpired:
            out.append(f"| `{name}` | timed out at {budget} s |")
            print(f"proof-reach: {name} timed out at {budget} s", flush=True)
            # The same rule as the no-number branch below: a floored
            # harness that returns no number fails the check. Before this
            # a timeout skipped the floor check and the run stayed green.
            if name in floors:
                fell.append((name, "timed out", floors[name]))
            continue
        stale_ids = STALE_UNWINDSET.findall(res.stderr)
        if stale_ids:
            out.append(f"| `{name}` | unwindset names no loop: "
                       f"{', '.join(f'`{i}`' for i in stale_ids)} |")
            print(f"proof-reach: {name} unwindset names {', '.join(stale_ids)}, "
                  "which matches no loop in its goto model; fix the launch "
                  "line in proof/run.sh", flush=True)
            stale.append(name)
            continue
        m = re.search(r"\*\* (\d+) of (\d+) covered \(([0-9.]+)%\)", res.stdout)
        # cbmc prints "ran out of memory" and then a summary of zero goals
        # reached with exit 0, so the summary is read only when the solver
        # did not say that.
        out_of_memory = "ran out of memory" in res.stderr or "bad_alloc" in res.stderr
        if not m or out_of_memory:
            why = "over memory" if out_of_memory or res.returncode < 0 else "not measured"
            out.append(f"| `{name}` | {why} |")
            print(f"proof-reach: {name} {why}", flush=True)
            # A harness with a floor that returns no number is a failed
            # check, not a blank: the floor exists to notice regressions,
            # and a silent blank is how one went unnoticed.
            if name in floors:
                fell.append((name, why, floors[name]))
            continue
        print(f"proof-reach: {name} {m.group(3)}%", flush=True)
        reached, total, pct = int(m.group(1)), int(m.group(2)), m.group(3)
        floor = floors.get(name)
        mark = ""
        if floor is not None:
            mark = f" (floor {floor}%)"
            if float(pct) < floor:
                mark = f" **below its {floor}% floor**"
                fell.append((name, float(pct), floor))
        out.append(f"| `{name}` | {pct}% ({reached}/{total}){mark} |")
        # Reaching nothing is the failure this measurement exists to catch:
        # the bound stops before the harness enters the code it names, and
        # the proof still reports success. Anything above zero is a number
        # to read, not a verdict, because a harness that stubs its
        # dependencies legitimately reaches less than one that does not.
        if reached == 0 and total > 0:
            dead.append(name)
    out.append("")
    out += dead_line(dead)
    return out, dead, fell, stale


def read_parts(directory):
    """Shard -> (count, head, rows, path) for each report under directory
    that a shard of a --reach run wrote. head is the report above its
    reach table, and rows maps each harness to its cell. A file that is
    no shard's part, or a second part of one shard, ends the merge."""
    parts = {}
    paths = sorted(directory.rglob(REPORT.name)) if directory.is_dir() else []
    for path in paths:
        if path.resolve() == REPORT.resolve():
            continue  # the merge's own output, from an earlier merge
        text = path.read_text()
        m = PART_HEADING.search(text)
        if not m:
            sys.exit(f"proof-reach-merge: {path} holds no shard's part of "
                     "the reach table")
        k, count = int(m.group(1)), int(m.group(2))
        if not 1 <= k <= count:
            sys.exit(f"proof-reach-merge: {path} names shard {k} of {count}")
        if k in parts:
            sys.exit(f"proof-reach-merge: {path} and {parts[k][3]} both hold "
                     f"shard {k}")
        parts[k] = (count, text[:m.start()], dict(REACH_ROW.findall(text, m.end())), path)
    return parts


def shard_rows(runs, shard, part, rows, status, problems):
    """Add one shard's rows to rows, its line to status, and what is wrong
    with its part to problems. part maps each harness to its cell, or is
    None when the shard wrote no report."""
    k, count = shard
    names = reach_names(runs, shard=shard)
    if part is None:
        status.append(f"- shard {k} of {count}: **did not report**, so its "
                      f"{len(names)} harnesses have no number")
        problems.append(f"shard {k} of {count} did not report; its "
                        f"{len(names)} harnesses have no row")
        for name in names:
            rows[name] = f"**no report**: shard {k} of {count} did not report"
        return
    for name in sorted(set(part) - set(names)):
        problems.append(f"shard {k}'s part holds {name}, which shard {k} "
                        f"of {count} does not measure in this checkout")
    for name in names:
        if name not in part:
            problems.append(f"shard {k}'s part has no row for {name}")
        rows[name] = part.get(name, f"**no row** in shard {k}'s part")
    status.append(f"- shard {k} of {count}: {len(names)} harnesses")


def merge_reports(directory, runs):
    """Join the reports that the shards of a --reach run wrote under
    directory into one report at REPORT, with one reach table. A shard
    whose job stopped before it wrote its report, as a job that runs out
    of time does, gets a row for each of its harnesses that says so. The
    merge then returns 1, because the table is incomplete.

    The parts come from one commit, so the text above each reach table
    is the same in all of them, and the merge keeps the first. Each
    shard's harnesses come from this checkout's proof/run.sh, so a part
    that holds another set of harnesses fails the merge too."""
    parts = read_parts(directory)
    REPORT.parent.mkdir(exist_ok=True)
    if not parts:
        REPORT.write_text("\n".join(
            [f"### {REACH_TITLE}", "",
             f"No shard wrote its part of the table under `{directory}`."]) + "\n")
        print(f"proof-reach-merge: no shard reported under {directory}")
        return 1
    counts = sorted({count for count, _, _, _ in parts.values()})
    if len(counts) != 1:
        sys.exit("proof-reach-merge: the parts name different shard counts: "
                 + ", ".join(map(str, counts)))
    count = counts[0]
    rows, status, problems = {}, [], []
    for k in range(1, count + 1):
        part = parts[k][2] if k in parts else None
        shard_rows(runs, (k, count), part, rows, status, problems)
    dead = [name for name, cell in sorted(rows.items()) if DEAD_CELL.match(cell)]
    lines = parts[min(parts)][1].rstrip("\n").split("\n") + [""]
    lines += reach_intro()
    lines += [f"This table joins the parts of {count} shards "
              "(`proof/coverage.py --merge`):", ""] + status + [""]
    lines += TABLE_HEAD + [f"| `{name}` | {cell} |" for name, cell in sorted(rows.items())]
    lines += [""] + dead_line(dead)
    REPORT.write_text("\n".join(lines) + "\n")
    print(f"proof-reach-merge: {len(parts)} of {count} shards reported, "
          f"{len(rows)} rows -> {REPORT.relative_to(ROOT)}")
    for problem in problems:
        print(f"proof-reach-merge: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
