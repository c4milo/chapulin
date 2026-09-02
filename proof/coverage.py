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

Writes bin/proof-coverage.md and prints a summary.
"""

import argparse
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT = ROOT / "bin" / "proof-coverage.md"

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
    runs = {}
    for m in re.finditer(r'^launch (\S+) (\w+) (\S+) (\d+) "([^"]*)"(.*)$', text, re.M):
        tier, _mode, name, unwind, unwindset, rest = m.groups()
        linked = re.findall(r"\b([a-z0-9_]+\.c)\b", rest)
        # Every flag the launch line carries, -D and otherwise: a launch
        # line that needs --object-bits to prove needs it to cover too,
        # or cbmc stops with "too many addressed objects" and the harness
        # reports not measured -- which is how handshake_record's floor
        # went unenforced (https://github.com/c4milo/chapulin/issues/57).
        defines = re.findall(r"(-D\S+)", rest)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reach", action="store_true",
                    help="measure reachability with cbmc --cover location (slow)")
    ap.add_argument("--only", action="append", default=[], metavar="HARNESS",
                    help="with --reach, measure just this harness (repeatable) "
                         "under the gate's own command; this is how one floor "
                         "gets re-measured by hand. A harness the floors file "
                         "lists as not gated runs when named here.")
    args = ap.parse_args()

    runs = launch_lines()
    for name in args.only:
        if name not in runs:
            sys.exit(f"proof-coverage: --only {name} matches no launch line "
                     "in proof/run.sh")
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
              "A fast row gates every push: `make check` runs it and a red",
              "one stops the build. A slow row carries the verdict of the",
              "last nightly leg that finished, not of this commit. A harness",
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

    reach_dead, reach_fell = [], []
    if args.reach:
        reach_lines, reach_dead, reach_fell = reach_table(runs, set(args.only))
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
        print(f"proof-coverage: {name} reaches {got}% of its locations, under "
              f"its recorded {floor}% floor; the bound no longer enters what "
              f"the harness names")
    if reach_dead or reach_fell:
        return 1


def reach_floors():
    """Harness -> the lowest reach share it is allowed to report."""
    path = ROOT / "proof" / "reach-floors.txt"
    floors = {}
    if not path.exists():
        return floors
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, pct = line.split()
        floors[name] = float(pct)
    return floors


def reach_not_gated():
    """The harnesses reach-floors.txt lists as not gated: cover does not
    converge on them, so the nightly does not run them. The list is the
    indented comment block under the file's "Not gated" heading."""
    path = ROOT / "proof" / "reach-floors.txt"
    names = set()
    if not path.exists():
        return names
    for line in path.read_text().splitlines():
        m = re.fullmatch(r"#\s{3}([a-z0-9_]+)", line)
        if m:
            names.add(m.group(1))
    return names


# A cover run that the floors file does not list as non-converging is
# expected to finish in seconds to minutes and well under this much
# memory. The cap turns an outlier into a reported failure; without it,
# one runaway formula takes the whole runner down and the nightly logs
# nothing (the 2026-09-02 run died that way).
REACH_MEMORY_BYTES = 12 * 1024 ** 3


def _cap_memory():
    import resource
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = REACH_MEMORY_BYTES
        if hard != resource.RLIM_INFINITY:
            cap = min(cap, hard)
        resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
    except (ValueError, OSError):
        # macOS refuses some address-space limits; the cap protects the
        # Linux runner, and a run without it is what every run was before.
        pass


def reach_command(name, runs, shared_defines):
    """The cover command for one harness: what its launch line links and
    bounds, then the defines launch() adds, in run.sh's order."""
    _tier, unwind, linked, unwindset, defines = runs[name]
    cmd = ["cbmc", str(ROOT / "proof" / f"{name}_harness.c")]
    cmd += [str(ROOT / src) for src in sorted(linked)]
    cmd += [*defines, *shared_defines, "-I", str(ROOT),
            "--cover", "location", "--unwind", str(unwind)]
    if unwindset:
        cmd += ["--unwindset", unwindset]
    return cmd


def reach_table(runs, only=frozenset()):
    """Per harness, the share of its goto locations CBMC can reach at
    the configured bound. A low number means the bound stops the proof
    short of the code it claims to cover. A non-empty `only` restricts
    the run to those harnesses and lets a not-gated one run."""
    dead = []
    fell = []
    floors = reach_floors()
    not_gated = reach_not_gated()
    shared_defines = launch_defines()
    out = ["### Reachability at the configured bounds", "",
           "`cbmc --cover location`: the share of program locations the",
           "harness can reach. A low number means the unwind bound stops",
           "short of the code the harness claims to prove.", "",
           "| harness | locations reached |", "| --- | --- |"]
    for name in sorted(runs):
        harness = ROOT / "proof" / f"{name}_harness.c"
        if not harness.exists() or (only and name not in only):
            continue
        if name in not_gated and name not in only:
            out.append(f"| `{name}` | not gated: cover does not converge "
                       "(proof/reach-floors.txt) |")
            print(f"proof-reach: {name} not gated, skipped", flush=True)
            continue
        cmd = reach_command(name, runs, shared_defines)
        # The log carries the exact command, so a floor can be re-measured
        # by hand under the flags the gate used and not a reconstruction.
        print(f"proof-reach: {name} command: {shlex.join(cmd)}", flush=True)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                                 preexec_fn=_cap_memory)
        except subprocess.TimeoutExpired:
            out.append(f"| `{name}` | timed out |")
            print(f"proof-reach: {name} timed out", flush=True)
            continue
        m = re.search(r"\*\* (\d+) of (\d+) covered \(([0-9.]+)%\)", res.stdout)
        if not m:
            why = "over memory" if res.returncode < 0 or "bad_alloc" in res.stderr \
                else "not measured"
            out.append(f"| `{name}` | {why} |")
            print(f"proof-reach: {name} {why}", flush=True)
            # A harness with a floor that returns no number is a failed
            # gate, not a blank: the floor exists to notice regressions,
            # and a silent blank is how one went unnoticed.
            if name in floors:
                fell.append((name, 0.0, floors[name]))
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
    if dead:
        out += ["**Reaches nothing at its bound:** " +
                ", ".join(f"`{n}`" for n in dead) + ".", ""]
    return out, dead, fell


if __name__ == "__main__":
    sys.exit(main())
