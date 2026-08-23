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
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT = ROOT / "bin" / "proof-coverage.md"

# Sources that ship in the library. A file here with no harness is a
# gap; a file absent from here is not library code.
LIB = sorted(p.name for p in ROOT.glob("*.c"))


def launch_lines():
    """Harness name -> (tier, unwind, linked sources) per running line."""
    text = (ROOT / "proof" / "run.sh").read_text()
    runs = {}
    for m in re.finditer(r"^launch (\S+) (\w+) (\S+) (\d+) (.*)$", text, re.M):
        tier, _mode, name, unwind, rest = m.groups()
        linked = re.findall(r"\b([a-z0-9_]+\.c)\b", rest)
        runs[name] = (tier, int(unwind), set(linked))
    return runs


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
    args = ap.parse_args()

    runs = launch_lines()
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

    if args.reach:
        lines += reach_table(runs)

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n")
    print(f"proof-coverage: {len(LIB) - len(uncovered)}/{len(LIB)} sources in a "
          f"launched harness, {len(dormant)} dormant -> {REPORT.relative_to(ROOT)}")
    if uncovered:
        print("proof-coverage: no harness for " + ", ".join(uncovered))
    for name, _ in sorted(dormant):
        print(f"proof-coverage: {name} has no launch line")


def reach_table(runs):
    """Per harness, the share of its goto locations CBMC can reach at
    the configured bound. A low number means the bound stops the proof
    short of the code it claims to cover."""
    out = ["### Reachability at the configured bounds", "",
           "`cbmc --cover location`: the share of program locations the",
           "harness can reach. A low number means the unwind bound stops",
           "short of the code the harness claims to prove.", "",
           "| harness | locations reached |", "| --- | --- |"]
    for name in sorted(runs):
        harness = ROOT / "proof" / f"{name}_harness.c"
        if not harness.exists():
            continue
        cmd = ["cbmc", str(harness), "-I", str(ROOT), "--cover", "location",
               "--unwind", str(runs[name][1])]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            out.append(f"| `{name}` | timed out |")
            continue
        m = re.search(r"\*\* (\d+) of (\d+) covered \(([0-9.]+)%\)", res.stdout)
        out.append(f"| `{name}` | {m.group(3)}% ({m.group(1)}/{m.group(2)}) |"
                   if m else f"| `{name}` | not measured |")
    out.append("")
    return out


if __name__ == "__main__":
    sys.exit(main())
