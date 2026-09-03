#!/usr/bin/env python3
"""Check that the nightly's report job waits on every other nightly job.

The report job in .github/workflows/nightly.yml files an issue when a job
in its needs list fails or times out. A job absent from that list still
runs and still goes red, and nothing files anything: proof-reach was
absent from the day it was added, so a red or timed-out proof-reach
filed no issue. This check holds the needs list equal to the set of
other jobs, so a job added to the file cannot be left out of the report.

Run through `make lint-nightly-report`.
"""

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NIGHTLY = ROOT / ".github" / "workflows" / "nightly.yml"
REPORT = "report"

# tools/toolchain-pins.py owns the job splitter, and the reasoning for
# splitting on indentation rather than on how a job's name is spelled. Its
# file name carries a hyphen, so it is loaded by path rather than imported
# by name.
_spec = importlib.util.spec_from_file_location(
    "toolchain_pins", Path(__file__).with_name("toolchain-pins.py")
)
toolchain_pins = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(toolchain_pins)


def needs_of(body):
    """The job ids in the body's `needs:` list, or None when it has none.

    The list is read as one flow sequence, `needs: [a, b]`, over as many
    lines as it takes to reach the closing bracket. That is the form the
    file uses, and lint-matrix reads the proof matrix the same way.
    """
    lines = body.split("\n")
    for i, line in enumerate(lines):
        m = re.match(r"^\s+needs:\s*(.*?)\s*(#.*)?$", line)
        if not m:
            continue
        text = m.group(1)
        if not text.startswith("["):
            sys.exit(
                f"lint-nightly-report: {REPORT}'s needs must be a flow list, "
                "[a, b], so this check can read it"
            )
        while "]" not in text:
            i += 1
            text += " " + lines[i].split("#", 1)[0].strip()
        inner = text[1 : text.index("]")]
        return [item.strip().strip("\"'") for item in inner.split(",") if item.strip()]
    return None


def main():
    rel = NIGHTLY.relative_to(ROOT)
    jobs = dict(toolchain_pins.split_jobs(NIGHTLY.read_text()))
    if REPORT not in jobs:
        sys.exit(f"lint-nightly-report: {rel} has no {REPORT} job")
    needs = needs_of(jobs[REPORT])
    if needs is None:
        sys.exit(f"lint-nightly-report: {rel}: {REPORT} has no needs list")

    others = set(jobs) - {REPORT}
    missing = sorted(others - set(needs))
    unknown = sorted(set(needs) - others)
    for name in missing:
        print(
            f"lint-nightly-report: {rel}: {name} is not in {REPORT}'s needs, "
            f"so a red or timed-out {name} files no issue"
        )
    for name in unknown:
        print(
            f"lint-nightly-report: {rel}: {REPORT} needs {name}, which is not "
            "a job in the file"
        )
    if missing or unknown:
        return 1
    print(f"lint-nightly-report: {REPORT} waits on all {len(others)} other nightly jobs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
