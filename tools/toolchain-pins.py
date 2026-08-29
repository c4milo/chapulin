#!/usr/bin/env python3
"""Check that tools/toolchain.env is the only place a tool version is written.

Two failures, both silent without this check.

The first is a workflow that hardcodes a version the pins file already
carries. That is a second source of truth, and it drifts: the pins used to
live only in check.yml's env block, so they applied on CI and nowhere else,
and a development machine linted with whatever clang-tidy it carried.

The second arrived with the fix. A job that reads a pin variable without
running the step that loads it gets an empty string, and `go-version: ""`
installs a default Go rather than failing. So every job that names a pin
must also load the pins.

Run through `make lint-pins`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = ROOT / "tools" / "toolchain.env"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

# Match the source line, not the name of the step that runs it. Every workflow
# calls that step "Load the toolchain pins" today, and a rename is a rename
# rather than a defect; sourcing the file is the thing that has to happen, so
# that is what this checks.
LOADS_PINS = re.compile(r"\.\s+\.?/?tools/toolchain\.env\b")

# LLVM_MAJOR is checked through the versioned binary names rather than the
# bare number, because "22" also appears in runner labels and timeouts.
DERIVED = ("clang-tidy-{LLVM_MAJOR}", "clang-format-{LLVM_MAJOR}", "clang-{LLVM_MAJOR}")
LITERAL_SKIP = {"LLVM_MAJOR"}


def read_pins():
    pins = {}
    for line in PINS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            sys.exit(f"lint-pins: {PINS} line is not NAME=value: {line!r}")
        name, _, value = line.partition("=")
        if name != name.strip() or value != value.strip() or '"' in value or "'" in value:
            sys.exit(
                f"lint-pins: {name} must be NAME=value with no spaces or quotes; "
                "the file is read by both `make include` and `sh .`"
            )
        pins[name] = value
    return pins


def split_jobs(text):
    """Yield (job_name, body) for each top-level job in a workflow."""
    lines = text.split("\n")
    starts = [
        (i, m.group(1))
        for i, line in enumerate(lines)
        if (m := re.match(r"^  ([A-Za-z][\w-]*):\s*$", line))
    ]
    # Everything above the first job header is `on:`/`env:` preamble.
    for n, (i, name) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        yield name, "\n".join(lines[i:end])


def main():
    pins = read_pins()
    problems = []

    hardcoded = {v: k for k, v in pins.items() if k not in LITERAL_SKIP}
    for pattern in DERIVED:
        hardcoded[pattern.format(**pins)] = "LLVM_MAJOR"

    for wf in WORKFLOWS:
        text = wf.read_text()
        rel = wf.relative_to(ROOT)

        for value, name in sorted(hardcoded.items()):
            for i, line in enumerate(text.split("\n"), 1):
                if value in line:
                    problems.append(
                        f"{rel}:{i}: {name} is hardcoded as {value!r}; "
                        f"read it from tools/toolchain.env instead\n    {line.strip()}"
                    )

        for job, body in split_jobs(text):
            used = {
                name
                for name in pins
                if re.search(rf"\${name}\b", body) or f"env.{name}" in body
            }
            if used and not LOADS_PINS.search(body):
                problems.append(
                    f"{rel}: job {job!r} reads {', '.join(sorted(used))} without "
                    "sourcing tools/toolchain.env, so the value is the empty string"
                )

    if problems:
        for p in problems:
            print(f"lint-pins: {p}")
        return 1

    print(
        f"lint-pins: {len(pins)} versions, one source, "
        f"every job that reads one loads it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
