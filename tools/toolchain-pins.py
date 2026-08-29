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

# LLVM_MAJOR is checked through the versioned binary names rather than the bare
# number: a bare "22" also matches inside the actions/setup-go commit SHAs.
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
    """Yield (job_name, body) for each job under the top-level `jobs:` key.

    Jobs are found by indentation, which is what YAML uses to delimit them,
    rather than by how the name is spelled. Keying on the name missed
    `build: # only on tags` and `"build":` — both legal — and a missed header
    is not a skipped job but a job whose body merges into the one above it,
    so a job with no loader step inherits the loader of its predecessor and
    the check passes when it should fail.
    """
    lines = text.split("\n")
    try:
        start = next(
            i for i, l in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", l)
        )
    except StopIteration:
        return

    heads = []
    end_of_jobs = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.strip() and not line.startswith(" "):
            end_of_jobs = i  # a new top-level key closes the jobs block
            break
        if re.match(r"^  [^\s#].*:", line):
            name = line.strip().split(":", 1)[0].strip("\"'")
            heads.append((i, name))

    for n, (i, name) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else end_of_jobs
        yield name, "\n".join(lines[i:end])


# A version tag is a pointer its owner can move; a commit SHA is not. Every
# action reference was converted by hand, and nothing stopped the next one from
# arriving as a tag: `uses: some-org/thing@v2` pasted from a README passed every
# check in the tree. Local `./` paths are exempt because they carry no upstream.
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(?:\s+#\s*(\S+))?")
PINNED_REF = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}$")


def check_action_refs(problems):
    """Every `uses:` names a 40-character commit SHA and its version in a comment."""
    for wf in WORKFLOWS:
        rel = wf.relative_to(ROOT)
        for i, line in enumerate(wf.read_text().split("\n"), 1):
            m = USES.match(line)
            if not m:
                continue
            ref, comment = m.group(1), m.group(2)
            if ref.startswith("./"):
                continue
            if not PINNED_REF.match(ref):
                problems.append(
                    f"{rel}:{i}: {ref} is not pinned to a commit SHA; a tag can be "
                    f"moved by whoever owns the action\n    {line.strip()}"
                )
            elif not comment:
                problems.append(
                    f"{rel}:{i}: {ref} has no trailing version comment, so a reader "
                    f"cannot tell which release this is\n    {line.strip()}"
                )


def main():
    pins = read_pins()
    problems = []
    check_action_refs(problems)

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

    refs = sum(
        1
        for w in WORKFLOWS
        for line in w.read_text().split("\n")
        if USES.match(line)
    )
    print(
        f"lint-pins: {len(pins)} versions from one file, {refs} action refs on a "
        f"commit SHA, every job that reads a pin loads it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
