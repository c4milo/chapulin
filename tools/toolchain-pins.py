#!/usr/bin/env python3
"""Check that tools/toolchain.env is the only place a tool version is written.

Two failures, both silent without this check.

The first is a workflow or a local action that hardcodes a version the pins
file already carries. That is a second source of truth, and it drifts: the
pins used to live only in check.yml's env block, so they applied on CI and
nowhere else, and a development machine linted with whatever clang-tidy it
carried.

The second arrived with the fix. A job that reads a pin variable without
running the action that loads it gets an empty string, and `go-version: ""`
installs a default Go rather than failing. So every job that names a pin,
in a script or in a `with:` value, must run ./.github/actions/load-pins
before the first read.

Run through `make lint-pins`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = ROOT / "tools" / "toolchain.env"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTIONS = sorted((ROOT / ".github" / "actions").glob("*/action.yml"))
# The shell each action runs. It is where a version would be typed by hand.
SCRIPTS = sorted((ROOT / ".github" / "actions").glob("*/*.sh"))

# The one loader. It appends every pin to GITHUB_ENV, so a job that runs it
# has loaded whatever it reads. A job that sources the file by hand and echoes
# the names it thinks it needs is the copy-paste the action replaced, and it
# fails here like any other job with no loader step.
LOADER = "./.github/actions/load-pins"
LOADS_PINS = re.compile(r"^\s*(-\s+)?uses:\s*" + re.escape(LOADER) + r"\s*(#.*)?$")

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
                "the file is read by `make include`, `sh .` and load-pins"
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


def pin_shaped_values(text):
    """Yield (line_no, value) for every `with:` entry and every input `default:`.

    A bare "23" cannot be searched for across a file: it also sits inside
    commit SHAs and sha256 values. These two places carry a value whole, so
    they can be compared exactly: a `with:` entry handed to an action, and an
    input's `default:` in an action.yml.
    """
    with_indent = None
    for i, line in enumerate(text.split("\n"), 1):
        body = line.lstrip()
        if not body or body.startswith("#"):
            continue
        indent = len(line) - len(body)
        if with_indent is not None and indent <= with_indent:
            with_indent = None
        if re.match(r"with:\s*(#.*)?$", body):
            with_indent = indent
            continue
        m = re.match(r"([\w-]+):\s*(.*?)\s*(#.*)?$", body)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if with_indent is not None or key == "default":
            yield i, value.strip("\"'")


# A version tag is a pointer its owner can move; a commit SHA is not. Every
# action reference was converted by hand, and nothing stopped the next one from
# arriving as a tag: `uses: some-org/thing@v2` pasted from a README passed every
# check in the tree. Local `./` paths carry no upstream, so for them the check
# is that the path exists: actionlint validates a local action's inputs only
# when it finds the action.yml, and says nothing when it does not.
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(?:\s+#\s*(\S+))?")
PINNED_REF = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}$")


def check_action_refs(problems):
    """Every `uses:` names a commit SHA with its version, or a local action that exists."""
    for f in WORKFLOWS + ACTIONS:
        rel = f.relative_to(ROOT)
        for i, line in enumerate(f.read_text().split("\n"), 1):
            m = USES.match(line)
            if not m:
                continue
            ref, comment = m.group(1), m.group(2)
            if ref.startswith("./"):
                if not (ROOT / ref[2:] / "action.yml").is_file():
                    problems.append(
                        f"{rel}:{i}: {ref} has no action.yml, and actionlint skips a "
                        f"local action it cannot find\n    {line.strip()}"
                    )
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


def check_hardcoded(problems, pins):
    """No workflow, action or action script carries a value the pins file holds."""
    hardcoded = {v: k for k, v in pins.items() if k not in LITERAL_SKIP}
    for pattern in DERIVED:
        hardcoded[pattern.format(**pins)] = "LLVM_MAJOR"
    whole = {pins[name]: name for name in LITERAL_SKIP}

    for f in WORKFLOWS + ACTIONS + SCRIPTS:
        text = f.read_text()
        rel = f.relative_to(ROOT)
        for value, name in sorted(hardcoded.items()):
            for i, line in enumerate(text.split("\n"), 1):
                if value in line:
                    problems.append(
                        f"{rel}:{i}: {name} is hardcoded as {value!r}; "
                        f"read it from tools/toolchain.env instead\n    {line.strip()}"
                    )
        if f.suffix != ".yml":
            continue
        for i, value in pin_shaped_values(text):
            if value in whole:
                problems.append(
                    f"{rel}:{i}: {whole[value]} is hardcoded as {value!r}; "
                    f"pass ${{{{ env.{whole[value]} }}}} from load-pins instead"
                )


def check_jobs_load(problems, pins):
    """Every job that reads a pin runs load-pins, and runs it first."""
    for wf in WORKFLOWS:
        rel = wf.relative_to(ROOT)
        for job, body in split_jobs(wf.read_text()):
            lines = body.split("\n")
            reads = {}
            for i, line in enumerate(lines):
                for name in pins:
                    if re.search(rf"\${name}\b", line) or f"env.{name}" in line:
                        reads.setdefault(name, i)
            if not reads:
                continue
            loader = next((i for i, l in enumerate(lines) if LOADS_PINS.match(l)), None)
            names = ", ".join(sorted(reads))
            if loader is None:
                problems.append(
                    f"{rel}: job {job!r} reads {names} without running {LOADER}, "
                    "so the value is the empty string"
                )
                continue
            early = sorted(name for name, i in reads.items() if i < loader)
            if early:
                problems.append(
                    f"{rel}: job {job!r} reads {', '.join(early)} before {LOADER} "
                    "runs, so the value is the empty string"
                )


def main():
    pins = read_pins()
    problems = []
    check_action_refs(problems)
    check_hardcoded(problems, pins)
    check_jobs_load(problems, pins)

    if problems:
        for p in problems:
            print(f"lint-pins: {p}")
        return 1

    refs = sum(
        1
        for f in WORKFLOWS + ACTIONS
        for line in f.read_text().split("\n")
        if USES.match(line) and not USES.match(line).group(1).startswith("./")
    )
    print(
        f"lint-pins: {len(pins)} versions from one file, {refs} action refs on a "
        f"commit SHA, every job that reads a pin runs load-pins first"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
