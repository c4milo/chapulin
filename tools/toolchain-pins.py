#!/usr/bin/env python3
"""Check that tools/toolchain.env is the only place a tool version is written.

Four failures, all silent without this check.

The first is a workflow or a local action that hardcodes a version the pins
file already carries. That is a second source of truth, and it drifts: the
pins used to live only in check.yml's env block, so they applied on CI and
nowhere else, and a development machine linted with whatever clang-tidy it
carried.

The second arrived with the fix. A job that reads a pin variable without
running the action that loads it gets an empty string, and `go-version: ""`
installs a default Go rather than failing. So every job that names a pin,
in a script or in a `with:` value, must run ./.github/actions/load-pins
before the first read. A read is any of the three spellings a workflow
has for a variable: `$NAME` and `${NAME}` in a run block, and `env.NAME`
in an expression. A comment is not a read.

The third is the one value the first check cannot search for. LLVM_MAJOR
is a bare number, and a bare "23" also sits inside commit SHAs and
sha256 values, so the workflows and action.yml files are checked through
the versioned package names instead. The action scripts carry no hashes:
there the bare token itself is rejected, so `llvm.sh 23` or `lld-23`
typed by hand fails as `clang-23` does.

The fourth is a download nothing checks. A version pin names a release,
and the install step downloads that release's file and unpacks or runs it,
so the file is checked against its *_SHA256 pin first or the job runs
whatever the server sent (https://github.com/c4milo/chapulin/issues/142).
The action scripts exist to install what they fetch, so every fetch there
needs a check. A workflow step or a local script may also fetch data that
is nothing to check -- toolchain-pins.yml reads go.dev's release list --
so there the rule is narrower: a fetch whose URL carries a version pin, on
the fetch line or through a variable assigned from one earlier in the same
unit, needs a check. A check is a `sha256sum -c` or `shasum -a 256 -c`
that follows the fetch before the next one.

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
# The scripts that mirror a CI lane on a development machine. They source
# tools/toolchain.env and fetch the same toolchains the actions do.
LOCAL_SCRIPTS = sorted(
    p for d in ("bench", "proof", "test") for p in (ROOT / d).glob("*.sh")
)

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


def bare_major(pins):
    """The bare LLVM major as a whole token, for the action scripts only.

    The scripts hold no SHAs or hashes, so the number itself can be searched
    for there. A dotted version is not the token: the runner's own name,
    ubuntu-24.04, would otherwise match the day the pin reads 24.
    """
    major = re.escape(pins["LLVM_MAJOR"])
    return re.compile(rf"(?<!\d\.)\b{major}\b(?!\.\d)")


def read_patterns(pins):
    """One pattern per pin, matching every spelling a job reads it by.

    `$NAME` and `${NAME}` in a run block, and `env.NAME` in an expression.
    The braces form went unmatched once, so a job could read a pin that way
    and pass. `$NAMEX` is another variable and does not match.
    """
    return {
        name: re.compile(rf"\$\{{?{re.escape(name)}\b\}}?|\benv\.{re.escape(name)}\b")
        for name in pins
    }


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
    """Yield (job_name, head, body) for each job under the top-level `jobs:` key.

    `head` is the index of the job's first line in `text`, so a finding
    inside the body can name its line in the file.

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
        yield name, i, "\n".join(lines[i:end])


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

    major = bare_major(pins)

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
        if f.suffix == ".sh":
            for i, line in enumerate(text.split("\n"), 1):
                if major.search(line):
                    problems.append(
                        f"{rel}:{i}: LLVM_MAJOR is hardcoded as the bare "
                        f"{pins['LLVM_MAJOR']!r}; read the major from the action's "
                        f"input instead\n    {line.strip()}"
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
    patterns = read_patterns(pins)
    for wf in WORKFLOWS:
        rel = wf.relative_to(ROOT)
        for job, _, body in split_jobs(wf.read_text()):
            lines = body.split("\n")
            reads = {}
            for i, line in enumerate(lines):
                if line.lstrip().startswith("#"):
                    continue  # a comment naming a pin reads nothing
                for name, pattern in patterns.items():
                    if pattern.search(line):
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


# curl or wget as a command: first on the line, or after a key, a pipe, a
# separator, a subshell or sudo. `apt-get install curl` names the package
# and matches nothing here.
FETCH = re.compile(r"(?:^|[:|;&(`]|\$\()\s*(?:sudo\s+)?(?:curl|wget)\b")
# The two spellings of a check: coreutils on the runners, perl's shasum on
# a development Mac.
CHECK = re.compile(r"\bsha256sum\s+(?:-c|--check)\b|\bshasum\s+-a\s*256\s+(?:-c|--check)\b")
# A shell assignment, `name=` at the start of a word. A variable assigned
# from a pinned one carries the pin to the fetch line that reads it.
ASSIGN = re.compile(r"(?:^|\s)([A-Za-z_]\w*)=")
# An action's env entries set from its inputs. The pins reach the action
# script under these names (VERSION, SHA256), not their own.
INPUT_ENV = re.compile(r"^\s+([A-Z][A-Z0-9_]*):\s*\$\{\{\s*inputs\.", re.M)


def logical_lines(lines, first):
    """Yield (line_no, text): comment lines dropped, backslash continuations joined.

    `first` is the file line number of lines[0]; a joined command keeps the
    number of its first line.
    """
    joined, start = "", None
    for i, line in enumerate(lines):
        body = line.strip()
        if start is None and (not body or body.startswith("#")):
            continue
        if start is None:
            start = first + i
        if body.endswith("\\"):
            joined += body[:-1] + " "
            continue
        yield start, joined + body
        joined, start = "", None
    if start is not None:
        yield start, joined


def reads_one_of(names):
    """A pattern for `$NAME` or `${NAME...}` with NAME in names."""
    if not names:
        return re.compile(r"(?!)")
    return re.compile(r"\$\{?(?:" + "|".join(map(re.escape, sorted(names))) + r")\b")


def fetches(lines, first, pinned, every):
    """Split one unit's fetches into (checked, unchecked).

    A fetch is checked when a hash check follows it before the next fetch or
    the end of the unit. `pinned` names the variables a pin can reach, and a
    variable assigned from one joins the set as the unit is read. With
    `every`, each fetch counts; otherwise only a fetch that reads a pinned
    variable does.
    """
    pinned = set(pinned)
    checked, unchecked, pending = [], [], None
    for no, text in logical_lines(lines, first):
        if CHECK.search(text):
            if pending is not None:
                checked.append(pending)
            pending = None
            continue
        for m in ASSIGN.finditer(text):
            if reads_one_of(pinned).search(text[m.end():]):
                pinned.add(m.group(1))
        if FETCH.search(text) and (every or reads_one_of(pinned).search(text)):
            if pending is not None:
                unchecked.append(pending)
            pending = (no, text)
    if pending is not None:
        unchecked.append(pending)
    return checked, unchecked


def step_name(step, key_indent):
    """The step's own `name:`, or its first line when it has none."""
    for line in step:
        m = re.match(r"^(?:\s{%d}|\s*-\s+)name:\s*(.*?)\s*$" % key_indent, line)
        if m:
            return m.group(1).strip("\"'")
    return step[0].strip().lstrip("- ")


def split_steps(lines):
    """Yield (offset, name, step_lines) for each step of one job body.

    Steps are the `- ` items under `steps:`, found by indentation as
    split_jobs finds jobs: the first item sets the indent, and every later
    line at that indent starting with `- ` opens the next step. A `- `
    deeper in, inside a run block, is that step's text.
    """
    try:
        steps_at = next(
            i for i, l in enumerate(lines) if re.match(r"^\s*steps:\s*(#.*)?$", l)
        )
    except StopIteration:
        return
    heads, indent = [], None
    for i in range(steps_at + 1, len(lines)):
        m = re.match(r"^(\s*)-\s", lines[i])
        if m and indent is None:
            indent = len(m.group(1))
        if m and len(m.group(1)) == indent:
            heads.append(i)
    for n, i in enumerate(heads):
        end = heads[n + 1] if n + 1 < len(heads) else len(lines)
        yield i, step_name(lines[i:end], indent + 2), lines[i:end]


def check_fetches(problems, pins):
    """Every download of a pinned release file is checked against a hash before use.

    Returns the number of checked fetches, for the summary line.
    """
    units = []  # (file, where, line number of lines[0], lines, pinned names, every)
    for f in SCRIPTS + ACTIONS:
        names = set(pins) | set(INPUT_ENV.findall((f.parent / "action.yml").read_text()))
        units.append((f, "the script", 1, f.read_text().split("\n"), names, True))
    for wf in WORKFLOWS:
        for job, head, body in split_jobs(wf.read_text()):
            for offset, name, step in split_steps(body.split("\n")):
                where = f"job {job!r} step {name!r}"
                units.append((wf, where, head + offset + 1, step, set(pins), False))
    for f in LOCAL_SCRIPTS:
        units.append((f, "the script", 1, f.read_text().split("\n"), set(pins), False))

    count = 0
    for f, where, first, lines, names, every in units:
        checked, unchecked = fetches(lines, first, names, every)
        count += len(checked)
        for no, text in unchecked:
            problems.append(
                f"{f.relative_to(ROOT)}:{no}: {where} downloads a file nothing "
                f"checks: no sha256sum -c follows it. Check the download against "
                f"its *_SHA256 pin in tools/toolchain.env before unpacking or "
                f"running it\n    {text}"
            )
    return count


def main():
    pins = read_pins()
    problems = []
    check_action_refs(problems)
    check_hardcoded(problems, pins)
    check_jobs_load(problems, pins)
    downloads = check_fetches(problems, pins)

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
        f"commit SHA, every job that reads a pin runs load-pins first, "
        f"{downloads} downloads each checked against a hash"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
