#!/usr/bin/env python3
"""Reads the mapping for tools/impact.py out of the tree.

Nothing here decides what to run. Each function answers one question
about what the tree already says, and every answer comes from a file
the tree keeps for another reason:

  make -qp              every variable expanded, and every rule with its
                        prerequisites and recipe, so each bin/ target
                        names the sources it compiles
  proof/run.sh          launch lines name each harness's tier and its
                        linked sources; the harness file names the
                        module it includes
  test/violations/      each .violation names the file it edits and the
                        target that must object
  test/lint-*.sh        each gate wrapper script names the make command
                        it execs

So the mapping decays if those stop naming their sources, which is why
a Makefile edit selects every gate.
"""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# The Makefile, read through make itself


def make_db():
    """Every variable expanded and every rule, from `make -qp`.

    -q runs no recipe and -p prints the database, so this reads the
    Makefile the way make does instead of parsing ifeq chains and
    $(filter-out) by hand. make exits 1 because targets are out of date;
    the database is on stdout either way."""
    text = run("make", "-qp").stdout
    variables, rules = {}, {}
    files = text.split("\n# Files\n", 1)
    head = files[0]
    for line in head.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*) :?= ?(.*)$", line)
        if m:
            variables[m.group(1)] = m.group(2)
    if len(files) == 1:
        return variables, rules
    target, recipe, prereqs = None, [], ""
    for line in files[1].splitlines():
        if line.startswith("\t"):
            if target:
                recipe.append(line[1:])
            continue
        m = re.match(r"^([^#\s][^:=]*):(?!=)\s?(.*)$", line)
        if m:
            if target:
                rules[target] = (prereqs.split(), recipe)
            target, prereqs, recipe = m.group(1).strip(), m.group(2), []
        elif not line.startswith("#") and not line.strip():
            continue
    if target:
        rules[target] = (prereqs.split(), recipe)
    return variables, rules


# The suffixes a recipe compiles. .cpp and .hpp are here for one file
# each -- test/hpp_test.cpp and chapulin.hpp, which cxx-check compiles --
# and without them a change to the C++ wrapper's test selected no build.
SUFFIXES = (".c", ".h", ".cpp", ".hpp")
SOURCE = re.compile(r"\b([a-z0-9_]+(?:/[a-z0-9_]+)*\.(?:c|h|cpp|hpp))\b")


def expand(text, variables, depth=0):
    """$(NAME) replaced by NAME's value, repeatedly.

    A reference inside a make function expands to the variable's whole
    value: $(filter-out p256.c,$(SRCS)) yields every name in SRCS,
    p256.c included. That over-selects by design — the rule at the top
    of this file — and it keeps this from reimplementing make."""
    if depth > 8:
        return text
    out = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]",
                 lambda m: variables.get(m.group(1), ""), text)
    return out if out == text else expand(out, variables, depth + 1)


def target_sources(target, variables, rules):
    """The sources a make target compiles: its prerequisites plus every
    source its recipe names once variables are expanded."""
    prereqs, recipe = rules.get(target, ([], []))
    found = {p for p in prereqs if SOURCE.fullmatch(p)}
    for line in recipe:
        found |= set(SOURCE.findall(expand(line, variables)))
    return found


def binary_sources(target, variables, rules, seen=None):
    """The sources a bin/ target compiles, following the bin/ rules it
    lists as prerequisites.

    One level is not enough. `bin/example_psk: $(EXAMPLE_PSK)` names one
    prerequisite, bin/obj/<variant>/example_psk, and that rule is where
    examples/psk_client.c is written; reading the first rule alone mapped
    both example binaries and bin/example_ca's siblings to no source at
    all. Only prerequisites under bin/ are followed, so a phony gate
    whose prerequisites are binaries keeps its own recipe's scope."""
    seen = seen if seen is not None else set()
    if target in seen:
        return set()
    seen.add(target)
    found = target_sources(target, variables, rules)
    prereqs, _recipe = rules.get(target, ([], []))
    for prereq in prereqs:
        if prereq.startswith("bin/") and prereq in rules:
            found |= binary_sources(prereq, variables, rules, seen)
    return found


# `./bin/name`, and not the first segment of `./bin/san/unit`: the
# sanitizer, coverage and cross lanes build into subdirectories, and
# reading "san" out of one of those paths would put a binary no rule
# defines into the roster.
RUNS_BINARY = re.compile(r"\./bin/([a-z0-9_]+)(?![\w/])")


def named_in(text):
    """Every source path this text names, whatever its spelling.

    SOURCE above reads the paths a recipe compiles, and its lowercase
    segments are what keep it from matching prose. This one answers a
    different question -- does any list in the tree name this file at all
    -- so it takes whitespace-separated words instead, and so it sees
    test/freertos/FreeRTOSConfig.h and .semgrep/invariants.c, which
    SOURCE does not match."""
    words = (w.strip("()\"',;:") for w in text.split())
    return {w for w in words if w.endswith(SUFFIXES)}


def binaries_run(recipe, variables):
    """The bin/ binaries a recipe runs, as `./bin/name`."""
    names = set()
    for line in recipe:
        names |= set(RUNS_BINARY.findall(expand(line, variables)))
    return names


# ---------------------------------------------------------------------------
# proof/run.sh


def harnesses():
    """Harness name -> (tier, sources it compiles).

    The launch line names the tier and the linked sources; the harness
    file names the module it includes, following a harness that wraps a
    sibling the way the PIN variants do."""
    text = (ROOT / "proof" / "run.sh").read_text()
    out = {}
    for m in re.finditer(r'^launch (\S+) (\w+) (\S+) (\d+) "([^"]*)"(.*)$', text, re.M):
        tier, _mode, name, _unwind, _unwindset, rest = m.groups()
        sources = set(re.findall(r"\b([a-z0-9_]+\.c)\b", rest))
        sources |= harness_sources(name)
        out[name] = (tier.split(":")[0], sources)
    return out


def harness_sources(name, seen=None):
    return proof_includes(ROOT / "proof" / f"{name}_harness.c", seen)


def proof_includes(path, seen=None):
    """The sources one harness compiles, following its includes.

    Three shapes appear: the module itself (#include "x25519.c"), a
    sibling harness the PIN variants wrap, and a proof-local header that
    includes the module for it — proof/x25519_stubs.h holds the multiply
    contract x25519_step and x25519_tail prove against, and includes
    x25519.c itself, so a harness that stops at the header sees no
    module."""
    seen = seen if seen is not None else set()
    if path in seen or not path.exists():
        return set()
    seen.add(path)
    found = {str(path.relative_to(ROOT))}
    for inc in re.findall(r'#include "([a-z0-9_]+\.[ch])"', path.read_text()):
        local = ROOT / "proof" / inc
        if local.exists():
            found |= proof_includes(local, seen)
        elif inc.endswith(".c"):
            found.add(inc)
    return found


# ---------------------------------------------------------------------------
# test/violations/ and the gate wrapper scripts


def violations():
    """Violation name -> (edited file, catches line)."""
    out = {}
    for path in sorted((ROOT / "test" / "violations").glob("*.violation")):
        head = {}
        for line in path.read_text().splitlines():
            if line.strip() in ("--- old", "--- new"):
                break
            key, _, value = line.partition(":")
            if value:
                head[key.strip()] = value.strip()
        if "file" in head and "catches" in head:
            out[path.stem] = (head["file"], head["catches"])
    return out


def script_target(script):
    """What a gate wrapper script passes to make, or None. A wrapper that
    names a variable gives it back too: test/lint-stack-webpki.sh answers
    "lint-stack TRUST=webpki".

    test/lint-wide-multiply.sh and its four siblings exist because
    test/violations.py runs a path and a make target is not a path. The
    plan runs the make command and records the script path as the gate,
    so a violation naming either one matches."""
    path = ROOT / script
    if not path.exists():
        return None
    m = re.search(r"^exec make -s (.+)$", path.read_text(), re.M)
    return m.group(1).strip() if m else None
