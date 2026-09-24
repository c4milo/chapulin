#!/usr/bin/env python3
"""Checks tools/impact.py against test/violations/ as the ground truth.

Run from the repository root: python3 test/impact_test.py

Every file in test/violations/ names the file it edits and the target
that must object to the edit. That pairing is a recorded fact about this
tree: break webpki_name.c this way and bin/webpki_name_test fails. So it
is also the strongest available statement of what a change to a file can
break, and a selection tool that drops one of those targets from its
plan would let the inner loop miss a failure it was built to catch.

For each violation this asserts that the plan for its edited file
carries the target its `catches` line names. A miss is a bug in the
mapping in tools/impact.py, never in this file: the fix is to teach the
mapping where that gate reads its sources, never to drop the violation
from the comparison.

Seven more assertions come free from the same data:

  every command the plan emits parses as `make <target>` naming a target
  the Makefile has, or as a script the tree holds — a plan that names a
  target nobody defined runs nothing and reports nothing

  every `make run-X` names a binary the Makefile builds, because the
  run-% pattern rule builds bin/$* and nothing else would

  every command that links the packaged object names RAND, which has no
  default: without it the build stops at cfg.h's #error, so the command
  fails on a tree with nothing wrong

  every plan entry whose gate is a gate wrapper script runs the command
  that script execs, variables included

  the everything plan runs every gate a narrow plan can select, so the
  plan for a Makefile edit is never thinner than the plan for one source

  a path the mapping refuses to narrow selects every gate, so the
  fail-closed rule is tested rather than asserted — including a source
  the tree's own lists do not name, which is what a new file is

  a working tree that differs from the base gives the plan its changed
  set, and an unchanged one prints no command: the two shapes `make
  impact-run` meets in an inner loop

It runs in a second or two (it starts a few make invocations and reads
files), so make check runs it through the lint-impact target.

It lives here rather than in tools/ because it reads test/violations/ as
its ground truth, and CLAUDE.md keeps a script with the thing it
operates on. The subject is tools/impact.py; the data is this
directory's.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

# After sys.path, which is the point. The tool is four modules: the
# readers, the mapping, the selectors, and the command line that runs
# them. Each assertion below names the one it reads.
import impact_map  # noqa: E402
import impact_read  # noqa: E402
import impact_select  # noqa: E402


def plan_gates(mapping, path):
    """Every gate id the plan for one changed path covers."""
    gates = set()
    for entry in impact_select.plan([path], mapping):
        gates |= set(entry.gates)
    return gates


def check_violations(mapping):
    """Every violation's catching target is in the plan for its file."""
    violations = impact_read.violations()
    plans, misses = {}, []
    for name in sorted(violations):
        edited, catches = violations[name]
        if edited not in plans:
            plans[edited] = plan_gates(mapping, edited)
        if catches not in plans[edited]:
            misses.append((name, edited, catches))
    print(f"impact-test: {len(violations)} violations, "
          f"{len(violations) - len(misses)} covered by the plan for the file "
          f"each one edits")
    for name, edited, catches in misses:
        print(f"impact-test: {name} edits {edited} and is caught by "
              f"{catches}, which the plan for {edited} does not select")
    return len(misses)


def check_commands(mapping):
    """Every command the plan can emit names something that exists."""
    targets = set(mapping.rules)
    bad = 0
    files = sorted({v[0] for v in impact_read.violations().values()})
    files += ["webpki_time.c", "spec/lean/Spec/Sha256.lean", "test/unit_test.c",
              "proof/record_harness.c", "docs/proofs.md", "test/e2e.sh"]
    seen = set()
    for path in files:
        for entry in impact_select.plan([path], mapping):
            if entry.command in seen or entry.command.startswith("#"):
                continue
            seen.add(entry.command)
            words = entry.command.split()
            if words[0] == "make":
                target = next((w for w in words[1:] if "=" not in w), None)
                if target is None or (target not in targets
                                      and not target.startswith("run-")
                                      and target != "prove-one"):
                    print(f"impact-test: the plan emits {entry.command!r}, "
                          f"and the Makefile has no target {target!r}")
                    bad += 1
            elif words[0] == "python3":
                if not (ROOT / words[1]).exists():
                    print(f"impact-test: the plan emits {entry.command!r}, "
                          f"and {words[1]} is not in the tree")
                    bad += 1
            elif not (ROOT / words[0]).exists():
                print(f"impact-test: the plan emits {entry.command!r}, "
                      f"and {words[0]} is not in the tree")
                bad += 1
    print(f"impact-test: {len(seen)} distinct commands, all naming a make "
          f"target or a file the tree holds")
    return bad


def check_run_targets(mapping):
    """Each `make run-X` the plan emits needs a bin/X rule, because the
    run-% pattern rule builds bin/$* and nothing else would."""
    bad = 0
    files = sorted({v[0] for v in impact_read.violations().values()})
    for path in files:
        for entry in impact_select.plan([path], mapping):
            for word in entry.command.split():
                if word.startswith("run-") and f"bin/{word[4:]}" not in mapping.rules:
                    print(f"impact-test: the plan emits {entry.command!r} and "
                          f"the Makefile has no bin/{word[4:]} rule")
                    bad += 1
    print("impact-test: every run- command names a binary the Makefile builds")
    return bad


# A source no list in the tree names, written under bin/ so nothing
# tracked is touched: .gitignore covers bin/, and the file is removed
# again. This is the shape of a file a change adds, and the only way to
# test that branch is to have the file on disk.
NEW_SOURCE = "bin/impact-test-new-source.c"


def check_fail_closed(mapping):
    """A path the mapping refuses to narrow selects every gate."""
    bad = 0
    every = plan_gates(mapping, "Makefile")
    new = ROOT / NEW_SOURCE
    new.parent.mkdir(exist_ok=True)
    new.write_text("int impact_test_new_source(void) { return 0; }\n")
    try:
        paths = ("Makefile", "ct.h", "cfg.h", "buf.h", "tools/toolchain.env",
                 ".github/workflows/check.yml", "proof/prove-one.sh",
                 "a_file_nobody_added.c", NEW_SOURCE)
        for path in paths:
            entries = impact_select.plan([path], mapping)
            if not entries or entries[0].group != "everything":
                print(f"impact-test: {path} must select every gate and does not")
                bad += 1
                continue
            gates = set()
            for entry in entries:
                gates |= set(entry.gates)
            missing = sorted(every - gates)
            if missing:
                print(f"impact-test: {path} selects everything but its gate "
                      f"list drops {' '.join(missing)}")
                bad += 1
    finally:
        new.unlink(missing_ok=True)
    print(f"impact-test: every wide path selects all {len(every)} gates, a "
          f"source no list names included")
    return bad


def everything_runs(mapping):
    """What the everything plan runs: every target its commands name,
    every target those targets run, the scripts in their recipes, the
    binaries behind both, and the helper scripts they call."""
    targets, scripts = set(), set()
    for _tier, command, _reason in impact_select.FULL_COMMANDS:
        words = command.split()
        if words[0] == "make":
            targets.add(next((w for w in words[1:] if "=" not in w), ""))
        else:
            scripts.add(words[0])
    targets = mapping.gate_targets(sorted(targets))
    binaries, helpers = set(), set()
    for target in targets:
        _prereqs, recipe = mapping.rules.get(target, ([], []))
        binaries |= impact_read.binaries_run(recipe, mapping.variables)
        for line in recipe:
            line = impact_read.expand(line, mapping.variables)
            scripts |= set(re.findall(r"\./(test/[a-z0-9_-]+\.sh)", line))
            helpers |= set(re.findall(
                r"\b((?:tools|test|proof|bench)/[a-z0-9_-]+\.(?:py|sh))", line))
    for script in scripts:
        binaries |= mapping.script_binaries.get(script, set())
    return targets, scripts | helpers, binaries


def command_gap(command, mapping, targets, scripts, binaries):
    """What the everything plan would have to add to run this command,
    or None when it already runs it."""
    words = command.split()
    if words[0] != "make":
        name = words[1] if words[0] == "python3" else words[0]
        return None if name in scripts else name
    names = [w for w in words[1:] if "=" not in w]
    target = names[0] if names else ""
    if target.startswith("bin/"):
        gaps = [n for n in names if n[len("bin/"):] not in binaries]
        return " ".join(gaps) if gaps else None
    if target.startswith("run-"):
        return None if target[len("run-"):] in binaries else target
    if target == "prove-one":
        name = next((w.split("=", 1)[1] for w in words
                     if w.startswith("HARNESS=")), "")
        return None if name in mapping.harnesses else command
    if command in impact_select.RUN_VIA.values():
        binary = next(b for b, c in impact_select.RUN_VIA.items() if c == command)
        if binary in binaries:
            return None
    return None if target in targets else target


def sample_paths():
    """The paths every command-shaped assertion runs over: each file a
    violation edits, plus one of every other shape the selectors have a
    rule for."""
    files = sorted({v[0] for v in impact_read.violations().values()})
    return files + ["webpki_time.c", "tls.c", "p256.c", "mlkem.c",
                    "spec/lean/Spec/Sha256.lean", "test/unit_test.c",
                    "test/hpp_test.cpp", "examples/psk_client.c",
                    "proof/record_harness.c", "docs/proofs.md", "test/e2e.sh",
                    "tools/proof-cover.py", "bench/sram.sh"]


def check_full_covers(mapping):
    """The everything plan runs every gate a narrow plan can select.

    Without this the plan for a Makefile edit can be thinner than the
    plan for one source file: FULL_COMMANDS held no sanitizer lane while
    58 single-file plans selected one. Comparing wide paths against
    full_plan's own output cannot see that, because both sides come from
    the same list."""
    targets, scripts, binaries = everything_runs(mapping)
    bad, seen = 0, set()
    for path in sample_paths():
        for entry in impact_select.plan([path], mapping):
            if entry.group == "everything" or entry.command.startswith("#"):
                continue
            if entry.command in seen:
                continue
            seen.add(entry.command)
            gap = command_gap(entry.command, mapping, targets, scripts,
                              binaries)
            if gap:
                print(f"impact-test: a plan emits {entry.command!r}, and the "
                      f"everything plan runs no {gap!r}; add it to "
                      f"FULL_COMMANDS")
                bad += 1
    print(f"impact-test: the everything plan runs every gate {len(seen)} "
          f"selected commands name")
    return bad


def check_script_commands(mapping):
    """A plan entry whose gate is a gate wrapper script runs the command
    that script execs.

    The wrapper exists so test/violations.py has a path to run, and the
    plan runs make directly, so the two spellings sit in different files
    and nothing else compares them. test/lint-stack-webpki.sh execs
    `make -s lint-stack TRUST=webpki`; a plan that emitted the same
    target without the variable would run the default budget and call
    the webpki object checked."""
    bad, seen = 0, set()
    for path in sample_paths():
        for entry in impact_select.plan([path], mapping):
            if entry.group == "everything":
                continue
            for gate in entry.gates:
                if not gate.endswith(".sh"):
                    continue
                wants = impact_read.script_target(gate)
                if wants is None or (gate, entry.command) in seen:
                    continue
                seen.add((gate, entry.command))
                if entry.command != f"make {wants}":
                    print(f"impact-test: {entry.command!r} carries the gate "
                          f"{gate}, which execs 'make -s {wants}'; the plan "
                          f"must run the same command")
                    bad += 1
    print("impact-test: every wrapper-script gate runs the command its "
          "script execs")
    return bad


def links_packaged_object(mapping):
    """Every make target whose prerequisites include the packaged
    object, directly or through another target."""
    found = {impact_read.expand("$(LIB_OBJ)", mapping.variables)}
    growing = True
    while growing:
        growing = False
        for target, (prereqs, _recipe) in mapping.rules.items():
            if target not in found and found & set(prereqs):
                found.add(target)
                growing = True
    return found


def check_rand_named(mapping):
    """Every command that builds the packaged object names RAND.

    RAND has no default, so a build that declares no entropy pattern
    stops at cfg.h's #error (Makefile). A plan that emitted a bare `make
    cxx-check` failed the whole run on a tree with nothing wrong."""
    linked = links_packaged_object(mapping)
    bad, seen = 0, set()
    for path in sample_paths():
        for entry in impact_select.plan([path], mapping):
            if entry.command in seen or entry.command.startswith("#"):
                continue
            seen.add(entry.command)
            words = entry.command.split()
            if words[0] != "make" or any(w.startswith("RAND=") for w in words):
                continue
            named = [w for w in words[1:] if "=" not in w and w in linked]
            if named:
                print(f"impact-test: the plan emits {entry.command!r}, which "
                      f"builds the packaged object and names no RAND")
                bad += 1
    print("impact-test: every command that links the packaged object names RAND")
    return bad


SCRATCH = "docs/impact.md"


def scratch_index(env):
    """The working tree written into a temporary index, so the
    repository's own index is untouched."""
    subprocess.run(["git", "add", "-A"], cwd=ROOT, env=env, check=True,
                   capture_output=True)


def check_dirty_tree():
    """A working tree that differs from the base gives the plan its
    changed set. That is the normal inner loop: a file edited and never
    committed has to appear in the plan.

    The difference is made in the base, not in the working tree. A
    temporary index records the tree as it stands, one path's entry is
    replaced by a blob holding other bytes, and that tree becomes the
    base -- so `git diff --name-only <base>` reports the path, and this
    check writes nothing a developer can lose. It used to edit
    docs/impact.md in place and restore it, which left the file modified
    if the run was killed between the two."""
    index = ROOT / "bin" / "impact-test-index"
    index.parent.mkdir(exist_ok=True)
    index.unlink(missing_ok=True)
    env = dict(os.environ, GIT_INDEX_FILE=str(index))
    try:
        scratch_index(env)
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"],
                              cwd=ROOT, input="impact-test scratch\n",
                              check=True, capture_output=True,
                              text=True).stdout.strip()
        subprocess.run(["git", "update-index", "--add", "--cacheinfo",
                        f"100644,{blob},{SCRATCH}"], cwd=ROOT, env=env,
                       check=True, capture_output=True)
        tree = subprocess.run(["git", "write-tree"], cwd=ROOT, env=env,
                              check=True, capture_output=True,
                              text=True).stdout.strip()
        out = subprocess.run([sys.executable, "tools/impact.py", "--base",
                              tree, "--json"], cwd=ROOT, capture_output=True,
                             text=True)
    finally:
        index.unlink(missing_ok=True)
    if out.returncode != 0:
        print(f"impact-test: tools/impact.py exited {out.returncode} against "
              f"a base the working tree differs from\n{out.stderr}")
        return 1
    if SCRATCH not in json.loads(out.stdout)["changed"]:
        print(f"impact-test: {SCRATCH} differs from the base and did not "
              f"appear in the changed set; the inner loop reads the working "
              f"tree")
        return 1
    print("impact-test: a file the base disagrees with appears in the "
          "changed set")
    return 0


def check_empty_plan():
    """An unchanged tree prints no command at all.

    --commands is read by a shell, so a note on stdout would run as a
    command: `make impact-run` on a clean tree failed with "impact::
    command not found" before this. The base is the working tree's own
    content, written through a temporary index so the repository's index
    is untouched.

    The tool runs against that index too. It asks `git ls-files --others`
    for the untracked files, and against the repository's index a scratch
    file a developer has not added yet is one -- so this check failed on
    a tree whose only fault was an unadded file."""
    index = ROOT / "bin" / "impact-test-index"
    index.parent.mkdir(exist_ok=True)
    index.unlink(missing_ok=True)
    env = dict(os.environ, GIT_INDEX_FILE=str(index))
    try:
        scratch_index(env)
        tree = subprocess.run(["git", "write-tree"], cwd=ROOT, env=env,
                              check=True, capture_output=True,
                              text=True).stdout.strip()
        out = subprocess.run([sys.executable, "tools/impact.py", "--base",
                              tree, "--commands"], cwd=ROOT, env=env,
                             capture_output=True, text=True)
    finally:
        index.unlink(missing_ok=True)
    if out.returncode != 0 or out.stdout.strip():
        print(f"impact-test: --commands on an unchanged tree printed "
              f"{out.stdout.strip()!r}; it must print nothing")
        return 1
    print("impact-test: an unchanged tree prints no command")
    return 0


def main():
    mapping = impact_map.Mapping()
    bad = (check_violations(mapping) + check_commands(mapping)
           + check_run_targets(mapping) + check_rand_named(mapping)
           + check_script_commands(mapping) + check_full_covers(mapping)
           + check_fail_closed(mapping)
           + check_dirty_tree() + check_empty_plan())
    if bad:
        print(f"impact-test: {bad} problem(s); fix the mapping in "
              f"tools/impact.py, never this comparison")
        return 1
    print("impact-test: the plan covers every recorded violation target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
