#!/usr/bin/env python3
"""What each gate reads, and the commands a selection produces.

Mapping answers the questions a selector asks: which sources a bin/
target compiles, which targets the gate graph holds, which tier already
runs each one, which sources each packaged object carries, and which
sources any list in the tree names at all. is_wide() names the paths no
selection may narrow. Entry and Plan hold what a selector produces: one
command, the reason it is in the plan, the gates it covers, and the tier
that already runs them.
"""

import re

from impact_read import (ROOT, RUNS_BINARY, SUFFIXES, binaries_run,
                         binary_sources, expand, harness_sources, harnesses,
                         make_db, named_in, run, violations)


# Paths whose change the mapping refuses to narrow. Each one either feeds
# every gate or has no source list to read.
#   Makefile, test/platforms.mk  every recipe and every roster
#   *.h at the root              $(HDRS) is a prerequisite of every
#                                binary, so narrowing would be a lie
#   cfg.h, ct.h, buf.h           the same, and every module includes them
#   tools/toolchain.env          the pinned compilers every gate runs
#   .github/                     the workflows that run the gates
#   .clang-tidy, .semgrep/       the lint rules themselves
#   proof/run.sh, harness.h      every harness's flags and bounds
#   proof/prove-one.sh           the wrapper every single-harness run
#                                execs, so it carries those same flags
#   tools/impact*.py             this mapping and its selectors
WIDE_PATHS = {
    "Makefile", "test/platforms.mk", "tools/toolchain.env", ".clang-tidy",
    "proof/run.sh", "proof/harness.h", "proof/coverage.py",
    "proof/prove-one.sh", "tools/exact-fill.py",
    "tools/impact.py", "tools/impact_read.py",
    "tools/impact_map.py", "tools/impact_select.py", "test/impact_test.py",
    ".clang-format",
}
WIDE_PREFIXES = (".github/", ".semgrep/")


# ---------------------------------------------------------------------------
# What a selector produces


class Entry:
    """One command, why it is in the plan, and the gates it covers.

    A gate id is what a .violation's `catches` line says: a bin/ binary
    by name, a script by path, or `proof/prove-one.sh <harness>`.

    The tier says which existing tier already runs this gate — check,
    check-slow, or only the nightly — so a plan can be compared against
    the tier it replaces instead of against a different set of gates."""

    def __init__(self, group, command, reason, gates=(), tier="nightly"):
        self.group = group
        self.command = command
        self.reason = reason
        self.gates = sorted(set(gates))
        self.tier = tier

    def as_dict(self):
        return {"group": self.group, "command": self.command,
                "reason": self.reason, "gates": self.gates, "tier": self.tier}


TIERS = ["check", "slow", "nightly"]

# Where the gate graph starts. Every target these name through a
# `$(MAKE) <target>` line is a gate, and the binaries and scripts those
# recipes run are the roster. check-slow lists check as a prerequisite;
# the rest are the legs only the nightly runs. A binary no gate runs —
# bin/timing, which only the load-sensitive `timing` target runs — stays
# out of the roster, so a change never selects it.
GATE_ROOTS = ["check-slow", "diff-ecdsa", "diff-pq", "diff-webpki",
              "handshake-sequence", "handshake-sequence-pq",
              "test-invariants", "prove-slow", "m3-check", "cross-check",
              "san-check"]

# The axis values print-lib-srcs is asked about. The first four are the
# packaged-object legs `make check` builds; the fifth adds the sources
# only PIN=ecdsa and KEX=pq package, so the five together are every
# source some object carries.
LIB_AXES = ["", "TRUST=ca", "TRUST=webpki", "TRANSPORT=quic",
            "PIN=ecdsa KEX=pq"]


# ---------------------------------------------------------------------------
# What the tree says each gate reads


class Mapping:
    """What the tree says each gate reads."""

    def __init__(self):
        self._lib_legs = None
        self._named = None
        self.variables, self.rules = make_db()
        self.harnesses = harnesses()
        self.violations = violations()
        self.sources = {t: binary_sources(t, self.variables, self.rules)
                        for t in self.rules if t.startswith("bin/")}
        self.gates = self.gate_targets()
        # The binaries a gate runs directly, and the scripts a gate runs
        # that run a binary of their own.
        self.direct_run = set()
        self.scripts = set()
        for target in self.gates:
            _prereqs, recipe = self.rules.get(target, ([], []))
            self.direct_run |= binaries_run(recipe, self.variables)
            for line in recipe:
                self.scripts |= set(re.findall(r"\./(test/[a-z0-9_-]+\.sh)", line))
        # The gate wrapper scripts a violation names are gates too.
        self.scripts |= {f"test/{p.name}" for p in ROOT.glob("test/lint-*.sh")}
        self.scripts |= {f"test/{p.name}" for p in ROOT.glob("test/docker-*.sh")}
        # Both directions: which scripts run a binary, and which binaries
        # a script runs. A script runs no make, so a plan that selects
        # one has to build what it runs — the same reason a violation
        # whose catches is a script carries a 'builds' line.
        self.script_runs = {}
        self.script_binaries = {}
        for script in sorted(self.scripts):
            path = ROOT / script
            if not path.exists():
                continue
            names = set(RUNS_BINARY.findall(path.read_text()))
            self.script_binaries[script] = names
            for name in names:
                self.script_runs.setdefault(name, set()).add(script)
        # A binary nothing in the gate graph runs is built, not gated.
        self.runnable = self.direct_run | set(self.script_runs)
        # Which tier already runs each gate, for tier_of below.
        self.check_targets = self.gate_targets(["check"])
        self.slow_targets = self.gate_targets(["check-slow"])
        self.check_binaries, self.slow_binaries = set(), set()
        self.script_tier = {}
        for tier, targets in (("slow", self.slow_targets),
                              ("check", self.check_targets)):
            for target in targets:
                _prereqs, recipe = self.rules.get(target, ([], []))
                binaries = binaries_run(recipe, self.variables)
                if tier == "check":
                    self.check_binaries |= binaries
                else:
                    self.slow_binaries |= binaries
                for line in recipe:
                    for script in re.findall(r"\./(test/[a-z0-9_-]+\.sh)", line):
                        self.script_tier[script] = tier

    def tier_of(self, command, gates=()):
        """Which existing tier already runs this command's gate.

        Read from the gate graph: the targets `make check` runs, then
        the ones `make check-slow` adds, then everything else, which only
        the nightly runs. The gates decide where they exist, because a
        command and its gate can differ — check-slow runs
        ./bin/handshake_sequence_test, and the plan runs the same binary
        through `make handshake-sequence`, which builds the oracle
        first."""
        found = ["nightly"]
        for gate in gates:
            if gate.startswith("proof/prove-one.sh "):
                found.append("slow" if self.harnesses[gate.split()[1]][0]
                             == "fast" else "nightly")
            elif "/" in gate:
                found.append(self.script_tier.get(gate, "nightly"))
            elif gate in self.check_binaries:
                found.append("check")
            elif gate in self.slow_binaries:
                found.append("slow")
        words = command.split()
        if words[0] == "make":
            target = next((w for w in words[1:] if "=" not in w), "")
            if target in self.check_targets:
                found.append("check")
            elif target in self.slow_targets:
                found.append("slow")
        elif words[0] in self.script_tier:
            found.append(self.script_tier[words[0]])
        return min(found, key=TIERS.index)

    def gate_targets(self, roots=None):
        """Every target the roots run, through a `$(MAKE) <target>`
        line or through a prerequisite that is itself a phony target.
        check-slow lists check as a prerequisite and runs
        ct-widemul-check through $(MAKE), so both edges are followed."""
        found, queue = set(), list(GATE_ROOTS if roots is None else roots)
        while queue:
            target = queue.pop()
            if target in found or target not in self.rules:
                continue
            found.add(target)
            prereqs, recipe = self.rules[target]
            queue += [p for p in prereqs
                      if p in self.rules and not p.startswith("bin/")]
            for line in recipe:
                for names in re.findall(r"\$\(MAKE\)((?: [A-Za-z0-9_=./-]+)+)",
                                        line):
                    queue += [w for w in names.split() if "=" not in w]
        return found

    def lib_legs(self):
        """Axis value -> the sources that object packages, asked of the
        Makefile's own print-lib-srcs rather than listed here. Computed
        once: it costs five make invocations, and test/impact_test.py
        builds a plan for every violation's file.

        The first four axis values are the packaged-object legs `make
        check` builds. The fifth adds the sources only PIN=ecdsa and
        KEX=pq package, so lib_sources() below is every source some
        object carries. bench/device-ram.sh and lint-trust-separation ask
        the same way, and a list kept here is what fell four modules
        behind the handshake split."""
        if self._lib_legs is None:
            legs = {}
            for axis in LIB_AXES:
                r = run("make", "-s", "print-lib-srcs", "RAND=drbg",
                        *axis.split())
                legs[axis] = {w for w in r.stdout.split() if w.endswith(".c")}
            self._lib_legs = legs
        return self._lib_legs

    def lib_sources(self):
        """Every source some packaged object carries."""
        return set().union(*self.lib_legs().values())

    def named_sources(self):
        """Every source the tree's own lists name.

        The make database is the first list: a variable's expanded value,
        a rule's prerequisites, a recipe line. The proof harnesses are
        the second, because a harness includes the module it proves and
        no make variable names that. A source in neither is a source no
        rule in the tree reads, which is what a file added in this change
        looks like -- and it is why a new file selects every gate rather
        than the lint-only plan it would otherwise get."""
        if self._named is None:
            found = set()
            for value in self.variables.values():
                found |= named_in(expand(value, self.variables))
            for target, (prereqs, recipe) in self.rules.items():
                found |= named_in(target)
                found |= {p for p in prereqs if p.endswith(SUFFIXES)}
                for line in recipe:
                    found |= named_in(expand(line, self.variables))
            for name in self.harnesses:
                found |= harness_sources(name)
            self._named = found
        return self._named


def is_wide(path, mapping):
    """True when a changed path selects everything, with the reason."""
    if path in WIDE_PATHS or path.startswith(WIDE_PREFIXES):
        return f"{path} feeds every gate, so nothing can be ruled out"
    if "/" not in path and path.endswith((".h", ".hpp")):
        return (f"{path} is a root header, and $(HDRS) is a prerequisite "
                f"of every test binary")
    if not (ROOT / path).exists():
        return f"{path} is gone from the tree, so no rule can read what it fed"
    if path.endswith(SUFFIXES) and path not in mapping.named_sources():
        return (f"{path} is a source no list in the tree names, so it is new "
                f"here and the gates that read git's own file list "
                f"(lint-trust-separation, lint-codegen-partition, lint-size) "
                f"are the ones that judge it")
    return None


def known(path):
    """True when a rule in plan() places this path.

    A source is placed by is_wide() above instead: one the tree names
    goes to the selectors, and one it does not selects every gate.

    .gitignore is deliberately absent: four gates read `git ls-files`,
    so an ignore rule decides which files they see at all, and no
    narrower selection is honest."""
    if path.endswith(SUFFIXES):
        return True
    return any(path.startswith(p) for p in
               ("spec/", "test/", "proof/", "docs/", "bench/", "examples/",
                "fuzz/", "tools/", ".githooks/")) or path in (
        "README.md", "SECURITY.md", "CONTRIBUTING.md", "CLAUDE.md")


class Plan:
    """The commands a change selects, deduplicated, each with its reason.

    add() merges a repeat rather than dropping it: two rules can select
    the same command for different reasons, and the gates the second one
    names are added to the entry the first one made."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.entries = []
        self.by_command = {}

    def add(self, group, command, reason, gates=(), tier=None):
        """tier overrides the one the gate graph gives this command. One
        rule needs it: the build line for a script's binaries runs at the
        script's tier, and its own command names no gate."""
        entry = self.by_command.get(command)
        if entry is None:
            entry = Entry(group, command, reason, gates)
            self.entries.append(entry)
            self.by_command[command] = entry
        else:
            entry.gates = sorted(set(entry.gates) | set(gates))
        entry.tier = tier or self.mapping.tier_of(command, entry.gates)
