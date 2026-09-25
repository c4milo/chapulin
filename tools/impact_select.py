#!/usr/bin/env python3
"""Turns a changed path into the commands that gate it.

One selector per kind of gate, and plan() runs them in order: the test
binaries and the lanes that write their own compile lines, the CBMC
harnesses, the differential, the packaged-object legs, the codegen
ceilings, the make targets that run a changed helper script, the
violations, and the lints. Each one adds a command, the reason it is in
the plan, and the gates it covers.

The rule is over-select, never miss, and tools/impact.py states it.
A path no selector places never falls through to a thin plan: plan()
sends it to full_plan(), which runs everything.
"""

import pathlib

from impact_map import Entry, Plan, is_wide, known
from impact_read import (ROOT, SUFFIXES, expand, script_target,
                         target_sources)


# Binaries whose own make target builds them but does not run them, and
# the command that does. bin/diff needs the Lean oracle built first, and
# the two enumerations compare against it, so each runs through the
# target that builds the spec.
RUN_VIA = {
    "diff": "make diff",
    "handshake_sequence_test": "make handshake-sequence",
    "handshake_sequence_pq": "make handshake-sequence-pq",
}

# A gate whose command is not `make <target>`. wycheproof-ct-widemul
# builds the decomposed-multiply vectors and ct-widemul-check is the
# target that runs them with the two binaries beside them; san-check
# needs the optimization level named, because "passed UBSan" says
# nothing without one (Makefile, O); cxx-check links the packaged
# object, and RAND has no default, so a bare `make cxx-check` stops at
# cfg.h's #error the way the examples do.
GATE_COMMAND = {
    "wycheproof-ct-widemul": "make ct-widemul-check",
    "san-check": "make san-check SAN=1 O=0",
    "cxx-check": "make cxx-check RAND=extern",
}

# Targets whose recipe stops unless a variable names what to run, and
# the commands that run them instead. A bare `make prove-one` and a bare
# `make cross-check` each print what to set and exit 1, so emitting one
# fails the whole run: select_proofs names the harness, and the two
# docker lanes pass CROSS and RUNNER.
NEEDS_VARIABLE = {
    "prove-one": [],
    "cross-check": ["test/docker-mips.sh", "test/docker-riscv32.sh"],
    # RAND has no default, so a bare `make lib-check` stops at cfg.h's
    # #error. The target reaches this selector at all only when the
    # impact tool itself runs under TRANSPORT=quic: there the lib-check
    # recipe writes quic.c's name in the message that says why the
    # RAND=extern import check stands down, and a recipe that names a
    # source is what select_recipe_gates looks for.
    "lib-check": ["make lib-check RAND=drbg",
                  "make lib-check cxx-check RAND=extern"],
}

# Targets no single change selects on its own. Each is an aggregate
# whose whole point is to run the others, so naming one here would turn
# a one-file change into a full run without saying so.
AGGREGATES = {"ci", "lint", "prove-all", "impact", "impact-run", "fmt",
              "clean", "check"}

# The packaged-object legs `make check` builds, keyed by the axis
# value impact_map.LIB_AXES asks print-lib-srcs about: what check runs
# for each leg, the reason each command is in a plan, and the gates it
# covers. A leg's object is built from its own source set under its own
# defines, so a source it packages is checked here and a source it
# filters out is not.
LIB_LEGS = [
    ("", [
        ("make lib-check RAND=drbg",
         "the RAND=drbg object packages {path}, and lib-check reads that "
         "object's export list", []),
        ("make lib-check cxx-check examples-check RAND=extern",
         "the RAND=extern object packages {path}, and the two examples and "
         "the C++ wrapper link that object", []),
        ("make lint-stack",
         "the default object compiles {path}, whose frame stays under the "
         "device budget", []),
    ]),
    ("TRUST=ca-rsa", [
        ("make lib-check cxx-check RAND=extern TRUST=ca-rsa",
         "the CA-mode object packages {path}, and it exports the "
         "provisioning call the other objects do not", []),
    ]),
    ("TRUST=webpki", [
        ("make lib-check cxx-check RAND=extern TRUST=webpki",
         "the TRUST=webpki object packages {path}", []),
        ("make lint-stack TRUST=webpki",
         "the TRUST=webpki object compiles {path} under -DCH_TRUST_WEBPKI, "
         "against that build's own frame budget",
         ["test/lint-stack-webpki.sh"]),
    ]),
    ("TRUST=webpki TRANSPORT=record", [
        ("make lib-check RAND=extern TRUST=webpki TRANSPORT=record",
         "the record-transport webpki object packages {path}, and it is the "
         "one client object that compiles ch_record_init and no ch_connect",
         ["test/lib-check-webpki-record.sh"]),
    ]),
    ("TRANSPORT=quic", [
        ("make lib-check cxx-check RAND=extern TRANSPORT=quic",
         "the TRANSPORT=quic object packages {path} and exports the fifteen "
         "ch_quic_ calls in place of the four TLS ones", []),
        ("make lint-stack TRANSPORT=quic",
         "the TRANSPORT=quic object compiles {path} under "
         "-DCH_TRANSPORT_QUIC, against that build's own frame budget",
         ["test/lint-stack-quic.sh"]),
    ]),
    ("TRUST=raw-ecdsa KEX=pq", [
        ("make lib-check RAND=extern TRUST=raw-ecdsa KEX=pq",
         "the raw-ecdsa KEX=pq object packages {path}, and it is the one "
         "leg that links ML-KEM into a raw-mode object", []),
    ]),
]

# What "everything" means, in the order to run it: the two tiers, then
# the legs only the nightly runs. Each entry is (tier, command, reason).
# full_plan() attaches every gate in the tree to the first command, so a
# caller reading the plan's gate list sees the whole set.
FULL_COMMANDS = [
    ("check", "make check", "the one-minute tier: lint, every unit and vector "
                            "binary, the packaged-object export list"),
    ("slow", "make check-slow", "proofs, e2e, the differential, the sequence "
                                "enumeration, the fast violation tier"),
    ("nightly", "make diff-ecdsa", "the ecdsa differential arm"),
    ("nightly", "make diff-pq", "the KEX=pq differential arm"),
    ("nightly", "make diff-webpki", "the TRUST=webpki differential arm"),
    ("nightly", "make handshake-sequence-pq", "the KEX=pq sequence enumeration"),
    ("nightly", "make prove-slow", "the SAT heavyweights"),
    ("nightly", "make test-invariants", "every violation, not only the fast tier"),
    ("nightly", "make lint-wide-multiply-gcc",
     "the codegen gate under the Arm GNU gcc"),
    ("nightly", "make m3-check", "the bare-metal Cortex-M3 roster under QEMU"),
    ("nightly", "make san-check SAN=1 O=0", "the ASan and UBSan lane"),
    ("nightly", "test/docker-mips.sh", "the mips cross lane, which runs "
                                       "cross-check under qemu-mips"),
    ("nightly", "test/docker-riscv32.sh", "the riscv32 cross lane, which runs "
                                          "cross-check under qemu-riscv32"),
]


def full_plan(mapping, why):
    entries = [Entry("everything", "# " + why,
                     "an unmapped change selects every gate (over-select, "
                     "never miss)")]
    gates = set(mapping.runnable)
    gates |= {f"proof/prove-one.sh {n}" for n in mapping.harnesses}
    gates |= {f"test/{p.name}" for p in ROOT.glob("test/*.sh")}
    for tier, command, reason in FULL_COMMANDS:
        entries.append(Entry("everything", command, reason, (), tier))
    # Every gate the tree holds, carried by the first command so a
    # caller reading the plan's gate list sees the whole set.
    entries[1].gates = sorted(gates)
    return entries


# bin/diff's driver compiled once more per define, and the rows that
# meet real C in that arm alone. The Makefile states each one at the
# target: the P-256 certificate rows at diff-ecdsa, the 1120-byte hybrid
# share at diff-pq, and the empty server_name acknowledgement with the
# three CertificateVerify schemes at diff-webpki. So a change bin/diff
# compiles can break an arm and leave `make diff` green.
DIFF_ARMS = [
    ("make diff-ecdsa", "the ecdsa arm compiles the same driver, and the "
                        "P-256 certificate rows run only there"),
    ("make diff-pq", "the KEX=pq arm compiles the same driver, and the "
                     "1120-byte hybrid share runs only there"),
    ("make diff-webpki", "the TRUST=webpki arm compiles the same driver, and "
                         "the webpki parser rows run only there"),
]


def select_tests(out, sources):
    """Every bin/ target whose sources name a changed file, and every
    script that runs one of those binaries. A bin/ rule lists what it
    compiles, so this is a lookup rather than a guess."""
    mapping = out.mapping
    for path in sources:
        for target in sorted(mapping.sources):
            if path not in mapping.sources[target]:
                continue
            name = target[len("bin/"):]
            if name not in mapping.runnable:
                continue
            if name in mapping.direct_run:
                out.add("tests", RUN_VIA.get(name, f"make run-{name}"),
                        f"bin/{name} compiles {path} "
                        f"(the Makefile names it in the recipe)", [name])
            if name == "diff":
                for command, reason in DIFF_ARMS:
                    out.add("differential", command, reason)
            for script in sorted(mapping.script_runs.get(name, ())):
                build = sorted(f"bin/{b}"
                               for b in mapping.script_binaries[script])
                # RAND has no default, and the examples link the packaged
                # object, so a bare make stops at cfg.h's #error. check
                # builds them the same way.
                out.add("tests", "make RAND=extern " + " ".join(build),
                        f"{script} runs these and builds none of them",
                        tier=mapping.tier_of(script, [script]))
                out.add("tests", script,
                        f"{script} runs bin/{name}, which compiles {path}",
                        [script, name])


def select_recipe_gates(out, sources):
    """Every gate that compiles or reads a changed source in its own
    recipe rather than through a bin/ rule.

    The scope is the target's own prerequisites and recipe, expanded, so
    this covers the lanes that write their compile lines out — the three
    differential arms, the Wycheproof suites, the sanitizer lane, the
    Cortex-M3 roster — and the lints whose recipe names its file list,
    such as lint-trust-separation. A target that needs a variable is
    named in NEEDS_VARIABLE above and runs through the commands listed
    there."""
    mapping = out.mapping
    for target in sorted(mapping.gates):
        if target.startswith("bin/") or target in AGGREGATES:
            continue
        scope = target_sources(target, mapping.variables, mapping.rules)
        hit = next((p for p in sources if p in scope), None)
        if hit is None:
            continue
        group = "lint" if target.startswith("lint-") else "tests"
        if target in NEEDS_VARIABLE:
            for command in NEEDS_VARIABLE[target]:
                out.add(group, command,
                        f"the {target} recipe compiles {hit}, and this "
                        f"command supplies the variables it needs")
            continue
        out.add(group, GATE_COMMAND.get(target, f"make {target}"),
                f"the {target} recipe names {hit}")


def select_proofs(out, csources):
    """Every CBMC harness whose launch line or includes name the file."""
    for path in csources:
        for name in sorted(out.mapping.harnesses):
            tier, sources = out.mapping.harnesses[name]
            if path in sources:
                out.add("proofs", f"make prove-one HARNESS={name}",
                        f"proof/{name}_harness.c compiles {path} "
                        f"(proof/run.sh {tier} tier)",
                        [f"proof/prove-one.sh {name}"])


# The differential arms and the two enumerations, with the gate each one
# runs. Any change under spec/ selects all of them: the differential is
# one binary run per arm, so there is nothing finer to select.
SPEC_GATES = [
    ("make diff", "the spec is the differential's oracle", ["diff"]),
    ("make diff-ecdsa", "the ecdsa arm reads the same oracle", []),
    ("make diff-pq", "the KEX=pq arm reads the same oracle", []),
    ("make diff-webpki", "the TRUST=webpki arm reads the same oracle", []),
    ("make handshake-sequence",
     "the enumeration compares against spec/lean/.lake/build/bin/diffspec",
     ["handshake_sequence_test"]),
    ("make handshake-sequence-pq",
     "the KEX=pq enumeration compares against the same binary",
     ["handshake_sequence_pq"]),
]


def select_spec(out, changed):
    if not any(p.startswith("spec/") for p in changed):
        return
    out.add("differential", "make lint-spec",
            "spec/ changed, and lint-spec bans the escape hatches in the model")
    for command, reason, gates in SPEC_GATES:
        out.add("differential", command, reason, gates)


def select_modes(out, sources, legs):
    """The packaged-object legs, one per axis value `make check` builds.

    Each leg compiles its own source set under its own defines and its
    own frame budget, so a source another leg filters out is compiled
    here and nowhere else — and so is an #ifdef body only this leg's
    defines keep. tls.c, handshake_auth.c, handshake_message.c,
    handshake_parser.c and handshake_parser_ee.c each hold a
    CH_TRUST_WEBPKI block the default object compiles out, so every leg
    that packages the file is selected, not the default leg alone."""
    packaged = set().union(*legs.values())
    for path in sources:
        for axis, commands in LIB_LEGS:
            if path not in legs.get(axis, ()):
                continue
            for command, reason, gates in commands:
                out.add("modes", command, reason.format(path=path), gates)
        # The mode partition reads every axis value's packaged source
        # list, and the webpki rows read git's list of root webpki*.c
        # files, which no make variable holds.
        if path in packaged:
            out.add("modes", "make lint-trust-separation",
                    f"{path} is packaged by some object, and this gate holds "
                    f"each axis value to its own source list")


# The files test/lib-pair-check.sh is or compiles. No bin/ rule names
# them, so the script is the one gate that reads them.
LIB_PAIR_FILES = {"test/lib-pair-check.sh", "test/lib_pair_half.c",
                  "test/lib_pair_main.c", "test/lib_pair.h"}


def select_pairs(out, changed, legs):
    """test/lib-pair-check.sh, which links two packaged objects of
    different transports into one image: a source some object packages
    can break it, and so can the files the script compiles."""
    packaged = set().union(*legs.values())
    for path in changed:
        if path in packaged or path in LIB_PAIR_FILES:
            out.add("modes", "test/lib-pair-check.sh",
                    f"{path} is packaged by some object or compiled by the "
                    f"script, and the script links objects of two "
                    f"transports into one image",
                    ["test/lib-pair-check.sh"])


def select_codegen(out, csources, lib):
    """The gates that read what the compiler emits rather than the
    source: the per-file multiply and branch ceilings, the runtime-call
    allowlist, and the two cross lanes that run the roster elsewhere."""
    mapping = out.mapping
    codegen = set(mapping.variables.get("CODEGEN_SRCS", "").split())
    cross = target_sources("cross-check", mapping.variables, mapping.rules)
    for path in csources:
        if path in codegen:
            for script in ("test/lint-wide-multiply.sh",
                           "test/lint-wide-multiply-gcc.sh",
                           "test/lint-runtime-symbols.sh"):
                out.add("codegen", f"make {script_target(script)}",
                        f"{path} is in CODEGEN_SRCS, whose emitted code "
                        f"{script} holds at its recorded ceiling", [script])
        if path in codegen or path in cross:
            for script in ("test/docker-mips.sh", "test/docker-riscv32.sh"):
                out.add("codegen", script,
                        f"the lane compiles {path} and runs it under its "
                        f"own toolchain", [script])
        if path in lib:
            out.add("codegen", "make lint-codegen-partition",
                    f"{path} must be in exactly one of the two gate lists")


def select_runners(out, changed):
    """The make targets whose recipe names a changed helper script.

    A Python or shell helper under tools/, test/, proof/ or bench/ has
    no prerequisite list, so the recipe that names it is the only
    statement of which gate it belongs to. A recipe that runs the helper
    and one that lints it both count: either can fail on the change."""
    helpers = [p for p in changed if p.endswith((".py", ".sh"))
               and not p.endswith("_test.py")]
    for path in helpers:
        for target in sorted(out.mapping.rules):
            if target.startswith("bin/") or target in AGGREGATES:
                continue
            _prereqs, recipe = out.mapping.rules[target]
            if not any(path in expand(line, out.mapping.variables)
                       for line in recipe):
                continue
            if target in NEEDS_VARIABLE:
                for command in NEEDS_VARIABLE[target]:
                    out.add("lint", command,
                            f"the {target} recipe names {path}, and this "
                            f"command supplies the variables it needs")
                continue
            out.add("lint", f"make {target}",
                    f"the {target} recipe names {path}")


def select_violations(out, changed):
    """Every violation that edits a changed file, and every violation
    the change itself adds or edits."""
    names = sorted(n for n, (f, _c) in out.mapping.violations.items()
                   if f in changed)
    if names:
        out.add("violations", "python3 test/violations.py " + " ".join(names),
                f"{len(names)} violation(s) edit these files; each requires "
                f"its target to fail")
    edited = sorted(pathlib.Path(p).stem for p in changed
                    if p.startswith("test/violations/"))
    if edited:
        out.add("violations", "python3 test/violations.py " + " ".join(edited),
                "the changed violations themselves")


# Lints that read every tracked .c and .h, so any source change selects
# them. The one that reads the library sources alone is below.
# The third element, where one is present, names the wrapper script a
# test/violations entry can put on its catches line for that same gate,
# so the violation the lint catches counts as covered by this command.
SOURCE_LINTS = [
    ("make lint-size", "every tracked .c and .h stays under 500 lines", ()),
    ("make lint-format", "clang-format covers every source", ()),
    ("make lint-tidy", "clang-tidy reads $(LINT_C) and $(HDRS)", ()),
    ("make lint-cppcheck", "cppcheck reads $(LINT_C)", ()),
    ("make lint-invariants", "semgrep scans every tracked .c and .h",
     ("test/lint-invariants.sh",)),
]


def select_lints(out, changed, csources, lib):
    for command, reason, gates in SOURCE_LINTS if csources else []:
        out.add("lint", command, reason, list(gates))
    # lint-proof-cover asks which shipped source a harness proves, so a
    # library source selects it and a test main does not. The frame budget
    # is per packaged object, so select_modes above runs one leg per
    # object instead of one lint-stack for every source.
    for path in csources:
        if path in lib:
            out.add("lint", "make lint-proof-cover",
                    f"{path} is shipped, so it needs a full harness or an "
                    f"audit entry")
    # lint-exact-fill reads the root .c files, so a root source selects it
    # whether or not the packaged object carries that source: the lint
    # judges the reader, not the object.
    for path in csources:
        if "/" not in path:
            out.add("lint", "make lint-exact-fill",
                    f"{path} is a root source, and tools/exact-fill.py reads "
                    f"every reader in one",
                    ["test/lint-exact-fill.sh"])
            break
    # The three gates that read the mode's own files. lint-quic-partition
    # compiles each quic file and checks which build keeps it;
    # lint-quic-surface compares quic.h against docs/quic.md's interface
    # table, against the stubs test/quic_stub_test.c would call if any
    # were left, and against the sources that may include each AES key
    # header; bin/quic_driver_test is
    # the build itself, which INV-26 turns into a check of its own, since
    # ch_quic holds no key and the key type is incomplete outside three
    # sources, so a write to a key field elsewhere does not compile. All
    # three read the .c files as well as the headers, so a root quic path
    # selects them whichever suffix it carries.
    quic_root = [p for p in csources if "/" not in p and p.startswith("quic")]
    if quic_root:
        out.add("lint", "make lint-quic-partition",
                "a root quic source changed, and this gate holds each quic "
                "file to the build that compiles it",
                ["test/lint-quic-partition.sh"])
        out.add("unit", "make bin/quic_driver_test",
                "the compiler is half of INV-26: a key field the session no "
                "longer holds names nothing",
                ["test/quic-builds.sh"])
    # handshake_message.c holds the refusal of SUITE=aesgcm in a raw or ca
    # client (docs/decisions.md entry 45), and test/quic-builds.sh compiles
    # that file on both sides of the refusal, beside ct.h's two.
    if "handshake_message.c" in csources:
        out.add("tests", "test/quic-builds.sh",
                "handshake_message.c refuses the AES suite in a raw or ca "
                "client, and this script compiles it either side of that",
                ["test/quic-builds.sh"])
    # lint-quic-surface also reads every root source for an include of a
    # key header, quic_aes_key.h, aes_traffic_key.h or aes_schedule.h,
    # outside the files each one names, so any root C source selects it.
    if any("/" not in p for p in csources) or "docs/quic.md" in changed:
        out.add("lint", "make lint-quic-surface",
                "quic.h and docs/quic.md must name one public surface, and "
                "only the sources each AES key header names may include it",
                ["test/lint-quic-surface.sh"])
    if any(p.endswith(".sh") or p.startswith(".githooks/") for p in changed):
        out.add("lint", "make lint-shellcheck",
                "shellcheck reads every tracked script")
    if any(p.startswith("proof/") for p in changed):
        out.add("lint", "make lint-matrix",
                "the nightly matrix must name every slow launch line")
        out.add("lint", "make lint-proof-cover",
                "a harness change moves what the signed-overflow claim rests on")
        out.add("lint", "make proof-coverage",
                "a harness with no launch line proves nothing")
        out.add("lint", "make proof-reach-smoke",
                "check runs one cover pass through proof/coverage.py --reach, "
                "on the epoch harness")
    if any(p.startswith("test/violations/") for p in changed):
        out.add("lint", "make lint-violation-builds",
                "a script target must name the binaries it runs")
    if any(p.startswith("docs/") or p in ("README.md", "SECURITY.md",
                                          "CONTRIBUTING.md") for p in changed):
        out.add("lint", "make lint-docs", "the README must name every document")
    if any(p.startswith(("docs/", "bench/")) or p == "README.md"
           for p in changed):
        out.add("lint", "make lint-bench-numbers",
                "the published memory numbers come from bench/")
    out.add("lint", "make lint-issue-links",
            "every issue reference carries its full URL, in any changed file")
    out.add("lint", "make lint-conflict-markers",
            "no tracked file keeps a merge marker")


def plan(changed, mapping):
    """The gates the changed paths can break."""
    changed = sorted(set(changed))
    for path in changed:
        why = is_wide(path, mapping)
        if why:
            return full_plan(mapping, why)
        if not known(path):
            return full_plan(mapping,
                             f"{path} matches no rule in "
                             f"tools/impact_select.py")
    out = Plan(mapping)
    # Two lists, because two questions are asked of them: the lints below
    # read the tracked .c and .h files, and a recipe compiles .cpp and
    # .hpp as well (test/hpp_test.cpp, chapulin.hpp).
    sources = [p for p in changed if p.endswith(SUFFIXES)]
    csources = [p for p in changed if p.endswith((".c", ".h"))]
    lib = mapping.lib_sources()
    select_tests(out, sources)
    select_recipe_gates(out, sources)
    select_proofs(out, csources)
    select_spec(out, changed)
    select_modes(out, sources, mapping.lib_legs())
    select_pairs(out, changed, mapping.lib_legs())
    select_codegen(out, csources, lib)
    select_runners(out, changed)
    select_violations(out, changed)
    select_lints(out, changed, csources, lib)
    return out.entries
