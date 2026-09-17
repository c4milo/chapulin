#!/usr/bin/env python3
"""Check that chapulin's TRANSPORT=quic mode stays in files named quic*.

Run from the repository root through `make lint-quic-partition`:

    python3 tools/quic-partition.py

INV-27. Every root source and header that only a `TRANSPORT=quic` build
compiles is named `quic*`, so `git ls-files 'quic*'` names every file the
mode owns. Two sets of file hold mode-only text under another name, and
the Makefile lists each so a reader finds them without the prefix:
`QUIC_SHARED`, the pair both transports compile, and `QUIC_CONDITIONAL`,
the shared files that carry a `#ifdef CH_TRANSPORT_QUIC` arm. A file
outside those two lists that gains text under the define fails here, so
a seventh conditional file is a decision someone makes rather than one
that lands unnoticed.

The preprocessor decides, not a list. Every root `.c` and `.h` file is
preprocessed twice, once without `-DCH_TRANSPORT_QUIC` and once with it,
and the two outputs are compared against each other. Comparing each run
against empty instead would see only the files that hold nothing else:
a QUIC-only declaration added to a file that already declares something
would pass, which is the likeliest way the partition breaks.

Three flags make the comparison answer for the file in hand.

`-fdirectives-only` handles directives and expands includes but leaves
macro invocations in the text alone. Expanding them makes files that
carry no QUIC arm read as conditional: `handshake.c` writes
`REC_HANDSHAKE`, `record.h` defines that macro in a TLS build alone, and
under full expansion `handshake.c`, `session.c` and `tls.c` all changed.

The line markers say which file each line came from, and only the lines
the file itself wrote are compared. Counting the lines its includes
contribute answers for `cfg.h` rather than for the file, and most root
files include `cfg.h`: over a third of them change when the whole
translation unit is read.

`-DCH_RAND_EXTERN` answers the `#error` `cfg.h` raises when no entropy
pattern is chosen, which is why `bench/sram.sh` passes it too.

A `quic*` file is held to more than the comparison: the whole
translation unit, its includes included, must preprocess to no
declaration without the define. An `#include` above the transport guard
passes the comparison, because the declarations it pulls in belong to
the file included, and it still puts those declarations in a TLS build
that reads the header.

What this cannot see. It reads whole files, so a QUIC-only function
inside a file both transports compile is invisible: a QUIC arm added to
`session.c` passes, and review catches that. It also cannot judge a file
that gates text on a `CH_QUIC_`-prefixed macro it does not define
itself, because the lint defines `CH_TRANSPORT_QUIC` and nothing else,
so it reports such a file rather than passing it.
"""

import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from impact_read import make_db

ROOT = Path(__file__).resolve().parent.parent

CC = os.environ.get("CC") or "cc"
FLAGS = ["-E", "-fdirectives-only", "-x", "c", "-std=c11", "-DCH_RAND_EXTERN",
         "-I."]
DEFINE = "-DCH_TRANSPORT_QUIC"

# A conditional and the identifiers it tests. `defined` is the operator,
# not a macro name.
CONDITIONAL = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif)\b(.*)$")
DEFINITION = re.compile(r"(?m)^\s*#\s*define\s+(\w+)")
IDENTIFIER = re.compile(r"\b([A-Za-z_]\w*)\b")
MARKER = re.compile(r'^#\s+\d+\s+"([^"]*)"')


def run(*args):
    """Read from git, or say which command failed and stop."""
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"quic-partition: {' '.join(args)} failed: "
                 f"{r.stderr.strip()}")
    return [line for line in r.stdout.split("\n") if line]


def preprocess(path, define):
    """One preprocessor run over one file, as (whole, own).

    `whole` is every line the run emitted, `own` only the lines the file
    itself wrote, read from the line markers. Both drop blank lines.
    None means the run failed or emitted no marker for the file, and the
    caller reports that as a file it cannot judge."""
    args = [CC] + FLAGS + ([DEFINE] if define else []) + [path]
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        return None
    whole, own, here, seen = [], [], False, False
    for line in r.stdout.split("\n"):
        marker = MARKER.match(line)
        if marker is not None:
            here = marker.group(1) == path
            seen = seen or here
            continue
        if not line.strip():
            continue
        whole.append(line.strip())
        if here:
            own.append(line.strip())
    return (whole, own) if seen else None


def code(lines):
    """The lines that declare something, which is every line that is not
    a preprocessor directive."""
    return [line for line in lines if not line.startswith("#")]


def declarations(lines):
    """How many of these lines end a statement. A parameter on its own
    line ends in a comma and counts for nothing."""
    return len([line for line in lines if line.endswith(";")])


def plural(count, word):
    """`1 line` and `3 lines`, so a count of one reads as English."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def unresolved_macros(path):
    """The `CH_QUIC_` macros one file gates text on and does not define
    itself. The lint defines `CH_TRANSPORT_QUIC` and nothing else, so an
    arm behind one of these stays closed in both runs and the file's
    verdict would be read off text neither build compiles. A file's own
    include guard is a definition, which is why it is not one of these.
    """
    text = (ROOT / path).read_text()
    own = set(DEFINITION.findall(text))
    found = []
    for line in text.split("\n"):
        conditional = CONDITIONAL.match(line)
        if conditional is None:
            continue
        for name in IDENTIFIER.findall(conditional.group(2)):
            if name.startswith("CH_QUIC_") and name not in own | set(found):
                found.append(name)
    return found


def lists():
    """The four Makefile variables this lint reads, expanded by make
    rather than parsed here: the two exemption lists and the two file
    lists the formatter and clang-tidy read."""
    variables, _ = make_db()
    return {name: variables.get(name, "").split()
            for name in ("QUIC_SHARED", "QUIC_CONDITIONAL", "HDRS", "LINT_C")}


def judge(path, quic, shared, conditional):
    """What one root file is, and every complaint about it.

    Returns the verdict -- "quic", "conditional", "shared" or "silent"
    -- and the messages. A file is QUIC-only when it writes no
    declaration without the define and gains something with it."""
    off = preprocess(path, False)
    if off is None:
        return None, [f"{path} does not preprocess without {DEFINE}, so this "
                      f"lint cannot judge it"]
    on = preprocess(path, True)
    if on is None:
        return None, [f"{path} does not preprocess with {DEFINE}, so this "
                      f"lint cannot judge it"]
    unresolved = unresolved_macros(path)
    if unresolved:
        return None, [f"{path} gates text on {', '.join(unresolved)}, which "
                      f"it does not define and this lint does not define "
                      f"either, so this lint cannot judge it; gate the "
                      f"mode's text on CH_TRANSPORT_QUIC"]

    whole_off, own_off = off
    _, own_on = on
    gained = [line for line in own_on if line not in own_off]
    lost = [line for line in own_off if line not in own_on]
    quic_only = not code(own_off) and (gained or lost)

    if path in quic:
        return "quic", quic_problems(path, code(own_off), code(whole_off),
                                     gained or lost)
    if path in shared:
        if quic_only:
            return "quic", [f"{path} is QUIC-only, and both transports must "
                            f"compile it; the QUIC_SHARED comment in the "
                            f"Makefile says why it carries no prefix"]
        return "shared", []
    if quic_only:
        return "quic", [f"{path} is QUIC-only and carries no quic prefix; "
                        f"name it quic_<stem> so git ls-files 'quic*' names "
                        f"every file the mode owns"]
    if gained or lost:
        if path in conditional:
            return "conditional", []
        return "conditional", [
            f"{path} gains {plural(len(gained), 'line')} with {DEFINE}, "
            f"{plural(declarations(code(gained)), 'declaration')} among "
            f"them, and neither QUIC_SHARED nor QUIC_CONDITIONAL names it; "
            f"move the mode's text into a quic* file, or add {path} to "
            f"QUIC_CONDITIONAL in the Makefile if the mode really owns an "
            f"arm there"]
    return "silent", []


def quic_problems(path, own_code, whole_code, gains):
    """What a `quic*` file must hold: nothing a TLS build compiles, and
    something a QUIC build does."""
    if own_code:
        return [f"{path} declares something without {DEFINE}; a quic* file "
                f"puts its whole body inside #ifdef CH_TRANSPORT_QUIC"]
    if whole_code:
        return [f"{path} preprocesses to declarations without {DEFINE}; put "
                f"the #include lines inside the #ifdef CH_TRANSPORT_QUIC with "
                f"the rest of the body, because an include above the guard "
                f"pulls its declarations into a TLS build"]
    if not gains:
        return [f"{path} contributes nothing that {DEFINE} changes, so no "
                f"build compiles anything from it that a TLS build does not"]
    return []


def missing(names, variable):
    """An exemption for a file that is not there any more."""
    return [f"{variable} names {name}, which does not exist; drop the entry"
            for name in names if not (ROOT / name).exists()]


def absent(names, variable):
    """A list whose every file is still to be written. QUIC_SHARED names
    the .c file before it exists, so the entries are checked as a set:
    one file on disk is the exemption standing for something."""
    if any((ROOT / name).exists() for name in names):
        return []
    return [f"{variable} names no file that exists, so the exemption stands "
            f"for nothing"]


def unused(names, variable, seen):
    """An exemption its file stopped needing. The list is where a reader
    looks for the mode's text outside the prefix, so an entry that names
    a file holding none of it sends that reader to the wrong place."""
    return [f"{variable} names {name}, which contributes the same text to "
            f"both transports; drop the entry"
            for name in names if (ROOT / name).exists() and name not in seen]


def listed(variable, want, have):
    """Every file of the mode must sit in the lists clang-format and
    clang-tidy read, or neither tool sees it. The Makefile has no
    TRANSPORT axis yet, so no list names a quic source to build; these
    two are the lists that exist today, and the axis lands beside them.
    """
    return [f"{name} is not in {variable}, so clang-format and clang-tidy "
            f"never read it; add it to {variable} in the Makefile"
            for name in want if name not in have]


def main(argv):
    if argv:
        sys.exit(f"quic-partition: unknown option {argv[0]}")
    names = lists()
    shared = [f for f in names["QUIC_SHARED"] if (ROOT / f).exists()]
    quic = [p for p in run("git", "ls-files", "quic*") if "/" not in p]
    roots = [p for p in run("git", "ls-files", "*.c", "*.h") if "/" not in p]

    problems, counts, conditional = [], {}, []
    if not quic:
        problems.append("git tracks no root quic*.c or quic*.h file, so the "
                        "checks below would read nothing")
    problems += absent(names["QUIC_SHARED"], "QUIC_SHARED")
    # Two preprocessor runs over ninety files is most of a second even
    # when each one is short, and `make check` holds a one-minute
    # budget, so the runs go out together. Each file is judged on its
    # own, and map keeps the answers in the order the files were read,
    # so the report reads the same every time.
    with ThreadPoolExecutor() as pool:
        verdicts = list(pool.map(
            lambda path: judge(path, quic, names["QUIC_SHARED"],
                               names["QUIC_CONDITIONAL"]), roots))
    for path, (verdict, found) in zip(roots, verdicts):
        problems += found
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict == "conditional":
            conditional.append(path)

    problems += missing(names["QUIC_CONDITIONAL"], "QUIC_CONDITIONAL")
    problems += unused(names["QUIC_CONDITIONAL"], "QUIC_CONDITIONAL",
                       conditional)
    problems += listed("HDRS", [p for p in quic if p.endswith(".h")],
                       names["HDRS"])
    problems += listed("LINT_C", [p for p in quic if p.endswith(".c")],
                       names["LINT_C"])

    if problems:
        for problem in problems:
            print(f"lint-quic-partition: {problem}")
        return 1
    print(f"lint-quic-partition: {counts.get('quic', 0)} of {len(roots)} root "
          f"files are QUIC-only and every one is named quic*; QUIC_SHARED "
          f"holds {len(shared)} that both transports compile and "
          f"QUIC_CONDITIONAL {counts.get('conditional', 0)} that carry a "
          f"transport arm")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
