#!/usr/bin/env python3
"""Report what chapulin's TRANSPORT=quic mode covers, read from the tree.

Run from the repository root through `make quic-footprint`:

    python3 tools/quic-footprint.py [--check-surface]

The mode is a partition, not a scattering: every source and header that
exists only for QUIC carries the `quic` prefix, so `git ls-files 'quic*'`
names every file the mode owns. `handshake_flight.[ch]` is the one
exception, and it is deliberate -- both transports compile it -- so the
report names it and marks it shared rather than leaving a reader to
notice its absence. The mode also writes text inside the
`#ifdef CH_TRANSPORT_QUIC` arms of files a TLS build compiles, and the
prefix does not name those, so the report counts them in their own
section.

Six questions, six sections, every answer read from the tree:

  Files                    every quic file with its line count, plus the
                           shared pair, plus a total
  Mode-only text elsewhere the lines each file outside the prefix
                           compiles only under CH_TRANSPORT_QUIC, which
                           the Files table does not hold
  Share of the library     those lines against every root .c and .h
                           line, and against the .c lines one build
                           compiles, so the footprint is a number and
                           each number says what it counts
  Declared against defined how many functions each header declares, how
                           many the matching .c file defines, and how
                           many of those are stubs rather than
                           implementations
  Public surface           the `ch_quic_` entries `quic.h` declares
                           against the names docs/quic.md's interface
                           table lists
  Sections cited           the sections the headers cite, per standard,
                           so coverage against RFC 9001 is read rather
                           than guessed

The report holds two values of its own, and both are anchors into
docs/quic.md: the heading above its interface table and that table's
header row. A section's heading is prose, so nothing in the tree derives
it; the report stops with a message when either anchor stops matching,
rather than reading the document as listing nothing. Every other value
is read -- the file list from git, the shared pair from the Makefile's
QUIC_SHARED, the line counts and the names from the files themselves.

`--check-surface` prints nothing while both comparisons agree and exits 1
on either mismatch: `quic.h` against docs/quic.md's interface table, and
the stub set against the function names test/quic_stub_test.c calls. The
second is what keeps the safety rule mechanical -- a stub the test never
calls is a stub whose refusal nothing measures, and a lane that adds one
would otherwise leave every check green. `make lint-quic-surface` runs
both, and `lint` runs it. The report reaches no verdict of its own, so it exits 0
on every count it prints; it stops with a message only when something it
reads is not there, such as a missing anchor.

The report states what does not exist, and it separates a definition
from an implementation. Every `quic*.c` file is a stub today: it defines
each function its header declares, returns the refusal the header
documents and writes nothing. "N declared, N stubbed, 0 implemented" is
the honest reading of that tree, and "N of N have a definition" would
not be. A body carrying the `// CH_QUIC_STUB: ` marker is a stub,
and the marker is the one form every stub takes, so the count is read
rather than kept by hand. The same section keeps answering as the code
lands: an implemented function drops the marker and moves to the
implemented count, and a header with no .c file says so on its own line.

How a citation gets its standard. A header names the standard once and
writes `SS5.4.3` for the rest of the paragraph, so most section marks
carry no name of their own. Three rules give them one, and resolve()
states each: the name touching the mark, then the name that section
number is always written with elsewhere in the mode, then the standard
the file is mostly about. The report prints how many marks each rule
answered, so a reader knows how much of the coverage is read off a name
and how much is inferred.
"""

import re
import subprocess
import sys
from pathlib import Path

from impact_read import make_db
from quic_source import (DECLARATOR, conditional_spans, declared, defined,
                         marks_in, resolve, section_key, strip_comments,
                         stubbed)

ROOT = Path(__file__).resolve().parent.parent

# The macro the mode's text sits behind, in the files a TLS build
# compiles as well.
TRANSPORT = "CH_TRANSPORT_QUIC"

# The Makefile's variables, expanded by make and held after the first
# read.
HELD = {}

# The heading above docs/quic.md's interface table, and the header row of
# the table itself. Two anchors rather than one: the section holds a
# second table for the callbacks, and the callbacks are not the public
# surface.
DOC = Path("docs/quic.md")
DOC_HEADING = "## The interface it exposes"
DOC_TABLE_HEAD = "| call | what it does |"


def run(*args):
    """Read from git, or say which command failed and stop."""
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"quic-footprint: {' '.join(args)} failed: "
                 f"{r.stderr.strip()}")
    return [line for line in r.stdout.split("\n") if line]


def doc_entries():
    """The `ch_quic_` names docs/quic.md's interface table lists.

    The heading and the table's header row are the two anchors, and a
    renamed one stops this rather than answering that the document lists
    nothing: an empty list reads as every entry missing, which is
    fifteen false statements in place of one true one."""
    path = ROOT / DOC
    if not path.exists():
        sys.exit(f"quic-footprint: {DOC} is missing, so the public surface "
                 f"has nothing to be checked against")
    lines = path.read_text().split("\n")
    names, inside, table = [], False, False
    seen_heading, seen_table = False, False
    for line in lines:
        if line.strip() == DOC_HEADING:
            inside, seen_heading = True, True
        elif inside and line.startswith("## "):
            break
        elif inside and line.strip() == DOC_TABLE_HEAD:
            table, seen_table = True, True
        elif table and not line.startswith("|"):
            table = False
        elif table:
            found = re.match(r"\|\s*`(ch_quic_\w+)", line)
            if found:
                names.append(found.group(1))
    if not seen_heading:
        sys.exit(f"quic-footprint: {DOC} has no heading \"{DOC_HEADING}\", so "
                 f"the public surface has nothing to be checked against")
    if not seen_table:
        sys.exit(f"quic-footprint: {DOC}'s \"{DOC_HEADING[3:]}\" holds no "
                 f"table opening \"{DOC_TABLE_HEAD}\", so the public surface "
                 f"has nothing to be checked against")
    return names


def shared_files():
    """The pair both transports compile, read from the Makefile's
    QUIC_SHARED rather than copied here. `make lint-quic-partition`
    reads the same variable, so the exemption has one home and one
    name."""
    return [p for p in makefile("QUIC_SHARED") if (ROOT / p).exists()]


def quic_files():
    """Every tracked file of the mode: the quic-prefixed ones, then the
    shared pair. `git ls-files` reads the index, so a staged file counts
    and a build artifact does not."""
    listed = [p for p in run("git", "ls-files", "quic*") if "/" not in p]
    return sorted(listed), shared_files()


def library_lines():
    """Every line of library source: the .c and .h files at the root. The
    subdirectories are tests, proofs, tools and benches, and none of them
    ships."""
    total = 0
    for path in run("git", "ls-files", "*.c", "*.h"):
        if "/" not in path:
            total += len((ROOT / path).read_text().split("\n")) - 1
    return total


def lines_in(path):
    return len((ROOT / path).read_text().split("\n")) - 1


def plural(count, word):
    """`1 header` and `9 headers`, so a count of one reads as English."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def wrap(items, width, indent):
    """One column of items over as few lines as fit in width."""
    out, line = [], ""
    for item in items:
        if line and len(line) + len(item) + 1 > width:
            out.append(indent + line)
            line = ""
        line = f"{line} {item}".strip()
    if line:
        out.append(indent + line)
    return out


def role_of(path):
    """What one file is, read from the names it declares or defines. A
    file that names a `ch_quic_` entry of its own is the public API; a
    comment that merely mentions one is not."""
    read = declared if path.endswith(".h") else defined
    names = read(ROOT / path)
    public = any(n.startswith("ch_quic_") for n in names or [])
    return "quic only, public API" if public else "quic only"


def conditional_rows(quic):
    """Every root file outside the prefix that compiles lines only under
    CH_TRANSPORT_QUIC, with how many blocks and how many lines. These
    are the mode's text under names `git ls-files 'quic*'` does not
    print, so a reader who takes the Files table for the whole mode
    reads too small a number."""
    rows = []
    for path in run("git", "ls-files", "*.c", "*.h"):
        if "/" in path or path in quic:
            continue
        spans = conditional_spans(ROOT / path, TRANSPORT)
        if spans:
            rows.append((path, len(spans),
                         sum(last - first - 1 for first, last in spans)))
    return rows


def report_files(quic, shared, conditional):
    print("Files")
    rows = []
    for path in quic:
        rows.append((path, lines_in(path), role_of(path)))
    for path in shared:
        rows.append((path, lines_in(path), "shared with TRANSPORT=tls"))
    width = max(len(r[0]) for r in rows)
    for path, count, role in rows:
        print(f"  {path.ljust(width)}  {count:5d}  {role}")
    quic_total = sum(lines_in(p) for p in quic)
    shared_total = sum(lines_in(p) for p in shared)
    print(f"  {'total'.ljust(width)}  {quic_total + shared_total:5d}  "
          f"{quic_total} quic only, {shared_total} shared, whole files only")
    print(f"  The table holds whole files. Another "
          f"{sum(r[2] for r in conditional)} lines of the mode sit")
    print(f"  inside the {TRANSPORT} arms of "
          f"{plural(len(conditional), 'file')} a TLS build")
    print(f"  compiles too, which the next section lists.")
    print()
    return quic_total, shared_total


def report_conditional(conditional):
    """The mode's text in files the prefix does not name."""
    print("Mode-only text elsewhere")
    if not conditional:
        print(f"  No file outside the prefix compiles a line only under "
              f"{TRANSPORT}.")
        print()
        return
    width = max(len(r[0]) for r in conditional)
    print(f"  {'file'.ljust(width)}  blocks  lines")
    for path, blocks, count in conditional:
        print(f"  {path.ljust(width)}  {blocks:6d}  {count:5d}")
    print(f"  {'total'.ljust(width)}  {sum(r[1] for r in conditional):6d}  "
          f"{sum(r[2] for r in conditional):5d}")
    print(f"  Counted: the lines between `#ifdef {TRANSPORT}` and its")
    print(f"  `#else` or `#endif`, and the lines between an "
          f"`#ifndef {TRANSPORT}`")
    print(f"  block's `#else` and its `#endif`. A conditional that names a "
          f"second")
    print(f"  macro is not counted: a build that defines that one compiles "
          f"the arm")
    print(f"  without {TRANSPORT}.")
    print()


def makefile(name):
    """One Makefile variable, expanded by make itself. The database is
    read once and held, because make costs more than every other read
    this report makes."""
    if not HELD:
        HELD.update(make_db()[0])
    return HELD.get(name, "").split()


def build_sources():
    """The .c files one build compiles: the Makefile's own LIB_SRCS,
    which `make -s print-lib-srcs` prints and
    test/lint-trust-separation.sh reads the same way. The axis values
    default to TRUST=raw PIN=rsa KEX=x25519, so this is the smallest
    build the tree has."""
    return [s for s in makefile("LIB_SRCS") if (ROOT / s).exists()]


def report_share(quic_total, shared_total, count, conditional_total):
    total = library_lines()
    compiled = build_sources()
    built = sum(lines_in(s) for s in compiled)
    sources = [p for p in run("git", "ls-files", "quic*.c") if "/" not in p]
    print("Share of the library")
    print(f"  {quic_total:5d} lines exist only for QUIC, in {count} files")
    print(f"  {conditional_total:5d} more sit in the {TRANSPORT} arms of "
          f"files both transports compile")
    print(f"  {shared_total:5d} lines both transports compile, in the "
          f"QUIC_SHARED pair")
    print(f"  {total:5d} lines of .c and .h at the root, every mode's "
          f"sources together")
    print(f"  {100.0 * quic_total / total:5.1f}% of the root .c and .h lines "
          f"in the tree exist only for QUIC")
    print(f"  {100.0 * (quic_total + conditional_total) / total:5.1f}% with "
          f"the conditional arms counted too")
    print(f"  Those two denominators are the tree, not a build: the root "
          f"holds every TRUST,")
    print(f"  PIN and KEX mode's sources at once and no library object "
          f"carries them all.")
    print(f"  {built:5d} lines of .c source one build compiles, the "
          f"{len(compiled)} files LIB_SRCS names")
    if sources:
        mode = sum(lines_in(p) for p in sources)
        named = len([p for p in sources if p in compiled])
        print(f"  {mode:5d} of the mode's lines sit in a .c file, and "
              f"LIB_SRCS names {named} of {len(sources)}")
        print(f"  {100.0 * mode / built:5.1f}% of that build's .c lines, "
              f"for the axis value this run read")
    else:
        print(f"      0 of the mode's lines sit in a .c file, so the mode "
              f"adds nothing to that")
        print(f"        build yet. A share of the sources a build compiles "
              f"waits for the")
        print(f"        Makefile's TRANSPORT axis, which is what makes "
              f"LIB_SRCS name them.")
    print()


def report_progress(quic):
    """How much of each header exists, in three counts rather than two.

    A definition is not an implementation. Every .c file of this mode is
    a stub today: it defines each function its header declares, returns
    the refusal the header documents and writes nothing. Counting
    definitions alone would read "43 of 43 declared functions have a
    definition", which a reader takes for a finished mode. So a defined
    function is counted as stubbed when its body carries the marker and
    as implemented when it does not, and the summary prints all three."""
    print("Declared against defined")
    headers = [p for p in quic if p.endswith(".h")]
    rows, missing = [], []
    declared_n, defined_n, stub_n = 0, 0, 0
    for header in headers:
        source = header[:-2] + ".c"
        names = declared(ROOT / header)
        bodies = defined(ROOT / source)
        declared_n += len(names)
        if bodies is None:
            missing.append(source)
            rows.append((header, len(names), "-", "-", f"no {source} yet"))
            continue
        here = [n for n in names if n in bodies]
        stubs = [n for n in here if n in (stubbed(ROOT / source) or [])]
        defined_n += len(here)
        stub_n += len(stubs)
        note = "" if len(here) == len(names) else (
            f"{', '.join(n for n in names if n not in bodies)} undefined")
        rows.append((header, len(names), str(len(here)), str(len(stubs)),
                     note))
    width = max(len(r[0]) for r in rows)
    print(f"  {'header'.ljust(width)}  decl  def  stub  note")
    for header, count, done, stubs, note in rows:
        print(f"  {header.ljust(width)}  {count:4d}  {done:>3}  {stubs:>4}  "
              f"{note}")
    print(f"  {declared_n} declared, {stub_n} stubbed, "
          f"{defined_n - stub_n} implemented.")
    print(f"  Stubbed means the body carries the CH_QUIC_STUB marker: it "
          f"returns the refusal")
    print(f"  the header documents and writes nothing. "
          f"{declared_n - defined_n} declared functions have no")
    print(f"  definition at all.")
    if len(missing) == len(rows):
        print(f"  No quic .c file exists, so the mode is {len(rows)} headers "
              f"and nothing else today.")
    elif missing:
        print(f"  {len(missing)} of {len(rows)} headers still have no .c "
              f"file:")
        for line in wrap(missing, 66, "     "):
            print(line)
    print()


def surface():
    """The public surface twice over: the `ch_quic_` entries quic.h
    declares, the names docs/quic.md's interface table lists, and the
    sentence each difference deserves."""
    header = [n for n in declared(ROOT / "quic.h") if n.startswith("ch_quic_")]
    documented = doc_entries()
    apart = [f"quic.h declares {name}, which {DOC} does not list"
             for name in header if name not in documented]
    apart += [f"{DOC} lists {name}, which quic.h does not declare"
              for name in documented if name not in header]
    return header, documented, apart


STUB_TEST = Path("test/quic_stub_test.c")


def stub_calls():
    """Every function name test/quic_stub_test.c calls.

    The same DECLARATOR quic_source.py reads a declaration's name with:
    an identifier that opens a paren. Over a .c file that answers every
    call the file makes, plus the functions it defines itself and the
    macros it invokes. Nothing here narrows that, because the one
    question asked of it is whether a given stub's name is in the set."""
    path = ROOT / STUB_TEST
    if not path.exists():
        sys.exit(f"quic-footprint: {STUB_TEST} is missing, so no stub's "
                 f"refusal is measured")
    code, _ = strip_comments(path.read_text())
    return set(DECLARATOR.findall(code))


def stubs_untested():
    """Every stub test/quic_stub_test.c does not call, each with its file.

    A stub that no call reaches is a stub whose refusal nothing measures.
    The test holds two rules -- no stub reports success, no stub writes
    through an out-parameter -- and it can only hold them for a function
    it calls. So the stub set and the called set are compared here rather
    than by a number a reader keeps in step by hand."""
    found = []
    for source in makefile("QUIC_SRCS"):
        path = ROOT / source
        if not path.exists():
            continue
        for name in stubbed(path) or []:
            found.append((source, name))
    called = stub_calls()
    return [(s, n) for s, n in found if n not in called]


def check_surface():
    """The two comparisons in this file that are a verdict: quic.h
    against docs/quic.md, and the stub set against the calls
    test/quic_stub_test.c makes. `make lint-quic-surface` runs both, and
    `lint` runs that."""
    _, _, apart = surface()
    for line in apart:
        print(f"lint-quic-surface: {line}")
    untested = stubs_untested()
    for source, name in untested:
        print(f"lint-quic-surface: {source} stubs {name}, which "
              f"{STUB_TEST} never calls, so nothing measures its refusal")
    if apart:
        print("lint-quic-surface: quic.h and its design record disagree "
              "about the public surface")
    if untested:
        print(f"lint-quic-surface: {STUB_TEST} must call every stub; add "
              f"each name above with its POISON check")
    return 1 if apart or untested else 0


def report_surface():
    print("Public surface")
    header, documented, apart = surface()
    print(f"  {len(header):2d} ch_quic_ entries declared in quic.h")
    print(f"  {len(documented):2d} ch_quic_ names in {DOC}, "
          f"\"{DOC_HEADING[3:]}\"")
    for line in wrap(header, 66, "     "):
        print(line)
    for line in apart:
        print(f"  {line}")
    if apart:
        print("  the header and its design record disagree about the "
              "public surface, which `make lint-quic-surface` fails on")
    else:
        print("  the header and its design record name the same entries")
    untested = stubs_untested()
    for source, name in untested:
        print(f"  {source} stubs {name}, which {STUB_TEST} never calls")
    if untested:
        print(f"  a stub the test never calls has no measured refusal, "
              f"which `make lint-quic-surface` fails on")
    else:
        print(f"  {STUB_TEST} calls every stub, so every refusal is "
              f"measured")
    print()


def report_sections(quic, shared):
    """The standards the headers cite, most cited first, so the RFC the
    mode implements leads the list without being named here."""
    print("Sections cited, by standard")
    scan = {p: marks_in(ROOT / p) for p in quic + shared if p.endswith(".h")}
    by_rule = resolve(scan)
    per_doc = {}
    for rule in ("adjacent", "section", "subject"):
        for doc, section, path in by_rule[rule]:
            per_doc.setdefault(doc, {}).setdefault(section, set()).add(path)
    order = sorted(per_doc, key=lambda d: (-len(per_doc[d]), d))
    for doc in order:
        sections = per_doc[doc]
        files = sorted({f for s in sections.values() for f in s})
        print(f"  {doc}: {plural(len(sections), 'section')} cited in "
              f"{plural(len(files), 'header')}")
        marks = sorted(sections, key=section_key)
        for line in wrap([f"\u00a7{s}" for s in marks], 66, "     "):
            print(line)
    total = sum(len(v) for v in by_rule.values())
    print(f"  {total} section marks in all, and how each one got its "
          f"standard:")
    print(f"     {len(by_rule['adjacent']):4d} carry a standard's name "
          f"immediately before them")
    print(f"     {len(by_rule['section']):4d} write a section number only "
          f"one standard is ever named with")
    print(f"     {len(by_rule['subject']):4d} take the standard their file "
          f"is mostly about")
    if by_rule["none"]:
        print(f"     {len(by_rule['none']):4d} sit in a file that names no "
              f"standard and are attributed to none")
    print()


def main(argv):
    if argv and argv != ["--check-surface"]:
        sys.exit(f"quic-footprint: unknown option {argv[0]}")
    quic, shared = quic_files()
    if not quic:
        sys.exit("quic-footprint: git ls-files names no quic file, so this "
                 "tree has no TRANSPORT=quic mode to report")
    if argv:
        return check_surface()
    conditional = conditional_rows(quic)
    print("quic-footprint: chapulin's TRANSPORT=quic mode, read from the "
          "tree\n")
    quic_total, shared_total = report_files(quic, shared, conditional)
    report_conditional(conditional)
    report_share(quic_total, shared_total, len(quic),
                 sum(r[2] for r in conditional))
    report_progress(quic)
    report_surface()
    report_sections(quic, shared)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
