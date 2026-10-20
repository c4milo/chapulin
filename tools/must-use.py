#!/usr/bin/env python3
"""Fails when a public call that returns int carries no CH_MUST_USE.

Usage: tools/must-use.py CC HEADERS DEFINES

HEADERS is lib-headers.txt from build.zig's lib-lists step: the headers
the module "chapulin" is translated from, one per line. DEFINES is
lib-def.txt from the same step: the -D flags the object compiled with.

Each public call that returns int returns a result code, result.h's, or
a verdict. The code says whether the caller can go on. A caller that
drops it can use bytes the call did not write, or go on after a check
that failed. result.h defines CH_MUST_USE as gcc's and clang's
warn_unused_result, so the compiler warns where a caller drops the code
(docs/decisions.md 143).

This runs the C preprocessor over the headers under the object's
defines, so a call counts only where the object declares it, under the
name the object exports. Each declaration and each inline definition at
file scope whose name starts with ch_ and whose return type is int must
hold warn_unused_result after the preprocessor expands CH_MUST_USE. So
the check fails both for a call without the mark and for a CH_MUST_USE
that expands to nothing. It prints the number of calls it checked.
"""

import pathlib
import re
import subprocess
import sys
import tempfile

# A declaration or definition of a ch_ call: what comes before the name,
# then the name and its opening parenthesis.
CALL = re.compile(r"^(?P<prefix>.*?)\b(?P<name>ch_[A-Za-z0-9_]+)\s*\(", re.S)

# What may stand before the return type.
ATTRIBUTE = re.compile(r"__attribute__\s*\(\(.*?\)\)", re.S)
SPECIFIERS = {"static", "inline", "extern", "__inline", "__inline__"}


def file_scope_heads(text):
    """The text of each declaration at file scope, and of each definition
    up to its body. Text inside braces, a struct's members or a function's
    body, is dropped."""
    depth = 0
    head = []
    for ch in text:
        if ch == "{":
            if depth == 0:
                yield "".join(head)
                head = []
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            if ch == ";":
                yield "".join(head)
                head = []
            else:
                head.append(ch)
    yield "".join(head)


def unmarked_calls(text):
    """The names of the int calls without warn_unused_result, and the
    number of int calls."""
    unmarked = []
    count = 0
    for head in file_scope_heads(text):
        m = CALL.match(head.strip())
        if not m:
            continue
        words = ATTRIBUTE.sub(" ", m.group("prefix")).split()
        if [w for w in words if w not in SPECIFIERS] != ["int"]:
            continue
        count += 1
        if "warn_unused_result" not in head:
            unmarked.append(m.group("name"))
    return sorted(set(unmarked)), count


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: tools/must-use.py CC HEADERS DEFINES")
    cc, headers_path, defines_path = sys.argv[1:]
    headers = pathlib.Path(headers_path).read_text().split()
    defines = pathlib.Path(defines_path).read_text().split()
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write("".join('#include "%s"\n' % h for h in headers))
        source = f.name
    try:
        text = subprocess.run([cc, "-E", "-P", "-std=c11", "-I."] + defines + [source],
                              capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit("must-use: the headers do not preprocess:\n" + e.stderr)
    finally:
        pathlib.Path(source).unlink()
    unmarked, count = unmarked_calls(text)
    for name in unmarked:
        print("must-use: %s returns int and carries no CH_MUST_USE (result.h)" % name,
              file=sys.stderr)
    if unmarked:
        return 1
    print(count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
