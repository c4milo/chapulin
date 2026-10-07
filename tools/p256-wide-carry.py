#!/usr/bin/env python3
"""Check which form of the two carry steps each compiler reads in p256_wide_word.h.

Run from the repository root, with the pinned clang:

    python3 tools/p256-wide-carry.py "$(make -s print-clang-rv)" p256_wide_word.h

The second argument is the header the script reads. It takes it so that the
recipe of make lint-p256-wide names it, and it refuses any other.

p256_wide_add_carry and p256_wide_sub_borrow have three forms, and the header
picks one by the compiler (docs/decisions.md 94): the overflow builtins under
clang, the two x86-64 intrinsics under gcc for x86-64, and a 128-bit sum under
gcc for any other machine. gcc must compile neither builtin: it expands one to
an add and a jump on the add's carry, a word's, and removes the jump only at an
optimization level whose if-conversion passes run.

No test here can see that jump. This machine's compiler is clang, the object's
level is -O2, and no lane runs a 64-bit gcc through lint-wide-multiply. So this
script reads what each compiler reads. It preprocesses the header with the
pinned clang for arm64 and for x86-64, once as clang and once with __clang__
undefined. A gcc defines no __clang__, and the header's choice reads no other
macro of the compiler's, so the second reading is gcc's. Then it requires, in
the preprocessed bodies of the two steps:

- as clang, for both machines: the builtins, and neither other form;
- as gcc for x86-64: the intrinsics, and neither other form;
- as gcc for arm64: the sums, and neither other form.

Requiring the form that must be there keeps a reading that preprocessed
nothing from passing.

What it does not catch: a gcc that makes a jump of an intrinsic or of a
128-bit sum. Neither gcc 13.3 nor 15.2 does at any level, and that was read
from their assembly by hand (docs/decisions.md 94). A build that defines
P256_WIDE_CARRY itself picks its own form, and this script reads no such
build.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADER = "p256_wide_word.h"

# The machines lint-wide-multiply compiles the wide files for, with its flags
# (the Makefile's WIDE64_SPECS).
MACHINES = {
    "arm64": ["--target=aarch64-none-elf", "-march=armv8-a"],
    "x86-64": ["--target=x86_64-unknown-linux-gnu", "-march=x86-64"],
}
FLAGS = ["-std=c11", "-ffreestanding", "-nostdlibinc", "-Itools/freestanding", "-I.",
         "-DCH_RAND_EXTERN", "-DCH_CPU_RUNTIME", "-E", "-P", "-x", "c", "-"]

# What names each form in the body of a step.
FORMS = {
    "builtins": re.compile(r"__builtin_(?:add|sub)_overflow\s*\("),
    "intrinsics": re.compile(r"_(?:addcarry|subborrow)_u64\s*\("),
    "sums": re.compile(r"\bct_u128\s+(?:sum|difference)\s*="),
}
# reading, machine -> the form it must hold.
WANT = {
    ("clang", "arm64"): "builtins",
    ("clang", "x86-64"): "builtins",
    ("gcc", "arm64"): "sums",
    ("gcc", "x86-64"): "intrinsics",
}
STEPS = ("p256_wide_add_carry", "p256_wide_sub_borrow")


def body(text, name):
    """The text between the braces of the static inline function `name`."""
    start = re.search(r"static\s+inline\s+uint64_t\s+" + name + r"\s*\([^)]*\)\s*\{", text)
    if not start:
        return None
    depth = 1
    at = start.end()
    while depth and at < len(text):
        depth += {"{": 1, "}": -1}.get(text[at], 0)
        at += 1
    return text[start.end():at - 1]


def read(clang, reading, machine):
    """The header as `reading` preprocesses it for `machine`."""
    undefine = ["-U__clang__"] if reading == "gcc" else []
    run = subprocess.run([clang, *undefine, *MACHINES[machine], *FLAGS],
                         input=f'#include "{HEADER}"\n', cwd=ROOT, capture_output=True, text=True)
    if run.returncode != 0:
        return None, run.stderr.strip().splitlines()[-1:] or ["no message"]
    return run.stdout, []


def main(argv):
    if len(argv) != 3 or argv[2] != HEADER:
        print(__doc__, file=sys.stderr)
        return 2
    clang = argv[1]
    failures = []
    for (reading, machine), want in WANT.items():
        text, why = read(clang, reading, machine)
        where = f"{HEADER} as {reading} reads it for {machine}"
        if text is None:
            failures.append(f"{where}: the preprocessor failed: {why[0]}")
            continue
        for step in STEPS:
            inside = body(text, step)
            if inside is None:
                failures.append(f"{where}: no body of {step}")
                continue
            held = sorted(form for form, names in FORMS.items() if names.search(inside))
            if held != [want]:
                failures.append(f"{where}: {step} holds {' and '.join(held) or 'no form'}, "
                                f"and must hold the {want} alone")
    for failure in failures:
        print(f"lint-p256-wide: {failure}")
    if failures:
        return 1
    print(f"lint-p256-wide: {HEADER}'s carry steps are the builtins as clang reads them, and as "
          "gcc reads them the intrinsics for x86-64 and the sums for arm64")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
