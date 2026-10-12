#!/usr/bin/env python3
"""Check that sha512_avx2.c's kernel, as a compiler wrote it, runs its schedule among its rounds.

Run from the repository root:

    python3 tools/schedule-order.py clang "$(make -s print-clang-rv)" sha512_avx2.c
    <a compile command that ends in -S -o -> sha512_avx2.c \
        | python3 tools/schedule-order.py assembly "<who compiled it>" sha512_avx2.c

The argument after the mode's own is the source the script reads. It takes it
so that the recipe of make lint-schedule-order names the file, and it refuses
any other.

sha512_avx2_compress_blocks runs a quarter of a schedule step after each
round (docs/decisions.md 128, INV-51). A step's instructions are on vector
registers and a round's on general registers, and with each step whole after
its four rounds SHA-384 over 16 KiB took 1 to 8 percent longer under gcc on
four CPU models. The order is the source's and a compiler may write another.
clang 18 and 23 keep it. gcc 13.3's second scheduling pass does not: it moves
each step's vector instructions in among those of one or two rounds and
leaves up to 99 instructions on general registers in a row with none, so the
Makefile compiles the file with -fno-schedule-insns2 wherever gcc compiles it
for x86-64 (SHA512_AVX2_GCC_CFLAGS there). Every digest is the same in each
order, so no test of what the kernel computes sees one that changed. This
script reads the order.

In `clang` mode it compiles the source for x86-64 with the pinned clang at
-O2, as tools/frame-align.py does and under its flags, so it gives one verdict
on every machine. In `assembly` mode it reads from its input the assembly a
command of the Makefile wrote: make lint-schedule-order-gcc runs the two
commands that compile the file with gcc, each with -S in place of -c.

It finds sha512_avx2_compress_blocks and, in it, the innermost loop that
holds a vector shift, which only the schedule runs: the loop of sixteen
rounds and four steps. A loop is the instructions from a label to a later
jump back to it. An instruction that names an xmm or ymm register is a vector
instruction, and any other is one on general registers. The script requires:

- at least 100 vector instructions in the loop, so a reading that found
  another loop, or a compiler that moved the schedule out of it, fails;
- at most MOST_BETWEEN instructions on general registers between two vector
  instructions of the loop. A round is 30 instructions under gcc 13.3 and 29
  to 31 under clang 18 and 23, and a kernel with a quarter of a step after
  each round has one round between two quarters. A step written after four
  rounds leaves 106 to 120 in a row, and gcc's second scheduling pass 99.

What it does not check: the order of the instructions inside a round or a
quarter, and the time any order takes. docs/decisions.md 128 holds the
timings, which are a hosted runner's and no check.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

SOURCE = "sha512_avx2.c"
FUNCTION = "sha512_avx2_compress_blocks"
# The most instructions on general registers that may lie between two vector
# instructions of the loop: a round and a third of one.
MOST_BETWEEN = 40
# The fewest vector instructions the loop holds: four steps of 36 are 144.
FEWEST_VECTOR = 100

# tools/frame-align.py's flags: lint-wide-multiply's x86-64 machine,
# headers, level and hosted compile, under the define of a host object.
CLANG_FLAGS = ["--target=x86_64-unknown-linux-gnu", "-march=x86-64", "-std=c11", "-O2",
               "-nostdlibinc", "-Itools/freestanding", "-I.", "-D_DEFAULT_SOURCE",
               "-DCH_RAND_EXTERN", "-DCH_CPU_RUNTIME", "-S", "-o", "-"]

LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*):")
JUMP = re.compile(r"^\s+j[a-z]+\s+([A-Za-z_.$][\w.$]*)\s*(?:#.*)?$")
INSTRUCTION = re.compile(r"^\s+([a-z][a-z0-9]*)\b")
VECTOR_REGISTER = re.compile(r"%[xy]mm\d")
SCHEDULE_SHIFT = "vpsrlq"


def function_lines(assembly, name):
    """The lines of one function, labels and instructions alike, or None."""
    lines = None
    for line in assembly.splitlines():
        match = LABEL.match(line)
        if match and not match.group(1).startswith(".L"):
            if lines is not None:
                break
            if match.group(1) == name:
                lines = []
            continue
        if lines is not None:
            if line.lstrip().startswith(".cfi_endproc"):
                break
            lines.append(line)
    return lines


def instructions_and_loops(lines):
    """A function's instructions as (mnemonic, is_vector) and its loops as pairs of indices:
    the first instruction after a label and the jump back to that label."""
    labels = {}
    instructions = []
    loops = []
    for line in lines:
        match = LABEL.match(line)
        if match:
            labels[match.group(1)] = len(instructions)
            continue
        match = INSTRUCTION.match(line)
        if not match:
            continue
        jump = JUMP.match(line)
        if jump and jump.group(1) in labels:
            loops.append((labels[jump.group(1)], len(instructions)))
        instructions.append((match.group(1), bool(VECTOR_REGISTER.search(line))))
    return instructions, loops


def schedule_loop(instructions, loops):
    """The innermost loop that holds a schedule shift: its instructions, or None."""
    holding = [(last - first, first, last) for first, last in loops
               if any(mnemonic == SCHEDULE_SHIFT for mnemonic, _ in instructions[first:last + 1])]
    if not holding:
        return None
    _, first, last = min(holding)
    return instructions[first:last + 1]


def runs_between(loop):
    """The count of vector instructions, and the lengths of the runs of instructions on
    general registers that lie between two vector instructions."""
    vector = sum(1 for _, is_vector in loop if is_vector)
    between = []
    run = None
    for _, is_vector in loop:
        if is_vector:
            if run:
                between.append(run)
            run = 0
        elif run is not None:
            run += 1
    return vector, between


def check(assembly, compiled_by):
    """The failures for one compiler's assembly, and a line that says what was read."""
    lines = function_lines(assembly, FUNCTION)
    if lines is None:
        return [f"the assembly {compiled_by} wrote holds no function {FUNCTION}"], ""
    instructions, loops = instructions_and_loops(lines)
    loop = schedule_loop(instructions, loops)
    if loop is None:
        return [f"as {compiled_by} compiled it, {FUNCTION} has no loop that holds "
                f"{SCHEDULE_SHIFT}, the schedule's shift"], ""
    vector, between = runs_between(loop)
    failures = []
    if vector < FEWEST_VECTOR:
        failures.append(
            f"as {compiled_by} compiled it, the loop of {FUNCTION} holds {vector} vector "
            f"instructions and not {FEWEST_VECTOR} or more; the schedule's four steps are not "
            "in the loop this script read")
    longest = max(between, default=0)
    if longest > MOST_BETWEEN:
        failures.append(
            f"as {compiled_by} compiled it, {longest} instructions on general registers lie "
            f"between two vector instructions of {FUNCTION}'s loop, more than {MOST_BETWEEN}: "
            "a quarter of a schedule step no longer follows each round. Under gcc the file "
            "compiles with -fno-schedule-insns2 (the Makefile's SHA512_AVX2_GCC_CFLAGS, "
            "docs/decisions.md 128)")
    said = (f"{compiled_by}: {vector} vector instructions in {len(between) + 1} runs, at most "
            f"{longest} instructions on general registers between two")
    return failures, said


def main():
    usage = ('usage: python3 tools/schedule-order.py clang "$(make -s print-clang-rv)" '
             f'{SOURCE}\n       <compile command> -S -o - {SOURCE} | '
             f'python3 tools/schedule-order.py assembly "<who compiled it>" {SOURCE}')
    if len(sys.argv) != 4 or sys.argv[1] not in ("clang", "assembly"):
        sys.exit(usage)
    if sys.argv[3] != SOURCE:
        sys.exit(f"lint-schedule-order: this script reads {SOURCE} and was given {sys.argv[3]}")
    if sys.argv[1] == "clang":
        run = subprocess.run([sys.argv[2], *CLANG_FLAGS, SOURCE], cwd=ROOT, capture_output=True,
                             text=True)
        if run.returncode != 0:
            first = (run.stderr.strip().splitlines() or ["no output"])[0]
            sys.exit(f"lint-schedule-order: {SOURCE} does not compile for x86-64: {first}")
        assembly = run.stdout
        compiled_by = "clang for x86-64 at -O2"
    else:
        assembly = sys.stdin.read()
        compiled_by = sys.argv[2]
    failures, said = check(assembly, compiled_by)
    for failure in failures:
        print(f"lint-schedule-order: {failure}")
    if failures:
        sys.exit(1)
    print(f"lint-schedule-order: {FUNCTION} runs its schedule among its rounds as {said}")


if __name__ == "__main__":
    main()
