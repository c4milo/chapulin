#!/usr/bin/env python3
"""Check that an AVX2 kernel whose loop uses 256-bit stack slots aligns its frame.

Run from the repository root, with the pinned clang:

    python3 tools/frame-align.py "$(make -s print-clang-rv)" chacha20_avx2.c keccak_avx2.c

The arguments after the compiler are the sources the script reads. It takes
them so that the recipe of make lint-frame-align names them, and it refuses
any other list.

chacha20_avx2.c's pass and keccak_avx2.c's keccak_avx2_permute hold more
256-bit values than AVX2 has registers, so their loops store values to
32-byte stack slots and load them back. clang gives such a slot the
alignment of the frame it is in, and aligns a frame to 32 bytes only where
the function carries force_align_arg_pointer or holds an object declared with
that alignment. Without either, the slots sit wherever the caller's stack
pointer leaves them, in steps of 16 bytes. In half of those places slots lie
across a cache line, and in a few a slot lies across a page boundary, where
each store and load of it stalls (docs/decisions.md 124, INV-49). gcc aligns
the frame on its own, and no clang build of this machine or of CI's check job
runs these files on a CPU: this machine is arm64 and CI compiles with gcc. So
this script reads what clang compiles.

It compiles each source for x86-64 with the pinned clang at -O2, the level of
the object `make lib` and build.zig build, and reads the assembly. The
compile is hosted, as the object's is, and that matters: -ffreestanding
implies -fno-builtin, under which clang keeps keccak_avx2.c's 25 lanes in an
array on the stack and aligns the frame for the array, attribute or none. A
clang with no libc headers compiles hosted here because tools/freestanding
holds the two libc headers the sources and <immintrin.h> include. For every
function it finds:

- the instructions inside a loop that name a 256-bit or 512-bit register and
  a slot of the stack, where a loop is the instructions from a label to a
  later jump back to it;
- the instruction that aligns the stack pointer, `andq $-32, %rsp` or a
  larger power of two.

A function with such an instruction in a loop must align its frame to the
register's width. The script also requires the function each source is known
to keep its slots in, pass and keccak_avx2_permute, to be in the assembly
with such an instruction in a loop, so a reading that compiled nothing, or a
compiler that moved the loop to another function, fails instead of passing.

What it does not catch: a slot a loop reads through a pointer in a general
register, which no function here does, and any file it is not given.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Each source, and the function whose loop keeps its values in stack slots.
SOURCES = {
    "chacha20_avx2.c": "pass",
    "keccak_avx2.c": "keccak_avx2_permute",
}

# lint-wide-multiply's x86-64 machine, headers, level and hosted compile
# (the Makefile's WIDE64_SPECS), under the define of a host object.
FLAGS = ["--target=x86_64-unknown-linux-gnu", "-march=x86-64", "-std=c11", "-O2",
         "-nostdlibinc", "-Itools/freestanding", "-I.", "-D_DEFAULT_SOURCE",
         "-DCH_RAND_EXTERN", "-DCH_CPU_RUNTIME", "-S", "-o", "-"]

LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*):")
JUMP = re.compile(r"^\s+j[a-z]+\s+([A-Za-z_.$][\w.$]*)\s*(?:#.*)?$")
ALIGN = re.compile(r"^\s+andq\s+\$-(\d+),\s*%rsp\b")
STACK_SLOT = re.compile(r"\(%r[sb]p[,)]")
WIDTHS = {"%ymm": 32, "%zmm": 64}


def functions(assembly):
    """The assembly's functions: name -> its lines, labels and instructions alike."""
    out = {}
    name = None
    for line in assembly.splitlines():
        match = LABEL.match(line)
        if match and not match.group(1).startswith(".L"):
            name = match.group(1)
            out[name] = []
            continue
        if name is not None:
            if line.lstrip().startswith(".cfi_endproc"):
                name = None
                continue
            out[name].append(line)
    return out


def read(lines):
    """A function's widest stack slot used in a loop, how many instructions use one there,
    and the alignment the function gives its frame: three byte counts, 0 for none."""
    labels = {}
    loops = []
    for index, line in enumerate(lines):
        match = LABEL.match(line)
        if match:
            labels[match.group(1)] = index
            continue
        match = JUMP.match(line)
        if match and match.group(1) in labels:
            loops.append((labels[match.group(1)], index))
    width = 0
    count = 0
    aligned = 0
    for index, line in enumerate(lines):
        match = ALIGN.match(line)
        if match:
            aligned = max(aligned, int(match.group(1)))
        if not STACK_SLOT.search(line) or not any(first <= index <= last for first, last in loops):
            continue
        widths = [bytes_ for register, bytes_ in WIDTHS.items() if register in line]
        if widths:
            width = max(width, max(widths))
            count += 1
    return width, count, aligned


def check(clang, source, holder):
    """The failures for one source, and a line that says what was read."""
    run = subprocess.run([clang, *FLAGS, source], cwd=ROOT, capture_output=True, text=True)
    if run.returncode != 0:
        first = (run.stderr.strip().splitlines() or ["no output"])[0]
        return [f"{source} does not compile for x86-64: {first}"], ""
    found = functions(run.stdout)
    failures = []
    seen = []
    for name, lines in found.items():
        width, count, aligned = read(lines)
        if width == 0:
            continue
        seen.append(f"{name} ({count} at {8 * width} bits, frame aligned to {aligned or 16} bytes)")
        if aligned < width:
            failures.append(
                f"{source}: {name} uses a {8 * width}-bit stack slot in {count} instructions "
                f"inside a loop and does not align its frame to {width} bytes; give it "
                f"__attribute__((force_align_arg_pointer)) (docs/decisions.md 124)")
    if holder not in found:
        failures.append(f"{source}: the assembly holds no function {holder}; name the function "
                        "that holds its loop in tools/frame-align.py")
    elif read(found[holder])[0] == 0:
        failures.append(f"{source}: {holder} uses no 256-bit stack slot inside a loop; name the "
                        "function that does in tools/frame-align.py, or drop the source when "
                        "none does")
    return failures, f"{source}: {', '.join(seen) or 'no such function'}"


def main():
    if len(sys.argv) < 3:
        sys.exit('usage: python3 tools/frame-align.py "$(make -s print-clang-rv)" '
                 + " ".join(SOURCES))
    clang = sys.argv[1]
    if sys.argv[2:] != list(SOURCES):
        sys.exit(f"lint-frame-align: this script reads {' '.join(SOURCES)} and was given "
                 f"{' '.join(sys.argv[2:])}")
    failures = []
    said = []
    for source, holder in SOURCES.items():
        found, line = check(clang, source, holder)
        failures += found
        if line:
            said.append(line)
    for failure in failures:
        print(f"lint-frame-align: {failure}")
    if failures:
        sys.exit(1)
    print("lint-frame-align: under clang for x86-64 at -O2, every function that uses a 256-bit "
          "stack slot inside a loop aligns its frame: " + "; ".join(said))


if __name__ == "__main__":
    main()
