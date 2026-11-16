#!/usr/bin/env python3
"""Prints the instructions each callgrind dump counted in one program's code.

Usage: callgrind-own.py PROGRAM DUMP...

Each DUMP is a file that valgrind --tool=callgrind wrote at a
CALLGRIND_DUMP_STATS_AT request, with --compress-strings=no and
--compress-pos=no, and PROGRAM is the path of the binary it ran. For each
dump in turn this prints one line: the label the request gave, a comma,
and the sum of the self cost, in instructions, of the functions in
PROGRAM's object.

Instructions in a shared library are left out. glibc picks its memcpy and
its memset from the CPU it starts on, so their counts differ from one
runner to the next, and a gate on them would fail with no change to this
tree (docs/decisions.md 235). The calls into them stay in the count.

The format is callgrind's "Callgrind Format Specification": an ob= line
names the object of the cost lines below it, a calls= line says that the
next cost line is the inclusive cost of a call, and every other line that
starts with a digit or a sign is a self cost whose last field is Ir. A
cost line leaves out a cost of zero, so a line of the position alone
costs nothing.
"""

import os
import sys


def own_cost(program, path):
    """The label and the self Ir in program's object of one dump."""
    label = None
    current = None
    after_calls = False
    total = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("desc: Trigger: Client Request: "):
                label = line[len("desc: Trigger: Client Request: "):]
            elif line.startswith("ob="):
                current = line[3:]
            elif line.startswith("calls="):
                after_calls = True
            elif line[:1].isdigit() or line[:1] in "+-*":
                if after_calls:
                    after_calls = False
                    continue
                fields = line.split()
                # A cost line leaves out a zero cost, so a line of one
                # field, the position alone, costs nothing.
                if len(fields) > 1 and current is not None and os.path.realpath(current) == program:
                    total += int(fields[-1])
    return label, total


def main():
    if len(sys.argv) < 3:
        print("usage: callgrind-own.py PROGRAM DUMP...", file=sys.stderr)
        return 2
    program = os.path.realpath(sys.argv[1])
    for path in sys.argv[2:]:
        label, total = own_cost(program, path)
        if label is None:
            print("callgrind-own: %s holds no client request label" % path, file=sys.stderr)
            return 1
        if total == 0:
            print("callgrind-own: %s counts no instruction in %s" % (path, program),
                  file=sys.stderr)
            return 1
        print("%s,%d" % (label, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
