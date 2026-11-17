#!/usr/bin/env python3
"""Holds a fresh count of instructions to the recorded one.

Usage: insn-gate.py RECORDED FRESH

RECORDED is a committed CSV, such as bench/results-insn-m3.csv, and FRESH
is the same script's output for the tree under test. Each file starts with
one comment line that names the compiler, then a header line, op and the
columns of counts, then one row for each operation. Later comment lines
are notes and take no part.

The rule is the ratchet of make lint-wide-multiply (docs/decisions.md
235):

- A count above its recorded value fails. The change that raised it
  records the new value, and its commit says why.
- A count below its recorded value passes and prints a line. The change
  that lowered it records the new value in the same commit, so the next
  rise shows.
- A row or a column in one file and not in the other fails.
- A compiler line that differs prints a note and fails nothing by
  itself. A runner image can move a compiler's package revision and
  leave every count where it was. Where the move changes a count, the
  rule above holds that count, and the note names the cause.

Exit 0 when nothing fails, 1 when something does, and 2 on a usage error
or a file that cannot be read.
"""

import csv
import sys


def read(path):
    """The compiler line, the column names and the rows of one CSV."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print("insn-gate: cannot read %s: %s" % (path, e))
        sys.exit(2)
    compiler = None
    body = []
    for line in lines:
        if line.startswith("#"):
            if compiler is None and not body:
                compiler = line
            continue
        if line.strip():
            body.append(line)
    if not body:
        print("insn-gate: %s holds no header and no rows" % path)
        sys.exit(2)
    reader = csv.reader(body)
    header = next(reader)
    if not header or header[0] != "op":
        print("insn-gate: %s does not start its header with op" % path)
        sys.exit(2)
    rows = {}
    for row in reader:
        if len(row) != len(header):
            print("insn-gate: %s: row %s has %d fields, the header %d"
                  % (path, row[0], len(row), len(header)))
            sys.exit(2)
        rows[row[0]] = row[1:]
    return compiler, header[1:], rows


def main():
    if len(sys.argv) != 3:
        print("usage: insn-gate.py RECORDED FRESH")
        return 2
    recorded_path, fresh_path = sys.argv[1], sys.argv[2]
    recorded_compiler, recorded_columns, recorded = read(recorded_path)
    fresh_compiler, fresh_columns, fresh = read(fresh_path)
    failed = False

    if recorded_compiler != fresh_compiler:
        print("insn-gate: note: %s was counted under another compiler." % recorded_path)
        print("  recorded: %s" % recorded_compiler)
        print("  fresh:    %s" % fresh_compiler)
    if recorded_columns != fresh_columns:
        print("insn-gate: FAIL the columns differ: %s recorded, %s fresh"
              % (",".join(recorded_columns), ",".join(fresh_columns)))
        return 1
    for op in sorted(set(recorded) ^ set(fresh)):
        where = "recorded" if op in recorded else "fresh"
        print("insn-gate: FAIL row %s is in the %s file alone" % (op, where))
        failed = True

    lowered = 0
    for op in [o for o in recorded if o in fresh]:
        for column, was, now in zip(recorded_columns, recorded[op], fresh[op]):
            try:
                was_n, now_n = int(was), int(now)
            except ValueError:
                print("insn-gate: FAIL %s %s is not a count: %s recorded, %s fresh"
                      % (op, column, was, now))
                failed = True
                continue
            if now_n > was_n:
                print("insn-gate: FAIL %s %s rose from %d to %d (+%.2f%%)"
                      % (op, column, was_n, now_n, 100.0 * (now_n - was_n) / was_n))
                failed = True
            elif now_n < was_n:
                print("insn-gate: %s %s fell from %d to %d (%.2f%%); record the new count"
                      % (op, column, was_n, now_n, 100.0 * (now_n - was_n) / was_n))
                lowered += 1

    if failed:
        print("insn-gate: %s: a count rose or the files differ. If the rise is the change's"
              % recorded_path)
        print("  cost, record the fresh file over it and say why in the commit.")
        return 1
    print("insn-gate: %s: %d rows, no count above its recorded value, %d below"
          % (recorded_path, len(recorded), lowered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
