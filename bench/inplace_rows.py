#!/usr/bin/env python3
"""The rows of bench/results-inplace-*.csv from the lines bench/inplace.c prints.

    python3 bench/inplace_rows.py ROWS

bench/inplace.sh runs the copying program and the in-place one back to back, many times, and
appends each run's lines to ROWS: path, direction, aead, bytes, the ch_cfg.cpu value and the
run's figure in ns. The n-th copying run of a row pairs with its n-th in-place run. For each row,
in the order the in-place program prints them, this prints direction, aead, bytes, the median of
each program's figures, and the median, the 25th and the 75th percentile over the pairs of the
copying figure over the in-place one. A percentile is the value at its nearest rank.
"""
import math
import statistics
import sys


def rank(values, fraction):
    """The value at the nearest rank of a fraction of a list."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def read_runs(path):
    """Each row's figures for each program, and the rows in the in-place program's order."""
    figures = {}
    order = []
    with open(path) as f:
        for line in f:
            program, direction, aead, size, _, ns = line.strip().split(",")
            key = (direction, aead, size)
            figures.setdefault((program, key), []).append(float(ns))
            if program == "in_place" and key not in order:
                order.append(key)
    return figures, order


def main():
    figures, order = read_runs(sys.argv[1])
    for key in order:
        copy = figures.get(("copy", key), [])
        in_place = figures[("in_place", key)]
        if len(copy) != len(in_place):
            sys.exit("inplace bench: %s has %d copying runs and %d in-place runs"
                     % (",".join(key), len(copy), len(in_place)))
        speeds = [c / i for c, i in zip(copy, in_place)]
        print("%s,%.1f,%.1f,%.3f,%.3f,%.3f" % (",".join(key), statistics.median(copy),
                                               statistics.median(in_place),
                                               statistics.median(speeds), rank(speeds, 0.25),
                                               rank(speeds, 0.75)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
