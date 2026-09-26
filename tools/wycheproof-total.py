#!/usr/bin/env python3
"""Checks the Wycheproof total docs/verification.md states against the
vectors make wycheproof generated.

Run from the repository root, after make wycheproof:
python3 tools/wycheproof-total.py

test/gen_wycheproof.py writes WP_CASES_TOTAL, the sum of every suite's
cases, into bin/wycheproof_vectors.h. The page states the same sum by
hand, and it went stale once: it said 5,475 while the suites held 5,967,
because four suites had been added since it was written. This fails when
the two differ.
"""

import pathlib
import re
import sys

HEADER = pathlib.Path("bin/wycheproof_vectors.h")
DOC = pathlib.Path("docs/verification.md")


def main():
    if not HEADER.exists():
        # make wycheproof skips without the pinned checkout, and then
        # writes no header; check-skips reports that skip.
        print("SKIP wycheproof-total: %s was not generated" % HEADER)
        return 0
    m = re.search(r"^#define WP_CASES_TOTAL (\d+)$", HEADER.read_text(), re.M)
    if m is None:
        print("wycheproof-total: %s has no WP_CASES_TOTAL; rerun make wycheproof" % HEADER)
        return 1
    total = int(m.group(1))
    d = re.search(r"\(`make wycheproof`\),\s+([0-9,]+)\s+across", DOC.read_text())
    if d is None:
        print("wycheproof-total: %s states no total as \"(`make wycheproof`), N across\"" % DOC)
        return 1
    stated = int(d.group(1).replace(",", ""))
    if stated != total:
        print("wycheproof-total: %s says %s Wycheproof cases; the vectors hold %s"
              % (DOC, d.group(1), "{:,}".format(total)))
        return 1
    print("wycheproof-total: %s states the %s cases the vectors hold" % (DOC, "{:,}".format(total)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
