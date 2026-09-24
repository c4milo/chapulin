#!/usr/bin/env python3
# make lint-commit-citations: every commit hash a commit body cites must
# name a commit that HEAD reaches. The Makefile comment above the target
# says why the rule exists.
#
# A citation is exactly seven hex characters with at least one a-f,
# git's abbreviation length here; the a-f keeps job ids and file digests
# out. Lines that start with "Claude-Session:" carry a session id, not a
# commit, and are skipped.
#
# One `git log` reads every hash and body. The shell loop this replaced
# started git once per commit, which took 12 seconds at 459 commits.
import re
import subprocess
import sys

CITATION = re.compile(r"(?<![0-9a-fx])\b([0-9a-f]{7})\b")
LETTER = re.compile(r"[a-f]")


def commits():
    """Yields (full hash, abbreviated hash, body), newest first."""
    log = subprocess.run(["git", "log", "--format=%H %h%n%b%x00"],
                         capture_output=True, text=True, check=True).stdout
    for record in log.split("\0"):
        record = record.lstrip("\n")
        if not record:
            continue
        head, _, body = record.partition("\n")
        full, abbreviated = head.split(" ")
        yield full, abbreviated, body


def citations(body):
    """The sorted, distinct hashes a body cites."""
    cited = set()
    for line in body.splitlines():
        if line.startswith("Claude-Session:"):
            continue
        cited.update(h for h in CITATION.findall(line) if LETTER.search(h))
    return sorted(cited)


def main():
    history = list(commits())
    prefixes = {full[:7] for full, _, _ in history}
    rc = 0
    for _, abbreviated, body in history:
        for cited in citations(body):
            if cited not in prefixes:
                print(f"lint-commit-citations: {abbreviated} cites {cited}, "
                      "which no commit reaches")
                rc = 1
    if rc == 0:
        print("lint-commit-citations: every hash a commit body cites resolves")
    return rc


if __name__ == "__main__":
    sys.exit(main())
