# Every issue reference carries its URL: a bare number is unresolvable
# outside GitHub's own web UI, and a reader holding only the source tree
# cannot follow it. Markdown link labels already carry the URL beside
# them. Hex colours and PKCS references are not issue numbers.
import re
import subprocess
import sys

BARE = re.compile(r'(?<![\w/])#(\d{1,3})\b(?![0-9a-fA-F])')
MD_LINK = re.compile(r'\]\(https://github\.com/c4milo/chapulin/issues/\d+\)')
URL = "https://github.com/c4milo/chapulin/issues/"

files = subprocess.run(["git", "ls-files", "*.c", "*.h", "*.md", "*.sh",
                        "*.py", "Makefile", "*.yml"],
                       capture_output=True, text=True).stdout.split()
rc = 0
for f in files:
    try:
        lines = open(f, encoding="utf-8").read().split("\n")
    except (OSError, UnicodeDecodeError):
        continue
    for n, line in enumerate(lines, 1):
        for m in BARE.finditer(line):
            before, after = line[:m.start()], line[m.end():]
            if before.endswith(('"', "'")) or before.endswith("PKCS "):
                continue
            if before.endswith("[") and MD_LINK.match(after):
                continue
            print("lint-issue-links: %s:%d cites %s without its URL (%s%s)"
                  % (f, n, m.group(0), URL, m.group(1)))
            rc = 1
if rc == 0:
    print("lint-issue-links: every issue reference carries its URL")
sys.exit(rc)
