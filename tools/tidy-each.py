#!/usr/bin/env python3
"""Run clang-tidy over files, one process per file, and skip each file
that passed before on the same inputs.

Run from the repository root, through lint-tidy:

    python3 tools/tidy-each.py --passes FILE
    python3 tools/tidy-each.py [--tidy-arg ARG]... SOURCE... -- FLAG...

A pass is one set of translation units and the compiler flags clang-tidy
parses them with, written as the second form's arguments. lint-tidy
writes one pass per line of FILE, and this checks the files of every
pass from one pool, so a short pass does not wait for a long one. The
same file may appear in several passes; each pass is its own check.
CLANG_TIDY names clang-tidy, CLANG the clang that lists each file's
includes, and LINT_JOBS how many processes run at once. clang-tidy reads
each translation unit on its own, so the order and the count change the
wall time and nothing else. Each process's output prints in one piece
when it ends, so two files' findings never interleave.

A file's key is a SHA-256 over clang-tidy's --version, the bytes of this
script and of tools/stamp.py, the pass's tidy arguments and flags, the file's path, the bytes of every .clang-tidy file
from the file's directory up to the repository root, and the path and
bytes of every file the translation unit includes under those flags,
system headers too, as `clang -M` lists them. A file whose key has a
stamp in bin/stamps/tidy/ passed clang-tidy on exactly those inputs, so
it does not run again. A file clang cannot list includes for gets no
key: it runs every time and writes no stamp. tools/stamp.py states what
a stamp holds and what it cannot see; CHECK_NO_STAMPS=1 runs every file.
"""

import concurrent.futures
import hashlib
import os
import pathlib
import shlex
import subprocess
import sys
import threading

import stamp

NAME = "tidy"


class Pass:
    """One set of translation units under one set of flags."""

    def __init__(self, words):
        if "--" not in words:
            sys.exit(f"tidy-each: a pass needs -- between its files and its flags: {' '.join(words)}")
        split = words.index("--")
        head, self.flags = words[:split], words[split + 1:]
        self.tidy_args, self.files = [], []
        i = 0
        while i < len(head):
            if head[i] == "--tidy-arg" and i + 1 < len(head):
                self.tidy_args.append(head[i + 1])
                i += 2
            else:
                self.files.append(head[i])
                i += 1
        if not self.files:
            sys.exit(f"tidy-each: a pass names no file: {' '.join(words)}")
        self.deps = {}


def parse(argv):
    """Every pass the arguments name."""
    if argv[:1] == ["--passes"] and len(argv) == 2:
        with open(argv[1], encoding="utf-8") as f:
            return [Pass(shlex.split(line)) for line in f if line.strip()]
    return [Pass(argv)]


def make_words(text):
    """The words of make rules, with backslash-newline continuations
    joined and a backslash-escaped space kept inside its path."""
    words, current, i = [], "", 0
    text = text.replace("\\\n", " ")
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] == " ":
            current += " "
            i += 2
            continue
        if c.isspace():
            if current:
                words.append(current)
            current = ""
        else:
            current += c
        i += 1
    if current:
        words.append(current)
    return words


def list_includes(clang, flags, paths):
    """For each translation unit, every file it reads under the flags.
    One clang process lists a batch, one rule per file in the order
    given, and each rule must name its own file among its prerequisites.
    A batch that fails either test is listed again one file at a time, so
    a file that does not preprocess costs only its own key."""
    r = subprocess.run([clang, "-M", *flags, *paths], cwd=stamp.ROOT, capture_output=True, text=True)
    rules = []
    if r.returncode == 0:
        for word in make_words(r.stdout):
            if word.endswith(":"):
                rules.append([])
            elif rules:
                rules[-1].append(word)
    if len(rules) == len(paths) and all(p in rule for p, rule in zip(paths, rules)):
        return dict(zip(paths, rules))
    if len(paths) == 1:
        return {}
    found = {}
    for p in paths:
        found.update(list_includes(clang, flags, [p]))
    return found


class Digests:
    """The SHA-256 of each file's bytes, read once per run."""

    def __init__(self):
        self.memo = {}
        self.lock = threading.Lock()

    def of(self, path):
        with self.lock:
            if path in self.memo:
                return self.memo[path]
        d = hashlib.sha256(stamp.file_bytes(path)).digest()
        with self.lock:
            self.memo[path] = d
        return d


def configs_for(path):
    """The .clang-tidy files clang-tidy may read for one source: one per
    directory from the source's own up to the repository root."""
    found = []
    d = (stamp.ROOT / path).resolve().parent
    while True:
        if (d / ".clang-tidy").exists():
            found.append(d / ".clang-tidy")
        if d == stamp.ROOT or d == d.parent:
            return found
        d = d.parent


def key_of(version, one, path, digests):
    """One file's key within one pass: the tool, the pass's arguments and
    flags, the configs, and every file its translation unit reads."""
    h = hashlib.sha256()
    stamp.feed(h, "version", version)
    for word in one.tidy_args:
        stamp.feed(h, "tidy-arg", word.encode())
    for word in one.flags:
        stamp.feed(h, "flag", word.encode())
    stamp.feed(h, "source", path.encode())
    for cfg in configs_for(path):
        stamp.feed(h, "config", str(cfg).encode())
        stamp.feed(h, "digest", digests.of(cfg))
    for dep in one.deps[path]:
        stamp.feed(h, "include", dep.encode())
        stamp.feed(h, "digest", digests.of(stamp.ROOT / dep))
    return h.hexdigest()


def batches(passes, jobs):
    """(pass, files) pairs for clang -M: a clang process costs more to
    start than to list one file, so a batch holds eight files or more."""
    for one in passes:
        count = max(1, min(jobs, len(one.files) // 8))
        for i in range(count):
            yield one, one.files[i::count]


def main(argv):
    passes = parse(argv)
    tidy = os.environ.get("CLANG_TIDY", "clang-tidy")
    clang = os.environ.get("CLANG", "")
    jobs = max(1, int(os.environ.get("LINT_JOBS", "4") or 4))
    # The tool's version, and this script's bytes and stamp.py's, so a
    # change to how a key is made runs every file again.
    version = b"\0".join([subprocess.run([tidy, "--version"], capture_output=True).stdout,
                          pathlib.Path(__file__).read_bytes(),
                          pathlib.Path(stamp.__file__).read_bytes()])

    if clang and not stamp.stamps_off():
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            work = list(batches(passes, jobs))
            for (one, _), found in zip(work, pool.map(lambda w: list_includes(clang, w[0].flags, w[1]), work)):
                one.deps.update(found)
    digests = Digests()
    todo, total = [], 0
    for one in passes:
        for path in one.files:
            total += 1
            key = key_of(version, one, path, digests) if path in one.deps else None
            if key is None or not stamp.stamp_path(NAME, key).exists():
                todo.append((one, path, key))

    lock = threading.Lock()

    def run(item):
        one, path, _ = item
        r = subprocess.run([tidy, "--quiet", *one.tidy_args, path, "--", *one.flags], cwd=stamp.ROOT,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = r.stdout.rstrip("\n")
        with lock:
            if out:
                print(out, flush=True)
        return r.returncode

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for (one, path, key), rc in zip(todo, pool.map(run, todo)):
            if rc != 0:
                failed += 1
            elif key and key_of(version, one, path, Digests()) == key:
                stamp.write_stamp(NAME, key, f"{path} -- {' '.join(one.flags)}")
    print(f"tidy-each: {len(todo)} of {total} files checked across {len(passes)} passes, "
          f"{total - len(todo)} passed before on the same inputs")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
