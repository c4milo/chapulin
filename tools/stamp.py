#!/usr/bin/env python3
"""Run a check, or skip it when it already passed on the same inputs.

Run from the repository root, through the Makefile:

    python3 tools/stamp.py NAME INPUT... -- COMMAND [ARG...]

NAME names the check, and its stamps sit in bin/stamps/NAME/. Each INPUT
names something the check reads:

    --content PATHSPEC  the names and bytes of every file git lists for
                        the pathspec, tracked or untracked but not
                        ignored, and which of those names the index
                        tracks. `--content .` is the whole working tree.
    --names PATHSPEC    the same names without the bytes, for a check
                        that reads which files exist but not what they
                        hold.
    --file PATH         the bytes of one file, which may sit where git
                        does not look, under bin/ for one.
    --output COMMAND    a shell command and what it prints, with its exit
                        status: a tool's --version, or a preprocessor run
                        that prints every byte a compile reads.
    --text TEXT         a literal string, such as the variables a check
                        runs under.

Every key also covers the variables make was given on its command line,
which make passes down in MAKEFLAGS, and the environment variables
ENVIRONMENT names below, since a check reads both without naming them.

The key is one SHA-256 over this file's own bytes, every input and
COMMAND. When
bin/stamps/NAME/KEY exists, COMMAND passed on exactly these inputs
before, so this prints one line saying so and exits 0 without running
it. Otherwise it runs COMMAND and exits with its status. When COMMAND
exits 0, this computes the key a second time and writes the stamp only
when the two agree, so a file edited while COMMAND ran is checked again
on the next run.

A stamp holds content, never a time. make 3.81 compares mtimes to the
second, so a file stamp dated after its inputs can still predate an edit
made in the same second, and a key over the bytes cannot.

A stamp sees only what its inputs name. A check that reads a file no
input names, or a tool whose version string stays put across a change in
behavior, can pass on a stamp it should not, so a check names more inputs
rather than fewer. CI starts every job without bin/, so every CI job runs
every check in full. CHECK_NO_STAMPS=1 runs COMMAND whatever the stamps
say and writes none.

tools/tidy-each.py keys each file clang-tidy reads the same way and
imports the helpers below.
"""

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAMPS = ROOT / "bin" / "stamps"
NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
KINDS = ("--content", "--names", "--file", "--output", "--text")
# The environment variables every key covers: the compilers and flags the
# Makefile takes from the environment, CI, which turns a skip into a
# failure in several checks, and PATH, which decides the tool a bare
# name runs.
ENVIRONMENT = ("CC", "CXX", "CFLAGS", "LDFLAGS", "CI", "PATH")


class NoKey(Exception):
    """An input could not be read, so no key covers this run."""


def feed(h, label, data):
    """Add one labelled field to a hash. The length prefix keeps two
    fields from reading as one: "ab" + "c" and "a" + "bc" differ."""
    h.update(label.encode() + b"\0" + str(len(data)).encode() + b"\0")
    h.update(data)


def file_bytes(path):
    """What a file holds, as a check that opens it would read it. A
    symbolic link is named by its target and a missing file by that
    fact, so neither hashes like an empty file."""
    p = Path(path)
    if p.is_symlink():
        return b"link\0" + os.readlink(p).encode()
    try:
        return b"file\0" + p.read_bytes()
    except FileNotFoundError:
        return b"missing"
    except IsADirectoryError:
        return b"directory"


def git_names(*args):
    """A sorted list of the paths a git ls-files query prints."""
    r = subprocess.run(["git", "ls-files", "-z", *args], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        raise NoKey(f"git ls-files {' '.join(args)} failed: {r.stderr.decode().strip()}")
    return sorted(p for p in r.stdout.split(b"\0") if p)


def feed_paths(h, pathspec, with_bytes):
    """The files git lists for a pathspec: every name in the working tree
    that .gitignore does not exclude, which of them the index tracks, and,
    when asked, the bytes of each."""
    seen = git_names("--cached", "--others", "--exclude-standard", "--", pathspec)
    tracked = git_names("--cached", "--", pathspec)
    feed(h, "pathspec", pathspec.encode())
    feed(h, "tracked", b"\0".join(tracked))
    for path in seen:
        feed(h, "path", path)
        if with_bytes:
            feed(h, "bytes", file_bytes(os.fsdecode(path)))


def feed_output(h, command):
    """A shell command and everything it prints, with its exit status."""
    r = subprocess.run(command, shell=True, cwd=ROOT, capture_output=True)
    feed(h, "command", command.encode())
    feed(h, "stdout", r.stdout)
    feed(h, "stderr", r.stderr)
    feed(h, "status", str(r.returncode).encode())


def make_overrides():
    """The variables make's command line set, as make passes them down:
    the words after ` -- ` in MAKEFLAGS. A sub-make lists them in another
    order than its parent, so they are sorted. The jobserver's file
    descriptors sit before the ` -- ` and change from run to run, so they
    are left out."""
    flags = os.environ.get("MAKEFLAGS", "")
    if " -- " not in f" {flags}":
        return []
    tail = f" {flags}".split(" -- ", 1)[1]
    words, current, escaped = [], "", False
    for c in tail:
        if escaped:
            current += c
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == " ":
            if current:
                words.append(current)
            current = ""
        else:
            current += c
    if current:
        words.append(current)
    return sorted(words)


def key_of(inputs, command):
    """The SHA-256 over every input and the command, in the order given.
    This file's own bytes open the key, so a change to how a key is made
    runs every check again."""
    h = hashlib.sha256()
    feed(h, "stamp.py", Path(__file__).read_bytes())
    for word in make_overrides():
        feed(h, "override", word.encode())
    for name in ENVIRONMENT:
        feed(h, "environment", f"{name}={os.environ.get(name, '')}".encode())
    for kind, value in inputs:
        if kind == "--content":
            feed_paths(h, value, True)
        elif kind == "--names":
            feed_paths(h, value, False)
        elif kind == "--file":
            feed(h, "file", value.encode())
            feed(h, "bytes", file_bytes(ROOT / value))
        elif kind == "--output":
            feed_output(h, value)
        else:
            feed(h, "text", value.encode())
    for word in command:
        feed(h, "argv", word.encode())
    return h.hexdigest()


def stamps_off():
    return os.environ.get("CHECK_NO_STAMPS", "") not in ("", "0")


def stamp_path(name, key):
    return STAMPS / name / key


def write_stamp(name, key, note):
    """Record that the check passed on the inputs this key covers. The
    rename makes the stamp appear whole or not at all."""
    path = stamp_path(name, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_name(f"{key}.{os.getpid()}")
    scratch.write_text(note + "\n")
    scratch.replace(path)


def parse(argv):
    """NAME, the inputs in order, and the command after `--`."""
    if len(argv) < 3 or "--" not in argv:
        sys.exit("usage: stamp.py NAME INPUT... -- COMMAND [ARG...]")
    split = argv.index("--")
    name, options, command = argv[0], argv[1:split], argv[split + 1:]
    if not NAME.match(name):
        sys.exit(f"stamp: {name!r} is not a stamp name; use letters, digits, '.', '_' and '-'")
    if not command:
        sys.exit(f"stamp: {name}: no command after --")
    inputs = []
    i = 0
    while i < len(options):
        kind = options[i]
        if kind not in KINDS or i + 1 >= len(options):
            sys.exit(f"stamp: {name}: {kind!r} is not an input; use one of {', '.join(KINDS)} with a value")
        inputs.append((kind, options[i + 1]))
        i += 2
    if not inputs:
        sys.exit(f"stamp: {name}: no input named; a stamp over nothing would skip every run")
    return name, inputs, command


def main(argv):
    name, inputs, command = parse(argv)
    key = None
    if not stamps_off():
        try:
            key = key_of(inputs, command)
        except NoKey as e:
            print(f"{name}: {e}; running with no stamp")
    if key and stamp_path(name, key).exists():
        print(f"{name}: passed before on these inputs (bin/stamps/{name}/{key[:12]}), so it did not run")
        return 0
    # close_fds=False passes on the descriptors make gave this process, so
    # a make that COMMAND starts joins the caller's jobserver instead of
    # warning that it is gone and running one job at a time.
    rc = subprocess.run(command, cwd=ROOT, close_fds=False).returncode
    if rc < 0:
        rc = 128 - rc
    if rc != 0 or key is None:
        return rc
    try:
        again = key_of(inputs, command)
    except NoKey:
        again = None
    if again == key:
        write_stamp(name, key, " ".join(command))
    else:
        print(f"{name}: an input changed while it ran, so no stamp was written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
