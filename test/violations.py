#!/usr/bin/env python3
"""Checks that the suite fails when an invariant is broken.

Run from the repository root: python3 test/violations.py [name ...]

    --tier=fast          only the second-scale targets FAST_TARGETS names
    --tier=slow          every other target
    --proof-backed       only the violations proof/prove-one.sh catches
    --not-proof-backed   every other violation
    --jobs N             run N violations at once, each in its own copy of
                         the tree; 1, the default, runs them one at a
                         time in the working tree
    --list               print the selected names, one per line; run nothing
    --lint-anchors       check every edit still matches its file exactly once

The selectors intersect. A selection that matches nothing is an error.

docs/invariants.md says what must never break, and each entry there
carries a Violation field describing what a breaking change looks like.
This turns those descriptions into edits and checks that some test
actually objects. A test suite that passes on broken code is not
guarding the invariant, whatever its name says.

make lint-invariants checks that the code does not violate an
invariant. This checks that a test notices when it does.

Each violation lives in test/violations/<name>.violation:

    invariant: INV-10
    file: record.c
    catches: unit             (a bin/ binary by name, or a script by path
                               followed by its arguments when it takes
                               any: proof/prove-one.sh x25519_tail runs
                               one CBMC harness)
    builds: bin/unit          (optional; required when catches is a script
                               that runs a bin/ binary, since a script
                               builds nothing of its own. A script that
                               only runs make, such as
                               test/lint-wide-multiply.sh, needs none)
    reason: one line on what breaks
    --- old
    <text to find, exactly once>
    --- new
    <text to replace it with>

The runner applies the edit, builds the named target, runs it, and
requires a NONZERO exit. Three outcomes:

  caught     the target failed, so the invariant is guarded
  unguarded  the target passed on broken code — a coverage hole
  STALE      the old text is gone, so the violation no longer applies

STALE is a failure too. A violation that silently stops matching is
worse than none, because it reports success forever.

With --jobs 1 the runner edits the working tree itself, one violation
after another, and restores each file before the next edit. With --jobs
N above 1 it first makes N copies of the working tree in a directory of
its own under bin/violations/, one per worker; make_copy says what a
copy holds. Each worker takes the next violation from one shared queue,
then applies, builds, runs and restores it inside its own copy, so no
two violations edit the same file and the working tree is never edited.
A violation whose target runs docker gets a fresh copy of its own. Each
violation's lines print whole when it finishes, so their order changes
from run to run, and the summary line reads the same either way. The
copies are deleted when the run ends. The proof-backed violations run
with --jobs 1 only: proof/run.sh admits each proof against the whole
machine's memory, so two at once could exhaust it.
"""

import concurrent.futures
import os
import pathlib
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import sys

# Each violation rebuilds and reruns its target, worth watching in
# real time, so flush per line rather than buffering until exit.
sys.stdout.reconfigure(line_buffering=True)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIOLATIONS = ROOT / "test" / "violations"

# The one script target that runs a CBMC harness. A violation whose
# catches line starts with it is proof-backed: its baseline and its
# mutant are each a proof of minutes, so the nightly runs that class in
# its own job, test-invariants-proof-backed, and every other violation
# in test-invariants (https://github.com/c4milo/chapulin/issues/144).
# The class is read from the catches line, never from a list kept by
# hand, so a new proof-backed violation lands in the right job the day
# it is added.
PROOF_RUNNER = "proof/prove-one.sh"

# prove-one.sh's exit status when its clock stops a run before cbmc
# reports either way, coreutils timeout's number. A mutant that keeps
# the formula from converging is not a mutant the proof refuted.
NO_VERDICT_EXIT = 124


def proof_backed(catches):
    return catches.split()[0] == PROOF_RUNNER


def date_after_every_build(target):
    """Dates target at the start of the next whole second and waits for
    that second to begin. Every file a build wrote before this call is
    then older than target, even to make 3.81, which compares whole
    seconds, so the next build compiles what depends on target. And
    target is never ahead of the clock: GNU make warns about a file dated
    in the future, and a catch script that reads make's output takes the
    warning for a finding. Nightly run 36308636104 failed seven baselines
    that way when target was the Makefile or a source a lint reads through
    make. The wait costs under a second per build."""
    now = time.time()
    second = float(int(now) + 1)
    time.sleep(second - now)
    os.utime(target, (second, second))


def parse(path):
    head, old, new, where = {}, [], [], "head"
    for line in path.read_text().splitlines():
        if line.strip() == "--- old":
            where = "old"
        elif line.strip() == "--- new":
            where = "new"
        elif where == "head":
            if line.strip() and not line.startswith("#"):
                key, _, value = line.partition(":")
                head[key.strip()] = value.strip()
        elif where == "old":
            old.append(line)
        else:
            new.append(line)
    for key in ("invariant", "file", "catches", "reason"):
        if key not in head:
            sys.exit(f"{path.name}: missing '{key}'")
    return head, "\n".join(old).strip("\n"), "\n".join(new).strip("\n")


def tail(output, lines=5):
    """The last few non-blank lines of a failed step's output, indented
    to sit under the ERROR line that quotes them."""
    kept = [l for l in (output or "").splitlines() if l.strip()][-lines:]
    return [f"           {l}" for l in kept]


def run(name, root=ROOT, env=None):
    """Apply one violation in the tree at root, build and run its target
    there, and restore the file. Returns the outcome and the lines that
    report it, which the caller prints whole. env is the environment of
    every command it starts; None passes the runner's own."""
    lines = []
    outcome = run_steps(name, root, env, lines.append)
    return outcome, "".join(f"{line}\n" for line in lines)


def run_steps(name, root, env, say):
    """run's steps. Each line of the report goes to say."""
    path = VIOLATIONS / f"{name}.violation"
    head, old, new = parse(path)
    target = root / head["file"]
    original = target.read_text()

    if original.count(old) != 1:
        say(f"  STALE    {name}: its 'old' text appears "
            f"{original.count(old)} times in {head['file']}, expected 1")
        return "stale"

    # A "catches" with a slash is a script run as-is, and the words after
    # it are its arguments (proof/prove-one.sh takes the harness name);
    # otherwise it names a binary under bin/. Either way the target must
    # be built from the source under test; a script that runs a bin/
    # binary and builds nothing of its own (test/e2e.sh runs no make)
    # needs a 'builds' line saying what to. A script that only runs make
    # (the codegen-gate scripts) or cbmc (proof/prove-one.sh) compiles the
    # edited source itself and needs none.
    command = head["catches"].split()
    target_is_script = "/" in command[0]
    if not target_is_script:
        command = [f"bin/{command[0]}"]
    binary = command[0]
    builds = head.get("builds", "" if target_is_script else binary).split()
    if target_is_script and not builds and binaries_run_by(root / binary):
        say(f"  STALE    {name}: a script target that runs a bin/ binary needs "
            f"a 'builds' line naming what to rebuild from the edited source")
        return "stale"

    def rebuild_and_run():
        """Rebuild the prerequisites from the source on disk now, then run
        the target. Returns (built_ok, run_returncode, output), where
        output is the failed step's stderr (stdout when stderr is
        empty) — the baseline error quotes it, because the target's
        own message otherwise never reaches the log.

        make decides staleness by whole-second mtimes, and a prior
        violation's edit-then-restore plus this one's edit can all land in
        one tick — leaving a binary make thinks is current but that was
        built from other source. So the edited file is dated after every
        file an earlier build wrote before each build
        (date_after_every_build): make then sees it as newer than any
        binary and rebuilds, and the verdict depends on the source rather
        than on build-cache timing. Dating the file, not deleting the
        objects, keeps the rebuild incremental — a delete would recompile
        every source each time."""
        date_after_every_build(target)
        # close_fds=False keeps the jobserver make hands this script (its
        # recipe line starts with +) open in the builds and the catch.
        # Closed, a make under them finds no jobserver and prints its
        # "Entering directory" lines into what a catch script reads from
        # make, which failed three catches on CI run 36278767672 (the
        # Makefile's comment above CHECK_REPORT).
        if builds:
            # RAND has no default and the examples link the packaged
            # object, so a bare make stops at cfg.h's #error. check
            # builds them the same way.
            b = subprocess.run(["make", "RAND=extern", *builds], cwd=root,
                               env=env, capture_output=True, text=True,
                               close_fds=False)
            if b.returncode != 0:
                return False, None, b.stderr or b.stdout
        r = subprocess.run(command, cwd=root, env=env, capture_output=True,
                           text=True, close_fds=False)
        return True, r.returncode, r.stderr or r.stdout

    # Baseline: the target must PASS on unedited source in this
    # environment before its verdict on an edit means anything. Without
    # it, a target that fails for an unrelated reason — a missing binary,
    # an absent oracle — makes the edit look caught when it was never
    # compiled in. "Break X, expect failure" says nothing unless X
    # demonstrably passes first.
    base_built, base_rc, base_output = rebuild_and_run()
    if not base_built:
        say(f"  ERROR    {name}: {' '.join(builds)} does not build on clean "
            f"source; cannot establish a baseline")
        for line in tail(base_output):
            say(line)
        return "error"
    if base_rc != 0:
        say(f"  ERROR    {name}: {head['catches']} fails on unedited source "
            f"(exit {base_rc}); its verdict on an edit would be meaningless")
        for line in tail(base_output):
            say(line)
        return "error"

    try:
        target.write_text(original.replace(old, new, 1))
        built, rc, output = rebuild_and_run()
        if not built:
            # An edit that will not compile proves nothing about the
            # tests, so say that rather than counting it as caught.
            say(f"  unguarded {name}: {head['file']} no longer compiles; "
                f"write an edit that builds")
            return "unguarded"
    finally:
        target.write_text(original)
        # After every build rather than now: make 3.81 compares mtimes
        # to the second, and the mutation build wrote its objects in the
        # second this restore lands in, so a source touched here does
        # not read as newer and make keeps them — a later `make check`
        # then reads an object built from the violation. Dating the
        # restored source after them makes every object and binary the
        # edit produced older, so the next build compiles this file
        # again. A script target is why it matters: it builds what it
        # runs, and the deletion below cannot name the objects it left. A
        # tcp-nonblocking tls.o survived a violation this way and failed its
        # own lib-check build afterwards, on restored source.
        date_after_every_build(target)
        # The binaries go as well, so no run takes one the violation
        # built. A poisoned bin/rsa_test once failed a full check an
        # hour after the violation run that made it.
        for b in builds:
            if b.startswith("bin/"):
                (root / b).unlink(missing_ok=True)
        if not target_is_script and binary.startswith("bin/"):
            (root / binary).unlink(missing_ok=True)

    if rc == NO_VERDICT_EXIT and proof_backed(head["catches"]):
        # The wrapper's clock stopped the run before cbmc reported either
        # way. A formula the edit keeps from converging is not a formula
        # the proof refuted, so this is not caught.
        say(f"  ERROR    {name}: {head['catches']} returned no verdict on "
            f"the edited source; a run the clock stopped refutes nothing")
        for line in tail(output):
            say(line)
        return "error"
    if rc != 0:
        say(f"  caught   {name} [{head['invariant']}] by {head['catches']}")
        return "caught"
    say(f"  unguarded {name} [{head['invariant']}]: {head['catches']} passed "
        f"on broken code")
    say(f"           {head['reason']}")
    return "unguarded"


# The fast tier for the PR lane is the targets that run in seconds: the
# unit suite, the strictness parsers, rsa_test, softmul_test, the webpki
# reader, session and certificate tests, the three codegen gate scripts, which compile
# with the pinned clang and with the Arm GNU gcc the m3 lane pins and
# answer in seconds, the trust-separation lint script, which reads
# the Makefile in three, the proof-cover lint script, which asks make for
# its builds' source lists in under two, the TRUST=webpki frame-budget
# script, which compiles that object's sources in two, the stack walk script, which
# compiles a fixture twice in under one, the QUIC partition lint
# script, which preprocesses the root sources in three, and the
# tcp-nonblocking webpki link script, which links that object in two
# and a half, the X25519 equivalence binary, which runs in fifteen
# seconds, and the two Zig build scripts, which answer in five and two
# seconds with their objects built and rebuild what an edit touches, the
# TX_RECORD build script, which answers in three, and the TX_RECORD loop
# binary, which builds in three and runs in under one. Left out are the ones whose single run is expensive — the
# exhaustive handshake enumeration (minutes), the end-to-end suite
# (needs live servers), and the differential (each run drives ~6000 oracle
# comparisons, so a baseline and a mutation pass together are ~30s per
# violation). The tier follows the target, so no per-violation field
# drifts from what the check runs. The set holds whole catches lines, so
# a line that carries an argument never matches: the proof-backed
# violations (proof/prove-one.sh <harness>) run only in the nightly's
# test-invariants-proof-backed job, where each is a CBMC proof of
# minutes, twice, and lint_fast_targets refuses one typed in here.
FAST_TARGETS = {"unit", "unit_ca", "x509strict", "x509strict_ecdsa",
                "rsa_test", "drbg_test", "handshake_strict_test", "handshake_strict_webpki",
                "webpki_name_test", "webpki_session_test", "webpki_chain_test",
                "webpki_resume_test", "webpki_resume_tcp_nonblocking",
                "webpki_auth_test", "webpki_encrypted_exts_test",
                "softmul_test", "unit_ct_widemul", "mlkem_test_ct_widemul",
                "webpki_spki_test", "webpki_sigalg_test", "webpki_cert_test",
                "webpki_time_test", "p384_test", "p256_field_test", "p256_ecdh_test",
                "sha3_test", "sha3_equiv_test",
                "test/lint-wide-multiply.sh", "test/lint-wide-multiply-gcc.sh",
                "test/lint-runtime-symbols.sh", "test/lint-trust-separation.sh",
                "test/lint-proof-cover.sh",
                "test/lint-p256-wide.sh",
                "test/lint-exact-fill.sh", "test/lint-invariants.sh",
                "test/lint-stack-webpki.sh",
                "test/lint-stack-quic.sh", "test/lint-stack-walk.sh",
                "test/lib-check-webpki-tcp-nonblocking.sh",
                "test/lint-quic-partition.sh", "test/lint-quic-surface.sh",
                "test/quic-builds.sh", "test/chacha-builds.sh", "test/mlkem-builds.sh",
                "test/zig-build-check.sh", "test/localize-check.sh",
                "test/tx-record-builds.sh", "webpki_loop_tx_record",
                "quic_driver_test", "srv_stub_test", "x25519_equiv_test", "chacha20_equiv_test",
                "mlkem_vector_equiv_test",
                "poly1305_equiv_test", "p256_equiv_test", "p256_equiv_test_sum",
                "p256_equiv_test_builtin", "p256_verify_equiv_test", "p384_equiv_test",
                "p384_test_host", "rsa_equiv_test",
                "rsa_sign_equiv_test",
                "rsa_sign_test_host",
                "quic_test_extern"}


def catches_of(name):
    return parse(VIOLATIONS / f"{name}.violation")[0]["catches"]


def binaries_run_by(script):
    """The bin/ binaries a script runs, read from its text."""
    return set(re.findall(r"\./(bin/[a-z0-9_]+)", script.read_text()))


def lint_anchors():
    """An edit whose old text no longer matches is reported stale, but only
    once the runner has built its target, which is minutes away and in
    check-slow. Matching the text costs no build at all, so this runs in
    check and says which file moved under which edit.

    It counts rather than tests presence: three TRUST arms write the same
    filter line, so an edit that named that line alone matched all three
    and was refused as ambiguous. Both failures read the same here."""
    bad = 0
    for path in sorted(VIOLATIONS.glob("*.violation")):
        head, old, _ = parse(path)
        target = pathlib.Path(head["file"])
        if not target.exists():
            print(f"lint-violation-anchors: {path.name} edits {target}, which is missing")
            bad = 1
            continue
        n = target.read_text().count(old)
        if n != 1:
            found = "no longer appears in" if n == 0 else f"appears {n} times in"
            print(f"lint-violation-anchors: {path.name}'s old text {found} {target}")
            bad = 1
    if bad:
        print("lint-violation-anchors: re-anchor each edit on the text that is there now")
        return 1
    print("lint-violation-anchors: every edit matches its file exactly once")
    return 0


def lint_builds():
    """A script target runs no make, so its 'builds' line is the only thing
    that puts binaries on disk. A name missing there fails quietly: the
    baseline runs a binary nobody built and that invariant loses its
    verdict. INV-21 lost bin/tlsclient_pq this way when KEX=pq added the
    go-pq tests."""
    bad = 0
    for path in sorted(VIOLATIONS.glob("*.violation")):
        head, _, _ = parse(path)
        catches = head["catches"]
        if "/" not in catches:
            continue
        script = pathlib.Path(catches.split()[0])
        if not script.exists():
            print(f"lint-violation-builds: {path.name} catches {script}, which is missing")
            bad = 1
            continue
        needs = binaries_run_by(script)
        builds = set(head.get("builds", "").split())
        missing = sorted(needs - builds)
        if missing:
            print(f"lint-violation-builds: {path.name} runs {' '.join(missing)} "
                  f"but does not build it")
            bad = 1
    bad |= builds_without_rule()
    if bad:
        return 1
    print("lint-violation-builds: every script target names the binaries it runs, "
          "and make has a rule for each")
    return 0


def builds_without_rule():
    """A 'builds' name make has no rule for fails only when that violation
    runs, in check-slow, as an error rather than a verdict: the webpki
    change deleted bin/tlsclient_webpki_pq while a server violation still
    listed it. make's own database, printed without building anything,
    names every target that has a rule; a dry run cannot stand in for it,
    because a binary left on disk from before the rule went away reads as
    a file with nothing to do. Returns 1 when a name has no rule."""
    uses = {}
    for path in sorted(VIOLATIONS.glob("*.violation")):
        head, _, _ = parse(path)
        for name in head.get("builds", "").split():
            uses.setdefault(name, []).append(path.name)
    if not uses:
        return 0
    r = subprocess.run(["make", "-p", "-q", "-n", "RAND=extern"], cwd=ROOT,
                       capture_output=True, text=True, close_fds=False)
    targets = set()
    previous = ""
    for line in r.stdout.splitlines():
        m = re.match(r"^([^#\s][^:=]*?):(?!=)", line)
        if m and previous != "# Not a target:":
            targets.update(m.group(1).split())
        previous = line
    unknown = sorted(name for name in uses if name not in targets)
    for name in unknown:
        print(f"lint-violation-builds: {', '.join(uses[name])} builds {name}, "
              "which make has no rule for")
    return 1 if unknown else 0


def lint_fast_targets():
    """FAST_TARGETS holds whole catches lines, so a proof-backed line gets
    in only by being typed there. Refuse it on every invocation: the fast
    tier is the PR lane's, and a CBMC proof run twice is not a PR-lane
    cost. make check reaches this through lint-violation-builds."""
    for line in sorted(FAST_TARGETS):
        if proof_backed(line):
            sys.exit(f"test-invariants: FAST_TARGETS holds {line!r}, a "
                     f"proof-backed target; the fast tier runs in the PR lane "
                     f"and a CBMC proof does not")


def select(argv):
    """The violation names argv picks: the positional names, or every
    file in test/violations/, narrowed by the tier and class selectors."""
    names = [a for a in argv if not a.startswith("--")]
    names = names or sorted(p.stem for p in VIOLATIONS.glob("*.violation"))
    tier = next((a[len("--tier="):] for a in argv
                 if a.startswith("--tier=")), None)
    if tier == "fast":
        names = [n for n in names if catches_of(n) in FAST_TARGETS]
    elif tier == "slow":
        names = [n for n in names if catches_of(n) not in FAST_TARGETS]
    elif tier is not None:
        sys.exit(f"test-invariants: unknown --tier={tier} (want fast or slow)")
    if "--proof-backed" in argv and "--not-proof-backed" in argv:
        sys.exit("test-invariants: --proof-backed and --not-proof-backed "
                 "together select nothing")
    if "--proof-backed" in argv:
        names = [n for n in names if proof_backed(catches_of(n))]
    if "--not-proof-backed" in argv:
        names = [n for n in names if not proof_backed(catches_of(n))]
    if not names:
        sys.exit("test-invariants: the selection matches no violation in "
                 "test/violations/")
    return names


# Where --jobs above 1 makes its copies of the tree. bin/ is ignored, so
# git in the working tree never lists a copy's files.
COPIES = ROOT / "bin" / "violations"

# The paths git ignores that a violation's build or catch target reads.
# Every other ignored path is something a build writes, and a copy writes
# its own. tools/node_modules is not here: only lint-commits reads it,
# and no violation runs that.
#
#   spec/lean/.lake    bin/diff and bin/handshake_sequence_test run the
#                      spec's oracle, .lake/build/bin/diffspec.
#                      test-invariants-not-proof-backed builds it before
#                      the runner starts, and no violation writes there,
#                      so a copy holds a symbolic link to it.
#   bin/wycheproof     the checkout `make wycheproof` (test/wycheproof.sh)
#                      and cross-check generate their vectors from.
#   bin/rv32tc-docker  the toolchain test/docker-riscv32.sh downloads.
#
# The docker lanes mount a copy at /src, where a symbolic link to a path
# on the host names nothing, so a copy holds hard links to the files of
# the last two. The targets read them and write none: the Makefile's
# fetch deletes bin/wycheproof and fetches it again when it names another
# commit, and the docker script downloads the toolchain only when it is
# missing.
LINKED_INPUTS = ("spec/lean/.lake",)
HARD_LINKED_INPUTS = ("bin/wycheproof", "bin/rv32tc-docker")
# bin/stamps holds tools/stamp.py's record of each check that passed and
# the assembly lint-wide-multiply keeps, each named by a SHA-256 over
# what the check or compile reads, with file names relative to the tree,
# and never by a time. A copy holds a copy of it, so its checks skip
# exactly what the working tree's would, and write their new stamps in
# the copy.
COPIED_INPUTS = ("bin/stamps",)

# The variables that make git read a repository other than the one it
# finds from its working directory. A copy's commands run without them,
# so the git in a copy reads the copy's own index and never writes the
# working tree's.
GIT_REPOSITORY_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                            "GIT_COMMON_DIR")

OUTCOMES = ("caught", "unguarded", "stale", "error")


class CopyFailed(Exception):
    """A step that makes a copy of the tree failed."""


def git(cwd, env, *args, stdin=None):
    """What a git command prints. Raises CopyFailed when it fails."""
    r = subprocess.run(["git", *args], cwd=cwd, env=env, input=stdin,
                       capture_output=True)
    if r.returncode != 0:
        raise CopyFailed(f"test-invariants: git {' '.join(args[:2])} failed "
                         f"in {cwd}: {r.stderr.decode().strip()}")
    return r.stdout


def link_or_copy(source, dest):
    """A hard link at dest to source, or a copy where the two sit on
    different file systems."""
    try:
        os.link(source, dest)
    except OSError:
        shutil.copy2(source, dest)


def make_copy(dest, files, staged, env):
    """A copy of the working tree at dest, for one worker or for one
    violation whose target runs docker. It holds:

      - files, the paths git lists in the working tree, tracked or
        untracked but not ignored, each copied with its mode and mtime,
        so make compares the copied files with each other as it does in
        the working tree;
      - a git repository whose index holds staged, the working tree's
        index entries, because lint-invariants, lint-trust-separation,
        lint-quic-partition, lint-proof-cover, test/zig-build-check.sh and
        tools/stamp.py ask `git ls-files` which files exist;
      - LINKED_INPUTS, HARD_LINKED_INPUTS and COPIED_INPUTS, where the
        working tree has them.

    Nothing else goes in bin/, so each copy builds every object and
    binary its violations need, and the make 3.81 handling in run_steps
    applies to that copy's objects alone."""
    for path in files:
        source = ROOT / path
        if not os.path.lexists(source):
            continue  # deleted from the working tree but still in its index
        (dest / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest / path, follow_symlinks=False)
    git(dest, env, "init", "-q")
    git(dest, env, "update-index", "-z", "--index-info", stdin=staged)
    for path in LINKED_INPUTS + HARD_LINKED_INPUTS + COPIED_INPUTS:
        source = ROOT / path
        if not source.exists():
            continue
        (dest / path).parent.mkdir(parents=True, exist_ok=True)
        if path in LINKED_INPUTS:
            (dest / path).symlink_to(source)
        elif path in HARD_LINKED_INPUTS:
            shutil.copytree(source, dest / path, symlinks=True,
                            copy_function=link_or_copy)
        else:
            shutil.copytree(source, dest / path, symlinks=True)
    return dest


def copier(env):
    """A function that makes a copy of the working tree at the path it is
    given. It lists the files once, so every copy holds the same ones."""
    listed = git(ROOT, env, "ls-files", "-z", "--cached", "--others",
                 "--exclude-standard")
    files = sorted({os.fsdecode(p) for p in listed.split(b"\0") if p})
    staged = git(ROOT, env, "ls-files", "-z", "--stage")
    return lambda dest: make_copy(dest, files, staged, env)


def runs_docker(catches):
    """Whether a catch target is a script that runs docker. The docker
    lanes mount the tree they run in at /src, and on Linux the files the
    container writes there belong to root, so a later build in the same
    tree may be unable to replace them."""
    script = catches.split()[0]
    return "/" in script and "docker run" in (ROOT / script).read_text()


def schedule(names):
    """The order the workers take names in: the slow tier's first, since
    one of those targets can run for many minutes and should not start
    last, then the fast tier's, each in name order."""
    return sorted(names, key=lambda n: catches_of(n) in FAST_TARGETS)


def run_parallel(names, jobs):
    """Run names on jobs workers, each in its own copy of the tree under
    COPIES, and print each report whole as it finishes. Returns the
    tally. The copies are deleted before it returns."""
    env = {k: v for k, v in os.environ.items()
           if k not in GIT_REPOSITORY_VARIABLES}
    COPIES.mkdir(parents=True, exist_ok=True)
    # A directory of its own, so two runs in one tree never share a copy.
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=COPIES))
    try:
        return run_workers(names, jobs, run_dir, copier(env), env)
    except CopyFailed as e:
        sys.exit(str(e))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def run_workers(names, jobs, run_dir, copy, env):
    """run_parallel's workers: one thread per copy, each taking the next
    name from one shared queue until the queue is empty."""
    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        copies = list(pool.map(copy, (run_dir / str(i) for i in range(jobs))))
    print(f"test-invariants: {jobs} workers, one copy of the tree each, "
          f"under {run_dir.relative_to(ROOT)}")
    # A violation whose target runs docker gets a copy of its own, deleted
    # after it, so no other violation builds where the container wrote.
    own_copy = {n for n in names if runs_docker(catches_of(n))}
    pending = queue.SimpleQueue()
    for name in schedule(names):
        pending.put(name)
    tally = dict.fromkeys(OUTCOMES, 0)
    lock = threading.Lock()

    def run_in(root, name):
        if name not in own_copy:
            return run(name, root, env)
        root = copy(run_dir / name)
        try:
            return run(name, root, env)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def worker(root):
        while True:
            try:
                name = pending.get_nowait()
            except queue.Empty:
                return
            try:
                outcome, report = run_in(root, name)
            except Exception as e:  # counted, so the tally covers every name
                outcome = "error"
                report = (f"  ERROR    {name}: the runner raised "
                          f"{type(e).__name__}: {e}\n")
            with lock:
                tally[outcome] += 1
                sys.stdout.write(report)
                sys.stdout.flush()

    threads = [threading.Thread(target=worker, args=(c,), daemon=True)
               for c in copies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return tally


def jobs_option(argv):
    """argv without its --jobs option, and the option's value: 1 when it
    is absent. It takes `--jobs N` or `--jobs=N`."""
    rest, value = [], "1"
    args = iter(argv)
    for a in args:
        if a == "--jobs":
            value = next(args, "")
        elif a.startswith("--jobs="):
            value = a[len("--jobs="):]
        else:
            rest.append(a)
    if not re.fullmatch(r"[0-9]+", value) or int(value) < 1:
        sys.exit(f"test-invariants: --jobs takes a whole number of at least "
                 f"1, not {value!r}")
    return rest, int(value)


OPTIONS = {"--lint-builds", "--lint-anchors", "--list", "--proof-backed",
           "--not-proof-backed"}


def main():
    lint_fast_targets()
    argv, jobs = jobs_option(sys.argv[1:])
    for flag in (a for a in argv if a.startswith("--")):
        if flag not in OPTIONS and not flag.startswith("--tier="):
            # A misspelt selector must not fall through to the whole set.
            sys.exit(f"test-invariants: unknown option {flag}")
    if "--lint-builds" in argv:
        sys.exit(lint_builds())
    if "--lint-anchors" in argv:
        sys.exit(lint_anchors())
    names = select(argv)
    if "--list" in argv:
        print("\n".join(names))
        return
    proofs = [n for n in names if jobs > 1 and proof_backed(catches_of(n))]
    if proofs:
        sys.exit(f"test-invariants: the selection holds {len(proofs)} "
                 f"proof-backed violations, and --jobs {jobs} would run them "
                 f"side by side while proof/run.sh admits each proof against "
                 f"the whole machine's memory; add --not-proof-backed, or run "
                 f"them with --jobs 1")
    print(f"test-invariants: {len(names)} violations to check")
    if jobs > 1:
        tally = run_parallel(names, min(jobs, len(names)))
    else:
        tally = dict.fromkeys(OUTCOMES, 0)
        for name in names:
            outcome, report = run(name)
            print(report, end="")
            tally[outcome] += 1
    print(f"test-invariants: {tally['caught']} caught, "
          f"{tally['unguarded']} unguarded, {tally['stale']} stale, "
          f"{tally['error']} error")
    if tally["unguarded"] or tally["stale"] or tally["error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
