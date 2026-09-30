#!/usr/bin/env python3
"""Checks that bench/stack.py follows a call and a tail call, keeps apart
two static functions of one name, and compiles what make packages.

Run from the repository root: python3 test/stack_walk.py bench/stack.py

bench/stack.py reads the call graph from the relocations objdump prints
under each call and jump, and adds the frames on the deepest path. This
compiles a three-object fixture for arm64 and for x86-64 Mach-O, reads
the objects with the script's own functions, and requires three walks,
each with the frames the .su files give:

- entry() reaches deep() through first(), whose first instruction is its
  tail call to deep(). The walk once read the target objdump prints on
  that branch line, a placeholder that names first() itself, and dropped
  the edge. Under CHACHA=vector that took chacha20_xor's jump to
  chacha20_vector_xor out of the call graph.
- wide() and narrow() each call a static helper() of their own object,
  with a different frame and different callees. The walk once keyed a
  function by its symbol alone, so it took the larger frame and both
  sets of callees for each helper(). It also compiled every root source
  then, and the two together put p384.c's point_add() and rsa_mont.c's
  mont_mul() under a TRUST=raw-ecdsa build's p256_ecdsa_verify(), so
  that build's ch_connect peak read 720 bytes high.

It also requires the walks to name sink(), which no object defines, as
the one call they count no frame for, STACK_PRUNE to take out one static
helper() by the name the report prints, and stack.py's main() to compile
the sources make packages for the build it walks, with the defines make
packages them with.

CLANG names the compiler, and STACK_NM and STACK_OBJDUMP the tools the
script reads with. make lint-stack-walk passes the pinned LLVM ones,
which read a Mach-O object on any host.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# noinline keeps each call a call. first() does nothing but call deep(),
# so clang compiles that call to a jump at its first instruction. On
# x86-64 that takes -fomit-frame-pointer, because the frame pointer's
# setup would come first. Every other call passes a local's address on,
# or has a call after it that does, so none of them is a tail call.
FIXTURE = """\
void sink(volatile unsigned char *p);

__attribute__((noinline)) void deep(void) {
    volatile unsigned char buf[256];
    sink(buf);
}

__attribute__((noinline)) void first(void) {
    deep();
}

void entry(void) {
    volatile unsigned char buf[32];
    first();
    sink(buf);
}
"""

# wide.c's helper() has the larger frame and calls deep(); narrow.c's has
# the smaller one and calls nothing the walk measures.
WIDE = """\
void sink(volatile unsigned char *p);
void deep(void);

__attribute__((noinline)) static void helper(void) {
    volatile unsigned char buf[512];
    deep();
    sink(buf);
}

void wide(void) {
    volatile unsigned char buf[32];
    helper();
    sink(buf);
}
"""

NARROW = """\
void sink(volatile unsigned char *p);

__attribute__((noinline)) static void helper(void) {
    volatile unsigned char buf[16];
    sink(buf);
}

void narrow(void) {
    volatile unsigned char buf[32];
    helper();
    sink(buf);
}
"""

SOURCES = {"fixture.c": FIXTURE, "wide.c": WIDE, "narrow.c": NARROW}

# Each walk the check requires: its entry point, the functions on its
# deepest path, each as the object whose .su file gives its frame and its
# name there, how many steps of the path are calls rather than jumps, and
# the path as the report prints it. first() jumps to deep(), so that step
# pushes no return address.
WALKS = [
    ("entry", [("fixture", "entry"), ("fixture", "first"), ("fixture", "deep")], 1,
     "entry > first > deep"),
    ("wide", [("wide", "wide"), ("wide", "helper"), ("fixture", "deep")], 2,
     "wide > wide.o:helper > deep"),
    ("narrow", [("narrow", "narrow"), ("narrow", "helper")], 1, "narrow > narrow.o:helper"),
]

# The target, its flags beyond the script's, and the bytes a call pushes
# that no frame's figure counts.
TARGETS = [
    ("arm64-apple-macos", [], 0),
    ("x86_64-apple-macos", ["-fomit-frame-pointer"], 8),
]


def su_frames(tmp: Path) -> dict[tuple[str, str], int]:
    """Each function's frame as the .su files give it, by object and name,
    read here rather than through the script."""
    out = {}
    for su in tmp.glob("*.su"):
        for line in su.read_text().splitlines():
            where, size = line.split("\t")[:2]
            out[(su.stem, where.split(":")[-1])] = int(size)
    return out


def stopped(call) -> str:
    """The message call stops the script with, or nothing."""
    try:
        call()
    except SystemExit as stop:
        return str(stop)
    return "nothing"


def check(stack, clang: str, triple: str, flags: list[str], pushed: int) -> bool:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # clang calls __stack_chk_fail by default for a Darwin target, and
        # -fno-stack-protector leaves sink() the one function the fixture
        # calls and does not define.
        for name, text in SOURCES.items():
            (tmp / name).write_text(text)
            subprocess.run([clang, f"--target={triple}", *stack.CFLAGS, *flags,
                            "-fno-stack-protector", "-c", name], cwd=tmp, check=True)
        su = su_frames(tmp)
        frames = stack.frames(tmp)
        edges, entry_pushed = stack.callgraph(tmp)
        walks = [(entry, stack.deepest("_" + entry, frames, edges, ()), functions, calls, chain)
                 for entry, functions, calls, chain in WALKS]
        # Every object calls sink() and none defines it, so the report
        # names it as the one call the walks count no frame for.
        lines = stack.report(frames, edges, ["_" + walk[0] for walk in WALKS], pushed)
        # STACK_PRUNE names a function as the report prints it, so
        # narrow.o:helper takes out narrow()'s helper() and leaves wide()'s,
        # and a bare helper names no function and stops the script.
        accepted = stopped(lambda: stack.prune(frames, edges, ["narrow.o:helper"]))
        pruned = [stack.deepest("_" + entry, frames, edges, ())[0] for entry in ("wide", "narrow")]
        refused = stopped(lambda: stack.prune(frames, edges, ["helper"]))
    ok = entry_pushed == pushed
    if not ok:
        print(f"lint-stack-walk: {triple}: a call pushes {entry_pushed} B; want {pushed} B")
    wants = {}
    for entry, (depth, path), functions, calls, chain in walks:
        wants[entry] = sum(su[f] for f in functions) + pushed * calls
        got = f"{depth} B via {' > '.join(stack.shown(p) for p in path)}"
        if got != f"{wants[entry]} B via {chain}":
            print(f"lint-stack-walk: {triple}: the walk from {entry} reads {got}; "
                  f"want {wants[entry]} B via {chain}")
            ok = False
        else:
            print(f"lint-stack-walk: {triple}: {got}")
    frameless = "(no frame counted for the calls no object defines: sink)"
    if frameless not in lines:
        print(f"lint-stack-walk: {triple}: the report reads {lines[len(WALKS):]}; want the "
              f"line {frameless}")
        ok = False
    want_pruned = [wants["wide"], su[("narrow", "narrow")]]
    if accepted != "nothing" or pruned != want_pruned:
        print(f"lint-stack-walk: {triple}: pruning narrow.o:helper prints {accepted} and "
              f"leaves wide and narrow at {pruned[0]} and {pruned[1]} B; want nothing, "
              f"and {want_pruned[0]} and {want_pruned[1]} B")
        ok = False
    if refused != "stack.py: STACK_PRUNE names no function called helper":
        print(f"lint-stack-walk: {triple}: pruning helper prints {refused}; want the "
              f"message that STACK_PRUNE names no function called helper")
        ok = False
    return ok


class Compiled(Exception):
    """Ends stack.py's main() once it names what it compiles."""


def check_sources(stack) -> bool:
    """main() compiles the sources make packages for the build it walks,
    with the defines make packages them with, and no other root source. It
    once compiled every root source, so a TRUST=raw-ecdsa walk read p384.c
    and rsa_mont.c, which that build does not package. The check walks
    that build because its defines name more than RAND's: without
    -DCH_PIN_ECDSA, handshake_auth.c calls the RSA verifier that build does
    not compile."""
    def build(tmp, srcs, flags):
        raise Compiled(srcs, flags)

    stack.build = build
    os.environ["STACK_MAKE"] = "TRUST=raw-ecdsa"
    os.environ["STACK_CFLAGS"] = ""
    try:
        stack.main()
        got = None
    except Compiled as compiled:
        got = (compiled.args[0], compiled.args[1])
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    lines = subprocess.run(["make", "-s", "--no-print-directory", "print-lib-lists",
                            "RAND=extern", "TRUST=raw-ecdsa"], env=env, check=True,
                           capture_output=True, text=True).stdout.splitlines()
    want = (lines[0].split(), lines[1].split())
    if got != want:
        print(f"lint-stack-walk: stack.py compiles {got}; want make's {want}")
        return False
    print(f"lint-stack-walk: stack.py compiles the {len(want[0])} sources make packages")
    return True


def main() -> int:
    spec = importlib.util.spec_from_file_location("stack", sys.argv[1])
    stack = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stack)
    clang = os.environ.get("CLANG") or "clang"
    results = [check(stack, clang, *target) for target in TARGETS]
    results.append(check_sources(stack))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
