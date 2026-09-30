#!/usr/bin/env python3
"""Worst-case stack per entry point, computed from the code, not by hand.

Builds the sources the Makefile packages for one build with
-fstack-usage, extracts the real call graph from the object code (the
branch relocations `objdump -d -r` prints under every call and tail call
in an arm64 or x86-64 Mach-O object), and walks the max-weight path under
each public entry point. Indirect calls (the caller's send/recv/on_ticket
hooks and ch_rand_bytes) execute on the caller's budget and are reported
as such, not silently omitted.
"""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
# The public calls, per build. ch_pubkey_from_pem exists only under
# a CA mode, so it is measured only when the object defines it -- but an
# entry that is listed and absent is a script bug, not a build variant,
# so main() names the difference instead of printing a silent 0. Its
# symbol name carries the transport (x509_ca.h), and this script builds
# TRANSPORT=tcp-blocking, the one whose calls ENTRIES names.
ENTRIES = ["_ch_connect", "_ch_read", "_ch_write", "_ch_close"]
CA_ENTRIES = ["_ch_pubkey_from_pem_tcp_blocking"]
# A ROLE=server build exports ch_srv_accept where a client exports
# ch_connect, and shares the other three.
SERVER_ENTRIES = ["_ch_srv_accept", "_ch_read", "_ch_write", "_ch_close"]

# STACK_MAKE: the make variables that name the build to walk, as a make
# command line takes them (e.g. TRUST=raw-ecdsa); empty walks the default
# build. The script compiles the sources make packages for that build,
# with the defines make packages them with (print-lib-lists), and no
# other root source, so the walk reads the functions that build's object
# holds. When it compiled every root source, the report listed
# ch_pubkey_from_pem for every build, where only a ca build exports it.
# RAND=extern comes first, so STACK_MAKE can replace it: cfg.h refuses a
# build that declares no entropy pattern, and the walk links no
# generator, so it measures the extern shape.
# STACK_CFLAGS: compile flags beyond the build's defines, such as
# -DCH_NATIVE_AES, the statement about the hardware that a SUITE=aesgcm
# build needs and the Makefile never writes.
# STACK_PRUNE: comma-separated functions removed from the graph, for
# paths a mode provably never enters, named as the report prints them.
# PSK mode never calls hsa_server_auth (the psk_selected check in
# handshake.c's run()), so pruning it measures the PSK-mode peak from the
# same objects.
# -fstack-usage reports how much each prologue subtracts from the stack
# pointer. An x86-64 function that calls nothing may also use up to 128
# bytes below the stack pointer without subtracting them (the red zone),
# and its figure then leaves those bytes out. -mno-red-zone makes the
# prologue subtract them, so each figure counts every byte its function
# uses. clang uses no red zone on arm64, and the flag leaves every arm64
# object byte for byte the same.
CFLAGS = ["-std=c11", "-O2", "-fstack-usage", "-mno-red-zone"]
# The tools that read the objects. LLVM's llvm-nm and llvm-objdump read a
# Mach-O object on any host, which is how test/stack_walk.py runs the walk
# on Linux.
NM = os.environ.get("STACK_NM") or "nm"
OBJDUMP = os.environ.get("STACK_OBJDUMP") or "objdump"


class Arch(NamedTuple):
    relocation: str  # the type of the relocation that names a callee
    calls: frozenset[str]
    jumps: frozenset[str]
    return_address: int  # bytes a call pushes that no frame's figure counts


# The architectures this reads, by the file format objdump names. objdump
# prints a call or jump to another function with a placeholder target and
# puts the relocation that names the callee under it. The placeholder is
# the branch's own address on arm64, so a branch at a function's first
# instruction reads as a branch to that function itself. On x86-64 it is
# the next instruction's address, so a branch that ends where the next
# function starts reads as a branch to that function. So a relocation,
# where there is one, names the callee. bl leaves the return address in
# x30, and the callee saves x30 in its own frame; an x86-64 call pushes
# the return address between the two frames, where neither figure counts
# it. A jump is a tail call and pushes nothing. The caller holds no frame
# by then, but the walk adds the caller's frame to the callee's depth
# anyway, which can only overstate a peak.
ARCHES = {
    "mach-o arm64": Arch("ARM64_RELOC_BRANCH26", frozenset({"bl"}),
                         frozenset({"b"}), 0),
    "mach-o 64-bit x86-64": Arch("X86_64_RELOC_BRANCH", frozenset({"call", "callq"}),
                                 frozenset({"jmp", "jmpq"}), 8),
}
# An instruction line of objdump -d -r: address, encoding, mnemonic and
# operands. objdump prints each relocation on a line of its own under the
# instruction it applies to, as an address, a type and a symbol.
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s[0-9a-f ]+\t(\S+)\s*(.*)$")


def library() -> tuple[list[str], list[str]]:
    """The sources and the defines of the build STACK_MAKE names, as make
    prints them for the object it packages."""
    command = ["make", "-s", "--no-print-directory", "-C", str(ROOT), "print-lib-lists",
               "RAND=extern", *shlex.split(os.environ.get("STACK_MAKE", ""))]
    # The child make gets no MAKEFLAGS, MFLAGS or MAKELEVEL, so it runs as
    # a make started from a shell. A make that runs this script, as make
    # lint-stack-walk does, names its jobserver in MAKEFLAGS, and GNU make
    # warns when it cannot use it. make's own error, such as a TRUST value
    # it refuses, goes to stderr.
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    made = subprocess.run(command, stdout=subprocess.PIPE, text=True, env=env)
    lines = made.stdout.splitlines()
    if made.returncode != 0 or len(lines) != 2 or not lines[0].split():
        sys.exit(f"stack.py: {shlex.join(command)} printed no source list")
    return lines[0].split(), lines[1].split()


def build(tmp: Path, srcs: list[str], flags: list[str]) -> None:
    for src in srcs:
        subprocess.run(["cc", *CFLAGS, "-I", str(ROOT), "-c", str(ROOT / src), *flags],
                       cwd=tmp, check=True, capture_output=True)


def functions(obj: Path) -> list[tuple[int, str, str]]:
    """Each function obj defines, in address order, as its start, its
    symbol and its key in the walk. A global function's key is its symbol.
    A static function's key is obj.o:symbol, because two objects can each
    define a static function under one symbol, and a call names the one in
    its own object."""
    return [(int(addr, 16), symbol, f"{obj.name}:{symbol}" if kind == "t" else symbol)
            for addr, kind, symbol in re.findall(r"^([0-9a-f]+) ([tT]) (_[A-Za-z0-9_]+)$",
                                                 run(NM, "-n", str(obj)), re.M)]


def frames(tmp: Path) -> dict[str, int]:
    """Each function's frame by its key, from the .su file -fstack-usage
    writes beside each object."""
    out = {}
    for su in tmp.glob("*.su"):
        keys = {symbol: key for _, symbol, key in functions(su.with_suffix(".o"))}
        for line in su.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].isdigit():
                out[keys["_" + parts[0].split(":")[-1]]] = int(parts[1])
    return out


def run(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def architecture(obj: Path, listing: str) -> Arch:
    form = re.search(r"file format (.+)$", listing, re.M)
    name = form.group(1).strip() if form else "no file format"
    if name not in ARCHES:
        sys.exit(f"stack.py: objdump reads {obj.name} as {name}; the walk reads "
                 f"{' and '.join(ARCHES)} objects")
    return ARCHES[name]


def instructions(listing: str, arch: Arch) -> list[tuple[int, str, str, str | None]]:
    """Each instruction's address, mnemonic and operands, and the symbol
    the relocation under it names as a callee, or None."""
    callee_line = re.compile(r"^\s+[0-9a-f]+:\s+" + re.escape(arch.relocation) + r"\s+(\S+)$")
    out = []
    for line in listing.splitlines():
        m = callee_line.match(line)
        if m and out:
            out[-1] = (*out[-1][:3], m.group(1))
            continue
        m = INSTRUCTION.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(2), m.group(3), None))
    return out


def owner(starts: list[tuple[int, str]], addr: int) -> str | None:
    """The function that holds addr: the last one to start at or before it."""
    fn = None
    for start, name in starts:
        if start <= addr:
            fn = name
    return fn


def object_edges(obj: Path, edges: dict[str, dict[str, int]]) -> Arch:
    """Adds each call and tail call in obj to edges, as the callee's key
    and the bytes the call pushes, and returns obj's architecture."""
    listing = run(OBJDUMP, "-d", "-r", str(obj))
    arch = architecture(obj, listing)
    # objdump labels the start of a section ltmp0 rather than the function
    # there, so each function's start comes from nm.
    defined = functions(obj)
    starts = [(addr, key) for addr, _, key in defined]
    # A relocation names a symbol: a static function when obj defines one
    # under it, and otherwise a global function.
    keys = {symbol: key for _, symbol, key in defined}
    for addr, mnemonic, operands, callee in instructions(listing, arch):
        fn = owner(starts, addr)
        callees = edges.setdefault(fn, {})
        # A call or jump with no relocation names its own target: the
        # function that holds the address objdump prints.
        if callee is None and mnemonic in arch.calls | arch.jumps:
            target = re.match(r"0x([0-9a-f]+)", operands)
            callee = owner(starts, int(target.group(1), 16)) if target else None
        elif callee is not None:
            callee = keys.get(callee, callee)
        if callee is not None and callee != fn:
            pushed = arch.return_address if mnemonic in arch.calls else 0
            callees[callee] = max(callees.get(callee, 0), pushed)
    return arch


def callgraph(tmp: Path) -> tuple[dict[str, dict[str, int]], int]:
    """Each function's callees, each with the bytes its call pushes, and
    the bytes a call into an entry point pushes."""
    edges: dict[str, dict[str, int]] = {}
    archs = {object_edges(obj, edges) for obj in sorted(tmp.glob("*.o"))}
    if len(archs) != 1:
        sys.exit(f"stack.py: the objects hold {len(archs)} architectures, not one")
    return edges, archs.pop().return_address


def deepest(fn: str, frames: dict, edges: dict, seen: tuple) -> tuple[int, list[str]]:
    if fn in seen:  # cycle guard; none expected
        return 0, []
    best, path = 0, []
    for callee, pushed in sorted(edges.get(fn, {}).items()):
        if callee in frames:
            d, p = deepest(callee, frames, edges, seen + (fn,))
            if pushed + d > best:
                best, path = pushed + d, p
    return frames.get(fn, 0) + best, [fn] + path


def shown(key: str) -> str:
    """A function as the report prints it: a global one by its C name, and
    a static one as obj.o:name."""
    obj, _, symbol = key.rpartition(":")
    return f"{obj}:{symbol[1:]}" if obj else symbol[1:]


def prune(frames: dict, edges: dict, names: list[str]) -> None:
    """Removes each function names lists, as the report prints it, from
    frames and edges. A name that matches no function stops the script:
    the graph would stay whole, and the report would give the unpruned
    peak as the pruned one."""
    keys = {shown(key): key for key in frames}
    unmatched = [name for name in names if name not in keys]
    if unmatched:
        sys.exit(f"stack.py: STACK_PRUNE names no function called {', '.join(unmatched)}")
    for name in names:
        edges.pop(keys[name], None)
        del frames[keys[name]]
        for callees in edges.values():
            callees.pop(keys[name], None)


def main() -> int:
    srcs, defines = library()
    entries = ENTRIES
    if "-DCH_ROLE_SERVER" in defines and "-DCH_ROLE_BOTH" not in defines:
        entries = SERVER_ENTRIES
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        build(tmp, srcs, defines + os.environ.get("STACK_CFLAGS", "").split())
        fr = frames(tmp)
        cg, pushed = callgraph(tmp)
        prune(fr, cg, [f for f in os.environ.get("STACK_PRUNE", "").split(",") if f])
        missing = [e for e in entries if e not in fr]
        if missing:
            # A frame of 0 for a real entry point means the symbol was
            # not measured, and deepest() would report it as free.
            print(f"stack.py: no frame for {', '.join(missing)}", file=sys.stderr)
            return 1
        # The call into an entry point pushes a return address too, so an
        # entry's figure is what a call to it takes from its caller's stack.
        for entry in entries + [e for e in CA_ENTRIES if e in fr]:
            depth, path = deepest(entry, fr, cg, ())
            chain = " > ".join(shown(p) for p in path)
            print(f"{shown(entry):12} {pushed + depth:5} B  via {chain}")
        print("(caller hooks — send/recv/on_ticket/ch_rand_bytes — run on the "
              "caller's own stack budget)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
