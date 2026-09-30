#!/usr/bin/env python3
"""Worst-case stack per entry point, computed from the code, not by hand.

Builds every library object with -fstack-usage, extracts the real call
graph from the object code (the branch relocations `objdump -d -r` prints
under every call and tail call in an arm64 or x86-64 Mach-O object), and
walks the max-weight path under each public entry point. Indirect calls
(the caller's send/recv/on_ticket hooks and ch_rand_bytes) execute on the
caller's budget and are reported as such, not silently omitted.
"""
import os
import re
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
# ch_connect, and shares the other three. STACK_CFLAGS names the role the
# way it names a trust mode.
SERVER_ENTRIES = ["_ch_srv_accept", "_ch_read", "_ch_write", "_ch_close"]
# Every root source, minus the ones a build's defines exclude. webpki.c,
# webpki_ticket.c, webpki_pin.c and webpki_cfg.c read the ch_cfg fields that exist
# only under CH_TRUST_WEBPKI, so they compile in that build alone; the
# other webpki_*.c files read none of them and compile everywhere.
SRCS = sorted(ROOT.glob("*.c"))

# STACK_CFLAGS: extra compile flags (e.g. -DCH_PIN_ECDSA to walk that
# build). STACK_PRUNE: comma-separated functions removed from the graph,
# for paths a mode provably never enters — PSK mode never reaches
# server_auth (the cfg.psk check in run()), so pruning it measures the
# PSK-mode peak from the same objects.
# cfg.h refuses a build that declares no entropy pattern. This walks the
# call graph, never links a generator, so it measures the extern shape.
EXTRA_CFLAGS = ["-DCH_RAND_EXTERN"] + os.environ.get("STACK_CFLAGS", "").split()
if "-DCH_TRUST_WEBPKI" not in EXTRA_CFLAGS:
    SRCS = [s for s in SRCS if s.name not in ("webpki.c", "webpki_ticket.c", "webpki_pin.c", "webpki_cfg.c")]
if "-DCH_ROLE_SERVER" in EXTRA_CFLAGS and "-DCH_ROLE_BOTH" not in EXTRA_CFLAGS:
    ENTRIES = SERVER_ENTRIES
# A SUITE=aesgcm build takes AES=hw or AES=extern, and quic_aes_soft.c
# refuses the suite, so the software AES is not one of that build's
# sources.
if "-DCH_SUITE_AES_GCM" in EXTRA_CFLAGS:
    SRCS = [s for s in SRCS if s.name != "quic_aes_soft.c"]
PRUNE = {"_" + f for f in os.environ.get("STACK_PRUNE", "").split(",") if f}
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


def build(tmp: Path) -> None:
    for src in SRCS:
        subprocess.run(["cc", *CFLAGS, "-I", str(ROOT), "-c", str(src)] + EXTRA_CFLAGS,
                       cwd=tmp, check=True, capture_output=True)


def frames(tmp: Path) -> dict[str, int]:
    out = {}
    for su in tmp.glob("*.su"):
        for line in su.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].isdigit():
                name = parts[0].split(":")[-1]
                out["_" + name] = max(out.get("_" + name, 0), int(parts[1]))
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
    """Adds each call and tail call in obj to edges, as the callee and the
    bytes the call pushes, and returns obj's architecture."""
    listing = run(OBJDUMP, "-d", "-r", str(obj))
    arch = architecture(obj, listing)
    # objdump labels the start of a section ltmp0 rather than the function
    # there, so each function's start comes from nm.
    starts = [(int(addr, 16), name) for addr, name in
              re.findall(r"^([0-9a-f]+) [tT] (_[A-Za-z0-9_]+)$",
                         run(NM, "-n", str(obj)), re.M)]
    for addr, mnemonic, operands, callee in instructions(listing, arch):
        fn = owner(starts, addr)
        callees = edges.setdefault(fn, {})
        # A call or jump with no relocation names its own target: the
        # function that holds the address objdump prints.
        if callee is None and mnemonic in arch.calls | arch.jumps:
            target = re.match(r"0x([0-9a-f]+)", operands)
            callee = owner(starts, int(target.group(1), 16)) if target else None
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


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        build(tmp)
        fr = frames(tmp)
        cg, pushed = callgraph(tmp)
        for fn in PRUNE:
            cg.pop(fn, None)
            fr.pop(fn, None)
            for callees in cg.values():
                callees.pop(fn, None)
        entries = list(ENTRIES)
        for entry in CA_ENTRIES:
            if entry in fr:
                entries.append(entry)
        missing = [e for e in ENTRIES if e not in fr]
        if missing:
            # A frame of 0 for a real entry point means the symbol was
            # not measured, and deepest() would report it as free.
            print(f"stack.py: no frame for {', '.join(missing)}", file=sys.stderr)
            return 1
        # The call into an entry point pushes a return address too, so an
        # entry's figure is what a call to it takes from its caller's stack.
        for entry in entries:
            depth, path = deepest(entry, fr, cg, ())
            chain = " > ".join(p.lstrip("_") for p in path)
            print(f"{entry.lstrip('_'):12} {pushed + depth:5} B  via {chain}")
        print("(caller hooks — send/recv/on_ticket/ch_rand_bytes — run on the "
              "caller's own stack budget)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
