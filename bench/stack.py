#!/usr/bin/env python3
"""Worst-case stack per entry point, computed from the code, not by hand.

Builds every library object with -fstack-usage, extracts the real call
graph from the object code (arm64 `bl`/`b` sites via otool), and walks the
max-weight path under each public entry point. Indirect calls (the
caller's send/recv/on_ticket hooks and ms_rand_bytes) execute on the
caller's budget and are reported as such, not silently omitted.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRIES = ["_ms_connect", "_ms_read", "_ms_write", "_ms_close"]
SRCS = sorted(ROOT.glob("*.c"))


def build(tmp: Path) -> None:
    for src in SRCS:
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-I", str(ROOT), "-fstack-usage", "-c", str(src)],
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


def callgraph(tmp: Path) -> dict[str, set[str]]:
    # Function boundaries come from nm (objdump labels the section start
    # ltmp0); call targets come from bl annotations when resolved locally
    # and from the ARM64_RELOC_BRANCH26 relocation lines objdump -d -r
    # interleaves for cross-object calls.
    edges: dict[str, set[str]] = {}
    for obj in tmp.glob("*.o"):
        syms = []
        nm = subprocess.run(["nm", "-n", str(obj)],
                            check=True, capture_output=True, text=True).stdout
        for line in nm.splitlines():
            m = re.match(r"^([0-9a-f]+) [tT] (_[A-Za-z0-9_]+)$", line)
            if m:
                syms.append((int(m.group(1), 16), m.group(2)))
        text = subprocess.run(["objdump", "-d", "-r", str(obj)],
                              check=True, capture_output=True, text=True).stdout
        fn = None
        pending = False
        for line in text.splitlines():
            m = re.search(r"ARM64_RELOC_BRANCH26\s+(_[A-Za-z0-9_]+)$", line)
            if m:
                if pending and fn is not None and m.group(1) != fn:
                    edges[fn].add(m.group(1))
                pending = False
                continue
            # Instruction lines carry an 8-hex opcode; relocation lines do
            # not, which is how the two are told apart.
            m = re.match(r"^\s*([0-9a-f]+): [0-9a-f]{8}\s", line)
            if m:
                addr = int(m.group(1), 16)
                for start, name in syms:
                    if start <= addr:
                        fn = name
                edges.setdefault(fn, set())
                pending = False
                # bl is a call; a plain b to another function is a tail
                # call, counted like a call (over-approximates by the
                # caller's frame, which is the safe direction). A resolved
                # target is an offset-free <_symbol> annotation; anything
                # else (address-only, or <fn+0x..> pointing back into the
                # caller) means the real target arrives as a relocation.
                if "\tbl\t" in line or "\tb\t" in line:
                    t = re.search(r"<(_[A-Za-z0-9_]+)>$", line)
                    if t and t.group(1) != fn:
                        edges[fn].add(t.group(1))
                    elif not t:
                        pending = True
    return edges


def deepest(fn: str, frames: dict, edges: dict, seen: tuple) -> tuple[int, list[str]]:
    if fn in seen:  # cycle guard; none expected
        return 0, []
    best, path = 0, []
    for callee in sorted(edges.get(fn, ())):
        if callee in frames:
            d, p = deepest(callee, frames, edges, seen + (fn,))
            if d > best:
                best, path = d, p
    return frames.get(fn, 0) + best, [fn] + path


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        build(tmp)
        fr = frames(tmp)
        cg = callgraph(tmp)
        for entry in ENTRIES:
            depth, path = deepest(entry, fr, cg, ())
            chain = " > ".join(p.lstrip("_") for p in path)
            print(f"{entry.lstrip('_'):12} {depth:5} B  via {chain}")
        print("(caller hooks — send/recv/on_ticket/ms_rand_bytes — run on the "
              "caller's own stack budget)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
