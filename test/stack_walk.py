#!/usr/bin/env python3
"""Checks that bench/stack.py follows a call and a tail call.

Run from the repository root: python3 test/stack_walk.py bench/stack.py

bench/stack.py reads the call graph from the relocations objdump prints
under each call and jump, and adds the frames on the deepest path. This
compiles a three-function fixture for arm64 and for x86-64 Mach-O, reads
the object with the script's own functions, and requires the walk from
entry() to reach deep() through first(), whose first instruction is its
tail call to deep(). The walk once read the target objdump prints on
that branch line, a placeholder that names first() itself, and dropped
the edge. Under CHACHA=vector that took chacha20_xor's jump to
chacha20_vector_xor out of the call graph.

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
# setup would come first.
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

# The target, its flags beyond the script's, and the bytes a call pushes
# that no frame's figure counts.
TARGETS = [
    ("arm64-apple-macos", [], 0),
    ("x86_64-apple-macos", ["-fomit-frame-pointer"], 8),
]


def check(stack, clang: str, triple: str, flags: list[str], pushed: int) -> bool:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "fixture.c").write_text(FIXTURE)
        subprocess.run([clang, f"--target={triple}", *stack.CFLAGS, *flags,
                        "-c", "fixture.c"], cwd=tmp, check=True)
        frames = stack.frames(tmp)
        edges, entry_pushed = stack.callgraph(tmp)
        depth, path = stack.deepest("_entry", frames, edges, ())
    want = frames["_entry"] + pushed + frames["_first"] + frames["_deep"]
    got = f"{depth} B via {' > '.join(p.lstrip('_') for p in path)}"
    if path != ["_entry", "_first", "_deep"] or depth != want or entry_pushed != pushed:
        print(f"lint-stack-walk: {triple}: the walk from entry reads {got}, and a call "
              f"pushes {entry_pushed} B; want {want} B via entry > first > deep, "
              f"and {pushed} B")
        return False
    print(f"lint-stack-walk: {triple}: {got}")
    return True


def main() -> int:
    spec = importlib.util.spec_from_file_location("stack", sys.argv[1])
    stack = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stack)
    clang = os.environ.get("CLANG") or "clang"
    results = [check(stack, clang, *target) for target in TARGETS]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
