#!/usr/bin/env python3
"""Reports how much the Lean spec actually checks.

Run from the repository root: python3 test/spec_coverage.py

Lean 4 ships no line-coverage tool, so this measures the two things
that can be measured and that matter:

1. Op coverage. Every operation the spec exposes, and whether the
   differential driver sends it. An op nothing drives is spec code no
   test exercises: it can drift from the C without anything noticing.

2. C coverage from the differential alone. The share of each shipping
   source file that the differential reaches, measured with gcov over
   a build that runs only test/diff_test.c. This answers the question the
   Lean spec exists to answer — how much of the code that ships is
   checked against an independent model — and it is the number that
   shows which modules the spec does not model at all.

Writes bin/spec-coverage.md and prints a summary.
"""

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "bin" / "speccov"
REPORT = ROOT / "bin" / "spec-coverage.md"

# The library sources the differential could reach. Kept explicit so a
# new module shows up as a missing row rather than vanishing.
SRCS = """ct.c sha256.c sha3.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c
rsa.c rsa_mont.c x509.c x509_der.c buf.c record.c keysched.c io.c hsmsg.c
hsparse.c hspump.c session.c handshake.c tls.c""".split()


def spec_ops():
    """Op names the spec's dispatch accepts."""
    text = (ROOT / "spec" / "Main.lean").read_text()
    body = text[text.index("def dispatch"):]
    return sorted(set(re.findall(r'^\s*\|\s*\["([a-z0-9_]+)"', body, re.M)))


# Every driver that talks to the spec, not only test/diff_test.c: drbg_test
# and hsseq_test each own an op and speak the same protocol.
DRIVERS = ["diff_test.c", "diff_driver.h", "diff_p256.h", "diff_rsa.h", "diff_sha3.h",
           "diff_x509.h", "diff_x509_bounds.h", "diff_x509_chain.h", "drbg_test.c",
           "hsseq_test.c", "hsseq_server.h"]


def driven_ops():
    """Op names any driver sends to the spec."""
    found = set()
    for name in DRIVERS:
        path = ROOT / "test" / name
        if not path.exists():
            continue
        text = path.read_text()
        # A command is always the format string of an snprintf into
        # cmd, or a literal handed to expect. Matching those two shapes
        # keeps ordinary strings that happen to start with an op name
        # out of the count.
        found |= set(re.findall(r'snprintf\(\s*cmd[^"]*"([a-z0-9_]+)', text))
        found |= set(re.findall(r'expect\(\s*"([a-z0-9_]+)"', text))
    return found


def build_and_run():
    """Builds a coverage-instrumented differential and runs it once."""
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)
    flags = ["--coverage", "-O0", "-g", "-std=c11", "-D_DEFAULT_SOURCE",
             "-DCH_TRUST_CA", f"-I{ROOT}"]
    objs = []
    for src in SRCS:
        obj = OUT_DIR / (src[:-2] + ".o")
        subprocess.run(["gcc", *flags, "-c", str(ROOT / src), "-o", str(obj)],
                       check=True, cwd=ROOT)
        objs.append(str(obj))
    binary = OUT_DIR / "diff"
    subprocess.run(["gcc", *flags, str(ROOT / "test" / "diff_test.c"), *objs,
                    "-o", str(binary)], check=True, cwd=ROOT)
    spec_bin = ROOT / "spec" / ".lake" / "build" / "bin" / "diffspec"
    if not spec_bin.exists():
        sys.exit("spec binary missing: run `make -C spec` or `lake build` first")
    run = subprocess.run([str(binary), str(spec_bin)], cwd=OUT_DIR,
                         capture_output=True, text=True)
    if run.returncode != 0:
        sys.stdout.write(run.stdout)
        sys.stderr.write(run.stderr)
        sys.exit("the differential failed; fix that before measuring it")
    return run.stdout.strip().splitlines()[-1]


def c_coverage():
    """Per-file line coverage from the instrumented run."""
    rows = {}
    for src in SRCS:
        gcda = OUT_DIR / (src[:-2] + ".gcda")
        if not gcda.exists():
            rows[src] = None
            continue
        out = subprocess.run(["gcov", "-n", gcda.name], cwd=OUT_DIR,
                             capture_output=True, text=True).stdout
        # gcov prints the file it is reporting, then its percentage.
        block = re.search(r"File '(?:.*/)?%s'\n *Lines executed:([0-9.]+)%% of (\d+)"
                          % re.escape(src), out)
        rows[src] = (float(block.group(1)), int(block.group(2))) if block else None
    return rows


def main():
    ops, driven = spec_ops(), driven_ops()
    undriven = [op for op in ops if op not in driven]

    summary = build_and_run()
    cov = c_coverage()

    lines = ["## What the Lean spec checks", "",
             "Lean 4 has no line-coverage tool, so this reports op coverage",
             "and the share of the C the differential reaches on its own.", "",
             "### Spec ops", "",
             "| op | driven by the differential |", "| --- | --- |"]
    for op in ops:
        lines.append(f"| `{op}` | {'yes' if op in driven else '**no**'} |")
    lines += ["", f"{len(ops) - len(undriven)} of {len(ops)} ops driven.", ""]
    if undriven:
        lines.append("Undriven ops are spec code no test exercises: "
                     + ", ".join(f"`{op}`" for op in undriven) + ".")
        lines.append("")

    lines += ["### C reached by the differential alone", "",
              "The rest of the gate covers these files too; this column is",
              "only what the spec checks. A zero means the spec does not",
              "model that module at all.", "",
              "| file | lines | reached by the spec |", "| --- | --- | --- |"]
    modelled, unmodelled = [], []
    for src in SRCS:
        entry = cov.get(src)
        if entry is None:
            lines.append(f"| `{src}` | — | not built |")
            continue
        pct, total = entry
        mark = "**0%**" if pct == 0 else f"{pct:.1f}%"
        lines.append(f"| `{src}` | {total} | {mark} |")
        (unmodelled if pct == 0 else modelled).append(src)
    lines += ["", summary, ""]
    if unmodelled:
        lines.append("Not modelled by the spec: "
                     + ", ".join(f"`{s}`" for s in unmodelled) + ".")
        lines.append("")

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n")
    print(f"spec-coverage: {len(ops) - len(undriven)}/{len(ops)} ops driven, "
          f"{len(unmodelled)} module(s) unmodelled -> {REPORT.relative_to(ROOT)}")
    if undriven:
        print("spec-coverage: undriven ops: " + ", ".join(undriven))


if __name__ == "__main__":
    main()
