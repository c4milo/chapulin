#!/usr/bin/env python3
"""Reports how much the Lean spec actually checks.

Run from the repository root: python3 test/spec_coverage.py

Lean 4 ships no line-coverage tool, so this measures the two things
that can be measured and that matter:

1. Op coverage. Every operation the spec exposes, and whether a
   driver sends it. An op nothing drives is spec code no test
   exercises: it can drift from the C without anything noticing.

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
#
# The quic sources, and aes.c and gcm.c beside them, are on the list for
# that reason alone. This run compiles every file under -DCH_TRUST_CA and
# no -DCH_TRANSPORT_QUIC_NONBLOCKING, because the TLS sources beside them
# do not compile under that define, and no -DCH_SUITE_AES_GCM, so each of
# those files compiles to an empty translation unit and its row reads
# "not built". bin/diff_quic compares aes.c, gcm.c, quic_keys.c and
# quic_retry.c against the spec from a main of its own,
# test/diff_quic_test.c, which this run does not build. The rows move to
# a percentage in the commit that builds that main here, and until then
# each is a row a reader sees rather than a name that is absent.
SRCS = """ct.c sha256.c sha512.c sha512_compress.c sha3.c mlkem.c mlkem_poly.c hkdf.c chacha20.c poly1305.c aead.c x25519.c p256.c
p384.c p384_field.c rsa.c rsa_mont.c rsa_pkcs1.c pem.c x509.c x509_der.c x509_ca.c webpki_time.c webpki_name.c webpki_spki.c webpki_sigalg.c webpki_ext.c webpki_cert.c webpki.c buf.c record.c keysched.c io.c handshake_message.c
handshake_parser.c handshake_parser_ee.c handshake_record.c session.c handshake_auth.c handshake_flight.c handshake.c handshake_post.c tls.c tls_write.c
quic.c quic_config.c quic_initial.c quic_keys.c quic_packet.c quic_retry.c quic_step.c aes.c gcm.c""".split()

# Sources this leg names but cannot compile. webpki.c reads
# ch_cfg.now_seconds, which cfg.h declares under -DCH_TRUST_WEBPKI and
# refuses beside -DCH_TRUST_CA, so the leg that measures it is
# `make diff-webpki` and bin/diff does not compile it either. Naming it
# here keeps its row in the table, reading "not built", rather than
# dropping the file from the report.
TRUST_WEBPKI_ONLY = ["webpki.c"]


def spec_ops():
    """Op names the spec's dispatch accepts."""
    text = (ROOT / "spec" / "lean" / "Main.lean").read_text()
    body = text[text.index("def dispatch"):]
    return sorted(set(re.findall(r'^\s*\|\s*\["([a-z0-9_]+)"', body, re.M)))


# A quoted include, the form every test file uses for a file beside it.
INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)


def add_with_includes(path, found):
    """Adds path to found, then every file beside it that it includes."""
    if path in found or not path.exists():
        return
    found.add(path)
    for name in INCLUDE.findall(path.read_text()):
        add_with_includes(path.parent / name, found)


def drivers():
    """Every file that can send ops to the spec, read from the includes.

    test/diff_driver.h holds the pipe to the spec process, so a test main
    that includes it is a driver, and so is every test header such a
    main includes, directly or through another header. Reading the
    includes counts a new driver from the commit that adds it, where a
    hand-kept list fell behind."""
    found = set()
    for main in (ROOT / "test").glob("*.c"):
        if "diff_driver.h" in INCLUDE.findall(main.read_text()):
            add_with_includes(main, found)
    return sorted(found)


def driven_ops():
    """Op names any driver sends to the spec."""
    found = set()
    for path in drivers():
        text = path.read_text()
        # A driver writes a command in one of five shapes, and matching
        # only these keeps an ordinary string that starts with an op
        # name out of the count:
        #   - the format string of an snprintf into cmd;
        #   - a literal handed to expect;
        #   - the op literal handed to hspd_request, which the handshake
        #     message drivers build every command through;
        #   - the op literal handed to diff_pin_command, which the two
        #     SPKI pin drivers build every command through;
        #   - a literal that a return statement hands back from a
        #     function whose result is the first argument of an snprintf
        #     into cmd whose format string opens with %s. test/diff_gcm.h
        #     names its four ops through diff_gcm_op this way.
        found |= set(re.findall(r'snprintf\(\s*cmd[^"]*"([a-z0-9_]+)', text))
        found |= set(re.findall(r'expect\(\s*"([a-z0-9_]+)"', text))
        found |= set(re.findall(r'hspd_request\(\s*cmd[^"]*"([a-z0-9_]+)"', text))
        found |= set(re.findall(r'diff_pin_command\(\s*cmd,\s*"([a-z0-9_]+)"', text))
        for helper in set(re.findall(r'snprintf\(\s*cmd[^"]*"%s[^"]*",\s*([a-z0-9_]+)\(', text)):
            body = re.search(r'\b%s\([^)]*\)\s*\{(.*?)^\}' % helper, text, re.S | re.M)
            for statement in re.findall(r'\breturn\b[^;]*;', body.group(1) if body else ""):
                found |= set(re.findall(r'"([a-z0-9_]+)"', statement))
    return found


def build_and_run():
    """Builds a coverage-instrumented differential and runs it once."""
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)
    # cfg.h refuses a build that declares no entropy pattern, and this
    # driver never links a generator, so it builds the extern pattern.
    # -DCH_RSA_MODULUS_MAX=512, as the Makefile's bin/diff line passes
    # through RSA_WIDE_DEF: the RSA differential samples a 4096-bit
    # modulus, which rsa.h admits only at that bound. The bound is named
    # rather than -DCH_TRUST_WEBPKI, which cfg.h refuses beside
    # -DCH_TRUST_CA. -DCH_HASH_SHA384, as bin/diff passes it, so the
    # SHA-384 rows of test/diff_hash384.h run too.
    flags =["--coverage", "-O0", "-g", "-std=c11", "-D_DEFAULT_SOURCE",
             "-DCH_RAND_EXTERN", "-DCH_TRUST_CA", "-DCH_RSA_MODULUS_MAX=512", "-DCH_HASH_SHA384",
             f"-I{ROOT}"]
    objs = []
    for src in (s for s in SRCS if s not in TRUST_WEBPKI_ONLY):
        obj = OUT_DIR / (src[:-2] + ".o")
        subprocess.run(["gcc", *flags, "-c", str(ROOT / src), "-o", str(obj)],
                       check=True, cwd=ROOT)
        objs.append(str(obj))
    binary = OUT_DIR / "diff"
    subprocess.run(["gcc", *flags, str(ROOT / "test" / "diff_test.c"), *objs,
                    "-o", str(binary)], check=True, cwd=ROOT)
    spec_bin = ROOT / "spec" / "lean" / ".lake" / "build" / "bin" / "diffspec"
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
              "The rest of the test suite covers these files too; this column is",
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
    if TRUST_WEBPKI_ONLY:
        lines.append("Built by `make diff-webpki` rather than this leg, which "
                     "compiles under -DCH_TRUST_CA: "
                     + ", ".join(f"`{s}`" for s in TRUST_WEBPKI_ONLY) + ".")
        lines.append("")
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
