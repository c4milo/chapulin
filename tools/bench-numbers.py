# The README publishes speed, memory and flash figures that only bench/ can
# know. Nothing tied the prose to the CSVs, so the flash figure sat at 26.4
# kB while the real number was 27.3: bench/device-ram.sh had quietly dropped
# four modules and no one could tell. The Memory table drifted the same way
# (three stale stack rows, https://github.com/c4milo/chapulin/issues/90).
# This renders the numbers the CSVs imply and fails when the README
# disagrees.
#
# The decomposition sentence under the speed table went the same way once:
# its nine percentages, the milliseconds and the flash came from a scratch
# run with -DCH_NATIVE_WIDEMUL that no file recorded
# (https://github.com/c4milo/chapulin/issues/146). Each instruction CSV now
# carries that run as its native_insns column and the device model as its
# `total (CH_NATIVE_WIDEMUL)` row, and this renders the sentence from them,
# along with the two sentences that restate its mips32r2 figures.
#
# It compares rendered strings rather than parsing prose, so the rounding
# rule lives here and the README follows it.
import csv
import re
import sys

MHZ_HZ = 500_000  # 500 MHz at one instruction per cycle, in kilo-instructions

# CSV op -> the README table label that must carry its numbers.
OPS = {
    "aead_seal_1kib": "AEAD seal, per 1 KB record",
    "sha256_1kib": "SHA-256, per 1 KB",
    "x25519_scalarmult": "x25519 scalar multiply",
    "rsa_pss_verify_3072": "RSA-3072 PSS verify (default)",
    "p256_ecdsa_verify": "P-256 verify (`PIN=ecdsa`)",
    "handshake_crypto": "full pinned handshake crypto (default)",
    "mlkem_keygen": "ML-KEM-768 keygen (`KEX=pq`)",
    "mlkem_decaps": "ML-KEM-768 decapsulate (`KEX=pq`)",
    "handshake_crypto_pq": "full hybrid handshake crypto (`KEX=pq`)",
}

# The three instruction CSVs in the speed table's column order. Each carries
# an insns column over the multiply decomposition firmware ships and a
# native_insns column over the same driver built with -DCH_NATIVE_WIDEMUL.
# The first cell is how the decomposition sentence names the target.
TARGETS = [
    ("mips32r2", "bench/results-insn.csv"),
    ("the Cortex-M3", "bench/results-insn-m3.csv"),
    ("rv32imac", "bench/results-insn-rv32.csv"),
]

# The rows the decomposition sentence prices, in the order it states them,
# and the rows it says the decomposition leaves unchanged.
DECOMPOSED_OPS = ["aead_seal_1kib", "x25519_scalarmult", "handshake_crypto"]
UNCHANGED_OPS = ["sha256_1kib", "rsa_pss_verify_3072", "p256_ecdsa_verify"]

# The sentence the README's Verification section and docs/porting.md each
# carry, restating the mips32r2 handshake percentage and the flash.
RESTATED = re.compile(r"the pinned handshake's crypto costs (\d+%) more on mips32r2, "
                      r"and the decomposition is ([0-9.]+ kB) of flash")

# README Memory table row label -> the bench/results-sram.csv quantities its
# cells carry, one list per column. A cell that shows two figures, such as
# "5504 / 3696", lists both. A label that opens with ** is a bold row, and
# the table bolds its cells too.
MEMORY = [
    ("`ch_tls` session struct (includes 622 B TX staging)",
     [["session_struct_arm64"], ["session_struct_rv32"]]),
    ("receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`)",
     [["receive_buffer"], ["receive_buffer"]]),
    ("**total static working set**",
     [["static_working_set_arm64"], ["static_working_set_rv32"]]),
    ("`ch_tls` under `KEX=pq` (includes 1806 B TX staging)",
     [["session_struct_pq_arm64"], ["session_struct_pq_rv32"]]),
    ("**total static working set, `KEX=pq`** (2048 buffer)",
     [["static_working_set_pq_arm64"], ["static_working_set_pq_rv32"]]),
    ("peak stack, `ch_connect` (RSA-3072 verify)", [["stack_connect_rsa"]]),
    ("peak stack, `ch_connect` (`PIN=ecdsa`)", [["stack_connect_ecdsa"]]),
    ("peak stack, `ch_connect` (PSK)", [["stack_connect_psk"]]),
    ("peak stack, `ch_connect` (`TRUST=ca`, RSA / ECDSA)",
     [["stack_connect_ca_rsa", "stack_connect_ca_ecdsa"]]),
    ("peak stack, `ch_read` (worst case: KeyUpdate rekey)", [["stack_read"]]),
    ("peak stack, `ch_connect` (`KEX=pq`)", [["stack_connect_pq"]]),
    ("peak stack, `ch_write` / `ch_close`", [["stack_write", "stack_close"]]),
]


def render_insns(n):
    """Instruction count as the table writes it: thousands under a million."""
    if n < 1_000_000:
        return "%d k" % round(n / 1000)
    return "%.1f M" % (n / 1_000_000)


def render_ms(n):
    """Milliseconds at 500 MHz, 1 IPC: two decimals under a millisecond."""
    ms = n / MHZ_HZ
    return "%.2f" % ms if ms < 1 else "%d" % round(ms)


def render_percent_more(insns, native):
    """The decomposition's cost as the sentence states it: the shipped count
    over the native one, as a whole percent of the native count."""
    return "%d%%" % round(100 * (insns - native) / native)


def read_csv(path, column):
    """Each row's first cell mapped to its named column, as an integer. The
    first uncommented row is the header that names the columns; a cell
    that is not a number is skipped."""
    rows = {}
    index = None
    with open(path) as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            if index is None:
                if column not in row:
                    print("lint-bench-numbers: %s has no %s column" % (path, column))
                    return rows
                index = row.index(column)
                continue
            try:
                rows[row[0]] = int(row[index])
            except (ValueError, IndexError):
                continue
    return rows


def prose(text):
    """The text with each run of whitespace as one space, so a sentence
    matches however the source wraps it."""
    return re.sub(r"\s+", " ", text)


def table_row(readme, label, cell_count):
    """The cells of the table row carrying this label, whatever its spacing."""
    pattern = r"\|\s*%s\s*\|" % re.escape(label) + r"\s*([^|]+?)\s*\|" * cell_count
    m = re.search(pattern, readme)
    return None if m is None else m.groups()


def check_speed(readme):
    """Each speed row, rendered from the mips32r2, Cortex-M3 and rv32imac counts."""
    rc = 0
    columns = [(path, read_csv(path, "insns")) for _, path in TARGETS]
    for op, label in OPS.items():
        missing = [path for path, counts in columns if op not in counts]
        if missing:
            for path in missing:
                print("lint-bench-numbers: %s missing from %s" % (op, path))
            rc = 1
            continue
        mips, m3, rv32 = (counts[op] for _, counts in columns)
        want = (render_insns(mips), render_ms(mips), render_insns(m3), render_insns(rv32))
        got = table_row(readme, label, len(want))
        if got is None:
            print("lint-bench-numbers: README has no speed row for %r" % label)
            rc = 1
        elif got != want:
            print("lint-bench-numbers: %r says %s; the CSVs render as %s"
                  % (label, " / ".join(got), " / ".join(want)))
            rc = 1
    return rc


def check_decomposition(readme):
    """The decomposition sentence's clause for each target: what the three
    rows the decomposition sets cost over the native multiply, and that
    the rows it calls unchanged are."""
    rc = 0
    text = prose(readme)
    for target, path in TARGETS:
        insns = read_csv(path, "insns")
        native = read_csv(path, "native_insns")
        missing = [op for op in DECOMPOSED_OPS + UNCHANGED_OPS
                   if op not in insns or op not in native]
        if missing:
            print("lint-bench-numbers: %s lacks insns or native_insns for %s"
                  % (path, ", ".join(missing)))
            rc = 1
            continue
        want = tuple(render_percent_more(insns[op], native[op]) for op in DECOMPOSED_OPS)
        m = re.search(r"on %s, AEAD seal costs (\d+%%) more, x25519 (\d+%%) more, "
                      r"and the pinned handshake (\d+%%) more" % re.escape(target), text)
        if m is None:
            print("lint-bench-numbers: the decomposition sentence has no clause for %s" % target)
            rc = 1
        elif m.groups() != want:
            print("lint-bench-numbers: the decomposition sentence says %s costs %s more; "
                  "%s renders as %s" % (target, " / ".join(m.groups()), path, " / ".join(want)))
            rc = 1
        moved = [op for op in UNCHANGED_OPS if insns[op] != native[op]]
        if moved:
            print("lint-bench-numbers: the decomposition sentence calls SHA-256 and both "
                  "signature verifies unchanged, but %s moves %s" % (path, ", ".join(moved)))
            rc = 1
    return rc


def check_decomposition_mips(readme):
    """The mips32r2 clause's milliseconds and the flash the decomposition
    takes, then the two sentences that restate that clause."""
    rc = 0
    text = prose(readme)
    insns = read_csv("bench/results-insn.csv", "insns")
    native = read_csv("bench/results-insn.csv", "native_insns")
    flash = read_csv("bench/results-device.csv", "mips_flash_B")
    if "handshake_crypto" not in native or "total (CH_NATIVE_WIDEMUL)" not in flash:
        print("lint-bench-numbers: bench/results-insn.csv lacks native_insns for "
              "handshake_crypto, or bench/results-device.csv the total (CH_NATIVE_WIDEMUL) row")
        return 1
    want_ms = render_ms(insns["handshake_crypto"] - native["handshake_crypto"])
    m = re.search(r"the pinned handshake \d+% more, or (\d+) ms at 500 MHz", text)
    if m is None:
        print("lint-bench-numbers: the decomposition sentence does not state the mips32r2 "
              "handshake cost in milliseconds")
        rc = 1
    elif m.group(1) != want_ms:
        print("lint-bench-numbers: the decomposition sentence says the mips32r2 handshake "
              "costs %s ms more; bench/results-insn.csv renders as %s" % (m.group(1), want_ms))
        rc = 1
    want_kb = "%.1f kB" % ((flash["total"] - flash["total (CH_NATIVE_WIDEMUL)"]) / 1024)
    m = re.search(r"of which the multiply decomposition is ([0-9.]+ kB)", text)
    if m is None:
        print("lint-bench-numbers: README does not state the flash the decomposition takes")
        rc = 1
    elif m.group(1) != want_kb:
        print("lint-bench-numbers: README says the multiply decomposition is %s of flash, "
              "the device model says %s" % (m.group(1), want_kb))
        rc = 1
    want = (render_percent_more(insns["handshake_crypto"], native["handshake_crypto"]), want_kb)
    return rc | check_restated("README.md", text, want) \
        | check_restated("docs/porting.md", prose(open("docs/porting.md").read()), want)


def check_restated(name, text, want):
    """One file's restatement of the mips32r2 handshake percentage and the
    decomposition's flash, against the pair the CSVs render."""
    m = RESTATED.search(text)
    if m is None:
        print("lint-bench-numbers: %s does not restate the mips32r2 handshake percentage "
              "and the decomposition's flash" % name)
        return 1
    if m.groups() != want:
        print("lint-bench-numbers: %s restates the decomposition as %s more and %s; "
              "bench/ renders as %s more and %s" % (name, m.group(1), m.group(2), want[0], want[1]))
        return 1
    return 0


def check_memory(readme):
    """Each Memory table row, and the prose that repeats a row's figure."""
    sram = read_csv("bench/results-sram.csv", "bytes")
    needed = [q for _, columns in MEMORY for cells in columns for q in cells]
    missing = sorted(set(q for q in needed if q not in sram))
    if missing:
        print("lint-bench-numbers: bench/results-sram.csv lacks %s" % ", ".join(missing))
        return 1
    rc = 0
    for label, columns in MEMORY:
        cell = "**%s**" if label.startswith("**") else "%s"
        want = tuple(cell % " / ".join(str(sram[q]) for q in cells) for cells in columns)
        got = table_row(readme, label, len(columns))
        if got is None:
            print("lint-bench-numbers: README has no memory row for %r" % label)
            rc = 1
        elif got != want:
            print("lint-bench-numbers: %r says %s; bench/results-sram.csv renders as %s"
                  % (label, " | ".join(got), " | ".join(want)))
            rc = 1
    return rc | check_memory_prose(readme, sram)


def check_memory_prose(readme, sram):
    """The two Memory sentences that restate a table figure."""
    rc = 0
    # "needs N bytes less than the host figure in either build": one N for
    # both builds, so the two differences must agree before the prose can.
    less = sram["session_struct_arm64"] - sram["session_struct_rv32"]
    less_pq = sram["session_struct_pq_arm64"] - sram["session_struct_pq_rv32"]
    m = re.search(r"needs ([0-9]+) bytes less than the host figure in either build", readme)
    if less != less_pq:
        print("lint-bench-numbers: rv32 saves %d bytes in the default build but %d under "
              "KEX=pq; the README states one figure for both" % (less, less_pq))
        rc = 1
    elif not m:
        print("lint-bench-numbers: README does not state the rv32 saving")
        rc = 1
    elif m.group(1) != "%d" % less:
        print("lint-bench-numbers: README says rv32 saves %s bytes, the CSV says %d"
              % (m.group(1), less))
        rc = 1
    want = "{:,}".format(sram["stack_connect_pq"])
    m = re.search(r"The whole chain peaks at ([0-9,]+) bytes", readme)
    if not m:
        print("lint-bench-numbers: README does not state the KEX=pq stack peak in prose")
        rc = 1
    elif m.group(1) != want:
        print("lint-bench-numbers: README prose says the KEX=pq chain peaks at %s bytes, "
              "the CSV says %s" % (m.group(1), want))
        rc = 1
    return rc


def check_flash(readme):
    """The totals row of the device model, as kB in the prose."""
    rc = 0
    flash = read_csv("bench/results-device.csv", "mips_flash_B")
    if "total" not in flash:
        print("lint-bench-numbers: bench/results-device.csv has no total row")
        return 1
    want_kb = "%.1f kB" % (flash["total"] / 1024)
    m = re.search(r"Flash is ([0-9.]+ kB) for the default build", readme)
    if not m:
        print("lint-bench-numbers: README does not state the default flash figure")
        rc = 1
    elif m.group(1) != want_kb:
        print("lint-bench-numbers: README says flash is %s, the device model says %s"
              % (m.group(1), want_kb))
        rc = 1
    return rc


def main():
    readme = open("README.md").read()
    rc = 0
    rc |= check_speed(readme)
    rc |= check_decomposition(readme)
    rc |= check_decomposition_mips(readme)
    rc |= check_memory(readme)
    rc |= check_flash(readme)
    if rc == 0:
        print("lint-bench-numbers: the README's speed, decomposition, memory and flash "
              "figures match bench/")
    return rc


if __name__ == "__main__":
    sys.exit(main())
