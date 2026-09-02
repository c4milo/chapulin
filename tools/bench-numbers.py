# The README publishes speed, memory and flash figures that only bench/ can
# know. Nothing tied the prose to the CSVs, so the flash figure sat at 26.4
# kB while the real number was 27.3: bench/device-ram.sh had quietly dropped
# four modules and no one could tell. The Memory table drifted the same way
# (three stale stack rows, https://github.com/c4milo/chapulin/issues/90).
# This renders the numbers the CSVs imply and fails when the README
# disagrees.
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


def read_csv(path, key_col=0, val_col=1):
    rows = {}
    with open(path) as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#") or row[0] in ("op", "module", "quantity"):
                continue
            try:
                rows[row[key_col]] = int(row[val_col])
            except (ValueError, IndexError):
                continue
    return rows


def table_row(readme, label, cell_count):
    """The cells of the table row carrying this label, whatever its spacing."""
    pattern = r"\|\s*%s\s*\|" % re.escape(label) + r"\s*([^|]+?)\s*\|" * cell_count
    m = re.search(pattern, readme)
    return None if m is None else m.groups()


def check_speed(readme):
    """Each speed row, rendered from the mips32r2 and Cortex-M3 counts."""
    rc = 0
    insns = read_csv("bench/results-insn.csv")
    m3 = read_csv("bench/results-insn-m3.csv")
    for op, label in OPS.items():
        if op not in insns:
            print("lint-bench-numbers: %s missing from bench/results-insn.csv" % op)
            rc = 1
            continue
        if op not in m3:
            print("lint-bench-numbers: %s missing from bench/results-insn-m3.csv" % op)
            rc = 1
            continue
        want = (render_insns(insns[op]), render_ms(insns[op]), render_insns(m3[op]))
        got = table_row(readme, label, 3)
        if got is None:
            print("lint-bench-numbers: README has no speed row for %r" % label)
            rc = 1
        elif got != want:
            print("lint-bench-numbers: %r says %s / %s / %s; the CSVs render as %s / %s / %s"
                  % ((label,) + got + want))
            rc = 1
    return rc


def check_memory(readme):
    """Each Memory table row, and the prose that repeats a row's figure."""
    sram = read_csv("bench/results-sram.csv")
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
    flash = read_csv("bench/results-device.csv", val_col=3)
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
    rc |= check_memory(readme)
    rc |= check_flash(readme)
    if rc == 0:
        print("lint-bench-numbers: the README's speed, memory and flash figures match bench/")
    return rc


if __name__ == "__main__":
    sys.exit(main())
