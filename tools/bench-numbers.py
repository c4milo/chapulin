# The README publishes speed and flash figures that only bench/ can know.
# Nothing tied the prose to the CSVs, so the flash figure sat at 26.4 kB
# while the real number was 27.3: bench/device-ram.sh had quietly dropped
# four modules and no one could tell. This renders the numbers the CSVs
# imply and fails when the README disagrees.
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
            if not row or row[0].startswith("#") or row[0] in ("op", "module"):
                continue
            try:
                rows[row[key_col]] = int(row[val_col])
            except (ValueError, IndexError):
                continue
    return rows


def main():
    readme = open("README.md").read()
    rc = 0

    insns = read_csv("bench/results-insn.csv")
    for op, label in OPS.items():
        if op not in insns:
            print("lint-bench-numbers: %s missing from bench/results-insn.csv" % op)
            rc = 1
            continue
        want_n, want_ms = render_insns(insns[op]), render_ms(insns[op])
        # the table row for this label, whatever its cell spacing
        pattern = r"\|\s*%s\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|" % re.escape(label)
        m = re.search(pattern, readme)
        if not m:
            print("lint-bench-numbers: README has no speed row for %r" % label)
            rc = 1
            continue
        got_n, got_ms = m.group(1), m.group(2)
        if got_n != want_n or got_ms != want_ms:
            print("lint-bench-numbers: %r says %s / %s, %d insns render as %s / %s"
                  % (label, got_n, got_ms, insns[op], want_n, want_ms))
            rc = 1

    # Flash: the totals row of the device model, as kB in the prose.
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

    if rc == 0:
        print("lint-bench-numbers: the README's speed and flash figures match bench/")
    return rc


if __name__ == "__main__":
    sys.exit(main())
