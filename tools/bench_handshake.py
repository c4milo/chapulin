# docs/performance.md, "Where a server handshake's instructions go",
# renders two tables from the CSV bench/handshake-n2.sh writes,
# bench/results-handshake-n2.csv: the stages of the server's side of one
# connection, and the whole connection on the Neoverse-N2 itself.
# tools/bench-numbers.py calls check_handshake, so `make lint-bench-numbers`
# fails when a cell of either table disagrees with the CSV.
import csv

CSV = "bench/results-handshake-n2.csv"


def cell(server, cpu, tool, row, digits=2):
    """A table cell: the CSV row's instructions in millions, to digits places."""
    return (server, cpu, tool, row, digits)


# The stage table's columns: the trace of each build and value, and of the
# two OpenSSL releases that a trace splits.
STAGE_COLUMNS = [
    ("chapulin-n2", "0xe7"),
    ("chapulin-n2", "0x07"),
    ("chapulin-n2", "0x03"),
    ("chapulin-base", "0xe7"),
    ("openssl-pinned", "-"),
    ("openssl-system-static", "-"),
]

STAGE_ROWS = [
    ("X25519 key generation", "x25519_keygen", 3),
    ("X25519 shared secret", "x25519_shared", 3),
    ("CertificateVerify: the P-256 ECDSA signature", "sign", 3),
    ("of which k·G", "sign_base_mul", 3),
    ("of which the nonce", "sign_nonce", 3),
    ("of which the rest", "sign_rest", 3),
    ("HKDF and HMAC of the key schedule", "key_schedule", 3),
    ("hashes of the transcript, the signed content and the ClientHello", "transcript", 3),
    ("certificate, other messages and their records", "messages", 3),
    ("the handshake", "handshake", 3),
    ("one request's records and the two close_notify", "exchange", 3),
    ("of the handshake, the image's own memset", "memset", 3),
    ("of the handshake, the C library", "c_library", 3),
]

# The whole-connection table: one row per server and value.
WHOLE_ROWS = [
    ("chapulin, Neoverse-N2 build, `0xe7`", "chapulin-n2", "0xe7"),
    ("chapulin, Neoverse-N2 build, `0x07`", "chapulin-n2", "0x07"),
    ("chapulin, Neoverse-N2 build, `0x03`", "chapulin-n2", "0x03"),
    ("chapulin, base armv8-a build, `0xe7`", "chapulin-base", "0xe7"),
    ("chapulin, base armv8-a build, `0x07`", "chapulin-base", "0x07"),
    ("chapulin, base armv8-a build, `0x03`", "chapulin-base", "0x03"),
    ("OpenSSL 3.6.4, static", "openssl-pinned", "-"),
    ("OpenSSL 3.0.13, shared", "openssl-system", "-"),
    ("OpenSSL 3.0.13, static", "openssl-system-static", "-"),
]

# The base build's rows that callgrind counts, beside the trace's.
CALLGRIND_ROWS = [
    ("X25519 key generation", "x25519_keygen", 3),
    ("X25519 shared secret", "x25519_shared", 3),
    ("CertificateVerify: the P-256 ECDSA signature", "sign", 3),
    ("of which k·G", "sign_base_mul", 3),
    ("the handshake", "handshake", 3),
    ("one request's records and the two close_notify", "exchange", 3),
    ("of the handshake, the image's own memset", "memset", 3),
]
CALLGRIND_COLUMNS = [
    ("chapulin-base", "0x07", "callgrind"),
    ("chapulin-base", "0x07", "qemu"),
    ("chapulin-base", "0x03", "callgrind"),
    ("chapulin-base", "0x03", "qemu"),
]

TABLES = [
    ("server side of the second connection, M instructions (QEMU's trace)",
     [(label, [cell(server, cpu, "qemu", row, digits) for server, cpu in STAGE_COLUMNS])
      for label, row, digits in STAGE_ROWS]),
    ("server side of the second connection on the Neoverse-N2, M instructions",
     [(label, [cell(server, cpu, "perf_event", "handshake", 3),
               cell(server, cpu, "perf_event", "exchange", 3),
               cell(server, cpu, "perf_stat", "connection", 3),
               cell(server, cpu, "callgrind", "handshake", 3),
               ("ratio", server, cpu)])
      for label, server, cpu in WHOLE_ROWS]),
    ("base armv8-a build, M instructions",
     [(label, [cell(server, cpu, tool, row, digits) for server, cpu, tool in CALLGRIND_COLUMNS])
      for label, row, digits in CALLGRIND_ROWS]),
]


def read():
    rows = {}
    with open(CSV) as f:
        header = None
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            if header is None:
                header = row
                continue
            rows[tuple(row[:4])] = int(row[4])
    return rows


def render(rows, spec):
    """The text of one cell: millions to the spec's places, the handshake
    as a share of OpenSSL 3.6.4's for a ratio, or a dash for no row."""
    if spec[0] == "ratio":
        _, server, cpu = spec
        ours = rows.get((server, cpu, "perf_event", "handshake"))
        theirs = rows.get(("openssl-pinned", "-", "perf_event", "handshake"))
        return "—" if ours is None or theirs is None else "%.2f" % (ours / theirs)
    server, cpu, tool, row, digits = spec
    value = rows.get((server, cpu, tool, row))
    return "—" if value is None else "%.*f" % (digits, value / 1e6)


def table_rows(text, header):
    """The body rows of the table whose header row's first cell is header,
    as a dict from each row's first cell to its other cells, or None."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells[0] == header:
            body = {}
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                body[cells[0]] = cells[1:]
            return body
    return None


def check_handshake(text):
    rows = read()
    rc = 0
    for header, specs in TABLES:
        body = table_rows(text, header)
        if body is None:
            print("lint-bench-numbers: docs/performance.md has no table headed %r" % header)
            rc = 1
            continue
        for label, cells in specs:
            want = [render(rows, spec) for spec in cells]
            got = body.get(label)
            if got != want:
                print("lint-bench-numbers: %r in %r says %s; %s renders as %s"
                      % (label, header, " / ".join(got or ["nothing"]), CSV, " / ".join(want)))
                rc = 1
    return rc
