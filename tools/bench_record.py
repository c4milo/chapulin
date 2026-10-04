# docs/performance.md, "Where a record's time goes", renders four tables from
# the CSVs bench/record.sh writes, one column per CSV, and one sentence from
# their check lines. tools/bench-numbers.py calls check_record, so
# `make lint-bench-numbers` fails when a table cell or that sentence
# disagrees with the CSVs, as it does for the other figures in that file.
#
# The CSVs in RECORD_CSVS were measured before docs/decisions.md 89, and
# the build labels below are theirs: the names of the build variables that
# chose each path then. bench/record.sh now labels its rows by the
# ch_cfg.cpu value they run under, "ch_cfg.cpu 0x3", "0x7" and "0x1f",
# and times no row on chacha20.c's portable loop, which no host session
# runs. So a change that commits a fresh CSV moves these labels, the rows
# of the ChaCha20-Poly1305 table and docs/performance.md with it.
import csv
import math
import re

# The CSVs, in the order of the tables' columns.
RECORD_CSVS = [
    "bench/results-record-darwin-arm64-clang.csv",
    "bench/results-record-linux-arm64-clang.csv",
    "bench/results-record-linux-arm64-gcc.csv",
]

PACKAGED = "WIDEMUL=decomposed"
NATIVE = "WIDEMUL=native"
VECTOR = "CHACHA=vector WIDEMUL=decomposed"
VECTOR_NATIVE = "CHACHA=vector WIDEMUL=native"
RECORD = 16384


def cell(aead, stage, build=PACKAGED, size=RECORD, column="ns"):
    """The CSV cell a table cell renders: the row whose aead and stage match,
    whose build starts with build, at size bytes, in the named column."""
    return (aead, build, stage, size, column)


# Each table: the first cell of its header row, the unit it renders, and its
# rows. A row names the cell it renders, and for a stage of rec_seal also the
# rec_seal cell its share is taken of.
TABLES = [
    ("AES-128-GCM, one 16 KiB record, µs", "us", [
        ("`rec_seal`", cell("aes128gcm", "rec_seal"), None),
        ("`rec_seal` without its AEAD", cell("aes128gcm", "rec_seal_without_aead"),
         cell("aes128gcm", "rec_seal")),
        ("the AEAD's seal, `gcm_traffic_seal`", cell("aes128gcm", "aead_seal"),
         cell("aes128gcm", "rec_seal")),
        ("counter mode and GHASH in one loop, the seal's whole passes",
         cell("aes128gcm", "seal_passes"), cell("aes128gcm", "rec_seal")),
        ("counter mode alone, in place", cell("aes128gcm", "counter_mode_in_place"), None),
        ("GHASH alone, over the ciphertext", cell("aes128gcm", "ghash_data"), None),
        ("`rec_open`", cell("aes128gcm", "rec_open"), None),
        ("the AEAD's open, `gcm_traffic_open`", cell("aes128gcm", "aead_open"), None),
        ("GHASH and counter mode in one loop, the open's whole passes",
         cell("aes128gcm", "open_passes"), None),
        ("OpenSSL, one record sealed", cell("aes128gcm", "openssl_seal", "OpenSSL"), None),
        ("OpenSSL, one record opened", cell("aes128gcm", "openssl_open", "OpenSSL"), None),
        ("Zig `std.crypto`, one record sealed", cell("aes128gcm", "zig_seal", "zig"), None),
    ]),
    ("AES-256-GCM, one 16 KiB record, µs", "us", [
        ("`rec_seal`", cell("aes256gcm", "rec_seal"), None),
        ("the AEAD's seal, `gcm_traffic_seal`", cell("aes256gcm", "aead_seal"),
         cell("aes256gcm", "rec_seal")),
        ("counter mode and GHASH in one loop, the seal's whole passes",
         cell("aes256gcm", "seal_passes"), cell("aes256gcm", "rec_seal")),
        ("`rec_open`", cell("aes256gcm", "rec_open"), None),
        ("the AEAD's open, `gcm_traffic_open`", cell("aes256gcm", "aead_open"), None),
        ("OpenSSL, one record sealed", cell("aes256gcm", "openssl_seal", "OpenSSL"), None),
        ("OpenSSL, one record opened", cell("aes256gcm", "openssl_open", "OpenSSL"), None),
        ("Zig `std.crypto`, one record sealed", cell("aes256gcm", "zig_seal", "zig"), None),
    ]),
    ("ChaCha20-Poly1305, one 16 KiB record, µs", "us", [
        ("`rec_seal`, the packaged multiply", cell("chacha20poly1305", "rec_seal"), None),
        ("`rec_seal` without its AEAD", cell("chacha20poly1305", "rec_seal_without_aead"),
         cell("chacha20poly1305", "rec_seal")),
        ("the ChaCha20 block function", cell("chacha20poly1305", "chacha20_blocks"),
         cell("chacha20poly1305", "rec_seal")),
        ("exclusive-or, loads and stores, in place", cell("chacha20poly1305", "xor_rest_in_place"),
         cell("chacha20poly1305", "rec_seal")),
        ("Poly1305 over the ciphertext", cell("chacha20poly1305", "poly1305_data"),
         cell("chacha20poly1305", "rec_seal")),
        ("`rec_seal`, `WIDEMUL=native`", cell("chacha20poly1305", "rec_seal", NATIVE), None),
        ("Poly1305 over the ciphertext, `WIDEMUL=native`",
         cell("chacha20poly1305", "poly1305_data", NATIVE),
         cell("chacha20poly1305", "rec_seal", NATIVE)),
        ("`rec_open`, the packaged multiply", cell("chacha20poly1305", "rec_open"), None),
        ("`rec_seal`, `CHACHA=vector`", cell("chacha20poly1305", "rec_seal", VECTOR), None),
        ("ChaCha20 in place, `CHACHA=vector`",
         cell("chacha20poly1305", "chacha20_xor_in_place", VECTOR),
         cell("chacha20poly1305", "rec_seal", VECTOR)),
        ("`rec_seal`, `CHACHA=vector WIDEMUL=native`",
         cell("chacha20poly1305", "rec_seal", VECTOR_NATIVE), None),
        ("ChaCha20 in place, `CHACHA=vector WIDEMUL=native`",
         cell("chacha20poly1305", "chacha20_xor_in_place", VECTOR_NATIVE),
         cell("chacha20poly1305", "rec_seal", VECTOR_NATIVE)),
        ("Poly1305 over the ciphertext, `CHACHA=vector WIDEMUL=native`",
         cell("chacha20poly1305", "poly1305_data", VECTOR_NATIVE),
         cell("chacha20poly1305", "rec_seal", VECTOR_NATIVE)),
        ("`rec_open`, `CHACHA=vector`", cell("chacha20poly1305", "rec_open", VECTOR), None),
        ("`rec_open`, `CHACHA=vector WIDEMUL=native`",
         cell("chacha20poly1305", "rec_open", VECTOR_NATIVE), None),
        ("OpenSSL, one record sealed", cell("chacha20poly1305", "openssl_seal", "OpenSSL"), None),
        ("OpenSSL, one record opened", cell("chacha20poly1305", "openssl_open", "OpenSSL"), None),
        ("Zig `std.crypto`, one record sealed", cell("chacha20poly1305", "zig_seal", "zig"),
         None),
    ]),
    ("Work a record pays whatever its size, and a 1 KiB record, ns", "ns", [
        ("AES-128 key expansion, `aes_traffic_key_init`",
         cell("aes128gcm", "key_expansion", size=0), None),
        ("AES-256 key expansion", cell("aes256gcm", "key_expansion", size=0), None),
        ("the wipe of the expanded key", cell("aes128gcm", "key_wipe", size=0), None),
        ("the GCM tag's fixed work", cell("aes128gcm", "compute_tag_fixed", size=0), None),
        ("the Poly1305 tag's fixed work, the packaged multiply",
         cell("chacha20poly1305", "mac_fixed", size=0), None),
        ("AES-128-GCM `rec_seal`, 1 KiB", cell("aes128gcm", "rec_seal", size=1024), None),
        ("`rec_seal` without its AEAD, 1 KiB",
         cell("aes128gcm", "rec_seal_without_aead", size=1024),
         cell("aes128gcm", "rec_seal", size=1024)),
    ]),
]

# The sentence that states how closely each whole matches the sum of its
# parts.
TOLERANCE = re.compile(r"every whole is within (\d+)% of the sum of its parts")


def read_record_csv(path):
    """Each data row, keyed by aead, build, stage and size, as a dict of its
    columns; and each check line as (aead, build, size, whole, difference)."""
    rows = {}
    checks = []
    with open(path) as f:
        header = None
        for row in csv.reader(f):
            if not row:
                continue
            if row[0] == "# check":
                whole = row[4].split(" =")[0]
                checks.append((row[1], row[2], int(row[3]), whole, float(row[7].rstrip("%"))))
                continue
            if row[0].startswith("#"):
                continue
            if header is None:
                header = row
                continue
            rows[(row[0], row[1], row[2], int(row[3]))] = dict(zip(header, row))
    return rows, checks


def lookup(rows, spec):
    """The value of one table cell's CSV cell, or None when no row has it."""
    aead, build, stage, size, column = spec
    for (a, b, s, n), row in rows.items():
        if a == aead and b.startswith(build) and s == stage and n == size and row[column]:
            return float(row[column])
    return None


def render(rows, unit, spec, share_of):
    value = lookup(rows, spec)
    if value is None:
        return "—"
    text = "%.1f" % (value / 1000) if unit == "us" else "%d" % round(value)
    if share_of is not None:
        text += " (%d%%)" % round(100 * value / lookup(rows, share_of))
    return text


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


def check_tables(text, data):
    rc = 0
    for header, unit, specs in TABLES:
        body = table_rows(text, header)
        if body is None:
            print("lint-bench-numbers: docs/performance.md has no table headed %r" % header)
            rc = 1
            continue
        for label, spec, share_of in specs:
            want = [render(rows, unit, spec, share_of) for rows, _ in data]
            got = body.get(label)
            if got != want:
                print("lint-bench-numbers: %r in %r says %s; the record CSVs render as %s"
                      % (label, header, " / ".join(got or ["nothing"]), " / ".join(want)))
                rc = 1
    return rc


def check_tolerance(text, data):
    """The stated percent: the largest difference of any check, rounded up."""
    m = TOLERANCE.search(re.sub(r"\s+", " ", text))
    if m is None:
        print("lint-bench-numbers: docs/performance.md does not state how the record stages sum")
        return 1
    within = max(abs(d) for _, checks in data for (_, _, _, _, d) in checks)
    want = "%d" % math.ceil(within)
    if m.group(1) != want:
        print("lint-bench-numbers: the record sum sentence says %s%%; the checks render as %s%%"
              % (m.group(1), want))
        return 1
    return 0


def check_record(text):
    data = [read_record_csv(path) for path in RECORD_CSVS]
    return check_tables(text, data) | check_tolerance(text, data)
