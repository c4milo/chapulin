# docs/performance.md, "Where a record's time goes", renders four tables from
# the CSVs bench/record.sh writes, one column per CSV, and one sentence from
# their check lines. tools/bench-numbers.py calls check_record, so
# `make lint-bench-numbers` fails when a table cell or that sentence
# disagrees with the CSVs, as it does for the other figures in that file.
#
# bench/record.sh labels each row with the ch_cfg.cpu value it ran under
# (docs/decisions.md 89), and the constants below are those labels. A value
# with the AES bit times the AES-GCM rows, and a value's multiply bit picks
# the Poly1305 its ChaCha20-Poly1305 rows run. tools/bench_scoreboard.py
# reads the same CSVs for the AEAD rows of the table that sets chapulin
# beside OpenSSL.
import csv
import math
import re

# The CSVs, in the order of the tables' columns.
RECORD_CSVS = [
    "bench/results-record-darwin-arm64-clang.csv",
    "bench/results-record-linux-arm64-clang.csv",
    "bench/results-record-linux-arm64-gcc.csv",
]

# The probe's bit and the AES bit: the AES-GCM rows, and ChaCha20-Poly1305
# with Poly1305 on the 16x16 decomposition.
STATES_AES = "ch_cfg.cpu 0x3"
# Those and the multiply bit: ChaCha20-Poly1305 with the vector Poly1305.
STATES_MULTIPLY = "ch_cfg.cpu 0x7"
RECORD = 16384


def cell(aead, stage, build=STATES_AES, size=RECORD, column="ns"):
    """The CSV cell a table cell renders: the row whose aead and stage match,
    whose build is build, or begins with it where build names a tool whose
    version follows, at size bytes, in the named column."""
    return (aead, build, stage, size, column)


# The stage of an OpenSSL row is openssl_ and the stage of this bench that
# times the same operation, which depends on the OpenSSL release
# (bench/record.sh, openssl_stage). So a table has one row per operation
# OpenSSL may time, and a column whose release times another operation
# renders that cell empty.
def openssl(aead, stage):
    return cell(aead, "openssl_" + stage, "OpenSSL")


def aes_gcm_rows(aead, stages):
    """One AES-GCM table's rows: the seal's and the open's, with the stage
    rows the first table adds, then the other libraries'."""
    seal = cell(aead, "rec_seal")
    rows = [("`rec_seal`", seal, None)]
    if stages:
        rows.append(("`rec_seal` without its AEAD", cell(aead, "rec_seal_without_aead"), seal))
    rows += [
        ("the AEAD under a key expanded for the record, as `seal_aes_gcm` runs it",
         cell(aead, "seal_aes_gcm"), None),
        ("the AEAD's seal, `gcm_traffic_seal`", cell(aead, "aead_seal"), seal),
        ("counter mode and GHASH in one loop, the seal's whole passes",
         cell(aead, "seal_passes"), seal),
    ]
    if stages:
        rows += [
            ("counter mode alone, in place", cell(aead, "counter_mode_in_place"), None),
            ("GHASH alone, over the ciphertext", cell(aead, "ghash_data"), None),
        ]
    rows += [
        ("`rec_open`", cell(aead, "rec_open"), None),
        ("the AEAD under a key expanded for the record, as `open_aes_gcm` runs it",
         cell(aead, "open_aes_gcm"), None),
        ("the AEAD's open, `gcm_traffic_open`", cell(aead, "aead_open"), None),
    ]
    if stages:
        rows.append(("GHASH and counter mode in one loop, the open's whole passes",
                     cell(aead, "open_passes"), None))
    rows += [
        ("OpenSSL, the key set and one record sealed", openssl(aead, "seal_aes_gcm"), None),
        ("OpenSSL, the key set and one record opened", openssl(aead, "open_aes_gcm"), None),
        ("OpenSSL, one record sealed under a key set before", openssl(aead, "aead_seal"), None),
        ("OpenSSL, one record opened under a key set before", openssl(aead, "aead_open"), None),
        ("Zig `std.crypto`, one record sealed", cell(aead, "zig_seal", "zig"), None),
    ]
    return rows


CHACHA = "chacha20poly1305"

# Each table: the first cell of its header row, the unit it renders, and its
# rows. A row names the cell it renders, and for a stage of rec_seal also the
# rec_seal cell its share is taken of.
TABLES = [
    ("AES-128-GCM, one 16 KiB record, µs", "us", aes_gcm_rows("aes128gcm", True)),
    ("AES-256-GCM, one 16 KiB record, µs", "us", aes_gcm_rows("aes256gcm", False)),
    ("ChaCha20-Poly1305, one 16 KiB record, µs", "us", [
        ("`rec_seal`, `ch_cfg.cpu 0x3`", cell(CHACHA, "rec_seal"), None),
        ("`rec_seal` without its AEAD", cell(CHACHA, "rec_seal_without_aead"),
         cell(CHACHA, "rec_seal")),
        ("ChaCha20 in place", cell(CHACHA, "chacha20_xor_in_place"), cell(CHACHA, "rec_seal")),
        ("Poly1305 over the ciphertext, on the 16x16 decomposition",
         cell(CHACHA, "poly1305_data"), cell(CHACHA, "rec_seal")),
        ("`rec_open`, `ch_cfg.cpu 0x3`", cell(CHACHA, "rec_open"), None),
        ("`rec_seal`, `ch_cfg.cpu 0x7`", cell(CHACHA, "rec_seal", STATES_MULTIPLY), None),
        ("the AEAD's seal, `aead_seal_cpu`, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "aead_seal", STATES_MULTIPLY), cell(CHACHA, "rec_seal", STATES_MULTIPLY)),
        ("the seal less its tag's fixed work, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "aead_seal_data", STATES_MULTIPLY), None),
        ("ChaCha20 in place, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "chacha20_xor_in_place", STATES_MULTIPLY),
         cell(CHACHA, "rec_seal", STATES_MULTIPLY)),
        ("Poly1305 over the ciphertext, the vector path",
         cell(CHACHA, "poly1305_data", STATES_MULTIPLY),
         cell(CHACHA, "rec_seal", STATES_MULTIPLY)),
        ("`rec_open`, `ch_cfg.cpu 0x7`", cell(CHACHA, "rec_open", STATES_MULTIPLY), None),
        ("the AEAD's open, `aead_open_cpu`, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "aead_open", STATES_MULTIPLY), None),
        ("the open less its tag's fixed work, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "aead_open_data", STATES_MULTIPLY), None),
        ("OpenSSL, one record sealed", openssl(CHACHA, "aead_seal"), None),
        ("OpenSSL, one record opened", openssl(CHACHA, "aead_open"), None),
        ("OpenSSL, ChaCha20 and Poly1305 over the record's bytes, sealing",
         openssl(CHACHA, "aead_seal_data"), None),
        ("OpenSSL, ChaCha20 and Poly1305 over the record's bytes, opening",
         openssl(CHACHA, "aead_open_data"), None),
        ("Zig `std.crypto`, one record sealed", cell(CHACHA, "zig_seal", "zig"), None),
    ]),
    ("Work a record pays whatever its size, and a 1 KiB record, ns", "ns", [
        ("AES-128 key expansion, `aes_traffic_key_init`",
         cell("aes128gcm", "key_expansion", size=0), None),
        ("AES-256 key expansion", cell("aes256gcm", "key_expansion", size=0), None),
        ("the wipe of the expanded key", cell("aes128gcm", "key_wipe", size=0), None),
        ("the GCM tag's fixed work", cell("aes128gcm", "compute_tag_fixed", size=0), None),
        ("the Poly1305 tag's fixed work, on the 16x16 decomposition",
         cell(CHACHA, "mac_fixed", size=0), None),
        ("the Poly1305 tag's fixed work, `ch_cfg.cpu 0x7`",
         cell(CHACHA, "mac_fixed", STATES_MULTIPLY, size=0), None),
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
        named = b == build or b.startswith(build + " ")
        if a == aead and named and s == stage and n == size and row[column]:
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
