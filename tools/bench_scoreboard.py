# docs/performance.md, "chapulin beside OpenSSL", holds one table: a row per
# primitive TLS runs, and for each machine chapulin's time, OpenSSL's time
# and the first over the second. This file renders the table and the line
# that states each machine from the CSVs bench/primitives.sh and
# bench/record.sh wrote there. tools/bench-numbers.py calls
# check_scoreboard, so `make lint-bench-numbers` fails when the document
# disagrees with the CSVs. Run as a program, it prints what the document
# must hold, to paste after a run moves a row:
#
#   python3 tools/bench_scoreboard.py
#
# A chapulin figure is the row of the widest ch_cfg.cpu value the CSV
# holds, the value a caller on that CPU states (docs/decisions.md 89). A
# ratio above 1 is a row where chapulin is behind, and it renders in bold.
# Where `openssl speed` times a different operation than chapulin's row,
# the OpenSSL cell names that operation and the row has no ratio.
#
# check_scoreboard also holds one sentence under "Where the time goes" to
# the first machine's CSV: what the wide X25519 field takes beside the
# 16-word one, and a client's side of a handshake under the widest value,
# which the machine's line states, and under CH_CPU_PROBED alone.
import csv
import os
import re
import sys

# One machine per column group: the name its header cells carry, the CSV
# bench/primitives.sh wrote on it, and the CSV bench/record.sh wrote on it,
# which holds the AEAD rows. The x86-64 groups are two CPUs, one without
# AVX-512 and one with AVX-512 IFMA, each under gcc and the pinned clang;
# the bench workflow's record-x86_64 job checks which kind it drew.
MACHINES = [
    ("M1 Pro", "bench/results-primitives-darwin-arm64-clang.csv",
     "bench/results-record-darwin-arm64-clang.csv"),
    ("x86-64 gcc", "bench/results-primitives-linux-x86_64-gcc.csv",
     "bench/results-record-linux-x86_64-gcc.csv"),
    ("x86-64 clang", "bench/results-primitives-linux-x86_64-clang.csv",
     "bench/results-record-linux-x86_64-clang.csv"),
    ("x86-64 AVX-512 gcc", "bench/results-primitives-linux-x86_64-avx512-gcc.csv",
     "bench/results-record-linux-x86_64-avx512-gcc.csv"),
    ("x86-64 AVX-512 clang", "bench/results-primitives-linux-x86_64-avx512-clang.csv",
     "bench/results-record-linux-x86_64-avx512-clang.csv"),
]

# The first cell of the table's header row, which is how the check finds it.
HEADER = "one operation"

V15 = "PKCS#1 v1.5"

# Each primitive row: its label, chapulin's row and OpenSSL's row in the
# primitives CSV, and the row's bytes. A fifth element names the operation
# OpenSSL's row times where it is not chapulin's, and that row has no ratio.
PRIMITIVES = [
    ("SHA-256, 16 KiB", "sha256", "sha256", 16384),
    ("SHA-256, 64 bytes", "sha256", "sha256", 64),
    ("SHA-384, 16 KiB", "sha384", "sha384", 16384),
    ("SHA-384, 64 bytes", "sha384", "sha384", 64),
    ("SHA3-256, 16 KiB", "sha3_256", "sha3_256", 16384),
    ("SHA3-256, 64 bytes", "sha3_256", "sha3_256", 64),
    ("X25519 key generation", "x25519_base", "x25519_base", 0),
    ("X25519 shared secret", "x25519", "x25519", 0),
    ("P-256 key generation", "p256_ecdh_keygen", "p256_ecdh_keygen", 0),
    ("P-256 shared secret", "p256_ecdh", "p256_ecdh", 0),
    ("ECDSA P-256 sign", "p256_sign", "p256_sign", 0),
    ("ECDSA P-256 verify", "p256_ecdsa_verify", "p256_ecdsa_verify", 0),
    ("ECDSA P-384 verify", "p384_ecdsa_verify", "p384_ecdsa_verify", 0),
    ("RSA-2048 PSS sign", "rsa_pss_sign_2048", "rsa_pkcs1_sign_2048", 0, V15 + " sign"),
    ("RSA-2048 PSS verify", "rsa_pss_verify_2048", "rsa_pkcs1_verify_2048", 0, V15 + " verify"),
    ("RSA-2048 " + V15 + " verify", "rsa_pkcs1_verify_2048", "rsa_pkcs1_verify_2048", 0),
    ("RSA-3072 PSS sign", "rsa_pss_sign_3072", "rsa_pkcs1_sign_3072", 0, V15 + " sign"),
    ("RSA-3072 PSS verify", "rsa_pss_verify_3072", "rsa_pkcs1_verify_3072", 0, V15 + " verify"),
    ("RSA-3072 " + V15 + " verify", "rsa_pkcs1_verify_3072", "rsa_pkcs1_verify_3072", 0),
    ("ML-KEM-768 key generation", "mlkem768_keygen", "mlkem768_keygen", 0),
    ("ML-KEM-768 encapsulation", "mlkem768_encaps", "mlkem768_encaps", 0),
    ("ML-KEM-768 decapsulation", "mlkem768_decaps", "mlkem768_decaps", 0),
]

# Each AEAD row: its label, the aead column of the record CSV and
# chapulin's stage. OpenSSL's row is the one whose stage is openssl_ and that
# stage's name: bench/record.sh gives an OpenSSL row the name of the stage
# that times the same operation, which depends on the OpenSSL release. These
# are the operations OpenSSL 3.6's `speed -aead` times, and under another
# release the OpenSSL cell and the ratio stay empty. Every row is over a
# record of RECORD bytes.
RECORD = 16384
AEADS = [
    ("AES-128-GCM, the key set and one 16 KiB record sealed", "aes128gcm", "seal_aes_gcm"),
    ("AES-128-GCM, the key set and one 16 KiB record opened", "aes128gcm", "open_aes_gcm"),
    ("AES-256-GCM, the key set and one 16 KiB record sealed", "aes256gcm", "seal_aes_gcm"),
    ("AES-256-GCM, the key set and one 16 KiB record opened", "aes256gcm", "open_aes_gcm"),
    ("ChaCha20-Poly1305, 16 KiB encrypted and hashed, no tag", "chacha20poly1305",
     "aead_seal_data"),
    ("ChaCha20-Poly1305, 16 KiB hashed and decrypted, no tag", "chacha20poly1305",
     "aead_open_data"),
]

CPU_LABEL = "ch_cfg.cpu "
# The bits of ch_cfg.cpu that change a row bench/record.sh times: the probe's
# bit, the AES and multiply bits and the two x86-64 kernel bits (cpu_cfg.h).
# A record's protection hashes nothing and verifies no RSA signature, so that
# script states no hash bit and no CH_CPU_AVX512_IFMA, and the widest value
# of its CSV is the primitives' widest value without the three hash bits and
# that one (docs/decisions.md 93 and 119).
RECORD_BITS = 0x1f
IFMA_BIT = 0x100
FIRST_LINE = re.compile(r"^# bench/\S+ on (?P<cpu>.+?) \((?P<arch>\w+)\), (?:.+, )?"
                        r"(?P<os>\S+ \S+), (?P<date>\d{4}-\d\d-\d\d), tree (?P<tree>\S+)$")
LOAD_LINE = re.compile(r"^# load average \(1, 5, 15 min\) before: (\S+) .*; after: (\S+) ")


def read_csv(path):
    """A bench CSV's comment lines, and its data rows as a dict of columns
    each. None when the file is absent, which is a machine nobody has
    measured yet."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        lines = f.read().splitlines()
    comments = [line for line in lines if line.startswith("#")]
    data = list(csv.reader(line for line in lines if line and not line.startswith("#")))
    return comments, [dict(zip(data[0], row)) for row in data[1:]]


def cpu_value(build):
    """The ch_cfg.cpu value a build column names, or None for another build."""
    if not build.startswith(CPU_LABEL):
        return None
    return int(build[len(CPU_LABEL):], 16)


def widest(rows, matches, sign=1):
    """Among the rows matches accepts, the one whose build names the widest
    ch_cfg.cpu value, or with sign -1 the narrowest, or None."""
    best = None
    for row in rows:
        value = cpu_value(row["build"])
        if value is not None and matches(row) and (best is None or sign * value > sign * best[0]):
            best = (value, row)
    return None if best is None else best[1]


def narrowest(rows, matches):
    """The row of the value that states the fewest bits: CH_CPU_PROBED alone."""
    return widest(rows, matches, -1)


def openssl_row(rows, matches):
    for row in rows:
        if row["build"].startswith("OpenSSL ") and matches(row):
            return row
    return None


def primitive_ns(row):
    """One operation's nanoseconds: a per-byte row times its bytes."""
    if row is None:
        return None
    ns = float(row["ns"])
    return ns * int(row["bytes"]) if row["unit"] == "byte" else ns


def figures(x):
    """Three significant figures of a time or a ratio."""
    if x < 10:
        return "%.2f" % x
    return "%.1f" % x if x < 100 else "%d" % round(x)


def render_time(ns):
    if ns is None:
        return "—"
    for unit, scale in (("ms", 1e6), ("µs", 1e3)):
        if ns >= scale:
            return "%s %s" % (figures(ns / scale), unit)
    return "%s ns" % figures(ns)


def render_ratio(ours, theirs):
    if ours is None or theirs is None:
        return "—"
    ratio = ours / theirs
    return "**%s**" % figures(ratio) if ratio > 1 else figures(ratio)


def primitive_row(name, size):
    """Whether a row of the primitives CSV is the primitive name at size bytes."""
    return lambda row: row["primitive"] == name and int(row["bytes"]) == size


def record_row(aead, stage):
    """Whether a row of the record CSV is one stage of one AEAD over a record."""
    return lambda row: (row["aead"] == aead and row["stage"] == stage
                        and int(row["record_bytes"]) == RECORD)


def record_ns(row):
    return None if row is None else float(row["ns"])


def machine_cells(primitives, record):
    """One machine's three cells for every row of the table, in order."""
    cells = []
    rows = [] if primitives is None else primitives[1]
    for label, ours_name, theirs_name, size, *other in PRIMITIVES:
        ours = primitive_ns(widest(rows, primitive_row(ours_name, size)))
        theirs = primitive_ns(openssl_row(rows, primitive_row(theirs_name, size)))
        if other:
            theirs_text = "—" if theirs is None else "%s, %s" % (render_time(theirs), other[0])
            cells.append((label, [render_time(ours), theirs_text, "—"]))
        else:
            cells.append((label, [render_time(ours), render_time(theirs),
                                  render_ratio(ours, theirs)]))
    rows = [] if record is None else record[1]
    for label, aead, stage in AEADS:
        ours = record_ns(widest(rows, record_row(aead, stage)))
        theirs = record_ns(openssl_row(rows, record_row(aead, "openssl_" + stage)))
        cells.append((label, [render_time(ours), render_time(theirs),
                              render_ratio(ours, theirs)]))
    return cells


def facts(comments, rows):
    """What a CSV's header states about its run: the CPU, the system, the
    compiler, the tree, and the one-minute load average before and after."""
    first = FIRST_LINE.match(comments[0])
    load = next(m for m in map(LOAD_LINE.match, comments) if m)
    openssl = sorted(set(r["build"] for r in rows if r["build"].startswith("OpenSSL ")))
    values = [v for v in (cpu_value(r["build"]) for r in rows) if v is not None]
    return {
        "cpu": first.group("cpu"), "os": first.group("os"), "date": first.group("date"),
        "tree": first.group("tree"), "compiler": comments[1][2:].split(";")[0],
        "before": load.group(1), "after": load.group(2),
        "openssl": openssl[0] if openssl else "no OpenSSL", "value": max(values, default=None),
    }


def machine_line(name, primitives, record):
    """The sentence that states one machine: its CPU, system, compiler and
    OpenSSL, the ch_cfg.cpu value its chapulin rows ran under, and the load
    average around each of its two runs. Where the primitives' value holds
    a hash bit, the sentence states the AEAD rows' value beside it. None
    when the two CSVs disagree about the machine, or about the widest value
    they ran under in a bit a record reads."""
    if primitives is None or record is None:
        return "**%s**: no run recorded" % name
    ours = facts(*primitives)
    aead = facts(*record)
    if ours["value"] is None:
        return "**%s**: no run recorded" % name
    if any(ours[k] != aead[k] for k in ("cpu", "os", "compiler", "openssl")):
        return None
    if aead["value"] is None or ours["value"] & RECORD_BITS != aead["value"]:
        return None
    values = "`ch_cfg.cpu 0x%x`" % ours["value"]
    if aead["value"] != ours["value"]:
        unread = ("neither a hash bit nor `CH_CPU_AVX512_IFMA` changes"
                  if ours["value"] & IFMA_BIT else "no hash bit changes")
        values += ", and `0x%x` for the AEAD rows, which %s" % (aead["value"], unread)
    return ("**%s**: %s, %s, %s, %s, %s; one-minute load average %s before the "
            "primitives' run and %s after it, and %s and %s around the AEAD rows' run"
            % (name, ours["cpu"], ours["os"], ours["compiler"], ours["openssl"], values,
               ours["before"], ours["after"], aead["before"], aead["after"]))


def render():
    """The table's rows, each a label and every machine's cells in turn,
    and the machines' lines."""
    data = [(name, read_csv(primitives), read_csv(record))
            for name, primitives, record in MACHINES]
    columns = [machine_cells(primitives, record) for _, primitives, record in data]
    table = [(columns[0][i][0], [c for column in columns for c in column[i][1]])
             for i in range(len(columns[0]))]
    return table, [(name, machine_line(name, primitives, record))
                   for name, primitives, record in data]


def table_rows(text):
    """The body rows of the table whose header row's first cell is HEADER,
    as a dict from each row's first cell to its other cells, or None."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells[0] == HEADER:
            body = {}
            for row in lines[i + 2:]:
                if not row.startswith("|"):
                    break
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                body[cells[0]] = cells[1:]
            return body
    return None


# The sentence that states the wide X25519 field's gain on the first machine.
# Its handshake figures are the widest value's and CH_CPU_PROBED's. The
# sentence names the first as the value the machine's line states, because
# a run after docs/decisions.md 93 states the hash instructions beside the
# multiply, and the handshake's hashes then run on them.
FIELD = re.compile(r"a scalar multiplication takes (\S+ \S+) on that field against (\S+ \S+) on "
                   r"the 16-word one over the decomposition, and the client side of a pinned "
                   r"RSA-3072 handshake takes (\S+ \S+) under the value that machine's line "
                   r"states below against (\S+ \S+) under `CH_CPU_PROBED` alone")


def check_field(prose):
    """That sentence against the first machine's primitives CSV: X25519 and
    a client's side of a handshake, under the widest value and under
    CH_CPU_PROBED alone."""
    primitives = read_csv(MACHINES[0][1])
    rows = [] if primitives is None else primitives[1]
    want = tuple(render_time(primitive_ns(pick(rows, primitive_row(name, 0))))
                 for name in ("x25519", "handshake_pinned_rsa3072_client_side")
                 for pick in (widest, narrowest))
    m = FIELD.search(prose)
    if m is None:
        print("lint-bench-numbers: docs/performance.md does not state the wide X25519 field's time")
        return 1
    if m.groups() != want:
        print("lint-bench-numbers: docs/performance.md says the wide field takes %s against %s "
              "and the client side %s against %s; %s renders as %s, %s, %s and %s"
              % (m.groups() + (MACHINES[0][1],) + want))
        return 1
    return 0


def check_scoreboard(text):
    table, lines = render()
    rc = 0
    body = table_rows(text)
    if body is None:
        print("lint-bench-numbers: docs/performance.md has no table headed %r" % HEADER)
        return 1
    for label, want in table:
        got = body.get(label)
        if got != want:
            print("lint-bench-numbers: %r beside OpenSSL says %s; the CSVs render as %s"
                  % (label, " / ".join(got or ["nothing"]), " / ".join(want)))
            rc = 1
    prose = re.sub(r"\s+", " ", text)
    for name, line in lines:
        if line is None:
            print("lint-bench-numbers: the two CSVs of %s name two machines, compilers or OpenSSL "
                  "versions, or widest ch_cfg.cpu values that differ in a bit a record reads, so "
                  "its column mixes two runs" % name)
            rc = 1
        elif line not in prose:
            print("lint-bench-numbers: docs/performance.md does not state %s as its CSVs do: %s"
                  % (name, line))
            rc = 1
    return rc | check_field(prose)


def main():
    table, lines = render()
    heads = [cell for name, _, _ in MACHINES
             for cell in ("%s, chapulin" % name, "%s, OpenSSL" % name, "ratio")]
    print("| %s | %s |" % (HEADER, " | ".join(heads)))
    print("|%s" % (" --- |" * (len(heads) + 1)))
    for label, cells in table:
        print("| %s | %s |" % (label, " | ".join(cells)))
    print()
    for _, line in lines:
        print("- %s" % line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
