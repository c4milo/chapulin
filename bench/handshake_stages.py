#!/usr/bin/env python3
"""Splits one counted TLS connection into the stages bench/handshake-n2.sh reports.

The connection is the window bench/handshake_window.h describes: a
handshake part, the instructions from bench_window_open to
bench_window_handshake, and an exchange part, from there to
bench_window_close. Each stage of the handshake is the work under a set
of named functions, its roots (ROOTS below). An instruction belongs to
the outermost root on the call stack when it runs, so the HMAC inside a
signature's nonce counts toward the signature and not toward the key
schedule. The handshake's instructions under no root are its
certificate, its other messages and their records.

Two modes read two tools' output:

  trace BINARY OPEN_ADDRESS COUNTED  reads a QEMU user-mode exec log on
      stdin, one instruction a line (-one-insn-per-tb -d exec,nochain).
      It rebuilds the call stack from the binary's bl and blr addresses,
      which objdump lists, and the return addresses those calls push.
      OPEN_ADDRESS is where the server printed bench_window_open, which
      places the binary; COUNTED is which window it splits, 1 for the
      first.
  callgrind FILE  reads a callgrind.out file of a run under
      --toggle-collect=bench_counted and prints the inclusive cost of the
      functions INCLUSIVE_ROWS names, for the rows whose roots no other
      root calls.

Each mode prints one line per row it counts, NAME VALUE, in the order of
ROWS.
"""
import bisect
import collections
import re
import subprocess
import sys

# The rows, in the order docs/performance.md's table holds them.
ROWS = [
    "x25519_keygen",
    "x25519_shared",
    "sign",
    "sign_base_mul",
    "sign_nonce",
    "sign_rest",
    "key_schedule",
    "transcript",
    "messages",
    "handshake",
    "exchange",
    "memset",
    "c_library",
]

# Two more rows cross the stages: the handshake's instructions in the
# image's own memset, which Zig links from its compiler_rt, and those in
# the C library, outside the binary. A row a mode cannot count, it omits.

# Each stage's roots: exact names, then name prefixes. chapulin's names
# come from its sources, and OpenSSL's are the EVP calls libssl makes,
# which both releases export, so a stripped libcrypto names them too.
ROOTS = {
    "x25519_keygen": (
        {"x25519_wide_base", "x25519_base", "EVP_PKEY_keygen", "EVP_PKEY_generate",
         "EVP_PKEY_keygen_init"},
        (),
    ),
    "x25519_shared": (
        {"x25519_wide", "x25519", "EVP_PKEY_derive", "EVP_PKEY_derive_init",
         "EVP_PKEY_derive_init_ex", "EVP_PKEY_derive_set_peer", "EVP_PKEY_derive_set_peer_ex",
         "EVP_PKEY_set1_encoded_public_key"},
        (),
    ),
    "sign": (
        {"p256_sign_cpu", "p256_sign", "EVP_DigestSign", "EVP_DigestSignInit",
         "EVP_DigestSignInit_ex", "EVP_DigestSignUpdate", "EVP_DigestSignFinal"},
        (),
    ),
    "key_schedule": (
        {"EVP_Q_mac", "HMAC", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final"},
        ("ks_", "hkdf_", "hmac", "EVP_KDF_", "EVP_MAC_"),
    ),
    # The transcript hashes, and two more SHA-256 calls of chapulin's: the
    # CertificateVerify signed content, and the ClientHello digest that
    # srv_parse_client_hello computes for each hello (client_hello.frozen).
    # The sha256_ prefix makes that digest a root of this row.
    "transcript": (
        {"hsr_transcript_hash", "hsr_restart_transcript", "srv_hash_signed_content",
         "EVP_DigestUpdate", "EVP_DigestFinal", "EVP_DigestFinal_ex", "EVP_DigestInit",
         "EVP_DigestInit_ex", "EVP_DigestInit_ex2", "EVP_MD_CTX_copy", "EVP_MD_CTX_copy_ex",
         "EVP_Digest"},
        ("transcript_", "sha256_", "sha384_", "sha512_"),
    ),
}

# The parts of a signature: the outermost part root under the signature's
# root. k·G is chapulin's table or ladder and OpenSSL's EC_POINT_mul. The
# nonce is RFC 6979's HMAC-SHA-256 for chapulin, with the generator's own
# functions that p256_sign.c keeps out of line (generator_), and the call
# that draws k for OpenSSL. The rest is the inversions, the scalar arithmetic and the
# DER, and for OpenSSL also the digest of the signed content and the EVP
# calls around the signature.
PARTS = {
    "sign_base_mul": (
        {"p256_wide_base_mul", "p256_point_base_mul", "ecp_nistz256_points_mul",
         "ecp_nistz256_point_mul", "EC_POINT_mul"},
        (),
    ),
    "sign_nonce": (
        {"ossl_bn_gen_dsa_nonce_fixed_top", "bn_gen_dsa_nonce_fixed_top",
         "BN_generate_dsa_nonce", "ossl_gen_deterministic_nonce_k"},
        ("hmac", "sha256_", "generator_"),
    ),
}

# The handshake's and the exchange's calls under each server.
HANDSHAKE_CALL = "bench_handshake"
EXCHANGE_CALL = "bench_exchange"


def label_of(name, table):
    """The key of table whose names or prefixes hold name, or None."""
    for label, (names, prefixes) in table.items():
        if name in names or name.startswith(prefixes):
            return label
    return None


def finish(handshake, exchange, stages, parts, extra):
    """Prints the rows from the two windows, the stages' sums and the rows
    in extra."""
    rows = {name: stages.get(name, 0) for name in ROOTS}
    sign = rows["sign"]
    rows["sign_base_mul"] = parts.get("sign_base_mul", 0)
    rows["sign_nonce"] = parts.get("sign_nonce", 0)
    rows["sign_rest"] = sign - rows["sign_base_mul"] - rows["sign_nonce"]
    rows["messages"] = handshake - sum(stages.get(name, 0) for name in ROOTS)
    rows["handshake"] = handshake
    rows["exchange"] = exchange
    rows.update(extra)
    for name in ROWS:
        if name in rows:
            print(f"{name} {rows[name]}")


# ---- trace mode -------------------------------------------------------


def symbols(binary):
    """The binary's functions as sorted starts, ends and names (nm -S)."""
    out = subprocess.run(["nm", "-S", "--defined-only", binary], check=True,
                         capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in "tTwW":
            start = int(fields[0], 16)
            found.append((start, start + int(fields[1], 16), fields[3]))
    found.sort()
    return [f[0] for f in found], [f[1] for f in found], [f[2] for f in found]


CALL = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{8}\s+)?(bl|blr)\s")


def call_sites(binary):
    """The addresses of the binary's bl and blr instructions."""
    out = subprocess.run(["objdump", "-d", binary], check=True, capture_output=True,
                         text=True).stdout
    return {int(m.group(1), 16) for m in map(CALL.match, out.splitlines()) if m}


def trace(binary, open_address, counted):
    starts, ends, names = symbols(binary)
    by_name = {name: start for start, name in zip(starts, names)}
    delta = open_address - by_name["bench_window_open"]
    starts = [s + delta for s in starts]
    ends = [e + delta for e in ends]
    calls = {c + delta for c in call_sites(binary)}
    open_pc = by_name["bench_window_open"] + delta
    handshake_pc = by_name["bench_window_handshake"] + delta
    close_pc = by_name["bench_window_close"] + delta

    def name_at(pc):
        i = bisect.bisect_right(starts, pc) - 1
        return names[i] if i >= 0 and pc < ends[i] else None

    seen = 0
    stream = sys.stdin.buffer
    marker = b"/%016x/" % open_pc
    for line in stream:
        if marker in line and int(line.split(b"/", 2)[1], 16) == open_pc:
            seen += 1
            if seen == counted:
                break
    if seen != counted:
        sys.exit(f"handshake_stages: the trace holds {seen} windows, not {counted}")

    # The first instruction of each root, which a tail call reaches with a
    # branch that pushes no frame.
    entries = {}
    for start, name in zip(starts, names):
        if label_of(name, ROOTS) is not None or label_of(name, PARTS) is not None:
            entries[start] = name
    low, high = starts[0], ends[-1]
    memset_at = by_name.get("memset")
    memset_end = ends[starts.index(memset_at + delta)] if memset_at is not None else 0
    memset_at = memset_at + delta if memset_at is not None else 0

    # Each frame: its return address, its stage, its part and the function
    # that called it. The stage of an instruction is the outermost frame's
    # stage; its part, the outermost part under the signature.
    stack = []
    returns = collections.Counter()
    stage = None
    part = None
    pending = None  # the return address of a call whose callee comes next
    caller = None  # the function that made that call
    window = "handshake"
    counts = collections.Counter()
    at = collections.Counter()  # (stage, pc) -> instructions, for the report
    outside = collections.Counter()  # (stage, caller) -> C library instructions
    entered = collections.Counter()
    depth_max = 0
    in_memset = 0

    def labels(name, stage, part):
        """The stage and part of a frame of name under a frame of stage and part."""
        if stage is None:
            stage = label_of(name, ROOTS)
            if stage is not None:
                entered[name] += 1
        elif stage == "sign" and part is None:
            part = label_of(name, PARTS)
            if part is not None:
                entered[name] += 1
        return stage, part

    for line in stream:
        if not line.startswith(b"Trace"):
            continue
        pc = int(line.split(b"/", 2)[1], 16)
        if pending is not None:
            name = name_at(pc)
            frame_stage, frame_part = (stage, part) if name is None else labels(name, stage, part)
            stack.append((pending, frame_stage, frame_part, caller))
            returns[pending] += 1
            depth_max = max(depth_max, len(stack))
            stage, part = frame_stage, frame_part
            pending = None
        elif returns[pc]:
            while stack:
                ret = stack.pop()[0]
                returns[ret] -= 1
                if ret == pc:
                    break
            stage, part = (stack[-1][1], stack[-1][2]) if stack else (None, None)
        elif pc in entries and stack:
            # A tail call: the callee takes the caller's frame.
            stage, part = labels(entries[pc], stage, part)
            ret, _, _, frame_caller = stack[-1]
            stack[-1] = (ret, stage, part, frame_caller)
        if pc == handshake_pc:
            window = "exchange"
        elif pc == close_pc:
            break
        counts[(window, stage, part)] += 1
        if window == "handshake":
            if low <= pc < high:
                at[(stage, pc)] += 1
                if memset_at <= pc < memset_end:
                    in_memset += 1
            else:
                outside[(stage, stack[-1][3] if stack else None)] += 1
        if pc in calls:
            pending = pc + 4
            caller = name_at(pc)
    handshake = sum(v for (w, _, _), v in counts.items() if w == "handshake")
    exchange = sum(v for (w, _, _), v in counts.items() if w == "exchange")
    stages = collections.Counter()
    parts = collections.Counter()
    for (w, s, p), v in counts.items():
        if w == "handshake" and s is not None:
            stages[s] += v
            if p is not None:
                parts[p] += v
    # The server writes the rest of its run to the pipe, and stops when
    # no one reads it.
    for _ in stream:
        pass
    for name, n in sorted(entered.items()):
        print(f"# entered {name} {n}", file=sys.stderr)
    print(f"# deepest stack {depth_max}", file=sys.stderr)
    # The functions that ran the most instructions of each stage, the
    # instructions of the function itself and of no call it makes. The C
    # library's are named by the function in the binary that called it.
    by_function = collections.Counter()
    for (s, pc), v in at.items():
        by_function[(s or "messages", name_at(pc) or "(no symbol)")] += v
    for (s, c), v in outside.items():
        by_function[(s or "messages", f"C library, called from {c}")] += v
    for label in list(ROOTS) + ["messages"]:
        top = sorted(((v, f) for (s, f), v in by_function.items() if s == label), reverse=True)
        for v, f in top[:12]:
            print(f"# {label} {f} {v}", file=sys.stderr)
    finish(handshake, exchange, stages, parts,
           {"memset": in_memset, "c_library": sum(outside.values())})


# ---- callgrind mode ---------------------------------------------------

NAMED = re.compile(r"^\((\d+)\)(?: (.*))?$")

# The functions whose inclusive cost is a row in callgrind mode. callgrind
# keeps no call stacks, so this mode prints the rows whose roots no other
# root of the run calls, and leaves out the key schedule, the transcript
# and the nonce, whose hashes the signature runs too.
INCLUSIVE_ROWS = {
    "x25519_keygen": ("x25519_wide_base", "x25519_base"),
    "x25519_shared": ("x25519_wide", "x25519"),
    "sign": ("p256_sign_cpu", "p256_sign"),
    "sign_base_mul": ("p256_wide_base_mul", "p256_point_base_mul"),
    "handshake": (HANDSHAKE_CALL,),
    "exchange": (EXCHANGE_CALL,),
}


def callgrind(path):
    """Prints each row of INCLUSIVE_ROWS that the run holds: the cost of its
    functions and of every call they make, and the cost of memset itself."""
    names = {}

    def resolve(value):
        m = NAMED.match(value)
        if not m:
            return value
        if m.group(2) is not None:
            names[m.group(1)] = m.group(2)
        return names[m.group(1)]

    own = collections.Counter()  # function -> instructions of its own
    calls = collections.Counter()  # function -> instructions of the calls it makes
    function = callee = None
    after_calls = False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if after_calls:
                after_calls = False
                fields = line.split()
                if callee != function and len(fields) > 1:
                    calls[function] += int(fields[1])
            elif line.startswith("fn="):
                function = resolve(line[3:].rstrip("\n"))
            elif line.startswith("cfn="):
                callee = resolve(line[4:].rstrip("\n"))
            elif line.startswith("calls="):
                after_calls = True
            elif line[:1].isdigit() or line[:1] in "+-*":
                fields = line.split()
                if len(fields) > 1 and function is not None:
                    own[function] += int(fields[1])
    seen = set(own) | set(calls)
    for row in ROWS:
        held = [fn for fn in INCLUSIVE_ROWS.get(row, ()) if fn in seen]
        if held:
            print(f"{row} {sum(own[fn] + calls[fn] for fn in held)}")
        elif row == "memset" and "memset" in seen:
            print(f"memset {own['memset']}")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "trace":
        trace(sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4]))
    elif len(sys.argv) == 3 and sys.argv[1] == "callgrind":
        callgrind(sys.argv[2])
    else:
        sys.exit("usage: handshake_stages.py trace BINARY OPEN_ADDRESS COUNTED < LOG\n"
                 "       handshake_stages.py callgrind CALLGRIND_OUT")


if __name__ == "__main__":
    main()
