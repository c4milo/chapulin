#!/usr/bin/env python3
"""The sources some packaged object compiles, asked of make.

tools/proof-cover.py holds each of these sources to a full harness or an
audit (INV-47), and tools/impact_map.py selects that lint for a change to
any of them. Both import the set from here, so both read the same builds.
The impact tool once read the legs check builds instead, and the plan for
srv_quic.c ran no lint-proof-cover.
"""

import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The builds whose packaged sources make prints through print-lib-srcs. Each
# names every variable that picks a source, and HOST_TARGET too, so each reads
# the same on every compiler. Between them they take every value of ROLE,
# TRUST, TRANSPORT, SUITE, KEX, AES, RAND and the host test that some build
# accepts, and the union of their lists is every source an accepted build
# packages. A host object takes no AES or KEX value, so the last three name
# neither. EXPORTER, KEYLOG, TX_RECORD and WIDEMUL change defines and no
# source, so each build takes their defaults. A source that a later build
# packages under a combination this list lacks is a root .c file outside the
# union, and tools/proof-cover.py fails it until a build here packages it.
BUILDS = [
    "ROLE=client TRUST=raw-rsa TRANSPORT=tcp-blocking SUITE=chacha KEX=x25519 AES=soft "
    "RAND=drbg HOST_TARGET=",
    "ROLE=client TRUST=raw-ecdsa TRANSPORT=tcp-nonblocking SUITE=chacha KEX=pq AES=soft "
    "RAND=extern HOST_TARGET=",
    "ROLE=client TRUST=ca-rsa TRANSPORT=quic-nonblocking SUITE=chacha KEX=x25519 AES=soft "
    "RAND=session HOST_TARGET=",
    "ROLE=client TRUST=ca-ecdsa TRANSPORT=quic-nonblocking SUITE=chacha KEX=pq AES=extern "
    "RAND=drbg HOST_TARGET=",
    "ROLE=both TRUST=webpki TRANSPORT=quic-nonblocking SUITE=aesgcm RAND=drbg HOST_TARGET=yes",
    "ROLE=server TRUST=none TRANSPORT=tcp-blocking SUITE=aesgcm RAND=drbg HOST_TARGET=yes",
    "ROLE=server TRUST=none TRANSPORT=tcp-nonblocking SUITE=aesgcm RAND=drbg HOST_TARGET=yes",
]

# make passes the variables its own command line set to every make below it,
# in MAKEFLAGS. Left there, `make check TX_RECORD=16384` would hand its value to
# the QUIC builds above, which refuse it, and an AES value would stop the host
# builds. So the builds run with those variables cleared, and each reads only
# the values it names.
MAKE_ENV = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}

# A quoted include of a .c file: one source compiling another's text.
INCLUDED_SOURCE = re.compile(r'^[ \t]*#[ \t]*include[ \t]+"([^"/]+\.c)"', re.M)


def packaged(build):
    """What print-lib-srcs prints for one build: the build, make's exit
    status, the sources and make's error output."""
    r = subprocess.run(["make", "-s", "--no-print-directory", "-f", "Makefile", "print-lib-srcs",
                        *build.split()], cwd=ROOT, env=MAKE_ENV, capture_output=True, text=True)
    return build, r.returncode, {w for w in r.stdout.split() if w.endswith(".c")}, r.stderr.strip()


def shipped_sources(caller):
    """Every source a build in BUILDS packages, and every source whose text
    one of those includes. print-lib-srcs names the files make compiles, so
    it names poly1305_vector_native.c and never poly1305_vector.c, whose
    text that file includes. make cannot answer for an include, so this
    reads the includes rather than keeping a list of them by hand.

    A build whose make fails stops the program, and the message starts with
    caller: a set without that build's sources would be short, and nothing
    would say so."""
    with ThreadPoolExecutor(len(BUILDS)) as pool:
        results = list(pool.map(packaged, BUILDS))
    out = set()
    for build, status, sources, error in results:
        if status != 0:
            sys.exit(f"{caller}: make print-lib-srcs {build} failed, so the sources "
                     f"that build packages are unknown:\n{error}")
        out |= sources
    out = {s for s in out if (ROOT / s).exists()}
    pending = sorted(out)
    while pending:
        for name in INCLUDED_SOURCE.findall((ROOT / pending.pop()).read_text()):
            if name not in out and (ROOT / name).exists():
                out.add(name)
                pending.append(name)
    return out
