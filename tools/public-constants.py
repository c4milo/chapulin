#!/usr/bin/env python3
"""Lists the lengths and caps one packaged object's public headers name,
and fails when a name is not defined for that object's consumer.

Usage: tools/public-constants.py CC HEADERS DEFINES

HEADERS is lib-headers.txt from build.zig's lib-lists step: the headers
the module "chapulin" is translated from, one per line. DEFINES is
lib-def.txt from the same step: the -D flags the object compiled with.

A public header documents a field or a buffer by the constant that sizes
it: srv_cfg.h says ticket_key points at CH_SRV_TICKET_KEY_LEN bytes. The
consumer has to be able to name that constant. At 8a813e2 the ticket
key's length lived in srv_ticket.h, which no public header includes,
so colibri's QUIC server could not size its ticket key through the Zig
module.

This runs the C preprocessor over the headers under the object's
defines, keeping comments, so only a comment in a region the object
compiles counts: a QUIC constant named inside #ifdef
CH_TRANSPORT_QUIC_NONBLOCKING is not required of a TCP object. A name
counts when it has the shape of a length or a cap (a suffix below) and
sits in a comment of a public header. The public headers are the ones
listed plus the four that declare ch_cfg and the types its members
take, which every public call takes. A named constant must be defined after the headers are included,
or the script fails and names it. Otherwise it prints each name, one
per line, and test/zig-consumer's matches.zig requires the module to
declare and evaluate each one.
"""

import collections
import pathlib
import re
import subprocess
import sys
import tempfile

# The headers that declare ch_cfg and its members, and the ones cfg.h
# includes under a mode's define. Every object's module includes them
# through the headers of its calls.
CONFIG_HEADERS = {"cfg.h", "quic_cfg.h", "srv_cfg.h", "ticket.h", "webpki_cfg.h"}

# The suffixes of a name that sizes something a caller allocates or
# fills in.
LENGTH = re.compile(r"\b([A-Z][A-Z0-9]*_[A-Z0-9_]*(?:_LEN|_MAX|_MIN|RXBUF))\b")

# A line marker the preprocessor writes: # LINE "FILE" FLAGS.
MARKER = re.compile(r'^# \d+ "([^"]+)"')


def comment_names(text, public):
    """Name -> the public headers whose active comments name it. The
    preprocessor keeps comments with -C, and a line marker says which
    file each following line came from."""
    named = collections.defaultdict(set)
    header = None
    in_block = False
    for line in text.splitlines():
        m = MARKER.match(line)
        if m:
            # The tree's headers come in as relative paths through -I.;
            # system headers and the generated source are absolute.
            path = pathlib.Path(m.group(1))
            header = None if path.is_absolute() else path.name
            continue
        comment = ""
        if in_block:
            end = line.find("*/")
            comment, in_block = (line, True) if end < 0 else (line[:end], False)
        elif "//" in line:
            comment = line[line.index("//"):]
        elif "/*" in line:
            start = line.index("/*")
            end = line.find("*/", start)
            comment, in_block = (line[start:], True) if end < 0 else (line[start:end], False)
        if header in public:
            for name in LENGTH.findall(comment):
                named[name].add(header)
    return named


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: tools/public-constants.py CC HEADERS DEFINES")
    cc, headers_path, defines_path = sys.argv[1:]
    headers = pathlib.Path(headers_path).read_text().split()
    defines = pathlib.Path(defines_path).read_text().split()
    public = set(headers) | CONFIG_HEADERS
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write("".join('#include "%s"\n' % h for h in headers))
        source = f.name
    flags = ["-std=c11", "-I."] + defines
    try:
        kept = subprocess.run([cc, "-E", "-C"] + flags + [source],
                              capture_output=True, text=True, check=True).stdout
        macros = subprocess.run([cc, "-E", "-dM"] + flags + [source],
                                capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit("public-constants: the headers do not preprocess:\n" + e.stderr)
    finally:
        pathlib.Path(source).unlink()
    defined = set(re.findall(r"^#define (\w+)", macros, re.M))
    named = comment_names(kept, public)
    missing = sorted(n for n in named if n not in defined)
    for name in missing:
        print("public-constants: %s names %s, which no header this object's consumer "
              "includes defines" % (" and ".join(sorted(named[name])), name), file=sys.stderr)
    if missing:
        return 1
    print("\n".join(sorted(named)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
