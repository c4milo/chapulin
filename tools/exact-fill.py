#!/usr/bin/env python3
"""Check that every reader over a sliced container compares what is left to something.

A reader that decodes a container's fields and never checks what is left
accepts a trailing byte inside the container, so two encodings name one value.
Two reviews caught that shape in three files at once. This turns the
rule into a check: a function that builds an rbuf over a slice with
`rb_init(&r, ...)` must also compare `rb_left(&r)` for equality -- a closing
`rb_left(&r) == 0` or `!= 0`, or a header equality such as
`len != rb_left(&r)` -- or carry an entry in ALLOWED or WALKED below saying
where its exact-fill check lives instead.

WALKED is the one exception to that: a reader whose loop runs until the
reader is empty and whose every failure returns has consumed the container by
the time it succeeds, and there is no length of its own to compare. The tool
holds such an entry to that shape -- the body must carry the
`while (rb_left(&r) > 0)` loop -- so a reader that stops walking stops
matching and is reported again.

The equality is the whole point. `while (rb_left(&r) > 0)` walks a list and
`if (rb_left(&r) > 0)` guards an optional field; neither says anything about
whether the fields fill the container, and every list reader in the tree has
one. Accepting any mention of `rb_left` let a deleted `list_len !=
rb_left(&w)` sit beside a surviving `while (rb_left(&w) > 0)` and pass.

What it catches: a reader landed with no exact-fill check at all, which is the
drift those three files had; a reader whose only `rb_left` is a loop condition
or an optional-field guard; and a check written against a different reader than
the one it opened.

What it does not catch:

* The removal of one of several equality checks on one rbuf. `read_rsa_key`
  checks that the RSAPublicKey SEQUENCE fills the BIT STRING and again that
  the two INTEGERs fill the SEQUENCE; delete either and the other still
  answers this lint. Those readers are held by the boundary pairs in
  `test/webpki_spki_test.c` and `test/webpki_cert_mutants.h`, and by the
  `inv05-webpki-*` mutants that require them to object.
* A check that is present and wrong -- `rb_left(&r) != 0` where `== 0` was
  meant, a check on a path the parser can skip, or a check that runs before
  the last field is read. It reads source text, so it knows nothing about
  which branch runs.
* A check that exists in only one `#ifdef` arm. Readers are keyed by file,
  function and reader name, so `x509_read_spki`'s two `rb_init(&s, body,
  len)` arms merge into one entry and a check in either arm answers for both.
  That merging is also why the reader count printed at the end is one below
  the tree's `rb_init` count.
* A container parsed straight off a pointer, which builds no rbuf for this to
  find. INV-25's rbuf rule is what keeps those from existing.

Run through `make lint-exact-fill`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Readers whose exact-fill check sits in another function: one this one
# calls, or the one that framed the same container before this runs. Each
# entry names that function and what it requires. Keys are file, function
# and reader; an entry that no longer matches a reader is an error, so a
# renamed reader is reported rather than silently exempt.
ALLOWED = {
    ("pem.c", "pem_decode_certificate", "r"): (
        "read_tail(&r) requires every byte after the END line to be a line "
        "terminator, so it consumes the rest or refuses it"
    ),
    ("webpki_pin.c", "webpki_path_pinned", "r"): (
        "it reads back the first path_entries entries of a list "
        "webpki_verify_chain accepted, and read_entries (WALKED below) "
        "framed that list to its end first. The entries after the path "
        "stay unread on purpose, because no pin may name them "
        "(webpki_pin.h), and a framing failure here returns 0"
    ),
}

# Readers that consume the container by walking it to its end. The loop
# condition is the statement: it runs until the reader is empty, and every
# failure inside it returns, so a success means the fields filled the
# container. Keys are file, function and reader, and the entry holds only
# while the loop is still there.
WALKED = {
    ("webpki.c", "read_entries", "r"): (
        "the loop runs while rb_left(&r) > 0 and every framing failure "
        "returns 0, so a success means the entries filled the list; the "
        "certificate bytes inside a trailing entry stay unparsed on purpose "
        "(docs/webpki.md, \"The chain walk\")"
    ),
    ("srv_parser.c", "srv_ext_duplicate", "r"): (
        "the loop runs while rb_left(&r) > 0 and every framing failure "
        "returns 0. It has no length of its own to compare: the block's "
        "exact fill is checked by its caller, srv_parse_client_hello, with "
        "exts_len != rb_left(&r) before this predicate runs. A duplicate "
        "returns 1 from inside the loop on purpose, because the duplicate "
        "is the whole answer and srv_parser.h says this predicate reaches "
        "no verdict about framing"
    ),
    ("srv_parser.c", "type_before", "r"): (
        "the loop runs while rb_left(&r) > 0 and every framing failure "
        "returns 0. Its container is a prefix of the extension block that "
        "srv_ext_duplicate cut on an extension boundary, so there is no "
        "length of its own to compare, and the block's exact fill was "
        "checked by srv_parse_client_hello before either ran"
    ),
}

READER = re.compile(r"\brb_init\(&(\w+)\s*,")


def walks_to_empty(body, reader):
    """True when the body loops until the reader is empty."""
    return re.search(r"while\s*\(\s*rb_left\(&%s\)\s*>\s*0\s*\)" % re.escape(reader), body) is not None


def checked(body, reader):
    """True when the body compares rb_left(&reader) for equality.

    Either order counts: `rb_left(&r) == 0` closes a reader and
    `len != rb_left(&r)` requires a header's length to fill it. A `>` or
    `>=` comparison does not count -- that is a list walk or an optional
    field, not a statement about the container being full.
    """
    call = re.escape(f"rb_left(&{reader})")
    return re.search(r"%s\s*[=!]=|[=!]=\s*%s" % (call, call), body) is not None


def strip_noise(text):
    """Blank out comments and string literals, keeping every byte offset."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif two == "/*":
            while i < n and text[i:i + 2] != "*/":
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for j in range(i, min(i + 2, n)):
                out[j] = " "
            i += 2
        elif text[i] in "\"'":
            quote = text[i]
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\":
                    out[i] = " "
                    i += 1
                if i < n:
                    if text[i] != "\n":
                        out[i] = " "
                    i += 1
            i += 1
        else:
            i += 1
    return "".join(out)


def functions(path):
    """Every top-level braced block in one file: name, body, first line number.

    A file-scope initializer is a block too. It declares no reader, so it
    costs one entry and no false report.
    """
    text = strip_noise(path.read_text())
    found, depth, start, anchor, signature = [], 0, 0, 0, ""
    for i, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start, signature = i, text[anchor:i]
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                name = re.findall(r"(\w+)\s*\(", signature)
                line = text.count("\n", 0, start) + 1
                found.append((name[-1] if name else "?", text[start:i + 1], line))
                anchor = i + 1
        elif char == ";" and depth == 0:
            anchor = i + 1
    return found


def problems_in(path):
    out, seen = [], set()
    for name, body, start in functions(path):
        for reader in READER.findall(body):
            key = (path.name, name, reader)
            seen.add(key)
            if checked(body, reader):
                continue
            if key in ALLOWED:
                continue
            if key in WALKED and walks_to_empty(body, reader):
                continue
            out.append(
                f"{path.name}:{start} {name} reads a container through rbuf "
                f"{reader} and never compares rb_left(&{reader}) for equality, "
                f"so bytes left inside the container pass unread. A "
                f"`rb_left(&{reader}) > 0` loop or guard is not that check. "
                f"Add the exact-fill check, or record where it lives in "
                f"tools/exact-fill.py."
            )
    return out, seen


def main():
    problems, seen, readers = [], set(), 0
    for path in sorted(ROOT.glob("*.c")):
        found, keys = problems_in(path)
        problems += found
        seen |= keys
        readers += len(keys)

    for table, name in ((ALLOWED, "ALLOWED"), (WALKED, "WALKED")):
        for key in sorted(set(table) - seen):
            problems.append(
                f"{name} names {key[0]} {key[1]}'s reader {key[2]}, which no "
                f"longer exists. Delete the entry or fix the name."
            )

    if problems:
        for p in problems:
            print(f"lint-exact-fill: {p}")
        return 1

    print(
        f"lint-exact-fill: {readers} sliced readers in the library, "
        f"{readers - len(ALLOWED) - len(WALKED)} checked in place, "
        f"{len(ALLOWED)} checked in another function, {len(WALKED)} walked to the end"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
