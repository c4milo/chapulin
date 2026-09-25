#!/usr/bin/env python3
"""Fail when Semgrep could not parse a file that lint-invariants scanned.

Semgrep reports a parse failure as a warning and still exits 0, and no rule
checks what it did not parse. It dropped two whole files that way: srv.c,
whose srv_config_ok header was split across #if and #else, and
handshake_flight.c, which also put #ifdef inside argument lists. A
ch_rand_bytes call added to either passed INV-4's rules.

This reads the scan's --json-output file and fails on two things:

* Any error other than a partial parse. A whole-file "Syntax error" is the
  case above; a timeout or a lexer failure hides a file from a rule the
  same way.
* A partial parse of a file PARTIAL does not list. Semgrep skips the span it
  cannot parse and reads the rest, so a call inside the span is invisible.

PARTIAL holds the files that parsed only in part when this check landed,
each with the construct that makes Semgrep skip a span. An entry goes when
its file is reshaped: a listed file that parses whole fails as stale, so
the list only shrinks.

What it does not catch:

* A new skipped span inside a file PARTIAL lists. The entry covers the
  file, not a count of its spans.
* A file Semgrep never parsed. Semgrep skips a file that holds none of the
  identifiers a rule names, and a file with no such identifier has no call
  for a rule to find either.
"""
import json
import sys

PARTIAL = {
    "handshake_auth.c": "hsa_server_auth closes and hsa_read_certificate_verify "
    "opens inside one #if arm",
    "handshake_message.c": "#ifdef inside hs_build_client_hello's parameter list",
    "handshake_message.h": "#ifdef inside hs_build_client_hello's parameter list",
    "handshake_parser.c": "#ifdef inside hsp_parse_certificate_verify's parameter list",
    "handshake_parser.h": "#ifdef inside the parameter lists of hsp_parse_encrypted_exts "
    "and hsp_parse_certificate_verify",
    "handshake_parser_ee.c": "#ifdef inside hsp_parse_encrypted_exts's parameter list",
    "handshake_post.c": "#ifdef inside handle_ticket's parameter list",
}


def spans(error):
    return ", ".join(
        f"{s['start']['line']}-{s['end']['line']}" for s in error["type"][1] if "start" in s
    )


def main(path):
    try:
        with open(path, encoding="utf-8") as f:
            errors = json.load(f)["errors"]
    except (OSError, ValueError, KeyError) as e:
        print(f"lint-invariants: no scan result to read in {path}: {e}")
        return 1
    rc = 0
    reported = set()
    for error in errors:
        kind = error.get("type")
        where = error.get("path", "(no path)")
        reported.add(where)
        if isinstance(kind, list) and kind[0] == "PartialParsing":
            if where not in PARTIAL:
                print(
                    f"lint-invariants: semgrep parsed {where} only in part and no rule "
                    f"checked lines {spans(error)}; reshape them (tools/semgrep-parse.py)"
                )
                rc = 1
            continue
        print(f"lint-invariants: semgrep reported {kind} in {where}, so no rule checked it")
        rc = 1
    for name in sorted(set(PARTIAL) - reported):
        print(
            f"lint-invariants: {name} now parses whole; drop its PARTIAL entry "
            f"in tools/semgrep-parse.py"
        )
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
