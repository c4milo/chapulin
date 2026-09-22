#!/usr/bin/env bash
# The catch target for the webpki-over-record link violation in
# test/violations/. test/violations.py runs a script by path with no
# arguments and reads its exit status, and a make target is not a path,
# so this is the path. It links the object from the sources on disk,
# which are the edited sources while a violation is applied; a nonzero
# exit is lib-check objecting.
#
# This is the one client object that compiles ch_record_init and no
# ch_connect, so it is the only leg that reports a ch_connect the webpki
# arm left unguarded: the compiled call imports the ch_handshake this
# variant leaves out (https://github.com/c4milo/chapulin/issues/171).
# The export list does not move, because the link localizes every symbol
# PUBLIC does not name, so the import check is what fails.
# tools/impact.py emits the same command for a source this object
# packages; the two have to stay the same command, and
# test/impact_test.py compares them.
cd "$(dirname "$0")/.." || exit 1
exec make -s lib-check RAND=extern TRUST=webpki TRANSPORT=record
