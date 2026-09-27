#!/usr/bin/env bash
# The catch target for the RAND=session import violation in
# test/violations/. test/violations.py runs a script by path with no
# arguments and reads its exit status, and a make target is not a path,
# so this is the path. It links the object from the sources on disk,
# which are the edited sources while a violation is applied; a nonzero
# exit is lib-check objecting.
#
# This is the RAND=session object that compiles every draw site, the
# client's and the server's, so a draw site that calls ch_rand_bytes
# makes the object import a hook no RAND=session image defines, and the
# counterpart of the RAND=extern import check fails (docs/decisions.md
# 77). tools/impact.py emits the same command for a source this object
# packages; the two have to stay the same command, and
# test/impact_test.py compares them.
cd "$(dirname "$0")/.." || exit 1
exec make -s lib-check RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking ROLE=both
