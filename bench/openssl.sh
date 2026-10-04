# shellcheck shell=bash
# The OpenSSL a bench times beside chapulin on the same machine.
# bench/record.sh and bench/primitives.sh source this file.
#
# openssl_find prints the binary test/e2e.sh takes, by the search that
# script runs, so a bench and the e2e suite use one OpenSSL: OPENSSL from
# the environment first, so a caller can name a build, then the first
# OpenSSL 3 on Homebrew's paths, then `openssl` on PATH. It prints nothing
# when none of them is an OpenSSL 3, and the caller then writes no OpenSSL
# row.
openssl_find() {
    local candidate
    for candidate in "${OPENSSL:-}" /opt/homebrew/opt/openssl@3/bin/openssl \
        /opt/homebrew/opt/openssl/bin/openssl /usr/local/opt/openssl/bin/openssl openssl; do
        [ -n "$candidate" ] || continue
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" version 2>/dev/null | grep -q '^OpenSSL 3'; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 0
}

# The name and version of the binary openssl_find printed, such as
# "OpenSSL 3.6.4": the build column of every row that binary fills.
openssl_label() { # $1 = the binary
    "$1" version | awk '{ print $1 " " $2 }'
}
