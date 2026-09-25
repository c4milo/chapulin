#!/bin/bash
# Proves the OpenSSL on PATH is the pinned one and can issue what e2e.sh
# needs. Not just a version check: it mints a certificate the way e2e.sh
# does and reads the date back. A toolchain that cannot issue is how this
# broke before, and the failure was silent.
set -euo pipefail

command -v openssl
openssl version
tmp=$(mktemp -d)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/k.pem"
openssl req -new -key "$tmp/k.pem" -subj /CN=probe -out "$tmp/r.csr"
openssl x509 -req -in "$tmp/r.csr" -signkey "$tmp/k.pem" \
    -not_before 000103000000Z -not_after 491231235959Z \
    -sha256 -out "$tmp/c.pem"
openssl x509 -in "$tmp/c.pem" -noout -startdate |
    grep -q "Jan  3 00:00:00 2000" ||
    { echo "the pinned OpenSSL did not honour -not_before"; exit 1; }
openssl s_server -help 2>&1 | grep -q -- -enable_server_rpk ||
    { echo "the pinned OpenSSL's s_server has no -enable_server_rpk"; exit 1; }
echo "issued a certificate at an absolute notBefore, and s_server offers raw public keys"
