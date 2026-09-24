# Web PKI corpus keys

The private keys `test/gen_webpki_corpus.py` mints its chains under. They
are test fixtures and protect nothing: the leaves over them name
`s3.example.test`, `*.example.test` or `*.com`, the CA certificates name
themselves `Corpus ...`, and nothing outside `test/webpki_corpus.h` trusts
them.

The keys live in the tree so that the header is stable. With the keys fixed, the
dates fixed, the serials fixed and RFC 6979 nonces for ECDSA
(`openssl x509 -sigopt nonce-type:1`), a run reproduces
`test/webpki_corpus.h` byte for byte. The generator mints a key file only
when it is missing, with

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:<bits> -out keys/<label>.pem
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:<curve> -out keys/<label>.pem

and prints that it did. Delete a file and run `make webpki-corpus` to
re-key; every certificate over that key changes, and so does the header.

| file | key | role |
| --- | --- | --- |
| `root_aws_rsa2048.pem` | RSA-2048 | the aws shape's anchor |
| `root_cross_rsa2048.pem` | RSA-2048 | cross-signs the aws root, as Starfield does Amazon Root CA 1 |
| `root_gcs_rsa4096.pem` | RSA-4096 | the gcs shape's anchor, as GTS Root R1 |
| `root_p384.pem` | P-384 | the r2 and letsencrypt shapes' anchor |
| `impostor_p384.pem` | P-384 | an anchor carrying the P-384 root's Name over this other key |
| `int_aws_rsa2048.pem` | RSA-2048 | the aws intermediate, and the short-validity intermediate over the same key |
| `int_aws_rsa2048_v2.pem` | RSA-2048 | the aws intermediate's new key, certified under the old one |
| `int_gcs_rsa2048.pem` | RSA-2048 | the gcs intermediate |
| `int_r2_p256.pem` | P-256 | the r2 intermediate, and its constrained, non-CA and alias variants |
| `int_le1_p384.pem` | P-384 | the letsencrypt intermediate below the other |
| `int_le2_p384.pem` | P-384 | the letsencrypt intermediate under the anchor |
| `leaf_rsa2048.pem` | RSA-2048 | the aws leaf and its variants |
| `leaf_rsa1024.pem` | RSA-1024 | the leaf below the modulus floor |
| `leaf_p256.pem` | P-256 | every ECDSA leaf, and the key a test server signs with when it presents the r2 chain (`webpki_corpus_server_priv`) |

The corpus dates: leaves run 2026-01-01T00:00:00Z to
2026-12-31T23:59:59Z, CA certificates 2025-01-01T00:00:00Z to
2040-12-31T23:59:59Z, and `now_seconds` is 2026-07-01T00:00:00Z unless a
row moves it to a boundary. One intermediate, `int_aws_rsa2048_short`,
runs 2026-03-01T00:00:00Z to 2026-09-30T23:59:59Z, inside the leaf
window, so the four issuer validity rows move only its verdict.
`test/gen_webpki_corpus.py` prints the epoch values on every run.
