# Web PKI trust mode

`TRUST=webpki` verifies a server's certificate chain against trust anchors the
caller supplies, checks the chain's validity dates against a clock the caller
supplies, and checks the server's hostname against the leaf's
subjectAltName. It exists so a host-side client can reach a public endpoint —
an S3-compatible object store is the case it was built for.

It is the third trust mode, beside `TRUST=raw`, which pins the server's own
key, and `TRUST=ca`, which pins a CA key the chain must reach. Those two are
the device modes: they read no clock and no names, and this mode does not
change them. A `webpki` object needs a clock, a hostname and a receive buffer
far larger than a device carries, so it is not for a device.

This document states the profile, the bounds and — at the end, in its own
section — what the mode does not check. Read that section before deploying.

`docs/decisions.md` records why the mode exists at all, and the argument it
overturns. Entry 17 used to say public CAs were a non-goal for the whole
client; it now scopes that to the device modes.

## Status

Partly implemented. The build mode, the configuration below, the ClientHello
and the EncryptedExtensions reply are in the tree. The chain walk is not, so a
`TRUST=webpki` handshake fails closed at the Certificate message with
`internal_error` and `CH_EAUTH`. For the parts not yet in the tree, this
document is the design record and the plan of record.
Numbers marked *measured* come from a capture or a build. Numbers marked
*derived* come from a formula over measured inputs. Nothing here is an
estimate, and no number in this file is a substitute for `bench/sram.sh`.

## What a public chain actually looks like

Every bound below comes from these captures, taken 2026-09-15 and kept
under `test/webpki_captures/`. The point of recording them is that the
mode's caps are answers to measurements rather than round numbers.

| endpoint | entries | `Certificate` body | shape, leaf first |
| --- | --- | --- | --- |
| `s3.amazonaws.com` | 3 | 4419 B | RSA-2048 leaf (2104 B) ← Amazon RSA 2048 M04 ← Amazon Root CA 1, cross-signed by Starfield |
| `storage.googleapis.com` | 3 | 3791 B | P-256 leaf, sha256WithRSA ← WR2, RSA-2048 ← GTS Root R1, RSA-4096 |
| `r2.cloudflarestorage.com` | 3 | 2925 B | P-256 leaf, ecdsa-with-SHA256 ← WE1, P-256, ecdsa-with-SHA384 ← GTS Root R4, P-384 |
| `acme-v02.api.letsencrypt.org` | 4 | 3605 B | P-256 leaf, ecdsa-with-SHA384 ← YE2, P-384 ← Root YE, P-384 ← ISRG Root X2, P-384 |

Four facts follow, and each one drives a decision further down.

1. **The chain's links are signed by different algorithm families.** A P-256
   leaf sits under an RSA-2048 issuer at Google and under a P-384 issuer at
   Let's Encrypt. One object must therefore carry every verifier. This is why
   `CLAUDE.md`'s "never both in one library object" now scopes to raw and ca.
2. **Digest length and curve order disagree.** Let's Encrypt signs a P-256
   leaf with `ecdsa-with-SHA384`. Certificate signatures carry no
   curve-to-hash binding; only CertificateVerify does, in RFC 9846 §4.4.3. So
   ECDSA verification takes the leftmost `min(bitlen(n), bitlen(H))` bits per
   FIPS 186-4 §6.4, and a fixed 32-byte digest parameter cannot express it.
3. **Every chain ends in a certificate the client must not need.** Amazon
   sends its root cross-signed by Starfield; Google sends its roots
   cross-signed by GlobalSign. The walk therefore consults the anchors before
   it reads the next entry, and stops at the first anchor that both names the
   issuer and verifies the signature.
4. **A leaf carries more extensions, and a larger one, than the ca profile
   admits.** The S3 leaf has ten extensions and a subjectAltName value of
   roughly 700 bytes, against the ca profile's caps of eight and 256.

## Algorithms

Chain signatures, all of which the captures show in use:

| signature | where it appears |
| --- | --- |
| `sha256WithRSAEncryption`, PKCS#1 v1.5 | every AWS link; the GCS leaf and intermediate |
| `sha384WithRSAEncryption`, PKCS#1 v1.5 | issued, though absent from the captures |
| `ecdsa-with-SHA256` | the R2 leaf |
| `ecdsa-with-SHA384` | the Let's Encrypt links, the GTS root links |

Public keys: RSA 2048, 3072 and 4096 bit moduli, and ECDSA P-256 and P-384.
RSA-4096 is not optional — GTS Root R1 is a 4096-bit key, so a client that
refuses one cannot reach Google Cloud Storage.

RSA-PSS does not appear in a public chain and is not admitted for one. It
stays the CertificateVerify algorithm, where RFC 9846 requires it for an RSA
key. PKCS#1 v1.5 is admitted for certificate signatures and refused for
CertificateVerify, which RFC 9846 §4.4.3 forbids: `rsa_pkcs1_*` codepoints
appear in `signature_algorithms` for certificates only.

SHA-384 needs a SHA-512 core, so `sha512.[ch]` is new. It is packaged only in
a webpki object, the way `sha3.[ch]` is packaged only under `KEX=pq`.

### Refused, and why

- **SHA-1 in any signature.** Web PKI retired it in 2017.
- **Moduli below 2048 bits.**
- **P-521, brainpool, and every other curve.** Two curves cover the captures.
- **Ed25519.** No public CA issues it for TLS server authentication.

## Key exchange

The mode does not change the key exchange, and `docs/decisions.md` entry 12
stands: a build offers one group, never two. Build `KEX=pq TRUST=webpki` and
every connection uses X25519MLKEM768.

That is not a compromise for this use. Measured 2026-09-09 with an
ML-KEM-only offer, where a refusal is a `handshake_failure` alert and not a
silent fallback:

| endpoint | X25519MLKEM768 |
| --- | --- |
| `s3.amazonaws.com`, and `us-east-1`, `us-west-2`, `eu-central-1`, `ap-southeast-2`, `us-gov-west-1` | negotiates |
| `storage.googleapis.com`, `r2.cloudflarestorage.com`, `s3.filebase.com`, `play.min.io` | negotiates |
| Wasabi, Backblaze B2, DigitalOcean Spaces, Storj | refuses; accepts X25519, P-256, P-384 |

So a post-quantum build reaches every AWS region tried, and Google and
Cloudflare besides. Failing closed against the four that refuse is the
property entry 12 argues for: the threat is harvest-now-decrypt-later, and a
client that fell back would complete a classically protected session against
it. Reaching those four means building `KEX=x25519`, and accepting that.

Entry 12's own argument named one gap: "no part of the API reports which
exchange ran." Two fields close it. `ch_tls.group` reports the group the
ServerHello selected, and `ch_cfg.require_pq` fails the handshake when that
group is not `CH_GROUP_X25519MLKEM768`. Under `KEX=pq` the flag asserts a
build-time property at run time, which is what makes it worth having:
checkable rather than assumed.

## The chain walk

The order matters, and every step's failure is a distinct alert. `depth` is 0
at the leaf.

1. Read the `Certificate` message. Refuse a non-empty
   `certificate_request_context`.
2. Read entry 0 as the leaf. Refuse an entry over `CH_WEBPKI_CERT_MAX`.
3. Check the leaf's profile: version 3, a serial inside 20 value bytes, a
   subjectAltName present, `keyUsage` asserting `digitalSignature`,
   `extendedKeyUsage` asserting `id-kp-serverAuth`, `basicConstraints` not
   asserting CA, and no unrecognized critical extension.
4. Check the leaf's validity against `now_seconds`.
5. Match the hostname against the leaf's subjectAltName `dNSName` entries.
6. Then, for the certificate in hand at each depth:
   a. **Consult the anchors first.** For every anchor whose subject Name
      equals this certificate's issuer Name, byte for byte, verify this
      certificate's signature under that anchor's public key. On the first
      that verifies, the path is complete: stop, and read no further entry.
   b. Otherwise read the next entry as the issuer. If there is none, fail.
   c. Check the issuer's profile: `basicConstraints` critical and asserting
      CA, `keyUsage` asserting `keyCertSign`, a `pathLenConstraint` that
      admits the depth below it, and no unrecognized critical extension.
   d. Check the issuer's validity against `now_seconds`.
   e. Check that the issuer's subject Name equals this certificate's issuer
      Name, byte for byte.
   f. Verify this certificate's signature under the issuer's public key.
   g. Descend.

Step 6a is what makes the measured AWS flight cost two signature
verifications and leave the third entry unread, unparsed and unsized. It is
also what makes a root re-keyed under one Name work, because every anchor
naming the issuer is tried rather than only the first.

Trailing entries after the terminating certificate are ignored, not refused.
That reverses the ca profile deliberately, because a server may append
certificates the walk never needs — every captured chain does. A strictness
test pins the behaviour by replacing the trailing entry with invalid DER and
requiring success.

Name chaining alone never authorizes anything. An anchor whose subject Name
matches but whose key does not verify the signature fails, and the corpus
carries that case.

### Validity

`notBefore <= now_seconds <= notAfter`, both ends inclusive. RFC 5280
§4.1.2.5 makes `notAfter` the last instant of validity, not the first instant
of expiry, and treating the two ends alike is why the boundary tests can name
`notAfter` valid and `notAfter + 1` invalid.

The anchor's own dates are not read. An anchor is trusted because the caller
configured it, not because it carries a date, and a caller who ships an
expired root has a provisioning problem the client cannot see.

Dates are compared as a packed field-wise number rather than as a count of
seconds, so no comparison needs a division. `docs/proofs.md` records what a
division costs a formula: `pem.c`'s `x % 4` on a `size_t` became a 64-bit
division circuit and 73 minutes of symbolic execution, against 84 seconds for
`x & 3U`. Only the one routine that converts the caller's clock runs a
division, once per connection, outside any peer input.

### Hostnames

The reference name is checked for shape before anything is matched against
it: only `[A-Za-z0-9.-]`, no empty label, no leading or trailing dot, no
label over 63 bytes, no label that starts or ends with `-`, and a last label
that is not all digits, because RFC 6066 forbids an IP literal in
`server_name`.

That check is the whole defence against a leaf whose subjectAltName carries
`evil.example\0s3.amazonaws.com`. It is what guarantees the reference name
holds no NUL and no `*`, after which the matcher compares equal-length byte
ranges and a NUL in a presented name can only fail. It therefore has its own
invariant and its own mutant, because nothing else in the mode would notice
if it were removed.

The hyphen rule is the label rule of RFC 952 as RFC 1123 §2.1 amends it. A
label holds letters, digits and hyphens, and it starts and ends with a letter
or a digit. RFC 1123 allows a leading digit, which RFC 952 did not. So
`-a.b`, `a.b-`, `a-.b` and `a.-b` fail the check, and `a-b` and
`xn--abc.example` pass it. rustls-webpki refuses such a reference name the
same way. Go's `crypto/x509` checks only the start of a label: its
`validHostname` refuses a label that starts with `-` and accepts one that
ends with it.

The matcher applies no hyphen rule to a presented name. A presented label
that starts or ends with `-` matches only a reference label equal to it up to
case, and the check refuses a reference name that holds such a label.

Matching is `dNSName` only. There is no fallback to the subject common name,
which is the rule every modern client follows and which OpenSSL's
`-verify_hostname` does not — see the divergence table below.

The walk reads the tag and the length of every GeneralName entry, including
the entries after a match. The tag must be one of the nine DER identifier
bytes of the CHOICE arms in RFC 5280 §4.2.1.6 (`a0`, `81`, `82`, `a3`, `a4`,
`a5`, `86`, `87`, `88`), and the length must be minimal and inside the
SEQUENCE. Any other entry refuses the whole subjectAltName, even after a
match. The tag rule refuses the high-tag-number form, whose tag number
continues past the first byte. A reader that took one tag byte would read
the next byte as the length, and bytes inside that entry's content could
then be read as a `dNSName` entry and match.

A `dNSName` byte outside ASCII equals no byte of the reference name. That
entry does not match, and the subjectAltName is not refused for it.

A wildcard matches one label, in the leftmost position, as an entire label.
So `*.example.test` matches `s3.example.test`, and does not match
`example.test`, `a.b.example.test`, or anything under a name with fewer
labels than the pattern. There is no partial-label wildcard: `s3*.example`
matches nothing. A wildcard directly under a public suffix is refused.

The caller supplies an A-label. A hostname with non-ASCII bytes fails
`ch_connect`, and converting a U-label to punycode is the caller's job.

## Trust anchors

`ch_cfg.anchors` points at `ch_cfg.anchor_count` entries of
`ch_trust_anchor`. Each entry is a subject Name as its DER `Name` TLV
(`name`, `name_len`), and a public key as its DER `SubjectPublicKeyInfo`
(`spki`, `spki_len`). The caller embeds the roots it wants; nothing is
bundled, nothing is fetched, and the array is the whole trust boundary.

The rest of the configuration is the hostname and the clock:

- `ch_cfg.hostname` and `ch_cfg.hostname_len`: the ASCII hostname the
  leaf must name, sent as the ClientHello's `server_name`.
- `ch_cfg.now_seconds`: seconds since 1970-01-01T00:00:00Z. 0 means the
  caller never set the clock.

`ch_connect` returns `CH_EINVAL` before it sends a byte when:

- `anchor_count` is outside 1 to `CH_WEBPKI_ANCHOR_MAX`, or any entry has
  a NULL or empty `name` or `spki`;
- the hostname fails `webpki_hostname_ok`;
- `now_seconds` is 0;
- `psk`, `psk_len`, `psk_id`, `psk_id_len` or `resumption` is set;
- either `server_pubkey` slot, or its length, is set;
- an epoch callback is set;
- `buf_len` is under `CH_MIN_RXBUF`, 12,324 bytes in this mode.

`ch_trust_anchor`, `CH_WEBPKI_ANCHOR_MAX` and the five `ch_cfg` fields
exist only in a `TRUST=webpki` build, so the raw and ca objects keep the
`ch_cfg` and `ch_tls` layout they had before this mode. A raw or ca build
that sets one of the fields fails to compile. `chapulin.hpp` forwards the
three through `Config::anchors`, `Config::hostname` and
`Config::now_seconds`, which a raw or ca build does not declare either.

Measured anchor sizes, from the captures: 120 B for a P-384 key, 294 B for
RSA-2048, 550 B for RSA-4096.

`CH_WEBPKI_ANCHOR_MAX` is 12. The number is a measurement, not a round
figure. Amazon Trust Services is five roots — Amazon Root CA 1 through 4 plus
the legacy Starfield Services Root G2 — and AWS documents that an endpoint
may move between them without notice. Let's Encrypt needs two, ISRG Root X1
for RSA chains and X2 for ECDSA. Google Trust Services needs GTS Root R1 and
R4 for the GCS and R2 captures above. That is nine for the endpoints this
document measures, before a private CA is added, so a cap of four would
refuse AWS's own recommended set.

Any anchor may certify any name. The mode offers no per-anchor name
constraint, so an anchor's authority is total: configure only anchors whose
authority you accept over every name you will connect to.

## Bounds

Every cap and the measurement behind it. *Derived* means a formula over
measured inputs, and the formula is given.

| constant | value | where it comes from |
| --- | --- | --- |
| `CH_WEBPKI_CERT_MAX` | 3072 | measured: the largest captured certificate is the 2104 B S3 leaf |
| `CH_WEBPKI_CHAIN_MAX` | 3 | measured: the Let's Encrypt capture needs 3 (leaf, YE2, Root YE, then the ISRG Root X2 anchor); the other three need 2 |
| `CH_WEBPKI_FLIGHT_ENTRIES` | 4 | measured: Let's Encrypt sends 4 |
| `CH_TRUST_MIN_RXBUF` | 12324 B | derived: `4 * (3072 + 5) + 16` |
| `CH_WEBPKI_ANCHOR_MAX` | 12 | measured: 9 roots cover the four endpoints above |
| `CH_WEBPKI_EXT_COUNT_MAX` | 16 | measured: the S3 leaf carries 10 |
| `CH_WEBPKI_EXT_TLV_MAX` | 1024 | measured: the S3 leaf's subjectAltName value is roughly 700 B |
| `CH_HOSTNAME_MAX` | 253 | DNS's own limit |
| `CH_RSA_MODULUS_MAX` | 512 under webpki, 384 otherwise | measured: GTS Root R1 is RSA-4096 |

`CH_WEBPKI_CERT_MAX` leaves 46% margin over the largest certificate
measured. `CH_WEBPKI_CHAIN_MAX` of 3 admits one two-intermediate
hierarchy; each further entry is one more signature an unauthenticated
peer can force before any anchor is consulted, and one more certificate
in the formula least likely to converge.

The ClientHello this mode sends carries a `server_name` extension of up
to 262 bytes and five signature schemes, so its largest hello,
`CH_HELLO_MAX`, is 879 bytes, and 2,063 under `KEX=pq`. The session's
TX staging array, `CH_TX_STAGE`, grows to match. The PSK arm sets that
maximum even though this mode refuses a PSK, because the builder takes
any config; the hello `ch_connect` lets this mode send is 528 bytes, or
1,712 under `KEX=pq`.

`CH_WEBPKI_FLIGHT_ENTRIES` is sized separately from the walk, because a
server may append entries the walk never reads and every captured chain
does. `CH_TRUST_MIN_RXBUF` follows the formula `cfg.h` already uses for
the ca mode, widened from 2 entries to 4. That floor is the number that
puts this mode on a host; a device build stays at 512 bytes.

`CH_HOSTNAME_MAX` is DNS's own limit rather than something shorter. A
cap of 128 was considered and rejected: an S3 PrivateLink name of the
form `<bucket>.<vpce-id>-<az-id>.s3.<region>.vpce.amazonaws.com` reaches
roughly 127 bytes and exceeds 128 with a long region, and the failure
would be `CH_EINVAL` at `ch_connect`.

`CH_RSA_MODULUS_MAX` resolves to 384 under raw and ca, so those objects
do not change. Under webpki it widens `rsa_pss_verify`'s accepted domain
as well, which moves that function's CBMC bound and its Lean domain in
that build; the commit that makes the change carries both.

## What the mode does not check

Read this list as part of the profile, not as a list of future work.

- **No revocation.** No CRL, no OCSP, no OCSP stapling. A stolen server key
  authenticates until its certificate expires. Short certificate lifetimes
  are the whole mitigation, and the CA/Browser Forum is shortening them:
  ballot SC-081 takes the maximum to 200 days in March 2026, 100 days in
  March 2027 and 47 days in March 2029.
- **No Certificate Transparency.** SCTs are not read. The consequence differs
  from revocation's: mis-issuance by any anchor in the array is undetectable
  to this client, and CT is the only ecosystem control that would catch it.
  The CT poison extension is critical, so a precertificate is refused by the
  unknown-critical rule rather than by a rule of its own.
- **No name constraints, and no policy extensions.** `nameConstraints`,
  `policyConstraints`, `inhibitAnyPolicy` and `policyMappings` are refused
  when critical, because RFC 5280 requires refusing a critical extension a
  client cannot honour, and honouring them is substantial work. This is a
  real interop limit rather than a bug: a technically-constrained corporate
  sub-CA is required to carry critical `nameConstraints`, so this mode cannot
  verify a chain under one.
- **No PSK, and no resumption.** `TRUST=webpki` refuses `ch_cfg.psk` and
  `ch_cfg.resumption` at `ch_connect`. The reason is the hostname, not
  authentication: a resumed handshake authenticates the peer by the PSK, and
  the shipped modes fail closed when a server does not select an offered PSK,
  but nothing binds a ticket to the hostname it was issued for, so a resumed
  connection would skip the name check. Every webpki connection is a full
  handshake. NewSessionTicket is still parsed and exposed, an RFC 9846 MUST
  this client keeps; it simply cannot be presented back. Binding a ticket to
  a hostname is the future path, and it is an API change.
- **No clock-skew tolerance.** `now_seconds` is compared exactly. As
  certificate lifetimes shorten, a fleet whose clock drifts turns a soft
  failure into a hard one, so the caller owns keeping the clock right.
- **No leaf key pinning alongside the chain.** The mode verifies a chain or it
  does not. Pinning a leaf key as well as verifying the chain is a defence
  this design does not offer.
- **Nothing in the repository proves anything about a live endpoint.** Every
  test is hermetic against a local server, as every other suite in this tree
  is. The captures in this document were taken by hand and are recorded as
  fixtures; nothing in `make check` or `make check-slow` reaches the network.

## Where this profile is stricter than OpenSSL

`test/gen_webpki_corpus.py` runs every corpus chain through `openssl verify
-purpose sslserver -verify_hostname` as an oracle, and fails unless the
disagreements are exactly the seven it expects. openssl agrees on 17 of 24
chains. Six of the seven disagreements are rows where this mode refuses what
openssl accepts. Five of them are the table below: each is a rule that would
otherwise rot unnoticed, so each carries a `test/violations/` mutant.

| case | openssl | this mode | why |
| --- | --- | --- | --- |
| leaf with no subjectAltName | accepts | refuses | openssl falls back to the common name |
| `keyUsage` without `digitalSignature` | accepts | refuses | openssl admits `keyEncipherment` for `sslserver`; TLS 1.3 has no RSA key transport |
| SHA-1 signature | accepts | refuses | web PKI retired SHA-1 in 2017 |
| RSA-1024 leaf | accepts | refuses | below the modulus floor |
| critical `nameConstraints` | accepts | refuses | openssl implements them; this mode does not, and RFC 5280 requires refusing what it cannot honour |

The sixth is `leaf_asserts_ca`: the leaf's basicConstraints asserts CA, which
this mode refuses and openssl, under `-purpose sslserver`, does not read. The
seventh is the one row where openssl refuses what this mode accepts,
`not_after_boundary`: at `now_seconds` equal to `notAfter`, openssl's
`X509_cmp_time` reports the leaf expired, and this mode accepts it, as
"Validity" above states.

## Verification

What is proved, what is tested, and at what bounds. The README's rule holds
here: never overclaim.

- **Wycheproof.** Eight suites the new code owes, all present at the pinned
  `WYCHEPROOF_COMMIT`, so no new fetched input needs a hash:
  `rsa_signature_2048_sha256` (259 cases), `_3072_sha256` (259),
  `_4096_sha256` (258), `_2048_sha384` (258), `_4096_sha384` (259),
  `ecdsa_secp384r1_sha384` (504), `ecdsa_secp384r1_sha256` (472) and
  `ecdsa_secp256r1_sha512` (554). The last two are the guard for the
  digest-length rule: they are the cases where digest length and curve order
  disagree in each direction. Wycheproof's `rsa_signature_*` suites are
  PKCS#1 v1.5 verification suites, which is the operation this mode needs.
- **SHA-384 has no Wycheproof suite.** Wycheproof does not test plain hashes.
  Its vectors are RFC 6234 and NIST CAVP, and the README says so rather than
  letting "Wycheproof" imply coverage it does not have.
- **Lean spec and theorems.** Every new module gets a spec module, as all 23
  existing C modules do. `spec/` gains mathlib, which unblocks the arithmetic
  theorems `spec/CONTRACT.md` records as blocked: P-256, P-384, the RSA
  lemmas and the X25519 ladder invariants. mathlib v4.33.0 targets
  `leanprover/lean4:v4.33.0`, which `spec/lean-toolchain` already pins, so no
  toolchain moves. P-256 and P-384 theorems are in this work; the X25519 and
  RSA lemmas become newly possible and are filed separately rather than
  absorbed here.
- **Differential testing has an asymmetry worth stating.** Random inputs
  essentially never form a valid signature, so a differential run over
  signature verification exercises the reject path. The accept path rests on
  the Wycheproof vectors above. Hostname matching is the opposite case — a
  pure predicate over a small alphabet, where random sampling covers the
  space meaningfully — and it is where the differential effort goes.
- **CBMC.** A harness per module, at the module's real bound. Two are
  expected to be hard and are called out rather than promised: the
  certificate parser, whose ca-mode counterpart already records no verdict in
  25 minutes for a two-entry formula at 7.1 GB, and the name matcher, whose
  cost grows with roughly the cube of input length. Where a bound cannot be
  reached, the README states the partial bound that was reached.
- **Fixtures.** Two corpora, doing different jobs. The captured chains above
  carry real extension bulk and test the bounds. A generated corpus of 24
  chains — 7 positive (the four shapes above, one wildcard match and the two
  validity boundaries), 17 negative taking one rule each — is small, offline
  and deterministic, and tests the logic. `test/gen_webpki_corpus.py` renders
  both into exact RFC 9846 §4.4.2 `Certificate` message bytes, so a test feeds
  the parser what the wire would.
