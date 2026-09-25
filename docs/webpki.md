# Web PKI trust mode

`TRUST=webpki` verifies a server's certificate chain against trust anchors the
caller supplies, checks the chain's validity dates against a clock the caller
supplies, and checks the server's hostname against the leaf's
subjectAltName. It exists so a host-side client can reach a public endpoint —
an S3-compatible object store is the case it was built for.

It is the third trust mode, beside the raw modes, which pin the server's own
key, and the CA modes, which pin a CA key the chain must reach. It also takes
SPKI pins, and with them RFC 7250 raw public keys, for a DNS-over-TLS caller
(see "Raw public keys and SPKI pins"). Those two are
the device modes: they read no clock and no names, and this mode does not
change them. A `webpki` object needs a clock, a hostname and a receive buffer
far larger than a device carries, so it is not for a device.

This document states the profile, the bounds and — at the end, in its own
section — what the mode does not check. Read that section before deploying.

`docs/decisions.md` records why the mode exists at all, and the argument it
overturns. Entry 17 used to say public CAs were a non-goal for the whole
client; it now scopes that to the device modes.

## Status

Implemented. The build mode, the configuration below, the ClientHello, the
EncryptedExtensions reply, the ALPN negotiation, the certificate files and
the chain walk in `webpki.c` are all in the tree, and `handshake_auth.c` runs
the walk before it checks CertificateVerify against the leaf key the walk
copied out.
`test/e2e.sh` runs that handshake against a local `openssl s_server` over
a root, intermediate and leaf it mints for the run: the client verifies
the chain, and the four negative legs each fail closed with `CH_EAUTH`.
`test/e2e.sh` checks that return code and does not observe the alert;
`test/webpki_cert_test.c` and `test/webpki_chain_test.c` pin the alerts
`webpki.h`'s table names. No test here opens a network connection, and
the captures under `test/webpki_captures/` are the only bytes in this
tree a public endpoint ever sent.

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
   curve-to-hash binding; only CertificateVerify does, in RFC 9846 §4.3.3. So
   ECDSA verification takes the leftmost `min(bitlen(n), bitlen(H))` bits per
   FIPS 186-4 §6.4, and a fixed 32-byte digest parameter cannot express it.
3. **Every chain ends in a certificate the client must not need.** Amazon
   sends its root cross-signed by Starfield; Google sends its roots
   cross-signed by GlobalSign. The walk therefore consults the anchors before
   it reads the next entry, and stops at the first anchor that both names the
   issuer and verifies the signature.
4. **A leaf carries more extensions, and a larger one, than the ca profile
   admits.** The S3 leaf has ten extensions, and its subjectAltName Extension
   TLV is 653 bytes, of which the extnValue is 640. The ca profile caps them
   at eight extensions and a 256-byte Extension TLV.

## Algorithms

Chain signatures, all of which the captures show in use:

| signature | where it appears |
| --- | --- |
| `sha256WithRSAEncryption`, PKCS#1 v1.5 | every AWS link; the GCS leaf and intermediate |
| `sha384WithRSAEncryption`, PKCS#1 v1.5 | issued, though absent from the captures |
| `ecdsa-with-SHA256` | the R2 leaf |
| `ecdsa-with-SHA384` | the Let's Encrypt links, the GTS root links |

Public keys: RSA 2048, 3072 and 4096 bit moduli, and ECDSA P-256 and P-384.
An RSA `publicExponent` must be 65537: `webpki_spki.c` compares its DER
bytes against that one encoding and refuses every other value.
RSA-4096 is not optional — GTS Root R1 is a 4096-bit key, so a client that
refuses one cannot reach Google Cloud Storage.

RSA-PSS does not appear in a public chain and is not admitted for one. It
stays the CertificateVerify algorithm, where RFC 9846 requires it for an RSA
key. PKCS#1 v1.5 is admitted for certificate signatures and refused for
CertificateVerify, which RFC 9846 §4.3.3 forbids: `rsa_pkcs1_*` codepoints
appear in `signature_algorithms` for certificates only.

CertificateVerify carries one scheme, and the leaf key's family decides which:
`rsa_pss_rsae_sha256` for an RSA key, `ecdsa_secp256r1_sha256` for P-256 and
`ecdsa_secp384r1_sha384` for P-384 (RFC 9846 §4.5.2).
`check_certificate_verify` in `handshake_auth.c` refuses every other pairing
with `illegal_parameter`, and verifies the signature that passes under that
family's own verifier. The P-384 scheme is the one place in this client where
the signed content takes SHA-384; the transcript hash inside that content stays
32 bytes, because the cipher suite fixes it. `test/webpki_auth_test.c` drives
the arm over one corpus chain per family with the signatures in
`test/webpki_auth_vectors.h`, `test/e2e.sh` runs the two ECDSA arms against a
local `openssl s_server`, and the `certverify_webpki` CBMC harness proves the
binding and the hash choice over every scheme value and every leaf key family.

SHA-384 needs a SHA-512 core, so `sha512.[ch]` is new. It is packaged only in
a webpki object, the way `sha3.[ch]` is packaged only where ML-KEM is: under
`KEX=pq` and in a webpki object.

### Refused, and why

- **SHA-1 in any signature.** Web PKI retired it in 2017.
- **Moduli below 2048 bits.**
- **An RSA `publicExponent` other than 65537.** Every captured RSA key
  carries 65537, and one admitted encoding keeps the reader a byte compare.
- **P-521, brainpool, and every other curve.** Two curves cover the captures.
- **Ed25519.** No public CA issues it for TLS server authentication.

## Key exchange

Every webpki build offers three groups, which `docs/decisions.md` entries 39,
53 and 63 decide, and the Makefile refuses a `KEX` value beside
`TRUST=webpki`, because it would select nothing. The ClientHello lists
X25519MLKEM768, x25519 and secp256r1 in `supported_groups`, and carries a key
share for the first two in the same order: the 1216-byte hybrid share, then a
32-byte x25519 share that repeats the x25519 half of the hybrid one (RFC 9954
§3.2 permits the reuse). A server selects either of those in one round trip,
and the client wipes the unused ML-KEM seed as soon as the ServerHello selects
x25519. The raw and ca modes keep entry 12's one group per build.

secp256r1, the key exchange RFC 9846 §9.1 makes a MUST, is listed with no
share. A server that holds it and neither of the others, nghttpd 1.52.0 on
OpenSSL 3.0 among them, answers with a HelloRetryRequest that names it, and
the retry hello carries one secp256r1 share, the 65-byte uncompressed point,
in place of the two shares, with a cookie when the retry sent one. The P-256
key pair is drawn only then, and the retry wipes the first hello's x25519 and
ML-KEM key pairs. The ServerHello must select secp256r1, the client checks
the server's point is on the curve, and the shared secret is its 32-byte X
coordinate. `ch_tls.group` reports `CH_GROUP_SECP256R1`. That server costs
one extra round trip.

So a HelloRetryRequest can ask this client for a cookie, for secp256r1, or for
both. The refusals, each an `illegal_parameter` abort before any key exists
(RFC 9846 §4.2.4, §4.3.8 and §4.3.8.2):

- a HelloRetryRequest that names the hybrid or x25519, whose share the hello
  already carried, or any group the hello did not list;
- a HelloRetryRequest with neither a cookie nor a group, which asks for no
  change;
- a HelloRetryRequest that names secp256r1 when `ch_cfg.require_pq` kept it
  off the hello;
- a ServerHello that selects secp256r1 when no retry named it, or selects
  the hybrid or x25519 after one did;
- a secp256r1 share of any length but 65, or a point that is not on the
  curve or whose form byte is not 0x04;
- a ServerHello that selects x25519 when `ch_cfg.require_pq` kept x25519 off
  the hello.

Measured 2026-09-09 with an ML-KEM-only offer, where a refusal is a
`handshake_failure` alert and not a silent fallback:

| endpoint | X25519MLKEM768 |
| --- | --- |
| `s3.amazonaws.com`, and `us-east-1`, `us-west-2`, `eu-central-1`, `ap-southeast-2`, `us-gov-west-1` | negotiates |
| `storage.googleapis.com`, `r2.cloudflarestorage.com`, `s3.filebase.com`, `play.min.io` | negotiates |
| Wasabi, Backblaze B2, DigitalOcean Spaces, Storj | refuses; accepts X25519, P-256, P-384 |

So the hybrid runs against every AWS region tried, and Google and Cloudflare
besides. The four that refuse it accept X25519, and a server that accepts
X25519 selects the x25519 share in the first round trip, which `test/e2e.sh`
checks against an OpenSSL server restricted to x25519. That is entry 39's
trade: entry 12's fail-closed property does not survive the second group,
and secp256r1 is a third classic group beside it.
A caller that wants it back sets `ch_cfg.require_pq`. The flag drops x25519 and secp256r1 from the hello, so a server
without the hybrid finds no common group and fails the handshake, and
`ch_tls.group` must be `CH_GROUP_X25519MLKEM768` when the ServerHello is
accepted. `ch_tls.group` reports the group the ServerHello selected in every
build, so a caller that does not set the flag can still see which exchange
ran.

## The chain walk

The order matters. `webpki.h`'s alert table maps each failure to the alert the
walk sends, and several steps share one alert. `depth` is 0 at the leaf.

1. Read the `Certificate` message. Refuse a non-empty
   `certificate_request_context`. Read every entry's framing, its
   length and its extensions vector: refuse an entry over
   `CH_WEBPKI_CERT_MAX`, more than `CH_WEBPKI_FLIGHT_ENTRIES` entries,
   and a non-empty extensions vector on any entry, the last with
   `unsupported_extension` (see "Decisions").
2. Read entry 0 as the leaf.
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
      admits the CA certificates below it, where a self-issued one does
      not count (RFC 5280 §6.1.4 (l); see "Decisions"), and no
      unrecognized critical extension.
   d. Check the issuer's validity against `now_seconds`.
   e. Check that the issuer's subject Name equals this certificate's issuer
      Name, byte for byte.
   f. Verify this certificate's signature under the issuer's public key.
   g. Descend.

Step 6a is what makes the measured AWS flight cost two signature
verifications and leave the third entry unparsed and unverified; the next
paragraph says what the walk still reads of it. Step 6a is also what makes a root re-keyed under one Name work, because every anchor
naming the issuer is tried rather than only the first.

The certificate bytes of a trailing entry after the terminating certificate
are never parsed, so a trailing entry may hold anything a CertificateEntry
frames. That reverses the ca profile deliberately, because a server may
append certificates the walk never needs — every captured chain does. A
strictness test pins the behaviour by replacing the trailing entry with
invalid DER and requiring success. The entry's framing is still read, on
every entry: its length must fit the list and the cap, and its extensions
vector must be empty.

Name chaining alone never authorizes anything. An anchor whose subject Name
matches but whose key does not verify the signature fails, and the corpus
carries that case.

### Validity

`notBefore <= now_seconds <= notAfter`, both ends inclusive. RFC 5280
§4.1.2.5 makes `notAfter` the last instant of validity, not the first instant
of expiry, and treating the two ends alike is why the boundary tests can name
`notAfter` valid and `notAfter + 1` invalid.

The same rule holds for every issuer the walk reads, at step 6d: the corpus
rows `issuer_not_after_boundary` and `issuer_not_before_boundary` sit on an
intermediate's two boundaries with the leaf valid throughout, and
`issuer_expired` and `issuer_not_yet_valid` are one second past each.

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
matches nothing. A pattern with fewer than two labels after the wildcard
matches nothing, so `*.com` matches nothing. That count is the whole rule.
This mode carries no public suffix list, so `*.co.uk` matches `a.co.uk`.
The cost: a CA that issued a certificate for `*.co.uk` would let one key
answer for every name under `co.uk`, and this client would accept it. The
CA/Browser Forum Baseline Requirements forbid a CA to issue that
certificate, and that rule is the only defence here.

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
  a NULL or empty `name` or `spki`, unless SPKI pins stand alone (see "Raw
  public keys and SPKI pins");
- the hostname fails `webpki_hostname_ok`, or is unset beside anchors;
- `now_seconds` is 0 beside anchors;
- `spki_pin_count` is over `CH_SPKI_PIN_MAX`, or a pin list and its count
  disagree about whether pins are set;
- a PSK field is set and the fields do not present a ticket bound to this
  hostname and these anchors (see "Resumption" below);
- either `server_pubkey` slot, or its length, is set;
- an epoch callback is set;
- `buf_len` is under `CH_MIN_RXBUF`, 12,338 bytes in this mode.

`ch_trust_anchor`, `CH_WEBPKI_ANCHOR_MAX`, `CH_SPKI_PIN_MAX` and the ten
`ch_cfg` fields exist only in a `TRUST=webpki` build, so the raw and ca
objects keep the `ch_cfg` and `ch_tls` layout they had before this mode.
`webpki_cfg.h` declares them and states each field's rule, and
`webpki_cfg.c` checks the rules. A raw or ca build that sets one of the
fields fails to compile. `chapulin.hpp` forwards them through
`Config::anchors`, `Config::hostname`, `Config::now_seconds`,
`Config::alpn`, `Config::spki_pins` and `Config::ticket_binding`, which a
raw or ca build does not declare either.

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

## Application protocols (ALPN)

`ch_cfg.alpn_protocols` points at `ch_cfg.alpn_count` entries of
`ch_alpn_protocol`, each a protocol name and its length. The ClientHello
sends them as RFC 7301 §3.1's `ProtocolNameList`, in the caller's order,
and the server picks one. This is the mode's second negotiation surface,
after the signature schemes, and `docs/decisions.md` entry 37 states what
it costs and what it buys.

Offering nothing is legal: leave both fields zero and the hello carries no
ALPN extension. Otherwise `ch_connect` returns `CH_EINVAL` before it sends
a byte when:

- `alpn_count` is outside 1 to `CH_ALPN_MAX`, or is set without
  `alpn_protocols`, or `alpn_protocols` is set without a count;
- any entry has a NULL `name`, an empty one, or one over
  `CH_ALPN_NAME_MAX` bytes;
- two entries carry the same name. A repeat would make the server's
  selection name two indices, and `ch_tls.alpn_selected` reports one.

`ch_tls.alpn_selected` is the index in `ch_cfg.alpn_protocols` of the
protocol the server selected, or `CH_ALPN_NONE` when it selected none.
Read it after `ch_connect` returns `CH_OK` and branch on it. There is no
copy and no second buffer: the caller already owns the names.

**A silent server is not a failure.** RFC 7301 §3.2 lets a server that
does not implement ALPN answer without the extension, and this client
accepts that: the handshake completes and `ch_tls.alpn_selected` is
`CH_ALPN_NONE`. Failing closed there would refuse every endpoint that
speaks `http/1.1` by convention. A caller that needs a protocol checks the
field and closes the session itself.

What the client does refuse, all fatal:

| the EncryptedExtensions ALPN extension | alert |
| --- | --- |
| more than one `ProtocolName` | `decode_error` |
| a `ProtocolName` of zero bytes | `decode_error` |
| a list length the names do not fill, or a byte past the one name | `decode_error` |
| a name the ClientHello did not offer | `illegal_parameter` |
| any ALPN extension when the caller offered none | `unsupported_extension` |
| a second ALPN extension in the same message | `illegal_parameter`, the alert `handshake.c` seeds for this message |

RFC 7301 §3.2 fixes the first three by structure: the reply is the client's
own structure "except that the 'ProtocolNameList' MUST contain exactly one
'ProtocolName'", and §3.1 gives a `ProtocolName` 1 to 255 bytes. A body that
is not one whole name has a length RFC 9846 §6 calls a `decode_error`. A
name outside the offer is well formed and unacceptable, §6.2's
`illegal_parameter`: §3.2 gives the server no way to select outside the
offer, and one that shares no protocol with the client sends a
`no_application_protocol` alert instead.

## Resumption

A connection presents a ticket an earlier session received, and resumes
without a certificate. RFC 9846 §4.7.1 lets a client resume only when the
new `server_name` is valid for the certificate of the original session
(`rfc9846.txt:3222-3224`). A resumed handshake checks no chain and no
hostname, so this mode binds each ticket to the configuration that
received it, and refuses to present it under any other.

- **What the caller does.** `on_ticket` hands over `ch_ticket.psk`,
  `identity` and, in this build, `binding`, 32 bytes. The caller stores all
  three. To resume, it sets the full chain configuration as usual, then
  `psk` to the 32-byte PSK, `psk_id` to the identity, `resumption` to 1,
  `obfuscated_age` as in the other modes, and `ticket_binding` to the
  stored binding.
- **What the binding covers.** `webpki_ticket_config_hash` hashes the
  hostname with its ASCII capitals in lower case, then every anchor's
  `name` and `spki` in array order, then the SPKI pins, each field
  prefixed by its length.
  The binding is HMAC-SHA256 keyed by the ticket's PSK over the label
  `chapulin webpki ticket` and that hash. `webpki_ticket.h` states the
  bytes, and `test/webpki_resume_cases.h` checks them against a value
  computed outside this tree.
- **What `ch_connect` refuses, with `CH_EINVAL` and no byte sent.** A
  ticket whose binding does not match this hostname, these anchors and
  these pins. A
  binding from another ticket, because the key is that ticket's PSK. A
  PSK that is not 32 bytes, an identity outside 1 to `CH_TICKET_ID_MAX`
  bytes, a ticket with no binding, a binding with no ticket, and an
  external PSK (`resumption` 0). `ch_record_init` applies the same rules.
- **The same name in other capitals resumes.** The chain walk matches
  names without case (RFC 6125 §6.4.1), so `S3.Example.TEST` resumes a
  ticket `s3.example.test` received.
- **The same anchors in another order do not.** The hash reads the array
  as given. A caller that rebuilds its anchor array in a different order
  loses its tickets and makes one full handshake.
- **ALPN is not bound.** Every handshake, resumed or not, negotiates ALPN
  again, and `ch_tls.alpn_selected` reports the new answer. RFC 9846 ties
  the application protocol to a ticket only for 0-RTT data, which this
  client never sends.
- **The resuming hello offers the certificate path too.** It carries
  the five signature schemes, and `server_certificate_type` when SPKI pins
  are set, ahead of `pre_shared_key`, which stays the last extension
  because the binder covers every byte before it. A retry hello after a
  HelloRetryRequest carries the same extensions and a new binder.
- **A declined ticket becomes a full handshake.** A ServerHello with no
  `pre_shared_key` declined the ticket. The client wipes the PSK's early
  secret and binder key, derives the early secret of no PSK
  (`rfc9846.txt:4182-4185`), and reads Certificate and CertificateVerify
  as a handshake with no ticket does: the chain, the clock, the hostname,
  the anchors and any SPKI pins are all checked. A pre_shared_key that
  names any identity but 0 is refused with `illegal_parameter`.
  `docs/decisions.md` entry 55 says why the hello offers both, and records
  the dns.google measurement behind it.
- **`ch_tls.psk_selected` says which one happened.** It is 1 when the
  server selected the ticket and sent no certificate, and 0 when the
  handshake was a full one, whether the hello offered a ticket or not.
- **The caller owns the ticket's age.** A ticket lives at most seven days
  (RFC 9846 §4.7.1), and the other modes leave that limit and
  `obfuscated_age` to the caller as well.
- **A `TRANSPORT=quic-nonblocking` webpki client resumes the same way.**
  `ch_quic_init` takes the configuration hash as `ch_connect` does, so the
  tickets a QUIC session hands to `on_ticket` carry a binding to its
  hostname and anchors, and `quic_config.c` checks a presented ticket with
  the same `webpki_resumption_ok`, refusing the same shapes with
  `CH_EINVAL`. `bin/quic_loop_webpki` resumes a bound ticket against this
  tree's QUIC server and checks the binding on the ticket it issues next;
  `docs/quic_server.md`, "Resumption", says what a QUIC caller does.

## Raw public keys and SPKI pins

RFC 8310 §9 asks a DNS-over-TLS client to implement RFC 7250 raw public
keys, and to offer them only when it has an SPKI pin set
(`rfc8310.txt:1134-1138`). An SPKI pin is the SHA-256 of a DER
SubjectPublicKeyInfo (RFC 7858 §4.2, `rfc7858.txt:434-440`), and the
caller sets up to `CH_SPKI_PIN_MAX` (4) of them in `ch_cfg.spki_pins`.

- **The offer.** With pins set, the ClientHello sends
  `server_certificate_type` (RFC 7250 §4.1) listing RawPublicKey, and X509
  after it when anchors are also set. Without pins it sends no extension,
  and the server sends the X.509 type RFC 9846 §4.5.1 defaults to. A
  resuming hello makes the same offer, because a server that declines the
  ticket sends a Certificate after all (see "Resumption").
- **Pins alone** are a whole configuration: no anchors, no clock, and no
  hostname unless the caller wants one sent as `server_name`. This is RFC
  8310's "SPKI + IP" profile, for a DNS server on a private network with
  no certificate from a public CA. The client offers RawPublicKey alone.
  Without a hostname the hello carries no `server_name`, and an
  EncryptedExtensions that acknowledges one anyway is refused with
  `unsupported_extension`, because the server acknowledged a name nobody
  sent (RFC 6066 §3).
- **A raw public key** carries no name and no dates, so the pins are the
  whole check: the one CertificateEntry must hold a SubjectPublicKeyInfo
  the mode's key rules accept, and one pin must equal its SHA-256. The
  key then verifies CertificateVerify, as a leaf key does.
- **A chain beside pins** must pass everything a chain passes without pins
  — the anchors, the clock, the hostname — and one pin must also name a
  key on the path the walk verified: the leaf, an intermediate the walk
  used, or the anchor that verified. RFC 8310 §6.4 asks a client
  configured with both a name and pins to require both
  (`rfc8310.txt:805-814`), and RFC 7858 §4.2 pins the validated chain. A
  certificate the server sent beyond that path does not count, so a
  pinned certificate appended to a chain another CA signed does not pass.
- **What the server chose** is `ch_tls.server_cert_type`:
  `CH_CERT_TYPE_RAW_PUBLIC_KEY` (2) or `CH_CERT_TYPE_X509` (0).
- **Refusals.** A key no pin names: `bad_certificate`, `CH_EAUTH`. An
  X.509 answer to a configuration of pins alone, which has no anchor to
  verify it with: `unsupported_certificate` (RFC 7250 §4.2), `CH_EAUTH`.
  A `server_certificate_type` in EncryptedExtensions the client did not
  offer, or naming a type it did not list, is refused there, before any
  Certificate arrives. `webpki_pin.h` and `handshake_parser.h` give the
  full table.
- **Rotation.** RFC 7858 §4.2 asks for a backup pin. Any pin may match, so
  a caller rotating a server key sets the old and the new pin together,
  and removes the old one after the server moves.
- **Tickets** bind the pin set as well as the hostname and the anchors
  (see "Resumption"), so a pin change makes the next connection a full
  handshake.
- **Not here.** The server role neither sends nor accepts a raw public
  key: it ignores the extension and sends its certificate, which a
  configuration with anchors verifies as before. A `TRANSPORT=quic-nonblocking`
  webpki client refuses pins. Client raw public
  keys (`client_certificate_type`) are not offered, because this client
  sends no certificate.

## Bounds

Every cap and the measurement behind it. *Derived* means a formula over
measured inputs, and the formula is given.

| constant | value | where it comes from |
| --- | --- | --- |
| `CH_WEBPKI_CERT_MAX` | 3072 | measured: the largest captured certificate is the 2104 B S3 leaf |
| `CH_WEBPKI_CHAIN_MAX` | 3 | measured: the Let's Encrypt capture needs 3 (leaf, YE2, Root YE, then the ISRG Root X2 anchor); the other three need 2 |
| `CH_WEBPKI_FLIGHT_ENTRIES` | 4 | measured: Let's Encrypt sends 4 |
| `CH_TRUST_MIN_RXBUF` | 12338 B | derived: `4 * (3072 + 5) + 8 + 22`, the largest Certificate message plus the record that completes it |
| `CH_WEBPKI_ANCHOR_MAX` | 12 | measured: 9 roots cover the four endpoints above |
| `CH_WEBPKI_EXT_COUNT_MAX` | 16 | measured: the S3 leaf carries 10 |
| `CH_WEBPKI_EXT_TLV_MAX` | 1024 | measured: the S3 leaf's subjectAltName Extension TLV is 653 B |
| `CH_HOSTNAME_MAX` | 253 | DNS's own limit |
| `CH_ALPN_MAX` | 8 | ClientHello budget: eight names of 32 bytes cost the hello 270 B |
| `CH_ALPN_NAME_MAX` | 32 | the same budget; every protocol ID this tree offers or tests is under 11 B |
| `CH_RSA_MODULUS_MAX` | 512 under webpki, 384 otherwise | measured: GTS Root R1 is RSA-4096 |

`CH_WEBPKI_CERT_MAX` leaves 46% margin over the largest certificate
measured. `CH_WEBPKI_CHAIN_MAX` of 3 admits one two-intermediate
hierarchy; each further entry is one more signature an unauthenticated
peer can force before any anchor is consulted, and one more certificate
in the formula least likely to converge.

The ClientHello this mode sends carries a `server_name` extension of up
to 262 bytes, an ALPN extension of up to 270, three groups with a key
share for the first two, and the certificate path: five signature
schemes, 16 bytes, and with SPKI pins the `server_certificate_type`
offer, 7 bytes at most. So its largest hello, `CH_HELLO_MAX`, is 2,396
bytes, 2,416 under `SUITE=aesgcm`, and 2,650 over QUIC. The session's TX
staging array, `CH_TX_STAGE`, grows to match, and
`test/webpki_session_cases.h` measures the built hello against both
numbers. A resuming hello sets that maximum, because it carries the
certificate path and the `pre_shared_key` extension both. A hello with no
ticket is at most 2,029 bytes. The retry hello to secp256r1 is 1,187
bytes shorter than a cookie retry, because its one 69-byte share replaces
the first hello's two.

`CH_ALPN_MAX` and `CH_ALPN_NAME_MAX` are that budget split two ways. The
extension costs 4 type and length bytes, 2 list-length bytes, and one
length byte per name, so eight names of 32 bytes cost 270. RFC 7301 §3.1
allows a `ProtocolName` of up to 255 bytes, and four of those would cost
the hello a kilobyte; 32 bytes holds every protocol ID this tree offers
or tests, the longest being `http/1.1` at 8. Eight names is four times
the two-name offer an HTTP caller sends.

`CH_WEBPKI_FLIGHT_ENTRIES` is sized separately from the walk, because a
server may append entries the walk never reads and every captured chain
does. `CH_TRUST_MIN_RXBUF` follows the formula `cfg.h` uses for the ca
mode, widened from 2 entries to 4: the message's 8 bytes of framing, the
cap + 5 per entry, and the 22 bytes of the record that completes the
message — its header, its inner content type and its AEAD tag — which
`handshake_record.c` holds beside the message while it reassembles it.
`test/rxbuf_floor_tests.h` reassembles that message at the floor and
fails it one byte under. That floor is the number that puts this mode
on a host; a device build stays at 512 bytes.

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
- **A resumed connection checks no certificate.** It authenticates the
  server by the ticket's PSK. The chain, the clock and the hostname were
  checked by the full handshake that issued the ticket, and the binding
  (see "Resumption") holds the ticket to that hostname and those anchors.
  A certificate that expired since, or an anchor distrusted without the
  anchor array changing, is not checked again until the next full
  handshake. A server that declines the ticket gives that full handshake
  in the same connection.
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
disagreements are exactly the eight it expects. openssl agrees on 22 of 30
corpus chains. Six of the eight disagreements are rows where this mode refuses what
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
rows where openssl refuses what this mode accepts are `not_after_boundary`
and `issuer_not_after_boundary`: at `now_seconds` equal to a certificate's
`notAfter`, openssl's `X509_cmp_time` reports that certificate expired, and
this mode accepts it, as "Validity" above states.

## Decisions

Two rules where this mode could have been stricter than the RFCs, what it
does, and why.

- **A self-issued certificate does not count against `pathLenConstraint`.**
  RFC 5280 §6.1 calls a certificate self-issued when its subject Name
  equals its issuer Name, which is what a CA re-keying under its own Name
  issues for the new key under the old one. §6.1.4 (l) leaves such a
  certificate out of the count `pathLenConstraint` bounds, and OpenSSL
  follows the RFC. The stricter rule — count every certificate on the
  path — was considered and rejected: it refuses a re-keyed CA's chain
  that every other client accepts, and a public CA re-keys without
  notice. The walk therefore counts, for each issuer, the CA
  certificates it read below it whose subject Name differs from their
  issuer Name (`webpki.c`, `self_issued` and `path_len_admits`;
  `spec/lean/Spec/Webpki.lean`, `selfIssued` and `pathLenAdmits`). Every other
  rule still applies to a self-issued certificate: it is parsed under the
  issuer arm, its validity is checked, and it verifies under the next
  key. The corpus row `rekeyed_intermediate` pins the acceptance and
  `path_len_exceeded` the refusal it does not relax; the differential
  compares both against the spec.
- **A CertificateEntry extension is refused on every entry, with
  `unsupported_extension`.** RFC 9846 §4.5.1 lets a server answer a
  `status_request` or `signed_certificate_timestamp` extension inside an
  entry, and §4.3 says a peer that receives an extension it did not offer
  aborts with `unsupported_extension`. This client offers neither, so an
  entry extension is a reply to a request nobody made, wherever it sits:
  the walk reads every entry's framing, the trailing ones included, and
  refuses a non-empty extensions vector on any of them with that alert
  (`read_entries` in `webpki.c`). Skipping the vector on a trailing entry
  was considered and rejected: the walk would then accept bytes the RFC
  tells it to refuse, and the framing is read either way.

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
  existing C modules do. `spec/lean/` gains mathlib, which unblocks the arithmetic
  theorems `spec/lean/CONTRACT.md` records as blocked: P-256, P-384, the RSA
  lemmas and the X25519 ladder invariants. mathlib v4.33.0 targets
  `leanprover/lean4:v4.33.0`, which `spec/lean/lean-toolchain` already pins, so no
  toolchain moves. P-256 and P-384 theorems are in this work; the X25519 and
  RSA lemmas become newly possible and are filed separately rather than
  absorbed here.
- **Differential testing has an asymmetry worth stating.** Random inputs
  essentially never form a valid signature, so a differential run over
  signature verification exercises the reject path. The accept path rests on
  the Wycheproof vectors above. Hostname matching is the opposite case — a
  pure predicate over a small alphabet, where random sampling covers the
  space meaningfully — and it is where the differential effort goes.
- **CBMC.** A harness per module, at the module's real bound. Two were
  expected to be hard and are called out rather than promised: the
  certificate parser, whose ca-mode counterpart already records no verdict in
  25 minutes for a two-entry formula at 7.1 GB, and the name matcher, whose
  cost grows with roughly the cube of input length. Where a bound cannot be
  reached, the README states the partial bound that was reached. The walk
  itself turned out cheap rather than hard, because its harness stubs the
  parser and the verifiers and so keeps every certificate byte out of the
  formula: `webpki_chain` proves 1103 properties in 117 s at 3.0 GB over a
  48-byte entry list (cbmc 6.11.0 with kissat under `/usr/bin/time -l`,
  through `proof/run.sh` on 2026-09-16). What that costs is soundness: the stubs answer an
  unconstrained verdict, so the proof says nothing about which chains the
  walk accepts, and `spec/lean/Spec/Webpki.lean` states that property instead.
- **Fixtures.** Two corpora, doing different jobs. The captured chains above
  carry real extension bulk and test the bounds. A generated corpus of 30
  chains — 11 positive (the four shapes above, a P-384 leaf, one wildcard
  match, the two leaf validity boundaries, the two issuer validity boundaries
  and a re-keyed intermediate), 19 negative taking one rule each — is
  small, offline and deterministic, and tests the logic. `test/gen_webpki_corpus.py` renders
  both into exact RFC 9846 §4.5.1 `Certificate` message bytes, so a test feeds
  the parser what the wire would. `test/webpki_auth_vectors.h` adds a
  CertificateVerify signature over three of those chains, one per leaf key
  family, which is what `test/webpki_auth_test.c` drives `hsa_server_auth`
  with.
