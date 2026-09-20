# QUIC handshake mode

A `TRANSPORT=quic` build runs the TLS 1.3 client this tree already has over
QUIC's CRYPTO frames instead of TLS records, and protects QUIC packets with the
keys that handshake produces. It takes handshake bytes from the caller, hands
handshake bytes back, seals and opens packets on request, and opens no socket.

It exists because colibri, an HTTP/2 and HTTP/3 library, calls chapulin through
stompy, and HTTP/3 runs over QUIC. chapulin covers HTTP/1.1 and HTTP/2 over TLS
and TCP today, which is what stompy's S3 client needs, so this mode is about
HTTP/3 alone.

The mode is not a QUIC client. chapulin owns every key and every packet's
protection. colibri owns everything that is not cryptography: packet numbers,
ACKs, loss recovery, congestion control, flow control, streams, connection IDs,
Retry and version negotiation logic, and path validation. RFC 9001 §4.1.3 and
§4.1.4 define the interface a TLS stack owes QUIC; §5 defines the packet
protection that interface feeds. This mode covers both and stops there.

This document states what the mode is, the AES exception it needs and how the
build holds it, the interface it exposes, the suspendable driver step by step
with the state each step leaves behind, what the build reuses, the bounds that
need measuring, what the mode does not do, what it does not check or provide,
and which `CLAUDE.md` sentences and numbered invariants a `TRANSPORT=quic`
build falsifies. An appendix holds three replacement texts: the two AES rules
and the file-pair chain. The section "What changes in `CLAUDE.md`" holds the
other eight sentences, "What changes in `docs/invariants.md`" holds the four
invariants the mode amends and the two it adds, and "What changes in
`docs/decisions.md`" holds the five entries it falsifies beside entry 6.

`docs/decisions.md` entry 38 records the trade. `docs/webpki.md` is the model
for this document's shape, and the trust mode it describes is unaffected: a
QUIC build is still `TRUST=raw`, `TRUST=ca` or `TRUST=webpki`.

## Status

Decided, the interface is written, the build axis carries it, and the mode
is implemented. The design has chapulin owning packet protection at every
level, with the AES exception below. `quic.c`, `quic_config.c` and
`quic_step.c` run the handshake over CRYPTO frames, and the six
packet-protection sources under them protect the packets. The Makefile's
`TRANSPORT` axis packages all of it: `make lib TRANSPORT=quic` links an
object that exports the fifteen `ch_quic_` calls. `make quic-footprint`
prints what exists, read from the tree, and `make lint-quic-partition` holds
the mode to the files named `quic*`. The next section states the stub rule
the mode was built under, which has no subject left here.

`quic_config.[ch]` is not in the file list below. It holds the configuration
rules `ch_quic_init` applies and the stored revocation epoch it loads, which
are `tls.c`'s and which a `TRANSPORT=quic` object does not compile. They sit
in their own pair because `CLAUDE.md` caps a hand-written file at 500 lines
and `quic.c` was at it.

Every claim about chapulin names the file and line it came from, read at
commit `3432a5d`. The citations into `docs/invariants.md` are read after the
commit that added INV-27 there, which moved every line below it. Numbers
marked *measured* come from a program that ran, or
from a command whose text is given. *Derived* means a formula over measured
inputs, and the formula is shown. Nothing here is an estimate, and no number in
this file substitutes for `bench/sram.sh`.

Every RFC line number cites the plain-text file rfc-editor.org publishes:
`rfc9001.txt`, `rfc9000.txt`, `rfc8999.txt`, `rfc9221.txt`, `rfc7301.txt` and
`rfc9846.txt`. This tree does not carry those files. TLS 1.3 is cited as RFC
9846, as the rest of the tree cites it (`docs/decisions.md` entry 4). QUIC is
RFC 9000, QUIC-TLS is RFC 9001, loss recovery is RFC 9002, the
version-independent header shape is RFC 8999, ALPN is RFC 7301, and unreliable
datagrams are RFC 9221.

The programs quoted below ran outside the repository. They are evidence, not
code to land.

## The stubs and the marker

The build axis landed with the first line of code and not after it, so every
later lane had a target that compiled and every check already ran on the new
axis. That meant the mode's `.c` files existed before the mode did: each one
defined every function its header declares and implemented none, and the mode
linked and did nothing. Three rules held that state, and each was checked
rather than stated.

1. **Every stub fails closed.** A stub returned a refusal its header
   documents and wrote nothing through its out-parameters. No stub returned
   `CH_OK`. A stub that could would have handed a caller an unprotected packet
   the day it linked.
2. **Every stub is greppable and counted.** A stub body carried one line, in
   one fixed form: `// CH_QUIC_STUB: not implemented yet; this call fails
   closed and writes nothing.` `make quic-footprint` counts that line per
   function, so the report read "43 declared, 39 stubbed, 4 implemented"
   rather than a count of definitions. The Makefile's `QUIC_STUB_SRCS` grepped
   the same line, and two checks carried an exception bounded by that list:
   `lint-tidy`'s stub pass, with `readability-non-const-parameter` off, and
   `lib-check`'s `RAND=extern` import check.
3. **A test proves rule 1.** `bin/quic_stub_test` called every function that
   was still a stub, required each refusal, and filled every buffer it passed
   with `0xa5` before the call and compared it after, so "writes nothing" was
   measured. `make lint-quic-surface` failed on a stub the file never called.

Every function is implemented now, so the marker matches nothing and the
three rules have no subject. `QUIC_STUB_SRCS`, the two exceptions,
`bin/quic_stub_test` and the mutant on `quic_step.c` went in the commit that
implemented the last stub, as INV-28 said they would. `make quic-footprint`
still counts the marker and reports 0 stubbed, and `make lint-quic-surface`
still holds `quic.h` to the interface table below. INV-28 then held the same
three rules over the `ROLE=server` stubs, which carried `CH_SRV_STUB`, and it
retired in turn when the last of those was implemented; `docs/invariants.md`
records the retirement above its first entry.

Two things the axis did that this document did not plan, both named in the
Makefile beside the list they change. `QUIC_PENDING` held the four sources
that keep their TLS text and owe a QUIC arm — `handshake_parser.c`,
`handshake_record.c`, `handshake_auth.c` and `handshake_post.c` — for as long
as the object could not compile them. Every arm landed with the driver, so
the list is empty and the object compiles all four beside
`handshake_message.c`; the name stays because `TRANSPORT_FILTER` and
`tools/quic-partition.py` read it. And `LIB_VARIANT` gained `$(TRANSPORT)` as
a term, so the two transports never write an object of the same name to the
same path.

## What QUIC asks of a TLS stack

RFC 9001 §4.1.3 states the split (`rfc9001.txt:462-464`): QUIC takes the
unprotected content of TLS handshake records as the content of CRYPTO frames,
and TLS record protection is not used by QUIC. So the stack produces and
consumes bare handshake messages — the 4-byte header and its body — with no
record header, no inner content type, no padding and no record AEAD.

RFC 9001 §4.1.4 names what TLS hands over per encryption level
(`rfc9001.txt:546-553`): a secret, an AEAD function and a KDF. QUIC then derives
the packet protection key, the packet protection IV and the header protection
key by the labels in §5.1. In this mode that derivation happens inside the TLS
object.

Four encryption levels, three packet number spaces, and CRYPTO frames in three
of the four levels (RFC 9001 §4.1.3, `rfc9001.txt:455-460`):

| level | packet number space | carries CRYPTO frames | secret comes from |
| --- | --- | --- | --- |
| Initial | Initial | yes | the client's Destination Connection ID, not TLS (RFC 9001 §5.2) |
| 0-RTT | application data | no | TLS, if 0-RTT is offered |
| Handshake | Handshake | yes | TLS |
| 1-RTT | application data | yes | TLS |

The order of the handover, from the client column of RFC 9001 §4.1.5 Figure 5
(`rfc9001.txt:597-632`), with the transport parameters added from §8.2
(`rfc9001.txt:1930-1932`): QUIC gives TLS its transport parameters, asks for
bytes and gets the ClientHello; gives TLS the server's Initial-level bytes and
gets the Handshake keys; gives TLS the server's Handshake-level bytes and gets
the client Finished, the completion signal and the 1-RTT keys. After that TLS
is passive. It still consumes CRYPTO bytes, because a NewSessionTicket arrives
that way.

One ordering rule shapes the interface below. RFC 9001 §4.1.4 says the
availability of new keys is always a result of providing inputs to TLS
(`rfc9001.txt:530-531`). A QUIC stack never polls for keys; it delivers bytes
and collects what that delivery produced.

## What the derivation costs, measured

RFC 9001 §5.1 derives packet keys with TLS 1.3's HKDF-Expand-Label
(`rfc9001.txt:1017-1021`), so every QUIC label goes through the `tls13 ` prefix
`hkdf.c` writes. Six labels are involved: `client in` and `server in` (§5.2),
`quic key`, `quic iv` and `quic hp` (§5.1), and `quic ku` (§6.1). The longest
is 9 bytes and `HKDF_LABEL_MAX` is 12 (`hkdf.h:26`), so no constant moves. QUIC
always passes a zero-length context (`rfc9001.txt:1021`).

*Measured*, 2026-09-16. A program linking the tree's unmodified `hkdf.c`,
`chacha20.c`, `poly1305.c`, `aead.c`, `ct.c` and `sha256.c`, and nothing else,
reproduces RFC 9001 Appendix A.1's Initial secrets and keys for both directions
and every value of Appendix A.5:

    quic key             c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
    quic iv              e0459b3474bdd0e44a41c144
    quic hp              25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
    quic ku              1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9
    payload ciphertext   655e5cd55c41f69080575d7999c25a5bfb
    mask                 aefefe7d03
    packet               4cfe4189655e5cd55c41f69080575d7999c25a5bfb

The last line is a complete, wire-valid QUIC 1-RTT packet built out of this
tree. Three facts follow.

The key schedule needs no change. `keysched.c` includes only `ct.h` and `hkdf.h`
(`keysched.c:3-4`) and holds no reference to the record layer.

The ChaCha20 header protection of RFC 9001 §5.4.4 already exists.
`chacha20_block(key, nonce, counter, out)` (`chacha20.h:23-24`) is the function
§5.4.4 names (`rfc9001.txt:1338-1362`). `counter` is `sample[0..3]` read as a
little-endian 32-bit value, byte by byte: §5.4.4 says an implementation that
takes a 32-bit integer in place of the byte sequence reads that sequence
little-endian (`rfc9001.txt:1344-1347`), and `CLAUDE.md` forbids assuming host
endianness. `nonce` is `sample[4..15]` taken as bytes. `chacha20_block` writes
64 bytes (`chacha20.h:12`, `chacha20.h:24`), of which `quic_packet.c` reads
the first 5 as the mask. Appendix A.5 is the unit vector that pins the byte
order: `sample = 5e5cd55c41f69080575d7999c25a5bfb` and `mask = aefefe7d03`
(`rfc9001.txt:2546-2547`), which the measured program above reproduces. The
header comment says the function exists to derive the Poly1305 one-time key
(`chacha20.h:22`), and QUIC gives it a second caller.

The AEAD already takes a variable-length associated data. `aead_seal` and
`aead_open` take an `aad` pointer and an `aad_len` (`aead.h:19-29`). The TLS
record layer always passes its fixed 5-byte header and the function never
assumed that; a QUIC packet's associated data is the whole unprotected header
(`rfc9001.txt:1141-1143`), whose length varies.

The same program derives the Initial-level keys correctly too — the 16-byte
`quic key` and 16-byte `quic hp` of Appendix A.1. Deriving them is not the
problem. Using them is.

## Where packet protection lives

### The requirement

RFC 9001 §5 and §5.2: Initial packets use AEAD_AES_128_GCM with keys derived
from the Destination Connection ID of the client's first Initial packet
(`rfc9001.txt:989-991`). RFC 9001 §5.4.1 makes header protection follow the
AEAD, and §5.4.3 makes the Initial level's mask `AES-ECB(hp_key, sample)`
(`rfc9001.txt:1336`). RFC 9001 §5.8 computes the Retry Integrity Tag with
AEAD_AES_128_GCM under a key and a nonce the RFC prints
(`rfc9001.txt:1499-1502`), and RFC 9000 §17.2.5.2 makes a client discard a
Retry packet whose tag does not validate.

None of it is negotiable. The salt, the AEAD and the hash belong to the QUIC
version and are fixed before any TLS message is parsed (RFC 9001 §5.2). A
client that selects TLS_CHACHA20_POLY1305_SHA256 still performs AES-128-GCM and
AES-128-ECB on Initial packets, because the TLS suite does not reach that level.
The Handshake and 1-RTT levels are unaffected, and the measured packet above is
a complete 1-RTT packet built from this tree with nothing added.

The AES surface is narrow. GCM uses only the forward cipher function (NIST SP
800-38D), and the §5.4.3 mask is one forward block (FIPS 197), so no inverse
cipher is needed. It is still AES, plus GHASH.

### The rule it contradicts

`CLAUDE.md`: "ChaCha20/Poly1305/x25519 are constant time by construction — keep
them that way; AES never enters this codebase precisely to avoid tables."
`docs/decisions.md` entry 6 records the same trade: "Cost: the IoT profile's
mandatory AES-CCM suite and AES-only servers. Gain: constant time by
construction on any core — no lookup tables, no timing story to defend."

The rule is categorical and the reason under it is not. The reason is about
what a lookup table leaks, and a table leaks the key it is indexed with. Every
key AES touches in QUIC is public, and the RFC says so in its own words.

### Every key AES touches in QUIC is public

**Initial.** The secret comes from HKDF-Extract with a salt of
`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a` and the Destination Connection ID
field as input keying material (`rfc9001.txt:1051-1055`). The salt is printed
in the RFC (`rfc9001.txt:1066`). The Destination Connection ID travels in the
clear in every long header (RFC 8999 §5.1, `rfc8999.txt:181-182`). RFC 9001
draws the conclusion itself (`rfc9001.txt:999-1001`): because anyone can
compute the Initial keys, Initial packets are not considered to have
confidentiality or integrity protection.

**Retry.** RFC 9001 §5.8 prints the key and the nonce
(`rfc9001.txt:1499-1502`): K is 128 bits equal to
`0xbe0c690b9f66575a1d766b54e368c84e` and N is 96 bits equal to
`0x461599d35d632bf2239825bb`. RFC 9001 §5 says the same of these packets
(`rfc9001.txt:1002-1003`): Retry packets use a fixed key and so lack
confidentiality and integrity protection.

**Header protection at those levels.** The mask key is `quic hp` derived from
the same Initial secret (RFC 9001 §5.1, `rfc9001.txt:1029-1032`), so it is
public for the same reason the packet key is.

So the complete list of key bytes an AES implementation in this tree ever sees
is three items: a 16-byte packet key and a 16-byte header protection key, both
expanded from `HKDF-Extract(initial_salt, dcid)`, and one 16-byte constant the
RFC prints. No traffic secret `keysched.c` derives is among them.

### The AES exception, stated as an invariant

The argument above is only as good as the rule that keeps it true tomorrow, so
the rule has to be checkable, not merely stated. It is INV-26 in
`docs/invariants.md`, which stops at INV-27 (`docs/invariants.md:279`), in the
entry shape INV-20 already uses for the certificate parser, at the weaker of
the two Semgrep grades for the reason below.

**What it forbids, exactly.** No source in this tree may pass a key to `quic_aes.c`
or `quic_gcm.c` other than these three: the `hkdf_expand_label` output over
`initial_secret`, where `initial_secret` is `hkdf_extract` over RFC 9001 §5.2's
printed salt and the Destination Connection ID the caller supplied; the header
protection key expanded from that same secret; and the 16-byte constant of RFC
9001 §5.8. Equivalently and more bluntly: exactly two library sources may call
a symbol `quic_aes.h` or `quic_gcm.h` declares, `quic_initial.c` (the Initial packet
path) and `quic_retry.c` (the Retry tag check), and no other file may call one
or construct the key type below. Every symbol those two headers declare begins
`aes_` or `gcm_`; the invariant states that naming rule too, so its claim and
the Semgrep rule that checks it name the same set of symbols.

**No session field holds an AES key, and the key type is opaque outside three
sources.** `quic_aes.h` declares a key type, `aes_public_key`, and two
constructors: `aes_public_key_initial`, over the Initial secret's inputs, and
`aes_public_key_retry`, over the §5.8 constant. Every `aes_` and `gcm_` entry
takes that type and nothing else, so a call that passes a `rec_dir` key or a
bare `uint8_t` array does not compile.

`ch_quic` stores the Destination Connection ID in `initial_dcid` and
`initial_dcid_len`, and stores no key. `ch_quic_initial_keys` copies those
bytes and derives nothing; `quic_initial.c` builds the one direction's key each
packet needs on its own stack, and `quic_retry.c` does the same with the §5.8
constant. So no key object outlives a call, and the shape that used to defeat
this rule has no target: a file could write `q->initial_tx.key.round_keys` and
`quic_initial.c` would then pass that struct to `aes_encrypt_block` as a
permitted caller, and today `initial_tx` does not exist.

Because nothing stores a key by value, the type can be opaque, and it is.
`quic_aes.h` declares `typedef struct aes_public_key aes_public_key;` and
stops. `quic_aes_key.h` holds the body, and exactly three sources include it:
`quic_aes.c`, `quic_initial.c` and `quic_retry.c`, the three that build a key
on a stack frame. In every other file the type is incomplete, so
`aes_public_key k;`, `aes_public_key k[1];`, an assignment and a write to a
field are each a compiler error rather than a pattern someone has to match.
Zero heap does not forbid this, because the three sources that need the body
are the three that include the header carrying it.

So INV-26 is now two things with different grades. Building a key is a
compile-time refusal. Naming an `aes_` or `gcm_` entry is Semgrep-tripwire on
`docs/invariants.md`'s scale — an identifier ban, which catches honest drift
and not a determined reintroduction under another name
(`docs/invariants.md:25-26`). The allowlist that keeps the type incomplete is a
tripwire too: a fourth name added to `KEY_HOLDERS` in
`tools/quic-footprint.py` is a diff a reviewer looks for.

**What the change does not close.** A file can write a traffic secret into
`q->initial_dcid` instead, and the constructor will derive an AES key from it.
That is safer than writing round keys, because `hkdf_extract` and three
`hkdf_expand_label` calls sit between the write and the S-box: what the table
is indexed with is an HKDF output, not the secret, and recovering it by cache
timing gives an attacker the Initial packet protection key that RFC 9001 §5
says anyone can compute anyway. `WIDEMUL_CEILING` holds `hkdf.c` and `sha256.c`
at 0 wide multiplies and `lint-wide-multiply` holds each one's
conditional-branch count per compiler and target, so a branch a compiler puts
on secret bytes shows as a count that grew. The write is still wrong and
review is still what catches it.
`docs/invariants.md` INV-26 states it in the same words.

**How the build catches the rest.** Four checks, three of which already exist
for something else.

1. A Semgrep rule, `inv-26-aes-public-keys-only`, written as the family shape
   `inv-5-profiled-cert-parser` uses (`.semgrep/invariants.yml:129-139`)
   rather than as a list of names. `pattern-either:` holds four branches, the
   shape `inv-1-seal-only-in-record` uses for its two alternatives
   (`.semgrep/invariants.yml:108-110`). The first branch is a `patterns:`
   block with `pattern: $F(...)` and `metavariable-regex: metavariable: $F,
   regex: ^(aes|gcm)_`, the conjunction shape `inv-5-profiled-cert-parser`
   uses, because the regex constrains the same node the pattern matched. The
   second branch is the same `metavariable-regex` over a bare `pattern: $F`,
   which matches the name used as a value: `&aes_encrypt_block`, a function
   pointer assigned from the name, the name passed as an argument. The first
   branch matches none of those, because the later call through the pointer
   binds `$F` to the pointer's own name, so taking the address alone would
   otherwise defeat the rule. The rule carried two more branches,
   `pattern: aes_public_key $K = ...;` and
   `pattern: aes_key_schedule $K = ...;`, and they are gone: an initializer
   needs the type's body, and outside the three sources that include
   `quic_aes_key.h` there is no body, so the compiler refuses the edit before
   a pattern could match it. Either branch is an error outside
   `paths: exclude: [test,
   proof, fuzz, spec, bench, bin, examples, quic_initial.c, quic_retry.c, quic_aes.c, quic_gcm.c]`, the two permitted
   callers and the two definition sites. The regex covers every symbol `quic_aes.h`
   and `quic_gcm.h` declare under those two prefixes, including a symbol
   added tomorrow, which an enumerated list of names would not, and check 4
   below is what holds that premise. It is still a
   tripwire rather than structural, because this tree grades this exact
   construct that way: `inv-5-profiled-cert-parser` is built from the same two
   pieces, `pattern: $F(...)` with a prefix-family `metavariable-regex`
   (`.semgrep/invariants.yml:130`, `:133`), and its own message calls it
   tripwire grade, catching honest drift by name and not a reintroduction
   under another name (`.semgrep/invariants.yml:123-124`,
   `docs/invariants.md:142`). An AES entry point named something else evades
   `^(aes|gcm)_`. So the invariant states the naming rule that makes its claim
   and this check say the same thing: every symbol `quic_aes.h` and `quic_gcm.h` declare
   begins `aes_` or `gcm_`, and INV-26 claims that no library source outside
   `quic_initial.c` and `quic_retry.c` names a symbol that begins `aes_`
   or `gcm_`. Check 4 fails the build when
   that naming rule stops holding. `.semgrep/invariants.yml`
   holds 13 rules today (*measured*,
   `grep -c 'id:' .semgrep/invariants.yml`), and
   `lint-invariants` runs them.
2. `lint-codegen-partition` (`Makefile:1813-1830`) already forces every library
   source into exactly one of two hand-kept lists: `WIDEMUL_CEILING`, the
   secret-bearing sources held at a wide-multiply count, which holds 24 files
   today, and `WIDEMUL_PUBLIC`, the sources whose every operand is public,
   which holds 19. The two sum to the 43 `.c` files at the repository root.
   `quic_aes.c` and `quic_gcm.c` belong in `WIDEMUL_PUBLIC`, beside the entry the list
   already carries for each file saying what that file may see
   (`Makefile:1742-1783`). The Makefile states the consequence in its own
   words: "A secret arriving in any of these is a design change, and this list
   is where it lands." Moving `quic_aes.c` out of that list is the diff a reviewer
   looks for.
3. `lib-check` (`Makefile:417-423`) diffs the packaged object's exported symbols
   against `PUBLIC` (`Makefile:363`) and fails on any difference. No `aes_` or
   `gcm_` symbol is in `PUBLIC`, so the AES cannot leave the object and be
   reused on something else by a caller.
4. `lint-quic-surface` (`Makefile:1663-1664`) runs `tools/quic-footprint.py
   --check-surface`, which already reads `quic_aes.h` and `quic_gcm.h` for its
   report. It fails on three things. A function or a function-like macro in
   either header named outside the `aes_` and `gcm_` family: check 1 matches
   names, so a name outside what it matches is AES the rule never sees. A type
   either header gives a body, which would put a key back within reach of
   every file that includes them. And any root source outside `quic_aes.c`,
   `quic_initial.c` and `quic_retry.c` that includes `quic_aes_key.h`, which
   is the one line that undoes the opacity. All three turn a premise from a
   comment into a check.

**The mutants that prove checks 1 and 4 work.** One `.violation` file whose edit adds
a call to `aes_encrypt_block` on the 1-RTT packet path in `quic_packet.c`,
with `invariant: INV-26`, `file: quic_packet.c`,
`catches: test/lint-invariants.sh` and no `builds:` line. The framework takes
a `bin/` binary by name or a script by path (`test/violations.py:135-138`), and
a make target is neither, so `test/lint-invariants.sh` is a new script, in the
shape of `test/lint-wide-multiply.sh`, that runs `make lint-invariants`. The
work creates it, and `SH_SRCS` reads the tracked `*.sh` files rather than a
hand-kept list (`Makefile:120`), so `lint-shellcheck` picks it up with no
further edit. A script target
with no `builds:` line rebuilds nothing (`test/violations.py:140`,
`test/violations.py:166-169`), so the edit is one Semgrep matches whether or
not it compiles. `test/violations/` holds 89 files today (*measured*,
`ls test/violations/*.violation | wc -l`), `test/violations.py` applies the
edit and requires the named target to fail, and an edit whose old text no
longer matches fails as stale rather than passing silently.

The value branch and check 4 each get the same treatment, because a branch no
mutant fires is a branch nobody has seen work.
`inv26-aes-entry-taken-as-value.violation` stores `&aes_encrypt_block_hp` in a
function pointer in `quic_packet.c` and calls through the pointer, so the call
branch matches nothing and the value branch is what fails
`test/lint-invariants.sh`. `inv26-cipher-entry-off-prefix.violation` adds a
`quic_encrypt_block` declaration to `quic_aes.h` and fails
`test/lint-quic-surface.sh`, a second script in the shape of
`test/lint-quic-partition.sh`. `inv26-key-header-fourth-reader.violation` adds
`#include "quic_aes_key.h"` to `quic_packet.c` and fails the same script,
because that include is what makes a key buildable there.

**The mutant that proves the compiler works.** A compiler refusal needs a catch
target that compiles, and `test/violations.py` counts a build failure under a
`builds:` line as `unguarded` rather than `caught`, because an edit that will
not compile proves nothing about the tests
(`test/violations.py:203-208`). A script target builds nothing of its own, so
the compiler's refusal becomes the script's own exit status.
`test/quic-builds.sh` runs `make bin/quic_driver_test`, which compiles every
`QUIC_SRCS` file, and `inv26-secret-into-stored-key.violation` writes a byte of
`q->t.wr_secret` into `q->initial_tx.key.round_keys` in `quic.c` and requires
that script to fail. That is the original bypass, and it now names a member
that does not exist.

### The AES axis, and what each value means

The Makefile `AES` variable picks which implementation of the AES-128 key
expansion and forward cipher an object carries. `quic_aes_block.h` states the
contract all three meet, and `quic_aes.c` calls it: that file owns the
`aes_public_key`, derives the RFC 9001 keys into it, and hands round keys down
as plain bytes.

| value | source | what it is |
| --- | --- | --- |
| `soft` (default) | `quic_aes_soft.c` | FIPS 197 in C, with the S-box as a 256-byte table |
| `hw` | `quic_aes_hw.c` | the compiler's AES intrinsics, ARMv8 or x86-64 |
| `extern` | `quic_aes_extern.c` | forwards to `ch_aes_block`, which the image defines |

One implementation per object, the way `PIN` puts one pinned algorithm in one
object. All three define the same two entries, so a second one would not link;
`lint-trust-separation` checks the packaged source list per `AES` value, and
`test/violations/aes-two-implementations-in-one-object.violation` is the mutant
that proves it fires.

The entries take plain byte arrays rather than an `aes_key_schedule`. That is
INV-26's first check holding: `quic_aes_key.h` is the one file that gives
`aes_public_key` a body, exactly three sources include it, and an
implementation that took the struct would have to become a fourth. Taking
bytes keeps the count at three, so none of the three implementations can build
a key object at all.

**Detection is the compiler's, at build time.** `quic_aes_hw.c` guards on
`__ARM_FEATURE_AES` (ARMv8 crypto extensions, `<arm_neon.h>`, `vaeseq_u8` and
`vaesmcq_u8`) and `__AES__` (x86-64 AES-NI, `<wmmintrin.h>`, `_mm_aesenc_si128`,
`_mm_aesenclast_si128` and `_mm_aeskeygenassist_si128`). Nothing probes a CPU
and nothing asks an operating system. An arm64 core cannot answer the question
itself — reading `ID_AA64ISAR0_EL1` from EL0 takes SIGILL — so runtime
detection means per-OS code, which the C11-and-libc rule forbids and which the
bare-metal m3 and freertos lanes have nobody to ask. A consumer compiles
chapulin into its own build, so it already chooses `-march=armv8-a+crypto` or
`-maes`. A build without the flag takes `AES=soft` and stays correct;
`AES=hw` without the instructions is a hard `#error`, not a silent fall back,
because `AES=hw` is a statement about what the object contains. The intrinsic
headers are the compiler's own, so they are not third-party code.

### What the AES axis proves

CBMC cannot read an intrinsic. An AES instruction has no C body to unwind, and
`ch_aes_block` is a function this tree does not contain, so the proofs cover
`quic_aes_soft.c` alone and the other two are held to it by test. This is what
each one rests on, and nothing more:

| path | proved | tested |
| --- | --- | --- |
| `soft` | `proof/quic_aes_harness.c`: memory safety and absence of UB over unconstrained inputs at the module's real bound. `spec/Spec/Aes.lean` through `test/diff_aes.h`: the cipher against FIPS 197 as the spec states it | FIPS 197 §B and §C.1, RFC 9001 Appendix A, SP 800-38D and Wycheproof AES-GCM, in `bin/quic_test` |
| `hw` | nothing | `bin/aes_equiv_test`: the round keys and the cipher block against `soft`, byte for byte, over fixed edge cases, every single-bit key and block, and 200,000 random pairs. `bin/quic_test_hw`: the same published vectors `bin/quic_test` runs. `bin/wycheproof_test_aes_hw`: the AES-GCM suite |
| `extern` | nothing | nothing here can: the block function is the image's |

`bin/aes_equiv_test` compares two things rather than one. The round keys are
compared whole, so a key schedule that diverges is named at the schedule rather
than three rounds later inside a block, and the cipher output is compared,
which is the answer callers depend on. It also runs both implementations with
`in == out`, the aliasing `quic_gcm.c` uses for its counter block.
`test/violations/aes-hw-diverges-from-soft.violation` starts the hardware key
expansion from the wrong round constant and requires that binary to fail, so
the equivalence check is itself checked. That mutant edits
`aes_expand_round_keys`, which sits outside the two architecture arms, so it
lands on an ARMv8 runner and an x86-64 one alike.

**What none of this proves.** An `AES=extern` build is unverified by this tree
beyond the contract `quic_aes_block.h` states; the integrator owns
`ch_aes_block` the way it owns `ch_rand_bytes`. And an `AES=hw` object is
checked on the architecture the runner has: a run on an ARMv8 host exercises
the `vaeseq_u8` arm and leaves the AES-NI arm compiled but unrun, and the
reverse on x86-64. Both arms are exercised only across both CI legs.

None of the three rows is a timing measurement. Every entry above compares
bytes, and no check in this tree times an AES instruction or a table lookup.
What the rows do carry is a branch count: `quic_aes.c`, `quic_aes_soft.c`,
`quic_aes_extern.c` and `quic_gcm.c` are in `BRANCH_SRCS`, so a compiler that
lowers one of their masked selects to a conditional branch fails
`lint-wide-multiply`. `quic_aes_hw.c` is not and cannot be: every spec targets
a core without the AES instructions, where that file is its own `#error`.

So whether an AES instruction runs in constant time is a claim this tree never
checks. It asks the build to make it instead. `-DCH_SUITE_AES_GCM` is how a
build says it carries a TLS cipher suite whose AEAD is AES-GCM, and therefore
hands AES a traffic key; `ct.h` refuses that build unless it also takes
`AES=hw` and defines `CH_NATIVE_AES`, the build's own assertion about the part.
`__ARM_FEATURE_AES` and `__AES__` do not carry it -- they say the instructions
exist -- and `ct.h` refuses the same inference for the widening multiply
([#53](https://github.com/c4milo/chapulin/issues/53)). INV-26 in
docs/invariants.md states what that build would owe and what is already in
place for it.

**What the axis does not change.** INV-26 still bounds which keys reach this
cipher, under every `AES` value. An AES instruction takes no table, so an
`AES=hw` build carries no S-box lookup where `AES=soft` does; whether its
latency depends on its operands is the claim `CH_NATIVE_AES` asserts above, and
that property is what `docs/decisions.md` entry 6 says a secret-key AES suite
would need. But no key
from the TLS key schedule reaches `quic_aes.c` today whatever the build, and
lifting that bound is a separate change with its own gates, not a consequence
of this one. An `AES=extern` build cannot even state its timing: what
`ch_aes_block` costs is the peripheral's.


### What the AES exception costs, against today's counts

Every count in the *today* column is *measured* at `3432a5d` with the command
shown. Every count in the *what is owed* column is *derived* from it or from
the design above, and each cell carries its derivation.

| what is owed | today | command |
| --- | --- | --- |
| CBMC launch lines: 2 more, one `full` harness per new source, plus one more if the GCM formula splits the way `aead`'s did — four harness files, three launch lines (`proof/run.sh:351-355`) | 83 launch lines, 86 harness files | `grep -c '^[[:space:]]*launch ' proof/run.sh`; `ls proof/*_harness.c \| wc -l` |
| Lean modules: 2 more, `Spec/Aes.lean` and `Spec/Gcm.lean`, plus rows in `test/diff_test.c` | 30 modules in `spec/Spec/` | `ls spec/Spec/*.lean \| wc -l` |
| Wycheproof: one suite, `aes_gcm_test.json`, and one generator arm | 18 vector files across 9 generator arms | read `test/gen_wycheproof.py:395-425` |
| `lint-wide-multiply`: 16 more `BRANCH_CEILING` entries, for `quic_keys.c` and `quic_packet.c` across 8 compiler and architecture specs. `quic_aes.c` and `quic_gcm.c` owe none: `WIDEMUL_PUBLIC` means no codegen gate compiles them, and `lint-codegen-partition` fails a file in both lists (`Makefile:1822`) | 96 entries, 12 files across 8 specs | `Makefile:2020-2047` |
| `docs/invariants.md`: 1 more invariant, INV-26. INV-27, the mode's partition, landed with the interface headers | stops at INV-27 | `docs/invariants.md:279` |
| `test/violations/`: one new mutant | 89 files | `ls test/violations/*.violation \| wc -l` |
| `.semgrep/invariants.yml`: 1 new rule, `inv-26-aes-public-keys-only`, carrying two patterns | 13 rules | `grep -c 'id:' .semgrep/invariants.yml` |

Three notes on that table. The GCM split is not a guess about difficulty; it is
what happened to `aead`, which carries four harness files and only three launch
lines, because the fourth formula returned no verdict in an hour under kissat
and an unconverged launch line proves nothing (`proof/run.sh:354-355`,
`proof/run.sh:351-353`). Every new launch line must be measured with
`/usr/bin/time -v` under `run.sh`'s own flags before it is committed
(`docs/proofs.md`). AES-ECB has no Wycheproof suite of its own, so the forward
block function's vectors come from FIPS 197's appendix and belong in
`test/unit_test.c` beside the other RFC vectors.

### The new sources, by name

Every gate above reads a file name: the Semgrep `paths: exclude:` list, the
`WIDEMUL_CEILING` and `WIDEMUL_PUBLIC` rows, the `proof/` harness names and
the `CLAUDE.md` dependency chain. These are the names, so an author can start
the gates with the first line of code. Each pair is one concern, and each
joins exactly one of the two `lint-codegen-partition` lists.

| pair | concern | codegen list, and why | harness | place in `CLAUDE.md`'s chain |
| --- | --- | --- | --- | --- |
| `quic_aes.[ch]` | the AES-128 forward cipher (FIPS 197), the `aes_public_key` type, declared incomplete here and given a body by `quic_aes_key.h`, and its two constructors | `WIDEMUL_PUBLIC`: every key it sees is public by INV-26 | `quic_aes_harness.c` | beside `chacha20.[ch]`, under `hkdf.[ch]`, which the constructors call |
| `quic_aes_key.h` | the body of `aes_public_key`, and nothing else. `quic_aes.c`, `quic_initial.c` and `quic_retry.c` include it; every other file sees the incomplete type `quic_aes.h` declares | none: it holds no code | none of its own; `quic_aes_harness.c` compiles it | beside `quic_aes.[ch]` |
| `quic_gcm.[ch]` | AEAD_AES_128_GCM seal and open, and GHASH (SP 800-38D) | `WIDEMUL_PUBLIC`: the same three keys, and GHASH multiplies a public key by public ciphertext | `quic_gcm_harness.c`, split the way `aead` split if a formula fails to converge | beside `aead.[ch]` |
| `quic_keys.[ch]` | the §5.1 labels `quic key`, `quic iv` and `quic hp`, the §6.1 `quic ku` step, and the per-level, per-direction key set that replaces `rec_dir`. It writes one `quic_hp_key` per direction per level when that level's traffic secret arrives, and the `quic ku` step rewrites the packet key and IV alone (RFC 9001 §5.4 and §6.1, `rfc9001.txt:1172-1174`, `rfc9001.txt:1607`) | `WIDEMUL_CEILING`, held at 0: it derives from traffic secrets. It joins `BRANCH_SRCS` with `quic_packet.c`, which is where the 16 new `BRANCH_CEILING` entries land | `quic_keys_harness.c` | in place of `record.[ch]` |
| `quic_packet.[ch]` | §5.3 packet protection and §5.4.4 header protection under ChaCha20-Poly1305, the §6.5 receive key-set selection — the Key Phase bit picks the phase and the recovered packet number tells the previous phase from the next — the §5.4.2 length check and the §6.6 counters | `WIDEMUL_CEILING`, held at 0: it holds 1-RTT keys. It joins `BRANCH_SRCS` too, with both halves counted: §9.5 puts a MUST on the open path and another on the seal path | `quic_packet_harness.c`, and one more for open if the seal-and-open formula does not converge | beside `quic_keys.[ch]` |
| `quic_initial.[ch]` | the Initial packet path: AES-128-GCM seal and open and the §5.4.3 AES-ECB mask, each taking the Destination Connection ID and deriving its own key on its own stack (INV-26) | `WIDEMUL_PUBLIC`: the Initial keys are public (RFC 9001 §5) | `quic_initial_harness.c` | beside `quic_packet.[ch]`, over `quic_aes.[ch]` and `quic_gcm.[ch]` |
| `quic_retry.[ch]` | the §5.8 Retry integrity tag under the printed key and nonce | `WIDEMUL_PUBLIC`: the key is printed in the RFC | `quic_retry_harness.c` | beside `quic_initial.[ch]` |
| `handshake_flight.[ch]` | the flight handlers both drivers call, moved out of `handshake.c` with their bodies unchanged but for the two edits "Entry points and their contracts" names. *Measured* after the move: `handshake.c` went from 395 lines to 156, and `handshake_flight.c` is 347. Every build compiles it | `WIDEMUL_CEILING`, held at 0: it holds every handshake secret | none of its own; `handshake_psk`, `handshake_pin` and the step legs compile it, which is what `tools/proof-cover.py` requires | between `handshake_auth.[ch]` and `handshake.[ch]` |
| `quic_step.[ch]` | `HSQ_STEP_*`, `hsq_advance` and the six step functions: one whole handshake message each | `WIDEMUL_CEILING`, held at 0: the steps derive and install traffic secrets | `quic_step_harness.c`, one launch line per step and mode | beside `handshake.[ch]`, over `handshake_flight.[ch]` |
| `quic.[ch]` | `ch_quic`, the `ch_quic_` entries, the input loop, the staged output, and the wipe that replaces `tlsi_wipe` (`session.c:25-34`), because what it wipes is key sets rather than `rec_dir` | `WIDEMUL_CEILING`, held at 0, where `tls.c` sits today | `handshake_quic_harness.c` | in place of `tls.[ch]`, above every file in this table |

`quic_aes.[ch]` and `quic_gcm.[ch]` are the only pairs the AES exception adds; the other
seven are the transport, and `quic_aes_key.h` is a header of its own with no
`.c` file: it holds the body of `aes_public_key` and nothing else, so the
three sources that build a key on a stack frame include it and every other
file sees an incomplete type. Four of the nine names appear in gate 1's
`paths: exclude:` list — `quic_aes.c`, `quic_gcm.c`, `quic_initial.c` and `quic_retry.c`. The
other five are absent from it on purpose: a call from any of them to a symbol
`quic_aes.h` or `quic_gcm.h` declares is exactly the error that rule reports. The
`WIDEMUL_PUBLIC` reason column joins the list's existing comment block
(`Makefile:1742-1783`) as its own entries, and every `WIDEMUL_CEILING` row is
an entry of the form `<name>.c:0` beside the twenty-four the list carries
today.

The table adds five `WIDEMUL_CEILING` entries, and four of them need a gate
change before they compile at all. Both gates that read the list build every
file on it under one fixed flag set with no transport define:
`lint-wide-multiply` at `Makefile:2085` and `lint-runtime-symbols` at
`Makefile:2163-2165`, each with `-DCH_RAND_EXTERN -DCH_KEX_PQ -I.` and nothing
else. `quic.c`, `quic_keys.c`, `quic_packet.c` and `quic_step.c` do not
compile without `-DCH_TRANSPORT_QUIC`, because `CH_LEVEL_*` and the new
`ch_cfg` fields sit under that guard, and adding the define to the shared line
breaks `record.c`, `io.c`, `session.c`, `handshake.c` and `tls.c`, which stay
on the same list. `handshake_flight.c` is the fifth entry and needs nothing,
because both transports compile it. Every mode-specific source in the tree
today sits in `WIDEMUL_PUBLIC` instead (`Makefile:1802-1804`), which these two
gates never compile, and `sha3.c` and `mlkem*.c` are on the gated list only
because the shared line hardcodes `-DCH_KEX_PQ`. `lint-wide-multiply` treats a
failed compile as a failure rather than a zero, in its own words: "a count of
zero from a failed compile is not a measurement" (`Makefile:2086`). So
`WIDEMUL_CEILING` gains per-file defines, in the shape `WIDEMUL_CEILING_SPEC`
already uses for per-spec ceiling overrides (`Makefile:1997-1998`, read at
`Makefile:2083`): a list of `file:defines` entries that both gate lines add for
that file alone. The QUIC sources carry `-DCH_TRANSPORT_QUIC` there and the
five TLS sources carry nothing. Every new `WIDEMUL_CEILING` entry also owes
`lint-runtime-symbols` an `RV_ALLOWED` decision, because that gate names every
compiler-runtime symbol a file pulls on rv32ic.

The work creates two files that are neither a pair nor a library source.
`test/lint-invariants.sh` is the AES mutant's catch target, above.
`test/quic_driver_test.c` builds `bin/quic_driver_test`, which is the catch
target of all nine driver mutants and the home of the QUIC sequence
differential against the Lean oracle, the work INV-22's amended mechanism
names. Both join the Makefile edits table below.

`quic_packet.c`, `quic_initial.c` and `quic_retry.c` read the packet through
the `rbuf` reader and write sealed output through the `wbuf` writer, as
`CLAUDE.md:140-141` requires of every other file. Header protection is the one
exception, and it is an exception because the mask is applied in place: RFC
9001 §5.4.1 XORs the first mask byte into the low four bits of byte 0 for a
long header and the low five bits for a short header, and XORs the next
`pn_len` mask bytes into the packet number field; the remaining mask bytes go
unused (`rfc9001.txt:1164-1170`, `rfc9001.txt:1188-1193`,
`rfc9001.txt:1202-1211`). `level` picks the width: `CH_LEVEL_INITIAL` and
`CH_LEVEL_HANDSHAKE` carry long headers and take the four-bit width,
`CH_LEVEL_APPLICATION` carries a short header and takes the five-bit one. All
of it happens inside a buffer the caller owns. One pair of functions in
`quic_packet.c` does it, `quic_header_protect` and `quic_header_unprotect`.
Each takes the five mask bytes as an argument and computes no mask, so
`quic_initial.c` computes its AES-ECB mask under the Initial keys and calls the
same pair, and no other file writes a masked byte. The `pn_off + 4 + 16` length
check runs before either, so the bytes they touch are inside a range already
proved present.

Both widths and the `pn_len` count take the boundary test `CLAUDE.md`
requires, against the RFC's own vectors first. Appendix A.2's long-header
Initial packet XORs `mask[0] & 0x0f` into byte 0 and four mask bytes into a
4-byte packet number (`rfc9001.txt:2401`, `rfc9001.txt:2411-2417`). Appendix
A.5's short-header 1-RTT packet XORs `mask[0] & 0x1f` into byte 0 and three
mask bytes into a 3-byte packet number: `4200bff4` and `aefefe7d03` give
`4cfe4189` (`rfc9001.txt:2539-2548`). Two constructed cases over A.5's key and
sample pin the ends of the range, because the RFC prints no vector at either:
a 1-byte packet number, where `mask[2]` through `mask[4]` stay unused, and a
4-byte one, where `mask[4]` is the last byte used. The `CLAUDE.md` table below
carries the replacement sentence.

Two concerns the mode needs are not new pairs, because the design puts them in
files that already exist. Reassembling one level's ordered CRYPTO bytes into
whole handshake messages, with the `cfg.buf_len` bound and the §4.1.3 refusals,
is the QUIC arm of `handshake_record.[ch]`, beside the record arm a TLS build
compiles. colibri orders the bytes by CRYPTO frame offset before it calls, so
chapulin never reads an offset. That leaves one bound on colibri's side of the
call, and it is worth stating because the obvious way to size it is wrong.
RFC 9000 §7.5 makes an endpoint buffer at least 4096 bytes of out-of-order
CRYPTO frames and close with `CRYPTO_BUFFER_EXCEEDED` rather than fail the
handshake. That is not `cfg.buf_len`: `cfg.buf_len` bounds one whole handshake
message, and under `TRUST=raw` `CH_QUIC_MIN_RXBUF` is 490, below the 4096 floor
and correctly so, because a 490-byte message and 4096 bytes of out-of-order
frames measure different things. A caller that sized its reassembly buffer from
`cfg.buf_len` would fail a handshake whose frames arrived out of order. §7.5
adds that a larger limit during the handshake is what admits larger keys, which
is the `KEX=pq` case: the hybrid ServerHello alone is 1,184 bytes.

chapulin holds the other half of the bound, and holds it in code rather than in
this paragraph. A message header naming a body past `cfg.buf_len` returns
`CH_ECAP` from `ch_quic_crypto_in` and kills the session, so no delivery grows
the object past the buffer the caller supplied, whatever the caller's own
reassembly did. NewSessionTicket stays in
`handshake_post.[ch]`, where `handle_ticket` (`handshake_post.c:31-57`) keeps
its `static` linkage and a QUIC-only wrapper reaches it. "Suspending the
driver" states both arms.

One more thing moves that is not a count. `README.md:845-849` names an AES-CCM
build flag as the likeliest v2 addition. That range is the one this commit
produces: the same commit adds two lines above that paragraph, which starts at
`README.md:843` at `3432a5d`. That paragraph has to say instead that
an AES exists in one build, protects two packet types, and is not available for
negotiation. The sentence in `CLAUDE.md` and entry 6 change in the commit that
lands the first AES source, not before; the appendix holds both replacement
texts.

### What a reader should be suspicious of

A constrained primitive tends to grow callers.

The safety here comes from who calls the code, not from how the code is
written. A table-driven AES is a table-driven AES whatever comment sits above
it. The day a 1-RTT traffic secret is passed to `aes_encrypt_block`, this tree
has a timing story to defend and entry 6's stated gain is gone — not
degraded, gone, because the gain was "no timing story to defend."

The key type makes that day an initializer or a constructor call a reviewer
can see, the Semgrep rule makes it a failed build, and the other two gates
make an edit around both visible rather than silent; the mutant proves the
first gate works. None of them stops a maintainer who edits the key type's
constructors, the Semgrep rule, the `WIDEMUL_PUBLIC` entry and the invariant
in one commit.
What stops that is a reviewer reading the diff, which is what
`docs/decisions.md` entry 32 says this codebase optimizes for.

The second suspicion is narrower and worth naming: INV-26 puts one
exception in a rule that has had none, and the next request will cite it. The
answer to that request is the invariant's own text, which permits three named
key sources and no fourth.

### The decision: chapulin owns packet protection at every level

chapulin holds every key a QUIC connection uses, derives them all, seals and
opens every packet at every level, computes every header protection mask,
validates the Retry tag, wipes a level's keys when colibri calls
`ch_quic_discard` (RFC 9001 §4.9) and wipes the rest on close. colibri writes
no crypto.

Cost, and most of it is this tree's.

- The AES exception above, with the verification debt the table counts.
- The transport's own exported symbols grow from four to the fifteen below,
  against `docs/decisions.md` entry 28. `PUBLIC` is
  `ch_connect ch_read ch_write ch_close $(PUBLIC_RAND) $(PUBLIC_CA)` today
  (`Makefile:363`), so the four TLS names are one term of three. The
  `TRANSPORT` axis replaces that term and nothing else: `PUBLIC` becomes
  `$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)`, where `PUBLIC_TRANSPORT`
  is the four TLS names under `TRANSPORT=tls` and the fifteen `ch_quic_` names
  under `TRANSPORT=quic`, selected the way `PUBLIC_CA` is selected on `TRUST`
  (`Makefile:211-221`). The other two terms keep their meaning:
  `ch_pubkey_from_pem` under `TRUST=ca` (`Makefile:211`) and `ch_drbg_seed`
  under `RAND=drbg` (`Makefile:258`). So a QUIC object exports fifteen symbols
  under `TRUST=raw RAND=extern`, sixteen under `TRUST=ca` or `RAND=drbg`, and
  seventeen under both. It cannot be a second term added to the first, because
  `lib-check` diffs the object's exported symbols against `PUBLIC` for exact
  equality (`Makefile:419-422`), so a `PUBLIC_TRANSPORT` carrying both sets
  fails every build.
- The suspendable driver, planned in its own section below. It is the larger
  piece.
- Three sets of 1-RTT receive keys instead of the one `rec_dir` per direction
  the session holds today (`record.h:23-27`). Two of the three are a normative
  floor: RFC 9001 §6.3 makes an endpoint retain two sets of packet protection
  keys for receiving, the current phase's and the next phase's
  (`rfc9001.txt:1711-1712`). The third, the previous phase's, is the policy
  choice this record makes, because §6.5 opens a delayed packet from the old
  phase under it and a two-set client discards that packet.
- One exception to entry 21's fail-closed rule, inside this tree rather than in
  the caller. `ch_quic_open` must report "discard this packet" and keep the
  session alive, because RFC 9001 §5.5 says failure to unprotect a packet does
  not necessarily indicate a protocol error or an attack
  (`rfc9001.txt:1373-1376`). INV-13 is the invariant that exception amends, and
  "What changes in `docs/invariants.md`" holds the replacement text; without it
  entry 21 is weakened quietly.
- A fifth build axis in the gates that read a build axis by name.

Gain.

- No crypto in colibri. Every traffic secret a QUIC connection uses is
  derived, held, used and wiped inside one object this tree proves. The one
  secret that leaves is the one that leaves today, the resumption PSK
  `on_ticket` hands out, and it is a key for a future connection.
- RFC 9001 §9.5 requires the whole receive path to run in constant time
  (`rfc9001.txt:2110-2112`): header protection removal, packet number recovery
  and packet protection removal MUST be applied together without timing and
  other side channels. §6.3 adds the same demand for the Key Phase bit
  (`rfc9001.txt:1684-1686`), and §9.5 puts a second MUST on the send path:
  packet payloads and packet numbers must be free of side channels that reveal
  the packet number or the size it was encoded in (`rfc9001.txt:2114-2116`).
  So the packet number and the length the caller encoded it in are secret bytes
  for both rules, and neither the nonce construction nor the mask application
  takes a branch or a memory index on either. Both halves are one function each
  in `quic_packet.c`, under `CLAUDE.md`'s constant-time rules, inside
  `lint-wide-multiply`'s multiply and conditional-branch counts and inside a
  CBMC harness. `quic_initial.c` runs the same three steps for Initial packets
  and no codegen gate compiles it, because it sits in `WIDEMUL_PUBLIC`. What
  the gate would measure there leaks nothing: anyone can compute the Initial
  keys and open the packet, so the packet number the §9.5 side channel would
  reveal is already public (RFC 9001 §5, `rfc9001.txt:999-1001`). The
  constant-time rule still binds the code; the gate is what the Initial level
  does not owe.
- One implementation of the six QUIC labels, so the `tls13 ` prefix and the
  zero-length context are written once.
- QUIC interop bugs are fixed in one repository.

### Considered and rejected: colibri owns packet protection

chapulin would expose the state machine, the per-level traffic secrets of RFC
9001 §4.1.4, the `quic_transport_parameters` body in both directions, and the
alert description of §4.8. colibri would seal and open every packet at every
level.

The cost is mostly colibri's, and it is larger than it looks. A 32-byte secret
per level per direction would be the whole of what leaves the object, so
colibri would implement: HKDF-Expand-Label with the `tls13 ` prefix,
HMAC-SHA-256 and SHA-256 under it, the six QUIC labels, ChaCha20-Poly1305
packet protection, the §5.4.4 ChaCha20 mask, AEAD_AES_128_GCM, the §5.4.3
AES-ECB mask and the §5.8 Retry tag. That is seven primitives, not two. The
secret-bearing 1-RTT crypto would then sit outside this tree's proofs, which is
the cost entry 36 refused to pay for the certificate parser: "Verifying the
chain in the caller instead of here was considered and rejected: it duplicates
a certificate parser in a second language, outside this tree's proofs." §9.5's
constant-time MUST would be re-argued there with no `lint-wide-multiply`, no
CBMC harness and no Lean module. And live traffic secrets would leave the
object. One secret leaves it today, the resumption PSK in `ch_ticket.psk`
(`cfg.h:144`), through `on_ticket` (`cfg.h:294`, `handshake_post.c:53-54`). It
is a key for a future connection, not a live traffic secret. Secrets enter
through `ch_cfg.psk` (`cfg.h:264`) and `ch_drbg_seed` (`drbg.h:26`). The
rejected split would add one 32-byte traffic secret per level per direction
to that, and each would be the first live key to leave.

Two ways to shrink that list were considered with it: export the per-level key
derivation so HKDF stays here, or export the ChaCha20 packet protection and
mask too, so only the Initial and Retry AES is colibri's. Each widens `PUBLIC`
and `lib-check`'s list, and the second is the decision above with the AES
exception removed and the AES duplicated.

What this split would have kept: `CLAUDE.md`'s AES sentence and entry 6 as
written, no AES object, no INV-26, no new Wycheproof suite, and fewer new
symbols in `PUBLIC`. It would not have kept GHASH out of a codegen gate,
because no gate measures it either way: `quic_gcm.c` sits in `WIDEMUL_PUBLIC`, and
neither `lint-wide-multiply` nor `lint-runtime-symbols` compiles a file on that
list. The suspendable driver and
the parser change are identical work either way.

### Considered and rejected: a second TLS stack for HTTP/3

colibri would adopt a second TLS stack for HTTP/3 and chapulin would stay the
TLS-over-TCP client for HTTP/1.1 and HTTP/2.

One product would then have two trust models, two failure disciplines and two
key-exchange policies. Entry 12's fail-closed post-quantum property — a
`KEX=pq` build offers X25519MLKEM768 alone and fails closed against a server
without it — would hold on the TCP path and not on the QUIC path. Entry 21's
fail-closed rule would hold on one and not the other. `TRUST=webpki`'s anchors,
hostname rule and absent revocation (`docs/webpki.md`) would be configured
twice, in two shapes. Two stacks are two audit targets, against entry 32's
stated optimization target.

What it would have kept: no work here, no AES anywhere in this tree, and the
adopted stack brings RFC 9002 loss recovery and congestion control — the
largest part of QUIC, and the part chapulin never owns.

## What the mode is

A build axis, not a run-time flag, for the same reason `TRUST`, `PIN` and `KEX`
are builds: within a mode the client offers exactly one of everything
(`CLAUDE.md`), and QUIC inverts rules the TLS build must keep. RFC 9001 §6
forbids the TLS KeyUpdate that entry 3 keeps and `handshake_post.c:63-77`
implements. RFC 9001 §8.4 forbids a client from requesting compatibility mode
(`rfc9001.txt:1979-1980`); `handshake_message.c:42` already sends an empty
legacy_session_id, so nothing changes there. The ChangeCipherSpec tolerance
at `handshake_record.c:53-59` goes with the record layer (§4.1.3,
`rfc9001.txt:462-464`), because QUIC provides no means to carry that record
(`rfc9001.txt:1977-1978`). RFC 9001 §4.1.3 removes the record layer that
entry 19's `record_size_limit` sizes.

`LIB_VARIANT` is `$(PIN)-$(TRUST)-$(KEX)-$(RAND)` today (`Makefile:287`), so
the axis is a fifth value in it: `TRANSPORT=quic`, against `TRANSPORT=tls` as
the default. The other four axes keep their meaning in a QUIC build. One
key-exchange group per build stays (entry 12), so a `KEX=pq` QUIC build offers
X25519MLKEM768 alone and fails closed against a server without it, the same as
over TCP.

## The interface it exposes

`ch_connect`, `ch_read`, `ch_write` and `ch_close` (`tls.h:14-25`) are a
byte-stream API over a socket the library drives. None of them fits. A QUIC
object exports a different set: `PUBLIC` becomes
`$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)` (`Makefile:363`), and
`PUBLIC_TRANSPORT` holds the four TLS names under `TRANSPORT=tls` and these
fifteen under `TRANSPORT=quic`, selected the way `PUBLIC_CA` is selected on
`TRUST` (`Makefile:211-221`). `PUBLIC_RAND` and `PUBLIC_CA` are unchanged on
both transports, so `lib-check`'s list is these fifteen plus
`ch_pubkey_from_pem` under `TRUST=ca` and `ch_drbg_seed` under `RAND=drbg`.
These are the names the header will use.

| call | what it does |
| --- | --- |
| `ch_quic_init(q, cfg)` | validates the configuration, prepares the state machine and builds the ClientHello into `t.tx` and sets `tx_len`. It sends nothing, and the caller takes those bytes with `ch_quic_crypto_out`. Refuses with `CH_EINVAL` for the same errors `tls.c:83-91` refuses today, minus the `cfg.send` and `cfg.recv` checks, which have no meaning here. Keeps the `cfg.buf_len >= CH_MIN_RXBUF` check, for the reason below, and keeps the `alpn_ok` check (`tls.c:376`). Adds three rules of its own, which "Suspending the driver" states: the caller's transport parameters, `on_level_ready`, and an ALPN offer of at least one protocol |
| `ch_quic_initial_keys(q, dcid, dcid_len)` | stores the caller's Destination Connection ID, which RFC 9001 §5.2 derives the Initial keys from, and marks both directions of the Initial level ready. It derives no key: the packet calls do that on their own stack (INV-26). The caller calls it again after a Retry, because the secrets change then (`rfc9001.txt:1092-1094`) |
| `ch_quic_crypto_in(q, level, p, n)` | delivers the bytes CRYPTO frames carried at one level, in order. Runs the state machine until it needs more bytes, then returns |
| `ch_quic_crypto_out(q, level, out, cap, out_len)` | hands out the one handshake message the client owes at that level, whole or not at all. Returns `CH_OK` and no bytes when nothing is owed there, and `CH_ECAP` with nothing consumed when `cap` is shorter than the message, so the caller can call again with a larger buffer |
| `ch_quic_seal(q, level, pn, pn_len, hdr, hdr_len, pt, pt_len, out, cap, out_len)` | protects one packet: the nonce from the IV and the packet number, the header as associated data (RFC 9001 §5.3), then the header protection mask over byte 0 and the `pn_len` packet number bytes the caller encoded (§5.4). It writes one whole packet into `out` and modifies neither `hdr` nor `pt`: it copies the `hdr_len` header bytes into `out`, seals `pt` after them, and applies the header protection mask to the copy in `out`. `hdr` carries the packet number field the caller encoded, so `hdr_len` counts those bytes and `pn_len` says how many of the last ones they are; `pn` is that same number and it builds the nonce. `*out_len` is `hdr_len + pt_len + 16`, and a `cap` below it returns `CH_ECAP` with nothing written. It refuses a packet it cannot sample with `CH_EINVAL` and seals nothing. The sample starts 4 bytes after the packet number offset and is 16 bytes long, and RFC 9001 §5.4.2 requires the encoded packet number and the protected payload to run at least 4 bytes past it (`rfc9001.txt:1283-1286`). That is `pn_len + pt_len >= 4` here, because the AEAD adds 16 bytes. Writing the padding is colibri's, because colibri frames the packet, and the refusal is what keeps the sample inside `out`. The boundary test is that `pn_len + pt_len == 4` seals and `pn_len + pt_len == 3` returns `CH_EINVAL`. RFC 9001 §9.5 carries a second MUST for this direction: packet payloads and packet numbers must be free of side channels that reveal the packet number or the size it was encoded in (`rfc9001.txt:2114-2116`). So `pn` and `pn_len` are secret bytes for that rule, and the nonce construction and the mask application take no branch and no memory index on either. Under the Initial keys it counts the packets it seals against §6.6's confidentiality limit and refuses the 2^23rd |
| `ch_quic_open(q, level, pkt, pkt_len, pn_off, largest_pn, current_phase_lowest_pn, key_set, pn, pt_len)` | removes header protection, recovers the packet number and removes packet protection in one call, because RFC 9001 §9.5 requires the three applied together without timing side channels (`rfc9001.txt:2110-2112`). `largest_pn` is the largest packet number the caller has successfully processed in that packet number space, the value RFC 9000 §17.1 and Appendix A.3 recover from (`rfc9000.txt:8350-8351`). `current_phase_lowest_pn` is the lowest packet number the caller has processed in the current key phase, which §6.5's selection rule reads. Discards a packet shorter than `pn_off + 4 + 16` bytes before it samples (§5.4.2). A call at `CH_LEVEL_APPLICATION` while `t.state` is below `CH_ST_CONNECTED` returns `CH_EINVAL` and changes nothing, because RFC 9001 §5.7 forbids a client from processing a 1-RTT packet before the TLS handshake is complete even when it already holds the 1-RTT keys (`rfc9001.txt:1484-1486`). At the 1-RTT level it selects the receive key set by §6.5's rule rather than by the Key Phase bit alone: the previous phase and the next phase carry the same Key Phase value (`rfc9001.txt:1735-1737`), so the bit picks the phase and, when the bit differs from the current phase's bit, the recovered packet number decides (`rfc9001.txt:1739-1743`) — below `current_phase_lowest_pn` the previous keys open the packet, at or above it the next keys do. That keeps the §5.5 MUST at `rfc9001.txt:1365-1369`, which forbids opening a higher-numbered packet under the previous keys. The phase compare and the packet number compare both run branchless under §9.5, in the mask arithmetic `ct.h` supplies, never an `if` and never an index a secret chooses. It writes the set that opened the packet to `key_set`: `CH_QUIC_KEY_PREVIOUS`, `CH_QUIC_KEY_CURRENT` or `CH_QUIC_KEY_NEXT`. It works in place in `pkt`, which the caller owns and which holds one whole packet. The two new parameters are `uint64_t *pn` and `size_t *pt_len`. On `CH_OK` the unprotected header sits at the front of `pkt`, the plaintext follows it at `pn_off + pn_len`, `*pt_len` is the plaintext length in bytes and `*pn` is the recovered packet number; a call that does not return `CH_OK` leaves both outputs alone. `*pn` is the value RFC 9000 Appendix A.3 decodes (`rfc9000.txt:8350-8351`), and the caller has no other source for it: it feeds the next call's `largest_pn` and `current_phase_lowest_pn`, and §6.4's KEY_UPDATE_ERROR compares it against the packet numbers of newer key phases, which §6.4 leaves colibri to judge. Recovering it a second time in the caller would put packet number recovery outside the function §9.5 requires it to share with the two unprotect steps (`rfc9001.txt:2110-2112`). A `CH_QUIC_KEY_NEXT` result is a peer-initiated key update, and the caller must call `ch_quic_key_update` before it seals the ACK (§6.2, `rfc9001.txt:1654-1656`). A successful open leaves the unprotected header in `pkt`, so the caller reads byte 0 there for the reserved bits, the Key Phase bit and the packet number length. A packet whose Key Phase bit differs from the current phase and that then fails to authenticate under the selected key set is a discard, and it changes no key set: `ch_quic_open` never installs an update, and `key_set` is written only on a successful open. That is the second §5.5 MUST, which discards a packet that appears to trigger a key update and cannot be unprotected (`rfc9001.txt:1369-1371`), and §6.3 gives the reason, that packets carrying an apparent key update are easy to forge (`rfc9001.txt:1706-1707`). A packet that fails to authenticate is a discard rather than a session failure (§5.5), and it raises the connection-wide §6.6 count of failed opens; the call that carries `open_failures` past 2^36 returns `CH_QUIC_AEAD_LIMIT` and makes the session dead, so no later call processes a packet |
| `ch_quic_retry_ok(q, pseudo, n, tag)` | recomputes the §5.8 tag under the RFC's printed key and nonce and compares it with `ct_memeq` |
| `ch_quic_key_update(q)` | advances the 1-RTT send secret with `quic ku` (§6.1), toggles `key_phase`, which is the bit the caller must set in byte 0 of every 1-RTT header it seals from then on (RFC 9001 §6.1, `rfc9001.txt:1615-1616`), moves the current receive key set to previous and holds it, promotes the next receive keys to current and generates the next ones (§6.3). No call derives a receive key set while it opens a packet: RFC 9001 §6.3 makes that a timing signal an attacker reads (`rfc9001.txt:1692-1696`), and §9.5 says an endpoint generates and saves the next set after receiving a key update (`rfc9001.txt:2122-2123`). It rewrites the packet protection key and the packet protection IV of every set it touches from the new `quic ku` secret, and it leaves both `quic_hp_key` values alone: RFC 9001 §5.4 keeps one header protection key for the whole connection (`rfc9001.txt:1172-1174`) and §6.1 says the header protection key is not updated (`rfc9001.txt:1607`). A build that derived a new one would compute a mask the peer cannot reproduce, and every 1-RTT packet after the first update would fail header protection removal at both ends. It never drops a set: RFC 9001 §6.1 makes an endpoint retain its old keys until a packet sent under the new keys opens (`rfc9001.txt:1637-1638`), and `ch_quic_drop_previous_keys` is the only call that wipes the previous set. The caller initiates under §6.1's two MUST NOTs, not before the handshake is confirmed and not before a packet under the current keys was acknowledged (`rfc9001.txt:1618-1621`), and responds under §6.2 when `ch_quic_open` reports `CH_QUIC_KEY_NEXT`: then this call is mandatory before the ACK is sealed |
| `ch_quic_key_phase(q)` | reports `key_phase`, the Key Phase bit the current 1-RTT send key carries. The caller writes it into byte 0 before it calls `ch_quic_seal` at `CH_LEVEL_APPLICATION`. chapulin holds the send key and the bit that names it, so the two cannot disagree |
| `ch_quic_drop_previous_keys(q)` | wipes the previous 1-RTT receive key set, after which a packet from the old key phase is a discard. colibri calls it when its own PTO timer fires, which is the retention period §6.5 leaves to the endpoint |
| `ch_quic_discard(q, level)` | wipes that level's key sets in both directions. After a discard, `ch_quic_seal` and `ch_quic_open` at that level return `CH_EINVAL` and change nothing, the code that leaves the session live, because a packet under discarded keys is one the caller drops rather than a peer error. `ch_quic_crypto_in` at that level fails the session with `CH_EPROTO` and `ch_quic_error_code` reports 0x0a, which is the §4.1.3 rule for CRYPTO bytes at a level this client has left. A call at a level whose keys are not installed yet is `CH_EINVAL` for the same reason, so a seal at `CH_LEVEL_APPLICATION` before the Finished step changes nothing. RFC 9001 §4.9.1 makes a client discard Initial keys when it first sends a Handshake packet (`rfc9001.txt:942-946`), and §4.9.2 makes it discard Handshake keys when the handshake is confirmed (`rfc9001.txt:953-954`) |
| `ch_quic_state(q)` | reports whether the handshake is complete in the sense of RFC 9001 §4.1.1: this client has sent its Finished and verified the server's. It reports complete only after `ch_quic_crypto_out` has handed the Finished to the caller, never while those bytes are still staged |
| `ch_quic_alert(q)` | reports the alert description. `ch_quic_error_code` is what the caller puts on the wire; this call names the TLS alert behind it |
| `ch_quic_error_code(q)` | reports the transport error code the caller sends in CONNECTION_CLOSE (RFC 9001 §4.8). It returns a `uint64_t`, because that field is a variable-length integer (RFC 9000 §19.19, `rfc9000.txt:6670-6671`), even though every value this mode produces fits in 16 bits. It returns 0x0a, PROTOCOL_VIOLATION, for the four refusals RFC 9001 makes a connection error of that type — CRYPTO bytes at a level below `rx_level`, CRYPTO bytes at a higher level while bytes at a lower one sit unconsumed (§4.1.3, `rfc9001.txt:482-486`, `rfc9001.txt:491-493`), a post-handshake CertificateRequest (§4.4) and a NewSessionTicket whose `early_data` names any `max_early_data_size` but 0xffffffff (§4.6.1, `rfc9001.txt:808-809`) — and 0x0100 plus `ch_quic_alert`'s description for every other failure |
| `ch_quic_close(q)` | wipes every secret a `ch_quic_discard` has not wiped yet and marks the session dead |

Two callbacks in `ch_cfg` carry what a return value cannot:

| callback | what it does |
| --- | --- |
| `on_level_ready(io, level, direction)` | reports that one direction at one encryption level can now protect or unprotect packets. It carries no key material: no secret leaves the object through it. It fires inside `ch_quic_crypto_in`, never from a poll, because RFC 9001 §4.1.4 makes new keys a result of providing input to TLS (`rfc9001.txt:530-531`) |
| `on_transport_params(io, body, len)` | hands the server's `quic_transport_parameters` body to the caller. The body is opaque to TLS (RFC 9001 §8.2) |

**One level produces two calls, one per direction.** Two is right, for two
reasons in the RFC. §4.1.4 says TLS indicates that reading *or* writing keys at
that level are available (`rfc9001.txt:526-528`), which is two indications.
§5.1 says each encryption level has separate secret values for each direction
(`rfc9001.txt:1010-1012`). In this client the two fire back to back, because
`handshake_flight.c:231` computes `c_hs` and `s_hs` together and
`handshake_flight.c:338` does the same for the application secrets, but the
interface still reports them separately so a caller can install a read key
before it has anything to send.

**`cfg.buf_len` stays, and what it now bounds.** Today `buf_len` does two jobs.
It is checked against `CH_MIN_RXBUF` at `tls.c:88` and `tls.c:383` so the
largest server flight fits, and its value minus record overhead is advertised
as `record_size_limit` at `handshake.c:138-139`, which is why `cfg.h:281-282`
can say "the peer can never overflow it". QUIC deletes the second job and
leaves the first, so `buf_len` becomes the *only* cap on what a peer can send
into this object. It bounds the largest single handshake message at one
encryption level, and the driver refuses a message that could never fit rather
than assume one does. One message, not one flight: the driver feeds, peeks and
runs a step per message, and it enforces the bound at the message header, the
check `handshake_post.c:88` already makes. "Suspending the driver" gives the
termination argument that rests on it. The constant is `CH_QUIC_MIN_RXBUF`,
defined in `cfg.h` beside `CH_TRUST_MIN_RXBUF` and `CH_KEX_MIN_RXBUF`. It is
the maximum of three terms: the trust term without its 22 record bytes, the
key-exchange term without its 5 record-header bytes, and the server's
transport-parameters body. Under `TRANSPORT=quic`, `CH_MIN_RXBUF` is
`CH_QUIC_MIN_RXBUF` and nothing else, because the two TLS terms measure a
record stream this build has no record layer for (`cfg.h:115` keeps its meaning
under `TRANSPORT=tls`). The shape of the formula is the tree's, not the mode's:
`CH_MIN_RXBUF` is already a maximum over per-feature terms, and a QUIC build
takes the maximum over the QUIC terms.

Each term loses the record bytes a CRYPTO stream does not pay, and no term is
dropped. The trust term is `2 * (CH_X509_MAX + 5) + 8 + 22` under `TRUST=ca`
(`cfg.h:98`), `4 * (3072 + 5) + 8 + 22`, 12,338 bytes, under `TRUST=webpki`
(`cfg.h:105`) and 512 under `TRUST=raw` (`cfg.h:107`); the 22 bytes pay for
the record that completes a message (`cfg.h:82-87`), and a CRYPTO stream has
no such record. The key-exchange term is `5 + 4 + 40 + 6 + 1128 + 6` under
`KEX=pq` (`cfg.h:110`), 1,189 bytes, of which the leading 5 are the record
header (`cfg.h:88-91`); the 1,184 bytes left are the hybrid ServerHello
message itself, which a QUIC build must hold whole like any other message.
Dropping that term would floor a `TRANSPORT=quic KEX=pq TRUST=raw` build at
the trust term alone, 512 at most, against that 1,184-byte message. The third
term is the server's transport-parameters body, which has no measurement in
this tree. `CH_QUIC_MIN_RXBUF` is the maximum of the three, and each term is
measured before it is written. Dropping the check would leave the object with
no bound at all.

**Configuration.** Two new configuration fields carry the client's own encoded
transport parameters, `ch_cfg.transport_params` and
`ch_cfg.transport_params_len`, which the hello copies unread. The ALPN list
already exists: `ch_cfg.alpn_protocols` and `ch_cfg.alpn_count`
(`cfg.h:375-376`), the server's choice in `ch_tls.alpn_selected`
(`session.h:105`) with `CH_ALPN_NONE` (`cfg.h:236`) for no selection, and the
`alpn_ok` check in `ch_connect` (`tls.c:376`). `docs/webpki.md` states what the
caller sets and what the client refuses, and `docs/decisions.md` entry 37
states why. Today only a `TRUST=webpki` build declares them; RFC 9001 §8.1
makes them mandatory in every trust mode of a `TRANSPORT=quic` build
(`rfc9001.txt:1891-1895`), so the `#ifdef CH_TRUST_WEBPKI` guards around them
move, and `ch_quic_init` keeps the `alpn_ok` check. One rule differs from
`docs/webpki.md`'s: there a server that sends no ALPN extension leaves
`ch_tls.alpn_selected` at `CH_ALPN_NONE` and the handshake completes. Under
`TRANSPORT=quic`, §8.1 makes a client close with `no_application_protocol` when
no protocol is negotiated (`rfc9001.txt:1897-1902`), so `CH_ALPN_NONE` after
EncryptedExtensions is a failure with that alert.

Zero heap is unchanged in kind. There is still one session struct and one
caller-supplied buffer, and no allocation anywhere. The struct's size changes;
see the next section.

## Suspending the driver

This is the largest single piece of work in the mode, larger than the AES. It
decides what the mode costs.

### What the driver does today

`ch_handshake` (`handshake.c:133`) puts a `handshake_state` on its own stack
frame (`handshake.c:134`), calls `run(&h)` (`handshake.c:149`), and wipes the
frame before returning (`handshake.c:151`). `run` (`handshake.c:81`) is one
straight-line function. It blocks on the wire at five call sites, every one of
them a call to `hsr_next_msg`:

| site | message it waits for |
| --- | --- |
| `handshake_flight.c:150` (`hsf_read_server_hello`) | ServerHello, reached once or twice, because `hello_exchange` calls it again after a HelloRetryRequest (`handshake.c:69`) |
| `handshake_flight.c:243` | EncryptedExtensions |
| `handshake_auth.c:245` (`hsa_server_auth`) | Certificate |
| `handshake_auth.c:100` (`check_certificate_verify`) | CertificateVerify |
| `handshake_flight.c:305` (`hsf_read_finished`) | server Finished |

All five call `hsr_next_msg` (`handshake_record.c:115`), which loops calling
`hsr_fetch_record` (`handshake_record.c:75`, called at
`handshake_record.c:133`) until a whole message sits in `cfg.buf`, and
`hsr_fetch_record` calls `io_read_record` (`handshake_record.c:87`), which
blocks on `cfg.recv` (`cfg.h:290`). A sixth pull sits after the handshake, at
`handshake_post.c:220`.

So the driver calls the network; the network does not call the driver. A QUIC
interface reverses that: `ch_quic_crypto_in` must return when the bytes it was
handed run out, and resume where it stopped when the caller brings more.

### The design: one whole message per step

The QUIC object runs one step per arriving handshake message. A step is a
function of one whole message and the saved state, and it runs only when a
whole message is already in `cfg.buf`. Nothing inside a step waits, so no
step needs a resume point inside itself, and the stored state is a single
step number rather than a program counter.

Three rules hold the design together.

1. **The QUIC reader never waits, and the driver never runs a step without a
   whole message.** Under `TRANSPORT=quic`, `hsr_next_msg` keeps its name,
   signature and contract — "yields the next complete handshake message, raw
   (header included) for the transcript" (`handshake_record.h:65-67`) — and
   reads no record: it yields the message the driver has already checked is
   present. That check is `hsr_peek_message`, a new pure function the driver
   calls first.
2. **The protocol handlers move out of `handshake.c` into
   `handshake_flight.c`, which both transports compile.** The QUIC object gets
   no second copy of the HelloRetryRequest transcript rule, the acceptance
   checks, the binder, the key derivation or the Finished check.
3. **Every step advances the stored step number, and a step number no step
   wrote kills the session.** There is no other way to reach a handler.

**The session object.** `TRANSPORT=quic` exports `ch_quic`, which holds a
`ch_tls`, the `handshake_state` that today lives on `ch_handshake`'s frame,
and the driver's own fields:

```c
typedef struct {
    ch_tls t;
    handshake_state hs;   // hs.t == &q->t, rewritten at every public entry
    uint8_t step;         // HSQ_STEP_*, below
    uint8_t rx_level;     // the one level whose CRYPTO bytes cfg.buf holds
    uint8_t tx_level;     // the level of the bytes in t.tx, when tx_len != 0
    uint8_t alert;        // what ch_quic_alert reports after a failure
    size_t tx_len;        // 0 when nothing is owed
    uint8_t key_phase;    // the Key Phase bit the current 1-RTT set carries
    uint8_t initial_dcid[CH_QUIC_DCID_MAX]; // the Initial level derives from these
    uint8_t initial_dcid_len;               // 0 through CH_QUIC_DCID_MAX
    quic_keys handshake_rx, handshake_tx;   // the Handshake level
    quic_hp_key handshake_hp_rx, handshake_hp_tx; // fixed for the connection
    quic_keys app_tx;                       // the 1-RTT send set
    quic_keys app_rx[CH_QUIC_KEY_SETS];     // previous, current, next
    quic_hp_key app_hp_rx, app_hp_tx;       // fixed for the connection
    uint64_t open_failures;   // RFC 9001 6.6, connection-wide, every level
    uint64_t initial_sealed;  // RFC 9001 6.6, the Initial keys alone
} ch_quic;
```

One `quic_keys` value is one direction at one encryption level: the packet
protection key and the packet protection IV RFC 9001 §5.1 derives under
`quic key` and `quic iv`. The header protection key §5.1 derives under
`quic hp` is a separate value, `quic_hp_key`, one per direction per encryption
level, because its lifetime is different. §5.4 keeps one header protection
key for the whole connection, with the value not changing after a key update
(`rfc9001.txt:1172-1174`), and §6.1 states the same rule for the update step:
the header protection key is not updated (`rfc9001.txt:1607`). So each
`quic_hp_key` is written once, when that level's traffic secret first arrives,
and `ch_quic_key_update` never rewrites one. The Initial level stores neither
value. Its AEAD is AES-128-GCM (§5.2) and its header protection is AES-ECB
(§5.4.3), and INV-26 keeps every AES key off this struct: `initial_dcid` holds
the Destination Connection ID the keys come from, and `quic_initial.c` builds
one `aes_public_key` per packet on its own stack.
`aes_public_key_initial(k, dcid, dcid_len, direction)` writes all three fields
of it: the 16-byte AEAD_AES_128_GCM packet protection key expanded into its
round keys, the 12-byte packet protection IV, and the 16-byte AES-128-ECB
header protection key expanded into its own round keys, which are RFC 9001
§5.1's `quic key`, `quic iv` and `quic hp` over the Initial secret.
`aes_public_key_retry()` writes the §5.8 key alone and leaves the IV and the
header protection key zero, because the Retry tag takes the nonce §5.8 prints
and applies no header protection, and `quic_retry.c` is its only caller. So the
§5.4 rule that the header protection key never changes holds at every level:
`ch_quic_key_update` rewrites no `quic_hp_key` and reaches no Initial key at
all, and `ch_quic_initial_keys` rewrites `initial_dcid`, which §5.2 requires
after a Retry and which is not a key update. `CH_QUIC_KEY_SETS` is 3 and
its slots are the `#define`d indices `CH_QUIC_KEY_PREVIOUS` 0,
`CH_QUIC_KEY_CURRENT` 1 and `CH_QUIC_KEY_NEXT` 2, which are the same three
values `ch_quic_open` writes to `key_set` and the only names this record gives
them. §6.3 makes two of the three a floor
(`rfc9001.txt:1711-1712`) and the previous set is this record's policy
choice, stated in "The decision" above. `ch_quic_open` never indexes
`app_rx` by a value a secret chose: it reads all three slots and masks the
chosen one out, which is what §9.5 and §6.3 require of the selection
(`rfc9001.txt:2110-2112`, `rfc9001.txt:1684-1686`).

Zero heap holds: one static struct, one caller buffer, no allocation. Under
`-DCH_TRANSPORT_QUIC` the `ch_tls` inside it drops `rd` and `wr`
(`session.h:73-74`), `peer_limit` (`session.h:79`), `keys` (`session.h:81`)
and `send_epochs` (`session.h:117`), and its `tx` loses the `REC_HDR` prefix of
`session.h:121`. It keeps `rd_secret` and `wr_secret` (`session.h:75-76`),
which hold the 1-RTT traffic secrets the `quic ku` step reads: `ks_master`
already writes them (`handshake_flight.c:338`), and a second pair of fields under
another name would be a second name for one thing. It keeps `pt_off` and
`pt_len` (`session.h:119-120`) with
the meaning the TLS reader gives them at `handshake_record.c:115-116`: the
unread bytes inside `cfg.buf`, here the unread CRYPTO bytes of one level.
Every one of those edits is an `#ifdef` or `#ifndef`, so the preprocessed
struct a TLS build compiles is the text it is today. `alpn_selected`
(`session.h:95-106`) is the precedent.

**The step numbers.** `HSQ_STEP_AWAIT_SERVER_HELLO` 0,
`HSQ_STEP_AWAIT_RETRY_HELLO` 1, `HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS` 2,
`HSQ_STEP_AWAIT_CERTIFICATE` 3, `HSQ_STEP_AWAIT_CERTIFICATE_VERIFY` 4,
`HSQ_STEP_AWAIT_FINISHED` 5 and `HSQ_STEP_COMPLETE` 6. They are `#define`d
`uint8_t` values, not an enum, in the style `CH_ST_START` and its three
neighbours already use (`session.h:66-69`), and `ch_quic.step` stores one.
The psk and pin configurations differ at one step:
`HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS` advances to `HSQ_STEP_AWAIT_FINISHED`
when `cfg.psk` is set and to `HSQ_STEP_AWAIT_CERTIFICATE` when it is not,
which is the branch `handshake.c:103` takes today and the fork
`spec/Spec/Handshake.lean:99-100` models.

**The levels.** `CH_LEVEL_INITIAL` 0, `CH_LEVEL_HANDSHAKE` 1 and
`CH_LEVEL_APPLICATION` 2, declared in `cfg.h` under the QUIC guard.
`rx_level` moves twice, once in the ServerHello step and once in the Finished
step. No code indexes a key field by `rx_level`; each step installs keys into
the fields of one named level.

**`ch_quic_init(q, cfg)` builds the ClientHello.** It zeroes `q`, copies the
configuration, and applies the rules `ch_connect` applies today
(`tls.c:77-91` for raw and ca, `tls.c:379-386` for webpki) minus the
`cfg.send` and `cfg.recv` checks, which have no meaning here. It keeps
`buf_len >= CH_MIN_RXBUF` and the `alpn_ok` check (`tls.c:376`), and adds
three rules of its own: the caller's encoded transport parameters are present
and within `CH_TRANSPORT_PARAMS_MAX`, `on_level_ready` is not NULL, and the
ALPN offer names at least one protocol, because RFC 9001 §8.1 makes ALPN
mandatory. Any failure sets `CH_ST_FAILED` and returns `CH_EINVAL`. Then it
runs `hsf_begin`, builds the ClientHello into `t.tx` and sets `tx_len`,
`tx_level = CH_LEVEL_INITIAL`, `step = HSQ_STEP_AWAIT_SERVER_HELLO`,
`rx_level = CH_LEVEL_INITIAL` and `t.state = CH_ST_START`. It sends nothing:
colibri takes the bytes with `ch_quic_crypto_out`. Building the hello here
rather than at the first `ch_quic_crypto_out` costs one step value fewer and
needs no field saying a hello is owed, and it makes
`HSQ_STEP_AWAIT_SERVER_HELLO` mean exactly what Lean's `start` means,
"ClientHello sent" (`spec/Spec/Handshake.lean:63-64`).

**`ch_quic_crypto_in(q, level, p, n)` is the one suspension point.** It
asserts `t.state <= CH_ST_FAILED`, the contract-point guard `tls.c:178`
uses, and rewrites `hs.t = &q->t` so a copied session cannot leave a dangling
pointer in the public calls. Then:

- a failed or closed session returns `CH_EPROTO`, the code `ch_write` returns
  for a state that is not `CH_ST_CONNECTED` (`tls.c:220-222`); the rule here is
  narrower, because this call takes CRYPTO bytes throughout the handshake;
- `level` above `CH_LEVEL_APPLICATION`, or `tx_len != 0`, returns `CH_EINVAL`
  and changes nothing, the meaning `cfg.h:48` gives that code, and `t.tx`
  holds one message at a time;
- `level` above `rx_level` splits in two, on the unread window `pt_off` and
  `pt_len` name. With `pt_off != pt_len`, bytes at a lower level sit
  unconsumed while keys for a higher one arrive, which RFC 9001 §4.1.3 makes
  a connection error of type PROTOCOL_VIOLATION (`rfc9001.txt:491-493`): the
  session fails with `CH_EPROTO`, and `ch_quic_error_code` reports 0x0a. With
  `pt_off == pt_len` it is `CH_EINVAL` and nothing changes, because a level
  whose keys are not installed is QUIC's to hold (`rfc9001.txt:488-490`) and
  the caller may deliver the same bytes again once it is;
- `level` below `rx_level` is a byte at a level this client has left. RFC 9001
  §4.1.3 makes data that extends past the end of what was already received at
  that level a connection error of type PROTOCOL_VIOLATION
  (`rfc9001.txt:482-486`). colibri delivers each level's CRYPTO bytes once and
  in order, so every byte that reaches this arm is such a byte: the session
  fails with `CH_EPROTO`, and `ch_quic_error_code` reports 0x0a. A
  retransmitted CRYPTO frame is legal on the wire and colibri drops its bytes
  rather than delivering them again;
- otherwise the driver loops: copy what fits into `cfg.buf`, ask
  `hsr_peek_message` whether a whole message is present, run one step if it
  is, return `CH_OK` if it is not.

The loop terminates and never resizes anything, for a reason worth stating
because a proof rests on it. The copy compacts first, so `pt_off` is 0 and the
copy takes `min(n, buf_len - pt_len)` bytes. If input bytes remain after a
copy, the buffer is full; `pt_len == buf_len >= CH_MIN_RXBUF`, and every term
of `CH_QUIC_MIN_RXBUF` is at least 490, the raw trust term without its 22
record bytes, so `hsr_peek_message` can read a 4-byte header, and it either
refuses the message or finds it whole. So a full buffer never reports "more
bytes needed", which means that answer implies every input byte was taken. Each
iteration consumes at least four buffer bytes or ends the call.

After a step returns, the driver makes one more check. A step that moved
`rx_level` or staged a message must leave `cfg.buf` empty and consume the
whole delivery; a leftover byte fails the session with `CH_EPROTO`, and
`ch_quic_error_code` reports 0x0a. RFC 9001 §4.1.3 makes unconsumed data from
a previous encryption level a connection error of type PROTOCOL_VIOLATION
when keys for a higher level arrive (`rfc9001.txt:488-493`), and the same
check covers the HelloRetryRequest: the server's second flight answers the
second ClientHello (RFC 9846 §4.2.4, `rfc9846.txt:1444`), so an Initial byte
that arrives with the HelloRetryRequest, before that hello has gone out, is
out of order.

**`hsq_advance(q)` is the one switch**, in `quic_step.c`. It maps the
stored step to one of six step functions — `HSQ_STEP_AWAIT_SERVER_HELLO` and
`HSQ_STEP_AWAIT_RETRY_HELLO` share one — and its default arm sets
`unexpected_message` and returns `CH_EPROTO`. So a one-byte corruption of
`step` kills the session rather than faulting or running a handler: it does
not reach `ch_assert_fail`, and it does not run a step.

**The ServerHello step, with the HelloRetryRequest restart.** It calls
`hsf_read_server_hello`, which is today's `read_server_hello`
(`handshake_flight.c:146-177`) moved whole, transcript rule and cookie copy
included. On a HelloRetryRequest it checks the stored step: at
`HSQ_STEP_AWAIT_RETRY_HELLO` a second HelloRetryRequest is
`unexpected_message`, which is the refusal `handshake.c:73-76` makes today
by call position; otherwise it builds the retry ClientHello into `t.tx` and
sets the step to `HSQ_STEP_AWAIT_RETRY_HELLO`. `t.tx` is free at that moment
because `ch_quic_crypto_in` refuses input while `tx_len != 0`. On an
accepted ServerHello it runs `hsf_accept_server_hello`
(`handshake_flight.c:179-202`) and `hsf_derive_handshake_secrets`
(`handshake_flight.c:204-236`), installs the Handshake-level packet keys, fires
`on_level_ready` twice, sets `rx_level = CH_LEVEL_HANDSHAKE` and advances the
step. The derivation runs in the same call as the read because
`info.server_ct` points into `cfg.buf` under `KEX=pq`
(`handshake_parser.h:39-44`) and the ML-KEM decapsulation reads it.
`info.server_pub` is a copy the parser writes into the struct
(`handshake_parser.h:38`), so a classic build could defer the derivation; the
design keeps one step for both so the step table has one shape.

**The rest of the flight**, one step each.

| step | what it runs | where it goes |
| --- | --- | --- |
| `HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS` | `hsf_read_encrypted_extensions` (`handshake_flight.c:238-297`), whose QUIC arm hands the `quic_transport_parameters` body to `on_transport_params` | `HSQ_STEP_AWAIT_FINISHED` under psk, `HSQ_STEP_AWAIT_CERTIFICATE` under pin |
| `HSQ_STEP_AWAIT_CERTIFICATE` | `hsa_server_auth`, whose QUIC arm returns right after it hashes the Certificate (`handshake_auth.c:293`), with `hs.leaf`, `t.pin_slot` and the epoch status written | `HSQ_STEP_AWAIT_CERTIFICATE_VERIFY` |
| `HSQ_STEP_AWAIT_CERTIFICATE_VERIFY` | `hsa_read_certificate_verify`, QUIC only, which is `handshake_auth.c:295-297`: take the transcript hash, then `check_certificate_verify` unchanged | `HSQ_STEP_AWAIT_FINISHED` |
| `HSQ_STEP_AWAIT_FINISHED` | `hsf_read_finished` (`handshake_flight.c:299-328`), `hsa_epoch_commit` under `TRUST=ca` (`handshake.c:113-115`), then `hsf_complete`: `ks_master`, the client Finished built and hashed, `ks_res_master`. The Finished goes into `t.tx` at the Handshake level; the application secrets become the 1-RTT send set `app_tx` and two 1-RTT receive sets: `app_rx[CH_QUIC_KEY_CURRENT]` from the server application traffic secret and `app_rx[CH_QUIC_KEY_NEXT]` from that secret advanced once with `quic ku`, so the next set exists before any packet arrives under it. `app_rx[CH_QUIC_KEY_PREVIOUS]` stays zero until the first `ch_quic_key_update`. Then two `on_level_ready` calls | `HSQ_STEP_COMPLETE`, and `hs` is wiped here |
| `HSQ_STEP_COMPLETE` | the message is a NewSessionTicket or the session dies. `hspost_take_ticket` reaches `handle_ticket` (`handshake_post.c:31-57`); every other type is `unexpected_message` and `CH_EPROTO`, and the step records the message type it refused, because two of them take different codes on the wire: a CertificateRequest is PROTOCOL_VIOLATION, 0x0a (RFC 9001 §4.4, `rfc9001.txt:736-738`), and a KeyUpdate is 0x010a, which is 0x0100 plus unexpected_message (RFC 9001 §6, `rfc9001.txt:1566-1568`). `ch_quic_error_code` reads that record. The QUIC arm of `handle_ticket` reads the ticket's extension block: an absent `early_data` and an `early_data` whose `max_early_data_size` is 0xffffffff are accepted, and any other value fails the session with `CH_EPROTO` and makes `ch_quic_error_code` report 0x0a, because RFC 9001 §4.6.1 puts an unconditional client MUST on it (`rfc9001.txt:808-809`) | `HSQ_STEP_COMPLETE` |

Two details in that table are load-bearing. The wipe of `hs` at
`HSQ_STEP_COMPLETE` is INV-17's rule that handshake secrets die at CONNECTED
(`docs/invariants.md:770-774`), one round trip earlier than the TLS driver
reaches it at `handshake.c:151`. And the CertificateVerify step recomputes
the transcript hash rather than carrying it from the Certificate step, which
is correct only while nothing touches `t.transcript` between the two steps; a
comment at the recompute names that dependency.

**`ch_quic_crypto_out(q, level, out, cap, out_len)` is all or nothing.** With
nothing owed at that level it returns `CH_OK` and no bytes. With `cap`
shorter than the staged message it returns `CH_ECAP` and consumes nothing, so
the caller can call again with a larger buffer; that short buffer is the
caller's, not the peer's, and it does not kill the session. Otherwise it
copies the whole message and clears `tx_len`. Refusing a partial drain keeps
an offset out of the saved state, and colibri holds sent CRYPTO bytes for
retransmission anyway (RFC 9001 §4.9). When the step is `HSQ_STEP_COMPLETE`
and the bytes handed out are the client Finished, `t.state` becomes
`CH_ST_CONNECTED`: that is the moment RFC 9001 §4.1.1 names, the stack has
sent its Finished and verified the peer's. `ch_quic_state` reports `t.state`,
so it never reports complete while the Finished is still staged.

**Failure is one function.** `quic_fail` copies `hs.alert` into `q->alert`,
wipes `hs`, every key field the struct holds, `t.rd_secret` and `t.wr_secret`,
clears `tx_len`,
`t.pt_off` and `t.pt_len`, and sets `CH_ST_FAILED`. It is what `tlsi_fail`
(`session.c:36-40`) is for TLS, minus the alert record, which QUIC has no way
to carry. `ch_quic_alert` then reports `q->alert`, and `ch_quic_close` wipes
the same fields and sets `CH_ST_CLOSED`.

Cognitive complexity is what `clang-tidy` measures against the threshold of
15 (`.clang-tidy:98`), and the shape above is built for it: no function holds
more than one message's worth of logic, and the one switch does nothing but
dispatch.

### What moves out of `handshake.c`

`handshake_flight.c` takes the handlers with the prefix `hsf_`. Their bodies
are unchanged but for the two edits "Entry points and their contracts" names:
six wipes added inside `hsf_derive_handshake_secrets`, and one reordering
inside `hsf_complete`. Both transports compile it. *Measured* after the move:
`handshake.c` went from 395 lines to 156, and `handshake_flight.c` is 347.
What stays in `handshake.c` is the TLS driver: `run`'s call order, the record
header and `io_send_all` at `handshake.c:33-40` and `:45-50`, the
`rec_dir_init` installs at `:94-97` and `:125-129`, and `ch_handshake` itself
(`:133-156`), unchanged.

The alternative to that move is a second copy of about 150 lines of protocol
logic in the QUIC object: the HelloRetryRequest transcript rule, the
acceptance checks, the binder computation, the Finished check and the key
derivation. The proofs, the sequence oracle and the violation files would
then cover one of the two copies. Auditable beats compact (`CLAUDE.md`).

### The state that survives a return

Everything between calls lives in the one `ch_quic`. *Measured* 2026-09-16,
compiling the tree's unmodified headers at `3432a5d` against a program outside
the tree with `cc -std=c11 -DCH_RAND_EXTERN -I.` and the mode's own defines:

    sizeof(handshake_state) = 448   TRUST=raw            sizeof(ch_tls) = 1144
    sizeof(handshake_state) = 856   TRUST=ca PIN=rsa     sizeof(ch_tls) = 1144
    sizeof(handshake_state) = 536   TRUST=ca PIN=ecdsa   sizeof(ch_tls) = 1144
    sizeof(handshake_state) = 976   TRUST=webpki         sizeof(ch_tls) = 1744
    sizeof(handshake_state) = 512   KEX=pq               sizeof(ch_tls) = 2328
    sizeof(rec_dir)         = 56    all five

The two CA rows are the largest device numbers, and a `TRUST=ca` QUIC build is
a device build this mode keeps. `handshake_record.h:52-54` holds
`x509_leaf_info leaf;` under `#ifdef CH_TRUST_CA`, the field the raw rows do
not carry, and `leaf.key` is `CH_X509_KEY_MAX` bytes: 384 under the default
PIN=rsa and 64 under `PIN=ecdsa` (`x509.h:35-39`). Those 320 bytes are the
whole difference between 856 and 536.

The 448 cross-checks against the tree itself: `proof/run.sh:396-397` unwinds
`ct_wipe` to 449 for the handshake harnesses, which is that frame plus one.

These are struct sizes, not the README's memory row, and no arithmetic over
them produces one. The QUIC `handshake_state` is smaller than the TLS one by
the four fields fenced out below; the QUIC `ch_tls` is smaller by the five
fields listed above and by the `REC_HDR` prefix on `tx`, and larger by
nothing; `ch_quic` adds the driver's own fields, the two Initial keys, the
two Handshake key sets, the 1-RTT send set, the three 1-RTT receive sets and
the four `quic_hp_key` values, two per level at the two levels whose header
protection is ChaCha20.
`CLAUDE.md` forbids estimating these numbers. `bench/sram.sh` measures
`sizeof(ch_tls)` from `-D` probes (`bench/sram.sh:28-45`), and it needs a
`-DCH_TRANSPORT_QUIC` probe over the real header before the README says
anything.

Each row names a field, the bound a harness assumes on entry and asserts on
exit, and why the field must outlive the call. The bounds are the inductive
shape `proof/handshake_record_harness.c:202-210` already uses for `pt_off`
and `pt_len`.

| field | type | bound | why it survives the return |
| --- | --- | --- | --- |
| `hs.t` | `ch_tls *` | none: every public entry rewrites it to `&q->t` | every `hsf_` and `hsa_` function reaches `cfg`, the transcript, `group`, `pin_slot` and the epoch fields through it |
| `hs.priv`, `hs.pub`, `hs.random` | `uint8_t[32]` each | any bytes | the retry ClientHello resends the same share and random (`handshake_flight.c:75`), and `priv` feeds x25519 at the accepted ServerHello (`handshake_flight.c:210`). Wiped at the end of `hsf_derive_handshake_secrets` |
| `hs.dz`, `KEX=pq` only | `uint8_t[64]` | any bytes | the seed re-expands for the retry share and for decapsulation (`handshake_flight.c:103-104`, `:119`). Wiped with `priv` |
| `hs.early`, `hs.binder_key` | `uint8_t[32]` each | any bytes | the retry binder (`handshake_flight.c:87`) and `ks_handshake` (`handshake_flight.c:231`). Wiped with `priv` |
| `hs.handshake_secret` | `uint8_t[32]` | any bytes | `ks_master` at the Finished step (`handshake_flight.c:338`) |
| `hs.c_hs`, `hs.s_hs` | `uint8_t[32]` each | any bytes | the client Finished (`handshake_flight.c:343`) and the server Finished check (`handshake_flight.c:320`); `s_hs` also seeds the Handshake-level packet keys |
| `hs.master` | `uint8_t[32]` | any bytes | written and read inside `hsf_complete` (`handshake_flight.c:338`, `:346`); it survives no call and sits in the struct only because the struct is one piece |
| `hs.cookie`, `hs.cookie_len` | `uint8_t[HSP_COOKIE_MAX]`, `size_t` | `cookie_len <= HSP_COOKIE_MAX` (`handshake_parser.h:19`) | the retry echo (`handshake_flight.c:75-76`, `:171-172`) |
| `hs.alert` | `uint8_t` | any | each step seeds it before it parses (`handshake_flight.c:263`, `handshake_auth.c:110`, `:259`, `:269`, `:280`); a later step's failure reports it |
| `hs.server_finished_ok` | `uint8_t` | any | `hsf_read_finished` sets it (`handshake_flight.c:326`) and `hsa_epoch_commit` asserts it (`handshake_auth.c:232`), both inside the Finished step |
| `hs.leaf` | `x509_leaf_info` under `TRUST=ca`, `webpki_leaf_info` under `TRUST=webpki` | `key_len <= CH_X509_KEY_MAX` (`x509.h:35-39`) or `<= CH_WEBPKI_KEY_MAX` (`webpki.h:38`) | written at the Certificate step, read at the CertificateVerify step. This is the reason `hsa_server_auth` becomes two entry points |
| fenced out under QUIC: `hs.record_size_limit`, `hs.encrypted`, `hs.ccs_seen`, `hs.quiet` (`handshake_record.h:43-46`) | — | — | only the TLS builder (`handshake_flight.c:69`) and the TLS record reader (`handshake_record.c:22`, `:57-58`, `:68-69`) read them |
| `step` | `uint8_t` | the full byte range; the default arm refuses every value above 6 | names the message the driver waits for |
| `rx_level` | `uint8_t` | the full range; compared, never an index | the one level whose CRYPTO bytes `cfg.buf` holds |
| `tx_level`, `tx_len` | `uint8_t`, `size_t` | `tx_len <= CH_TX_STAGE` | the one message colibri has not taken yet |
| `alert` | `uint8_t` | any | what `ch_quic_alert` answers after `hs` is wiped |
| `t.pt_off`, `t.pt_len` | `size_t` each | `pt_off <= pt_len <= cfg.buf_len` | the unread CRYPTO bytes of `rx_level` |
| `handshake_rx`, `handshake_tx`, `handshake_hp_rx`, `handshake_hp_tx`, `app_tx`, `app_rx`, `app_hp_rx`, `app_hp_tx`, `key_phase`, and `ch_tls`'s own `rd_secret` and `wr_secret` | `quic_keys`, `quic_keys[CH_QUIC_KEY_SETS]`, `quic_hp_key`, `uint8_t`, `uint8_t[32]` | `app_rx`'s three slots are the named indices, never a computed one | written into the fields of one named level; read by the packet calls and by `quic ku`. Each `quic_hp_key` is written once and never rewritten, which is the §6.1 rule (`rfc9001.txt:1607`) |
| `initial_dcid`, `initial_dcid_len` | `uint8_t[CH_QUIC_DCID_MAX]`, `uint8_t` | `initial_dcid_len <= CH_QUIC_DCID_MAX`, RFC 9000 §17.2's cap (`rfc9000.txt:4991-4998`) | the Destination Connection ID the Initial keys are derived from, written by `ch_quic_initial_keys` and read by the two Initial packet calls, which build the key they need on their own stack. It holds no key, which is INV-26 |
| `levels_ready` | `uint8_t` | six bits, one per level per direction at `CH_QUIC_LEVEL_BIT` | the only answer to "installed and not discarded", which `ch_quic_seal` and `ch_quic_open` read on every call. A key set of all-zero bytes is a legitimate derivation, so no call decides that question by comparing key bytes |
| `error_code` | `uint64_t` | 0, or a QUIC transport error code | the code `ch_quic_error_code` reports for the four refusals RFC 9001 makes a connection error of type PROTOCOL_VIOLATION. `quic_fail_level` and those four steps are its only writers, and the caller reads it after the call that failed |
| `open_failures`, `initial_sealed` | `uint64_t` each | `open_failures` stops the session at RFC 9001 §6.6's integrity limit, `initial_sealed` at its confidentiality limit | the §6.6 counts are per connection, so every call adds to the count the last call left |

Five things are never saved: a pointer into `cfg.buf` past the step that took
it, a `server_hello_info`, a transcript hash, a parse cursor inside a message,
and any secret past the step that reads it last.

**What bounds `cfg.buf`.** Today `hsr_next_msg` waits until `4 + msg_len`
bytes sit in `cfg.buf` and returns a pointer into it
(`handshake_record.c:122-127`), and the peer cannot overflow that buffer
because its size minus record overhead was advertised as `record_size_limit`.
QUIC removes the advertisement, so `cfg.buf_len` is the only bound a peer
meets, and the driver enforces it at the message header: a message that could
never fit is refused there, the check `handshake_post.c:88` already makes.
Three CRYPTO streams exist, one per level, each starting at offset 0 (RFC
9000 §19.6, `rfc9000.txt:6162-6163`), and in practice a client never has two
in flight at once, so one buffer suffices. The level rules above are what
keep that true rather than assumed.

### Entry points and their contracts

Every function that takes a message requires `raw_len >= 4`, `raw` inside
`cfg.buf`, and `raw_len` agreeing with the 3-byte header — the contract
`proof/handshake_record_harness.c:202-208` proves of the TLS reader today.

**`handshake_flight.[ch]`, prefix `hsf_`, in every build.** `hsf_begin`
(`handshake_flight.c:16-49`, including the two `CH_ASSERT`s that no drawn
value is all-zero, four under `KEX=pq`, at `handshake_flight.c:32-37`);
`hsf_build_client_hello` (`handshake_flight.c:57-91`, with the `KEX=pq`
expansion frame of `:102-108`), which returns the message length or 0 with
`ALERT_INTERNAL_ERROR` and the transcript untouched; `hsf_read_server_hello`
(`handshake_flight.c:146-177`); `hsf_accept_server_hello`
(`handshake_flight.c:179-202`); `hsf_derive_handshake_secrets`
(`handshake_flight.c:204-236` plus `hybrid_secret`, `:116-127`), which added
six wipes and clears `priv`, `pub`, `random`, `dz`, `early` and `binder_key`
on both exits (`handshake_flight.c:217-234`). Before the move those six died
at the frame wipe of `handshake.c:151`, which in the QUIC driver is a round
trip away. Then `hsf_read_encrypted_extensions`
(`handshake_flight.c:238-297`); `hsf_read_finished`
(`handshake_flight.c:299-328`); and `hsf_complete`, which requires
`server_finished_ok` and runs `ks_master`, the client Finished and
`ks_res_master` (`handshake_flight.c:338`, `:339-344`, `:346`). None of them
calls the record layer, the I/O shim or a `tlsi_` function. One ordering
changed for TLS inside `hsf_complete`: `ks_res_master` runs before the client
Finished goes out rather than after, where the tree ran `ks_master`,
`send_client_finished` and `ks_res_master` in that order. Nothing observable
depends on it, because a failed send wipes the session either way.

**`handshake_auth.[ch]`, prefix `hsa_`.** `hsa_server_auth` keeps its TLS
contract (`handshake_auth.h:11-15`); under `CH_TRANSPORT_QUIC` it returns
`CH_OK` right after `sha256_update` at `handshake_auth.c:293`.
`hsa_read_certificate_verify` is new and QUIC-only, declared under `#ifdef`,
and requires a preceding `hsa_server_auth` that returned `CH_OK` in the same
session. `hsa_epoch_commit` does not change.

**`handshake_record.[ch]`, prefix `hsr_`.** The TLS arm
(`handshake_record.c:17-135`) sits under `#ifndef CH_TRANSPORT_QUIC`;
`hsr_transcript_hash` (`:137-141`) stays in both. The QUIC arm adds
`hsr_feed`, which compacts the unread window the way
`handshake_record.c:74-78` does, copies what fits and returns the count;
`hsr_peek_message`, which is pure and answers "a whole message of this
length", "more bytes needed", `CH_EPROTO` with `ALERT_DECODE_ERROR` for
`msg_len > 0x4000` (the rule at `handshake_record.c:119-121`, whose TLS arm
returns `CH_EPROTO` and sets no alert, so the QUIC arm adds one) or `CH_ECAP`
with `ALERT_INTERNAL_ERROR` for a message that cannot fit `cfg.buf_len`; and
the QUIC `hsr_next_msg`, whose one difference from the TLS one the header
states in a paragraph: it never waits. It returns neither `CH_EIO` nor
`CH_EAUTH`.

**`quic_step.[ch]`, prefix `hsq_`, QUIC only.** The `HSQ_STEP_*` values
and `hsq_advance`, which requires a whole message at `pt_off` and on `CH_OK`
may raise the step, move `rx_level`, write `t.tx`, install keys and fire the
callbacks. On an error it leaves the alert in `hs.alert` and the caller kills
the session. It has external linkage so the driver's harness can stub it. The
six step functions and the hello builder stay `static` and the step harness
reaches them by `#include`, the way `proof/certverify_webpki_harness.c:104`
already reaches a static function.

**`quic.[ch]`, the public file beside `tls.[ch]`.** `ch_quic`, the entries in
"The interface it exposes", and the two static functions the input loop and
the failure path use.
`PUBLIC_TRANSPORT` takes these fifteen names in place of the four TLS ones
under `TRANSPORT=quic`, and `lib-check` (`Makefile:417-423`) holds
`$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)` (`Makefile:363`). It is a
selection on one term, not an addition: `lib-check` diffs the object's
exported symbols against `PUBLIC` for exact equality (`Makefile:419-422`), so
a `PUBLIC_TRANSPORT` carrying both sets fails a TLS build by the fifteen
`ch_quic_` names and a QUIC build by the four TLS ones. `ch_pubkey_from_pem`
and `ch_drbg_seed` are unchanged on both transports, so a `TRUST=ca` QUIC
object exports sixteen symbols and a `TRUST=ca RAND=drbg` one seventeen. The
ALPN configuration rules `tls.c:329-371` holds today are needed here in every
trust mode.

**`handshake_post.[ch]`.** `handle_ticket` stays `static` at
`handshake_post.c:31`. Under `#ifdef CH_TRANSPORT_QUIC` the file gains
`hspost_take_ticket`, a wrapper that calls it; `handle_key_update`
(`:63-77`), `handle_post_handshake` (`:83-109`) and `hspost_read`
(`:116-153`) sit under `#ifndef`.

**New `ch_cfg` fields, under the QUIC guard.** `ch_cfg.transport_params`, a
`const uint8_t *`, and `ch_cfg.transport_params_len`, a `size_t` at most
`CH_TRANSPORT_PARAMS_MAX`; `ch_quic_init` refuses a null pointer or a zero
length with `CH_EINVAL`, and `handshake_message.c` copies those bytes unread
into extension 0x39;
`on_level_ready(io, level, direction)` with `CH_KEY_READ` and `CH_KEY_WRITE`;
and `on_transport_params(io, body, len)`. Both callbacks fire from a step
inside `ch_quic_crypto_in`, which is what RFC 9001 §4.1.4 requires
(`rfc9001.txt:530-531`), and neither may call back into `q`. That
re-entrancy rule is a caller contract with no run-time check, and `cfg.h`
states it. So is one more: colibri delivers each level's CRYPTO bytes once,
in order, and never re-delivers bytes chapulin has consumed. A retransmitted
CRYPTO frame is a duplicate colibri drops; chapulin holds no offset and
cannot tell one from new data. `cfg.h` states that one too.

**The return codes, in one sentence each.** `CH_OK` from
`ch_quic_crypto_in` means the driver needs more bytes or has finished the
ones it got. `CH_EINVAL` means the caller called out of order and nothing
changed. `CH_ECAP` from `ch_quic_crypto_out` means the caller's buffer was
short and nothing was consumed. `CH_QUIC_DISCARD` from `ch_quic_open` means the
packet is gone and the session is live (RFC 9001 §5.5).
`CH_QUIC_AEAD_LIMIT` from `ch_quic_open` means `open_failures` passed 2^36 and
the session is dead. Every other error means the session is now
dead, `ch_quic_alert` names the alert and `ch_quic_error_code` names the
transport error code. `cfg.h` gains two codes beside `CH_EINVAL`
(`cfg.h:42-48`), both `int` like every other `ch_err` code. `CH_QUIC_DISCARD`
(-7) is what `ch_quic_open` returns for a packet it cannot authenticate and for
one too short to sample; it leaves every field of `q` unchanged except
`open_failures`, and the session stays live. `CH_QUIC_AEAD_LIMIT` (-8) is what
the call that carries `open_failures` past RFC 9001 §6.6's 2^36 returns; it
leaves the session dead. No other call returns either. Both keep the `CH_QUIC_`
prefix rather than the `CH_E` shape the codes at `cfg.h:42-48` use, because
neither has a meaning on the TLS transport.

### What it costs the `TRANSPORT=tls` builds

Behaviour: two body edits land on the TLS path, neither is observable, and
nothing else changes. `hsf_derive_handshake_secrets` gains six wipes, which
only shorten the lifetimes of `priv`, `pub`, `random`, `dz`, `early` and
`binder_key`: nothing reads them after the derivation, and the frame wipe at
`handshake.c:151` already ends them. `hsf_complete` runs `ks_res_master`
(`handshake_flight.c:346`) before the client Finished goes out
(`handshake.c:121`) rather than after, which changes only whether
`t.res_master` is written when that send
fails; `tlsi_fail` calls `tlsi_wipe` (`session.c:36-38`) and `tlsi_wipe` wipes
`res_master` (`session.c:30`), so a failed send leaves the same zeroed field
either way, and no caller reads `res_master` except through `on_ticket` after
the handshake. The same messages go out in the same order and every refusal
keeps its alert. `make check` and `make check-slow`
are what hold that, in particular the 466,286-sequence enumeration of
`test/handshake_sequence_test.c` against the Lean oracle
(`docs/invariants.md:752-757`) and the e2e run against a real server.

Object bytes: one object changes, and the PR says which by comparing every
`bin/obj/<variant>/*.o` before and after. `LIB_CFLAGS` (`Makefile:54`) is
`CFLAGS` (`Makefile:4`) at `-O2` with no `-g`, so the only line numbers
inside a packaged object are `CH_ASSERT`'s `__LINE__` (`ch_assert.h:14-19`).
Every edit listed below other than `handshake.c`'s is an `#ifdef` fence or an
addition below the last `CH_ASSERT` in its file, so the preprocessed text a
TLS build compiles does not move. `handshake.c` is the exception: its two
`CH_ASSERT`s, four under `KEX=pq`, moved into `hsf_begin`
(`handshake_flight.c:32-37`), so `handshake.o` changes in every
TLS variant, and the partially linked `chapulin.o` with it. Deleting lines
above those assertions to hold the numbers is line golf, and `tls.c:255-260`
already records why this tree refuses that trade.

| file | the edit |
| --- | --- |
| `handshake.c` | the 233 lines listed above move to `handshake_flight.c`; `run`'s call order and `ch_handshake` stay |
| `handshake_auth.c` | `:293-297` gain a QUIC arm that returns `CH_OK`; `hsa_read_certificate_verify` is added below `:298`. No line above `:232` changes |
| `handshake_record.c` | `#ifndef` around the `io.h` and `record.h` includes and `:17-135`; the QUIC arm after `:141` |
| `handshake_post.c` | `#ifndef` around `:59-109` and `:111-153`; `hspost_take_ticket` after `:153`; and an `#ifdef CH_TRANSPORT_QUIC` arm at `handshake_post.c:43-44`, where the body reads the extension block's length and skips its bytes today (`handshake_post.c:27-28` states why), which instead reads the block, refuses any `early_data` whose `max_early_data_size` is not 0xffffffff, and records the refusal so `ch_quic_error_code` reports 0x0a rather than the bare `CH_EPROTO` of `handshake_post.c:46`. The arm is a fence, so the text a TLS build preprocesses does not move |
| `session.h` | fences around `:73-74`, `:79`, `:81` and `:117`; a QUIC-shaped `tx` beside `:121`; `alpn_selected`'s guard at `:95` widens to webpki or quic |
| `cfg.h` | the ALPN block (`:213-236`, `:365-376`) widens to webpki or quic; a new QUIC block carries `CH_LEVEL_*`, `CH_KEY_*`, `CH_TRANSPORT_PARAMS_MAX`, the two fields and the two callbacks |
| `handshake_message.c`, `handshake_parser.c` | the QUIC arms "The parser change, in full" specifies, plus `ALERT_MISSING_EXTENSION` 109 and `ALERT_NO_APPLICATION_PROTOCOL` 120 in `handshake_message.h:113-129` |
| `tls.c` | the ALPN rule functions `:329-371` move into a header of static functions included where `tls.c:263` sits, below every `CH_ASSERT`. Byte identity is measured, not claimed; if `tls.o` moves, `quic.c` carries its own copy and a unit row holds the two to the same verdicts |
| `Makefile` | `SRCS` (`:122-124`) and `HDRS` (`:126-128`) gain `handshake_flight`; a `TRANSPORT` axis beside `TRUST` (`:207-233`), defaulting to `tls`, which under `quic` adds `-DCH_TRANSPORT_QUIC`, drops `io.c record.c session.c handshake.c tls.c` and adds `quic.c quic_step.c` and the packet-protection sources; `LIB_VARIANT` (`:287`); a `PUBLIC_TRANSPORT` variable and `PUBLIC` (`:363`) rewritten as `$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)`, selected on the new axis the way `PUBLIC_CA` is selected on `TRUST` (`:211-221`); `lint-trust-separation` rows (`:329-353`); per-file defines on `WIDEMUL_CEILING`, read at `:2085` and `:2163-2165`; an `RV_ALLOWED` decision for each of the five new `WIDEMUL_CEILING` entries, and a row only where the file pulls a runtime symbol, because a row for a file that pulls nothing prints a line on every run (`Makefile:2175-2178`); a `bin/quic_driver_test` target over `test/quic_driver_test.c`, which `check` runs beside the other test binaries and which `test-invariants-fast` gains as a prerequisite (`Makefile:1635`); a `cxx-check TRANSPORT=quic` invocation beside the three at `:753`, `:764` and `:767`; a `bin/quic_test` target over `test/quic_vectors.c`, in the shape of `bin/sha3_test` (`:491-493`); and the three lint passes that read a file name. `LINT_C` (`:137`) gains the nine new sources and `test/quic_driver_test.c`, and `HDRS` (`:126-128`) gains the nine new headers, so `lint-format` and `lint-cppcheck` read them. `lint-tidy` gains a third pass in the shape of the `-DCH_TRUST_WEBPKI` pass at `:1470-1475`, over `quic.c quic_step.c quic_keys.c quic_packet.c quic_initial.c quic_retry.c quic_aes.c quic_gcm.c handshake_flight.c handshake_record.c handshake_post.c handshake_parser.c handshake_message.c handshake_auth.c test/quic_driver_test.c` with `-DCH_TRANSPORT_QUIC`, and the four sources that need the define are filtered out of the first pass the way `webpki.c` is at `:1461`, because that pass declares no transport and reads none of the QUIC arms |
| `test/violations.py` | `FAST_TARGETS` (`test/violations.py:252-261`) gains `"quic_driver_test"` and `"test/lint-invariants.sh"`. Without both names the nine driver mutants and the AES one fall into the slow tier (`test/violations.py:322-325`), which `check-slow` does not run: `Makefile:859` runs `test-invariants-fast` alone, so they would run in the nightly and not in the run `CLAUDE.md` calls the definition of done |
| `io.c`, `record.c`, `session.c`, `keysched.c` | nothing |

### What it does to the proofs

Every launch line here, new or moved, is measured with `/usr/bin/time -v`
under `run.sh`'s exact flags before it is committed, and no tier is assigned
before that measurement (`docs/proofs.md`). Every `--unwindset` identifier is
checked against `cbmc --show-loops`. A new slow line also needs its row in
the nightly matrix (`.github/workflows/nightly.yml:52`), which `lint-matrix`
(`Makefile:1681-1691`) holds equal to `run.sh`'s slow tier.

1. **`handshake_psk` and `handshake_pin` (`proof/run.sh:396-397`) keep their
   shape and must be re-measured anyway.** `proof/handshake_harness.c` still
   includes `handshake.c` whole (`:420`), still stubs `hsr_fetch_record` and
   `hsr_next_msg` as the nondeterministic source (`:360-411`), and still
   starts `run` from the zeroed frame `ch_handshake` builds
   (`handshake.c:135`). Two edits: the launch lines add `handshake_flight.c`
   beside `handshake_auth.c buf.c ct.c`, because the handlers now live there,
   and the stubs move into a shared header the step harness includes too, so
   the stub contracts stay one text. `ct_wipe.0:449` stays, because the TLS
   `handshake_state` is still 448 bytes. `proof/run.sh:386-392` records what
   these two cost today: the psk leg 1683 properties, 231 s, 1.6 GB of cbmc
   and 7.8 GB of kissat on the development machine, and 191 s at 1.9 GB and
   3.7 GB in the pinned container; the pin leg 1685 properties and 55 s.
   The same stubs over the same driver give no reason to expect growth, and
   no reason is not a measurement.
2. **`handshake_crypto`, new.** The QUIC arm of `handshake_record.c` at
   `-DCH_PROOF_RXBUF=12`: `hsr_feed`, `hsr_peek_message`, `hsr_next_msg` and
   `hsr_transcript_hash`, all real. It proves that `hsr_feed` writes nothing
   past `buf_len` and returns what it says, that "more bytes needed" leaves
   every buffer byte and both offsets equal to a copy taken after the feed
   and implies the whole input was taken, that a whole message satisfies the
   five properties `proof/handshake_record_harness.c:202-208` asserts, that
   `CH_EPROTO` names `ALERT_DECODE_ERROR` and `CH_ECAP` names
   `ALERT_INTERNAL_ERROR`, and the window bound on exit (`:210`).
3. **`quic_step_*`, new, one launch line per step and mode.**
   `proof/quic_step_harness.c` with selector files in the
   `CH_PROOF_PSK` and `CH_PROOF_PIN` pattern (`proof/handshake_psk_harness.c:5-7`):
   the ServerHello and EncryptedExtensions steps in both modes, because those
   two read `cfg.psk`, and the Certificate, CertificateVerify, Finished and
   complete steps in pin configuration, because the psk configuration never
   reaches the certificate steps and the other two read no mode. Each
   includes `quic_step.c` and compiles `handshake_flight.c
   handshake_auth.c buf.c ct.c` with `-DCH_TRANSPORT_QUIC`. The saved state
   is havocked per the table above, and havocked the way `docs/proofs.md`
   requires: every array through a typed nondet fill and never a byte-count
   fill of a typed object, the transcript through the harness's own
   transcript fill, `cookie_len` and `leaf.key_len` constrained to their
   caps, `cfg.buf` at `CH_PROOF_RXBUF` bytes — 96 for these legs, the size
   `proof/handshake_harness.c:435` already gives the handshake harnesses —
   with `pt_off <= pt_len <= CH_PROOF_RXBUF`, `tx_len <= CH_TX_STAGE`, and
   `step` assumed equal to the selector's value — except the complete step,
   which assumes `step >= HSQ_STEP_COMPLETE` over the whole byte range so the
   default arm is inside the formula. Each operand is havocked freshly
   before each call. The assertions on exit are the window bound, the caps,
   that `CH_OK` below `HSQ_STEP_COMPLETE` raises the step, that `CH_OK` from
   `HSQ_STEP_AWAIT_RETRY_HELLO` lands on `HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS`
   — the second-HelloRetryRequest refusal stated as a property — that an
   error leaves `tx_len` alone, and that a step value above
   `HSQ_STEP_COMPLETE` returns `CH_EPROTO` with `unexpected_message` and
   changes nothing else.
4. **`handshake_quic`, new.** `quic.c` at `-DCH_PROOF_RXBUF=12` with the
   QUIC `handshake_record.c` real and `hsq_advance` stubbed to the contract
   above, so the stub's list and the step assertions are one contract a
   reviewer reads as a pair. That 12 is the value
   `proof/handshake_record_harness.c:54-55` and `proof/run.sh:788` already
   use, and it is inside leg 3's 96, so every state this leg reaches is inside
   the window leg 3 discharges. It proves that any error leaves
   `CH_ST_FAILED`, `tx_len == 0`, `pt_off == pt_len == 0` and the wiped
   secrets zero; that `CH_EINVAL` leaves every field equal to the entry
   copy; that a non-empty `t.tx`, and `level` above `rx_level` with
   `pt_off == pt_len`, are refused with `CH_EINVAL`; that `level` above
   `rx_level` with `pt_off != pt_len`, and `level` below `rx_level`, fail
   with `CH_EPROTO` and make `ch_quic_error_code` report 0x0a; that a
   `CH_LEVEL_APPLICATION` open below `CH_ST_CONNECTED` is `CH_EINVAL`; and
   that a short `cap` in `ch_quic_crypto_out` changed nothing.
5. **Moved lines.** `hybrid_secret` (`proof/run.sh:592`) includes
   `handshake_flight.c` instead of `handshake.c` and is re-measured.
   `certverify_webpki` (`:469`) does not move, because
   `check_certificate_verify` stays at `handshake_auth.c:96-176` and the
   harness's `hsr_next_msg` stub still fits it. `epoch` (`:578`) does not
   move, because the QUIC arm at `handshake_auth.c:293-297` is `#ifdef`-fenced,
   so a TLS build preprocesses the text it compiles today and nothing above
   the `CH_ASSERT` at `handshake_auth.c:232` moves.
   `handshake_post` (`:583`), `handshake_record` (`:788`) and `io`
   (`:565`) keep their subjects. Each proves a TLS arm that a TLS build
   still compiles, so none of the three is retired: the design keeps
   `handshake_record.c` and `handshake_post.c` in both transports, and it
   leaves `io.c` to the TLS build alone.
6. **Coverage.** `tools/proof-cover.py` fails a shipped source that no `full`
   harness compiles and no `AUDITED` entry lists. Leg 1 and leg 3 compile
   `handshake_flight.c`, leg 3 compiles `quic_step.c`, leg 4 compiles
   `quic.c`, and leg 2 compiles the QUIC arm of `handshake_record.c`. No
   `AUDITED` entry is added.
7. **Mutants, planted before the code lands.** Each is planted, watched to
   make the named target fail, and landed as a `test/violations/*.violation`
   file. `test/violations.py:102-104` requires four header fields —
   `invariant`, `file`, `catches` and `reason` — and exits on the file
   before it applies the edit when one is missing, so each mutant's
   `invariant` and `catches` values are named here. All nine catch on
   `bin/quic_driver_test`, the new binary "The new sources, by name" adds,
   and `catches: quic_driver_test` is how a violation file names it
   (`test/violations.py:135-138` reads a name without a slash as
   `bin/<name>`).

   | mutant | `file` | `invariant` | `catches` |
   | --- | --- | --- | --- |
   | the second-HelloRetryRequest compare removed from the ServerHello step | `quic_step.c` | INV-14 | `quic_driver_test` |
   | `level < rx_level` accepted in `ch_quic_crypto_in` | `quic.c` | INV-22 | `quic_driver_test` |
   | the leftover-byte check removed from the driver, so bytes after the ServerHello survive the level move | `quic.c` | INV-22 | `quic_driver_test` |
   | the `tx_len != 0` refusal dropped, so a second `ch_quic_crypto_in` overwrites the staged hello | `quic.c` | INV-13 | `quic_driver_test` |
   | `hsr_peek_message` accepting a message larger than `cfg.buf_len` | `handshake_record.c` | INV-2 | `quic_driver_test` |
   | a KeyUpdate accepted at `HSQ_STEP_COMPLETE` | `quic_step.c` | INV-22 | `quic_driver_test` |
   | the CertificateRequest arm folded into the KeyUpdate arm, so `ch_quic_error_code` reports 0x010a for a post-handshake CertificateRequest | `quic_step.c` | INV-22 | `quic_driver_test` |
   | the §5.7 check removed from `ch_quic_open`, so a 1-RTT packet opens before `t.state` reaches `CH_ST_CONNECTED` | `quic.c` | INV-22 | `quic_driver_test` |
   | the next receive keys promoted inside `ch_quic_open` before the open succeeds, so a forged Key Phase bit installs a key update | `quic.c` | INV-13 | `quic_driver_test` |
   | the `seen` check removed from `hsp_parse_encrypted_exts`, so an EncryptedExtensions with no `quic_transport_parameters` is accepted | `handshake_parser.c` | INV-14 | `quic_driver_test` |

The Lean oracle moves with the driver. `spec/Spec/Handshake.lean`'s `State`
(`:62-78`) names the same states the step numbers do, constructor for
constructor except `closed`, which no C step reaches because `ch_quic_close` is
the caller's call. One arm differs: `.connected, .keyUpdate => some .connected`
(`spec/Spec/Handshake.lean:110`) is what RFC 9001 §6 forbids. The spec gains a
transport parameter, that one arm answers `none` under `quic`, every existing
theorem keeps its content over both values, gaining the level in `step`'s
arguments and in its own binders, and one new theorem says an accepted QUIC
trace contains no KeyUpdate. The alphabet gains the encryption level, because
the two refusals the QUIC driver adds are level rules and a message-only oracle
cannot judge them. `seq?` reads each message as one letter under `tls` and as a
level digit — 0 for Initial, 1 for Handshake, 2 for application — followed by
the message letter under `quic`, and `step` takes the level beside the message.
Under `quic` a message below the level the trace has reached and a message
above it with bytes unread both answer `none`, which is what
`ch_quic_crypto_in` does in "Suspending the driver". `bin/quic_driver_test`
drives the pairs, so the two level mutants fail against the oracle rather than
against a hand-written case alone. The oracle command at
`spec/Main.lean:216-222` takes the transport as a fourth word, and the TLS test
passes `tls`. The QUIC sequence differential never draws application data or
close_notify, so its input domain stays inside what the C and the spec agree on
(`CLAUDE.md`).

### What a reader should be suspicious of here

1. **`hsr_next_msg` names two functions.** One blocks in `cfg.recv`, the
   other cannot. They share a name, a signature and a contract sentence, and
   an auditor reading a step has to know which object they are in. The header
   says so in a paragraph, and the QUIC body is short enough to read whole.
2. **The driver's harness stubs `hsq_advance`.** The composition is sound
   only if the step formulas assert everything the stub assumes. A property
   the stub assumes and no step asserts is a gap, so the two lists are
   reviewed as one contract.
3. **`handshake.o` changes in every TLS build.** A reviewer reads the
   `handshake.c` diff as a move, function by function against the ranges
   above, rather than comparing objects.
4. **`CH_EINVAL` leaves the session live.** A caller that ignores it stalls
   instead of failing closed. Killing the session on a caller mistake would
   punish the peer for colibri's bug, so the header says which return codes
   mean dead and which mean call again.
5. **Callbacks fire before the step that installed the keys returns.** A
   callback that re-enters `q` corrupts the step, and nothing checks it at
   run time.
6. **Secrets sit in SRAM between calls.** `handshake_secret`, `c_hs` and
   `s_hs` live for one round trip, from the ServerHello step to the Finished
   step, where the TLS driver holds them only inside one call
   (`handshake.c:151`). The wipe inside `hsf_derive_handshake_secrets` and
   the wipe of `hs` at `HSQ_STEP_COMPLETE` are what bound the rest.
7. **INV-22's mechanism stops being "no state variable to desynchronize"**
   (`docs/invariants.md:743-751`) for the QUIC build. What replaces it is the
   stored step, the default arm, the Lean `State` the step numbers copy,
   and the QUIC sequence
   differential, and that differential is real work in
   `test/handshake_sequence_server.h` that lands with the driver, not after.

### The summary of this section

The suspendable driver moves 233 of `handshake.c`'s 395 lines into
`handshake_flight.c`, which both transports compile; adds `quic_step.c`
and `quic.c`; splits `hsa_server_auth` into two entry points; adds the
reader that takes bytes at `t.pt_off` beside the record reader in
`handshake_record.c`;
moves 448 bytes of handshake state, 856 under `TRUST=ca PIN=rsa`, 976 under
`TRUST=webpki` and 512 under `KEX=pq`, from a stack frame into the session;
changes `handshake.o` in every
TLS build; and owes ten or so new launch lines plus three re-measured ones.
The AES is two files with published vectors and a bounded formula each. A
reader pricing this mode should weigh this section, not the AES one.

## What is reused, and what changes

One reuse fraction over every `.c` file at the repository root — 43 files,
8,167 lines at `3432a5d` — is not a property of anything shipped. No build
compiles all 43: `PIN`, `TRUST` and `KEX` each filter or extend the list
(`Makefile:177-243`; the one assignment is `Makefile:235`). So the fraction is
given per build.

*Measured*, at `3432a5d`, by `make print-lib-srcs` for each variant and
`wc -l` over the files it names. The formula is
`reuse = unchanged lines / that variant's total lines`.

| build | files | lines | unchanged | changed | replaced | reuse |
| --- | --- | --- | --- | --- | --- | --- |
| device, `TRUST=raw PIN=rsa KEX=x25519` | 22 | 3460 | 12 files, 1335 | 5 files, 1135 | 5 files, 990 | 1335 / 3460 = 38.6% |
| device, `TRUST=raw KEX=pq` | 25 | 4242 | 15 files, 2117 | 1135 | 990 | 2117 / 4242 = 49.9% |
| device, `TRUST=ca` | 26 | 4676 | 16 files, 2551 | 1135 | 990 | 2551 / 4676 = 54.6% |
| host, `TRUST=webpki` | 36 | 6517 | 26 files, 4392 | 1135 | 990 | 4392 / 6517 = 67.4% |

The two rows the mode is about are the first and the last. The changed and
replaced columns hold the same ten files in every build, which is why the
fraction rises with the variant's size: a webpki object carries about 3,000
more lines of certificate and signature code (4392 − 1335 = 3057), and none of
it touches the transport. Weigh the device row. On the smallest build that
ships, QUIC reuses two lines in five, and the part of that object this work
touches, the ten files, is three fifths of it (2,125 of 3,460).

The replaced five are `record.c` 98, `io.c` 44, `session.c` 40, `handshake.c`
395 and `tls.c` 413, 990 lines. A QUIC object compiles none of them. That
column overstates what is rewritten in one place: 233 of `handshake.c`'s 395
lines move into `handshake_flight.c` with their bodies unchanged but for the
two edits named above, and every
build compiles that file, so the protocol logic those lines hold is reused
rather than replaced. "Suspending the driver" gives the ranges. The
`tlsi_wipe` half of `session.c` (`session.c:25-34`) is rewritten in `quic.c`,
because what it wipes is key sets rather than `rec_dir`.

The changed five are `handshake_message.c` 147, `handshake_parser.c` 396,
`handshake_record.c` 141, `handshake_auth.c` 298 and `handshake_post.c` 153,
1,135 lines. Each keeps its TLS text and gains a QUIC arm under an `#ifdef`, so
both transports compile all five. The two the driver adds arms to are
`handshake_record.c`, which gains the reader that takes bytes at `t.pt_off`
beside the record reader, and `handshake_post.c`, whose `handle_ticket`
(`handshake_post.c:31-57`) stays `static` and gains a QUIC-only wrapper. "The
new sources, by name" lists every new pair.

The driver touches the record layer at 15 call sites in three files, counted by
`grep` for `io_send_all`, `io_read_record`, `rec_seal`, `rec_open`,
`rec_dir_init` and `rec_dir_update`: `handshake.c` 7, `handshake_post.c` 6,
`handshake_record.c` 2. Outside the handshake files, `session.c` has 3 and
`tls.c` 4, for 22 in all.

Four behaviours replace those 15 sites:

1. **Output.** `handshake.c:40` sends the ClientHello after writing a 5-byte
   record header by hand (`handshake.c:33-39`), `handshake.c:50` sends the
   sealed client Finished, and `handshake_post.c:71` sends a sealed KeyUpdate
   reply. The first two become one staged message in `ch_tls.tx` that
   `ch_quic_crypto_out` hands to the caller, tagged with its level; the
   middlebox version byte at `handshake.c:37` goes with the record header.
   The third has no QUIC counterpart, because a KeyUpdate message is a
   connection error there (RFC 9001 §6).
2. **Input.** `handshake_record.c:87` and `handshake_post.c:220` call
   `io_read_record`, which blocks on `cfg.recv`. Both sit inside the arms a
   QUIC build fences out. The bytes arrive through `ch_quic_crypto_in`
   instead, by the plan above.
3. **Key installation.** `handshake.c:94-95` and `handshake.c:125-126`
   install four traffic secrets into `rec_dir` structures through
   `rec_dir_init`, which derives the TLS `key` and `iv` labels
   (`record.c:6-10`). Each becomes a `quic key` and `quic iv` derivation
   into that level's `quic_keys` value and a `quic hp` derivation into its
   `quic_hp_key`, plus one `on_level_ready` call.
   `rec_dir_update`'s `traffic upd` label (`record.c:14`) is replaced by
   `quic ku` (RFC 9001 §6.1).
4. **Framing.** The record header, the ChangeCipherSpec tolerance
   (`handshake_record.c:53-59`), the alert record path and the
   `record_size_limit` sizing (`handshake.c:138-139`) all go.

The five changed files:

| file | lines | change |
| --- | --- | --- |
| `handshake_message.c` | 147 | drop the `record_size_limit` extension (`handshake_message.c:93-95`), add `quic_transport_parameters` at code point 0x39 (RFC 9001 §8.2, `rfc9001.txt:1923`), and move `write_alpn` (`handshake_message.c:5-27`) out of `CH_TRUST_WEBPKI` so a device QUIC build sends ALPN too (RFC 9001 §8.1) |
| `handshake_parser.c` | 396 | one new admitted extension with a body to read, `quic_transport_parameters`, and the ALPN arm (`handshake_parser.c:275-294`, `:303-312`) lifted out of `CH_TRUST_WEBPKI`; see below |
| `handshake_record.c` | 141 | the record arm (`:17-135`) goes under `#ifndef CH_TRANSPORT_QUIC`; `hsr_transcript_hash` (`:137-141`) stays in both; the QUIC arm adds `hsr_feed`, `hsr_peek_message` and a non-waiting `hsr_next_msg` |
| `handshake_auth.c` | 298 | its verification logic is unchanged, but its two `hsr_next_msg` calls at `:245` and `:100` are suspension points, so `hsa_server_auth` splits into two entry points |
| `handshake_post.c` | 153 | `handle_ticket` (`:31-57`) is reached through a QUIC-only wrapper, and gains an `#ifdef CH_TRANSPORT_QUIC` arm at `:43-44` that reads the extension block instead of skipping it, refuses any `early_data` whose `max_early_data_size` is not 0xffffffff, and records the refusal so `ch_quic_error_code` reports 0x0a rather than the bare `CH_EPROTO` of `:46`; the arm is a fence, so a TLS build compiles the text it compiles today. `handle_key_update` (`:63-77`), `handle_post_handshake` (`:83-109`) and `hspost_read` (`:116-153`) go under `#ifndef CH_TRANSPORT_QUIC` |

The message builders, the transcript, the PSK binder, the Finished MAC, the
HelloRetryRequest transcript restart and the whole authentication flight stay
as they are. RFC 9001 §4.7 keeps HelloRetryRequest: QUIC does not treat it
differently from any other handshake message in Initial packets.

### The parser change, in full

`hsp_parse_encrypted_exts` (`handshake_parser.c:336-396`) admits exactly four
extension types — `record_size_limit`, `supported_groups`, and under
`TRUST=webpki` one empty `server_name` acknowledgement and one ALPN selection
the ClientHello offered (`handshake_parser.c:303-312`) — and refuses every
other one (`handshake_parser.c:382-388`): with `unsupported_extension` in a
device build, and under `TRUST=webpki` with the alert
`unadmitted_extension_alert` names (`handshake_parser.c:322-327`). Today's
parser would fail every QUIC handshake closed at that line. Three things
follow.

1. **`quic_transport_parameters`, code point 0x39.** One more admitted type,
   and an out parameter carrying the body to the caller, because the body is
   opaque to TLS (RFC 9001 §8.2) and the QUIC layer needs it. That changes the
   function's signature.

   Admitting the type is not the whole edit, because §8.2 puts a client MUST
   on its absence: a client that receives an EncryptedExtensions without
   `quic_transport_parameters` MUST close the connection with error 0x016d
   (`rfc9001.txt:1932-1936`). Today's parser ends its loop and returns `CH_OK`
   with `seen` unread (`handshake_parser.c:395`), so admitting one more type
   would accept an EncryptedExtensions that carries none. Under
   `CH_TRANSPORT_QUIC` the function reads the mask before it returns: a
   message with the `quic_transport_parameters` bit clear writes
   `ALERT_MISSING_EXTENSION` and returns `CH_EPROTO`, and §4.8's 0x0100
   conversion makes `ch_quic_error_code` report 0x016d, the code §8.2 names.
   That takes the boundary test `CLAUDE.md` requires: one EncryptedExtensions
   carrying the extension accepted, the same message with it removed refused
   with alert 109.

   The admitted arm for 0x39 sits under `#ifdef CH_TRANSPORT_QUIC` alone,
   never under the webpki-or-quic guard the ALPN block takes, so a
   `TRANSPORT=tls` build still reaches the unadmitted arm and answers
   `unsupported_extension` (`handshake_parser.c:386`, 110 at
   `handshake_message.h:129`). RFC 9001 §8.2 requires exactly that of an
   implementation that understands the extension on a transport that is not
   QUIC (`rfc9001.txt:1945-1949`), so a unit row sends 0x39 in
   EncryptedExtensions to a `TRANSPORT=tls` build and requires alert 110.
2. **The server's ALPN reply, in every trust mode.** A hello that offers ALPN
   must accept the answer, and RFC 9001 §8.1 requires a client to close with
   `no_application_protocol` when negotiation fails, so this extension cannot
   be tolerated and ignored the way `supported_groups` is
   (`handshake_parser.c:377`: "tolerated; its body is deliberately unread").
   ALPN landed in 545bf5d under `TRUST=webpki` alone: `write_alpn`
   (`handshake_message.c:5-27`) sends the offer and `parse_alpn`
   (`handshake_parser.c:275-294`) reads the `ProtocolNameList`, requires
   exactly one name and requires a name the ClientHello offered. The second
   requirement is this client's own rule: RFC 7301 §3.2 expects a server to
   select only a protocol the client supports (`rfc7301.txt:256-258`) and
   states no client-side check. The device builds still send none
   (`examples/server/README.md:32`). The QUIC work is to move both out of
   `CH_TRUST_WEBPKI` and to add the `no_application_protocol` alert, which no
   build sends today. That alert replaces one that exists. `parse_alpn`'s
   no-match arm writes `ALERT_ILLEGAL_PARAMETER` today
   (`handshake_parser.c:292`), which is 47 (`handshake_message.h:124`), so
   §4.8's 0x0100 conversion reaches the wire as 0x012f, where RFC 9001 §8.1
   requires 0x0178 from a client whenever ALPN negotiation fails
   (`rfc9001.txt:1901-1902`). So under
   `CH_TRANSPORT_QUIC` that arm writes `ALERT_NO_APPLICATION_PROTOCOL`, and a
   `TRANSPORT=tls` build keeps `illegal_parameter` for the reason the comment
   at `handshake_parser.c:268-270` already gives: the body is well formed and
   its value is not acceptable. Both arms of that fork take the boundary test
   `CLAUDE.md` requires: one offered name accepted, one unoffered name
   refused, with 120 under `TRANSPORT=quic` and 47 under `TRANSPORT=tls`.
3. **Two alert descriptions and the harness contract.** `missing_extension`
   (109) for a ClientHello or EncryptedExtensions without
   `quic_transport_parameters` (RFC 9001 §8.2, `rfc9001.txt:1935`) and
   `no_application_protocol` (120) for a failed ALPN negotiation (RFC 9001
   §8.1, `rfc9001.txt:1899`) are both absent from
   `handshake_message.h:113-129`. Adding them widens the parser's alert
   contract, which `proof/eeparse_harness.c:36-56` and
   `proof/eeparse_alpn_harness.c` assert by name, so three launch lines move:
   `eeparse` (`proof/run.sh:419`), `eeparse_webpki` (`proof/run.sh:440`) and
   `eeparse_alpn` (`proof/run.sh:455`). The harness also proves at a 256-byte
   message (`proof/eeparse_harness.c:19`), and a QUIC EncryptedExtensions
   carrying a transport-parameters body plus an ALPN reply can exceed that, so
   the bound is a second thing to re-measure.

A fourth item is smaller but real: the `seen` bitmask at
`handshake_parser.c:355-357` uses four bits of a `uint8_t` today and would use
five. That fits. The cognitive-complexity ceiling of 15 is the constraint to
watch, not the mask.

### One existing proof bound moves with the AEAD reuse

`aead.c` carries over unchanged, but its proof does not.
`proof/aead_harness.c:19` declares `uint8_t aad[16]` and `:31` assumes
`aad_len <= 16`, so the harness proves `aead_seal` and `aead_open` for
associated data up to 16 bytes. A QUIC packet's associated data is the whole
unprotected header (`rfc9001.txt:1141-1143`), and the RFC's own client Initial
example is 22 bytes: `c300000001088394c8f03e5157080000449e00000002` at
`rfc9001.txt:2401`. A long header with maximum-length connection IDs and a
Retry token is larger still. So taking this reuse moves an existing launch
line: the AAD bound in `proof/aead_harness.c` rises, and `proof/run.sh:351`
must be re-measured with `/usr/bin/time -v` under `run.sh`'s flags. The same
applies to `aead_overlap` and `aead_forge` (`proof/run.sh:352-353`), which
share the shape. This is not new work the QUIC mode adds; it is existing work
the QUIC mode disturbs.

## Bounds that need measuring

No value here is chosen yet, except the one RFC 9001 fixes. Each row says
what sets the bound and how it is measured, the way `docs/webpki.md` states
its caps.

| bound | what sets it | how it is measured |
| --- | --- | --- |
| `CH_QUIC_MIN_RXBUF` | the largest single handshake message at one level. `CH_MIN_RXBUF` stays the maximum `cfg.h:115` already takes, over three terms: the trust term with the 22 record bytes removed, the key-exchange term with its 5 record-header bytes removed, and the server's transport-parameters body. QUIC removes the check that caps the buffer today: `cfg.buf`'s size is advertised as `record_size_limit` so the peer can never overflow it (`cfg.h:281-282`, `handshake.c:138-139`) | derive each term the way the tree derives it today. The trust term is `2 * (CH_X509_MAX + 5) + 8 + 22` under ca (`cfg.h:98`), `4 * (3072 + 5) + 8 + 22`, 12,338 bytes, under webpki (`cfg.h:105`) and 512 under raw (`cfg.h:107`); the 22 bytes are a completing record's cost (`cfg.h:82-87`), which a CRYPTO stream does not pay. The key-exchange term is `5 + 4 + 40 + 6 + 1128 + 6` under `KEX=pq` (`cfg.h:110`), 1,189 bytes, of which 1,184 are the hybrid ServerHello message and 5 are the record header (`cfg.h:88-91`). The third term, the server's transport-parameters body, has no measurement in this tree |
| the shortest packet `ch_quic_open` samples | RFC 9001 §5.4.2: the sample starts 4 bytes after the packet number offset and is 16 bytes long, and a packet too short to contain a complete sample MUST be discarded | fixed by the RFC, not measured: `ch_quic_open` discards a packet shorter than `pn_off + 4 + 16` bytes before it samples, and the boundary test is that the last valid length opens and the first invalid one discards |
| the shortest packet `ch_quic_seal` can sample | RFC 9001 §5.4.2: the encoded packet number and the protected payload must run at least 4 bytes past the 16-byte sample (`rfc9001.txt:1283-1286`), which is `pn_len + pt_len >= 4` here, because the AEAD adds 16 bytes | fixed by the RFC, not measured: `ch_quic_seal` returns `CH_EINVAL` and writes nothing below it, and the boundary test is that `pn_len + pt_len == 4` seals and `pn_len + pt_len == 3` refuses |
| the §6.6 integrity limit | RFC 9001 §6.6: the endpoint closes once the count of received packets that fail authentication exceeds the limit of the AEAD in use, which is 2^36 invalid packets for AEAD_CHACHA20_POLY1305 (`rfc9001.txt:1830-1831`) | fixed by the RFC, not measured: the boundary test is that the 2^36th failed open returns `CH_QUIC_DISCARD` and the 2^36+1st returns `CH_QUIC_AEAD_LIMIT` |
| the out-of-order CRYPTO buffer | RFC 9000 §7.5 makes an endpoint support at least 4096 bytes of out-of-order CRYPTO data, or close with CRYPTO_BUFFER_EXCEEDED | the caller's, under the interface above: chapulin takes ordered bytes. It belongs in colibri's bounds |
| the largest handshake message | `hsr_next_msg` refuses `msg_len > 0x4000` (`handshake_record.c:119`), which is this client's own choice | unchanged. RFC 9000 and RFC 9001 state no per-message limit; the buffer rule of RFC 9000 §7.5 (`rfc9000.txt:2154-2157`) is the only bound they give, and `CH_QUIC_MIN_RXBUF` above is the real bound here |
| `CH_HELLO_MAX` and `CH_TX_STAGE` | the QUIC hello drops 6 bytes of `record_size_limit` and adds `quic_transport_parameters`, plus ALPN in the device builds, which do not send it over TLS | measured: `session.h` holds 1141 for raw and ca classic, 2325 under `KEX=pq`, 1403 under `TRUST=webpki` and 2587 under both, each the TLS value plus 254 and, in the two device modes, plus 270 again. `quic.c` asserts `CH_HELLO_MAX` against `CH_TX_STAGE`, so a stale value fails the build |
| the session struct | `ch_quic` holds a `ch_tls`, the `handshake_state` that lives on a stack frame today, the driver's own fields, the two Initial keys, the two Handshake key sets, the 1-RTT send set, the three 1-RTT receive sets and the four `quic_hp_key` values; the components are measured under "Suspending the driver" | `bench/sram.sh`, with a `-DCH_TRANSPORT_QUIC` probe beside its `-DCH_KEX_PQ` and `-DCH_TRUST_WEBPKI` ones (`bench/sram.sh:28-45`), over the real header. No arithmetic over the components in that section is the answer |
| the 1-RTT key sets | RFC 9001 §6.3 makes two receive sets a floor, current and next (`rfc9001.txt:1711-1712`); the previous set is this record's policy choice, for the delayed packets §6.5 opens | `CH_QUIC_KEY_SETS` is 3, so the count is fixed and only `sizeof(quic_keys)` and `sizeof(quic_hp_key)` are left to measure; measure the struct again after them |
| the transport-parameters body, both directions | the client's body is the caller's; the server's arrives in EncryptedExtensions | capture real server bodies, as `docs/webpki.md` captured real chains. This tree holds no QUIC bytes today |
| `STACK_BUDGET` | `Makefile:9` sets 2560 by default, `Makefile:17` raises it to 4096 for `TRUST=webpki` and `Makefile:26` to 6144 for the hybrid | measure the mode's own object list under `lint-stack`; never carry another mode's ceiling |
| the SRAM row | `bench/sram.sh` regenerates the README's numbers from `sizeof` probes and `bench/stack.py`; `bench/device-ram.sh` sizes the packaged modules from `make print-lib-srcs` (`bench/device-ram.sh:81`) | add a probe for the new axis to each script; `LIB_VARIANT` (`Makefile:287`) gains the axis. `CLAUDE.md` forbids estimating these |

## What the mode does not do

chapulin owns every key and every packet's protection, and nothing else. The
rest is colibri's.

- **No packet framing.** colibri decodes the long and short headers, finds the
  packet number offset, and hands chapulin a header slice and a payload slice
  (RFC 9000 §17).
- **No reserved-bit check.** RFC 9000 §17.2 and §17.3.1 protect the two
  reserved bits of byte 0 with header protection and make a non-zero value a
  connection error of type PROTOCOL_VIOLATION, checkable only after both
  header protection and packet protection come off, because discarding the
  packet after header protection alone opens an attack
  (`rfc9000.txt:5508-5510`, `rfc9000.txt:5053-5056`). A successful
  `ch_quic_open` leaves the unprotected header in `pkt`, so colibri reads
  byte 0 there and raises that error itself. chapulin does not read those
  bits and reports nothing about them.
- **No packet number spaces, no send-side packet numbers and no ACKs.** colibri
  chooses what it sends and tracks three spaces (RFC 9000 §12.5, §17.1).
  chapulin recovers a received packet number inside `ch_quic_open` only
  because RFC 9001 §9.5 requires that recovery to happen without a timing side
  channel alongside the two unprotect steps (`rfc9001.txt:2110-2112`).
- **No CRYPTO frame parsing.** colibri decodes frames and orders bytes by
  offset (RFC 9000 §19.6).
- **No streams.** RFC 9000 §2 through §4 are colibri's.
- **No transport parameter encoding, decoding or checking.** The extension body
  is opaque to TLS (RFC 9001 §8.2), and the checks RFC 9000 §7.3 requires
  compare parameters against connection IDs the TLS stack never sees.
- **No 0-RTT.** Entry 2 stands, and QUIC does not use TLS early data anyway
  (RFC 9001 §4.6.1).
- **No key update policy.** chapulin derives with `quic ku`, holds the key
  sets, and reports through `ch_quic_open`'s `key_set` which set opened a
  packet. When to initiate under §6.1's two MUST NOTs is colibri's; the bit
  it writes is `ch_quic_key_phase`'s answer. Retention is split rather than
  handed over, because the keys are here and the timer is there: `ch_quic_key_update` moves the
  current receive set to previous and holds it, which is the §6.1 MUST
  (`rfc9001.txt:1637-1638`), and colibri ends the retention period §6.5
  leaves to the endpoint by calling `ch_quic_drop_previous_keys`. A
  peer-initiated update is split the same way: `ch_quic_open` detects it as
  `CH_QUIC_KEY_NEXT`, and colibri calls `ch_quic_key_update` before it seals
  the ACK (§6.2).
- **No key discard schedule.** RFC 9001 §4.9.1 makes a client discard Initial
  keys when it first sends a Handshake packet (`rfc9001.txt:942-946`), and
  §4.9.2 makes it discard Handshake keys when the handshake is confirmed
  (`rfc9001.txt:953-954`), which at the client is the receipt of a
  HANDSHAKE_DONE frame (§4.1.2, `rfc9001.txt:417-418`). Both events are
  colibri's to see, because chapulin sends no packets and reads no frames.
  The wipe itself is chapulin's, through `ch_quic_discard`. `ch_quic_state`
  reports complete (§4.1.1), never confirmed (§4.1.2).
- **No loss recovery, congestion control or flow control.** RFC 9002 entire,
  and RFC 9000 §4.
- **No connection IDs, address validation, path validation or migration.** RFC
  9000 §5.1, §8, §9.
- **No Retry logic and no version negotiation.** chapulin checks a Retry tag
  when asked (`ch_quic_retry_ok`) and re-derives Initial keys when asked
  (`ch_quic_initial_keys`); whether to accept the Retry, the token, and RFC
  8999 §5 and §6 version negotiation are colibri's. RFC 9221 datagrams are
  outside the interface.
- **No connection close.** chapulin reports an alert description; colibri
  builds the CONNECTION_CLOSE frame (RFC 9001 §4.8).
- **No second transport in one object.** `TRANSPORT` is a build axis, so a QUIC
  object holds no record layer and a TLS object holds no QUIC code.
- **No server role.** Unchanged from the README's non-goals.

## What the mode does not check or provide

Read this as part of the profile, not as a list of future work.

- **The fail-closed rule gains an exception, and it is inside this tree.**
  chapulin fails closed: `rec_open` returns -1, the caller treats every -1 as
  fatal (`record.h:48-49`), `handshake_record.c:35-38` raises
  `bad_record_mac`, and entry 21 makes the rule general. QUIC requires the
  opposite for packets. RFC 9001 §5.5 says failure to unprotect a packet does
  not necessarily indicate a protocol error or an attack
  (`rfc9001.txt:1373-1376`), and §6.6 closes only when the integrity limit is
  exceeded. So `ch_quic_open` reports a discard and keeps the session alive.
  The inversion sits here, at exactly one function, and INV-13 is the
  invariant it amends; "What changes in `docs/invariants.md`" holds the
  replacement text, without which entry 21 is weakened without anyone
  noticing.
- **The integrity limit is one count for the connection, and it is
  chapulin's.** RFC 9001 §6.6 counts received packets that fail
  authentication within the connection, across all keys, and makes the
  endpoint close with AEAD_LIMIT_REACHED and process no more packets once
  that count exceeds the limit of the AEAD in use (`rfc9001.txt:1823-1827`).
  The AEAD in use is the one TLS negotiated,
  TLS_CHACHA20_POLY1305_SHA256, whose integrity limit is 2^36 invalid
  packets (`rfc9001.txt:1830-1831`). So `ch_quic` holds one `open_failures`
  counter, not one per key set, and every failed `ch_quic_open` raises it at
  every level, Initial included. The call that carries the count past 2^36
  returns `CH_QUIC_AEAD_LIMIT` and makes the session dead, so no later call
  processes a packet; colibri sends the CONNECTION_CLOSE with
  AEAD_LIMIT_REACHED.
- **The confidentiality limit is per key set, and only the Initial keys pay
  it.** RFC 9001 §6.6 makes an endpoint count the packets it encrypts under
  each set of keys. For AEAD_AES_128_GCM the confidentiality limit is 2^23
  encrypted packets; for AEAD_CHACHA20_POLY1305 it exceeds the packet number
  space and is disregarded. So the count is owed under the Initial keys
  alone: `initial_sealed` counts what `ch_quic_seal` seals at that level and
  the call refuses the 2^23rd. Two details make this client stricter than the
  RFC and never weaker: §6.6 stops an endpoint once the count exceeds the
  limit (`rfc9001.txt:1800-1802`), so refusing the 2^23rd refuses one legal
  packet, and `ch_quic_initial_keys` does not reset `initial_sealed` when a
  Retry produces a new set of Initial keys, so one running count covers both
  sets. The close is colibri's.
- **A 1-RTT packet before the handshake completes is refused here.** RFC 9001
  §5.7 forbids a client from processing an incoming 1-RTT protected packet
  before the TLS handshake is complete (`rfc9001.txt:1484-1486`), and this
  design opens the window that rule is about: the Finished step installs the
  1-RTT key set and fires `on_level_ready` twice, and `t.state` becomes
  `CH_ST_CONNECTED` only later, when `ch_quic_crypto_out` hands the Finished
  to the caller. Between those two moments colibri holds a read key it may
  not use yet. So `ch_quic_open` at `CH_LEVEL_APPLICATION` returns
  `CH_EINVAL` and changes nothing while `t.state` is below
  `CH_ST_CONNECTED`, and colibri buffers the packet and delivers it again
  after `ch_quic_state` reports complete.
- **A packet without a complete sample is discarded here.** RFC 9001 §5.4.2
  makes an endpoint discard packets that are not long enough to contain a
  complete sample. `ch_quic_open` enforces it: a packet shorter than
  `pn_off + 4 + 16` bytes is a discard before any key is touched. The bounds
  table carries the row.
- **The peer-initiated key update and its error are split.** RFC 9001 §6.2
  makes the response to a peer's key update mandatory: a packet that opens
  under the next keys means the peer updated, and the endpoint MUST update
  its send keys before it sends an acknowledgment (`rfc9001.txt:1654-1656`).
  `ch_quic_open` reports the `CH_QUIC_KEY_NEXT` result; colibri calls
  `ch_quic_key_update` before it seals the ACK. §6.4 makes it a connection
  error of type KEY_UPDATE_ERROR when a packet opens under old keys after
  newer keys were used for packets with lower packet numbers. chapulin
  reports the key set and the recovered packet number; colibri, which holds
  the packet numbers, raises the error.
- **A post-handshake CertificateRequest has a different error code.** RFC
  9001 §4.4 makes a client treat one as a connection error of type
  PROTOCOL_VIOLATION (0x0a). `handshake_post.c:95-101` answers every unknown
  post-handshake type with `CH_EPROTO` and a TLS alert today. Under
  `TRANSPORT=quic` the driver refuses the message the same way, so chapulin
  detects it; the code on the wire is the transport's PROTOCOL_VIOLATION, not
  0x0100 plus the alert, so colibri reads `ch_quic_error_code`, which returns
  0x0a for this refusal and 0x0100 plus the alert description for the
  failures that are not on its list.
- **Unconsumed bytes at a lower level are refused here.** RFC 9001 §4.1.3
  makes it a connection error of type PROTOCOL_VIOLATION when keys for a
  higher level arrive and TLS has not consumed data from a previous level
  (`rfc9001.txt:491-493`). That is a different rule from the one about data
  at a level this client has already left (`rfc9001.txt:482-486`), and
  "Suspending the driver" states both beside each other. chapulin holds the
  reassembly buffer, so `ch_quic_crypto_in` enforces this one in two places:
  a delivery at a level above `rx_level` while `pt_off != pt_len` fails with
  `CH_EPROTO`, and a step that moved `rx_level` and left a byte in `cfg.buf`
  fails with `CH_EPROTO` in the same call. The same delivery with
  `pt_off == pt_len` is `CH_EINVAL` instead, because no bytes went
  unconsumed and the caller may deliver them again once the keys are
  installed. `ch_quic_error_code` reports 0x0a for both failures.
- **The server's transport parameters reach the caller before this client has
  authenticated the server.** `on_transport_params` fires from the
  EncryptedExtensions step, which in pin and webpki modes runs before
  CertificateVerify. RFC 9001 §8.2 says the value of transport parameters is
  not authenticated until the handshake completes, so any use of them cannot
  depend on their authenticity (`rfc9001.txt:1940-1942`). chapulin hands the
  bytes over and checks nothing about them; colibri waits for
  `ch_quic_state` to report complete before it acts on anything whose safety
  rests on them.
- **No connection ID checks.** RFC 9000 §7.3 requires matching
  `initial_source_connection_id`, `original_destination_connection_id` and
  `retry_source_connection_id` against connection IDs on the wire. chapulin
  sees the Destination Connection ID colibri hands to `ch_quic_initial_keys`
  and nothing else.
- **ALPN exists in one mode.** 545bf5d added ALPN under `TRUST=webpki`
  (`handshake_message.c:5-27`, `handshake_parser.c:275-294`); the device
  builds send none, which is what `examples/server/README.md:32` describes.
  RFC 9001 §8.1 makes ALPN mandatory for QUIC, so a device QUIC build must
  carry both halves outside `CH_TRUST_WEBPKI`, and no build sends
  `no_application_protocol` today.
- **No ticket reuse rule.** RFC 9001 §4.5 says clients SHOULD NOT reuse
  tickets, which is a SHOULD, and nothing in `handshake_post.c` holds it.
  Reuse is the caller's choice, as it is over TLS. §4.6.1's `early_data`
  rule is a client MUST and does not sit here: the `HSQ_STEP_COMPLETE` row
  in "Suspending the driver" states where the QUIC arm of `handle_ticket`
  enforces it.
- **No change to the trust mode.** A QUIC build is still `TRUST=raw`, `ca` or
  `webpki`, and `docs/webpki.md`'s own "What the mode does not check" list —
  no revocation, no Certificate Transparency, no name constraints — applies
  unchanged.
- **Nothing in the repository proves anything about a live QUIC endpoint.**
  `test/e2e.sh` runs against `openssl s_server`, which does not speak QUIC, so
  a QUIC end-to-end leg needs a server this tree does not have. Every existing
  suite stays hermetic.
- **Nothing about QUIC is proved yet.** The 83 launch lines in `proof/run.sh`,
  the 30 modules in `spec/Spec/` and the 89 files in `test/violations/` cover
  the TLS transport. "Verification owed" lists what the mode owes, and owing is
  not having.

## Verification owed

The tree's rules decide this section; QUIC adds nothing to it. A crypto or
protocol change touches the code, its Lean spec and the tests in one commit
(`CLAUDE.md`), and `make check-slow` must pass before the change is done.

**CBMC.** `tools/proof-cover.py` fails a shipped source that no `full` harness
compiles and no `AUDITED` entry lists, so every new `.c` owes a harness.
Against 83 launch lines and 86 harness files today:

- New: one per new source, by the names in "The new sources, by name":
  `quic_keys.c`, `quic_packet.c`, `quic_initial.c`, `quic_retry.c`,
  `quic_step.c` and `quic.c`, plus `quic_aes.c` and `quic_gcm.c`, all
  landed. `handshake_flight.c` is the exception and needs no harness of its
  own: `handshake_psk`, `handshake_pin` and `hybrid_secret` compile it, which
  is what `tools/proof-cover.py` asks for. The QUIC arm of
  `handshake_record.c` and all of `quic_config.c` are compiled into
  `quic_driver` rather than a leg of their own. The transport parameters add
  no source: `handshake_message.c` writes them and `handshake_parser.c` reads
  them. `quic_gcm` split the way `aead` did — five harness files, three
  launch lines, because two formulas returned no verdict.
- Moved: `aead`, `aead_overlap` and `aead_forge` (`proof/run.sh:351-353`) for
  the AAD bound; `eeparse`, `eeparse_webpki` and `eeparse_alpn`
  (`proof/run.sh:419`, `:440`, `:455`) for the parser's alert contract and
  message bound; `handshake_psk` and `handshake_pin` (`proof/run.sh:396-397`),
  which keep their harness shape and gain `handshake_flight.c` on the line; and
`hybrid_secret` (`proof/run.sh:592`), which includes `handshake_flight.c` in
place of `handshake.c`.
  `proof/run.sh:386-392` records what those two cost after the ClientHello
  stub's fill became a constant `cap` rather than a symbolic `n`
  (`proof/handshake_harness.c:167-176`); the `fill_nondet.0:618` bound stays
  on both lines. A source that moves between objects re-opens that
  measurement.
- Retired: none. `handshake_record` (`proof/run.sh:788`), `handshake_post`
  (`:583`) and `io` (`:565`) each prove an arm a TLS build still compiles,
  so all three keep their subjects. "Suspending the driver" says why.

Every one of those lines, new or moved, must be measured with
`/usr/bin/time -v` under `run.sh`'s exact flags before it is committed
(`docs/proofs.md`). A launch line whose formula has not been seen to converge
proves nothing.

**Lean.** `spec/Spec/Record.lean` models the TLS record layer and its
`nextSecret` is `traffic upd`; it says nothing about QUIC and does not move. A
QUIC mode owes its own modules — the key labels of §5.1 and §6.1, the §5.3
seal and open, the §5.4 mask, and AES and GHASH for INV-26 — and an
amendment to `HandshakeParser.lean` for `quic_transport_parameters` (it models
the ALPN reply already), against 30 modules in `spec/Spec/` today. Each new
module owes rows in `test/diff_test.c`, whose input domain stays inside what
the C and the spec agree on.

**Tests.** RFC 9001 Appendix A.1 through A.5 are exact vectors, and they live
in `test/quic_vectors.c`, which builds `bin/quic_test` under
`-DCH_TRANSPORT_QUIC` over the mode's sources and the primitives they call.
That line grows with the sections: it carries `hkdf.c sha256.c ct.c` for the
AES ones today, and a lane adds its own source when it adds its section.
`test/quic_vectors.c` compiles `quic_aes.c` rather than linking it, because
FIPS 197's vectors fix the key and INV-26 keeps the two constructors the only
public way to write an `aes_public_key`; compiling the source in also gives the
test `quic_aes_key.h`'s body of that type, which no library source outside the
three INV-26 admits can see. So that source stays off the link line. That is
the shape `bin/sha3_test` (`Makefile:491-493`) and `bin/mlkem_test`
(`Makefile:498-500`) already use for a mode's own sources, and `check` builds
and runs it beside the other test binaries. The Wycheproof AES-GCM suite runs
there too. `test/unit_test.c` gains nothing: it includes `tls.h` and calls
`rec_seal` (`test/unit_test.c:23`, `:276-306`), which a `-DCH_TRANSPORT_QUIC`
build does not compile. A.1's Initial keys and the header protection masks
A.2 and A.3 print guard `quic_aes.c` today, beside FIPS 197's own block
vectors; the rest of A.2, A.3 and A.4 waits for the sources that seal and open
a packet. Wycheproof gains one suite. The sequence
enumerations and the violation files follow the rule every other mode follows:
a mutation experiment that finds an unguarded rule lands a `.violation` file,
never a new lint.

**Fuzz.** `fuzz/` holds six libFuzzer targets over the attacker-facing
parsers, and the nightly runs them at `FUZZ_TIME=400` inside a 45-minute cap
(`.github/workflows/nightly.yml:508`, `:524`), which `lint-fuzz-budget` holds
as targets times seconds under that cap (`Makefile:2235-2246`). The mode adds
one target, `fuzz/fuzz_quic.c`, over `ch_quic_crypto_in` and the QUIC arm of
`handshake_record.c`, which is where a peer's bytes arrive. Seven targets do
not fit at 400 s, so the same commit lowers `FUZZ_TIME` to 380, which reads 44
minutes, the trade the comment at `.github/workflows/nightly.yml:518-523`
already records for the sixth target. `ch_quic_open` takes no target of its
own: its input is one packet under a key a fuzzer would have to forge, and
`quic_packet_harness.c` proves that path over unconstrained input instead.

**Gates that read a build axis by name.** `LIB_VARIANT` (`Makefile:287`),
`PUBLIC` and `lib-check` (`Makefile:363`, `Makefile:417-423`),
`lint-trust-separation`, `lint-stack`, `lint-matrix`, `lint-impact` with
`docs/impact.md`, `lint-proof-cover`, `lint-codegen-partition`,
`lint-wide-multiply`, `lint-runtime-symbols` with an `RV_ALLOWED` decision for
each new gated source, `make cxx-check` with `chapulin.hpp` and `test/hpp_test.cpp`,
`test/violations.py`'s `FAST_TARGETS` (`test/violations.py:252-261`) with
`"quic_driver_test"` and `"test/lint-invariants.sh"` and `test-invariants-fast`
(`Makefile:1635`) with `bin/quic_driver_test`, `bench/sram.sh`, and `make
coverage` (`Makefile:1016-1095`), whose object sets are written by hand per
mode: the mode adds a `TRANSPORT=quic` leg beside the `TRUST=webpki` one at
`Makefile:1046`, over `bin/quic_test` and `bin/quic_driver_test`, and
`COVERAGE_FLOOR` (`Makefile:964`) moves in the same diff by the ratchet rule
stated there. That leg is the one check here that still waits: the mode is
implemented and `bin/quic_driver_test` runs in `check`, so "What is still
open" carries it and the comment above `COVERAGE_FLOOR` names what the
commit that adds it does. `test/spec_coverage.py`'s `SRCS` list holds the
quic sources, which read as rows saying "not built" while the differential
has no QUIC leg; `bin/quic_driver_test` is a unit test and not a
differential driver, so its `DRIVERS` list waits for the leg that compares
the mode against `spec/`. Every
one of those needs a row or a leg for the new axis, which is work that is done
with the first line of code and not after it, and a gate that waits says so in
"What is still open" rather than staying silent. `test/e2e.sh` is the exception:
it stays a TLS leg, for the reason "What the mode does not check or provide"
gives, and "What is still open" holds the choice. The `FAST_TARGETS` pair is
the one whose absence is silent: a `catches` value outside that set runs in the
slow tier (`test/violations.py:322-325`), and `check-slow` runs
`test-invariants-fast` alone (`Makefile:859`), so without both names every
mutant this record plans runs in the nightly and not in `make check-slow`.

`cxx-check` is the one that cannot be answered with a row. It runs inside `make
check`, once per trust mode (`Makefile:753`, `:764`, `:767`), and links
`test/hpp_test.cpp` against the packaged object (`Makefile:409`, `:414`).
`chapulin.hpp` calls `ch_close`, `ch_connect`, `ch_write` and `ch_read`
(`chapulin.hpp:286`, `:290`, `:294`, `:298`), and a `TRANSPORT=quic` object
exports none of the four, so `make check TRANSPORT=quic` fails at the link. The
decision is to give the wrapper a QUIC arm rather than to skip the gate:
`chapulin.hpp` puts today's `Session` class under `#ifndef CH_TRANSPORT_QUIC`
and adds a `Quic` class under `#ifdef CH_TRANSPORT_QUIC` that forwards the
fifteen entries and adds only the RAII cleanup, byte views and typed results
`CLAUDE.md:249-254` allows it; `test/hpp_test.cpp` gains a QUIC leg; and
`check` gains a fourth `cxx-check` invocation with `TRANSPORT=quic`. `Config`
(`chapulin.hpp:108-246`) forks with `Session`, because it builds `ch_cfg` and
carries the `Io` callbacks (`chapulin.hpp:82`) a QUIC build has no use for, and
the two new callbacks and `ch_cfg.transport_params` surface there. Skipping the
gate under one axis would leave the largest API surface in the tree with no C++
leg, which is the one thing that sentence exists to prevent. The commit that
lands `quic.[ch]` applies it.

## What is still open

The mode, its owner split and the AES exception are decided. These are not:

- the `BRANCH_CEILING` entries for `quic_keys.c` and `quic_packet.c`. The
  table above owes 16, across 8 compiler and architecture specs, and neither
  file joins `BRANCH_SRCS` while it is a stub: a count measured against an
  empty body records nothing and falls the day the code lands. Both join that
  list, with their numbers measured under each spec, in the commit that
  implements them. `WIDEMUL_CEILING` already holds both at 0, and
  `WIDEMUL_DEFINES` gives them the transport define the shared gate lines do
  not pass;
- the CBMC harnesses the mode owes: every source has one now, by the table
  above, and `proof/run.sh` names what each launch line costs. `quic_gcm` and
  `quic_gcm_forge` still carry no launch line, because neither formula has
  returned a verdict;

- `CH_QUIC_MIN_RXBUF`: its formula, measured against the largest single
  handshake message of each term — the trust term's Certificate, the
  key-exchange term's hybrid ServerHello (`cfg.h:110`) and the server's
  transport-parameters body;
- `sizeof(quic_keys)` and the struct size that follows from it. The count of
  1-RTT receive key sets is not open: RFC 9001 §6.3 makes two a floor
  (`rfc9001.txt:1711-1712`), the only choice was between two and three, and
  this record takes three so §6.5 can open a delayed packet from the
  previous phase. That choice fixes `ch_quic_open`'s selection rule and its
  `current_phase_lowest_pn` argument;
- the exact `ch_quic_open` signature beyond the arguments named above:
  `largest_pn` is the caller's largest successfully processed packet number
  in that space (RFC 9000 Appendix A.3, `rfc9000.txt:8350-8351`),
  `current_phase_lowest_pn` is the lowest it has processed under the current
  key phase, the outputs are `key_set`, `pn` and `pt_len`, and what else
  colibri's packet number reconstruction needs is open;
- the `handshake_psk` and `handshake_pin` cost after the driver becomes
  resumable, which only a run can answer;
- the `make coverage` leg. The recipe builds its object sets by hand, one per
  PIN over `$(SRCS)` and one over the webpki sources, and neither names a QUIC
  source, so the QUIC sources contribute nothing to `COVERAGE_FLOOR`. The leg
  lands in the shape of the webpki leg, with `bin/quic_test` and
  `bin/quic_driver_test` in its run list, and that commit moves the floor to
  CI's re-measured reading. The comment above `COVERAGE_FLOOR` carries the
  same debt;
- the end-to-end leg. `test/e2e.sh` runs against `openssl s_server`, which
  speaks no QUIC, so the mode has no interop evidence at all until a QUIC
  server joins the suite. The three candidates are an OpenSSL 3.5 QUIC
  server, a Go `quic-go` echo server beside the Go echo server the suite
  already starts, and no leg at all, which leaves `make check-slow` green on
  a transport nothing has ever spoken to. The commit that landed `quic.[ch]`
  named none: `bin/quic_driver_test` drives the driver to the Handshake level
  with a ServerHello the test builds itself, and every message after that
  one is encrypted under keys only a server holds, so the record still
  claims no interop.

## What changes in `CLAUDE.md`

A `TRANSPORT=quic` build falsifies ten sentences in `CLAUDE.md` at `3432a5d`.
The AES sentence and the file-pair chain are in the appendix. Each row names
the sentence, its replacement and the commit that applies it; nothing changes
before that commit.

| sentence | replacement | commit |
| --- | --- | --- |
| `CLAUDE.md:103-104`, "AES never enters this codebase precisely to avoid tables" | the appendix text | the first AES source, `quic_aes.[ch]` |
| `CLAUDE.md:10-11`, "Zero heap. No malloc anywhere, ever — one static `ch_tls` session struct plus a caller-provided record buffer is the entire working set." | "Zero heap. No malloc anywhere, ever — one static session struct, `ch_tls` under `TRANSPORT=tls` and `ch_quic` under `TRANSPORT=quic`, plus one caller-provided buffer is the entire working set. The buffer holds records in a TLS build and one encryption level's CRYPTO bytes in a QUIC build." | `quic.[ch]` |
| `CLAUDE.md:140-141`, "All parsing goes through the bounds-checked `rbuf` reader and all output bytes through the `wbuf` writer; no raw buffer arithmetic outside them." | the same sentence, then: "Header protection is the one exception, and only in `quic_packet.c`, the one file that writes a masked byte: RFC 9001 §5.4.1 XORs the first mask byte into the low four bits of byte 0 for a long header and the low five bits for a short header, and the next `pn_len` mask bytes into the packet number field, in the caller's `pkt` on the open path and in `out` on the seal path, which `quic_header_protect` and `quic_header_unprotect` do, on five mask bytes their caller computed, and nothing else does. The `pn_off + 4 + 16` length check runs before either, so the bytes they touch are inside a range already checked." | `quic_packet.[ch]` |
| `CLAUDE.md:249-254`, "`chapulin.hpp` is an optional, header-only C++ wrapper ... `make cxx-check` compiles it against the packaged library object as part of check." | the same sentence, then: "A `TRANSPORT=quic` object exports the `ch_quic_` entries and none of the four TLS calls, so the wrapper forks with the object: `Session` sits under `#ifndef CH_TRANSPORT_QUIC` and `Quic` under `#ifdef CH_TRANSPORT_QUIC`, forwarding the QUIC entries and adding no logic either. `cxx-check` runs on both transports." | `quic.[ch]` |
| `CLAUDE.md:144-145`, "Operational errors (bad peer input, short buffers, I/O failure) return `ch_err` codes and fail closed — alert, wipe keys, dead session." | the same sentence, then: "`TRANSPORT=quic` has two stated exceptions and no others. `ch_quic_open` reports a discard and keeps the session alive, because RFC 9001 §5.5 says a packet that fails to unprotect is not necessarily an attack; and `CH_EINVAL` from a `ch_quic_` entry means the caller called out of order, changed nothing, and may call again. INV-13 carries both." | `quic_packet.[ch]` for the first, `quic.[ch]` for the second |
| `CLAUDE.md:148-150`, "Record size discipline: the client always sends `record_size_limit` (RFC 8449) sized to the caller's buffer. A peer record over the limit is a protocol error, not a resize." | "Record size discipline: a `TRANSPORT=tls` client always sends `record_size_limit` (RFC 8449) sized to the caller's buffer, and a peer record over the limit is a protocol error, not a resize. A `TRANSPORT=quic` build has no record layer (RFC 9001 §4.1.3); there `cfg.buf_len` bounds one level's reassembled CRYPTO bytes, and a message that does not fit is a protocol error, not a resize." | the `handshake_record.[ch]` QUIC arm |
| `CLAUDE.md:151-152`, "RFC MUSTs we keep even though this is minimal: HelloRetryRequest handling, KeyUpdate receipt, ..." | "... HelloRetryRequest handling in both transports, KeyUpdate receipt over TLS (under `TRANSPORT=quic` a KeyUpdate message is a connection error, RFC 9001 §6, and the key update is the packet-level one of §6), ..." | `quic.[ch]` |
| `CLAUDE.md:53-90`, the file-pair chain, which names every library file and none of the nine new pairs, and ends "Firmware takes everything below `tls.[ch]` as-is and supplies I/O callbacks and `ch_rand_bytes`" (`CLAUDE.md:79-80`) | the appendix text | each pair's own commit adds its entry, and the last one lands the whole chain |
| `CLAUDE.md:215-221`, "Every change passes `make check` ... and `make check-slow` (proofs, e2e against a real TLS 1.3 server, ...)" | the same sentence, then: "The `TRANSPORT` axis does not multiply those runs. `make check` and `make check-slow` build the `TRANSPORT=tls` binaries and add one `cxx-check TRANSPORT=quic` leg, one `bin/quic_test` run and one `bin/quic_driver_test` run. The QUIC object has no e2e leg until a QUIC server joins the suite, because `test/e2e.sh` runs `openssl s_server`, which speaks no QUIC; \"What is still open\" names that choice." | `quic.[ch]` |
| `CLAUDE.md:46-52`, "TRUST=webpki keeps that rule ... and breaks it twice ... offers the list of ALPN protocols the caller configured" | the same sentence with "and every `TRANSPORT=quic` build offers the ALPN list too, because RFC 9001 §8.1 requires it" | the commit that moves `write_alpn` and `parse_alpn` out of `CH_TRUST_WEBPKI` |

## What changes in `docs/invariants.md`

A `TRANSPORT=quic` build falsifies four numbered invariants and adds two. The
file stops at INV-27 today (`docs/invariants.md:279`). Each row names the
entry, what replaces it and the commit that applies it; nothing changes before
that commit. Two more entries take a sentence rather than a row: INV-14's claim
lists the refusals (`docs/invariants.md:462-468`) and INV-18's claim says all
state lives in `ch_tls` (`docs/invariants.md:784`), and a QUIC build adds
refusals to the first and holds its state in `ch_quic`, so the commit that lands
`quic.[ch]` names the transport in both.

| entry | replacement | commit |
| --- | --- | --- |
| INV-1, "one sealing path" (`docs/invariants.md:36-46`). Its claim is "Record protection is the only path that seals or opens bytes", its mechanism "only `record.c` calls them", and `inv-1-seal-only-in-record` implements it with `paths: exclude: [test, proof, fuzz, spec, bench, bin, examples, record.c, aead.c]` (`.semgrep/invariants.yml:99-110`). A QUIC build calls `aead_seal` and `aead_open` from `quic_packet.c`, so the claim is false and the rule fails on the first line of code | the claim becomes "Record protection is the only path that seals or opens bytes under `TRANSPORT=tls`, and packet protection is the only one under `TRANSPORT=quic`"; the mechanism names `record.c` as the TLS caller and `quic_packet.c` as the QUIC one, and adds that `quic_initial.c` and `quic_retry.c` seal and open with `gcm_seal` and `gcm_open`, which INV-26 governs and this rule does not match; the check names the amended `inv-1-seal-only-in-record`, whose exclude list becomes `[test, proof, fuzz, spec, bench, bin, examples, record.c, aead.c, quic_packet.c]` | `quic_packet.[ch]` |
| INV-13, "no resumable errors" (`docs/invariants.md:448-458`). Its claim is "Every error kills the session: alert, wipe, dead. There is no error a caller can retry past", its mechanism "`tlsi_fail` is the single funnel", and its check the 466k-sequence run | the claim gains "under `TRANSPORT=quic` two errors leave the session live and nothing else does: `ch_quic_open`'s discard of a packet it cannot authenticate (RFC 9001 §5.5), which raises the §6.6 count and changes no key set, because `ch_quic_open` never installs an update and writes `key_set` only on a successful open, and `CH_EINVAL` from a `ch_quic_` entry, which changed nothing and may be called again"; the mechanism names `quic_fail` as the QUIC funnel beside `tlsi_fail`; the check names the QUIC sequence differential in `bin/quic_driver_test`, which asserts that no other return code leaves the session live | `quic.[ch]` for the `CH_EINVAL` half, `quic_packet.[ch]` for the discard |
| INV-17, "secrets die at phase boundaries" (`docs/invariants.md:770-780`). Its claim is "every failure path wipes through `tlsi_wipe`" (`:772-773`) and its check "the wipe sits in the single `tlsi_fail` funnel" (`:777`). A QUIC object compiles no `session.c`, so neither function exists in it | the claim and the check name `quic_fail` under `TRANSPORT=quic` beside `tlsi_fail` under `TRANSPORT=tls`, and the claim adds that the QUIC driver wipes `hs` at `HSQ_STEP_COMPLETE`, one round trip before the TLS driver reaches the same wipe at `handshake.c:151` | `quic.[ch]` |
| INV-22, "the server's flight arrives in one order" (`docs/invariants.md:732-766`). Its mechanism is "There is no state variable to desynchronize; the order is the call order" (`:746-747`), and its check is `handshake_sequence_test` (`:755`), which links TRUST=raw over the TLS driver (`:758`). A QUIC build stores `ch_quic.step`, so the mechanism is false there and the check covers no QUIC trace | the mechanism gains: under `TRANSPORT=quic` the order is the stored `ch_quic.step`, `hsq_advance`'s default arm, which answers `unexpected_message` for every value above `HSQ_STEP_COMPLETE`, and the step numbers that copy Lean's `State` constructor for constructor; the check names the QUIC sequence differential in `bin/quic_driver_test` against the same oracle under the transport `quic` | `quic_step.[ch]` |
| INV-26, new: the AES exception. "The AES exception, stated as an invariant" above holds its claim, its mechanism, its check `inv-26-aes-public-keys-only` and its violation | the whole entry, written in the shape INV-20 uses, with its **Check** field reading "Semgrep-tripwire (`inv-26-aes-public-keys-only`)" and its claim naming the `aes_` and `gcm_` prefixes the rule matches, so the claim and the check say the same thing | the first AES source, `quic_aes.[ch]` |
| INV-27, new, and the one row here that has landed: the partition. Every root file only a `TRANSPORT=quic` build compiles is named `quic*`, and the Makefile's `QUIC_SHARED` and `QUIC_CONDITIONAL` name the mode's text that is not | the whole entry, written in the shape INV-20 uses, with its **Check** field reading "Semgrep-tripwire grade (`make lint-quic-partition`, `tools/quic-partition.py`)" and three mutants in `test/violations/` measuring it | the interface headers, which landed it |

## What changes in `docs/decisions.md`

A `TRANSPORT=quic` build falsifies five more entries, beside entry 6, which the
appendix replaces whole. Each row names the entry, what replaces it and the
commit that applies it; nothing changes before that commit. Entry 38 records
the trade and names each conflict; these rows amend the entries it conflicts
with, so a reader holding `docs/decisions.md` alone reads no absolute that a
QUIC build breaks.

| entry | replacement | commit |
| --- | --- | --- |
| entry 3, "The MUSTs stay despite minimalism" (`docs/decisions.md:17-21`), whose list reads "KeyUpdate both directions" (`:18`) | the entry gains: "KeyUpdate receipt is the TLS message over `TRANSPORT=tls`; a `TRANSPORT=quic` build treats that message as a connection error and takes the packet-level key update of RFC 9001 §6 instead." | `quic.[ch]` |
| entry 19, "`record_size_limit` is the receive buffer's size" (`docs/decisions.md:188-191`) | the entry gains: "A `TRANSPORT=quic` build sends no `record_size_limit`, because RFC 9001 §4.1.3 removes the record layer. There `cfg.buf_len` bounds one encryption level's reassembled CRYPTO bytes, and `CH_QUIC_MIN_RXBUF` is the floor it must meet." | the `handshake_record.[ch]` QUIC arm |
| entry 21, "Every operational error fails closed" (`docs/decisions.md:224-229`) | the entry gains: "A `TRANSPORT=quic` build has two stated exceptions and no others: `ch_quic_open` reports a discard and keeps the session alive (RFC 9001 §5.5), and `CH_EINVAL` from a `ch_quic_` entry means the caller called out of order and changed nothing. INV-13 carries both." | `quic_packet.[ch]` for the first, `quic.[ch]` for the second |
| entry 28, "Four exported symbols" (`docs/decisions.md:296-299`) | the heading and the first sentence become "**Four exported symbols under `TRANSPORT=tls`, fifteen under `TRANSPORT=quic`.** The library packages as one relocatable object; partial linking plus symbol localization does the namespacing. `PUBLIC` is `$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)`, and the transport axis selects the first term rather than adding to it." | `quic.[ch]` |
| entry 37, "A `TRUST=webpki` caller offers a list of application protocols and the server picks one" (`docs/decisions.md:388-408`) | the entry gains: "A `TRANSPORT=quic` build offers the same ALPN list in every trust mode, because RFC 9001 §8.1 requires it, and closes with `no_application_protocol` when no protocol is negotiated." | the commit that moves `write_alpn` and `parse_alpn` out of `CH_TRUST_WEBPKI` |

## Appendix: replacement text

The first two replacements below are the AES ones, and the commit that lands
the first AES source applies both. Neither changes before that commit. The
third is the file-pair chain, and each pair's own commit adds that pair's
entry to it.

**`CLAUDE.md`**, replacing the sentence at `CLAUDE.md:103-104` ("ChaCha20/
Poly1305/x25519 are constant time by construction — keep them that way; AES
never enters this codebase precisely to avoid tables."):

> ChaCha20/Poly1305/x25519 are constant time by construction — keep them
> that way. AES is table-driven and exists in one place for one reason: RFC
> 9001 fixes AES-128-GCM for QUIC Initial packets (§5.2), AES-128-ECB for
> their header protection (§5.4.3) and the Retry integrity tag (§5.8), and
> every key those three use is public — derived from a printed salt and a
> connection ID that travels in the clear, or printed in the RFC itself.
> `quic_aes.[ch]` and `quic_gcm.[ch]` take a key type, `aes_public_key`, whose
> body lives in `quic_aes_key.h` and which only `quic_initial.c` and
> `quic_retry.c` may build; `ch_quic` stores no key at all. INV-26 states
> the rule, the compiler refuses a key object elsewhere, a Semgrep rule
> holds the calls, `.violation` mutants prove each fires, and both files
> sit in `WIDEMUL_PUBLIC`. No key from the TLS key
> schedule is ever passed to AES, and AES is never a cipher suite.

**`docs/decisions.md` entry 6**, replacing the whole entry (`docs/decisions.md:38-42`):

> 6. **ChaCha20-Poly1305 only as a cipher suite; AES exists for QUIC's
>    public-key packets alone.** Cost: the IoT profile's mandatory AES-CCM
>    suite and AES-only servers. Gain: constant time by construction on any
>    core for every secret this tree holds — no lookup table is ever indexed
>    with a key from the TLS key schedule, so there is no timing story to
>    defend. The one AES in the tree protects QUIC Initial packets and checks
>    the Retry tag, where RFC 9001 §5 states the keys are public, and entry
>    38 and INV-26 state how the build keeps it there. An AES-CCM build flag
>    is the most likely future concession, and it would not reuse that AES.

**`CLAUDE.md`**, replacing the file-pair chain at `CLAUDE.md:53-90`. Each new
pair sits at the place "The new sources, by name" gives it, and the pairs a
`TRANSPORT=quic` build compiles in place of another are written beside it:

> - One concern per file pair, dependencies pointing down only:
>   `ct.[ch]` (constant-time bytes) ← `sha256.[ch]` + `sha3.[ch]` +
>   `sha512.[ch]`/`sha512_compress.[ch]` (SHA-384 and SHA-512; the
>   TRUST=webpki build packages them, other builds keep them test-only) ←
>   `mlkem.[ch]`/`mlkem_poly.[ch]` (ML-KEM-768; the KEX=pq build packages
>   them with `sha3.[ch]`, other builds keep them test-only) ← `hkdf.[ch]`
>   (HMAC + HKDF + TLS labels) ← `chacha20.[ch]` + `poly1305.[ch]` +
>   `quic_aes.[ch]` with `quic_aes_key.h` (the AES-128 forward cipher of FIPS
>   197 and the `aes_public_key` type, TRANSPORT=quic; INV-26 names the three
>   keys it may see) ← `aead.[ch]` (RFC 8439 seal/open) + `quic_gcm.[ch]`
>   (AEAD_AES_128_GCM and GHASH, TRANSPORT=quic) ← `x25519.[ch]` +
>   `p256.[ch]` + `rsa.[ch]`/`rsa_mont.c` (pinned-mode verify) +
>   `p384.[ch]`/`p384_field.[ch]` + `rsa_pkcs1.[ch]` (the chain signatures a
>   public CA writes, TRUST=webpki) ←
>   `pem.[ch]` (RFC 7468 armour and RFC 4648 base64, decode only) +
>   `x509_der.[ch]` (canonical DER, read by both certificate verifiers) +
>   `x509.[ch]` (profiled certificate verify, TRUST=ca) +
>   `webpki.[ch]` with `webpki_cert.c`, `webpki_ext.c`, `webpki_name.c`,
>   `webpki_sigalg.c`, `webpki_spki.c` and `webpki_time.c` (chain verify
>   against caller-supplied anchors, TRUST=webpki) ←
>   `record.[ch]` (record layer, TRANSPORT=tls) or `quic_keys.[ch]` (the
>   RFC 9001 §5.1 labels and the §6.1 key update) + `quic_packet.[ch]`
>   (§5.3 packet protection and §5.4.4 header protection) +
>   `quic_initial.[ch]` (the Initial packets, over `quic_aes.[ch]` and
>   `quic_gcm.[ch]`) + `quic_retry.[ch]` (the §5.8 Retry tag), TRANSPORT=quic ←
>   `handshake_parser.[ch]` (message parsers) ←
>   `handshake_record.[ch]` (record reading and message reassembly under
>   TRANSPORT=tls, one level's ordered CRYPTO bytes reassembled into
>   messages under TRANSPORT=quic) ←
>   `handshake_auth.[ch]` (server authentication: the Certificate and
>   CertificateVerify flight, the CA build's revocation epoch, and the
>   webpki build's chain walk and hostname check) ←
>   `handshake_flight.[ch]` (the flight handlers both transports compile) ←
>   `handshake.[ch]` (client state machine, TRANSPORT=tls) or
>   `quic_step.[ch]` (one step per whole handshake message,
>   TRANSPORT=quic) ←
>   `handshake_post.[ch]` (NewSessionTicket and KeyUpdate, the messages
>   that arrive after the handshake) ← `tls.[ch]` (public API,
>   TRANSPORT=tls) or `quic.[ch]` (public API, TRANSPORT=quic) ← demo/test
>   mains. A `TRANSPORT=quic` build compiles `quic_step`, `quic`,
>   `quic_keys`, `quic_packet`, `quic_initial` and `quic_retry`, with `aes`
>   and `gcm` under the last two, in place of `io`, `record`, `session`,
>   `handshake` and `tls`, and compiles `handshake_flight`,
>   `handshake_record` and `handshake_post` as a `TRANSPORT=tls` build does.
>   Firmware takes everything below `tls.[ch]` or `quic.[ch]` as-is,
>   supplies `ch_rand_bytes` in both, and supplies I/O callbacks only under
>   `TRANSPORT=tls`, because a QUIC object opens no socket.
>   One pair sits off that chain rather than in it: `x509_ca.[ch]`
>   (provisioning — one PEM certificate to the key bytes
>   `ch_cfg.server_pubkey` takes) reads `pem.[ch]` and `x509.[ch]`, and
>   no library source reads it. A CA-mode build exports its
>   `ch_pubkey_from_pem` as a fifth public call, which firmware calls
>   while provisioning and no session reaches.
