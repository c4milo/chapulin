# Server role

A `ROLE=server` build answers a TLS 1.3 client over the same caller-supplied
I/O callbacks the client role uses. It reads a ClientHello, selects one
parameter set from what the client offered, proves one identity with one
private key, and protects records with the layer this tree already has. It
opens no socket and accepts no connection; the caller does both.

The scope Camilo set, and this document does not revisit: the server serves any
strictly conformant TLS 1.3 client, and it accepts every cipher suite selection
such a client may make. "What the widened scope forces, and what it cannot
cover" states exactly how far that scope carries and where it stops, because it
stops short of the word "any" and a reader must know where.

This document states the cost that dominates the role, what the role asks of
this tree, the profile it offers, where each new piece of cryptography lives,
the interface it exposes, what it reuses, the bounds that need measuring, what
it does not check, the verification it owes, what is still open, and which
`CLAUDE.md` sentences and numbered invariants a `ROLE=server` build falsifies.
An appendix holds the replacement text for the rules a single sentence cannot
repair.

`docs/quic.md` is the model for this document's shape and for the order of the
work: the design record first, then headers with contracts and no bodies, then
a build axis that links an object whose every call fails closed, then the
bodies one module at a time. `docs/webpki.md` is the model for "What the mode
does not check".

## Status

Implemented. `SRV_SRCS` names eight sources — `srv_parser.c`,
`srv_parser_ext.c`, `srv_message.c`, `srv_cookie.c`, `srv_auth.c`,
`srv_flight.c`, `srv_handshake.c` and `srv.c` — and every one of them has a
body. No `CH_SRV_STUB` marker is left in the tree, `make lib-check
ROLE=server TRUST=none` links the object, and `make check` runs `bin/srv_auth_test`,
`bin/srv_test` and `bin/srv_flight_test` over it. Four surveys and three
competing architectures preceded this record; the architecture below is the
build-axis one, and the section "Considered and rejected" names what it took
from the other two and what it refused.

One piece of the plan has not landed. `chapulin.hpp` declares no `Server`
type, so the `ROLE=server` leg of `lib-check` runs without `cxx-check`.
`test/e2e.sh` does drive another stack against a chapulin server now:
OpenSSL's `s_client` and this tree's own client each make a full handshake
with `bin/tlsserver` and then resume the ticket it issued ("Resumption"
below).

Three items were stated as blocking the first line of code, and all three are
in "What is still open": whether the key schedule goes hash-agile in the
shared files or in a role arm, whether a split CBMC harness for AES-GCM
converges, and how many signing identities a deployment provisions. The code
landed without this record recording an answer to any of the three, so read
the sources, not this section, for what they chose.

This is the fourth round of this record. An adversarial review of the second
round raised thirteen blockers, three analysts resolved them against the tree,
and the third round applied every resolution. Six of the thirteen ended in a
question only Camilo can answer; each one is stated in "What is still open"
rather than decided here.

A review of the third round confirmed all thirteen closed and raised six more,
which this round closes. One was a protocol error and the rest were numbers or
contradictions: the two signer sketches stated the wrong hash rule for the
CertificateVerify signature, and "The CertificateVerify signature uses two
different hashes" now states the right one; the record disagreed with itself
about the `sha512.c` and `sha512_compress.c` branch ceilings, and now says
seven files join `BRANCH_SRCS`; "Bounds that need measuring" gained a row for
re-measuring `hkdf.c`, which the change pushes over its recorded ceiling; the
`p256.c` branch count is 78, re-measured, where the third round printed 34; the
`§4.4.3` comments the third round recommended fixing were fixed by `91c0569`;
and `test/lint-invariants.sh`, which `gcm.patch` also creates, is now stated as
one file whose order open question nine decides.

One dependency on somebody else's work is stated here rather than buried. The
appendix's replacement file-pair chain names `handshake_flight.[ch]` as the
client's flight handlers. That pair is whole: `docs/quic.md`'s lane landed
`handshake_flight.c` in `33978f6`, moving the `hsf_` handlers out of
`handshake.c`. The partition below puts `handshake_flight.c` in
`CLIENT_REPLACED`, so a server object does not compile the client's flight
handlers.

## Method

Every claim about this tree comes from a command run in a worktree, and quotes
the decisive line with its file and line number. The third round ran at commit
`bed745608d92724e91a367202f3f1222e03e45c8`; this round ran at `91c0569`, one
commit later. `91c0569` is a comment-only change, so the counts it could move
were re-run at the branch head: the `§4.4.3` grep below now returns 0, and four
others are unchanged — `ls test/violations/*.violation | wc -l` 94,
`grep -c '^#define ALERT_' handshake_message.h` 18, the tree-wide `INV-26`
count 22, and `grep -c 'INV-26' docs/invariants.md` 0.
Every claim about RFC 9846 carries its line number in
the plain-text file this tree does not carry; the citations were read from a
local copy of 7,397 lines. TLS 1.3 is RFC 9846 here, as the rest of the tree
cites it (`docs/decisions.md` entry 4). RFC 8446 is never cited, and its
section numbers are never copied: RFC 9846 renumbers, so there is no §4.4.3.
Certificate is §4.5.1 (`rfc9846.txt:2783`), Certificate Verify is §4.5.2
(`rfc9846.txt:3010`) and Finished is §4.5.3 (`rfc9846.txt:3109`).

Ten comments in the tree carried the wrong number at `bed7456`, and commit
`91c0569` "docs: cite the sections RFC 9846 actually has" fixed all of them
along with the rest of the renumbering: `git show --stat 91c0569` ends
`36 files changed, 229 insertions(+), 229 deletions(-)`, and the body reads
"Old 4.4.3 splits two ways: signed content to 4.5.2, what a SignatureScheme
means to 4.3.3." Run at `91c0569`,
`grep -rn 'RFC 9846 §4.4.3' --include='*.c' --include='*.h' . | wc -l` returns
**0**. Server code has nothing left to copy, and this record cites the two
sections that split apart at their new numbers.

Three analysts resolved the second round's thirteen review blockers in
clusters, and four of their resolutions met on one section. Each meeting is
settled here rather than left to a reader. The signing mutant: one analyst put
the copied compare-and-subtract in `p256_sign.c` and the other in
`p256_field.c`; it lands in `p256_field.c`, because moving the arithmetic there
is what leaves the signer no reduction of its own to corrupt, and both analysts
named the same target. `BRANCH_SRCS` membership: one named the two signers and
the other named the five arithmetic files; the five win, for the reason
`Makefile:2232-2238` gives, and `p256_sign.c` is not among them because its
arithmetic moved out. The codegen bounds row: one analyst said it must stop
citing `make lint-codegen-partition` as the check that holds the numbers and
the other said branch ceilings live in `BRANCH_CEILING` rather than
`WIDEMUL_CEILING_SPEC`; both corrections land, as one rewritten row and one new
one. And `hkdf.c`'s HMAC: one analyst measured its call sites and its cognitive
complexity while the other renamed it; the counts and the rename are one
paragraph, and the record writes `hmac_sha256` only where it names the function
the tree has today.

Numbers marked *measured* come from a program that ran or a command whose text
is given. *Derived* means a formula over measured inputs, and the formula is
shown. Anything else that could have been a number says it is **unmeasured**.
No number in this file substitutes for `bench/sram.sh`, which has no server row
and cannot get one until a server struct exists.

## The cost that dominates: the key schedule stops being SHA-256

This section is first because it is the single largest cost in the role
measured by interfaces touched, and because it changes files both roles
compile.

### The largest costs, in one table

Every row is measured, and each one is derived below. The table is here rather
than in an appendix because these are the numbers that decide whether the role
lands.

| Cost | Measured | Where the measurement is |
|---|---|---|
| `sizeof(ch_tls)` grows | 1144 to 1296 arm64, 1072 to 1224 rv32, +152 both | "The session struct, measured both ways" |
| `sizeof(handshake_state)` grows, and it is a stack local | 448 to 544 arm64, 436 to 532 rv32, +96 both | "The largest frame cost is not in `ch_tls`" |
| `ch_handshake`'s stack frame grows | 688 to 784 arm64, 608 to 704 rv32, 712 to 808 Cortex-M3 | the same |
| HMAC's stack frame grows | 304 to 528 bytes in the shape that passes `make lint-tidy` | "What it costs in this tree" |
| A one-function hash-agile HMAC fails `make lint-tidy` | cognitive complexity 24 against `.clang-tidy:98`'s threshold of 15 | the same |
| Having SHA-384 at all costs flash | 2,280 bytes of text and const | "The flash cost of having SHA-384 at all" |
| The HMAC split costs flash | 388 to 672 bytes of `__text` at `-Os`, +284 | "What it costs in this tree" |
| Declarations that change signature | 14, across four headers | the same |
| Struct fields that change type | 10, in three headers | the same |
| CBMC harnesses re-aimed | 8, every launch line re-measured | "What it costs the proofs" |
| Lean definitions and theorem statements that stop asserting 32 | 6 definitions, 5 statements, plus `Spec/Record.lean`'s | "What it costs the Lean specs" |
| A `TRANSPORT=quic` session pays for AES-256's round keys | +260 bytes per session in the byte form | the `aes.[ch]` and `gcm.[ch]` section |

Two costs in the role carry more unmeasured risk than any row above, and
neither is a hash cost: whether a split CBMC harness for AES-GCM converges, and
what a constant-time AES costs in flash and cycles. "Where the cryptography
lives" ranks all of them.

### Why the scope forces it

`rfc9846.txt:4540-4543` reads:

    4540:   *  A TLS-compliant application MUST implement the
    4541:      TLS_AES_128_GCM_SHA256 [GCM] cipher suite and SHOULD implement the
    4542:      TLS_AES_256_GCM_SHA384 [GCM] and TLS_CHACHA20_POLY1305_SHA256
    4543:      [RFC8439] cipher suites (see Appendix B.4).

A client must implement AES-128-GCM and may implement the other two. Nothing
requires a client to *offer* any particular suite. So a conformant client may
offer `TLS_AES_256_GCM_SHA384` alone, and Camilo's scope says the server serves
it. That suite names SHA-384, and `rfc9846.txt:4055-4056` says what the name
governs:

    4055:   The Hash function used by Transcript-Hash and HKDF is the cipher
    4056:   suite hash algorithm.  Hash.length is its output length in bytes.

So the transcript hash, every HKDF-Extract, every HKDF-Expand-Label, every
Derive-Secret, every traffic secret, the Finished key, the `verify_data` and
the PSK binder all change length with the selected suite. This is not a record
layer change. The AEAD key stays 32 bytes for AES-256-GCM, the same as
ChaCha20's, so `AEAD_KEY` does not move; what moves is every secret above it.

### What it costs in this tree

Today `keysched.h:1-2` states the opposite as the module's premise:

    keysched.h:1    // TLS 1.3 key schedule (RFC 9846 §7.1), specialized to one PSK and
    keysched.h:2    // SHA-256. Pure functions over 32-byte secrets; the handshake owns where

**Fourteen function declarations change signature, and one of them is
renamed.** Five in `hkdf.h`: `hmac_sha256` (`:13`), which becomes `hmac`
because a function that computes HMAC-SHA-384 when it is handed a `hash_len`
of 48 must not carry `sha256` in its name; `hkdf_extract` (`:16`),
`hkdf_expand` (`:21`),
`hkdf_expand_label` (`:27`), `hkdf_derive_secret` (`:31`). Six in `keysched.h`:
`ks_early` (`:14`), `ks_verify_data` (`:18`), `ks_handshake` (`:23`),
`ks_master` (`:29`), `ks_res_master` (`:34`), `ks_res_psk` (`:36`). Two in
`record.h`: `rec_dir_init` (`:30`), `rec_dir_update` (`:35`). One in
`handshake_record.h`: `hsr_transcript_hash` (`:191`). Each takes a leading
`size_t hash_len` whose only valid values are `SHA256_LEN` and `SHA384_LEN`,
and each array parameter becomes `HKDF_HASH_MAX` wide.

**Ten struct fields change type.** `session.h:104-106` (`rd_secret`,
`wr_secret`, `res_master`), `handshake_record.h:48-53` (`early`, `binder_key`,
`handshake_secret`, `c_hs`, `s_hs`, `master`), and `cfg.h:169` (`psk`, whose
length is the hash length of the suite its ticket was issued under).

**The rename is a three-surface change, and the Lean spec is the one surface
that does not change.** `git grep -n 'hmac_sha256'` returns twelve occurrences in
seven files: the declaration (`hkdf.h:13`), the definition (`hkdf.c:8`), eight
calls (`hkdf.c:44`, `hkdf.c:62`, `keysched.c:23`, `proof/hkdf_harness.c:28`,
`test/diff_hash.h:39`, `test/unit_test.c:88`, `:90`, `:95`), one harness comment
(`proof/hkdf_harness.c:1`) and one measured bench row
(`bench/results-device.csv:5`, which `bench/device-ram.sh:252` regenerates and
nobody edits by hand). `srv_cookie.c`'s MAC is the ninth call once the server
lands. `hkdf.h:1` changes with them: "HMAC-SHA-256 (RFC 2104)" becomes "HMAC
(RFC 2104) over SHA-256 or SHA-384".

The new name is `hmac` rather than `hkdf_hmac` or `ch_hmac`, because
`spec/lean/Spec/Hkdf.lean:24` already defines `hmac`, `spec/lean/CONTRACT.md:50` already
writes `Spec.Hkdf.hmac`, and the differential driver's line op is already the
literal string `hmac` (`test/diff_hash.h:47` and `spec/lean/Main.lean:120`). So the
C, the spec and the driver share one name, which is what `CLAUDE.md:166-169`
asks for, and any other candidate would invent a second name for a thing that
already has one. A bare name cannot collide in firmware, because the packaged
object localizes every symbol outside `PUBLIC` (`Makefile:360-363`), which
`make lint-runtime-symbols` and `lib-check` (`Makefile:517-523`) hold. So the
three surfaces `CLAUDE.md:125-140` requires are the C (`hkdf.[ch]`,
`keysched.c`), the tests (`test/unit_test.c`, `test/diff_hash.h`) and the CBMC
harness (`proof/hkdf_harness.c`, whose first line names the function in its
"Proves:" sentence). A reader who looks for the fourth will not find it.

**The transcript context changes type, not just length.** `session.h:107`
declares `sha256 transcript;`. A hash-agile session holds either context. The
measurement below assumes a union of `sha256` and `sha512` plus one byte
recording which is live.

**Two internal buffers grow, both declared as literals.** `hkdf.c:52` declares
`uint8_t msg[SHA256_LEN + 64 + 1]`, 97 bytes, which becomes 113.
`hkdf.c:79` declares `uint8_t info[2 + 1 + 6 + HKDF_LABEL_MAX + 1 + SHA256_LEN]`,
54 bytes, which becomes 70. Both are derived from the declarations.

**The HMAC is the concentrated cost, and it is larger than a block size.**
`hmac_sha256` runs from `hkdf.c:8` to `hkdf.c:35`. In those 28 lines it holds
nine hash call sites (`hkdf.c:12`, `:21`, `:22`, `:23`, `:24`, `:28`, `:29`,
`:30`, `:31`), seven reads of `SHA256_BLOCK` (`:10`, `:11`, `:16`, `:18`,
`:22`, `:25`, `:29`) and one context declaration, `sha256 s;` at `:17`. Every
count is measured: `grep -c 'sha256_[a-z]*(' hkdf.c` returns **9** and
`grep -c 'SHA256_BLOCK' hkdf.c` returns **7**. Each call site selects a hash,
each block-size read becomes the live block size, and the context becomes a
union of `sha256` and `sha512`.

Across the whole file `SHA256_LEN` appears **21** times on **18** lines
(`grep -c` returns 18 and `grep -o | wc -l` returns 21), and the three groups
take three different edits: seven array bounds in signatures become
`HKDF_HASH_MAX`, eight runtime lengths become `hash_len`, and six buffer
sizings take the larger hash.

**Written as one function, the hash-agile HMAC fails `make lint-tidy`.**
Measured: the one-function form reports `function 'hmac' has cognitive
complexity of 24 (threshold 15)
[readability-function-cognitive-complexity,-warnings-as-errors]` under
clang-tidy 23.1.1 with the tree's own `.clang-tidy`, whose
`readability-function-cognitive-complexity.Threshold` is `'15'`
(`.clang-tidy:98`). So the function has to be split. The shape that passes is
one HMAC body per hash behind a two-arm dispatcher, and the three numbers that
decide it were measured on the host, arm64, at the tree's `CFLAGS`:

| shape | stack frame, `-O2` | `__TEXT,__text`, `-Os` | clang-tidy |
|---|---|---|---|
| today, `hmac_sha256` (`hkdf.c:8-35`) | 304 | 388 | clean |
| hash-agile, one body, nine `if`s | 544 | 548 | **complexity 24** |
| hash-agile, one body per hash plus a dispatcher | 528 | 672 | clean |

Frames from `-fstack-usage`, sizes from `size -m` on a `-Os` object compiled
with `-I. -D_DEFAULT_SOURCE -DCH_RAND_EXTERN`. So the split costs 284 bytes of
flash over today's HMAC and 224 bytes of stack, and it is the shape the record
takes. Open question eleven asks whether Camilo accepts it, because the
one-function form is ruled out by a measurement rather than by taste.

`make lint-stack` turns a frame miss into a compile failure (`Makefile:1500`
compiles at `-Wframe-larger-than=$(STACK_BUDGET)`), and the numbers above are
what it will measure.

### The session struct, measured both ways

Measured, not estimated. `scratchpad/repair/base.c` includes the tree's own
`session.h` and prints `sizeof`; `scratchpad/repair/agile/session.h` is that
header with the three secrets at `SHA384_LEN`, the transcript as a union of
`sha256` and `sha512`, and one `hash_len` byte, and
`scratchpad/repair/agile/agile.c` prints the same values against it. Both were
compiled with `cc -Os -std=c11 -I. -DCH_RAND_EXTERN`, and the same two headers
were compiled for rv32 with
`/opt/homebrew/opt/llvm/bin/clang -target riscv32-unknown-elf -march=rv32ic
-mabi=ilp32 -Os -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN` and read with
`llvm-nm --print-size --defined-only`.

| `sizeof(ch_tls)` | arm64 | rv32 |
|---|---|---|
| today, SHA-256 only | 1144 | 1072 |
| hash-agile | 1296 | 1224 |
| difference | +152 | +152 |

The +152 breaks down exactly, and the breakdown is measured rather than
argued. A third build with the `hash_len` byte removed
(`scratchpad/repair/agile2/session.h`) prints `sizeof(ch_tls)=1288`. So the
three 16-byte secret extensions are 48 bytes, the transcript union is
`sizeof(sha512) - sizeof(sha256)` = 208 - 112 = 96 bytes, and the selector byte
with its padding is the remaining 8.

**The largest frame cost is not in `ch_tls`.** Six of the ten fields that
change type live in `handshake_state` (`handshake_record.h:48-53`), and
`handshake_state` is a stack local: `handshake.c:373` declares it inside
`ch_handshake` and `handshake.c:390` wipes it. Measured with only those six
declarations widened to `HKDF_HASH_MAX` and nothing else changed,
`sizeof(handshake_state)` goes **448 to 544** on arm64 and **436 to 532** on
rv32, and `ch_handshake`'s own frame goes **688 to 784** (arm64, Apple clang
21.0.0, `-O2`, `-fstack-usage`), 608 to 704 (rv32, Homebrew clang 23.1.1) and
712 to 808 (Cortex-M3, arm-none-eabi-gcc 16.2.0). The same +96 on all three
compilers. The other builds move by the same 96: a CA mode 1088 to 1184,
`TRUST=webpki` 1216 to 1312, `KEX=pq` 3152 to 3248.

`make lint-stack` still passes everywhere, and saying so is part of the
measurement. The smallest `STACK_BUDGET` is 2560 (`Makefile:9`), and the
tallest library frame in the default build is `rsa_mont.c:127 rsa_vp1` at
2400, which the hash change does not touch. `ch_handshake` at 784 is the
fourth tallest.

The client's 1144 is the number `README.md:128` publishes and
`make lint-bench-numbers` holds against `bench/results-sram.csv`. If the
hash-agile signatures land unconditionally, that row moves by 152 bytes on both
targets for a client that will never select SHA-384. If they land inside
`#ifdef CH_ROLE_SERVER`, the row does not move and `hkdf.[ch]`, `keysched.[ch]`,
`record.[ch]` and `session.h` each carry a role arm. Open question one asks
which, because it is a `CLAUDE.md` question rather than a size question.

### The flash cost of having SHA-384 at all

`sha512.c` and `sha512_compress.c` are today packaged only by a `TRUST=webpki`
object. Measured with `scratchpad/repair/objsize.sh`, which runs
`cc -c -Os -std=c11 -I. -DCH_RAND_EXTERN` and reads `size -m`:

| object | `__TEXT,__text` | `__TEXT,__const` |
|---|---|---|
| `sha256.c` | 1,288 | 256 |
| `sha512.c` | 1,160 | 0 |
| `sha512_compress.c` | 480 | 640 |
| `hkdf.c` | 1,188 | 32 |
| `keysched.c` | 744 | 64 |
| `record.c` | 1,016 | 0 |

A server object that can run SHA-384 adds 2,280 bytes of text and const over a
SHA-256-only object (1,160 + 480 + 640, derived from the measured rows). For
comparison, the same script measures this tree's ChaCha20-Poly1305 at 980 +
2,512 + 680 = 4,172 bytes of text.

### `sha512.c` is already the right shape, and its header says the wrong thing

The C side needs no new hash. `sha512.h` declares a streaming SHA-384 in the
same shape `sha256.h` has: `sha384_init` (`:32`), `sha512_update` (`:33`),
`sha384_final` (`:41`) and `sha384_of` (`:44`), over one context type that
serves both hashes. `handshake_auth.c:47-55` already runs it under
`CH_TRUST_WEBPKI` for a P-384 CertificateVerify, so the call shape is exercised
today.

Two sentences in that header become false the day a server selects
`TLS_AES_256_GCM_SHA384`:

    sha512.h:8     // Only a TRUST=webpki object packages this file, for the
    sha512.h:13    // key schedule and the transcript stay on SHA-256.

Both are rewritten in the commit that lands the hash-agile schedule. A third
consequence follows from `Makefile:2034`, which lists `sha512.c` and
`sha512_compress.c` in `WIDEMUL_PUBLIC`, the list whose reason
(`Makefile:1950-1952`) is that every operand is a byte the peer sent in the
clear. A SHA-384 key schedule hashes secrets, so both files move to
`WIDEMUL_CEILING` (`Makefile:2018`) and need a measured widening-multiply
ceiling per compiler.

That move alone buys no branch count. `Makefile:2335` runs the branch count
only for files named in `BRANCH_SRCS`, so both files join that list too, beside
the `sha256.c` already on it (`Makefile:2241`), and each takes eight measured
`BRANCH_CEILING` entries. "The codegen partition" states the membership and the
two rv32imac starting points, 23 and 4; "Bounds that need measuring" carries
both rows.

### What it costs the proofs

Eight CBMC harnesses stand over the key schedule and the secrets it produces:
`keysched_harness.c`, `hkdf_harness.c`, `hkdf_expand_harness.c`,
`hkdf_expand_label_harness.c`, `record_harness.c`, `handshake_harness.c`,
`handshake_post_harness.c` and `handshake_record_harness.c`. Their launch
lines carry the cost, and two of them say so in `proof/run.sh` itself:

    proof/run.sh:566    # keysched: 13 s under this script's own flags. Extract and Expand-Label sequencing
    proof/run.sh:567    # over 32-byte secrets; sha256 is harness.h's stub, since the schedule's
    proof/run.sh:568    # arithmetic is length handling rather than compression.

    proof/run.sh:503    # record: measured 830 s / 3.0 GB (kissat) since the direction-domain
    proof/run.sh:504    # and in-place-open shapes joined the formula — under the fast pool's

and `proof/run.sh:505` names that pool's slowest harness at 1,034 s.

The keysched harness is scoped to 32-byte secrets in its own comment, so hash
agility does not extend it; it either gets a second launch line at 48 bytes or
a nondet `hash_len` that doubles its domain. The record harness is the one to
watch: at 830 s and 3.0 GB it already sits 204 s under the slowest harness,
and it gains both a longer secret and a per-suite branch. Whether it still
converges in the pool is **unmeasured**, and `docs/proofs.md` forbids
committing a launch line nobody has seen converge, so it gets measured with
`/usr/bin/time -v` under `run.sh`'s exact flags before the change lands.
`proof/harness.h:55-64` stubs `sha256_final` and `sha256_of`; it gains the two
SHA-384 stubs beside them.

### What it costs the Lean specs

`spec/lean/Spec/Hkdf.lean` fixes both hash parameters as constants:

    spec/lean/Spec/Hkdf.lean:13    def blockSize : Nat := 64
    spec/lean/Spec/Hkdf.lean:16    def hashLen : Nat := 32

`hashLen` appears 16 times in that file and 22 more sites write the literal
`32`. Six definitions take the two constants — `hmac` (`:24`), `extract`
(`:34`), `expand` (`:42`), `expandLabel` (`:62`), `deriveSecret` (`:73`) and
`schedule` (`:93`) — and five theorem statements assert a size that is no
longer fixed: `hmac_size` (`:111`), the fold invariant inside `expand_size`
(`:123`), `expandLabel_size` (`:132`), `schedule_eq` (`:210`) and
`schedule_sizes` (`:235`). `spec/lean/Spec/Record.lean`'s `nextSecret_size` asserts
the same 32.

The hash itself is already there and already proved.
`spec/lean/Spec/Sha512.lean:141` defines `sha384` and `:171` proves
`sha384_size : (sha384 msg).size = 48`. What does not exist is an HMAC and an
HKDF parameterized over a hash. `spec/lean/CONTRACT.md`'s "Writing proofs here"
section governs the rewrite, including the second pass that shrinks a green
proof's script with the statement frozen; a `Spec/Hkdf.lean` whose statements
carry a `hashLen` hypothesis they do not need is the failure to avoid.

### Where SHA-384 does not apply

Four things keep SHA-256 whatever the suite, and saying so keeps the change
bounded.

The HelloRetryRequest cookie MAC stays HMAC-SHA-256. It is the server's own
integrity protection over its own bytes, not a protocol value, and
`rfc9846.txt:1779-1783` names no algorithm. The RFC 6979 nonce derivation stays
HMAC-SHA-256 for the same reason. And the record layer's own constants do not
move: `AEAD_KEY` is 32, `AEAD_NONCE` is 12 and `AEAD_TAG` is 16, all measured,
so `REC_OVERHEAD` stays 22 and the nonce construction of
`rfc9846.txt:3670-3679` is one rule for all three suites.

The fourth is the CertificateVerify signature. It is the one an implementer
gets wrong, and getting it wrong breaks interoperability rather than showing up
as a compile error, so it has its own subsection.

#### The CertificateVerify signature uses two different hashes

Two hashes meet in one message, and each is named by a different negotiated
parameter.

The **transcript hash** goes *inside* the signed content. Its length is the
cipher suite's hash length, so it is 32 bytes under
`TLS_CHACHA20_POLY1305_SHA256` and `TLS_AES_128_GCM_SHA256` and 48 bytes under
`TLS_AES_256_GCM_SHA384`. `rfc9846.txt:3031-3035` says so: "The content that is
covered under the signature is the hash output as described in Section 4.1,
namely: Transcript-Hash(Handshake Context, Certificate)".

The **hash that covers that content**, and whose output the signature equation
consumes, is named by the SignatureScheme in the CertificateVerify message, not
by the cipher suite. `rfc9846.txt:3037` says the signature "is then computed
over the concatenation of" the 64 spaces, the context string, the zero byte and
that content, and `rfc9846.txt:1888-1891` fixes which hash performs that
computation for ECDSA: "the corresponding hash algorithm as defined in [SHS]",
where "corresponding" means the one the scheme's name carries.
`rfc9846.txt:1894-1898` says the same for RSASSA-PSS RSAE, and adds that MGF1
and the salt length follow that same hash.

Both schemes this server offers name SHA-256:

| Scheme offered | Hash that covers the signed content | Transcript hash inside that content |
|---|---|---|
| `ecdsa_secp256r1_sha256` (0x0403) | SHA-256, 32 bytes out | 32 or 48 bytes, from the suite |
| `rsa_pss_rsae_sha256` (0x0804) | SHA-256, 32 bytes out, and MGF1-SHA256 with a 32-byte salt | 32 or 48 bytes, from the suite |

So both signers take a 32-byte `msg_hash` in every build of this design, and
neither takes a `hash_len`. Only the length the builder feeds into the hash
changes with the suite.

The tree already writes this rule correctly on the verify side.
`handshake_auth.c:42` is
`static void hash_signed_content(uint16_t scheme, const uint8_t hash[SHA256_LEN], uint8_t out[SHA384_LEN])`,
and it branches on `scheme == SIGALG_ECDSA_P384_SHA384`
(`handshake_auth.c:46`), never on a suite. Its comment at
`handshake_auth.c:36-41` states the rule in one sentence. Both verify entry
points agree: `p256.h:16` is
`int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], ...)`
and `rsa.h:34` is
`int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], ...)`.

Getting this wrong produces a CertificateVerify no conformant client verifies,
under exactly the suite the widened scope exists to serve. That is why the rule
is stated here once and cited from both signer sketches.

## The three plain statements

These come next because every later section assumes them.

### Two families of secret scalar enter this tree

Nothing in chapulin has ever performed a private-key operation outside the
x25519 ladder. Both elliptic-curve headers say so in their first sentence, and
so does the RSA header:

    p256.h:2    // signing, no scalar secrets: every input — the peer's public key, the
    rsa.h:4     // — is public, so the arithmetic is deliberately variable time and

The Makefile says it as a build rule. `WIDEMUL_PUBLIC` is the list of sources
whose operands are all public, so no constant-time codegen count measures them,
and its comment gives the reason:

    Makefile:1955    transcript hash and a signature, and the client never signs, so
    Makefile:1956    there is no signing entry point to add a secret to.

A server signs the CertificateVerify, so that sentence becomes false. The
widened scope forces it in both algorithm families, which is the change from
the first draft of this record: §9.1 names `rsa_pss_rsae_sha256` as
mandatory-to-support for CertificateVerify, so a server that can sign only with
ECDSA refuses a conformant client that offers only RSA-PSS. The scope therefore
carries four secret scalars, not one: the ephemeral P-256 key-exchange scalar,
the ephemeral x25519 scalar the tree already has, the long-term ECDSA key and
the long-term RSA private exponent. The two long-term values are the serious
ones, because a leak of either is permanent.

The design puts every value computed from a long-term key in one file per
family, `p256_sign.c` and `rsa_sign.c`, named so an auditor finds them without
reading the build. Both are new `WIDEMUL_CEILING` entries with measured
ceilings.

### AES-GCM becomes a cipher suite carrying user data, in two key sizes

`rfc9846.txt:4540-4541` makes `TLS_AES_128_GCM_SHA256` a MUST-implement and
`:4542` makes `TLS_AES_256_GCM_SHA384` a SHOULD. The widened scope takes both.
AES-128 uses 11 round keys and AES-256 uses 15 (FIPS 197, Nr = 10 and 14), so
the round-key array is 176 bytes for one and 240 for the other;
`quic_aes.h:26` fixes `AES_ROUND_KEYS 11` today and that constant becomes the
larger one, or the type carries both.

Today `CLAUDE.md:104` reads:

    CLAUDE.md:104    that way; AES never enters this codebase precisely to avoid tables.

That sentence is still true of the landed code. `grep -c 'INV-26'
docs/invariants.md` returns **0**: the invariant that landed code already cites
by name does not exist in the file, while
`grep -rn 'INV-26' --include='*.c' --include='*.h' --include='*.md' --include='*.yml' --include='Makefile' . | wc -l`
returns **22**. INV-26 arrives with the unlanded patch at
`scratchpad/crypto/gcm.patch`, which writes it twice under one number, as "AES
sees three public keys and no other" (`gcm.patch:335`) and "...and no others"
(`gcm.patch:397`).

A server's AES key is `hkdf_expand_label(secret, "key", ...)` over a traffic
secret (`record.c:7`). So INV-26's premise — every AES key in this tree is
public, therefore a lookup table leaks nothing — does not transfer, and no
fourth key source repairs it. **INV-26 is withdrawn and replaced, not
amended.** Because it was never written, the replacement is a first landing
rather than an edit, and "What changes in `docs/invariants.md`" says so.

The cost is measurable and it is stated here rather than in a footnote. The
patch's AES is table-driven; its own text says so, and the table is visible in
the object file. Measured by compiling the patch's bodies with
`cc -c -Os -std=c11 -I. -DCH_TRANSPORT_QUIC -DCH_RAND_EXTERN` and reading
`size -m`:

| object | `__TEXT,__text` | `__TEXT,__const` |
|---|---|---|
| the patch's AES body | 1,312 | 292 |
| the patch's GCM body | 1,548 | 16 |

Those 292 const bytes are the 256-byte FIPS 197 S-box plus the 20-byte QUIC
initial salt and the 16-byte Retry key the same file declares
(256 + 20 + 16 = 292, derived from the declarations at `gcm.patch:962`, `:968`
and `:973`). The table a server must not have is 256 of them. A constant-time
AES is larger than the table version by an amount that is **unmeasured**, on
every target, and AES-256's key schedule is a second unmeasured increment on
top.

### What the widened scope forces, and what it cannot cover

The scope says the server serves any strictly conformant client. No finite
server meets that sentence literally, and the honest bound is worth stating
before anyone writes code against the looser reading.

§9.1 tells a client what it must *support*. It never tells a client what to
*offer*. I looked for a line requiring a client to offer any particular scheme
and found none: §4.3.3 at `rfc9846.txt:1812-1816` requires only that a client
wanting certificate authentication send the `signature_algorithms` extension,
and says nothing about its contents. So for every parameter the client controls,
a conformant client may offer a set this server does not hold, and the RFC's own
answer is `handshake_failure` (`rfc9846.txt:1181-1184`), which is conformant.

The server therefore holds the whole §9.1 mandatory-to-implement set plus the
two SHOULDs that sit beside it, and that is the claim this document makes:
**every client whose offer intersects the §9.1 set finds a parameter here.**
Three residuals remain, and each is a client this server refuses:

- **Cipher suites.** The server holds all three of `rfc9846.txt:4540-4543`.
  Table 5 at `rfc9846.txt:6024-6026` also registers `TLS_AES_128_CCM_SHA256`
  and `TLS_AES_128_CCM_8_SHA256`. A client offering only a CCM suite is
  conformant and gets `handshake_failure`. Open question two asks whether
  Camilo accepts that.
- **Groups.** `rfc9846.txt:4548-4550` makes secp256r1 a MUST and X25519 a
  SHOULD, and the server holds both. A client offering only secp384r1, x448, or
  a finite-field group gets `handshake_failure`.
- **Signature schemes.** `rfc9846.txt:4545-4547` reads in full:

        4545:   *  A TLS-compliant application MUST support digital signatures with
        4546:      rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
        4547:      CertificateVerify and certificates), and ecdsa_secp256r1_sha256.

  The parenthetical on `rsa_pss_rsae_sha256` is the load-bearing one: it names
  CertificateVerify. So a server holding one key cannot meet §9.1, whatever the
  key is, and this is a shortfall in the code rather than an accident of
  provisioning. The design answers it by holding two identities, one ECDSA
  P-256 and one RSA. A client offering only `ecdsa_secp384r1_sha384` or
  `ed25519` still gets `handshake_failure`. §4.5.2 at `rfc9846.txt:3078-3081`
  requires the server's CertificateVerify algorithm to be one the client
  offered, and `rfc9846.txt:3088-3089` requires it to be compatible with the
  key in the server's own end-entity certificate, so the two rules together are
  what force two keys rather than one.

Open question three asks how many identities a deployment provisions, because a
device with one certificate is a real deployment and the build must say what it
serves.

## What the role asks of this tree

Measured against `bed7456`. Each row names what exists today and what the role
needs instead.

| What a server needs | What exists today |
|---|---|
| A ClientHello parser | None. `handshake_parser.h` declares four parsers and every one reads a server-to-client message: `hsp_parse_server_hello` (`:53`), `hsp_parse_encrypted_exts` (`:119`), `hsp_parse_certificate` (`:134`), `hsp_parse_certificate_verify` (`:149`). |
| Seven message builders | One. `hs_build_client_hello` (`handshake_message.c:29`). The message type codes, the alert descriptions and the extension codes are already defined (`handshake_message.h:16-37`, `:113-145`). |
| Three cipher suites | One, written as a literal: `handshake_message.c:44` writes `SUITE_CHACHA20_POLY1305_SHA256`, defined at `handshake_message.h:40`. AES exists as fail-closed stubs; `quic_gcm.c:1` reads "Stub only." |
| A SHA-384 key schedule | None. `keysched.h:2` says "specialized to one PSK and SHA-256". The hash itself exists: `sha512.h:32`, `:41`, `:44`. |
| P-256 ECDH with a secret scalar | None. `p256.h:16` declares `p256_ecdsa_verify` and nothing else; `nm -gU p256.o` after `cc -c -Os -std=c11 -I. -DCH_RAND_EXTERN p256.c` prints exactly `_p256_ecdsa_verify`. |
| Two signing operations | None. See "Two families of secret scalar enter this tree". |
| `protocol_version` (70) | Absent. `grep -c '^#define ALERT_' handshake_message.h` returns **18** and `grep -c 'ALERT_PROTOCOL_VERSION' handshake_message.h` returns **0**. `rfc9846.txt:1253` makes alert 70 a MUST for a server. |
| The `cookie` extension, written | Half. The client parses and echoes one (`parse_cookie`, `handshake_parser.c:63`); minting one under a MAC does not exist. `rfc9846.txt:4560` makes the extension mandatory to implement. |
| The `server_name` extension, read | None. The client writes SNI (`handshake_message.c:51-57`); no code reads a `ServerNameList`. `rfc9846.txt:4571` makes it mandatory to implement. |
| A `change_cipher_spec` record, sent | None. `handshake_message.c:42` writes an empty `legacy_session_id` with the comment "no middlebox compat needed", so the client never opts in and never owes the record. A conformant client may send a non-empty one, and then `rfc9846.txt:6401-6403` makes the dummy record a MUST. |
| Room for a full ClientHello | `CH_MIN_RXBUF` is 512 (`cfg.h:138`), and `handshake_record.c:119` refuses any handshake message over 0x4000. |

Two premises from the surveys are worth carrying forward because they change
what the first commit does. `quic_aes.[ch]` and `quic_gcm.[ch]` are already
tracked files at `bed7456`, so the file layout and the names are already
chosen; the patch adds their bodies. And INV-26 is cited by landed code and
does not exist, which is a defect independent of this work and cheaper to fix
before the patch lands than after.

## The profile it offers

| Parameter | Values, in the server's preference order | Why |
|---|---|---|
| Version | TLS 1.3 (0x0304) only | §4.3.1, `rfc9846.txt:1734-1738`, selects from `supported_versions` alone. |
| Cipher suite | `TLS_CHACHA20_POLY1305_SHA256` (0x1303), then `TLS_AES_128_GCM_SHA256` (0x1301), then `TLS_AES_256_GCM_SHA384` (0x1302) | All three of `rfc9846.txt:4540-4543`. ChaCha is preferred where the client offers it, because it is the code this tree has proved, differential-tested and kept free of tables, and because it keeps the handshake on SHA-256. AES-128-GCM comes before AES-256-GCM for the second reason: its schedule is SHA-256, the hash every handshake proof covers (`docs/decisions.md` entry 58). |
| Hash | SHA-256 with 0x1303 and 0x1301, SHA-384 with 0x1302 | `rfc9846.txt:4055-4056` binds the hash to the suite. The section above states the cost. |
| Group | X25519MLKEM768 (0x11ec), then x25519 (0x001d) | The hybrid first, for every client that lists it ("Key exchange" below, `docs/decisions.md` entry 54). X25519 is the §9.1 SHOULD at `rfc9846.txt:4549-4550`. secp256r1, the §9.1 MUST at `:4548-4549`, is not held, for the reason `srv_parser.h` gives at `SRV_GROUP_X25519`. |
| Signature scheme | `ecdsa_secp256r1_sha256` (0x0403), then `rsa_pss_rsae_sha256` (0x0804) | Both are §9.1 CertificateVerify obligations at `rfc9846.txt:4545-4547`. The selected scheme picks which provisioned identity signs. |
| Key exchange mode | `psk_dhe_ke` when a PSK is selected, certificate authentication otherwise | `rfc9846.txt:1150-1152` requires selecting a mode the client listed. |
| ALPN | the caller's list, or none | The server cannot know which protocol the endpoint speaks. |

The preference order is the default, and `ch_srv_cfg.cipher_suites`
replaces it: a host with an AES accelerator names the order it wants, and a
list may leave a suite out (`docs/decisions.md` entry 58).

Runtime selection is unavoidable here and it is worth saying why. A build axis
cannot carry the suite: a conformant client may offer AES-128-GCM alone, so the
same binary must hold all three and pick per connection. The same argument
carries the two groups and the two signature schemes. Every one of those
branches reads a value the peer sent in the clear, so none of them is a
constant-time defect; INV-16 requires each branch to name the public value it
reads at the call site.

### What the server refuses

Each row names an RFC obligation. The alert column separates three things the
second round of this record ran together. Where the RFC names the alert beside
the obligation, the alert line is the obligation line. Where §6.2's description
of an alert names the failure itself, the alert line cites that description.
Where the RFC states the obligation and neither line names an alert, the alert
is this design's choice under §6 and the alert line cites §6. A message that
cannot be parsed against the syntax is `decode_error`
(`rfc9846.txt:3785-3788`) and a message that parses but is semantically invalid
is `illegal_parameter` (`rfc9846.txt:3789-3791`, with the description at
`:3947`).

| Condition | Alert | Obligation | Alert source |
|---|---|---|---|
| `legacy_version` is not 0x0303 | none: the field is read and not judged. §4.2.2 tells a server that sees `supported_versions` to ignore it (1306-1313), and a hello without `supported_versions` takes the row below | 1306-1313 | — |
| `legacy_compression_methods` is not exactly one zero byte | `illegal_parameter` (47) | 1284-1288 | 1284-1288 |
| No bytes after the compression list, or no `supported_versions` carrying 0x0304 | `protocol_version` (70) | 1306-1313, 1742-1744 | design's choice; 3972-3973 |
| No `pre_shared_key`, and `signature_algorithms` or `supported_groups` missing | `missing_extension` (109) | 4595-4605 | 4595-4605 |
| `supported_groups` without `key_share`, or the reverse | `missing_extension` (109) | 4599-4605 | 4599-4605 |
| Certificate authentication with no `signature_algorithms` | `missing_extension` (109) | 1812-1816 | 1812-1816 |
| More than `SRV_CLIENT_HELLO_EXT_MAX` (128) extensions in one ClientHello, checked before every row below on the extensions themselves (`docs/decisions.md` 59) | `illegal_parameter` (47) | none; 1237 bounds the block's bytes, not its count | design's choice; 3789-3791 |
| A second extension of one type | `illegal_parameter` (47) | 1673-1674 | design's choice; 3789-3791 |
| A recognized extension in a message the §4.3 table forbids it in | `illegal_parameter` (47) | 1593-1596 | 1593-1596 |
| Bytes left after an extension body the server implements | `decode_error` (50) | 1561-1565 | 1561-1565 |
| `pre_shared_key` is not the last extension | `illegal_parameter` (47) | 2564-2567 | 2564-2567 |
| `pre_shared_key` without `psk_key_exchange_modes` | `illegal_parameter` (47) | 2306-2307 | design's choice; 3789-3791 |
| A wrong or absent binder for the selected PSK | `decrypt_error` (51) | 2543 | 3968-3970 |
| A P-256 share that is not 65 bytes, or whose `legacy_form` is not 4 | `illegal_parameter` (47) | 2264-2275 | design's choice; 3789-3791 |
| A P-256 point at infinity, a coordinate at or above p, or a point off the curve | `illegal_parameter` (47) | 2277-2286 | design's choice; 3789-3791 |
| No overlap in groups, suites or signature schemes | `handshake_failure` (40) | 1145-1148, 1181-1184 | 1181-1184 |
| A ClientHello after TLS 1.3 was negotiated | `unexpected_message` (10) | 1215-1217 | 1215-1217 |
| `early_data` in the retried ClientHello | `illegal_parameter` (47) | 2397-2398 | design's choice; 3789-3791 |
| A retried ClientHello that changed a field §4.2.2 freezes; the order of its extensions is not one of them (1669-1670, `docs/decisions.md` 59) | `illegal_parameter` (47) | 1191-1213 | design's choice; 3789-3791 |
| A `change_cipher_spec` record whose body is not the single byte 0x01, or one that arrives protected | `unexpected_message` (10) | 3433-3435 | 3433-3435 |
| A record content type the document does not define | `unexpected_message` (10) | 3441-3444 | 3441-3444 |
| A wrong client Finished | `decrypt_error` (51) | 3115-3117 | 3115-3117 |
| Any deprotection failure | `bad_record_mac` (20) | 3641-3642 | 3641-3642 |
| A ciphertext over 2^14 + 256, or a plaintext over 2^14 | `record_overflow` (22) | 3595-3598, 3644-3649 | 3595-3598 |
| A `request_update` byte other than 0 or 1 | `illegal_parameter` (47) | 3362-3365 | 3362-3365 |
| A KeyUpdate before the client's Finished | `unexpected_message` (10) | 3346-3349 | 3346-3349 |

Eight rows say "design's choice" and each one is defensible on its own line.
`rfc9846.txt:1742-1744` reads "Servers MUST be prepared to receive ClientHellos
that include this extension but do not include 0x0304 in the list of versions",
which is an obligation with no alert, and `rfc9846.txt:3972-3973` describes
`protocol_version` as "recognized but not supported", which is the case.
`rfc9846.txt:2306-2307` reads "servers MUST abort the handshake" with no
description. The extension count row has no obligation behind it at all.
`rfc9846.txt:1237` bounds the extension block's bytes and not its count, so
a hello of 129 extensions parses under the syntax, which rules out
`decode_error` (`rfc9846.txt:3785-3788`), and the server refuses a value it
will not process, which is `illegal_parameter`'s class. The bound exists
because the duplicate check and the frozen digest each cost the square of
the count, and `docs/decisions.md` entry 59 gives the evidence for 128 and
the RFC rule the bound departs from. `rfc9846.txt:2397-2398` reads "A client
MUST NOT include the 'early_data' extension in its followup ClientHello",
addressed to the client and naming no alert. `rfc9846.txt:1673-1674` reads
"There MUST NOT be more than one extension of the same type in a given
extension block" and names no alert.
`rfc9846.txt:2264-2275` is the `UncompressedPointRepresentation` struct and its
prose, and `rfc9846.txt:2277-2286` says only that "peers MUST validate each
other's public value Q"; neither names an alert, and `rfc9846.txt:3790` gives
"a DHE share of p - 1" as its own example of the class `illegal_parameter`
covers, which is the same class of fault. `rfc9846.txt:1191-1213` lists what a
client may change in a retried ClientHello and names no alert for a server that
sees something else; the named alerts nearby (`:1467-1472`, `:1489-1491`) are
all addressed to the client.

One row is neither the obligation's own alert nor a design's choice, and it is
the third clause of the rule above. `rfc9846.txt:2543` reads "the server MUST
abort the handshake" and names no alert, but §6.2's description does:
`rfc9846.txt:3968-3970` defines `decrypt_error` as covering "being unable to
correctly verify a signature or validate a Finished message or a PSK binder".
The failure is named in the alert's own description, so the alert line cites
that description.

One reading the `supported_groups`/`key_share` row must not invite: an empty
`KeyShare.client_shares` list is a present extension, not a missing one.
`rfc9846.txt:4600-4601` reads "An empty KeyShare.client_shares list is
permitted." A parser that treats it as absent answers `missing_extension` to a
strictly conformant client. The row covers one extension present and the other
absent, and nothing else. "The state machine" states what an empty list
produces instead, which is a HelloRetryRequest.

`insufficient_security` (71) is not added. `rfc9846.txt:1147` and `:1183` both
permit `handshake_failure` in its place, and `ALERT_HANDSHAKE_FAILURE 40`
already exists at `handshake_message.h:119`.

### What the server ignores

The RFC draws this line sharply and the ClientHello parser inverts the client's
habit at exactly one point. §4.2.2 at `rfc9846.txt:1299` reads "Servers MUST
ignore unrecognized extensions", and §9.3 at `rfc9846.txt:4636-4637` restates it
as a protocol invariant: a server "MUST correctly ignore all unrecognized
cipher suites, extensions, and other parameters." A ClientHello carrying GREASE
code points must still negotiate.

The client does the opposite, deliberately. `server_hello_ext_bit` returns 0 for
anything it does not know:

    handshake_parser.c:29        return 0; // ServerHello may carry nothing else

and its caller refuses on that zero:

    handshake_parser.c:90        if (bit == 0) {
    handshake_parser.c:91            return CH_EPROTO;

This is the sharpest behavioral inversion in the whole role. The ClientHello
parser's default arm skips by the extension's length. It gets its own named
predicate, its own boundary test, and its own violation mutant, because a
reviewer who reads one line of this parser will read that one.

An unknown extension still counts toward `SRV_CLIENT_HELLO_EXT_MAX`, 128. A
hello whose unknown extensions carry it past that count is refused with
`illegal_parameter` rather than ignored. That departs from
`rfc9846.txt:1299` and `rfc9846.txt:4636-4637` for a hello no client sends:
a browser's carries about 20 extensions. `docs/decisions.md` entry 59 gives
the evidence and the cost the bound removes.

### What the server declines, conformantly

- **Client certificates.** It sends no CertificateRequest. `rfc9846.txt:2675-2676`
  makes the request a MAY. This removes the WAIT_CERT and WAIT_CV states of
  Appendix A.2 (`rfc9846.txt:5535-5540`), both client-message parsers, the
  `oid_filters` and `certificate_authorities` extensions, and every certificate
  verdict alert. `README.md:834` already lists client certificates as a
  non-goal, and the role keeps them there, stated as a refusal rather than an
  omission.
- **`signature_algorithms_cert`, and the record's second round claimed more
  than the RFC allows.** `rfc9846.txt:4564-4565` makes the extension mandatory
  to implement, and it is the §9.2 bullet between `signature_algorithms` and
  `supported_groups`. It constrains signatures inside certificates, which this
  server never verifies — but it does send them, and it holds two identities
  (`ch_identity ecdsa_p256` and `ch_identity rsa_pss`), each with its own
  chain, so it is a sender that selects. `rfc9846.txt:2948-2950` states the rule
  for exactly that: "All certificates provided by the sender MUST be signed by a
  signature algorithm advertised by the peer, if it is able to provide such a
  chain", and `rfc9846.txt:2971-2973` says a sender with multiple certificates
  chooses among them on those criteria. **This server does not meet that MUST.**
  It selects on the CertificateVerify scheme alone, out of `signature_algorithms`,
  and reads the chain signatures of neither chain, because it parses no X.509.
  The permission it takes is the SHOULD at `rfc9846.txt:2954-2960`: a server
  that cannot produce a conforming chain "SHOULD continue the handshake by
  sending a certificate chain of its choice that may include algorithms that are
  not known to be supported by the client." So the cost is not zero, and it is
  not code: a client whose `signature_algorithms_cert` excludes the chain
  signatures of the selected identity gets a chain it will reject, and aborts
  with `unsupported_certificate` or another certificate alert
  (`rfc9846.txt:2965-2969`). That is the client's conformant answer, not a
  server fault. The fallback chain must not use SHA-1
  (`rfc9846.txt:2958-2960`), which is a constraint on what an operator
  provisions and which `ch_srv_check` cannot enforce, because it reads no chain
  bytes. The ClientHello parser's skip-unknown arm is still the handling, and
  `rfc9846.txt:1809-1811` still makes the extension's absence harmless: "If no
  'signature_algorithms_cert' extension is present, then the
  'signature_algorithms' extension also applies to signatures appearing in
  certificates." Open question twelve asks whether that stays the answer.
- **`rsa_pkcs1_sha256` as a CertificateVerify scheme.** §4.3.3 at
  `rfc9846.txt:1882-1884` says the RSASSA-PKCS1-v1_5 code points "refer solely
  to signatures which appear in certificates ... and are not defined for use in
  signed TLS handshake messages", so the scheme can never sign a
  CertificateVerify. §9.1's parenthetical agrees: "(for certificates)". A
  server that verifies no certificate signature therefore owes it no code, and
  `rsa_pkcs1.c` stays what `rsa_pkcs1.h:5-7` says it is, a `TRUST=webpki` file.
  This is a reading of `rfc9846.txt:4545-4546` against `:1882-1884`, not a
  measurement.
- **Post-handshake authentication.** `rfc9846.txt:3317-3319` makes it a MAY.
  `post_handshake_auth` is a ClientHello-only extension and the skip-unknown
  default arm handles it.
- **0-RTT.** It takes the first of the three behaviors `rfc9846.txt:2385-2401`
  permits: ignore the extension and answer 1-RTT. It sends no `early_data` in
  EncryptedExtensions, and that absence is the rejection signal
  (`rfc9846.txt:2426-2428`). "What the mode does not check" states the discard
  budget the first behavior costs.
- **More than one NewSessionTicket.** `rfc9846.txt:3194-3196` makes
  issuing one a MAY. The server issues one per connection, full or resumed,
  and "Resumption" below says why one is enough.
- **`status_request`.** `rfc9846.txt:2881-2892` imposes no MUST, and
  `status_request_v2` must never be echoed (`:2894-2900`), which the
  skip-unknown arm gives without a special case.
- **Requiring `server_name`.** `rfc9846.txt:4609-4612` makes requiring it a MAY.
  The server parses the name and hands it to the caller; the caller decides.
- **Sending `supported_groups` to the client.** `rfc9846.txt:2122-2127` makes it
  a SHOULD.
- **`quic_transport_parameters`, which is refused rather than declined.** It is
  the one ClientHello extension the parser recognizes in order to refuse. RFC
  9001 §8.2 requires a fatal `unsupported_extension` from an implementation
  that understands the extension when the transport is not QUIC
  (`rfc9001.txt:1945-1949`), and every build here runs over TLS records,
  because `srv_cfg.h` refuses `CH_ROLE_SERVER` together with
  `CH_TRANSPORT_QUIC`. The skip-unknown arm cannot give that answer, so the
  type carries a `SRV_EXT_` bit of its own. `srv_build_encrypted_extensions`
  writes the same extension from a body its caller supplies, which is the
  server's half of `ch_cfg.transport_params`; a build over TLS records passes
  NULL and sends none, and the QUIC server's driver passes the caller's body
  (`docs/quic_server.md`).

## Where the cryptography lives

Five pieces, ranked by cost. The ranking is the honest answer to "what is the
largest single cost", and each rank names the measure.

1. **Hash agility**, by interfaces touched: 14 declarations of which one is
   renamed, 10 struct fields, 8 CBMC harnesses, 6 Lean definitions and 5 Lean
   theorem statements, +152 bytes of `ch_tls` on both targets, +96 bytes of
   `ch_handshake`'s stack frame, +2,280 bytes of flash to have SHA-384 at all
   and +284 more for the HMAC split `make lint-tidy` forces. Every number
   measured above.
2. **Constant-time AES and GCM**, by unmeasured risk: the GCM harness is
   measured as failing today and the split is unattempted. If it does not
   converge this lane does not land at all.
3. **RSA-PSS signing**, by new code with no existing shape: a constant-time
   secret-exponent ladder, a new CBMC formula at 96 or 128 limbs, and a Lean
   module written from nothing.
4. **Constant-time P-256**, which the mandatory group forces anyway, in two
   files: `p256_field.[ch]` for the arithmetic and `p256_ecdh.[ch]` for the
   three operations a key exchange performs.
5. **ECDSA signing**, small once 4 exists.

### The hash-agile key schedule

`hkdf.[ch]`, `keysched.[ch]`, `record.[ch]` and `session.h` take `hash_len` as
a leading `size_t` parameter with two valid values, `SHA256_LEN` and
`SHA384_LEN`, and size every secret array at `HKDF_HASH_MAX`, which is
`SHA384_LEN`. The bulk of the work is in `hkdf.c`, and "The cost that dominates"
gives the measured counts: nine hash call sites, seven block-size reads and one
context declaration inside a 28-line HMAC, and 21 uses of `SHA256_LEN` on 18
lines across the file. `keysched.c` and `record.c` call no hash at all —
`grep -c 'sha256_[a-z]*('` returns 0 for both — so there the change really is
the array widths and the pass-through of the parameter.

No function-pointer table appears, and the shape that replaces one is measured
rather than asserted: one HMAC body per hash behind a two-arm dispatcher, at
528 bytes of frame and 672 of `__text`, because the one-function form measures
cognitive complexity 24 against `.clang-tidy:98`'s threshold of 15 and fails
`make lint-tidy`. `CLAUDE.md:222-226` says auditable wins over compact when the
two conflict, and a reader who greps `hash_len` finds every place the hash
varies.

`hash_len` is public: it is fixed by the suite the ServerHello announced in the
clear. Each branch on it names that fact, which is what INV-16 requires
(`docs/invariants.md:649`).

**The landing commit fails `make lint-wide-multiply` until `hkdf.c`'s branch
ceilings move, and `hkdf.c` is the only file in that position.** `hkdf.c` is
already in `BRANCH_SRCS` (`Makefile:2241`) and already carries a
`BRANCH_CEILING` entry on all eight specs, and it sits exactly at that entry on
both specs measurable on this machine: measured under `lint-wide-multiply`'s own
compiler and flags, `hkdf.c` emits **14** conditional branches on `rv32imac`
against the recorded `rv32imac/hkdf.c:14` (`Makefile:2259`) and **13** on `m3`
against the recorded `m3/hkdf.c:13` (`Makefile:2254`). One added branch fails
the check at `Makefile:2341-2343`, and the two-arm dispatcher plus the
`hash_len` parameter on four more functions adds several. The eight entries are
re-measured and raised in the same commit; "Bounds that need measuring" carries
the row. No other `BRANCH_SRCS` file changes: this design edits `hkdf.c`,
`keysched.c`, `record.c` and `session.h` among the shared sources, and of those
four only `hkdf.c` is on `BRANCH_SRCS`. `sha256.c`, `sha3.c`, `chacha20.c`,
`poly1305.c`, `aead.c`, `x25519.c`, `mlkem.c`, `mlkem_poly.c`, `drbg.c`, `ct.c`
and `softmul.c` are untouched, and `aead.[ch]` in particular is listed
"Unchanged" in "What it reuses". `sha512.c` and `sha512_compress.c` change no
code and still need eight entries each, because they are joining the list for
the first time.

Open question one asks whether the parameter lands unconditionally or inside
`#ifdef CH_ROLE_SERVER`. The unconditional form keeps one set of signatures for
both roles and moves the client's published `ch_tls` from 1144 to 1296 on
arm64. The role-arm form keeps the client at 1144 and puts a role arm in four
shared files, which `lint-role-partition` then holds. Both are measured above;
the choice is Camilo's.

### `aes.[ch]` and `gcm.[ch]`: constant time, renamed before the patch lands

**Decision: write a constant-time AES, and rename `quic_aes.[ch]` and
`quic_gcm.[ch]` to `aes.[ch]` and `gcm.[ch]` before `gcm.patch` lands.**

The rejected alternative is to keep the patch's table and state a threat model:
an S-box leak needs a shared data cache, a bare-metal MCU has none, so the leak
is a host-side concern. The argument is statable. I reject it for three
reasons. `CLAUDE.md:104` states the rule as a purpose rather than a preference,
and `docs/decisions.md:38-42` names what that purpose bought: "no lookup
tables, no timing story to defend." Keeping the table makes the timing claim
conditional on the deployment for the first time, and conditional on the data
path, on every 16 bytes of every record. And `TRUST=webpki` already admits a
host-side mode into this tree, so the deployment the argument excludes is one
this tree already serves.

The algorithm work is narrower than it sounds. GHASH, counter mode and the
counter increment in the patch's GCM body select with arithmetic masks and index
only by loop counters. The S-box lookup is the one variable-time construct,
declared at `gcm.patch:973` and indexed at `gcm.patch:1037`
(`state[i] = SBOX[state[i]];`) and again at `gcm.patch:1012-1015` in the key
schedule. So a constant-time AES replaces the cipher and the key expansion and
changes no GCM arithmetic.

**The file work is wider than the algorithm work, and the first draft of this
record said only the narrow half.** The rename splits the type, and that split
changes `gcm.c`. `quic_aes_key.h:43-48` bundles a round-key schedule, a 12-byte IV
and a second schedule for QUIC header protection into `aes_public_key`, and
every GCM entry point takes it:

    quic_aes.h:130    void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
    quic_gcm.h:52     void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
    quic_gcm.h:70     int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,

A TLS `rec_dir` has an IV and no header protection key, so `aes.h` declares the
block cipher's schedule alone and the QUIC bundle stays with the QUIC files:

```c
// aes.h
#define AES_BLOCK 16
#define AES_128_KEY 16
#define AES_256_KEY 32
#define AES_ROUND_KEYS 15                       // Nr + 1 at AES-256, FIPS 197
typedef struct {
    uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK];
    uint8_t rounds;
} aes_key;  // 241 bytes, measured under -Wall -Wextra -Wpedantic -Werror -std=c11 -O2

void aes_expand(aes_key *k, const uint8_t *key, size_t key_len);  // constant time
void aes_encrypt_block(const aes_key *k, const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
```

**The round keys are bytes rather than words, and the second round of this
record wrote a `uint32_t rk[60]` with a `// 241 bytes` comment that was wrong
on every target.** Measured: the word form is `sizeof` **244** and `_Alignof`
4 — `uint32_t rk[60]` is 240 bytes, `uint8_t rounds` is one, and the alignment
of 4 pads it to 244 — while the byte form above is `sizeof` **241** and
`_Alignof` 1. The byte form is also the tree's existing shape, with the reason
stated in the file being renamed: `quic_aes.h:40-41` reads "Bytes rather than
words, so no step of the schedule or the cipher assumes host endianness", and
`CLAUDE.md:142-143` states the same rule for the whole tree. So the byte form
keeps the rule, keeps the comment true, and makes the change from
`aes_key_schedule` a rename plus one added field rather than a retyping. Open
question fourteen puts the choice to Camilo, because the word form is faster on
a 32-bit core and the record must then say how `aes.c` fills those words
without assuming host order.

So the rename costs three declaration changes in `gcm.h` (`gcm_seal`,
`gcm_open`, `gcm_ghash` each take `const aes_key *`), three call sites inside
`gcm.c`, one change at every QUIC caller, which passes `&bundle->key`, **and
the QUIC bundle's own two fields**. `quic_aes_key.h:40` closes the typedef
`aes_key_schedule`, and `quic_aes_key.h:45` and `:47` declare
`aes_key_schedule key;` and `aes_key_schedule hp;` inside `aes_public_key`. The
typedef is renamed `aes_key`, moves to `aes.h`, and both fields take the new
name. The patch's own body calls `aes_encrypt_block(k, ...)` with the bundle
type at `scratchpad/server/quic_gcm_new.c:98`, `:150` and `:168`, so those three
lines move with it. The landing order below assumes this is a type change rather
than a rename, because it is one.

**A `TRANSPORT=quic` build pays for round keys AES-128 never fills, and the
cost is measured — but it is now stack, not SRAM.** `AES_ROUND_KEYS` goes from
11 to 15. On the host, at the tree's `CFLAGS`: one schedule goes 176 to 241
bytes and one bundle goes 364 to 494. The paragraphs below were written when
`ch_quic` stored two bundles and the cost was **728 to 988** bytes of session
SRAM, **260 bytes** per QUIC session against a measured client `ch_tls` of
1,144. INV-26 removed that storage: `ch_quic` now declares `initial_dcid` and
`initial_dcid_len` and no key, and each packet call builds one bundle on its
own stack. So the 130 extra bytes land in a frame rather than in the session,
against `lint-stack`'s 2,560-byte budget, and the SRAM row is gone.
The two ways out are **unmeasured** and still available if a frame ever needs
them: give `aes_key` a `CH_AES_ROUND_KEYS` that a `TRANSPORT=quic` build
without `ROLE=server` sets to 11, or keep the QUIC bundle on its own 11-round
type. Open question fifteen asks which, and "Bounds that need measuring"
carries the row.

The rename satisfies both halves of INV-27 (`docs/invariants.md:279`), which
claims that every root file only a `TRANSPORT=quic` build compiles is named
`quic*` and no other root file is. These two files stop being QUIC-only, so
they lose the prefix rather than joining `QUIC_SHARED` (`Makefile:1615`).
Renaming before the patch lands is cheaper: the patch already carries the old
names into its Makefile lists, its Semgrep rule, its proof harness names, its
Lean modules `spec/lean/Spec/Aes.lean` and `spec/lean/Spec/Gcm.lean`, and four
`.violation` files.

Bitsliced or masked is **undecided and unmeasured**. Both are constant time.
Neither has been built here, so neither has a size or a speed on any target.
The lane starts by building both and measuring on rv32 beside the table
version's 1,312 text bytes, and `docs/decisions.md` records the answer.

**The proof is the landing blocker, and it is already measured as failing.**
The patch's own note in `proof/run.sh` says so:

    gcm.patch:917    # 2,144 s under kissat with no verdict, and quic_gcm_forge passed ten
    gcm.patch:918    # minutes at 2.6 GB resident and climbing.

while the AES harness converges at 377 properties, 23 s and 0.67 GB peak
(`gcm.patch:910`). `CLAUDE.md:105-113` makes proofs mandatory, so a bulk AEAD
with no converged harness does not land, and this one would be the AEAD on the
data path. The patch names the likely answer — the split `aead` already took,
one property per formula, at a bound below one block — and nobody has run it.
**Whether the split converges is unmeasured, and it is the first thing to
measure.**

### `p256_ecdh.[ch]`: a constant-time P-256

`rfc9846.txt:4548-4549` makes key exchange with secp256r1 a MUST.

`p256.c` carries every routine a key exchange needs and not one of them may
hold a secret scalar. The header says so and the code shows it. The scalar
multiply branches on the scalar bit:

    p256.c:287            if ((k[(size_t)i / 32] >> ((size_t)i % 32)) & 1) {

`mont_mul`'s final conditional subtract branches on its operands:

    p256.c:142        if (t[LIMBS] || fe_cmp(t, mod->m) >= 0) {

`mod_add` and `mod_sub` carry the same correction (`p256.c:98`, `:105`), and
`point_add` branches on whether an input is infinity and on whether the points
are equal (`p256.c:226`, `:230`, `:252`, `:253`). Every one is free when the
inputs are public and a leak when they are not.

So `p256_ecdh.c` is new code over new constant-time field arithmetic, not a call
into the old module. Two constraints the file must meet, both from
`CLAUDE.md:87-104`. The ladder selects with branchless mask arithmetic, the way
`x25519.c:36` writes `cswap`. The point addition uses complete formulas, so no
branch on infinity or equality exists to remove.

```c
// p256_ecdh.h
#define P256_SCALAR 32
#define P256_POINT  65   // legacy_form 0x04 || X || Y (rfc9846.txt:2264-2275)

// Turns 32 drawn bytes into a scalar in [1, n-1]. Returns 0 when the draw is
// out of range and the caller draws again; the rejection probability is below
// 2^-32. Keeping the draw in the caller keeps every ch_rand_bytes call in one
// file, which is what INV-4 counts.
int p256_ecdh_keygen(const uint8_t draw[P256_SCALAR], uint8_t priv[P256_SCALAR],
                     uint8_t pub[P256_POINT]);

// Validates the peer point — legacy_form is 4, both coordinates are below p,
// the point is on the curve and is not the point at infinity
// (rfc9846.txt:2277-2286). Subgroup membership is not required for this curve
// and is not checked: the cofactor is 1. Every input is public, and the file's
// constant-time arithmetic runs here anyway rather than forking a second
// implementation.
int p256_ecdh_point_valid(const uint8_t point[P256_POINT]);

// The shared X coordinate. Returns 0 for an invalid point or an all-zero
// result.
int p256_ecdh(const uint8_t priv[P256_SCALAR], const uint8_t point[P256_POINT],
              uint8_t out[P256_SCALAR]);
```

The arithmetic under those three declarations is `p256_field.[ch]`, which
`p256_sign.c` includes too. This header declares the three operations a key
exchange performs and no arithmetic of its own.

**Point validation lives here, not in `p256.c`, and the first draft of this
record had that wrong.** `on_curve` is file-static and takes internal limb
arrays:

    p256.c:295    static int on_curve(const uint32_t x[LIMBS], const uint32_t y[LIMBS]) {

It also depends on `MODP`, `B`, `mod_mul`, `mod_sub`, `mod_add` and `fe_cmp`,
all static in the same file, and `p256.h` has exactly one declaration, at
`p256.h:16`, with the header ending at line 19. `nm -gU p256.o` prints one
symbol. So the call the first draft routed into `p256.c` cannot be made, and
"p256.c stays exactly as it is" cannot hold beside it. Writing the check in
`p256_ecdh.c` keeps `p256.c` untouched and costs nothing extra, because the
coordinates must be range-checked and converted into the new representation
anyway.

A server object still compiles `p256.c`, for one call: `ch_srv_check` verifies
its own ECDSA signature with `p256_ecdsa_verify` at boot. That is the only
entry into that file from a server build.

### `p256_field.[ch]`: the constant-time arithmetic both new files call

**The second round of this record routed `p256_sign.c` into `p256_ecdh.c`
across an interface that did not exist.** It said the base-point multiply `k*G`
"runs through `p256_ecdh.c`'s ladder" and that the signer "computes over
`p256_ecdh.c`'s constant-time field arithmetic", while `p256_ecdh.h` declared
three functions — `p256_ecdh_keygen`, `p256_ecdh_point_valid` and `p256_ecdh` —
and not one of them is a ladder or a field operation. That is the same defect
the record corrected one file over, where it found that `p256.c`'s `on_curve`
is static and unreachable.

**The arithmetic goes in a third file that both signers and the key exchange
include, and the tree already did this once for the same reason.**
`p384_field.[ch]` is the field and scalar arithmetic `p384.c` uses, split out
under exactly this naming: `p384_field.h:1-3` reads "NIST P-384 field and
scalar arithmetic for p384.c: the limb layout, the two moduli (the field prime
p and the group order n) and the modular routines both share."
`CLAUDE.md:61-62` already lists `p384.[ch]`/`p384_field.[ch]` as a pair, so the
shape needs no new rule. The split also keeps both new files inside
`CLAUDE.md:227-228`'s 500-line budget, against `p256.c`'s 420 lines today.

Two more reasons the arithmetic is not in `p256_ecdh.h`. Half of what
`p256_sign.c` needs is not a key exchange's business: ECDH does arithmetic mod
*p* and one range check mod *n*, while signing needs a multiply and an inverse
mod *n* for `s = k^-1(z + r*d)`, so declaring those in `p256_ecdh.h` would put
two routines in a header whose own file never calls them. And reusing
`p256_ecdh_keygen` for `k*G` does not fit its own contract: the sketch above
says keygen "Returns 0 when the draw is out of range and the caller draws
again", while an RFC 6979 nonce never draws — its retry is the generator's
`K = HMAC(K, V || 0x00)` step. Reusing the name would make the signer's retry
read as a randomness retry, which is the opposite of what
`inv31-nonce-from-rand.violation` exists to prove.

```c
// p256_field.h — the constant-time P-256 arithmetic p256_ecdh.c and
// p256_sign.c share. Every routine here is constant time in every operand:
// no branch and no memory index depends on any input. That is the whole
// reason this file exists beside p256.c, whose arithmetic is variable time
// on purpose because it only ever sees a public key, a public hash and a
// public signature (p256.c:142 branches on mont_mul's operands, and
// p256.c:161 builds mod_inv entirely out of mont_mul).
//
// Elements are 8 little-endian uint32 limbs; products and carries live in
// uint64 through ct.h's widening multiply. Every conditional correction is
// a branchless mask select in the shape x25519.c:36 writes cswap, never an
// if. Every routine is a pure function of its inputs and writes only
// through its out-parameters: it keeps no static state, so no value
// computed from a private scalar outlives the caller's frame.
#ifndef CH_P256_FIELD_H
#define CH_P256_FIELD_H

#include <stdint.h>

#define P256_LIMBS 8  // limb: one 32-bit word of a big number; P-256 = 8 limbs
#define P256_LEN 32   // bytes in one coordinate or one scalar

typedef struct {
    uint32_t m[P256_LIMBS];   // the modulus
    uint32_t r2[P256_LIMBS];  // 2^512 mod m, entry ticket to the Montgomery domain
    uint32_t m0inv;           // -m^-1 mod 2^32
} p256_modulus;

// SEC 2 secp256r1: the field prime p and the group order n.
extern const p256_modulus p256_modp;
extern const p256_modulus p256_modn;

// Predicates, branchless. p256_is_zero returns an all-ones mask when every
// limb is zero and an all-zero mask otherwise; p256_less returns an
// all-ones mask when a < b. Neither returns early, and neither is an int
// the caller may branch on without stating that its operand is public.
uint32_t p256_is_zero(const uint32_t a[P256_LIMBS]);
uint32_t p256_less(const uint32_t a[P256_LIMBS], const uint32_t b[P256_LIMBS]);

// o = mask ? a : b, one limb at a time, no branch.
void p256_select(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                 const uint32_t b[P256_LIMBS], uint32_t mask);

// 32 big-endian bytes <-> 8 little-endian limbs, byte by byte, no host
// endianness assumed.
void p256_from_bytes(uint32_t o[P256_LIMBS], const uint8_t b[P256_LEN]);
void p256_to_bytes(uint8_t b[P256_LEN], const uint32_t a[P256_LIMBS]);

// Modular arithmetic. Inputs below mod->m, results below mod->m; o may
// alias a or b in every routine. The final conditional subtract is a mask
// select over the borrow, not the compare-and-branch p256.c:142 writes.
void p256_mod_add(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                  const uint32_t b[P256_LIMBS], const p256_modulus *mod);
void p256_mod_sub(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                  const uint32_t b[P256_LIMBS], const p256_modulus *mod);
// Montgomery product o = a*b / 2^256 mod m.
void p256_mont_mul(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                   const uint32_t b[P256_LIMBS], const p256_modulus *mod);
// Plain product o = a*b mod m.
void p256_mod_mul(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                  const uint32_t b[P256_LIMBS], const p256_modulus *mod);
// o = a^-1 mod m by Fermat, a^(m-2). The exponent is the public constant
// m-2, so the square-and-multiply schedule is fixed and public; what makes
// the routine constant time in a is p256_mont_mul, which has no
// operand-dependent correction. a must be non-zero, and the caller checks
// that with p256_is_zero before calling.
void p256_mod_inverse(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS],
                      const p256_modulus *mod);
// o = a mod n for an a below p. One masked conditional subtract of n,
// because p < 2n. This is how r is taken from the x coordinate.
void p256_reduce_n(uint32_t o[P256_LIMBS], const uint32_t a[P256_LIMBS]);

// A point in Jacobian coordinates. The point at infinity is z == 0.
typedef struct {
    uint32_t x[P256_LIMBS];
    uint32_t y[P256_LIMBS];
    uint32_t z[P256_LIMBS];
} p256_point;

// SEC 2 secp256r1's generator G, in affine coordinates with z = 1.
extern const p256_point p256_generator;

// Complete addition formulas (Renes-Costello-Batina), so no branch on
// infinity and no branch on a == b exists to remove. o may alias a or b.
void p256_point_add(p256_point *o, const p256_point *a, const p256_point *b);
void p256_point_double(p256_point *o, const p256_point *a);

// o = k*p, one fixed-count ladder, selecting each step with p256_select.
// Constant time in k: the trip count is 256 whatever k is, and no step
// indexes memory by a bit of k. This is the one ladder in the build, and
// p256_base_mul is the k*G case, written out because G is a constant.
void p256_scalar_mul(p256_point *o, const uint32_t k[P256_LIMBS], const p256_point *p);
void p256_base_mul(p256_point *o, const uint32_t k[P256_LIMBS]);

// Jacobian to affine: one mod-p inverse of z, then x/z^2 and y/z^3.
// Returns 0 for the point at infinity, which is what p256_ecdh.c rejects
// and what p256_sign.c can never see for a nonce in [1, n-1].
int p256_to_affine(uint32_t x[P256_LIMBS], uint32_t y[P256_LIMBS], const p256_point *a);

#endif
```

**One contract carries the whole file, and it is stated three times in that
header on purpose: every routine is constant time in every operand, so no
caller has to know which of its arguments is secret.** A routine that ran
faster on some operand than on another would leak the nonce through
`p256_base_mul` and the private scalar through `p256_mod_mul`, and one leaked
nonce recovers the key. So the file has no operand-dependent path at all — not
for the conditional subtract, not for the ladder's bit select, not for the
compare. Every correction is a mask. The alternative, a file with a fast path
for public inputs and a slow one for secret inputs, is how a variable-time
routine reaches a nonce, and it is what `p256.c` is. Keeping `p256.c` untouched
and variable time, and `p256_field.c` uniformly constant time, means the two
cannot be confused at a call site.

### `p256_sign.[ch]`: ECDSA over the constant-time arithmetic

**This file never calls into `p256.c`.** That is the correction the first draft
most needed. `mont_mul` branches on its operands (`p256.c:142`) and `mod_inv`
is a Fermat ladder built entirely out of it (`p256.c:161-177`, with `mont_mul`
calls at `:171` and `:173`). Running the RFC 6979 nonce `k` or the private
scalar `d` through them leaks `k` through the conditional subtract, and one
leaked nonce recovers the long-term key. The point is not academic and the
build makes it moot as well: `nm -gU p256.o` returns one symbol, so none of
that arithmetic is linkable from another file in the first place.

So `p256_sign.c` computes over `p256_field.c`, the constant-time arithmetic
`p256_ecdh.c` uses too, and calls nothing in `p256.c`. `p256_field.h` above
declares every routine either file calls. The base-point multiply `k*G` is
`p256_base_mul`, one of the two entries into that file's single ladder, so no
second ladder appears. The mod-n arithmetic for `s = k^-1(z + r*d)` is the same
file's `p256_mod_mul`, `p256_mod_add` and `p256_mod_inverse`, each taking
`&p256_modn`. The inversion is by Fermat over the public exponent `n - 2`,
whose schedule is fixed, rather than by a data-dependent extended Euclid; what
makes it constant time in `k` is `p256_mont_mul`, which has no
operand-dependent correction. `p256.c:157-159` already says the same thing of
the same construction: "The exponent is a public constant, so the bit-dependent
multiply leaks nothing.". What stays inside `p256_sign.c` is the RFC 6979
generator, the DER writer and the retry loop, and nothing else.

Every step of ECDSA names its call, so the partition is provable rather than
asserted:

| Step | Call | Secret in it |
|---|---|---|
| `z` from `msg_hash` | `p256_from_bytes`, `p256_reduce_n` | no |
| `k` in range | `p256_is_zero`, `p256_less` against `p256_modn.m` | yes, `k` |
| `k*G` | `p256_base_mul`, then `p256_to_affine` | yes, `k` |
| `r = x mod n` | `p256_reduce_n` | no once computed |
| `r*d` | `p256_mod_mul` with `&p256_modn` | yes, `d` |
| `z + r*d` | `p256_mod_add` with `&p256_modn` | yes |
| `k^-1` | `p256_mod_inverse` with `&p256_modn` | yes, `k` |
| `s` | `p256_mod_mul` with `&p256_modn` | yes |
| `r == 0` or `s == 0` retry | `p256_is_zero` | the mask is public: both values are outputs |

```c
// p256_sign.h — one of the two files in this tree that read a long-term
// private key. Every routine here is constant time in the private scalar and
// in the nonce: no branch and no memory index depends on either. It calls
// p256_field.c's arithmetic and never p256.c, whose mont_mul branches on
// its operands (p256.c:142).
//
// The nonce is RFC 6979 deterministic, derived from the key and the message
// hash through hmac (hkdf.h:13), so no entropy is drawn here and two
// signatures under one nonce cannot happen. The derivation stays on SHA-256
// whatever the cipher suite selected, because it is this file's own
// construction and not a protocol value.
//
// sig is a DER ECDSA-Sig-Value (rfc9846.txt:1888-1892); 72 bytes is the
// maximum for P-256 and the caller passes that much room. msg_hash is always
// 32 bytes: this file signs ecdsa_secp256r1_sha256 and nothing else, and that
// scheme names SHA-256 as the hash that covers the signed content
// (rfc9846.txt:1888-1891). The transcript hash inside that content is 48 bytes
// under TLS_AES_256_GCM_SHA384, which changes what the caller hashes and not
// what this file receives.
#define P256_SIG_MAX 72
int p256_sign(const uint8_t priv[P256_SCALAR], const uint8_t msg_hash[32],
              uint8_t sig[P256_SIG_MAX], size_t *sig_len);
```

The RFC 6979 generator and the DER writer live in this file rather than in
files of their own. That looks like a breach of one concern per file pair and
it is the opposite: the concern is the secret scalar and everything computed
from it, and splitting it would put a value derived from the key into a second
file.

The Lean side is unusually far ahead. `spec/lean/Spec/P256.lean:82` already defines
`ecdsaSign d k z`, `:156-161` already proves `ecdsaVerify_ecdsaSign`,
`spec/lean/Main.lean:295` already exposes a `p256_sign` driver command, and
`test/diff_p256.h:83` already calls it. The differential run has an oracle on
the day the C file compiles. What is genuinely new in Lean is
`Spec/Rfc6979.lean`: the tree carries the RFC 6979 A.2.5 P-256 vectors
(`spec/lean/Spec/P256.lean:163-178`, `test/diff_x509.h:43-48`,
`test/p256_tests.h:1-9`) and no HMAC_DRBG derivation.

**Two claims about RFC 6979 are narrower than they read.**

First, it removes one `ch_rand_bytes` call, not the dependency. A server still
draws the 32-byte ServerHello random every connection (`rfc9846.txt:1358-1363`)
and the ephemeral key-exchange scalar. `rand.h:7-8` already says a device
without entropy "has no business starting a handshake", and that stays true of
a server.

Second, deterministic ECDSA signs one message with one nonce every time, which
is the shape a differential fault attack wants: one correct signature and one
faulted signature over the same message recover the key. Randomized ECDSA does
not have that shape, and this tree's stated target is a bare MCU, where an
attacker may have physical access. The published mitigation is hedged
determinism — mix fresh bytes into the HMAC_DRBG input — which keeps the
nonce-reuse resistance and loses the "no runtime entropy" property.

**v1 signs with plain RFC 6979 and `SIGN_HEDGED=1` mixes 32 fresh bytes into
the seed.** Plain is the default because nonce reuse is instantaneous and total
while a fault attack needs physical access and equipment, and because a
deterministic signer is the only one a fixed test vector and the Lean oracle
can check end to end. The hedge is one extra HMAC input below the signing
equations, so the core, the oracle and the vectors are unchanged under it. A
deployment with physical exposure builds with it. This is open question four.

Two things RFC 6979 requires and this record has not settled, raised now
because they change the harness rather than the prose. The generator retries
when `k` lands out of range and when `r` or `s` comes out zero, so its loop has
no fixed trip count, and a CBMC unwind bound over it needs an argument.
`hmac` (`hkdf.h:13`) is one-shot over one contiguous message, so the
RFC 6979 `V || 0x00 || int2octets(x) || bits2octets(h)` input must be staged in
a stack buffer that holds the private key. Both belong in the header's contract
before the body is written.

### `rsa_sign.[ch]`: RSA-PSS with a secret exponent

The widened scope puts this lane in v1 rather than deferring it.
`rfc9846.txt:4546-4547` names `rsa_pss_rsae_sha256` "(for CertificateVerify and
certificates)", so a server with no RSA key refuses a conformant client that
offers that scheme alone.

The verify side already exists and is reused unchanged: `rsa_pss_verify`
(`rsa.h:34`) is what `ch_srv_check` calls to check the RSA identity at boot.
The sign side shares none of its arithmetic, and `rsa.h:4-6` says why: "Every
input — the modulus, the signature, the message hash — is public, so the
arithmetic is deliberately variable time". A private exponentiation is the
opposite case.

The cost against the existing verify path is a ratio, not a rewrite.
`rsa_mont.c` has four `mont_mul` call sites (`:143`, `:146`, `:148`, `:153`)
and runs 19 of them for the public exponent 65537, derived from the loop bound
at `rsa_mont.c:145`:

    rsa_mont.c:145        for (int i = 0; i < 16; i++) {

A 3072-bit private exponent needs roughly 3,072 squarings plus multiplies, in a
ladder whose operand selection is branchless and whose table reads, if it uses
a window, are constant-time scans. `README.md:135` records a 4,992-byte peak
stack for an RSA-3072 *verify*.

`rsa_sign.[ch]` is written, and this paragraph is what it changed about the
lines above. It uses no window and no table at all: a Montgomery ladder runs
one multiplication and one squaring per exponent bit, over every one of the
8 * n_len bit positions, which costs about 1.6 times a 4-bit window and saves
the window's 16 * n_len bytes of stack. A ladder step selects with mask
arithmetic, so no table read has to be a scan.

The signing frame is *measured* now, by the method `make lint-stack` uses,
which is `-Wframe-larger-than` per function; the three frames below sit on one
call chain, so the peak is their sum. At the device bound of RSA-3072, under
the Arm GNU gcc 16.2.0 the m3 lane uses, at -Os: `rsa_pss_sign` 1,072 bytes,
`rsa_sp1` 1,536 and `mont_mul` 440, so 3,048 bytes. Under clang 23 at -O2 on
arm64, the same three are 1,216, 1,696 and 496, so 3,408, and at the
TRUST=webpki bound of RSA-4096 they are 1,472, 2,208 and 624, so 4,304.

Two of those three peaks are above `STACK_BUDGET`, which is 2,560 bytes for a
device build, and the `ROLE=server` object packages `rsa_sign.c` now. The
budget stayed at 2,560 and `make lint-stack ROLE=server` passes, because that
gate compiles with `-Wframe-larger-than` and so measures one frame at a time:
the largest single frame here is `rsa_sp1`'s, under 2,560 on both compilers
above. The sums are what a device's stack actually has to hold, so a server
deployment sizes its stack from them and not from the gate.

```c
// rsa_sign.h — the second of the two files that read a long-term private key.
// Constant time in d, p, q and every CRT intermediate. Produces
// rsa_pss_rsae_sha256 signatures, and that scheme fixes every hash here:
// SHA-256 over the signed content, MGF1-SHA256, and a 32-byte salt
// (rfc9846.txt:1894-1898, RFC 8017 §9.1.1). msg_hash is always 32 bytes;
// see "The CertificateVerify signature uses two different hashes".
int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 uint8_t *sig, size_t cap, size_t *sig_len);
```

`rsa_pss_verify` today fixes MGF1-SHA256 and salt length 32 (`rsa.h:31-33`),
and the signer keeps every one of those three constants, because
`rsa_pss_rsae_sha256` names SHA-256 for all of them
(`rfc9846.txt:1894-1898`). The cipher suite changes nothing in this file. What
it changes is the transcript hash the caller puts inside the signed content
before hashing it: 32 bytes under the two SHA-256 suites and 48 under
`TLS_AES_256_GCM_SHA384`. The 32 bytes this signer receives is the SHA-256 of
that content either way. `handshake_auth.c:42-43` draws the same split on the
verify side, where the parameter is `const uint8_t hash[SHA256_LEN]` and the
output is `uint8_t out[SHA384_LEN]`.

Whether one deployment provisions both an ECDSA and an RSA identity is open
question three. A build that provisions one still compiles both signers unless
a `SIGN=` axis removes one, and adding that axis reintroduces exactly the
"refuses some conformant client" corner the widened scope was meant to close.

## The build axis and the file partition

### The axis

This section records the design as it was written, and the Makefile has moved
under it since: `PIN` is no longer an axis. The pinned algorithm became half of
a `TRUST` value (`TRUST=raw-rsa`, `TRUST=raw-ecdsa`, `TRUST=ca-rsa`,
`TRUST=ca-ecdsa`, `TRUST=webpki`), so the two refusals below are one, the
quoted block's `$(origin PIN)` test is gone, and every `Makefile:NNN` here
points into the older file. A server also names its trust mode now,
`TRUST=none`, rather than taking the client default: the default named one
algorithm where this object holds both verifiers, and a recursion that did not
name a trust value inherited one. The reasoning stands; only the spelling
moved.

`ROLE` is a Makefile axis beside `TRUST`, `KEX`, `RAND` and `TRANSPORT`.
`ROLE=client` is the default and builds what the tree builds today.

```make
ROLE ?= client
ifeq ($(ROLE),server)
# A server proves its own identity and never judges a peer's certificate, so
# TRUST has no meaning here, and the values that would add a certificate parser
# are refused rather than ignored (Makefile:186-190).
ifneq ($(TRUST),raw)
$(error ROLE=server judges no peer certificate, so it has no trust mode to choose; use TRUST=raw)
endif
# PIN names the algorithm of a pinned peer key, of which a server has none. The
# object still needs both verifiers, because ch_srv_check verifies both
# provisioned identities at boot, so PIN selects nothing here.
ifneq ($(filter command line environment,$(origin PIN)),)
$(error ROLE=server carries both verifiers for ch_srv_check, so PIN selects nothing in it; drop PIN=$(PIN))
endif
ifneq ($(TRANSPORT),tls)
$(error ROLE=server runs over TLS records only; use TRANSPORT=tls)
endif
ROLE_DEF    := -DCH_ROLE_SERVER
ROLE_FILTER := $(CLIENT_REPLACED)
ROLE_ADD    := $(SRV_SRCS) p256_field.c p256_ecdh.c p256_sign.c rsa_sign.c aes.c gcm.c
PUBLIC_ROLE := ch_srv_accept ch_srv_check ch_read ch_write ch_close
# An empty PIN_FILTER keeps every verifier, because LIB_SRCS filters out what
# the filter names (Makefile:313).
PIN_DEF     :=
PIN_FILTER  :=
else ifeq ($(ROLE),client)
ROLE_DEF    :=
ROLE_FILTER :=
ROLE_ADD    :=
PUBLIC_ROLE := $(PUBLIC_TRANSPORT)
else
$(error ROLE=$(ROLE) is not a role; use ROLE=client or ROLE=server)
endif
```

**Three lines read what that block sets, and the second round of this record
amended none of them.** The defect was measured: the record's own snippet was
built into a copy of the Makefile, and `make print-lib-srcs ROLE=server`
printed the client's source list while `make print-lib-def ROLE=server` printed
nothing. `Makefile:310` reads
`LIB_DEF := $(strip $(PIN_DEF) $(TRUST_DEF) $(TRANSPORT_DEF))` and
`Makefile:313-314` read
`LIB_SRCS := $(filter-out $(PIN_FILTER) $(TRUST_FILTER) $(TRANSPORT_FILTER),$(SRCS)) \`
then `$(TRUST_ADD) $(TRANSPORT_ADD)`. No `ROLE` term appears in either. So:
`Makefile:310` gains `$(ROLE_DEF)`, `Makefile:313` gains `$(ROLE_FILTER)`
inside the `filter-out`, and `Makefile:314` gains `$(ROLE_ADD)` after
`$(TRANSPORT_ADD)`. With the three edits, `ROLE=client` produces a source list
byte-identical to today's, measured by `diff`, and `ROLE=server` produces the
server list with `-DCH_ROLE_SERVER`.

Without them, `make lib ROLE=server` compiles the client and
`lint-role-partition` passes on it, because preprocessing every file with and
without a define that no build ever sets finds every file identical. That is
the failure `Makefile:186-190` records for another axis, where `make check
TRUST=webpki` built and passed as `TRUST=raw`.

**The block sits between the `TRANSPORT` axis's `endif` (`Makefile:299`) and
`LIB_DEF` (`Makefile:310`).** Every assignment in it is immediate, so position
is the whole of it: `ROLE_FILTER` reads `CLIENT_REPLACED`, the client arm reads
`PUBLIC_TRANSPORT` from `Makefile:296`, the server arm rewrites the `PIN`
variables set at `Makefile:202-206`, and `Makefile:310` and `:313` read the
result. The record's own `SRV_SRCS` and `CLIENT_REPLACED` lists sit above the
block for the same reason.

**`make lint-trust-separation` is the check that fails on the unwired build,
and it has no `ROLE` row today.** `Makefile:421-449` reads `print-lib-srcs` and
`print-lib-def` per axis value and fails when a value packages the wrong
sources or the wrong defines. It has rows for `PIN`, `TRUST`, `KEX` and
`TRANSPORT`. It gains two, one per role, beside the transport rows at
`Makefile:446-447`. Measured against a copy of the Makefile with the snippet
wired, the target prints `lint-trust-separation: every axis value packages
exactly its own sources and defines`; measured against a copy with `:310` and
`:313` untouched, it prints eleven `must package` and `must not package` lines
and `ROLE=server must define -DCH_ROLE_SERVER`, and exits 1.
`make lint-role-partition` cannot do this job, because it compares preprocessed
text and a source list is not text in a file.

**`ROLE_FILTER` is `$(CLIENT_REPLACED)` and nothing else.** The second round
wrote `$(CLIENT_REPLACED) $(WEBPKI_SRCS) pem.c x509.c x509_der.c x509_ca.c
rsa_pkcs1.c`, and measured both ways the server source list is identical.
`TRUST=raw`, the only trust value the block admits, already names
`pem.c x509.c x509_der.c x509_ca.c $(WEBPKI_SRCS)` at `Makefile:240`. And
`rsa_pkcs1.c` is not in `SRCS` at all (`Makefile:122-124`); it enters through
`TRUST_ADD` at `Makefile:246`, which `filter-out` never reads, so naming it in
any filter is inert. The five extra terms are dropped and the `TRUST` error arm
carries the reason.

All four error arms fire, measured on the wired copy: `ROLE=server
TRUST=webpki`, `ROLE=server PIN=ecdsa`, `ROLE=server TRANSPORT=quic` and a
misspelled `ROLE=sever` each stop the build with the message beside them.
`$(origin PIN)` is what tells `PIN=rsa` typed on the command line from the
`PIN ?= rsa` default at `Makefile:200`, and the local GNU Make 3.81 answers it
correctly.

The empty `PIN_FILTER` deserves its own paragraph, because the first draft of
this record reached the right line through the wrong argument.
`Makefile:313` reads:

    Makefile:313    LIB_SRCS := $(filter-out $(PIN_FILTER) $(TRUST_FILTER) $(TRANSPORT_FILTER),$(SRCS)) \

`filter-out` removes what the filter names. So an empty filter *keeps* every
verifier; it does not drop them. `Makefile:203` shows `PIN=ecdsa` setting
`PIN_FILTER := rsa.c rsa_mont.c` to drop the RSA verifier, and `Makefile:251`
shows `TRUST=webpki` emptying it, with the reason at `Makefile:247-249`: "this
object carries every verifier and PIN selects nothing in it". A `ROLE=server`
object wants exactly that, for a different reason: it holds two signing
identities and `ch_srv_check` verifies both at boot, so it needs
`p256_ecdsa_verify` and `rsa_pss_verify` in the same object. `rsa_pkcs1.c` is
the one verifier a server never needs, and no filter has to name it: it reaches
a build only through `TRUST_ADD` (`Makefile:246`), which the `TRUST=raw` the
block requires never sets.

`PUBLIC` becomes `$(PUBLIC_ROLE) $(PUBLIC_RAND) $(PUBLIC_CA)`, replacing
`$(PUBLIC_TRANSPORT)` at `Makefile:463`. `make lib-check` already diffs the
packaged object's exports against that one list for exact equality, so an
object carrying both roles' calls fails every build.

`LIB_VARIANT := $(PIN)-$(TRUST)-$(KEX)-$(RAND)-$(TRANSPORT)` (`Makefile:372`)
gains `-$(ROLE)`, so the object directory and the relink stamp key on the role.

The four error arms are in the block above rather than in this prose, because
a rule stated only in prose is a rule nobody runs. They stop the build on the
products that have no meaning, the way every other axis already stops on an
unknown value, and for the reason `Makefile:186-190` records: a misspelled
value used to resolve to the default, so `make check TRUST=webpki` built and
passed as `TRUST=raw`. `KEX=pq` is left open and is off by default; "What is
still open" asks whether it stays open.

### The partition

The rule, stated the way INV-27 states its own: every root source and header
that only a `ROLE=server` build compiles is named `srv*`, and no other root
file is, except what two named lists carry with their reasons.

```make
# The server's protocol files. One concern per pair, dependencies down.
SRV_SRCS := srv_parser.c srv_parser_ext.c srv_message.c srv_cookie.c srv_auth.c \
            srv_flight.c srv_handshake.c srv.c
# Named for the algorithm rather than the role, because they are primitives.
# aes.c and gcm.c are also compiled by a TRANSPORT=quic build. Test binaries
# compile all six in every build, the way they already compile both rsa.c and
# p256.c, so all six stay tested everywhere.
ROLE_SHARED := p256_field.c p256_field.h p256_ecdh.c p256_ecdh.h \
               p256_sign.c p256_sign.h \
               rsa_sign.c rsa_sign.h aes.c aes.h gcm.c gcm.h
# Shared files carrying a #ifdef CH_ROLE_SERVER arm.
ROLE_CONDITIONAL := cfg.h session.h record.h record.c handshake_record.h \
                    handshake_record.c handshake_post.c tls.c \
                    hkdf.h hkdf.c keysched.h keysched.c
# Client driver sources a server object does not compile.
CLIENT_REPLACED := handshake.c handshake_auth.c handshake_parser.c \
                   handshake_message.c handshake_flight.c
```

**`tls.c` is on `ROLE_CONDITIONAL`, not `CLIENT_REPLACED`, and this is the one
correction without which no server object links.** `ch_read`, `ch_write` and
`ch_close` are defined only in that file. Compiling it with
`cc -c -Os -std=c11 -I. -DCH_RAND_EXTERN tls.c` and running `nm -gU tls.o`
prints exactly four symbols:

    _ch_close  _ch_connect  _ch_read  _ch_write

`ch_read` is at `tls.c:174`, `ch_write` at `:214`, `ch_close` at `:242` and
`ch_connect` at `:72`. `PUBLIC_ROLE` above requires the server object to export
the first three, and `make lib-check` diffs exports against `PUBLIC` for exact
equality, so filtering `tls.c` out would fail every server build. The role tool
skips `CLIENT_REPLACED` for the same reason `tools/quic-partition.py` skips
`QUIC_REPLACED` — macro differences in a file the mode does not compile mean
nothing — so nothing would have caught it either.

So `tls.c` splits inside the file. The `#ifndef CH_ROLE_SERVER` arm holds
`ch_connect` and every static that only `ch_connect` reaches, directly or
through another static, and `ch_srv_accept` and `ch_srv_check` go in the server
arm. The three shared calls stay outside both arms.

**The record does not name those statics, because a list rots and the compiler
does not.** `CFLAGS` at `Makefile:4` carries `-Wall -Werror`, a static no arm
calls is `-Wunused-function`, and the build stops. Measured on Apple clang and
on Arm GNU gcc 16.2.0; gcc reports it when it compiles rather than under
`-fsyntax-only`, and clang reports it under both. The second round of this
record did enumerate nine names, and the enumeration was wrong: it omitted
`alpn_name_ok` (`tls.c:333`) and `alpn_name_repeats` (`tls.c:342`), which only
`alpn_ok` calls (`tls.c:366`). Putting `alpn_ok` behind the arm and leaving
those two outside it was measured to produce two `-Wunused-function` errors.

The file's twelve statics also divide by trust mode rather than by role alone,
which is the other reason one list cannot hold them. `epoch_init` (`tls.c:17`)
sits under no guard. `pin_len_ok` (`tls.c:64`) is in the
`#ifndef CH_TRUST_WEBPKI` arm at `tls.c:60`. The six predicates
`chain_config_ok` (`tls.c:374-377`) calls — `anchors_ok`, `hostname_ok`,
`clock_set`, `psk_unset`, `pins_unset` and `alpn_ok`, where `psk_unset` has
since moved to `webpki_ticket.c` as `webpki_resumption_ok`
(`docs/decisions.md` entry 47) — and the two statics
`alpn_ok` calls are all inside the `#ifdef CH_TRUST_WEBPKI` arm at `tls.c:255`,
which a server build never compiles, because the `ROLE` block refuses
`TRUST=webpki`. So the two errors above need both defines to reach one
compile, which the `ROLE` block prevents — the enumeration was still wrong, and
a reader who trusted it would write the wrong arm. The static helper
`ch_read` needs, `dispatch_one_record` at `tls.c:128`, is already role-neutral:
it calls `io_read_record`, `rec_open` on `t->rd`, `hspost_read` and `tlsi_fail`,
and names no client-only symbol. `lint-role-partition` then preprocesses the
file twice and checks the split instead of taking it on faith.

`hkdf` and `keysched` appear on `ROLE_CONDITIONAL` only under the role-arm
answer to open question one. Under the unconditional answer they carry no arm
and leave both lists.

`make lint-role-partition` runs `tools/role-partition.py`, which is
`tools/quic-partition.py` with a different define and different lists. It
preprocesses every root `.c` and `.h` twice, once without `-DCH_ROLE_SERVER`
and once with it, and compares. A file outside the three lists that gains text
under the define fails the check, and a file on a list that stops carrying such
text fails it too.

The define is the whole reason `ROLE` is an axis rather than a second library
object built from its own source list. A separate object has nothing to
preprocess against, so no check can prove that client-only text stayed out of a
shared file, and the partition becomes a list someone maintains by hand.

`make role-footprint` mirrors `tools/quic-footprint.py`: files and line counts,
mode-only text elsewhere, share of the library, declared against defined, stubs
remaining, and a surface comparison that `srv.h` and this document's interface
table name the same `ch_srv_` entries. `make lint-role-surface` is the target
that fails on a disagreement, so the report reaches no verdict of its own — the
split `lint-quic-surface` already uses.

### The codegen partition

`make lint-codegen-partition` requires every library source to be in exactly
one of `WIDEMUL_CEILING` and `WIDEMUL_PUBLIC`, and fails on a source in neither
or both (`Makefile:2052-2056`). The role changes both lists, and the first
draft of this record undercounted in both directions.

Four files **move** from `WIDEMUL_PUBLIC` (`Makefile:2034`) to
`WIDEMUL_CEILING` (`Makefile:2018`): `quic_aes.c` and `quic_gcm.c` under their
new names `aes.c` and `gcm.c`, because a server's AES key is a traffic secret;
and `sha512.c` and `sha512_compress.c`, because a SHA-384 key schedule hashes
secrets. Nothing about `p256_sign.c` is a move: it is a new file.

Twelve files are **added**, all to `WIDEMUL_CEILING`: the seven `SRV_SRCS`,
`p256_field.c`, `p256_ecdh.c`, `p256_sign.c`, `rsa_sign.c`, and
`handshake_flight.c` when the QUIC lane lands it. Sixteen files in all, counting
the four that move.

**Membership in `WIDEMUL_CEILING` buys a widening-multiply ceiling and nothing
else, and the second round of this record ran the two lists together.** The
conditional-branch count runs only for files named in `BRANCH_SRCS`:
`Makefile:2335` reads
`case " $(BRANCH_SRCS) " in *" $$f "*) ;; *) continue ;; esac;`, and
`BRANCH_SRCS` today is the twelve arithmetic sources at `Makefile:2241-2242`.
The branch ceilings live in `BRANCH_CEILING` (`Makefile:2253`), not in
`WIDEMUL_CEILING_SPEC`.

`Makefile:2232-2238` says why the two lists differ, and the reason decides
which new files join which: "The files the branch count covers: the arithmetic
under the record layer, whose every input is a key, a limb or a block, and
whose only branches are loop control on public counts. The other CODEGEN_SRCS
files -- buf.c, record.c, keysched.c, io.c, session.c, the handshake files and
tls.c -- branch on lengths, types and states the peer sent in the clear,
several dozen each, so a count there would record the parser and move with
every feature." The seven `SRV_SRCS` files are parsers and builders, so they
take a widening-multiply ceiling and no branch count. **Seven of the sixteen
join `BRANCH_SRCS` as well: `aes.c`, `gcm.c`, `p256_field.c`, `p256_ecdh.c`,
`rsa_sign.c`, `sha512.c` and `sha512_compress.c`.** `p256_sign.c` is not one of
them, because its arithmetic moved to `p256_field.c` and what is left is the
RFC 6979 generator, the DER writer and the retry loop. The two hash files are
on the list for the same reason `sha256.c` is already on it
(`Makefile:2241`): once the key schedule is hash-agile, every input they read
is a key or a block, which is the sentence `Makefile:2232-2238` uses to draw
the line. `WIDEMUL_SPECS` has eight rows (`Makefile:2185-2193`), four of them
measured through `test/docker-mips.sh` and `test/docker-riscv32.sh`, so seven
files cost fifty-six measured branch numbers. Open question thirteen asks
whether Camilo takes that bill, because without it no check in the tree fails
when a signer's arithmetic branches on the nonce.

Two of the fifty-six are measured already, and they are the two hash files on
the clang `rv32imac` spec. Run under `lint-wide-multiply`'s own compiler and
flags — `/opt/homebrew/opt/llvm/bin/clang -target riscv32-unknown-elf
-nostdlibinc -Itools/freestanding -Os -march=rv32imac -std=c11 -ffreestanding
-D_DEFAULT_SOURCE -DCH_RAND_EXTERN -DCH_KEX_PQ -I. -S`, the `Makefile:2326`
filter `grep -vE '^[[:space:]]*\.'`, then the `BRANCH_OPS_RV` list at
`Makefile:2174` — `sha512.c` emits **23** conditional branches and
`sha512_compress.c` emits **4**. On the `m3` spec, whose list is
`BRANCH_OPS_ARM` at `Makefile:2172`, they are **24** and **4**.
The pipeline that produced them reproduces four recorded ceilings exactly:
`rv32imac/sha256.c` 17 and `rv32imac/x25519.c` 31 (`Makefile:2259-2260`),
`m3/sha256.c` 17 and `m3/x25519.c` 34 (`Makefile:2254-2255`). Whoever records the ceilings starts
from those four numbers and measures the other fifty-two.

**Three checks that look like they would catch a signer calling into `p256.c`
do not, and this was measured.** `make lint-codegen-partition` compares file
names against two lists; its two failure arms are "is in neither
WIDEMUL_CEILING nor WIDEMUL_PUBLIC" (`Makefile:2054`) and "is in both"
(`Makefile:2055`), and neither reads a call. `make lib-check` reads a packaged
object whose recipe has already localized every symbol outside `PUBLIC`
(`Makefile:494-499`): with `static` dropped from `p256.c:114`, `make lib-check`
still printed `lib-check: 4 exported symbols, all public API` and exited 0.
`make lint-runtime-symbols` keeps only `__`-prefixed undefined names
(`Makefile:2415`), and `mont_mul` has no leading underscores.

**The mutant for this cannot be written as a cross-file call at all.**
`p256.c:114` is `static void mont_mul(...)` and `p256.c:161` is
`static void mod_inv(...)`, so a call from another file is an undeclared
identifier under `-Werror` (`Makefile:4`), and `test/violations.py:196-201`
reports an edit that does not compile as `unguarded` — "An edit that will not
compile proves nothing about the tests". An `#include "p256.c"` duplicates
`p256_ecdsa_verify` and fails to link, which is the same outcome. So the mutant
is one file's worth of copied code, and the conditional-branch ceiling is the
target that fails on it. That is the mutation the tree already proves catchable:
`Makefile:2149-2154` records that `inv16-widemul-s-sign-branch.violation` turns
two mask corrections into `if`s and every gcc spec's branch count rises.

Two numbers for scale, one measured and one not, and neither is a substitute
for the ceilings the files themselves need. Compiled for `rv32imac` under
`lint-wide-multiply`'s own compiler and flags, `p256.c` emits **78**
conditional branches by the `BRANCH_OPS_RV` list at `Makefile:2174`, and the
same 78 on `m3` by `BRANCH_OPS_ARM` at `Makefile:2172`. Not one of them is held
to anything: `p256.c` is in `WIDEMUL_PUBLIC` (`Makefile:2034`), which carries
no branch ceiling, and it is not in `BRANCH_SRCS` (`Makefile:2241`). The second
round of this record printed 34 here, which no run reproduces; 78 is what the
pipeline above prints, and that pipeline reproduces four recorded ceilings
exactly. What a copied reduction would add to `p256_field.c` is **unmeasured**,
because that file does not exist.

### Stubs first

Every `SRV_SRCS` file lands defining every function its header declares and
implementing none, each body carrying one line:

    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.

`make lib ROLE=server` then links an object exporting five calls, of which the
two new ones refuse and the three shared ones fail on a session no handshake
ever brought up. No stub returns `CH_OK`. `test/srv_stub_test.c` calls every
function, requires each refusal, and fills every buffer with `0xa5` before the
call and compares after, so "writes nothing" is measured — the shape
`test/quic_stub_test.c` ran for the other axis until that mode was implemented.
INV-28 carried this claim (`docs/invariants.md`, "a stub never reports
success"); the QUIC stubs were its first subject and the server stubs its
last. Every `SRV_SRCS` file is implemented now, so the marker matches nothing,
`test/srv_stub_test.c` became `test/srv_auth_test.c`, and INV-28 retired.

## The interface it exposes

```c
// srv.h — a TLS 1.3 server. The caller has already accepted the connection and
// supplies the same blocking I/O callbacks and the same ch_rand_bytes the
// client build needs.

// Runs the full handshake as the server. On CH_OK the session is ready for
// ch_read and ch_write. Any error sends the alert the failure chose, wipes all
// key material, and leaves the session dead.
int ch_srv_accept(ch_tls *t, const ch_cfg *cfg);

// Checks at boot that this build can sign with each provisioned private key
// and that each result verifies under the matching public key. Runs no I/O and
// touches no session. Returns CH_OK, or CH_EINVAL for a configuration that
// cannot serve.
int ch_srv_check(const ch_cfg *cfg);
```

`ch_read`, `ch_write` and `ch_close` keep their `tls.h` contracts exactly and
are the same functions in the same file, not forks. `record.[ch]` names no
side: `rec_seal` writes `REC_APPDATA` unconditionally (`record.c:41`) and
`rec_open` refuses any other outer type (`record.c:71`). One name per thing, so
a server's read is `ch_read`.

Five exported calls against the client's four, held by `make lib-check`
against `PUBLIC`. `docs/decisions.md` entry 28 records four and entry 38
already amends it to fifteen under `TRANSPORT=quic`; the server row joins them.

`ch_srv_check` is the boot-time replacement for parsing the chain. It signs a
fixed message with each provisioned key and verifies it with the verifier
already in the object — `p256_ecdsa_verify` (`p256.h:16`) for the ECDSA
identity and `rsa_pss_verify` (`rsa.h:34`) for the RSA one. It catches a broken
signer and a key the operator paired with the wrong certificate, once, at boot,
with a local error code instead of a client-side alert on every connection. It
reads no chain bytes, so it catches neither a chain whose end-entity key is not
the provisioned public key nor a fallback chain signed with the SHA-1 that
`rfc9846.txt:2958-2960` forbids; a provisioning script does both off the
device.

`ch_pubkey_from_pem` does not exist in a server build. It is the CA mode's
provisioning reader and a server pins nothing.

`chapulin.hpp` forks by role. `CLAUDE.md:249-254` says the wrapper adds no logic
the C core lacks, and a server session is the same RAII shape over one
different name, so the fork is one forwarding function under
`#ifdef CH_ROLE_SERVER`. `make cxx-check` runs on both roles.

### The record transport: a server that does not block

`ch_srv_accept` runs the whole handshake behind `cfg.send` and `cfg.recv`, and
both block. That is the right shape for the firmware this tree targets, where a
blocking socket is all there is. It is the wrong shape for a host whose I/O is a
completion-based event loop: a callback that blocks inside the loop's own thread
stalls every other connection the loop holds, and there is no thread to park it
on. `TRANSPORT=record ROLE=server` is the same server handshake with the socket
given back to the caller.

```c
// srv_rec.h — the same TLS 1.3 server, driven by a caller that owns the socket.

// Prepares a server session. It reads the configuration and waits: unlike
// ch_record_init it stages no message, because a server speaks second.
int ch_srv_record_init(ch_record *r, const ch_cfg *cfg);

// Delivers n bytes the caller read from its socket and reports how many it
// consumed. The server's own records leave through cfg.srv.on_record_out
// during this call.
int ch_srv_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed);
```

`ch_record_state`, `ch_record_alert` and `ch_record_close` are `rec.h`'s and are
not repeated: they read no side, so `rec.c` compiles them in either role and the
client driver above them is what a `ROLE=server` object guards out
(`rec.c:25`). `ch_read`, `ch_write` and `ch_close` are the same record-layer
calls a client uses, for the reason this section already gives.

**Output is a push, not a pull.** There is no `ch_srv_record_out`, and the
certificate chain is why. `srv_flight.c` stages a protected message on the
handler's own stack frame and streams the Certificate straight out of
`cfg.srv.identity` through `srv_frag` (`srv_flight.c:6-8`), because one
Certificate message is larger than `ch_tls.tx`, which is `CH_TX_STAGE` bytes
(`session.h:64`). So there is no buffer for a caller to collect from. A pull
would need a resume point inside `srv_out_sealed`'s record loop, which is the
one thing the record mode's design rules out: `rec_step.h:12` states that a step
runs only when a whole message is already present, consumes that one message,
and waits nowhere inside it. `srv_quic.h:18` reached the same conclusion for the
same reason on the other transport, and `ch_srv_cfg.on_record_out` is
`on_crypto_out` without the encryption level.

That still answers the problem the mode exists for. The callback copies each
record into a buffer the caller owns and returns; it never waits on a socket, so
nothing blocks the loop.

The whole flight leaves inside one `ch_srv_record_in`, because every send sits
in the step that read the message it answers. `bin/srv_rec_test` measures it:
one ClientHello in, five records out — the ServerHello in the clear, then the
EncryptedExtensions, the Certificate, the CertificateVerify and the Finished,
each protected. The test's `send` and `recv` fail the run if the driver ever
calls them, which is how the mode's claim is checked rather than argued.

#### The file partition

| file | what it holds |
| --- | --- |
| `srv_rec.[ch]` | the driver: the three steps and the two entry points. `srv_quic.[ch]`'s mirror on the transport that keeps its records. |
| `rec_frame.[ch]` | taking one inbound record, and dying. Both drivers call it, so INV-17's wipe list has one copy to check, the way `quic_fail.[ch]` holds QUIC's. |

`srv_rec.c` installs no keys. Every `rec_dir_init` a server makes already sits
inside the handler that derived the secret it takes — the handshake keys in
`srv_derive_handshake_secrets` (`srv_flight.c:308`), the application write key
in `srv_send_finished` (`srv_flight.c:425`) and the application read key in
`srv_complete` (`srv_flight.c:464`) — because the blocking driver needs them
there too. The step table decides only which handler runs next.

`srv_out.c` gains a third arm. It had two: a QUIC arm that pushes to
`on_crypto_out`, and a blocking arm that calls `io_send_all`. The record arm is
the blocking one with `emit` in place of that call, so the framing, the
`record_size_limit` and the fragmentation are the same lines.

#### The build line

```sh
make RAND=drbg TRUST=none TRANSPORT=record ROLE=server lib
```

`TRUST=none` is required, as it is for any `ROLE=server` build: a server judges
no peer certificate. `ROLE=both` takes the record transport too, with a real
`TRUST` value, and carries both drivers in one object — `ch_record_init` and
`ch_srv_record_init` are different names for that reason.

`make lint-trust-separation` carries a row for this build: it requires
`srv_rec.c`, `rec.c` and `rec_frame.c`, and refuses `srv_handshake.c`,
`srv_quic.c` and `rec_step.c`. Each role row names the one driver its transport
wants. The rows read git's root `srv*.c` list and subtracted a single driver
name from it until `srv_rec.c` became the third, which no subtraction tells
apart.

`TRUST=webpki TRANSPORT=record` links too, which is the combination a
public-PKI host client wants. It did not until the webpki `ch_connect` gained
the `#ifndef CH_TRANSPORT_RECORD` guard the pinned one always had, and until
that mode defined the `tlsi_config_ok` `session.h` declares for every trust
mode: the webpki arm checked the receive floor and `require_pq` inside
`ch_connect` and left the call undefined, so an object with `ch_record_init`
and no `ch_connect` imported both it and `ch_handshake`. Folding those two
checks into `tlsi_config_ok` is what gives `ch_record_init` the webpki floor
and the `require_pq` refusal, which it did not have in this mode
([171](https://github.com/c4milo/chapulin/issues/171)).

Nothing caught it because `check` linked no `TRANSPORT=record` library variant
at all — only `bin/recclient`, which pins. Two `lib-check` legs now link one
per side: `TRUST=none ROLE=server` and `TRUST=webpki`, both over this
transport.

### What `ch_cfg` gains and drops

`cfg.h` forks under `#ifdef CH_ROLE_SERVER`, the way it already forks under
`#ifdef CH_TRANSPORT_QUIC`.

```c
#ifdef CH_ROLE_SERVER
typedef struct { const uint8_t *der; size_t len; } ch_cert;

// One identity per signature scheme the server offers. End-entity first
// (rfc9846.txt:2850-2851), never empty (rfc9846.txt:2876). The bytes are
// opaque DER in the caller's flash. The server writes them out unread and
// parses no X.509, so a server object links no DER reader. A slot whose
// chain_count is 0 is not provisioned, and the server never selects that
// scheme; ch_srv_check refuses a configuration with no identity at all.
typedef struct {
    const ch_cert *chain;
    uint8_t        chain_count;
    const void    *priv;      // read by p256_sign.c or rsa_sign.c and nowhere else
    size_t         priv_len;  // sizeof the type that signer reads
    const uint8_t *pub;       // read by ch_srv_check and by the RSA cap test
    size_t         pub_len;
} ch_identity;

`priv` is `void` because the two signers read different types: 32 big-endian
bytes for `p256_sign`, one `ch_rsa_priv` for `rsa_pss_sign`. `srv_cfg.h` states
both, and `srv_auth.c` tests `priv_len` against the size of the type the
selected scheme's signer reads before it passes the pointer on, so no line
outside a signer reads a private key. The RSA signature is exactly as long as
the modulus, so `pub_len` is also the length `srv_sign_certificate_verify`
tests the caller's buffer against.

ch_identity ecdsa_p256;       // signs ecdsa_secp256r1_sha256
ch_identity rsa_pss;          // signs rsa_pss_rsae_sha256

// The HMAC-SHA-256 key that protects the HelloRetryRequest cookie
// (rfc9846.txt:1779-1783), 32 bytes, caller-owned. One key per deployment, so a
// second ClientHello that lands on a different session still verifies.
const uint8_t *cookie_key;

// Optional. The ClientHello parser copies the server_name here; the handshake
// continues either way unless require_server_name is set, which
// rfc9846.txt:4609-4612 permits.
uint8_t *sni_buf;
size_t   sni_cap;
uint8_t  require_server_name;
#endif
```

It drops, in the same arm, every field that answers "do I trust this peer":
`server_pubkey`, `server_pubkey2` (`cfg.h:354-358`), the webpki anchors and
hostname, `require_pq`, and the client's PSK-offer fields. Setting any of them
is `CH_EINVAL` from `ch_srv_accept`, the same fail-closed shape `TRUST=webpki`
already uses for the pin fields.

`cfg.buf`, `cfg.buf_len`, `cfg.send`, `cfg.recv` and `cfg.io` stay exactly as
they are, so the integrator's I/O contract does not change and `CLAUDE.md:7-9`
survives word for word. Accepting the connection is the caller's, as connecting
is for a client.

A private key stays a pointer and is never copied into `ch_tls`. Copying it and
wiping at close would put a second copy of a deployment-lifetime secret in SRAM
and buy nothing, because the original outlives every wipe. This is INV-31.

### What `ch_tls` gains and drops

The session keeps the name `ch_tls`. It is a TLS session, and one name per
thing. A second `ch_srv` type would fork `record.c`, `handshake_record.c`,
`ch_read`, `ch_write`, `ch_close`, `tlsi_wipe` and `tlsi_fail` behind it, to
share nothing.

Gains, with the sizes the RFC or the tree already fixes:

```c
uint8_t  session_id[32];  // legacy_session_id_echo (rfc9846.txt:1365-1368),
uint8_t  session_id_len;  // and it must survive the retry (rfc9846.txt:1451)
uint16_t suite;           // the selected cipher suite; the client's is a
                          // compile-time literal at handshake_message.c:44
uint8_t  hash_len;        // 32 or 48, fixed by suite (rfc9846.txt:4055-4056)
uint16_t sigalg;          // the scheme the CertificateVerify will carry
uint8_t  hrr_sent;        // at most one; see "The state machine"
uint8_t  compat_ccs;      // the client sent a non-empty session id, so one
                          // dummy CCS record is owed (rfc9846.txt:6401-6403)
```

40 bytes before padding, derived from the field widths. `group` already exists
and already holds the selected group (`session.h:137`). `alpn_selected` already
exists under `CH_TRUST_WEBPKI` and `CH_TRANSPORT_QUIC` (`session.h:152`) and a
server build declares it in every mode.

Drops: `pin_slot` (`session.h:128`), `epoch`, `epoch_store_failed`,
`epoch_seen` and `epoch_status` (`session.h:157-163`). All five answer a
question a server that requests no client certificate never asks.

`rec_dir` gains one byte under the server arm so the three suites can share it.
`record.h:24` already declares `key[AEAD_KEY]` at 32 bytes, which holds
AES-128's 16 and AES-256's 32, and `sizeof(rec_dir)` is **56** today, measured.

**The size of a server `ch_tls` is unmeasured.** The struct does not exist. The
hash-agile session is measured above at 1,296 arm64 and 1,224 rv32, and a
server's own fields move it again in both directions. What is otherwise
measured is the client's, under `cc -Os -std=c11 -I. -DCH_RAND_EXTERN` at
`bed7456`:

    sizeof(ch_tls)=1144  sizeof(ch_cfg)=152  sizeof(rec_dir)=56
    offsetof(ch_tls,tx)=520  CH_TX_STAGE=617  CH_TX_PT=512
    CH_MIN_RXBUF=512  HSP_COOKIE_MAX=128
    AEAD_KEY=32 AEAD_NONCE=12 AEAD_TAG=16 REC_HDR=5 REC_OVERHEAD=22

## The state machine

`srv_handshake.c` calls the flight handlers in one straight line, so INV-22's
mechanism sentence — "There is no state variable to desynchronize; the order is
the call order" (`docs/invariants.md:776-782`) — holds for the server as it
holds for the client.

```c
// srv_handshake.c. Each rc line below is `if (rc != CH_OK) return rc;`.
static int hello_exchange(handshake_state *h, client_hello *ch, selection *sel) {
    srv_begin(h);                                  /* transcript, randoms */
    rc = srv_read_client_hello(h, ch);
    rc = srv_select(h, ch, sel);                   /* suite, hash, group, sigalg */
    if (sel->need_retry) {
        rc = srv_send_hello_retry_request(h, ch, sel);
        rc = srv_send_compat_ccs(h, ch);           /* the first message was the HRR */
        rc = srv_read_client_hello(h, ch);         /* the second and last */
        rc = srv_check_retry_hello(h, ch, sel);    /* cookie in, transcript restarted */
        rc = srv_send_server_hello(h, ch, sel);
    } else {
        rc = srv_send_server_hello(h, ch, sel);
        rc = srv_send_compat_ccs(h, ch);           /* the first message was the SH */
    }
    return srv_derive_handshake_secrets(h, ch, sel);
}

static int auth_flight(handshake_state *h, const selection *sel) {
    rc = srv_send_encrypted_extensions(h, sel);
    if (!sel->psk_selected) {
        rc = srv_send_certificate(h, sel);
        rc = srv_send_certificate_verify(h, sel);
    }
    return srv_send_finished(h);                   /* the write direction advances */
}

static int run(handshake_state *h) {
    rc = hello_exchange(h, &ch, &sel);
    rc = auth_flight(h, &sel);
    rc = srv_read_client_finished(h);              /* still under the handshake key */
    srv_complete(h);                               /* the read direction advances */
    return CH_OK;
}
```

**`srv_select` sets `sel->need_retry` when both halves hold: the client's
`supported_groups` names the group this build holds, and the client's
`key_share` carries no `KeyShareEntry` for that group.** The second round of
this record specified the whole HelloRetryRequest mechanism and never stated
that condition. `rfc9846.txt:1158-1161` makes it a MUST — "If the server selects
an asymmetric key exchange group and the client did not offer a compatible
'key_share' extension in the initial ClientHello, the server MUST respond with a
HelloRetryRequest" — and `rfc9846.txt:1446-1449` states the same condition in
general terms. The two halves are exactly the two checks the client runs on
`selected_group` in reply (`rfc9846.txt:2205-2212`), so a server that sets the
value any other way sends a HelloRetryRequest the client aborts with
`illegal_parameter`.

The common input is the empty share list §9.2 permits: `rfc9846.txt:4599-4601`
reads "If containing a 'supported_groups' extension, it MUST also contain a
'key_share' extension, and vice versa. An empty KeyShare.client_shares list is
permitted." So a client that sends `supported_groups` and an empty `key_share`
is strictly conformant and forces one round trip. When the first half fails
instead — no group in `supported_groups` that this build holds — there is
nothing to retry and the answer is `handshake_failure`
(`rfc9846.txt:1145-1148`). `sel->need_retry` is therefore never set on a second
ClientHello: `srv_check_retry_hello` is the only reader after the first, and the
state machine has one retry by call position.

`ch_srv_accept` wraps `run` the way `ch_handshake` wraps its own
(`handshake.c:372-395`): zero the state, call, take `h->alert`, `ct_wipe` the
state, fail the session on any error.

The split into three functions is not decoration. `.clang-tidy:98` sets
`readability-function-cognitive-complexity.Threshold: '15'`, and each
`if (rc != CH_OK) return rc;` at the top level counts one. The sketch above has
fifteen of them plus two branches, so a single `run()` over all of it reaches
the threshold on the return checks alone and fails `make lint-tidy`. The exact
number is **unmeasured** until the code exists, and it does not need to be: the
split is forced rather than chosen. The client already splits for the same
reason — `hello_exchange`
(`handshake.c:205`), `hsa_server_auth` and `expect_finished`
(`handshake.c:160`) — and INV-22's mechanism sentence names those three
functions, not one. So the server's three are the same shape, and the order is
still the call order.

**The dummy `change_cipher_spec` follows whichever message the server wrote
first, and that is why it has two call sites.** Appendix E.4 is explicit:

    rfc9846.txt:6391    *  The server sends a dummy change_cipher_spec record immediately
    rfc9846.txt:6392       after its first handshake message.  This may either be after a
    rfc9846.txt:6393       ServerHello or a HelloRetryRequest.

and `rfc9846.txt:6401-6403` turns the appendix into a MUST once the client sent
a non-empty session id. A single call after `srv_send_server_hello` would land
the record after the server's second handshake message on the retry path, and
after the client had already sent its second ClientHello. Two call sites, one
flag-free condition each, keep it a straight line.

Three more points in that order deserve their own sentences.

**A second HelloRetryRequest is unreachable by call position, and no RFC
sentence forbids the server from sending one.** `rfc9846.txt:1469-1472` is a
client receipt obligation: "If a client receives a second HelloRetryRequest in
the same connection ... it MUST abort the handshake with an
'unexpected_message' alert." Searching §4.2.4 (`rfc9846.txt:1444-1500`) for a
server-side limit returns none; the nearest server sentence is
`rfc9846.txt:1158-1161`, which requires sending one and says nothing about a
second. So the argument is about consequences, not obligations: a server that
sent a second HelloRetryRequest would fail every conformant client, and there is
no third call site from which to send one.

**The two directions advance at different points, and this is the one place the
server's flight is not a mirror of the client's.** The client changes both
directions at once:

    handshake.c:364    rec_dir_init(&t->rd, t->rd_secret);
    handshake.c:365    rec_dir_init(&t->wr, t->wr_secret);

The server cannot: it must still read the client Finished under the handshake
key. So `srv_send_finished` installs the application write key and
`srv_complete` installs the application read key, and a server that advanced
both in one place would fail every handshake. Four lines make the difference
visible instead of a flag hiding it.

**The server does not send application data before the client's Finished.**
`rfc9846.txt:3127-3130` permits it and says the server then has no assurance of
the peer's identity or liveness. `ch_write` before `ch_srv_accept` returns is
not reachable through this API. Refusing the permission costs nothing and
removes a state.

### The direction swap, in three lines

`keysched.h` declares **six** functions, not five: `ks_early` (`:14`),
`ks_verify_data` (`:18`), `ks_handshake` (`:23`), `ks_master` (`:29`),
`ks_res_master` (`:34`) and `ks_res_psk` (`:36`). The server calls all six:
the last two issue a ticket after the client Finished, and `ks_early` takes a
ticket's PSK when a handshake resumes one ("Resumption" below).

No function assumes which side the caller is on. Two of them name the sides in
their parameter order, and that ordering is the whole asymmetry:
`ks_handshake` writes `c_hs` then `s_hs` (`keysched.h:24-25`) and `ks_master`
writes `c_ap` then `s_ap` (`keysched.h:29-30`). The client binds them:

    handshake.c:309    rec_dir_init(&t->rd, h->s_hs);
    handshake.c:310    rec_dir_init(&t->wr, h->c_hs);
    handshake.c:357    ks_master(h->handshake_secret, hash, h->master, t->wr_secret, t->rd_secret);

The server writes `REC_DIR_INIT_SUITE(&t->wr, h->s_hs, sel->suite)` and
`REC_DIR_INIT_SUITE(&t->rd, h->c_hs, sel->suite)`, and passes `t->rd_secret` where
`ks_master` takes `c_ap` and `t->wr_secret` where it takes `s_ap`. The two
comments at `session.h:101-102` are rewritten in the server arm.

Nothing in INV-10 says which assignment is correct, so a server that swapped
them would pass every check in the tree today. "Verification owed" lands a
mutant for exactly that.

### The Certificate message is streamed

A chain is the caller's size, not the build's, so staging it whole would put
the operator's certificate inside `sizeof(ch_tls)`. `srv_send_certificate`
walks the selected identity's `chain`, writes the message header and the
`certificate_list` framing, and emits the message in fragments, each sized to
`min(CH_TX_PT, peer_limit)`, feeding the transcript hash as it goes and sealing
each fragment as its own record through `rec_seal`. `rfc9846.txt:3460-3462`
permits the fragmentation and forbids interleaving another record type, which a
straight-line writer cannot do.

`store_selection` (`srv_handshake.c`) writes the client's `record_size_limit`
into `peer_limit` only when it is smaller than the `CH_TX_PT` the driver
seeded, so `peer_limit` is already at or below this build's own cap and the
`min` above restates that bound rather than establishing it. The client lowers
its own the same way (`handshake_parser.c:233`). A send site that reads
`peer_limit` alone is therefore correct, which is what keeps the staging array
below the size derived next.

So a server's staging array is one sealed record: `CH_TX_PT + 1 + AEAD_TAG` =
512 + 1 + 16 = **529 bytes** (derived from the measured constants above),
against the client's measured `CH_TX_STAGE` of 617. The Certificate costs the
session nothing whatever the chain's size.

The rejected alternative is a scatter-gather `rec_seal` that seals a header
stage plus the caller's chain pointer without copying. It is what a tighter
server would want, and it is a second sealing entry point, which is exactly
what INV-1's mechanism sentence exists to prevent. If the copy turns out to
cost too much, that is the change to make, and it should be made by amending
INV-1 deliberately.

### The cookie

`rfc9846.txt:4560` makes the `cookie` extension mandatory to implement.
`rfc9846.txt:1779-1783` says a stateless server stores `Hash(ClientHello1)` in
it under integrity protection, and `rfc9846.txt:1084-1087` says the synthetic
transcript exists so that hash is all the server must keep.

```
body   = version(1) || suite(2) || group(2) || Hash(ClientHello1)(hash_len)
         || Hash(frozen fields)(32)
cookie = body || HMAC-SHA-256(cfg.cookie_key, body)(32)
```

101 bytes with a SHA-256 suite and 117 with SHA-384, derived from the field
widths. Both fit inside `HSP_COOKIE_MAX`, measured at **128**
(`handshake_parser.h:19`), and `handshake_state` already carries
`uint8_t cookie[HSP_COOKIE_MAX]` (`handshake_record.h:54`), so the field costs
nothing new. `hmac` (`hkdf.h:13`) supplies the integrity protection, called with
`SHA256_LEN`.

**The suite is in the cookie because a HelloRetryRequest carries one.**
`rfc9846.txt:1449-1452` says the HelloRetryRequest "has the same format as a
ServerHello message, and the legacy_version, legacy_session_id_echo,
cipher_suite, and legacy_compression_method fields have the same meaning." The
first draft of this record said the rebuild's inputs were "the only variable
fields in the message", and with three suites that is false. Two bytes in the
cookie body close it, and they also fix the length of the `Hash(ClientHello1)`
term that follows, which the hash cannot do for itself.

The group is in the cookie because the retry transcript is
`Hash(message_hash || 00 00 len || Hash(CH1)) || HRR || CH2`, so the server must
hash HelloRetryRequest bytes it wrote and no longer holds. It rebuilds them
from the second ClientHello's `legacy_session_id`, the cookie's suite and
group, and the cookie itself, which the client echoed.

The second digest is SHA-256 over only the ClientHello fields
`rfc9846.txt:1191-1206` forbids the client to change, computed during the
first parse: the head, `legacy_version` through
`legacy_compression_methods`, and then each extension except key_share,
early_data, cookie, pre_shared_key and padding, whole, from its type through
its body. The extensions go into the hash in ascending type order, not in the
order the client sent them (`add_frozen_extensions`, `srv_parser.c`), so a
second hello that carries the same extensions in another order has the same
digest. RFC 9846 §4.3 lets extensions appear in any order
(`rfc9846.txt:1669-1670`), and ngtcp2's interop client reorders them on its
second hello; `docs/decisions.md` entry 59 gives the construction, why the
parser's refusal of a second extension of one type is what makes it sound,
and what the walk costs. On the second ClientHello the server recomputes the
digest and compares with `ct_memeq`, which is how it checks the freeze rule
without storing the first hello. The MAC is compared with `ct_memeq` over all 32 bytes; a mismatch
is `illegal_parameter`, because a cookie the server did not mint is a
semantically invalid field (`rfc9846.txt:3947`).

`hrr_transcript` (`handshake.c:117-125`) already builds the §4.1 synthetic
message and is exactly what the server needs with its own bytes in `raw`. It
moves to a file both roles compile rather than being duplicated, so one
construction of a rule the RFC states once exists once. Its `SHA256_LEN`
literals become `hash_len` with the schedule.

## What is reused

Most of the work. Each row was read at the line given.

| Module | What a server does with it |
|---|---|
| `ct.[ch]`, `buf.[ch]`, `sha256.[ch]` | Unchanged. |
| `sha512.[ch]`, `sha512_compress.[ch]` | Packaged rather than rewritten. `sha384_init` (`sha512.h:32`), `sha512_update` (`:33`) and `sha384_final` (`:41`) are the streaming shape the transcript needs. Two sentences of the header's comment become false; see "The cost that dominates". |
| `hkdf.[ch]` | Hash-agile. Five declarations change, and `hmac_sha256` is renamed `hmac`, because a function that computes HMAC-SHA-384 when it is handed 48 must not be called `hmac_sha256`. It also serves the cookie MAC and the RFC 6979 nonce, which pass `SHA256_LEN` and get the same computation they get today. |
| `keysched.[ch]` | Six functions, all of which the server calls: the last two issue its tickets ("Resumption"). All six change signature with the hash. No function assumes a side; `ks_handshake` and `ks_master` name client before server in their parameter order, which is the whole asymmetry. |
| `record.[ch]` | Unchanged as control flow; the suite and the hash length appear in three lines. `rec_dir_init` derives `AEAD_KEY` bytes at `record.c:7`, and `rec_seal` and `rec_open` call the ChaCha20-Poly1305 functions by name at `record.c:56` and `record.c:82`. |
| `chacha20.[ch]`, `poly1305.[ch]`, `aead.[ch]` | Unchanged, and not enough: `rfc9846.txt:4540` requires AES-128-GCM beside them and `:4542` makes AES-256-GCM a SHOULD the scope takes. |
| `x25519.[ch]` | Unchanged and symmetric. The client's all-zero refusal (`handshake.c:300`) is the check a server makes too. |
| `mlkem.[ch]` | Reused as it stood. `srv_kex.c` calls `mlkem_encaps_derand` (`mlkem.h:40`), which already had known-answer vectors and a CBMC harness. The function takes its 32-byte message `m` from the caller, so a server that selects the hybrid draws it through `ch_rand_bytes`, which is INV-4's eighth site ("Key exchange" below). |
| `handshake_record.[ch]` | Reusable. `accept_record` decrypts with `t->rd` (`handshake_record.c:35`), which is already the read direction. The ChangeCipherSpec tolerance at `handshake_record.c:53-58` is what `rfc9846.txt:1793-1797` requires of a stateless server, already written and already capped at four. |
| the CertificateVerify signed content | **Moved, then reused.** See below. |
| `handshake_post.[ch]` | A role arm. A server receives no NewSessionTicket and may write them; KeyUpdate receipt and the one-response rule are the same in both directions. |
| `p256.c` | One call, `p256_ecdsa_verify` (`p256.h:16`), from `ch_srv_check`. Point validation is *not* one of them; `on_curve` is static (`p256.c:295`) and `p256_ecdh.c` does its own. |
| `rsa.[ch]`, `rsa_mont.c` | One call, `rsa_pss_verify` (`rsa.h:34`), from `ch_srv_check`. The signing arithmetic shares none of it. |
| `x509*.[ch]`, `webpki*.[ch]`, `pem.[ch]`, `rsa_pkcs1.[ch]` | None of them. A server that sends opaque DER and requests no client certificate links no certificate reader and no certificate-signature verifier. |

**The signed-content builder is moved, not reused where it sits.** The first
draft of this record called it reuse and it is not, for three reasons.
`handshake_auth.c` is in `CLIENT_REPLACED`, so a server object never compiles
it. The named function `hash_signed_content` at `handshake_auth.c:42` sits
inside `#ifdef CH_TRUST_WEBPKI` (opened at `:35`, closed at `:91`), and
`ROLE=server` errors on `TRUST=webpki`, so under every server build that block
is preprocessed away. And in the non-webpki path there is no function at all:
`handshake_auth.c:132-143` builds the 64 spaces, the context string, the NUL
and the transcript hash inline in the middle of another function's body.
`grep -rn 'server CertificateVerify' --include='*.c' --include='*.h' .` returns
four copies already — `handshake_auth.c:44`, `handshake_auth.c:134`,
`bench/insn_driver.c:69` and `test/rfc8448_tests.h:90` — and none is exported.
So the builder moves to a file both roles compile, with one construction of a
rule the RFC states once, and the table row says "moved, then reused". It is
the same treatment `hrr_transcript` gets above.

The moved builder takes one parameter more than the client's. The client's
`hash_signed_content` at `handshake_auth.c:42` takes the SignatureScheme, the
transcript hash at a fixed `SHA256_LEN`, and the output buffer; the length is
fixed in the parameter's type because a client that offers one suite has one
transcript length. A server whose selected suite may be SHA-384 cannot fix it
there, so the moved builder takes that length as its own parameter, for the
reason "The CertificateVerify signature uses two different hashes" gives: the
suite fixes the transcript hash going in, and the SignatureScheme fixes the hash
run over the assembled content. It writes 32 bytes for both schemes this server
offers. A builder that read only one length would be the conflation that
produces an unverifiable CertificateVerify.

`record.[ch]` gains the suite under the server arm alone:

```c
#define REC_SUITE_CHACHA20   0
#define REC_SUITE_AES128GCM  1
#define REC_SUITE_AES256GCM  2
typedef struct {
    uint8_t key[AEAD_KEY];
    uint8_t iv[AEAD_NONCE];
#ifdef CH_ROLE_SERVER
    uint8_t suite;
#endif
    uint64_t seq;
} rec_dir;
void rec_dir_init(rec_dir *d, const uint8_t *secret, size_t hash_len, uint8_t suite);
```

A client object compiles the file it compiles today, with no suite field and no
suite branch, so INV-7's "absence of selection code" stays literally true
there. Inside the server arm the derived key length becomes 16 or `AEAD_KEY`,
and `rec_seal` and `rec_open` each branch once on `d->suite`.

That branch reads a public value — the suite the ServerHello announced in the
clear — so it is not a constant-time defect. INV-16 requires variable time to
be stated at the call site (`docs/invariants.md:654-656`), and the comment at
each branch names the value it reads and why that value is public.

No buffer bound moves. `AEAD_NONCE` is 12 and `AEAD_TAG` is 16, measured, and
`GCM_TAG` is 16 (`quic_gcm.h:22`) with a 96-bit nonce, so `REC_OVERHEAD` stays
at the measured 22 and the nonce construction of `rfc9846.txt:3670-3679` is the
same for all three suites.

One new send-side rule arrives with GCM. `rfc9846.txt:3743-3744` requires
closing or rekeying before the key-usage limit, and `rfc9846.txt:3750-3751`
gives AES-GCM's as "up to 2^24.5 full-size records (about 24 million)" — a
limit ChaCha20-Poly1305 never made anyone think about. `rec_seal` gains a
per-suite ceiling beside its existing wrap guard at `record.c:33`, and the
session rekeys with `rec_dir_update` before that count.
`rfc9846.txt:3747-3748` is explicit that the limit is not enforced on receipt.

## Considered and rejected

### A runtime role flag rather than a build axis

Rejected. A device carries one role for the life of the deployment, so both
roles in one object doubles the flash a firmware links for no gain. It also
makes `lint-stack` measure frames a build never reaches: `Makefile:1500`
compiles every library source at `-Wframe-larger-than=$(STACK_BUDGET)`, and a
client image would have to fit the server's signing frame. And it reintroduces
exactly the runtime selection INV-7 exists to forbid.

### A second library object built from its own source list

Rejected. It duplicates machinery the Makefile already applies once per axis,
and it has no define to preprocess against, so no check can prove client-only
text stayed out of a shared file. The partition section states this in full.

### Streaming the ClientHello through a bounded window

A competing design consumes the ClientHello as a byte stream through a
136-byte window, never materializing the message, so the receive buffer stops
depending on the ClientHello's size at all. It is the only answer that meets
the strict scope on a 512-byte device, and it is genuinely the better result.

Rejected for v1, and named as the follow-on rather than discarded. Three
reasons. It makes the parser something other than a pure function over one
caller buffer, which is the shape every existing parser harness and INV-25's
exact-fill rule depend on (`handshake_parser.c:119`). It puts new refill
machinery in front of unauthenticated attacker-controlled bytes that arrive
before any key exists, which is the largest new attack surface any of the three
designs proposed. And its own author records the window harness as the hardest
new proof in the design, with convergence unmeasured and the buffered parser as
the fallback — which is this design. Building the fallback first and the
optimization second costs nothing, because the parser above the window does not
change shape either way.

**The bound is therefore the caller's buffer, stated rather than hidden.** Under
`ROLE=server` the ceiling at `handshake_record.c:119` becomes
`t->cfg.buf_len - REC_HDR` rather than the literal 0x4000, with a floor
`CH_SRV_MIN_RXBUF` asserted the way `CH_MIN_RXBUF` is at `cfg.h:149`. A host
caller that passes a 64 KB buffer accepts every legal ClientHello and meets the
scope exactly. A device caller that passes less meets it up to its buffer, and
the README must say so in the same sentence that states the scope. A
ClientHello larger than the buffer dies with `CH_ECAP` and an `internal_error`
alert (80), because the RFC defines no "too large" alert and 80 is the honest
one for a local limit: `rfc9846.txt:3979-3981` defines it as an error unrelated
to the correctness of the protocol, which a buffer size is.

### One signing identity, with the §9.1 shortfall stated

Rejected under the widened scope, and it was this record's v1 answer before the
scope widened. §9.1 names `rsa_pss_rsae_sha256` "(for CertificateVerify and
certificates)" at `rfc9846.txt:4546-4547`. A build holding only
`ecdsa_secp256r1_sha256` does not meet §9.1 for that message, whatever identity
the operator provisioned, so the shortfall is in the code rather than in the
deployment. Holding both costs the whole `rsa_sign.c` lane, and "Where the
cryptography lives" prices it. Open question three asks what a one-certificate
deployment builds.

### Keeping the table-driven AES and stating a threat model

Rejected. "AES-GCM becomes a cipher suite carrying user data, in two key sizes"
gives the reason.

### A `HASH=sha256` axis that drops `TLS_AES_256_GCM_SHA384`

Rejected. It would remove the largest cost in the role, and it would put the
server back in the position §9.1 puts a one-identity server: refusing a
conformant client whose offer this build cannot meet. The scope Camilo set is
the reason, and the cost is stated in full at the top of this document so the
trade can be reopened with numbers rather than impressions.

## Bounds that need measuring

Every row is a number a command must produce before the code it describes
lands. None of them exists today.

| Bound | Who measures it | Why it matters |
|---|---|---|
| `sizeof(ch_tls)`, `sizeof(ch_cfg)` and `CH_TX_STAGE` for a server | `bench/sram.sh` with a server row | `README.md:126-142` is a table `make lint-bench-numbers` holds against `bench/results-sram.csv`, and it has no server row. The hash-agile client numbers are measured above; the server's are not. |
| `CH_SRV_MIN_RXBUF` | the same run, once the parser and the builders exist | It is the smallest ClientHello this server can serve plus the largest message it sends. |
| The widening-multiply ceiling of each of the sixteen files the codegen partition gains or moves | `make lint-wide-multiply`, per compiler, in the `WIDEMUL_CEILING_SPEC` shape (`Makefile:2230`) | `make lint-codegen-partition` fails any library source in neither list (`Makefile:2054`), so none of the sixteen can land without a list. It checks list membership and nothing about the numbers; the ceiling is what `lint-wide-multiply` measures. |
| The conditional-branch ceiling of the seven files that also join `BRANCH_SRCS`: `aes.c`, `gcm.c`, `p256_field.c`, `p256_ecdh.c`, `rsa_sign.c`, `sha512.c`, `sha512_compress.c` | `make lint-wide-multiply`, `make lint-wide-multiply-gcc`, `test/docker-mips.sh` and `test/docker-riscv32.sh`, in the `BRANCH_CEILING` shape (`Makefile:2253`) | The branch count runs only for files on `BRANCH_SRCS` (`Makefile:2335`). Eight `WIDEMUL_SPECS` rows times seven files is fifty-six numbers, four rows of them through the two Docker scripts. Without them no check fails when a signer's arithmetic branches on the nonce, and none fails when the SHA-384 key schedule branches on a secret block. Four of the fifty-six are measured already: `sha512.c` 23 and `sha512_compress.c` 4 on `rv32imac`, 24 and 4 on `m3`. |
| The eight `BRANCH_CEILING` entries `hkdf.c` already has, re-measured | the same four commands | `hkdf.c` is already on `BRANCH_SRCS` and the hash-agile HMAC adds branches to it. It sits exactly at its recorded entry on both specs measured here: 14 on `rv32imac` against `rv32imac/hkdf.c:14` (`Makefile:2259`) and 13 on `m3` against `m3/hkdf.c:13` (`Makefile:2254`). Going over fails at `Makefile:2341-2342`, so the landing commit fails `make lint-wide-multiply` until all eight entries move. It is the only file already under a ceiling whose count this design changes; `keysched.c`, `record.c` and `session.h` are the other shared files it edits and none of the three is on `BRANCH_SRCS`. |
| The stack frame of the P-256 ladder, of ECDSA signing, and of RSA-PSS signing | `make lint-stack` | INV-19 fixes a frame budget per build (`docs/invariants.md:835`) and `Makefile:1500` compiles at `-Wframe-larger-than=$(STACK_BUDGET)`, so a miss is a compile failure. `README.md:135` gives 4,992 bytes for an RSA-3072 *verify* as the only nearby figure. |
| The stack frame of a hash-agile `hmac` | `make lint-stack` | Measured at 544 bytes for the one-function form and 528 for the split, against today's 304 (arm64, `-O2`, `-fstack-usage`). The row stays because the number that matters is the one the landing commit's own compiler prints. |
| The stack frame of `srv_handshake`'s equivalent of `ch_handshake` | the same | `ch_handshake` measures 688 today and 784 hash-agile against a 2560-byte budget. A server holds a `client_hello` and a `selection` in the same frame, and neither struct exists yet. |
| Code size and speed of a constant-time AES, bitsliced and masked, at both key sizes, on rv32 | `bench/insn_driver.c` and `bench/sram.sh` | It decides which one to write, and whether a server fits the target at all. |
| The per-record cost of AES key expansion against stored round keys | the same | One AES-256 round-key array is 15 x 16 = 240 bytes and the struct that holds it measures 241; two of them are 482, against a measured client `ch_tls` of 1,144. v1 stores the key and expands per record, because SRAM is the scarce resource; `CH_AES_KEY_SCHEDULE_CACHED` trades those bytes back. Which default is right is **unmeasured**. |
| Whether a `TRANSPORT=quic` build without `ROLE=server` carries the 15-round schedule | `make lint-stack TRANSPORT=quic` | Measured: one `aes_public_key` bundle goes 364 to 494 bytes. Since INV-26 `ch_quic` stores no bundle, so the cost is 130 bytes of stack in each call that builds a key, against a 2,560-byte budget, and no SRAM. The two ways out are a build-conditional `CH_AES_ROUND_KEYS` and a separate 11-round QUIC type, and neither is measured. |
| Every new and every re-aimed CBMC launch line, including the eight the hash change touches | `/usr/bin/time -v` under `proof/run.sh`'s exact flags | `docs/proofs.md` requires the measurement before a launch line may be committed. `record` already stands at 830 s and 3.0 GB (`proof/run.sh:503`) against the fast pool's slowest harness at 1,034 s (`proof/run.sh:505`). |
| The CI matrix cost of a sixth axis | a CI run | **Unmeasured.** |

## What the mode does not check, and why that is safe

- **The client's identity.** It sends no CertificateRequest, so no client
  certificate arrives and it reaches no verdict about the peer.
  `rfc9846.txt:2675-2676` makes requesting one a MAY. This is safe because the
  application above the session authenticates its users, and unsafe if an
  integrator believes TLS did it. A server object links no `x509*.c`, no
  `pem.c`, no `webpki*.c` and no `rsa_pkcs1.c`, which is what keeps INV-5's
  "exactly one certificate verifier" true.
- **Its own chain.** The bytes go out unread. A chain that is malformed,
  expired, wrongly ordered, or whose end-entity key is not the provisioned
  private key produces a handshake every client rejects; that is a provisioning
  error, and `ch_srv_check` catches the signer half of it at boot.
  `rfc9846.txt:2921-2926` and `:1931-1933` are provisioning checks, not runtime
  ones, when the identity is fixed at build time.
- **Time.** It reads no clock. It verifies no certificate validity, and the
  cookie carries no timestamp. The one instant it uses is the caller's:
  `ch_cfg.srv.now_seconds`, which dates the tickets it issues and judges
  the ones it is offered. A caller that leaves it 0 gets no tickets at all
  ("Resumption" below).
- **Cookie freshness.** A captured cookie is replayable. The attacker gains one
  skipped round trip on a handshake that fails at the Finished regardless. A
  4-byte caller-supplied epoch in the cookie body would close it and is
  available as an option; the default keeps the server free of a clock.
- **The `server_name` contents.** Parsed, bounds-checked, copied to the
  caller's buffer, and never used to select a certificate, because the identity
  is selected by signature scheme rather than by name.
  `rfc9846.txt:2943-2946` makes SNI-guided selection the reason for the
  extension; a server with one identity per scheme has nothing further to
  select.
- **Early data, and this one needs the argument stated in full.** §4.3.10 at
  `rfc9846.txt:2338-2339` says a client may send early data "When a PSK is used
  and early data is allowed for that PSK". Permission comes from the PSK, and
  for an *external* PSK that permission is provisioned on the client, not
  granted by this server. So a strictly conformant client holding an external
  PSK that allows early data may offer that PSK here and stream 0-RTT
  `application_data` records behind its ClientHello, whatever this server has
  ever issued. The first draft of this record argued the case away and it does
  not go away.

  The server takes the first of the three behaviors `rfc9846.txt:2385-2394`
  permits, and that behavior comes with an obligation: "The server then skips
  past early data by attempting to deprotect received records using the
  handshake traffic key, discarding records which fail deprotection (up to the
  configured max_early_data_size)." The tree's reader does not discard today.
  With `h->encrypted` set, `handshake_record.c:30` accepts an outer
  `REC_APPDATA`, calls `rec_open`, and on failure does this:

        handshake_record.c:37        h->alert = ALERT_BAD_RECORD_MAC;
        handshake_record.c:38        return CH_EAUTH;

  So a server build gives `handshake_record.c` a role arm with an explicit
  discard budget: while the client Finished has not arrived and
  `ch.early_data_offered` is set, a record that fails `rec_open` is dropped and
  counted, and the session fails once the count or the byte total passes
  `CH_SRV_MAX_EARLY_DISCARD`. On the HelloRetryRequest path
  `rfc9846.txt:2399-2401` allows the cheaper rule the first draft named: skip
  every record whose outer type is `application_data` by its length, without
  decrypting. Both budgets are build constants and both are **unmeasured**.
- **Subgroup membership of a P-256 peer point.** `rfc9846.txt:2277-2286`
  requires three checks and not that one; the curve's cofactor is 1.
- **The AEAD key-usage limit on receipt.** `rfc9846.txt:3747-3748` is a
  send-side rule and the RFC says not to enforce it on receipt.

## Verification owed

`CLAUDE.md:105-116` makes proofs mandatory and a change unfinished until
`check-slow` passes. This section is the bill. The inner loop runs only touched
harnesses through `PROVE_ONLY`; the full tier stays in `check-slow` and the
nightly.

### CBMC harnesses

Written by `docs/proofs.md`: split along the multiply count, store nondet values
through the object's own type, havoc every operand before every call, cover the
aliasing shapes real callers use, and measure each launch line with
`/usr/bin/time -v` under `run.sh`'s exact flags before committing it.

| Harness | Proves | Expected difficulty |
|---|---|---|
| `srv_parser_harness.c` | the ClientHello parser is memory-safe and free of UB over unconstrained bytes at the real bound, and skips every unknown extension by its length | likely splits into a message harness and an extension harness; the extension loop is the cost |
| `srv_message_harness.c` | the seven builders never write past `cap` and report a short buffer rather than truncating | should converge; the `wbuf` harnesses are the precedent |
| `srv_cookie_harness.c` | mint and open round-trip at both hash lengths, and a flipped bit never opens | small |
| `srv_flight_harness.c` | every non-`CH_OK` return from a handler writes an alert first | small |
| `p256_ecdh_harness.c` | point validation, the field arithmetic and the ladder | **expect no verdict without stub contracts.** `proof/p256_harness.c:11-20` already refuses to unwind `point_mul` and `mod_inv` ("25k+ Montgomery multiplies never leave symex"), and `README.md:380-389` records x25519's ladder returning "no verdict past 14 GB" until `proof/x25519_stubs.h` replaced the widening multiply with a contract |
| `p256_sign_harness.c` | the RFC 6979 generator over a stubbed HMAC, and the DER writer's bounds | the `hkdf_expand_harness` shape. The generator's retry loop has no fixed trip count, so the unwind bound needs its own argument |
| `rsa_sign_harness.c` | the private exponentiation's bounds and the PSS encoder | written and launched: the marshalling and every limb helper at 96 limbs, the mask, the exponent index, the encoder whole over a stubbed SHA-256, and the `rsa_mul_harness` carry lemma. *Measured* (cbmc 6.11.0, kissat, `/usr/bin/time -l`): 759 properties, 7 s, 194 MB |
| `aes_harness.c` | the constant-time AES against its spec, at both key sizes | the table version converges at 377 properties, 23 s, 0.67 GB (`gcm.patch:910`); the constant-time version is **unmeasured** |
| `gcm_harness.c`, `gcm_forge_harness.c` | GCM seal and open, and that a forged tag opens nothing | **measured as failing today**: 2,144 s under kissat with no verdict, and the forge harness at 2.6 GB and climbing (`gcm.patch:917-918`). The split is unattempted and is on this design's critical path |

Eight existing harnesses are re-aimed rather than written, because the key
schedule's secrets change length: `keysched`, `hkdf`, `hkdf_expand`,
`hkdf_expand_label`, `record`, `handshake`, `handshake_post` and
`handshake_record`. `proof/harness.h:55-64` gains SHA-384 stubs beside its
`sha256_final` and `sha256_of` ones. Every one of the eight launch lines gets
re-measured.

### Lean specs

`ls spec/lean/Spec/` returns 30 modules and none models the client-to-server
direction: `spec/lean/Spec/Handshake.lean:4` models "server-to-client messages after
the ClientHello".

- `Spec/Hkdf.lean` — rewritten, not added. `blockSize` (`:13`) and `hashLen`
  (`:16`) become parameters, six definitions take them, and five theorem
  statements stop asserting a constant 32. `Spec/Record.lean`'s
  `nextSecret_size` follows.
- `Spec/ClientHello.lean` — the parser's admitted shapes and its ignore-unknown
  rule, the mirror of `Spec/HandshakeParser.lean`.
- `Spec/ServerHandshake.lean` — the mirror of theorem 17: which client message
  orders the server accepts. The evidence for INV-30.
- `Spec/Rfc6979.lean` — the nonce derivation, one of the two genuinely new
  crypto modules. `Spec/P256.lean:82` already defines `ecdsaSign` and
  `:156-161` already proves `ecdsaVerify_ecdsaSign`.
- `Spec/RsaPss.lean` — the signing side of PSS. `Spec/Rsa.lean` models the
  verify side today.
- `Spec/Aes.lean` and `Spec/Gcm.lean` arrive with the renamed patch.

`spec/lean/CONTRACT.md`'s "Writing proofs here" section governs, including the second
pass that shrinks a green proof's script with the statement frozen.

### Tests

- Unit vectors: the RFC 8448 traces use AES-128-GCM, and `README.md:344-347`
  today says the replay "stops at secrets and MACs and never opens a record"
  because "those traces use AES-128-GCM, which chapulin excludes". That reason
  disappears with this role, so the replay opens records or the sentence gives
  a different reason. SHA-384 key schedule vectors and AES-256-GCM vectors
  arrive with the suite. RFC 6979 §A.2.5 P-256 material is already in the tree
  at `test/diff_x509.h:43-48`.
- The differential driver: `test/diff_p256.h:83` already calls a `p256_sign`
  driver command that `spec/lean/Main.lean:295` already exposes, so the ECDSA signer
  has an oracle from its first commit. A new `test/diff_srv.h` drives the
  ClientHello parser against `Spec/ClientHello.lean`, and `test/diff_hash.h`
  gains the SHA-384 arm of every schedule case it already runs at SHA-256.
- A server sequence enumeration, the counterpart of `handshake_sequence_test`'s
  466,286 sequences (`docs/invariants.md:788`), over the client message orders a
  server may receive, including a second ClientHello in every position, a
  ClientHello after the handshake, and `change_cipher_spec` in every legal and
  illegal position. `test/handshake_sequence_server.h` already carries a mock
  server that runs the key schedule (`:278-330`), so the harness has a starting
  shape. Its size is **unmeasured**.
- Exact boundary pairs, per `CLAUDE.md:132-134`: a ClientHello at
  `cfg.buf_len - REC_HDR` works and one byte more fails; a cookie at its
  SHA-384 length opens and a truncated one does not; a `legacy_session_id` at
  32 bytes echoes and 33 is `decode_error`.
- End to end: `test/e2e.sh:2` describes today's run as "against openssl
  s_server and a Go" server. A server build needs the opposite leg — `openssl
  s_client`, a Go `crypto/tls` client, and a strict-conformance driver that
  sends the ClientHellos a real client never sends: an AES-256-GCM-only cipher
  list, an AES-128-GCM-only list, an RSA-PSS-only `signature_algorithms`, an
  empty `client_shares` list, a P-256-only key share, GREASE code points in
  every list, a large padding extension, a non-empty `legacy_session_id`, and a
  retried ClientHello that changed a frozen field.

### Violation mutants

`ls test/violations/*.violation | wc -l` returns **94** today. `test/violations.py`
applies the edit, rebuilds, and requires the named target to fail; an edit whose
old text no longer matches fails as stale.

**Every target below names a script by path or a test binary, never a make
target, and the second round of this record named four make targets.** The
rows that describe a target in words rather than naming one describe a test
that does not exist yet; each becomes a `bin/` binary or a path when it is
written. `test/violations.py:136`
reads `target_is_script = "/" in command[0]`, and no violation in the tree names
a make target: `grep -h '^catches:' test/violations/*.violation | sort | uniq -c`
returns **33** distinct targets, thirteen of them naming a script by path and
the rest `bin/` binaries. `test/lint-wide-multiply.sh` already exists for this
reason, and five violations name it.
`test/lint-invariants.sh` is a file in the same shape — it runs
`make -s lint-invariants` over the source on disk, which is the edited source
while a violation is applied, and a nonzero exit is Semgrep objecting. It runs
only `make`, so the violations need no `builds:` line
(`test/violations.py:32-35`), and it belongs in `FAST_TARGETS`
(`test/violations.py:253-266`) on a measured `make lint-invariants` wall clock
of **6.6 s**. `make lint-shellcheck` covers every shell script in the tree, so
the script is linted the day it lands.

**Two documents write that file, and open question nine decides which one
does.** The path does not exist in the tree today: `ls test/*.sh` prints
thirteen scripts and none is `lint-invariants.sh`. `gcm.patch:2354` is
`diff --git a/test/lint-invariants.sh b/test/lint-invariants.sh`, creating it
with nine lines whose last is `exec make -s lint-invariants`; the patch also
adds the path to `FAST_TARGETS` twice (`gcm.patch:3097` and `:3101`) and names
it as the catch target of three of its own violations (`gcm.patch:3153`,
`:3183`, `:3236`). Open question nine puts the ROLE work first, so the ROLE
work writes the script and the `FAST_TARGETS` entry, and `gcm.patch` drops both
hunks when it rebases — the same treatment the rename and the INV-26 entry get,
and the reason open question nine exists. Nothing here changes if Camilo
reverses that order; then the patch lands the file and the ROLE work writes
only the four violations below that name it. What must not happen is both,
because the second one to land hits a conflict on a file neither document said
was shared.

| File | Edit | Target that must fail |
|---|---|---|
| `inv29-suite-not-offered.violation` | select AES-128-GCM when the client offered only ChaCha | the strict-parser test |
| `inv29-hash-not-from-suite.violation` | run the SHA-256 schedule after selecting `TLS_AES_256_GCM_SHA384` | the strict e2e driver |
| `inv29-group-not-in-supported.violation` | send a `key_share` for a group absent from `supported_groups` (`rfc9846.txt:2230-2232`) | the sequence enumeration |
| `inv29-sigalg-not-intersected.violation` | sign with an identity's scheme without checking `signature_algorithms` (`rfc9846.txt:3078-3081`) | the strict e2e driver |
| `inv29-unknown-extension-refused.violation` | refuse an unrecognized ClientHello extension instead of skipping it (`rfc9846.txt:1299`) | the GREASE e2e case, not a parser test |
| `inv30-direction-swap.violation` | restore `handshake.c:309-310`'s client assignment in the server | e2e |
| `inv30-second-hello-retry.violation` | add a third `srv_send_hello_retry_request` call site | the sequence enumeration |
| `inv30-flight-order-swap.violation` | send CertificateVerify before Certificate | the sequence enumeration |
| `inv30-ccs-after-second-hello.violation` | move `srv_send_compat_ccs` to one call site after the ServerHello | the strict e2e driver's retry case |
| `inv31-private-key-copied.violation` | copy a `ch_identity.priv` into `ch_tls` | `test/lint-invariants.sh` |
| `inv31-nonce-from-rand.violation` | draw the ECDSA nonce from `ch_rand_bytes` instead of RFC 6979 | the differential run |
| `inv31-sign-conditional-subtract.violation` | write `p256_field.c`'s masked final subtract as the `if` `p256.c:142` uses, taken on the nonce | `test/lint-wide-multiply.sh` |
| `inv26-aes-sbox-table.violation` | restore the table-driven S-box | `test/lint-invariants.sh` |
| `srv-cookie-memcmp.violation` | verify the cookie MAC with `memcmp` instead of `ct_memeq` | `test/lint-invariants.sh` |
| `srv-finished-memcmp.violation` | the same for the client's Finished | `test/lint-invariants.sh` |
| `srv-early-data-no-discard.violation` | restore `handshake_record.c:37-38` on the early-data path | the strict e2e driver's external-PSK case |

The patch's four INV-26 mutants need their reason text rewritten, and none of
them is deleted. Three rest on the withdrawn premise in the same words:
`inv26-gcm-on-traffic-key` (`gcm.patch:3228`), `inv26-aes-on-traffic-key`
(`gcm.patch:3184-3186`) and `inv26-aes-mask-on-1rtt-path`, whose reason at
`gcm.patch:3154-3158` reads "aes_encrypt_block reads a header protection key
quic_hp_key_init derived from a TLS traffic secret. That is the one thing
INV-26 forbids: a secret key reaching a table-driven cipher." The fourth,
`inv26-aes-schedule-past-round-keys`, is an off-by-one in the key schedule loop
caught by `proof/prove-one.sh` (`gcm.patch:3214-3219`); the invariant's wording
never entered it and the rewording leaves it untouched. All three of the first
group keep firing under the replacement rule, because the replacement keeps a
call-site allow-list that still excludes `quic_packet.c`. Only their reason
text changes.

## Resumption

Open question five asked whether v1 accepts PSKs and issues tickets, and
Camilo answered yes on 2026-09-24: colibri needs the QUIC Interop Runner's
`resumption` case in both roles, and two chapulin endpoints resuming each
other is the deployment the client was written for. `docs/decisions.md`
entry 51 records the choice. `srv_ticket.[ch]` is the ticket format and
`srv_resume.[ch]` the two flight steps that use it; both headers state
every rule this section summarizes.

**What the caller supplies.** `ch_cfg.srv.ticket_key`, 32 bytes of
ChaCha20-Poly1305 key (`SRV_TICKET_KEY_LEN`), one per deployment and not the
cookie key; NULL issues no ticket and accepts none. And
`ch_cfg.srv.now_seconds`, its clock in seconds at the start of the
connection, from one epoch on every server that shares the key; 0 means no
clock, and a server with no clock issues no ticket and accepts none, because
it could not tell a fresh ticket from an expired one. The instant is a
configuration field rather than an argument to `ch_srv_accept`,
`ch_srv_record_init` and `ch_srv_quic_init`, so the three calls keep their
signatures; `ch_cfg.now_seconds` is the client's precedent.

**What the server issues.** One NewSessionTicket per connection, full or
resumed, after the client Finished verifies (`rfc9846.txt:3194-3196`), under
the application write key: a record over TCP, CRYPTO bytes at
`CH_LEVEL_APPLICATION` over QUIC. It carries no extension, so no
`early_data`, a fresh random `ticket_age_add` and 8-byte `ticket_nonce`
(`rfc9846.txt:3265-3273`), and a `ticket_lifetime` of what is left of
`SRV_TICKET_LIFETIME`, 604800 seconds by default, the most
`rfc9846.txt:3257-3258` allows. One is enough because a client that resumes
serially gets a fresh ticket on every resumed connection; a client racing
parallel connections would want more, and none asks.

**What a ticket carries.** 104 bytes: a version byte, a 12-byte random
nonce, and a 75-byte body sealed with ChaCha20-Poly1305 with the version
byte as associated data. The body holds the instant of the last full
handshake behind the ticket, the cipher suite, the ALPN protocol and the
32-byte PSK. The instant is carried forward through every resumed
handshake, so a chain of resumptions ends one lifetime after the
certificate last signed. `srv_ticket.h` lays the bytes out and states when
the key must rotate.

**What a ticket binds, and what it does not.** It binds the suite's KDF hash
(`rfc9846.txt:3219-3220`), the lifetime on the server's own clock, and the
ALPN protocol, so a ticket resumes only a connection that negotiates the
protocol it was issued under. It binds neither the server name, which
`rfc9846.txt:2525-2527` says a server need not associate with a ticket, nor
the signing identity, which the ticket key stands in for. `srv_resume.h`
gives the reason for each.

**What the server accepts.** A ticket it sealed, offered under `psk_dhe_ke`:
a client that lists `psk_ke` alone gets a full handshake, because this
server always runs a key exchange (`rfc9846.txt:2307-2308`). It walks the
identities in the client's order, selects the first that opens and holds,
and checks that identity's binder alone (`rfc9846.txt:2544-2546`) with
`ct_memeq` over the transcript truncated before the binders list. A binder
that is absent or wrong ends the handshake with `decrypt_error`
(`rfc9846.txt:2541-2544`, `:3968-3970`). An identity that does not open, has
expired, was issued in the future, names another hash or another protocol
is passed over (`rfc9846.txt:2533-2537`), and a hello that had no other
identity gets a full handshake, or `missing_extension` when it offered no
signature scheme to authenticate one with. A resumed ServerHello carries
`pre_shared_key` and a key share, and the flight after it is
EncryptedExtensions and Finished alone. The session then reports
`ch_tls.psk_selected` 1 and `ch_tls.sigalg` 0, even when the hello offered
schemes beside the ticket, as OpenSSL's `s_client` does: no
CertificateVerify goes out, so no scheme is selected. On a hello that owes a
HelloRetryRequest the ticket is not judged; the second hello carries it
again, and its binder covers the retry.

**What stays as it was.** The server accepts no external PSK, sends no
`early_data` in EncryptedExtensions or in a ticket, and still has no
early-data discard (see "What the mode does not check"): a client that
sends 0-RTT records under a ticket this server issued breaks the ticket's
terms, and its first such record fails with `bad_record_mac`.

## Key exchange

Every server build holds two groups, X25519MLKEM768 and x25519, and
`srv_kex.[ch]` holds what the server does with them. Camilo answered open
question ten on 2026-09-24, and `docs/decisions.md` entry 54 records the trade.

**Which group.** The server reads `supported_groups` and prefers the hybrid:
X25519MLKEM768 whenever the client lists it, x25519 when it lists x25519 alone,
and handshake_failure when it lists neither (`rfc9846.txt:1145-1148`). The
key_share then decides between a ServerHello and a HelloRetryRequest, the shape
RFC 9846 §4.3.8 gives a server that selects from `supported_groups` first
(`rfc9846.txt:2172-2177`). So a hello that carries the hybrid share gets the
hybrid in one round trip, with or without an x25519 share beside it; a hello
that lists the hybrid and shares x25519 alone gets a HelloRetryRequest that
names X25519MLKEM768, and its second hello must carry that share
(`rfc9846.txt:2212-2215`); and a hello that lists x25519 alone gets x25519, in
one round trip or after a retry as before. The retry is the cookie path this
server already had, and the cookie carries the group.

**The hybrid's bytes.** RFC 10024 fixes them, and `srv_kex.h` states them. The
client's share is the ML-KEM-768 encapsulation key, 1,184 bytes, then its
x25519 value; the server encapsulates to that key and answers with the
1,088-byte ciphertext, then its own x25519 value, 1,120 bytes in all; and the
input keying material is the ML-KEM shared secret, then the x25519 one. That
order is the one `handshake_flight.c`'s `hybrid_secret` reads, so a chapulin
client and a chapulin server agree on it, and OpenSSL 3.6's `s_client` agrees
with both in `test/e2e.sh`.

**What it refuses.** A hybrid share of any length but 1,216 bytes and an x25519
share of any length but 32, with illegal_parameter, at the parser. An
encapsulation key that fails FIPS 203 §7.2's modulus check, with
illegal_parameter, which RFC 10024 asks of a server; `mlkem_encaps_derand`
runs the check before it writes anything. An x25519 half that yields the
all-zero secret, with illegal_parameter (`rfc9846.txt:4293-4295`, INV-3).

**What it draws and wipes.** The 32 bytes of encapsulation randomness come from
`ch_rand_bytes` when the server selects the hybrid, and not otherwise (INV-4).
The ML-KEM shared secret lives in `handshake_state.mlkem_ss` from the
ServerHello, where the encapsulation runs, to `srv_derive_handshake_secrets`,
which copies it into the input keying material and wipes it (INV-17).

**What it costs.** The ServerHello, staged in the clear in `ch_tls.tx`, is up
to 1,216 bytes (`SRV_SERVER_HELLO_MAX`, proved sufficient by the
`srv_message` harness), so a server's TX array holds that many bytes behind
the record header. `bench/sram.sh` measures the server's `ch_tls` at 1,968
bytes on arm64, against 1,368 before, and `ch_srv_accept`'s stack peak at
10,304 bytes, against 5,248, through the encapsulation into K-PKE encrypt.
Every server object packages `mlkem.c`, `mlkem_poly.c` and `sha3.c`, and its
frames are held to the hybrid's 6,656-byte budget (INV-19).

## What is still open

Fourteen questions are open. The first three block the first line of code.
Questions eleven through sixteen arrived with the third round of this record.
Each one is a choice the design cannot make on its own, and each one names what
was measured on both answers. Question five is answered and has left this list,
and question ten is answered and stays below with its answer; the others keep
their numbers, because comments across the tree cite them by number.

**One: does the hash-agile key schedule land in the shared files or in a role
arm?** Unconditional keeps one set of signatures for both roles and moves the
client's published `ch_tls` from 1144 to 1296 on arm64 and 1072 to 1224 on
rv32, both measured above, for a client that never selects SHA-384. A role arm
keeps those numbers and puts `#ifdef CH_ROLE_SERVER` inside `hkdf.[ch]`,
`keysched.[ch]`, `record.[ch]` and `session.h`, which `lint-role-partition`
then holds. This is a `CLAUDE.md` question rather than a size question, which
is why it is Camilo's.

**Two: does "every cipher suite selection a conformant client may make" include
the CCM suites?** The server holds all three §9.1 suites. Table 5 at
`rfc9846.txt:6024-6026` registers `TLS_AES_128_CCM_SHA256` and
`TLS_AES_128_CCM_8_SHA256`, which §9.1 requires nobody to implement. A client
offering only CCM gets `handshake_failure`. `README.md:844-847` already says
"The IoT profile's mandatory suite is AES-128-CCM-8", so this is a deployment
this tree has already thought about once.

**Three: how many signing identities does a deployment provision?** §9.1 needs
both `ecdsa_secp256r1_sha256` and `rsa_pss_rsae_sha256` for CertificateVerify,
so meeting it needs two certificates and two private keys in flash, plus
`rsa_sign.c`. A device with one certificate is a real deployment. The two
answers are a `SIGN=` axis that reintroduces the shortfall, or a runtime slot
that is simply unprovisioned and a server that refuses the schemes it cannot
sign. The design takes the second and `ch_srv_check` reports which slots are
live; Camilo should confirm it.

**Four: does a split GCM harness converge?** Measured as failing today at the
patch's flags. Under `CLAUDE.md`'s rule that proofs are mandatory, a bulk AEAD
with no converged harness does not land, and this one is the AEAD on the data
path. Measure this before writing any server protocol code. If it does not
converge, the choice is between a `README.md` sentence saying the AEAD is
tested and not proved, and stopping the lane.

**Six: bitsliced or masked-table for the constant-time AES?** Unmeasured on
every target, and now at two key sizes. Build both, measure on rv32 against the
table version's measured 1,312 text bytes, and record the answer in
`docs/decisions.md`.

**Seven: plain RFC 6979 or hedged determinism as the default?** The design takes
plain with `SIGN_HEDGED=1` available, and states the fault-attack exposure it
accepts. Settle this before `p256_sign.c` is written, and settle the two
smaller RFC 6979 questions with it: the retry loop's CBMC unwind bound, and
whether `hmac`'s one-shot signature forces staging the private key in a
contiguous stack buffer.

**Eight: the receive buffer, and therefore whether a device-class server can
claim the scope.** The design bounds the ClientHello by the caller's buffer and
says so. A 512-byte device server does not accept every conformant ClientHello.
The streaming reader is the follow-on that would close it, and its own harness
is unmeasured.

**Nine: who lands INV-26, in which form, and before or after `gcm.patch`?** The
invariant is cited by 22 places in the tree and does not exist in
`docs/invariants.md`. The patch writes it twice under one number with different
titles (`gcm.patch:335` and `:397`), which is one of its review blockers. The
cheapest order is to land INV-26 once in the form this document gives, and
rename `quic_aes.[ch]` and `quic_gcm.[ch]` with the type change this document
prices, before the patch lands its Makefile lists, Semgrep rule, harness names,
Lean modules and four mutants on the old wording. That is the only step here
that blocks somebody else's work.

A third hunk joins that list, and it is a whole file rather than a rewording:
`gcm.patch:2354` creates `test/lint-invariants.sh`, which "Violation mutants"
above also writes and four of this record's own mutants name as their target.
Under this order the ROLE work creates it, and the patch drops that hunk along
with its two `FAST_TARGETS` edits at `gcm.patch:3097` and `:3101`. Under the
reverse order the patch creates it and this record writes only the mutants. The
order must be chosen, because two documents creating one path is a conflict for
whoever lands second.

**Ten: does `ROLE=server` multiply with `KEX=pq`, and is a QUIC server in
scope? Answered on 2026-09-24.** Both halves are yes, and the first is yes for
every build rather than for a `KEX=pq` one: a server role holds X25519MLKEM768
beside x25519 in every build and prefers it, and `KEX` chooses nothing for a
server ("Key exchange" above, `docs/decisions.md` entry 54). The QUIC server
had already landed (`docs/quic_server.md`), and it runs the hybrid like the
other two drivers. The draw the question priced, the 32-byte ML-KEM
encapsulation message `m` (`mlkem.h:40-41`), is INV-4's eighth site, made only
when the server selects the hybrid. The note on `quic_keys.h`'s three entry
points typed `secret[SHA256_LEN]` (`:88`, `:100`, `:124`) belongs to question
one, and stands.

**Eleven: does `hkdf.c` carry one HMAC body per hash behind a dispatcher?**
The one-function form is ruled out by measurement rather than by taste: it
reports cognitive complexity 24 against `.clang-tidy:98`'s threshold of 15, so
`make lint-tidy` fails and it cannot land. The split measures clean, at a
528-byte frame against today's 304 and 672 bytes of `__text` at `-Os` against
today's 388 — 284 bytes of flash for the shape that passes. The record takes
the split. The alternative is a different restructure that also clears 15, and
it has to be priced before it is chosen.

**Twelve: does `signature_algorithms_cert` stay a decline?** The server does not
meet `rfc9846.txt:2948-2950`, the sending-side MUST, because it holds two chains
and selects between them on the CertificateVerify scheme alone. It takes the
SHOULD at `rfc9846.txt:2954-2960` instead, and the honest cost is a client that
rejects the chain it receives, conformantly, with `unsupported_certificate`. The
alternative is to read each identity's chain signatures at provisioning time in
`ch_srv_check` and intersect them, which means linking an X.509 reader into a
server build and giving up the claim that a server object links no `x509*.c`.

**Thirteen: do the five new arithmetic files join `BRANCH_SRCS`?** Without
them, no check in the tree fails when a signer's arithmetic branches on the
nonce: `make lint-codegen-partition` compares list membership,
`make lib-check` reads a packaged object whose symbols are already localized,
and `make lint-runtime-symbols` keeps only `__`-prefixed names. All three were
measured as passing on the defect. The bill is `aes.c`, `gcm.c`,
`p256_field.c`, `p256_ecdh.c` and `rsa_sign.c` on `BRANCH_SRCS` with a measured
`BRANCH_CEILING` entry per spec — forty numbers across the eight
`WIDEMUL_SPECS` rows, four of those rows measured through
`test/docker-mips.sh` and `test/docker-riscv32.sh`.

Two more files join `BRANCH_SRCS` whatever Camilo answers here, and they are
not part of this question. `sha512.c` and `sha512_compress.c` run every HMAC of
a SHA-384 key schedule, so they take the same treatment `sha256.c` already has;
that is sixteen more numbers, and "The codegen partition" gives four of them.
`hkdf.c`'s eight existing entries are re-measured for the same reason. Those
twenty-four numbers are the price of the hash-agile schedule, which the scope
already settled, so they are in "Bounds that need measuring" rather than here.

**Fourteen: are `aes_key`'s round keys bytes or `uint32_t` words?** The byte
form measures `sizeof` 241 and `_Alignof` 1, matches the existing
`aes_key_schedule` (`quic_aes_key.h:36-40`) and keeps `CLAUDE.md:142-143`'s
no-host-endianness rule without a sentence. The word form measures 244 and 4,
three bytes more per schedule, and is faster on a 32-bit core; taking it means
the record must state how `aes.c` fills those words byte by byte. The record
takes bytes.

**Fifteen: does a `TRANSPORT=quic` build without `ROLE=server` carry the
15-round AES-256 schedule?** Measured: one `aes_public_key` bundle goes from
364 to 494 bytes. The question used to cost SRAM, because `ch_quic` stored two
bundles; INV-26 removed that storage, so a QUIC build now pays **130 bytes** of
stack in each call that builds a key, against `lint-stack`'s 2,560-byte
budget. The two ways out are a build-conditional
`CH_AES_ROUND_KEYS` set to 11 for that build, and a separate 11-round type for
the QUIC bundle. Both are **unmeasured**.

**Sixteen: does `ch_srv_accept` call `epoch_init` to refuse a configuration
that sets `epoch_load` or `epoch_store`?** `epoch_init` (`tls.c:17`) is the one
static in `tls.c` under no guard, and both `ch_connect` definitions call it. If
the server calls it, it stays outside both role arms; if it does not, it moves
into the client arm and the server writes its own refusal. The answer decides
one `#ifndef` boundary and nothing else.

One smaller item, recorded so it is not rediscovered: the other 13 review
blockers on `gcm.patch` are unread, and the surveys found the duplicate INV-26
section on their own.

The second round listed a second item here, a `docs:` commit for the ten
"RFC 9846 §4.4.3" comments. That commit has landed: `91c0569` renumbered 229
references across 36 files, the grep in "Method" returns 0 at the branch head,
and nothing is left to do. No server code can copy a wrong number from the tree
now.

## What changes in `CLAUDE.md`

A `ROLE=server` build falsifies twelve sentences. The identity sentence, the
negotiation-surface rule, the constant-time paragraph and the file-pair chain
are in the appendix. Each row names the sentence, its replacement and the commit
that applies it; nothing changes before that commit.

| sentence | replacement | commit |
|---|---|---|
| `CLAUDE.md:3-4`, "chapulin is a TLS 1.3-only client for devices with a few kB of SRAM to spare" | the appendix text | `srv.[ch]` |
| `CLAUDE.md:14-16` and `:44-45`, the one-profile rule and "the client offers exactly one of everything" | the appendix text | `srv_parser.[ch]` |
| `CLAUDE.md:103-104`, "AES never enters this codebase precisely to avoid tables" | the appendix text | `aes.[ch]` |
| `CLAUDE.md:53-86`, the file-pair chain | the appendix text, which puts `p256_field.[ch]` below `p256_ecdh.[ch]` and `p256_sign.[ch]` in the position `p384_field.[ch]` already holds below `p384.[ch]` | each pair's own commit adds its entry; the last one lands the whole chain |
| `CLAUDE.md:10-13`, "one static `ch_tls` session struct plus a caller-provided record buffer is the entire working set" | the same sentence, then: "A `ROLE=server` build adds caller-owned objects and no allocation: one certificate chain and one private key per signature scheme it offers, which the server writes out unread and reads through pointers. `bench/sram.sh` measures a server row beside the client's." | `srv.[ch]` |
| `CLAUDE.md:17-32`, the `TRUST` and `PIN` axes | the same sentences, then: "Both axes name how this endpoint trusts a peer's key. A `ROLE=server` build judges no peer key, so `TRUST` has no meaning there and the Makefile stops the build on it. `PIN` selects nothing there either, so its filter is empty and the object keeps both verifiers, which `ch_srv_check` uses at boot." | the `ROLE` axis |
| `CLAUDE.md:71`, "`handshake_parser.[ch]` (message parsers)" | "`handshake_parser.[ch]` (the parsers for the messages a server sends, ROLE=client) and `srv_parser.[ch]` (the ClientHello parser, ROLE=server, which ignores an extension it does not recognize where the client refuses one)" | `srv_parser.[ch]` |
| `CLAUDE.md:73-76`, `handshake_auth.[ch]` and `handshake.[ch]` | the same sentences with "ROLE=client" added, then the `srv_auth.[ch]` and `srv_handshake.[ch]` entries the appendix chain carries | `srv_auth.[ch]`, `srv_handshake.[ch]` |
| `CLAUDE.md:79-80`, "Firmware takes everything below `tls.[ch]` as-is and supplies I/O callbacks and `ch_rand_bytes`" | the same sentence, then: "A `ROLE=server` firmware supplies the same two and adds the certificate chains, the private keys and the cookie key, all caller-owned and all read through pointers." | `srv.[ch]` |
| `CLAUDE.md:148-150`, "the client always sends `record_size_limit` sized to the caller's buffer" | "Record size discipline runs in both directions. A client sends `record_size_limit` (RFC 8449) sized to the caller's buffer; a server sends its own in EncryptedExtensions and holds its sends to the client's. A peer record over the limit is a protocol error, not a resize, in both roles." | `srv_message.[ch]` |
| `CLAUDE.md:151-153`, the MUSTs list | "RFC MUSTs we keep even though this is minimal, per role. A client: HelloRetryRequest handling, KeyUpdate receipt, NewSessionTicket parse-and-expose, RFC 9257 binder discipline. A server: HelloRetryRequest generation with an integrity-protected cookie (RFC 9846 §9.2 makes the extension mandatory to implement), KeyUpdate receipt and response, the dummy `change_cipher_spec` record a client's non-empty session id obliges, and the early-data discard §4.3.10 requires of a server that answers 1-RTT. Issuing NewSessionTicket is a MAY (`rfc9846.txt:3194-3196`) and is not on this list; a server that issues them, as this one does, also verifies a binder before it accepts a ticket, which `rfc9846.txt:2541-2544` makes a MUST." | `srv_flight.[ch]` |
| `CLAUDE.md:215-221`, `make check` and `make check-slow` | the same sentence, then: "The `ROLE` axis adds one leg to each: one `cxx-check ROLE=server`, one `bin/srv_test` run, and in `check-slow` one e2e leg driving a real TLS 1.3 client against a chapulin server." | `srv.[ch]` |
| `CLAUDE.md:249-254`, the C++ wrapper | the same sentence, then: "A `ROLE=server` object exports `ch_srv_accept` and `ch_srv_check` beside `ch_read`, `ch_write` and `ch_close`, so the wrapper adds a `Server` type under `#ifdef CH_ROLE_SERVER` forwarding those, and adds no logic there either. `cxx-check` runs on both roles." | `srv.[ch]` |

## What changes in `docs/invariants.md`

`grep -n '^### INV-' docs/invariants.md` runs INV-1 to INV-27 with none
absent. INV-26, the AES exception, landed with the QUIC mode, and INV-28
retired with the last `ROLE=server` stub; neither number is reused for a
server rule. New server entries start at 29.

New entries:

- **INV-26 — AES is constant time, and its key may be a traffic secret.**
  Replaces the unlanded "AES sees three public keys and no other", which was
  never written to `docs/invariants.md` and exists only in `gcm.patch`.

  Claim one: no source in this tree indexes a table with cipher state, so an
  AES key may come from the TLS key schedule. Check: a new Semgrep rule,
  `inv-26-no-cipher-state-table`, which fails a 256-entry constant and a
  subscript whose index is itself a byte of the state, in `aes.c` and `gcm.c`
  by `paths: include`. `make lint-invariants` runs it, `make lint-docs` holds
  the doc-to-rule mapping in both directions (`Makefile:1514-1521`), and
  `inv26-aes-sbox-table.violation` proves it fires. Measured: against the
  patch's table-driven AES renamed `aes.c` the rule reports five findings and
  exit 1, quoting the `static const uint8_t SBOX[256]` declaration, three
  key-schedule lookups and the cipher lookup; against a file with a computed
  substitution and an `RCON[11]` table indexed by the public round counter it
  reports none and exits 0. A second Semgrep rule, re-aimed from the patch's
  `inv-26-aes-public-keys-only`, admits `record.c` beside `quic_initial.c` and
  `quic_retry.c` as callers, and the patch's three re-worded mutants keep firing
  under it.

  Claim two, separate: no instruction either file emits branches on a key byte.
  Mechanism: `aes.c` and `gcm.c` move from `WIDEMUL_PUBLIC` (`Makefile:2034`)
  to `WIDEMUL_CEILING` (`Makefile:2018`) **and** join `BRANCH_SRCS`
  (`Makefile:2241`), because the branch count runs only for files on that list
  (`Makefile:2335`), each needing a measured `BRANCH_CEILING` entry per spec.

  **`lint-wide-multiply` cannot hold claim one, and the second round of this
  record said it could.** It compiles each file to assembly and counts two
  regular expressions over it (`Makefile:2326-2337`). A lookup is a load, and no
  load appears in `WIDEMUL_OPS_RV` (`Makefile:2118`) or `BRANCH_OPS_RV`
  (`Makefile:2174`). Measured: the patch's table-driven AES emits **0** widening
  multiplies and **15** conditional branches on rv32imac and the same two
  numbers on m3, so a `WIDEMUL_CEILING` entry of zero passes with the table in
  place. Coming in under a ceiling only prints (`Makefile:2333`, `:2345`), so a
  constant-time file's higher count would not fail either. That is why the table
  claim is Semgrep's and the branch claim is `lint-wide-multiply`'s.
- **INV-29 — the server selects from a closed set and refuses the rest.** The
  second arm INV-7 needs, written from the selecting side. Claim: three cipher
  suites, two groups, two signature schemes, one version, and a key-exchange
  mode the client listed; the server never sends a `key_share` for a group
  absent from `supported_groups`, never signs with a scheme the client did not
  offer, never runs a hash the selected suite did not name, and refuses
  everything else with the alert §4.2.1 names. Check: the strict-parser test
  and the sequence enumeration.
- **INV-30 — the server accepts exactly the client message orders §4 allows.**
  The mirror of INV-22. Mechanism: `srv_handshake.c` is a straight line with no
  state variable, and at most one HelloRetryRequest by call position. Check: the
  Lean theorem in `Spec/ServerHandshake.lean` and the server sequence
  enumeration.
- **INV-31 — two files read a private key, and nothing copies one.** Claim:
  `p256_sign.c` and `rsa_sign.c` are the only sources that read a
  `ch_identity.priv`; no field of `ch_tls` holds one; the arithmetic both
  signers call is pure, keeps no static state and writes only through its
  out-parameters, so every value computed from a private key dies in the
  signer's frame; and neither signer calls into the variable-time arithmetic of
  `p256.c` or `rsa_mont.c`. The second round of this record claimed that every
  such value dies in the signer's own frame, which stopped being true when `d`
  and `k` began passing through `p256_field.c`; the purity clause is what
  replaces it, and `make lint-invariants`'s existing
  `inv-18-no-global-mutable-state` rule already fails a non-const file-scope
  object, so "keeps no static state" is checked today. Check:
  `inv-31-no-private-key-read-outside-signers` and
  `inv-31-signer-uses-no-variable-time-arithmetic`, two Semgrep rules;
  `p256_field.c`, `p256_ecdh.c`, `p256_sign.c` and `rsa_sign.c` on
  `WIDEMUL_CEILING`, and all but `p256_sign.c` on `BRANCH_SRCS` with a measured
  ceiling per spec row; `inv31-private-key-copied.violation` and
  `inv31-sign-conditional-subtract.violation`. The second rule was written and
  run: against a synthetic `p256_sign.c` calling a copied `mont_mul` it reported
  one finding and exit 1, and against a clean `rsa_sign.c` and a `p256.c` making
  the identical call it reported none, because `paths: include` scopes it to the
  two signers. `paths: include` is the shape `inv-23-no-division-in-mlkem`
  already uses (`.semgrep/invariants.yml:66-67`). The rule matches names, so a
  copy under a new name passes it, which is why the branch ceiling is the
  primary check and the rule is the second.
- **INV-32 — the server role stays in files named `srv*`.** The mirror of
  INV-27, with `ROLE_SHARED` and `ROLE_CONDITIONAL` as the named exemptions.
  Check: `make lint-role-partition`.

Amended entries:

- **INV-1**, one sealing path. Its mechanism sentence names one AEAD by type
  (`docs/invariants.md:40-42`). Two AEADs now go out on the wire, both through one
  dispatch in `record.c`, which is the amended mechanism, and
  `inv-1-seal-only-in-record`'s exclude list admits `gcm.c`.
- **INV-2**, zero heap. The allocator half is untouched; the enumeration at
  `docs/invariants.md:50-51` gains the chains and the keys as caller-owned
  objects.
- **INV-4**, randomness only through the hook. Its claim names three sites, all
  in `handshake.c` (`docs/invariants.md:78-82`), the third only under `KEX=pq`.
  A server's count is per build the same way, and the second round of this
  record gave one number for both builds. Under the default `KEX=x25519` a
  server draws **two** values in `srv_handshake.c`: the ServerHello random and
  the key-exchange scalar. Under `KEX=pq` it draws **three**: the same two, plus
  the 32-byte ML-KEM encapsulation message `m` that `mlkem_encaps_derand` takes
  from its caller (`mlkem.h:40-41`, described at `mlkem.h:36-37`, with
  `mlkem.h:7` stating that the module calls `ch_rand_bytes` nowhere). The client
  never draws `m`, because the client decapsulates; the server is the
  encapsulating side. Every server draw carries the same all-zero check the
  client's three do (`handshake.c:266-272`). The cookie key is not one of
  them — it is caller-owned, one per deployment, which is what makes a cookie
  minted on one session open on another, and `ch_cfg` declares it as a pointer.
  So the count and the file change per role, and `.semgrep/invariants.yml:96`
  gains `srv_handshake.c`; the rule excludes by path rather than by call site,
  so one entry covers all three draws.
- **INV-5**, one certificate verifier. It gains one sentence: a `ROLE=server`
  build compiles no certificate reader at all, because the chain is presented
  pre-encoded and never parsed.
- **INV-7**, no negotiation. It keeps its first arm and gains INV-29 as its
  second.
- **INV-10**, nonce discipline. It gains the direction binding, which no
  sentence states today, and the per-suite key-usage ceiling.
- **INV-11**, transcript and secret schedule (`docs/invariants.md:426`). Its
  claim that secrets snapshot at RFC-defined points survives; its unstated
  premise that a secret is 32 bytes does not. It gains the sentence that the
  hash and every secret length come from the selected suite.
- **INV-14**, the refusal set. It gains the server's list, which is "What the
  server refuses" above.
- **INV-16**, constant time where secrets flow. Its exemption list at
  `docs/invariants.md:654-656` is exhaustive and names algorithms; the amended
  sentence names files, keeping `p256.c`, `rsa.c` and `rsa_mont.c` and
  excluding `p256_ecdh.c`, `p256_sign.c`, `rsa_sign.c`, `aes.c`, `gcm.c`,
  `sha512.c` and `sha512_compress.c` by name.
- **INV-19**, bounded stack. It gains a server row with a measured worst frame.
  Every new frame is **unmeasured**, and `make lint-stack` turns a miss into a
  compile failure.
- **INV-27**, the QUIC partition. Its claim survives once `aes.c` and `gcm.c`
  lose the `quic_` prefix, because they stop being files only a
  `TRANSPORT=quic` build compiles.
- **INV-28**, stubs never report success. It ran out of subjects: the QUIC
  stubs it first covered and the `CH_SRV_STUB` bodies it covered after them
  are all implemented, so the entry retired rather than changed.

## What changes in `docs/decisions.md`

Entry 38 is the last (`docs/decisions.md:410`), so the server role is entry 39,
written in entry 38's shape: a mode that is decided and unbuilt, naming each
rule it conflicts with, with this document carrying the replacement text. Eight
existing entries need re-arguing, because `docs/decisions.md:3-6` says changing
one means re-arguing the trade rather than editing the code.

| entry | what it must now say |
|---|---|
| 1, one profile, nothing negotiated (`:10-13`) | The gain is what the server role spends. The entry states the new cost — a selection surface on the serving side, over three suites, two hashes, two groups and two signature schemes — and what it buys, which is every client whose offer meets §9.1. |
| 3, the MUSTs stay (`:17-21`) | Every MUST inverts for a server, and cookie generation and the early-data discard join the list. "a conforming client" becomes "a conforming client and a conforming server". |
| 6, ChaCha only; AES never enters (`:38-42`) | Replaced whole by the appendix text. The QUIC work already has a pending replacement, and the server changes its shape, because a server's AES key is a traffic secret while QUIC's are public. |
| 8, one pinned signature algorithm per build (`:48-53`) | The entry is about verification. A server holds one identity per scheme it offers, and what varies is which scheme the client offered. Different trade, different failure mode. |
| 9, RSA is verify-only (`:54-60`) | It stops being true. A `ROLE=server` build signs with RSA-PSS through `rsa_sign.c`, which shares no arithmetic with `rsa.c` and carries the constant-time burden `rsa.h:4-6` says the verifier does not. The entry names both files and the rule that separates them. |
| 20, single task, single connection (`:192-223`) | The entry admits that the reference generator has global state and every session in an image draws from one stream. A server serving one connection at a time is covered; one serving several is not, and the entry must say which this is. |
| 28, four exported symbols (`:296-299`) | Five under `ROLE=server`, fifteen under `TRANSPORT=quic` per entry 38, four otherwise. `PUBLIC` selects the first term rather than adding to it. |
| the SHA-256 specialization, wherever the entry that fixed it lives | A new entry records why the key schedule stopped being SHA-256-only, with the measured cost this document's first section gives, so the trade can be reopened with numbers. |

`README.md` owes its own pass. `README.md:833-835` loses "the server role" and
qualifies "cipher agility", and the same paragraph gains the sentence naming
`docs/server.md` that `make lint-docs` requires (`Makefile:1511-1512`).
`README.md:5-7` and `:9-14` are the headline sentences with the same damage as
`CLAUDE.md:3-4`. `README.md:344-347` says the RFC 8448 replay "stops at secrets
and MACs and never opens a record" because "those traces use AES-128-GCM, which
chapulin excludes"; the stated reason disappears. `README.md:407-411` carries
the constant-time claim and the "P-256 and RSA verification are variable-time on
purpose" sentence, both of which need the file-level wording INV-16 gets.
`README.md:126-142` gains server rows and, under the unconditional answer to
open question one, new client rows. And `README.md:274-276` says "Forty-two of
the forty-three C sources"; `ls *.c` at the root returns **51** today, so the
count is already stale before any server work and gets re-measured rather than
adjusted.

## Appendix: replacement text

Four replacements a row in the table above could not hold. Nothing changes
before the commit named beside each.

**`CLAUDE.md`**, replacing the identity sentence at `CLAUDE.md:3-4`:

> chapulin is a TLS 1.3-only stack for devices with a few kB of SRAM to spare,
> named after El Chapulín Colorado: small, unassuming, protective. Home:
> github.com/c4milo. The Makefile `ROLE` variable picks one role per build:
> `ROLE=client` is the default and is the client every rule below describes
> unless it says otherwise; `ROLE=server` answers a client over the same
> caller-supplied I/O callbacks, proves one identity per signature scheme it
> offers, and is the role `docs/server.md` records. One object holds one role.

**`CLAUDE.md`**, replacing the negotiation rule at `CLAUDE.md:14-16` and its
restatement at `CLAUDE.md:44-45`:

> One profile per role, and the smallest negotiation surface each role's job
> admits. A `ROLE=client` build offers TLS 1.3,
> TLS_CHACHA20_POLY1305_SHA256, one key-exchange group, and one of two auth
> modes — ECDHE-PSK (psk_dhe_ke) or a server key checked against
> CertificateVerify. Within a mode the client offers exactly one of everything;
> the server takes it or the handshake fails closed. A `ROLE=server` build
> selects rather than offers, because RFC 9846 §9.1 tells a client what to
> support and never what to offer, so a conformant client may offer any subset
> of the mandatory set. It holds the three cipher suites of §9.1 and therefore
> both transcript hashes, SHA-256 and SHA-384; two key-exchange groups,
> secp256r1 and x25519; one signature scheme per provisioned identity, out of
> the two §9.1 names for CertificateVerify; and one version. It refuses
> everything outside that set with the alert the RFC names. INV-29 states the
> closed set and holds it; the server never selects a parameter the client did
> not offer.

**`CLAUDE.md`**, replacing the constant-time sentence at `CLAUDE.md:103-104`:

> ChaCha20/Poly1305/x25519 are constant time by construction — keep them that
> way. AES is in this tree for two reasons and is constant time for one of
> them: RFC 9001 fixes AES-128-GCM, AES-128-ECB and the Retry tag for QUIC,
> where every key is public, and RFC 9846 §9.1 fixes TLS_AES_128_GCM_SHA256 as
> the one cipher suite a compliant application must implement, where the key is
> a traffic secret the TLS key schedule produced. The second use is why
> `aes.[ch]` carries no lookup table indexed by cipher state: a table-driven
> AES on the record path would index its S-box with a secret on every 16 bytes
> of every record. INV-26 states the rule. The Semgrep rule
> `inv-26-no-cipher-state-table` fails a table in `aes.c` or `gcm.c`, a second
> Semgrep rule holds every `aes_` and `gcm_` call to `record.c`,
> `quic_initial.c` and `quic_retry.c`, `lint-wide-multiply` measures both files
> for widening multiplies and for conditional branches the compiler chose, and a
> `.violation` mutant proves each rule fires. The same rule applies to the hashes:
> a `ROLE=server` build runs SHA-384 over key-schedule secrets when the
> selected suite names it, so `sha512.c` and `sha512_compress.c` sit in
> `WIDEMUL_CEILING` beside them rather than in `WIDEMUL_PUBLIC`. AES is a
> cipher suite in a `ROLE=server` build and in no other, and `docs/server.md`
> records the trade.

**`CLAUDE.md`**, replacing the file-pair chain at `CLAUDE.md:53-86`. Only the
rows the server role changes are written out; every other row keeps its current
text. Two rows below name files that do not exist yet: `handshake_flight.[ch]`
has a header and no `.c`, and `docs/quic.md`'s lane lands the body, so this
replacement cannot be committed before that lane does.

> - One concern per file pair, dependencies pointing down only:
>   `ct.[ch]` (constant-time bytes) ← the hashes, of which `sha512.[ch]` and
>   `sha512_compress.[ch]` are packaged by a `TRUST=webpki` build for a public
>   chain's signatures and by a `ROLE=server` build for the SHA-384 key
>   schedule of TLS_AES_256_GCM_SHA384 ← `hkdf.[ch]` (HMAC + HKDF + TLS
>   labels, over either hash; every entry point takes a `hash_len` of 32 or 48,
>   fixed by the selected cipher suite) ← `chacha20.[ch]` + `poly1305.[ch]` +
>   `aes.[ch]` (the AES forward cipher of FIPS 197 at both key sizes, constant
>   time, packaged by a `TRANSPORT=quic` or a `ROLE=server` build) ←
>   `aead.[ch]` (RFC 8439 seal/open) + `gcm.[ch]` (AEAD_AES_128_GCM,
>   AEAD_AES_256_GCM and GHASH, the same two builds) ←
>   `x25519.[ch]` + `p256.[ch]` + `rsa.[ch]`/`rsa_mont.c` (pinned-mode verify,
>   and the boot-time self-check of a `ROLE=server` build) + `p384.[ch]`/
>   `p384_field.[ch]` + `rsa_pkcs1.[ch]` (the chain signatures a public CA
>   writes, TRUST=webpki) + `p256_field.[ch]` (the constant-time P-256 field
>   and scalar arithmetic, in the position `p384_field.[ch]` holds below
>   `p384.[ch]`; every routine is constant time in every operand, so no caller
>   has to know which argument is secret) + `p256_ecdh.[ch]` (constant-time
>   P-256 key exchange over a secret scalar, including peer-point validation,
>   ROLE=server; `p256.[ch]` beside it stays verify-only and variable time on
>   purpose) ←
>   `p256_sign.[ch]` (ECDSA P-256 signing with an RFC 6979 nonce over
>   `hkdf.[ch]`'s HMAC, and the DER ECDSA-Sig-Value writer) + `rsa_sign.[ch]`
>   (RSA-PSS signing with a secret exponent) — the two files in this tree that
>   read a long-term private key, both ROLE=server, both computing over
>   `p256_field.[ch]` or their own constant-time arithmetic and never over
>   `p256.c` or `rsa_mont.c` ←
>   the certificate readers, which a `ROLE=server` build compiles none of ←
>   `record.[ch]` (record layer; under ROLE=server one `rec_dir` carries a
>   suite tag and all three AEADs are called through this file and no other) ←
>   `handshake_parser.[ch]` (the parsers for the messages a server sends,
>   ROLE=client) or `srv_parser.[ch]` (the ClientHello parser, ROLE=server,
>   which ignores an extension it does not recognize where the client refuses
>   one) ← `handshake_record.[ch]` (record reading and message reassembly, both
>   roles) ← `handshake_auth.[ch]` (server authentication, ROLE=client) or
>   `srv_auth.[ch]` (the Certificate and CertificateVerify flight a server
>   writes, over `p256_sign.[ch]` and `rsa_sign.[ch]`) + `srv_message.[ch]`
>   (the seven builders) + `srv_cookie.[ch]` (the HelloRetryRequest cookie,
>   minted and opened under `hmac`) ← `handshake_flight.[ch]` (the
>   client's flight handlers) or `srv_flight.[ch]` (the server's) ←
>   `handshake.[ch]` (client state machine) or `srv_handshake.[ch]` (server
>   state machine) ← `handshake_post.[ch]` (NewSessionTicket and KeyUpdate,
>   parsed by a client and written by a server) ← `tls.[ch]` (public API; the
>   file both roles compile, with `ch_connect` under `#ifndef CH_ROLE_SERVER`
>   and `ch_srv_accept` and `ch_srv_check` in the server arm, and `ch_read`,
>   `ch_write` and `ch_close` outside both) ← demo/test mains. A `ROLE=server`
>   build compiles the `srv*` pairs, `p256_field`, `p256_ecdh`, `p256_sign`,
>   `rsa_sign`, `aes` and `gcm` in place of `handshake`, `handshake_auth`,
>   `handshake_parser`, `handshake_message`, `handshake_flight` and every
>   certificate reader. Firmware takes everything below `tls.[ch]` as-is and
>   supplies I/O callbacks and `ch_rand_bytes` in both roles; a server firmware
>   also supplies one certificate chain and one private key per signature
>   scheme it offers, plus the cookie key, all caller-owned and all read
>   through pointers.
>   One pair sits off that chain rather than in it: `x509_ca.[ch]`
>   (provisioning — one PEM certificate to the key bytes
>   `ch_cfg.server_pubkey` takes) reads `pem.[ch]` and `x509.[ch]`, and no
>   library source reads it. A CA-mode build exports its `ch_pubkey_from_pem`
>   as a fifth public call, which firmware calls while provisioning and no
>   session reaches.
