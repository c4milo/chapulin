# chapulin rules

chapulin is a TLS 1.3-only client for devices with a few kB of SRAM to
spare, named after El Chapulín Colorado: small, unassuming, protective.
Home: github.com/c4milo.

- C11, libc only. No third-party code, no OS assumptions beyond the
  caller-supplied I/O callbacks. The target is a bare-metal MCU or an
  lwIP-class socket stack.
- Zero heap. No malloc anywhere, ever — one static `ch_tls` session
  struct plus a caller-provided record buffer is the entire working set.
  bench/sram.sh measures the README's memory numbers; never estimate
  them, and re-measure when the code changes.
- One profile, no negotiation surface: TLS 1.3, TLS_CHACHA20_POLY1305_SHA256,
  one key-exchange group, and one of two auth modes — ECDHE-PSK
  (psk_dhe_ke) or a pinned server key checked against CertificateVerify.
  The pinned key is one
  algorithm per build, chosen by the Makefile PIN variable: RSA-PSS up to
  3072 bits (default, `rsa.[ch]`) or ECDSA P-256 (PIN=ecdsa, -DCH_PIN_ECDSA,
  `p256.[ch]`) — never both in one library object, though test binaries
  compile both so both stay tested. The key exchange is one group per
  build, chosen by the Makefile KEX variable: x25519 (default) or the
  X25519MLKEM768 hybrid (KEX=pq, -DCH_KEX_PQ, `mlkem.[ch]`) — never both
  in one ClientHello, so a pq client and a classic-only server fail
  closed against each other. No X.509 parsing outside the CA-mode
  profile in x509.[ch] (pinned mode hashes
  the certificate into the transcript, never reads it), no RFC 7250
  raw-public-key certificate types, no 0-RTT, no compression, no
  renegotiation-era anything. Within a mode the client offers exactly one
  of everything; the server takes it or the handshake fails closed.
- One concern per file pair, dependencies pointing down only:
  `ct.[ch]` (constant-time bytes) ← `sha256.[ch]` + `sha3.[ch]` ←
  `mlkem.[ch]`/`mlkem_poly.[ch]` (ML-KEM-768; the KEX=pq build packages
  them with `sha3.[ch]`, other builds keep them test-only) ← `hkdf.[ch]`
  (HMAC + HKDF + TLS labels) ← `chacha20.[ch]` + `poly1305.[ch]` ←
  `aead.[ch]` (RFC 8439 seal/open) ← `x25519.[ch]` + `p256.[ch]` +
  `rsa.[ch]`/`rsa_mont.c` (pinned-mode verify) ←
  `x509.[ch]`/`x509_der.c` (profiled certificate verify, CA mode) ←
  `record.[ch]`
  (record layer) ← `handshake_parser.[ch]` (message parsers) ←
  `handshake_record.[ch]` (record reading and message reassembly) ←
  `handshake_auth.[ch]` (server authentication: the Certificate and
  CertificateVerify flight, and the CA build's revocation epoch) ←
  `handshake.[ch]` (client state machine) ←
  `handshake_post.[ch]` (NewSessionTicket and KeyUpdate, the messages
  that arrive after the handshake) ← `tls.[ch]`
  (public API) ← demo/test mains. Firmware takes everything below
  `tls.[ch]` as-is and supplies I/O callbacks and `ch_rand_bytes`.
- Everything that touches secret bytes is constant time: no secret-
  dependent branches, no secret-dependent memory indices. Comparisons go
  through `ct_memeq` and wipes through `ct_wipe`; constant-time selects,
  where needed, are branchless mask arithmetic inline (x25519's `cswap`,
  poly1305's final reduction), never an `if`. A core with no hardware
  multiplier turns `*` into a runtime-library call that branches on its
  operands, so `softmul.c` supplies constant-time `__mulsi3`/`__muldi3`
  under the compiler's own names; it compiles to nothing where the
  instruction exists.
  ChaCha20/Poly1305/x25519 are constant time by construction — keep them
  that way; AES never enters this codebase precisely to avoid tables.
- Proofs run in `check`, not on the side. Every module carries a
  CBMC harness in `proof/` proving memory safety and absence of UB
  (bounds, pointer validity, arithmetic overflow, division) over
  unconstrained inputs at the module's real bound. Crypto primitives
  additionally prove functional equivalence to a tiny reference spec at
  bounded sizes, plus RFC test vectors in `test/unit_test.c`. The README's
  verification section states exactly what is proved, at what bounds, and
  what is only tested — never overclaim.
- Write harnesses by docs/proofs.md. The rules that keep formulas
  solvable: SAT cost tracks the multiply count per formula, so split
  along it; store nondet values through the object's own type, never a
  byte-pointer fill of a typed object; havoc every operand freshly
  before every call; cover the aliasing shapes real callers use; and
  measure each launch line with `/usr/bin/time -v` under run.sh's exact
  flags before committing it — a launch line whose formula has not been
  seen to converge proves nothing.
- A crypto or protocol change touches three surfaces, not one. When you
  change behavior in a C module, update in the same commit: (1) the code,
  (2) its Lean spec in `spec/` if the change alters what the spec models
  or its stated domain, and (3) the tests — unit vectors, the differential
  driver in `test/diff_test.c` (keep its input domain inside what both C and
  spec agree on), and the CBMC harness if the contract moved. A fix that
  the spec and oracle do not know about is a divergence the differential
  run cannot catch. Boundary changes get an exact boundary test (the last
  valid value works, the first invalid one fails).
- All parsing goes through the bounds-checked `rbuf` reader and all output
  bytes through the `wbuf` writer; no raw buffer arithmetic outside them.
  Never assume host endianness; emit and read multi-byte values
  byte-by-byte.
- Operational errors (bad peer input, short buffers, I/O failure) return
  `ch_err` codes and fail closed — alert, wipe keys, dead session.
  `CH_ASSERT` is for programmer-error invariants only, seeded at contract
  points, never in per-byte paths.
- Record size discipline: the client always sends `record_size_limit`
  (RFC 8449) sized to the caller's buffer. A peer record over the limit is
  a protocol error, not a resize.
- RFC MUSTs we keep even though this is minimal: HelloRetryRequest
  handling, KeyUpdate receipt, NewSessionTicket parse-and-expose
  (resumption is just another PSK here), RFC 9257 binder discipline.
- Write all prose — README, docs, comments, commit messages — in active
  voice with plain words, following Google's Technical Writing One and
  Two: short sentences with one idea each, terms defined before use,
  lists for list-like content, strong verbs, no rhetorical flourishes or
  metaphors.
- Name what literally happens. The failure mode is a vague spatial
  metaphor standing in for a plain verb: a value "reaches" storage
  instead of being written, a change is "folded in" instead of added, a
  boundary becomes a "seam" instead of the constant it is. Before an
  abstract word, ask what literally happens and write that. Literal uses
  stay — a device really cannot reach a server. This matters most in
  comments, where an auditor cannot check the metaphor against anything.
- One name per thing, and it is the name in the code. Never invent prose
  shorthand for something a field or constant already names: write "the
  stored epoch" for `ch_tls.epoch`, never "the mark". A second name
  makes the reader hold a glossary the compiler cannot check, and it
  rots as soon as the field is renamed. When two related values need
  telling apart, take both names from the code (`epoch` and
  `epoch_seen`), not from a metaphor.
- Linters follow fix-or-drop: fix the finding, or disable the check in
  `.clang-tidy` with its reason. Never `NOLINT` in code.
- CI pins the same tool versions the development machine runs (see the
  env block in .github/workflows/check.yml). When the local toolchain
  upgrades, bump the pins in the same commit. Never adapt code or
  suppressions to an older checker.
- CI compiles with gcc on purpose, even though development machines run
  clang: chapulin's consumers are firmware trees whose vendor SDKs ship
  gcc cross-compilers, so gcc-only diagnostics belong in CI, not in a
  consumer's build. Between local clang and CI gcc, both major compiler
  families stay covered without a second CI leg. Do not switch CI to
  clang for convenience.
- Commits are Conventional Commits (feat/fix/docs/test/refactor/perf/
  build/ci/chore), enforced by commitlint via `.githooks/commit-msg`
  (`make hooks` once after clone) and `make lint-commits` in check.
  Bodies stay short: at most three short paragraphs and about 80 words,
  wrapped at 100 columns. The diff shows the what, so never restate it.
  Use plain English and the voice of one engineer telling another why
  the change exists. Reasoning that outlives the commit belongs in
  `docs/`, not the body: state the why in a sentence and name the
  document. Write the body from the diff; never trim a long draft down,
  because editing anchors on the draft and lands long every time.
- Every change passes `make check` (lint + unit + proofs; e2e against a
  real TLS 1.3 server once the handshake lands), not just compile.
- The code optimizes for third-party audit: when compact and
  auditable conflict, auditable wins. A predicate-named function is
  pure; state changes get their own line. Prefer a byte-compare
  against a named constant over decode-and-judge. The naming,
  complexity, and prose rules below all serve this.
- Functions stay at cognitive complexity 15 or less; hand-written files
  under 500 lines. `spec/` is exempt from the line count: both limits
  serve third-party audit of the C, and in a proof file the audited
  unit is the theorem statement, not the tactic script under it — Lean's
  kernel checks that. Judge a spec module by whether each statement
  reads in a few lines and carries no hypothesis it does not need; a
  long proof of a short statement costs an auditor nothing.
- Names spell words out. Module prefixes stay short — they are C's
  namespaces (`ch_`, `ks_`, `rec_`, `rb_`/`wb_`, `hsp_`, `ct_`) — but
  the stem after the prefix is real words: `parse_server_hello`, not
  `parse_sh`; `record_len`, not `recn`. No vowel-dropping, no ad-hoc
  abbreviation. Domain vocabulary the RFCs themselves use stays as the
  RFCs spell it (`pt`, `aad`, `iv`, `psk`, `hrr`, `verify_data`,
  `obfuscated_age`). One-letter names only for loop indices; `rc` for
  return codes is C idiom and stays. `_len` always counts
  bytes — the API's one length unit, never elements or bits. No
  quantity crosses the API in two units. When counts coexist,
  each names what it counts (`ext_count`); an operation's sole byte
  count may stay the idiomatic `n`.
- `chapulin.hpp` is an optional, header-only C++ wrapper: freestanding
  (only <cstddef>/<cstdint>), -fno-exceptions -fno-rtti, zero heap, no
  runtime cost over the C calls. It never gains logic the C core lacks —
  it forwards to the C API and adds only RAII cleanup, byte views, and
  typed results. `make cxx-check` compiles it against the packaged
  library object as part of check.
