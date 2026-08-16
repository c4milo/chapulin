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
  x25519, and one of two auth modes — ECDHE-PSK (psk_dhe_ke) or a pinned
  server key checked against CertificateVerify. The pinned key is one
  algorithm per build, chosen by the Makefile PIN variable: RSA-PSS up to
  3072 bits (default, `rsa.[ch]`) or ECDSA P-256 (PIN=ecdsa, -DCH_PIN_ECDSA,
  `p256.[ch]`) — never both in one library object, though test binaries
  compile both so both stay tested. No X.509 parsing (pinned mode hashes
  the certificate into the transcript, never reads it), no RFC 7250
  raw-public-key certificate types, no 0-RTT, no compression, no
  renegotiation-era anything. Within a mode the client offers exactly one
  of everything; the server takes it or the handshake fails closed.
- One concern per file pair, dependencies pointing down only:
  `ct.[ch]` (constant-time bytes) ← `sha256.[ch]` ← `hkdf.[ch]`
  (HMAC + HKDF + TLS labels) ← `chacha20.[ch]` + `poly1305.[ch]` ←
  `aead.[ch]` (RFC 8439 seal/open) ← `x25519.[ch]` + `p256.[ch]` +
  `rsa.[ch]`/`rsa_mont.c` (pinned-mode verify) ← `record.[ch]`
  (record layer) ← `handshake.[ch]` (client state machine) ← `tls.[ch]`
  (public API) ← demo/test mains. Firmware takes everything below
  `tls.[ch]` as-is and supplies I/O callbacks and `ch_rand_bytes`.
- Everything that touches secret bytes is constant time: no secret-
  dependent branches, no secret-dependent memory indices. Comparisons go
  through `ct_memeq` and wipes through `ct_wipe`; constant-time selects,
  where needed, are branchless mask arithmetic inline (x25519's `cswap`,
  poly1305's final reduction), never an `if`.
  ChaCha20/Poly1305/x25519 are constant time by construction — keep them
  that way; AES never enters this codebase precisely to avoid tables.
- Proofs run in `check`, not on the side. Every module carries a
  CBMC harness in `proof/` proving memory safety and absence of UB
  (bounds, pointer validity, arithmetic overflow, division) over
  unconstrained inputs at the module's real bound. Crypto primitives
  additionally prove functional equivalence to a tiny reference spec at
  bounded sizes, plus RFC test vectors in `test/unit.c`. The README's
  verification section states exactly what is proved, at what bounds, and
  what is only tested — never overclaim.
- A crypto or protocol change touches three surfaces, not one. When you
  change behavior in a C module, update in the same commit: (1) the code,
  (2) its Lean spec in `spec/` if the change alters what the spec models
  or its stated domain, and (3) the tests — unit vectors, the differential
  driver in `test/diff.c` (keep its input domain inside what both C and
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
- Linters follow fix-or-drop: fix the finding, or disable the check in
  `.clang-tidy` with its reason. Never `NOLINT` in code.
- CI pins the same tool versions the development machine runs (see the
  env block in .github/workflows/check.yml). When the local toolchain
  upgrades, bump the pins in the same commit. Never adapt code or
  suppressions to an older checker.
- Commits are Conventional Commits (feat/fix/docs/test/refactor/perf/
  build/ci/chore), enforced by commitlint via `.githooks/commit-msg`
  (`make hooks` once after clone) and `make lint-commits` in check.
  Bodies still explain WHY and wrap at 100 columns.
- Every change passes `make check` (lint + unit + proofs; e2e against a
  real TLS 1.3 server once the handshake lands), not just compile.
- Functions stay at cognitive complexity 20 or less; hand-written files
  under 500 lines.
- `chapulin.hpp` is an optional, header-only C++ wrapper: freestanding
  (only <cstddef>/<cstdint>), -fno-exceptions -fno-rtti, zero heap, no
  runtime cost over the C calls. It never gains logic the C core lacks —
  it forwards to the C API and adds only RAII cleanup, byte views, and
  typed results. `make cxx-check` compiles it against the packaged
  library object as part of check.
