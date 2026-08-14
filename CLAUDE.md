# matasapos rules

matasapos is a TLS 1.3-only client for devices with a few kB of SRAM to
spare. Sapo = eavesdropper; this kills them. Home: github.com/c4milo.

- C11, libc only. No third-party code, no OS assumptions beyond the
  caller-supplied I/O callbacks. The target is a bare-metal MCU or an
  lwIP-class socket stack.
- Zero heap. No malloc anywhere, ever — one static `ms_tls` session
  struct plus a caller-provided record buffer is the entire working set.
  The SRAM headline (session struct + record buffer, measured, not
  estimated) leads the README and every change re-earns it.
- One profile, no negotiation surface: TLS 1.3, TLS_CHACHA20_POLY1305_SHA256,
  x25519, ECDHE-PSK (psk_dhe_ke) only. No X.509, no raw public keys, no
  0-RTT, no compression, no renegotiation-era anything. The client offers
  exactly one of everything; the server takes it or the handshake fails
  closed.
- One concern per file pair, dependencies pointing down only:
  `ct.[ch]` (constant-time bytes) ← `sha256.[ch]` ← `hkdf.[ch]`
  (HMAC + HKDF + TLS labels) ← `chacha20.[ch]` + `poly1305.[ch]` ←
  `aead.[ch]` (RFC 8439 seal/open) ← `x25519.[ch]` ← `record.[ch]`
  (record layer) ← `handshake.[ch]` (client state machine) ← `tls.[ch]`
  (public API) ← demo/test mains. Firmware takes everything below
  `tls.[ch]` as-is and supplies I/O callbacks and `ms_rand_bytes`.
- Everything that touches secret bytes is constant time: no secret-
  dependent branches, no secret-dependent memory indices. Comparisons go
  through `ct_memeq`, wipes through `ct_wipe`, selects through `ct_select`.
  ChaCha20/Poly1305/x25519 are constant time by construction — keep them
  that way; AES never enters this codebase precisely to avoid tables.
- Proofs are part of `check`, not a side quest. Every module carries a
  CBMC harness in `proof/` proving memory safety and absence of UB
  (bounds, pointer validity, arithmetic overflow, division) over
  unconstrained inputs at the module's real bound. Crypto primitives
  additionally prove functional equivalence to a tiny reference spec at
  bounded sizes, plus RFC test vectors in `test/unit.c`. The README's
  verification section states exactly what is proved, at what bounds, and
  what is only tested — never overclaim.
- All parsing goes through the bounds-checked `rbuf` reader and all output
  bytes through the `wbuf` writer; no raw buffer arithmetic outside them.
  Never assume host endianness; emit and read multi-byte values
  byte-by-byte.
- Operational errors (bad peer input, short buffers, I/O failure) return
  `ms_err` codes and fail closed — alert, wipe keys, dead session.
  `MS_ASSERT` is for programmer-error invariants only, seeded at contract
  points, never in per-byte paths.
- Record size discipline: the client always sends `record_size_limit`
  (RFC 8449) sized to the caller's buffer. A peer record over the limit is
  a protocol error, not a resize.
- RFC MUSTs we keep even though this is minimal: HelloRetryRequest
  handling, KeyUpdate receipt, NewSessionTicket parse-and-expose
  (resumption is just another PSK here), RFC 9257 binder discipline.
- Linters follow fix-or-drop: fix the finding, or disable the check in
  `.clang-tidy` with its reason. Never `NOLINT` in code.
- Every change passes `make check` (lint + unit + proofs; e2e against a
  real TLS 1.3 server once the handshake lands), not just compile.
- Functions stay at cognitive complexity 20 or less; hand-written files
  under 500 lines.
