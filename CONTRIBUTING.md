# Contributing

chapulin holds a high bar because its claims are strong: whole-stack
memory-safety proofs, a differential oracle against a Lean spec, and
measured — never estimated — footprint numbers. This page states the
bar, decodes the naming system, and walks the workflow. Read
[CLAUDE.md](CLAUDE.md) for the full design rules; this is the
contributor's summary.

## The bar

Write for the auditor who did not write it. chapulin optimizes for
third-party review: spelled-out names, functions under cognitive
complexity 15, pure predicates with state changes on their own
lines, byte-compares against named constants instead of
decode-and-judge. When compact and auditable conflict, auditable
wins (docs/decisions.md records the trade).

New code lands with its assurance attached. By change type:

| Change | Must land with |
| --- | --- |
| New parser or message handler | CBMC harness over hostile bytes at the real bound, plus negative tests that assert the reject fires and picks the right alert |
| New crypto primitive | Lean spec module, RFC/selftest vectors in `test/unit_test.c`, differential entries in `test/diff_test.c`, CBMC harness |
| Behavior change | The RFC section cited at the code, and the same-commit three-surface update: code, Lean spec, tests |
| Boundary change | An exact boundary test: the last valid value works, the first invalid one fails |
| Any change | `make check` green on both PIN builds (`make check` and `make check PIN=ecdsa`) |

A PR must not break an invariant in
[docs/invariants.md](docs/invariants.md) without amending that
document in the same diff.

## Naming

The prefix is the module's namespace; the stem after it spells real
words. Since 8ce17dd these prefixes are the only contractions in the
tree — the abbreviation budget is spent on this one system.

| Prefix | Home |
| --- | --- |
| `ch_` | Public API (`tls.[ch]`), and its constants: `CH_EPROTO`, `CH_ASSERT`, ... Nothing else escapes the library; lib-check enforces it |
| `tlsi_` | Internal-but-cross-file: shared between library files, never for the application |
| `wb_` / `rb_` | Write and read buffers (`buf.[ch]`) |
| `ct_` | Constant-time bytes (`ct.[ch]`) |
| `ks_` | Key schedule (`keysched.[ch]`) |
| `rec_` | Record protection (`record.[ch]`) |
| `hs_` / `hsp_` | Handshake message build and parse (`hsmsg.[ch]`, `hsparse.[ch]`) |
| `rsa_`, `p256_`, `x25519_`, `aead_`, `hkdf_`, `sha256_`, `drbg_`, `io_` | The self-naming crypto and I/O modules |

Domain vocabulary keeps the RFCs' own spelling: `pt`, `aad`, `iv`,
`psk`, `hrr`, `verify_data`. One-letter names only for loop indices;
`rc` for return codes.

## Workflow

- Commits are Conventional Commits, enforced by commitlint: run
  `make hooks` once after clone, or CI tells you at PR time. Bodies
  explain why and wrap at 100 columns.
- `make check` runs the build, linters, unit and differential tests,
  and the fast proof tier. The four slow proofs run as
  `make prove-slow` in CI and before a release.
- The PIN variable splits the pinned-key build: RSA-PSS by default,
  `PIN=ecdsa` for P-256. One algorithm per library object; test both.
- Generated files never get committed. `test/gen_rfc8448.py` and
  friends regenerate them into `bin/`; if you change a generator,
  the diff shows in the tests that consume its output.
- Every document must be named in the README — `make lint-docs`
  fails on an orphan.

## Security reports are not PRs

A vulnerability goes through the private route in
[SECURITY.md](SECURITY.md), never the public tracker and never a
public PR that fixes-and-reveals it in one step.
