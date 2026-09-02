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
| New crypto primitive | Lean spec module (styleguide: [spec/CONTRACT.md](spec/CONTRACT.md)), RFC/selftest vectors in `test/unit_test.c`, differential entries in `test/diff_test.c`, CBMC harness |
| Behavior change | The RFC section cited at the code, and the same-commit three-surface update: code, Lean spec, tests |
| Boundary change | An exact boundary test: the last valid value works, the first invalid one fails |
| Any change | `make check` green on both PIN builds (`make check` and `make check PIN=ecdsa`), then `make check-slow` |

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
| `hs_` / `hsp_` | Handshake message build and parse (`handshake_message.[ch]`, `handshake_parser.[ch]`) |
| `hsr_` / `hsa_` | Handshake record reading (`handshake_record.[ch]`) and server authentication (`handshake_auth.[ch]`) |
| `hspost_` | The post-handshake messages (`handshake_post.[ch]`). Spelled out because the family's one-letter suffixes are spoken for |
| `rsa_`, `p256_`, `x25519_`, `aead_`, `hkdf_`, `sha256_`, `sha3_`, `shake_`, `mlkem_`, `drbg_`, `io_` | The self-naming crypto and I/O modules |
| `mlk_` | ML-KEM's polynomial layer (`mlkem_poly.[ch]`) |

Domain vocabulary keeps the RFCs' own spelling: `pt`, `aad`, `iv`,
`psk`, `hrr`, `verify_data`. One-letter names only for loop indices;
`rc` for return codes.

## Workflow

- Commits are Conventional Commits, enforced by commitlint: run
  `npm ci --prefix tools` and `make hooks` once after clone, or CI tells
  you at PR time. Bodies explain why and wrap at 100 columns.
- `make check` is the inner loop and answers in about a minute: build,
  linters, unit and strict-parser tests, Wycheproof vectors, and the
  packaged-object export list. `make check-slow` runs what costs minutes —
  the proofs, e2e against a real server, the spec differential, the
  sequence enumerations — and the nightly runs it. Both must pass; they
  are split by duration, not by importance. The slow proof tier runs as
  `make prove-slow` in CI and before a release.
- Dev tooling lives in `tools/`: the lint helper scripts and the node
  packages commitlint needs. Nothing there is built into the library.
- The lint tools are required, not optional. clang-tidy, clang-format,
  cppcheck, semgrep, shellcheck, commitlint and lake each fail `make lint`
  when missing, on every machine. A lint gate that skipped would let
  `make check` exit 0 with a finding still waiting on CI. Install them
  at the versions the env block in `.github/workflows/check.yml` pins.
  Targets outside `lint` still skip locally and fail only on CI — cbmc
  for the proofs, gcovr for coverage, and lake for the differential and
  the spec coverage report. Skipping those costs coverage the pushed
  branch still gets; skipping a linter hides a verdict already at hand.
- The PIN variable splits the pinned-key build: RSA-PSS by default,
  `PIN=ecdsa` for P-256. One algorithm per library object; test both.
- The RAND variable declares the entropy pattern and is the one build
  variable with no default: `RAND=extern` when the image supplies
  `ch_rand_bytes`, `RAND=drbg` to package the reference generator and
  export `ch_drbg_seed`. `make lib` needs one of them; `make check`
  builds both. A build naming neither stops at an `#error` in `cfg.h`,
  which is the point — docs/decisions.md 20 has the reasoning.
- Generated files never get committed. `test/gen_rfc8448.py` and
  friends regenerate them into `bin/`; if you change a generator,
  the diff shows in the tests that consume its output.
- Every document must be named in the README — `make lint-docs`
  fails on an orphan.
- The status checks main requires before a merge are listed in
  `.github/required-status-checks.txt`, one job id per line. A step in
  `check.yml`'s check job fails when GitHub's branch setting and that
  file disagree, so a change to the required set edits both in one
  commit.

## Security reports are not PRs

A vulnerability goes through the private route in
[SECURITY.md](SECURITY.md), never the public tracker and never a
public PR that fixes-and-reveals it in one step.
