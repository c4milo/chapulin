# Verification

This page states what is proved, at what bound, what is only tested,
and what rests on neither. The README's "Verification and testing"
section summarizes it.

Four layers cover four different failure classes:

- **Proofs cover memory safety.** See [What the proofs cover](#what-the-proofs-cover)
  and [Harnesses](#harnesses).
- **Vectors cover known answers.** See [Known-answer vectors](#known-answer-vectors).
- **A Lean spec covers what the code computes.** See
  [The differential oracle](#the-differential-oracle).
- **Some properties rest on tests, not proofs.** See
  [What rests on tests, not proofs](#what-rests-on-tests-not-proofs).

## What the proofs cover

99 of the 132 C sources in the tree root are compiled into a
[CBMC](https://www.cprover.org/cbmc/) harness that a launch line in
`proof/run.sh` runs. For every input within the harness's bound, the
proof shows the source is free of:

- out-of-bounds access;
- invalid pointers;
- bad shifts;
- division by zero;
- signed overflow, except in the harnesses that run without that check:
  `x25519`, `x25519_mul_alias_a`, `x25519_mul_alias_b`,
  `x25519_mul_inputs_alias` and `x25519_sqr` (see [x25519](#x25519)).

The wide X25519 field's harnesses also check unsigned wrap, which C
defines and the other checks never see, because that field's bounds are
all on unsigned values (see [x25519_wide](#x25519_wide)). The wide P-256
files' harnesses check it for the same reason
(see [p256_wide](#p256_wide)). So do four of the harnesses of RSA's
64-bit arithmetic, whose claim is that no sum in it wraps
(see [rsa_mont64](#rsa_mont64)), the two that prove how the signer on
those words reads an exponent (see [rsa_sign64](#rsa_sign64)), the
harness of the AVX-512 IFMA product's sums (see [rsa_ifma](#rsa_ifma)),
the two that bound the AVX-512 IFMA Poly1305's sums and powers of r
(see [poly1305_ifma](#poly1305_ifma)), and the harness of P-384's
64-bit field, whose claim is the same (see [p384_wide](#p384_wide)).

Where a bound equals the module's real maximum, the proof covers all
inputs.

### Sources with no launched harness

The other 33 sources are in no such harness:

| Source | Why | What covers it instead |
|---|---|---|
| `srv_flight.c` | Its harness's formula returns no verdict ([srv_flight](#srv_flight)). | `bin/srv_flight_test` |
| `srv_tcp_nonblocking.c` | Its harness's formula returns no verdict ([srv_tcp_nonblocking](#srv_tcp_nonblocking)). | `bin/srv_tcp_nonblocking_test` |
| `srv_out.c`, `srv_quic.c`, `tcp_nonblocking.c`, `tcp_nonblocking_step.c` | No harness. | `bin/srv_flight_test`, `bin/srv_quic_test`, `bin/srv_tcp_nonblocking_test` and `bin/tcp_nonblocking_loop_test` |
| `aes_hw.c` | It calls the compiler's AES intrinsics, which CBMC cannot unwind. | `bin/aes_equiv_test` holds its cipher and both architectures' key expansions to `quic_aes_soft.c`, and searches the stack each expansion leaves ([The host object's AES key expansions](#the-host-objects-aes-key-expansions)). |
| `ghash_hw.c` | It runs GHASH on the carry-less multiply intrinsics, through `ghash_vector.h`. | `bin/ghash_equiv_test` holds it to `gcm.c`'s proven portable multiply. |
| `gcm_hw.c` | It runs counter mode and the one-pass seal and open on the AES and carry-less multiply intrinsics. | `bin/aes_equiv_test` holds its counter mode to `quic_aes_soft.c`, and `bin/ghash_equiv_test` holds its seal and open to `gcm.c`'s proven one-block loop and portable GHASH. |
| `gcm_vaes.c` | It runs `gcm_hw.c`'s three loops on the 256-bit VAES and VPCLMULQDQ intrinsics. | On an x86-64 CPU with those instructions, `bin/aes_equiv_test` holds its counter mode to `quic_aes_soft.c`, and `bin/ghash_equiv_test`, `bin/quic_test_hw` and the Wycheproof host binary run its seal and open against `gcm.c`'s proven one-block loop and portable GHASH and the published vectors ([The x86-64 kernels](#the-x86-64-kernels)). |
| `chacha20_vector.c` | It runs ChaCha20 on NEON or SSE2 intrinsics, which CBMC cannot unwind. | `bin/chacha20_equiv_test` holds it to `chacha20.c`'s proven loop, and RFC 8439's vectors and the Wycheproof suite run on it ([The vector ChaCha20](#the-vector-chacha20)). |
| `chacha20_avx2.c` | It runs ChaCha20 on AVX2 intrinsics. | On an x86-64 CPU with AVX2, `bin/chacha20_equiv_test` holds it to `chacha20.c`'s proven loop, and `bin/unit_host` and the Wycheproof host binary run RFC 8439's vectors and the Wycheproof suite on it ([The x86-64 kernels](#the-x86-64-kernels)). |
| `chacha20_avx512.c` | It runs ChaCha20 on AVX-512F intrinsics, and has a body on x86-64 alone. | On an x86-64 CPU with AVX-512F, `bin/chacha20_equiv_test` holds it to `chacha20.c`'s proven loop, and `bin/unit_host` and the Wycheproof host binary run RFC 8439's vectors and the Wycheproof suite on it under a `ch_cfg.cpu` value with `CH_CPU_AVX512_IFMA`; the nightly's `rsa-ifma-sde` job runs the first under Intel SDE. |
| `avx512_wipe.c` | It is one block of inline assembly, which CBMC does not read, and holds no C a harness could drive. It has a body on x86-64 alone. | On a CPU with AVX-512F, `bin/avx512_wipe_test` sets every bit of zmm0 to zmm31 and k1 to k7, calls it, and requires each register to read back as zero; the nightly's `rsa-ifma-sde` job runs the binary under Intel SDE. |
| `poly1305_vector.c` | It runs Poly1305's block loop on NEON or SSE2 intrinsics. | `bin/poly1305_equiv_test` holds it to `poly1305.c`'s proven loop, and RFC 8439's vectors and the Wycheproof suite run on it ([The vector Poly1305](#the-vector-poly1305)). |
| `poly1305_avx2.c` | It runs Poly1305's block loop on AVX2 intrinsics, and has a body in an x86-64 host object's native copy alone. | On a CPU with AVX2, `bin/poly1305_equiv_test` holds it to `poly1305.c`'s proven loop, and the Wycheproof suite's four longest messages run on it ([The AVX2 Poly1305](#the-avx2-poly1305)). |
| `mlkem_vector.c` | It runs ML-KEM's NTT and base multiplication on NEON or SSE2 intrinsics. | `bin/mlkem_vector_equiv_test` holds it to `mlkem_poly.c`'s proven loops, and the ML-KEM-768 vectors and the Wycheproof suite run on it ([The vector NTT](#the-vector-ntt)). |
| `keccak_avx2.c` | It runs Keccak-f[1600] on four states at once in AVX2 intrinsics, and has a body on x86-64 alone. | On a CPU with AVX2, `bin/mlkem_avx2_equiv_test` holds its four SHAKE128 streams to `sha3.c`'s proven code for ten blocks each ([The four-way Keccak](#the-four-way-keccak)). |
| `mlkem_avx2.c` | It is `mlkem.c` compiled once more beside a row sampler that calls `keccak_avx2.c`, so it has a body on x86-64 alone. | The `mlkem` harness proves `mlkem.c`'s text but for `mlk_matvec_row`, which the copy supplies, and `bin/mlkem_avx2_equiv_test` holds the copy's keys, ciphertexts and secrets to `mlkem.c`'s ([The four-way Keccak](#the-four-way-keccak)). |
| `sha256_hw.c` | It runs SHA-256 on the CPU's SHA-256 intrinsics, which CBMC cannot unwind. | `bin/sha2_equiv_test` holds it to `sha256.c`'s proven code, and FIPS 180-4's vectors and the Wycheproof HMAC and HKDF suites run on it ([The hash instructions](#the-hash-instructions)). |
| `sha512_hw.c` | It runs SHA-384 and SHA-512 on arm64's SHA-512 intrinsics, and has no body on x86-64. | On arm64, `bin/sha2_equiv_test` holds it to `sha512.c`'s and `sha512_compress.c`'s proven code, and FIPS 180-4's vectors, RFC 4231's and the Wycheproof HMAC-SHA-384 and HKDF-SHA-384 suites run on it ([The hash instructions](#the-hash-instructions)). |
| `sha3_hw.c` | It runs Keccak-f[1600] on arm64's SHA-3 intrinsics. It has no body on x86-64, and none under a compiler other than clang, because gcc 13 keeps lanes of the state in stack slots it picks (decision 99). | Where it has a body, `bin/sha3_hw_equiv_test` holds it to `sha3.c`'s proven code, compares it with FIPS 202 as `proof/sha3_reference.h` writes it, and searches the stack each kind of call leaves for any lane the call computed. |
| `mlkem_hw.c`, `mlkem_poly_hw.c` | Each is its file compiled once more for a host object, with its SHA-3 and SHAKE calls on `sha3_hw.c` and under the names `keccak_hw.h` gives (decision 99). Each has a body where `sha3_hw.c` has one. | The file's own harnesses prove the same text under its own names, but for the host arms of `mlkem.c`'s three NTT wrappers, each one call into `mlkem_vector.c` ([The vector NTT](#the-vector-ntt)), and `bin/mlkem_hw_equiv_test` holds each copy's keys, ciphertexts and secrets to its file's. |
| `hkdf_hw.c`, `keysched_hw.c` | Each is its file compiled once more for a host object, with its SHA-256 calls on `sha256_hw.c`, on arm64 its SHA-384 calls on `sha512_hw.c`, and under the names `hash_hw.h` gives (decision 93). | The file's own harnesses prove the same text under its own names, `bin/sha2_equiv_test` holds each copy's output to its file's, and `test/hash-builds.sh` reads which hash each calls. |
| `build.c` | It holds one const record and no function, so there is no path for a harness to drive. | `lib-check` reads every field back. |
| `poly1305_native.c`, `mlkem_poly_native.c` | Each is its file compiled once more for a host object, on the native multiply and under the names `widemul_native.h` gives (decisions 87 and 89). | The file's own harnesses, which compile it on the native multiply because `proof/run.sh` passes them `CH_NATIVE_WIDEMUL`: the same text under other names, but for the arms of `poly1305.c`'s `whole_blocks` that hand whole groups of blocks to the vector paths, and on x86-64 `poly1305_update_avx2` and `poly1305_update_ifma`, which only `poly1305_native.c` compiles ([The host object's two multiplies](#the-host-objects-two-multiplies)). |
| `poly1305_vector_native.c` | It is `poly1305_vector.c` under the names `widemul_native.h` gives, on the same intrinsics. | `bin/poly1305_equiv_test` holds `poly1305_vector.c` to `poly1305.c`'s proven loop, and the host object's binaries run the copy over RFC 8439's vectors and the Wycheproof suite. |
| `poly1305_avx2_native.c` | It is `poly1305_avx2.c` under the names `widemul_native.h` gives, on the same intrinsics. | `bin/poly1305_equiv_test` holds the copy to `poly1305.c`'s proven loop on a CPU with AVX2. |
| `poly1305_ifma_native.c` | It is `poly1305_ifma.c` under the names `widemul_native.h` gives, on the AVX-512 IFMA intrinsics in `poly1305_ifma_lanes.h`, which CBMC cannot read. | The `poly1305_ifma` harnesses prove the same text over a model of each instruction ([poly1305_ifma](#poly1305_ifma)), and on a CPU with AVX-512 IFMA `bin/poly1305_equiv_test` holds the copy to `poly1305.c`'s proven loop and searches the stack below a call for every power of r it computes; the nightly's `rsa-ifma-sde` job runs it under Intel SDE. |
| `tls.c` | No harness. Its send path, `ch_write` and `ch_writable_len`, is `tls_write.c`, which [writable_len](#writable_len) proves. | `bin/unit`, `bin/tcp_blocking_loop_test`, `bin/tcp_nonblocking_loop_test` and the webpki loop tests |

`aes_extern.c` is proved, but only up to the `ch_aes_block` the caller
writes, which has no body here to prove ([aes_extern](#aes_extern)).
`tcp_nonblocking_frame.c` is in a harness for one call, and the rest of
the file is not proved ([record_whole_len](#record_whole_len)).
`tls_write.c` holds `ch_write`, `ch_writable_len` and their helpers
alone, and [writable_len](#writable_len) drives both calls in each build
the file compiles differently in.

`make check` runs `make proof-coverage`, which counts them and
regenerates the source-by-source table in `bin/proof-coverage.md`. It
fails when this section's count, the list of harnesses run without the
signed-overflow check, the table above or the harness entries below
disagree with `proof/run.sh`.

## How the proofs run

The proofs run in two tiers:

- **Fast tier.** `make check-slow` runs it through `make prove`. CI
  runs it in the check workflow's `prove` job on every push to main, but
  not on a pull request, which gets `make check` and no proof job.
- **Slow tier.** `make prove-slow` runs its harnesses. CI runs them
  nightly, one job each.

A slow-tier entry below carries the verdict of the last nightly job that
finished, not of the current commit. A harness that starts and returns
no verdict proves nothing, and this page cannot tell that apart from one
that passed. For the slow entries, read the nightly.

[`docs/proofs.md`](proofs.md) is the harness playbook: the measured
cost model and the rules that keep a formula solvable.

CBMC found one real bug during development: `carry()` left-shifted a
negative value, which is undefined behavior even though compilers
tolerate it. The code multiplies instead now.

## Harnesses

Each entry opens with its harnesses and each one's tier, as
`proof/run.sh` launches them. A harness marked "no launch line" exists
and proves nothing. The entry then states what the harnesses prove, the
bound, and what they leave unproved. `make proof-coverage` fails when a
launched harness has no entry here, or when an entry gives a harness a
tier `proof/run.sh` does not.

The entries are grouped by area:

- [Constant-time helpers and buffers](#constant-time-helpers-and-buffers)
- [Hashes, key derivation and the DRBG](#hashes-key-derivation-and-the-drbg)
- [Symmetric ciphers and AEADs](#symmetric-ciphers-and-aeads)
- [Key exchange](#key-exchange)
- [Signatures](#signatures)
- [Record layer and transport I/O](#record-layer-and-transport-io)
- [Client handshake](#client-handshake)
- [Server](#server)
- [QUIC](#quic)
- [Certificates: provisioning and the ca modes](#certificates-provisioning-and-the-ca-modes)
- [Certificates: TRUST=webpki](#certificates-trustwebpki)

### Constant-time helpers and buffers

#### ct

- **Harness:** `ct` (fast)
- **Proves:** `ct_memeq` matches a plain compare, and
  `proof/ct_wipe_stub.c`, the `ct_wipe` contract stub, writes zero to
  p[0..n) and no byte past it.
- **Bound:** inputs ≤ 64 B.
- **Not proved:** the stub is not the `ct_wipe` that ships. It is the
  byte loop `ct_wipe` was before `ct_wipe.c` began to call `memset`
  through a volatile function pointer, one volatile store per byte, and
  every launch line that links `ct.c` links it in place of `ct_wipe.c`.
  So each of those harnesses proves its own code over the loop, and its
  formula and its `ct_wipe.0` unwind bound did not change when the
  shipped body did. The two have one contract, zero over p[0..n) and no
  other byte written: this harness proves it of the stub and `ct_wipe`
  proves it of `ct_wipe.c` (docs/decisions.md 91).

#### ct_wipe

- **Harness:** `ct_wipe` (fast)
- **Proves:** `ct_wipe.c`, the `ct_wipe` that ships, is memory-safe and
  UB-free, writes zero to p[0..n) and no other byte, and makes no call
  when n is 0, so a null p with nothing to wipe is safe.
- **Bound:** none on the length: a heap buffer of every size CBMC's
  pointer encoding holds, and every offset and n inside it, with one
  nondet index for every byte.
- **Not proved:** CBMC reads the volatile pointer as the `memset` it was
  initialized with and runs its own model of `memset`, so the libc's
  `memset` is not proved, and neither is the property the pointer exists
  for, that no compiler deletes the call. That is a property of the
  compiler's output, not of the C: docs/decisions.md 91 records the
  disassembly read for each compiler and target, and
  `bin/poly1305_equiv_test` checks the stack after a wipe whose body the
  compiler can see.

#### ctwidemul

- **Harness:** `ctwidemul` (fast)
- **Proves:** the 16x16 decomposition in `ct.h` is free of undefined
  behavior and keeps its shifts in range, and returns the same product
  as the C operator it stands in for. This equality is what carries
  every other proof to a target that runs the decomposition; see
  [What carries the proofs to the target](#what-carries-the-proofs-to-the-target).
- **Bound:** undefined behavior and shift range at full 32-bit width;
  the products themselves at 8-bit operands, the widest bound whose
  formula converges.

#### softmul

- **Harness:** `softmul` (fast)
- **Proves:** `softmul.c`'s constant-time `__mulsi3` and `__muldi3` are
  free of undefined behavior over unconstrained 32-bit and 64-bit
  inputs, run the fixed loop counts they claim, and return the same
  product as the C operator at 8-bit operands.
- **Bound:** the undefined behavior, pointer and unwinding checks run on
  unconstrained inputs; the product equality at operands ≤ 0xFF on both
  sides. Both functions still run all 32 and 64 iterations, but the
  equality does not cover the accumulator's upper half, since an 8x8
  product is 16 bits. 12-bit operands returned no verdict in 5 minutes.

#### buf

- **Harness:** `buf` (fast)
- **Proves:** any 12-operation reader/writer run stays safe, and the
  length never exceeds the capacity.
- **Bound:** buffers ≤ 64 B.

### Hashes, key derivation and the DRBG

#### sha256

- **Harness:** `sha256` (slow)
- **Proves:** safe for any two-chunk split.
- **Bound:** messages ≤ 96 B. That covers every fill state the padding
  path can see: the fill is the length mod 64, and 0..96 covers all 64
  residues.

#### sha512

- **Harnesses:** `sha512` (slow), `sha512_compress` (fast)
- **Proves:**
  - `sha512`: the framing is safe for both SHA-512 and SHA-384, with the
    compression function stubbed to its contract. The framing is the
    block assembly across a two-chunk split, the padding and the 128-bit
    length.
  - `sha512_compress`: the compression function is safe over any state
    and any block, which discharges that stub.
- **Bound:** framing: messages ≤ 192 B, every fill state the padding
  path can see, since the fill is the length mod 128 and 0..192 covers
  all 128 residues. Compression: the full domain.

#### sha3

- **Harnesses:** `sha3` (fast), `sha3_stream` (fast), `sha3_round` (fast)
- **Proves:**
  - `sha3`: every mode is safe for a one-call message and XOF output
    from a fresh context.
  - `sha3_stream`: the SHAKE streaming calls are safe from any context
    state (arbitrary lanes, either rate, every position), for split
    absorbs and squeezes.
  - `sha3_round`: `sha3.c`'s round, written out lane by lane, leaves the
    state that FIPS 202's round leaves, for every state and every round
    constant. The reference is `proof/sha3_reference.h`: the standard's
    five step algorithms as loops, with the rho offsets and the round
    constants computed by the standard's rules. The table of round
    constants holds the 24 values the standard's shift register gives,
    and `keccak_f1600` leaves the state that 24 rounds of the reference
    leave from the state of zeros (decision 98, INV-45).
- **Bound:** one-call: messages ≤ 200 B, output ≤ 400 B. Streaming:
  chunks ≤ 32 B. The round: the full domain. The 24 rounds: one state.
- **Tested instead:** that absorb, the padding and squeeze move the
  standard's bytes. `bin/sha3_equiv_test` holds every entry of `sha3.h`
  to the reference's sponge, which moves one byte at a time, over 6,043
  outputs; `bin/sha3_test` runs the FIPS 202 vectors; and the spec
  differential runs every mode against the Lean model.

#### hkdf

- **Harnesses:** `hkdf` (fast), `hkdf_expand` (slow), `hkdf_expand_label` (slow)
- **Proves:** HMAC and extract (`hkdf`), expand (`hkdf_expand`) and
  expand-label (`hkdf_expand_label`) are safe over the proven sha256
  contract.
- **Bound:** keys ≤ 96 B; HMAC and extract messages ≤ 48 B; expand and
  expand-label output ≤ 96 B, and info ≤ `HKDF_INFO_MAX`, which is 54 at
  the default label cap of 12, the cap these harnesses prove.
- **Not proved:** `EXPORTER=on` raises the label cap to 32 and the info
  bound to 74, and no launched harness proves that domain (see
  [keysched_exporter](#keysched_exporter)).

#### hkdf384

- **Harnesses:** `hkdf384` (fast), `hkdf384_expand` (slow), `hkdf384_expand_label` (slow)
- **Proves:** the same calls under `CH_HASH_SHA384`, the build
  `TLS_AES_256_GCM_SHA384` needs, over the proven sha256 and sha512
  contracts:
  - `hmac_sha384` directly;
  - extract with `hash_len` free over 32 and 48, so both arms of the
    `hmac` dispatcher;
  - expand and expand-label at `hash_len` 48.
- **Bound:** keys ≤ 160 B; HMAC and extract messages ≤ 48 B; expand and
  expand-label output ≤ 144 B, info ≤ 70 B, context ≤ 48 B.
- **Not proved:** the SHA-256 arm of that build, 32-byte hashes in its
  48-byte buffers. The [hkdf](#hkdf) harnesses prove the SHA-256 arm in
  buffers sized to it.

#### keysched, keysched384

- **Harnesses:** `keysched` (fast), `keysched384` (fast)
- **Proves:** every `ks_*` entry point is memory-safe and UB-free over
  unconstrained secrets and lengths, with hkdf real and the hashes
  stubbed to their contracts, at the default label cap of 12.
  `keysched384` is the same harness under `CH_HASH_SHA384` at `hash_len`
  48.
- **Bound:** secrets 32 B; 48 B for `keysched384`.
- **Not proved:** what the outputs hold. Nothing here asserts it.

#### keysched_exporter

- **Harness:** `keysched_exporter` (no launch line)
- **Not proved.** `proof/keysched_exporter_harness.c` runs the keysched
  harness under `EXPORTER=on`, which adds `ks_exp_master` and
  `ks_exporter` and widens hkdf's label cap to 32. Its formula returns
  no verdict: none in 10 minutes with the label length free, and none in
  7 min 50 s with it fixed at 13 and 32. `proof/run.sh` records both.
- **Tested instead:** `bin/exporter_test`, whose four vectors are
  cross-checked against an independent from-spec implementation rather
  than published, since RFC 9846 prints none.

#### drbg

- **Harness:** `drbg` (fast)
- **Proves:** the generator stays safe for any seed `ch_drbg_seed` takes
  and any request, seeded and across rekeys, with SHA-256 and ChaCha20
  stubbed to their contracts.
- **Bound:** seeds of 32 to 96 B, requests ≤ 96 B.
- **Not proved:** that a seed under 32 bytes faults, and that the key is
  the seed's SHA-256. `bin/drbg_test` tests both.

### Symmetric ciphers and AEADs

#### chacha20

- **Harness:** `chacha20` (fast)
- **Proves:** safe at any counter, in place and into a distinct buffer.
- **Bound:** ≤ 160 B: three blocks, full, full and partial.
- **Not proved:** a host object's vector path, whose intrinsics CBMC
  cannot unwind. The harness compiles `chacha20.c` without
  `-DCH_CPU_RUNTIME`, as a device object does, and
  [The vector ChaCha20](#the-vector-chacha20) states what holds the
  vector path to this loop.

#### poly1305

- **Harness:** `poly1305` (fast)
- **Proves:** safe for any three-chunk split; 64-bit products stay in
  range.
- **Bound:** messages ≤ 80 B: five blocks, crossing the buffered-block
  path in every alignment.
- **Not proved:** the five-call shape `aead.c` uses. The aead harnesses
  stub Poly1305, so that shape rests on the unit vectors, Wycheproof and
  the differential. Nor a host object's vector Poly1305, whose intrinsics
  CBMC cannot unwind. The harness compiles `poly1305.c` without
  `-DCH_CPU_RUNTIME`, so `whole_blocks` calls the loop it proves, and
  [The vector Poly1305](#the-vector-poly1305) states what holds the
  vector path to that loop.

#### poly1305_ifma

- **Harnesses:** `poly1305_ifma_lanes` (fast), `poly1305_ifma_sums` (fast), `poly1305_ifma_product` (fast), `poly1305_ifma_blocks` (fast)
- **Build:** Poly1305's block loop on AVX-512 IFMA (`poly1305_ifma.c`),
  under `-DCH_CPU_RUNTIME` and `-DCH_POLY1305_IFMA_MODEL`, over
  `test/poly1305_ifma_model_lanes.h`, the model of each instruction in
  portable C that `bin/poly1305_equiv_test` runs on every machine. The
  two lane multiplications are contracts (`proof/poly1305_ifma_stubs.h`):
  each asserts that its operands are below 2^52 and adds a value below
  the power of two their bit lengths give. `poly1305_ifma_blocks` takes
  any value from each instead. `poly1305_ifma_sums` and
  `poly1305_ifma_product` add `--unsigned-overflow-check`.
- **Proves:**
  - `poly1305_ifma_lanes`: on the model's real multiply, each lane
    multiplication adds a value in its contract's set, for every sum and
    every pair of operands below 2^52.
  - `poly1305_ifma_sums`: no sum wraps and every multiplication's
    operands are below 2^52, at each step of the kernel's loop, from
    digits within the bounds the stubs name, digits 0 and 1 below
    2^44 + 2^17 and digit 2 below 2^42 + 2^17: `digits_of_words` on any
    accumulator whose words are at most 2^26; a group's `group_sums` and
    `carry` over any 256 bytes and any two multipliers within the bounds,
    which leave the lanes within them again; and the lane totals,
    `words_of_totals` and `carry_scalar` at the end.
  - `poly1305_ifma_product`: `multiplier_product` from any two
    multipliers within the bounds, the same struct or two, wraps no sum,
    takes no operand of 2^52 or more, and writes a product within them.
    `compute_powers` runs that step five times on r, whose digits
    `digits_of_words` writes within the bounds, and on products, and its
    selects copy lanes of those or 1, so its four multipliers keep the
    bounds by induction; the Lean model's `powers_mod` proves that
    composition.
  - `poly1305_ifma_blocks`: `poly1305_ifma_blocks` whole, `compute_powers`
    included, reads and writes inside the message, the context, its frame
    and the struct of powers it wipes, at one group and at two, which run
    every statement.
- **Bound:** one group of sixteen blocks for `poly1305_ifma_sums`, which
  the loop repeats from the bounds it proves; one and two groups for
  `poly1305_ifma_blocks`.
- **Not proved:** any value the kernel computes.
  `spec/lean/Spec/Poly1305Ifma.lean` proves on a model of the C that a
  group step computes (h + first) x + second y modulo 2^130 - 5 for its
  two multipliers x and y, that `compute_powers` gives each lane the
  power of r its blocks are owed, and the same bounds on the products
  themselves. `bin/diff_poly1305_ifma` compares that model with the C on
  samples, and `bin/poly1305_equiv_test` holds the C to `poly1305.c`'s
  loop
  ([The AVX-512 IFMA Poly1305](#the-avx-512-ifma-poly1305)). No proof
  joins the lanes' groups into Horner's rule over the whole message. The
  instructions in `poly1305_ifma_lanes.h`, which CBMC cannot read, are
  held to `poly1305.c`'s loop only by `bin/poly1305_equiv_test`, on a CPU
  with AVX-512 IFMA or under SDE.

#### aead

- **Harnesses:** `aead` (fast), `aead_forge` (fast), `aead_overlap` (fast), `aead_inplace` (no launch line)
- **Proves:**
  - `aead`: seal and open round-trip.
  - `aead_forge`: a forged tag writes zero bytes.
  - `aead_overlap`: backward-overlap decrypt works.

  ChaCha20 and Poly1305 are stubbed to their contracts, which their own
  harnesses prove: a keystream that is the same for the same key, nonce
  and counter, and a tag that is a function of the bytes absorbed.
  Compiling them in returned no verdict in five hours; the stubbed
  formulas take about three seconds. The top of `proof/aead_stubs.h`
  states what the stubs give up, and why the composition is an argument
  rather than a machine-checked step.
- **Bound:** plaintext ≤ 16 B, aad ≤ 16 B.
- **Not proved:** sealing fully in place (`pt == ct`, the shape every
  outgoing record uses). `proof/aead_inplace_harness.c` states it, but
  the formula has returned no verdict, so it carries no launch line.

#### aes

- **Harness:** `aes` (fast)
- **Build:** `TRANSPORT=quic-nonblocking` only.
- **Proves:** the AES-128 key schedule and forward cipher and both
  `aes_public_key` constructors are safe over unconstrained inputs, in
  the aliasing shape the callers use (`in == out`) and at every
  Destination Connection ID length RFC 9000 §17.2 admits. It also covers
  the first length past the cap, where the call refuses without reading
  the pointer. The QUIC version the constructors choose a salt, labels
  and a Retry key by is any value, not only one the callers admit, so
  both entries of each per-version table, version 1's and version 2's,
  are read inside the formula. HKDF is stubbed to its contract
  (`proof/aes_stubs.h`), which the three `hkdf` harnesses prove. Which
  salt, labels and key a version gets is not proved: RFC 9001's and RFC
  9369's Appendix A vectors in `bin/quic_test` and the Lean differential
  test that.
- **Bound:** connection IDs ≤ `CH_QUIC_DCID_MAX` (20 B); the rest of the
  domain is fixed-size.

#### aes_extern

- **Harness:** `aes_extern` (fast)
- **Proves:** `aes_extern.c`'s four entries, which a `SUITE=aesgcm
  AES=extern` build compiles, are safe over unconstrained inputs.
  - Each expansion writes the key and then zeros at exactly the bound
    `aes_block.h` states.
  - Each cipher entry calls `ch_aes_block` once, with the stored key,
    the key length its name says (16 or 32 bytes), a readable input and
    a writable output, `in == out` included.
- **Bound:** the full domain.
- **Not proved:** the cipher the image's peripheral computes, and its
  timing. The hook is a contract stub the harness defines. The
  `AES=extern` test binaries run a stand-in hook over the published
  vectors, Wycheproof and e2e.

#### aes256, aes_traffic

- **Harnesses:** `aes256` (fast), `aes_traffic` (fast)
- **Proves:**
  - `aes256`: the software AES-256 key schedule and forward cipher that
    `-DCH_AES_256_TEST` compiles are safe over unconstrained inputs, and
    `aes_encrypt_schedule` runs ten or fourteen rounds by the round
    count the schedule records. That software cipher is the reference
    `bin/aes_equiv_test` holds the instructions to.
  - `aes_traffic`: `aes_traffic_key_init` writes AES-128's round count
    for a 16-byte key and AES-256's for a 32-byte one, and the dispatch
    runs the cipher that count names, for one block and for counter
    mode's whole blocks, over contract stubs of `aes_hw.c`'s entries, in
    the TCP host object, which holds the instructions alone.
- **Bound:** the full domain.
- **Not proved:** the instructions' AES-256 cipher a suite build runs. CBMC
  cannot read an intrinsic, so `bin/aes_equiv_test` holds it to the
  software one over 200,400 pairs.

#### aes_runtime

- **Harness:** `aes_runtime` (fast)
- **Build:** `TRANSPORT=quic-nonblocking SUITE=aesgcm` as a host object
  (`-DCH_CPU_RUNTIME`), the object that holds the AES instructions and
  the table.
- **Proves:** `aes.c` is safe over unconstrained inputs and puts each key
  on the cipher `docs/decisions.md` entries 81 and 89 name, over contract
  stubs of both ciphers' six entries, each of which asserts the buffers
  `aes_block.h` states and whether the key in hand may run on it:
  - an Initial key expands and runs on the instructions only when the
    session's `ch_cfg.cpu` holds `CH_CPU_CONSTANT_TIME_AES`, and on the
    table for every other value, and both of its schedules record which;
  - the Retry key expands and runs on the table under any value;
  - the table runs no traffic key of either length.
- **Bound:** the full domain: every 32-bit `ch_cfg.cpu`, every admitted
  connection ID length and every endpoint byte.
- **Not proved:** either cipher's arithmetic, which `aes` proves for the
  table and `bin/aes_equiv_test` tests for the instructions; and `gcm.c`'s
  choice between the two GHASH bodies and between the one-block counter
  loop and `gcm_hw.c`, which `bin/aes_runtime_test` counts and
  `gcm.c`'s `instruction_rounds` asserts.

#### gcm

- **Harnesses:** `gcm_safety` (slow), `gcm_refusal` (slow), `ghash` (slow), `gcm` (no launch line), `gcm_forge` (no launch line)
- **Proves:**
  - `gcm_safety`: `gcm_seal`, `gcm_open` and `gcm_ghash` read and write
    only inside their buffers and commit no undefined behavior, for any
    key schedule, any nonce, and both aliasing shapes the header admits:
    separate buffers, and `pt == ct`, which is how `quic_initial.c`
    decrypts a payload in place.
  - `gcm_refusal`: `gcm_open` releases no plaintext. For any tag at
    all, a call that returns 0 leaves zeros in the n bytes of its output,
    and no call writes a byte past them. The open decrypts while it
    hashes and wipes what it wrote on a mismatch (`docs/decisions.md`
    entry 85). The same harness runs twice more, once per arm, with a
    define that asserts that arm is unreachable, and both runs must
    fail.
  - `ghash`: the same safety for GHASH alone, at sixteen blocks per
    argument, where the whole-module formula gets two.
- **Bound:** plaintext and associated data ≤ 32 B each for safety and
  refusal: two blocks, every length either side of the block boundary,
  on both arguments. ≤ 256 B each for `ghash`.
- **Not proved:**
  - that a genuine seal opens back to the plaintext it sealed;
  - that a forged tag is refused.

  `proof/gcm_harness.c` and `proof/gcm_forge_harness.c` state them, but
  neither formula returns a verdict, so neither carries a launch line,
  and `proof/run.sh` records both measurements. Those two rest on tests
  instead: SP 800-38D's four AES-128 cases, RFC 9001 Appendix A.2's
  client Initial packet and A.4's Retry tag, RFC 9369 Appendix A.2's
  and A.3's Initial packets and A.4's Retry tag in QUIC version 2, 67
  AES-128-GCM and 66 AES-256-GCM Wycheproof cases on all four
  builds, and the Lean differential.
- **The host object's GHASH and counter mode:** every harness compiles
  the portable GHASH and the one-block counter loop. A host object runs
  `ghash_hw.c`'s GHASH on the carry-less multiply instead, for a schedule
  on the AES instructions, three products
  a block and eight blocks a pass against the powers of H each call
  computes, with the reduction on the same instruction, and runs
  counter mode's whole blocks through `gcm_hw.c`'s `gcm_counter_blocks_hw`,
  several at a time, and a seal's and an open's whole passes of eight
  blocks through `gcm_seal_passes_hw` and `gcm_open_passes_hw`, which run
  counter mode and GHASH over the ciphertext in one loop. No harness reads
  any of them. `gcm_refusal`'s wipe on a mismatch sits in `gcm.c` after
  both paths, so it holds for both. `bin/ghash_equiv_test` holds both to
  the portable paths byte for byte, the opens in place and below the
  ciphertext included,
  `bin/aes_equiv_test` holds the multi-block counter mode to the soft
  cipher at every block count through three passes and across the 2^32
  counter wrap, and the vectors, the host Wycheproof test and
  `bin/diff_quic_hw` run over both.

### Key exchange

#### x25519

- **Harnesses:** `x25519_ops` (fast), `x25519` (slow), `x25519_mul` (fast), `x25519_mul_ct` (fast), `x25519_mul_alias_a` (slow), `x25519_mul_alias_b` (slow), `x25519_mul_inputs_alias` (slow), `x25519_sqr` (slow), `x25519_step` (slow), `x25519_tail` (fast)
- **Proves:**
  - carry, add, sub, pack, cswap and unpack are safe with every check
    on, add and sub in the ladder's aliased shape too, and the ladder's
    scalar bit index stays in bounds (fast tier);
  - mul's index walk is safe in every caller aliasing shape: distinct,
    output aliasing either input, and sqr's all-one-object. These run
    with the signed-overflow class off (slow tier, one shape set per
    formula);
  - a separate lemma proves mul's int64 accumulation and fold cannot
    overflow (fast tier).

  Every one of these holds only inside the word range under **Bound**.
  `x25519_step` and `x25519_tail` prove the ladder keeps its words
  there. One loop step, on the shipped `step()`, takes any state with
  every word in (-2^17, 2^17) back into that bound and hands mul only
  operands under 2^18; mul's output, one `invert` round, and the final
  multiply and pack do the same. The 255 steps and 254 rounds follow by
  induction from a base case read off `ladder()`'s prologue.

  Both harnesses replace mul's multiply with a magnitude contract
  (`proof/x25519_stubs.h`) that `x25519_mul` discharges on the native
  multiply and `x25519_mul_ct` on the shipped decomposition; see
  [x25519's ladder proof abstracts the multiply to its magnitude](#x25519s-ladder-proof-abstracts-the-multiply-to-its-magnitude).
- **Bound:** words ≤ 2^24; into carry, ≤ 2^58; between the ladder's
  operations, < 2^17.

#### x25519_wide

- **Harnesses:** `x25519_wide_mul` (fast), `x25519_wide_sqr` (fast), `x25519_wide_ops` (fast), `x25519_wide_step` (fast), `x25519_wide_invert` (fast), `x25519_wide_tail` (fast), `x25519_wide_mul128` (fast)
- **Build:** a host object's wide field (`x25519_wide.c`, INV-34), under
  `-DCH_CPU_RUNTIME`, with `--unsigned-overflow-check` on every line.
- **Proves:**
  - On the real 64x64->128 multiply, `mul` and `sqr` over any operands
    whose words are under 2^54 wrap nothing: every column sum stays
    under 2^115 and every carry under 2^64. They leave words 0, 2, 3 and
    4 under 2^51 and word 1 under 2^51 + 2^13.
  - add, sub, `mul_a24`, cswap, unpack and pack are safe at the same
    bounds; cswap swaps exactly when its bit is 1, and pack writes a
    value below p.
  - `x25519_wide_step` proves one loop step, on the shipped `step()`,
    from any state inside INV-34's bounds back into them.
    `x25519_wide_invert` proves the whole inversion chain, and
    `x25519_wide_tail` the output form of every product and the final
    multiply and pack. Those three replace the multiply with a contract,
    operands under 2^55 and 2^60 to a product under 2^115, which
    `x25519_wide_mul128` proves on the real multiply.
  - The 255 steps follow by induction from a base case read off
    `x25519_wide_ladder()`'s prologue.

  One step over the real products also converged, in 64 s at 4.5 GB,
  and has no launch line. The field's two entries, `x25519_wide` and
  `x25519_wide_base`, are `x25519.c`'s clamp and all-zero check compiled
  a second time around this ladder. No harness drives them: [x25519](#x25519)
  proves that text around the 16-word ladder, and the vectors below run
  it around this one.
- **Bound:** operand words < 2^54; between the ladder's operations,
  word 1 < 2^51 + 2^20 and every other word < 2^51.

#### mlkem

- **Harnesses:** `mlkem` (fast), `mlkem_poly` (fast), `mlkem_ntt` (slow), `mlkem_invntt_low` (slow), `mlkem_invntt_high` (slow), `mlkem_basemul` (slow)
- **Proves:**
  - keygen, encaps and decaps are safe for every seed, message, and
    hostile key or ciphertext, with the polynomial layer stubbed to its
    contracts;
  - the polynomial layer is safe over full-range int16 coefficients.
    That is a superset of anything the KEM layer passes it, so no
    coefficient value can overflow the reduction arithmetic.

  Sampling, reductions and coding prove in the fast tier. The NTT, the
  two halves of its inverse, and the base multiplication, whose
  chained-product overflow proofs are the SAT-hard part, each prove in
  their own slow-tier formula.
- **Bound:** the full domain: every input is a fixed-size array, and the
  sampling read stops at its 1536-byte cap.

#### p256_ecdh

- **Harness:** `p256_ecdh` (fast)
- **Proves:** the three public entries, over the scalar and point layers
  stubbed to their contracts (`p256_scalar_stubs.h`,
  `p256_point_stubs.h`):
  - memory safety over any 65 peer bytes and any 32 scalar bytes;
  - each entry answers 0 or 1;
  - a refusal leaves no private key, no public key and no shared secret
    behind, for every verdict the stubbed arithmetic can give.

  The ladder and the point decode are [p256_point](#p256_point)'s.
- **Bound:** any 65-byte point, any 32-byte scalar, full-range points,
  scalar bits 0..255.

#### hybrid_secret

- **Harness:** `hybrid_secret` (fast)
- **Build:** `KEX=pq`. It and [key_share](#key_share) are the only
  harnesses that build `-DCH_KEX_PQ`.
- **Proves:**
  - the `KEX=pq` shared-secret derivation is safe for any stored seed,
    any server ciphertext and any server share;
  - a refused key exchange wipes all 64 bytes rather than leaving half a
    secret on the stack (INV-3);
  - both exits leave the 64-byte ML-KEM seed zero.

  ML-KEM and x25519 are stubbed to their contracts, which their own
  harnesses prove.
- **Bound:** the full domain.
- **Not proved:** the rest of the hybrid driver. The differential, the
  sequence enumeration and the e2e tests cover it.

### Signatures

#### p256

- **Harnesses:** `p256` (fast), `p256_mul` (fast)
- **Proves:** the DER parser and word marshalling stay safe on hostile
  signatures; a carry lemma covers the Montgomery multiply.
- **Bound:** signatures ≤ 80 B.
- **Build:** a device object's arm of `p256.c`. A host object's arm reads
  the signature with the same DER parser and hands r and s to
  `p256_wide_verify.c` ([p256_wide_verify](#p256_wide_verify)).

#### p256_field

- **Harness:** `p256_field` (fast)
- **Proves:** the constant-time field arithmetic, which is written as
  masks and is proved as masks:
  - the word add and subtract, the conditional subtraction of p, the
    select, `p256_fe_cmov`, `p256_fe_cswap` and the three predicates each
    match a reference that writes the same choice as a branch, so an
    inverted mask fails here;
  - `p256_fe_add`, `p256_fe_sub` and `p256_fe_neg` take elements below p
    to an element below p;
  - the byte marshalling round-trips;
  - every routine is memory-safe and UB-free over full-range words in
    each aliasing shape a point routine uses.

  `p256_fe_inv`'s 256 rounds are not unrolled. Each round body is the
  Montgomery multiply, and the exponent bit index is proved in bounds
  for every round.
- **Bound:** full-range words, any 32 bytes, exponent bits 0..255.
- **Not proved:** the Montgomery product's value. Equality of two
  multipliers is the SAT instance that does not converge
  (`docs/proofs.md`), so the value rests on `test/p256_field_test.c`'s
  vectors, which run over both forms of `ct_widemul`, and its carry
  chain on the `p256_mul` lemma.

#### p256_scalar

- **Harness:** `p256_scalar` (fast)
- **Proves:** the signer's arithmetic mod the group order, concretely:
  - every masked choice equals a reference that writes the same choice
    as a branch;
  - both predicates equal `==`;
  - the byte round trip;
  - the two contracts `p256_sign.c` rests on: `p256_scalar_reduce` lands
    any 256-bit value below n, and `p256_scalar_add` leaves a scalar;
  - the three wipes `p256_scalar.h` states: `p256_scalar_add` hands
    `ct_wipe` its sum and the conditional subtraction's difference, and
    `p256_scalar_reduce` and `p256_scalar_reduced_mask` one difference
    each. The harness defines `ct_wipe`, the stub's loop with a count of
    the bytes it was handed, and asserts the count after each call.

  The Montgomery product is memory-safe. `p256_scalar_inverse`'s 256
  rounds are not unrolled; only its exponent index expressions are
  proven in bounds.
- **Bound:** full-range words, every aliasing shape `p256_sign.c` uses,
  exponent bits 0..255.
- **Not proved:** the Montgomery product's value; there is no assertion
  on it. Equality of two multipliers is the hard SAT instance, so its
  value rests on `test/p256_sign_test.c`'s vectors against Python's
  integers.

#### p256_point

- **Harnesses:** `p256_point` (fast), `p256_point_ladder` (fast)
- **Proves:**
  - `p256_point`: `p256_point_add` and `p256_point_affine`, over the
    field stubbed to its contract, in all four aliasing shapes,
    including both inputs the same object, which is the doubling the
    ladder performs.
  - `p256_point_ladder`: one round of `p256_point_mul`, on the shipped
    `ladder_round`, for any scalar, any three points and any bit index
    in [0, 255]. So the index and the shift are proven in bounds, and
    every mask the round builds is 0 or all ones at every
    `p256_fe_cswap`.
- **Bound:** full-range coordinates.
- **Not proved:** the 256-round loop whole. It calls nothing but that
  round; unrolled whole, it returned no verdict in 42 minutes.

#### p256_wide

- **Harnesses:** `p256_wide_row` (fast), `p256_wide_row_sum` (fast), `p256_wide_sqr` (fast), `p256_wide_field` (fast), `p256_wide_field_mul` (fast), `p256_wide_scalar` (fast), `p256_wide_inverse_steps` (fast), `p256_wide_inverse_range` (slow), `p256_wide_inverse` (fast), `p256_wide_inverse_round` (fast), `p256_wide_point` (fast), `p256_wide_digit` (fast), `p256_wide_mul` (fast), `p256_wide_wipe` (fast)
- **Build:** a host object's wide P-256 files (`p256_wide_field.c`,
  `p256_wide_scalar.c`, `p256_wide_inverse.c`, `p256_wide_point.c`,
  `p256_wide_mul.c`, `p256_wide_table.c` and `p256_wide_wipe.c`,
  decisions 94 and 115), under `-DCH_CPU_RUNTIME`, with
  `--unsigned-overflow-check` on every line but `p256_wide_inverse_steps`,
  `p256_wide_inverse_range` and `p256_wide_inverse_round`: the inverse's
  masks and packed factors wrap on purpose, and the first two lines fix
  every value they compute by an equality instead.
- **Proves:**
  - `p256_wide_row`: on the real 64x64->128 multiply, one row of a
    product, x times four words plus four words, wraps nothing for any
    operands, so the word it returns holds everything above the four.
    The add with carry and the subtract with borrow each match a
    128-bit reference, and each carry out is 0 or 1.
  - `p256_wide_row_sum`: `p256_wide_row` once more, on another form of
    those two steps. `p256_wide_word.h` holds three forms and picks one
    by the compiler: the overflow builtins under clang, a 128-bit sum
    under gcc for a machine other than x86-64, and two intrinsics under
    gcc for x86-64. cbmc runs the preprocessor of the machine it is on,
    so each harness names its form. `p256_wide_row` and the three
    harnesses below read the builtins, and this one reads the sums. One
    reference holds both forms, so the two return the same word and the
    same carry for every operand, and a verdict over one form is a
    verdict over the other.
  - `p256_wide_sqr`: on the real 64x64->128 multiply, the square of
    four words, ten products whose cross terms are summed once, doubled
    and added to the four squares, wraps nothing for any words, so its
    eight words hold the whole square (decision 105). It reads the
    builtins, which `p256_wide_row` holds to the sums' reference.
  - `p256_wide_field`: every routine with no product, on its real body,
    the addition and the subtraction `p256_wide_field.h` defines inline
    among them (decision 114). The conditional subtraction of p, `p256_wide_fe_add`,
    `p256_wide_fe_sub`, `p256_wide_fe_cmov` and the three predicates
    each match a reference that writes the same choice as a branch, so
    an inverted mask fails here. Add, subtract
    and negate take elements below p to an element below p, and the
    negative of an element that is not zero is p less it, against a
    reference that subtracts the words as they are. The byte
    marshalling and the copies to and from `p256_field.h`'s words
    round-trip. The Montgomery reduction, which for this prime is shifts
    and adds, wraps nothing for any eight words, and takes a value below
    p * 2^256, which every product of two elements is, to a value below
    p.
  - `p256_wide_field_mul`: `p256_wide_fe_mul`, `p256_wide_fe_sqr`, the
    two domain conversions and `p256_wide_fe_inv` are safe and wrap
    nothing in every aliasing shape a point formula uses. Each row of a
    product is a contract there, any four words and any word above them,
    which `p256_wide_row` proves of the real row, and so is the square of
    four words, any eight words, which `p256_wide_sqr` proves.
    `p256_wide_fe_inv` runs over a contract of `p256_wide_inverse`, which
    reads its input and writes any four words.
  - `p256_wide_scalar`: the same for the arithmetic modulo the group
    order, whose reduction rounds are products. The conditional
    subtraction of n matches a reference that branches, a round's carry
    out is 0 or 1, and `mont_mul` and `p256_wide_scalar_mul` are safe in
    every aliasing shape `p256_sign.c` uses. `p256_wide_scalar_inverse`
    and `p256_wide_scalar_inverse_public` run whole over contracts of
    `p256_wide_inverse` and `p256_wide_inverse_public`.
  - `p256_wide_inverse_steps`: the binary GCD's pieces, on their real
    bodies, over every input. The approximations of any a and b are a
    reference's, which finds the bit length of a | b one bit at a time
    and reads the 33 bits from there one at a time. One step on any
    approximations, any odd second one and any factors packed two to a
    word leaves what a reference step that branches and keeps each
    factor in its own signed variable leaves, and the mask of the next
    approximation's low bit. And the unpacking returns every factor
    between -(2^31 - 1) and 2^31 from the packed words.
  - `p256_wide_inverse_range`: the reference's 31 steps, from the
    factors 1, 0, 0 and 1, end with every factor in that range, for any
    approximations with the second odd. So `step_factors` returns the
    reference's factors for every input. One formula holds all 31 steps,
    because only the whole run keeps a factor off -2^31.
  - `p256_wide_inverse`: the combinations of a round are safe and wrap
    nothing: the exact one for any operands and factors, and the one
    modulo m for any modulus and operands when the factors' sizes add
    to at most 2^31, over a row contract whose word above the four is at
    most the multiplier. That bound follows from the row's value, four
    words plus the multiplier times four words, which is a product's value
    and rests on the tests below.
  - `p256_wide_inverse_round`: one round whole, for any state and modulus,
    over `proof/p256_wide_stubs.h`'s rows: every access and every shift.
    `p256_wide_inverse` runs that round 17 times on one state and wipes it
    once, and `p256_wide_inverse_public` runs it at most 17 times and
    stops at a zero a. 17 rounds in one formula left cbmc's symbolic
    execution without a formula after 18 minutes.
  - `p256_wide_point`: `p256_wide_point_add` in all four aliasing
    shapes, `p256_wide_point_add_affine`,
    `p256_wide_point_add_affine_incomplete` and
    `p256_wide_point_double_jacobian` in both of theirs,
    `p256_wide_point_add_jacobian_incomplete` in its three, the two
    conversions between homogeneous and Jacobian points,
    `p256_wide_point_from_bytes` over any 65 bytes and
    `p256_wide_point_affine` with and without a y output, over the field
    stubbed to its contract: the stub header renames the header's inline
    addition and subtraction to their stubs, as `proof/p256_wide_stubs.h`
    renames the product row. Both answers are 0 or `UINT32_MAX`.
  - `p256_wide_digit`: the digits and the scan of the table, on their
    real bodies. For every 256-bit k, at both widths, the 64 four-bit
    signed odd digits and the 43 six-bit ones `window_digit` returns
    add up to k | 1, each digit's index is inside
    a row, its sign is a mask, and the top window's digit is positive.
    `table_select` and `multiple_select` return the row's entry at the
    index, word for word, for any row contents and every index, and
    `equal_mask` is all ones exactly for equal values.
  - `p256_wide_mul`: the whole of `p256_wide_base_mul` and of
    `p256_wide_mul`, every window of the shipped loops, over the point
    formulas stubbed to their contracts and the shipped table. The
    scalar's bits, the table's rows, the eight multiples of the point
    and each step of a scan are in bounds at every trip, and every mask
    handed to `p256_wide_fe_cmov` is 0 or all ones.
  - `p256_wide_wipe`: `p256_wide_wipe_below` calls `wipe_frame` through
    its volatile pointer, and the wipe covers the array of
    `P256_WIDE_BELOW_LEN` bytes and no byte outside it.
- **Bound:** full-range words, any 65-byte point, any scalar, scalar
  bits 0..255, windows 0..63, row entries 0..7, the inverse's 17 rounds
  of 31 steps.
- **Not proved:**
  - a product's value, and so that the scalar's `mont_mul` leaves a
    value below n, that a round's combinations compute the sums
    `spec/lean/Spec/P256WideInverse.lean` models and that the four point
    formulas compute the group law. That the rounds invert is the Lean
    proof's, over its model of the steps and the sums.
  - the form of the two carry steps that gcc compiles for x86-64,
    `_addcarry_u64` and `_subborrow_u64`. cbmc reads no intrinsic, and
    `bin/p256_equiv_test` holds that form under gcc and under
    qemu-x86_64.
  - that a scan of the table reads every entry whatever the index
    holds. A formula over values cannot state it: the code reads
    `row[j]` for every j of a loop whose count is a literal, and
    `lint-wide-multiply` holds the file's conditional branches at their
    ceiling.
  - that the array `p256_wide_wipe_below` wipes lies where the frames of
    the call before it lay. That is the compiler's layout and not a
    property of C.
  - the host half of `widemul.h`'s dispatchers. No harness compiles
    `p256_sign.c` or `p256_ecdh.c` with the host object's define:
    [p256_sign](#p256_sign) and [p256_ecdh](#p256_ecdh) prove them over
    the device half, which calls the 32-bit files.

  [The wide P-256 files](#the-wide-p-256-files) says what holds each of
  these.

#### p256_wide_verify

- **Harness:** `p256_wide_verify` (fast)
- **Build:** a host object's ECDSA P-256 verifier, `p256_wide_verify.c`
  (decisions 96 and 104), under `-DCH_CPU_RUNTIME`.
- **Proves:** `p256_wide_verify_rs` over any key, hash, r and s, with
  the entries of the wide files it calls stubbed to their contracts, and
  `p256_scalar.c`'s marshalling, reduction and range predicates on their
  real bodies:
  - it answers 0 or 1;
  - it answers 0 for an r or an s outside 1..n-1, and calls no entry of
    the wide files for one;
  - it answers 0 for a key the decoder refuses and for a sum at
    infinity, converts no key the decoder refused, asks for no x of a
    sum at infinity, and answers 1 only after the decoder took the key,
    the sum was finite and its x was r modulo n;
  - the encoding it hands the decoder starts with 0x04;
  - every scalar it hands `p256_wide_scalar_inverse_public`,
    `p256_wide_scalar_mul` and `p256_wide_jacobian_double_mul` is below
    n, and the r it compares is in 1..n-1.

  Asserting that the verdict is never 1 fails, so an accepting verdict
  is reached.
- **Bound:** any 64-byte key, any 32-byte hash, any 32-byte r and s.
- **Not proved:** that the equation holds for a signature and for no
  other pair: the stubs write unconstrained words.
  `bin/p256_verify_equiv_test` holds the verdict to `p256.c`'s 32-bit
  arm and the host Wycheproof test to Wycheproof's; see
  [The wide P-256 files](#the-wide-p-256-files).

#### p256_wide_verify_point, p256_wide_verify_digits

- **Harnesses:** `p256_wide_verify_point` (fast), `p256_wide_verify_digits` (fast)
- **Build:** the verifier's points, `p256_wide_verify_point.c`
  (decision 104), under `-DCH_CPU_RUNTIME`, over the contracts of
  `proof/p256_wide_field_stubs.h`, whose predicates answer an
  unconstrained mask, so every branch on a coordinate is taken both
  ways. Both link `p256_wide_table.c`.
- **Proves:** memory safety and absence of UB, with the unsigned
  overflow check on:
  - `p256_wide_verify_point`: the doubling, the general and the mixed
    addition on any points, into another point and in place; the table
    of a point's eight odd multiples; the key's conversion; the
    infinity test and the comparison of x with r on any point and any r;
  - `p256_wide_verify_digits`: the signed digits of any 256-bit scalar
    on their real body, each digit zero or odd in [-15, 15], the count
    at most 257 and the digits past it zero; and the addition of any
    digit's multiple of G and of the key, so both table reads are in
    bounds.
- **Bound:** any scalar, any coordinates, any r.
- **Not proved:** the loop of `p256_wide_jacobian_double_mul`, whose
  body is the doubling and the two additions proven above and whose
  reads of the digit arrays stay below the count the digits proof
  bounds; that a result is the sum of two points; and that the digits
  spell the scalar. `bin/p256_verify_equiv_test` and the host Wycheproof
  test hold the verdicts.

#### p256_sign

- **Harness:** `p256_sign` (fast)
- **Proves:** the RFC 6979 generator and the DER writer, with the
  arithmetic stubbed:
  - the generator spends the same number of HMAC calls whatever the
    candidate nonces were, which is the constant-time claim about the
    retry;
  - the DER writer stays inside `P256_SIG_MAX`, writes a minimal
    INTEGER, and refuses a short capacity rather than truncating, with no
    byte written past it;
  - `p256_sign_key_ok`, the key test a server also runs on its
    configuration, reads the key and answers 1 or 0.
- **Bound:** any key, any message hash, any capacity ≤ `P256_SIG_MAX`.
- **Not proved:** whether a signature is genuine. `test/p256_sign_test.c`
  checks that against RFC 6979 A.2.5 and Python, and the Wycheproof lane
  hands every signature to the independent verifier in `p256.c`.

#### p384

- **Harnesses:** `p384` (fast), `p384_mul` (fast)
- **Proves:** what p256's two prove, at twelve words:
  - every piece of `p384_ecdsa_verify` that handles attacker bytes: the
    strict-DER parser, the marshalling, the field and group arithmetic
    in every aliasing shape the code uses, and the on-curve check, over
    fully nondet words and points;
  - the bit-walk index for every scalar bit;
  - the CIOS carry lemma behind `p384_mont_mul`, for any uint32
    operands.
- **Bound:** signatures ≤ 112 B (a valid one is ≤ 104), full-range words
  and points, scalar bits 0..383.
- **Not proved:** the two 384-iteration loop drivers, `point_mul` and
  `p384_mod_inverse`, are not unrolled; their bodies are the proven
  pieces.

#### p384_wide

- **Harnesses:** `p384_wide_field` (fast), `p384_wide_point` (fast), `p384_wide_digits` (fast), `p384_wide_verify` (fast)
- **Build:** a host object's ECDSA P-384 verifier on six 64-bit words,
  `p384_wide_field.c`, `p384_wide_point.c` and `p384_wide_verify.c`
  (decision 97, INV-44), under `-DCH_CPU_RUNTIME`. `p384_wide_field`
  adds `--unsigned-overflow-check`.
- **Proves:** three layers, each over a contract of the one below it:
  - `p384_wide_field`: every routine of the field but the Fermat loop,
    in every shape of its arguments a caller uses, for any words, any
    modulus record and any m0inv, with the 64x64->128 multiply replaced
    by the contract `rsa_mont64_mul128` proves of it. No access is out
    of bounds and no sum wraps.
  - `p384_wide_point`: the doubling, the addition, the table of a
    point's eight odd multiples, the key's decoding and the comparison
    of x with r, over contracts of the field's product, sum and
    difference. Every operand the points hand the field is below p, and
    a key the decoder takes is three coordinates below p.
  - `p384_wide_digits`: the signed digits of any 384-bit scalar, on
    their real body. The count fits the array, every digit is zero or
    odd in [-15, 15], the digits past the count are zero, and adding
    any such digit reads the table inside its eight entries.
  - `p384_wide_verify`: the whole of `p384_wide_verify_rs` over any
    key, hash, r and s, with the points' four entries and the field's
    product and inverse stubbed to their contracts. It answers 0 or 1;
    it answers 0 for an r or an s outside 1..n-1, and calls no entry of
    the points and no product for one; it answers 0 for a key the
    decoder refuses and for a sum at infinity, and 1 only after the
    decoder took the key and the comparison said so; and every scalar
    it hands the field is below n, the one it inverts not zero.

  Asserting in `p384_wide_verify` that the verdict is never 1 fails, so
  an accepting verdict is reached.
- **Bound:** any 96-byte key, any 48-byte hash, any 48-byte r and s; any
  words, any points, any scalar.
- **Not proved:** `p384_wide_mod_inverse`'s 384 rounds and
  `p384_wide_double_mul`'s 385 are not unrolled. Their bodies are the
  proven pieces, and the bit walk of the first and the two digit arrays
  of the second are proven in bounds for every round. No harness says
  that a product is the Montgomery product, that a result is below the
  modulus, that the digits spell the scalar, or that the equation holds
  for a signature and for no other pair: the stubs write unconstrained
  words. `bin/p384_equiv_test` holds each routine of the field to
  `p384_field.c`'s result and the verdict to `p384.c`'s 32-bit arm, and
  the host Wycheproof test holds the verdict to Wycheproof's; see
  [The host object's P-384](#the-host-objects-p-384).

#### rsa

- **Harnesses:** `rsa` (fast), `rsa_mul` (fast), `rsa_webpki` (fast), `rsa_mul_webpki` (fast)
- **Proves:** the PSS decode and word marshalling stay safe with the
  RSAVP1 result replaced by arbitrary bytes. `rsa_webpki` and
  `rsa_mul_webpki` are the same two harnesses at the `CH_TRUST_WEBPKI`
  bound, `CH_RSA_MODULUS_MAX` of 512.
- **Bound:** 384 B modulus, and 512 B under `CH_TRUST_WEBPKI`. Every byte
  is hostile except the top one, which each call pins to one of the
  three alignment shapes the decode takes; a symbolic top bit was
  measured at 7 GB of CNF.

#### rsa_mont_host

- **Harnesses:** `rsa_mont_host` (fast), `rsa_mont_host_webpki` (slow)
- **Build:** `rsa_mont.c`'s host arm, `rsa_vp1` as a host object
  compiles it, under `-DCH_CPU_RUNTIME` (decision 103).
- **Proves:** `rsa_vp1` whole, over any odd modulus bytes and any
  signature bytes at the largest length, reads and writes inside its
  arrays and divides by no zero. A modulus whose top bit is set takes
  the division that computes R^2: `rsa_mont64_modulus_load`, the
  complement of the modulus, and its k steps, each with its quotient
  estimate, its subtraction and the passes that add the modulus back.
  Any other modulus takes `rsa_mont64_modulus_init` under the bit length
  its bytes give. The products are the contract
  `rsa_mont64_mul128` proves, and `rsa_mont64_modulus_init` and
  `rsa_mont64_public` are contracts that assert what their `CH_ASSERT`s
  need, which the [rsa_mont64](#rsa_mont64) harnesses discharge. The
  `_webpki` line is the same harness at the `CH_TRUST_WEBPKI` bound.
- **Bound:** 384 bytes and 48 words, and 512 bytes and 64 words under
  `CH_TRUST_WEBPKI`; any odd modulus bytes.
- **Not proved:** that the words the division writes are R^2 mod n; see
  [The host object's RSA arithmetic](#the-host-objects-rsa-arithmetic).
  The lines run without `--unsigned-overflow-check`, because a step
  wraps the word above the modulus's words to zero on purpose when it
  adds the modulus back. No line drives `rsa_vp1_cpu`, the dispatch to
  `rsa_ifma.c`; see
  [The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation).
  `power_of_two_mod`, which computes the power of two that call takes,
  has lines of its own under [rsa_ifma](#rsa_ifma).

#### rsa_mont64

- **Harnesses:** `rsa_mont64_mul128` (fast), `rsa_mont64_step` (fast), `rsa_mont64_step_sum` (fast), `rsa_mont64_sums` (fast), `rsa_mont64_ops` (fast), `rsa_mont64_ops_webpki` (fast), `rsa_mont64_mul` (fast), `rsa_mont64_mul_webpki` (fast), `rsa_mont64_init` (fast), `rsa_mont64_init_webpki` (fast), `rsa_mont64_public` (fast), `rsa_mont64_public_webpki` (slow)
- **Build:** a host object's Montgomery arithmetic on 64-bit words
  (`rsa_mont64.c`, INV-41), under `-DCH_CPU_RUNTIME`.
  `rsa_mont64_mul128`, `rsa_mont64_step_sum`, `rsa_mont64_sums` and the
  two `rsa_mont64_ops` lines add `--unsigned-overflow-check`.
- **Proves:**
  - `rsa_mont64_mul128`: on the real 64x64->128 multiply, the product of
    any two words is at or below (2^64 - 1)^2. Every other line but the
    two `rsa_mont64_ops` ones replaces the multiply with that bound as a
    contract (`proof/rsa_mont64_stubs.h`).
  - `rsa_mont64_step` and `rsa_mont64_step_sum`: `rsa_mont64.h`'s
    `rsa_mont64_mul_add_add`, the step of the multiplication's and the
    square's inner loops, returns the two words of x * y + a + b for
    every x, y, a and b, and for every product the multiply's contract
    admits, which it records as it returns it. The first runs the
    compare form clang reads, whose two adds wrap on purpose (decision
    117), without the wrap check, and the second the sum form gcc reads,
    with it. Every line over `proof/rsa_mont64_stubs.h` replaces the step
    with that 128-bit sum, which wraps nothing.
  - `rsa_mont64_sums`: `rsa_mont64_mont_mul` at four words, over any
    operands, any modulus and any `m0inv`, in the four aliasing shapes
    its callers use, wraps no unsigned value: no sum of a product, a
    word and a carry, no top step and no word of the last subtraction.
    Nor does `rsa_mont64_mont_square`, in its two shapes, whose running
    sum's top word stays at most 3 under any products the contract gives
    (decision 106), nor `rsa_mont64_mul_add`, the plain product and sum,
    at four words.
    Four words run every statement of the function in every position it
    takes, and each sum reads only values that are unconstrained there,
    so the word count is no part of the argument.
  - `rsa_mont64_ops`: the byte marshalling over any length from 1 byte
    to the bound, the comparison, the masked subtraction, the reduction
    by one subtraction in both of its aliasing shapes, the doubling and
    the power of two the modulus setup starts from stay inside their
    arrays and wrap nothing, at the largest word count. `mask_of_bit` is
    all ones or all zeros, and `at_or_above` answers one bit. So do
    `rsa_mont64_add` and `rsa_mont64_sub`, with the output apart from
    both operands, on the first and on the second, `rsa_mont64_add` with
    the output and both operands one array, the doubling of
    [rsa_ifma_sign](#rsa_ifma_sign)'s `state_setup`, and
    `rsa_mont64_reduce_once`.
  - `rsa_mont64_mul`: the multiplication reads and writes inside its
    arrays at the largest word count, in the four aliasing shapes, the
    square in its two, and `rsa_mont64_mul_add` at half that count, a
    prime's, into twice as many words.
  - `rsa_mont64_init`: `rsa_mont64_modulus_init` whole, over any modulus
    bytes at the largest length with the top bit's bit length: the
    marshalling, `neg_inverse`, its 2k + 1 doublings and its five
    squares.
  - `rsa_mont64_public`: `rsa_mont64_public` whole, over any base bytes
    and any modulus words at the largest length, its two
    multiplications, its sixteen squares and two wipes among them. The base is unconstrained,
    so a base at or above the modulus is covered.

  The `_webpki` lines are the same harnesses at the `CH_TRUST_WEBPKI`
  bound.
- **Bound:** 384 bytes and 48 words, and 512 bytes and 64 words under
  `CH_TRUST_WEBPKI`; full-range words; four words for `rsa_mont64_sums`.
- **Not driven:** the multiplication at the build's word count with the
  wrap check on, which returned no verdict in five minutes at 8.5 GB;
  and a modulus setup for a bit length below the top bit, which runs up
  to 64 more doublings a word. Each of those is `double_mod`, which
  `rsa_mont64_ops` proves for any words, and `bin/rsa_equiv_test` runs
  moduli of bit lengths from 1 up.
- **Not proved:** any value. That a product is the Montgomery product
  and below the modulus, that the setup writes R^2 mod m and the inverse
  of the low word, and that the public operation writes the 65537th
  power rest on [tests](#the-host-objects-rsa-arithmetic). The file's
  timing claim is `make lint-wide-multiply`'s, which counts the
  conditional branches it compiles to.

#### rsa_mont64_blocks

- **Harnesses:** `rsa_mont64_blocks_sums` (fast), `rsa_mont64_blocks` (fast), `rsa_mont64_blocks_webpki` (slow)
- **Build:** the multiplication and the square in blocks of four words
  that a clang build for arm64 runs (`rsa_mont64_blocks.c`, INV-41,
  decision 118), under `-DCH_CPU_RUNTIME`, with `RSA_MONT64_BLOCKS` at 1
  whatever compiler preprocesses the harness, over the product contract
  of `proof/rsa_mont64_stubs.h`. `rsa_mont64_blocks_sums` adds
  `--unsigned-overflow-check`.
- **Proves:**
  - `rsa_mont64_blocks_sums`: at four words and at eight, over any
    operands, any modulus and any `m0inv`, no sum in the blocks wraps:
    each sum of a block's two carry chains, the word a block returns, a
    row's tail, the top step of a multiplication's round, the doubling
    and the squares of the square, and each step of its reduction. It
    runs the multiplication through `rsa_mont64_mont_mul` and
    `rsa_mont64_mont_square`, which runs a square of up to
    `RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX` words as the multiplication of
    a by itself, and the square through `rsa_mont64_blocks_square`
    itself.
  - `rsa_mont64_blocks`: through `rsa_mont64_mont_mul` and
    `rsa_mont64_mont_square`, the blocks read and write inside their
    arrays at the largest word count, the multiplication in the four
    aliasing shapes its callers use and the square in its two, and so
    does the square at 32 words, `RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX`,
    the largest count it runs as the multiplication, in the same two.

  The `_webpki` line is the same harness at the `CH_TRUST_WEBPKI`
  bound.
- **Bound:** 48 words, and 64 under `CH_TRUST_WEBPKI`; full-range words;
  four and eight words for `rsa_mont64_blocks_sums`.
- **Not proved:** any value. That the blocks write the words
  `rsa_mont64.c`'s loops write rests on
  [tests](#the-host-objects-rsa-arithmetic). The file's timing claim is
  `make lint-wide-multiply`'s, which counts the conditional branches it
  compiles to, and `bin/rsa_sign_equiv_test`'s search of the stack,
  which runs the blocks only where a clang build for arm64 runs them.

#### rsa_ifma

- **Harnesses:** `rsa_ifma_lanes` (fast), `rsa_ifma_sums` (fast), `rsa_ifma_public_5` (fast), `rsa_ifma_public` (fast), `rsa_ifma_public_webpki` (slow), `rsa_ifma_product` (fast), `rsa_ifma_product_webpki` (fast), `rsa_mont_power` (fast), `rsa_mont_power_webpki` (fast), `rsa_mont_power_value` (fast)
- **Build:** the public operation on AVX-512 IFMA (`rsa_ifma.c`), under
  `-DCH_CPU_RUNTIME` and `-DCH_RSA_IFMA_MODEL`, over
  `test/rsa_ifma_model_lanes.h`, the model of each instruction in
  portable C that `bin/rsa_ifma_model_test` runs; and `rsa_mont.c`'s
  `power_of_two_mod`, which computes the 2^(104n) mod m that call takes.
  The lane multiplications, the scalar multiply and, in the memory
  lines, every lane operation are contracts (`proof/rsa_ifma_stubs.h`).
  `rsa_ifma_sums` adds `--unsigned-overflow-check`.
- **Proves:**
  - `rsa_ifma_lanes`: on the model's real operations and the real
    multiply, a lane multiplication adds a value below 2^52 to each lane,
    the high one a value at or below 2^52 - 2, the product of two digits
    is at or below (2^52 - 1)^2, and a load and a store touch nothing
    outside eight words. Those are the contracts the other lines run.
  - `rsa_ifma_sums`: no sum in the product or in `normalize_digits`
    wraps, at 1 and 2 registers, for every digit count they hold, in the
    two aliasing shapes `rsa_ifma_public` calls: no lane add, no 128-bit
    scalar sum and no add to `digit_zero`. `normalize_digits` wraps
    nothing for any lanes at all.
  - `rsa_ifma_public_5`, `rsa_ifma_public` and `rsa_ifma_public_webpki`:
    `rsa_ifma_public` whole reads and writes inside its arrays at 32, 48
    and 64 words, 5, 8 and 10 registers, the smallest and the largest
    count of each build: the marshalling, the conversions to and from
    digits, its eighteen products and the last subtraction.
  - `rsa_ifma_product` and `rsa_ifma_product_webpki`: the copies of the
    product for 6 and 7 registers, at 38 and 45 words, and under
    `CH_TRUST_WEBPKI` for 8 and 9, at 51 and 58, read and write inside
    their arrays in both aliasing shapes.
  - `rsa_mont_power` and `rsa_mont_power_webpki`: `power_of_two_mod`
    reads and writes inside its arrays and divides by no zero, at 32
    words and at the build's largest count, with the exponents
    `rsa_vp1_cpu` passes, for any modulus words whose top bit is set and
    whose bottom bit is 1.
  - `rsa_mont_power_value`: at two words, `power_of_two_mod` writes
    2^exponent mod m for every odd m whose top bit is set and every
    exponent from 64 to 131, on the real multiply and division, against
    a reference that doubles one bit at a time.
- **Bound:** 1 and 2 registers for `rsa_ifma_sums`; the word counts
  above for the memory lines; two words and exponents 64 to 131 for
  `rsa_mont_power_value`.
- **Not proved:** any value of the product or of `rsa_ifma_public`.
  `spec/lean/Spec/RsaIfma.lean` proves them of a model of the C, which
  `bin/diff_rsa_ifma` compares with the C on samples, and
  `bin/rsa_ifma_model_test` holds the C to `rsa_mont64.c`
  ([The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)).
  That no lane wraps at 5 to 10 registers rests on the bound a lane's
  rounds give it, below 2^61, which Lean proves on its model of the
  rounds; one product at 10 registers wrote 58 million clauses and was
  not run. `power_of_two_mod`'s value above exponent 131, where a step's
  quotient estimate has more than four bits, returned no verdict:
  exponents 64 to 135 and 160 alone in 600 s each, 64 to 191 in
  1,200 s. Its value at the exponents `rsa_vp1_cpu` passes rests on
  tests and on the Lean theorem, which takes each step's division as
  given. The instructions in `rsa_ifma_lanes.h`, which CBMC cannot read,
  are held to the model only by `bin/rsa_ifma_equiv_test`, on a CPU with
  AVX-512 IFMA or under SDE.

#### rsa_ifma_sign

- **Harnesses:** `rsa_ifma_sign_pair` (fast), `rsa_ifma_sign_pair_webpki` (fast), `rsa_ifma_sign_select` (fast), `rsa_ifma_sign_select_webpki` (fast), `rsa_ifma_sign_setup` (fast), `rsa_ifma_sign_setup_webpki` (fast), `rsa_ifma_sign_power` (fast), `rsa_ifma_sign_power_webpki` (slow), `rsa_ifma_sign_wipe` (fast), `rsa_ifma_sign_wipe_webpki` (fast)
- **Build:** RSA signing's two exponentiations on AVX-512 IFMA
  (`rsa_ifma_sign.c`, INV-41), under `-DCH_CPU_RUNTIME` and
  `-DCH_RSA_IFMA_MODEL`, over `test/rsa_ifma_model_lanes.h`, as the
  [rsa_ifma](#rsa_ifma) lines compile `rsa_ifma.c`. The pair, setup and
  power lines run every lane operation as a contract
  (`proof/rsa_ifma_stubs.h`), and the setup and power lines the three
  `rsa_mont64.c` entries the file calls as contracts
  (`proof/rsa_ifma_sign_stubs.h`), which the [rsa_mont64](#rsa_mont64)
  harnesses discharge. The select line runs the model's own lane
  operations, which multiply nothing there. The
  `_webpki` lines are the same harnesses at the `CH_TRUST_WEBPKI` bound,
  whose largest primes take five registers.
- **Proves:**
  - `rsa_ifma_sign_pair`: `product_pair` and the copies of the two
    products side by side read and write inside their arrays at 3 and 4
    registers, and at 5 under `CH_TRUST_WEBPKI`, each at the largest
    prime word count it holds, over any digits and any m0inv below 2^52,
    in each aliasing shape the exponentiation calls them in.
  - `rsa_ifma_sign_select`: `table_select` writes the table's entry at
    the exponent's digit to every lane of the build's registers and
    leaves the lanes past them as they were, for any table, any exponent
    byte and either digit of it: the high half of the byte for an even
    index and the low half for an odd one.
  - `rsa_ifma_sign_setup`: `state_setup` and `state_finish` read and
    write inside their arrays at every prime word count from 16 to 24,
    and to 32 under `CH_TRUST_WEBPKI`; and at each of those counts
    `words_to_digits` and then `digits_to_words` write any k words back,
    with a zero word above them.
  - `rsa_ifma_sign_power`: `rsa_ifma_sign_power_pair` whole reads and
    writes inside its arrays at the smallest and the largest prime word
    count of each build, with each output on its base, as `rsa_sign64.c`
    calls it.
  - `rsa_ifma_sign_wipe`: `rsa_ifma_sign_wipe_below` runs `wipe_frame`
    through its volatile pointer, and that wipe writes zero to every byte
    of its array of `RSA_IFMA_SIGN_BELOW_LEN` bytes and to no byte
    outside it.
- **Bound:** the prime word counts above; exponents of one byte, two
  steps, for `rsa_ifma_sign_power`, whose steps run the same statements
  at every index. `rsa_ifma_sign_power_webpki` peaks near 7 GB, so it
  runs in the slow tier, and its verdict comes from the last nightly.
- **Not proved:** any value of the C. `spec/lean/Spec/RsaIfma.lean`
  proves the exponentiation's value of a model of the C, which
  `bin/diff_rsa_ifma` compares with the C on samples
  ([The AVX-512 IFMA signer](#the-avx-512-ifma-signer)).
  `bin/rsa_ifma_sign_model_test` holds every exponentiation to
  `rsa_sign64.c`'s window over the lane model, and on a CPU with AVX-512
  IFMA `bin/rsa_ifma_sign_equiv_test` holds the instructions to it. That
  no sum of the round wraps rests on `rsa_ifma_sums`, which compiles the
  same round, `rsa_ifma_product.h`'s, through `rsa_ifma.c`, and on the
  bound Lean proves on its model of the rounds ([rsa_ifma](#rsa_ifma)).
  That the wipe's array lies where the frames of the calls before it
  lay is not a property of C: `bin/rsa_ifma_sign_residue_test` measures
  it. That a compiler emits no branch for `table_select`'s mask rests on
  a Semgrep rule and on the branch counts of `make lint-wide-multiply`
  (INV-16).

#### rsa_sign64

- **Harnesses:** `rsa_sign64_window` (fast), `rsa_sign64_window_webpki` (fast), `rsa_sign64_power` (fast), `rsa_sign64_power_webpki` (fast), `rsa_sign64_crt` (fast), `rsa_sign64_crt_webpki` (fast), `rsa_sign64_ifma` (fast), `rsa_sign64_ifma_webpki` (fast)
- **Build:** a host object's RSA signer on 64-bit words
  (`rsa_sign64.c`, INV-41 and INV-42), under `-DCH_CPU_RUNTIME`. The two
  `rsa_sign64_window` lines add `--unsigned-overflow-check`.
- **Proves:**
  - `rsa_sign64_window`: `exponent_digit` returns the high half of byte
    i / 2 for an even i and the low half for an odd one, for any
    exponent bytes and any i below twice the bound, so a digit is a
    table index. `table_select` writes exactly the entry at its index,
    for any table, any index below 16 and any words in its output
    before the call, at a prime's largest word count. `mask_of_bit` is
    all ones or all zeros.
  - `rsa_sign64_power`: `rsa_sign64_power` reads and writes inside its
    arrays at each of its two bounds: the longest exponent a key has,
    half the modulus's bytes, over a modulus of one word, and a prime's
    largest word count under an exponent of two bytes, with the output
    apart from the base and on it.
  - `rsa_sign64_crt`: the five pieces a CRT signature joins read and
    write inside their arrays, each whole: `message_mod_prime`, which
    splits the message into its low words and the words above them;
    `crt_combine`, Garner's formula into twice a prime's words;
    `rsa_sign64_key_ok`, which multiplies the primes and compares the
    product with the modulus; `signature_verifies`, the check of a
    signature; and `write_if_verified`, which copies a candidate to the
    caller. All but the second run at the largest modulus and at 8
    bytes below it, where each prime is half a word past a whole number
    of words.
  - `rsa_sign64_crt` also states what three of them compare and copy,
    over any bytes and words the contracts below may write: the check
    raises the whole candidate modulo the key's modulus and returns 1
    exactly when every byte of the power is the byte of the encoded
    message; `write_if_verified` leaves every byte of the caller's
    buffer as it was unless that check passed, and then the buffer
    holds the candidate; and the key test returns 1 exactly when every
    word of the product is the word of the modulus (INV-42).
  - `rsa_sign64_ifma`: the AVX-512 IFMA arm, under a `ch_cfg.cpu` value
    that holds `CH_CPU_AVX512_IFMA` and the multiply bit and with
    `-DCH_RSA_IFMA_MODEL`, under which the arm compiles on any target.
    `both_powers` calls `rsa_ifma_sign_power_pair` once, on both halves
    in place, with `dp`, `dq`, both primes' records and the primes'
    length, and then wipes the stack below it once. The check calls
    `rsa_vp1_cpu` once, under the session's value, on the key's modulus
    and the whole candidate, and then wipes the stack below it once; and
    the check and the write keep `rsa_sign64_crt`'s statements. The
    kernels and the wipe are contracts in the harness that assert what
    each needs of its arguments, and the [rsa_ifma_sign](#rsa_ifma_sign)
    and [rsa_ifma](#rsa_ifma) harnesses prove the real ones. Over the
    model no vector register holds a value, so the arm's wipe of them is
    empty there; `bin/x86_kernels_test` counts it on x86-64.

  Every call into `rsa_mont64.c` is a contract
  (`proof/rsa_sign64_stubs.h`) that asserts what the real entry needs,
  and the [rsa_mont64](#rsa_mont64) harnesses discharge them. The
  `_webpki` lines are the same harnesses at the `CH_TRUST_WEBPKI` bound.
- **Bound:** 384 bytes, 48 words and primes of 24, and 512 bytes, 64
  words and primes of 32 under `CH_TRUST_WEBPKI`.
- **Not driven:** `rsa_sign64_power` at both bounds at once, which
  returned no verdict in fifteen minutes when the table held whole
  moduli; no index in the function is computed from both lengths.
  `rsa_sign64_sp1` whole, which is that exponentiation at both bounds,
  twice: its own statements are two modulus setups, the message's
  marshalling, the pieces above and seven wipes.
  `rsa_sign64_pss` is `rsa_sign.c`'s text, which [rsa_sign](#rsa_sign)
  proves.
- **Not proved:** any value, that `table_select` reads every entry
  whatever its index is, and that a compiler emits no branch for its
  mask. The values rest on [tests](#the-host-objects-rsa-arithmetic) and
  on the signer's own check of every signature (INV-42). The read of
  the whole table rests on a Semgrep rule, and the mask on that rule,
  on the branch counts of two builds and on a reading of the assembly
  of nine (INV-16).

#### rsa_sign

- **Harness:** `rsa_sign` (fast)
- **Proves:**
  - the signer's word marshalling and every word helper (the borrow, the
    masked subtract, the comparison and the conditional swap) stay safe
    over fully nondet words at 96 words;
  - `mask_of_bit` returns all ones or all zeros and nothing else, and
    `below` answers the one bit that mask admits;
  - `rsa_pss_sign_key_ok`, the key test `rsa_pss_sign` runs first and a
    server runs on its configuration, reads inside the modulus for any
    `n_len`, and every key it admits has the `n_len` the 96-word bound
    assumes;
  - the ladder's exponent byte index stays inside `d` for every bit
    position the loop reads;
  - the PSS encoder writes inside the encoded message at the largest one
    it builds, over any salt its caller hands it but the all-zero one,
    which it asserts against, with SHA-256 stubbed to its contract;
  - a carry lemma covers the CIOS accumulation for any uint32 operands.
- **Bound:** 384 B modulus (96 words), full-range words, exponent bit
  positions 0..8*n_len-1, encoded message at `CH_RSA_MODULUS_MAX`.
- **Not driven:** `mont_mul` whole, `mont_r2`, and `rsa_sp1` above them.
  A symbolic modexp does not leave symbolic execution, and `mont_r2`'s
  shift loop runs 6,144 times, so their arithmetic rests on the carry
  lemma, on the Wycheproof signing vectors and on
  `test/rsa_sign_test.c`.
- **Not proved:** the timing claim `rsa_sign.h` makes. `make
  lint-wide-multiply` holds that, by counting the wide multiplies and the
  conditional branches the file compiles to.

#### rsa_pkcs1

- **Harnesses:** `rsa_pkcs1` (fast), `rsa_pkcs1_webpki` (fast)
- **Proves:** the shipped `rsa_pkcs1_verify` end to end, over any
  modulus, digest, signature and claimed lengths, with RSAVP1 stubbed to
  the contract `rsa_mul` proves: the size check, the odd-modulus check,
  the DigestInfo choice, the range check, and the encode-and-compare,
  with the encoder at the shortest admitted modulus.
  `rsa_pkcs1_webpki` is the same harness at the `CH_TRUST_WEBPKI` bound.
- **Bound:** n_len at the 384-byte limit, and at the 512-byte limit of a
  `CH_TRUST_WEBPKI` build, each the binding case for its bound as for
  `rsa`; both admitted digest lengths.

### Record layer and transport I/O

#### io

- **Harness:** `io` (slow)
- **Proves:** `io_read_record` and `io_send_all` are memory-safe and
  UB-free against a transport that returns anything at all, and a record
  `io_read_record` accepts lies wholly inside the caller's buffer. The
  recv stub honors no contract: it returns an arbitrary int and writes
  only the bytes it claims, up to what it was asked for.
- **Bound:** buffers ≤ 16 B.

#### record

- **Harness:** `record` (slow)
- **Proves:**
  - seal works across its contract and returns, rather than traps, over
    the whole direction state: any key, IV and sequence number, the
    saturation refusal included, and any claimed buffer size;
  - `rec_open` stays safe on fully hostile bytes, into a separate buffer
    and in place, the shape both shipped callers use.
- **Bound:** records ≤ 160 B.

#### record_suite

- **Harness:** `record_suite` (fast)
- **Build:** `SUITE=aesgcm`.
- **Proves:** `rec_dir_init_suite` and `rec_dir_update`, over each of the
  three suites, derive at the suite's hash and key length and keep the
  suite across a KeyUpdate, and one seal and one open run the AEAD the
  suite names. The seal runs at any sequence number and refuses exactly
  two kinds: the last one there is, where the next increment would wrap,
  and under AES-GCM every one at or past `REC_AES_GCM_RECORDS_MAX`, the
  most records one AES-GCM key seals (docs/decisions.md 78). HKDF, the
  ChaCha20 AEAD and the AES-GCM traffic entries are stubbed to their
  contracts.
- **Bound:** records ≤ 16 B, secrets one hash long.

#### record_whole_len

- **Harness:** `record_whole_len` (fast)
- **Build:** `TRANSPORT=tcp-nonblocking`.
- **Proves:** `ch_record_whole_len` reads no byte outside `p[0..n)`, in
  a heap object exactly `n` bytes long, and answers exactly what
  `tcp_nonblocking.h` states for every byte `p` holds: 0 while the
  header or the body it names is not whole, `REC_HDR` for a length field
  above 2^14 + 256, and the whole record's length otherwise. So every
  answer is 0 or a length from `REC_HDR` to `n`. `buf.c` is real.
- **Bound:** `n` ≤ 2^20 B. The longest record the call frames is 16,645
  B, and the call has no loop.
- **Not proved:** the rest of `tcp_nonblocking_frame.c`, which
  `bin/tcp_nonblocking_loop_test` and `bin/srv_tcp_nonblocking_test`
  test.

#### writable_len

- **Harness:** `writable_len` (fast)
- **Proves:**
  - `ch_writable_len` is safe and free of UB for any `peer_limit` and
    any `cap`;
  - its answer is the most plaintext `ch_write` sends in `cap` bytes:
    the real `ch_write` hands `cfg.send` at most `cap` bytes for the
    answer, and more than `cap` bytes for one byte more.

  `rec_seal` and `io_send_all` are stubbed to their contracts: a sealed
  record is `REC_OVERHEAD` bytes longer than its plaintext, which
  [record](#record) proves, and the stub send counts what it is handed.
- **Bound:** the second claim at `cap` ≤ 1,603 B, three whole records
  of `CH_TX_PT` bytes and one byte, and `peer_limit` ≥ 63, the least a
  connected session holds, at the default `CH_TX_PT` of 512. The
  claim is an equality over a division, and at 16 bits of `cap` a model
  of it returned no verdict in 600 s. `bin/unit` checks the answer
  against `ch_write` for every `cap` up to three records and one byte at
  three limits, and at `SIZE_MAX`.
- **Not proved:** `tls.c`: `ch_connect`, `ch_read`, `ch_close` and
  `ch_export`, and `tlsi_config_ok`. Tests cover them. The one-suite
  build compiles no AES-GCM ceiling, so this harness reads none;
  [writable_len_suite](#writable_len_suite) proves the build that does.
  That no unsigned sum or product in `records_fill` wraps is Lean's
  `recordsFill_fits`, which that entry states.

#### writable_len_suite

- **Harnesses:** `writable_len_suite` (fast), `writable_len_suite_any` (fast)
- **Build:** `SUITE=aesgcm`.
- **Proves:**
  - `writable_len_suite_any`: `ch_writable_len` is safe and free of UB
    for any `peer_limit`, any suite code point, any write sequence number
    and any `cap`, the path that counts a KeyUpdate included;
  - `writable_len_suite`: its answer is the most plaintext `ch_write`
    sends in `cap` bytes, the KeyUpdate record `ch_write` sends at an
    AES-GCM write key's ceiling included: the real `ch_write` hands
    `cfg.send` at most `cap` bytes for the answer, and more than `cap`
    bytes for one byte more;
  - on the way, what `ch_write` does at the ceiling: under AES-GCM it
    seals no data record at the key's last sequence number,
    `REC_AES_GCM_RECORDS_MAX - 1`, sends the KeyUpdate there and nowhere
    else, and returns with that last sequence number still free; under
    ChaCha20-Poly1305 it sends no KeyUpdate.

  The two claims sit in two harnesses because each costs a division, and
  in one formula they returned no verdict in 14 minutes.
- **Not proved by CBMC:** that no unsigned sum or product on the
  KeyUpdate path wraps. C defines unsigned wrap, so the checks this page
  lists do not look for it, and with `--unsigned-overflow-check`,
  `writable_len_suite_any` returned no verdict in 10 minutes, on 64 bits
  and on 32. [`spec/lean/Spec/TlsWrite.lean`](../spec/lean/Spec/TlsWrite.lean)
  proves it in Lean instead, over a model of `ch_writable_len`,
  `records_fill` and `fill_across_key_update` with one `let` per C local:
  - `recordsFill_fits`: for every width `w` of 15 bits or more, every
    `cap` below `2^w` and every limit from 1 to 16384, each sum and
    product `records_fill` computes is below `2^w`;
  - `fillAcrossKeyUpdate_fits`: when `room` is below the count
    `records_fill` returns for `cap`, each product and sum
    `fill_across_key_update` computes is at most `cap`, its answer
    included;
  - `writableLen_le_cap`: the answer is at most `cap`, at every limit and
    every `room`, `SIZE_MAX` for a ChaCha20-Poly1305 key among them.

  15 bits is the least width the proofs need, because `limit +
  REC_OVERHEAD` is 16406 at the largest limit, and C gives every `size_t`
  16 bits or more. An unsigned value below `2^w` is exact in a `size_t` of
  `w` bits, so at every such width each C operation gives the value the
  model's matching `let` gives. The theorems are about the model. Two
  things tie it to the C: it has one `let` per C local, in the C's order,
  for a reader to check against `tls_write.c`; and
  `test/diff_writable_len.h` compares it with `ch_writable_len` at 64
  bits, in `bin/diff` at the default `CH_TX_PT` and in
  `bin/diff_webpki_aes`, which `make diff-webpki` builds under
  `-DCH_SUITE_AES_GCM` at `CH_TX_PT=16384`.
  `inv38-writable-len-last-record-no-overhead` is an edit to
  `records_fill` that `bin/diff` refuses.

  `rec_seal`, `io_send_all` and `hspost_send_key_update` are stubbed to
  their contracts: a sealed record is `REC_OVERHEAD` bytes longer than
  its plaintext and moves the sequence number on by one, and a KeyUpdate
  is one record of `CH_KEY_UPDATE_RECORD_LEN` bytes followed by the next
  key at sequence number 0.
- **Bound:** `writable_len_suite` at `peer_limit` ≥ 63, `cap` up to three
  whole records of the session's own limit, a KeyUpdate record and one
  byte (1,630 B at `CH_TX_PT`), each of the three suites, every write
  sequence number below `REC_AES_GCM_RECORDS_MAX`, and a KeyUpdate count
  below 2^48 − 1. So `ch_write` turns at most four times, and the
  KeyUpdate falls before the first record, between two, or after the
  last whole one. A cap of three records of `CH_TX_PT` instead, the
  bound [writable_len](#writable_len) takes, lets `ch_write` turn 20 times
  at a limit of 63, and with the KeyUpdate term that formula returned no
  verdict in 10 minutes; `test/key_limit_cases.h` sweeps every cap up to
  three records at a limit of 63 against the real `ch_write`. A write here
  crosses the ceiling once at most, so no answer stops at the one
  KeyUpdate `ch_writable_len` counts (tls.h); `test/key_limit_cases.h`
  checks that answer at `SIZE_MAX`, and the write at the KeyUpdate count's
  cap.

### Client handshake

#### handshake

- **Harnesses:** `handshake_psk` (slow), `handshake_pin` (slow), `handshake_ca` (no launch line)
- **Proves:** the driver stays safe on any record stream: HelloRetryRequest
  restart, the state machine, and the flight's own arithmetic, in PSK
  and pinned-key mode. Record reading and message reassembly are stubbed
  to the contract [handshake_record](#handshake_record) proves, and the
  check before a key change, `hsr_check_record_end`, to the contract
  `handshake_record.h` states, so the driver meets both of its answers.
  Compiling them in multiplies this formula by the product of their loop
  bounds, beyond what any runner solves.
- **Bound:** 96 B receive buffer.
- **Not proved:** the ca-mode driver. It has a harness but no launch
  line; [epoch](#epoch) proves that arm's own arithmetic.

#### handshake_record

- **Harness:** `handshake_record` (slow)
- **Proves:**
  - the record reader stays safe on any stream a peer can send:
    compaction, CCS tolerance, the quiet cap, in-place decryption, and
    reassembly across records;
  - a message it yields lies wholly inside `cfg.buf`, with a length that
    agrees with its own 3-byte header;
  - `hsr_transcript_hash` leaves the running transcript byte for byte as
    it found it.

  `io_read_record` and `rec_open` are stubbed to the contracts
  [io](#io) and [record](#record) prove.
- **Bound:** 12 B receive buffer, `CH_QUIET_CAP` 1.

#### transcript384

- **Harness:** `transcript384` (fast)
- **Proves:** the transcript's two hashes under `CH_HASH_SHA384`:
  `hsr_transcript_hash`, `transcript_hash_after` and the
  HelloRetryRequest restart `hsr_restart_transcript`, with `hash_len`
  free over 32 and 48 and both hashes stubbed to their contracts. Each
  read and the synthetic message stay inside buffers of the hash they
  name.
- **Bound:** the full domain.

#### hello_build

- **Harnesses:** `hello_build` (fast), `hello_build_webpki` (fast), `hello_build_suite` (fast)
- **Proves:**
  - the ClientHello builder writes nothing outside the caller's buffer
    at any capacity, for every cookie and every PSK identity of at most
    `CH_TICKET_ID_MAX` bytes, and returns either zero or a length that
    fits;
  - at `CH_HELLO_MAX` the build always succeeds for those inputs, so the
    constant `handshake.c` asserts `CH_TX_STAGE` against is sufficient,
    not merely plausible. The proof assumes an identity of at most
    `CH_TICKET_ID_MAX` bytes, and every client entry's configuration
    check is what makes that true: `psk_id_len_ok` in `tls.c` and
    `quic_config.c`, and `ticket_shape_ok` under `TRUST=webpki`, refuse
    any other length (INV-14). So the drivers' branches for a first or
    retry hello that does not fit are unreachable for every accepted
    configuration (`docs/decisions.md` entry 84);
  - `hello_build_webpki` is the same harness under `-DCH_TRUST_WEBPKI`,
    with the server_name extension over any hostname, the ALPN extension
    over any offer, and the five signature schemes, which a resuming
    hello carries beside the ticket too. It covers both key shares, the
    one secp256r1 share of a retry hello, and, under `require_pq`, the
    hybrid one alone, against that build's `CH_HELLO_MAX` of 2,396.
    There the bound is tight: the assertion moved to `CH_HELLO_MAX - 1`
    fails.
  - `hello_build_suite` is the same harness under `-DCH_TRUST_WEBPKI
    -DCH_SUITE_AES_GCM`: cipher_suites in `suite.h`'s default order or
    as a caller's list of 1 to `SUITE_HELD_COUNT` code points of any
    value (`docs/decisions.md` entry 80), and a ticket whose binder is
    SHA-256's or SHA-384's, against that build's `CH_HELLO_MAX`, where
    the bound is tight too. A probe that asserts no hello over a
    three-suite list is built fails, and so does one for a SHA-384
    binder, so both arms are reached.
- **Bound:** capacity ≤ `CH_HELLO_MAX`, identity ≤ 320 B, cookie ≤
  128 B, hostname ≤ 253 B, 8 ALPN names ≤ 32 B each, 3 cipher suites.
- **Not proved:** that `pre_shared_key` is the last extension.
  `test/session_cfg_tests.h` and `test/webpki_session_cases.h` test it.
  The assertion over the hello's last bytes gave kissat a formula that
  returned no verdict in nine minutes at 5.7 GB.

#### key_share

- **Harnesses:** `key_share` (fast), `key_share_webpki` (fast)
- **Proves:**
  - the `KEX=pq` arm of the ServerHello key_share parser is safe on any
    extension bytes. On acceptance it records the hybrid group
    (`info.group == CH_GROUP_X25519MLKEM768`, the value `ch_tls.group`
    reports and `ch_cfg.require_pq` compares) and returns a whole
    readable ML-KEM ciphertext inside the bytes it consumed. That is the
    contract [hybrid_secret](#hybrid_secret) assumes, so this proof
    discharges that assumption.
  - `key_share_webpki` builds the same harness under
    `-DCH_TRUST_WEBPKI`. There the arm also accepts a ServerHello
    selecting x25519, whose share that build's hello carries beside the
    hybrid one, and one selecting secp256r1, whose share its retry hello
    carries. An x25519 share is exactly the group, the length and 32
    bytes, with no ciphertext pointer; a secp256r1 share is the group,
    the length and the 65-byte point, which the pointer spans inside the
    consumed bytes. There a HelloRetryRequest key_share may name
    secp256r1 and no other group; under `-DCH_KEX_PQ` every one is
    refused.
- **Bound:** extension ≤ 1,132 B, the full hybrid share.
- **Not proved:** that `ch_cfg.require_pq` refuses an x25519 selection.
  That is `hsf_accept_server_hello`'s check, which
  `bin/webpki_session_test` tests.

#### handshake_groups

- **Harness:** `handshake_groups` (fast)
- **Proves:** the `TRUST=webpki` client's three-group rules,
  `handshake_groups.c`, stay safe over any configuration and every
  verdict their primitives return, and do what `handshake_groups.h`
  states:
  - a retry naming no group is taken exactly when it carries a cookie;
  - a retry naming secp256r1 is refused under `require_pq`, and
    otherwise records the group, draws the P-256 key pair and wipes the
    first hello's x25519 and ML-KEM key pairs;
  - a ServerHello may select secp256r1 exactly when a retry named it;
  - the P-256 secret runs over the scalar and the server's point, and
    wipes the scalar on both exits;
  - a refused exchange leaves no byte of the secret (INV-3, INV-17).

  The P-256 exchange, x25519 and `ch_rand_bytes` are stubbed to their
  contracts, as in [srv_kex](#srv_kex).
- **Bound:** every configuration and verdict.

#### Handshake message parsers

- **Harnesses:** `handshake_parser` (fast), `handshake_parser_suite` (fast), `eeparse` (fast), `certparse` (fast), `eeparse_webpki` (fast), `eeparse_alpn` (fast), `certparse_webpki` (fast)
- **Proves:**
  - the ServerHello, EncryptedExtensions, Certificate and
    CertificateVerify parsers stay safe on hostile bytes, and the
    certificate list and signature slices they hand back lie inside the
    message;
  - the `_webpki` harnesses prove the `TRUST=webpki` arms, the empty
    server_name acknowledgement and the three CertificateVerify schemes,
    and `certparse_webpki` also proves that an accepted scheme is one of
    those three;
  - the three `eeparse` harnesses also prove the EncryptedExtensions
    alert contract. The parser keeps the caller's seeded alert or writes
    unsupported_extension. A `TRUST=webpki` arm may also write
    decode_error and illegal_parameter, the second for an ALPN name or a
    server certificate type outside the offer. The parser writes no
    other alert;
  - `eeparse_webpki` also proves that an accepted server certificate
    type is the caller's seed or one the offer holds;
  - `eeparse_alpn` proves the ALPN arm where it lives, over one
    extension body rather than a whole message. Against an offer of up
    to 8 protocol names of up to 32 bytes, every byte and every length
    symbolic, an accepted body names a protocol the offer holds, a
    refused one leaves the caller's `CH_ALPN_NONE`, and the alert is the
    caller's seed or one of the arm's two. Driving that offer through
    the whole extension loop multiplies the two bounds and returned no
    verdict in 21 minutes, so the loop around the arm is
    `eeparse_webpki`'s, at its 256-byte message with an empty offer;
  - `handshake_parser_suite` is `handshake_parser` in the `SUITE=aesgcm
    TRUST=webpki` client, and also proves that an accepted ServerHello
    or retry carries ChaCha20, AES-128-GCM or AES-256-GCM, the three
    suites that client offers.
- **Bound:** messages ≤ 256 B; the ALPN arm, one extension body ≤ 40 B
  against 8 names ≤ 32 B each.
- **Not proved here:** the `KEX=pq` key_share arm. The 256-byte bound
  cannot hold a hybrid key_share, so [key_share](#key_share) drives that
  arm instead.

#### epoch

- **Harness:** `epoch` (fast)
- **Build:** a ca mode.
- **Proves:** the revocation epoch's two rules, which nothing else
  checks:
  - `epoch_check`'s verdict always matches the status it reports;
  - `hsa_epoch_commit` never lowers the stored epoch. A commit that
    moved backwards would let a replayed certificate undo a bump.
- **Bound:** any stored epoch and any leaf epoch ≤ `CH_EPOCH_MAX`, the
  range `ch_connect` and the certificate parser admit.
- **Not proved:** the ca arm's whole driver, which does not converge
  ([#37](https://github.com/c4milo/chapulin/issues/37)). The record
  reading it leaves out is [handshake](#handshake)'s.

#### certverify_webpki

- **Harness:** `certverify_webpki` (fast)
- **Proves:** the `TRUST=webpki` CertificateVerify arm of
  `handshake_auth.c`, over every signature scheme value and every leaf
  key family:
  - a signature is passed to a verifier only under the scheme the leaf
    key's family can produce;
  - the verifier that runs is that family's own;
  - the signed content takes SHA-384 for a P-384 leaf and SHA-256 for
    every other.

  The record reader, the two hashes and the three verifiers are stubs
  the harness defines, each asserting what the arm passes it.
  `handshake_record`, `sha256`, `sha512` and the three verifier
  harnesses prove them.
- **Bound:** CertificateVerify messages ≤ 12 B, leaf keys ≤
  `CH_WEBPKI_KEY_MAX`.
- **Not proved:** whether a signature is genuine.
  `test/webpki_auth_test.c` tests that over real chains and real
  signatures. Nor the bytes of the signed content, which the stubbed
  hashes never read: the differential compares their digest with the
  spec's (see [The differential oracle](#the-differential-oracle)).

#### handshake_post

- **Harness:** `handshake_post` (slow)
- **Proves:** the post-handshake parser stays safe on hostile decrypted
  bytes and consumes no more than its input, hands `on_ticket` no
  ticket whose `ticket_lifetime` is 0, rekeys on a KeyUpdate only
  when it is the last message of its input, the one RFC 9846 §5.1 lets
  precede a key change (INV-39), and writes no alert but three, each
  only on a failure: decode_error for a message that does not parse
  (§6), illegal_parameter for a request_update neither 0 nor 1
  (§4.7.3, INV-14), and internal_error for a KeyUpdate reply that could
  not be sealed or sent (§6.2, INV-13).
- **Bound:** messages ≤ 128 B.

### Server

Every harness in this group builds the server role (`-DCH_ROLE_SERVER`).

#### srv_accept

- **Harness:** `srv_accept` (fast)
- **Proves:** `ch_srv_accept` and `ch_srv_check` stay safe over an
  unconstrained `ch_cfg`: every pointer NULL or live, every length any
  `size_t`, an ALPN offer at `CH_ALPN_MAX` names of `CH_ALPN_NAME_MAX`
  bytes. `srv_handshake` drives the flight in one order:
  - a configuration it refuses runs no handler and leaves a dead
    session;
  - a handshake that fails after a handler ran wipes the record keys
    and leaves a dead session;
  - only a flight that got as far as `srv_complete` answers `CH_OK`.
- **Bound:** ALPN offers ≤ 8 names of ≤ 32 B.
- **Not proved:** any message this server writes. The fourteen
  `srv_flight.h` handlers, `srv_resume.h`'s ticket call, `srv_auth.h`'s
  three entry points, `handshake_record.h`'s check before a key change,
  `rec_seal` and `io_send_all` are contract stubs the harness defines.
  [srv_flight](#srv_flight) is where those handlers are real.

#### srv_kex

- **Harness:** `srv_kex` (fast)
- **Proves:** the server's key exchange, `srv_kex.c`, stays safe over
  any groups and shares a parsed ClientHello reports and every verdict
  its two primitives return, and computes what `srv_kex.h` states:
  - X25519MLKEM768 whenever the client listed it, x25519 when it listed
    x25519 and not the hybrid, and secp256r1 only when it listed
    neither;
  - an x25519 share that is `h->pub`;
  - a hybrid share that is the ciphertext and then `h->pub`,
    encapsulated to the key the hello carried;
  - a secp256r1 share that is the point the key generation wrote, drawn
    only after the client's point passed its check;
  - a refused encapsulation key that keeps no ML-KEM secret, and a
    refused client point that draws no key;
  - input keying material that is the ML-KEM secret and then the x25519
    one, computed against the x25519 value that ends the client's share,
    which is RFC 10024's order, or the P-256 secret of the scalar and
    the client's point;
  - on both exits, a wiped ML-KEM secret, P-256 scalar and x25519 key
    pair, with the whole 64-byte secret wiped on a refusal (INV-3,
    INV-17).

  ML-KEM, x25519, the P-256 exchange and `ch_rand_bytes` are stubbed to
  their contracts, as in [hybrid_secret](#hybrid_secret).
- **Bound:** every group and share a hello can report.

#### srv_select_suite

- **Harness:** `srv_select_suite` (fast)
- **Proves:** `srv_first_offered_suite`, the walk a `SUITE=aesgcm`
  server runs over its suite order. Over every offer of the three suites
  and every order of up to three code points, the suite it names is
  offered, held, in the order, and the first such; and it names none
  when no suite in the order is offered.
- **Bound:** the full domain.

#### srv_select_runtime

- **Harness:** `srv_select_runtime` (fast)
- **Build:** `ROLE=server SUITE=aesgcm` as a host object
  (`-DCH_CPU_RUNTIME`).
- **Proves:** `suite_session_default`, the order a session offers or
  prefers when its caller names none, is ChaCha20 alone for every 32-bit
  `ch_cfg.cpu` without `CH_CPU_CONSTANT_TIME_AES`, and the build's default
  order for every value with it; and `srv_first_offered_suite` over it,
  from any offer of the three suites, names no suite `suite_runs_here`
  refuses for the session (`docs/decisions.md` entries 81 and 89).
- **Bound:** the full domain.

#### srv_parser_walk

- **Harness:** `srv_parser_walk` (slow)
- **Proves:** the ClientHello walk in `srv_parser.c` stays safe and free
  of UB over any message, every byte and the length symbolic, with each
  reader stubbed to its contract:
  - an accepted hello carried supported_versions and satisfies each rule
    `check_required` states;
  - a refused one names one of the five alerts `srv_parser.h` lists.

  What each reader writes is [srv_parser_ext](#srv_parser_ext)'s. The
  duplicate check and the frozen digest's walk run real inside it, and
  never over more extensions than `SRV_CLIENT_HELLO_EXT_MAX`, which the
  harness takes at 4 (`docs/decisions.md` 59). SHA-256 is a stub that
  keeps no context.
- **Bound:** messages ≤ 64 B, five empty extensions after the head, one
  past the harness's bound.

#### srv_parser_ext

- **Harness:** `srv_parser_ext` (fast)
- **Proves:** every reader of `srv_parser_ext.c` stays safe and free of
  UB over an unconstrained extension body, any extension type and any
  offset the walk can hand it, and each answers `CH_OK` or `CH_EPROTO`.
- **Bound:** bodies ≤ 24 B.

#### srv_parser_frozen

- **Harness:** `srv_parser_frozen` (slow)
- **Proves:** the frozen digest a HelloRetryRequest cookie carries
  (`docs/decisions.md` 59):
  - over any extension block, the ascending walk and
    `srv_ext_duplicate` stay safe and read only inside the block;
  - on a whole block, `srv_ext_duplicate` answers 1 exactly when two
    extensions share a type, unknown types included;
  - on a whole block with no duplicate, the walk hands SHA-256 each
    covered extension once, whole, in strictly ascending type order.
    That is what lets the retry check compare a second ClientHello's
    extensions as a set.

  SHA-256 is a stub that records what it is handed.
- **Bound:** blocks ≤ 24 B, six extensions.
- **Not proved:** that the digest itself resists collision. That rests
  on SHA-256.

#### srv_parser_count

- **Harness:** `srv_parser_count` (fast)
- **Proves:** `srv_ext_over_max`, the count that bounds the parser's two
  walks whose cost is the square of the count (`docs/decisions.md` 59).
  Over any extension block it stays safe, answers 1 exactly when the
  block begins with more than `SRV_CLIENT_HELLO_EXT_MAX` whole
  extensions, and reads no header past the one that passes the bound.
- **Bound:** blocks ≤ 24 B, six extensions, the bound at 3, which
  `srv_parser.h` admits for a harness.
- **Not proved:** the real bound, 128. `bin/srv_test`,
  `bin/srv_tcp_nonblocking_test` and `bin/srv_quic_test` test it.

#### srv_message

- **Harness:** `srv_message` (fast)
- **Proves:** every builder in `srv_message.c` writes only inside the
  caller's buffer, for any capacity:
  - memory safety and absence of undefined behavior;
  - the return contract `srv_message.h` states for all of them: zero, or
    a length that fits the capacity;
  - the three refusals a builder makes on something other than the
    capacity: a cert_data length past the three-byte field, a
    request_update that is neither of its two legal values, and a
    transport-parameters body past `CH_TRANSPORT_PARAMS_MAX`;
  - a ServerHello, whatever group the selection names, is never longer
    than `SRV_SERVER_HELLO_MAX`, and a buffer of that length always
    holds it, so the constant `session.h` sizes `ch_tls.tx` by is
    sufficient;
  - `srv_certificate_fits` answers exactly the chain rule
    `srv_message.h` states, over entries of any length and either
    pointer, so no sum inside it wraps.

  The `wbuf` writer is real, not stubbed.
- **Bound:** capacity ≤ 256 B, larger than any message these builders
  emit under the bounds here; signatures ≤ 64 B; transport parameters ≤
  16 B; chains of 2 entries. A signature or parameter length past its
  real cap is also drawn, to cover the refusal, which returns before it
  reads a byte.

#### srv_auth

- **Harness:** `srv_auth` (fast)
- **Proves:** the six entries of `srv_auth.c` read and write only
  inside their own buffers and commit no undefined behavior, over an
  unconstrained configuration, an unconstrained transcript hash at every
  length the contract admits, and every SignatureScheme code point.
  - Each key pointer names one of four objects: the one its scheme
    wants, the one the other scheme wants, an object too short for
    either, or NULL. A chain pointer names 255 certificates, the most
    `chain_count` counts.
  - Under the caller's contract that each key length measures its
    object, `key_lengths_match` is the only line that keeps `srv_auth.c`
    from handing a signer, or a signer's key test, a buffer shorter than
    it reads. The signer stubs assert the key buffer is readable at the
    length they read, and those assertions fail if that line stops doing
    its job.
  - `srv_identities_usable`, the rule a configuration is held to before
    a session starts, answers 0 or 1, and an assert against either
    answer fails, so the formula holds both.

  The two signers, the two verifiers, the ECDSA key test, the chain rule
  and SHA-256 are contract stubs. [p256_sign](#p256_sign),
  [rsa_sign](#rsa_sign), [srv_message](#srv_message) and
  [sha256](#sha256) prove the real ones. The RSA key test is inline in
  `rsa_sign.h` and runs as written. The RSA-PSS salt `sign_rsa_pss`
  draws through `rand_draw` goes to a `ch_rand_bytes` stubbed to its
  contract, and the signer stub asserts the salt is readable at its
  length.
- **Bound:** the full domain. `srv_auth.c` holds no parser and no loop,
  and the harness varies all of its inputs: both identity slots, the
  sigalg code point, `hash_len` and the capacity.
- **Not proved:** that a signature is correct. The stubs return an
  unconstrained verdict, so the proof covers both answers.

#### srv_cookie

- **Harness:** `srv_cookie` (fast)
- **Proves:**
  - `srv_cookie_mint` writes only inside the caller's buffer and returns
    zero or a length that fits the capacity and equals the format's own;
  - at a capacity of `SRV_COOKIE_MAX` the mint always succeeds, so the
    constant `srv_flight.h` asserts against `HSP_COOKIE_MAX` is
    sufficient;
  - `srv_cookie_open` reads only inside the bytes the client echoed and
    answers one of its two verdicts, and a `CH_OK` answer reports a hash
    length the caller's buffer holds, over a cookie whose length is the
    one its suite fixes.
- **Bound:** cookies ≤ 118 B, one past `SRV_COOKIE_MAX`; transcript
  hashes ≤ `SRV_COOKIE_HASH_MAX` (48 B).
- **Not proved:** the round trip, that a minted cookie opens back to
  what it carried. SHA-256 is the contract stub, so the MAC comparison
  is unconstrained. `test/srv_cookie_tests.h` tests the round trip and a
  tamper sweep.

#### srv_ticket

- **Harness:** `srv_ticket` (fast)
- **Proves:**
  - `srv_ticket_seal` writes only inside the caller's buffer, and writes
    either nothing or the whole `SRV_TICKET_LEN`-byte ticket, which it
    always writes when the capacity and the ALPN length allow;
  - `srv_ticket_open` reads only inside the bytes it is given, answers
    `CH_OK` only for a ticket of exactly `SRV_TICKET_LEN` bytes whose
    first is `SRV_TICKET_VERSION` and whose ALPN length fits its field,
    and leaves the contents zeroed on a refusal, the QUIC version
    included.
- **Bound:** tickets ≤ 109 B, one past `SRV_TICKET_LEN`, and any
  contents, the QUIC version any `uint32_t`.
- **Not proved:** that a sealed ticket opens under its own key and under
  no other, and to the QUIC version it carried. The AEAD is a contract
  stub; `test/srv_ticket_tests.h` tests both and the body byte by byte.

#### srv_resume

- **Harness:** `srv_resume` (slow)
- **Proves:**
  - `srv_select_auth` walks any identities and binders lists without
    reading past either, selects a ticket only under `psk_dhe_ke` with a
    ticket key and a clock, names an index inside the list, and answers
    `CH_OK` with a way to authenticate, `CH_EAUTH` with decrypt_error, or
    `CH_EPROTO` with missing_extension or handshake_failure;
  - a selected ticket records the session's QUIC version, which over the
    TCP build the harness compiles is 0, whatever version each opened
    ticket carries;
  - `srv_send_new_session_ticket` sends at most one ticket, none without
    a key and a clock, with a lifetime of 1 to `SRV_TICKET_LIFETIME`, and
    seals the session's QUIC version into it.
- **Bound:** identities ≤ 121 B, one whole ticket and a short entry;
  binders ≤ 35 B.
- **Not proved:** which binder matches, and the QUIC arm, where the
  session's version is `ch_tls.quic_negotiated_version`. `srv_ticket.c`,
  the key schedule and the builders are contract stubs;
  `test/srv_resume_tests.h` tests the binder, and
  `test/quic_loop_ticket_versions.h` the QUIC arm.

#### srv_flight

- **Harness:** `srv_flight` (no launch line)
- **Not proved.** `proof/srv_flight_harness.c` exists, and its formula
  returns no verdict with all fifteen handlers real: no answer in 55
  minutes at `--unwind 40`, and none at 20 or 18. `proof/run.sh` records
  what was tried and the layered split it needs.
- **Tested instead:** `bin/srv_flight_test` and four `.violation`
  mutants cover the handlers.

#### srv_tcp_nonblocking

- **Harness:** `srv_tcp_nonblocking` (no launch line)
- **Not proved.** `proof/srv_tcp_nonblocking_harness.c` exists, and its
  formula returns no verdict with the record loop, the message loop and
  the step table in one solve: none in 11 minutes at `--unwind 8` over
  12-byte buffers, and none in 9 min 52 s at 6.2 GB at `--unwind 4` over
  8-byte buffers. `proof/run.sh` records what was tried and the layered
  split it needs.
- **Tested instead:** `bin/srv_tcp_nonblocking_test`,
  `bin/tcp_nonblocking_loop_test` and fifteen `.violation` mutants cover
  `srv_tcp_nonblocking.c` and `tcp_nonblocking_frame.c`, among them the
  alert record a failure seals before its wipe and pushes (INV-13).

### QUIC

Every harness in this group builds `TRANSPORT=quic-nonblocking`. The
[aes](#aes) entry covers the AES-128 cipher the Initial keys run on.

#### quic_keys

- **Harness:** `quic_keys` (fast)
- **Proves:** `quic_keys_init`, `quic_hp_key_init` and
  `quic_keys_update` read and write only inside their buffers and commit
  no undefined behavior, for any traffic secret and any QUIC version, the
  value that chooses their labels. `quic_keys_update`
  writes the next secret back over the caller's buffer and derives the
  key set from it, so the same 32 bytes are an input and an output of
  one call, and the harness covers that aliasing. HKDF is a contract
  stub (`proof/aes_stubs.h`).
- **Bound:** the full domain. Every buffer is a fixed-size array, every
  derivation asks HKDF for a constant number of bytes, and the harness
  varies all 32 secret bytes.
- **Not proved:** what the derivations compute. `test/quic_vectors.c`
  checks them against RFC 9001 Appendix A.5's four printed values and
  RFC 9369 Appendix A.5's four in version 2, and the Lean differential
  compares them with `spec/lean/Spec/Quic.lean` over random secrets in
  both versions.

#### quic_packet

- **Harness:** `quic_packet` (fast)
- **Proves:** every entry of `quic_packet.c` reads and writes only inside
  the buffers its caller gave it and commits no undefined behavior, over
  unconstrained packets, keys, lengths, packet numbers and key set
  names. The formula exists for two things:
  - the shift distances `quic_pn_read` and `quic_pn_decode` build from
    `pn_len` stay below the operand's width for any `pn_len`, because
    both mask the distance;
  - the offsets the open path derives from `pn_off` and `pn_len` (the
    packet number field, the associated data, the ciphertext and the
    tag) stay inside the packet.

  ChaCha20 and the AEAD are contract stubs, so this formula holds the
  framing rather than a keystream and a tag.
- **Bound:** headers ≤ 8 B, payloads ≤ 8 B, packets ≤ 40 B.
- **Not proved:** the bytes. `test/quic_packet_tests.h` checks RFC 9001
  Appendix A.5's whole packet end to end.

#### quic_initial

- **Harness:** `quic_initial` (fast)
- **Proves:** `quic_initial_seal` and `quic_initial_open` read and write
  only inside their buffers, commit no undefined behavior, and answer
  one of the codes their header documents, over unconstrained
  connection-ID, packet-number, header, payload, capacity and packet
  lengths and any QUIC version. Three properties beside safety:
  - a refusal writes neither output;
  - a successful open reports a plaintext length inside the packet it
    was handed;
  - a version `quic_version_derived` refuses is refused with `CH_EINVAL`
    before a key is built, and the key constructor is handed only a
    version it admits.

  The eight calls the two entries make are stubbed to their contracts
  (`proof/quic_initial_stubs.h`). [aes](#aes) and the three [gcm](#gcm)
  harnesses prove four of them, and [quic_packet](#quic_packet) proves
  the header protection pair and the packet number pair.
- **Bound:** headers ≤ 6 B, payloads ≤ 6 B, packets ≤ 28 B (two bytes
  either side of §5.4.2's sample bound), connection IDs ≤
  `CH_QUIC_DCID_MAX` (20 B).
- **Not proved:** what the derivation, the seal and the mask compute.
  `test/quic_vectors.c` checks them against RFC 9001 Appendix A.2's
  client Initial packet, and against RFC 9369 Appendix A.2's and A.3's
  packets byte for byte in version 2.

#### quic_retry

- **Harness:** `quic_retry` (fast)
- **Proves:** `quic_retry_ok` reads only inside the pseudo-packet and the
  tag it is handed and commits no undefined behavior. For any QUIC
  version `quic_version_derived` admits it answers 1 for the tag
  `gcm_seal` computed over that pseudo-packet, and 0 for a tag that
  differs in one byte, at any position and by any nonzero amount; for any
  other version `quic_retry_tag` returns `CH_EINVAL` and writes no tag
  byte, and `quic_retry_ok` answers 0 to the genuine tag.
  `gcm_seal` and `aes_public_key_retry` are contract stubs the harness
  defines. The `aes_public_key_retry` stub asserts it is asked for the
  version the caller named, and the `gcm_seal` stub asserts what RFC
  9001 §5.8 fixes at this one call site: the key `aes_public_key_retry`
  wrote, the nonce that version's RFC prints (RFC 9001 §5.8's for
  version 1, RFC 9369 §3.3.3's for version 2, both written in the
  harness), the caller's whole pseudo-packet as associated data, and an
  empty plaintext.
- **Bound:** pseudo-packets ≤ 64 B.
- **Not proved:** that the AEAD meets that contract, or that the key
  `aes_public_key_retry` writes is the one the version's RFC prints. The
  [gcm](#gcm) harnesses, RFC 9001 Appendix A.4, RFC 9369 Appendix A.4
  and the Lean differential's Retry rows cover that, not this harness.

#### quic_token

- **Harness:** `quic_token` (fast)
- **Build:** `ROLE=server` or `ROLE=both`.
- **Proves:**
  - `ch_srv_quic_token_mint` writes only inside the caller's buffer;
    writes the type byte, the issue instant, both lengths and both
    connection IDs where `quic_token.h`'s layout puts them; writes
    nothing on a refusal; and never refuses a capacity of
    `CH_QUIC_TOKEN_MAX`.
  - `ch_srv_quic_token_check` reads only inside the token and the
    address. It answers `CH_EINVAL` for exactly the address lengths
    outside 1 to `CH_QUIC_TOKEN_ADDRESS_MAX` and the QUIC versions
    `quic_version_derived` refuses, as the mint does, `CH_EPROTO` only for a
    token that is not a Retry token, and `CH_EAUTH` only for one that
    is. It writes nothing on any refusal. It answers `CH_OK` only for a
    token whose length its two length bytes fix, whose connection IDs
    fit their arrays, and whose issue instant is at most the lifetime
    before now and not after it.
- **Bound:** any address length, any QUIC version, any connection ID
  length a byte holds, any instant and lifetime; tokens ≤ 84 B, one past
  `CH_QUIC_TOKEN_MAX`.
- **Not proved:** that a minted token checks, and that another address,
  key or QUIC version does not. SHA-256 is the contract stub, so the tag
  is unconstrained; `test/quic_token_tests.h` tests them.

#### quic_driver

- **Harness:** `quic_driver` (fast)
- **Proves:** `quic.c`'s eighteen public entries and its input loop are
  safe and free of undefined behavior over any saved state, any saved
  QUIC version and any caller argument:
  - the unread window stays inside `cfg.buf`;
  - `CH_EINVAL` changes nothing and names one of the three refusals
    `quic.h` lists;
  - every other error leaves the session dead with nothing staged and
    nothing unread, no read key, no traffic secret and no write key at a
    level whose write bit is clear;
  - a level delivered out of order reports RFC 9001 §4.1.3's
    PROTOCOL_VIOLATION;
  - a dead session seals and opens no packet through `ch_quic_seal` and
    `ch_quic_open`;
  - `ch_quic_seal_close` seals only for a failed session at a level
    whose write bit is set, in a version that level admits, wipes that
    level's write keys and clears its bit, and refuses a second call at
    that level (`docs/decisions.md` entry 57);
  - `ch_quic_init` refuses an original version `quic_version_derived`
    does not admit and starts the negotiated version at the one it
    admits;
  - a packet call refuses a version its level does not admit, and an
    open refused so counts no failure and changes no bit or state;
  - `ch_quic_retry_ok` answers 0 in any version but the original;
  - `ch_quic_switch_version` succeeds only for a live client session that
    waits for the ServerHello with no server byte taken, has not
    switched, and is given a different version this build derives; it
    writes that version and nothing else, and refuses the next switch
    (`docs/decisions.md` entry 79).

  The QUIC arm of `handshake_record.c` and all of `quic_config.c` in a
  raw build are compiled in, and [quic_config_webpki](#quic_config_webpki)
  proves its `TRUST=webpki` arm. `hsq_advance`, the two flight handlers
  `ch_quic_init` calls, and the packet calls are contract stubs
  (`proof/quic_driver_stubs.h`). [quic_step](#quic_step) proves the step
  table against the same `hsq_advance` contract, so the two read as a
  pair.
- **Bound:** 12 B receive buffer, 32 B staged message.

#### quic_step

- **Harnesses:** `quic_step` (fast), `quic_step_ca` (fast)
- **Proves:** `hsq_advance` is safe over any saved state, a step number
  no step wrote included. It:
  - consumes its message, and raises the step or waits for the retry
    hello;
  - never raises `t.state`;
  - touches no packet counter and writes no version;
  - derives every key under the session's negotiated version;
  - stages nothing on an error;
  - at the Finished step, stages the client Finished at the Handshake
    level, moves to 1-RTT, reports that level in both directions, and
    writes the back pointer again after the wipe.

  Every flight handler and the three `quic_keys.c` derivations are
  contract stubs. `quic_step_ca` is the same harness under a ca mode,
  where `hsa_epoch_commit` runs and the wipe bound is that build's
  larger `handshake_state`.
- **Bound:** 12 B receive buffer.

#### quic_config_webpki

- **Harnesses:** `quic_config_webpki` (fast), `quic_config_webpki_suite` (fast)
- **Build:** `TRUST=webpki TRANSPORT=quic-nonblocking` only, and
  `quic_config_webpki_suite` under `SUITE=aesgcm` as a host object
  (`-DCH_CPU_RUNTIME`) too.
- **Proves:** `ch_quic_init`'s configuration rules under `TRUST=webpki`,
  which are `webpki_cfg_ok`'s, SPKI pins included, plus RFC 9001's
  (`docs/decisions.md` entry 64). `quic_config_ok`:
  - is safe over any configuration;
  - reads no anchor or protocol entry past its cap, whatever the count
    says;
  - runs `webpki_resumption_ok` only once the pin, hostname and anchor
    rules hold;
  - answers `CH_OK` only for a configuration that keeps the rules
    `webpki_cfg.h` and `quic.h` state: 0 to `CH_SPKI_PIN_MAX` pins;
    either pins alone or 1 to `CH_WEBPKI_ANCHOR_MAX` anchors with a
    hostname and a clock; no pin slot; a ticket `webpki_resumption_ok`
    took or no PSK; with `resumption` set, a ticket age no older than
    the ticket's lifetime or `CH_TICKET_LIFETIME_MAX` seconds, and a
    ticket QUIC version equal to the original version; 1 to
    `CH_ALPN_MAX` protocols; the transport parameters; `on_level_ready`;
    the buffer floor; an original version `quic_version_derived` admits;
    and no epoch callback;
  - in `quic_config_webpki_suite`, answers `CH_OK` only when the
    client's `cipher_suites` is unset with a count of 0, or holds 1 to
    `SUITE_HELD_COUNT` suites the build holds with none repeated, and
    reads no suite past that cap whatever the count says
    (`docs/decisions.md` entry 80). Narrowing the harness's rule to two
    suites fails the formula, so the cap it admits is exact. There it also
    answers `CH_OK` only when `ch_cfg.cpu`, any 32-bit value, holds
    `CH_CPU_PROBED` and no bit `cpu_cfg.h` leaves undefined for the
    architecture, and without `CH_CPU_CONSTANT_TIME_AES` only for a
    `cipher_suites` that names no AES-GCM suite (`docs/decisions.md`
    entries 81 and 89).

  `quic_config.c` and `webpki_cfg.c` are real; `webpki_hostname_ok`,
  `webpki_resumption_ok` and `ct_memeq` are contract stubs.
- **Bound:** every pointer NULL or set, every count and length any
  `size_t`, the ticket age any `uint64_t`, the lifetime and both versions
  any `uint32_t`, anchor names and keys ≤ 4 B.
- **Not proved:** which hostnames pass, which bindings match and which
  names repeat. Those are tested.

#### quic_keys_suite, quic_packet_suite

- **Harnesses:** `quic_keys_suite` (fast), `quic_packet_suite` (fast)
- **Build:** `SUITE=aesgcm`.
- **Proves:** the QUIC key derivations and packet protection, over each
  of the three suites:
  - the three §5.1 derivations and the §6.1 update derive at the suite's
    hash and key length, under one of the four labels of the QUIC version
    they were given;
  - the mask, the seal and the Handshake open run the cipher the key
    set's suite names, at its key length;
  - the seal counts and refuses under AES-GCM's §6.6 limit alone.

  Every cipher is a contract stub, because the AES entries run on the
  instructions.
- **Bound:** headers ≤ 8 B, payloads ≤ 8 B, packets ≤ 40 B.
- **Not proved:** the bytes. `bin/quic_suite_test` checks them.

### Certificates: provisioning and the ca modes

#### pem_step

- **Harnesses:** `pem_step` (fast), `pem_step_ecdsa` (fast)
- **Proves:**
  - `b64_value` returns exactly what RFC 4648 §4's alphabet table
    returns, on all 256 bytes;
  - `pad_ok` is exactly §3.5's rule;
  - one body character preserves the decoder's accounting invariant
    from any state it admits, so induction carries that invariant to any
    input length.
- **Bound:** unbounded: one character, any state.

#### pem

- **Harnesses:** `pem` (fast), `pem_ecdsa` (fast)
- **Proves:** the PEM decoder stays safe on hostile bytes at the shipped
  caps and honors its contract: a success yields a non-empty length
  inside the caller's array, every rejection yields zero, and an input
  over `CH_PEM_MAX` is refused before a byte is read.
- **Bound:** inputs ≤ 64 B.
  [PEM input longer than 64 bytes](#pem-input-longer-than-64-bytes)
  states what holds past that.

#### x509der

- **Harnesses:** `x509der` (fast), `x509der_ecdsa` (fast)
- **Proves:** every DER primitive stays safe on hostile bytes at the
  rbuf shape its caller hands it, honors the pointer contracts the
  walker rests on, and consumes no more than the per-primitive cap the
  walker proof replays, in both builds.
- **Bound:** inputs ≤ 448 B; keyusage at its 256 B extnValue cap.

#### x509parse

- **Harnesses:** `x509parse` (slow), `x509parse_ecdsa` (slow)
- **Proves:** the certificate walker stays safe on any entry list, with
  the primitives stubbed to their proven contracts. Only the ECDSA build
  proves the full two-entry flight.
- **Bound:** ECDSA: ≤ 256 B, two entries. RSA: ≤ 840 B, one entry.
- **Not proved:** the RSA build's two-entry walk. The RSA bound holds one
  maximum certificate plus framing, so its two-entry walk rests on the
  ECDSA proof and on the walker being identical outside the SPKI arm.

#### x509ca

- **Harnesses:** `x509ca` (fast), `x509ca_ecdsa` (fast)
- **Proves:** the provisioning walk stays safe on any input and honors
  its contract: a success yields a key inside `CH_X509_KEY_MAX`, and
  every rejection yields zero with the key wiped. DER primitives are
  stubbed to the contracts [x509der](#x509der) proves. The SPKI stub
  deliberately returns lengths outside the real range, so the entry's
  own bound check is what keeps the copy in range.
- **Bound:** any input; decoded certificate ≤ `CH_X509_MAX`.

### Certificates: TRUST=webpki

#### webpki_spki

- **Harness:** `webpki_spki` (fast)
- **Proves:** `webpki_read_spki` over any bytes, with the real DER
  primitives:
  - it reads no byte outside the input, a heap object of exactly its
    length;
  - a success leaves the reader's error clear and consumes exactly the
    length of the returned key's canonical encoding, at most 550 bytes
    (the largest SubjectPublicKeyInfo the modulus check admits). Every
    part of that encoding has a minimum size, so the equality leaves no
    container room for a byte after its last field;
  - the key lies inside the consumed bytes and has its algorithm's
    shape: an RSA modulus of 256 to `CH_RSA_MODULUS_MAX` bytes in steps
    of 8 with its top and low bits set, a 64-byte P-256 point, or a
    96-byte P-384 point.
- **Bound:** inputs ≤ `CH_WEBPKI_CERT_MAX` (3,072 B),
  `CH_RSA_MODULUS_MAX` 512.
- **Not proved:** whether the point is on the curve; that is tested.
  `p256_ecdsa_verify` and `p384_ecdsa_verify` check it, and the `p256`
  and `p384` harnesses call that check for memory safety with no
  assertion on its result. `test/webpki_sigalg_test.c` gives
  `webpki_verify` signatures forged for the point (1, 0), which only the
  curve check refuses.

#### webpki_sigalg

- **Harness:** `webpki_sigalg` (fast)
- **Proves:**
  - `webpki_read_sigalg` over any bytes in a heap object of exactly
    their length: it reads no byte past the end, and a success yields
    one of the four algorithms and consumes exactly its encoding.
  - `webpki_verify` over any certificate and signer, with the key in an
    anchor buffer or in the certificate buffer, and both hashes and the
    three verifiers stubbed to their contracts:
    - a TBS over the cap, an unknown algorithm, or a key of the other
      family calls no hash and no verifier;
    - the hash is the one the algorithm names, over the DER SEQUENCE
      header for the TBS length, checked against bytes the harness
      writes itself, and then exactly the TBS;
    - the verifier is the one the key's algorithm names, and it gets the
      signer's key and the certificate's signature at their own lengths;
    - `p256_ecdsa_verify` gets the digest's first 32 bytes, and
      `p384_ecdsa_verify` the SHA-384 digest or 16 zero bytes then the
      SHA-256 digest (FIPS 186-4 §6.4);
    - the verdict is the verifier's.
- **Bound:** inputs ≤ `CH_WEBPKI_CERT_MAX`, TBS lengths to one byte past
  it.

#### webpki_time

- **Harness:** `webpki_time` (fast)
- **Proves:**
  - the `TRUST=webpki` Time reader stays safe on hostile bytes from any
    reader state, any position and either err value included. A success
    leaves err clear, consumes exactly one Time TLV (15 or 17 bytes),
    and yields a packed date inside [19500101000000, 99991231235959];
  - the clock packer stays safe over every uint64, its clamp at
    9999-12-31T23:59:59Z included, and yields a value inside the same
    range.
- **Bound:** Time bytes ≤ 40 B; the clock at its full range.
- **Not proved:** that the packer keeps the order of clocks. Asserted
  over two nondet clocks, it returned no verdict in 30 minutes. The
  evidence for that order is `Spec.WebpkiTime.packSeconds_mono` and the
  differential; see
  [The subjectAltName walk against a full-length hostname](#the-subjectaltname-walk-against-a-full-length-hostname).

#### webpki_name

- **Harness:** `webpki_name` (fast)
- **Proves:**
  - the `TRUST=webpki` hostname shape check stays safe over any host and
    honors the contract `webpki_match_san` depends on: a name it accepts
    is 1..253 bytes of `[A-Za-z0-9.-]`, so it holds no NUL and no `*`,
    and every `-` in it has a byte other than a dot on each side, so no
    label starts or ends with `-`;
  - the per-entry dNSName compare, both its exact and its wildcard arm,
    stays safe over any presented name against any host.
- **Bound:** host ≤ `CH_HOSTNAME_MAX` (253 B), the real bound; presented
  name ≤ `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the Extension bound, which no
  dNSName inside an Extension exceeds.

#### webpki_san

- **Harness:** `webpki_san` (fast)
- **Proves:** the subjectAltName walk, in two parts like
  [pem_step](#pem_step) and [pem](#pem):
  - reading one GeneralName entry (its tag, its length, its content, the
    dNSName compare) is safe from any reader state, any position and
    either err value included. An entry it accepts starts with one of
    the nine GeneralName tags, leaves err clear, and moves the position
    forward by two or more bytes and never past the end, which is why
    the loop ends;
  - `webpki_match_san` whole (the SEQUENCE header, its length check, the
    loop over entries) is safe on any bytes.

  The host is short in both parts: the walk passes it to the compare
  without change and reads no byte of it, and [webpki_name](#webpki_name)
  proves that compare with a 253-byte host and a presented name of up to
  1024 bytes; see
  [The subjectAltName walk against a full-length hostname](#the-subjectaltname-walk-against-a-full-length-hostname).
- **Bound:** one entry at `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the real
  bound; the whole walk ≤ 32 B; host ≤ 16 B. At 64 B the unrolled loop
  returned no verdict in 16 minutes, and before the split the walk at
  1024 B was still being converted at 30 minutes.

#### webpki_ext

- **Harnesses:** `webpki_ext` (slow), `webpki_ext_one` (slow), `webpki_ext_walk` (slow)
- **Proves:** the certificate extension walk, in parts like
  [webpki_san](#webpki_san).
  - `webpki_ext` proves the pieces that read one element, the first
    three over heap objects of exactly their input's length, so none
    reads a byte past the end:
    - one KeyPurposeId from any reader state, which, when accepted,
      leaves err clear and moves the position forward by three bytes or
      more and never past the end, so the purposes loop ends;
    - `x509_read_extension` at the 1024-byte cap from any reader state,
      whose accepted Extension takes 7 to 1024 bytes with its extnID and
      extnValue inside them;
    - basicConstraints over any extnValue, cA 0 or 1 and a
      pathLenConstraint from −1 to 32767;
    - the whole purposes loop.
  - `webpki_ext_one` judges one Extension from any reader state and any
    walk state before it. A refusal names one of the two alerts. An
    accepted one consumes 7 to 1024 bytes, adds at most one seen bit not
    already set, moves san only with its bit and inside the consumed
    bytes, and moves is_ca and path_len only with basicConstraints,
    is_ca equal to the arm.
  - `webpki_ext_walk` runs `webpki_read_extensions` whole, the field
    read from its first byte. On `CH_OK` the arm's required extensions
    were seen, is_ca equals the arm, path_len is −1 on the leaf, and san
    is inside the consumed bytes and present on the leaf. Asserting 0 on
    each arm's success tail fails both, so both tails are reached.
- **Bound:** one KeyPurposeId, `x509_read_extension` and
  basicConstraints at `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the real bound;
  the purposes loop ≤ 64 B; one judged Extension ≤ 96 B; the whole walk
  ≤ 48 B, which holds the leaf's shortest accepted field of 47 B.
  - One judged Extension at 128 B returned no verdict in 31 minutes.
  - The whole walk from any reader state converged at 40 B and returned
    no verdict at 48 B in 31 minutes; from the first byte it returned
    none at 64 B in 30 minutes.

#### webpki_cert

- **Harness:** `webpki_cert` (fast)
- **Proves:** `webpki_parse_certificate` over any bytes and any arm
  value, with the four readers it hands fields to
  (`webpki_read_sigalg`, `webpki_read_time`, `webpki_read_spki`,
  `webpki_read_extensions`) stubbed to the contracts their own harnesses
  prove and the DER primitives real:
  - it reads no byte outside the certificate, a heap object of exactly
    its length, so a read one past the end fails a bounds check at any
    length;
  - it returns `CH_OK` or `CH_EPROTO`, and a refusal leaves
    `ALERT_BAD_CERTIFICATE` or sets `ALERT_UNSUPPORTED_CERTIFICATE`;
  - a success leaves the alert untouched and is at most
    `CH_WEBPKI_CERT_MAX` bytes;
  - tbs lies inside the certificate; issuer, subject, the key and a
    non-NULL san lie inside tbs; the signature is non-empty, inside the
    certificate and after tbs;
  - notBefore is no later than notAfter, the algorithm values are in
    range, and is_ca is the arm normalized to 0 or 1 with that arm's
    extensions seen.

  Asserting at the success tail that the length is under
  `CH_WEBPKI_CERT_MAX` fails, so a certificate at the cap reaches the
  tail.
- **Bound:** certificates ≤ 3,073 B, the real bound and the first length
  refused.
- **Not proved:** the stubbed `webpki_read_extensions` contract past
  `webpki_ext_walk`'s bound, the only bound it is proven at; see
  [The extension walk over a full-size extensions field](#the-extension-walk-over-a-full-size-extensions-field).

#### webpki_cert_key

- **Harness:** `webpki_cert_key` (fast)
- **Proves:** `webpki_read_certificate_key`, the reader a leaf pinned
  with no anchor goes through (`docs/decisions.md` entry 65), over any
  bytes, with [webpki_cert](#webpki_cert)'s four reader stubs:
  - it reads no byte outside the certificate, a heap object of exactly
    its length, so a read one past the end fails a bounds check at any
    length;
  - it returns `CH_OK` or `CH_EPROTO` with one of the two alerts;
  - a success keeps the alert, is at most `CH_WEBPKI_LEAF_PIN_CERT_MAX`
    bytes, and puts tbs inside the certificate; issuer, subject and the
    SubjectPublicKeyInfo TLV inside tbs; and the key inside that TLV;
  - on every return, the extensions reader never ran and the fields the
    call does not write are untouched.

  Asserting at the success tail that the length is under
  `CH_WEBPKI_LEAF_PIN_CERT_MAX` fails, so a certificate at the cap
  reaches the tail.
- **Bound:** certificates ≤ 16,376 B: `CH_WEBPKI_LEAF_PIN_CERT_MAX`, the
  real bound, which one entry of the largest Certificate message holds,
  and the first length refused. cbmc gives each read at a symbolic offset
  into a fixed-size array clauses in proportion to its length, so a
  fixed array of that size made 78 million clauses and a 9.1 GB solve;
  the certificate is a heap object of symbolic size instead, 0.8 million
  clauses and 0.44 GB.

#### webpki_chain

- **Harness:** `webpki_chain` (fast)
- **Proves:** `webpki_verify_chain` over any CertificateEntry list and
  any anchor array, with the six calls it makes
  (`webpki_parse_certificate`, `webpki_read_spki`, `webpki_verify`,
  `webpki_match_san`, `webpki_pack_seconds`, `ct_memeq`) stubbed to the
  contracts their own harnesses prove:
  - it returns `CH_OK`, `CH_EPROTO` or `CH_EAUTH`;
  - a refusal names one of the five alerts `webpki.h`'s table lists;
  - a success keeps the caller's alert and copies out a leaf key of at
    most `CH_WEBPKI_KEY_MAX` bytes under one of the three key
    algorithms.

  Asserting 0 at the success tail fails, so the tail is reached.
- **Bound:** lists ≤ 48 B, which holds eight framed entries of 6 bytes
  each, so both the `CH_WEBPKI_FLIGHT_ENTRIES` refusal and the
  `CH_WEBPKI_CHAIN_MAX` one are inside it; 2 anchors of ≤ 8 B each.
- **Not proved:** which chains it accepts. The verify and match stubs
  answer an unconstrained verdict, so the formula says nothing about
  soundness. The `ct_memeq` stub asserts that it may read both Names and
  answers an unconstrained verdict too, so the formula does not say
  which Names the walk finds equal; the [ct](#ct) harness proves the
  comparison. `Spec.Webpki.verifyChain_ok` states that an accepted chain
  has a verified signature path to an anchor, and
  `test/webpki_chain_test.c` and `test/diff_webpki_chain.h` test it over
  the corpus; see
  [Which chains the TRUST=webpki walk accepts](#which-chains-the-trustwebpki-walk-accepts).

#### webpki_pin

- **Harness:** `webpki_pin` (fast)
- **Proves:** the SPKI pin calls of `webpki_pin.c` are memory-safe and
  UB-free over any input at their real bounds, and hold
  `webpki_pin.h`'s contracts:
  - `webpki_verify_raw_key`, the rule for an RFC 7250 raw public key,
    reads no byte outside the list, a heap object of exactly its length,
    returns `CH_OK`, `CH_EPROTO` or `CH_EAUTH` with an alert from
    `webpki_pin.h`'s table, and a refusal leaves the output as it was.
    `CH_OK` means the list is one CertificateEntry (its u24 length, that
    many bytes, an empty u16 extensions vector, and nothing after it);
    the one pin compare hashed exactly the entry's bytes, and one of the
    pins equals that digest; and the output holds a key of one of the
    three algorithms and at most `CH_WEBPKI_KEY_MAX` bytes, with
    `path_entries` and `anchor_index` 0, and the caller's alert.
  - The key copy into the output writes at most `CH_WEBPKI_KEY_MAX`
    bytes, to a writable destination, from a readable source that does
    not overlap it.
  - `webpki_path_pinned` answers 0 or 1. It parses at most
    `path_entries` certificates, the first under the leaf arm and the
    rest under the issuer arm. It hashes each of their
    SubjectPublicKeyInfo ranges and then the spki of
    `cfg->anchors[anchor_index]`, and nothing else. A leaf the walk
    cannot write, a path over `CH_WEBPKI_CHAIN_MAX`, or an anchor index
    past `anchor_count` answers 0.

  `webpki_read_spki`, `webpki_parse_certificate` and SHA-256 are stubs,
  as in [webpki_chain](#webpki_chain); `webpki_read_entry`, the `rbuf`
  reader and `ct_memeq` are real.
- **Bound:** raw lists up to one byte past a raw entry at
  `CH_WEBPKI_SPKI_MAX` (550 B); up to `CH_SPKI_PIN_MAX` pins; pinned
  paths ≤ 24 B; 2 anchors of ≤ 8 B each.
- **Not proved:** that a digest names the key it was taken over. The
  SHA-256 stub answers any digest; `spec/lean/Spec/WebpkiPin.lean`
  states the rule over the real SHA-256, and the differential compares
  the two.
- **Tested instead:** `webpki_verify_raw_key` with the real key reader
  and SHA-256 the harness stubs, over lists longer than the bound.
  `fuzz/fuzz_webpki_raw_key.c`, which the nightly runs, drives the call
  over the lists and pins libFuzzer generates: up to `CH_SPKI_PIN_MAX`
  pins, in inputs of up to 4,096 bytes. Its seeds are the 27 distinct
  keys of `test/webpki_auth_vectors.h`'s raw rows and
  `test/webpki_corpus.h`, each the one entry of a list after its own
  pin, two RSA-4096 anchors at `CH_WEBPKI_SPKI_MAX` among them, and one
  entry a byte past that cap after `CH_SPKI_PIN_MAX` pins.

#### webpki_leaf_pin

- **Harness:** `webpki_leaf_pin` (fast)
- **Proves:** `webpki_verify_leaf_pin`, the rule for a chain under SPKI
  pins alone (`docs/decisions.md` entry 65), over any list and up to
  `CH_SPKI_PIN_MAX` pins, with the list framing real and
  `webpki_read_certificate_key` and SHA-256 stubbed:
  - it returns `CH_OK`, `CH_EPROTO` or `CH_EAUTH` with an alert from
    `webpki_pin.h`'s table;
  - it runs the key reader at most once, and on entry 0;
  - it leaves the output alone on a refusal;
  - a success has a framed first entry, hashed exactly the
    SubjectPublicKeyInfo the reader returned for it, matched one of the
    pins, and returns that key with a path of the leaf alone.
- **Bound:** lists ≤ 30 B, which hold five one-byte entries, one past
  the walk's `CH_WEBPKI_FLIGHT_ENTRIES`; pins alone store only the leaf,
  so they cap no count. Every entry of so short a list is far shorter
  than `CH_WEBPKI_LEAF_PIN_CERT_MAX`, the cap pins alone put on each
  entry: that cap is one compare in `webpki_read_entry`, which
  [webpki_pin](#webpki_pin) proves on both sides of its own cap, and
  `test/webpki_leaf_pins.h` tests on both sides of this one. The key
  reader's stub admits a certificate up to that cap, which
  [webpki_cert_key](#webpki_cert_key) proves. The key copy it shares
  with the raw rule is proved at the raw rule's full bound, in
  [webpki_pin](#webpki_pin).
- **Not proved:** which digests match. `Spec.WebpkiPin.verifyLeafPin_ok`
  states the rule over the real SHA-256, and
  `test/diff_webpki_leaf_pin.h` compares the two.
- **Tested instead:** lists longer than the bound, and the rule inside
  a handshake:
  - `fuzz/fuzz_webpki_leaf_pin.c`, which the nightly runs, drives the
    call over the lists and pins libFuzzer generates: up to
    `CH_SPKI_PIN_MAX` pins, in inputs of up to 16,413 bytes. Its seeds
    are every list in `test/webpki_corpus.h`, the corpus leaf over
    `CH_WEBPKI_CERT_MAX`, 5,558 bytes, included, and the r2 leaf rebuilt
    at `CH_WEBPKI_LEAF_PIN_CERT_MAX`, whose seed sets that input length.
    Each seed carries the pin of its leaf's key, but for the two leaves
    the key reader refuses.
  - `bin/webpki_loop_tcp_nonblocking` and `bin/quic_loop_webpki` run
    pins alone against this tree's server presenting the corpus leaf
    over `CH_WEBPKI_CERT_MAX`. A pin on its key completes the handshake,
    and a server that presents the same chain and signs with another key
    is refused with decrypt_error.

#### webpki_ticket

- **Harness:** `webpki_ticket` (fast)
- **Proves:** the `TRUST=webpki` resumption rule in `webpki_ticket.c`:
  - the configuration hash reads only inside the hostname and the
    anchors the config names;
  - `webpki_resumption_ok` reads a presented ticket's PSK and binding
    only after the shape check admits them;
  - it answers 0 or 1, and 1 only for a config whose PSK fields are all
    unset or that presents a ticket of the shape `webpki_ticket.h`
    states.
- **Bound:** hostname ≤ 253 B, 1 to 12 anchors with name and spki ≤ 4 B
  each, every PSK field NULL or set.
- **Not proved:** which bindings match. SHA-256 is the contract stub;
  `test/webpki_resume_cases.h` tests that against a known answer
  computed outside this tree.

## Known-answer vectors

Unit tests replay [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)'s
traces message by message:

- the shared secret;
- every derived secret at its transcript snapshot;
- both Finished MACs;
- the ticket's resumption PSK;
- the PSK binder chain and the HelloRetryRequest restart.

Those traces use AES-128-GCM, which the default build excludes, so the
replay stops at secrets and MACs. `bin/aes_suite_test` opens one of
their records under `SUITE=aesgcm`.

## What rests on tests, not proofs

Each section below names a property no proof covers and the evidence
that stands in for a proof.

### PEM input longer than 64 bytes

The decoder is a per-character state machine over symbolic bytes, the
shape bounded model checking pays most for. Its cost was measured at
roughly the third power of the input length, so a proof at the shipped
3,136-byte cap would not finish.

64 is the lowest bound that still works. The shortest accepting input is
58 bytes, and at 56 the success arm is unreachable, so its assertion
passes vacuously while the run still reports success.

`proof/pem_harness.c` states what holds past 64:

- `pem.c` does no raw buffer arithmetic, so its memory safety is
  `buf.c`'s;
- `pem_step` proves the per-character invariant from an arbitrary state.

What does not carry over is the boundary sequence at lengths this bound
never gets to. `test/diff_pem.h` exercises that up to `CH_PEM_MAX`
against the Lean oracle instead.

No fuzz target covers this parser, on purpose. The differential drives
the same domain against an oracle that checks the verdict and the bytes,
where a fuzzer checks only for a crash, and a ninth target would push
the nightly fuzz job past the budget `lint-fuzz-budget` holds.

### x25519, P-256 and RSA functional correctness

Each rests on published vectors
([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) including the
1,000-iteration chain, [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979),
and OpenSSL-produced PSS at 2048 and 3072 bits), plus fresh signatures
the Lean spec mints and the C must accept. CBMC proves the pieces; it
does not run a scalar multiplication or a 3072-bit exponentiation
whole.

The wide X25519 field rests on the same vectors, which `bin/unit_host`
and the host Wycheproof test run on it under the multiply bit, on its own
Lean differential binary, and on `bin/x25519_equiv_test`. In
`make check`, that binary compares the wide field with the 16-word field,
each as a host object compiles it, over 12,175 inputs:

- the RFC vectors and the 1,000-round chain;
- every low-order and non-canonical u-coordinate;
- 10,000 random scalar and u-coordinate pairs;
- 1,000 random scalars on the base point.

### P-256 ECDH functional correctness

This rests on tests for the same reason. The 355 Wycheproof
`ecdh_secp256r1` cases and `test/p256_ecdh_test.c`'s Python-computed key
pairs and shared secrets are what says the ladder computes the right
point; the proofs cover its memory safety and its range check.
`bin/diff_p256_wide` adds 25 key generations and 25 key exchanges
against the Lean spec under each answer
([What `make diff` runs](#what-make-diff-runs)).

The complete addition formula is correct when a point is added to
itself or to the point at infinity, which is what lets the ladder run
without a branch. That is Renes, Costello and Batina's theorem, tested
here and not machine checked.

The routines a host object's key exchange runs in Jacobian coordinates
(docs/decisions.md 112) are machine checked.
[`spec/lean/Spec/P256WidePoint.lean`](../spec/lean/Spec/P256WidePoint.lean)
holds the steps of `p256_wide_point_double_jacobian`,
`p256_wide_point_add_jacobian_incomplete` and the two conversions. It
proves that the doubling doubles every point of every curve
y^2 = x^3 - 3x + b over every field in which 2 is not zero, the point at
infinity and a point with y = 0 among them; that the addition adds two
finite points whose x differ, over every field; and that the conversions
keep every point. It also proves that the key exchange's odd multiples and
its windows 62 to 1 meet the addition's condition at every addition, so
they compute the multiples and the sum of the windows' multiples of the
point: for digits that are odd and at most 15 in size, wherever the
point's order is at least 2^252, and at P-256 for every finite point with
p and n prime and n • P = 0 as hypotheses. `bin/diff_p256_wide` holds the
C's steps to the model's, coordinate for coordinate, on random coordinates
and where a value a routine computes is zero. What none of this shows:
that the C is the model on every input, which the differential samples,
and anything about the complete additions, the top window of k·G, window 0
of the key exchange or the corrections, which stay tested.

The incomplete addition a host object's k·G runs in windows 1 to 41,
`p256_wide_point_add_affine_incomplete` (docs/decisions.md 111), is
machine checked the same way. The same module holds its steps and proves
that they add a finite point and an affine one whose x differ, over every
field. It also proves that the loop of those windows meets that condition
at every addition, so the loop computes the sum of the windows' multiples
of G: for digits that are odd and at most 63 in size, wherever G's order
is at least 2^252, and at P-256 with p and n prime and n • G = 0 as
hypotheses. `bin/diff_p256_wide` holds the C's steps to the model's on
random coordinates, at Z = 0 and where the two x are equal. The proof takes
the digits and the table as given: `window_digit` builds each digit from
five bits and a sign, the `p256_wide_digit` proof holds the digits to
k | 1, and `bin/p256_equiv_test` recomputes every entry of the table.

The inverse both wide moduli run, `p256_wide_inverse.c` (docs/decisions.md
115), is machine checked too.
[`spec/lean/Spec/P256WideInverse.lean`](../spec/lean/Spec/P256WideInverse.lean)
holds its rounds: the approximations, the 31 steps on them, the factors
and the two combinations, the sums over integers and modulo m. It proves
that 17 rounds invert every y coprime to an odd modulus below 2^256, and
send 0 to 0, and states both at P-256 with p and n prime as hypotheses.
It also proves that `p256_wide_inverse_public`, which stops at the first
round whose a is zero, gives the answer of all 17 rounds for every y
(docs/decisions.md 116).
The core is that a round shortens a and b by 31 bits between them while a
is not zero, although a comparison of the approximations can go the other
way from the comparison of a and b. Pornin's paper argues that bound; the
proof here follows a corrected form of the argument, in which a value may
grow back by one bit after such a step but only while both values are
below 2^(n - 32). The four `p256_wide_inverse` harnesses tie the C's
approximations and steps to references that branch, over every input, and
`bin/diff_p256_wide` holds both entries' answers to the model's at both
moduli on the edges, every power of two and every power of two less one,
and random values of every length. What none of this shows: that the C's
combinations compute the model's sums on every input, which the
differential and `bin/p256_equiv_test` sample.

### The wide P-256 files

A host session with the multiply bit signs and exchanges keys on
`p256_wide_field.c`, `p256_wide_scalar.c`, `p256_wide_inverse.c`,
`p256_wide_point.c` and `p256_wide_mul.c`, and computes k·G from
`p256_wide_table.c` (decisions 94 and 115). The 32-bit files carry the Python
vectors, RFC 6979's and the proofs of their masks; these checks carry
the wide files to the same answers:

- `bin/p256_equiv_test`, in `make check`, runs the wide files and the
  32-bit files on the same inputs, 68,051 comparisons on a CPU with the
  SHA-256 instructions, and requires the same words, bytes and verdicts.
  Both fields keep an element in the Montgomery domain with R = 2^256, so
  each comparison is of words taken two at a time, not of a value read
  back through another routine:
  - every field routine on 20,000 random pairs, a quarter of whose words
    are all ones and a quarter zero, on the elements at the edges and on
    values at and above p, and the wide field on
    `test/p256_field_vectors.h`'s values, which Python computed;
  - the scalar product and both scalar inverses, the constant-time one
    and the verifier's, on random scalars and on the ones at the edges;
  - the complete addition on 3,000 pairs of random coordinates, which
    are on no curve, and on a point with itself, with its negative and
    with the point at infinity on either side;
  - every one of the 1,376 entries of the table of multiples of G,
    recomputed from `p256_point_generator` with `p256_point_add` and
    `p256_point_affine`: row i starts six doublings above the row
    before, and each entry must be the affine bytes of the odd multiple
    it stands for. The entry's words leave the Montgomery domain through
    `p256_field.c`, so no wide routine runs on either side;
  - the mixed addition on 3,000 pairs of random coordinates and on a
    point with the generator, the generator with itself, with its
    negative and with the point at infinity, word for word against the
    complete addition with Z = 1;
  - the Jacobian doubling on the point at infinity, on the generator and
    on 24 random multiples of it, four doublings in a row from each,
    against the complete addition of the point with itself. The two
    formulas give the same point in other coordinates, so the comparison
    is of the affine bytes after the conversion back, whose point at
    infinity must also be (0 : Y : 0) with Y not zero, which the affine
    bytes cannot tell from (0 : 0 : 0);
  - the incomplete Jacobian addition on 24 pairs of random multiples of
    the generator and on the seven additions that make the odd multiples
    of a point, against the complete addition as points, and on the
    inputs outside its condition: a point with its negative and the point
    at infinity with itself, where it must give the point at infinity,
    and a point with itself and with the point at infinity on either
    side, where its Z must be zero; and both conversions, there and back,
    on the same points and on the Jacobian point with every coordinate
    zero;
  - the incomplete addition on 24 random multiples of the generator and
    entries of the table, against the complete addition as points, and
    on the three inputs outside its condition: the generator with
    itself and the point at infinity with the generator, where every
    coordinate must be zero, and the generator with its negative, where
    it must give (0 : Y : 0) with Y not zero;
  - the point decode on a point and on each way a point is refused, and
    the affine conversion on a finite point and on the point at infinity;
  - both scalar multiplications on 23 scalars at the edges, 0, 1, n - 1,
    n, n + 1 and 2^256 - 1 among them, the two whose sum before the top
    window of k·G is that window's entry, and n - 2 and n - 3, whose sum
    before window 0 of k·p is that window's entry, and on 40 random ones,
    half of them even;
  - a key pair, a signature and a shared secret under both answers.
- `bin/p256_equiv_test_sum`, in `make check`, is that binary with the
  two carry steps of `p256_wide_word.h` on the 128-bit sums, the form
  gcc compiles for a machine other than x86-64. `bin/p256_equiv_test`
  runs the form its compiler picks: the builtins under clang, and the
  two intrinsics under gcc for x86-64, which is what CI's check job and
  `test/docker-check.sh` compile with. No machine that runs check picks
  the sums, so the second binary names them.
- `bin/p256_equiv_test_builtin`, in `make check`, is that binary with
  the two carry steps on the overflow builtins, the form clang compiles.
  Under clang it runs what `bin/p256_equiv_test` runs. Under gcc for
  x86-64 it is the one binary of check that runs the builtins, so CI
  holds what that form computes too.
- `bin/p256_verify_equiv_test`, in `make check`, holds a host object's
  verifier, `p256_wide_verify.c`, to `p256.c`'s 32-bit arm, which
  `test/p256_verify_portable.c` compiles under a second name. It
  requires one verdict from the two, and the verdict each case names,
  over 1,113 verdicts:
  - signatures `p256_sign.c` wrote under both of its answers, each with
    one bit changed in the hash, in the key and in the signature;
  - signatures the test computes on `p256_scalar.c` and `p256_point.c`,
    an arithmetic that is neither verifier's: an s of 1, 2 and 3, and
    each with n added; a hash at or above n; a hash of zero, where u1
    is zero; u2 of one, where R is the key; u1·G equal to u2·Q, where
    the last addition is a doubling; and their negatives, where R is
    the point at infinity;
  - five cases over four keys whose multiples meet the sum inside the
    host arm's pass over the digits (decision 104): the keys G and -G
    with u1 equal to u2, the key -G with u1 = u2 + 2, and the keys G/2
    and -G/2 with u1 = 1 and u2 = 2, so that an addition there has two
    equal operands or two negatives;
  - r and s at 0, n - 1, n and 2^256 - 1; a key with a coordinate at p
    or above, a key off the curve and a key of zeros; and DER that is
    cut short, runs long, has another tag or pads an INTEGER.

  `bin/p256_equiv_test` reads the signatures it makes with that 32-bit
  arm, which the wide files do not compute. The host Wycheproof test
  runs Wycheproof's ECDSA P-256 vectors on the host verifier, among
  them the signatures whose k·G has an X of n or more.
- `test/aes-runtime-qemu.sh`, which the mips job of `check.yml` runs on
  every push, builds `bin/p256_equiv_test` with gcc for x86-64, the two
  intrinsics named, and for arm64, the 128-bit sums named, and runs each
  under qemu. `test/docker-aes-runtime-qemu.sh p256-equiv` runs those two
  rows alone on any machine with docker, and the two violations of the
  intrinsics name it as their catch: a machine whose compiler is clang
  compiles no line of that form.
- `tools/p256_wide.py`, in `make lint`, writes the table from SEC 2's G
  with Python's integers, and `make lint-p256-wide` fails when the
  checked-in file is not what it prints. The same script recomputes
  every constant the wide files hold from the SEC 2 values: the prime
  and the order in 64-bit words, 2^256 modulo p and 2^512 modulo each,
  2^768 modulo p, which the field's inverse multiplies by, the curve's b
  times 2^256, `N0_INV`, and -p^-1 mod 2^64, which the field's modulus
  for `p256_wide_inverse` carries. It also holds `p256_wide_inverse.c`'s
  `STEPS` and `ROUNDS` to the `steps` and `rounds` of
  `spec/lean/Spec/P256WideInverse.lean`, which the proof covers: every value
  the tests draw needs 14 rounds or fewer, so no test would see fewer.
- `bin/p256_sign_test_host` and `bin/p256_ecdh_test_host` run RFC 6979
  A.2.5 and the Python vectors once with the bit and once without it,
  and the Wycheproof host binary runs the 355 `ecdh_secp256r1` cases and
  signs and verifies every P-256 message in the corpus in each of its
  runs with the bit. In each of its runs `bin/p256_sign_test_host` also
  signs the vectors through `p256_sign_cpu` with the SHA-256 bit, so the
  nonce's HMACs run on the instructions where the CPU has them, and
  without it, and requires the vectors' bytes from both.
- `bin/p256_equiv_test` searches the stack below one more signature,
  made through `p256_sign_cpu` with the SHA-256 bit, for the same words
  it searches for below a signature through `p256_sign`: the nonce's
  HMACs then run in `hkdf_hw.c` and `sha256_hw.c`, whose frames lie
  below the signer's. A CPU without the instructions skips that search,
  or fails it under `CH_REQUIRE_HASH_INSTRUCTIONS=1`.
- `bin/diff_p256_wide`, in `make diff`, runs a key generation, a
  signature and a key exchange against the Lean spec under each answer,
  the incomplete additions, the Jacobian doubling and the two
  conversions against `spec/lean/Spec/P256WidePoint.lean`'s, coordinate for
  coordinate, and `p256_wide_inverse` and `p256_wide_inverse_public`
  against `spec/lean/Spec/P256WideInverse.lean`'s rounds at both moduli
  ([What `make diff` runs](#what-make-diff-runs)).
- `bin/widemul_runtime_test` counts the calls: the wide entries alone
  under the constant-time answer and the 32-bit files alone under every
  other byte ([The host object's two multiplies](#the-host-objects-two-multiplies)).

That the wide files run in constant time rests on how they are written,
and four checks hold parts of it:

- `make lint-wide-multiply` holds each file's count of conditional
  branches at its recorded number on arm64 and x86-64 under clang, so a
  select that clang turns into a branch, or a scan that passes over the
  entries a digit does not name, shows as a count that grows.
- `make lint-p256-wide` runs `tools/p256-wide-carry.py`, which reads
  `p256_wide_word.h` as clang preprocesses it and as gcc does, for arm64
  and for x86-64, and requires the overflow builtins in the two carry
  steps under clang and under no gcc. gcc expands such a builtin to an
  add and a jump on the add's carry, which is a word's, and removes the
  jump only where its if-conversion passes run. Every value stays right
  either way, so no test binary sees which form gcc read.
- The Semgrep rule `inv-16-p256-wide-no-subscript-by-digit` refuses a
  subscript by a digit's index in `p256_wide_mul.c`. A table read by
  index gives the right value in the same time with one branch fewer, so
  nothing else in the tree sees it.
- `make timing`, which no check runs, builds `bin/timing_p256_wide`:
  Welch's t-test over a key generation, a key exchange and a signature on
  the wide files, one fixed scalar against fresh random ones. It is
  evidence about one host, not proof.

Not in the tree: a run under memcheck with every secret marked
undefined, which reports each branch and each address that depends on
one. Decision 94 records one such run by hand and what it found.

Not in the tree either: a count of these files' branches under a 64-bit
gcc. `lint-wide-multiply` counts them under clang, and gcc lowers some
of the same source otherwise: it made jumps of the overflow builtins,
which is why it compiles another form of the two carry steps. Decision
94 has what was read by hand under gcc 13.3 and 15.2: every conditional
branch of the wide files at `-O0`, `-Og`, `-O1`, `-O2`, `-O3` and `-Os`,
and at `-O2` with both if-conversion passes turned off.

What the wide calls leave on the stack is measured, not proved. Each
routine wipes the objects it names, and `widemul.h` calls
`p256_wide_wipe_below` after each wide call whose operands are secret,
because a compiler keeps values in stack slots no `ct_wipe` can name.
`bin/p256_equiv_test` checks three things on a copy of the stack below
its own frame:

- each wide entry writes within `P256_WIDE_BELOW_LEN` bytes of its
  caller, so the wipe covers every frame the call used;
- after each of the six dispatchers that hand a wide entry a secret, the
  stack holds zero where the wipe's array lay;
- after a signature and after a key exchange under the constant-time
  answer, no 64-bit word of the private scalar, the nonce, its inverse,
  z + r d or the shared X coordinate is there, as the value is or in the
  Montgomery domain, and none of the private scalar, the nonce or
  z + r d less n, which `p256_scalar_reduced_mask` and
  `p256_scalar_add` compute into temporaries they wipe.

`make check` builds that binary at `-O2`, the level `make lib` and
`build.zig` compile the object at. The same checks were run by hand at
`-O0`, `-O1`, `-O3` and `-Os` under eight compilers, and decision 94
names them and what they found.

`make san-check` runs the binary under ASan and UBSan without these
three checks: a sanitizer's redzones make its frames several times the
object's, so its depths and its residue are not the object's.

A register is out of every wipe's reach, here as everywhere else in the
tree. The same search finds words of the nonce's inverse and of the
shared X coordinate below a session that runs the 32-bit files: the
Montgomery product modulo n, `p256_scalar_inverse` and `p256_field.c`
wipe none of the temporaries they name. Decision 94 records that and
leaves them as they are.

### The host object's P-384

A host object verifies ECDSA P-384 on six 64-bit words
(`p384_wide_field.c`, `p384_wide_point.c` and `p384_wide_verify.c`,
decision 97), and a device object on `p384.c`'s twelve 32-bit words
over `p384_field.c`, which stay the reference. The 64-bit files carry
the four proofs of [p384_wide](#p384_wide), which hold their memory
accesses, their sums and what they hand each other. That they compute
the right number, and the right verdict, rests on these:

- `bin/p384_equiv_test`, in `make check`, compiles both arms into one
  binary: `test/p384_portable.c` compiles `p384_field.c` and `p384.c`'s
  32-bit arm, the verifier under a second name. It first holds the
  field: each constant must be one number at both widths, and each
  routine must leave `p384_field.c`'s number, for both moduli, on every
  pair of thirteen operands at the moduli's edges and on 300 pairs with
  a random operand, in each shape of its arguments. That is 23,406
  results. It then requires one verdict from the two verifiers, and the
  verdict each case names, over 186 inputs:
  - signatures of random keys and scalars, each with s negated and with
    one bit changed in the hash, in the key, in r and in s;
  - signatures in which the verifier's two scalars are chosen: zero and
    one, the values either side of a signed digit's window, the values
    just under n, and the ones whose digits carry out of bit 383;
  - the keys G, 2G, -G and -2G and a random one, with scalars for which
    u1·G is u2·Q, or its negative, or either but for five times G, so
    that an addition inside the pass meets its own operand or its
    negative;
  - a hash at 0, 1, n - 1, n, n + 1 and 2^384 - 1; an s of 1, 2 and 3,
    and each with n added;
  - the point whose x is n + 2, where r is 2 and x's second value
    verifies; the point whose x is 0 with r = p - n, where r + n is p;
    and a random point with r = x + 2^384 - n, where r + n is x only
    after it wraps;
  - r and s at 0, n and 2^384 - 1;
  - a key whose x is p, the negative of the key, a key whose y is p, a
    key whose x is 2^384 - 1, a key of zeros, and a key off the curve
    under the signature its own multiple makes, which verifies if
    nothing checks the key;
  - a signature whose DER is cut short, runs long, has another tag or
    pads an INTEGER it need not.

  Every key and signature is computed on the 32-bit arm's field and
  points, so a case's signature is right when the reference is, and the
  cases that state a verdict hold both arms to it. The random values
  come from a seeded generator, and `CH_P384_EQUIV_SEED` varies the
  seed.
- `bin/p384_test_host`, in `make check`, is `bin/p384_test`'s main
  built as a host object builds its sources: the RFC 6979 A.2.6
  vectors, the three openssl signatures, the mutations and the
  strict-DER boundary, on the host arm.
- The host Wycheproof test runs Wycheproof's ECDSA P-384 vectors on the
  host arm, and the other Wycheproof tests run them on the 32-bit arm.
- `test/widemul-builds.sh`, in `make check`, compiles `p384.c` either
  side of `-DCH_CPU_RUNTIME` and requires the host arm to call
  `p384_wide_verify_rs` and nothing of `p384_field.c`, and the device
  arm the reverse. It requires `p384_field.c` to define its routines in
  a device object alone and the three 64-bit files in a host object
  alone, and `make` and `build.zig` each to write the three for a
  TRUST=webpki host object and none of them for a device object.

Twenty-four `inv44-*` mutants in `test/violations/` each fail one of
these or the `p384_wide_verify` proof (INV-44).

### x25519's ladder proof abstracts the multiply to its magnitude

Each field-op proof holds inside a stated word range: `carry` at
`|word| < 2^58`, and add, sub, mul and pack at `< 2^24`. `x25519_step`
and `x25519_tail` prove the ladder stays inside them.

The machine-checked part is one loop step and one `invert` round, each
from any state with every word in (-2^17, 2^17) back into it, on the
shipped `step`, `sqr`, `mul` and `pack`. The 255 steps and 254 rounds
are an induction over that. Its base case (`a = d = 1`, `c = 0`, `b` the
unpacked point) is read from five lines of `ladder()`, not checked.

The abstraction: mul's 256 products per call put 2,560 symbolic
multiplies in one step, and that formula returned no verdict past
14 GB. So `proof/x25519_stubs.h` replaces `ct_widemul_s` with a
contract: operands under 2^18, product in [-2^36, 2^36). Two harnesses
prove `ct_widemul_s` meets it, each with every check on and at the
contract's own operand range:

- `x25519_mul`, on the native `(int64_t)a * b` arm the proof runner
  compiles;
- `x25519_mul_ct`, on the 16x16 decomposition firmware ships
  ([#145](https://github.com/c4milo/chapulin/issues/145)).

A bound is a cheaper question than equality. `ctwidemul`'s proof that
the two forms compute the same product converges only at 8-bit
operands; the decomposition's product bound proves at the full range in
128 s.

No property in the ladder harnesses reads a product's value, only
bounds, so the composition loses nothing the stub header does not
state. The stub also checks each operand after mul's narrowing to
int32; the header says why no word gets to that narrowing outside its
exact range.

### The connected-phase driver

The post-handshake parser is proven on hostile bytes, but the `ch_read`
/ `ch_write` / `ch_close` loop around it (record reading and
cross-record reassembly) does not converge as one CBMC formula. It
rests on end-to-end runs, the mock-transport unit tests, and the
fuzzer.

Closing is part of it. A close_notify closes its sender's direction
alone (RFC 9846 §6.1), so the `ch_read` that reads the peer's returns 0,
wipes the read key and sends nothing, and this side writes until its
own `ch_close`. `bin/unit`, `bin/tcp_nonblocking_loop_test` and e2e's
go-half-close test check that (INV-22, INV-17), and no proof covers it.
The peer's fatal alert is the same kind of claim: the call that reads
it sends nothing and records it for `ch_alert_received` (§6.2), and a
record of the alert type that is not one 2-byte alert gets decode_error.
`bin/unit`, `bin/tcp_blocking_loop_test` and
`bin/tcp_nonblocking_loop_test` test it in every TCP reader (INV-22).
The `handshake_record` harness reaches `hsr_refuse_alert` from both of
the blocking reader's alert branches, so it proves the call memory-safe,
and nothing proves what the session sends after it.

### The record boundary before a key change

RFC 9846 §5.1 requires the message before a key change to end its
record: the ServerHello and the server Finished on a client, the
ClientHello a ServerHello answers and the client Finished on a server,
and a KeyUpdate on either (INV-39). Each TCP driver checks it with
`hsr_check_record_end`, which takes a message to be the last of its
record when no handshake byte is left unread after it. That holds
because each reader takes a new record only while the bytes it holds end
in a partial message. No harness proves that property of the reassembly:
the drivers' harnesses stub the check and prove them safe over both
answers, and `handshake_record` proves the reader safe without tracking
which record a byte came from. `handshake_post` proves the KeyUpdate
half of the rule over its own input. The rest is tested: `bin/unit`,
`bin/tcp_nonblocking_loop_test` and `bin/tcp_blocking_loop_test` hold
each check at a record that ends with the message and at one byte more,
`bin/quic_driver_test` and `bin/srv_quic_test` hold the QUIC drivers'
level checks the same way, and twelve `.violation` mutants, one per
check, require them to fail.

### The server's choice of the negotiated version

`srv_quic.c` has no harness (the table above), so the rules of
`ch_srv_cfg.choose_version` rest on tests: one call per connection,
after the client's transport parameters and before `srv_select`, none for
the second ClientHello, and a session failed with `CH_EIO` and
internal_error for an answer `quic_version_derived` refuses.
`bin/srv_quic_test` and `bin/srv_quic_both_test`
(`test/srv_quic_version_tests.h`) hold each rule, the underived answers
at 0, the values beside version 1 and version 2 and a reserved version,
over this tree's hello and ngtcp2's recorded retry round.
`bin/quic_loop_test` completes a handshake packet by packet between a
version 1 client and a server that chooses version 2
(`test/quic_loop_version.h`). `inv07-srv-quic-choose-after-select`,
`inv07-srv-quic-choose-after-retry` and `inv07-srv-quic-choose-unchecked`
require `bin/srv_quic_test` to fail.

### The QUIC version of tickets and Retry tokens

The srv_resume harness proves the server's ticket version rule in the TCP
build, where a session's version is 0. The arm that reads
`ch_tls.quic_negotiated_version` rests on
`test/quic_loop_ticket_versions.h`, which `bin/quic_loop_test` and
`bin/quic_loop_webpki` run: a ticket records the version its connection
negotiated at both ends, the client refuses it in a connection that starts
in the other version, and a server that chose the other version passes it
over. `srv-resume-quic-version-unbound`,
`srv-resume-ticket-records-original-version`,
`inv14-quic-ticket-version-unchecked` and `inv14-ticket-quic-version-unset`
require `bin/quic_loop_test` to fail. The Retry token's version binding sits
under the tag the quic_token harness leaves unconstrained, so it rests on
`test/quic_token_tests.h`, and `quic-token-version-unbound` requires
`bin/srv_quic_test` to fail.

### Constant-time behavior

Constant time comes from construction: no branch and no memory index
depends on a secret, and no secret key is passed to the AES lookup
table. A `SUITE=aesgcm` build runs its traffic keys on AES instructions
or on an AES peripheral: a host object's caller states the instructions'
timing with `CH_CPU_CONSTANT_TIME_AES`, and an `AES=extern` build states
the peripheral's with `CH_AES_EXTERN_CONSTANT_TIME`; nothing here measures
either (INV-26).

`make timing` checks constant time with a Welch's t-test, which is
evidence, not proof. P-256 and RSA verification are variable-time on
purpose, since all of their inputs are public.

#### Cores with no hardware multiplier

On a core with no hardware multiplier, the compiler turns every `*` into
a runtime-library call that branches on its operands. That would undo
constant time in poly1305, x25519 and ML-KEM. `softmul.c` supplies
constant-time `__mulsi3` and `__muldi3` under those names, so they
replace the library's at link time.

`make lint-runtime-symbols` builds every secret-touching source for
rv32ic under the pinned clang and holds, file by file, the runtime calls
each may make:

- `__mulsi3` in poly1305, x25519, mlkem_poly, rsa_sign, p256_field,
  p256_scalar and tls_write;
- `__udivsi3` in tls_write, for `ch_writable_len`'s division of the
  caller's buffer length by a record's length, both public;
- none anywhere else.

It also checks that `softmul.c` still defines the two names it admits.
It measures clang.

Under the Bootlin riscv32 gcc at `-Os`, `softmul.c` used to recurse. gcc
rewrote `__muldi3`'s mask select `a & (0 - bit)` as `a * bit`, which on
that core is a call to `__muldi3` from inside `__muldi3`. The mask is
now an arithmetic shift of the bit, a form gcc keeps at every
optimization level. The rv32ic spec of `make lint-wide-multiply-gcc`
counts, under that gcc, the calls to `__muldi3` in every
secret-touching file and holds `softmul.c` at zero, so the rewrite
cannot come back unseen. `docs/porting.md` shows the count per file.

#### Variable-time multipliers

A multiplier that exists but is variable-time is the other half. ARM's
Cortex-M3 `umull` returns sooner when both operands are below 65536,
with further undocumented exits on zero and powers of two, and 32-bit
x86 and PowerPC have the same shape; the M3's 32-to-32 `mul` does not.
So `ct.h` builds every widening product out of four 16x16 pieces.

`make lint-wide-multiply` compiles every secret-touching source (the
chain from ct.c to tls.c, drbg.c and softmul.c, twenty-four files) for
Cortex-M3, mips32r2 and rv32imac. It counts, per file, the widening
multiplies, the divisions and the calls into the compiler's 64-bit
division runtime, matching each opcode as a prefix so a condition-code
suffix cannot hide one. Under the pinned clang every file is at zero
except tls_write.c, whose `ch_writable_len` divides the caller's buffer
length by one record's length, both public. A `SUITE=aesgcm` build's
`ch_writable_len` divides by that length a second time when the write
it sizes crosses an AES-GCM key's ceiling; the lint compiles tls_write.c
without the suite define, so it counts the first division alone.

`make lint-wide-multiply-gcc` runs the same count under the gcc each CI
lane ships:

- the Arm GNU gcc for the Cortex-M3;
- Ubuntu's gcc for mips32r2;
- the Bootlin gcc for rv32imac and rv32ic.

At `-Os` every file is at zero there too, except tls_write.c's one
division. At `-O2` the mips gcc
copies that division into both paths of `ch_writable_len`, so
tls_write.c counts two there, one per path.

It was not always so. gcc fused the decomposition's 64-bit
cross-product sum back into `umlal`, and rewrote the sign mask
`x & (0 - bit)` in `ct_widemul_s` and in x25519's `cswap` as a multiply
by the secret bit: eight widening multiplies on the M3 and one on
rv32imac, until the rework in `ct.h` and `x25519.c` removed both forms
([#106](https://github.com/c4milo/chapulin/issues/106)).
`test/violations/inv16-widemul-mid-widened.violation` puts the old sum
back and requires the gcc lint to object.

The lint compiles at `-Os`, and the mips gcc spec runs once more at
`-O2`. There that gcc inlines `ct_widemul` into poly1305's block and
puts two of its 75 `product + x` sums through `madd`, a
multiply-accumulate through the 64-bit HI/LO pair, on the same 16-bit
operands. The lint holds that count at two as a record, not an
allowance: the one form that hands gcc no such sum costs 38% of AEAD
seal on mips32r2. `docs/porting.md` has the measurements and the
violation the `-O2` spec alone catches
([#122](https://github.com/c4milo/chapulin/issues/122)).

#### Branch counts

The same pass counts the conditional branches each compiler emits:

- `b<cond>`, `cbz`, `cbnz` and IT blocks on arm;
- `beq`, `bne` and the compare-with-zero forms on mips;
- the six base branches and the compressed pair on rv32.

It counts them in the sixteen arithmetic files under the record layer,
the twelve on the TLS path, and the four AES and GCM sources a QUIC or
`SUITE=aesgcm` build compiles, and holds each file at a ceiling measured
per compiler. Those ceilings are public loop control, not zero: the
block loops, x25519's ladder, Keccak's counters and softmul's fixed
iterations. So the lint holds that no count grows, not that no branch
exists.

What the ceilings record is that these compile to a predicated
instruction, `sltu` or a shift under every compiler measured. That is
each compiler's choice, with no check on it until the count
([#141](https://github.com/c4milo/chapulin/issues/141)):

- the compare-carries in `ct_widemul_opaque`;
- the sign masks in `ct_widemul_s` and `poly1305_final`;
- the two select masks in `gcm.c`'s `multiply_by_subkey`.

Three violations show the count sees a branch:

- `test/violations/inv16-poly1305-final-sign-branch.violation` writes
  the final select as an `if` on the last word's sign, and every spec's
  count rises by one;
- `inv16-widemul-s-sign-branch` does the same to `ct_widemul_s`. clang
  lowers it back to the mask while every gcc emits two branches in
  x25519, so only the gcc lint objects;
- `inv16-ghash-subkey-select-branch` writes `multiply_by_subkey`'s first
  mask as an `if` on the accumulator bit, and every clang spec's count
  for `gcm.c` rises.

#### The 32-to-32 multiply

What is left is the 32-to-32 multiply, which ARM documents as
single-cycle on the M3. mips32r2 does not document its own, so on that
core the decomposition narrows the exposure rather than closing it.
`ct.h` says so, and that is the stated assumption, by decision
(https://github.com/c4milo/chapulin/issues/53): a vendor statement on
the multiply's timing would close it, and nothing in this tree can.

Every target gets the decomposition unless its build passes
`CH_NATIVE_WIDEMUL`, and no list exempts architectures by name. RISC-V
publishes Zkt to attest data-independent latency, Arm publishes
FEAT_DIT and Intel DOITM, and all three exist because the base
architectures do not promise it, so no architecture macro carries the
claim. The Makefile passes that flag for host test binaries, where
nothing secret is at risk and solver time is, and filters it out of the
packaged object.

That cost is measured, not assumed:
the pinned handshake's crypto costs 29% more on mips32r2, and the
decomposition is 2.3 kB of flash, itemised in
[`performance.md`](performance.md), "Speed and flash".

#### What carries the proofs to the target

The decomposition is also what carries every other proof to the target.
Those formulas verify the single-multiply form, since the proof runner
asserts `CH_NATIVE_WIDEMUL` on the development machine, so they describe
what ships only if the two forms compute the same function.
[ctwidemul](#ctwidemul) proves that: undefined behavior and shift range
at full 32-bit width, and the products themselves against the C
operator at 8-bit operands, the widest bound whose formula converges.
The x25519 ladder proofs need less than equality: their contract on
`ct_widemul_s` is a product bound, and `x25519_mul_ct` proves it on the
decomposition at the ladder's full operand range.

`make timing` measures the decomposed path rather than the host's native
one. `make ct-widemul-check`, in `check-slow`, rebuilds the unit, ML-KEM
and Wycheproof binaries with `CH_CT_WIDEMUL`. So the RFC 7748, RFC 8439
and RFC 8448 vectors, the FIPS 203 known answers and the Wycheproof
cases are also checked over the decomposition as poly1305, x25519 and
mlkem_poly inline it. That is evidence at those inputs, while the
equality proof stays at 8-bit operands.

#### The wide X25519 field

The wide X25519 field is one of three secret-bearing sources none of
those specs can build, since it needs `unsigned __int128`; the others are
a host object's two vector paths (below). It multiplies on
the 64x64->128 instruction. `ct.h` defines that multiply for a host
object alone, and `widemul.h` runs the field only for a session whose
caller set `CH_CPU_CONSTANT_TIME_MULTIPLY`, the statement that the
multiply runs in constant time at both widths (decision 89):

- Arm lists MUL and UMULH as data-independent while PSTATE.DIT is set;
- Intel lists MUL and MULX in its DOIT instructions, which on recent
  parts hold only while the operating system enables DOITM.

`make lint-wide-multiply` compiles the file for arm64 and x86-64 under
the pinned clang. It holds the file's divisions and 128-bit runtime
calls at zero and its branch count at the loop control it has, and
`inv16-x25519-wide-cswap-branch` shows the count sees a `cswap` written
as an `if`. No gcc measures it.

### The vector ChaCha20

`chacha20_vector.c` computes ChaCha20 on NEON or SSE2 intrinsics, in
passes of eight blocks on NEON, two groups of four side by side, and of
four blocks on SSE2 (decisions 82 and 86). Every host object holds it,
and every host session runs it: in a host object `chacha20_xor` calls it
in place of `chacha20.c`'s loop, which a device object runs (decision
89). CBMC cannot unwind an intrinsic, so no harness compiles the file,
and the [chacha20](#chacha20) proof covers `chacha20.c`'s loop alone. As
the AES instructions rest on `bin/aes_equiv_test` and the published
vectors, the vector path rests on these, each in `make check` on a host
target:

- `bin/chacha20_equiv_test` compares it with `chacha20.c`'s loop over
  49,211 cases:
  - every length from 0 to 2,048 bytes, which crosses a NEON pass's edge
    four times and an SSE2 pass's eight, in each aliasing shape
    `chacha20.h` allows: a separate output, the output on the input, and
    the output 5 bytes below the input, as `rec_open` writes it;
  - the counter at 0 and at its last 17 values, at every length to 1,280
    bytes, so the 32-bit counter wraps inside each group of a pass, at
    the edge between a pass's two groups, at a pass's edge, inside the
    pass after it and in the last partial pass;
  - 20,000 random cases to 2,048 bytes, at random alignments and shifts;
  - a 16,385-byte and a 65,536-byte input.

  Each case checks every output byte and every byte around the output,
  then runs again on heap buffers of exactly the case's size, which
  `make san-check` runs under AddressSanitizer.
- `bin/unit_host`, the unit suite compiled as a host object, runs on the
  path under each `ch_cfg.cpu` value it takes: RFC 8439's §2.3.2,
  §2.4.2, A.2 and A.5 vectors, of which A.2's 375-byte vector and A.5's
  265 bytes run a whole group of four blocks and a partial one, and
  every record the suite seals and opens.
- The Wycheproof ChaCha20-Poly1305 suite runs on it in the host binary,
  under every `ch_cfg.cpu` value that binary takes, with messages up to
  513 bytes.
- `make lint-wide-multiply` compiles the file for arm64 and x86-64 under
  the pinned clang and holds its conditional branches at 40 and 23,
  every one loop control over a public count or a test of the byte
  count: most of them test whether the last pass's limit covers a row of
  16 bytes. It multiplies nothing.
- `test/chacha-builds.sh` compiles `chacha20.c` both ways. A host
  object's `chacha20_xor` must call `chacha20_vector_xor`, and a device
  object's must call no vector path.
- `make lint-trust-separation` requires `chacha20_vector.c` and
  `chacha20_avx2.c` in every host object's source list, bans both from
  every device object's, and requires the Makefile to refuse the `CHACHA`
  variable for both.

Ten violations break the path or the rule that puts it in a host object
alone, and each is caught. The equivalence test catches
`chacha-vector-tail-whole-rows-only`,
`chacha-vector-counter-carries-into-nonce`,
`chacha-vector-skips-a-lane` and
`chacha-vector-blocks-in-descending-order`; `test/chacha-builds.sh`
catches `chacha-vector-header-admits-any-target`,
`chacha-vector-header-admits-big-endian` and
`chacha-vector-falls-back-to-portable`; and `make lint-trust-separation`
catches `inv16-host-object-drops-vector-chacha`,
`inv16-device-object-holds-vector-chacha` and
`inv16-chacha-variable-accepted`.

None of this proves the two paths agree on an input no case runs.
The path's timing rests on construction, as the portable loop's does:
it runs adds, exclusive-ors, shifts and lane moves, with no table and no
multiply. No gcc measures its branches. No proof covers the ChaCha20 a
host session runs: the proved loop runs in a device object alone, which
is the cost decision 89 states.

### The vector Poly1305

`poly1305_vector.c` runs Poly1305's block loop four blocks at a time, in
two lanes on NEON or SSE2 intrinsics (decision 83). It exists in a host
object's native copy alone, `poly1305_vector_native.c`, which
`poly1305_native.c` calls, so a session runs it only where its caller
set `CH_CPU_CONSTANT_TIME_MULTIPLY` (decision 89). A session without the
bit, and every device object, runs `poly1305.c`'s loop. CBMC cannot
unwind an intrinsic, so no harness compiles the file, and the
[poly1305](#poly1305) proof covers `poly1305.c`'s loop alone. The vector
path rests on these, each in `make check` on a host target:

- `bin/poly1305_equiv_test` compares it with `poly1305.c`'s loop over
  43,282 cases. Each case compares the accumulator modulo 2^130 - 5
  after the updates, the buffered partial block and the tag:
  - every length from 0 to 416 bytes, which crosses the path's 128-byte
    threshold and four more groups, in one update and cut at every odd
    offset below 128 bytes;
  - keys and messages of all 0x00 and all 0xff bytes, the smallest and
    the largest words;
  - `poly1305_vector_blocks` called alone on one to twelve groups, after
    zero to four blocks, with the word bounds its header states checked
    on return, and once on a group a search found, whose lane totals
    carry h1 past 2^26 in the first pass;
  - 20,000 random cases to 2,048 bytes, cut into three updates at random
    offsets and alignments;
  - a 16,385-byte and a 65,536-byte input.

  The vector build reads each message from a heap buffer that ends where
  the message ends, which `make san-check` runs under AddressSanitizer.
- The same binary copies the stack below one call over four groups, where
  the call's dead frame lay, and requires none of r^2, r^3 and r^4 there:
  not as five words side by side, as the call's struct holds each power,
  nor one word every 8 or 16 bytes, as a NEON or SSE2 multiplier holds a
  lane's (test/poly1305_equiv_residue.h). Five words match when they hold
  the power's value modulo 2^130 - 5, whatever their carry form. The
  search also looks for r^5 to r^8, and for one word every 32 bytes, the
  AVX2 kernel's powers and layout, which this path never writes.
- `bin/unit_host` runs the unit suite on the path under a `ch_cfg.cpu`
  with the multiply bit: RFC 8439's A.3 vectors 2 and 3, 375 bytes each,
  and A.5's 265 bytes run on it, as does every record the suite seals and
  opens with 128 bytes of whole blocks or more. Under the probe's bit
  alone the same suite runs `poly1305.c`'s loop.
- The Wycheproof ChaCha20-Poly1305 suite runs on it in the host binary's
  runs with the multiply bit.
- `bin/widemul_runtime_test` counts the calls into each copy: with the
  bit an AEAD call and a record run the native copy, and without it
  neither does. `bin/quic_loop_host` counts the same for the packets of
  whole QUIC handshakes
  ([The host object's two multiplies](#the-host-objects-two-multiplies)).
- `make lint-wide-multiply` compiles the native copy for arm64 and
  x86-64 under the pinned clang and holds its conditional branches at 4
  on each: the contract check at the entry and the group loop, all on
  the byte count. It divides nothing and calls no runtime routine. Its
  multiplies are the ones the caller's bit states, so the count leaves
  them out, as it leaves out `x25519_wide.c`'s. Under its own name the
  file compiles to nothing, and the count holds that at 0.
- `test/widemul-builds.sh` compiles `poly1305_native.c` as a host object
  does and requires its call to the path, requires none from `poly1305.c`
  under its own names, and none from the native copy under
  `CH_CT_WIDEMUL`. `test/chacha-builds.sh` compiles a device object's
  `poly1305.c`, with `-DCH_NATIVE_WIDEMUL` and without it, and requires
  no call to the path.

Nine violations break the path, and each is caught. The equivalence
test catches `poly1305-vector-last-group-even-powers`,
`poly1305-vector-carry-drops-fold`, `poly1305-vector-one-carry-round`,
`poly1305-vector-lane-1-starts-from-h`,
`poly1305-vector-hands-partial-group`,
`poly1305-vector-returns-wide-h1` and `poly1305-vector-keeps-powers`,
which drops the wipe; `test/widemul-builds.sh` catches
`poly1305-vector-falls-back-to-portable`, and `test/chacha-builds.sh`
catches `poly1305-vector-in-device-object`.

None of this proves the two paths agree on an input no case runs.
The word bounds that keep every sum below 2^64 are argued in the file's
comments, not proved. The residue check reads the stack one compiler
left on one call; it cannot see registers, or a spill slot that holds a
power in a layout it does not search. It runs under CI's gcc and clang
and under Apple clang on arm64. No CI job builds x86-64 with Apple
clang, the one compiler that kept powers in spill slots before the
x86-64 multiply read them through volatile pointers
([`docs/decisions.md`](decisions.md) 83), so that build's check runs by
hand: `make CC='cc -arch x86_64' bin/poly1305_equiv_test` on a copy of
the tree, under Rosetta. The path's timing rests on the
caller's `CH_CPU_CONSTANT_TIME_MULTIPLY` bit for its multiplies, as the
native copy of the portable loop does, and on construction for the rest:
adds, masks, fixed shifts and lane moves, with no table. No gcc measures
its branches.

### The AVX2 Poly1305

`poly1305_avx2.c` runs Poly1305's block loop eight blocks at a time in
four AVX2 lanes (decision 110). It exists in an x86-64 host object's
native copy alone, `poly1305_avx2_native.c`, which `poly1305_native.c`'s
`poly1305_update_avx2_native` calls for an update with 512 bytes or more
of whole blocks. `widemul.h` calls that update for a session whose caller
set both `CH_CPU_CONSTANT_TIME_MULTIPLY` and `CH_CPU_AVX2`
(`widemul_poly1305_avx2`), and only for a record's or a packet's
ciphertext. CBMC cannot unwind an intrinsic, so no harness compiles the
file. The kernel rests on these:

- `bin/poly1305_equiv_test`, in `make check` on an x86-64 host with AVX2,
  runs the 128-bit path's kinds of case on the kernel, from the same
  seed, 140,562 in all: every length from 0 to 1,056 bytes, which crosses
  the 512-byte threshold and four more groups of 128 bytes, cut at every
  odd offset below 256; the extreme keys and messages; the kernel's entry
  called alone on one to twelve groups, with the bounds its header states
  checked on return, and on a group a search found whose lane totals
  carry h1 past 2^26 in the first pass; 20,000 random cases; and the two
  large inputs. It searches the stack below a call over four groups for
  r^2 to r^8 in the layouts the 128-bit path's search reads and in one
  word every 32 bytes, as an AVX2 multiplier holds a lane's power. On a
  CPU without AVX2 it skips the kernel and says so.
- `test/aes-runtime-qemu.sh poly1305-avx2` builds the same binary for
  x86-64 and runs it under qemu-x86_64 with AVX2, in CI's mips job on
  every push, so an arm64 machine runs it too.
- The Wycheproof host binary's runs under 0xf and 0x1f put the four
  messages of the ChaCha20-Poly1305 suite that hold 512 bytes of whole
  blocks through the kernel. RFC 8439's vectors are shorter than that, so
  `bin/unit_host` under 0xd runs none of them on it.
- `bin/x86_kernels_test` counts the kernel's calls under 33 `ch_cfg.cpu`
  values. Every seal and open of a ChaCha20-Poly1305 record or packet,
  with 528 bytes of whole blocks, and an open that refuses a wrong tag
  must call it once where the value holds both bits and never where it
  lacks one, and `aead_seal` and `aead_open` must never call it.
- `test/chacha-builds.sh` compiles for x86-64 and arm64 under the pinned
  clang and requires the kernel's 256-bit instructions in
  `poly1305_avx2_native.c` alone, its call from `poly1305_native.c` on
  x86-64 alone, and no AVX2 entry in `poly1305.c` under its own names or
  in the native copy under `CH_CT_WIDEMUL`.
- `make lint-wide-multiply` holds the kernel's conditional branches at 4
  on x86-64, all on the byte count, and `poly1305_native.c`'s at 20 there,
  one more than on arm64: the AVX2 update's test of n against 512. `make
  lint-trust-separation` holds the copy to the host object.

CI's `x86-64-kernels` job runs `bin/poly1305_equiv_test` with
`CH_REQUIRE_X86_KERNELS=1`, so a runner without AVX2 fails it rather than
skips it.

Nine violations break the kernel and its choice, and each is caught.
`test/aes-runtime-qemu.sh poly1305-avx2` catches
`poly1305-avx2-last-group-lanes-exchanged`,
`poly1305-avx2-carry-drops-fold`, `poly1305-avx2-odd-blocks-exchanged`,
`poly1305-avx2-hands-partial-group` and `poly1305-avx2-keeps-powers`,
which drops the wipe. `test/aes-runtime-qemu.sh x86-kernels` catches
`poly1305-avx2-without-multiply-bit`, `poly1305-avx2-ignores-cpu-bit` and
`poly1305-avx2-mac-without-cpu`, and `test/lint-trust-separation.sh`
catches `inv16-poly1305-avx2-copy-dropped`.

None of this proves the kernel and the loop agree on an input no case
runs, and the bounds that keep a lane's sums below 2^58 are argued in the
file's comments, not proved. The stack search reads what one compiler
left on one call: gcc 13 and clang 18 under qemu, and gcc 13 on CI's
runner. The kernel's timing rests on the caller's multiply bit for
VPMULUDQ and on construction for the rest, as the 128-bit path's does.

### The AVX-512 IFMA Poly1305

`poly1305_ifma.c` runs Poly1305's block loop sixteen blocks at a time in
eight 64-bit lanes, on AVX-512 IFMA's VPMADD52LUQ and VPMADD52HUQ. A
lane holds its number in three digits of 44, 44 and 42 bits. The kernel
exists in an x86-64 host object's native copy alone,
`poly1305_ifma_native.c`, which `poly1305_native.c`'s
`poly1305_update_ifma_native` calls for an update with 512 bytes or more
of whole blocks. `widemul.h` calls that update for a session whose caller
set both `CH_CPU_CONSTANT_TIME_MULTIPLY` and `CH_CPU_AVX512_IFMA`
(`widemul_poly1305_ifma`), ahead of the AVX2 kernel, and only for a
record's or a packet's ciphertext.

CBMC and Lean prove parts of the kernel over a model of its
instructions, and nothing proves the instructions equal to that model.
`test/poly1305_ifma_model_lanes.h` writes each lane operation in
portable C from Intel's pseudocode, and `test/poly1305_ifma_model.c`
compiles the kernel's own text over it under second names. The
[poly1305_ifma](#poly1305_ifma) harnesses compile the same text with
each lane multiplication a contract that `poly1305_ifma_lanes`
discharges on the model. They prove that no sum wraps and no operand of a
multiplication is 2^52 or more, from the start through a group, the powers
of r and the lane totals, and that the whole call reads and writes inside
its arrays. They prove no value.

[`spec/lean/Spec/Poly1305Ifma.lean`](../spec/lean/Spec/Poly1305Ifma.lean)
models one lane of the C's group step, its product and its carry, and
`compute_powers` lane by lane with the C's masks, on whole numbers. Its
theorems state that:

- a group step computes (h + first) x + second y modulo 2^130 - 5, for
  digits, blocks and multipliers within the bounds (`groupStep_mod`), and
  `multiplier_product` computes a b (`product_mod`);
- from those bounds every operand is below 2^52, every sum below 2^56,
  and the result within the bounds again (`groupStep_bounds` and
  `product_bounds`), on the real products where the CBMC harnesses take
  the contracts;
- lane l of the last group's two multipliers holds r^(16 - b) and
  r^(8 - b), and every lane of the other groups' multipliers r^16 and
  r^8, b being the block `load_blocks` gives lane l (`powers_mod`);
- `load_blocks`, `digits_of_words` and `words_of_totals` keep the number
  they convert (`blockDigits_value`, `digitsOfWords_value` and
  `totals_value`).

`bin/diff_poly1305_ifma`, in `make diff`, holds the C over the lane model
to the spec in 4,001 comparisons: the selftest, 1,000 runs of
`compute_powers` from r's words at 0, at 2^26 - 1, at random below 2^26
and from random keys, and 3,000 group steps from digits at and below the
bounds and from the multipliers `compute_powers` writes for random keys,
over random blocks and blocks of all ones bits. Each row compares every
digit of every lane.

Tests hold the rest:

- `bin/poly1305_equiv_test`, in `make check` on every host, runs the
  128-bit path's kinds of case on the kernel's text over the model, from
  the same seed, 358,545 in all, and searches the stack below a call over
  four groups for r^2 to r^16 in every layout the residue search reads,
  three 64-bit digits among them. On an x86-64 CPU with AVX-512 IFMA it
  runs them again on the instructions. On a CPU without it skips that run
  and says so, and under `CH_REQUIRE_AVX512_IFMA=1` fails instead.
- The Wycheproof host binary's run under 0x11f puts the four messages of
  the ChaCha20-Poly1305 suite that hold 512 bytes of whole blocks through
  the kernel, where the CPU has AVX-512 IFMA.
- `bin/x86_kernels_test` counts the kernel's calls under its 33
  `ch_cfg.cpu` values: every seal and open of a record or packet with 528
  bytes of whole blocks must call it once where the value holds both bits
  and never where it lacks one, and the AVX2 kernel must not run where
  the IFMA kernel does.
- `bin/avx512_wipe_test` sets every bit of zmm0 to zmm31 and k1 to k7,
  calls `avx512_wipe_registers`, and requires each to read back as zero.
- `test/chacha-builds.sh` compiles for x86-64 and arm64 under the pinned
  clang and requires the kernel's 512-bit instructions in
  `poly1305_ifma_native.c` alone, its call to `avx512_wipe_registers`,
  its call from `poly1305_native.c` on x86-64 alone, and no IFMA entry in
  `poly1305.c` under its own names or in the native copy under
  `CH_CT_WIDEMUL`.
- `make lint-wide-multiply` holds the kernel's conditional branches at 4
  on x86-64, and `poly1305_native.c`'s at 21 there.
  `test/widemul-builds.sh` refuses a library build that names
  `CH_POLY1305_IFMA_MODEL`.

The nightly's `rsa-ifma-sde` job runs `bin/poly1305_equiv_test`,
`bin/chacha20_equiv_test` and `bin/avx512_wipe_test` with
`CH_REQUIRE_AVX512_IFMA=1` under Intel SDE's model of an Ice Lake server,
and requires each binary's line for a pass.

Fourteen violations break the kernel, its model, its choice and its wipe,
and each is caught. `bin/poly1305_equiv_test`, through the model on every
host, catches `poly1305-ifma-carry-drops-fold`,
`poly1305-ifma-block-without-high-bit`,
`poly1305-ifma-last-group-powers-exchanged`,
`poly1305-ifma-product-without-times-20` and
`poly1305-ifma-digits-keep-high-bits`. `test/chacha-builds.sh` catches
`poly1305-ifma-ignores-cpu-bit`, `poly1305-ifma-runs-without-cpu-bit`,
`poly1305-ifma-without-target`, `inv17-poly1305-ifma-keeps-registers`
and `inv17-avx512-wipe-skips-zmm31`. `test/aes-runtime-qemu.sh
x86-kernels` catches `poly1305-ifma-without-multiply-bit`.
`test/lint-trust-separation.sh` catches `inv16-poly1305-ifma-copy-dropped`
and `inv16-device-object-holds-avx512-wipe`, and `test/widemul-builds.sh`
catches `inv16-poly1305-ifma-model-in-library`.

None of this proves the kernel and the loop agree on an input no case
runs, and no proof joins the eight lanes' Horner steps into the whole
message's polynomial. The stack search reads what one compiler left on
one call. The kernel's timing rests on the caller's multiply bit for
VPMADD52LUQ and VPMADD52HUQ and on construction for the rest, as the
other kernels' does.

### A host session without the AES bit

A host object's session whose caller did not set
`CH_CPU_CONSTANT_TIME_AES` must run neither AES nor the carry-less
multiply (decisions 81 and 89). The [aes_runtime](#aes_runtime) proof
holds the cipher `aes.c` puts each key on, over contract stubs of both
ciphers. No proof reads the instructions the compiler emits, or the calls
the rest of a session makes. Three checks stand in:

- `bin/aes_runtime_test`, in `make check`, counts every call into the
  table, the instructions and the carry-less multiply over RFC 9001 and
  RFC 9369 Appendix A with the bit and without it. Without the bit no
  call goes to the instructions.
- `test/aes-runtime-qemu.sh`, in CI's mips job on every push, builds that
  binary and the two suite loop binaries for x86-64 with the runner's gcc,
  as host objects. It runs them under `qemu-x86_64 -cpu
  max,-aes,-pclmulqdq,-avx2`, where each of those instructions raises
  SIGILL. The
  vectors must pass without the bit, and so must the whole QUIC and TCP
  handshakes, resumptions and pin rows with both ends stating the probe's
  bit alone. The rows with the bit, and `bin/quic_test_hw`'s vectors,
  must die of SIGILL, so a qemu whose CPU model kept the instructions
  fails the step rather than passing it. `test/docker-aes-runtime-qemu.sh`
  runs the same script in a container on a development machine.
- `test/aes-runtime-disasm.sh`, in CI's arm64 and macOS jobs, builds
  three host objects, disassembles every source's object, and requires
  the AES and carry-less multiply instructions in `aes_hw.c`'s,
  `ghash_hw.c`'s, `gcm_hw.c`'s and `gcm_vaes.c`'s functions alone. It
  requires an AES instruction in the first, a carry-less multiply in the
  second and both in the third, so a disassembler that spelled them
  another way would fail it rather than pass it.

`inv26-runtime-initial-seal-ignores-answer` makes `quic.c` seal every
Initial packet as though the caller had set the bit. Both ciphers compute
the same packet, and `bin/aes_runtime_test` links no `quic.c`, so no test
on a CPU with the instructions sees it; the qemu run catches it.

None of this runs a session without the bit on an arm64 CPU without the
AES extension: QEMU's arm64 models all implement it, and none turns it
off. On arm64 the claim rests on the counts and the disassembly. The qemu
run executes the vectors and the rows the loop binaries hold, and no
other path.

### The host object's AES key expansions

`aes_hw.c` expands an AES-128 or AES-256 key in one of two ways, by
architecture (decision 123). On arm64 a loop computes FIPS 197 §5.2 a word
at a time through two 4-byte arrays, which it wipes when it returns. On
x86-64 the expansion computes a round key at a time in vector registers,
on AESENCLAST and SSE2's shifts, shuffle, or and exclusive-or, and stores
each round key to the schedule once. CBMC cannot unwind an intrinsic, so
no harness compiles either, and `aes_hw.c` stays in
[the table of sources with no harness](#sources-with-no-launched-harness).
These hold both:

- `bin/aes_equiv_test`, in `make check`, holds every schedule to the one
  `quic_aes_soft.c`'s table writes, byte for byte, over fixed keys, every
  single-bit key and 200,000 random keys of each size, before it compares
  a block under it.
- The same binary searches the stack each expansion leaves
  (`test/aes_equiv_residue.h`). For 16 random keys of each size it clears
  the 4,096 bytes below its own frame, makes one expansion one frame
  deeper, copies the bytes, and looks at every byte offset for a 32-bit
  word the expansion computed: a word of the schedule, the SubWord,
  rotation or temporary of a step, or a sum `prefix_xor` forms. A byte
  the call did not write is zero, so a match is a word the call left. The
  extra frame matters: called straight from the frame that copies,
  gcc 13 made the call a jump, and a value an x86-64 leaf function keeps
  below its stack pointer lay above the copy.
- A machine's own compiler reads one of the two arms, so
  `test/aes-runtime-qemu.sh aes-equiv` builds the binary for x86-64 and
  for arm64 with the container's gcc 13 and runs each under qemu's max
  model. CI's mips job runs that part in the script's full run on every
  push.
- `bin/quic_test_hw` runs FIPS 197's, SP 800-38D's and RFC 9001's
  vectors on the instructions, the host Wycheproof binary runs the
  AES-GCM suites under each `ch_cfg.cpu` value `make check` passes it,
  and `bin/diff_quic_hw` runs the AES and GCM rows of the Lean
  differential. CI's x86-64 `check` job runs the first two on the register
  expansion, and its arm64 and macOS jobs run them on the word loop
  through `suite-check`. `make diff` runs the third, in CI's x86-64
  `slow` job.

Eight violations break the two expansions, and the qemu part catches each,
so each verdict is the same on every machine:
`aes-hw-diverges-from-soft` and `aes256-schedule-one-round-key-short` break
arm64's round constant and AES-256's length,
`aes-hw-registers-round-constant-one-round-late`,
`aes-hw-registers-shuffle-takes-word-2`,
`aes-hw-registers-256-last-round-key-unstored` and
`aes-hw-registers-256-second-step-takes-rot-word` break x86-64's
arithmetic, and `aes-hw-registers-round-key-on-stack` and
`aes-hw-word-loop-keeps-its-word` leave a round key's word on the stack,
one on each architecture.

What none of this shows:

- **Every compiler's stack.** The search reads the stack the binary's own
  build leaves. It found nothing under gcc 13.3 and clang 23 for x86-64 at
  `-O2`, `-O3` and `-Os`, under Apple clang 21 for arm64 at `-O2`, under
  the qemu part's gcc 13 for both, and on six x86-64 runners under gcc
  13.3 and clang 23 at `-O2` (run 38001049465). Under gcc 13 at `-O3` an
  earlier form left the key in a stack slot, and at `-Os` another left a
  round key (decision 123). A compiler or a level not listed may differ.
- **The registers.** When an expansion returns, vector registers still
  hold its last round keys, as they hold the cipher's state after
  `aes_cipher_block` returns. C has no statement that clears a register.
- **Timing.** The register expansion's timing rests on
  `CH_CPU_CONSTANT_TIME_AES`, as the cipher's does.

### The vector NTT

`mlkem_vector.c` computes ML-KEM's forward and inverse NTT and its base
multiplication on eight 16-bit lanes, NEON on arm64 and SSE2 on x86-64,
through the lane operations in `mlkem_lanes.h` (decision 101). Every
host object holds it, and every host session runs it: in a host object
`mlkem.c` calls it in place of `mlkem_poly.c`'s loops, which a device
object runs and the `mlkem_ntt`, `mlkem_invntt_low`, `mlkem_invntt_high`
and `mlkem_basemul` proofs cover ([mlkem](#mlkem)). CBMC cannot unwind an
intrinsic, so no harness compiles the file, and these hold it (INV-46):

- `bin/mlkem_vector_equiv_test`, in `make check` on a host target and in
  `make san-check`, runs each transform both ways on 7,029 polynomials and
  compares every coefficient: every coefficient at 0, 1, -1, the largest
  int16 and the smallest; one coefficient at each of the last four at
  each of the 256 positions; and 2,000 random polynomials drawn from all
  of int16, 2,000 from [0, q) and 2,000 from [-2, 2]. It runs the base
  multiplication both ways on 5,049 pairs: every pair of the five values,
  which multiplies -32768 by -32768, one coefficient of a at an edge
  value at each position against b at another, and 2,000 random pairs
  from all of int16 and 2,000 from an NTT's output range and a matrix
  entry's. Each lane formula is exact for every int16 input, so the test
  requires the same coefficients, not coefficients equal modulo q.
- `test/aes-runtime-qemu.sh mlkem-vector`, in CI's mips job on every
  push, builds the same binary for x86-64 and for arm64 and runs both
  under qemu, so the arm a machine's own compiler does not read runs
  too.
- `bin/mlkem_test_host` runs the ML-KEM-768 known answers and the CCTV
  decapsulation anchors on the path, and the host Wycheproof test runs
  Wycheproof's ML-KEM-768 suites on it.
- `make lint-wide-multiply` compiles the file for arm64 and x86-64 under
  the pinned clang and holds its conditional branches at 9 on each:
  every one closes a loop whose count is a constant.
- `test/mlkem-builds.sh` compiles `mlkem.c` both ways. A host object's
  `mlkem.c`, and its copy over the SHA-3 instructions on arm64, must call
  the three vector entries and none of the loops, and a device object's
  must call the loops and no vector entry.
- `make lint-trust-separation` requires `mlkem_vector.c` in every host
  object that carries ML-KEM and bans it from every device object.

What none of this shows: the timing of the vector multiplies. Decision
101 states what Arm's and Intel's lists say about them, and no test here
measures it.

### The four-way Keccak

`keccak_avx2.c` runs Keccak-f[1600] on four states at once in AVX2, and
`mlkem_avx2.c`, `mlkem.c` compiled once more, samples each row of
ML-KEM's matrix on it for an x86-64 session whose `ch_cfg.cpu` holds
`CH_CPU_AVX2` (decision 107). Its input is public: the matrix's seed and
indices. CBMC cannot unwind an intrinsic, and both files have a body on
x86-64 alone, so no harness compiles either. `mlk_sample_groups`, the
rejection step the copy runs on each block, is the loop the `mlkem_poly`
proof covers inside `mlk_sample_ntt`. These hold the rest (INV-48):

- `bin/mlkem_avx2_equiv_test`, in `make check` on an x86-64 host with
  AVX2 and in `make san-check`, compares ten blocks of each of the four
  streams with `sha3.c`'s SHAKE128 for 200 random seeds, each state with
  an index pair of its own. It compares the copy's key generation,
  encapsulation and decapsulation with `mlkem.c`'s for 200 random seeds
  under each of the two answers a compression runs under: the keys, the
  ciphertext, the shared secret, the secret a decapsulation recovers and
  the one it writes for a changed ciphertext. It runs the three session
  calls with `CH_CPU_AVX2` and without. It counts the sampled entries
  whose stream needs a fourth block, and fails if there are none. On an
  arm64 host it has nothing to run and says so.
- `test/aes-runtime-qemu.sh mlkem-avx2`, in CI's mips job on every push,
  builds the same binary for x86-64 and runs it under qemu with AVX2, so
  an arm64 machine runs it too. The lane's loops with one end stating
  `CH_CPU_AVX2` and the other not complete their handshakes, ML-KEM's
  share included.
- `bin/x86_kernels_test` counts the copy's calls under thirty-three
  `ch_cfg.cpu` values: a session call runs it exactly where the value
  holds `CH_CPU_AVX2`.
- `test/mlkem-builds.sh` requires the copy's rows to call the four-way
  Keccak and not `mlk_sample_ntt`, both files to hold nothing on arm64,
  and no other source at the root to include `keccak_avx2.h` or call its
  entries.
- `make lint-wide-multiply` holds `keccak_avx2.c` at 7 conditional
  branches and `mlkem_avx2.c` at 28 on x86-64, and `make
  lint-trust-separation` holds both to the host object.

What none of this shows: the copy at the cap, where an entry's stream
gives `MLK_SAMPLE_GROUPS` groups without 256 coefficients. No seed reaches
it in practice, so no test runs it, and the copy stops at the cap's group
by the arithmetic its entry in `tools/proof-cover.py` reads.

### The x86-64 kernels

`chacha20_avx2.c` computes ChaCha20 eight blocks a pass in 256-bit AVX2
vectors, and `gcm_vaes.c` runs `gcm_hw.c`'s three loops two blocks to a
256-bit register on VAES and VPCLMULQDQ (decision 90). `rsa_ifma.c` runs
RSA's public operation in digits of 52 bits on AVX-512 IFMA (decision
119), `chacha20_avx512.c` computes ChaCha20 sixteen blocks a pass in
512-bit vectors (decision 121), and `rsa_ifma_sign.c` runs RSA signing's
two exponentiations on `rsa_ifma.c`'s product (decision 120). Every
x86-64 host object carries the first four and the AVX-512 IFMA Poly1305,
which has a section of its own
([The AVX-512 IFMA Poly1305](#the-avx-512-ifma-poly1305)), and every one
that signs with RSA the fifth, each function turning its instructions on
through its own target attribute. Five predicates read the caller's bits,
and one branch per call picks a kernel or the path under it (decision
89):

- `chacha20.c`'s `use_avx2` answers for `CH_CPU_AVX2`. `aead_seal_cpu`
  and `aead_open_cpu` hand it the session's `ch_cfg.cpu`, which a record
  direction holds and a QUIC packet call takes, through
  `chacha20_xor_cpu`. `chacha20_xor`, which takes no value, runs the
  128-bit path.
- `chacha20.c`'s `use_avx512` answers for `CH_CPU_AVX512_IFMA`, and
  `chacha20_xor_cpu` asks it before `use_avx2`, with the same value.
- `gcm_vaes.h`'s `gcm_use_vaes` answers for `CH_CPU_VAES` and
  `CH_CPU_CONSTANT_TIME_AES` together. It reads the byte each AES key
  schedule records from its session's `ch_cfg.cpu`, and `gcm.c` asks it
  only for a schedule the AES instructions run.
- `rsa_mont.c`'s `use_ifma` answers for `CH_CPU_AVX512_IFMA`.
  `rsa_vp1_cpu` asks it with the value `rsa_pss_verify_cpu` and
  `rsa_pkcs1_verify_cpu` hand on from a session, and takes the kernel
  only for an odd modulus whose bit length is a multiple of 64, at least
  2,048. `rsa_vp1`, which takes no value, runs `rsa_mont64.c`.
- `rsa_sign64.c`'s `use_ifma` answers for `CH_CPU_AVX512_IFMA` and
  `CH_CPU_CONSTANT_TIME_MULTIPLY` together. `rsa_sign64_sp1` asks it with
  the value `widemul_rsa_pss_sign_cpu` hands on from a server's session,
  and under it runs the pair and the check through `rsa_vp1_cpu`, each
  followed by the wipe of the stack below and `avx512_wipe_registers`.

CBMC cannot unwind an intrinsic, so no harness compiles the kernels on
their instructions, and the [chacha20](#chacha20) and GCM proofs cover
the portable code they are held to. Two questions need tests: what a
kernel computes, and which calls run it. For `rsa_ifma.c` the first
rests on a model of its instructions, over which CBMC and Lean prove
parts of its arithmetic, and has a section of its own,
[The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation),
and so does it for `rsa_ifma_sign.c`,
[The AVX-512 IFMA signer](#the-avx-512-ifma-signer).

**What a kernel computes** rests on these, each in `make check` on an
x86-64 host. Each binary asks its CPU through `__builtin_cpu_supports`
and CPUID (`test/x86_kernels_cpu.h`), which only test code does, and
skips a kernel's cases on a CPU without its instructions:

- `bin/chacha20_equiv_test` runs its 73,787 cases on the AVX2 kernel
  and then on the AVX-512 kernel after the 128-bit path, from the same
  seed, with buffers at every offset past a 32-byte boundary, which
  covers every offset inside the AVX2 kernel's 32-byte rows, and every
  length that crosses the AVX-512 kernel's pass of sixteen blocks four
  times, with its row pass of four blocks alone and beside a pass.
- `bin/aes_equiv_test` runs its 2,258 counter-mode cases on
  `gcm_counter_blocks_vaes` after `gcm_counter_blocks_hw`: every block
  count to three passes and one, so each odd count's last block runs
  through half a register, and counters within two passes of 2^32.
- `bin/unit_host` runs once more under `ch_cfg.cpu` 0xd, which adds
  `CH_CPU_AVX2`: the unit suite with RFC 8439's vectors and every record
  it seals, on the AVX2 kernel. Under 0x10d, which adds
  `CH_CPU_AVX512_IFMA`, it runs them again on the AVX-512 kernel.
- `bin/ghash_equiv_test` runs its 3,213 AEAD cases and its stack checks
  a second time under a key whose schedule names the kernels
  (`test/ghash_equiv_vaes.h`). The stack checks look for H, its powers,
  a pass's sums and a pass's keystream below a seal and an open.
- `bin/quic_test_hw` runs FIPS 197's, SP 800-38D's and RFC 9001's
  vectors a second time on the kernels (`run_vectors_on_kernels`).
- The Wycheproof host binary runs three times more, under 0xf, 0x1f and
  0x11f: the ChaCha20-Poly1305 suite on the AVX2 kernel, then the AES-GCM
  suites on the VAES kernels, and then, where the CPU has AVX-512 IFMA,
  the RSA-PSS and PKCS#1 v1.5 suites on `rsa_ifma.c` and the
  ChaCha20-Poly1305 suite on the AVX-512 kernel and the IFMA Poly1305.
- `bin/rsa_test_host` and `bin/rsa_pkcs1_test_host` run once more under
  0x10d: the openssl-minted vectors from RSA-2048 to RSA-4096, and every
  refusal, on `rsa_ifma.c` where the CPU has AVX-512 IFMA.
- `bin/rsa_ifma_equiv_test` holds `rsa_ifma.c` on the instructions to the
  model of each instruction that `bin/rsa_ifma_model_test` runs on every
  machine
  ([The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)).

**Which calls run a kernel** rests on these:

- `bin/x86_kernels_test` counts the calls into each kernel under each of
  33 `ch_cfg.cpu` values: the 32 the five bits from 0x02 to 0x10 and
  0x100 make beside `CH_CPU_PROBED`, and 0, which a wiped record
  direction holds. Its rows are `chacha20_xor_cpu` and the two AEAD
  entries that take a value, a record under each of the three suites, a
  QUIC 1-RTT packet under each suite and a Handshake packet, an Initial
  packet, and a traffic key's schedule. The same rows count the AVX-512
  kernel's calls, and the two Poly1305 kernels'
  ([The AVX2 Poly1305](#the-avx2-poly1305),
  [The AVX-512 IFMA Poly1305](#the-avx-512-ifma-poly1305)). Its RSA
  rows run the two verifiers' entries that take a value and
  `rsa_vp1_cpu` over five moduli, three of which `rsa_ifma_public` does
  not take, and count that call, which `CH_CPU_AVX512_IFMA` picks. One of
  the two it takes is RSA-3072, whose 2^(104n) mod m starts at bit 32 of
  the top word, so a wrong start bit in `rsa_mont.c`'s
  `power_of_two_mod` changes its bytes. Its signer rows sign with
  `widemul_rsa_pss_sign_cpu` under an RSA-2048 key and count the calls
  into the pair, into `rsa_ifma_public` for the check, into the wipe
  below and into `avx512_wipe_registers`, which must run where the value
  holds `CH_CPU_AVX512_IFMA` and the multiply bit and nowhere else. Under
  each value a call must run a kernel exactly when the value names it,
  and must return the same bytes. The counting entries
  (`test/x86_kernels_count.c`, `test/rsa_ifma_count.c` and
  `test/rsa_ifma_sign_count.c`) forward to the 128-bit paths and to
  `rsa_mont64.c`, so the binary runs no kernel
  instruction and passes on every x86-64 CPU. An arm64 build of it has no
  row.
- `bin/tcp_blocking_loop_host` and `bin/webpki_auth_host` link
  `test/rsa_ifma_count.c` in place of `rsa_ifma.c`, as every binary the
  Makefile's `widemul_counted` builds does, and count the RSA public
  operations each caller of the two verifiers sends to `rsa_ifma_public`
  over a handshake, with the bit and without it. A pinned client's
  CertificateVerify, through `ch_connect` and through the client's
  handlers, makes one call where the client's value holds
  `CH_CPU_AVX512_IFMA`, whatever the server's holds, and
  `ch_srv_check`'s check of the RSA identity makes one where the server's
  does (`test/tcp_blocking_loop_ifma.h`). Where the server's value holds
  the multiply bit too, `ch_srv_check`'s signature with that identity
  makes one call into the signer's pair and one more into
  `rsa_ifma_public` for its check. The aws chain's flight through
  `hsa_server_auth`, whose leaf, intermediate and anchor keys are each
  RSA-2048, makes three: the leaf's signature under the intermediate in
  `webpki.c`'s `read_issuer`, the intermediate's under the anchor in
  `anchor_verifies`, and the CertificateVerify in `handshake_auth.c`. The
  r2 chain, which holds no RSA key, makes none
  (`test/webpki_auth_ifma.h`). Without the bit every count is 0. An arm64
  object refuses the bit and makes no call, so there the rows run without
  it alone. The CA client's CertificateVerify under a pinned CA, which
  only a `ROLE=both TRUST=ca-rsa` host object compiles, has no such row,
  because no host binary builds that object.
- `test/aes-runtime-qemu.sh` runs whole handshakes on CPU models, in CI's
  mips job on every push. On `max,-aes,-pclmulqdq,-avx2` the loops with
  `CH_CPU_AVX2` on both ends must die of SIGILL, which shows the model
  traps AVX2, and so that the rows without the bit ran none of it. On
  `max,-avx2` the loops with the AES bit must pass on the 128-bit loops,
  and with `CH_CPU_VAES` added they must die of SIGILL. On `max`, where
  the qemu has a kernel's instructions, one end runs the kernel and the
  other the 128-bit path, in both orders, and a whole QUIC handshake and
  a whole TCP one must complete between them on the suite the two values
  share. A qemu without a kernel's instructions skips that kernel's mixed
  rows and says so. On `max,-avx512ifma` the webpki loop, whose server's
  `ch_srv_check` verifies an RSA-PSS signature before the handshake,
  must pass with both ends stating the probe's bit alone and die of
  SIGILL with both stating `CH_CPU_AVX512_IFMA`: QEMU implements no
  AVX-512 instruction, so no model there runs `rsa_ifma.c`, and the
  fault shows the check called it. The script also builds and runs
  `bin/x86_kernels_test`, which is the one way an arm64 development
  machine runs it; `test/docker-aes-runtime-qemu.sh x86-kernels` runs
  that binary alone, `test/docker-aes-runtime-qemu.sh
  rsa-ifma-callers` runs `bin/tcp_blocking_loop_host` and
  `bin/webpki_auth_host` alone, for x86-64, and
  `test/docker-aes-runtime-qemu.sh rsa-ifma` the webpki loop's two rows
  alone.
- `test/chacha-builds.sh` and `test/quic-builds.sh` compile the kernels
  for x86-64 with no instruction flag under the pinned clang. They
  require each kernel's 256-bit instructions there, the AVX-512 ChaCha20's
  512-bit ones and its call to `avx512_wipe_registers`, a zeroing
  instruction in `avx512_wipe.c` for each of zmm0 to zmm31 and k1 to k7,
  no 256-bit register in `chacha20.c`, `chacha20_vector.c`, `gcm.c` or
  `gcm_hw.c`, and no kernel on arm64. They also read which entries each
  source calls. `chacha20_xor_cpu`'s own body must call both kernels and
  the 128-bit path, and `chacha20_xor`'s the 128-bit path alone. `gcm.c`
  must call all six entries, the three kernels and `gcm_hw.c`'s three,
  and `gcm_hw.c` no kernel. A predicate that answers one value for every
  session leaves a call out.
- `make lint-wide-multiply` holds `chacha20_avx2.c`'s conditional
  branches at 23 on x86-64 and 0 on arm64, and `chacha20_avx512.c`'s at
  35 and 0, each a loop over a public count or a test of the byte count. `gcm_vaes.c` sits in
  `WIDEMUL_PUBLIC` beside `gcm_hw.c`.

CI's `x86-64-kernels` job runs the binaries above and the Wycheproof host
binary with `CH_REQUIRE_X86_KERNELS=1`, under which a CPU without AVX2,
VAES and VPCLMULQDQ fails them rather than skips them, after `make
x86-64-kernels-cpu` names the runner's CPU. A runner without AVX-512
IFMA still skips the runs under a value with `CH_CPU_AVX512_IFMA`, which
only `CH_REQUIRE_AVX512_IFMA=1` turns into failures. The nightly's
`rsa-ifma-sde` job sets it and runs `rsa_ifma.c`'s binaries, and
`bin/chacha20_equiv_test`, `bin/poly1305_equiv_test` and
`bin/avx512_wipe_test`, under Intel SDE, an emulator, on a CPU model that
has AVX-512 IFMA
([The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)).

Thirty-six violations break these rules, and each is caught:

- `test/chacha-builds.sh` catches `chacha-avx2-runs-without-cpu-bit` and
  `chacha-avx2-ignores-cpu-bit`, a `use_avx2` that answers 1 or 0 for
  every value, and `chacha-avx2-without-target`, and the same three for
  `use_avx512`, `chacha-avx512-runs-without-cpu-bit`,
  `chacha-avx512-ignores-cpu-bit` and `chacha-avx512-without-target`, and
  `inv17-chacha-avx512-keeps-registers`, a kernel that returns without
  the wipe.
- `bin/rsa_ifma_model_test` catches `inv41-rsa-ifma-runs-without-cpu-bit`
  and `inv41-rsa-ifma-ignores-cpu-bit`, the same two for `rsa_mont.c`'s
  `use_ifma`, on every machine: it counts the calls `rsa_vp1_cpu` makes
  into the kernel over the lane model, under the bit and under
  `CH_CPU_PROBED` alone. `test/widemul-builds.sh` catches
  `inv41-rsa-ifma-without-target`.
- `bin/rsa_ifma_sign_model_test` catches
  `inv41-rsa-sign64-ifma-ignores-ifma-bit` and
  `inv41-rsa-sign64-ifma-ignores-multiply-bit`, a `use_ifma` in
  `rsa_sign64.c` that reads one of its two bits alone, on every machine,
  through its count of the calls into the pair. `test/widemul-builds.sh`
  catches `inv41-rsa-ifma-sign-without-target`.
- `test/quic-builds.sh` catches `inv26-vaes-runs-without-cpu-bits` and
  `inv26-vaes-ignores-cpu-bits`, the same two for `gcm_use_vaes`, and
  `inv26-vaes-without-target`.
- `bin/aes_runtime_test` catches `inv26-initial-key-drops-cpu`,
  `inv26-traffic-key-init-keeps-cpu` and
  `inv26-traffic-key-cpu-unwritten`, which break the byte a schedule
  records. That byte is written on every architecture, so the binary
  reads it on arm64 too.
- `bin/x86_kernels_test` catches the rest, which only an x86-64 binary
  compiles: `chacha-avx2-reads-vaes-bit`, `inv26-vaes-without-aes-bit`
  and `inv26-vaes-without-vaes-bit`, a predicate that reads the wrong
  bit or one bit of two, and `inv16-aead-seal-cpu-drops-avx2`,
  `inv16-aead-open-cpu-drops-avx2`, `inv26-record-seal-key-drops-cpu`,
  `inv26-record-open-key-drops-cpu`, `inv26-packet-seal-key-drops-cpu`
  and `inv26-packet-open-key-drops-cpu`, a call that hands on no value.
  Each names `test/docker-aes-runtime-qemu.sh x86-kernels` as its catch,
  so `test/violations.py` runs it in a container on an arm64 host. So do
  `inv41-rsa-sign64-ifma-skips-register-wipe` and
  `inv42-rsa-sign64-ifma-check-on-loops`, a signer that leaves out the
  wipe of the registers and a check that runs on `rsa_vp1`.
- `bin/tcp_blocking_loop_host` and `bin/webpki_auth_host` catch five
  callers that hand an RSA verifier 0 in place of the session's
  `ch_cfg.cpu`: `inv41-rsa-ifma-pinned-certificate-verify-drops-cpu`,
  `inv41-rsa-ifma-srv-check-drops-cpu`,
  `inv41-rsa-ifma-webpki-certificate-verify-drops-cpu`,
  `inv41-rsa-ifma-webpki-issuer-drops-cpu` and
  `inv41-rsa-ifma-webpki-anchor-drops-cpu`. Only an x86-64 object makes
  the call, so each names `test/docker-aes-runtime-qemu.sh
  rsa-ifma-callers` as its catch. `bin/tcp_blocking_loop_host` catches
  `inv41-rsa-ifma-srv-signs-without-cpu` the same way, a server that
  signs under 0.

A mutant of the ChaCha20 or GCM kernels' arithmetic is caught only on a
CPU with the kernel's instructions, and `test/violations.py` runs every
violation on the host that runs it, so on an arm64 host such a mutant
would pass as unguarded. None is in `test/violations/`. `rsa_ifma.c` and
`rsa_ifma_sign.c` are the exception: `bin/rsa_ifma_model_test` and
`bin/rsa_ifma_sign_model_test` run their own text over a model of each
instruction on every machine, and violations of their arithmetic, their
dispatch and their build are in `test/violations/`
([The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)
and [The AVX-512 IFMA signer](#the-avx-512-ifma-signer)).
For the other two kernels, 27 such mutants were
run by hand once, built with gcc 13 and run under `qemu-x86_64 -cpu max`
from QEMU 8.2, with VPCLMULQDQ, which QEMU does not implement, replaced
by one PCLMULQDQ per 128-bit half. The binaries of decision 90's commit
caught 26:

- in the ChaCha20 kernel, the keystream of the upper four blocks, a
  counter lane, a rotation, the order of two rows, which the equivalence
  test and the RFC vectors each caught, the last rows of a pass and the
  last bytes;
- in the GCM kernels, a counter step, a carry into the IV, an odd block,
  the last round key, a pair of powers, a byte order, the accumulator's
  half, a sum's halves, the middle product, a seal or an open that hashes
  its plaintext, a pass left unhashed, an odd step that writes two passes,
  a counter offset in a seal or an open, and the wipe.

The one they missed reads the powers without `volatile`. Built with gcc,
it left no copy of a power on the stack, so the stack checks had nothing
to find. Built with clang 18, it left copies, and the GHASH equivalence
test's run on the kernels caught it. The reads stay volatile for the
reason `ghash_power_at` gives. Those runs used binaries that renamed the
128-bit entries to the kernels; `bin/unit_host`, `bin/ghash_equiv_test`
and `bin/quic_test_hw` run the same cases on the kernels now, and the 27
mutants have not been run against them.

None of this proves a kernel agrees with the portable code on an input no
case runs. QEMU's `max` model has AVX2 and VAES and no VPCLMULQDQ, in
8.2, 10.0 and 11.1 alike, so under qemu the AVX2 rows run and every row
on the VAES kernels skips: no handshake there runs those kernels against
the 128-bit loops. Those rows run where the CPU has the instructions,
which among the machines these checks use is the runner of CI's
`x86-64-kernels` job alone. They ran once by hand at decision 89's fifth
commit, under QEMU 10.0 and gcc 14, with each VPCLMULQDQ replaced by one
PCLMULQDQ per 128-bit half, as the 27 mutants did: the lane's handshakes
with one end on the VAES kernels and the other on the 128-bit loops, the
two equivalence tests' second pass, `bin/quic_test_hw`'s vectors and the
Wycheproof host binary under 0x1f, all with `CH_REQUIRE_X86_KERNELS=1`.
Each passed. That run holds the calls that pick the kernels and the
kernels' AES rounds, and not the 256-bit multiply itself. The
ChaCha20 kernel's timing rests on construction, as the portable loop's
does: adds, exclusive-ors, shifts and byte shuffles under constant
orders, with no table and no multiply, and so does the AVX-512 kernel's,
whose rotations are VPROLD's under constant counts. The GCM kernels' timing rests on
the caller's `CH_CPU_CONSTANT_TIME_AES` bit, which `gcm_use_vaes`
requires beside `CH_CPU_VAES` and whose statement covers the AES
instructions and the carry-less multiply at every width (decision 89).
`rsa_ifma.c`'s timing needs no statement for a verifier: its inputs are
public, and `CH_CPU_AVX512_IFMA` states presence alone (decision 119).
For a signature, `rsa_ifma_sign.c`'s timing, and `rsa_ifma.c`'s in the
signature's check, rest on the caller's
`CH_CPU_CONSTANT_TIME_MULTIPLY`, whose statement covers IFMA's 52-bit
products and which `rsa_sign64.c`'s `use_ifma` requires beside
`CH_CPU_AVX512_IFMA` (decision 120).

### The hash instructions

`sha256_hw.c` computes SHA-256 on the CPU's SHA-256 instructions:
FEAT_SHA256 on arm64, and the SHA extensions with SSSE3 and SSE4.1 on
x86-64. `sha512_hw.c` computes SHA-384 and SHA-512 on arm64's SHA-512
instructions, FEAT_SHA512, and has no body on x86-64 (decision 93).
Every host object carries the first beside `sha256.c`, and a host object
with `SUITE=aesgcm` the second beside `sha512.c`. Each function turns
its instructions on through its file's own target attribute. A host
object also carries `hkdf.c` and `keysched.c` a second time, as
`hkdf_hw.c` and `keysched_hw.c`: the same source text under the names
`hash_hw.h` gives, with its SHA-256 calls on `sha256_hw.c` and, on
arm64, its SHA-384 calls on `sha512_hw.c`. Three predicates read the
caller's bits, and one branch per call picks a path:

- `sha256.h`'s `sha256_on_instructions` answers for
  `CH_CPU_CONSTANT_TIME_SHA256`. The three entries that end `sha256.h`
  ask it.
- `sha512.h`'s `sha512_on_instructions` answers for
  `CH_CPU_CONSTANT_TIME_SHA512` on arm64, and no on x86-64. The five
  entries that end `sha512.h` ask it. `transcript.h`'s two entries call
  both headers', so each hash of a transcript follows its own bit.
- `hkdf.h`'s `hash_on_instructions` answers for a call that names its
  hash by `hash_len`: the SHA-256 bit where the hash is SHA-256, and the
  SHA-512 bit where it is SHA-384. The entries that end `hkdf.h` and
  `keysched.h` ask it.

A call that takes no value runs the portable code. The DRBG, the
certificate verifiers, the RSA signer, `p256_sign`, the cookie and token
MACs, the CertificateVerify content hash, an SPKI pin's hash, the
server's hash of a ClientHello's frozen bytes and the webpki ticket
binding make such calls, and each starts and ends its context on that
path. `p256_sign_cpu`, which a server signs a CertificateVerify through,
takes the session's value and hands it to `hmac_sha256_cpu` for each
HMAC of the RFC 6979 nonce (decision 102).

CBMC cannot unwind an intrinsic, so no harness compiles `sha256_hw.c` or
`sha512_hw.c`, and the [sha256](#sha256), [sha512](#sha512),
[hkdf](#hkdf), [hkdf384](#hkdf384) and [keysched](#keysched-keysched384)
proofs cover the portable code they are held to. `hkdf_hw.c` and
`keysched_hw.c` are the text those harnesses prove, under other names.
The twelve harnesses that compile the host object's define read the
entries, and the three whose code calls a copy, `aes_runtime`,
`record_suite` and `quic_keys_suite`, define it as the stub of the call
it copies. Two questions need tests: what the instructions compute, and
which calls run them.

**What the instructions compute** rests on these. Each binary asks its
CPU (`test/hash_instructions_cpu.h`), which only test code does, and
skips what the CPU has no instructions for, or fails under
`CH_REQUIRE_HASH_INSTRUCTIONS=1`:

- `bin/sha2_equiv_test`, in `make check`, runs 75,467 SHA-256 cases, and
  on arm64 148,479 more for SHA-384 and SHA-512. Each hashes a message
  on the portable code in one call, and a copy of it in three updates
  and a final, each on the path one bit of the case's mask names, so a
  context passes between the two paths at each call. It compares the two
  contexts before the final, then the digests, and the digest of the
  call that takes a whole message. The SHA-256 inputs are every length
  from 0 to 273 bytes cut at every offset below 130, messages of all
  0x00 and all 0xff at every length next to a block boundary, 20,000
  random lengths, cuts, alignments and masks, 16,385 bytes and 64 KiB,
  an update of no bytes from a NULL pointer, and 2,000 random inputs to
  each call of the two copies against the file under its own names. The
  SHA-512 inputs are the same shapes at its 128-byte block, every length
  to 529 bytes cut below 258, with each case run as SHA-384 or as
  SHA-512, and the copies at SHA-384's hash length.
- The same binary copies the stack below five kinds of SHA-256 call and
  six kinds of SHA-512 call, which between them run every call each file
  makes to its compression function. In each copy it requires no four
  32-bit words in a row, or two 64-bit ones, that the call computed from
  its input: a schedule word, a partial sum before one, a schedule word
  plus its constant, a working variable after any round, a round's T1,
  or a state word (`test/sha2_equiv_residue.h`,
  `test/sha2_equiv_residue512.h`).
- `bin/unit_host` runs once more under `ch_cfg.cpu` 0x25, which adds the
  SHA-256 bit: FIPS 180-4's vectors, RFC 4231's and RFC 5869's on the
  instructions, and every record direction the suite keys.
- On arm64 `bin/sha512_test_host` and `bin/hkdf384_test_host` run once
  more under 0x65, which adds the SHA-512 bit: FIPS 180-4's SHA-384 and
  SHA-512 vectors, RFC 6234's million-byte message, RFC 4231's
  HMAC-SHA-384 cases and a TLS_AES_256_GCM_SHA384 key schedule on the
  instructions.
- The Wycheproof host binary runs once more under 0x27, its HMAC-SHA-256
  and HKDF-SHA-256 suites on the instructions, and on arm64 under 0x67,
  its HMAC-SHA-384 and HKDF-SHA-384 suites too.
- `bin/quic_test_hw` runs RFC 9001's and RFC 9369's Appendix A once more
  with the SHA-256 bit, whose keys HKDF then derives on the instructions.
- `bin/quic_loop_aes` and `bin/webpki_loop_aes` run whole handshakes
  with one end's hashes on the instructions and the other's on the
  portable code, in both orders, under ChaCha20 and under AES-256-GCM,
  whose key schedule runs SHA-384. The four host loop binaries run one
  with every bit the architecture defines.

**Which calls run the instructions** rests on these:

- `bin/hash_runtime_test` and `bin/hash_runtime_exporter_test`, in
  `make check`, count the calls into each path of each hash under 257
  `ch_cfg.cpu` values: the 256 the eight bits beside `CH_CPU_PROBED`
  make, and 0. One of the eight, `CH_CPU_AVX512_IFMA`, picks no hash.
  The counting entries (`test/hash_runtime_count.c`) run
  every path on the portable code, and the row that seals an Initial
  packet clears the value's AES, AVX2 and VAES bits, so its AES-GCM runs
  on the table. So the binaries run no instruction a bit names and give
  one verdict on every CPU of their architecture. A row is one call
  that takes a session's value: `sha256.h`'s three entries and
  `sha512.h`'s five, `hkdf.h`'s five and `keysched.h`'s eight at each
  hash length, `p256_sign_cpu`, whose RFC 6979 nonce runs sixteen
  HMAC-SHA-256 calls, the transcript, a record direction's keying and
  KeyUpdate under each suite, and a QUIC level's keys, their update and
  an Initial packet. Under each value a row must make every SHA-256 call
  it makes under `CH_CPU_PROBED` alone on the instructions where the
  value holds the SHA-256 bit and on `sha256.c` where it does not, the
  same for its SHA-512 calls and the SHA-512 bit, and write the same
  bytes. An x86-64 binary requires every SHA-512 call on `sha512.c` under
  every value.
- `test/hash-builds.sh`, in `make check`, compiles the hash sources for
  x86-64 and arm64 with no instruction flag under the pinned clang. It
  requires SHA-256 instructions in `sha256_hw.c`, SHA-512 instructions
  in arm64's `sha512_hw.c`, and neither in any other hash source; none
  of FEAT_SHA3's four instructions in `sha512_hw.c`, whose target
  attribute turns them on beside FEAT_SHA512's; each file's entries
  defined, and none in x86-64's `sha512_hw.c`; each copy's calls on the
  `_hw` names its target has and the files' own on the portable ones;
  and no `_hw` symbol in a device object's sources.
- `test/aes-runtime-disasm.sh` disassembles three packaged host objects
  built with the host's compiler and requires every SHA-256 instruction
  in `sha256_hw.o`, every SHA-512 instruction in `sha512_hw.o`, and none
  of FEAT_SHA3's four in `sha512_hw.o`.
- `test/aes-runtime-qemu.sh` runs whole handshakes on CPU models, in
  CI's mips job on every push. On x86-64's `max,-sha-ni` the loops whose
  ends leave the SHA-256 bit clear must pass, and with the bit on both
  ends they must die of SIGILL, which shows the model traps the
  instructions, and so that the rows without the bit ran none.
  `bin/aes_runtime_test`, whose rows derive Initial keys and state no
  hash bit, must pass there too. On an x86-64 model without AES-NI,
  PCLMULQDQ, AVX2 and the SHA extensions the two counting binaries must
  pass. On arm64's `cortex-a72`, which has FEAT_SHA256 and no
  FEAT_SHA512, the same holds for the SHA-512 bit, and the two counting
  binaries run there as an arm64 object. On each `max` it runs
  `bin/sha2_equiv_test` and the handshakes with one end on the
  instructions, with `CH_REQUIRE_HASH_INSTRUCTIONS=1`.

The counting tests hold the entries and the calls their rows make. They
do not hold every call site of a session: a site that hands an entry
another value than its session's computes the same bytes. The qemu rows
hold the sites a whole handshake runs, and
`inv16-transcript-hashed-under-every-bit` is the mutant of one.

The stack checks ran clean under Apple clang 21 on arm64, and in a
container under gcc 13.3 and clang 18 for arm64 and for x86-64, the
x86-64 binaries under `qemu-x86_64`. Apple clang 21's x86-64 code was
read and not run, because Rosetta has no SHA extensions: every vector
store of `compress_blocks` lands inside the `block_state` it wipes. The
checks hold the compilers they ran under and no other. A binary built
without optimization keeps every temporary in a stack slot, and one
under AddressSanitizer has frames of the sanitizer's own layout, so
either skips the search and says so (`test/stack_residue.c`): the
sanitizer lane runs the cases and not the search. `sha512_hw.c` reads
the state a block began with through a volatile pointer, as
`sha256_hw.c` does. On arm64 neither compiler put that state in a stack
slot of its own without the read, so no mutant shows what the read
prevents there.

No QEMU arm64 model turns FEAT_SHA256 off, so on arm64 the claim that a
session without the SHA-256 bit runs no SHA-256 instruction rests on the
counts, on `test/hash-builds.sh` and on the disassembly. The timing of
either hash's instructions rests on the caller's bit alone: nothing here
measures it.

Keccak has the same arrangement in an arm64 object that clang compiled
(decision 99). `sha3_hw.c` computes SHA-3 and SHAKE with Keccak-f[1600]
on FEAT_SHA3's four instructions, and `mlkem_hw.c` and `mlkem_poly_hw.c`
are `mlkem.c` and `mlkem_poly.c` compiled once more over it, under the
names `keccak_hw.h` gives. A session whose `ch_cfg.cpu` holds
`CH_CPU_CONSTANT_TIME_SHA3` runs them, through the entries that end
`sha3.h` and `mlkem.h`. Under any other compiler the three files hold
nothing and every session runs `sha3.c`.

What holds them:

- `bin/sha3_hw_equiv_test` compares `sha3_hw.c` with `sha3.c` over
  SHA3-256 and SHA3-512 of every length from 0 to 700 bytes and of two
  long messages, and over 400 SHAKE128 and SHAKE256 streams absorbed and
  squeezed in random pieces, once with every call on the instructions
  and once with each call on a path picked at random. At 17 lengths
  around a block's end it compares the instructions with FIPS 202 as
  `proof/sha3_reference.h` writes it.
- The same binary copies the stack below six kinds of call, which
  between them run every way the file runs its permutation, and requires
  no 64-bit word there that the call computed: a lane of a state, a
  column's parity, a value theta adds, or a lane after theta, rho or chi
  of any round (`test/sha3_hw_equiv_residue.h`).
- `bin/mlkem_hw_equiv_test` compares, over 200 random seeds, the keys,
  ciphertexts and secrets the copies write with `mlkem.c`'s, under each
  answer a compression runs under, and the three calls a session makes
  under a `ch_cfg.cpu` value with and without the bit.
- The two loops, built with clang for arm64 and run under
  `qemu-aarch64`, complete each handshake, ML-KEM included, with one end
  on the instructions and the other on `sha3.c`, in both orders, on the
  `max` model. On cortex-a72, which has no FEAT_SHA3, a session without
  the bit completes and one with it dies of SIGILL
  (`test/aes-runtime-qemu.sh`).
- The host loops in `make check` give one end the SHA-3 bit beside the
  SHA-256 and SHA-512 bits where the object holds the path and the CPU
  has FEAT_SHA3 (`test/test_cpu.h`).
- `test/hash-builds.sh` requires FEAT_SHA3's instructions in
  `sha3_hw.c` alone, and each copy's SHA-3 and SHAKE calls on the `_hw`
  names, for arm64 under the pinned clang, and no body in any of the
  three files for x86-64 or a device object.
- CI builds the two binaries with Apple clang in the macos job and with
  the pinned clang in the arm64 job, whose own compiler is gcc (`make
  keccak-instructions-check`), and runs them natively.

Four violations each break one of those rules, and each is caught:
`inv17-sha3-digest-state-kept` and `inv17-sha3-hw-lane-in-stack-slot`
by the stack check, `inv16-mlkem-copy-absorb-on-portable` by
`test/hash-builds.sh`, and `inv16-sha3-instructions-without-bit` by the
qemu lane on cortex-a72.

None of this proves the two paths agree on an input no case runs. The
stack check reads the stack one compiler left on one call, and cannot
see a register. It ran under Apple clang 21, clang 18 and clang 23, and
nothing holds the claim for a clang that is none of them. No binary
counts which path each ML-KEM call takes, as `bin/hash_runtime_test`
does for SHA-2, so a call site that hands the portable code a session
with the bit runs slower and no check fails.

### The host object's two multiplies

A host object holds each operation built on the widening multiply
twice, and each session's `CH_CPU_CONSTANT_TIME_MULTIPLY` bit picks a
copy for each operation (decisions 87 and 89). Two files compile twice,
the second time as a native copy. X25519's second copy is the wide
field, P-256's is the wide files (decision 94) and RSA signing's is the
signer on 64-bit words (decision 95), and each has harnesses of its own
([x25519_wide](#x25519_wide), [p256_wide](#p256_wide),
[rsa_sign64](#rsa_sign64)).
`widemul_answer` turns the bit into
the answer every dispatcher in `widemul.h` takes. No harness compiles a
native copy, and neither copy needs a run of its own:

- The native copy is its file's text on the native multiply under other
  names. `proof/run.sh` passes `CH_NATIVE_WIDEMUL` to every harness of
  those files, so each proves that text, but for the arm of
  `poly1305.c`'s `whole_blocks` that hands whole groups of blocks to the
  vector path. Only `poly1305_native.c` compiles that arm: `size_t`
  arithmetic on the byte count, which `bin/poly1305_equiv_test` runs
  ([The vector Poly1305](#the-vector-poly1305)).
- The file under its own names compiles to the same assembly with the
  host object's define as without it, which `test/widemul-builds.sh`
  requires, so it is the `WIDEMUL=decomposed` build's file.
  [ctwidemul](#ctwidemul) carries the verdicts above to it, as it carries
  them to every target that runs the decomposition.
- The twelve harnesses that compile the host object's define get no
  `CH_NATIVE_WIDEMUL`, which `ct.h` refuses beside it. None of their
  formulas holds a widening product: each stubs the AEAD or calls none.
  The text of eight of them changed when the answer moved to the bit,
  because a record direction stores the answer there and `session.h`
  includes `widemul.h`, and each of the twelve was proved again on that
  commit.
- Every other harness preprocesses to the text it had before that
  commit, so no other verdict moved.

What no proof covers is the choice itself: which copy each operation
runs, and whether each session passes the answer its own `ch_cfg.cpu`
gives. Tests hold it:

- `bin/widemul_runtime_test`, in `make check`, compiles the files built
  on the multiply and the wide field
  again under counted names and runs the AEAD, X25519, ML-KEM, P-256, RSA
  signing and record operations under each answer. Under
  `WIDEMUL_CONSTANT_TIME` they call the native copies alone, X25519
  the wide field and P-256 the wide files, under
  `WIDEMUL_NOT_STATED` the decomposition alone and as many times, and
  under 0, 3, 0x80 and 0xff the decomposition, with the same bytes out of
  all of them. It also holds `widemul_answer` to the multiply bit alone:
  the constant-time answer for a `ch_cfg.cpu` that holds the bit, by
  itself or beside every other bit, and the other answer for a value
  without it.
- `bin/tcp_blocking_loop_host`, `bin/tcp_nonblocking_loop_host`,
  `bin/quic_loop_host` and `bin/webpki_session_host` run whole
  handshakes on the same counts for each value of the bit at each end.
  Where both ends are this tree's sessions,
  each end's calls are counted around its own calls, so a direction, a
  packet or a signature that runs under another answer than its session's
  shows.
- The unit, ML-KEM, P-256 and RSA signing vectors run once with the bit
  and once without it, and the Wycheproof suite once for each of the four
  values the AES bit and the multiply bit give.

A mutant that inverts a dispatcher, reads the answer from another bit,
or drops the answer at any of the places that pass it, computes the same
bytes, so only the counts catch it; those mutants are among the
fifty-eight `INV-16` violations that hold the host object's multiply
(docs/invariants.md). The counts say which copy ran, not what the native
multiply costs in time: that is the caller's statement, which nothing
here can check.

### The host object's RSA arithmetic

A host object computes `rsa_vp1`, the public operation of both RSA
verifiers, on `rsa_mont64.c`'s 64-bit words, and a device object on
`rsa_mont.c`'s 32-bit words, which stay the reference (decision 95).
`rsa_mont.c` compiles to one arm or the other, so no bit of `ch_cfg.cpu`
picks between them and no count is needed to say which ran. On x86-64
one bit picks a third path for `rsa_vp1_cpu`, `rsa_ifma.c`, which
[The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)
covers. The host
arm computes R^2 by a long division for a modulus whose top bit is set,
and by `rsa_mont64_modulus_init` for any other (decision 103). The
proofs of [rsa_mont64](#rsa_mont64) and
[rsa_mont_host](#rsa_mont_host) hold the 64-bit arm's memory accesses
and its sums, over a contract of the multiply, and say nothing about a
value. Tests hold the values:

- `bin/rsa_equiv_test`, in `make check`, compiles both arms into one
  binary, the device arm under a second name
  (`test/rsa_equiv_portable.c`), and requires the same bytes from each:
  over four random odd moduli with the top bit set at each of the 33
  lengths from 256 to 512 bytes; over moduli of all ones, of the top and
  bottom bits alone, with a low word of 1 and of all ones, and with zero
  words between the top and the bottom; over the modulus
  (B^(k + 1) + 1) / (B + 1), for B = 2^64 and an even word count k,
  whose division meets the remainder n - 1 and takes the largest
  estimate, which no random modulus does; and over moduli of 24 bit
  lengths below the top bit, down to 3 bits, and the moduli 3 and 1, at
  256, 264 and 512 bytes.
  Under each it tries the signatures 0, 1, 2, n - 2, n - 1, the top bit
  alone and random values, 2,044 comparisons in all. It also holds
  `rsa_mont64_mont_square` to the multiplication of a number by itself,
  apart from its operand and on it, at every word count from 1 to 64, a
  prime's among them: 0, 1, n - 1, the top bit alone and random values
  below n, 1,024 squares (decision 106). The powers of 0, 1
  and n - 1 are known, so those rows check both arms against the answer
  and not only against each other. Its random values come from a seed
  the nightly can vary (`CH_RSA_EQUIV_SEED`). Under random moduli about
  a third of the division's steps add the modulus back once, and about
  one in sixty twice. It runs the form of `rsa_mont64.h`'s step its
  compiler picks, and `bin/rsa_equiv_test_compare` and
  `bin/rsa_equiv_test_sum` are the same binary on each form, so a machine
  of either compiler runs both (decision 117). Under clang for arm64 it
  runs `rsa_mont64_blocks.c`'s blocks at a word count that is a multiple
  of 4, and the other two turn them off, so the loops run at every count
  (decision 118).
- `bin/rsa_blocks_equiv_test`, in `make check`, holds the blocks to the
  loops, word for word. It compiles with the blocks on under any
  compiler, and `test/rsa_mont64_loops.c` compiles `rsa_mont64.c` once
  more with them off, under second names. At every word count from 1 to
  64, under two random odd moduli with the top bit set and the five
  edge moduli above, it compares the modulus record each init writes;
  the multiplication of a from 0, 1, n - 1, the top bit alone, all ones
  and random values, which may be above n, by b from 0, 1, n - 1, the
  top bit alone and random values below n, with the output apart, on a
  and on b; and for each a below n the multiplication of a by itself
  and the square, each with the output apart from a and on it. At a
  multiple of 4 it also
  holds `rsa_mont64_blocks_square` to
  `rsa_mont64_blocks_mul(o, a, a, mod)` before the last subtraction,
  since `rsa_mont64_mont_square` runs the square only above 32 words:
  62,720 multiplications and 7,056 squares in all.
- `bin/rsa_test_host` and `bin/rsa_pkcs1_test_host` are the mains of
  `bin/rsa_test` and `bin/rsa_pkcs1_test` built as a host object builds
  their sources: the openssl-minted RSA-PSS vectors at 2047, 2048, 3072,
  4032 and 4096 bits, the PKCS#1 v1.5 ones at 2048, 3072, 4032 and 4096,
  and every refusal, on the 64-bit arm. Each verifies through the entry
  that takes the `ch_cfg.cpu` value it runs under, and check runs each
  under every value that changes a path, so on x86-64 its vectors run on
  `rsa_ifma.c` too ([The x86-64 kernels](#the-x86-64-kernels)).
- The Wycheproof host binary runs the RSA-PSS and PKCS#1 v1.5 suites on
  it, and every host loop, session and webpki test verifies its
  CertificateVerify and chain signatures on it.
- `test/widemul-builds.sh` requires `rsa_mont.c` to call `rsa_mont64.c`
  when it is compiled as a host object compiles it, and not otherwise.

Neither arm defines the result for an even modulus, which is no RSA
modulus, and the two write different bytes for one, so no row here is
even. `rsa_pkcs1_verify` refuses an even modulus before the operation
runs. `rsa_pss_verify` does not, and its decode then judges bytes that
are no power of the signature in either object.

A host object signs on those words too, in a session that states its
multiply: `rsa_sign64.c`, by the Chinese remainder theorem from the
key's primes, beside `rsa_sign.c`'s ladder over n and d, which stays the
reference (decision 95). On x86-64 a session that also sets
`CH_CPU_AVX512_IFMA` computes the two exponentiations on
`rsa_ifma_sign.c`, which
[The AVX-512 IFMA signer](#the-avx-512-ifma-signer) covers. The proofs of [rsa_sign64](#rsa_sign64) hold
how it reads an exponent and its memory accesses. Tests hold the values:

- `bin/rsa_sign_equiv_test`, in `make check`, requires the ladder's
  bytes from the 64-bit signer under the four keys of
  `test/rsa_sign_vectors.h`, which openssl minted with their CRT
  integers: RSA-2048, RSA-2112, whose primes are 132 bytes, half a word
  past a whole number of 64-bit words, RSA-3072 and RSA-4096. Under each
  it signs the messages 0, 1 and n - 1, which are their own signatures,
  and random ones: 19 comparisons.
- The same binary holds the window, `rsa_sign64_power`, to the ladder
  under random moduli of 256 bytes, the longest prime the build takes:
  over the exponents 0, 1, 2, 15, 16 and 17, all ones, the top bit
  alone, every digit value in turn and zero high or low digits, and
  random moduli, exponents and messages. The powers 0 and 1 are known,
  so those rows check both against the answer. Under moduli of 8, 12,
  128 and 132 bytes and exponents of 1 byte, 5 bytes and the modulus's
  length it holds the window to a square-and-multiply over
  `rsa_mont64_mont_mul` that reads one bit a step and keeps no table,
  and requires that zero bytes ahead of an exponent change nothing: 110
  comparisons.
- It also copies the stack a call left, under three of the keys. Seven
  runs for a key look for what the call computed from the private key
  and require no two words of it side by side: a signature, a refused
  one, the key test on a key it admits and on one it refuses, and the
  reduction, the exponentiation and the recombination each on its own.
  Nine more make one call under two secrets that a caller cannot tell
  apart and require the two stacks equal in every byte, which holds a
  value shorter than a word (INV-17): 42 comparisons. A binary built
  without optimization or under AddressSanitizer makes none of the
  sixteen and says why (`test/stack_residue.c`), so the sanitizer lane
  runs the binary's other 129 comparisons and no run over the stack.
- `bin/rsa_sign_test_host` signs the four keys through
  `widemul_rsa_pss_sign_cpu` under each value of the multiply bit and
  requires OpenSSL's bytes. It changes one bit of each CRT integer and
  requires an error and no signature bytes from the 64-bit signer
  (INV-42). The Wycheproof host binary runs `widemul_rsa_sp1_cpu` over the
  PKCS#1 v1.5 generation vectors under each value too, with the CRT
  integers of Wycheproof's own keys.
- `bin/widemul_runtime_test` counts the calls into each signer and into
  the 64-bit signer's key test, and requires them for a session that
  states its multiply and for no other, and every host loop that
  authenticates with the RSA identity reads the same counts over a whole
  handshake.
- `bin/diff_rsa_sign64`, in `make diff`, has the Lean spec sign random
  digests under random salts with the four keys, from n and d, and
  requires its bytes from both signers: 21 comparisons. The spec states
  RSASP1 as m^d mod n over `Nat` and has no model of the CRT; the
  comparison is what holds the CRT to it.

Twenty-one violations hold the arm: thirteen break a value, and
`bin/rsa_equiv_test` catches seven of them, `bin/rsa_equiv_test_compare`
and `bin/rsa_equiv_test_sum` one each and `bin/rsa_blocks_equiv_test`
four, three in the blocks and one that runs them at every even word
count; four break a sum, a bound or the no-wrap form and a proof
catches each; one writes the last subtraction
as a branch and `lint-wide-multiply`'s count catches it; two move the
file between the host and the device object and `lint-trust-separation`
catches each; and one keeps a host object on the 32-bit arm, which
`test/widemul-builds.sh` catches (INV-41 and INV-16 in
docs/invariants.md). Forty-one hold the signer: three break a value and
`bin/rsa_sign_equiv_test` catches each; twenty-one drop a wipe, one for
each wipe of the two files, and the same binary's copy of the stack
catches each; one keeps a digit of the exponent in a frame, which that
binary's two stacks catch; three break the check of a signature or the
key test, which `bin/rsa_sign_test_host` catches; two leave one byte or
one word out of a comparison, which the `rsa_sign64_crt` proof catches;
six change the read of the table, by its subscript, its scan, its masks
or the zeros it does not write, which `lint-invariants` catches; three
invert a dispatch, which `bin/widemul_runtime_test` catches; one adds a
difference's modulus back by a branch, which `lint-wide-multiply`'s
count catches; and one puts the signer in a device object, which
`lint-trust-separation` catches (INV-41, INV-42, INV-16 and INV-17).

### The AVX-512 IFMA public operation

`rsa_ifma.c` runs RSA's public operation in digits of 52 bits, eight to
a 512-bit register, on AVX-512 IFMA (decision 119). `rsa_mont.c`'s
`rsa_vp1_cpu` calls it on x86-64 for a session whose `ch_cfg.cpu` holds
`CH_CPU_AVX512_IFMA` and an odd modulus whose bit length is a multiple
of 64, at least 2,048, with 2^(104n) mod m from `power_of_two_mod`.
For every input it must write the bytes `rsa_vp1` writes.

CBMC and Lean prove parts of the arithmetic over the lane model below,
and nothing proves the instructions equal to that model. CBMC cannot
read an intrinsic, so the [rsa_ifma](#rsa_ifma) harnesses compile
`rsa_ifma.c`'s own text over `test/rsa_ifma_model_lanes.h`, with each
lane multiplication a contract that `rsa_ifma_lanes` discharges on the
model. They prove that `rsa_ifma_public` and each copy of the product
read and write inside their arrays at every register count, that no sum
in the product or in `normalize_digits` wraps at one and two registers,
and that `power_of_two_mod` reads and writes inside its arrays at the
exponents `rsa_vp1_cpu` passes. They prove no value.

[`spec/lean/Spec/RsaIfma.lean`](../spec/lean/Spec/RsaIfma.lean) models
the product round by round as the C runs it, and `normalize_digits`
register by register with the C's masks, on whole numbers. Its theorems
state that:

- a product of operands below 2m is below 2m, and is a b / 2^(52n)
  mod m, for an m0inv with m0inv × m + 1 a multiple of 2^52;
- every lane stays at or below 2^61, and `digit_zero` below 2^62, for up
  to 128 rounds;
- `normalize_digits` writes digits below 2^52 that hold the number it
  was given modulo 2^(52 × lanes);
- the steps of `power_of_two_mod` from its start bit give 2^e mod m,
  where each step computes rem × 2^64 mod m;
- the chain `rsa_ifma_public` runs, a product, sixteen squares, a
  product and one subtraction of m, writes base^65537 mod m for every
  base below 2^(64k).

`bin/diff_rsa_ifma`, in `make diff`, holds the C over the lane model to
the spec's operations in 3,626 comparisons: every lane of products at
every word count from 32 to 64, powers of two, public operations, each
product of the chain at 32, 48 and 64 words, `normalize_digits` on
lanes chosen for its carries, and the signer's exponentiations
([The AVX-512 IFMA signer](#the-avx-512-ifma-signer)). It checks on each row that the C's m0inv
meets the theorems' hypothesis, which no proof covers. No proof drives
`rsa_vp1_cpu`, and the spec states the division in each step of
`power_of_two_mod`, the conversions between words and digits and the
last subtraction on whole numbers. Every claim below about the
instructions rests on a test.

What the kernel computes rests on these:

- `bin/rsa_ifma_model_test` and `bin/rsa_ifma_model_test_384`, in `make
  check` and `make san-check` on every machine. The first builds at the
  512-byte bound, where the kernel has copies of the product for five to
  ten registers, and the second at the 384-byte bound, which every host
  object but a `TRUST=webpki` one compiles, with copies for five to
  eight. `test/rsa_ifma_model.c` compiles `rsa_mont.c` and
  `rsa_ifma.c` under `CH_RSA_IFMA_MODEL` and second names, so
  `rsa_ifma.c` includes `test/rsa_ifma_model_lanes.h`, each lane operation
  written in portable C from Intel's pseudocode, in place of the
  instructions. At every word count from 32 to the bound's 64 or 48, so
  at every register count the build has a copy for, under random odd
  moduli with the top bit set, 2^(64k) - 1, 2^(64k - 1) + 1 and, at an
  even count, (B^(k + 1) + 1) / (B + 1), it requires `rsa_vp1`'s bytes
  from `rsa_vp1_cpu` under the bit and under `CH_CPU_PROBED` alone for
  the signatures 0, 1, m - 1 and random ones, and the known answer for
  the first three. It counts the calls `rsa_vp1_cpu` makes into
  `rsa_ifma_public`, through `test/rsa_ifma_model.c`'s count, and
  requires one under the bit and none without it. It requires
  `rsa_mont64_public`'s bytes from `rsa_ifma_public` for bases at or
  above m, which no verifier passes, under a power of two it computes by
  doublings that share nothing with `rsa_mont.c`'s division. For each
  product along a public operation, and for products of operands up to
  2m, it requires every digit below 2^52, zeros from digit n up and a
  number below 2m. It hands an even modulus, one whose top bit is clear,
  one of 31 words and one of 260 bytes to `rsa_vp1_cpu` under the bit,
  and requires `rsa_vp1`'s bytes and no call into the kernel. It runs
  `normalize_digits` alone on 20,000 sets of lanes chosen for its
  carries, one to ten registers at the 512-byte bound and one to eight
  at the 384-byte bound, which random products almost never give it: the
  number must stay the same modulo 2^(52 × lanes), and every digit must
  end below 2^52. That is 31,340 checks at the 512-byte bound and 25,868
  at the 384-byte bound under the default seed, which
  `CH_RSA_EQUIV_SEED` replaces.
- `bin/rsa_ifma_equiv_test`, in `make check` and `make san-check`,
  holds the instructions to that model on an x86-64 CPU with AVX-512
  IFMA. It compares each lane operation over 2,000 sets of lanes that mix
  random words, words at and around 2^52 and lanes equal to the other
  operand's, under random mask bits; `normalize_digits` over 5,000 sets
  at every register count up to ten; and the conversions between words
  and digits at every word count. Under the moduli above, at every word
  count from 32 to 64, it compares products of operands below m and up
  to 2m in every lane, and `rsa_ifma_public`'s bytes for bases below and
  above m, and requires `rsa_vp1`'s bytes from `rsa_vp1_cpu` under the
  bit. On arm64 it says the kernel is x86-64 only. On an x86-64 CPU
  without AVX-512 IFMA it skips, and fails instead under
  `CH_REQUIRE_AVX512_IFMA=1`.
- CI's `check` job runs `make check` on an x86-64 runner. There the
  binary above, `bin/rsa_test_host` and `bin/rsa_pkcs1_test_host` under
  0x10d, the host Wycheproof binary under 0x11f and the `ch_srv_check`
  rows of `bin/tcp_blocking_loop_aes`, under every bit the architecture
  defines, run the kernel when the runner's CPU has AVX-512 IFMA, and
  skip it when it does not.
- The nightly's `rsa-ifma-sde` job runs `make rsa-ifma-sde-check` under
  Intel SDE, pinned and checked against its SHA-256 in
  `tools/toolchain.env`, on SDE's model of an Ice Lake server, which has
  AVX-512 IFMA. With `CH_REQUIRE_AVX512_IFMA=1` it runs
  `bin/rsa_ifma_equiv_test` and `bin/x86_kernels_test`; the two RSA
  vector binaries under 0x10d and the host Wycheproof binary under 0x11f,
  with `CH_REQUIRE_X86_KERNELS=1` too, so that a model without AVX2 or
  VAES fails them rather than skips the value; and `bin/webpki_loop_aes`
  with both ends stating 0x101 and then 0x13f, every x86-64 bit, whose
  server's `ch_srv_check` verifies an RSA-PSS signature on the kernel
  before a handshake. Each run must exit 0 and print the line its binary
  prints when every check passed, so an `sde64` that exits 0 without
  starting the program fails the job. SDE is an emulator: the job shows
  what the instructions compute, and nothing about how long they take on
  any CPU.

Which calls run it rests on `bin/x86_kernels_test`,
`bin/tcp_blocking_loop_host` and `bin/webpki_auth_host`, which count the
calls each value and each caller sends to it on a stand-in that runs
`rsa_mont64.c`, and on `test/aes-runtime-qemu.sh`'s two rows of the
webpki loop on a QEMU model without AVX-512 IFMA
([The x86-64 kernels](#the-x86-64-kernels)).

The build rests on these:

- `test/widemul-builds.sh`, in `make check`, compiles `rsa_ifma.c` and
  `rsa_mont.c` for x86-64 and arm64 under the pinned clang with no
  instruction flag. It requires the x86-64 object to define
  `rsa_ifma_public` on 512-bit registers with VPMADD52LUQ and
  VPMADD52HUQ, and the arm64 object to define nothing. It requires the
  x86-64 `rsa_vp1_cpu` to call the kernel, and neither the x86-64
  `rsa_vp1` nor the arm64 `rsa_vp1_cpu` to call it. It requires no
  512-bit register in `rsa.c`, `rsa_pkcs1.c`, `rsa_mont.c`,
  `rsa_mont64.c`, `rsa_mont64_blocks.c`, `rsa_sign.c` or `rsa_sign64.c`
  for x86-64. It requires no root source but `rsa_mont.c` that calls
  `rsa_ifma_public`, and none but it and `rsa_ifma_sign.c` that includes
  `rsa_ifma.h`, so the signer's check runs the kernel through
  `rsa_vp1_cpu` alone.
  It refuses a root source that defines `CH_RSA_IFMA_MODEL`, and a host
  object's defines from make or `build.zig` that name it.
- `make lint-wide-multiply` holds `rsa_ifma.c` at 19 conditional
  branches under clang for x86-64 at the 384-byte bound, and, as
  `rsa_ifma.c@512`, at 23 at the 512-byte bound, whose copies for nine
  and ten registers the first build does not compile. Each branch tests
  a count or an index. It holds both at 0 for arm64, where the file
  compiles to nothing, and at no division and no 128-bit runtime call.
  Both counts read clang alone. gcc's code for the file is held by the
  tests in this section, and its frames by the `lint-stack` of CI's
  x86-64 `check` job.
- `test/zig-build-check.sh`, in `make check`, builds colibri's HTTP/2
  object with `build.zig` for x86-64's baseline CPU, which has no
  AVX-512, on every machine. The file compiles there only because
  `build.zig` adds the evex512 feature to an x86-64 host object's
  target (decision 119).

Twenty-six violations break the kernel, its dispatch or its build, and
each is caught. `bin/rsa_ifma_model_test` catches fifteen on every
machine: `inv41-rsa-ifma-digit-zero-dropped`,
`inv41-rsa-ifma-high-pass-reads-a-for-m`,
`inv41-rsa-ifma-quotient-unmasked`, `inv41-rsa-ifma-power-skips-r2`,
`inv41-rsa-ifma-words-drop-third-digit`, the four that break a carry of
`normalize_digits`, `inv41-rsa-ifma-normalize-drops-generate-from-below`,
`inv41-rsa-ifma-normalize-drops-carry-between-registers`,
`inv41-rsa-ifma-normalize-carries-skip-propagate` and
`inv41-rsa-ifma-normalize-keeps-top-carry`, and the four in `rsa_mont.c`,
`inv41-rsa-mont-ifma-power-52n`,
`inv41-rsa-mont-ifma-power-one-step-short`,
`inv41-rsa-mont-ifma-power-starts-at-bit-zero` and
`inv41-rsa-mont-ifma-takes-even-modulus`, and the two whose `use_ifma`
answers 1 or 0 for every value, `inv41-rsa-ifma-runs-without-cpu-bit`
and `inv41-rsa-ifma-ignores-cpu-bit`, through its count of the calls
into the kernel. `bin/rsa_ifma_model_test_384` catches
`inv41-rsa-ifma-eight-register-copy-takes-a-for-b`, whose switch hands
the copy for eight registers a in place of b: it compiles with no
warning, because the other cases still read b. `test/widemul-builds.sh`
catches five: `inv41-rsa-ifma-model-in-library`, which writes
`CH_RSA_IFMA_MODEL` for every host object;
`inv41-rsa-ifma-without-target`, which drops the target attribute, so
the file no longer compiles with no instruction flag;
`inv41-rsa-sign64-includes-rsa-ifma` and
`inv41-rsa-sign64-checks-on-rsa-ifma`, whose signer includes
`rsa_ifma.h` or checks its signatures on the kernel through a
declaration of its own; and `inv16-device-object-holds-rsa-ifma`, which
lists the file in a device object. The proofs catch five:
`rsa_ifma_sums` catches `inv41-rsa-ifma-digit-zero-keeps-low-bits`,
whose round keeps the low bits of its scalar sum in `digit_zero`;
`rsa_ifma_public_5` catches `inv41-rsa-ifma-reads-word-past-count`,
whose `words_to_digits` reads one word past the count; `rsa_ifma_lanes`
catches `inv41-rsa-ifma-model-high-half-from-bit-51`, whose model of
VPMADD52HUQ adds the bits from 51 up; `rsa_mont_power` catches
`inv41-rsa-mont-power-start-past-top-word`, whose `power_of_two_mod`
writes its start bit one word above the top; and `bin/diff_rsa_ifma`
catches `inv41-rsa-ifma-normalize-generate-from-bit-six`, whose
`normalize_digits` hands each register bit 6 of the generate mask below
it in place of bit 7. Five more hand a verifier 0 in place
of a session's value, and `test/docker-aes-runtime-qemu.sh
rsa-ifma-callers` catches each ([The x86-64 kernels](#the-x86-64-kernels)).
`test/zig-build-check.sh` catches `inv36-zig-x86-64-host-drops-evex512`,
which takes evex512 off `build.zig`'s x86-64 target.

What none of this shows:

- That a model function equals its instruction for every input. The two
  are compared on the inputs `bin/rsa_ifma_equiv_test` runs, and only on
  a CPU with AVX-512 IFMA or under SDE. On any other machine the kernel's
  text runs over the model alone.
- That the C over the model computes what the Lean model computes for
  every input. `bin/diff_rsa_ifma` compares them on samples.
- That no sum wraps at five to ten registers in the C. CBMC proves it at
  one and two, and Lean proves the lanes' bound on its model of the
  rounds, for up to 128.
- Anything about time. None is claimed: the inputs are public, and the
  bit states presence alone.
- The CA client's CertificateVerify under `TRUST=ca-rsa`, which only a
  `ROLE=both TRUST=ca-rsa` host object compiles with the kernel: no host
  binary builds that object, so no row counts its call.

### The AVX-512 IFMA signer

`rsa_ifma_sign.c` runs RSA signing's two exponentiations, m1^dp mod p
and m2^dq mod q, in digits of 52 bits on AVX-512 IFMA, on the product
`rsa_ifma.c` runs (decision 120). `rsa_sign64.c` calls it on x86-64 for
a session whose `ch_cfg.cpu` holds `CH_CPU_AVX512_IFMA` and
`CH_CPU_CONSTANT_TIME_MULTIPLY`, checks each signature on `rsa_ifma.c`
through `rsa_vp1_cpu`, and after each of the two calls wipes the stack
below it and the vector registers. For every key and every message it
must write the bytes `rsa_sign64.c`'s window writes, and leave no word it
computed from the key on the stack below its caller or in a vector
register.

CBMC and Lean prove parts of it over the lane model, and nothing proves
the instructions equal to that model. The [rsa_ifma_sign](#rsa_ifma_sign)
harnesses compile the file's own text over `test/rsa_ifma_model_lanes.h`.
They prove the memory accesses of each copy of the pair at every register
count, of `state_setup` and `state_finish` at every prime word count and
of the whole exponentiation at the smallest and the largest, that
`table_select` writes the digit's entry to every lane, that the two
conversions between words and digits are inverse, and that the wipe below
the caller clears its whole array. [rsa_sign64](#rsa_sign64)'s
`rsa_sign64_ifma` proves that `rsa_sign64.c`'s arm hands the kernels the
key's integers and wipes after each call.

[`spec/lean/Spec/RsaIfma.lean`](../spec/lean/Spec/RsaIfma.lean) models
the exponentiation on its model of the product as the C runs it: the
doublings of `state_setup`, a table of sixteen entries each the one
before it times entry 1, four squares and a product by the digit's entry
for each digit, and the last product by R mod m. Its theorems state that:

- `windowPower_eq`: the window raises the base to the number the
  exponent's digits hold, on any product below 2m whose result is
  a b / w modulo m, which `product_lt` and `product_mul` show the
  kernel's product is;
- `windowValue_bytes`: the digits `table_select` reads, the high half of
  each byte and then the low half, hold the number the exponent's bytes
  hold;
- `signPower_eq`: for the base b R mod m in `rsa_mont64.c`'s domain,
  R = 2^(64k), and R mod m beside it, the exponentiation writes
  b^e R mod m, for an m below 2^(64k), m0inv the C's -m^-1 mod 2^52 and
  at most 128 digits.

`bin/diff_rsa_ifma`, in `make diff`, holds the C over the lane model to
that model: at every prime word count from 16 to 32 a call of the pair on
a random base and a random exponent of 4 bytes beside a random second
prime; at the word counts where the register count changes, at
RSA-3072's 24 and at the first and the last, the same under each other
kind of modulus, and the bases 0, 1 and m - 1 with the exponents of all
ones, all zeros and 1; and at RSA-2048's prime a random exponent of the
128 bytes `rsa_sign64.c` passes. Each call's two halves are a row each,
130 rows in all. The spec takes about 3 ms a product at 32 words, so most
rows use exponents of 4 bytes, eight digits, which run the table, the
squares and every kind of step. Every claim below about the instructions
rests on a test.

What the kernel computes rests on these:

- `bin/rsa_ifma_sign_model_test` and `bin/rsa_ifma_sign_model_test_384`,
  in `make check` on every machine, compile `rsa_ifma_sign.c`,
  `rsa_sign64.c`, `rsa_ifma.c` and `rsa_mont.c`'s dispatch under
  `CH_RSA_IFMA_MODEL`. They hold the pair to two calls of
  `rsa_sign64_power` at the first and the last prime word count of each
  register count, under moduli of four shapes, the bases 0, 1, m - 1 and
  random ones, and exponents of all zeros, all ones, 1, every digit value
  in turn and the top bit alone, with each output on a base of its own
  and written over its base. They hold `rsa_sign64_sp1` under the IFMA
  value to the same call under the multiply bit alone for the keys of
  `test/rsa_sign_vectors.h` the build takes, require one call into the
  pair and two wipes of the stack below from each signature under the
  IFMA value and none under any other, and require a key with one bit of
  dp changed refused with the signature untouched. They run
  `state_finish` on powers at or above 2^(64k), which only the word above
  the k words holds. That is 3,022 checks at the 512-byte bound and 1,744
  at the 384-byte bound.
- `bin/rsa_ifma_sign_equiv_test` and its `_384` twin run the same
  comparisons on the instructions at every prime word count, 7,022 and
  3,744 of them, on an x86-64 CPU with AVX-512 IFMA.
- `bin/rsa_sign_equiv_test`, on such a CPU, signs on the kernel beside
  the ladder and prints a line that says it did.
- `bin/rsa_ifma_sign_residue_test` and its `_384` twin, on such a CPU,
  measure how far below its caller the pair and the check write and
  require the wipe to cover it, and search the stack below each call and
  zmm0 to zmm31 after it for every word the call computed from the key:
  24 checks at the 512-byte bound and 16 at the 384-byte bound.
- Each of the four binaries above skips on an x86-64 CPU without AVX-512
  IFMA, and fails instead under `CH_REQUIRE_AVX512_IFMA=1`. The nightly's
  `rsa-ifma-sde` job runs each under SDE with that variable and requires
  its pass line, beside the RSA vector binaries, the Wycheproof host
  binary and the webpki loop, whose values hold the multiply bit and
  `CH_CPU_AVX512_IFMA`, so their signatures run the kernel too.
- Run 37999949864 ran the model, equivalence and residue binaries,
  `bin/rsa_sign_equiv_test` and `bin/x86_kernels_test` on three runners
  whose CPUs have AVX-512 IFMA, an EPYC 9V45, a Xeon Platinum 8573C and
  an EPYC 9V74, under gcc 13.3 and clang 23, and each passed. Run
  38004528544 ran the nightly's `rsa-ifma-sde` job on four runners of a
  throwaway branch, an EPYC 7763 without AVX-512 and a Xeon Platinum
  8370C and two EPYC 9V74s with it, and each run printed every binary's
  pass line.

Which calls run it rests on `bin/x86_kernels_test` and
`bin/tcp_blocking_loop_host`, which count the calls each value and each
caller makes into the pair, the check's kernel and the two wipes
([The x86-64 kernels](#the-x86-64-kernels)).

The build rests on these:

- `test/widemul-builds.sh`, in `make check`, requires the x86-64 object
  of `rsa_ifma_sign.c` to define `rsa_ifma_sign_power_pair` on 512-bit
  registers with VPMADD52LUQ and VPMADD52HUQ, and the arm64 object to
  define nothing. It requires `rsa_sign64.c` for x86-64 to call the
  pair, the wipe below, `avx512_wipe_registers` and `rsa_vp1_cpu`, and
  for arm64 none of them, and no root source but `rsa_sign64.c` that
  includes `rsa_ifma_sign.h` or calls into the file.
- `make lint-wide-multiply` holds `rsa_ifma_sign.c` at 24 conditional
  branches under clang for x86-64 at the 384-byte bound and 27 at the
  512-byte bound, and `rsa_sign64.c` at 29, each a test of a count, an
  index or a `CH_ASSERT`, and both files at 0 for arm64.
  `inv-16-rsa-ifma-table-read` refuses a `table_select` that keeps an
  entry by any means but the mask it reads back through its volatile
  word.
- `make lint-stack` holds the file's frames under 21,504 bytes, which
  holds the wipe's array of 20,480.

Twenty violations break the kernel, its dispatch, its wipes or its
build, and each is caught (INV-41, INV-42 and INV-16 in
docs/invariants.md). `bin/rsa_ifma_sign_model_test` catches nine on
every machine: five that break a value, two that make `use_ifma` read
one bit, and two that leave out a wipe of the stack below.
`bin/x86_kernels_test` and `bin/tcp_blocking_loop_host` catch three,
under `test/docker-aes-runtime-qemu.sh`: a signer that leaves out the
wipe of the registers, a check on the loops, and a server that signs
under 0. `test/widemul-builds.sh` catches the file without its target
attribute, and `lint-invariants` two reads of the table that a compiler
may turn into a branch. The proofs catch four: `rsa_ifma_sign_select` a
read that stops one register short, `rsa_ifma_sign_setup` a finish whose
array has no word above the k words, `rsa_ifma_sign_power` a step past
the exponent's end, and `rsa_sign64_ifma` a second half raised to dp.
`bin/diff_rsa_ifma` catches a read of each byte's low half first.

What none of this shows:

- That a model function equals its instruction for every input, as for
  the public operation.
- That the C over the model computes what the Lean model computes for
  every input. `bin/diff_rsa_ifma` compares them on samples.
- That the wipes clear every copy. The residue test searches for the
  words it knows on the CPUs and compilers it ran on; a compiler that
  writes further below its caller than `RSA_IFMA_SIGN_BELOW_LEN` would
  leave words below the wipe's array, and the test's depth check would
  then fail.
- Anything about time. The kernel's timing rests on the caller's
  multiply bit, whose statement covers IFMA's 52-bit products, and on
  the code's shape: every branch and every memory index depends on a
  count, an index or the exponent's length. No test here measures it.

### The host object's description of the CPU

On arm64 and x86-64 a `TRUST=webpki` client, `ROLE=server` and
`ROLE=both` build a host object, `-DCH_CPU_RUNTIME`, whose sessions take
the caller's description of its CPU in `ch_cfg.cpu` (decision 89).
Twelve harnesses compile the define, each named in its own entry above.
One of them, `quic_config_webpki_suite`, proves that `ch_quic_init`'s
configuration check returns `CH_OK` only for a field `cpu_bits_ok`
admits ([quic_config_webpki](#quic_config_webpki)). No harness drives the
other init calls or `ch_srv_check`, so no proof covers the rule at those
calls. Tests hold it at every one:

- `bin/tcp_blocking_loop_host`, `bin/tcp_nonblocking_loop_host`,
  `bin/quic_loop_host` and `bin/webpki_session_host`, in `make check`,
  compile their loop or session as a host object and run every case with
  both ends' fields set. Their rows refuse 0, every defined bit but
  `CH_CPU_PROBED`, a bit no architecture defines and, on arm64, each
  x86-64 bit, at every init call and `ch_srv_check`, and take the probe's
  bit alone and every bit the architecture defines.
- `test/host-builds.sh` holds the host test in `cpu_cfg.h`, the Makefile
  and `build.zig` against this host's compiler and the pinned clang's
  cross targets, and `lint-trust-separation` holds which products build
  the host object.

### The subjectAltName walk against a full-length hostname

`webpki_name` proves the `TRUST=webpki` per-entry dNSName compare with
the host at its real 253-byte bound and the presented name at 1024
bytes. `webpki_san` proves the walk over a whole GeneralNames with a
host of at most 16 bytes. One formula holding both wrote a 7.9 GB CNF at
a 64-byte GeneralNames, because every entry of the walk repeats the
compare against the whole host. No proof covers the two together.

The argument that they compose is that the walk passes host and
host_len to the compare without change and reads no byte of host. That
is a fact about a twenty-line function, checked by reading, not by a
solver. `test/diff_webpki.h` adds evidence: it compares the walk with
the Lean model over hosts and presented names drawn from the seven-byte
alphabet that file names.

The clock packer's order, a later clock never packing lower, has the
same kind of evidence: `Spec.WebpkiTime.packSeconds_mono` and the same
differential, as the [webpki_time](#webpki_time) entry says.

### The extension walk over a full-size extensions field

The `TRUST=webpki` pieces that read one element are proved at the real
1024-byte bound. A proof that composes them unrolls every reader below
it, because a harness cannot replace the walk's statics with their
contracts: `webpki_ext_one` judges one Extension of at most 96 bytes,
and `webpki_ext_walk` walks a field of at most 48 bytes. The S3 leaf's
subjectAltName Extension alone is 653 bytes.

The argument for any length is induction over the per-element contracts
the pieces prove (the position moving forward and never past the end,
with err clear), checked by reading. `webpki_ext_walk` also starts its
reader at the buffer's first byte, where `webpki_parse_certificate`
hands it a reader in the middle of the TBS; the walk reads its bytes
only through rbuf, which reads at `p + off` either way. `webpki_cert`
stubs the walk to the contract `webpki_ext_walk` proves, so the
certificate parser inherits both gaps.

`test/webpki_cert_test.c` and `test/diff_webpki_cert.h` add evidence:
every corpus and captured certificate, boundary mutants at each cap,
single-byte changes and random extension lists, against the Lean model.

### Which chains the TRUST=webpki walk accepts

`webpki_chain` proves the walk memory-safe and UB-free over any entry
list and any anchors, and proves the shape of what it returns. But its
stubs for `webpki_verify` and `webpki_match_san` answer an unconstrained
verdict, so the formula says nothing about which chains end in
`CH_OK`. Putting the real verifiers in the formula would put an RSA and
two ECDSA verifications inside it, which no harness in this tree
converges on.

`Spec.Webpki.verifyChain_ok` states the property instead, and Lean's
kernel checks that proof. An accepted chain has a verified signature
path to an anchor, and its leaf matched the caller's hostname through a
dNSName of its own subjectAltName. Every step of the path is:

- parsed under the issuer arm;
- covering the clock;
- named by the certificate below it;
- inside its own pathLenConstraint.

`test/webpki_chain_test.c` and `test/diff_webpki_chain.h` add evidence
at the bytes: the 25 minted chains, the 5 captured ones, and their
clock, hostname, anchor, entry and byte mutations.

### The quality of the random bytes

This rests on nothing here at all. The source, `ch_rand_bytes` or
under `RAND=session` each session's `cfg.rand_bytes`, is the image's to
supply, and no check in a library can grade it: a weak generator
completes the handshake, sends a key share that looks uniform on the
wire, and returns `CH_OK`.

Two things narrow the gap, and neither closes it:

- The build makes the choice explicit instead of silent: `RAND=extern`,
  `RAND=drbg` or `RAND=session`, with no default.
- Every draw site INV-4 lists refuses an all-zero draw, which catches a
  source that returned without writing.

What the tests do show is where the bytes come from. Under
`RAND=session` the loop tests count every draw against the source its
session names, and replay a connection byte for byte from two seeds
(INV-4).

A weak generator passes both. [`docs/entropy.md`](entropy.md) covers the
rest.

## More evidence on every push

Three more suites run on every push and add evidence rather than proof.

### Wycheproof

[Wycheproof](https://github.com/C2SP/wycheproof)'s attack-derived cases
(`make wycheproof`), 5,967 across:

- x25519 and ECDH over P-256;
- ChaCha20-Poly1305, AES-128-GCM and AES-256-GCM;
- HKDF-SHA256, HMAC-SHA256, HKDF-SHA384 and HMAC-SHA384;
- ECDSA over P-256 and P-384, at every digest length a certificate
  signature can pair with either curve;
- RSA-PSS and RSA PKCS#1 v1.5 verification, up to RSA-4096, and
  RSA-PSS signing;
- ML-KEM-768.

`make check` fails when that total differs from the sum of the vectors
`make wycheproof` generates (`tools/wycheproof-total.py`).

The x25519 suite's 518 cases run a second time over the wide X25519
field, in the host Wycheproof test's runs with the multiply bit. The
ChaCha20-Poly1305 suite's 316 cases run over the vector ChaCha20 in
every run of that test, and over the vector Poly1305 in its runs with the
multiply bit.

The HMAC-SHA256 suite calls `hmac_sha256` directly. So the MAC that
Finished, the binders, the QUIC Retry token, the HelloRetryRequest
cookie and the webpki ticket binding compute is tested on its own and
not only through HKDF.

The same lane signs every P-256 message in that corpus with `p256_sign`
and hands the result to `p256_ecdsa_verify`, which shares no arithmetic
with the signer. Wycheproof publishes no ECDSA signing vectors, so the
signer's known answers are RFC 6979 A.2.5 and Python's integers in
`test/p256_sign_test.c`.

Wycheproof tests no plain hash, so SHA-384 and SHA-512 rest on the
FIPS 180-4 examples and RFC 6234 §8.5 in `test/sha512_test.c`, with the
padding and block boundaries of the 128-byte block checked either side.

### Sanitizers

AddressSanitizer and UndefinedBehaviorSanitizer run over every
deterministic suite (`make san-check`), with a committed canary proving
the sanitizer is armed. The lane compiles each suite from the variable
the suite's own rule reads, which `make check` builds, so a source the
suite comes to need fails check before it fails the lane (INV-40).

### Line coverage

Line coverage is measured in CI, and the job fails below the Makefile's
`COVERAGE_FLOOR`.

## The differential oracle

[`spec/lean/`](../spec/lean/) is an executable
[Lean 4](https://lean-lang.org/) specification of everything chapulin
computes:

- SHA-256, SHA-384 and SHA-512, SHA-3 and both SHAKE XOFs;
- ML-KEM-768;
- HKDF and the key schedule;
- ChaCha20, Poly1305 and the AEAD;
- the DRBG;
- record framing;
- x25519;
- the AES-128 and AES-256 forward cipher of FIPS 197, AEAD_AES_128_GCM,
  AEAD_AES_256_GCM and the GHASH under them (NIST SP 800-38D);
- the QUIC packet protection keys of a `TRANSPORT=quic-nonblocking`
  build in QUIC version 1 and version 2 (RFC 9001, RFC 9369): the
  Initial keys, the keys a traffic secret derives, the key update, and
  the Retry integrity tag;
- P-256 and RSA-PSS, and the doubling and the incomplete addition a host
  object's P-256 runs;
- the grammar of the four handshake messages a server sends;
- the content a server's CertificateVerify signs (RFC 9846 §4.5.2),
  which the driver hashes under the signature scheme and compares with
  the digest `hsa_hash_signed_content` writes;
- the provisioning path: RFC 7468 armour with RFC 4648 base64, and the
  certificate walk that turns one PEM block into the key bytes a pin
  slot takes;
- the ca modes' revocation epoch;
- for `TRUST=webpki`, the public-key and signature-algorithm readers,
  the certificate signature verify over RSA PKCS#1 v1.5, P-256 and
  P-384, the one-certificate parser with its extension walk, the Time
  reader, hostname matching, the chain walk, and SPKI pins with RFC 7250
  raw public keys;
- the plaintext `ch_writable_len` lets one `ch_write` seal into `cap`
  bytes of records.

It follows the RFC text and never the C, because a differential oracle
only works when a shared misreading cannot make both sides agree. There
are five exceptions. `Spec/TlsWrite.lean` models `ch_writable_len` from
`tls_write.c` line by line: its theorems bound that code's own
intermediate values, which no RFC states. `Spec/P256WidePoint.lean`
models `p256_wide_point_add_affine_incomplete`, the Jacobian doubling,
the incomplete Jacobian addition and the two conversions the same way:
its theorems say what that code's steps compute, and no standard states
those steps. `Spec/P256WideInverse.lean` models the rounds of
`p256_wide_inverse.c`, whose bound no standard states either.
`Spec/RsaIfma.lean` and `Spec/Poly1305Ifma.lean` model the AVX-512 IFMA
kernels of `rsa_ifma.c` and `poly1305_ifma.c` the same way.
[`spec/lean/CONTRACT.md`](../spec/lean/CONTRACT.md) says why that is
safe.

### What `make diff` runs

`make diff` builds the spec, runs its selftests, and then drives
comparisons between the C and the spec over a pipe, from a fixed seed:

1. 22,034 random-input comparisons, the SHA-384 rows of HMAC, HKDF,
   `expand_label` and the key schedule included, 406 rows of the
   CertificateVerify signed content, and 791 rows of `ch_writable_len`'s
   arithmetic.
2. The `TRANSPORT=quic-nonblocking` rows, 1,095 over the AES-128 and
   AES-256 blocks, AES-128-GCM, AES-256-GCM and GHASH, and in both QUIC
   versions the Initial keys at every connection ID length for both
   endpoints, 40 traffic secrets' packet keys, 40 key updates and the
   Retry tag at every pseudo-packet length up to 80 bytes, three times:
   - under the build's `AES` value;
   - in a QUIC host object, on the instructions and the carry-less
     multiply, where the compiler passes the host test;
   - under `AES=extern`, through the stand-in hook
     `test/aes_extern_hook.c`.
3. The x25519 rows, ten times over the wide X25519 field, 1,501
   comparisons, where the compiler passes the host test. The spec
   computes over natural numbers mod p, so one model serves both fields.
4. The wide P-256 rows, 4,327 comparisons, where the compiler
   passes the host test: 25 key generations, signatures and key
   exchanges through `p256_ecdh_keygen`, `p256_sign` and `p256_ecdh`
   under each answer, so the wide P-256 files and the 32-bit files each
   answer the spec. The key generation must write the spec's public
   key. The spec's verifier must accept the signature and refuse it for
   a hash with one byte changed. The key exchange with the spec's point
   b G must give the X coordinate of the spec's (a b) G. Then 75
   incomplete mixed additions through
   `p256_wide_point_add_affine_incomplete` against
   `Spec/P256WidePoint.lean`'s `addAffineIncomplete`, coordinate for
   coordinate: 25 on random coordinates, 25 at Z = 0, and 25 at Z = 1
   with the two x equal. Then the key exchange's routines against the
   model's: 50 conversions to Jacobian coordinates, 25 on random
   coordinates and 25 at Z = 0; 75 conversions back, the same and 25 at
   Z = 0 with Y = 0; 125 doublings, 25 on random coordinates and 25 each
   where Z, Y, X - Z^2 and X + Z^2 is zero; and 125 incomplete
   additions, 25 on random coordinates, 25 each at Z1 = 0 and at Z2 = 0,
   25 with the same x and Z, and 25 on one point twice. Then 1,838
   inverses through `p256_wide_inverse` against `Spec/P256WideInverse.lean`'s
   `inverse`, 919 at the field prime and 919 at the group order: 0 to 3
   and m - 1 to m - 3, every power of two and every power of two less one
   below 2^256, and 200 random values below m, each whole and cut to a
   random length. Each runs with the answer apart from y and over it.
   Then the same 1,838 through `p256_wide_inverse_public` against
   `inversePublic`.
5. The AVX-512 IFMA rows, where the compiler passes the host test, on
   each kernel's text compiled over its lane model: `bin/diff_rsa_ifma`'s
   ([The AVX-512 IFMA public operation](#the-avx-512-ifma-public-operation)),
   and `bin/diff_poly1305_ifma`'s 4,001, which hold `compute_powers` and
   a group step to `Spec/Poly1305Ifma.lean` digit for digit
   ([The AVX-512 IFMA Poly1305](#the-avx-512-ifma-poly1305)).

`make diff-ecdsa`, `make diff-pq` and `make diff-webpki` rebuild the
same driver under `TRUST=raw-ecdsa`, `KEX=pq` and `TRUST=webpki`, whose
parsers take other arms, and the nightly runs them. `make diff-webpki`
builds a second binary under `-DCH_SUITE_AES_GCM` at `CH_TX_PT=16384`,
where the AES instructions exist, and only there do the
`ch_writable_len` rows take limits up to 2^14 and cross an AES-GCM
key's KeyUpdate record.

The spec depends on Mathlib, so run `lake exe cache get` inside
`spec/lean/` once after clone to download Mathlib's compiled files.
Until then, every spec target stops and names that command.

### Rows where the C answers first

Some rows are signatures the spec mints and the C must accept. The spec
holds the private keys and signs, and the C, which can only verify,
must accept every genuine signature and reject every mutated one.

About 730 rows feed the certificate parser generated DER: uniform
bytes, edits at random TLV sites, and leaves the spec re-signs. Nobody
knows those answers in advance, so the C answers first and the spec
must reproduce it. The provisioning rows work the same way, on
certificates the spec mints and the driver armours at every line width
the decoder admits.

Under `make diff`, 6,898 rows feed the `TRUST=webpki` certificate
parser: 4,282 from every corpus and captured certificate under both
arms and single-byte changes of them, and 2,616 random extension lists
inside one corpus certificate. Each reply
carries every field's offset into the certificate, so the C's pointers
are compared, not only its verdict.

### Theorems about the spec

The spec also carries theorems about itself, so an agreement between C
and spec transfers a proven fact rather than a matching answer. The
theorems constrain the model, not the C: they stop a spec regression
from quietly weakening the oracle.
[`spec/lean/CONTRACT.md`](../spec/lean/CONTRACT.md) lists them.

## Message sequences

The state machine gets the same treatment one level up.
[`spec/lean/Spec/Handshake.lean`](../spec/lean/Spec/Handshake.lean)
models the message-ordering rules as a step function, and
[`test/handshake_sequence_test.c`](../test/handshake_sequence_test.c)
enumerates every server message sequence the model admits: all eleven
letters to depth 5, and the six handshake letters to depth 6, in both
modes, 466,286 in all. It renders each as real records over a mock
transport, runs the real client, and requires its verdict to match the
model's.
[`test/handshake_sequence_shards.sh`](../test/handshake_sequence_shards.sh)
splits the run across N processes, one per core, where process K checks
every sequence whose index is K mod N, and it fails unless the N counts
add up to the whole enumeration.

The worst TLS bugs on record were ordering bugs of exactly this kind:
early-CCS, skipped Finished, the SMACK/FREAK class. Memory-safety proofs
and golden-path end-to-end tests both miss them.

## End-to-end runs

[`test/e2e.sh`](../test/e2e.sh) runs the real thing against real peers:
PSK, ticket resumption, and pinned handshakes on both pinned algorithms,
against OpenSSL 3 and Go, moving application data both ways. The
ca-mode clients run chain handshakes against OpenSSL, including CA slot
rotation.
