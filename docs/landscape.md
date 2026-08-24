# Embedded TLS landscape (surveyed 2026-08-14; completeness re-swept 2026-08-17)

Why chapulin exists: no shipping C TLS stack is simultaneously (a)
heap-free at few-kB SRAM, (b) TLS 1.3 PSK-minimal, and (c) carrying
machine-checked proofs. Each row below holds at most one of those.

## Direct competitors

**Mbed TLS** (Apache-2.0; 4.x split into TLS layer + TF-PSA-Crypto).
TLS 1.3 client/server incl. PSK modes. Best published TLS 1.3 PSK
numbers (Cortex-M4, [Restuccia et al.](https://arxiv.org/abs/2011.12035)):
~24 kB flash, 6.8 kB peak heap + 8.8 kB stack (~15.5 kB working RAM;
stack reducible to ~2.6 kB with small AES tables, so ~9.4 kB floor).
Cannot run without an allocator — the official fallback is a static-pool
allocator, still malloc semantics
([KB](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/using-static-memory-instead-of-the-heap/)).
Its shipped minimal-PSK example config is TLS 1.2 only. PQShield's
PQMicroLib (announced Embedded World 2026) sells drop-in post-quantum
TLS for embedded as an Mbed TLS integration — PQ crypto under 5 kB by
their claim, TLS layer and footprint are Mbed TLS's.

**wolfSSL** (GPLv3 since 5.8.2 — a licensing break from GPLv2 — or
commercial). The widely cited LeanPSK 20 kB build is TLS 1.2 only. TLS 1.3
PSK-only: "less than 50 kB" code, no RAM figure published
([wolfSSL](https://www.wolfssl.com/small-tls-1-3-psk/)); measured 6.2 kB
peak heap in the arXiv paper above. Static-memory mode exists, still
allocator semantics. wolfSSL's own answer to the minimal-client niche is
[wolfNanoTLS](https://github.com/aidangarske/wolfNanoTLS) (GPL-3.0,
created 2026-06): TLS 1.3-only, client-first, a zero-dynamic-allocation
mode — no published flash/RAM numbers yet, crypto inherited from
wolfSSL.

**BearSSL** (MIT). The closest design ancestor: zero malloc, constant-time
by default, ~25 kB RAM dominated by 16 kB record buffers. **Still no
TLS 1.3 in 2026** ([status](https://bearssl.org/tls13.html) unchanged
since ~2018); curl dropped it for that. Effectively frozen — this is the
gap chapulin fills.

**picotls** (MIT). TLS 1.3, built for H2O/QUIC servers; malloc-backed
growable buffers; no embedded footprint story.

**Mongoose built-in TLS** (GPLv2/commercial). TLS 1.3-only ECC stack,
~50 kB flash, "few kB RAM per connection"; certificate-based, no PSK
mode apparent; uses the enclosing allocator.

**SharkSSL** (commercial). "<20 kB" compiled, 13 kB RAM total-system
demo; cert-based, anti-PSK marketing. Smallest commercial claim.

**MatrixSSL** — TLS 1.3 complete but dormant (last release 2022).
**CycloneSSL** — TLS 1.0–1.3 + DTLS, no published numbers.

**embedded-tls** (Rust, MIT/Apache-2.0,
[drogue-iot](https://github.com/drogue-iot/embedded-tls)). TLS 1.3
client, no_std, no allocator, PSK — the closest architectural cousin.
Self-described work-in-progress, no proofs, no C ABI, no published RAM
figure beyond a user-supplied 16 kB frame buffer.

**krabitls** (Rust, Apache-2.0,
[kaidokert](https://github.com/kaidokert/krabitls-rs)). New (crate first
published 2026-06): TLS 1.3-only client, optional DTLS 1.3, and it
publishes real numbers — .text 37.5–96.2 KiB and peak stack
9.7–111.6 kB depending on the algorithm set. The most serious new
entrant; still 3–10x chapulin's stack and no proofs, no C ABI.

**NetX Duo Secure** (MIT since the 2024 move to Eclipse ThreadX;
ex-Express Logic/Azure RTOS). TLS 1.2 + 1.3 client/server built for
MCUs; configuration knobs to shrink RAM (single-hash builds), but no
TLS-specific ROM/RAM numbers published. The established stack this
survey originally missed.

**Tuxera TLS module** (commercial; ex-HCC Embedded, which also absorbed
InterNiche). Standalone MISRA C:2012-compliant TLS 1.3 module for MCUs
with or without an RTOS, ~20 kB ROM / ~8 kB RAM at its 2020 launch;
ISO 26262-ready variant. Assurance story is process compliance (MISRA
report), not proofs.

**SEGGER emSSL** (commercial). The best published commercial footprints:
17–43 kB ROM, static RAM "tens of bytes" plus ~1.5 kB per connection —
but the headline minima are for legacy suites (RC4, CBC-SHA1), and per
its own manual (v3.10.0, 2025-07) it is TLS 1.0–1.2 only. No TLS 1.3.

**DigiCert TrustCore SDK / NanoSSL** (Mocana lineage; AGPLv3 since the
Aug 2025 open-sourcing, or commercial). TLS/DTLS 1.3 client+server with
post-quantum algorithms and a long industrial track record — but
~90 kB for the SSL library plus ~311 kB of crypto (ARM), an order of
magnitude above kB-class.

## Verified TLS/crypto

- **HACL*/EverCrypt**: verified primitives, extracted C usable
  standalone; no embedded footprint figures; portable Curve25519 leans on
  emulated 128-bit arithmetic (slow on M0/M3).
- **miTLS / Project Everest**: archived; handshake proof left incomplete
  ([retrospective](https://dl.acm.org/doi/10.1145/3805702)).
- **Bertie** ([Cryspen](https://github.com/cryspen/bertie)): minimal
  TLS 1.3 in hacspec/Rust, same single-suite product shape, verified
  protocol; explicitly not for production, allocation-heavy, not C, not
  embedded. The CCS'25 paper
  ([eprint 2025/980](https://eprint.iacr.org/2025/980)) completes the
  verification ("Bert13"), classical and post-quantum suites.
- **secunet's agentic Ada/SPARK suite**
  ([arXiv 2607.14340](https://arxiv.org/abs/2607.14340), 2026-07): a
  ~15 kLOC SPARK-verified TLS 1.3 client running bare-metal on the Muen
  separation kernel — the closest published relative of a verified
  minimal client. No footprint numbers published; Ada/SPARK toolchain,
  not C.
- **OCaml-TLS / MirageOS**
  ([mirleft](https://github.com/mirleft/ocaml-tls), BSD-2): memory-safe
  TLS 1.3 since 2020, actively maintained (v2.1.2, 2026-07); needs the
  OCaml runtime and GC — unikernel/server class, not firmware.
- **rustls** (Apache/MIT/ISC): memory-safe with a real assurance stack —
  Cure53 audit, Prossimo-funded maintainer, verified crypto via
  aws-lc-rs; no_std-capable since 0.23 but code size and RAM remain
  desktop-class, and it needs atomics.
- **RecordFlux / GreenTLS** (AdaCore, Apache-2.0): TLS 1.3 message
  parsers generated from provable message specifications — a
  methodology cousin of our Lean-spec approach; the TLS artifact is a
  parser layer grafted onto Fizz, not a standalone client.
- **s2n-tls (AWS)**: SAW/Cryptol proofs for HMAC, DRBG, and the handshake
  state machine, in CI ([CAV'18](https://d1.awsstatic.com/Security/pdfs/Continuous_Formal_Verification_Of_Amazon_s2n.pdf)).
  Server-class; not whole-stack memory safety; needs a libcrypto.
- **The methodology chapulin copies**: AWS proves the FreeRTOS core
  libraries memory-safe with CBMC
  ([coreMQTT](https://www.freertos.org/Documentation/03-Libraries/03-FreeRTOS-core/02-coreMQTT/00-coreMQTT)),
  and [mlkem-native](https://github.com/pq-code-package/mlkem-native)
  proves an entire ML-KEM implementation memory-safe/type-safe with CBMC
  contracts. Production-scale precedent — never yet applied to a whole
  TLS stack.
- A caution:
  [eprint 2026/192](https://eprint.iacr.org/2026/192.pdf) found 13 vulns
  in *verified* crypto libraries — 9 in unverified glue, 4 in specs. The
  answer is whole-stack coverage and an explicit statement of what is
  proved at what bounds, which is what our README does.

## Table stakes vs. cuts (per [draft-ietf-uta-tls13-iot-profile](https://datatracker.ietf.org/doc/html/draft-ietf-uta-tls13-iot-profile) + RFC 9257)

Kept: HRR handling, KeyUpdate, NewSessionTicket → resumption PSK,
record_size_limit (MTI, and the enabler of the SRAM headline), RFC 9257
binder discipline, ECDHE-PSK (`psk_dhe_ke`), pluggable RNG.
Cut: 0-RTT (profile says MUST NOT), DTLS, X.509 beyond the profiled
`TRUST=ca` chain check, RFC 7250 raw public keys, compressed certs,
CID, exporters. Known deviation: the profile's MTI suite is
AES-128-CCM-8; ChaCha-only is deliberate (no tables ⇒ constant time on
anything) and fine when both ends are ours.

## The number to beat

Every competitor's RAM claim hides the 16,384+ B max record buffer.
Published minima for a working TLS 1.3 PSK client: wolfSSL ~6.2 kB heap
(buffers extra), mbedTLS ~9–15 kB (buffers extra), SharkSSL 13 kB
total-system (cert-based). chapulin: 1,056 B session + a 2 kB record
buffer = ~3 kB total static, zero heap, buffer included — with
record_size_limit making the small buffer safe rather than hopeful.
