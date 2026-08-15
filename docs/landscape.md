# Embedded TLS landscape (surveyed 2026-08-14)

Why matasapos exists: no shipping C TLS stack is simultaneously (a)
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
Its shipped minimal-PSK example config is TLS 1.2 only.

**wolfSSL** (GPLv3 since 5.8.2 — a licensing break from GPLv2 — or
commercial). The famous LeanPSK 20 kB build is TLS 1.2 only. TLS 1.3
PSK-only: "less than 50 kB" code, no RAM figure published
([wolfSSL](https://www.wolfssl.com/small-tls-1-3-psk/)); measured 6.2 kB
peak heap in the arXiv paper above. Static-memory mode exists, still
allocator semantics.

**BearSSL** (MIT). The philosophical ancestor: zero malloc, constant-time
by default, ~25 kB RAM dominated by 16 kB record buffers. **Still no
TLS 1.3 in 2026** ([status](https://bearssl.org/tls13.html) unchanged
since ~2018); curl dropped it for that. Effectively frozen — this is the
vacuum matasapos fills.

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

## Verified TLS/crypto

- **HACL*/EverCrypt**: verified primitives, extracted C usable
  standalone; no embedded footprint figures; portable Curve25519 leans on
  emulated 128-bit arithmetic (slow on M0/M3).
- **miTLS / Project Everest**: archived; handshake proof left incomplete
  ([retrospective](https://dl.acm.org/doi/10.1145/3805702)).
- **Bertie** ([Cryspen](https://github.com/cryspen/bertie)): minimal
  TLS 1.3 in hacspec/Rust, same single-suite product shape, verified
  protocol; explicitly not for production, allocation-heavy, not C, not
  embedded.
- **s2n-tls (AWS)**: SAW/Cryptol proofs for HMAC, DRBG, and the handshake
  state machine, in CI ([CAV'18](https://d1.awsstatic.com/Security/pdfs/Continuous_Formal_Verification_Of_Amazon_s2n.pdf)).
  Server-class; not whole-stack memory safety; needs a libcrypto.
- **The methodology matasapos copies**: AWS proves the FreeRTOS core
  libraries memory-safe with CBMC
  ([coreMQTT](https://www.freertos.org/Documentation/03-Libraries/03-FreeRTOS-core/02-coreMQTT/00-coreMQTT)),
  and [mlkem-native](https://github.com/pq-code-package/mlkem-native)
  proves an entire ML-KEM implementation memory-safe/type-safe with CBMC
  contracts. Production-scale precedent — never yet applied to a whole
  TLS stack.
- Cautionary tale worth internalizing:
  [eprint 2026/192](https://eprint.iacr.org/2026/192.pdf) found 13 vulns
  in *verified* crypto libraries — 9 in unverified glue, 4 in specs. The
  answer is whole-stack coverage and an explicit statement of what is
  proved at what bounds, which is what our README does.

## Table stakes vs. cuts (per [draft-ietf-uta-tls13-iot-profile](https://datatracker.ietf.org/doc/html/draft-ietf-uta-tls13-iot-profile) + RFC 9257)

Kept: HRR handling, KeyUpdate, NewSessionTicket → resumption PSK,
record_size_limit (MTI, and the enabler of the SRAM headline), RFC 9257
binder discipline, ECDHE-PSK (`psk_dhe_ke`), pluggable RNG.
Cut: 0-RTT (profile says MUST NOT), DTLS, X.509/raw-pubkey, compressed
certs, CID, exporters. Known deviation: the profile's MTI suite is
AES-128-CCM-8; ChaCha-only is deliberate (no tables ⇒ constant time on
anything) and fine when both ends are ours.

## The number to beat

Every competitor's RAM claim hides the 16,384+ B max record buffer.
Published minima for a working TLS 1.3 PSK client: wolfSSL ~6.2 kB heap
(buffers extra), mbedTLS ~9–15 kB (buffers extra), SharkSSL 13 kB
total-system (cert-based). matasapos: 968 B session + a 2 kB record
buffer = ~3 kB total static, zero heap, buffer included — with
record_size_limit making the small buffer safe rather than hopeful.
