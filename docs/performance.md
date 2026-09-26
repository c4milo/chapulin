# Memory, speed and flash

What each build costs in RAM, instructions and flash, measured by the scripts in [`bench/`](../bench/). `make lint-bench-numbers` fails when a figure here disagrees with the CSV the scripts write.

## Memory

[`bench/sram.sh`](../bench/sram.sh) measures every number below and writes
them to [`bench/results-sram.csv`](../bench/results-sram.csv);
`make lint-bench-numbers` fails when this table disagrees with that file.
The session struct is measured twice, once native on arm64 and once for
rv32ic — the byte-count constants do not move, only the pointer fields, so
a 32-bit device needs 72 bytes less than the host figure in either device
build. `TRUST=webpki` adds pointer-sized fields to `ch_cfg`, pointers
and `size_t` lengths,
so that build needs 104 bytes less than the host figure on rv32.
The stack peaks are arm64 only: `bench/stack.py` reads arm64 relocations,
so an rv32 peak needs tooling that does not exist yet.

| what | arm64 | rv32 |
|---|---|---|
| `ch_tls` session struct (includes 622 B TX staging) | 1144 | 1072 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 | 2048 |
| **total static working set** | **3192** | **3120** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2328 | 2256 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4376** | **4304** |
| `ch_tls` under `TRUST=webpki` (includes 2401 B TX staging) | 3048 | 2944 |
| **total static working set, `TRUST=webpki`** (12338 buffer, its floor) | **15386** | **15282** |
| peak stack, `ch_connect` (RSA-3072 verify) | 4992 |
| peak stack, `ch_connect` (`TRUST=raw-ecdsa`) | 3824 |
| peak stack, `ch_connect` (PSK) | 2768 |
| peak stack, `ch_connect` (`TRUST=ca-rsa` / `TRUST=ca-ecdsa`) | 5472 / 3984 |
| peak stack, `ch_connect` (`TRUST=webpki`) | 16528 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1728 |
| peak stack, `ch_connect` (`KEX=pq`) | 15872 |
| peak stack, `ch_write` / `ch_close` | 912 / 864 |
| `ch_tls` under `ROLE=server` (includes 1221 B TX staging) | 1968 | 1816 |
| **total static working set, `ROLE=server`** (2048 buffer) | **4016** | **3864** |
| peak stack, `ch_srv_accept` (`ROLE=server`) | 10304 |
| `ch_tls` under `ROLE=server SUITE=aesgcm` | 2256 |
| **total static working set, `ROLE=server SUITE=aesgcm`** (2048 buffer) | **4304** |
| peak stack, `ch_srv_accept` (`ROLE=server SUITE=aesgcm`) | 10448 |
| `ch_tls` under `TRUST=webpki SUITE=aesgcm` | 3336 |
| **total static working set, `TRUST=webpki SUITE=aesgcm`** (12338 buffer, its floor) | **15674** |
| peak stack, `ch_connect` (`TRUST=webpki SUITE=aesgcm`) | 16656 |

The hybrid build costs more of both. The session struct grows because
the ClientHello carries a 1,216-byte key share and is built whole into
one staging array, and the stack grows because ML-KEM's K-PKE encrypt
holds three polynomial vectors and two polynomials: 5,744 bytes in that
one frame, against a 2,560-byte budget for every other build (INV-19
carries the per-build numbers). The whole chain peaks at 15,872 bytes,
through `mlkem_decaps` into K-PKE encrypt and Keccak, so the hybrid
build needs about three times the stack of the classic one rather than
the single frame's 5,744. A device that cannot spare it builds the
classic key exchange. A `TRUST=webpki` build carries the hybrid in every
build, so it pays both costs too, and its handshake state also holds the
P-256 scalar and point a retry to secp256r1 draws
([`docs/decisions.md`](decisions.md) 63).

A `ROLE=server` build pays them as well, because every server holds the
hybrid ([`docs/decisions.md`](decisions.md) 54). Its ServerHello is
built in the clear in the same staging array, and the hybrid one carries a
1,120-byte share, so the array holds 1,216 bytes of message behind the
record header. `ch_srv_accept` peaks at 10,304 bytes, through the
encapsulation to the client's key into K-PKE encrypt and Keccak, above
the 5,280 its RSA-PSS signer reaches with the encapsulation pruned from
the call graph (`STACK_PRUNE=srv_kex_share`).

`bench/sram.sh` measures a `SUITE=aesgcm` build with `AES=hw` on this host,
so its rows are host figures and have no rv32 column. A suite build with
`AES=extern` can run on a device with an AES peripheral
([`docs/decisions.md`](decisions.md) 68), and no script here measures
one on a device target yet. Its session struct is
288 bytes larger than the same `ROLE=server` build without the suite, and
288 larger for `TRUST=webpki`: the transcript runs a SHA-512 context beside
SHA-256's, the traffic secrets take SHA-384's 48 bytes, and a webpki hello
lists two more suites ([`docs/decisions.md`](decisions.md) 58).

You size the receive buffer, and the client advertises that size as its
`record_size_limit` ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)), so a peer can never send a record the
buffer cannot hold. One extra rule in pinned mode: the server's
Certificate message must also fit. A self-signed P-256 certificate
needs about 600 bytes and an RSA-3072 one about 1.2 kB, so the 2 kB
buffer above covers both. A ca-mode build knows its own worst case
and derives the floor for you: `CH_MIN_RXBUF` becomes 3,112 bytes
(RSA) or 1,576 (ECDSA), the largest Certificate message plus the record
that completes it, so a buffer too small for the largest chain fails at
setup rather than mid-handshake. A `TRUST=webpki` build derives 12,338
bytes the same way, four certificates at its 3,072-byte cap, and its
session struct carries a larger TX staging array for the `server_name`
and ALPN extensions and for both key shares, the 1,216-byte hybrid one
and a 32-byte x25519 one ([`docs/decisions.md`](decisions.md) 51),
and for the third group it lists, secp256r1 (63).
Its `ch_connect` peaks at 16,528 bytes, through ML-KEM's decapsulation,
above the 7,152 its chain walk into an RSA-4096 verify reaches, the
widest modulus a public root carries.

Provisioning with `ch_pubkey_from_pem` needs three more caller-side
buffers, none of them part of the static working set above and none of
them live between calls: the staged PEM text (up to `CH_PEM_MAX`,
3,136 bytes RSA or 1,600 ECDSA), a scratch array for the decoded
certificate (`CH_X509_MAX`, 1,536 or 768), and the key slot the device
already needed (`CH_X509_KEY_MAX`, 384 or 64). The scratch must not be
`cfg.buf` while a session is live: `ch_read` serves unread plaintext
out of that buffer across calls. The call itself measures 576 bytes of
stack, reported by `bench/stack.py` beside the other public calls.

The script computes each entry point's worst case from the object
code's call graph. It does not rely on a hand-picked call chain. The
RSA verify holds the deepest frames, so it sets the `ch_connect` peak
in the default build; it runs once per ticket lifetime and every byte
unwinds before `ch_connect` returns.

For comparison: wolfSSL needs about 6.2 kB of heap plus buffers, and
mbedTLS needs 9 to 15 kB and cannot run without an allocator. Both need
a 16 kB record buffer unless the peer supports `record_size_limit`.
[`docs/landscape.md`](landscape.md) holds the survey with sources.

## Speed and flash

[`bench/insn-mips.sh`](../bench/insn-mips.sh) and [`bench/device-ram.sh`](../bench/device-ram.sh) cross-compile for mips32r2,
the reference target's ISA (32-bit, big-endian, in-order), and measure
on that ISA. Cost is published as instruction counts, not guessed
milliseconds. The millisecond column assumes 500 MHz and one
instruction per cycle on that core, which is optimistic for an in-order
design, so read it as a lower bound. Every count is a property of what
one compiler emits, so each column names its compiler. The mips32r2
column is Alpine's clang 22 at `-Os` (`CLANG_MAJOR` in
[`bench/toolchain.env`](../bench/toolchain.env)); the flash figures below
come from clang 23 at `-Os` (`LLVM_MAJOR` in
[`tools/toolchain.env`](../tools/toolchain.env)), the clang the codegen
lints run.
[`bench/insn-m3.sh`](../bench/insn-m3.sh) measures the same operations as
thumbv7m instruction counts on QEMU's Cortex-M3, the core the m3 and
freertos CI lanes execute, built with the pinned Arm GNU Toolchain
15.3.rel1 gcc (`ARM_GNU_VERSION`) at `-O2`.
[`bench/insn-rv32.sh`](../bench/insn-rv32.sh) measures them a third time
as rv32imac instruction counts: the 32-bit little-endian build the
riscv32 CI lane ships, compiled by the pinned Bootlin gcc 14.3.0
(`RV32_TC_VERSION`) at `-Os` and run under qemu-riscv32 user mode. All
three instruction columns run the multiply decomposition firmware
ships. Each script also builds the same driver with
`-DCH_NATIVE_WIDEMUL` and records that count beside the shipped one,
as the CSV's `native_insns` column; the sentence under the table is
rendered from the two, and `make lint-bench-numbers` fails when the
prose and the CSVs disagree, as it does for every cell of the table.

| work | mips32r2 insns | ms (500 MHz, 1 IPC) | Cortex-M3 insns | rv32imac insns |
|---|---|---|---|---|
| AEAD seal, per 1 KB record | 82 k | 0.16 | 68 k | 107 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 38.9 M | 78 | 27.4 M | 51.4 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`TRUST=raw-ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 90.2 M | 180 | 63.8 M | 117.0 M |
| ML-KEM-768 keygen (`KEX=pq`) | 3.2 M | 6 | 2.7 M | 3.6 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 3.6 M | 7 | 3.0 M | 4.1 M |
| full hybrid handshake crypto (`KEX=pq`) | 100.4 M | 201 | 72.2 M | 128.3 M |

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:
on mips32r2, AEAD seal costs 73% more, x25519 36% more, and the
pinned handshake 29% more, or 41 ms at 500 MHz; on the Cortex-M3, AEAD
seal costs 93% more, x25519 129% more, and the pinned handshake 94%
more; on rv32imac, AEAD seal costs 66% more, x25519 137% more, and the
pinned handshake 104% more. SHA-256 and both signature verifies are
unchanged, because SHA-256 does not multiply and the verifies read only
public bytes.

Flash is 28.0 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.3 kB, nearly all of it
poly1305's unrolled block: the `total (CH_NATIVE_WIDEMUL)` row of
[`bench/results-device.csv`](../bench/results-device.csv) sizes the same
modules over the native multiply. The `TRUST=raw-ecdsa` build trades 2.2 kB
of RSA for 5.8 kB of P-256 and totals 31.5 kB. Its verify costs 4.0 times
the default's on mips32r2, so the 64-byte pin costs both flash and handshake
time.

The hybrid key exchange costs less than its wire size suggests. `KEX=pq`
adds two ML-KEM key expansions and one decapsulation — the key pair lives
as a 64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](decisions.md) 24 explains — for 10.2 M
instructions, 11% over the classic handshake. One ML-KEM-768 keygen is
an order of magnitude cheaper than one x25519 on this core, because
chapulin keeps the 16-bit-limb ladder for its machine-checked overflow
proof.

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 156 ms is the recurring
floor and 86% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake. Because a device typically opens one long-lived connection,
chapulin keeps the 16-bit-limb x25519 as the default and the device
path, for its machine-checked overflow proof and because a 32-bit core
has no wider multiply to run a faster field on. A 64-bit host that
opens many short connections can build `X25519=wide` instead (decision
52): five 51-bit limbs whose products run on the 64x64->128 multiply.
On an Apple M1 Pro a scalar multiplication takes 34 µs there against
953 µs in the default build, and the client side of a pinned RSA-3072
handshake falls from 2.57 ms to 0.77 ms
([`bench/notes-primitives.md`](../bench/notes-primitives.md)).
