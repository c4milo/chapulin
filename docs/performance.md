# Memory, speed and flash

What each build costs in RAM, instructions and flash, measured by the
scripts in [`bench/`](../bench/). `make lint-bench-numbers` fails when a
figure here disagrees with the CSV the scripts write.

## Memory

[`bench/sram.sh`](../bench/sram.sh) measures every number in this
section and writes them to
[`bench/results-sram.csv`](../bench/results-sram.csv).

### Static working set

The session struct is measured twice, once native on arm64 and once for
rv32ic. The byte-count constants do not move, only the pointer fields,
so a 32-bit device needs 80 bytes less than the host figure in either device
build. `TRUST=webpki` adds pointer-sized fields to `ch_cfg`, pointers
and `size_t` lengths, so that build needs 112 bytes less than the host figure on rv32.

| what | arm64 | rv32 |
|---|---|---|
| `ch_tls` session struct (includes 622 B TX staging) | 1160 | 1080 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 | 2048 |
| **total static working set** | **3208** | **3128** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2344 | 2264 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4392** | **4312** |
| `ch_tls` under `TRUST=webpki` (includes 2401 B TX staging) | 3064 | 2952 |
| **total static working set, `TRUST=webpki`** (12338 buffer, its floor) | **15402** | **15290** |
| `ch_tls` under `ROLE=server` (includes 1221 B TX staging) | 1984 | 1824 |
| **total static working set, `ROLE=server`** (2048 buffer) | **4032** | **3872** |
| `ch_tls` under `ROLE=server SUITE=aesgcm` | 2280 | — |
| **total static working set, `ROLE=server SUITE=aesgcm`** (2048 buffer) | **4328** | — |
| `ch_tls` under `TRUST=webpki SUITE=aesgcm` | 3376 | — |
| **total static working set, `TRUST=webpki SUITE=aesgcm`** (12338 buffer, its floor) | **15714** | — |
| `ch_tls` under `TRUST=webpki`, host object | 3072 | — |
| **total static working set, `TRUST=webpki`, host object** (12338 buffer, its floor) | **15410** | — |
| `ch_tls` under `ROLE=server`, host object | 1992 | — |
| **total static working set, `ROLE=server`, host object** (2048 buffer) | **4040** | — |

### Peak stack

The stack peaks are arm64 only. `bench/stack.py` reads the call graph
from the relocations in an arm64 or x86-64 Mach-O object, and
`bench/sram.sh` runs it on an arm64 Mac, so an rv32 peak needs tooling
that does not exist yet.

The script computes each entry point's worst case from the object code's
call graph. It does not rely on a hand-picked call chain. It compiles
the sources the Makefile packages for the build it measures, with that
build's defines, and no other source. It treats static functions of one
name in two objects as two functions: `p256.c` and `p384.c` each define
a static `point_add`, with different frames. It counts a tail call like
a call, adding the callee's depth to the caller's whole frame, which can
only overstate a peak. `make lint-stack-walk` checks that it follows a
tail call at a function's first instruction, keeps two static functions
of one name apart, names the calls below that no object defines, and
compiles what make packages. The RSA verify holds the deepest frames, so
it sets the `ch_connect` peak in the default build; it runs once per
ticket lifetime, and every byte unwinds before `ch_connect` returns.

A peak leaves out the frames of the calls below, and the script's report
names them for each build:

- C library calls, such as `memcpy` and `strlen`;
- `__stack_chk_fail`, `__memcpy_chk` and `__memset_chk`, the stack
  protector and the checked `memcpy` and `memset` that the host compiler
  adds by default;
- the hooks the image defines, such as `ch_assert_fail` and
  `ch_rand_bytes` ([`docs/porting.md`](porting.md));
- the caller's `send`, `recv` and `on_ticket`, which the objects call
  through pointers.

The image's C library and the caller's own functions set those frames.

| call | arm64 |
|---|---|
| peak stack, `ch_connect` (RSA-3072 verify) | 4992 |
| peak stack, `ch_connect` (`TRUST=raw-ecdsa`) | 3104 |
| peak stack, `ch_connect` (PSK) | 2768 |
| peak stack, `ch_connect` (`TRUST=ca-rsa` / `TRUST=ca-ecdsa`) | 5472 / 3264 |
| peak stack, `ch_connect` (`TRUST=webpki`) | 16688 |
| peak stack, `ch_connect` (`TRUST=webpki SUITE=aesgcm`) | 16816 |
| peak stack, `ch_connect` (`KEX=pq`) | 16000 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1712 |
| peak stack, `ch_write` / `ch_close` | 944 / 896 |
| peak stack, `ch_srv_accept` (`ROLE=server`) | 11840 |
| peak stack, `ch_srv_accept` (`ROLE=server SUITE=aesgcm`) | 12016 |

### What the larger builds pay for

**`KEX=pq`.** The hybrid build costs more of both:

- The session struct grows because the ClientHello carries a 1,216-byte
  key share and is built whole into one staging array.
- The stack grows because ML-KEM's K-PKE encrypt holds three polynomial
  vectors and two polynomials: 5,744 bytes in that one frame, against a
  2,560-byte budget for every other build (INV-19 carries the per-build
  numbers). The whole chain peaks at 16,000 bytes, through
  `mlkem_decaps` into K-PKE encrypt, the matrix sampler and Keccak, so
  the hybrid build needs about three times the stack of the classic one
  rather than the single frame's 5,744.

A device that cannot spare it builds the classic key exchange.

**`TRUST=webpki`.** A `TRUST=webpki` build carries the hybrid in every
build, so it pays both costs too, and its handshake state also holds the
P-256 scalar and point a retry to secp256r1 draws
([`docs/decisions.md`](decisions.md) 63). Its session struct carries a
larger TX staging array for the `server_name` and ALPN extensions and
for both key shares, the 1,216-byte hybrid one and a 32-byte x25519 one
([`docs/decisions.md`](decisions.md) 51), and for the third group it
lists, secp256r1 (63). Its `ch_connect` peaks at 16,688 bytes, through
ML-KEM's decapsulation. With ML-KEM and its copies over the SHA-3
instructions pruned from the call graph
(`STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk,mlkem_decaps_hw,mlkem_keygen_dk_hw`)
the deepest chain is the chain walk into a P-384 verify, at 8,304 bytes:
this host builds the host object, whose P-384 verifier runs on six
64-bit words ([`docs/decisions.md`](decisions.md) 97). A device object
holds no copies over the SHA-3 instructions, and with ML-KEM pruned
(`STACK_MAKE='TRUST=webpki HOST_TARGET='
STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk`) its deepest chain is the chain
walk into an RSA-4096 verify on 32-bit words, at 7,344 bytes. RSA-4096
is the widest modulus a public root carries.

**`ROLE=server`.** A server build pays them as well, because every
server holds the hybrid ([`docs/decisions.md`](decisions.md) 54). Its
ServerHello is built in the clear in the same staging array, and the
hybrid one carries a 1,120-byte share, so the array holds 1,216 bytes of
message behind the record header. `ch_srv_accept` peaks at 11,840
bytes in the host object this host builds, through `rsa_sign64.c`'s
RSA-PSS signer, which holds a modulus record for each prime, the
signature it checks and a table of sixteen powers
([`docs/decisions.md`](decisions.md) 95), and whose square holds a copy
of 2a (106). With that signer pruned from
the call graph (`STACK_PRUNE=rsa_sign64_pss`) the deepest chain is the
encapsulation to the client's key into K-PKE encrypt and Keccak, at
10,464 bytes, and with the encapsulation pruned as well
(`STACK_PRUNE=rsa_sign64_pss,srv_kex_share`) it is `rsa_sign.c`'s
ladder, at 5,376. A device object holds the ladder alone: its
`ch_srv_accept` peaks at 10,432 bytes, through the encapsulation, and
its signer's chain takes 5,280
(`STACK_MAKE='ROLE=server TRUST=none HOST_TARGET='`).

**`SUITE=aesgcm`.** `bench/sram.sh` measures a `SUITE=aesgcm` build as the
host object this host builds for it ([`docs/decisions.md`](decisions.md)
89), so its rows are host figures and have no rv32 column. A suite build
with `AES=extern` can run on a device with an AES peripheral
([`docs/decisions.md`](decisions.md) 68), and no script here measures one
on a device target yet. Its session struct is 288 bytes larger than the
same `ROLE=server` host object without the suite, and 304 larger for
`TRUST=webpki`:

- the transcript runs a SHA-512 context beside SHA-256's;
- the traffic secrets take SHA-384's 48 bytes;
- a webpki hello lists two more suites
  ([`docs/decisions.md`](decisions.md) 58);
- a webpki client's configuration holds the caller's suite order, a
  pointer and a count ([`docs/decisions.md`](decisions.md) 80).

**A host object.** On arm64 and x86-64 the Makefile and `build.zig`
build a `TRUST=webpki` client, `ROLE=server` and `ROLE=both` as a host
object, whose `ch_cfg` holds `cpu`, the caller's description of its CPU
([`docs/decisions.md`](decisions.md) 89). The field is 4 bytes, and with
the alignment of the pointer after it each session struct is 8 bytes
larger than the same build's portable object, which the rows without
"host object" measure, and the `SUITE=aesgcm` rows above are host objects
too. Each record direction also holds a copy of `cpu`, from which a
record reads its paths ([`docs/decisions.md`](decisions.md) 87 and 89),
in the 4 bytes the alignment of its sequence number left unused, so the
directions do not grow. A host object runs on those two architectures alone, so
these rows are host figures. The stack peaks of `TRUST=webpki` and
`ROLE=server` are a host object's too: `bench/stack.py` compiles what make
packages for those builds on this host, which holds both multiplies.

### The receive buffer

You size the receive buffer, and the client advertises that size as its
`record_size_limit` ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)),
so a peer can never send a record the buffer cannot hold. Each trust
mode adds one rule:

- **Pinned mode.** The server's Certificate message must also fit. A
  self-signed P-256 certificate needs about 600 bytes and an RSA-3072
  one about 1.2 kB, so the 2 kB buffer above covers both.
- **The ca modes.** A ca-mode build knows its own worst case and derives
  the floor for you: `CH_MIN_RXBUF` becomes 3,112 bytes (RSA) or 1,576
  (ECDSA), the largest Certificate message plus the record that
  completes it. A buffer too small for the largest chain fails at setup
  rather than mid-handshake.
- **`TRUST=webpki`.** The build derives 12,338 bytes the same way, four
  certificates at its 3,072-byte cap.

### Provisioning buffers

Provisioning with `ch_pubkey_from_pem` needs three more caller-side
buffers. None of them is part of the static working set above, and none
is live between calls:

| buffer | RSA | ECDSA |
|---|---|---|
| the staged PEM text (`CH_PEM_MAX`) | 3,136 | 1,600 |
| a scratch array for the decoded certificate (`CH_X509_MAX`) | 1,536 | 768 |
| the key slot the device already needed (`CH_X509_KEY_MAX`) | 384 | 64 |

The scratch must not be `cfg.buf` while a session is live: `ch_read`
serves unread plaintext out of that buffer across calls. The call
itself measures 576 bytes of stack under `TRUST=ca-rsa` and 496 under
`TRUST=ca-ecdsa`, reported by `bench/stack.py` beside the other public
calls.

### Compared with other libraries

wolfSSL needs about 6.2 kB of heap plus buffers, and mbedTLS needs 9 to
15 kB and cannot run without an allocator. Both need a 16 kB record
buffer unless the peer supports `record_size_limit`.
[`docs/landscape.md`](landscape.md) holds the survey with sources.

## Speed and flash

Cost is published as instruction counts, not guessed milliseconds.
Every count is a property of what one compiler emits, so each column
names its compiler:

- **mips32r2.** [`bench/insn-mips.sh`](../bench/insn-mips.sh) and
  [`bench/device-ram.sh`](../bench/device-ram.sh) cross-compile for
  mips32r2, the reference target's ISA (32-bit, big-endian, in-order),
  and measure on that ISA. The column is Alpine's clang 22 at `-Os`
  (`CLANG_MAJOR` in [`bench/toolchain.env`](../bench/toolchain.env)).
  The millisecond column assumes 500 MHz and one instruction per cycle
  on that core, which is optimistic for an in-order design, so read it
  as a lower bound.
- **Cortex-M3.** [`bench/insn-m3.sh`](../bench/insn-m3.sh) measures the
  same operations as thumbv7m instruction counts on QEMU's Cortex-M3,
  the core the m3 and freertos CI lanes execute, built with the pinned
  Arm GNU Toolchain 15.3.rel1 gcc (`ARM_GNU_VERSION`) at `-O2`.
- **rv32imac.** [`bench/insn-rv32.sh`](../bench/insn-rv32.sh) measures
  them a third time as rv32imac instruction counts: the 32-bit
  little-endian build the riscv32 CI lane ships, compiled by the pinned
  Bootlin gcc 14.3.0 (`RV32_TC_VERSION`) at `-Os` and run under
  qemu-riscv32 user mode.

The flash figures below come from clang 23 at `-Os` (`LLVM_MAJOR` in
[`tools/toolchain.env`](../tools/toolchain.env)), the clang the codegen
lints run.

All three instruction columns run the multiply decomposition firmware
ships. Each script also builds the same driver with
`-DCH_NATIVE_WIDEMUL` and records that count beside the shipped one, as
the CSV's `native_insns` column. The decomposition figures under the
table are rendered from the two, and `make lint-bench-numbers` fails
when the prose and the CSVs disagree, as it does for every cell of the
table.

| work | mips32r2 insns | ms (500 MHz, 1 IPC) | Cortex-M3 insns | rv32imac insns |
|---|---|---|---|---|
| AEAD seal, per 1 KB record | 82 k | 0.16 | 67 k | 107 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 38.9 M | 78 | 27.4 M | 51.4 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`TRUST=raw-ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 90.2 M | 180 | 63.7 M | 117.0 M |
| ML-KEM-768 keygen (`KEX=pq`) | 1.3 M | 3 | 1.0 M | 1.2 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 1.6 M | 3 | 1.3 M | 1.6 M |
| full hybrid handshake crypto (`KEX=pq`) | 94.4 M | 189 | 67.2 M | 121.1 M |

### The multiply decomposition

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:

- on mips32r2, AEAD seal costs 73% more, x25519 36% more, and the
  pinned handshake 29% more, or 41 ms at 500 MHz;
- on the Cortex-M3, AEAD seal costs 94% more, x25519 129% more, and the
  pinned handshake 94% more;
- on rv32imac, AEAD seal costs 66% more, x25519 137% more, and the
  pinned handshake 104% more.

SHA-256 and both signature verifies are unchanged, because SHA-256 does
not multiply and the verifies read only public bytes.

### Flash

Flash is 30.3 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.3 kB, nearly all of it
poly1305's unrolled block: the `total (CH_NATIVE_WIDEMUL)` row of
[`bench/results-device.csv`](../bench/results-device.csv) sizes the same
modules over the native multiply.

The `TRUST=raw-ecdsa` build trades 2.2 kB of RSA for 5.8 kB of P-256
and totals 33.8 kB. Its verify costs 4.0 times the default's on
mips32r2, so the 64-byte pin costs both flash and handshake time.

### The hybrid key exchange

The hybrid key exchange costs less than its wire size suggests.
`KEX=pq` adds two ML-KEM key expansions and one decapsulation for 4.4 M
instructions, 5% over the classic handshake. The key pair lives as a
64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](decisions.md) 24 explains.

One ML-KEM-768 keygen is an order of magnitude cheaper than one x25519
on this core, because chapulin keeps the 16-bit-word ladder for its
machine-checked overflow proof.

### Where the time goes

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 156 ms is the recurring
floor and 86% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake.

Because a device typically opens one long-lived connection, chapulin
keeps the 16-bit-word x25519 as the default and the device path. It
does so for its machine-checked overflow proof, and because a 32-bit
core has no wider multiply to run a faster field on.

A host object holds a second field for a session whose caller sets
`CH_CPU_CONSTANT_TIME_MULTIPLY` (decisions 52 and 89): five 51-bit words
whose products run on the 64x64->128 multiply. On an Apple M1 Pro a
scalar multiplication takes 33.0 µs on that field against 901 µs on the
16-word one over the decomposition, and the client side of a pinned
RSA-3072 handshake takes 116 µs under the value that machine's line
states below against 2.34 ms under `CH_CPU_PROBED` alone
([`bench/results-primitives-darwin-arm64-clang.csv`](../bench/results-primitives-darwin-arm64-clang.csv),
[`bench/notes-primitives.md`](../bench/notes-primitives.md)).

### chapulin beside OpenSSL

Camilo set the goal on 2026-10-03: chapulin beats OpenSSL on every primitive TLS runs, in C an
auditor can read. This table states the goal as numbers. It has one row per primitive and three
cells per machine and compiler: chapulin's time for one operation, OpenSSL's time for it on the
same machine in the same run, and the first over the second. A ratio above 1 is a row where
chapulin is behind, and it is in bold. Work on a primitive starts from its row here, and the
scripts that wrote the row judge the change. The table holds two x86-64 CPUs, one without AVX-512
and one with AVX-512 IFMA. On the second, a host object whose caller sets `CH_CPU_AVX512_IFMA`
verifies RSA on `rsa_ifma.c` (decision 119). Each CPU has two groups of cells: gcc, which CI
compiles with, and the pinned clang 23, a newer clang than Zig 0.16's clang 21, which `build.zig`
compiles the object with for a Zig project such as colibri.

| one operation | M1 Pro, chapulin | M1 Pro, OpenSSL | ratio | x86-64 gcc, chapulin | x86-64 gcc, OpenSSL | ratio | x86-64 clang, chapulin | x86-64 clang, OpenSSL | ratio | x86-64 AVX-512 gcc, chapulin | x86-64 AVX-512 gcc, OpenSSL | ratio | x86-64 AVX-512 clang, chapulin | x86-64 AVX-512 clang, OpenSSL | ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SHA-256, 16 KiB | 7.00 µs | 6.90 µs | **1.01** | 10.4 µs | 10.4 µs | 1.00 | 10.4 µs | 10.4 µs | 1.00 | 10.7 µs | 10.8 µs | 0.99 | 10.6 µs | 10.4 µs | **1.03** |
| SHA-256, 64 bytes | 108 ns | 151 ns | 0.71 | 171 ns | 191 ns | 0.89 | 168 ns | 191 ns | 0.88 | 151 ns | 176 ns | 0.86 | 143 ns | 168 ns | 0.85 |
| SHA-384, 16 KiB | 12.0 µs | 11.8 µs | **1.02** | 46.9 µs | 21.9 µs | **2.14** | 47.6 µs | 21.9 µs | **2.17** | 49.2 µs | 24.8 µs | **1.98** | 40.1 µs | 23.4 µs | **1.71** |
| SHA-384, 64 bytes | 197 ns | 187 ns | **1.05** | 521 ns | 333 ns | **1.57** | 632 ns | 332 ns | **1.90** | 516 ns | 336 ns | **1.54** | 496 ns | 311 ns | **1.59** |
| SHA3-256, 16 KiB | 19.2 µs | 18.7 µs | **1.03** | 51.3 µs | 38.5 µs | **1.33** | 47.8 µs | 38.5 µs | **1.24** | 47.0 µs | 36.3 µs | **1.30** | 43.3 µs | 33.8 µs | **1.28** |
| SHA3-256, 64 bytes | 206 ns | 344 ns | 0.60 | 515 ns | 489 ns | **1.05** | 477 ns | 492 ns | 0.97 | 459 ns | 450 ns | **1.02** | 428 ns | 420 ns | **1.02** |
| X25519 key generation | 33.0 µs | 30.8 µs | **1.07** | 54.7 µs | 33.7 µs | **1.62** | 47.1 µs | 33.9 µs | **1.39** | 42.6 µs | 30.8 µs | **1.38** | 34.9 µs | 28.7 µs | **1.22** |
| X25519 shared secret | 33.0 µs | 30.7 µs | **1.08** | 54.2 µs | 36.5 µs | **1.49** | 47.2 µs | 36.5 µs | **1.29** | 42.7 µs | 34.0 µs | **1.25** | 36.4 µs | 32.4 µs | **1.12** |
| P-256 key generation | 9.95 µs | 9.53 µs | **1.04** | 18.7 µs | 12.5 µs | **1.49** | 13.7 µs | 12.5 µs | **1.10** | 16.1 µs | 11.8 µs | **1.37** | 11.2 µs | 11.4 µs | 0.99 |
| P-256 shared secret | 52.0 µs | 40.9 µs | **1.27** | 93.2 µs | 51.7 µs | **1.80** | 70.8 µs | 51.7 µs | **1.37** | 80.6 µs | 56.8 µs | **1.42** | 56.9 µs | 53.2 µs | **1.07** |
| ECDSA P-256 sign | 13.8 µs | 17.9 µs | 0.77 | 27.0 µs | 22.3 µs | **1.21** | 20.3 µs | 22.3 µs | 0.91 | 24.5 µs | 22.7 µs | **1.08** | 18.2 µs | 21.4 µs | 0.85 |
| ECDSA P-256 verify | 53.5 µs | 55.0 µs | 0.97 | 95.9 µs | 67.8 µs | **1.41** | 71.8 µs | 67.6 µs | **1.06** | 83.0 µs | 72.9 µs | **1.14** | 58.8 µs | 70.5 µs | 0.83 |
| ECDSA P-384 verify | 272 µs | 309 µs | 0.88 | 676 µs | 733 µs | 0.92 | 365 µs | 730 µs | 0.50 | 553 µs | 584 µs | 0.95 | 287 µs | 560 µs | 0.51 |
| RSA-2048 PSS sign | 655 µs | 552 µs, PKCS#1 v1.5 sign | — | 1.48 ms | 659 µs, PKCS#1 v1.5 sign | — | 1.36 ms | 659 µs, PKCS#1 v1.5 sign | — | 1.24 ms | 324 µs, PKCS#1 v1.5 sign | — | 886 µs | 303 µs, PKCS#1 v1.5 sign | — |
| RSA-2048 PSS verify | 21.2 µs | 14.3 µs, PKCS#1 v1.5 verify | — | 38.6 µs | 18.9 µs, PKCS#1 v1.5 verify | — | 38.0 µs | 18.9 µs, PKCS#1 v1.5 verify | — | 12.2 µs | 18.1 µs, PKCS#1 v1.5 verify | — | 11.0 µs | 17.5 µs, PKCS#1 v1.5 verify | — |
| RSA-2048 PKCS#1 v1.5 verify | 17.7 µs | 14.3 µs | **1.24** | 35.3 µs | 18.9 µs | **1.87** | 34.4 µs | 18.9 µs | **1.83** | 8.90 µs | 18.1 µs | 0.49 | 8.41 µs | 17.5 µs | 0.48 |
| RSA-3072 PSS sign | 1.96 ms | 1.62 ms, PKCS#1 v1.5 sign | — | 4.53 ms | 2.01 ms, PKCS#1 v1.5 sign | — | 4.28 ms | 2.01 ms, PKCS#1 v1.5 sign | — | 3.62 ms | 894 µs, PKCS#1 v1.5 sign | — | 2.66 ms | 804 µs, PKCS#1 v1.5 sign | — |
| RSA-3072 PSS verify | 40.8 µs | 30.4 µs, PKCS#1 v1.5 verify | — | 83.8 µs | 40.2 µs, PKCS#1 v1.5 verify | — | 82.7 µs | 40.1 µs, PKCS#1 v1.5 verify | — | 20.0 µs | 39.5 µs, PKCS#1 v1.5 verify | — | 19.1 µs | 36.7 µs, PKCS#1 v1.5 verify | — |
| RSA-3072 PKCS#1 v1.5 verify | 36.9 µs | 30.4 µs | **1.21** | 79.8 µs | 40.2 µs | **1.99** | 78.4 µs | 40.1 µs | **1.95** | 15.7 µs | 39.5 µs | 0.40 | 15.4 µs | 36.7 µs | 0.42 |
| ML-KEM-768 key generation | 12.1 µs | 35.5 µs | 0.34 | 19.6 µs | 36.4 µs | 0.54 | 18.7 µs | 36.3 µs | 0.52 | 20.6 µs | 35.2 µs | 0.58 | 16.3 µs | 33.3 µs | 0.49 |
| ML-KEM-768 encapsulation | 13.8 µs | 23.5 µs | 0.59 | 22.1 µs | 21.9 µs | **1.01** | 20.5 µs | 21.7 µs | 0.94 | 23.5 µs | 20.3 µs | **1.16** | 19.3 µs | 19.2 µs | **1.00** |
| ML-KEM-768 decapsulation | 14.7 µs | 36.8 µs | 0.40 | 25.3 µs | 33.4 µs | 0.76 | 22.4 µs | 33.3 µs | 0.67 | 26.5 µs | 31.5 µs | 0.84 | 20.0 µs | 29.4 µs | 0.68 |
| AES-128-GCM, the key set and one 16 KiB record sealed | 2.33 µs | 2.05 µs | **1.13** | 3.18 µs | 4.05 µs | 0.79 | 2.68 µs | 4.05 µs | 0.66 | 2.78 µs | 1.19 µs | **2.33** | 2.38 µs | 1.17 µs | **2.03** |
| AES-128-GCM, the key set and one 16 KiB record opened | 2.39 µs | 2.08 µs | **1.15** | 3.13 µs | 4.12 µs | 0.76 | 2.78 µs | 4.12 µs | 0.67 | 2.74 µs | 1.25 µs | **2.19** | 2.47 µs | 1.24 µs | **1.99** |
| AES-256-GCM, the key set and one 16 KiB record sealed | 2.82 µs | 2.47 µs | **1.14** | 3.61 µs | 4.37 µs | 0.83 | 3.07 µs | 4.36 µs | 0.70 | 3.20 µs | 1.45 µs | **2.21** | 2.80 µs | 1.40 µs | **2.00** |
| AES-256-GCM, the key set and one 16 KiB record opened | 2.85 µs | 2.48 µs | **1.15** | 3.56 µs | 4.43 µs | 0.80 | 3.20 µs | 4.43 µs | 0.72 | 3.19 µs | 1.45 µs | **2.19** | 2.88 µs | 1.42 µs | **2.02** |
| ChaCha20-Poly1305, 16 KiB encrypted and hashed, no tag | 10.8 µs | 9.16 µs | **1.18** | 9.20 µs | 7.46 µs | **1.23** | 8.67 µs | 7.46 µs | **1.16** | 11.4 µs | 4.48 µs | **2.54** | 10.8 µs | 4.43 µs | **2.43** |
| ChaCha20-Poly1305, 16 KiB hashed and decrypted, no tag | 10.8 µs | 9.10 µs | **1.18** | 9.21 µs | 7.48 µs | **1.23** | 8.80 µs | 7.48 µs | **1.18** | 10.1 µs | 4.51 µs | **2.25** | 9.95 µs | 4.44 µs | **2.24** |

The machines, as the CSV headers state them:

- **M1 Pro**: Apple M1 Pro, Darwin 25.6.0, Apple clang version 21.0.0 (clang-2100.3.34.2), OpenSSL
  3.6.5, `ch_cfg.cpu 0xe7`, and `0x7` for the AEAD rows, which no hash bit changes; one-minute load
  average 4.16 before the primitives' run and 3.70 after it, and 3.48 and 4.20 around the AEAD rows'
  run.
- **x86-64 gcc**: AMD EPYC 7763 64-Core Processor, Linux 6.17.0-1022-azure, gcc (Ubuntu
  13.3.0-6ubuntu2~24.04.1) 13.3.0, OpenSSL 3.6.4, `ch_cfg.cpu 0x3f`, and `0x1f` for the AEAD rows,
  which no hash bit changes; one-minute load average 1.00 before the primitives' run and 1.00 after
  it, and 0.95 and 1.02 around the AEAD rows' run.
- **x86-64 clang**: AMD EPYC 7763 64-Core Processor, Linux 6.17.0-1022-azure, Ubuntu clang version
  23.1.2 (++20260919103626+4b1925210476-1~exp1~20260919223755.77), OpenSSL 3.6.4, `ch_cfg.cpu 0x3f`,
  and `0x1f` for the AEAD rows, which no hash bit changes; one-minute load average 1.00 before the
  primitives' run and 1.00 after it, and 1.00 and 1.00 around the AEAD rows' run.
- **x86-64 AVX-512 gcc**: INTEL(R) XEON(R) PLATINUM 8573C, Linux 6.17.0-1022-azure, gcc (Ubuntu
  13.3.0-6ubuntu2~24.04.1) 13.3.0, OpenSSL 3.6.4, `ch_cfg.cpu 0x13f`, and `0x1f` for the AEAD rows,
  which neither a hash bit nor `CH_CPU_AVX512_IFMA` changes; one-minute load average 0.97 before the
  primitives' run and 1.00 after it, and 0.66 and 0.89 around the AEAD rows' run.
- **x86-64 AVX-512 clang**: INTEL(R) XEON(R) PLATINUM 8573C, Linux 6.17.0-1022-azure, Ubuntu clang
  version 23.1.2 (++20260919103626+4b1925210476-1~exp1~20260919223755.77), OpenSSL 3.6.4,
  `ch_cfg.cpu 0x13f`, and `0x1f` for the AEAD rows, which neither a hash bit nor
  `CH_CPU_AVX512_IFMA` changes; one-minute load average 1.00 before the primitives' run and 1.00
  after it, and 1.00 and 1.00 around the AEAD rows' run.

[`bench/primitives.sh`](../bench/primitives.sh) (`make bench-primitives`) writes the rows above the
AEADs to a CSV for each machine and compiler, such as
[`bench/results-primitives-darwin-arm64-clang.csv`](../bench/results-primitives-darwin-arm64-clang.csv),
and [`bench/record.sh`](../bench/record.sh) writes the six AEAD rows to the record CSVs of the next
section. [`tools/bench_scoreboard.py`](../tools/bench_scoreboard.py) renders the table
and the machines' lines from those files, and `make lint-bench-numbers` fails when this document
disagrees with them.

How the figures are taken:

- **chapulin.** Every timed program is a host object, and each row runs under the `ch_cfg.cpu`
  value a caller on that CPU states, every bit the CPU has (decision 89). The machine's line above
  names the value. The CSV also holds each row under `ch_cfg.cpu 0x1`, `CH_CPU_PROBED` alone, which
  a caller that states nothing runs: the 16x16 multiply decomposition and the 16-word X25519 field,
  which a device object runs too. [`bench/notes-primitives.md`](../bench/notes-primitives.md) reads
  those rows and the handshakes'.
- **OpenSSL.** `openssl speed -mr -seconds 1`, on the binary `test/e2e.sh` takes
  ([`bench/openssl.sh`](../bench/openssl.sh)). Each machine's line names its version.
- **The clock.** `openssl speed` divides the operations it ran by the user CPU time its process
  took. `bench/primitives.c` times each sample on its thread's CPU clock. So neither side counts
  the time a loaded machine gave to other work. The load in a machine's line can still move both
  through the caches and the cores they share with that work, and on an M1 Pro through a run that
  macOS places on efficiency cores, which run the same code in about three times the time.
  `bench/primitives.sh` warns of a row whose runs differ by more than half, and the CSV's
  `run_spread_pct` states each row's spread. The AEAD rows are `bench/record.c`'s, batches of 1 ms
  on the wall clock.
- **The runs.** Each figure is the median of five runs. One run of `bench/primitives.sh` is every
  chapulin row and then one second of each OpenSSL row, so the two sides of a ratio are never more
  than a run apart.
- **Instructions.** On macOS the primitives CSV also holds the instructions each chapulin
  operation retired, as `/usr/bin/time -l` counts them for a process. A count does not move with
  the machine's load, so it shows what a change did to a row where a time cannot.

What a row compares:

- **RSA.** `openssl speed` signs and verifies RSA with PKCS#1 v1.5 padding. chapulin signs PSS
  alone, so each PSS row shows OpenSSL's PKCS#1 v1.5 time and no ratio. The two PKCS#1 v1.5 verify
  rows compare one operation: chapulin checks a SHA-256 DigestInfo, and `openssl speed` a 36-byte
  value without one.
- **Key generation and encapsulation.** chapulin's calls take their random bytes as arguments, so
  its rows time no draw. OpenSSL's rows draw theirs, and its key generation also builds a key
  object.
- **ECDSA.** chapulin derives its nonce by RFC 6979 and signs a 32-byte digest. `openssl speed`
  draws its nonce and signs 20 bytes.
- **AES-GCM.** One operation of OpenSSL 3.6's `speed -aead` sets the key and the IV, hashes 13
  bytes of associated data, encrypts 16,384 bytes and computes the tag. chapulin's row is the
  operation `record.c` runs for every record: it expands the key, seals 16,385 bytes with the
  record's 5-byte header as associated data, and wipes the expanded key. On arm64
  `bench/record.sh` times AES-GCM under `ch_cfg.cpu 0x3`, and the multiply bit changes no AES-GCM
  path.
- **ChaCha20-Poly1305.** One operation of OpenSSL 3.6's `speed -aead` is one update over 16,384
  bytes: ChaCha20 and Poly1305 over them, with no nonce, associated data or tag. chapulin's row is
  its seal or open of one record less the tag's fixed work, which is the same work on the bytes.
  The next section has the rows for a whole record, for `rec_seal` and for each stage.

What the M1 Pro's column shows:

- SHA-256 and SHA-384 take 1.01 to 1.05 times OpenSSL's time, and a 64-byte SHA-256 0.71 of it.
  Under their bits a session's hashes run on the ARMv8 SHA-256 and SHA-512 instructions (decision
  93), and so do the HMACs of a server's ECDSA nonce (decision 102). A hash call that takes no
  `ch_cfg.cpu` value still runs portable C: a certificate's, the RSA signer's and the DRBG's.
- The two ECDSA verifiers run on 64-bit words in every session, where the 32-bit words took 23
  and 13 times OpenSSL's time. P-384 verifies in 0.88 of it: six 64-bit words, coordinates kept in
  the Montgomery domain and one pass over both scalars' signed digits (decision 97). P-256
  verifies in 0.97 of it, on variable-time Jacobian points in one pass, as P-384's (decision 104),
  with the field's additions inline (decision 114) and s's inverse by a binary GCD that stops once
  a is zero (decisions 115 and 116). The wide files' constant-time scalar multiplications took
  1.89 times (decision 104), and before decisions 114 to 116 it took 1.29 times.
- SHA3-256 takes 1.03 times OpenSSL's time over 16 KiB and 0.60 of it over 64 bytes. Under
  `CH_CPU_CONSTANT_TIME_SHA3` an arm64 object that clang compiled runs Keccak on the ARMv8 SHA-3
  instructions, as OpenSSL does (decision 99). On the portable code it took 1.58 and 0.89 times,
  and 3.33 and 1.19 before `sha3.c` moved eight bytes at a time (decision 98).
- RSA verifies in 1.24 and 1.21 times OpenSSL's time, on `rsa_mont64.c`'s 64-bit words in every
  session, with R^2 from a long division of the public modulus and a square of its own (decisions
  103 and 106), under clang a step that adds the carry from the word below last (decision 117),
  and under clang for arm64 multiplications and squares in blocks of four words (decision 118).
  Before decision 118 it took 1.51 and 1.52 times, before decision 117 1.75 to 1.81 times, and
  on the 32-bit words 18 to 21 times. `openssl speed` verifies under a key object
  that keeps the Montgomery values it computed the first time. A client verifies under each
  certificate's key once, and with the key built from its bytes before each verification OpenSSL
  took 26.2 and 47.3 µs (decision 103). Under the multiply bit an RSA-2048 PSS signature takes
  655 µs, by the Chinese remainder theorem with a check of every signature, where OpenSSL's
  PKCS#1 v1.5 signature takes 552 µs. Before decision 118, on `rsa_mont64.c`'s loops alone, it
  took 813 µs, and the ladder took 37.6 ms (decision 95).
- P-256's key generation and shared secret take 1.04 and 1.27 times OpenSSL's time, and its
  signature 0.77 of it. Under the multiply bit they run on four 64-bit words, k·G adds 43 entries
  of an 86 KiB table of multiples of G (decisions 94 and 109), 41 of them on nine products and two
  squares (decision 111), the key exchange doubles and adds in Jacobian coordinates (decision 112),
  the field and the scalar square on ten products (decision 105), the field adds and subtracts
  inline (decision 114), an inverse runs Pornin's binary GCD (decision 115), and a server's nonce
  runs on the SHA-256 instructions (decision 102). On the 32-bit words they took 15 to 63 times.
  Before decisions 114 and 115 they took 1.35, 1.43 and 1.23 times, before decisions 111 and 112
  1.57, 1.67 and 1.35, and before decisions 108 and 109 1.99, 1.91 and 1.56. A field multiply in
  C is what is left, and "Where a server handshake's instructions go" below orders the work.
- ML-KEM-768 is ahead of OpenSSL in all three operations: 0.34 of its time for key generation,
  0.59 for encapsulation and 0.40 for decapsulation. Its hashes run on the SHA-3 instructions, its
  matrix sampler squeezes eight groups a call (decision 100), and its NTT and base multiplication
  run on NEON (decision 101). X25519 and the three AEADs are within a quarter of OpenSSL's time.
- OpenSSL's ML-KEM-768 rows run on one key object, which holds the matrix OpenSSL expanded when it
  made the key, and chapulin's start from the key's bytes, as a handshake's do. Decoding the
  public key first takes OpenSSL's encapsulation on this M1 Pro from 23.9 µs to 36.0 µs (decision
  100).

What the columns of the x86-64 CPU without AVX-512 show, where they differ from the M1 Pro's:

- Both compilers' columns are one run of 2026-10-09 on the tree of decision 119, on an AMD EPYC
  7763, the CPU the runs on the trees of decisions 107, 109, 110, 113, 116 and 117 drew as well.
  The bench job stops on a CPU with AVX-512, so these columns never run `rsa_ifma.c`. The runner's
  CPU changes from run to run, so a column compares rows of one run with each other, and with an
  earlier run's only on the same CPU. Against the run on the tree of decision 117, under
  `ch_cfg.cpu 0x3f` no gcc row moved by more than 4%, and no clang row by more than 3% but RSA's
  and the DRBG's: under clang RSA's verifications took 0.93 to 0.95 of their earlier time, its
  signatures 0.95 and the RSA handshakes 0.95 to 0.96, and the DRBG 1.08 and 1.09 times it.
  Against the run on the tree of decision 113, decisions 114 to 116 took P-256's key generation,
  shared secret, signature and verification under gcc from 1.64, 1.97, 1.60 and 1.63 times
  OpenSSL's time to this run's 1.49, 1.80, 1.21 and 1.41, and before that decisions 111 to 113
  took the first three from 2.08, 2.16 and 1.84 times, and X25519's two rows from 1.82 and 1.68
  to 1.60 and 1.49.
- The clang column is the same object built by the pinned clang 23 on the same CPU in the same
  job. clang's code is faster on the wide fields' carry chains: P-256 takes 0.73 to 0.76 of gcc's
  time, which puts its signature at 0.91 of OpenSSL's time and its verification at 1.06 times,
  P-384 verifies in 0.54 of gcc's time and X25519 in 0.86 and 0.87. It is also faster for
  ML-KEM-768, 0.88 to 0.95 of gcc's time, and AES-GCM, 0.84 to 0.90, and every ML-KEM-768 and
  AES-GCM row is ahead of OpenSSL. RSA verifies in 0.98 to 0.99 of gcc's time. clang is slower for
  SHA-384, 1.02 times gcc's time over 16 KiB and 1.21 times over 64 bytes.
- AES-GCM is ahead of OpenSSL. Under the VAES bit the seal and the open run the VAES and
  VPCLMULQDQ kernels of decision 90, and with the key expansion they take 0.76 to 0.83 of
  OpenSSL's time under gcc. ChaCha20-Poly1305 takes 1.23 times. Under `CH_CPU_AVX2` and the
  multiply bit its keystream runs eight blocks a pass in 256-bit vectors (decision 90) and its
  Poly1305 eight blocks at a time in four AVX2 lanes (decision 110). Of the 9.20 µs that sealing a
  16 KiB record takes under gcc, less the tag's fixed work, the keystream is 6.50 and Poly1305
  2.65, where OpenSSL takes 7.46.
- ML-KEM-768's key generation, encapsulation and decapsulation take 0.54, 1.01 and 0.76 of
  OpenSSL's time under gcc, against rows that hold a key's expanded matrix (decision 100). Under
  `CH_CPU_AVX2` its matrix runs on four Keccak states side by side (decision 107), and its NTT and
  base multiplication run on SSE2 (decision 101).
- P-384 verifies in 0.92 of OpenSSL's time under gcc and P-256 in 1.41 times, on the 64-bit words of
  decisions 97 and 96 and, for P-256, the Jacobian points of decision 104 and the inverse of
  decisions 115 and 116, where the 32-bit words took 8.8 and 30 times.
- SHA-256 runs at OpenSSL's time over 16 KiB and in 0.89 of it over 64 bytes under gcc, on the
  SHA extensions (decision 93). SHA-384 stays on portable C there, 2.14 and 1.57 times: the tree
  holds no x86-64 SHA-512 code, and `sha512_hw.c` is arm64's alone (decision 93). SHA3-256 takes
  1.33 and 1.05 times, where
  `sha3.c`'s loops took 7.68 and 5.02 times (decision 98).
- P-256's key generation and shared secret take 1.49 and 1.80 times OpenSSL's time under gcc, and
  its signature 1.21 times, on the wide files with the table of decision 109, the additions of
  decision 111, the Jacobian key exchange of decision 112, the inline additions of decision 114
  and the binary GCD of decision 115, where the native copies of the 32-bit files took 21 to 90
  times. gcc compiles the wide files' carry steps from the two x86-64 intrinsics (decision 94).
- RSA verifies in 1.87 and 1.99 times OpenSSL's time under gcc, and an RSA-2048 PSS signature takes
  1.48 ms where OpenSSL's PKCS#1 v1.5 signature takes 659 µs. This CPU has no AVX-512 IFMA, so
  the public operation runs on `rsa_mont64.c`'s loops (decisions 95 and 117).
- X25519 is further behind than on the M1 Pro: 1.62 times OpenSSL's time for key generation and
  1.49 times for a shared secret on gcc's code, and 1.39 and 1.29 times on clang's, which takes
  0.86 and 0.87 of gcc's time even with gcc's carry inline (decision 113).

What the AVX-512 machine's columns show:

- Both compilers' columns are one run of 2026-10-09 on the tree of decision 119, on an Intel Xeon
  Platinum 8573C, under `ch_cfg.cpu 0x13f`, the bits the CPU without AVX-512 states and
  `CH_CPU_AVX512_IFMA`, and under `0x1f` for the AEAD rows. The two x86-64 machines are different
  CPUs, so both chapulin's and OpenSSL's times change between them. OpenSSL's change most where
  its source holds AVX-512 code: an AES-128-GCM seal takes 1.19 µs here and 4.05 µs on the CPU
  without AVX-512, a ChaCha20-Poly1305 seal 4.48 and 7.46 µs, and an RSA-2048 signature 324 and
  659 µs, under gcc.
- RSA verifies in 0.49 and 0.40 of OpenSSL's time under gcc and 0.48 and 0.42 under clang, the one
  machine where chapulin's RSA verification is ahead. Under `CH_CPU_AVX512_IFMA` the public
  operation runs in `rsa_ifma.c`'s 52-bit digits on AVX-512 IFMA (decision 119). OpenSSL 3.6.4
  verifies on its MULX Montgomery multiplication, `bn_mulx4x_mont` in
  `crypto/bn/asm/x86_64-mont.pl`.
- An RSA-2048 PSS signature takes 1.24 ms under gcc and 886 µs under clang, where OpenSSL's PKCS#1
  v1.5 signature takes 324 and 303 µs. On a CPU with AVX-512 IFMA, OpenSSL 3.6.4 runs the two
  exponentiations of a 2,048-, 3,072- or 4,096-bit private key on it
  (`ossl_rsaz_mod_exp_avx512_x2`, `crypto/bn/asm/rsaz-2k-avx512.pl` and its 3k and 4k files).
  These columns were recorded before decision 120, when chapulin signed on `rsa_sign64.c`'s 64-bit
  words under the multiply bit with `CH_CPU_AVX512_IFMA` or without it. Under both bits it now
  computes the two exponentiations on `rsa_ifma_sign.c` and checks the signature on `rsa_ifma.c`,
  and decision 120 records what that changed on this CPU model.
- AES-GCM takes 2.0 to 2.3 times OpenSSL's time and ChaCha20-Poly1305 2.2 to 2.5 times. OpenSSL
  3.6.4's source holds AVX-512 code for both: `crypto/modes/asm/aes-gcm-avx512.pl`, and AVX-512
  paths in `crypto/chacha/asm/chacha-x86_64.pl` and `crypto/poly1305/asm/poly1305-x86_64.pl`.
  chapulin runs AES-GCM two blocks to a 256-bit register on VAES and its ChaCha20 keystream on AVX2
  (decision 90), and Poly1305 in four AVX2 lanes (decision 110).
- Under clang P-256's key generation, signature and verification take 0.99, 0.85 and 0.83 of
  OpenSSL's time and its shared secret 1.07 times, and P-384 verifies in 0.51 of it. Under gcc
  P-256 takes 1.08 to 1.42 times and P-384 0.95.
- SHA-384 takes 1.54 to 1.98 times OpenSSL's time, SHA3-256 1.30 times under gcc and 1.28 under
  clang over 16 KiB, and X25519 1.12 to 1.38 times. ML-KEM-768's encapsulation takes 1.16 times
  under gcc and 1.00 under clang, and its key generation and decapsulation 0.49 to 0.84 of OpenSSL's
  time.

To record a column again after a change to a primitive:

```sh
make bench-primitives              # every row above the AEADs; about nine minutes
make bench-record                  # the six AEAD rows; about a minute
python3 tools/bench_scoreboard.py  # prints the table and the machines' lines to paste here
make lint-bench-numbers
```

The four x86-64 column groups are bench.yml's `record-x86_64` job, a matrix of two jobs. Each job
runs both scripts under gcc and under the pinned clang on its own GitHub runner: one on a CPU
without AVX-512, and one, with `BENCH_MACHINE=avx512`, on a CPU with AVX-512 IFMA. A runner's CPU
model is drawn, not chosen, so each job first reads `/proc/cpuinfo` and stops when it drew the wrong
kind; `gh run rerun <run> --failed` draws again. `gh workflow run bench.yml --ref <branch>` starts
both, and the CSVs they keep in their `results-linux-x86_64` and `results-linux-x86_64-avx512`
artifacts, `results-primitives-linux-x86_64[-avx512]-<compiler>.csv` and
`results-record-linux-x86_64[-avx512]-<compiler>.csv` for gcc and clang, go into `bench/`.

### Where a record's time goes

[`bench/record.sh`](../bench/record.sh) (`make bench-record`) times the protection of one TLS
record and splits it into its stages, for [#184](https://github.com/c4milo/chapulin/issues/184)
(AES-GCM) and [#181](https://github.com/c4milo/chapulin/issues/181) (ChaCha20-Poly1305). It
compiles the library sources with the flags `make lib` uses and the defines of a
`SUITE=aesgcm` host object, once for each `ch_cfg.cpu` value it times, and every row hands that
value to the calls a session hands its own to (decision 89). The values are 0x3, the probe's bit
and the AES bit; 0x7, which adds the multiply bit and so the vector Poly1305 (decision 83); and,
on an x86-64 CPU with the instructions, 0x1f, which adds the kernels of decision 90. It times
these on the same buffers:

- `rec_seal`, which copies the caller's plaintext into the record and seals it in place, as
  `ch_write` calls it, and `rec_open`, which opens a record in place, as `ch_read` calls it;
- the AEAD calls `record.c` makes, with the same buffers;
- each stage of the AEAD: a library function where the stage has one, and an entry
  [`bench/record_stages.h`](../bench/record_stages.h) adds where the stage is static; for
  AES-GCM that includes counter mode and GHASH alone, which the seal and the open no longer run
  apart over whole passes, beside the loops that run them together;
- `rec_seal` and `rec_open` compiled with stubs in place of the AEAD, which is the record
  layer's own work.

One stage has no function of its own, so its row is a difference of two timed rows:
`chacha20_xor_cpu` less the keystream's passes gives the ChaCha20 exclusive-or. The passes' row is
`chacha20_vector.c`'s, eight blocks a pass on NEON and four on SSE2, or the AVX2 kernel's, with each
pass's keystream stored to a buffer. AES-GCM's exclusive-or has no row: `gcm_hw.c` runs it in the
same pass as the AES rounds (below), so its time is inside counter mode's and the loops'.

Each figure is the median of five runs, and each run's figure is the median of 15 batches of at
least 1 ms, with every row's batches interleaved. The CSVs hold every row at 1 KiB, 16 KiB and
64 KiB, each with its spread and its batches at the 10th and 90th percentile, and a check line
that compares each whole with the sum of its parts.

The machine is an Apple M1 Pro that ran other work: its one-minute load average was 6.3 to 7.9
where the CSV headers record it. A Linux CSV's own load average line is the VM's, and its first
line holds the host's. So these figures are the filter's, in the terms of the method below. The
three columns are three CSVs:

- macOS 26 with Apple clang 21:
  [`bench/results-record-darwin-arm64-clang.csv`](../bench/results-record-darwin-arm64-clang.csv);
- Linux 7.0 in an OrbStack VM on the same machine, which is where stompy runs, with clang 18:
  [`bench/results-record-linux-arm64-clang.csv`](../bench/results-record-linux-arm64-clang.csv);
- the same VM with gcc 13, the compiler CI runs:
  [`bench/results-record-linux-arm64-gcc.csv`](../bench/results-record-linux-arm64-gcc.csv).

Each row's build column names the `ch_cfg.cpu` value it ran under:

- `ch_cfg.cpu 0x3` is a host session whose caller set `CH_CPU_CONSTANT_TIME_AES`: the AES-GCM
  rows, and ChaCha20-Poly1305 with Poly1305 on the 16x16 decomposition;
- `ch_cfg.cpu 0x7` adds `CH_CPU_CONSTANT_TIME_MULTIPLY`, and its ChaCha20-Poly1305 rows run the
  vector Poly1305. The bit changes no AES-GCM path, so the 0x3 AES-GCM rows are that session's too.

A host session never runs `chacha20.c`'s portable loop, so no row here times it;
[`bench/aead.sh`](../bench/aead.sh) times it in a device object's sources. The tables this section
held before decision 89, when build variables chose the paths, had rows for that loop, and the text
below names their figures where it compares against them, with the commit that measured them.

stompy's chapulin compiles with Zig's clang, so the clang columns are the nearest to it. A share
in parentheses is the stage's part of `rec_seal`. The last rows of each table are two other
libraries on the same machine: `openssl speed -aead`, the median of five one-second runs, and
Zig 0.16.0's `std.crypto`, timed as the other rows are, which the VM does not have.

What one operation of `openssl speed -aead` holds depends on the OpenSSL release, and the macOS
column's is 3.6.5 where the VM's is 3.0.13. So each table has a row for each operation, and a
column fills the rows its release times ([`bench/record.sh`](../bench/record.sh) states where each
reading comes from):

- OpenSSL 3.0 sets the IV, hashes 13 bytes of associated data, encrypts the record and computes
  the tag, under a key set before the loop. chapulin's row for that operation is the AEAD's seal
  or open.
- OpenSSL 3.6 does the same for AES-GCM and sets the key as well, for every operation. chapulin's
  row for that operation is the AEAD under a key expanded for the record, which is what
  `record.c`'s `seal_aes_gcm` and `open_aes_gcm` run: `rec_dir` keeps the key's bytes and no
  expanded key, so every record pays the expansion.
- For ChaCha20-Poly1305, OpenSSL 3.6 runs one update over the record's bytes, with no nonce,
  associated data or tag. chapulin's row for that operation is the seal or the open less its
  tag's fixed work.

| AES-128-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 2.6 | 3.1 | 3.2 |
| `rec_seal` without its AEAD | 0.5 (18%) | 0.6 (19%) | 0.7 (21%) |
| the AEAD under a key expanded for the record, as `seal_aes_gcm` runs it | 2.3 | 2.8 | 2.8 |
| the AEAD's seal, `gcm_traffic_seal` | 2.1 (83%) | 2.6 (83%) | 2.5 (79%) |
| counter mode and GHASH in one loop, the seal's whole passes | 2.1 (81%) | 2.5 (80%) | 2.5 (77%) |
| counter mode alone, in place | 1.6 | 1.7 | 1.7 |
| GHASH alone, over the ciphertext | 1.0 | 1.1 | 1.4 |
| `rec_open` | 2.4 | 2.8 | 2.8 |
| the AEAD under a key expanded for the record, as `open_aes_gcm` runs it | 2.4 | 2.8 | 2.8 |
| the AEAD's open, `gcm_traffic_open` | 2.2 | 2.6 | 2.5 |
| GHASH and counter mode in one loop, the open's whole passes | 2.1 | 2.5 | 2.4 |
| OpenSSL, the key set and one record sealed | 2.1 | — | — |
| OpenSSL, the key set and one record opened | 2.1 | — | — |
| OpenSSL, one record sealed under a key set before | — | 2.8 | 2.8 |
| OpenSSL, one record opened under a key set before | — | 2.9 | 2.9 |
| Zig `std.crypto`, one record sealed | 4.3 | — | — |

| AES-256-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 3.0 | 3.6 | 3.7 |
| the AEAD under a key expanded for the record, as `seal_aes_gcm` runs it | 2.8 | 3.2 | 3.3 |
| the AEAD's seal, `gcm_traffic_seal` | 2.6 (84%) | 3.0 (82%) | 3.0 (80%) |
| counter mode and GHASH in one loop, the seal's whole passes | 2.5 (82%) | 2.9 (80%) | 3.0 (80%) |
| `rec_open` | 2.9 | 3.3 | 3.3 |
| the AEAD under a key expanded for the record, as `open_aes_gcm` runs it | 2.9 | 3.3 | 3.3 |
| the AEAD's open, `gcm_traffic_open` | 2.6 | 3.0 | 3.0 |
| OpenSSL, the key set and one record sealed | 2.5 | — | — |
| OpenSSL, the key set and one record opened | 2.5 | — | — |
| OpenSSL, one record sealed under a key set before | — | 3.1 | 3.1 |
| OpenSSL, one record opened under a key set before | — | 3.2 | 3.1 |
| Zig `std.crypto`, one record sealed | 5.3 | — | — |

| ChaCha20-Poly1305, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal`, `ch_cfg.cpu 0x3` | 40.7 | 37.1 | 54.9 |
| `rec_seal` without its AEAD | 0.2 (1%) | 0.4 (1%) | 0.4 (1%) |
| ChaCha20 in place | 8.1 (20%) | 8.1 (22%) | 9.0 (16%) |
| Poly1305 over the ciphertext, on the 16x16 decomposition | 31.9 (78%) | 28.1 (76%) | 45.6 (83%) |
| `rec_open`, `ch_cfg.cpu 0x3` | 40.4 | 36.7 | 54.6 |
| `rec_seal`, `ch_cfg.cpu 0x7` | 11.2 | 11.6 | 12.3 |
| the AEAD's seal, `aead_seal_cpu`, `ch_cfg.cpu 0x7` | 10.9 (98%) | 11.3 (97%) | 11.8 (97%) |
| the seal less its tag's fixed work, `ch_cfg.cpu 0x7` | 10.8 | 11.1 | 11.7 |
| ChaCha20 in place, `ch_cfg.cpu 0x7` | 8.1 (73%) | 8.2 (70%) | 8.9 (73%) |
| Poly1305 over the ciphertext, the vector path | 2.6 (23%) | 2.9 (25%) | 2.8 (22%) |
| `rec_open`, `ch_cfg.cpu 0x7` | 10.9 | 11.2 | 11.9 |
| the AEAD's open, `aead_open_cpu`, `ch_cfg.cpu 0x7` | 10.9 | 11.2 | 11.9 |
| the open less its tag's fixed work, `ch_cfg.cpu 0x7` | 10.8 | 11.0 | 11.7 |
| OpenSSL, one record sealed | — | 10.0 | 10.0 |
| OpenSSL, one record opened | — | 10.0 | 10.0 |
| OpenSSL, ChaCha20 and Poly1305 over the record's bytes, sealing | 9.2 | — | — |
| OpenSSL, ChaCha20 and Poly1305 over the record's bytes, opening | 9.1 | — | — |
| Zig `std.crypto`, one record sealed | 36.8 | — | — |

| Work a record pays whatever its size, and a 1 KiB record, ns | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| AES-128 key expansion, `aes_traffic_key_init` | 196 | 205 | 283 |
| AES-256 key expansion | 247 | 273 | 330 |
| the wipe of the expanded key | 5 | 4 | 5 |
| the GCM tag's fixed work | 50 | 56 | 55 |
| the Poly1305 tag's fixed work, on the 16x16 decomposition | 189 | 176 | 252 |
| the Poly1305 tag's fixed work, `ch_cfg.cpu 0x7` | 151 | 146 | 148 |
| AES-128-GCM `rec_seal`, 1 KiB | 457 | 491 | 584 |
| `rec_seal` without its AEAD, 1 KiB | 223 (49%) | 224 (46%) | 314 (54%) |

The stages add up: every whole is within 9% of the sum of its parts. Every gap of 5% or more is at
1 KiB: the parts of an AES-GCM AEAD sum to as much as 8% less than the AEAD, and the parts of the
GCM tag to as much as 8% more than the tag.
What the numbers show for AES-GCM:

- Counter mode runs a record's whole blocks through `gcm_hw.c`, eight blocks a pass. Each round key
  is loaded once and runs on the eight counter blocks of the pass, the eight keystream blocks are
  exclusive-ored into the data in vector registers, and the state that holds a pass's keystream
  is wiped once per call. The last partial block takes the one-block cipher. Counter mode alone,
  `gcm_counter_blocks_hw`, takes 1.6 to 1.7 µs of a 16 KiB AES-128 record, where the AES
  calls and the exclusive-or in place took 16.6 to 20.1 µs at 044a49c.
- gcc 13 at `-O2` needed `#pragma GCC unroll 8` for that. Without it, gcc left each loop over a
  pass's eight blocks rolled and kept the eight states in memory, and counter mode took 16.5 µs
  on gcc against 1.8 µs on clang (the pitfalls below).
- GHASH multiplies eight blocks a pass by the powers H^8 to H of the hash subkey, which each call
  computes first, and reduces once per pass. Since 88c64be every value stays in a vector register
  from the load to the reduction: three carry-less products a block in Karatsuba's form, and a
  reduction by 0xc200000000000000 on the same instruction (`ghash_vector.h`). GHASH alone takes
  1.1 to 1.4 µs of a 16 KiB record, where the one-block loop took 9.2 to 10.4 at 044a49c and the
  eight-block loop that took its sums out of the vector registers for each reduction took 2.2 to
  2.8 at 225a890.
- clang's GHASH is no longer the slower one: 1.1 µs against gcc's 1.4. clang loaded each power of
  H through two general registers; the powers now come from `ghash_state` in one vector load each,
  a volatile read that also keeps the compilers from copying them to stack slots the wipe does not
  clear (INV-17).
- The seal runs its whole passes through `gcm_seal_passes_hw` (c91e2f3). Each pass computes its
  keystream, writes its ciphertext and then hashes the pass before, whose GHASH waits on no AES
  round of this one, so the core runs one pass's AES rounds beside the other's carry-less
  multiplies. The loop takes 2.1 to 2.5 µs of a 16 KiB AES-128 record, where counter mode and
  GHASH alone take 2.7 to 3.0 one after the other.
- The open runs the same loop the other way round, `gcm_open_passes_hw` (01ba8fc): iteration p
  hashes pass p and decrypts pass p - 1, and the tag is compared once the plaintext is written,
  which a mismatch then wipes (decision 85). The loop takes 2.2 to 2.5 µs of a 16 KiB AES-128
  record.
- `rec_seal` copies the caller's plaintext with one `memmove`. gcc 13 did not vectorize the byte
  loop that did it before, and ran it one byte at a time: 5.9 µs, three fifths of gcc's AES-GCM
  seal once counter mode and GHASH were fast. The record layer's own work is now 0.5 to 0.7 µs of
  a 16 KiB AES-GCM record and 0.3 to 0.4 µs of a ChaCha20-Poly1305 one on both compilers.
- Each GHASH call wipes the part of its state it wrote: H, the powers it computed and a pass's
  sums. The tag's fixed work, one GHASH call over the associated data and one multiply for the
  block of lengths, each of which computes one power, takes 52 to 56 ns, where it took 150 to 169
  while `ct_wipe` stored one byte at a time (decision 91) and 240 to 300 at 225a890; a 1 KiB seal
  takes 469 to 584 ns. At 1 KiB the key expansion makes most of the record layer's share. The
  wipe of the expanded key that `record.c` runs for every record takes 4 to 5 ns of it, where it
  took 91 to 93.
- Measured one commit at a time, the three commits for
  [#184](https://github.com/c4milo/chapulin/issues/184) took the 16 KiB seal from 26.8, 27.6 and
  36.3 µs at 044a49c to 11.5, 12.9 and 17.6 µs with counter mode, to 4.8, 5.4 and 10.0 µs with
  GHASH, and to 4.9, 5.3 and 4.9 µs with the `memmove`. Three more, in paired runs of the four
  trees, took it from 4.8, 5.2 and 5.0 µs at 225a890 to 3.5, 3.8 and 4.0 µs with GHASH in vector
  registers (88c64be) and to 3.0, 3.5 and 3.5 µs with the one-pass seal (c91e2f3); the one-pass
  open (01ba8fc) took the 16 KiB open from 3.3, 3.3 and 3.6 µs to 2.9, 3.2 and 3.2 µs. In paired
  runs of a104a3e and the tree after it, the `memset` wipe (decision 91) took the 16 KiB seal from
  3.1, 3.6 and 3.7 µs to 2.7, 3.5 and 3.3 µs, and the 16 KiB open from 3.0, 3.4 and 3.3 µs to 2.6,
  3.0 and 2.9 µs.
- The seal now takes 2.7, 3.1 and 3.2 µs, and its AEAD alone 2.2, 2.6 and 2.5 µs. The open takes
  2.5, 2.8 and 2.8 µs, and its AEAD alone 2.3, 2.6 and 2.5 µs. Against 044a49c the seal takes 0.10,
  0.11 and 0.09 of its time, and the open 0.13, 0.13 and 0.09.
- Against OpenSSL on the same machine, operation for operation: on the VM, where OpenSSL 3.0.13
  seals under a key set before the loop, the AEAD's seal takes 0.91 and 0.92 times its time, and
  the open 0.91 and 0.87 times. On macOS, where OpenSSL 3.6.5 sets the key for every operation,
  the AEAD under a key expanded for the record takes 2.4 µs to seal and 2.5 to open, 1.13 and 1.17
  times OpenSSL's 2.1. Of chapulin's time, `aes_traffic_key_init` takes 202 ns, and 255 ns for
  AES-256. OpenSSL's whole operation on 16 bytes, key and tag included, takes 136 and 144 ns
  (`openssl speed -aead -bytes 16`, one run on the same machine), less than chapulin's key
  expansion alone.

For ChaCha20-Poly1305:

- A session without the multiply bit, `ch_cfg.cpu 0x3`, runs Poly1305 on the 16x16 decomposition
  `ct.h` builds, and there Poly1305 is the largest stage: 76% to 83% of the record. colibri's
  sessions are such sessions until it sets the bit.
- ChaCha20 runs the keystream and the exclusive-or in 8.1 to 9.0 µs on the vector path, on both
  compilers. `chacha20.c`'s portable loop, which a device object runs, took 34 to 35 µs here at
  a104a3e, when a build without `CHACHA=vector` ran it: 25.2 to 29.0 for the block function and
  6.3 to 8.9 for its exclusive-or, which ran one byte at a time in place. Since 97826ba a NEON pass
  computes two groups of four blocks side by side and XORs the keystream into the data from the
  registers that computed it (decision 86); a pass of one group took 13.6 to 14.6 µs. On clang the
  exclusive-or adds 0.4 to 0.6 µs to the keystream alone, whose row stores each pass's keystream to
  a buffer; under gcc 13 that row takes 0.4 to 0.5 µs longer than the whole, so the difference
  measures nothing there.
- With the multiply bit, `ch_cfg.cpu 0x7`, a session runs the vector Poly1305 too (decision 83),
  which takes Poly1305 over the ciphertext from 28.1 to 45.6 µs on the decomposition to 2.7 to
  2.9 µs. `rec_seal` then takes 11.6 to 12.3 µs, 22% to 31% of the 0x3 record's time, and a 1 KiB
  one 31% to 42%. ChaCha20 is 70% to 73% of the record, and Poly1305 22% to 25%. `rec_open` takes
  11.2 to 11.9 µs.
- Against OpenSSL on the same machine, operation for operation: on the VM, where OpenSSL 3.0.13
  seals a whole record, the AEAD's seal takes 1.13 and 1.18 times its time and the open 1.12 and
  1.19 times, and `rec_seal` and `rec_open` 1.16 and 1.22, and 1.12 and 1.19. On macOS, where
  OpenSSL 3.6.5 runs ChaCha20 and Poly1305 over the bytes and nothing else, the seal and the open
  less their tag's fixed work take 11.3 µs, 1.22 times OpenSSL's 9.3.
- A one-pass seal and open did not pay. In a scratch timing loop on the three columns' compilers, a
  seal that runs ChaCha20 over a chunk and then Poly1305 over the ciphertext it just wrote, and an
  open that hashes each chunk and then decrypts it, took no less time than two passes at any chunk
  from 512 bytes to 16 KiB. A 16 KiB record stays in the M1 Pro's 128 KiB L1 data cache between the
  passes, so the second pass reads it from that cache too, and every chunk calls the vector
  Poly1305 again, which computes and wipes the powers of r on each call: in chunks of 1 KiB, the
  seal took 13.8 µs on macOS where two passes took 11.8. With the powers computed once a record,
  every chunk took from 2% less to 3% more than two passes. So the seal keeps its two passes, and
  the open still compares the tag before it decrypts, which decision 85 allows.

The split named four candidates for [#184](https://github.com/c4milo/chapulin/issues/184), in
the order of the share of the record each one addressed:

1. Several counter blocks per iteration. The AES stage was a third or more of the seal, and its
   time went to the work done for each block: the per-block wipe, the calls and the round-key
   loads. `gcm_counter_blocks_hw` does that work once per pass or once per call (above).
2. GHASH over several blocks against precomputed powers of H. It was four fifths of the seal on
   clang after 1, one dependent multiply per block; `ghash_hw.c` now runs eight blocks per
   reduction (above).
3. A word-wide exclusive-or. `gcm_counter_blocks_hw` runs the exclusive-or of whole blocks in vector
   registers, so the byte loop runs only on a record's last partial block and in the builds that
   run AES on the table or a peripheral, none of which this split times; no word-wide loop was
   written. Beside it, `rec_seal`'s plaintext copy, which gcc ran one byte at a time, is one
   `memmove` (above).
4. One pass for the keystream and the hash. GHASH's reduction outside the vector registers and
   clang's loads of the powers through general registers fell on the seal and the open alike, so
   88c64be moved both into vector registers first. Then `gcm_seal_passes_hw` (c91e2f3) and
   `gcm_open_passes_hw` (01ba8fc) ran counter mode and GHASH in one loop, which hides most of the
   shorter one: 2.2 to 2.6 µs of a 16 KiB AES-128 record, where the two alone take 2.8 to 3.1. The
   open's loop needed the open to decrypt before it compares the tag, and to wipe the plaintext
   when the tag does not match (decision 85).

For [#181](https://github.com/c4milo/chapulin/issues/181), the numbers supported the vector path for
ChaCha20 first, because the block function and the in-place exclusive-or were half of the record on
clang with Poly1305 on the decomposition and more than two thirds of it on the native multiply, and
decision 82 added it. Its two paired runs on each platform agreed: the vector `rec_seal` took 0.71,
0.68 and 0.78 of the portable one's time in the three columns in the second, and 0.78, 0.70 and
0.78 in the first. In the last runs that timed both, at a104a3e with decision 86's two groups a
pass, it took 0.62, 0.60 and 0.68. Most of what remained of that record was Poly1305 on the
multiply decomposition: the same loop on the native multiply ran in about a third of the time. A
vector Poly1305 needs a widening multiply too, so it needs
the same statement about that multiply's timing, and decision 83 added one under it: `CHACHA=vector`
with `WIDEMUL=native`, where Poly1305 was most of what the vector ChaCha20 left. Paired runs agree
on each platform, two in the Linux VM and three on macOS, where the second ran at a load average of
44 to 78. In the last pair on each, that build's `rec_seal` took 0.66, 0.66 and 0.69 of its time
before the change in the three columns; the earlier pairs gave 0.66 and 0.66 on macOS, 0.57 on the
VM's clang and 0.65 on gcc 13. Those pairs came before each call of the vector Poly1305 began to
end with a wipe of the powers of r it computed, one `ct_wipe` of 208 bytes on NEON and 352 on
SSE2. The runs the tables now hold measure the code with that wipe, and the 128-byte threshold
still rests on decision 83's scratch timing. Under `ch_cfg.cpu 0x7` the vector Poly1305 takes 2.7
and 2.8 µs on macOS and gcc 13, as in the pairs, and 2.9 µs on the VM's clang. On that compiler
the figure moves with where the linker places the function. It took 4.7 µs in the bench build the
tables held at d10b6e2, and 3.0 µs in one whose `aes_hw.c` differed in one function; that build
with `-falign-functions=64` took 2.8 µs (the pitfalls below). It took 3.0 µs in the runs at
97826ba, 4.8 µs again at a104a3e, before decision 91 and after it alike, and 4.6 µs in this tree's
bench an hour before the tables' run, when `bench/record_rows.c` lacked its two `seal_aes_gcm`
rows.

ChaCha20 was then the larger stage of that build, 80% of its record, and decision 86 runs two groups
of four blocks a pass on NEON, because one group left the vector units waiting on each quarter
round's chain of operations. In paired runs, that build's 16 KiB `rec_seal` took 0.68, 0.70 and 0.69
of its time before the change in the three columns, and 0.67, 0.64 and 0.67 in the first pair. The
two builds that ran the portable ChaCha20 then did not move beyond the spread between runs: 68.1,
62.0 and 80.5 µs on the decomposition where the tables held 67.5, 60.8 and 79.0 at 9287540, and
46.3, 44.9 and 47.8 on the native multiply where they held 46.3, 44.0 and 47.0. OpenSSL's ChaCha20
alone took 7.0 µs over 16 KiB on macOS in three one-second runs of `openssl speed -evp chacha20`,
against that build's 8.5, and its whole seal took 9.4 against 11.8.

No x86-64 machine that runs nothing else has timed the vector paths' SSE2 arms or the AES-NI
arm of `gcm_hw.c`. bench.yml's `record-x86_64` job times them on a shared GitHub runner, once
with gcc and once with clang, and on a runner whose CPU has AVX2, VAES and VPCLMULQDQ it adds
the `ch_cfg.cpu 0x1f` rows for the x86-64 kernels of decision 90, which records the figures they
had when their rows were marked `AVX2+VAES`. The table beside OpenSSL above takes its x86-64
AEAD rows from that job's gcc CSV, `bench/results-record-linux-x86_64-gcc.csv`. A column in this
section's tables needs `make bench-record` on an x86-64 host that runs nothing else, once with gcc
and once with clang, and `tools/bench_record.py` then takes the two files as columns. An emulated
x86-64, such as an OrbStack amd64 container, runs translated code, so its times say nothing about
those arms.

### Where a server handshake's instructions go

[#188](https://github.com/c4milo/chapulin/issues/188) measured colibri's server at 55.4 M user
instructions per TLS connection on a Neoverse-N2, where h2o and nginx over OpenSSL 3.0.13 took 2.1
and 2.4 M. This section counts the server's side of that connection inside chapulin and splits it
into stages. The connection is the one h2load makes in colibri's bench: TLS 1.3 with
TLS_AES_256_GCM_SHA384 over X25519, a P-256 ECDSA leaf and the P-256 root that signed it, as in
colibri's test identity (here 444 and 387 bytes of DER), ALPN h2 and no ticket key. After the
handshake the client sends one 100-byte request record, the server answers with one 256-byte
record, and each side sends close_notify.

The figures were taken this way:

- The object is the issue's: c798fb8 with `RAND=session TRANSPORT=tcp-nonblocking ROLE=both
  TRUST=webpki EXPORTER=on SUITE=aesgcm AES=runtime CHACHA=vector TX_RECORD=16384 KEYLOG=off`
  and `CH_NATIVE_AES`, built by `build.zig` with Zig 0.16.0 for aarch64-linux-gnu. colibri builds
  for the CPU it runs on, so the N2 columns pass `-Dcpu=neoverse_n2`, and one column builds for
  the base armv8-a instead.
- A test server calls the object as colibri's server does (`ch_srv_record_init`,
  `ch_srv_record_in`, `ch_read`, `ch_write`, `ch_close`). An OpenSSL 3.0.13 client offers what
  h2load 1.59.0 offers there: the one suite, h2load's default groups X25519, P-256, P-384 and
  P-521 with an X25519 share, and ALPN h2. Both run in an arm64 Ubuntu 24.04 container in OrbStack
  on an Apple M1 Pro.
- QEMU 8.2.2 in user mode, with `-cpu neoverse-n2`, runs the server one instruction per
  translation block, as `bench/insn-*.sh` count. A scratch tool rebuilds the call stack from that
  trace and the binary's `bl` and `blr` addresses, and charges each instruction to the outermost
  crypto function it runs under, and inside `p256_sign` to the part of the signature it runs in:
  the nonce generator, `p256_point_base_mul`, `p256_point_affine_x` or the scalar arithmetic.
  Valgrind 3.22's callgrind, which cannot run the N2 build's SVE instructions, counted the base
  build's handshake at 42,370,882 instructions, and QEMU at 42,370,683.
- Each figure counts the user-mode instructions of the server process in the second connection
  of a run. The first takes about 3,000 more, and under callgrind a third matched the second to
  within 100.
- The OpenSSL column serves the same connection with OpenSSL 3.0.13, the same chain and key and
  no session tickets, under callgrind. Its two key rows come from separate calls of OpenSSL's
  public API, 20 of each: `EVP_PKEY_keygen` and `EVP_PKEY_derive` for X25519, and
  `EVP_PKEY_sign` over a SHA-256 digest for P-256. Under valgrind, OpenSSL finds no SHA-512
  instructions, so its SHA-384 runs the scalar code, 0.27 M of its handshake. A Neoverse-N2 has
  those instructions, and OpenSSL uses them there.
- No script in `bench/` writes these figures yet, so `make lint-bench-numbers` checks none of
  them.

| server side of one connection, M instructions | c798fb8 for Neoverse-N2 | for the base armv8-a | N2, `WIDEMUL=native` | N2, `WIDEMUL=native X25519=wide` | base, Zig's ReleaseSafe flags | OpenSSL 3.0.13 |
| --- | --- | --- | --- | --- | --- | --- |
| X25519 key share: key generation and shared secret | 33.83 | 25.48 | 4.32 | 0.79 | 67.42 | 0.89 |
| CertificateVerify: P-256 ECDSA signature | 16.39 | 16.21 | 5.51 | 5.51 | 24.17 | 0.21 |
| of which k·G, the 256-round ladder | 14.45 | 14.26 | 4.82 | 4.82 | 21.43 | — |
| of which the two inversions, the scalar arithmetic and the DER | 1.75 | 1.74 | 0.50 | 0.50 | 2.43 | — |
| of which the RFC 6979 nonce | 0.19 | 0.19 | 0.19 | 0.19 | 0.29 | — |
| transcript hashes and key schedule | 0.59 | 0.62 | 0.59 | 0.59 | 0.88 | — |
| certificate, other messages and their records | 0.06 | 0.07 | 0.06 | 0.06 | 0.18 | — |
| the handshake | 50.87 | 42.37 | 10.48 | 6.95 | 92.65 | 2.10 |
| one request's records and the two close_notify | 0.020 | 0.025 | 0.020 | 0.020 | 0.075 | 0.045 |

What the numbers show:

- Two public-key operations make up 98% to 99% of the handshake on the decomposed multiply and 91%
  to 94% on the native one. In the issue's object X25519 takes 66.5% and the signature 32.2%.
  Each X25519 scalar multiplication costs half of its row, because key generation runs the same
  ladder as the shared secret.
- The multiply decomposition is most of the gap. `WIDEMUL=native` alone takes the N2 handshake
  from 50.87 M to 10.48 M, and `X25519=wide` then takes it to 6.95 M. X25519 then costs 0.79 M,
  against OpenSSL's 0.89 M. In 0.2.0 a host session gets both from `CH_CPU_CONSTANT_TIME_MULTIPLY`
  (decision 89). At the commit that moved the wide field under that bit, the same object as a host
  object, built for the base armv8-a with no `AES` value, takes 7.06 M when its `ch_cfg.cpu` holds
  the AES bit and the multiply bit, and 42.30 M with the AES bit alone: callgrind as above, 7,061,840
  and 42,302,196 instructions in the second connection. At a104a3e the default object took 42.37 M
  on the base armv8-a, as at c798fb8, and a `WIDEMUL=runtime` object answered
  `CH_WIDEMUL_CONSTANT_TIME` took 12.08 M, 0.02 M above `WIDEMUL=native`'s 12.07 M. That object
  ran the 16-word field on the native multiply, which no object holds now.
- The CPU target costs instructions only on the decomposed multiply. Built for `neoverse_n2`,
  `x25519.c`'s `mul` holds SVE instructions that clang 21 emits for that CPU, and it runs 5,452
  instructions a call where the base build's runs 4,079: 8.39 M more over the 6,114 calls of a
  handshake. On the native multiply the N2 build is the cheaper one: X25519 costs 4.32 M against
  the base build's 5.86 M.
- The signature remains. It costs 5.51 M on the native multiply, 26 times OpenSSL's 0.21 M.
  `p256_point_base_mul` runs a 256-round Montgomery ladder with two complete additions a round
  on 32-bit words, and keeps no table of multiples of G (`p256_point.h`). OpenSSL 3.0's arm64
  build signs with the `ecp_nistz256` assembly, which reads a precomputed table of multiples of G
  and computes on 64-bit words. Items 2 and 3 below have since changed both for a host session
  that states its multiply, and this table's objects were not counted again.
- The rest is small. The transcript and key schedule take 0.59 M: HKDF and its HMAC-SHA384 take
  0.44 M, the SHA-384 transcript 0.07 M, and the SHA-256 transcript, which `transcript.h` runs
  beside SHA-384, 0.08 M. Messages and their records take 0.06 M.
- colibri's ReleaseSafe does not change the object. `build.zig` compiles it at ReleaseFast with
  sanitize_c, the stack protector and the stack check off, whatever mode the dependent builds in,
  and `--verbose-cc` shows `-O2` with no `-fsanitize`. Zig 0.16 compiles C for ReleaseSafe with
  `-O2 -fsanitize=undefined -fsanitize-trap=undefined -fstack-protector-strong
  -D_FORTIFY_SOURCE=2`, and the same sources with those flags take 2.2 times the instructions.
- This count accounts for 50.89 M of the 55.41 M user instructions per connection the issue
  measured. The other 4.5 M are outside it: colibri's own code, which this harness does not run,
  and any difference between the CPU features Zig detects on the runner and its `neoverse_n2`
  model. colibri's cleartext connection costs 0.22 M.

The order of the work, by the instructions each item removes from a handshake:

1. A host session that states its multiply, in 0.2.0, removes 43.9 M of the N2 object's
   50.87 M. That statement is the caller's (decision 89), so this item is colibri's.
2. k·G from a precomputed table of multiples of G, read by a full scan with mask selection, in
   place of the ladder: done, for a host session that states its multiply (decision 94). Eight
   odd multiples for each of 64 four-bit windows take 32 KiB of affine points, and k·G is 64
   mixed additions. Decision 109 widened the windows to six bits: 32 odd multiples for each of 43
   windows take 86 KiB, k·G is 43 mixed additions, and a key generation on the M1 Pro took
   14.8 µs where it took 18.7. On the M1 Pro under Apple clang 21 a signature went from 1.88 M instructions
   to 0.53 M and a key generation from 1.58 M to 0.23 M, where OpenSSL 3.6.5 takes 0.18 M and
   0.17 M. A session without the bit keeps the ladder: the table's additions are the wide
   field's. The key exchange multiplies the peer's point, which no table holds, by four-bit
   windows over eight multiples of it: 0.92 M instructions where the ladder on the wide field
   took 1.58 M and OpenSSL takes 0.48 M. In `bench/primitives.sh`'s pinned ECDSA P-256 handshake
   on the M1 Pro, with this item and the next, the server's side takes 162 µs where it took
   784 µs, and both ends retire 12.24 M instructions where they retired 17.23 M. The client's
   side takes 1.41 ms, of which `p256.c`'s verification on 32-bit words is 1.30 ms.
3. A 64-bit-word P-256 field and scalar under the multiply bit, as `x25519_wide.c` is for X25519:
   done (decision 94). On the M1 Pro under Apple clang 21, with the ladder unchanged, a signature
   through `p256_sign` went from 5.52 M instructions to 1.88 M and a key exchange through
   `p256_ecdh` from 5.04 M to 1.58 M, where OpenSSL 3.6.5 takes 0.18 M and 0.48 M. The Lean spec
   computes modulo p and n and states no word, so it serves both copies, and
   `bin/diff_p256_wide` runs each against it.
4. SHA-256 on the ARMv8 and x86-64 SHA instructions and SHA-512 on the ARMv8.2 ones, behind new
   `ch_cfg.cpu` bits. Hashing takes 0.78 M of the 6.95 M: the transcript and key schedule's
   0.59 M, the nonce's 0.19 M and the signed content's 0.01 M. CBMC cannot read the intrinsics,
   so equivalence tests against the portable code hold them, as they hold the AES instructions.
   Since decision 94 the RFC 6979 nonce is the largest part of a signature: 0.24 M of its 0.53 M
   instructions on the M1 Pro, where OpenSSL's whole signature takes 0.18 M.
5. X25519 key generation from a table of multiples of the base point, as BoringSSL computes it,
   which bounds the gain at the key generation's 0.39 M. It needs the same ruling as item 2.
6. A server whose suite hashes with SHA-384 stops the SHA-256 transcript, 0.08 M.

## The method behind these numbers

Every performance change follows pepegrillo's
[docs/performance.md](https://github.com/c4milo/pepegrillo/blob/main/docs/performance.md): measure
the gap, attribute the cost, choose the lever, build for the hardware, prove it, land it. This
document is chapulin's appendix to it, and two things set this tree apart from the others that share
the method: what binds is SRAM and flash before instructions, and constant time is a correctness
property, never a cost to trade (`ct.[ch]`).

- The judge is the device builds, through the scripts in [`bench/`](../bench/) that write the
  figures above; a laptop's speed is a filter that orders candidates and lands in no document. A
  figure here is measured, never estimated, and a change to the code re-measures it in the same
  commit (`make lint-bench-numbers`).
- `make check` builds every program those scripts build and runs none of them
  (`test/script-builds.sh`), so a source list that misses a source the code calls fails check
  rather than the next measurement. The instruction-count scripts take their sources and defines from the
  Makefile's `INSN_SRCS` and `INSN_DEF`, and the host builds take `AES_HW_SRCS` (decision 88).
- The record split above prints a filter's figures, as an exception to the rule above: a
  `SUITE=aesgcm` host object runs on hosts alone, so no device build can judge it, and
  [#184](https://github.com/c4milo/chapulin/issues/184) and
  [#181](https://github.com/c4milo/chapulin/issues/181) asked for the order the split gives. It
  orders candidates. A change it points to still needs a judge's runs on a host that runs nothing
  else, and this document names no such host yet.
- The table beside OpenSSL prints a filter's figures too, for the same reason: every row of it
  runs in a host object. It states each machine's load beside its figures and takes both sides of
  a ratio in one run, on CPU time for every row above the AEADs, and its CSV holds each chapulin
  row's instruction count where macOS gives one. It ranks the work by ratio. A change that claims
  a row records the row again with both scripts, and reports the instructions of the rows it
  moved.
- The units of work are a handshake, a record, a byte of SRAM and a byte of flash.
- A change stays when it lowers SRAM, flash or instructions past the noise on the device builds and
  raises none of them past it; a change that trades constant time for any of the three is refused,
  whatever it saves.
- The pitfalls it has paid for, as symptom, cause and rule, are the table below.

| symptom | cause | rule |
| --- | --- | --- |
| The 16-byte wipe after each AES block took 7.5 µs of a 16 KiB AES-GCM record, more than the AES rounds (044a49c). | `ct_wipe` stores one byte per iteration through a volatile pointer and is a call, and `aes_hw.c` ran it after every block. | Wipe a buffer once, after the loop that fills it, never once per block. |
| gcc 13's AES-GCM counter mode took 16.5 µs of a 16 KiB record where clang's took 1.8. | gcc at `-O2` leaves a loop of eight iterations over vector states rolled and keeps the states in memory, so every round loads and stores all eight. | A loop over the states a pass keeps in registers carries `#pragma GCC unroll`, and every change is measured under gcc as well as clang. |
| clang's GHASH took 2.6 and 2.8 µs of a 16 KiB record where gcc's took 2.2, on the same core. | clang loads each lane of a vector that PMULL reads from memory as a 64-bit word in a general register and moves it back into a vector register, two moves for each operand. | Read a PMULL loop's disassembly under both compilers, and look for `fmov` and `dup` from general registers inside it. |
| The vector Poly1305 took 4.7 µs of a 16 KiB record in one bench build under the VM's clang 18, and 3.0 µs in a build whose only difference was a function in `aes_hw.c`. | Where the linker places the function: the first build with `-falign-functions=64` took 2.8 µs. | When a row moves on a path the change did not touch, rebuild with functions aligned before reading the move as the change's. |
| `bin/ghash_equiv_test` found powers of H in the stack below a GHASH call after the call had wiped the state that held them (88c64be). | Holding the eight powers in registers across a pass, clang and gcc copied some to stack slots of their own, which the wipe of the state does not clear. | Read a value the wipe must clear from the wiped state, through a volatile lvalue, each time it is used, and run the stack check after every change to a loop that holds one. |
| gcc 13's one-pass seal loop took 3.6 µs of a 16 KiB record where it had taken 2.7, once the open called the same exclusive-or. | gcc at `-O2` kept one out-of-line copy of a helper that two pass loops call. For the AES rounds, whose keys are bytes and so may alias the states, such a copy stored all eight states every round. | A helper that works on the states a pass keeps in registers is `static inline`, and a pass loop's disassembly under gcc holds no call. |
| gcc 13's one-pass open loop took 3.5 µs of a 16 KiB record where its seal loop took 2.6. | With the first pass's hash before the loop, gcc counted the low byte of each counter in a register of its own and built each counter word with `bfi`, where the seal's loop reverses one word with `rev`. | Count `bfi` and `rev` in a pass loop's counter code under gcc, and when gcc builds the counters from bytes, change the loop's shape rather than the arithmetic. |
| Under clang 18, `bin/ghash_equiv_test` found powers of H in the stack below the one-pass open, and it passed under Apple clang and gcc. | With a pass's hash and its AES rounds in one block, clang 18 moved the powers' volatile reads up among the rounds and ran out of registers. | Put a pass loop's hash and its rounds in separate `if` blocks, and run the stack check under clang 18 as well as the compilers `make check` runs. |
| On the EPYC 7763 under gcc 13, the server side of a pinned RSA-2048 handshake took 2.07 ms where it had taken 1.88, after a change to `sha3.c`, which that handshake never calls. The signature's own row, in another program, stayed at 1.74 ms. | RSA on 64-bit words runs at one of two speeds on that CPU, by where the linker places it. With `-falign-functions=64` the signature's row took 1.93 ms and the RSA-2048 verify's 65.8 µs against 59.0, and the handshake's stayed at 2.07 ms. | A build with functions aligned does not cure this one: it shows the slower speed. Read a move of about a tenth on a path the change did not touch against that build's figure, and when they agree, record it as placement and leave the change alone. |
| An eight-block ChaCha20 pass took 36.6 µs over 16 KiB under gcc 13 and 8.4 under clang 18, in a scratch timing loop. | gcc 13 at `-O2` kept one out-of-line copy of a `static inline` function that ran a quarter round on both groups of a pass, called eight times a double round, so every call stored the 32 state vectors to memory and loaded them back. | Build a pass's rounds from a helper small enough that gcc inlines it, such as one quarter round on one group, and read the round loop's disassembly under gcc for a call. |
| On the CPU clock, an AES-GCM seal through OpenSSL took 5.9 µs for some minutes on the M1 Pro, and 2.1 µs before and after. | macOS placed the process on efficiency cores while other work held the performance cores, and a CPU clock counts that time as it counts any other. Under `taskpolicy -b`, which runs a process on those cores, the same seal took 7.2 µs. | Read a row's spread between runs before its median. A run on efficiency cores moves the spread past 100%, and `bench/primitives.sh` warns past 50%. |
| The AES-GCM AEAD read as 1.05 times OpenSSL's seal on macOS, and under a key expanded for the record, which is the operation OpenSSL timed, as 1.13 times. | OpenSSL 3.6's `speed -aead` sets the key for every operation, where 3.0's sets it before the loop, and for ChaCha20-Poly1305 3.6 runs one update with no nonce and no tag. | Before a ratio against another library's benchmark, read what one of its operations holds in the release that ran, and time a 16-byte operation to confirm it. `bench/record.sh` names each OpenSSL row after the stage that times the same operation. |
| gcc 13 for arm64 wrote 13 vector registers to the stack in `sha3_hw.c`'s permutation, and three a round with four lanes held in a struct the function wiped, where clang 18, 21 and 23 wrote none. | A round of Keccak-f[1600] keeps 32 values at once, the 25 lanes and seven more, and arm64 has 32 vector registers. A compiler that needs a 33rd writes a lane to a slot it picks, and no wipe written in C clears one. | Before a path that keeps every register live holds secrets, count its stores of vector registers to the stack under each compiler that builds it. Decision 99 builds this one under clang alone. |
| Apple clang 21 and clang 23 compiled a second copy of an earlier form of `sha3_hw.c`'s permutation for the arguments one caller passed, and the second copy wrote five or six lanes to the stack where the first wrote none. | A compiler picks the registers of each copy of a function anew. | Call a function whose register use a check depends on through a volatile function pointer, so the one copy compiled is the copy checked (decision 99). |
| With four lanes of the Keccak state kept in memory to free four registers, clang took 30% longer over 16 KiB, and 2.5% longer once the round computed their row first. | The next round's column parities read those lanes first, so each read waited for the store the round before had just made. | A value a loop keeps in memory to free a register is written early in an iteration and read late. |
| Under gcc 13 on x86-64, an ML-KEM-768 encapsulation spent 49,591 of its 515,432 instructions in `sha3.c`'s `block_bytes`, which writes out squeezed bytes. | gcc at `-O2` kept `lane_to_bytes`, a loop over a lane's eight bytes, as a loop: a shift and a one-byte store each iteration. With each byte named, it compiles the eight stores to one 8-byte store. | Name each byte of a lane's store, as `lane_from_bytes` names each byte of its load, and count a byte loop's stores in gcc's disassembly. |
| The Jacobian key exchange's multiplication took 58.2 µs on the M1 Pro where a scratch program's, on the same products and sums, took 54.0 (decision 112). | The doubling computed Z3 = 2 Y1 Z1 last, as the Explicit-Formulas Database writes it, and the next doubling squares Z first, so each of 253 doublings waited for the product and the sum that ended the one before. Every field operation is a call, and the core starts a call's work before the call before it ends only where it reads nothing that call writes. | In a chain of point formulas, compute first what the next formula reads first, and time the chain, never one formula alone. |
