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
| `ch_tls` under `ROLE=server SUITE=aesgcm` | 2272 | — |
| **total static working set, `ROLE=server SUITE=aesgcm`** (2048 buffer) | **4320** | — |
| `ch_tls` under `TRUST=webpki SUITE=aesgcm` | 3368 | — |
| **total static working set, `TRUST=webpki SUITE=aesgcm`** (12338 buffer, its floor) | **15706** | — |
| `ch_tls` under `ROLE=server SUITE=aesgcm AES=runtime` | 2280 | — |
| **total static working set, `ROLE=server SUITE=aesgcm AES=runtime`** (2048 buffer) | **4328** | — |
| `ch_tls` under `TRUST=webpki SUITE=aesgcm AES=runtime` | 3376 | — |
| **total static working set, `TRUST=webpki SUITE=aesgcm AES=runtime`** (12338 buffer, its floor) | **15714** | — |

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
of one name apart, and compiles what make packages. The RSA verify holds
the deepest frames, so it sets the `ch_connect` peak in the default
build; it runs once per ticket lifetime, and every byte unwinds before
`ch_connect` returns.

| call | arm64 |
|---|---|
| peak stack, `ch_connect` (RSA-3072 verify) | 4992 |
| peak stack, `ch_connect` (`TRUST=raw-ecdsa`) | 3104 |
| peak stack, `ch_connect` (PSK) | 2768 |
| peak stack, `ch_connect` (`TRUST=ca-rsa` / `TRUST=ca-ecdsa`) | 5472 / 3264 |
| peak stack, `ch_connect` (`TRUST=webpki`) | 16528 |
| peak stack, `ch_connect` (`TRUST=webpki SUITE=aesgcm`) | 16656 |
| peak stack, `ch_connect` (`KEX=pq`) | 15872 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1712 |
| peak stack, `ch_write` / `ch_close` | 944 / 896 |
| peak stack, `ch_srv_accept` (`ROLE=server`) | 10304 |
| peak stack, `ch_srv_accept` (`ROLE=server SUITE=aesgcm`) | 10448 |

### What the larger builds pay for

**`KEX=pq`.** The hybrid build costs more of both:

- The session struct grows because the ClientHello carries a 1,216-byte
  key share and is built whole into one staging array.
- The stack grows because ML-KEM's K-PKE encrypt holds three polynomial
  vectors and two polynomials: 5,744 bytes in that one frame, against a
  2,560-byte budget for every other build (INV-19 carries the per-build
  numbers). The whole chain peaks at 15,872 bytes, through
  `mlkem_decaps` into K-PKE encrypt and Keccak, so the hybrid build
  needs about three times the stack of the classic one rather than the
  single frame's 5,744.

A device that cannot spare it builds the classic key exchange.

**`TRUST=webpki`.** A `TRUST=webpki` build carries the hybrid in every
build, so it pays both costs too, and its handshake state also holds the
P-256 scalar and point a retry to secp256r1 draws
([`docs/decisions.md`](decisions.md) 63). Its session struct carries a
larger TX staging array for the `server_name` and ALPN extensions and
for both key shares, the 1,216-byte hybrid one and a 32-byte x25519 one
([`docs/decisions.md`](decisions.md) 51), and for the third group it
lists, secp256r1 (63). Its `ch_connect` peaks at 16,528 bytes, through
ML-KEM's decapsulation, above the 7,344 its chain walk into an RSA-4096
verify reaches with ML-KEM pruned from the call graph
(`STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk`). RSA-4096 is the widest
modulus a public root carries.

**`ROLE=server`.** A server build pays them as well, because every
server holds the hybrid ([`docs/decisions.md`](decisions.md) 54). Its
ServerHello is built in the clear in the same staging array, and the
hybrid one carries a 1,120-byte share, so the array holds 1,216 bytes of
message behind the record header. `ch_srv_accept` peaks at 10,304
bytes, through the encapsulation to the client's key into K-PKE encrypt
and Keccak, above the 5,280 its RSA-PSS signer reaches with the
encapsulation pruned from the call graph (`STACK_PRUNE=srv_kex_share`).

**`SUITE=aesgcm`.** `bench/sram.sh` measures a `SUITE=aesgcm` build with
`AES=hw` on this host, so its rows are host figures and have no rv32
column. A suite build with `AES=extern` can run on a device with an AES
peripheral ([`docs/decisions.md`](decisions.md) 68), and no script here
measures one on a device target yet. Its session struct is 288 bytes
larger than the same `ROLE=server` build without the suite, and 304
larger for `TRUST=webpki`:

- the transcript runs a SHA-512 context beside SHA-256's;
- the traffic secrets take SHA-384's 48 bytes;
- a webpki hello lists two more suites
  ([`docs/decisions.md`](decisions.md) 58);
- a webpki client's configuration holds the caller's suite order, a
  pointer and a count ([`docs/decisions.md`](decisions.md) 80).

**`AES=runtime`.** The same two suite builds on `AES=runtime` hold one more
byte in `ch_cfg`, `aes_instructions`, the caller's answer about the AES
instructions ([`docs/decisions.md`](decisions.md) 81). The pointer that
follows it aligns to 8 bytes, so each session struct is 8 bytes larger than
the `AES=hw` build's, and `ch_quic` in the QUIC object colibri links, which
the script prints, is 8 bytes larger too. The value runs on arm64 and
x86-64 alone, so these rows are host figures as well. `bench/sram.sh` does
not measure the stack of an `AES=runtime` build.

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
| AEAD seal, per 1 KB record | 82 k | 0.16 | 68 k | 107 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 38.9 M | 78 | 27.4 M | 51.4 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`TRUST=raw-ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 90.2 M | 180 | 63.8 M | 117.0 M |
| ML-KEM-768 keygen (`KEX=pq`) | 3.2 M | 6 | 2.7 M | 3.6 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 3.6 M | 7 | 3.0 M | 4.1 M |
| full hybrid handshake crypto (`KEX=pq`) | 100.4 M | 201 | 72.2 M | 128.3 M |

### The multiply decomposition

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:

- on mips32r2, AEAD seal costs 73% more, x25519 36% more, and the
  pinned handshake 29% more, or 41 ms at 500 MHz;
- on the Cortex-M3, AEAD seal costs 93% more, x25519 129% more, and the
  pinned handshake 94% more;
- on rv32imac, AEAD seal costs 66% more, x25519 137% more, and the
  pinned handshake 104% more.

SHA-256 and both signature verifies are unchanged, because SHA-256 does
not multiply and the verifies read only public bytes.

### Flash

Flash is 28.0 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.3 kB, nearly all of it
poly1305's unrolled block: the `total (CH_NATIVE_WIDEMUL)` row of
[`bench/results-device.csv`](../bench/results-device.csv) sizes the same
modules over the native multiply.

The `TRUST=raw-ecdsa` build trades 2.2 kB of RSA for 5.8 kB of P-256
and totals 31.5 kB. Its verify costs 4.0 times the default's on
mips32r2, so the 64-byte pin costs both flash and handshake time.

### The hybrid key exchange

The hybrid key exchange costs less than its wire size suggests.
`KEX=pq` adds two ML-KEM key expansions and one decapsulation for 10.2 M
instructions, 11% over the classic handshake. The key pair lives as a
64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](decisions.md) 24 explains.

One ML-KEM-768 keygen is an order of magnitude cheaper than one x25519
on this core, because chapulin keeps the 16-bit-limb ladder for its
machine-checked overflow proof.

### Where the time goes

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 156 ms is the recurring
floor and 86% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake.

Because a device typically opens one long-lived connection, chapulin
keeps the 16-bit-limb x25519 as the default and the device path. It
does so for its machine-checked overflow proof, and because a 32-bit
core has no wider multiply to run a faster field on.

A 64-bit host that opens many short connections can build
`X25519=wide` instead (decision 52): five 51-bit limbs whose products
run on the 64x64->128 multiply. On an Apple M1 Pro a scalar
multiplication takes 34 µs there against 953 µs in the default build,
and the client side of a pinned RSA-3072 handshake falls from 2.57 ms
to 0.77 ms ([`bench/notes-primitives.md`](../bench/notes-primitives.md)).

### Where a record's time goes

[`bench/record.sh`](../bench/record.sh) (`make bench-record`) times the protection of one TLS
record and splits it into its stages, for [#184](https://github.com/c4milo/chapulin/issues/184)
(AES-GCM) and [#181](https://github.com/c4milo/chapulin/issues/181) (ChaCha20-Poly1305). It
compiles the library sources with the flags `make lib` uses and the defines of a
`SUITE=aesgcm AES=hw` object with `CH_NATIVE_AES`, and builds the ChaCha20-Poly1305 rows a
second time with `CHACHA=vector` (decision 82), which with `WIDEMUL=native` runs the vector
Poly1305 as well (decision 83). It times these on the same buffers:

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
`chacha20_xor` less the block function gives the ChaCha20 exclusive-or. Under `CHACHA=vector` the
block function's row is `chacha20_vector.c`'s four blocks at a time, with each group's keystream
stored to a buffer. AES-GCM's exclusive-or has no row: `gcm_hw.c` runs it in the same pass as the
AES rounds (below), so its time is inside counter mode's and the loops'.

Each figure is the median of five runs, and each run's figure is the median of 15 batches of at
least 1 ms, with every row's batches interleaved. The CSVs hold every row at 1 KiB, 16 KiB and
64 KiB, each with its spread and its batches at the 10th and 90th percentile, and a check line
that compares each whole with the sum of its parts.

The machine is an Apple M1 Pro that ran other work: its one-minute load average was 8.2 to 12.3
where the CSV headers record it. A Linux CSV's own load average line is the VM's, and its first
line holds the host's. So these figures are the filter's, in the terms of the method below. The
three columns are three CSVs:

- macOS 26 with Apple clang 21:
  [`bench/results-record-darwin-arm64-clang.csv`](../bench/results-record-darwin-arm64-clang.csv);
- Linux 7.0 in an OrbStack VM on the same machine, which is where stompy runs, with clang 18:
  [`bench/results-record-linux-arm64-clang.csv`](../bench/results-record-linux-arm64-clang.csv);
- the same VM with gcc 13, the compiler CI runs:
  [`bench/results-record-linux-arm64-gcc.csv`](../bench/results-record-linux-arm64-gcc.csv).

stompy's chapulin compiles with Zig's clang, so the clang columns are the nearest to it. A share
in parentheses is the stage's part of `rec_seal`. The last two rows of each table are ceilings on
the same machine: `openssl speed -aead`, the median of five one-second runs, and Zig 0.16.0's
`std.crypto`, timed as the other rows are, which the VM does not have.

| AES-128-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 3.0 | 3.5 | 3.5 |
| `rec_seal` without its AEAD | 0.5 (18%) | 0.6 (19%) | 0.7 (20%) |
| the AEAD's seal, `gcm_traffic_seal` | 2.5 (83%) | 2.8 (81%) | 2.8 (80%) |
| counter mode and GHASH in one loop, the seal's whole passes | 2.3 (76%) | 2.6 (75%) | 2.6 (73%) |
| counter mode alone, in place | 1.7 | 1.7 | 1.7 |
| GHASH alone, over the ciphertext | 1.2 | 1.2 | 1.4 |
| `rec_open` | 2.9 | 3.2 | 3.2 |
| the AEAD's open, `gcm_traffic_open` | 2.6 | 2.9 | 2.8 |
| GHASH and counter mode in one loop, the open's whole passes | 2.4 | 2.7 | 2.6 |
| OpenSSL, one record sealed | 2.1 | 2.8 | 2.8 |
| OpenSSL, one record opened | 2.2 | 2.8 | 2.9 |
| Zig `std.crypto`, one record sealed | 4.4 | — | — |

| AES-256-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 3.6 | 3.9 | 4.0 |
| the AEAD's seal, `gcm_traffic_seal` | 3.0 (84%) | 3.2 (82%) | 3.2 (81%) |
| counter mode and GHASH in one loop, the seal's whole passes | 2.8 (78%) | 3.0 (76%) | 3.0 (75%) |
| `rec_open` | 3.4 | 3.6 | 3.6 |
| the AEAD's open, `gcm_traffic_open` | 3.0 | 3.3 | 3.2 |
| OpenSSL, one record sealed | 2.6 | 3.1 | 3.1 |
| OpenSSL, one record opened | 2.6 | 3.1 | 3.1 |
| Zig `std.crypto`, one record sealed | 5.5 | — | — |

| ChaCha20-Poly1305, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal`, the packaged multiply | 67.5 | 60.8 | 79.0 |
| `rec_seal` without its AEAD | 0.3 (0%) | 0.4 (1%) | 0.4 (0%) |
| the ChaCha20 block function | 25.6 (38%) | 24.0 (39%) | 27.6 (35%) |
| exclusive-or, loads and stores, in place | 8.2 (12%) | 8.1 (13%) | 5.9 (7%) |
| Poly1305 over the ciphertext | 33.2 (49%) | 27.8 (46%) | 44.8 (57%) |
| `rec_seal`, `WIDEMUL=native` | 46.3 | 44.0 | 47.0 |
| Poly1305 over the ciphertext, `WIDEMUL=native` | 11.6 (25%) | 11.2 (25%) | 12.7 (27%) |
| `rec_open`, the packaged multiply | 59.3 | 52.4 | 78.4 |
| `rec_seal`, `CHACHA=vector` | 48.0 | 42.1 | 59.8 |
| ChaCha20 in place, `CHACHA=vector` | 14.0 (29%) | 13.7 (32%) | 14.6 (24%) |
| `rec_seal`, `CHACHA=vector WIDEMUL=native` | 17.3 | 17.1 | 17.9 |
| ChaCha20 in place, `CHACHA=vector WIDEMUL=native` | 14.0 (81%) | 13.6 (80%) | 14.6 (81%) |
| Poly1305 over the ciphertext, `CHACHA=vector WIDEMUL=native` | 2.8 (16%) | 2.9 (17%) | 2.8 (15%) |
| `rec_open`, `CHACHA=vector` | 47.7 | 41.7 | 59.4 |
| OpenSSL, one record sealed | 9.4 | 9.8 | 9.9 |
| Zig `std.crypto`, one record sealed | 38.1 | — | — |

| Work a record pays whatever its size, and a 1 KiB record, ns | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| AES-128 key expansion, `aes_traffic_key_init` | 194 | 186 | 274 |
| AES-256 key expansion | 258 | 271 | 320 |
| the wipe of the expanded key | 91 | 90 | 91 |
| the GCM tag's fixed work | 152 | 147 | 166 |
| the Poly1305 tag's fixed work, the packaged multiply | 239 | 217 | 298 |
| AES-128-GCM `rec_seal`, 1 KiB | 848 | 874 | 963 |
| `rec_seal` without its AEAD, 1 KiB | 307 (36%) | 280 (32%) | 380 (39%) |

The stages add up: every whole is within 14% of the sum of its parts. The larger gaps are all at
1 KiB, in the AEAD rows, where each AEAD takes 10% to 14% less than its parts timed apart. What the
numbers show for AES-GCM:

- Counter mode runs a record's whole blocks through `gcm_hw.c`, eight blocks a pass. Each round key
  is loaded once and runs on the eight counter blocks of the pass, the eight keystream blocks are
  exclusive-ored into the data in vector registers, and the state that holds a pass's keystream
  is wiped once per call. The last partial block takes the one-block cipher. Counter mode alone,
  `gcm_counter_blocks_hw`, takes 1.7 µs of a 16 KiB AES-128 record on all three, where the AES
  calls and the exclusive-or in place took 16.6 to 20.1 µs at 044a49c.
- gcc 13 at `-O2` needed `#pragma GCC unroll 8` for that. Without it, gcc left each loop over a
  pass's eight blocks rolled and kept the eight states in memory, and counter mode took 16.5 µs
  on gcc against 1.8 µs on clang (the pitfalls below).
- GHASH multiplies eight blocks a pass by the powers H^8 to H of the hash subkey, which each call
  computes first, and reduces once per pass. Since 88c64be every value stays in a vector register
  from the load to the reduction: three carry-less products a block in Karatsuba's form, and a
  reduction by 0xc200000000000000 on the same instruction (`ghash_vector.h`). GHASH alone takes
  1.2 to 1.4 µs of a 16 KiB record, where the one-block loop took 9.2 to 10.4 at 044a49c and the
  eight-block loop that took its sums out of the vector registers for each reduction took 2.2 to
  2.8 at 225a890.
- clang's GHASH is no longer the slower one: 1.2 µs against gcc's 1.4. clang loaded each power of
  H through two general registers; the powers now come from `ghash_state` in one vector load each,
  a volatile read that also keeps the compilers from copying them to stack slots the wipe does not
  clear (INV-17).
- The seal runs its whole passes through `gcm_seal_passes_hw` (c91e2f3). Each pass computes its
  keystream, writes its ciphertext and then hashes the pass before, whose GHASH waits on no AES
  round of this one, so the core runs one pass's AES rounds beside the other's carry-less
  multiplies. The loop takes 2.3 to 2.6 µs of a 16 KiB AES-128 record, where counter mode and
  GHASH alone take 2.9 to 3.1 one after the other.
- The open runs the same loop the other way round, `gcm_open_passes_hw` (01ba8fc): iteration p
  hashes pass p and decrypts pass p - 1, and the tag is compared once the plaintext is written,
  which a mismatch then wipes (decision 85). The loop takes 2.4 to 2.7 µs of a 16 KiB AES-128
  record.
- `rec_seal` copies the caller's plaintext with one `memmove`. gcc 13 did not vectorize the byte
  loop that did it before, and ran it one byte at a time: 5.9 µs, three fifths of gcc's AES-GCM
  seal once counter mode and GHASH were fast. The record layer's own work is now 0.5 to 0.7 µs of
  a 16 KiB AES-GCM record and 0.3 to 0.4 µs of a ChaCha20-Poly1305 one on both compilers.
- Each GHASH call wipes the part of its state it wrote: H, the powers it computed and a pass's
  sums. The tag's fixed work, one GHASH call over the associated data and one multiply for the
  block of lengths, each of which computes one power, takes 147 to 166 ns, where it took 240 to
  300 at 225a890; a 1 KiB seal takes 848 to 963 ns. At 1 KiB the key expansion and the wipe that
  `record.c` runs for every record make most of the record layer's share.
- Measured one commit at a time, the three commits for
  [#184](https://github.com/c4milo/chapulin/issues/184) took the 16 KiB seal from 26.8, 27.6 and
  36.3 µs at 044a49c to 11.5, 12.9 and 17.6 µs with counter mode, to 4.8, 5.4 and 10.0 µs with
  GHASH, and to 4.9, 5.3 and 4.9 µs with the `memmove`. Three more, in paired runs of the four
  trees, took it from 4.8, 5.2 and 5.0 µs at 225a890 to 3.5, 3.8 and 4.0 µs with GHASH in vector
  registers (88c64be) and to 3.0, 3.5 and 3.5 µs with the one-pass seal (c91e2f3); the one-pass
  open (01ba8fc) took the 16 KiB open from 3.3, 3.3 and 3.6 µs to 2.9, 3.2 and 3.2 µs.
- The seal now takes 3.0, 3.5 and 3.5 µs, and its AEAD alone 2.5, 2.8 and 2.8 µs, 1.18, 1.02 and
  1.01 times OpenSSL's seal of the same record on the same machine. The open takes 2.9, 3.2 and
  3.2 µs, and its AEAD alone 2.6, 2.9 and 2.8 µs, 1.20, 1.01 and 0.98 times OpenSSL's open. Against
  044a49c the seal takes 0.11, 0.13 and 0.10 of its time, and the open 0.15, 0.15 and 0.10. The
  VM's OpenSSL is 3.0.13 and the host's 3.6.4, whose seal takes 2.1 µs where the VM's takes
  2.8.

For ChaCha20-Poly1305:

- In the packaged build, which multiplies through the 16x16 decomposition `ct.h` builds, Poly1305
  is the largest stage, about half of the record. colibri's object is such a build. With
  `WIDEMUL=native`, the builder's statement that the multiply runs in constant time, Poly1305 is a
  quarter of a shorter record.
- The ChaCha20 block function is the next stage. Its share is a third to two fifths of the
  packaged record and more than half of the native one.
- The exclusive-or in `chacha20_xor`'s loop runs one byte at a time in place on both compilers.
  As the open runs it, clang vectorizes it and it adds almost nothing to the block function's
  time; gcc runs the byte loop there too.
- `CHACHA=vector` runs the keystream and the exclusive-or in 13.6 to 14.6 µs, where the portable
  loop takes 32 to 34, on both compilers. The exclusive-or adds nothing measurable there: the path
  loads, XORs and stores 16 bytes where the keystream alone stores them, and `chacha20_xor` takes
  the time of the keystream alone, in place and as the open runs it. A 16 KiB `rec_seal` falls
  by 29% on macOS clang, 31% on the VM's clang and 24% on gcc 13, and a 1 KiB one by 21% to 26%.
- With `WIDEMUL=native` as well, the build runs the vector Poly1305 too (decision 83), which takes
  Poly1305 over the ciphertext from 11.2 to 12.7 µs on the portable loop to 2.8 to 2.9 µs (below).
  `rec_seal` then takes 17.1 to 17.9 µs, 23% to 28% of the packaged portable record, and a 1 KiB
  one 30% to 38%. ChaCha20 is 80% to 81% of the record, and Poly1305 15% to 17%.

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
   shorter one: 2.3 to 2.6 µs of a 16 KiB AES-128 record, where the two alone take 2.9 to 3.1. The
   open's loop needed the open to decrypt before it compares the tag, and to wipe the plaintext
   when the tag does not match (decision 85).

For [#181](https://github.com/c4milo/chapulin/issues/181), the numbers supported the vector path
for ChaCha20 first, because the block function and the in-place exclusive-or were half of the
packaged record on clang and more than two thirds of the native one, and decision 82 added it.
Its two paired runs on each platform agreed: the vector `rec_seal` took 0.71, 0.68 and 0.78 of the
portable one's time in the three columns in the second, and 0.78, 0.70 and 0.78 in the first. In
the runs the tables now hold it takes 0.71, 0.69 and 0.76. Most of what remains of the packaged
record is Poly1305's multiply decomposition: `WIDEMUL=native` runs the same Poly1305 in about a
third of the time. A vector Poly1305 needs a widening multiply too, so it needs the same statement
about that multiply's timing, and decision 83 added one under it: `CHACHA=vector` with
`WIDEMUL=native`, where Poly1305 was most of what the vector ChaCha20 left. Paired runs agree on
each platform, two in the Linux VM and three on macOS, where the second ran at a load average of
44 to 78. In the last pair on each, that build's `rec_seal` took 0.66, 0.66 and 0.69 of its time
before the change in the three columns; the earlier pairs gave 0.66 and 0.66 on macOS, 0.57 on the
VM's clang and 0.65 on gcc 13. Those pairs came before each call of the vector Poly1305 began to
end with a wipe of the powers of r it computed, one `ct_wipe` of 208 bytes on NEON and 352 on
SSE2. The runs the tables now hold measure the code with that wipe, and the 128-byte threshold
still rests on decision 83's scratch timing. That build's Poly1305 takes 2.8 µs on macOS and gcc
13, as in the pairs, and 2.9 µs on the VM's clang. There it took 4.7 µs in the bench build the
tables held at d10b6e2, and 3.0 µs in one whose `aes_hw.c` differed in one function; that build
with `-falign-functions=64` took 2.8 µs, so where the linker placed the function caused the
difference (the pitfalls below).

No x86-64 machine has timed the vector paths' SSE2 arms or the AES-NI arm of `gcm_hw.c`;
CI's x86-64 runners test them. A column
for it needs `make bench-record` on an x86-64 host that runs nothing else, once with gcc and once
with clang: the script finds the AES instructions there with `-maes -mpclmul`, writes
`bench/results-record-linux-x86_64-gcc.csv` and its clang twin, and `tools/bench_record.py` then
takes the two files as columns. An emulated x86-64, such as an OrbStack amd64 container, runs
translated code, so its times say nothing about those arms.

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
- The record split above prints a filter's figures, as an exception to the rule above: a
  `SUITE=aesgcm AES=hw` build runs on hosts alone, so no device build can judge it, and
  [#184](https://github.com/c4milo/chapulin/issues/184) and
  [#181](https://github.com/c4milo/chapulin/issues/181) asked for the order the split gives. It
  orders candidates. A change it points to still needs a judge's runs on a host that runs nothing
  else, and this document names no such host yet.
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
