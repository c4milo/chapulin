# Memory, speed and flash

What each build costs in RAM, instructions and flash, measured by the scripts in
[`bench/`](../bench/). `make lint-bench-numbers` fails when a table, a chart or a checked sentence
here or in [`docs/performance-openssl.md`](performance-openssl.md) disagrees with the CSV the
scripts write.

Where to look:

- To size a device: [Memory](#memory), the working set, the stack peaks and the receive buffer of
  each build.
- To compare with OpenSSL, or to choose the `ch_cfg.cpu` bits of a host: [chapulin beside
  OpenSSL](#chapulin-beside-openssl), a chart of each primitive under the bits a CPU states, with
  the times in [`docs/performance-openssl.md`](performance-openssl.md), and [Where a server
  handshake's instructions go](#where-a-server-handshakes-instructions-go), what the bits do to one
  handshake.
- To read one TLS record's cost: [Where a record's time goes](#where-a-records-time-goes) and
  [Reads and writes in place](#reads-and-writes-in-place).
- To change a hot path: [The method behind these numbers](#the-method-behind-these-numbers),
  [Patterns of a fast primitive](#patterns-of-a-fast-primitive) and
  [docs/performance-pitfalls.md](performance-pitfalls.md).

How each figure moved from run to run is in the notes beside the scripts that measure it:
[`bench/notes-primitives.md`](../bench/notes-primitives.md),
[`bench/notes-record.md`](../bench/notes-record.md),
[`bench/notes-handshake.md`](../bench/notes-handshake.md) and
[`bench/notes-sram.md`](../bench/notes-sram.md).

## Memory

[`bench/sram.sh`](../bench/sram.sh) measures every number in this
section and writes them to
[`bench/results-sram.csv`](../bench/results-sram.csv).

### Static working set

The session struct is measured twice, once native on arm64 and once for
rv32ic. The byte-count constants do not move, only the pointer fields,
so a 32-bit device needs 80 bytes less than the host figure in either device
build. `TRUST=webpki` adds pointer-sized fields to `ch_cfg`, pointers
and `size_t` lengths, so that build needs 120 bytes less than the host figure on rv32.

| what | arm64 | rv32 |
|---|---|---|
| `ch_tls` session struct (includes 622 B TX staging) | 1152 | 1072 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 | 2048 |
| **total static working set** | **3200** | **3120** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2336 | 2256 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4384** | **4304** |
| `ch_tls` under `TRUST=webpki` (includes 2401 B TX staging) | 3072 | 2952 |
| **total static working set, `TRUST=webpki`** (12338 buffer, its floor) | **15410** | **15290** |
| `ch_tls` under `ROLE=server` (includes 1669 B TX staging) | 2448 | 2272 |
| **total static working set, `ROLE=server`** (2048 buffer) | **4496** | **4320** |
| `ch_tls` under `ROLE=server SUITE=aesgcm` | 3776 | — |
| **total static working set, `ROLE=server SUITE=aesgcm`** (2048 buffer) | **5824** | — |
| `ch_tls` under `TRUST=webpki SUITE=aesgcm` | 4368 | — |
| **total static working set, `TRUST=webpki SUITE=aesgcm`** (12338 buffer, its floor) | **16706** | — |
| `ch_tls` under `TRUST=webpki`, host object | 3072 | — |
| **total static working set, `TRUST=webpki`, host object** (12338 buffer, its floor) | **15410** | — |
| `ch_tls` under `ROLE=server`, host object | 2496 | — |
| **total static working set, `ROLE=server`, host object** (2048 buffer) | **4544** | — |
| `ch_tls` under `PROFILE=cnsa2 TRUST=raw-mldsa` | 2992 | — |
| **total static working set, `PROFILE=cnsa2 TRUST=raw-mldsa`** (7843 buffer, its floor) | **10835** | — |
| `ch_tls` under `PROFILE=cnsa2 TRUST=ca-mldsa` | 2992 | — |
| **total static working set, `PROFILE=cnsa2 TRUST=ca-mldsa`** (15656 buffer, its floor) | **18648** | — |
| `ch_tls` under `PROFILE=cnsa2 ROLE=server` (host object) | 3680 | — |
| **total static working set, `PROFILE=cnsa2 ROLE=server`** (2179 buffer, its floor) | **5859** | — |

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
only overstate a peak. A call through a volatile function pointer has no
relocation that names its callee. The script reads the callee from the
pointer's initializer in the preprocessed source, and it stops on such a
pointer that it cannot read. The stack wipes call their frames this way
(`p256_wide_wipe.c`, `sha512.c`), so each peak above a wipe counts the
array the wipe writes. `make lint-stack-walk` checks that the script
follows a tail call at a function's first instruction and a call through
a volatile function pointer, keeps two static functions of one name
apart, names the calls below that no object defines, and compiles what
make packages. The RSA verify holds the deepest frames, so
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
| peak stack, `ch_connect` (RSA-3072 verify) | 5008 |
| peak stack, `ch_connect` (`TRUST=raw-ecdsa`) | 3120 |
| peak stack, `ch_connect` (PSK) | 2784 |
| peak stack, `ch_connect` (`TRUST=ca-rsa` / `TRUST=ca-ecdsa`) | 5472 / 3264 |
| peak stack, `ch_connect` (`TRUST=webpki`) | 14288 |
| peak stack, `ch_connect` (`TRUST=webpki SUITE=aesgcm`) | 14416 |
| peak stack, `ch_connect` (`KEX=pq`) | 12720 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1888 |
| peak stack, `ch_write` / `ch_close` | 1616 / 1072 |
| peak stack, `ch_srv_accept` (`ROLE=server`) | 112864 |
| peak stack, `ch_srv_accept` (`ROLE=server SUITE=aesgcm`) | 113024 |
| peak stack, `ch_connect` (`PROFILE=cnsa2 TRUST=raw-mldsa`) | 14576 |
| peak stack, `ch_connect` (`PROFILE=cnsa2 TRUST=ca-mldsa`) | 17216 |
| peak stack, `ch_srv_accept` (`PROFILE=cnsa2 ROLE=server`) | 112160 |

How these peaks grew, row by row, with the frame `bench/stack.py` named each time, is in
[`bench/notes-sram.md`](../bench/notes-sram.md).

### What the larger builds pay for

**`KEX=pq`.** The hybrid build costs more of both:

- The session struct grows because the ClientHello carries a 1,216-byte
  key share and is built whole into one staging array.
- The stack grows because ML-KEM's K-PKE encrypt holds the vector r and
  four polynomials: 3,664 bytes in that one frame, against a 2,560-byte
  budget for every other build (INV-19 carries the per-build numbers,
  and [`docs/decisions.md`](decisions.md) 177 the code that holds one
  polynomial of each other vector). The whole chain peaks at 12,720
  bytes, through `mlkem_decaps_rank` into K-PKE encrypt, the matrix
  sampler and SHAKE128, whose entry then wipes 1,024 bytes of the stack
  below it ([`docs/decisions.md`](decisions.md) 219). So the hybrid
  build needs more than twice the stack of the classic one rather than
  the single frame's 3,664.

A device that cannot spare it builds the classic key exchange.

**`TRUST=webpki`.** A `TRUST=webpki` build carries the hybrid in every
build, so it pays both costs too, and its handshake state also holds the
P-256 scalar and point a retry to secp256r1 draws
([`docs/decisions.md`](decisions.md) 63). Its session struct carries a
larger TX staging array for the `server_name` and ALPN extensions and
for both key shares, the 1,216-byte hybrid one and a 32-byte x25519 one
([`docs/decisions.md`](decisions.md) 51), and for the third group it
lists, secp256r1 (63). Its `ch_connect` peaks at 14,288 bytes, through
ML-KEM's decapsulation. With ML-KEM and its copies over the SHA-3
instructions pruned from the call graph
(`STACK_PRUNE=mlkem_decaps_rank,mlkem_keygen_dk_rank,mlkem_decaps_rank_hw,mlkem_keygen_dk_rank_hw`)
the deepest chain is the chain walk into an RSA verify on 64-bit words, at 9,792 bytes:
this host builds the host object, whose RSA verifier squares on
`rsa_mont64_blocks.c`'s rows of four words ([`docs/decisions.md`](decisions.md)
209). On the tree of 90415b30 the deepest was the walk into a P-384
verify, at 8,304 bytes. A device object
holds no copies over the SHA-3 instructions, and with ML-KEM pruned
(`STACK_MAKE='TRUST=webpki HOST_TARGET='
STACK_PRUNE=mlkem_decaps_rank,mlkem_keygen_dk_rank`) its deepest chain is the chain
walk into an RSA-4096 verify on 32-bit words, at 7,344 bytes. RSA-4096
is the widest modulus a public root carries.

**`ROLE=server`.** A server build pays them as well, because every
server holds the hybrid ([`docs/decisions.md`](decisions.md) 54) and
ML-KEM-1024 (179). Its ServerHello is built in the clear in the same
staging array, and the ML-KEM-1024 one carries a 1,568-byte share, so
the array holds 1,664 bytes of message behind the record header.
`ch_srv_accept` peaks at 112,864 bytes in the host object this host
builds, through the ML-DSA-87 signer, which every host server holds
beside its ECDSA and RSA identities (180) and which the
`PROFILE=cnsa2` server also runs. The signer's frame holds A and the
NTTs of the key for the whole signature, 100,048 bytes (191). The peak
counts whether or not a deployment sets the `mldsa87` slot. With the ML-DSA-87 CertificateVerify,
whose own frame stages the 4,627-byte signature, pruned from the call
graph (`STACK_PRUNE=srv_mldsa_send_certificate_verify`) the deepest chain is
`rsa_sign64.c`'s RSA-PSS signer, at 20,320 bytes, which holds a modulus
record for each prime, the signature it checks and a table of sixteen
powers ([`docs/decisions.md`](decisions.md) 95) and the two blinded
exponents (187). The deepest frame on that
chain is `rsa_sign64_wipe.c`'s, which writes zero over the
`RSA_SIGN64_BELOW_LEN` bytes under each private call (181). Its square holds a copy
of 2a (106) and calls `rsa_mont64_blocks.c`'s square, which multiplies in
blocks of four words under clang for arm64 (118). With the RSA signer
pruned too (`STACK_PRUNE=srv_mldsa_send_certificate_verify,rsa_sign64_pss`) it is the
encapsulation to the client's key into K-PKE encrypt and Keccak, at
10,672 bytes. With the encapsulation pruned as well
(`STACK_PRUNE=srv_mldsa_send_certificate_verify,rsa_sign64_pss,srv_kex_share`) it is
`rsa_sign.c`'s ladder, at 6,240 bytes, which a session without the
multiply bit runs and whose blinded exponent takes two arrays of 99 words
(186). The ECDSA signer on the wide P-256 field lies under it: after each
wide operation, `p256_wide_wipe_below` writes zero over the stack below
it, in a frame of 3,120 bytes. A device object holds neither the 64-bit signer nor the
wide field: its `ch_srv_accept` peaks at 9,712 bytes, through the
encapsulation (`STACK_MAKE='ROLE=server TRUST=none HOST_TARGET='`).
There the signer's deepest chain is `rsa_sign.c`'s ladder, at 6,208
bytes (`STACK_PRUNE=srv_kex_share`).

**`SUITE=aesgcm`.** `bench/sram.sh` measures a `SUITE=aesgcm` build as the
host object this host builds for it ([`docs/decisions.md`](decisions.md)
89), so its rows are host figures and have no rv32 column. A suite build
with `AES=extern` can run on a device with an AES peripheral
([`docs/decisions.md`](decisions.md) 68), and no script here measures one
on a device target yet. Its session struct is 1280 bytes larger than the
same `ROLE=server` host object without the suite, and 1296 larger for
`TRUST=webpki`:

- each of the two record directions holds its AES key's expanded
  schedule, 243 bytes, so no record expands the key again
  ([`docs/decisions.md`](decisions.md) 160);
- each direction holds the powers H to H^8 of its key's hash subkey,
  256 bytes, so no record computes them again
  ([`docs/decisions.md`](decisions.md) 234). The `PROFILE=cnsa2
  ROLE=server` row holds them too;

- the transcript runs a SHA-512 context beside SHA-256's;
- the traffic secrets take SHA-384's 48 bytes;
- a webpki hello lists two more suites
  ([`docs/decisions.md`](decisions.md) 58);
- a webpki client's configuration holds the caller's suite order, a
  pointer and a count ([`docs/decisions.md`](decisions.md) 80).

**`TRUST=raw-mldsa` and `TRUST=ca-mldsa`.** The two ML-DSA-87 trust
modes build under `PROFILE=cnsa2` alone, on `AES=extern`
([`docs/decisions.md`](decisions.md) 157). `bench/sram.sh` measures
their portable object on this host, so their rows have no rv32 column.
The session struct is the same in both, because the blocking driver
holds the handshake state on its stack. The receive floor holds one
certificate of `CH_X509_MAX`, 7,808 bytes, in the raw mode and two in
the CA mode, and the static working set adds that floor. Each
`ch_connect` peaks through ML-KEM-1024's decapsulation, at 14,576 bytes
in the raw mode and 17,216 in the CA mode. The CA mode's handshake
state holds the leaf's 2,592-byte key, which is most of the difference.
With ML-KEM's two calls pruned
(`STACK_PRUNE=mlkem_decaps_rank,mlkem_keygen_dk_rank`) the deepest chain
is the ML-DSA-87 verify, at 14,144 bytes in the raw mode and 16,832 in
the CA mode, less than 0.5 kB under the peak. A device that runs either mode gives
`ch_connect` the larger peak. The profile's 133-byte retry cookie
(`HSP_COOKIE_MAX`, [`docs/decisions.md`](decisions.md) 162) adds 8
bytes to each struct with the alignment after it.

**`PROFILE=cnsa2 ROLE=server`.** The profile's server is a host object
alone ([`docs/decisions.md`](decisions.md) 162), so its rows have no rv32
column. `bench/sram.sh` measures:
- a session struct of 3,680 bytes, whose TX array holds the 1,664-byte
  ServerHello with the ML-KEM-1024 ciphertext;
- a receive floor of 2,179 bytes, the 2,174-byte largest ClientHello of
  the profile's client behind its record header, and 2,698 bytes over
  QUIC;
- a `ch_srv_accept` peak of 112,160 bytes, through the ML-DSA-87 signer's
  rejection loop under the CertificateVerify, whose frame holds A and the
  NTTs of the key (decision 191). With the signer pruned
  (`STACK_PRUNE=mldsa87_sign_cpu`) the peak is ML-KEM-1024's encapsulation,
  at 10,688 bytes.

The send side needs no floor of its own. The 7.5 kB Certificate and the
4,627-byte CertificateVerify each stream through `srv_frag`, 512 bytes a
record, and only the CertificateVerify's frame holds its whole
signature, 5,280 bytes in `srv_mldsa_send_certificate_verify`.

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

You size the receive buffer. The client advertises a `record_size_limit`
([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)) of the buffer less
21 bytes: the 5-byte record header and the 16-byte tag. A peer that
honors the extension sends no record that the buffer cannot hold.
OpenSSL and Go ignore it, so a server on those stacks must cap its own
records ([`examples/server/README.md`](../examples/server/README.md),
"Record size"). A record longer than the buffer fails the session with
`CH_ECAP`. Each trust mode adds one rule:

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
- **The ML-DSA-87 modes.** An ML-DSA-87 certificate holds a 2,592-byte
  key and a 4,627-byte signature, and OpenSSL 3.5 issues one of about
  7,500 bytes, so `CH_X509_MAX` is 7,808 there. `TRUST=raw-mldsa` derives
  a floor of 7,843 bytes, one certificate at the cap plus the record that
  completes it, and `TRUST=ca-mldsa` 15,656, two certificates
  ([`docs/decisions.md`](decisions.md) 157).

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
itself measures 640 bytes of stack under both `TRUST=ca-rsa` and
`TRUST=ca-ecdsa`, reported by `bench/stack.py` beside the other public
calls. Its deepest chain is the read of the PEM block's lines.

The three calls of `pem_files.h` (decision 131) take their rooms from the
caller the same way. A host program reads each file into a buffer of its
own. The call writes the DER into a second room, and the values point
into that room. So the DER room lives as long as the sessions that use
it, and the text does not. The caller sizes the rooms, and a call refuses a
file that does not fit them. A DER room of `pem_len / 4 * 3` bytes holds
the DER of any file.

| file | text, at most | DER room | entries |
|---|---|---|---|
| chain, `ch_chain_from_pem` | the caller's | the caller's | 16 bytes a `ch_cert`, 255 at most |
| P-256 key, `ch_p256_key_from_pem` | the caller's | none: 32 for the scalar and 64 for the point | none |
| RSA key, `ch_rsa_key_from_pem` | the caller's | none: one `ch_rsa_priv` | none |
| CA bundle, `ch_anchors_from_pem` | the caller's | the caller's | 32 bytes a `ch_trust_anchor` |

The sizes of an entry are the arm64 compiler's. Homebrew's
`ca-certificates` bundle is 289,562 bytes of text. It decodes to 205,893
bytes of DER and 192 anchors, 6,144 bytes of entries. The QUIC Interop
Runner's chain of nine certificates is 9,661 bytes of DER.

On arm64 `bench/stack.py` measures 592 bytes of stack for the chain
call, 3,776 for the key call and 560 for the bundle call. It reports
them for `ROLE=server TRUST=none`, `TRUST=webpki` and `ROLE=both
TRUST=webpki`, the host objects this host builds. The chain call's peak
is the read of each certificate's outer fields.

The key call's deepest chain ends in a stack wipe. Under
`CH_CPU_CONSTANT_TIME_MULTIPLY` the call computes the point on the wide
P-256 field. After each wide operation, `p256_wide_wipe_below` writes
zero over an array of 3,072 bytes (`P256_WIDE_BELOW_LEN`) in a frame of
3,120. A device object holds no wide field, and its key call peaks at
1,392 bytes (`STACK_MAKE='ROLE=server TRUST=none HOST_TARGET='`). So a
host program gives the key call 3,776 bytes of stack. Both grew 16 bytes
on 2026-10-31: the key call reads its blocks through `pem_blocks`, and
the EC PARAMETERS room now sits in the call's own frame
(docs/decisions.md 170).

The RSA key call (decision 184) decodes into a room of
`CH_PEM_RSA_KEY_DER_MAX` bytes in its own frame, and then signs once.
On arm64 it peaks at 20,720 bytes in `ROLE=server TRUST=none`. Its
deepest chain is the 64-bit signer's wipe below each private call, an
array of 16,384 bytes (decision 181). The call signs on that signer
under `CH_CPU_CONSTANT_TIME_MULTIPLY` alone. A device object holds the
ladder alone, and there the call peaks at 7,600 bytes, through the
verification of its signature
(`STACK_MAKE='ROLE=server TRUST=none HOST_TARGET='`).

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

CI counts every row again and holds it to its CSV (docs/decisions.md
235). check.yml's `insn-device` job runs `make insn-gate-m3`,
`insn-gate-rv32` and `insn-gate-mips`, and the `x86-64-kernels` and
`arm64` jobs run `make insn-gate-host`, which counts each primitive row
and each whole handshake of a host object under valgrind's callgrind
against `bench/results-insn-host-x86_64.csv` and
`bench/results-insn-host-arm64.csv`, and each row of the record bench
against `bench/results-insn-record-x86_64.csv` and
`bench/results-insn-record-arm64.csv`. The nightly's `insn-sde` job
runs `make insn-gate-sde`, which counts the AVX-512, VAES, IFMA and SHA
extension kernels under Intel SDE against
`bench/results-insn-sde-x86_64.csv` and
`bench/results-insn-sde-record-x86_64.csv`. A count above its recorded value
fails. A change that raises one records the fresh CSV and says why in
its commit, and a change that lowers one records it too.

| work | mips32r2 insns | ms (500 MHz, 1 IPC) | Cortex-M3 insns | rv32imac insns |
|---|---|---|---|---|
| AEAD seal, per 1 KB record | 83 k | 0.17 | 68 k | 108 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 35.0 M | 70 | 24.4 M | 38.2 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`TRUST=raw-ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 82.3 M | 165 | 57.7 M | 90.4 M |
| ML-KEM-768 keygen (`KEX=pq`) | 1.2 M | 2 | 1.0 M | 1.2 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 1.6 M | 3 | 1.3 M | 1.6 M |
| full hybrid handshake crypto (`KEX=pq`) | 86.4 M | 173 | 61.1 M | 94.5 M |

### The multiply decomposition

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:

- on mips32r2, AEAD seal costs 72% more, x25519 22% more, and the
  pinned handshake 18% more, or 25 ms at 500 MHz;
- on the Cortex-M3, AEAD seal costs 92% more, x25519 103% more, and the
  pinned handshake 75% more;
- on rv32imac, AEAD seal costs 65% more, x25519 76% more, and the
  pinned handshake 57% more.

SHA-256 and both signature verifies are unchanged, because SHA-256 does
not multiply and the verifies read only public bytes.

### Flash

Flash is 31.4 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.2 kB, nearly all of it
poly1305's unrolled block: the `total (CH_NATIVE_WIDEMUL)` row of
[`bench/results-device.csv`](../bench/results-device.csv) sizes the same
modules over the native multiply.

The `TRUST=raw-ecdsa` build trades 2.3 kB of RSA for 5.8 kB of P-256
and totals 34.9 kB. Its verify costs 4.0 times the default's on
mips32r2, so the 64-byte pin costs both flash and handshake time.

### The hybrid key exchange

The hybrid key exchange costs less than its wire size suggests.
`KEX=pq` adds two ML-KEM key expansions and one decapsulation for 4.2 M
instructions, 5% over the classic handshake. The key pair lives as a
64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](decisions.md) 24 explains.

One ML-KEM-768 keygen is an order of magnitude cheaper than one x25519
on this core, because chapulin keeps the 16-bit-word ladder for its
machine-checked overflow proof.

### Where the time goes

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 140 ms is the recurring
floor and 85% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake.

Because a device typically opens one long-lived connection, chapulin
keeps the 16-bit-word x25519 as the default and the device path. It
does so for its machine-checked overflow proof, and because a 32-bit
core has no wider multiply to run a faster field on.

A host object holds a second field for a session whose caller sets `CH_CPU_CONSTANT_TIME_MULTIPLY`
(decisions 52 and 89): five 51-bit words whose products run on the 64x64->128 multiply. On an Apple
M1 Pro a scalar multiplication takes 27.7 µs on that field against 880 µs on the 16-word one over
the decomposition, and the client side of a pinned RSA-3072 handshake takes 81.5 µs under the value
that [`docs/performance-openssl.md`](performance-openssl.md) names for that machine against 1.86 ms
under `CH_CPU_PROBED` alone
([`bench/results-primitives-darwin-arm64-clang.csv`](../bench/results-primitives-darwin-arm64-clang.csv),
[`bench/notes-primitives.md`](../bench/notes-primitives.md)).

### chapulin beside OpenSSL

Each bar is chapulin's speed on one primitive in multiples of OpenSSL's, on the same machine in the
same run. A bar past the dashed line at 1 is a row where chapulin is faster.
[`docs/performance-openssl.md`](performance-openssl.md) holds the times behind the bars, the
machines, how each figure is taken, and each row's speed at every run.

![Bars of chapulin's speed in multiples of OpenSSL's on the Apple M1 Pro, under Apple clang](img/speed-vs-openssl-m1-pro.svg)

![Bars of chapulin's speed in multiples of OpenSSL's on the AMD EPYC 7763, under gcc and clang](img/speed-vs-openssl-x86-64.svg)

![Bars of chapulin's speed in multiples of OpenSSL's on an x86-64 CPU with AVX-512 IFMA, under gcc and clang](img/speed-vs-openssl-x86-64-avx512.svg)

![Bars of chapulin's speed in multiples of OpenSSL's on an Arm Neoverse N2, under gcc and clang](img/speed-vs-openssl-arm64.svg)

### Where a record's time goes

[`bench/record.sh`](../bench/record.sh) (`make bench-record`) times the protection of one TLS
record and splits it into its stages, for [#184](https://github.com/c4milo/chapulin/issues/184)
(AES-GCM) and [#181](https://github.com/c4milo/chapulin/issues/181) (ChaCha20-Poly1305). It
compiles the library sources with the flags `make lib` uses and the defines of a
`SUITE=aesgcm` host object, once for each `ch_cfg.cpu` value it times, and every row hands that
value to the calls a session hands its own to (decision 89). The values are 0x3, the probe's bit
and the AES bit; 0x7, which adds the multiply bit and so the vector Poly1305 (decision 83); on an
x86-64 CPU with the instructions, 0x1f, which adds the kernels of decisions 90 and 110; and, on
one with AVX-512 IFMA, 0x11f, which adds `CH_CPU_AVX512_IFMA` and so the ChaCha20-Poly1305
kernels of decision 121; on an arm64 CPU with SVE2, 0x1007, which adds `CH_CPU_SVE2` to 0x7 and
so the SVE2 copy of the NEON ChaCha20 of decision 242, for the ChaCha20-Poly1305 rows alone; and,
on an x86-64 CPU with AVX-512F, AVX-512BW and AVX-512VL, 0x31f, which adds `CH_CPU_AVX512` and so
the 512-bit AES-GCM kernel of decision 130, for the AES-GCM rows alone.
Under that value the kernel runs each whole AEAD, and the stage rows still time the VAES loops,
which it does not call. It times these on the same buffers:

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
`chacha20_vector.c`'s, nine blocks a pass on NEON and four on SSE2, the AVX2 kernel's, or under
0x11f the AVX-512 kernel's, with each pass's keystream stored to a buffer. AES-GCM's exclusive-or
has no row: `gcm_hw.c` runs it in the same pass as the AES rounds (below), so its time is inside
counter mode's and the loops'.

Each figure is the median of five runs, and each run's figure is the median of 15 batches of at
least 1 ms, with every row's batches interleaved. The CSVs hold every row at 1 KiB, 16 KiB and
64 KiB, each with its spread and its batches at the 10th and 90th percentile, and a check line
that compares each whole with the sum of its parts.

The machine is an Apple M1 Pro that ran other work: its one-minute load average was 3.14 before and
3.55 after the macOS column's run of 2026-11-20, and 6.3 and 7.1 before the VM's runs of 2026-10-04.
A Linux CSV's own load average line is the VM's, and its first line holds the host's. So these
figures are the filter's, in the terms of the method below. The three columns are three CSVs:

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
- `ch_cfg.cpu 0x83`, on an arm64 CPU with FEAT_SHA3, adds `CH_CPU_CONSTANT_TIME_SHA3`, and its
  AES-GCM rows run the passes with EOR3 (decision 158). The tables read the 0x3 rows.

Since decision 158 an arm64 host object runs each AES-GCM seal and open whole in `gcm_arm64.c`,
and calls none of `gcm_hw.c`'s loops. So the macOS column has no figure for the two rows of those
loops. Its rows of counter mode alone and GHASH alone still time `gcm_hw.c`'s and
`ghash_hw.c`'s loops, which the AEAD does not call there. The VM's columns are runs of 2026-10-04,
before decision 158.

A host session never runs `chacha20.c`'s portable loop, so no row here times it;
[`bench/aead.sh`](../bench/aead.sh) times it in a device object's sources. The tables this section
held before decision 89, when build variables chose the paths, had rows for that loop, and the text
below names their figures where it compares against them, with the commit that measured them.

stompy's chapulin compiles with Zig's clang, so the clang columns are the nearest to it. A share
in parentheses is the stage's part of `rec_seal`. The last rows of each table are two other
libraries on the same machine: `openssl speed -aead`, the median of five one-second runs, and
Zig 0.16.0's `std.crypto`, timed as the other rows are, which the VM does not have.

What one operation of `openssl speed -aead` holds depends on the OpenSSL release, and the macOS
column's is 3.6.5 where the VM's is 3.0.13. So each table has a row for each operation, and a column
fills the rows its release times ([`bench/record.sh`](../bench/record.sh) states where each reading
comes from):

- OpenSSL 3.0 sets the IV, hashes 13 bytes of associated data, encrypts the record and computes
  the tag, under a key set before the loop. chapulin's row for that operation is the AEAD's seal
  or open.
- OpenSSL 3.6 does the same for AES-GCM and sets the key as well, for every operation. chapulin's
  row for that operation is the AEAD under a key expanded for the record. A device object's
  `seal_aes_gcm` and `open_aes_gcm` in `record.c` run that: its `rec_dir` keeps the key's bytes
  and no expanded key. A host object's records load the schedule and the GHASH powers that
  `rec_dir` stores beside the key (decisions 160 and 234), so they pay neither, and the row
  keeps the expansion to time the operation OpenSSL times.
- For ChaCha20-Poly1305, OpenSSL 3.6 runs one update over the record's bytes, with no nonce,
  associated data or tag. chapulin's row for that operation is the seal or the open less its
  tag's fixed work.

| AES-128-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 2.4 | 3.1 | 3.2 |
| `rec_seal` without its AEAD | 0.3 (11%) | 0.6 (19%) | 0.7 (21%) |
| the AEAD under a key expanded for the record, as `seal_aes_gcm` runs it | 2.2 | 2.8 | 2.8 |
| the AEAD's seal, `gcm_traffic_seal` | 2.1 (91%) | 2.6 (83%) | 2.5 (79%) |
| counter mode and GHASH in one loop, the seal's whole passes | — | 2.5 (80%) | 2.5 (77%) |
| counter mode alone, in place | 1.6 | 1.7 | 1.7 |
| GHASH alone, over the ciphertext | 1.0 | 1.1 | 1.4 |
| `rec_open` | 2.1 | 2.8 | 2.8 |
| the AEAD under a key expanded for the record, as `open_aes_gcm` runs it | 2.2 | 2.8 | 2.8 |
| the AEAD's open, `gcm_traffic_open` | 2.1 | 2.6 | 2.5 |
| GHASH and counter mode in one loop, the open's whole passes | — | 2.5 | 2.4 |
| OpenSSL, the key set and one record sealed | 2.1 | — | — |
| OpenSSL, the key set and one record opened | 2.1 | — | — |
| OpenSSL, one record sealed under a key set before | — | 2.8 | 2.8 |
| OpenSSL, one record opened under a key set before | — | 2.9 | 2.9 |
| Zig `std.crypto`, one record sealed | 4.3 | — | — |

| AES-256-GCM, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal` | 2.7 | 3.6 | 3.7 |
| the AEAD under a key expanded for the record, as `seal_aes_gcm` runs it | 2.5 | 3.2 | 3.3 |
| the AEAD's seal, `gcm_traffic_seal` | 2.5 (92%) | 3.0 (82%) | 3.0 (80%) |
| counter mode and GHASH in one loop, the seal's whole passes | — | 2.9 (80%) | 3.0 (80%) |
| `rec_open` | 2.5 | 3.3 | 3.3 |
| the AEAD under a key expanded for the record, as `open_aes_gcm` runs it | 2.5 | 3.3 | 3.3 |
| the AEAD's open, `gcm_traffic_open` | 2.5 | 3.0 | 3.0 |
| OpenSSL, the key set and one record sealed | 2.5 | — | — |
| OpenSSL, the key set and one record opened | 2.5 | — | — |
| OpenSSL, one record sealed under a key set before | — | 3.1 | 3.1 |
| OpenSSL, one record opened under a key set before | — | 3.2 | 3.1 |
| Zig `std.crypto`, one record sealed | 5.3 | — | — |

| ChaCha20-Poly1305, one 16 KiB record, µs | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| `rec_seal`, `ch_cfg.cpu 0x3` | 39.5 | 37.1 | 54.9 |
| `rec_seal` without its AEAD | 0.2 (1%) | 0.4 (1%) | 0.4 (1%) |
| ChaCha20 in place | 6.9 (17%) | 8.1 (22%) | 9.0 (16%) |
| Poly1305 over the ciphertext, on the 16x16 decomposition | 32.0 (81%) | 28.1 (76%) | 45.6 (83%) |
| `rec_open`, `ch_cfg.cpu 0x3` | 39.3 | 36.7 | 54.6 |
| `rec_seal`, `ch_cfg.cpu 0x7` | 9.4 | 11.6 | 12.3 |
| the AEAD's seal, `aead_seal_cpu`, `ch_cfg.cpu 0x7` | 9.1 (97%) | 11.3 (97%) | 11.8 (97%) |
| the seal less its tag's fixed work, `ch_cfg.cpu 0x7` | 9.0 | 11.1 | 11.7 |
| ChaCha20 in place, `ch_cfg.cpu 0x7` | 6.9 (74%) | 8.2 (70%) | 8.9 (73%) |
| Poly1305 over the ciphertext, the vector path | 2.0 (22%) | 2.9 (25%) | 2.8 (22%) |
| `rec_open`, `ch_cfg.cpu 0x7` | 9.1 | 11.2 | 11.9 |
| the AEAD's open, `aead_open_cpu`, `ch_cfg.cpu 0x7` | 9.1 | 11.2 | 11.9 |
| the open less its tag's fixed work, `ch_cfg.cpu 0x7` | 8.9 | 11.0 | 11.7 |
| OpenSSL, one record sealed | — | 10.0 | 10.0 |
| OpenSSL, one record opened | — | 10.0 | 10.0 |
| OpenSSL, ChaCha20 and Poly1305 over the record's bytes, sealing | 9.2 | — | — |
| OpenSSL, ChaCha20 and Poly1305 over the record's bytes, opening | 9.2 | — | — |
| Zig `std.crypto`, one record sealed | 36.9 | — | — |

| Work a record pays whatever its size, and a 1 KiB record, ns | macOS, Apple clang 21 | Linux VM, clang 18 | Linux VM, gcc 13 |
| --- | --- | --- | --- |
| AES-128 key expansion, `aes_traffic_key_init` | 10 | 205 | 283 |
| AES-256 key expansion | 11 | 273 | 330 |
| the wipe of the expanded key | 14 | 4 | 5 |
| the GCM tag's fixed work | 42 | 56 | 55 |
| the Poly1305 tag's fixed work, on the 16x16 decomposition | 203 | 176 | 252 |
| the Poly1305 tag's fixed work, `ch_cfg.cpu 0x7` | 169 | 146 | 148 |
| AES-128-GCM `rec_seal`, 1 KiB | 217 | 491 | 584 |
| `rec_seal` without its AEAD, 1 KiB | 32 (15%) | 224 (46%) | 314 (54%) |

The stages add up: every whole is within 15% of the sum of its parts. Every gap of 5% or more is
at 16 bytes or 1 KiB. On the M1 the parts of a tag differ from the tag by as much as 14%: GCM's
sum to more or less than its tag, and Poly1305's to less. The parts of a 16-byte ChaCha20-Poly1305 AEAD sum to as
much as 8% less. On the Linux
VM the parts of an AES-GCM AEAD sum to as much as 8% less than the AEAD, and the parts of the GCM
tag to as much as 8% more than the tag.

What the tables show, stage by stage, and how each stage reached its time, is in
[`bench/notes-record.md`](../bench/notes-record.md). In short:

- An AES-GCM record's time is its AEAD's. The seal and the open each run counter mode and GHASH
  in one loop over the record (`gcm_seal_passes_hw`, `gcm_open_passes_hw`), and the record layer
  adds one `memmove` of the caller's plaintext.
- A ChaCha20-Poly1305 record's time is its keystream's and its Poly1305's. Without the multiply
  bit Poly1305 runs on the 16x16 decomposition and is the largest stage. With the bit the vector
  Poly1305 runs, and ChaCha20 is the larger stage.

No x86-64 machine that runs nothing else has timed the vector paths' SSE2 arms or the AES-NI arm of
`gcm_hw.c`. bench.yml's `record-x86_64` job times them on a shared GitHub runner, once with gcc and
once with clang, and on a runner whose CPU has AVX2, VAES and VPCLMULQDQ it adds the
`ch_cfg.cpu 0x1f` rows for the x86-64 kernels of decision 90, which records the figures they had
when their rows were marked `AVX2+VAES`. On a runner whose CPU has AVX-512 IFMA it also adds the
`0x11f` ChaCha20-Poly1305 rows for the kernels of decision 121, and on one with AVX-512F,
AVX-512BW and AVX-512VL the `0x31f` AES-GCM rows for the kernel of decision 130. The table beside
OpenSSL above takes its x86-64 AEAD rows from that job's CSVs, such as
`bench/results-record-linux-x86_64-gcc.csv`. A column in this section's tables needs
`make bench-record` on an x86-64 host that runs nothing else, once with gcc and once with clang,
and `tools/bench_record.py` then takes the two files as columns. An emulated x86-64, such as an
OrbStack amd64 container, runs translated code, so its times say nothing about those arms.

### Reads and writes in place

A `TRANSPORT=tcp-nonblocking` session reads each record where the caller holds it, with
`ch_read_in_place`. It seals each write where the caller wrote it, with `ch_seal_in_place`
(decisions 247 and 248). The `TRANSPORT=tcp-blocking` calls copy. `ch_read` copies each record
from `cfg.recv` into `cfg.buf`, and then its plaintext out. `ch_write` copies each record into
`ch_tls.tx`, and then out through `cfg.send`.

`bench/inplace.sh`, which `make bench-inplace` runs, times both pairs of calls from one tree. Its
two programs link objects that differ in `TRANSPORT` alone, and it writes
`bench/results-inplace-<os>-<arch>-<compiler>.csv`. `tools/inplace_chart.py` draws each CSV, and
`make lint-bench-numbers` fails when a chart is not what its CSV draws (INV-76).

![Bars of the in-place read's and write's speed in multiples of the copying calls' on a virtual Intel Xeon, under gcc 14](img/inplace-linux-x86_64-gcc.svg)

A bar is the in-place call's speed in multiples of the copying call's. A bar past the dashed line at
1 is a row where the in-place call is faster. The bench connects each session by hand, so the
chart times no handshake. A read row is the time per record over 64 records. A write row is the
time per call over 16 calls, and a write of 64 KiB is four records.

On the virtual Intel Xeon of this chart, one row's figure moved by up to 2.1 times from one run of
a program to another, in streaks of consecutive runs. So the bench runs the two programs back to back 256
times, once at each 16-byte stack position of a page. A bar is the median of the 256 ratios, and
its whisker spans their 25th to 75th percentile.

In place, AES-128-GCM reads run 1.07 to 1.35 times as fast as `ch_read`, and writes 1.12 to 1.30
times as fast as `ch_write`. AES-256-GCM reads run 1.08 to 1.31 times as fast, and writes 1.03 to
1.29 times. ChaCha20-Poly1305 reads and writes run 1.01 to 1.10 times as fast. At 16 KiB the
in-place read saves about the same time with each AEAD, 440 to 472 ns a record. The
ChaCha20-Poly1305 AEAD takes longer, so that time is a smaller share of its record. The AES-256-GCM
writes of 100 bytes and 1 KiB spread the most: their pairs' quartiles are 0.84 to 1.12 and 1.08 to
1.44 times.

### arm64 AES-GCM beside OpenSSL

Decision 158 set the goal on 2026-10-25: on arm64, AES-GCM takes no more time than OpenSSL, for both
key sizes, seal and open. The arm64 columns of the [table beside
OpenSSL](performance-openssl.md#the-table) show where it stands.
[`bench/notes-record.md`](../bench/notes-record.md), "arm64 AES-GCM beside OpenSSL", holds the runs
of decisions 158 and 161 on a Neoverse N2 and on the M1 Pro, and what each change of the passes
moved.

### Where a server handshake's instructions go

[#188](https://github.com/c4milo/chapulin/issues/188) measured colibri's server at 55.4 M user
instructions per TLS connection on a Neoverse-N2, where h2o and nginx over OpenSSL 3.0.13 took 2.1
and 2.4 M. This section counts the server's side of that connection, splits it into stages and
sets OpenSSL beside it. The connection is the one h2load makes in colibri's bench: TLS 1.3 with
TLS_AES_256_GCM_SHA384 over X25519, a P-256 ECDSA leaf and the P-256 root that signed it, ALPN h2
and no ticket key. After the handshake the client sends one 100-byte request record, the server
answers with one 256-byte record, and each side sends close_notify.

The section holds the count of 2026-10-30, which [`bench/handshake-n2.sh`](../bench/handshake-n2.sh)
made over the tree of c6ceecc3. `make lint-bench-numbers` holds its three tables to
`bench/results-handshake-n2.csv` (`tools/bench_handshake.py`). The script counted earlier trees too,
and [`bench/notes-handshake.md`](../bench/notes-handshake.md) gives those counts: "What changed
since 2026-10-25" the count of f96c5192 on 2026-10-25, "What changed since 2026-10-21" the count of
d0731465, and "What decision 148 changed" and "What decision 152 changed" the counts before those
entries. The note also keeps the count of 2026-10-01, at c798fb8, which no script made, as the
record of that date.

#### The count of 2026-10-30

The script counts this way:

- The machine is GitHub's `ubuntu-24.04-arm` runner, a Neoverse-N2 (CPU part 0xd49 in
  `/proc/cpuinfo`) with 4 cores, under Linux 7.0. A workflow on a scratch branch built the chapulin
  servers on an x86-64 runner with the pinned Zig, and ran the script on the arm64 runner.
- The object is the TCP object colibri builds: `RAND=session TRANSPORT=tcp-nonblocking
  ROLE=both TRUST=webpki EXPORTER=on SUITE=aesgcm TX_RECORD=16384 KEYLOG=off`, from colibri's
  `build/modules.zig`. `build.zig` builds it with Zig 0.16.0 for aarch64-linux-gnu, once for
  `-Dcpu=neoverse_n2` and once for the base armv8-a. colibri pins chapulin at bbfd316a, 20
  commits before c6ceecc3.
- `bench/handshake_server.c` calls the object as colibri's server does. It reads the chain and
  the key from PEM files, offers ALPN h2 and http/1.1, and holds a cookie key and no ticket key.
  Each session states one `ch_cfg.cpu` value. `0xe7` is what a caller on a Neoverse-N2 states:
  the AES, multiply, SHA-256, SHA-512 and SHA-3 bits. `0x07` holds the AES and multiply bits
  alone, the value colibri stated until its `cpu_of` (`src/tls/config.zig`) took the three SHA
  bits as well. `0x03` is the AES bit alone.
- `bench/handshake_openssl_server.c` serves the same connection over OpenSSL 3.6.4, the release
  `tools/toolchain.env` pins, linked statically, and over the runner's OpenSSL 3.0.13 (the libssl3
  package), shared and static. It holds the same chain and key, and no session tickets and no
  session cache. `bench/handshake_client.c`, over OpenSSL 3.0.13, offers what h2load 1.59.0 offers:
  the one suite, the groups X25519, P-256, P-384 and P-521 with an X25519 share, and ALPN h2.
- Each figure counts the server's user-mode instructions in the second connection of a run. The
  server reads the perf_events counter of its own process when the connection starts, when the
  handshake is complete and when the socket is closed. Each such figure is the median of five
  runs, and the five runs of a figure spread by 0.02% at most. `perf stat -e instructions:u` over
  the whole process, a run of two connections less a run of one, gives the third column.
- QEMU 8.2.2 in user mode, with `-cpu neoverse-n2`, runs each server one instruction per
  translation block. `bench/handshake_stages.py` rebuilds the call stack from that trace and the
  binary's `bl` and `blr` addresses, and charges each instruction to the outermost root function
  it runs under. A tail call gives its frame to the function it calls. Each handshake of the
  trace is within 0.09% of the perf_events count of the same server.
- The nonce row holds chapulin's RFC 6979 generator: its SHA-256 calls, and the functions of
  `p256_sign.c` whose names start with `generator_`. On 2026-10-21 the generator's own functions
  fell in the row of the rest.
- The row of hashes holds three uses of SHA-2 in chapulin: the transcript hashes, the SHA-256 of the
  CertificateVerify signed content, and the ClientHello digest. That digest is
  `client_hello.frozen`, the SHA-256 that `srv_parse_client_hello` computes over the fields of each
  ClientHello a HelloRetryRequest must not change. For OpenSSL the row holds its `EVP_Digest`
  calls.
- Valgrind 3.22's callgrind decodes neither SVE nor the SHA-512 instructions. So it cannot run the
  Neoverse-N2 build, whose code holds SVE instructions, or a session that states
  `CH_CPU_CONSTANT_TIME_SHA512`. It runs the base build under `0x07` and `0x03`, OpenSSL 3.6.4
  and the shared OpenSSL 3.0.13. It gives the inclusive cost of the functions under X25519, the
  signature and the two parts of the connection.

| server side of the second connection on the Neoverse-N2, M instructions | handshake, perf_events | request, response and close_notify, perf_events | whole connection, perf stat | handshake, callgrind | handshake against OpenSSL 3.6.4 |
| --- | --- | --- | --- | --- | --- |
| chapulin, Neoverse-N2 build, `0xe7` | 0.795 | 0.009 | 0.804 | — | 0.59 |
| chapulin, Neoverse-N2 build, `0x07` | 1.219 | 0.009 | 1.228 | — | 0.91 |
| chapulin, Neoverse-N2 build, `0x03` | 43.628 | 0.009 | 43.637 | — | 32.43 |
| chapulin, base armv8-a build, `0xe7` | 0.966 | 0.009 | 0.976 | — | 0.72 |
| chapulin, base armv8-a build, `0x07` | 1.398 | 0.010 | 1.408 | 1.408 | 1.04 |
| chapulin, base armv8-a build, `0x03` | 37.809 | 0.010 | 37.819 | 37.819 | 28.11 |
| OpenSSL 3.6.4, static | 1.345 | 0.038 | 1.385 | 1.606 | 1.00 |
| OpenSSL 3.0.13, shared | 1.877 | 0.047 | 1.926 | 2.142 | 1.40 |
| OpenSSL 3.0.13, static | 1.873 | 0.046 | 1.921 | — | 1.39 |

| server side of the second connection, M instructions (QEMU's trace) | Neoverse-N2 build, `0xe7` | Neoverse-N2 build, `0x07` | Neoverse-N2 build, `0x03` | base armv8-a build, `0xe7` | OpenSSL 3.6.4, static | OpenSSL 3.0.13, static |
| --- | --- | --- | --- | --- | --- | --- |
| X25519 key generation | 0.119 | 0.119 | 13.404 | 0.133 | 0.227 | 0.423 |
| X25519 shared secret | 0.320 | 0.320 | 13.404 | 0.448 | 0.380 | 0.469 |
| CertificateVerify: the P-256 ECDSA signature | 0.170 | 0.342 | 16.381 | 0.177 | 0.197 | 0.249 |
| of which k·G | 0.103 | 0.103 | 14.447 | 0.104 | 0.069 | 0.070 |
| of which the nonce | 0.023 | 0.194 | 0.194 | 0.028 | 0.011 | 0.021 |
| of which the rest | 0.044 | 0.044 | 1.740 | 0.046 | 0.117 | 0.159 |
| HKDF and HMAC of the key schedule | 0.094 | 0.284 | 0.284 | 0.093 | 0.309 | 0.459 |
| hashes of the transcript, the signed content and the ClientHello | 0.015 | 0.077 | 0.077 | 0.015 | 0.018 | 0.016 |
| certificate, other messages and their records | 0.077 | 0.077 | 0.077 | 0.101 | 0.215 | 0.257 |
| the handshake | 0.795 | 1.219 | 43.628 | 0.966 | 1.347 | 1.874 |
| one request's records and the two close_notify | 0.009 | 0.009 | 0.009 | 0.010 | 0.038 | 0.046 |
| of the handshake, the image's own memset | 0.043 | 0.041 | 0.041 | 0.071 | 0.000 | 0.000 |
| of the handshake, the C library | 0.000 | 0.000 | 0.000 | 0.000 | 0.162 | 0.233 |

| base armv8-a build, M instructions | `0x07`, callgrind | `0x07`, QEMU's trace | `0x03`, callgrind | `0x03`, QEMU's trace |
| --- | --- | --- | --- | --- |
| X25519 key generation | — | 0.133 | — | 10.581 |
| X25519 shared secret | 0.448 | 0.448 | 10.581 | 10.581 |
| CertificateVerify: the P-256 ECDSA signature | 0.353 | 0.353 | 16.183 | 16.183 |
| of which k·G | 0.104 | 0.104 | 14.261 | 14.261 |
| the handshake | 1.408 | 1.398 | 37.819 | 37.809 |
| one request's records and the two close_notify | 0.010 | 0.010 | 0.010 | 0.010 |
| of the handshake, the image's own memset | 0.069 | 0.069 | 0.069 | 0.069 |

What the count of 2026-10-30 shows:

- chapulin runs fewer instructions than OpenSSL 3.6.4 on this connection when the session states
  every bit the Neoverse-N2 has. Under `0xe7` the Neoverse-N2 build's handshake takes 795,008
  instructions, 0.59 of OpenSSL 3.6.4's 1,345,252 and 0.42 of OpenSSL 3.0.13's 1,876,936. The
  whole connection takes 0.804 M against 1.385 M and 1.926 M.
- Under `0x07` chapulin runs 0.91 of OpenSSL 3.6.4's handshake and 0.65 of OpenSSL 3.0.13's. The
  three SHA bits remove 424,060 instructions. The key schedule, the transcript hashes, the
  signed content's digest, the ClientHello digest and the nonce's SHA-256 calls then run on the
  SHA instructions. Only the caller can state those bits, and colibri's `cpu_of` now states them
  on arm64.
- Under `0xe7` every stage costs fewer instructions than OpenSSL 3.6.4's. The X25519 shared
  secret costs 0.320 M against 0.380 M, and key generation 0.119 M against 0.227 M. The
  signature costs 0.170 M against 0.197 M, and the messages 0.077 M against 0.215 M.
- 42,713 of the 795,024 instructions of the trace, 5%, run in the image's own `memset`. Zig
  0.16 links `memset` from its compiler_rt into each image it links, and that `memset` writes one
  byte at a time. `ct_wipe` calls it no longer (decision 144), so these are the calls that clear
  a structure before its first use. The OpenSSL servers, which gcc links, call the C library's
  `memset`, and their row of the C library holds it.
- The Neoverse-N2 build costs fewer instructions than the base build on the paths of a host
  session: 0.795 M against 0.966 M under `0xe7`. Under `0x03` it costs more, 43.63 M against
  37.81 M, because `x25519.c`'s `mul` holds SVE instructions, as on 2026-10-01.
- callgrind agrees with the trace on the base build. Under `0x07` k·G is the same to the
  instruction, the shared secret differs by 139 instructions and the signature by 36.
  callgrind's handshake under `0x07` is 0.7% larger than the trace's. Under valgrind OpenSSL
  finds no SHA-512 instructions and runs SHA-384 in scalar code, so callgrind counts its
  handshakes 19% and 14% above perf_events.
- callgrind has no row for X25519 key generation. `srv_kex_begin` now enters it with a tail
  jump, and callgrind charges the instructions after such a jump to the function that jumped.

How the count reached these figures, entry by entry, and the first count, of 2026-10-01, with
the order of the work it set, are in [`bench/notes-handshake.md`](../bench/notes-handshake.md).

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
- The [table beside OpenSSL](performance-openssl.md#the-table) prints a filter's figures too, for
  the same reason: every row of it runs in a host object. It states each machine's load beside its
  figures and takes both sides of a ratio in one run, on CPU time for every row above the AEADs, and
  its CSV holds each chapulin row's instruction count where macOS gives one. It ranks the work by
  ratio. A change that claims a row records the row again with both scripts, and reports the
  instructions of the rows it moved.
- The units of work are a handshake, a record, a byte of SRAM and a byte of flash.
- A change stays when it lowers SRAM, flash or instructions past the noise on the device builds and
  raises none of them past it; a change that trades constant time for any of the three is refused,
  whatever it saves.
- The pitfalls it has paid for, each as symptom, cause and rule, are in
  [docs/performance-pitfalls.md](performance-pitfalls.md).


### Patterns of a fast primitive

pepegrillo's [performance_hardware.md](https://github.com/c4milo/pepegrillo/blob/main/docs/performance/performance_hardware.md)
gives the patterns of any fast loop. A new primitive or kernel here follows them, and the four
patterns of multi-word arithmetic below, before its first measurement.

1. Count every operation of a formula: its additions, subtractions and halvings as well as its
   products and squares. 8·Y^4 takes three additions from Y^4, or
   one halving by a mask from (2Y)^4. On the EPYC 7763 an addition of four words takes 14.1 cycles
   under gcc and 7.6 under clang. P-256's doubling in `p256_wide_point.c` ran 14 additions and
   subtractions. It now computes the same point scaled by 1/2, in 7 and one halving (decision 196).
2. Reduce inside the products. Start each round of a Montgomery reduction as soon as its word of
   the product is ready, so the reduction and the next products overlap. Carry only where the
   proved bound requires it, and give each carry that a change removes a CBMC bound and a Lean
   theorem.
3. Read a value from a volatile object once for each step, for all of its uses in that step, not
   once for each use. Mark a small function of inline assembly `always_inline`, and read gcc's
   output for a call to it. `x25519_adx.c` reads the ladder bit from a volatile object in each of
   its two swaps of a step. Both were measured and did not win on the EPYC 7763: gcc's calls run
   beside the products (decision 197).

4. Order a formula's products in pairs that read nothing of each other, and put the products of
   the value the formula before wrote last after the products of older values. A product reads
   its operands from memory and writes its result there, and on an EPYC 7763 about two products
   fit in the core's window. A form of `p256_wide_fe_reduce_once` with 21% fewer instructions in
   gcc's doubling made the doubling slower, 334 cycles where it took 330, and the order of its
   products took it to 314 (decision 224).

This tree refuses these patterns, whatever they save:

- A load at an address that a secret selects (`ct.[ch]`).
- A table larger than the first-level cache of the smallest core that runs it. On the M1 Pro, a
  scan of a 148 KiB table took a time that followed the secret scalar, and a scan of 86 KiB did not
  (decision 109).
- State that a call keeps for the next call where the API holds none, such as an RSA key's R^2 mod
  n.
- A branch on a secret byte, such as a sampler that squeezes more bytes only when it needs them.
