# chapulin

[![check](https://github.com/c4milo/chapulin/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)
[![nightly](https://github.com/c4milo/chapulin/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/c4milo/chapulin/actions/workflows/nightly.yml?query=branch%3Amain)
[![coverage](https://raw.githubusercontent.com/c4milo/chapulin/badges/.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A TLS 1.3 library in C11 for devices with a few kilobytes of RAM. It
needs no heap and nothing beyond libc. It runs as a client, as a
server, or as the TLS layer under a QUIC stack.

The name comes from El Chapulín Colorado: small, unassuming, and it
protects you from the bad guys.

## At a glance

| | |
| --- | --- |
| Protocol | TLS 1.3 only ([RFC 9846](https://www.rfc-editor.org/rfc/rfc9846)). No TLS 1.2, no 0-RTT, no renegotiation. |
| Roles | Client, server (`ROLE=server`), or both in one object (`ROLE=both`) |
| Transports | TCP through blocking callbacks; TCP where your code moves the records; QUIC's TLS layer, QUIC versions 1 and 2 ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369)) |
| Cipher suites | `TLS_CHACHA20_POLY1305_SHA256`; `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` with `SUITE=aesgcm` |
| Key exchange | x25519, the X25519MLKEM768 post-quantum hybrid, and secp256r1. A device build offers one group; web PKI clients and servers hold all three. |
| Server authentication | Pre-shared key, pinned public key, pinned CA, or web PKI: a certificate chain, SPKI pins, or both |
| PEM files | Decodes certificate chains, P-256 keys, CA bundles and CA certificates from bytes your program reads |
| Memory, default build | 3120 B static working set on a 32-bit device, receive buffer included; 5008 B peak stack, measured on arm64; 31.4 kB of flash |
| Dependencies | C11 and libc. No `malloc` anywhere. |
| License | Apache-2.0 |

[`docs/performance.md`](docs/performance.md) has the figures for every
build, and `make lint-bench-numbers` checks the memory row against them.

## Why it exists

- The small embedded TLS stacks are mostly commercial (SEGGER emSSL,
  SharkSSL) or GPLv3 with a paid license (wolfSSL).
- The permissively licensed ones leave a gap. BearSSL has no TLS 1.3.
  picotls and Mbed TLS need an allocator, and Mbed TLS uses 9 to 15 kB
  of RAM before its buffers.
- chapulin is TLS 1.3 with no heap, in a few kilobytes, under
  Apache-2.0.
- The protocol profile is small enough to state exactly, so it is checked
  with proofs and an executable specification, not only with tests.

[`docs/landscape.md`](docs/landscape.md) surveys the field, with sources.

## Quick start

Build the library as one object file. `RAND` says where randomness comes
from, and it has no default:

```sh
make lib RAND=extern    # writes bin/chapulin.o and bin/chapulin.h
```

`bin/chapulin.o` exports only the public calls and its build record.
Your program supplies:

- a send callback and a receive callback for its socket. Each returns
  how many bytes it moved, and -1 when it fails (`cfg.h`);
- `ch_rand_bytes`, which fills a buffer from the platform's entropy
  source, or under `RAND=session` a source in each session's
  configuration;
- `ch_assert_fail`, which the library calls on a programmer error and
  which must not return.

A client that shares a key with its server:

```c
#include "tls.h"

static uint8_t rxbuf[2048];
static ch_tls tls;

ch_cfg cfg = {
    .psk = psk, .psk_len = 32,
    .psk_id = (const uint8_t *)"device-42", .psk_id_len = 9,
    .buf = rxbuf, .buf_len = sizeof rxbuf,
    .send = my_send, .recv = my_recv, .io = &sock,
};

if (ch_connect(&tls, &cfg) != CH_OK) {
    /* reconnect later: any error ends the session and wipes its keys */
}
ch_write(&tls, request, request_len);
int got = ch_read(&tls, reply, sizeof reply);  /* 0 when the peer closed */
ch_close(&tls);
```

The struct sizes depend on the defines the object was built with.
`bin/chapulin.h` holds those defines and includes the public headers, so
compile your program with it and pass no `-D` flag of your own:

```sh
cc -std=c11 -I path/to/chapulin -include path/to/chapulin/bin/chapulin.h \
    app.c path/to/chapulin/bin/chapulin.o -o app
```

A build that cannot take the header passes the flags that
`make print-lib-def` prints. Either way, call
`ch_build_matches(&ch_build)` (`build.h`) once at startup, as every
example does. It returns 0 when your defines and the object's differ
([`docs/building.md`](docs/building.md)).

A Zig project (Zig 0.16.0) can depend on chapulin as a package. Its
module `chapulin` is a Zig API over the same object, as `chapulin.hpp` is
for C++. It runs `TRANSPORT=tcp-nonblocking` and QUIC sessions that a
program places in its own memory. It takes values in place of `ch_cfg`,
and returns Zig errors in place of result codes. The module carries the
object, and `chapulin.c` holds the headers translated under the object's
defines. [`docs/zig.md`](docs/zig.md) is the API's reference, and
[`docs/building.md`](docs/building.md) shows the `b.dependency` call and
its options.

[`examples/`](examples/) has complete programs for each trust mode, and
`make examples-check` builds them. [`docs/usage.md`](docs/usage.md)
covers the configuration each mode takes, resumption, ALPN, the server
role and QUIC.

## Choosing a build

Each Makefile variable picks one thing the packaged object carries. The
first value listed is the default.

| Variable | Values | What it chooses |
| --- | --- | --- |
| `RAND` | `extern`, `drbg`, `session` (no default) | Your own `ch_rand_bytes`, the built-in seeded generator, or a source each session names in its configuration ([`docs/entropy.md`](docs/entropy.md)) |
| `TRUST` | `raw-rsa`, `raw-ecdsa`, `ca-rsa`, `ca-ecdsa`, `webpki`, `none` | How a client checks the server; `none` is for a server role |
| `ROLE` | `client`, `server`, `both` | Which side of the handshake the object runs |
| `TRANSPORT` | `tcp-blocking`, `tcp-nonblocking`, `quic-nonblocking` | What TLS runs over, and whether chapulin or your code does the I/O |
| `KEX` | `x25519`, `pq` | The key exchange of a raw or ca client |
| `SUITE` | `chacha`, `aesgcm` | Adds the AES-GCM suites to a web PKI client or a server |
| `AES` | `soft`, `extern` | A device object's AES, when its build uses AES: the table, for QUIC's public keys alone, or the `ch_aes_block` your image defines |
| `EXPORTER` | `off`, `on` | Adds `ch_export`, the TLS exporter |
| `KEYLOG` | `off`, `on` | Hands each traffic secret to a hook you define, for an NSS key log |
| `WIDEMUL` | `decomposed`, `native` | Whether a device object's wide multiplies use the CPU instruction, which you must know runs in constant time |

On arm64 and x86-64, a web PKI client and both server roles build a host
object, which takes neither `AES` nor `WIDEMUL`. It holds fast paths
beside the portable C, and each session picks among them from
`ch_cfg.cpu`. chapulin probes no CPU: your program sets that field from
the bits in `cpu_cfg.h`. The fast paths are:

- in every session, ChaCha20 and ML-KEM's NTT on 128-bit vectors, and
  ECDSA and RSA verification on 64-bit words;
- under `CH_CPU_CONSTANT_TIME_MULTIPLY`, X25519, P-256 and RSA signatures
  on the 64-bit multiply, and Poly1305 on the vector multiply;
- under `CH_CPU_CONSTANT_TIME_AES`, AES-GCM on the AES and carry-less
  multiply instructions;
- under `CH_CPU_CONSTANT_TIME_SHA256`, SHA-256 on its instructions;
- on arm64 under `CH_CPU_CONSTANT_TIME_SHA512`, SHA-384 on the SHA-512
  instructions, in an object with `SUITE=aesgcm`;
- on arm64 under `CH_CPU_CONSTANT_TIME_SHA3`, SHA-3 and SHAKE on their
  instructions, in an object that clang built;
- on x86-64, AVX2, VAES and AVX-512 kernels for ChaCha20, Poly1305,
  AES-GCM, ML-KEM and RSA, and an AVX2 kernel for SHA-384 under
  `SUITE=aesgcm`. `cpu_cfg.h` names the bits that each kernel needs.

[`docs/performance.md`](docs/performance.md) times each primitive beside
OpenSSL 3.6 on an Apple M1 Pro and two x86-64 CPUs. Some rows take less
time than OpenSSL's, and some take more.

[`docs/building.md`](docs/building.md) explains each value, what it adds
to the object, and the checks a build refuses to pass without.
[`docs/porting.md`](docs/porting.md) is the checklist for a new platform.

## Trust modes

A client checks the server in one of these ways, chosen when you build it.

| Mode | Build | What the client checks | What you provide |
| --- | --- | --- | --- |
| Pre-shared key | a raw or ca build, with `cfg.psk` set | The server knows the shared key (ECDHE-PSK, so the session keeps forward secrecy) | A secret provisioned on both sides |
| Pinned key | `TRUST=raw-rsa` (default) or `TRUST=raw-ecdsa` | The server's signature, against the public key you pinned. The client parses no certificate. | The server's public key |
| Pinned CA | `TRUST=ca-rsa` or `TRUST=ca-ecdsa` | A chain of one or two certificates up to the CA key you pinned. No clock. | A CA you run ([`docs/ca.md`](docs/ca.md)) |
| Web PKI | `TRUST=webpki` | A public certificate chain to the roots you supply, the hostname and the dates. SPKI pins add a check that one pin names a key on the verified path. Pins alone replace the chain check, and one pin must name the server's key. | A 12 kB receive buffer. For a chain: a clock, a hostname and the roots. For pins alone: the pins ([`docs/webpki.md`](docs/webpki.md)). |

The raw and ca modes are for devices: they read no clock and no names.
Web PKI is for hosts. [`docs/trust-modes.md`](docs/trust-modes.md) states
each mode in full, with resumption, and the ca modes' revocation without
a clock.

## PEM files

chapulin decodes the PEM files an operator holds into what a session
takes. Your program reads each file into memory, and each call writes
into buffers that your program gives. No call does I/O or checks a
signature, a date or a name, and no session calls one.

| Call | Objects that export it | File | Result |
| --- | --- | --- | --- |
| `ch_chain_from_pem` | `ROLE=server`, `ROLE=both` | A certificate chain | The chain of a server identity |
| `ch_p256_key_from_pem` | `ROLE=server`, `ROLE=both` | A P-256 key, PKCS #8 or SEC 1 | The scalar and the point of an ECDSA identity |
| `ch_anchors_from_pem` | `TRUST=webpki` | A CA bundle | The roots that `ch_cfg.anchors` takes |
| `ch_pubkey_from_pem` | `TRUST=ca-rsa`, `TRUST=ca-ecdsa` | One CA certificate | The key that `ch_cfg.server_pubkey` takes |

`pem_files.h` and `x509_ca.h` state each contract.
[`docs/server.md`](docs/server.md), [`docs/webpki.md`](docs/webpki.md)
and [`docs/ca.md`](docs/ca.md) describe the files each call reads.

## Verification and testing

- **Proofs.** Most C sources have a [CBMC](https://www.cprover.org/cbmc/)
  harness. Over every input up to a stated bound, it excludes
  out-of-bounds access, invalid pointers, bad shifts, division by zero
  and, in all but five X25519 harnesses, signed overflow. Crypto
  primitives also prove equivalence to a small reference at bounded
  sizes. A file of CPU intrinsics has no harness, unless the harness
  compiles it over a C model of each instruction. An equivalence test
  holds each such file to the proven portable C.
- **Specification.** [`spec/lean/`](spec/lean/) is an executable
  [Lean 4](https://lean-lang.org/) specification of the cryptography, the
  key schedule and the message formats, written from the RFCs.
  `make diff` compares the C against it on random inputs from a fixed
  seed, and the nightly runs it on new seeds.
- **State machine.** A test enumerates every server message sequence, up
  to a fixed length, that a Lean model of the handshake admits. It
  requires the real client's verdict on each to match the model's.
- **Test vectors.** The RFC 8448 handshake traces, the RFC vectors for
  each primitive, and the [Wycheproof](https://github.com/C2SP/wycheproof)
  cases.
- **Constant time.** Lints compile each arithmetic file for Cortex-M3,
  mips32r2 and rv32 under clang and gcc. They count the wide multiplies,
  the divisions and the branches the compilers emit. Under clang, they
  also compile most of a host object's arithmetic files for arm64 and
  x86-64. There they count the divisions, the 128-bit runtime calls and
  the branches. The AES-GCM instruction files have no count yet.
  `make timing` times ChaCha20, Poly1305, X25519, `ct_memeq` and
  `pem_read_block`. For each one, it compares two classes of input with
  Welch's t-test. On arm64 and x86-64, it also times a host object's X25519,
  P-256 and RSA arithmetic on 64-bit words.
- **Mutation checks.** Each file in [`test/violations/`](test/violations/)
  breaks one rule on purpose, and the named test must fail on it.
- **Interoperability.** End-to-end handshakes of the client against
  OpenSSL 3 and Go servers, and of the server against OpenSSL 3's client.
- **Fuzz targets and sanitizers.** libFuzzer targets, and
  AddressSanitizer with UndefinedBehaviorSanitizer over about half of
  the deterministic suites. The sanitized suites are the primitive
  tests, the web PKI tests, and the default build's unit and parser
  tests. The server, QUIC session and PEM file tests run without the
  sanitizers.

On each pull request and each push to main, CI runs the lints, the tests
and the platform suites. A push to main also runs the fast proofs, the
fast mutation checks, the end-to-end handshakes, the spec differential and
the state machine test. The nightly runs the slow proofs, every mutation
check, the differential on new seeds and the fuzz targets.
[`docs/verification.md`](docs/verification.md) lists every harness, its
bound, and what rests on tests instead of proofs.
[`docs/proofs.md`](docs/proofs.md) explains how the harnesses are
written, and [`docs/invariants.md`](docs/invariants.md) lists the rules a
change must not break.

## Supported platforms

A platform is listed when CI runs the suites there on every push to main.

| Platform | How the suites run | CI job |
| --- | --- | --- |
| Linux x86_64 | Natively: every lint, the fast proofs, the sanitizers, line coverage and the end-to-end handshakes. The host object's AVX2 and VAES kernels and its SHA-256 instructions, on a runner CPU that the job requires to have them (`make x86-64-kernels-check`). Under QEMU user mode, the host object on CPU models without AES-NI, PCLMULQDQ, AVX2 or the SHA extensions (`make aes-runtime-qemu`). Each night, the AVX-512 kernels under Intel SDE, an emulator (`make rsa-ifma-sde-check`). | `check`, `slow`, `mutants`, `prove`, `san`, `coverage`, `x86-64-kernels`, `mips`; nightly `rsa-ifma-sde` |
| Linux arm64 | Natively under gcc: the deterministic suites (`make suite-check`), which run the host object's AES, PMULL, SHA-256 and SHA-512 instructions. Under clang, SHA-3 on its instructions (`make keccak-instructions-check`). The host objects, disassembled (`make aes-runtime-disasm`). Under QEMU user mode, the host object on a CPU model without the SHA-512 instructions (`make aes-runtime-qemu`). | `arm64`, `mips` |
| macOS arm64 | Natively under Apple clang: the deterministic suites (`make suite-check`), which run the host object's AES, PMULL, SHA-256, SHA-512 and SHA-3 instructions. The host objects, disassembled (`make aes-runtime-disasm`). | `macos` |
| mips32r2, big-endian | Cross-built, under QEMU user mode (`make cross-check`) | `mips` |
| riscv32 | Cross-built with a pinned musl toolchain, under QEMU user mode | `riscv32` |
| Cortex-M3, bare metal | The unmodified suites through semihosting on QEMU (`make m3-check`) | `m3` |
| FreeRTOS on Cortex-M3 | A task completes a TLS 1.3 handshake through FreeRTOS+TCP to a live `openssl s_server` (`make freertos-check`) | `freertos` |

The development machines run macOS on Apple silicon. For another
platform, start with [`docs/porting.md`](docs/porting.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | The public calls, each mode's configuration, the server role and QUIC |
| [`docs/building.md`](docs/building.md) | Makefile targets and every build variable |
| [`docs/zig.md`](docs/zig.md) | The Zig API: values, sessions, errors and what it leaves to `chapulin.c` |
| [`docs/trust-modes.md`](docs/trust-modes.md) | How a client authenticates the server, mode by mode |
| [`docs/performance.md`](docs/performance.md) | Memory, stack, speed and flash for each build |
| [`docs/verification.md`](docs/verification.md) | What is proved, at what bound, and what is only tested |
| [`docs/porting.md`](docs/porting.md) | How to bring chapulin to a new platform or compiler |
| [`docs/entropy.md`](docs/entropy.md) | Where randomness comes from, and how to seed the built-in generator |
| [`docs/webpki.md`](docs/webpki.md) | The web PKI mode's profile and what it does not check |
| [`docs/ca.md`](docs/ca.md) | How to run a CA for the pinned-CA modes |
| [`docs/rotation.md`](docs/rotation.md) | How to rotate a pinned key safely |
| [`docs/server.md`](docs/server.md) | The server role's design |
| [`docs/quic.md`](docs/quic.md) | The QUIC mode's design |
| [`docs/quic_server.md`](docs/quic_server.md) | The scope of the QUIC server role, and what was built after it |
| [`docs/aes_suite.md`](docs/aes_suite.md) | The scope of the AES-GCM suites, and what changes when AES takes a traffic key |
| [`docs/proofs.md`](docs/proofs.md) | How the CBMC harnesses are written and measured |
| [`docs/invariants.md`](docs/invariants.md) | The invariants a change must not break |
| [`docs/decisions.md`](docs/decisions.md) | Every design trade, with its reasons |
| [`docs/landscape.md`](docs/landscape.md) | Other embedded TLS stacks, with sources |
| [`docs/impact.md`](docs/impact.md) | `make impact`, which lists the checks a change can break |

## Limits

- chapulin does not implement 0-RTT, DTLS, client certificates,
  CRL or OCSP, general X.509 path building, or any fallback to an older
  protocol. It reads no system root store.
- The device modes, raw and ca, do not trust public CAs. The web PKI
  mode does, against roots you supply. `ch_anchors_from_pem` decodes
  them from a CA bundle.
- It does not offer `TLS_AES_128_CCM_8_SHA256`, the IoT profile's
  mandatory suite. A peer that insists on AES-CCM will not connect.
- A pinned key breaks when the server rotates it.
  [`docs/rotation.md`](docs/rotation.md) shows the two-slot pin. The
  pinned-CA modes accept a new server key whose chain verifies up to the
  pinned CA key.
- The quality of your random bytes is yours to ensure: no library can
  detect a weak generator ([`docs/entropy.md`](docs/entropy.md)).

## Contributing and security

[`CONTRIBUTING.md`](CONTRIBUTING.md) states the workflow and the checks a
change must pass. Report vulnerabilities as [`SECURITY.md`](SECURITY.md)
describes, not in the public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
