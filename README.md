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
| Transports | TCP through blocking callbacks; TCP where your code moves the records; QUIC's TLS layer ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)) |
| Cipher suites | `TLS_CHACHA20_POLY1305_SHA256`; `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` with `SUITE=aesgcm` |
| Key exchange | x25519, the X25519MLKEM768 post-quantum hybrid, and secp256r1. A device build offers one group; web PKI clients and servers hold all three. |
| Server authentication | Pre-shared key, pinned public key, pinned CA, or web PKI chain with optional SPKI pins |
| Memory, default build | 3128 B static working set on a 32-bit device, receive buffer included; 4992 B peak stack, measured on arm64; 30.3 kB of flash |
| Dependencies | C11 and libc. No `malloc` anywhere. |
| License | Apache-2.0 |

[`docs/performance.md`](docs/performance.md) has the figures for every
build, and `make lint-bench-numbers` checks the row above against them.

## Why it exists

- The small embedded TLS stacks are mostly commercial (SEGGER emSSL,
  SharkSSL) or GPLv3 with a paid license (wolfSSL).
- The permissively licensed ones leave a gap. BearSSL has no TLS 1.3.
  picotls and Mbed TLS need an allocator, and Mbed TLS uses 9 to 15 kB
  of working RAM.
- chapulin is TLS 1.3 with no heap, in a few kilobytes, under
  Apache-2.0.
- The protocol profile is small enough to state exactly, so it is checked
  with proofs and an executable specification, not only with tests.

[`docs/landscape.md`](docs/landscape.md) surveys the field, with sources.

## Quick start

Build the library as one object file. `RAND` says where randomness comes
from, and it has no default:

```sh
make lib RAND=extern    # writes bin/chapulin.o
```

`bin/chapulin.o` exports only the public calls. Your program supplies:

- a send callback and a receive callback for its socket;
- `ch_rand_bytes`, which fills a buffer from the platform's entropy
  source, or under `RAND=session` a source in each session's
  configuration;
- `ch_assert_fail`, which the library calls on a programming error and
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

Compile your program with the same `-D` flags the object was built with,
because the struct sizes depend on them. `make print-lib-def` prints them
for the same variables; for this build it is `-DCH_RAND_EXTERN`:

```sh
cc -std=c11 -DCH_RAND_EXTERN -I path/to/chapulin app.c \
    path/to/chapulin/bin/chapulin.o -o app
```

Call `ch_build_matches(&ch_build)` once at startup: it returns 0 when your
flags and the object's differ ([`docs/building.md`](docs/building.md)).

A Zig project (Zig 0.16.0) can depend on chapulin as a package. Its
module `chapulin` is a Zig API over the same object, as `chapulin.hpp` is
for C++: sessions a program places in its own memory, values in place of
`ch_cfg`, and Zig errors in place of result codes. The module carries the
object, and `chapulin.c` holds the headers translated under the object's
defines. [`docs/zig.md`](docs/zig.md) is the API's reference, and
[`docs/building.md`](docs/building.md) shows the `build.zig.zon`
dependency and its options.

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
| `X25519` | `portable`, `wide` | The x25519 field: 16-bit limbs for any core, or 51-bit limbs for 64-bit hosts |
| `WIDEMUL` | `decomposed`, `native` | Whether a device object's wide multiplies use the CPU instruction, which you must know runs in constant time |

On arm64 and x86-64, a web PKI client and both server roles build a host
object. It holds the AES instructions and both multiplies, takes neither
`AES` nor `WIDEMUL`, and picks for each session from `ch_cfg.cpu`, your
program's description of the CPU.

[`docs/building.md`](docs/building.md) explains each value, what it adds
to the object, and the checks a build refuses to pass without.
[`docs/porting.md`](docs/porting.md) is the checklist for a new platform.

## Trust modes

A client checks the server in one of these ways, chosen when you build it.

| Mode | Build | What the client checks | What you provide |
| --- | --- | --- | --- |
| Pre-shared key | a raw or ca build, with `cfg.psk` set | The server knows the shared key (ECDHE-PSK, so the session keeps forward secrecy) | A secret provisioned on both sides |
| Pinned key | `TRUST=raw-rsa` (default) or `TRUST=raw-ecdsa` | The server's signature, against the public key you pinned. No certificate parsing. | The server's public key |
| Pinned CA | `TRUST=ca-rsa` or `TRUST=ca-ecdsa` | A chain of one or two certificates up to the CA key you pinned. No clock. | A CA you run ([`docs/ca.md`](docs/ca.md)) |
| Web PKI | `TRUST=webpki` | A public certificate chain to the roots you supply, the hostname and the dates, and SPKI pins if you set them | A clock, a hostname, the roots, and a 12 kB receive buffer ([`docs/webpki.md`](docs/webpki.md)) |

The raw and ca modes are for devices: they read no clock and no names.
Web PKI is for hosts. [`docs/trust-modes.md`](docs/trust-modes.md) states
each mode in full, including resumption and revocation without a clock.

## Verification and testing

- **Proofs.** Most C sources have a [CBMC](https://www.cprover.org/cbmc/)
  harness that proves them free of out-of-bounds access, invalid
  pointers, overflow and other undefined behavior, over every input up to
  a stated bound. Crypto primitives also prove equivalence to a small
  reference at bounded sizes.
- **Specification.** [`spec/lean/`](spec/lean/) is an executable
  [Lean 4](https://lean-lang.org/) specification of the cryptography, the
  key schedule and the message formats, written from the RFCs.
  `make diff` compares the C against it on random inputs.
- **State machine.** A test enumerates every server message sequence a
  Lean model of the handshake admits, and requires the real client's
  verdict on each to match the model's.
- **Test vectors.** The RFC 8448 handshake traces, the RFC vectors for
  each primitive, and the [Wycheproof](https://github.com/C2SP/wycheproof)
  cases.
- **Constant time.** Lints compile each secret-handling file for
  Cortex-M3, mips32r2 and rv32 and count the multiplies and branches the
  compilers emit. `make timing` runs a statistical timing test.
- **Mutation checks.** Each file in [`test/violations/`](test/violations/)
  breaks one rule on purpose, and the named test must fail on it.
- **Interoperability.** End-to-end handshakes against OpenSSL 3 and Go,
  as client and as server.
- **Fuzzing and sanitizers.** libFuzzer targets, and AddressSanitizer
  with UndefinedBehaviorSanitizer over every deterministic suite.

CI runs the lints, tests, fast proofs and cross-architecture suites on
every push, and the slow proofs, mutation checks and fuzzing nightly.
[`docs/verification.md`](docs/verification.md) lists every harness, its
bound, and what rests on tests instead of proofs.
[`docs/proofs.md`](docs/proofs.md) explains how the harnesses are
written, and [`docs/invariants.md`](docs/invariants.md) lists the rules a
change must not break.

## Supported platforms

A platform is listed when CI runs the suites there on every push to main.

| Platform | How the suites run | CI job |
| --- | --- | --- |
| Linux x86_64 | Natively, with every lint, proof and sanitizer, and the host object without its AES bit under QEMU user mode on a CPU model without AES-NI or PCLMULQDQ (`make aes-runtime-qemu`) | `check`, `san`, `mips` |
| Linux arm64 | Natively, the deterministic suites (`make suite-check`), the host object's AES on the Arm AES and PMULL instructions among them, and the host objects disassembled (`make aes-runtime-disasm`) | `arm64` |
| mips32r2, big-endian | Cross-built, under QEMU user mode (`make cross-check`) | `mips` |
| riscv32 | Cross-built with a pinned musl toolchain, under QEMU user mode | `riscv32` |
| Cortex-M3, bare metal | The unmodified suites through semihosting on QEMU (`make m3-check`) | `m3` |
| FreeRTOS on Cortex-M3 | A task completes a TLS 1.3 handshake through FreeRTOS+TCP to a live `openssl s_server` (`make freertos-check`) | `freertos` |

macOS is the development host. For another platform, start with
[`docs/porting.md`](docs/porting.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | The public calls, each mode's configuration, the server role and QUIC |
| [`docs/building.md`](docs/building.md) | Makefile targets and every build variable |
| [`docs/zig.md`](docs/zig.md) | The Zig API: values, sessions, errors and what it leaves to `chapulin.c` |
| [`docs/trust-modes.md`](docs/trust-modes.md) | How a client authenticates the server, mode by mode |
| [`docs/performance.md`](docs/performance.md) | Memory, stack, speed and flash for each build |
| [`docs/verification.md`](docs/verification.md) | What is proved, at what bound, and what is only tested |
| [`docs/porting.md`](docs/porting.md) | Bringing chapulin to a new platform or compiler |
| [`docs/entropy.md`](docs/entropy.md) | Where randomness comes from, and how to seed the built-in generator |
| [`docs/webpki.md`](docs/webpki.md) | The web PKI mode's profile and what it does not check |
| [`docs/ca.md`](docs/ca.md) | Running a CA for the pinned-CA modes |
| [`docs/rotation.md`](docs/rotation.md) | Rotating a pinned key safely |
| [`docs/server.md`](docs/server.md) | The server role's design |
| [`docs/quic.md`](docs/quic.md) | The QUIC mode's design |
| [`docs/quic_server.md`](docs/quic_server.md) | What chapulin provides a QUIC server |
| [`docs/aes_suite.md`](docs/aes_suite.md) | What the AES-GCM suites rest on |
| [`docs/proofs.md`](docs/proofs.md) | How the CBMC harnesses are written and measured |
| [`docs/invariants.md`](docs/invariants.md) | The invariants a change must not break |
| [`docs/decisions.md`](docs/decisions.md) | Every design trade, with its reasons |
| [`docs/landscape.md`](docs/landscape.md) | Other embedded TLS stacks, with sources |
| [`docs/impact.md`](docs/impact.md) | `make impact`, which lists the checks a change can break |

## Limits

- chapulin does not implement 0-RTT, DTLS, client certificates,
  CRL or OCSP, general X.509 path building, CA bundles, or any fallback
  to an older protocol.
- The device modes, raw and ca, do not trust public CAs. The web PKI
  mode does, against roots you supply.
- It does not offer `TLS_AES_128_CCM_8_SHA256`, the IoT profile's
  mandatory suite. A peer that insists on AES-CCM will not connect.
- A pinned key breaks when the server rotates it.
  [`docs/rotation.md`](docs/rotation.md) shows the two-slot pin, and the
  pinned-CA modes absorb routine rotation.
- The quality of your random bytes is yours to ensure: no library can
  detect a weak generator ([`docs/entropy.md`](docs/entropy.md)).

## Contributing and security

[`CONTRIBUTING.md`](CONTRIBUTING.md) states the workflow and the checks a
change must pass. Report vulnerabilities as [`SECURITY.md`](SECURITY.md)
describes, not in the public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
