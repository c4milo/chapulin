# chapulin

[![check](https://github.com/c4milo/chapulin/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)
[![nightly](https://github.com/c4milo/chapulin/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/c4milo/chapulin/actions/workflows/nightly.yml?query=branch%3Amain)
[![coverage](https://raw.githubusercontent.com/c4milo/chapulin/badges/.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A TLS 1.3 library in C11. On a device it runs in a few kilobytes of RAM,
with no heap and nothing beyond libc. On a host it runs at about
OpenSSL's speed. It runs as a client, as a server, or as the TLS layer
under a QUIC stack.

The name comes from El Chapulín Colorado: small, unassuming, and it
protects you from the bad guys.

## At a glance

| | |
| --- | --- |
| Protocol | TLS 1.3 only ([RFC 9846](https://www.rfc-editor.org/rfc/rfc9846)). No TLS 1.2, no 0-RTT, no renegotiation. |
| Roles | Client, server (`ROLE=server`), or both in one object (`ROLE=both`) |
| Transports | TCP through blocking callbacks; TCP where your code moves the records; QUIC's TLS layer, QUIC versions 1 and 2 ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369)) |
| Cipher suites | `TLS_CHACHA20_POLY1305_SHA256`; `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` with `SUITE=aesgcm` |
| Key exchange | x25519, the X25519MLKEM768 post-quantum hybrid, secp256r1, and ML-KEM-1024. A device build offers one group: x25519, X25519MLKEM768 under `KEX=pq`, or ML-KEM-1024 under `PROFILE=cnsa2`. A web PKI client offers the first three. A server holds all four and picks ML-KEM-1024 first. |
| Server authentication | Pre-shared key; a pinned public key or a pinned CA, under RSA-PSS, ECDSA P-256, or ML-DSA-87 with `PROFILE=cnsa2`; or web PKI: a certificate chain, SPKI pins, or both |
| PEM files | Decodes certificate chains, P-256, RSA and ML-DSA-87 keys, CA bundles and CA certificates from bytes your program reads |
| Memory, default build | 3120 B static working set on a 32-bit device, receive buffer included; 5008 B peak stack, measured on arm64; 31.4 kB of flash |
| Dependencies | C11 and libc. No `malloc` anywhere. |
| License | Apache-2.0 |

[`docs/performance.md`](docs/performance.md) has the figures for every
build, and `make lint-bench-numbers` checks the memory row against them.

## Who it is for

chapulin began as TLS for devices, and it now serves hosts too. One
protocol profile serves both, and it is small enough to state exactly,
so proofs and an executable specification check it, not tests alone
([Verification and testing](#verification-and-testing)).

**On a device.** No other permissively licensed C stack gives a device
TLS 1.3 in a few kilobytes, with no heap and with machine-checked proofs
([`docs/landscape.md`](docs/landscape.md), surveyed again on
2026-11-17):

- The small embedded TLS stacks are mostly commercial (SEGGER emSSL,
  SharkSSL) or GPLv3 with a paid license (wolfSSL). wolfSSL's tinytls13, of July
  2026, is a TLS 1.3 client profile of about 31 kB of flash, with an
  option for a static memory pool.
- BearSSL has no TLS 1.3. picotls and Mbed TLS need an allocator, and
  Mbed TLS uses 9 to 15 kB of RAM before its buffers.
- chapulin is TLS 1.3 with no heap, in a few kilobytes, under
  Apache-2.0, as a client, a server, or both.

**On a host.** A program on a server or a desktop gets the same proven
code, with fast paths for its CPU:

- TLS 1.3 and the TLS layer of QUIC versions 1 and 2, with web PKI,
  SPKI pins and session resumption.
- Post-quantum key exchange, X25519MLKEM768 and ML-KEM-1024, and a
  profile on CNSA 2.0's algorithms alone (`PROFILE=cnsa2`).
- Each primitive at about OpenSSL's speed
  ([Performance](#performance)). CI fails a change
  that makes a primitive run more instructions.

## Performance

Intel Xeon 6975P-C: chapulin is faster than OpenSSL 3.6.5 in 26 of 27 rows under gcc and 26 of 27 under clang.

The rows are the primitives TLS runs: hashes, key exchange, signatures,
ML-KEM and ML-DSA, and AES-GCM and ChaCha20-Poly1305 records. A bar is
OpenSSL's time over chapulin's, in one run on one machine, so a bar past
the dashed line at 1 is faster than OpenSSL.

![Bars of chapulin's speed in multiples of OpenSSL's on an x86-64 CPU with AVX-512 IFMA, under gcc and clang](docs/img/speed-vs-openssl-x86-64-avx512.svg)

<details>
<summary>AMD EPYC 7763: chapulin is faster than OpenSSL 3.6.5 in 25 of 27 rows under gcc and 25 of 27 under clang</summary>

![Bars of chapulin's speed in multiples of OpenSSL's on the AMD EPYC 7763, under gcc and clang](docs/img/speed-vs-openssl-x86-64.svg)

</details>

<details>
<summary>Apple M1 Pro: chapulin is faster than OpenSSL 3.6.5 in 24 of 27 rows under Apple clang</summary>

![Bars of chapulin's speed in multiples of OpenSSL's on the Apple M1 Pro, under Apple clang](docs/img/speed-vs-openssl-m1-pro.svg)

</details>

<details>
<summary>ARM Neoverse-N2: chapulin is faster than OpenSSL 3.6.5 in 16 of 27 rows under gcc and 17 of 27 under clang</summary>

![Bars of chapulin's speed in multiples of OpenSSL's on an Arm Neoverse N2, under gcc and clang](docs/img/speed-vs-openssl-arm64.svg)

</details>

[`docs/performance.md`](docs/performance.md#chapulin-beside-openssl)
holds the times, how each run was made, each run's machine and load, and
each row's speed at every run since 2026-10-08. `make lint-bench-numbers`
fails when a chart or a sentence above disagrees with the recorded CSVs.

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
#include <chapulin/tls.h>

static uint8_t rxbuf[2048];
static ch_tls tls;

int talk(void) {
    /* Headers that do not match the linked object write past its structs. */
    if (!ch_build_matches(&ch_build)) {
        return -1;
    }
    ch_cfg cfg = {
        .psk = psk, .psk_len = 32,
        .psk_id = (const uint8_t *)"device-42", .psk_id_len = 9,
        .buf = rxbuf, .buf_len = sizeof rxbuf,
        .send = my_send, .recv = my_recv, .io = &sock,
    };
    /* Any error ends the session and wipes its keys: reconnect later. */
    if (ch_connect(&tls, &cfg) != CH_OK ||
        ch_write(&tls, request, request_len) != CH_OK) {
        return -1;
    }
    int got = ch_read(&tls, reply, sizeof reply);  /* 0 when the peer closed */
    ch_close(&tls);
    return got;
}
```

`psk`, `my_send`, `my_recv`, `sock`, `request`, `request_len` and
`reply` are your program's. [`examples/psk_client.c`](examples/psk_client.c) is the whole
program.

The struct sizes depend on the defines the object was built with.
`bin/chapulin.h` holds those defines and the struct sizes, and includes
the public headers, so compile your program with it and pass no `-D`
flag of your own. The public headers sit in `include/chapulin/`:

```sh
cc -std=c11 -I path/to/chapulin/include -include path/to/chapulin/bin/chapulin.h \
    app.c path/to/chapulin/bin/chapulin.o -o app
```

A build that cannot take the header passes the flags that
`make print-lib-def` prints. Either way, call
`ch_build_matches(&ch_build)` (`build.h`) once at startup, as the
example above and every program in `examples/` do. It returns 0 when
your defines and the object's differ
([`docs/building.md`](docs/building.md)).

A Zig project (Zig 0.16.0) can depend on chapulin as a package. Its
module `chapulin` is a Zig API over the same object, as `chapulin.hpp` is
for C++. [`docs/zig.md`](docs/zig.md) is the API's reference, and
[`docs/building.md`](docs/building.md) shows how to add the dependency.

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
| `TRUST` | `raw-rsa`, `raw-ecdsa`, `ca-rsa`, `ca-ecdsa`, `raw-mldsa`, `ca-mldsa`, `webpki`, `none` | How a client checks the server; the two `mldsa` values build under `PROFILE=cnsa2` alone, and `none` is for a server role |
| `ROLE` | `client`, `server`, `both` | Which side of the handshake the object runs |
| `TRANSPORT` | `tcp-blocking`, `tcp-nonblocking`, `quic-nonblocking` | What TLS runs over, and whether chapulin or your code does the I/O |
| `KEX` | `x25519`, `pq` | The key exchange of a raw or ca client |
| `SUITE` | `chacha`, `aesgcm` | Adds the AES-GCM suites to a web PKI client or a server |
| `PROFILE` | `general`, `cnsa2` | `cnsa2` makes a raw or ca client on CNSA 2.0's algorithms alone: ML-KEM-1024, `TLS_AES_256_GCM_SHA384`, and an external PSK or, under `TRUST=raw-mldsa` and `TRUST=ca-mldsa`, an ML-DSA-87 server key, on `AES=extern` ([`docs/building.md`](docs/building.md)) |
| `AES` | `soft`, `extern` | A device object's AES, when its build uses AES: the table, for QUIC's public keys alone, or the `ch_aes_block` your image defines |
| `EXPORTER` | `off`, `on` | Adds `ch_export`, the TLS exporter |
| `KEYLOG` | `off`, `on` | Hands each traffic secret to a hook you define, for an NSS key log |
| `WIDEMUL` | `decomposed`, `native` | Whether a device object's wide multiplies use the CPU instruction, which you must know runs in constant time |

[`docs/building.md`](docs/building.md) lists the other variables:
`TX_RECORD` raises the record size a TCP host build sends, and
`DNSSEC`, `JWS` and `SCRAM` add calls for DNSSEC signatures, JSON Web
Signatures and SCRAM-SHA-256 to a host `TRUST=webpki` object.

On arm64 and x86-64, a web PKI client and the `ROLE=server` and
`ROLE=both` objects build a *host object*. A host object holds fast paths
beside the portable C: vector code, the 64-bit multiply, and the AES, SHA
and AVX-512 instructions. chapulin probes no CPU. Your program states what
its CPU has in `ch_cfg.cpu`, from the bits in `cpu_cfg.h`, and each
session picks its paths from that value. `cpu_cfg.h` states what each bit
picks. A host object takes neither `AES` nor `WIDEMUL`.

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
| ML-DSA-87 | `PROFILE=cnsa2` with `TRUST=raw-mldsa` or `TRUST=ca-mldsa` | The pinned-key or pinned-CA check, with ML-DSA-87 signatures and a 2592-byte key | A receive buffer of 7843 bytes (raw) or 15656 (ca), each mode's floor |
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
| `ch_p256_key_from_pem` | `ROLE=server`, `ROLE=both`, outside `PROFILE=cnsa2` | A P-256 key, PKCS #8 or SEC 1 | The scalar and the point of an ECDSA identity |
| `ch_rsa_key_from_pem` | `ROLE=server`, `ROLE=both`, outside `PROFILE=cnsa2` | An RSA key, PKCS #8 | The `ch_rsa_priv` of an RSA-PSS identity |
| `ch_mldsa_key_from_pem` | `ROLE=server` and `ROLE=both` host objects, and `PROFILE=cnsa2 ROLE=server` | An ML-DSA-87 key, PKCS #8 seed or both form | The secret and public keys of an ML-DSA-87 identity |
| `ch_anchors_from_pem` | `TRUST=webpki` | A CA bundle | The roots that `ch_cfg.anchors` takes |
| `ch_pubkey_from_pem` | `TRUST=ca-rsa`, `TRUST=ca-ecdsa`, `TRUST=ca-mldsa` | One CA certificate | The key that `ch_cfg.server_pubkey` takes |

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
- **Instruction counts.** CI counts the instructions of each primitive,
  each record stage and each handshake. It counts on QEMU for Cortex-M3,
  rv32imac and mips32r2, and under valgrind's callgrind for x86-64 and
  arm64. Each night it counts the AVX-512, VAES and SHA extension
  kernels under Intel SDE. A count above its recorded value fails the
  check ([`docs/decisions.md`](docs/decisions.md) 235).
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

On each pull request and each push to main, CI runs the lints, the tests,
the platform suites and the host instruction counts. A push to main also
runs the fast proofs, the fast mutation checks, the end-to-end handshakes,
the spec differential, the state machine test and the device instruction
counts. The nightly runs the slow proofs, every mutation check, the
differential on new seeds, the fuzz targets and the SDE instruction
counts.
[`docs/verification.md`](docs/verification.md) lists every harness, its
bound, and what rests on tests instead of proofs.
[`docs/proofs.md`](docs/proofs.md) explains how the harnesses are
written, and [`docs/invariants.md`](docs/invariants.md) lists the rules a
change must not break.

## Supported platforms

A platform is listed when CI runs the suites there on every push to main.
Each job in `.github/workflows/check.yml` names the make targets it runs.

| Platform | How the suites run | CI job |
| --- | --- | --- |
| Linux x86_64 | Natively: every lint, the fast proofs, the sanitizers and the end-to-end handshakes. The AVX2, VAES and SHA kernels on a runner that has them, and CPUs without them under QEMU. Each night, the AVX-512 kernels under Intel SDE, an emulator. | `check`, `slow`, `mutants`, `prove`, `san`, `coverage`, `x86-64-kernels`, `mips`; nightly `rsa-ifma-sde` |
| Linux arm64 | Natively under gcc and clang, with the AES, PMULL, SHA-256, SHA-512 and SHA-3 instructions, and a CPU without SHA-512 under QEMU | `arm64`, `mips` |
| macOS arm64 | Natively under Apple clang, with the AES, PMULL, SHA-256, SHA-512 and SHA-3 instructions | `macos` |
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
- It does not offer `TLS_AES_128_CCM_8_SHA256`, the suite that the TLS
  1.3 IoT profile
  ([draft-ietf-uta-tls13-iot-profile](https://datatracker.ietf.org/doc/html/draft-ietf-uta-tls13-iot-profile))
  makes mandatory. A peer that insists on AES-CCM will not connect.
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
