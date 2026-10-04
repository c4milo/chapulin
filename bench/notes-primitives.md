# Where the time goes: chapulin's primitives on arm64 and x86-64

This note reads the rows of `make bench-primitives` (bench/primitives.sh)
that docs/performance.md's table beside OpenSSL leaves out: the
handshakes, what the multiply bit changes, and the per-byte costs. That
table holds the comparison with OpenSSL, primitive by primitive. The two
files this note reads:

- bench/results-primitives-arm64.csv: every primitive, per byte or per
  operation, and whole handshakes between this tree's client and server,
  each under two `ch_cfg.cpu` values, with OpenSSL's rows beside them.
- bench/results-primitives-calls.csv: how many times each end of each
  handshake calls each primitive, counted with `-finstrument-functions`.

bench/record.sh times AES-GCM and one record's stages, and
docs/performance.md, "Where a record's time goes", reads its CSVs; this
note does not repeat them.

## Machine and method

- Apple M1 Pro (8 performance and 2 efficiency cores), macOS 26.6.2
  (Darwin 25.6.0), Apple clang 21.0.0, `-std=c11 -O2`, the packaged
  object's level. Tree 26fa782 with the change that added these rows.
- Every timed program is a host object, which holds each fast path
  beside the portable code (docs/decisions.md entry 89), and each row
  runs under two `ch_cfg.cpu` values:
  - `0x1`, `CH_CPU_PROBED` alone, is a caller that states nothing. Every
    operation built on the widening multiply runs ct.h's 16x16
    decomposition, and X25519 the 16-limb field. A device object runs
    the same code for those. ChaCha20 runs the NEON path, as every host
    session's does; a device object runs chacha20.c's portable loop,
    which bench/aead.sh times.
  - `0x7` is every bit this CPU has: `CH_CPU_CONSTANT_TIME_AES` and
    `CH_CPU_CONSTANT_TIME_MULTIPLY`. The multiply bit picks the native
    copies of poly1305.c, mlkem_poly.c, p256_field.c, p256_scalar.c and
    rsa_sign.c, the vector Poly1305, and x25519_wide.c's field. The AES
    bit changes no row of this file.
- Each row is the median over 5 runs of each run's median of 101
  samples. RSA signing and the RSA handshakes take 11 to 27 samples a
  run; the CSV's samples column says which. The method is in
  bench/primitives.c.
- The clock is the thread's CPU time, so the time the machine gave to
  other work is in no sample. OpenSSL's rows are `openssl speed`, which
  divides by its process's user CPU time.
- The program asks macOS for the user-interactive class, which it
  places on performance cores first.
- The instructions column holds what one operation retired, as macOS
  counts them for the process. Linux gives the program no such count, so
  the column is empty there.

## Load and variance

The committed run started at a 1-minute load average of 6.46 and ended
at 7.02, and each of its five runs started between 5.86 and 6.46.

The CPU clock kept the load out of the figures. Inside one run the
largest 25th-to-75th percentile spread is 9.4%, on the ECDSA handshake
under `0x1`, and outside the handshakes 6.4%. Between runs the largest
spread is 3.4%, on shake256_squeeze at 16 KB, and 1.5% among OpenSSL's
rows. The hashes, the DRBG and the verifiers run the same code under
both values, and their two rows differ by 0.7% at most, which is the
floor a difference between two rows of this file has to pass.

The clock cannot keep out a run that macOS places on efficiency cores,
which take about three times as long for the same code. No row of this
run shows one: such a run moves a row's spread between runs past 100%,
and bench/primitives.sh warns of a row that moved by more than half.

`bench/primitives.sh --quick` numbers are not measurements. Its three
0.1 ms samples once read `p256_ecdsa_verify` at 3.06 ms, against 1.25 ms
in a full run.

## Handshakes, measured

One sample is one handshake, both ends in one process
(bench/primitives_handshake.c, the pairing
test/tcp_nonblocking_loop_test.c drives), from two fresh sessions to
both ends connected. Both ends state the same `ch_cfg.cpu` value. Client
side and server side are the time spent inside each end's calls. The
hybrid rows add `-DCH_KEX_PQ`: the client offers X25519MLKEM768 alone and
the server selects it. Milliseconds:

| handshake | `ch_cfg.cpu` | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | 0x1 | 61.8 | 2.36 | 59.4 |
| pinned RSA-2048 | 0x7 | 37.9 | 0.39 | 37.5 |
| pinned RSA-3072 | 0x1 | 201.5 | 2.72 | 198.8 |
| pinned RSA-3072 | 0x7 | 147.1 | 0.77 | 146.3 |
| pinned ECDSA P-256 | 0x1 | 6.52 | 3.30 | 3.22 |
| pinned ECDSA P-256 | 0x7 | 2.19 | 1.40 | 0.78 |
| pinned RSA-2048, hybrid | 0x1 | 61.9 | 2.30 | 59.6 |
| pinned RSA-2048, hybrid | 0x7 | 38.0 | 0.50 | 37.5 |
| pinned RSA-3072, hybrid | 0x1 | 202.0 | 2.69 | 199.3 |
| pinned RSA-3072, hybrid | 0x7 | 147.5 | 0.89 | 146.6 |
| pinned ECDSA P-256, hybrid | 0x1 | 6.57 | 3.31 | 3.26 |
| pinned ECDSA P-256, hybrid | 0x7 | 2.34 | 1.51 | 0.82 |

The pairing gives the server no ticket key, so it times no resumed
handshake.

## Where a handshake's time goes

The call counts are measured, and identical under clang on macOS and gcc
13 on arm64 and x86-64 Linux. In every pinned handshake each end calls
x25519_base once and x25519 once. The client calls the verifier once
and HKDF-Expand-Label 18 times. The server calls the signer once and
HKDF-Expand-Label 17 times.

Each share below is a sum: the call count times that primitive's
per-operation median, as a percent of the measured side. The rest is the
measured side minus those sums. It holds the transcript hashing, the
Finished MACs, the record protection of the handshake flight and the
parsing.

| side | `ch_cfg.cpu` | x25519 pair | verify or sign | HKDF-Expand-Label | rest |
|---|---|---:|---:|---:|---:|
| RSA-3072 client | 0x1 | 68% | 24% | 1.0% | 7.1% |
| RSA-3072 client | 0x7 | 8.9% | 84% | 3.5% | 3.2% |
| ECDSA client | 0x1 | 56% | 39% | 0.8% | 3.9% |
| ECDSA client | 0x7 | 4.9% | 92% | 2.0% | 0.8% |
| RSA-3072 server | 0x1 | 0.9% | 99% | 0.0% | 0.5% |
| RSA-3072 server | 0x7 | 0.0% | 101% | 0.0% | -1.2% |
| ECDSA server | 0x1 | 58% | 41% | 0.8% | 0.8% |
| ECDSA server | 0x7 | 8.7% | 85% | 3.3% | 2.6% |

The rest runs from -1.2% to +7.1% of a side. So the public-key
operations account for nearly all of the time, and under `0x7` the
verifier or the signer alone is 84% or more of every side: the multiply
bit takes the x25519 pair from 1,856 us to 69 us and leaves the
verifiers as they are.

What the hybrid adds shows under `0x7`, on the sides short enough to
resolve it. The client adds two ML-KEM-768 key generations and one
decapsulation: handshake_flight.c calls mlkem_keygen_dk once to build
the ClientHello and once before it decapsulates, and
bench/results-primitives-calls.csv measures that count. Its side grows
by 105 to 115 us on the three handshakes, where those three rows sum to
82 us. The server adds one encapsulation, and the ECDSA server's side
grows by 40 us, against that row's 28 us. The rest of each difference is
the larger hello and ServerHello to write, hash and parse. An RSA
server's side takes 37 ms or more, and under `0x1` a client's takes
2.3 ms or more, so there the difference is below the side's spread.

A resumed PSK handshake (psk_dhe_ke) skips the verifier and keeps the
x25519 pair and the key schedule. The RSA-3072 client side minus the
verify row is 2.08 ms under `0x1` and 0.12 ms under `0x7`.

## Ranking: once-per-handshake costs

Microseconds per operation under each value, then OpenSSL 3.6.5's
`openssl speed` row for the same operation on the same machine, where it
has one. The last column says who calls it and how often.

| primitive | 0x1 | 0x7 | OpenSSL | called by |
|---|---:|---:|---:|---|
| rsa_pss_sign_3072 | 195,963 | 148,046 | | server, once, RSA-3072 identity |
| rsa_pss_sign_2048 | 57,396 | 37,221 | | server, once, RSA-2048 identity |
| p384_ecdsa_verify | 4,173 | 4,191 | 318 | client, per P-384 signature, TRUST=webpki |
| p256_ecdsa_verify | 1,290 | 1,297 | 55.9 | client, once, TRUST=raw-ecdsa; per link, webpki |
| p256_sign | 1,310 | 669 | 18.4 | server, once, ECDSA identity |
| p256_ecdh | 1,205 | 612 | 41.9 | both ends, once each, when secp256r1 runs (docs/decisions.md 63) |
| p256_ecdh_keygen | 1,205 | 610 | 9.8 | both ends, once each, when secp256r1 runs |
| rsa_pss_verify_4096 | 1,210 | 1,213 | | client, TRUST=webpki |
| rsa_pkcs1_verify_4096 | 1,203 | 1,211 | | client, per RSA-4096 link, webpki |
| x25519, x25519_base | 928, 928 | 34.3, 34.2 | 31.2, 31.7 | both ends, once each |
| rsa_pss_verify_3072 | 648 | 650 | | client, once, TRUST=raw-rsa default |
| rsa_pkcs1_verify_3072 | 648 | 649 | 31.2 | client, per link, webpki |
| rsa_pss_verify_2048 | 272 | 272 | | client, once |
| rsa_pkcs1_verify_2048 | 271 | 271 | 14.8 | client, per link, webpki |
| mlkem768_decaps | 31.8 | 30.2 | 37.8 | client, once, when the hybrid runs |
| mlkem768_encaps | 29.1 | 28.1 | 24.2 | server, once, when it selects the hybrid |
| mlkem768_keygen | 25.8 | 25.9 | 36.6 | client, twice, when the hybrid runs |
| hkdf_expand_label | 1.52 | 1.52 | | client 18, server 17 |

`openssl speed` signs RSA with PKCS#1 v1.5 padding, which chapulin does
not sign, so the two signing rows have no OpenSSL figure here: it signs
RSA-2048 in 565 us and RSA-3072 in 1,653 us that way. rsa_sign.h states
that chapulin signs without the CRT, which it puts at about four times
the cost of a CRT signature.

For a client under `0x1`, the x25519 pair is the largest cost in both
pinned modes and the verifier is second. Under `0x7` the pair takes
69 us, under a tenth of either client side, and the verifier is the
largest cost of every client. For a server with an RSA identity,
rsa_pss_sign is its whole side, to within the spread, under either
value.

## Ranking: per-byte costs

Nanoseconds per byte at 16 KB, then 64 B (32 B for the DRBG, whose
common draw is 32 bytes), under `0x1`; then under `0x7` where the bit
changes the row.

| primitive | 16 KB | 64 B | `0x7`, 16 KB | where a connection runs it |
|---|---:|---:|---:|---|
| hmac_sha256 | 4.85 | 27.9 | | key schedule, Finished; short inputs |
| sha256 | 4.79 | 11.7 | | transcript, inside HMAC and HKDF |
| sha3_256 | 3.91 | 6.53 | | inside ML-KEM |
| sha384, sha512 | 3.20, 3.19 | 9.14, 9.69 | | certificate signatures, webpki; the SHA-384 suite |
| chacha20_poly1305_seal | 2.53 | 9.27 | 0.68 | every sent record |
| chacha20_poly1305_open | 2.54 | 8.92 | 0.68 | every received record |
| shake256_squeeze | 2.37 | 5.41 | | inside ML-KEM |
| poly1305 | 2.02 | 2.45 | 0.17 | the hash half of the AEAD |
| shake128_squeeze | 2.02 | 5.40 | | inside ML-KEM |
| drbg | 1.58 | 3.74 | | every ch_rand_bytes call |
| chacha20 | 0.50 | 3.86 | | the cipher half of the AEAD |

A 1,200-byte record costs 3.40 us to seal under `0x1` and 1.21 us under
`0x7`. Record protection costs as much as the RSA-3072 client handshake
after about 1,076 KB sealed or opened under `0x1` and 1,141 KB under
`0x7`, and as much as the ECDSA client handshake after about 1,305 KB
and 2,077 KB. A connection that moves less than that spends most of its
crypto time in the handshake.

Under `0x1` Poly1305 is the slower half of the AEAD by a factor of four,
2.02 ns against the vector ChaCha20's 0.50. The multiply bit takes it to
0.17, and ChaCha20 becomes three quarters of the seal.

## What the multiply bit changes

Time under `0x1` over time under `0x7`, from the rows above:

| row | ratio |
|---|---:|
| x25519, x25519_base | 27.1 |
| poly1305, 16 KB | 12.1 |
| chacha20_poly1305_seal, 16 KB | 3.74 |
| p256_ecdh, p256_ecdh_keygen | 1.97 |
| p256_sign | 1.96 |
| rsa_pss_sign_2048 | 1.54 |
| rsa_pss_sign_3072 | 1.32 |
| mlkem768 keygen, encaps, decaps | 1.00 to 1.05 |
| ECDSA handshake, server side | 4.10 |
| RSA-3072 handshake, client side | 3.53 |
| ECDSA handshake, client side | 2.35 |
| RSA-3072 handshake, server side | 1.36 |

Three counts account for most of X25519's 27.1. A field multiply runs 25
products of 64 by 64 bits where the 16-limb field runs 256 of 32 by 32,
each built from 16x16 pieces; a squaring runs 15 where the 16-limb field
runs a whole multiply; and the inversion's fixed chain runs 11
multiplies where the 16-limb field's square-and-multiply runs 252. A
device cannot build the wide field, so the device rows in
docs/performance.md and bench/results-insn*.csv keep the 16-limb one.

ML-KEM barely moves: the multiply sits in its compression and its
message decoding alone, and its key generation runs neither.

The instructions column gives the same picture without a clock. One
operation retires, under `0x1` and then under `0x7`:

| row | `0x1` | `0x7` |
|---|---:|---:|
| x25519 | 12,732,157 | 372,816 |
| p256_sign | 16,326,935 | 5,518,659 |
| p256_ecdh | 15,107,732 | 5,038,964 |
| rsa_pss_sign_2048 | 754,601,745 | 350,920,892 |
| rsa_pss_sign_3072 | 2,528,135,677 | 1,167,368,366 |
| mlkem768_encaps | 439,926 | 422,133 |
| poly1305, per byte at 16 KB | 20.86 | 2.03 |
| pinned ECDSA P-256 handshake, both ends | 77,504,973 | 17,232,011 |

The two counts under `0x7` that docs/performance.md, "Where a server
handshake's instructions go", also holds agree with it: 0.37 M for one
X25519 scalar multiplication on the wide field against its 0.39 M, and
5.52 M for one P-256 signature against its 5.51 M, there on a
Neoverse-N2 build under QEMU.

## Instruction families that could speed each primitive

These are options to measure, not promised gains. The limb widths are
what the code uses today. This M1 Pro reports FEAT_SHA256, FEAT_SHA512
and FEAT_SHA3 (`sysctl hw.optional.arm`).

| primitive | arm64 | x86-64 |
|---|---|---|
| x25519 (16-bit limbs in int64 words; 51-bit limbs under the multiply bit) | the wide field runs the native 64x64 multiply with UMULH over 51-bit limbs; NEON for two field products at once is still open | the wide field runs MUL; MULX (BMI2) with ADCX and ADOX (ADX), and AVX2 for several field products at once, are still open |
| RSA verify and sign, P-256 and P-384 (32-bit limbs) | UMULH over 64-bit limbs; NEON UMULL and UMLAL for 32x32 products in lanes | MULX, ADCX and ADOX over 64-bit limbs; AVX2 VPMULUDQ; AVX-512 IFMA (VPMADD52LUQ, VPMADD52HUQ) |
| Poly1305 | under the multiply bit it runs four blocks at a time in NEON lanes (docs/decisions.md 83) | under the multiply bit it runs four blocks at a time in SSE2 lanes; an AVX2 Poly1305 is open (docs/decisions.md 90) |
| ChaCha20 | every host session runs NEON, eight blocks a pass (docs/decisions.md 86) | SSE2, four blocks a pass, and under `CH_CPU_AVX2` eight (docs/decisions.md 90); AVX-512, sixteen, is open |
| the DRBG, over chacha20_block | NEON for several blocks of a long draw | AVX2 for the same |
| SHA-256, HMAC, HKDF | the ARMv8 SHA-256 instructions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1) | SHA-NI (SHA256RNDS2, SHA256MSG1, SHA256MSG2) |
| SHA-384, SHA-512 | the ARMv8.2 SHA-512 instructions (SHA512H, SHA512H2, SHA512SU0, SHA512SU1) | AVX2 for the message schedule; the SHA512 extension (VSHA512RNDS2) only on the newest parts |
| SHA3-256, SHAKE128, SHAKE256 | the ARMv8.2 SHA-3 instructions (EOR3, RAX1, XAR, BCAX); NEON for two Keccak states at once | AVX2 for four Keccak states at once, which suits ML-KEM's independent SHAKE streams; no Keccak instruction |
| ML-KEM-768 NTT and polynomial arithmetic | NEON, eight 16-bit lanes (SQDMULH, SQRDMULH for the reductions) | AVX2, sixteen 16-bit lanes (VPMULHW, VPMULLW) |
| AES-GCM | under the AES bit, the AES instructions and PMULL (bench/record.sh) | under the AES bit, AES-NI and PCLMULQDQ, and under `CH_CPU_VAES` the 256-bit forms (docs/decisions.md 90) |

## What these numbers do not show

- How ML-KEM's time splits between Keccak and the NTT. The SHAKE rows
  give Keccak's speed per byte, not how many bytes ML-KEM squeezes.
- A TRUST=webpki handshake. Its chain verify runs one verifier row per
  link, but no chain was timed here.
- Which half of a difference between the arm64 and x86-64 runs is the
  compiler and which is the CPU. The arm64 run used clang and the
  x86-64 run uses gcc, so no row separates the two.
- Whether the multiply runs in constant time here. `0x7` states that it
  does, and nothing in the bench sets PSTATE.DIT, so those rows time the
  native multiply in whatever mode macOS runs the program in. `make
  timing`'s t-test is the evidence this tree has, and cpu_cfg.h says
  what a caller states with the bit.
- OpenSSL's instruction counts. `openssl speed` prints none, so the
  instructions column holds chapulin's rows alone.

## Earlier runs

Other documents cite figures this note held before these rows existed.
The run at tree 0ae2dbe, on this machine on 2026-09-24, built a device
object's sources three ways and timed them on the wall clock at a load
average of 12 to 24:

- over the 16x16 decomposition, x25519 took 953 us, p256_ecdh 1,228 us,
  and the RSA-3072 client side 2.57 ms, of which the x25519 pair was
  74%;
- with `CH_NATIVE_WIDEMUL`, the 16-limb x25519 took 428 us on the native
  multiply, which no object runs now;
- as the `X25519=wide` build, the wide field took 34.3 us and the
  RSA-3072 client side 0.77 ms.

docs/decisions.md entries 52 and 63 and srv_kex.h cite those. The rows
above run the same sources under `0x1` and `0x7` and agree with them to
within 3%, except the client side under `0x1`, which this run puts at
2.72 ms.

## x86-64

bench.yml's `record-x86_64` job writes
bench/results-primitives-x86_64.csv on a GitHub-hosted runner, under gcc,
with the same rows as the arm64 file. No run of these rows is recorded
yet. The file this note read before was a run of the device object's
builds at tree 4e02293, on an AMD EPYC 9V74 on 2026-09-24, and it is in
the history at that tree.
