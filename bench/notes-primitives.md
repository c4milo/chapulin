# Where the time goes: chapulin's primitives on arm64 and x86-64

This note reads the rows of `make bench-primitives` (bench/primitives.sh)
that docs/performance.md's table beside OpenSSL leaves out: the
handshakes, what the wider value changes, and the per-byte costs. That
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
  object's level. Tree 1f4a922, one run, on 2026-10-05.
- Every timed program is a host object, which holds each fast path
  beside the portable code (docs/decisions.md entry 89), and each row
  runs under two `ch_cfg.cpu` values:
  - `0x1`, `CH_CPU_PROBED` alone, is a caller that states nothing. Every
    operation built on the widening multiply runs ct.h's 16x16
    decomposition, X25519 the 16-limb field, RSA signing the ladder of
    rsa_sign.c, and the hashes portable C. A device object runs the same
    code for those. Two things a device object does not run, a host
    session runs whatever it states: ChaCha20 on the NEON path, where a
    device object runs chacha20.c's portable loop, which bench/aead.sh
    times, and RSA's public operation on rsa_mont64.c's 64-bit limbs,
    where a device object runs rsa_mont.c's 32-bit limbs
    (docs/decisions.md 95).
  - `0x67` is every bit this CPU has that an object reads:
    `CH_CPU_CONSTANT_TIME_AES`, `CH_CPU_CONSTANT_TIME_MULTIPLY`,
    `CH_CPU_CONSTANT_TIME_SHA256` and `CH_CPU_CONSTANT_TIME_SHA512`. The
    multiply bit picks the native copies of poly1305.c and mlkem_poly.c,
    the vector Poly1305, x25519_wide.c's field, for P-256's key exchange
    and signing the wide files and their table of multiples of G
    (docs/decisions.md 94), and for RSA signing rsa_sign64.c, which
    signs by the Chinese remainder theorem and checks each signature
    (docs/decisions.md 95). The two hash bits run SHA-256, SHA-384 and
    SHA-512 on the CPU's instructions, and HMAC, HKDF and a handshake's
    key schedule and transcript over them (docs/decisions.md 93). The
    AES bit changes no row of this file. The CPU has the SHA-3
    instructions too, and `CH_CPU_CONSTANT_TIME_SHA3` picks nothing yet,
    so the value leaves it out.
- Each row is the median over 5 runs of each run's median of 101
  samples. Under `0x1` RSA signing and the RSA handshakes take 11 to 19
  samples a run; the CSV's samples column says which. The method is in
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

The run started at a 1-minute load average of 4.53 and ended at 4.51,
and its five runs started at 4.53, 2.68, 2.69, 2.53 and 2.83.

The CPU clock kept that load out of most figures. Inside one run the
largest 25th-to-75th percentile spread is 10.0%, on p256_ecdsa_verify
under `0x67`, and 4.2% among the handshakes. Between runs the largest
spread is 6.8%, on the same row, 4.9% among the handshakes and 2.5%
among OpenSSL's rows. SHA-3 and the SHAKEs, the DRBG, ChaCha20, the
verifiers and ML-KEM's key generation run the same code under both
values, and their two rows differ by 0.23% at most, which is the floor a
difference between two rows of this run has to pass.

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
| pinned RSA-2048 | 0x1 | 57.8 | 1.84 | 56.0 |
| pinned RSA-2048 | 0x67 | 1.17 | 0.11 | 1.05 |
| pinned RSA-3072 | 0x1 | 189.5 | 1.89 | 187.6 |
| pinned RSA-3072 | 0x67 | 3.38 | 0.16 | 3.22 |
| pinned ECDSA P-256 | 0x1 | 6.07 | 3.02 | 3.03 |
| pinned ECDSA P-256 | 0x67 | 1.41 | 1.29 | 0.12 |
| pinned RSA-2048, hybrid | 0x1 | 58.2 | 2.05 | 56.1 |
| pinned RSA-2048, hybrid | 0x67 | 1.30 | 0.20 | 1.09 |
| pinned RSA-3072, hybrid | 0x1 | 189.0 | 2.13 | 186.9 |
| pinned RSA-3072, hybrid | 0x67 | 3.51 | 0.25 | 3.25 |
| pinned ECDSA P-256, hybrid | 0x1 | 6.25 | 3.14 | 3.08 |
| pinned ECDSA P-256, hybrid | 0x67 | 1.55 | 1.40 | 0.15 |

Before docs/decisions.md 95 an RSA server's side took 37.5 ms and
146.3 ms under the multiply bit, on the native copy of the ladder, and
an RSA-3072 client's 0.77 ms, with its verifier on 32-bit limbs.

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
| RSA-3072 client | 0x1 | 93% | 4.8% | 1.4% | 1.0% |
| RSA-3072 client | 0x67 | 40% | 55% | 2.3% | 2.9% |
| ECDSA client | 0x1 | 58% | 40% | 0.9% | 0.9% |
| ECDSA client | 0x67 | 5.0% | 94% | 0.3% | 0.6% |
| RSA-3072 server | 0x1 | 0.9% | 99% | 0.0% | -0.1% |
| RSA-3072 server | 0x67 | 2.0% | 98% | 0.1% | -0.4% |
| ECDSA server | 0x1 | 58% | 41% | 0.8% | 0.7% |
| ECDSA server | 0x67 | 53% | 39% | 2.9% | 4.8% |

The rest runs from -0.4% to +4.8% of a side. So the public-key
operations account for nearly all of the time. Under `0x1` the x25519
pair is the largest part of every side but the RSA server's: an RSA
verifier runs on 64-bit limbs under both values (docs/decisions.md 95),
and takes 4.8% of an RSA-3072 client's side. Under `0x67` the pair
falls from 1,752 us to 64 us, and the verifier or the signer is the
largest part of every side but one. The one is the ECDSA server's side,
121 us. Its signer runs the wide P-256 files (docs/decisions.md 94) and
takes 48 us, the pair takes 64 us, and the 17 HKDF-Expand-Label calls
take 3.5 us on the SHA-256 instructions (docs/decisions.md 93).

What the hybrid adds shows under `0x67`. The client adds two ML-KEM-768
key generations and one decapsulation: handshake_flight.c calls
mlkem_keygen_dk once to build the ClientHello and once before it
decapsulates, and bench/results-primitives-calls.csv measures that
count. Its side grows by 90 to 105 us on the three handshakes, where
those three rows sum to 77 us. The server adds one encapsulation, and
the ECDSA server's side grows by 32 us, against that row's 26 us. The
rest of each difference is the larger hello and ServerHello to write,
hash and parse. An RSA server's side takes 1.05 ms or more under `0x67`
and 56 ms or more under `0x1`, so there the difference is near or below
the side's spread.

A resumed PSK handshake (psk_dhe_ke) skips the verifier and keeps the
x25519 pair and the key schedule. The RSA-3072 client side minus the
verify row is 1.80 ms under `0x1` and 0.073 ms under `0x67`.

## Ranking: once-per-handshake costs

Microseconds per operation under each value, then OpenSSL 3.6.5's
`openssl speed` row for the same operation on the same machine, where it
has one. The last column says who calls it and how often.

| primitive | 0x1 | 0x67 | OpenSSL | called by |
|---|---:|---:|---:|---|
| rsa_pss_sign_3072 | 185,939 | 3,163 | | server, once, RSA-3072 identity |
| rsa_pss_sign_2048 | 54,209 | 991 | | server, once, RSA-2048 identity |
| p384_ecdsa_verify | 3,937 | 3,935 | 302 | client, per P-384 signature, TRUST=webpki |
| p256_ecdsa_verify | 1,214 | 1,215 | 53.1 | client, once, TRUST=raw-ecdsa; per link, webpki |
| p256_sign | 1,236 | 47.8 | 17.3 | server, once, ECDSA identity |
| p256_ecdh | 1,135 | 77.0 | 39.7 | both ends, once each, when secp256r1 runs (docs/decisions.md 63) |
| p256_ecdh_keygen | 1,134 | 18.4 | 9.19 | both ends, once each, when secp256r1 runs |
| x25519, x25519_base | 875, 876 | 32.1, 32.1 | 29.5, 30.0 | both ends, once each |
| rsa_pss_verify_4096 | 154 | 154 | | client, TRUST=webpki |
| rsa_pkcs1_verify_4096 | 147 | 147 | | client, per RSA-4096 link, webpki |
| rsa_pss_verify_3072 | 89.9 | 89.8 | | client, once, TRUST=raw-rsa default |
| rsa_pkcs1_verify_3072 | 84.7 | 84.7 | 29.5 | client, per link, webpki |
| rsa_pss_verify_2048 | 40.3 | 40.2 | | client, once |
| rsa_pkcs1_verify_2048 | 36.6 | 36.7 | 13.9 | client, per link, webpki |
| mlkem768_decaps | 29.9 | 28.5 | 35.9 | client, once, when the hybrid runs |
| mlkem768_encaps | 27.4 | 26.4 | 22.8 | server, once, when it selects the hybrid |
| mlkem768_keygen | 24.4 | 24.4 | 34.6 | client, twice, when the hybrid runs |
| hkdf_expand_label | 1.44 | 0.21 | | client 18, server 17 |

`openssl speed` signs RSA with PKCS#1 v1.5 padding, which chapulin does
not sign, so the two signing rows have no OpenSSL figure here: it signs
RSA-2048 in 537 us and RSA-3072 in 1,568 us that way. Under `0x67`
chapulin signs by the Chinese remainder theorem on 64-bit limbs and
checks each signature with the public exponent before it returns it
(docs/decisions.md 95). Under `0x1` it runs rsa_sign.c's ladder on the
decomposition, with no CRT.

For a client under `0x1`, the x25519 pair is the largest cost in both
pinned modes. Under `0x67` the pair takes 64 us, and the verifier is
the largest cost of every client: 55% of an RSA-3072 client's side and
94% of an ECDSA client's. For a server with an RSA identity,
rsa_pss_sign is its whole side, to within the spread, under either
value. For a server with an ECDSA identity under `0x67`, the pair is the
largest cost and the signer, 48 us, the second.

## Ranking: per-byte costs

Nanoseconds per byte at 16 KB, then 64 B (32 B for the DRBG, whose
common draw is 32 bytes), under `0x1`; then under `0x67` where a bit
changes the row.

| primitive | 16 KB | 64 B | `0x67`, 16 KB | where a connection runs it |
|---|---:|---:|---:|---|
| hmac_sha256 | 4.58 | 26.3 | 0.41 | key schedule, Finished; short inputs |
| sha256 | 4.52 | 11.1 | 0.41 | transcript, inside HMAC and HKDF |
| sha3_256 | 3.69 | 6.16 | | inside ML-KEM |
| sha384, sha512 | 3.02, 3.02 | 8.63, 9.15 | 0.70, 0.70 | certificate signatures, webpki; the SHA-384 suite |
| chacha20_poly1305_seal | 2.39 | 8.75 | 0.64 | every sent record |
| chacha20_poly1305_open | 2.39 | 8.41 | 0.63 | every received record |
| shake256_squeeze | 2.22 | 5.10 | | inside ML-KEM |
| poly1305 | 1.91 | 2.32 | 0.16 | the hash half of the AEAD |
| shake128_squeeze | 1.90 | 5.09 | | inside ML-KEM |
| drbg | 1.49 | 3.53 | | every ch_rand_bytes call |
| chacha20 | 0.47 | 3.65 | | the cipher half of the AEAD |

A 1,200-byte record costs 3.21 us to seal under `0x1` and 1.13 us under
`0x67`. Record protection costs as much as the RSA-3072 client handshake
after about 789 KB sealed or opened under `0x1` and 255 KB under `0x67`,
and as much as the ECDSA client handshake after about 1,263 KB and
2,030 KB. A connection that moves less than that spends most of its
crypto time in the handshake.

Under `0x1` Poly1305 is the slower half of the AEAD by a factor of four,
1.91 ns against the vector ChaCha20's 0.47. The multiply bit takes it to
0.16, and ChaCha20 becomes three quarters of the seal.

The hash bits take SHA-256 from 4.52 ns a byte to 0.41, and SHA-384 and
SHA-512 from 3.02 to 0.70. No bit changes SHA3-256 and the SHAKEs, so
under `0x67` Keccak is the slowest hashing a connection runs, at 1.90 to
3.69 ns a byte.

## What the wider value changes

Time under `0x1` over time under `0x67`, from the rows above:

| row | ratio |
|---|---:|
| p256_ecdh_keygen | 61.7 |
| rsa_pss_sign_3072, rsa_pss_sign_2048 | 58.8, 54.7 |
| x25519, x25519_base | 27.2, 27.3 |
| p256_sign | 25.9 |
| p256_ecdh | 14.7 |
| poly1305, 16 KB | 12.2 |
| sha256, hmac_sha256, 16 KB | 11.1, 11.0 |
| hkdf_expand_label | 6.97 |
| sha384, sha512, 16 KB | 4.30, 4.29 |
| chacha20_poly1305_seal, 16 KB | 3.76 |
| mlkem768 keygen, encaps, decaps | 1.00 to 1.05 |
| RSA-3072 handshake, server side | 58.3 |
| ECDSA handshake, server side | 25.0 |
| RSA-3072 handshake, client side | 11.6 |
| ECDSA handshake, client side | 2.34 |

The three P-256 rows are docs/decisions.md 94's. Under the bit the field
has four 64-bit limbs where the 32-bit files have eight limbs. A key
generation and a signature add 64 entries of a table of multiples of G
where the ladder runs 512 additions, and a key exchange runs 253
doublings and 71 additions in the ladder's place. The native copies of
the 32-bit files, which the bit picked before that entry, gave 1.97 and
1.96.

The two RSA signing rows are docs/decisions.md 95's. Under the bit a
signature is two exponentiations on 64-bit limbs, one modulo each prime,
each over half the modulus with half the exponent, read four bits at a
time, and then one public operation that checks the signature. Under
`0x1` it is one ladder over the whole modulus on the 16x16
decomposition. The native copy of that ladder, which the bit picked
before that entry, gave 1.54 and 1.32.

The hash rows are docs/decisions.md 93's: under their bits SHA-256,
SHA-384 and SHA-512 run on the CPU's instructions, and HMAC and
HKDF-Expand-Label over them.

Three counts account for most of X25519's 27.2. A field multiply runs 25
products of 64 by 64 bits where the 16-limb field runs 256 of 32 by 32,
each built from 16x16 pieces; a squaring runs 15 where the 16-limb field
runs a whole multiply; and the inversion's fixed chain runs 11
multiplies where the 16-limb field's square-and-multiply runs 252. A
device cannot build the wide field, so the device rows in
docs/performance.md and bench/results-insn*.csv keep the 16-limb one.

ML-KEM barely moves: the multiply sits in its compression and its
message decoding alone, and its key generation runs neither.

The instructions column gives the same picture without a clock. One
operation retires, under `0x1` and then under `0x67`:

| row | `0x1` | `0x67` |
|---|---:|---:|
| x25519 | 12,722,206 | 372,475 |
| p256_sign | 16,315,238 | 533,629 |
| p256_ecdh | 15,089,504 | 917,786 |
| p256_ecdh_keygen | 15,083,216 | 232,672 |
| rsa_pss_sign_2048 | 753,974,968 | 16,901,843 |
| rsa_pss_sign_3072 | 2,526,585,020 | 53,051,387 |
| mlkem768_encaps | 439,719 | 421,824 |
| hkdf_expand_label | 14,764 | 2,090 |
| poly1305, per byte at 16 KB | 20.84 | 2.03 |
| sha256, per byte at 16 KB | 49.44 | 1.64 |
| sha384, per byte at 16 KB | 31.91 | 4.29 |
| pinned ECDSA P-256 handshake, both ends | 77,425,395 | 11,575,179 |
| pinned RSA-3072 handshake, both ends | 2,579,736,522 | 56,064,388 |

The two counts under `0x67` that docs/performance.md, "Where a server
handshake's instructions go", also holds agree with it: 0.37 M for one
X25519 scalar multiplication on the wide field against its 0.39 M, there
on a Neoverse-N2 build under QEMU, and 0.53 M for one P-256 signature
against the 0.53 M its plan states for this machine. That section's
5.51 M for a signature is the 32-bit files on the native multiply, which
an earlier run of this note put at 5.52 M and which no object holds now.
On them the key exchange retired 5.04 M and the ECDSA handshake 17.23 M.

## Instruction families that could speed each primitive

These are options to measure, not promised gains. The limb widths are
what the code uses today. This M1 Pro reports FEAT_SHA256, FEAT_SHA512
and FEAT_SHA3 (`sysctl hw.optional.arm`).

| primitive | arm64 | x86-64 |
|---|---|---|
| x25519 (16-bit limbs in int64 words; 51-bit limbs under the multiply bit) | the wide field runs the native 64x64 multiply with UMULH over 51-bit limbs; NEON for two field products at once is still open | the wide field runs MUL; MULX (BMI2) with ADCX and ADOX (ADX), and AVX2 for several field products at once, are still open |
| the P-256 and P-384 verifiers (32-bit limbs) | UMULH over 64-bit limbs; NEON UMULL and UMLAL for 32x32 products in lanes | MULX, ADCX and ADOX over 64-bit limbs; AVX2 VPMULUDQ; AVX-512 IFMA (VPMADD52LUQ, VPMADD52HUQ) |
| RSA verify and sign (64-bit limbs in a host object, and the CRT for a signature under the multiply bit; 32-bit limbs in a device object) | rsa_mont64.c runs MUL and UMULH (docs/decisions.md 95); NEON UMULL and UMLAL for products in lanes are still open | rsa_mont64.c runs the 64x64->128 multiply; MULX with ADCX and ADOX, and AVX-512 IFMA (VPMADD52LUQ, VPMADD52HUQ), are still open |
| P-256 key exchange and signing (32-bit limbs; four 64-bit limbs under the multiply bit) | the wide files run MUL and UMULH, and clang makes add-with-carry chains of their carries (docs/decisions.md 94) | the wide files run the 64x64->128 multiply, and their carries are ADC and SBB: gcc makes them of two intrinsics and clang of the overflow builtins (docs/decisions.md 94). MULX with ADCX and ADOX is still open |
| Poly1305 | under the multiply bit it runs four blocks at a time in NEON lanes (docs/decisions.md 83) | under the multiply bit it runs four blocks at a time in SSE2 lanes; an AVX2 Poly1305 is open (docs/decisions.md 90) |
| ChaCha20 | every host session runs NEON, eight blocks a pass (docs/decisions.md 86) | SSE2, four blocks a pass, and under `CH_CPU_AVX2` eight (docs/decisions.md 90); AVX-512, sixteen, is open |
| the DRBG, over chacha20_block | NEON for several blocks of a long draw | AVX2 for the same |
| SHA-256, HMAC, HKDF | under the SHA-256 bit, the ARMv8 SHA-256 instructions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1) (docs/decisions.md 93) | under the SHA-256 bit, the SHA extensions (SHA256RNDS2, SHA256MSG1, SHA256MSG2) |
| SHA-384, SHA-512 | under the SHA-512 bit, the ARMv8.2 SHA-512 instructions (SHA512H, SHA512H2, SHA512SU0, SHA512SU1) (docs/decisions.md 93) | portable C; AVX2 for the message schedule is open, and the SHA512 extension (VSHA512RNDS2) is only on the newest parts |
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
- Whether the multiply and the hash instructions run in constant time
  here. `0x67` states that they do, and nothing in the bench sets
  PSTATE.DIT, so those rows time them in whatever mode macOS runs the
  program in. `make timing`'s t-test is the evidence this tree has, and
  cpu_cfg.h says what a caller states with each bit.
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

docs/decisions.md entries 52 and 63 and srv_kex.h cite those.

The run this note held before this one was of tree 26fa782, with a
second run for the P-256 rows docs/decisions.md 94 changed, under `0x1`
and `0x7`. Under `0x7`:

- rsa_pss_sign took 37.2 ms for RSA-2048 and 148 ms for RSA-3072, on the
  native copy of the ladder, and an RSA-3072 server's side 146.3 ms;
- rsa_pss_verify took 272 us for RSA-2048 and 650 us for RSA-3072, on
  32-bit limbs, and the RSA-3072 client side 0.77 ms, or 2.72 ms under
  `0x1`;
- sha256 took 4.79 ns a byte at 16 KB and sha384 3.20, in portable C,
  and hkdf_expand_label 1.52 us;
- the ECDSA server's side took 0.16 ms, and 0.78 ms before decision 94.

docs/decisions.md entry 94 cites the last of those.

## x86-64

bench/results-primitives-x86_64.csv is a run of the same script on a
GitHub-hosted runner: an AMD EPYC 7763 under Linux 6.17, gcc 13.3 at
`-std=c11 -O2`, tree 1f4a922, started by hand from
.github/workflows/bench.yml
(https://github.com/c4milo/chapulin/actions/runs/37297703527). The CPU
has AVX2, VAES, VPCLMULQDQ and the SHA extensions, so its second value
is `0x3f`: the AES, multiply and SHA-256 bits, `CH_CPU_AVX2` and
`CH_CPU_VAES`. No x86-64 CPU this tree targets has SHA-512 instructions,
so SHA-384 and SHA-512 run portable C under both values. The 1-minute
load average went from 0.91 to 1.01. The largest spread inside a run is
9.7% and between runs 9.9%, both on sha3_256 at 1 KB, and OpenSSL's rows
spread by 2.8% at most. The runner's CPU is not fixed: earlier runs of
this script drew an AMD EPYC 9V74 and a 7763, so figures from two runs
are not comparable to each other. Linux gives the program no instruction
count, so that column is empty.

Handshakes, milliseconds:

| handshake | `ch_cfg.cpu` | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | 0x1 | 94.3 | 4.13 | 90.2 |
| pinned RSA-2048 | 0x3f | 2.09 | 0.20 | 1.88 |
| pinned RSA-3072 | 0x1 | 295.9 | 4.19 | 291.7 |
| pinned RSA-3072 | 0x3f | 5.90 | 0.28 | 5.62 |
| pinned ECDSA P-256 | 0x1 | 12.9 | 5.96 | 6.97 |
| pinned ECDSA P-256 | 0x3f | 2.35 | 2.14 | 0.20 |
| pinned RSA-2048, hybrid | 0x1 | 95.1 | 4.57 | 90.6 |
| pinned RSA-2048, hybrid | 0x3f | 2.68 | 0.64 | 2.03 |
| pinned RSA-3072, hybrid | 0x1 | 296.9 | 4.65 | 292.2 |
| pinned RSA-3072, hybrid | 0x3f | 6.49 | 0.72 | 5.77 |
| pinned ECDSA P-256, hybrid | 0x1 | 13.6 | 6.42 | 7.16 |
| pinned ECDSA P-256, hybrid | 0x3f | 2.95 | 2.58 | 0.35 |

The hybrid resolves on every side under `0x3f`. A client's side grows by
438 to 447 us, against 438 us for two key generations and one
decapsulation, and a server's by 151 to 152 us, against 148 us for one
encapsulation.

Each row as a multiple of its time in bench/results-primitives-arm64.csv,
each machine under its widest value:

| row | x86-64 over arm64 |
|---|---:|
| shake256_squeeze, shake128_squeeze, 16 KB | 7.87, 7.54 |
| mlkem768 keygen, encaps, decaps | 5.61 to 5.74 |
| sha3_256, 16 KB | 4.87 |
| sha384, sha512, 16 KB | 3.96, 3.95 |
| poly1305, 16 KB | 2.53 |
| p256_ecdh | 1.93 |
| x25519 | 1.91 |
| rsa_pss_sign_2048, rsa_pss_sign_3072 | 1.76, 1.73 |
| p256_ecdsa_verify | 1.68 |
| p384_ecdsa_verify | 1.62 |
| hkdf_expand_label | 1.57 |
| sha256 and hmac_sha256, 16 KB | 1.56, 1.56 |
| rsa_pss_verify_3072 | 1.51 |
| p256_sign | 1.41 |
| chacha20_poly1305_seal, 16 KB | 1.25 |
| chacha20, 16 KB | 0.81 |

The wider value gains more here than on arm64 for X25519, P-256 and the
seal, and less for Poly1305, RSA signing and SHA-256. Time under `0x1`
over time under `0x3f`:

| row | ratio |
|---|---:|
| p256_ecdh_keygen | 82.0 |
| rsa_pss_sign_3072, rsa_pss_sign_2048 | 52.6, 49.5 |
| p256_sign | 44.8 |
| x25519 | 32.1 |
| p256_ecdh | 19.0 |
| poly1305, 16 KB | 8.61 |
| sha256, hmac_sha256, 16 KB | 5.93, 5.91 |
| chacha20_poly1305_seal, 16 KB | 5.32 |
| hkdf_expand_label | 4.00 |
| sha384, sha512, 16 KB | 1.00 |
| ML-KEM-768 | 1.00 to 1.02 |
| RSA-3072 handshake, server side | 51.9 |
| ECDSA handshake, server side | 34.3 |
| RSA-3072 handshake, client side | 15.1 |
| ECDSA handshake, client side | 2.79 |

What these show:

- Keccak is the outlier. SHA-3 and SHAKE take 4.9 to 7.9 times their
  arm64 time, and ML-KEM, which runs on them, takes 5.6 to 5.7 times. So
  ML-KEM-768 is 3.8 to 6.8 times OpenSSL's time here, where on the M1
  Pro it is ahead of OpenSSL or within 16% of it.
- SHA-384 and SHA-512 take 4.0 times their arm64 time. The M1 Pro runs
  them on its SHA-512 instructions, and this CPU has none.
- The elliptic-curve and RSA rows take 1.4 to 1.9 times their arm64
  time. Before docs/decisions.md 95 RSA signing was the one that ran
  faster here than on the M1 Pro, in 0.54 to 0.65 of its time, on the
  native copy of the ladder.
- SHA-256 takes 1.56 times its arm64 time on the SHA extensions, and
  ChaCha20 runs in 0.81 of it on the AVX2 kernel.
- Under `0x3f` the x25519 pair is 44% of an RSA-3072 client side and the
  verifier 49%; under `0x1` the pair is 94% of it.
