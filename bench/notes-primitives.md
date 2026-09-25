# Where the time goes: chapulin's primitives on arm64 and x86-64

This note ranks the primitives by the time they cost a connection, so
that SIMD and crypto-instruction work can start where it pays. It reads
two files that `make bench-primitives` (bench/primitives.sh) writes:

- bench/results-primitives-arm64.csv: every primitive, per byte or per
  operation, and whole handshakes between this tree's client and server.
- bench/results-primitives-calls.csv: how many times each end of each
  handshake calls each primitive, counted with `-finstrument-functions`.

AES-128-GCM is timed by bench/aead.sh and recorded in
bench/results-aead-arm64.csv; this note does not repeat it.

## Machine and method

- Apple M1 Pro (8 performance and 2 efficiency cores), macOS 26.6.2
  (Darwin 25.6.0), Apple clang 21.0.0, `-std=c11 -O2`, the packaged
  object's level. Tree 0ae2dbe.
- Each row is the median over 3 runs of each run's median of 101 samples
  (11 to 27 samples for the operations slower than 10 ms; the CSV's
  samples column says which). The method is in bench/primitives.c.
- The program asks macOS for the user-interactive class, which it
  places on performance cores first.
- `default` is the multiply the packaged object ships: ct.h builds each
  widening product from 16x16 pieces. `CH_NATIVE_WIDEMUL` is the build
  that asserts the native multiply is constant time. Only poly1305.c,
  x25519.c, mlkem_poly.c, p256_field.c, p256_scalar.c and rsa_sign.c
  compile differently under it: every other module the primitives
  program links builds to a byte-identical object either way (compared
  with clang 21), so the CSV times only the aead, secret_key and
  handshake groups twice.
- `X25519=wide` is the build that replaces x25519.c's 16-limb field with
  x25519_wide.c's five 51-bit limbs on the 64x64->128 multiply
  (docs/decisions.md entry 52). It changes one choice from the default
  and no other module, so the CSV times the two x25519 rows and the
  handshakes under it, and nothing else.

## Load and variance

The committed run started at a 1-minute load average of 24.25 and ended
at 12.19. Other work held the machine between 10 and 24 for the whole
run, where the run this note described before, at tree 6dd570f, ran
between 4.8 and 5.9.

The medians moved less than the load did. Against that earlier run,
the 92 rows both runs time read 2% slower on the median row, and 0.1% to
11% slower across rows. The spreads moved more: inside this run the
largest 25th-to-75th percentile spread is 187%, on the ECDSA handshake
rows, and the largest run-to-run spread is 128%, on the RSA-2048
handshake's server side. Outside the handshake group one row passed 10%
between runs, Poly1305 at 16 KB on the native multiply at 26%, and
every per-operation x25519 row stayed under 5%.

So read the handshake rows as medians of noisy samples, and compare rows
within this run rather than against the earlier one. The three-run
repeat the earlier note reported, which put about 6% of machine-wide
drift on an absolute number at a load near 5, was not repeated here.

`bench/primitives.sh --quick` numbers are not measurements. Its three
0.1 ms samples once read `p256_ecdsa_verify` at 3.06 ms, against 1.25 ms
in a full run.

## Handshakes, measured

One sample is one handshake, both ends in one process
(bench/primitives_handshake.c, the pairing test/rec_loop_test.c drives),
from two fresh sessions to both ends connected. Client side and server
side are the time spent inside each end's calls. Milliseconds:

| handshake | build | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | default | 64.6 | 2.18 | 62.3 |
| pinned RSA-2048 | CH_NATIVE_WIDEMUL | 40.5 | 1.19 | 39.2 |
| pinned RSA-2048 | X25519=wide | 59.4 | 0.40 | 59.0 |
| pinned RSA-3072 | default | 206.3 | 2.57 | 203.5 |
| pinned RSA-3072 | CH_NATIVE_WIDEMUL | 151.1 | 1.58 | 149.6 |
| pinned RSA-3072 | X25519=wide | 202.8 | 0.77 | 202.0 |
| pinned ECDSA P-256 | default | 6.77 | 3.29 | 3.30 |
| pinned ECDSA P-256 | CH_NATIVE_WIDEMUL | 4.04 | 2.31 | 1.58 |
| pinned ECDSA P-256 | X25519=wide | 3.94 | 1.45 | 1.44 |

The pairing gives the server no ticket key, so it times no resumed
handshake. This arm64 run predates the server's hybrid half (4d897ed),
so it timed no hybrid handshake either; the x86-64 section below times
one. Both appear below as sums.

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

| side | build | x25519 pair | verify or sign | HKDF-Expand-Label | rest |
|---|---|---:|---:|---:|---:|
| RSA-3072 client | default | 74% | 26% | 1.2% | -0.6% |
| RSA-3072 client | CH_NATIVE_WIDEMUL | 54% | 42% | 1.9% | 2.1% |
| RSA-3072 client | X25519=wide | 8.9% | 85% | 3.9% | 2.5% |
| ECDSA client | default | 58% | 40% | 0.9% | 1.2% |
| ECDSA client | CH_NATIVE_WIDEMUL | 37% | 57% | 1.3% | 4.4% |
| ECDSA client | X25519=wide | 4.7% | 91% | 2.1% | 2.1% |
| RSA-3072 server | default | 0.9% | 99% | 0.0% | 0.0% |
| ECDSA server | default | 57% | 40% | 0.9% | 1.8% |
| ECDSA server | CH_NATIVE_WIDEMUL | 54% | 42% | 1.8% | 1.7% |
| ECDSA server | X25519=wide | 4.8% | 92% | 2.0% | 1.8% |

The rest runs from -0.6% to +4.4% of a side, inside the run spread of
the rows it is computed from. So the public-key operations account for
all of the time this method can resolve, and it cannot split the rest
further.

Sums for the two handshakes this arm64 run did not time:

- `KEX=pq`: the client adds two ML-KEM-768 key generations and one
  decapsulation. handshake_flight.c calls mlkem_keygen_dk once to build
  the ClientHello and once before it decapsulates;
  bench/results-primitives-calls.csv measures that count, and the one
  encapsulation the server adds. The sum is 96 us on the default build,
  3.7% on top of the RSA-3072 client side, and 94 us, 6.0%, on the
  native one. `X25519=wide` does not change ML-KEM, so there the same
  96 us is 12% on top of the RSA-3072 client side. The server adds one
  encapsulation, 33 us.
- Resumed PSK (psk_dhe_ke): the client skips the verifier and keeps the
  x25519 pair and the key schedule. The RSA-3072 client side minus the
  verify row is 1.91 ms on the default build, 0.92 ms on the native one
  and 0.12 ms under `X25519=wide`.

## Ranking: once-per-handshake costs

Microseconds per operation, default build, then native. The last column
says who calls it and how often.

| primitive | default | native | called by |
|---|---:|---:|---|
| rsa_pss_sign_3072 | 201,526 | 149,218 | server, once, RSA-3072 identity |
| rsa_pss_sign_2048 | 59,167 | 38,093 | server, once, RSA-2048 identity |
| p384_ecdsa_verify | 4,275 | same | client, per P-384 signature, TRUST=webpki |
| p256_ecdsa_verify | 1,325 | same | client, once, TRUST=raw-ecdsa; per link, webpki |
| p256_sign | 1,320 | 670 | server, once, ECDSA identity |
| p256_ecdh | 1,228 | 610 | both ends, once each, when secp256r1 runs (docs/decisions.md 63) |
| rsa_pss_verify_4096 | 1,223 | same | client, TRUST=webpki |
| rsa_pkcs1_verify_4096 | 1,204 | same | client, per RSA-4096 link, webpki |
| x25519, x25519_base | 953, 944 | 428, 431 | both ends, once each |
| rsa_pss_verify_3072 | 656 | same | client, once, TRUST=raw-rsa default |
| rsa_pkcs1_verify_3072 | 652 | same | client, per link, webpki |
| rsa_pss_verify_2048 | 275 | same | client, once |
| rsa_pkcs1_verify_2048 | 273 | same | client, per link, webpki |
| mlkem768_decaps | 37.1 | 35.5 | client, once, KEX=pq |
| x25519, x25519_base, `X25519=wide` | 34.3, 34.5 | | both ends, once each |
| mlkem768_encaps | 33.2 | 32.0 | server, once, when it selects the hybrid |
| mlkem768_keygen | 29.5 | 29.4 | client, twice, KEX=pq |
| hkdf_expand_label | 1.66 | same | client 18, server 17 |

For a client on the default build, the x25519 pair is the largest cost
in both pinned modes and the verifier is second. The native multiply
halves the pair and leaves the verifiers as they are, so on that build
the P-256 verifier is the larger cost of an ECDSA client. `X25519=wide`
takes the pair to 69 us, under a tenth of either client side, and leaves
the verifier as the largest cost of every client. For a server with an
RSA identity, rsa_pss_sign is 99% of its side.
rsa_sign.h states that it signs without the CRT, which it puts at
about four times the cost of a CRT signature. That is a design choice
rather than an instruction family, and this bench does not measure it.

## Ranking: per-byte costs

Nanoseconds per byte at 16 KB, then 64 B (32 B for the DRBG, whose
common draw is 32 bytes). Default build; native where it differs.

| primitive | 16 KB | 64 B | native 16 KB | where a connection runs it |
|---|---:|---:|---:|---|
| hmac_sha256 | 4.92 | 29.3 | | key schedule, Finished; short inputs |
| sha256 | 4.83 | 11.9 | | transcript, inside HMAC and HKDF |
| sha3_256 | 3.93 | 7.61 | | inside ML-KEM |
| chacha20_poly1305_seal | 3.62 | 7.81 | 2.29 | every sent record |
| chacha20_poly1305_open | 3.60 | 7.55 | 2.29 | every received record |
| sha512, sha384 | 3.23, 3.23 | 9.81, 9.23 | | certificate signatures, webpki |
| shake256_squeeze | 2.37 | 5.44 | | inside ML-KEM |
| poly1305 | 2.02 | 2.61 | 0.71 | half of the AEAD |
| shake128_squeeze | 2.02 | 5.45 | | inside ML-KEM |
| drbg | 1.69 | 4.40 | | every ch_rand_bytes call |
| chacha20 | 1.58 | 1.71 | | half of the AEAD |

A 1,200-byte record costs 4.6 us to seal on the default build and 3.0 us
on the native one. Record protection costs as much as the RSA-3072
client handshake after about 710 KB sealed or opened (688 KB native),
and as much as the ECDSA client handshake after about 910 KB. Under
`X25519=wide` those fall to 214 KB and 402 KB. A connection that moves
less than that spends most of its crypto time in the handshake, and most
of that in x25519 and the verifier, or in the verifier alone once the
field is wide.

On the default build Poly1305 is the slower half of the AEAD, 2.02 ns
against ChaCha20's 1.58. The native multiply makes it 0.71, and
ChaCha20 becomes the larger half.

## The multiply build

Default time over native time, from the rows above:

| row | ratio |
|---|---:|
| poly1305, 16 KB | 2.84 |
| x25519 | 2.23 |
| p256_ecdh | 2.01 |
| p256_sign | 1.97 |
| chacha20_poly1305_seal, 16 KB | 1.58 |
| rsa_pss_sign_2048 | 1.55 |
| rsa_pss_sign_3072 | 1.35 |
| mlkem768 keygen, encaps, decaps | 1.00 to 1.05 |
| RSA-3072 handshake, client side | 1.63 |
| ECDSA handshake, client side | 1.42 |

ML-KEM barely moves. mlkem_poly.c builds to a different object under
the native multiply, and the difference is inside the run spread of
these rows.

## The X25519 field

`X25519=wide` against the two builds of the 16-limb field. The first
two rows are microseconds per scalar multiplication; the last two are
milliseconds of client side:

| row | default | CH_NATIVE_WIDEMUL | X25519=wide | default over wide | native over wide |
|---|---:|---:|---:|---:|---:|
| x25519 | 953 | 428 | 34.3 | 27.8 | 12.5 |
| x25519_base | 944 | 431 | 34.5 | 27.4 | 12.5 |
| RSA-3072 handshake, client side | 2.57 | 1.58 | 0.77 | 3.32 | 2.04 |
| ECDSA handshake, client side | 3.29 | 2.31 | 1.45 | 2.26 | 1.59 |

Three counts account for the 12.5 against the native multiply. A field
multiply runs 25 products of 64 by 64 bits where the 16-limb field runs
256 of 32 by 32; a squaring runs 15 where the 16-limb field runs a whole
multiply; and the inversion's fixed chain runs 11 multiplies where the
16-limb field's square-and-multiply runs 252. Against the default build
the 16x16 decomposition's cost comes on top, which is where 27.8 comes
from. A device cannot build the wide field, so the device rows in the
README and bench/results-insn*.csv keep the 16-limb one.

## Instruction families that could speed each primitive

These are options to measure, not promised gains. The limb widths are
what the code uses today. This M1 Pro reports FEAT_SHA256, FEAT_SHA512
and FEAT_SHA3 (`sysctl hw.optional.arm`).

| primitive | arm64 | x86-64 |
|---|---|---|
| x25519 (16-bit limbs in int64 words; 51-bit limbs under `X25519=wide`) | `X25519=wide` runs the native 64x64 multiply with UMULH over 51-bit limbs; NEON for two field products at once is still open | `X25519=wide` runs MUL; MULX (BMI2) with ADCX and ADOX (ADX), and AVX2 for several field products at once, are still open |
| RSA verify and sign, P-256 and P-384 (32-bit limbs) | UMULH over 64-bit limbs; NEON UMULL and UMLAL for 32x32 products in lanes | MULX, ADCX and ADOX over 64-bit limbs; AVX2 VPMULUDQ; AVX-512 IFMA (VPMADD52LUQ, VPMADD52HUQ) |
| Poly1305 | the native multiply first; NEON UMLAL over 26-bit limbs, several blocks at once | MULX; AVX2 VPMULUDQ over 26-bit limbs, four blocks at once |
| ChaCha20, and the DRBG over it | NEON, four blocks per pass | AVX2, eight blocks per pass; AVX-512, sixteen |
| SHA-256, HMAC, HKDF | the ARMv8 SHA-256 instructions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1) | SHA-NI (SHA256RNDS2, SHA256MSG1, SHA256MSG2) |
| SHA-384, SHA-512 | the ARMv8.2 SHA-512 instructions (SHA512H, SHA512H2, SHA512SU0, SHA512SU1) | AVX2 for the message schedule; the SHA512 extension (VSHA512RNDS2) only on the newest parts |
| SHA3-256, SHAKE128, SHAKE256 | the ARMv8.2 SHA-3 instructions (EOR3, RAX1, XAR, BCAX); NEON for two Keccak states at once | AVX2 for four Keccak states at once, which suits ML-KEM's independent SHAKE streams; no Keccak instruction |
| ML-KEM-768 NTT and polynomial arithmetic | NEON, eight 16-bit lanes (SQDMULH, SQRDMULH for the reductions) | AVX2, sixteen 16-bit lanes (VPMULHW, VPMULLW) |
| AES-128-GCM | AES and PMULL (bench/aead.sh) | AES-NI and PCLMULQDQ (bench/aead.sh) |

## What these numbers do not show

- How ML-KEM's time splits between Keccak and the NTT. The SHAKE rows
  give Keccak's speed per byte, not how many bytes ML-KEM squeezes.
- A TRUST=webpki handshake. Its chain verify runs one verifier row per
  link, but no chain was timed here.
- Which half of a difference between the arm64 and x86-64 runs is the
  compiler and which is the CPU. The arm64 run used clang and the
  x86-64 run used gcc, so no row separates the two.
- Whether the 64x64->128 multiply runs in constant time here. Nothing
  in the bench or in this tree sets PSTATE.DIT, so the `X25519=wide`
  rows time the field in whatever mode macOS runs the program in.
  `make timing`'s t-test is the evidence this tree has, and ct.h says
  what the build asserts instead.

## x86-64

bench/results-primitives-x86_64.csv is a run of the same script on a
GitHub-hosted runner: an AMD EPYC 9V74 under Linux 6.17, gcc 13.3 at
`-std=c11 -O2`, tree 4e02293, started by hand from
.github/workflows/bench.yml. The 1-minute load average went from 0.81
to 0.99. No row's spread inside a run passed 2.8%, and no row's spread
between runs passed 1.9%. The runner's CPU is not fixed: the previous
run of this script, at c91e449, drew an AMD EPYC 7763, so figures from
two runs are not comparable to each other.

Handshakes, milliseconds:

| handshake | build | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | default | 106.2 | 4.68 | 101.6 |
| pinned RSA-2048 | CH_NATIVE_WIDEMUL | 32.6 | 2.76 | 29.8 |
| pinned RSA-2048 | X25519=wide | 98.0 | 0.56 | 97.4 |
| pinned RSA-2048 | hybrid | 107.0 | 5.18 | 101.8 |
| pinned RSA-3072 | default | 334.5 | 5.14 | 329.4 |
| pinned RSA-3072 | CH_NATIVE_WIDEMUL | 95.9 | 3.19 | 92.7 |
| pinned RSA-3072 | X25519=wide | 326.3 | 1.02 | 325.3 |
| pinned RSA-3072 | hybrid | 335.3 | 5.68 | 329.6 |
| pinned ECDSA P-256 | default | 14.4 | 6.57 | 7.81 |
| pinned ECDSA P-256 | CH_NATIVE_WIDEMUL | 8.33 | 4.65 | 3.68 |
| pinned ECDSA P-256 | X25519=wide | 6.11 | 2.46 | 3.65 |
| pinned ECDSA P-256 | hybrid | 15.2 | 7.16 | 7.99 |

The hybrid rows are the default build with `-DCH_KEX_PQ`: the client
offers X25519MLKEM768 alone and the server selects it. What the hybrid
adds, measured, against the sum of its ML-KEM rows:

| side | measured | ML-KEM rows | rows used |
|---|---:|---:|---|
| RSA-2048 client | +501 us | 489 us | two keygens, one decapsulation |
| RSA-3072 client | +534 us | 489 us | the same |
| ECDSA client | +594 us | 489 us | the same |
| RSA-2048 server | +227 us | 166 us | one encapsulation |
| RSA-3072 server | +217 us | 166 us | the same |
| ECDSA server | +177 us | 166 us | the same |

The rest of each difference, 12 to 105 us on the client and 11 to 61 us
on the server, is the larger hello and ServerHello: 1,184 more bytes to
write, hash and parse one way and 1,088 the other.

Each row as a multiple of its time in bench/results-primitives-arm64.csv, default build:

| row | x86-64 over arm64 |
|---|---:|
| shake256_squeeze, 16 KB | 8.36 |
| shake128_squeeze, 16 KB | 8.00 |
| sha3_256, 16 KB | 5.09 |
| mlkem768_keygen, encaps, decaps | 4.92 to 5.19 |
| p256_sign, p256_ecdh | 2.63 to 2.66 |
| x25519 | 2.27 |
| x25519, `X25519=wide` | 2.01 |
| poly1305, 16 KB | 1.93 |
| chacha20_poly1305_seal, 16 KB | 1.80 |
| p256_ecdsa_verify | 1.76 |
| chacha20, 16 KB | 1.64 |
| rsa_pss_sign_3072 | 1.61 |
| rsa_pss_verify_3072 | 1.27 |
| sha512, 16 KB | 0.98 |
| sha256 and hmac_sha256, 16 KB | 0.83 to 0.84 |
| hkdf_expand_label | 0.83 |

The native multiply gains more here than on arm64. Default time over
native time:

| row | ratio |
|---|---:|
| poly1305, 16 KB | 4.43 |
| rsa_pss_sign_3072 | 3.60 |
| rsa_pss_sign_2048 | 3.56 |
| p256_sign, p256_ecdh | 2.63 to 2.64 |
| chacha20_poly1305_seal, 16 KB | 1.87 |
| x25519 | 1.83 |
| ML-KEM-768 | 1.00 to 1.02 |

What these show:

- The x25519 pair is 83% of an RSA-3072 client side on the default
  build. `X25519=wide` takes one scalar multiplication from 2,160 us to
  69 us, 31 times faster than the default build and 17 times faster
  than the native multiply, and the RSA-3072 client side from 5.14 ms
  to 1.02 ms, where the pair is 14%.
- The hybrid adds about 0.5 ms to a client and 0.2 ms to a server, and
  the ML-KEM rows account for most of both. Against an RSA-3072 client
  side that is 10% on the default build. No row times the hybrid with
  `X25519=wide`; the wide field leaves ML-KEM unchanged, so the same
  0.5 ms would be about half of that build's 1.02 ms client side.
- A server with an RSA identity spends its side in rsa_pss_sign, so the
  hybrid is 0.1% to 0.2% of it.
- Keccak is the outlier. SHA-3 and SHAKE take 5.1 to 8.4 times their
  arm64 time, where every other row takes at most 2.7 times, and
  ML-KEM, which runs on them, takes 4.9 to 5.2 times.
- SHA-256 runs faster here than on arm64, 0.84 of its time, without
  SHA-NI, and SHA-512 about the same, 0.98.
