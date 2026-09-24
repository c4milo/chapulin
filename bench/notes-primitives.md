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
  object's level. Tree 6dd570f with this change applied.
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

## Load and variance

The committed run started at a 1-minute load average of 4.83 and ended
at 5.89. Inside it, no row's 25th-to-75th percentile spread or run-to-run
spread passed 3.9%.

The whole script ran three times in eight minutes:

- The first run, at a load of 3.5 to 3.8, read faster than the committed
  one on nearly every row: by 5.6% on the median row, and by -2.9% to
  +6.4% across rows.
- The second run, while the load rose from 3.5 to 7.2, agreed with the
  committed one to 0.0% on the median row, and to -3.8% to +5.9% across
  rows.
- The largest noise was in the second run: `rsa_pss_sign_2048` under
  `CH_NATIVE_WIDEMUL` had a 61% spread inside one run and 78% between
  runs. The median over its three runs still landed within 0.1% of the
  committed value.

So on this machine an absolute number carries about 6% of machine-wide
drift, and the rows move together. Between the three runs only rows
within 3% of each other swapped places in the rankings below, the
handshake shares moved by up to 4 points, and the multiply ratios by up
to 0.16.

`bench/primitives.sh --quick` numbers are not measurements. Its three
0.1 ms samples read `p256_ecdsa_verify` at 3.06 ms, against 1.25 ms in a
full run.

## Handshakes, measured

One sample is one handshake, both ends in one process
(bench/primitives_handshake.c, the pairing test/rec_loop_test.c drives),
from two fresh sessions to both ends connected. Client side and server
side are the time spent inside each end's calls. Milliseconds:

| handshake | build | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | default | 59.8 | 2.11 | 57.7 |
| pinned RSA-2048 | CH_NATIVE_WIDEMUL | 38.4 | 1.13 | 37.3 |
| pinned RSA-3072 | default | 194.5 | 2.48 | 192.0 |
| pinned RSA-3072 | CH_NATIVE_WIDEMUL | 148.2 | 1.54 | 146.6 |
| pinned ECDSA P-256 | default | 6.44 | 3.17 | 3.26 |
| pinned ECDSA P-256 | CH_NATIVE_WIDEMUL | 3.63 | 2.12 | 1.51 |

The pairing gives the server no ticket key, so it times no resumed
handshake, and the server has no `KEX=pq` half (srv_flight.h), so a
hybrid one cannot run in it. Both appear below as sums.

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
| RSA-3072 client | default | 72% | 25% | 1.2% | 1.2% |
| RSA-3072 client | CH_NATIVE_WIDEMUL | 55% | 41% | 1.9% | 2.7% |
| ECDSA client | default | 57% | 39% | 0.9% | 3.1% |
| ECDSA client | CH_NATIVE_WIDEMUL | 40% | 59% | 1.4% | -0.4% |
| RSA-3072 server | default | 0.9% | 102% | 0.0% | -3.2% |
| ECDSA server | default | 55% | 39% | 0.9% | 5.2% |
| ECDSA server | CH_NATIVE_WIDEMUL | 56% | 44% | 1.8% | -1.9% |

The rest runs from -3.2% to +5.2% of a side, about the 3% run spread
of the rows it is computed from. So the public-key operations account
for all of the time this method can resolve, and it cannot split the
rest further.

Sums for the two handshakes the pairing cannot run:

- `KEX=pq`: the client adds two ML-KEM-768 key generations and one
  decapsulation. handshake_flight.c calls mlkem_keygen_dk once to build
  the ClientHello and once before it decapsulates; that count is read
  from the code, not measured. The sum is 90 us on the default build,
  3.6% on top of the RSA-3072 client side, and 91 us, 5.9%, on the
  native one. A server would add one encapsulation, 31 us.
- Resumed PSK (psk_dhe_ke): the client skips the verifier and keeps the
  x25519 pair and the key schedule. The RSA-3072 client side minus the
  verify row is 1.85 ms on the default build and 0.92 ms on the native
  one.

## Ranking: once-per-handshake costs

Microseconds per operation, default build, then native. The last column
says who calls it and how often.

| primitive | default | native | called by |
|---|---:|---:|---|
| rsa_pss_sign_3072 | 196,239 | 143,888 | server, once, RSA-3072 identity |
| rsa_pss_sign_2048 | 57,293 | 36,460 | server, once, RSA-2048 identity |
| p384_ecdsa_verify | 4,034 | same | client, per P-384 signature, TRUST=webpki |
| p256_sign | 1,269 | 668 | server, once, ECDSA identity |
| p256_ecdsa_verify | 1,251 | same | client, once, TRUST=raw-ecdsa; per link, webpki |
| p256_ecdh | 1,172 | 610 | no caller yet; a server's P-256 key exchange |
| rsa_pss_verify_4096 | 1,172 | same | client, TRUST=webpki |
| rsa_pkcs1_verify_4096 | 1,166 | same | client, per RSA-4096 link, webpki |
| x25519, x25519_base | 898, 897 | 423, 423 | both ends, once each |
| rsa_pss_verify_3072 | 628 | same | client, once, TRUST=raw-rsa default |
| rsa_pkcs1_verify_3072 | 627 | same | client, per link, webpki |
| rsa_pss_verify_2048 | 264 | same | client, once |
| rsa_pkcs1_verify_2048 | 262 | same | client, per link, webpki |
| mlkem768_decaps | 35.3 | 34.8 | client, once, KEX=pq |
| mlkem768_encaps | 31.5 | 31.2 | no caller yet; a server's KEX=pq half |
| mlkem768_keygen | 27.5 | 28.3 | client, twice, KEX=pq |
| hkdf_expand_label | 1.64 | same | client 18, server 17 |

For a client on the default build, the x25519 pair is the largest cost
in both pinned modes and the verifier is second. The native multiply
halves the pair and leaves the verifiers as they are, so on that build
the P-256 verifier is the larger cost of an ECDSA client. For a server
with an RSA identity, rsa_pss_sign is 97% to 102% of its side.
rsa_sign.h states that it signs without the CRT, which it puts at
about four times the cost of a CRT signature. That is a design choice
rather than an instruction family, and this bench does not measure it.

## Ranking: per-byte costs

Nanoseconds per byte at 16 KB, then 64 B (32 B for the DRBG, whose
common draw is 32 bytes). Default build; native where it differs.

| primitive | 16 KB | 64 B | native 16 KB | where a connection runs it |
|---|---:|---:|---:|---|
| hmac_sha256 | 4.85 | 29.0 | | key schedule, Finished; short inputs |
| sha256 | 4.79 | 11.7 | | transcript, inside HMAC and HKDF |
| sha3_256 | 3.92 | 7.53 | | inside ML-KEM |
| chacha20_poly1305_open | 3.48 | 7.31 | 2.28 | every received record |
| chacha20_poly1305_seal | 3.47 | 7.41 | 2.27 | every sent record |
| sha512, sha384 | 3.19, 3.19 | 9.66, 9.12 | | certificate signatures, webpki |
| shake256_squeeze | 2.35 | 5.40 | | inside ML-KEM |
| shake128_squeeze | 2.01 | 5.39 | | inside ML-KEM |
| poly1305 | 1.95 | 2.59 | 0.71 | half of the AEAD |
| drbg | 1.66 | 4.35 | | every ch_rand_bytes call |
| chacha20 | 1.55 | 1.69 | | half of the AEAD |

A 1,200-byte record costs 4.4 us to seal on the default build and 3.0 us
on the native one. Record protection costs as much as the RSA-3072
client handshake after about 714 KB sealed or opened (679 KB native),
and as much as the ECDSA client handshake after about 913 KB. A
connection that moves less than that spends most of its crypto time in
the handshake, and most of that in x25519 and the verifier.

On the default build Poly1305 is the slower half of the AEAD, 1.95 ns
against ChaCha20's 1.55. The native multiply makes it 0.71, and
ChaCha20 becomes the larger half.

## The multiply build

Default time over native time, from the rows above:

| row | ratio |
|---|---:|
| poly1305, 16 KB | 2.76 |
| x25519 | 2.12 |
| p256_ecdh | 1.92 |
| p256_sign | 1.90 |
| rsa_pss_sign_2048 | 1.57 |
| chacha20_poly1305_seal, 16 KB | 1.53 |
| rsa_pss_sign_3072 | 1.36 |
| mlkem768 keygen, encaps, decaps | 0.97 to 1.01 |
| RSA-3072 handshake, client side | 1.61 |
| ECDSA handshake, client side | 1.50 |

ML-KEM does not move. mlkem_poly.c builds to a different object under
the native multiply, and the difference does not show in these rows.

## Instruction families that could speed each primitive

These are options to measure, not promised gains. The limb widths are
what the code uses today. This M1 Pro reports FEAT_SHA256, FEAT_SHA512
and FEAT_SHA3 (`sysctl hw.optional.arm`).

| primitive | arm64 | x86-64 |
|---|---|---|
| x25519 (16-bit limbs in int64 words) | the native 64x64 multiply with UMULH over wider limbs; NEON for two field products at once | MULX (BMI2) with ADCX and ADOX (ADX); AVX2 for several field products at once |
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

## x86-64

bench/results-primitives-x86_64.csv is a run of the same script on a
GitHub-hosted runner: an AMD EPYC 7763 under Linux 6.17, gcc 13.3 at
`-std=c11 -O2`, tree c91e449, started by hand from
.github/workflows/bench.yml. The 1-minute load average went from 0.61
to 0.95. No row's spread inside a run passed 4.2%, and no row's spread
between runs passed 1.6%.

Handshakes, milliseconds:

| handshake | build | whole | client side | server side |
|---|---|---:|---:|---:|
| pinned RSA-2048 | default | 94.8 | 4.28 | 90.5 |
| pinned RSA-2048 | CH_NATIVE_WIDEMUL | 28.5 | 2.14 | 26.4 |
| pinned RSA-3072 | default | 297.8 | 4.66 | 293.1 |
| pinned RSA-3072 | CH_NATIVE_WIDEMUL | 85.6 | 2.52 | 83.0 |
| pinned ECDSA P-256 | default | 12.9 | 5.96 | 6.97 |
| pinned ECDSA P-256 | CH_NATIVE_WIDEMUL | 6.93 | 3.83 | 3.10 |

Each row as a multiple of its arm64 time, default build:

| row | x86-64 over arm64 |
|---|---:|
| shake256_squeeze, 16 KB | 7.50 |
| shake128_squeeze, 16 KB | 7.16 |
| mlkem768_keygen, encaps, decaps | 4.75 to 5.04 |
| sha3_256, 16 KB | 4.58 |
| p256_sign, p256_ecdh | 2.37 to 2.43 |
| x25519 | 2.20 |
| poly1305, 16 KB | 1.76 |
| chacha20_poly1305_seal, 16 KB | 1.65 |
| p256_ecdsa_verify | 1.64 |
| chacha20, 16 KB | 1.47 |
| rsa_pss_sign_3072 | 1.47 |
| rsa_pss_verify_3072 | 1.09 |
| sha512, 16 KB | 0.89 |
| hkdf_expand_label | 0.82 |
| sha256 and hmac_sha256, 16 KB | 0.79 |

The native multiply gains more here than on arm64. Default time over
native time:

| row | ratio |
|---|---:|
| poly1305, 16 KB | 4.73 |
| rsa_pss_sign_3072 | 3.56 |
| rsa_pss_sign_2048 | 3.53 |
| p256_sign, p256_ecdh | 2.50 |
| x25519 | 2.36 |
| chacha20_poly1305_seal, 16 KB | 1.89 |
| ML-KEM-768 | 1.00 to 1.02 |

What these show:

- The rankings match arm64 at the top. A client's largest cost is the
  x25519 pair, 3.95 ms of a 4.66 ms RSA-3072 client side on the
  default build, and a server with an RSA identity spends its side in
  rsa_pss_sign.
- Keccak is the outlier. SHA-3 and SHAKE take 4.6 to 7.5 times their
  arm64 time, where every other row takes at most 2.4 times, and
  ML-KEM, which runs on them, takes 4.8 to 5.0 times. A `KEX=pq` client
  adds two key generations and one decapsulation, 445 us, which is 9.6%
  on top of the RSA-3072 client side.
- SHA-256 is the one hash faster here than on arm64, without SHA-NI.
