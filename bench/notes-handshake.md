# Where a server handshake's instructions go: the counts before

This note holds the history of the count that docs/performance.md, "Where a
server handshake's instructions go", shows: what each count found against
the one before it, what decisions 148, 152 and 153 changed, and the first
count, of 2026-10-01, with the order of the work it set. It moved from that
page on 2026-11-27.

## What each count changed

What changed since 2026-10-25. The script counted f96c5192 on 2026-10-25, on the same runner type
under Linux 6.17:

| M instructions, server side of the second connection | 2026-10-25 | 2026-10-30 | OpenSSL 3.6.4, 2026-10-30 |
| --- | --- | --- | --- |
| the handshake, Neoverse-N2 build, `0xe7`, perf_events | 0.821 | 0.795 | 1.345 |
| the handshake, Neoverse-N2 build, `0x07`, perf_events | 1.233 | 1.219 | 1.345 |
| the handshake, base armv8-a build, `0xe7`, perf_events | 0.968 | 0.966 | 1.345 |
| X25519 shared secret, Neoverse-N2 build, `0xe7` | 0.345 | 0.320 | 0.380 |
| X25519 shared secret, base armv8-a build, `0xe7` | 0.447 | 0.448 | 0.380 |
| CertificateVerify, Neoverse-N2 build, `0xe7` | 0.165 | 0.170 | 0.197 |
| CertificateVerify, Neoverse-N2 build, `0x07` | 0.325 | 0.342 | 0.197 |
| certificate, other messages and their records, Neoverse-N2 build, `0xe7` | 0.084 | 0.077 | 0.215 |
| one request's records and the two close_notify, Neoverse-N2 build, `0xe7` | 0.015 | 0.009 | 0.038 |

- The wide X25519 field carries each column of `mul` and `sqr` at once (49f3ed2d). On the
  Neoverse-N2 build the shared secret takes 320,275 instructions where it took 345,032. The base
  build's moves by 552.
- The signature checks k·G and s before it leaves, and its nonce is hedged (decision 153). Under
  `0xe7` the signature takes 170,108 instructions where it took 165,082. Under `0x07` the
  nonce's four added SHA-256 compressions run on the portable code, and the signature takes
  341,661 where it took 324,506.
- The records cost less. Each AES traffic key keeps its schedule (decision 160), and arm64
  AES-GCM runs a record in one call (decisions 158 and 161). The request, the response and the
  two close_notify take 9,133 instructions where they took 15,329.

What changed since 2026-10-21. The script counted d0731465 that day, before docs/decisions.md 144
to 147 and 149, on the same runner type under Linux 7.0:

| Neoverse-N2 build, M instructions | `0xe7`, 2026-10-21 | `0xe7`, 2026-10-25 before entry 148 | `0x07`, 2026-10-21 | `0x07`, 2026-10-25 before entry 148 |
| --- | --- | --- | --- | --- |
| the handshake, perf_events | 1.307 | 1.144 | 1.830 | 1.555 |
| the handshake against OpenSSL 3.6.4 | 0.97 | 0.85 | 1.36 | 1.16 |
| CertificateVerify: the P-256 ECDSA signature | 0.220 | 0.165 | 0.416 | 0.324 |
| HKDF and HMAC of the key schedule | 0.158 | 0.094 | 0.381 | 0.284 |
| hashes of the transcript, the signed content and the ClientHello | 0.046 | 0.015 | 0.150 | 0.076 |
| of the handshake, the image's own memset | 0.207 | 0.042 | 0.221 | 0.040 |

- Two kinds of change are in the new column. `ct_wipe` stores words and calls no `memset`
  (decision 144), which every stage that wipes a secret gains from. The fixes of entries 145 to
  147 and 149 remove hash work: the signed content's digest and the ClientHello digest run on
  the session's path, the SHA-256 transcript stops at the ServerHello, and the nonce keeps its
  HMAC midstates for each K.
- A count of the fixes alone, on 2026-10-24 over 773ac1da, put the handshake at 1,281,526
  instructions under `0xe7` and 1,707,844 under `0x07`. So the fixes removed 25,951 and 121,800
  instructions, and `ct_wipe`'s word stores most of the rest.
- The nonce row now holds the generator's out-of-line functions as well as its SHA-256 calls, so
  compare the signature row across the two dates and not its parts.

What decision 148 changed. The script counted 5f2424a6 on 2026-10-25, before entry 148, on the
same runner type under Linux 6.17. The column with entry 148 counts the tree before entry 152:

| M instructions, server side of the second connection | before entry 148 | with entry 148 | OpenSSL 3.6.4 |
| --- | --- | --- | --- |
| X25519 key generation, Neoverse-N2 build, `0xe7` | 0.393 | 0.132 | 0.227 |
| X25519 key generation, base armv8-a build, `0xe7` | 0.457 | 0.150 | 0.227 |
| the handshake, Neoverse-N2 build, `0xe7`, perf_events | 1.144 | 0.883 | 1.346 |
| the handshake, Neoverse-N2 build, `0x07`, perf_events | 1.555 | 1.295 | 1.346 |
| the handshake, base armv8-a build, `0xe7`, perf_events | 1.300 | 0.991 | 1.346 |

- A session that states its multiply computes the public key from a table of multiples of
  edwards25519's base point in place of the ladder on u = 9 (decision 148). The key generation
  takes 132,403 instructions where it took 393,095, 0.58 of OpenSSL 3.6.4's 227,086, and the
  handshake loses 260,419 instructions under `0xe7`. The shared secret keeps the ladder. Under
  `0x03` nothing moves: that session runs the 16-word field's ladder for both.

What decision 152 changed. The script counted f96c5192 on 2026-10-25, on the same runner type
under Linux 6.17. That is the column with entry 152. The column before entry 152 is the count of
the tree with entry 148:

| M instructions, server side of the second connection | before entry 152 | with entry 152 | OpenSSL 3.6.4 |
| --- | --- | --- | --- |
| X25519 shared secret, Neoverse-N2 build, `0xe7` | 0.393 | 0.345 | 0.380 |
| X25519 key generation, Neoverse-N2 build, `0xe7` | 0.132 | 0.119 | 0.227 |
| X25519 shared secret, base armv8-a build, `0xe7` | 0.455 | 0.447 | 0.380 |
| the handshake, Neoverse-N2 build, `0xe7`, perf_events | 0.883 | 0.821 | 1.346 |
| the handshake, Neoverse-N2 build, `0x07`, perf_events | 1.295 | 1.233 | 1.346 |
| the handshake, base armv8-a build, `0xe7`, perf_events | 0.991 | 0.968 | 1.346 |

- The wide field's ladder swaps the points once a step, carries columns 1 to 4 in 64-bit words,
  runs `add`, `sub` and `cswap` without loops, and runs its products in place (decision 152).
  The shared secret takes 345,032 instructions where it took 393,447, 0.91 of OpenSSL 3.6.4's
  380,382. Key generation shares the field and takes 118,825 where it took 132,403.
- The base armv8-a build gains less: 455,006 to 447,353. On that target the products in place
  cost more than they save, and the other three changes more than make up for it.
- A QEMU trace of one shared secret, split by the source function of each instruction, gives the
  N2 build's parts. Code in place moves some loads and moves to the line of the product they
  feed, so the products' line grows although their count does not change:

  | Neoverse-N2 build, instructions of one shared secret | before entry 152 | with entry 152 |
  | --- | --- | --- |
  | `ct_mul128`, the 64x64->128 products | 106,140 | 118,142 |
  | `carry_columns` and `column_carry` | 102,427 | 82,169 |
  | `mul` and `sqr`: the sums of products and the multiples of 19 | 113,753 | 107,253 |
  | `cswap` | 31,110 | 11,527 |
  | `add` and `sub` | 28,560 | 19,384 |
  | `step`, the ladder's loop, `sqr_times` and `invert` | 10,164 | 5,250 |
  | the wipes, `pack`, `unpack` and the entry | 1,303 | 1,317 |
  | the whole shared secret | 393,457 | 345,042 |

  By call site, the 255 steps take 315,953 instructions where they took 362,100, and the
  inversion 22,960 where it took 25,521.
- On the M1 Pro, Apple clang 21 at `-O2`, `proc_pid_rusage` counts 372,726 instructions for a
  shared secret before entry 152 and 340,978 with it, and 129,818 and 119,682 for key
  generation. Decision 152 gives the x86-64 counts under gcc 13 and two clangs.

What decision 153 adds. The server's ECDSA signature now takes a hedged nonce, and the signer
checks that k·G is on the curve and that s·k = z + r·d before a signature leaves it. The tables of docs/performance.md, "The count of 2026-10-30", count the tree with that entry, and "What changed since 2026-10-25" gives its N2 cost. On
the M1 Pro, Apple clang 21 at `-O2`, `proc_pid_rusage` over
2,000 calls of a program that signs with the RFC 6979 key gives these counts of one signature:

| M1 Pro, instructions of one P-256 signature | before entry 153 | RFC 6979 with both checks | hedged with both checks |
| --- | --- | --- | --- |
| host object, `0xe7` | 172,683 | 179,127 | 179,944 |
| host object, `0x05` | 332,936 | 339,208 | 352,127 |
| host object, `0x01` | 16,288,929 | 16,314,992 | 16,332,321 |
| device object, `WIDEMUL=native` | 5,491,941 | 5,501,123 | 5,512,328 |
| device object, the 16x16 decomposition | 16,290,539 | 16,319,254 | 16,327,462 |

- The two checks add about 6,400 instructions on the wide field, which a host session that
  states its multiply runs, and 9,000 to 29,000 on the 32-bit field: two squares and a product
  for the curve equation, two scalar products for s·k and r·d. A count moves by up to 0.05% from
  one run to the next on a loaded machine, so the 16 M rows carry that much noise.
- The hedged nonce adds four SHA-256 compressions: steps d and f each hash 224 bytes where they
  hashed 97. That is about 800 instructions on the SHA-256 instructions and 13,000 on the
  portable code.
- Under `0xe7` a signature costs 1.04 times what it cost before. On the Neoverse-N2 the count
  of 2026-10-30 gives 1.03 times: 0.170 M where the count of 2026-10-25 gave 0.165 M.
- The bench's `p256_sign` row now times `p256_sign_hedged_cpu`, the server's path, over the first
  hedged vector's noise. Its CSVs keep the earlier entry's figures until the next run records
  them.

## The count of 2026-10-01

The figures were taken this way:

- The object is the issue's: c798fb8 with `RAND=session TRANSPORT=tcp-nonblocking ROLE=both
  TRUST=webpki EXPORTER=on SUITE=aesgcm AES=runtime CHACHA=vector TX_RECORD=16384 KEYLOG=off`
  and `CH_NATIVE_AES`, built by `build.zig` with Zig 0.16.0 for aarch64-linux-gnu. colibri builds
  for the CPU it runs on, so the N2 columns pass `-Dcpu=neoverse_n2`, and one column builds for
  the base armv8-a instead.
- A test server calls the object as colibri's server does (`ch_srv_tcp_init`,
  `ch_srv_tcp_in`, `ch_read`, `ch_write`, `ch_close`). An OpenSSL 3.0.13 client offers what
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
- No script wrote these figures, so `make lint-bench-numbers` checks none of them.

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
   `ch_cfg.cpu` bits: done (decision 93). Hashing took 0.78 M of the 6.95 M: the transcript and key
   schedule's 0.59 M, the nonce's 0.19 M and the signed content's 0.01 M. CBMC cannot read the
   intrinsics, so equivalence tests against the portable code hold them, as they hold the AES
   instructions. Since decision 94 the RFC 6979 nonce is the largest part of a signature: 0.24 M of
   its 0.53 M instructions on the M1 Pro, where OpenSSL's whole signature takes 0.18 M.
5. X25519 key generation from a table of multiples of the base point, as BoringSSL computes it:
   done, for a host session that states its multiply (decision 148). A clamped scalar is 64
   signed four-bit digits, and the key generation adds one entry of a 30 KiB table of multiples
   of edwards25519's base point for each, doubles four times, and maps the sum to its u. On a
   Neoverse-N2, `bench/handshake-n2.sh` counts a key generation at 132,403 instructions where the
   ladder took 393,095, and OpenSSL 3.6.4's at 227,086; the handshake under `0xe7` takes 0.883 M
   where it took 1.144 M ("What decision 148 changed", above). The table sits inside the L1 data
   cache of every core here, which decision 109 found to matter on the M1 Pro. The shared secret
   keeps the ladder.
6. A server whose suite hashes with SHA-384 stops the SHA-256 transcript, 0.08 M: done, among the
   fixes of entries 145 to 147 and 149 (above).
