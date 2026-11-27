# Where a record's time goes: what the record bench found

This note reads the CSVs of `make bench-record` (bench/record.sh) that
docs/performance.md, "Where a record's time goes", shows as tables. It
holds what those tables show, stage by stage, how each stage reached its
time, and the arm64 runs of decisions 158 and 161. It moved from that page
on 2026-11-27.

## What the record tables show

What the numbers show for AES-GCM:

- Counter mode runs a record's whole blocks through `gcm_hw.c`, eight blocks a pass. Each round key
  is loaded once and runs on the eight counter blocks of the pass, the eight keystream blocks are
  exclusive-ored into the data in vector registers, and the state that holds a pass's keystream
  is wiped once per call. The last partial block takes the one-block cipher. Counter mode alone,
  `gcm_counter_blocks_hw`, takes 1.5 to 1.7 µs of a 16 KiB AES-128 record, where the AES
  calls and the exclusive-or in place took 16.6 to 20.1 µs at 044a49c.
- gcc 13 at `-O2` needed `#pragma GCC unroll 8` for that. Without it, gcc left each loop over a
  pass's eight blocks rolled and kept the eight states in memory, and counter mode took 16.5 µs
  on gcc against 1.8 µs on clang (docs/performance-pitfalls.md).
- GHASH multiplies eight blocks a pass by the powers H^8 to H of the hash subkey, which each call
  computes first, and reduces once per pass. Since 88c64be every value stays in a vector register
  from the load to the reduction: three carry-less products a block in Karatsuba's form, and a
  reduction by 0xc200000000000000 on the same instruction (`ghash_vector.h`). GHASH alone takes
  1.1 to 1.4 µs of a 16 KiB record, where the one-block loop took 9.2 to 10.4 at 044a49c and the
  eight-block loop that took its sums out of the vector registers for each reduction took 2.2 to
  2.8 at 225a890.
- Since decision 234 a stored key holds those eight powers beside its schedule, and a record's
  calls read them from the session. `gcm_hw.c`'s two pass functions carry `flatten` since then,
  so each loop holds its hash under every compiler. A call computes powers only for a key that
  is not stored: a public key of QUIC, a selected 1-RTT set, and each key of a session without
  the AES bit. Decision 234's tables hold a record's instructions and times before it and after
  it. The record tables of docs/performance.md are runs from before it.
- clang's GHASH is no longer the slower one: 1.1 µs against gcc's 1.4. clang loaded each power of
  H through two general registers; the powers now come from `ghash_state` in one vector load each,
  a volatile read that also keeps the compilers from copying them to stack slots the wipe does not
  clear (INV-17).
- The seal runs its whole passes through `gcm_seal_passes_hw` (c91e2f3). Each pass computes its
  keystream, writes its ciphertext and then hashes the pass before, whose GHASH waits on no AES
  round of this one, so the core runs one pass's AES rounds beside the other's carry-less
  multiplies. On the VM the loop takes 2.5 µs of a 16 KiB AES-128 record, where counter mode and
  GHASH alone take 2.8 to 3.1 one after the other.
- The open runs the same loop the other way round, `gcm_open_passes_hw` (01ba8fc): iteration p
  hashes pass p and decrypts pass p - 1, and the tag is compared once the plaintext is written,
  which a mismatch then wipes (decision 85). On the VM the loop takes 2.4 to 2.5 µs of a 16 KiB
  AES-128 record.
- `rec_seal` copies the caller's plaintext with one `memmove`. gcc 13 did not vectorize the byte
  loop that did it before, and ran it one byte at a time: 5.9 µs, three fifths of gcc's AES-GCM
  seal once counter mode and GHASH were fast. The record layer's own work is now 0.2 to 0.7 µs of
  a 16 KiB AES-GCM record and 0.3 to 0.4 µs of a ChaCha20-Poly1305 one on both compilers.
- Each GHASH call wipes the part of its state it wrote: H, the powers it computed and a pass's sums.
  The tag's fixed work, one GHASH call over the associated data and one multiply for the block of
  lengths, each of which computes one power, takes 42 to 56 ns, where it took 150 to 169 while
  `ct_wipe` stored one byte at a time (decision 91) and 240 to 300 at 225a890; a 1 KiB seal takes
  217 to 584 ns. At 1 KiB the key expansion makes most of the record layer's share. The wipe of the
  expanded key that `record.c` runs for every record takes 4 to 14 ns of it, where it took 91 to 93.
- Measured one commit at a time, the three commits for
  [#184](https://github.com/c4milo/chapulin/issues/184) took the 16 KiB seal from 26.8, 27.6 and
  36.3 µs at 044a49c to 11.5, 12.9 and 17.6 µs with counter mode, to 4.8, 5.4 and 10.0 µs with
  GHASH, and to 4.9, 5.3 and 4.9 µs with the `memmove`. Three more, in paired runs of the four
  trees, took it from 4.8, 5.2 and 5.0 µs at 225a890 to 3.5, 3.8 and 4.0 µs with GHASH in vector
  registers (88c64be) and to 3.0, 3.5 and 3.5 µs with the one-pass seal (c91e2f3); the one-pass
  open (01ba8fc) took the 16 KiB open from 3.3, 3.3 and 3.6 µs to 2.9, 3.2 and 3.2 µs. In paired
  runs of a104a3e and the tree after it, the `memset` wipe (decision 91) took the 16 KiB seal from
  3.1, 3.6 and 3.7 µs to 2.7, 3.5 and 3.3 µs, and the 16 KiB open from 3.0, 3.4 and 3.3 µs to 2.6,
  3.0 and 2.9 µs.
- The seal now takes 2.4, 3.1 and 3.2 µs, and its AEAD alone 2.1, 2.6 and 2.5 µs. The open takes
  2.1, 2.8 and 2.8 µs, and its AEAD alone 2.1, 2.6 and 2.5 µs. Against 044a49c the seal takes 0.09,
  0.11 and 0.09 of its time, and on the VM the open 0.13 and 0.09.
- Against OpenSSL on the same machine, operation for operation: on the VM, where OpenSSL 3.0.13
  seals under a key set before the loop, the AEAD's seal takes 0.91 and 0.92 times its time, and the
  open 0.91 and 0.87 times. On macOS, where OpenSSL 3.6.5 sets the key for every operation, the AEAD
  under a key expanded for the record takes 2.2 µs to seal and to open under `0x3`, 1.05 and 1.04
  times OpenSSL's 2.1, and 0.97 and 0.96 of it under `0x83` (docs/performance-openssl.md). Of
  chapulin's time, `aes_traffic_key_init` takes 10 ns, and 11 ns for AES-256, where it took 202 and
  255 ns before decision 158. Over 16 bytes the seal takes 88 ns, key and tag included, where
  OpenSSL's whole operation takes 159 ns.

For ChaCha20-Poly1305:

- A session without the multiply bit, `ch_cfg.cpu 0x3`, runs Poly1305 on the 16x16 decomposition
  `ct.h` builds, and there Poly1305 is the largest stage: 76% to 83% of the record. colibri's
  `cpu_of` states the bit on arm64 (docs/performance.md, "Where a server handshake's instructions go"), so its sessions there do
  not run that Poly1305.
- ChaCha20 runs the keystream and the exclusive-or in 6.9 to 9.0 µs on the vector path, on both
  compilers. `chacha20.c`'s portable loop, which a device object runs, took 34 to 35 µs here at
  a104a3e, when a build without `CHACHA=vector` ran it: 25.2 to 29.0 for the block function and 6.3
  to 8.9 for its exclusive-or, which ran one byte at a time in place. Since 97826ba a NEON pass
  computes two groups of four blocks side by side and XORs the keystream into the data from the
  registers that computed it (decision 86); a pass of one group took 13.6 to 14.6 µs. On clang the
  exclusive-or adds 0.4 to 0.6 µs to the keystream alone, whose row stores each pass's keystream to
  a buffer; under gcc 13 that row takes 0.4 to 0.5 µs longer than the whole, so the difference
  measures nothing there.
- With the multiply bit, `ch_cfg.cpu 0x7`, a session runs the vector Poly1305 too (decision 83),
  which takes Poly1305 over the ciphertext from 28.1 to 45.6 µs on the decomposition to 2.0 to 2.9
  µs. `rec_seal` then takes 9.4 to 12.3 µs, 22% to 31% of the 0x3 record's time, and a 1 KiB one 31%
  to 42%. ChaCha20 is 70% to 74% of the record, and Poly1305 22% to 25%. `rec_open` takes 9.1 to
  11.9 µs.
- Against OpenSSL on the same machine, operation for operation: on the VM, where OpenSSL 3.0.13
  seals a whole record, the AEAD's seal takes 1.13 and 1.18 times its time and the open 1.12 and
  1.19 times, and `rec_seal` and `rec_open` 1.16 and 1.22, and 1.12 and 1.19. On macOS, where
  OpenSSL 3.6.5 runs ChaCha20 and Poly1305 over the bytes and nothing else, the seal and the open
  less their tag's fixed work take 9.0 and 8.9 µs, 0.98 and 0.97 of OpenSSL's 9.2.
- A one-pass seal and open did not pay. In a scratch timing loop on the three columns' compilers, a
  seal that runs ChaCha20 over a chunk and then Poly1305 over the ciphertext it just wrote, and an
  open that hashes each chunk and then decrypts it, took no less time than two passes at any chunk
  from 512 bytes to 16 KiB. A 16 KiB record stays in the M1 Pro's 128 KiB L1 data cache between the
  passes, so the second pass reads it from that cache too, and every chunk calls the vector
  Poly1305 again, which computes and wipes the powers of r on each call: in chunks of 1 KiB, the
  seal took 13.8 µs on macOS where two passes took 11.8. With the powers computed once a record,
  every chunk took from 2% less to 3% more than two passes. So the seal keeps its two passes, and
  the open still compares the tag before it decrypts, which decision 85 allows.

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
   shorter one: 2.2 to 2.6 µs of a 16 KiB AES-128 record, where the two alone take 2.8 to 3.1. The
   open's loop needed the open to decrypt before it compares the tag, and to wipe the plaintext
   when the tag does not match (decision 85).

For [#181](https://github.com/c4milo/chapulin/issues/181), the numbers supported the vector path for
ChaCha20 first, because the block function and the in-place exclusive-or were half of the record on
clang with Poly1305 on the decomposition and more than two thirds of it on the native multiply, and
decision 82 added it. Its two paired runs on each platform agreed: the vector `rec_seal` took 0.71,
0.68 and 0.78 of the portable one's time in the three columns in the second, and 0.78, 0.70 and 0.78
in the first. In the last runs that timed both, at a104a3e with decision 86's two groups a pass, it
took 0.62, 0.60 and 0.68. Most of what remained of that record was Poly1305 on the multiply
decomposition: the same loop on the native multiply ran in about a third of the time. A vector
Poly1305 needs a widening multiply too, so it needs the same statement about that multiply's timing,
and decision 83 added one under it: `CHACHA=vector` with `WIDEMUL=native`, where Poly1305 was most
of what the vector ChaCha20 left. Paired runs agree on each platform, two in the Linux VM and three
on macOS, where the second ran at a load average of 44 to 78. In the last pair on each, that build's
`rec_seal` took 0.66, 0.66 and 0.69 of its time before the change in the three columns; the earlier
pairs gave 0.66 and 0.66 on macOS, 0.57 on the VM's clang and 0.65 on gcc 13. Those pairs came
before each call of the vector Poly1305 began to end with a wipe of the powers of r it computed, one
`ct_wipe` of 208 bytes on NEON and 352 on SSE2. The runs the tables now hold measure the code with
that wipe, and the 128-byte threshold still rests on decision 83's scratch timing. Under `ch_cfg.cpu
0x7` the vector Poly1305 takes 2.0 and 2.8 µs on macOS and gcc 13, and 2.9 µs on the VM's clang. On
that compiler the figure moves with where the linker places the function. It took 4.7 µs in the
bench build the tables held at d10b6e2, and 3.0 µs in one whose `aes_hw.c` differed in one function;
that build with `-falign-functions=64` took 2.8 µs (docs/performance-pitfalls.md). It took 3.0 µs in the runs
at 97826ba, 4.8 µs again at a104a3e, before decision 91 and after it alike, and 4.6 µs in this
tree's bench an hour before the tables' run, when `bench/record_rows.c` lacked its two
`seal_aes_gcm` rows.

ChaCha20 was then the larger stage of that build, 80% of its record, and decision 86 runs two groups
of four blocks a pass on NEON, because one group left the vector units waiting on each quarter
round's chain of operations. In paired runs, that build's 16 KiB `rec_seal` took 0.68, 0.70 and 0.69
of its time before the change in the three columns, and 0.67, 0.64 and 0.67 in the first pair. The
two builds that ran the portable ChaCha20 then did not move beyond the spread between runs: 68.1,
62.0 and 80.5 µs on the decomposition where the tables held 67.5, 60.8 and 79.0 at 9287540, and
46.3, 44.9 and 47.8 on the native multiply where they held 46.3, 44.0 and 47.0. OpenSSL's ChaCha20
alone took 7.0 µs over 16 KiB on macOS in three one-second runs of `openssl speed -evp chacha20`,
against that build's 8.5, and its whole seal took 9.4 against 11.8.

## arm64 AES-GCM beside OpenSSL

Decision 158 set the goal on 2026-10-25: on arm64, AES-GCM takes no more time than OpenSSL 3.6.4,
for both key sizes, seal and open. This section holds the numbers on a Neoverse N2, the CPU of
GitHub's `ubuntu-24.04-arm` runner. `make bench-record` ran on it under gcc 13 and the pinned clang
23, beside the pinned OpenSSL 3.6.4. The "161" rows time the passes of decision 161, and their CSVs
are `bench/results-record-linux-arm64-n2-gcc.csv` and
`bench/results-record-linux-arm64-n2-clang.csv` as commit b8eb7bbb holds them. The bench workflow's
`record-arm64` job now writes those two files for the table beside OpenSSL
(docs/performance-openssl.md). The "before" run timed the tree of 54a05fd1, and the "after" run the
tree of decision 158, on the same runner type. Their CSVs are not in the tree.

Each cell is chapulin's time for one record over OpenSSL's in the same run: `seal_aes_gcm` or
`open_aes_gcm`, which expand the key, run the AEAD with 5 bytes of associated data and wipe the
key, against one operation of `openssl speed -aead`, which sets the key and runs the AEAD with 13
bytes of associated data. `0x3` is a session with the AES bit, and `0x83` adds
`CH_CPU_CONSTANT_TIME_SHA3`, which runs `gcm_arm64_eor3.c`'s copy with EOR3. A ratio above 1 is in
bold.

| N2, seal / open | 16 B | 1 KiB | 16 KiB |
|---|---|---|---|
| AES-128, clang, before | **1.68** / **1.29** | **1.44** / **1.29** | **1.18** / **1.15** |
| AES-128, clang, after, `0x3` | 0.72 / 0.58 | 0.97 / 0.85 | **1.02** / 0.99 |
| AES-128, clang, after, `0x83` | 0.75 / 0.59 | 0.94 / 0.82 | 0.98 / 0.94 |
| AES-128, clang, 161, `0x3` | 0.72 / 0.57 | 0.96 / 0.85 | 1.00 / 0.97 |
| AES-128, clang, 161, `0x83` | 0.74 / 0.59 | 0.94 / 0.82 | 0.97 / 0.94 |
| AES-128, gcc, before | **2.74** / **2.15** | **1.97** / **1.76** | **1.27** / **1.25** |
| AES-128, gcc, after, `0x3` | 0.73 / 0.60 | 0.97 / 0.87 | **1.02** / 0.99 |
| AES-128, gcc, after, `0x83` | 0.74 / 0.60 | 0.94 / 0.85 | 0.99 / 0.96 |
| AES-128, gcc, 161, `0x3` | 0.72 / 0.59 | 0.96 / 0.86 | 1.00 / 0.97 |
| AES-128, gcc, 161, `0x83` | 0.73 / 0.61 | 0.94 / 0.84 | 0.97 / 0.93 |
| AES-256, clang, before | **2.04** / **1.59** | **1.56** / **1.41** | **1.17** / **1.17** |
| AES-256, clang, after, `0x3` | 0.72 / 0.59 | 0.97 / 0.88 | **1.01** / **1.02** |
| AES-256, clang, after, `0x83` | 0.75 / 0.61 | 0.95 / 0.86 | 0.98 / 0.97 |
| AES-256, clang, 161, `0x3` | 0.72 / 0.58 | 0.96 / 0.87 | 1.00 / **1.01** |
| AES-256, clang, 161, `0x83` | 0.74 / 0.61 | 0.94 / 0.86 | 0.96 / 0.96 |
| AES-256, gcc, before | **3.12** / **2.48** | **2.05** / **1.89** | **1.24** / **1.26** |
| AES-256, gcc, after, `0x3` | 0.75 / 0.63 | 0.99 / 0.90 | **1.01** / **1.01** |
| AES-256, gcc, after, `0x83` | 0.76 / 0.63 | 0.96 / 0.88 | 0.98 / 0.99 |
| AES-256, gcc, 161, `0x3` | 0.74 / 0.61 | 0.97 / 0.90 | 0.99 / 1.00 |
| AES-256, gcc, 161, `0x83` | 0.75 / 0.63 | 0.95 / 0.87 | 0.98 / 0.99 |

The times behind the "after" rows, in ns, under clang and `0x83`: AES-128 seals 16 bytes in 137,
1 KiB in 384 and 16 KiB in 3,635, where OpenSSL takes 184, 410 and 3,717. AES-256 seals them in
142, 430 and 4,237, where OpenSSL takes 190, 452 and 4,342.

What the numbers show:

- The 16-byte and 1 KiB records gained the most. Before, the key expansion took 194 ns for AES-128
  and 335 ns for AES-256, and it now takes 25 ns. The steps around the passes took about 100 ns of
  a 1 KiB record, and the whole AEAD of `gcm_arm64.c` removed most of them.
- The 16 KiB records gained from the passes in assembly: 3.67 µs for AES-128's passes, where the
  compilers' code took 4.11 µs.
- Without the SHA-3 bit the 16 KiB cells take 0.99 to 1.02 of OpenSSL's time. Two exclusive-ors
  take the place of each EOR3, and the two vector pipes run the extra instructions.
- Two builds of the same tree differ by up to 3% in a 16 KiB cell, as the code's place in memory
  moves. The margins at 16 KiB under `0x83` are 1% to 6%.

The M1 Pro ran `make bench-record BENCH_MACHINE=m1` at a load average of 3.6 to 4.3, into
[`bench/results-record-darwin-arm64-m1-clang.csv`](../bench/results-record-darwin-arm64-m1-clang.csv),
on the passes of decision 161. Homebrew holds OpenSSL 3.5.9 on this machine, not 3.6, so the OpenSSL
figure is one operation of 3.5.9's `speed -aead`. The record tables of docs/performance.md hold the run of 2026-11-20
against OpenSSL 3.6.5, in which the AEAD of a 16 KiB record, under a key expanded for it, took 1.01
to 1.05 times OpenSSL's time under `0x3` and 0.95 to 0.97 of it under `0x83`.

| M1 Pro, Apple clang 21, seal / open | 16 B | 1 KiB | 16 KiB |
|---|---|---|---|
| AES-128, `0x3` | 0.63 / 0.55 | 0.93 / 0.82 | **1.04** / **1.04** |
| AES-128, `0x83` | 0.64 / 0.56 | 0.90 / 0.79 | 1.00 / 0.97 |
| AES-256, `0x3` | 0.62 / 0.53 | 0.92 / 0.82 | **1.01** / 1.00 |
| AES-256, `0x83` | 0.63 / 0.54 | 0.89 / 0.80 | 0.97 / 0.96 |

What the numbers show:

- Under `0x83` no cell takes more time than OpenSSL's. Before decision 161 the 16 KiB cells took
  1.00 to 1.03 of it, and under `0x3` 1.06 to 1.10. The rows of this run spread by 6%. In runs
  that set the code before and after decision 161 in turn, a 16 KiB record took 4.4% to 7.7% less
  time under `0x83` and 2.6% to 4.5% less under `0x3`.
- The M1 decodes the passes' instructions slower than its four vector pipes run them. Decision
  161 took 23 instructions out of each AES-128 pass. A first step that took 9 out gained about one
  cycle a pass.
- OpenSSL 3.5.9 runs its `unroll8_eor3` kernel on this CPU, so the `0x83` row compares two
  kernels that sum three values with EOR3.
- The `0x3` rows compare passes without EOR3 against OpenSSL's kernel with EOR3. On a CPU
  without FEAT_SHA3, OpenSSL runs its kernel of four blocks a pass, which has no EOR3.
  `OPENSSL_armcap=0x67d` clears OpenSSL's SHA-3 and EOR3 bits from this CPU's `0x987d`, and
  OpenSSL then runs that kernel. On 2026-10-29, at a load average of 3.9 to 5.7, four rounds
  timed the bench binary under `0x3` and `speed -aead` in turn, at 16 KiB. The medians:

  | M1 Pro, 16 KiB, ns | `0x3` | OpenSSL, `0x67d` | OpenSSL, `0x987d` | `0x3` / `0x67d` |
  |---|---|---|---|---|
  | AES-128 seal | 2,209 | 2,648 | 2,110 | 0.83 |
  | AES-128 open | 2,214 | 2,785 | 2,149 | 0.80 |
  | AES-256 seal | 2,578 | 3,059 | 2,525 | 0.84 |
  | AES-256 open | 2,544 | 2,996 | 2,514 | 0.85 |

  So a session without the SHA-3 bit takes 0.80 to 0.85 of the time OpenSSL takes without
  EOR3. Each M1 has FEAT_SHA3, so a caller on this CPU can state `0x83`.
- On the N2 decision 161 took up to 2.6% off the 16 KiB cells under both compilers. The 16-byte
  and 1 KiB cells took from 6.4% less to 1.1% more time. Its rows are the "161" rows of the N2 table.
