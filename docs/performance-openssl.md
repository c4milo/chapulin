# chapulin beside OpenSSL

[docs/performance.md](performance.md), "chapulin beside OpenSSL", shows chapulin's speed beside
OpenSSL's as four charts, one for each CPU. This page holds the times behind the bars, the machines
that ran them, how each figure is taken, and each row's speed at every run.

## The goal

Camilo set the goal on 2026-10-03: chapulin beats OpenSSL on every primitive TLS runs, in C an
auditor can read. The table below states the goal as numbers. It has one row per primitive and three
cells per machine and compiler: chapulin's time for one operation, OpenSSL's time for it on the same
machine in the same run, and the first over the second. A ratio above 1 is a row where chapulin is
behind, and it is in bold. Work on a primitive starts from its row here, and the scripts that wrote
the row judge the change. The table holds two x86-64 CPUs, one without AVX-512 and one with AVX-512
IFMA. On the second, a host object whose caller sets `CH_CPU_AVX512_IFMA` verifies RSA on
`rsa_ifma.c` (decision 119) and runs the ChaCha20 keystream on `chacha20_avx512.c` (decision 121),
and with `CH_CPU_CONSTANT_TIME_MULTIPLY` beside it signs RSA on `rsa_ifma_sign.c` (decision 120) and
runs Poly1305 on `poly1305_ifma.c` (decision 121). One whose caller sets `CH_CPU_AVX512` beside the
VAES and AES bits runs each AES-GCM seal and open on a 512-bit kernel (decision 130). Each CPU has
two groups of cells: gcc, which CI compiles with, and the pinned clang 23, a newer clang than Zig
0.16's clang 21, which `build.zig` compiles the object with for a Zig project such as colibri.

## The charts

The four charts of [docs/performance.md](performance.md), "chapulin beside OpenSSL", draw the rows
of the table as speed, one chart for each CPU. A bar is chapulin's speed in multiples of OpenSSL's:
OpenSSL's time over chapulin's, the inverse of the table's ratio. So a bar past the dashed line at 1
is a row where chapulin is faster. A row whose OpenSSL cell times another operation has no bar.
`tools/speed_chart.py` draws the charts from the CSVs the table reads, and `make lint-bench-numbers`
fails when a committed chart is not what the CSVs draw. After a run moves a CSV, run `python3
tools/speed_chart.py` and commit its SVGs with the CSVs (decision 237).

The four history charts draw the same rows at each run since 2026-10-08, one panel for each row.
`bench/history-speed-vs-openssl.csv` holds a point for each run of each column: the speeds the bars
draw, with the CPU, the date and the tree the CSVs state. `tools/speed_chart.py` adds a point when a
run moves a column, and `make lint-bench-numbers` fails when a column's last point is not what its
CSVs give, or when a history chart is not what the file draws. The points before the history file
came from git's commits of the CSVs (`python3 tools/speed_history.py --backfill`).

![Lines of chapulin's speed in multiples of OpenSSL's at each run on the Apple M1 Pro, one panel for each row](img/speed-history-m1-pro.svg)

![Lines of chapulin's speed in multiples of OpenSSL's at each run on the AMD EPYC 7763, under gcc and clang, one panel for each row](img/speed-history-x86-64.svg)

![Lines of chapulin's speed in multiples of OpenSSL's at each run on the x86-64 CPU with AVX-512 IFMA that the last run drew, under gcc and clang, one panel for each row](img/speed-history-x86-64-avx512.svg)

![Lines of chapulin's speed in multiples of OpenSSL's at each run on an Arm Neoverse N2, under gcc and clang, one panel for each row](img/speed-history-arm64.svg)

## The table

| one operation | M1 Pro, chapulin | M1 Pro, OpenSSL | ratio | x86-64 gcc, chapulin | x86-64 gcc, OpenSSL | ratio | x86-64 clang, chapulin | x86-64 clang, OpenSSL | ratio | x86-64 AVX-512 gcc, chapulin | x86-64 AVX-512 gcc, OpenSSL | ratio | x86-64 AVX-512 clang, chapulin | x86-64 AVX-512 clang, OpenSSL | ratio | arm64 gcc, chapulin | arm64 gcc, OpenSSL | ratio | arm64 clang, chapulin | arm64 clang, OpenSSL | ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SHA-256, 16 KiB | 6.90 µs | 6.92 µs | 1.00 | 10.4 µs | 10.5 µs | 0.99 | 10.4 µs | 10.4 µs | 0.99 | 8.75 µs | 8.82 µs | 0.99 | 8.77 µs | 8.87 µs | 0.99 | 7.99 µs | 7.66 µs | **1.04** | 7.76 µs | 7.66 µs | **1.01** |
| SHA-256, 64 bytes | 71.4 ns | 147 ns | 0.49 | 114 ns | 199 ns | 0.57 | 126 ns | 195 ns | 0.64 | 98.0 ns | 136 ns | 0.72 | 100 ns | 136 ns | 0.74 | 98.7 ns | 148 ns | 0.67 | 96.4 ns | 148 ns | 0.65 |
| SHA-384, 16 KiB | 11.7 µs | 11.8 µs | 0.99 | 23.0 µs | 21.9 µs | **1.05** | 22.9 µs | 21.9 µs | **1.04** | 21.6 µs | 20.1 µs | **1.07** | 21.0 µs | 20.2 µs | **1.04** | 13.4 µs | 12.5 µs | **1.07** | 13.2 µs | 12.5 µs | **1.05** |
| SHA-384, 64 bytes | 127 ns | 186 ns | 0.69 | 233 ns | 335 ns | 0.69 | 221 ns | 335 ns | 0.66 | 208 ns | 260 ns | 0.80 | 191 ns | 261 ns | 0.73 | 154 ns | 204 ns | 0.76 | 140 ns | 204 ns | 0.69 |
| SHA3-256, 16 KiB | 18.8 µs | 18.7 µs | **1.01** | 39.9 µs | 38.6 µs | **1.04** | 40.3 µs | 38.5 µs | **1.05** | 28.9 µs | 29.8 µs | 0.97 | 28.5 µs | 29.9 µs | 0.95 | 32.4 µs | 29.7 µs | **1.09** | 30.7 µs | 29.7 µs | **1.03** |
| SHA3-256, 64 bytes | 167 ns | 341 ns | 0.49 | 364 ns | 476 ns | 0.77 | 358 ns | 478 ns | 0.75 | 240 ns | 361 ns | 0.67 | 238 ns | 362 ns | 0.66 | 311 ns | 374 ns | 0.83 | 293 ns | 374 ns | 0.78 |
| X25519 key generation | 9.97 µs | 27.3 µs | 0.37 | 15.1 µs | 34.0 µs | 0.44 | 14.1 µs | 34.1 µs | 0.41 | 10.6 µs | 25.3 µs | 0.42 | 9.99 µs | 25.4 µs | 0.39 | 14.5 µs | 23.8 µs | 0.61 | 12.7 µs | 23.8 µs | 0.53 |
| X25519 shared secret | 27.7 µs | 28.4 µs | 0.98 | 35.1 µs | 35.2 µs | 1.00 | 33.5 µs | 35.1 µs | 0.95 | 26.6 µs | 26.9 µs | 0.99 | 25.3 µs | 27.0 µs | 0.94 | 36.5 µs | 37.4 µs | 0.98 | 39.1 µs | 37.4 µs | **1.04** |
| P-256 key generation | 8.72 µs | 9.45 µs | 0.92 | 11.8 µs | 12.3 µs | 0.96 | 11.4 µs | 12.4 µs | 0.92 | 9.52 µs | 9.52 µs | 1.00 | 9.48 µs | 9.57 µs | 0.99 | 12.8 µs | 10.5 µs | **1.21** | 11.0 µs | 10.5 µs | **1.04** |
| P-256 shared secret | 33.5 µs | 40.8 µs | 0.82 | 50.5 µs | 51.6 µs | 0.98 | 47.5 µs | 51.6 µs | 0.92 | 38.0 µs | 46.2 µs | 0.82 | 36.5 µs | 46.3 µs | 0.79 | 51.1 µs | 47.4 µs | **1.08** | 43.3 µs | 47.4 µs | 0.91 |
| ECDSA P-256 sign | 13.8 µs | 17.8 µs | 0.77 | 19.3 µs | 22.1 µs | 0.87 | 18.5 µs | 22.1 µs | 0.84 | 15.5 µs | 18.4 µs | 0.84 | 15.3 µs | 18.3 µs | 0.84 | 19.8 µs | 18.9 µs | **1.05** | 16.7 µs | 18.9 µs | 0.88 |
| ECDSA P-256 verify | 36.9 µs | 53.6 µs | 0.69 | 54.5 µs | 67.6 µs | 0.81 | 52.1 µs | 67.5 µs | 0.77 | 41.8 µs | 59.7 µs | 0.70 | 40.3 µs | 59.7 µs | 0.68 | 54.5 µs | 61.5 µs | 0.89 | 46.5 µs | 61.5 µs | 0.76 |
| ECDSA P-384 verify | 269 µs | 477 µs | 0.56 | 464 µs | 752 µs | 0.62 | 365 µs | 741 µs | 0.49 | 400 µs | 478 µs | 0.84 | 262 µs | 478 µs | 0.55 | 357 µs | 637 µs | 0.56 | 344 µs | 637 µs | 0.54 |
| RSA-2048 PSS sign | 653 µs | 549 µs, PKCS#1 v1.5 sign | — | 1.01 ms | 660 µs, PKCS#1 v1.5 sign | — | 945 µs | 660 µs, PKCS#1 v1.5 sign | — | 269 µs | 260 µs, PKCS#1 v1.5 sign | — | 244 µs | 254 µs, PKCS#1 v1.5 sign | — | 1.30 ms | 763 µs, PKCS#1 v1.5 sign | — | 1.01 ms | 763 µs, PKCS#1 v1.5 sign | — |
| RSA-2048 PSS verify | 17.1 µs | 14.1 µs, PKCS#1 v1.5 verify | — | 21.0 µs | 18.9 µs, PKCS#1 v1.5 verify | — | 20.4 µs | 18.9 µs, PKCS#1 v1.5 verify | — | 9.71 µs | 15.0 µs, PKCS#1 v1.5 verify | — | 9.28 µs | 15.1 µs, PKCS#1 v1.5 verify | — | 33.0 µs | 19.3 µs, PKCS#1 v1.5 verify | — | 24.0 µs | 19.3 µs, PKCS#1 v1.5 verify | — |
| RSA-2048 PKCS#1 v1.5 verify | 13.5 µs | 14.1 µs | 0.95 | 17.6 µs | 18.9 µs | 0.93 | 16.7 µs | 18.9 µs | 0.88 | 7.01 µs | 15.0 µs | 0.47 | 6.86 µs | 15.1 µs | 0.46 | 28.4 µs | 19.3 µs | **1.47** | 20.8 µs | 19.3 µs | **1.08** |
| RSA-3072 PSS sign | 1.93 ms | 1.60 ms, PKCS#1 v1.5 sign | — | 2.92 ms | 2.01 ms, PKCS#1 v1.5 sign | — | 2.75 ms | 2.01 ms, PKCS#1 v1.5 sign | — | 622 µs | 723 µs, PKCS#1 v1.5 sign | — | 579 µs | 705 µs, PKCS#1 v1.5 sign | — | 3.95 ms | 2.26 ms, PKCS#1 v1.5 sign | — | 2.95 ms | 2.26 ms, PKCS#1 v1.5 sign | — |
| RSA-3072 PSS verify | 32.8 µs | 30.1 µs, PKCS#1 v1.5 verify | — | 37.7 µs | 40.2 µs, PKCS#1 v1.5 verify | — | 36.9 µs | 40.2 µs, PKCS#1 v1.5 verify | — | 16.0 µs | 32.3 µs, PKCS#1 v1.5 verify | — | 15.8 µs | 32.3 µs, PKCS#1 v1.5 verify | — | 68.4 µs | 41.8 µs, PKCS#1 v1.5 verify | — | 47.2 µs | 41.8 µs, PKCS#1 v1.5 verify | — |
| RSA-3072 PKCS#1 v1.5 verify | 28.1 µs | 30.1 µs | 0.93 | 33.9 µs | 40.2 µs | 0.84 | 32.9 µs | 40.2 µs | 0.82 | 12.9 µs | 32.3 µs | 0.40 | 13.2 µs | 32.3 µs | 0.41 | 62.7 µs | 41.8 µs | **1.50** | 43.2 µs | 41.8 µs | **1.03** |
| ML-KEM-768 key generation | 9.21 µs | 21.5 µs | 0.43 | 15.2 µs | 38.5 µs | 0.39 | 14.6 µs | 38.6 µs | 0.38 | 12.5 µs | 29.0 µs | 0.43 | 11.5 µs | 29.0 µs | 0.40 | 21.2 µs | 29.9 µs | 0.71 | 19.1 µs | 29.9 µs | 0.64 |
| ML-KEM-768 encapsulation | 10.3 µs | 25.2 µs | 0.41 | 15.8 µs | 22.0 µs | 0.72 | 14.9 µs | 22.0 µs | 0.68 | 13.1 µs | 14.4 µs | 0.91 | 12.0 µs | 14.5 µs | 0.83 | 23.4 µs | 32.2 µs | 0.73 | 21.3 µs | 32.3 µs | 0.66 |
| ML-KEM-768 decapsulation | 11.3 µs | 18.2 µs | 0.62 | 19.1 µs | 34.2 µs | 0.56 | 17.0 µs | 34.2 µs | 0.50 | 15.6 µs | 23.4 µs | 0.67 | 13.7 µs | 23.4 µs | 0.59 | 26.1 µs | 26.8 µs | 0.97 | 23.7 µs | 26.8 µs | 0.88 |
| ML-DSA-87 key generation | 126 µs | 168 µs | 0.75 | 159 µs | 281 µs | 0.56 | 188 µs | 282 µs | 0.67 | 133 µs | 202 µs | 0.66 | 156 µs | 203 µs | 0.77 | 229 µs | 235 µs | 0.97 | 277 µs | 235 µs | **1.18** |
| ML-DSA-87 sign | 400 µs | 698 µs | 0.57 | 694 µs | 1.25 ms | 0.56 | 642 µs | 1.22 ms | 0.53 | 583 µs | 827 µs | 0.70 | 564 µs | 842 µs | 0.67 | 965 µs | 1.06 ms | 0.91 | 828 µs | 1.05 ms | 0.79 |
| ML-DSA-87 verify | 60.1 µs | 174 µs | 0.35 | 96.1 µs | 305 µs | 0.32 | 86.9 µs | 305 µs | 0.28 | 85.4 µs | 215 µs | 0.40 | 79.2 µs | 215 µs | 0.37 | 157 µs | 256 µs | 0.61 | 147 µs | 256 µs | 0.57 |
| AES-128-GCM, the key set and one 16 KiB record sealed | 2.01 µs | 2.06 µs | 0.97 | 2.85 µs | 4.07 µs | 0.70 | 2.49 µs | 4.07 µs | 0.61 | 939 ns | 952 ns | 0.99 | 901 ns | 946 ns | 0.95 | 3.63 µs | 3.72 µs | 0.98 | 3.63 µs | 3.72 µs | 0.98 |
| AES-128-GCM, the key set and one 16 KiB record opened | 2.00 µs | 2.08 µs | 0.96 | 2.78 µs | 4.11 µs | 0.68 | 2.49 µs | 4.12 µs | 0.61 | 937 ns | 966 ns | 0.97 | 897 ns | 968 ns | 0.93 | 3.61 µs | 3.82 µs | 0.94 | 3.64 µs | 3.82 µs | 0.95 |
| AES-256-GCM, the key set and one 16 KiB record sealed | 2.42 µs | 2.50 µs | 0.97 | 3.19 µs | 4.38 µs | 0.73 | 2.80 µs | 4.37 µs | 0.64 | 1.09 µs | 1.10 µs | 1.00 | 1.08 µs | 1.09 µs | 0.99 | 4.18 µs | 4.34 µs | 0.96 | 4.23 µs | 4.30 µs | 0.98 |
| AES-256-GCM, the key set and one 16 KiB record opened | 2.35 µs | 2.48 µs | 0.95 | 3.12 µs | 4.42 µs | 0.70 | 2.82 µs | 4.42 µs | 0.64 | 1.08 µs | 1.17 µs | 0.92 | 1.08 µs | 1.14 µs | 0.95 | 4.21 µs | 4.34 µs | 0.97 | 4.22 µs | 4.34 µs | 0.97 |
| ChaCha20-Poly1305, 16 KiB encrypted and hashed, no tag | 8.96 µs | 9.18 µs | 0.98 | 6.45 µs | 7.47 µs | 0.86 | 6.60 µs | 7.46 µs | 0.88 | 3.24 µs | 3.70 µs | 0.87 | 3.40 µs | 3.68 µs | 0.92 | 12.2 µs | 13.0 µs | 0.94 | 12.4 µs | 13.0 µs | 0.95 |
| ChaCha20-Poly1305, 16 KiB hashed and decrypted, no tag | 8.95 µs | 9.19 µs | 0.97 | 6.39 µs | 7.47 µs | 0.85 | 6.58 µs | 7.49 µs | 0.88 | 3.25 µs | 3.73 µs | 0.87 | 3.38 µs | 3.67 µs | 0.92 | 12.3 µs | 13.0 µs | 0.94 | 12.4 µs | 13.0 µs | 0.96 |

## The machines

The machines, as the CSV headers state them:

- **M1 Pro**: Apple M1 Pro, Darwin 25.6.0, Apple clang version 21.0.0 (clang-2100.3.34.2), OpenSSL 3.6.5, `ch_cfg.cpu 0xe7`, and `0x83` for the AES-GCM rows and `0x7` for the ChaCha20-Poly1305 rows, as `CH_CPU_CONSTANT_TIME_SHA3` runs AES-GCM's passes with EOR3 (decision 158) and no other hash bit changes a record; one-minute load average 2.90 before the primitives' run and 3.09 after it, and 3.14 and 3.55 around the AEAD rows' run
- **x86-64 gcc**: AMD EPYC 7763 64-Core Processor, Linux 7.0.0-1017-azure, gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, OpenSSL 3.6.5, `ch_cfg.cpu 0xc3f`, and `0x1f` for the AEAD rows, which no hash bit changes; one-minute load average 1.03 before the primitives' run and 1.21 after it, and 0.81 and 1.03 around the AEAD rows' run
- **x86-64 clang**: AMD EPYC 7763 64-Core Processor, Linux 7.0.0-1017-azure, Ubuntu clang version 23.1.6 (++20261116013850+5b10d2d74929-1~exp1~20261116133903.98), OpenSSL 3.6.5, `ch_cfg.cpu 0xc3f`, and `0x1f` for the AEAD rows, which no hash bit changes; one-minute load average 1.11 before the primitives' run and 1.03 after it, and 1.20 and 1.10 around the AEAD rows' run
- **x86-64 AVX-512 gcc**: Intel(R) Xeon(R) 6975P-C, Linux 7.0.0-1014-aws, gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, OpenSSL 3.6.5, `ch_cfg.cpu 0xf3f`, and `0x31f` for the AES-GCM rows and `0x11f` for the ChaCha20-Poly1305 rows, which no hash bit changes; one-minute load average 1.00 before the primitives' run and 1.10 after it, and 1.01 and 1.00 around the AEAD rows' run
- **x86-64 AVX-512 clang**: Intel(R) Xeon(R) 6975P-C, Linux 7.0.0-1014-aws, Ubuntu clang version 23.1.6 (++20261116013850+5b10d2d74929-1~exp1~20261116133903.98), OpenSSL 3.6.5, `ch_cfg.cpu 0xf3f`, and `0x31f` for the AES-GCM rows and `0x11f` for the ChaCha20-Poly1305 rows, which no hash bit changes; one-minute load average 1.00 before the primitives' run and 1.00 after it, and 1.07 and 1.00 around the AEAD rows' run
- **arm64 gcc**: ARM Neoverse-N2, Linux 7.0.0-1019-azure, gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, OpenSSL 3.6.5, `ch_cfg.cpu 0x3067`, and `0x2003` for the AES-GCM rows and `0x1007` for the ChaCha20-Poly1305 rows, as `CH_CPU_CONSTANT_TIME_EOR3` runs AES-GCM's passes with EOR3 (decisions 158 and 244) and `CH_CPU_SVE2` ChaCha20's on its SVE2 copy (decision 242), and no other hash bit changes a record; one-minute load average 1.14 before the primitives' run and 1.15 after it, and 0.72 and 1.06 around the AEAD rows' run
- **arm64 clang**: ARM Neoverse-N2, Linux 7.0.0-1019-azure, Ubuntu clang version 23.1.6 (++20261116013916+5b10d2d74929-1~exp1~20261116133927.96), OpenSSL 3.6.5, `ch_cfg.cpu 0x3067`, and `0x2003` for the AES-GCM rows and `0x1007` for the ChaCha20-Poly1305 rows, as `CH_CPU_CONSTANT_TIME_EOR3` runs AES-GCM's passes with EOR3 (decisions 158 and 244) and `CH_CPU_SVE2` ChaCha20's on its SVE2 copy (decision 242), and no other hash bit changes a record; one-minute load average 1.18 before the primitives' run and 1.20 after it, and 1.10 and 1.10 around the AEAD rows' run

[`bench/primitives.sh`](../bench/primitives.sh) (`make bench-primitives`) writes the rows above the
AEADs to a CSV for each machine and compiler, such as
[`bench/results-primitives-darwin-arm64-clang.csv`](../bench/results-primitives-darwin-arm64-clang.csv),
and [`bench/record.sh`](../bench/record.sh) writes the six AEAD rows to the record CSVs of
[docs/performance.md](performance.md), "Where a record's time goes".
[`tools/bench_scoreboard.py`](../tools/bench_scoreboard.py) renders the table and the machines'
lines from those files, and `make lint-bench-numbers` fails when this document disagrees with them.

## How the figures are taken

- **chapulin.** Every timed program is a host object, and each row runs under the `ch_cfg.cpu`
  value a caller on that CPU states, every bit the CPU has (decision 89). The machine's line above
  names the value. The CSV also holds each row under `ch_cfg.cpu 0x1`, `CH_CPU_PROBED` alone, which
  a caller that states nothing runs: the 16x16 multiply decomposition and the 16-word X25519 field,
  which a device object runs too. [`bench/notes-primitives.md`](../bench/notes-primitives.md) reads
  those rows and the handshakes'.
- **OpenSSL.** `openssl speed -mr -seconds 1`, on the binary `test/e2e.sh` takes
  ([`bench/openssl.sh`](../bench/openssl.sh)). Each machine's line names its version. The ML-KEM-768
  encapsulation row is [`bench/openssl_kem.c`](../bench/openssl_kem.c)'s, built against that
  binary's library: each operation makes a key object from the 1,184 bytes of an encapsulation key
  and encapsulates to it, as a TLS server does with the key the client sends (decision 239). A
  column recorded before that decision holds `openssl speed`'s row, which reuses one key object.
- **The clock.** `openssl speed` divides the operations it ran by the user CPU time its process
  took. `bench/primitives.c` times each sample on its thread's CPU clock. So neither side counts
  the time a loaded machine gave to other work. The load in a machine's line can still move both
  through the caches and the cores they share with that work, and on an M1 Pro through a run that
  macOS places on efficiency cores, which run the same code in about three times the time.
  `bench/primitives.sh` warns of a row whose runs differ by more than half, and the CSV's
  `run_spread_pct` states each row's spread. The AEAD rows are `bench/record.c`'s, batches of 1 ms
  on the wall clock.
- **The runs.** Each figure is the median of five runs. One run of `bench/primitives.sh` is every
  chapulin row and then one second of each OpenSSL row, so the two sides of a ratio are never more
  than a run apart.
- **Instructions.** On macOS the primitives CSV also holds the instructions each chapulin
  operation retired, as `/usr/bin/time -l` counts them for a process. A count does not move with
  the machine's load, so it shows what a change did to a row where a time cannot.

## What a row compares

- **RSA.** `openssl speed` signs and verifies RSA with PKCS#1 v1.5 padding. chapulin signs PSS
  alone, so each PSS row shows OpenSSL's PKCS#1 v1.5 time and no ratio. The two PKCS#1 v1.5 verify
  rows compare one operation: chapulin checks a SHA-256 DigestInfo, and `openssl speed` a 36-byte
  value without one.
- **Key generation and encapsulation.** chapulin's calls take their random bytes as arguments, so
  its rows time no draw. OpenSSL's rows draw theirs, and its key generation also builds a key
  object. chapulin's ML-KEM-768 encapsulation reads the key's bytes and runs FIPS 203's modulus
  check at each call, as OpenSSL's row does when it makes the key object. Its decapsulation reads
  the decapsulation key's bytes at each call too, while OpenSSL's row decapsulates under the key
  object its key generation made, as a TLS client does.
- **ECDSA.** chapulin derives its nonce by RFC 6979 and signs a 32-byte digest. `openssl speed`
  draws its nonce and signs 20 bytes.
- **AES-GCM.** One operation of OpenSSL 3.6's `speed -aead` sets the key and the IV, hashes 13 bytes
  of associated data, encrypts 16,384 bytes and computes the tag. chapulin's row is the operation
  `record.c` runs for every record: it expands the key, seals 16,385 bytes with the record's 5-byte
  header as associated data, and wipes the expanded key. On arm64 `bench/record.sh` times AES-GCM
  under `ch_cfg.cpu 0x3`, and the multiply bit changes no AES-GCM path. Where the CPU has FEAT_SHA3
  it also times it under `0x83`, which runs the copy with EOR3 (decision 158). On the x86-64 CPU
  without AVX-512 it times AES-GCM under `0x1f`. On the one with AVX-512 it times AES-GCM under
  `0x31f`, under which `CH_CPU_AVX512` beside the VAES and AES bits runs each seal and open whole on
  the 512-bit kernel (decision 130), and `CH_CPU_AVX512_IFMA` changes no AES-GCM path.
- **ChaCha20-Poly1305.** One operation of OpenSSL 3.6's `speed -aead` is one update over 16,384
  bytes: ChaCha20 and Poly1305 over them, with no nonce, associated data or tag. chapulin's row is
  its seal or open of one record less the tag's fixed work, which is the same work on the bytes.
  [docs/performance.md](performance.md), "Where a record's time goes", has the rows for a whole
  record, for `rec_seal` and for each stage.

The bold cells of the table are the rows where chapulin takes more time than OpenSSL.
[`bench/notes-primitives.md`](../bench/notes-primitives.md), "Each machine's columns of the table
beside OpenSSL", says what each machine's columns show, why each bold row is behind, and how each
row moved from run to run.

## To record a column again

After a change to a primitive, run:

```sh
make bench-primitives              # every row above the AEADs; about nine minutes
make bench-record                  # the six AEAD rows; about a minute
python3 tools/bench_scoreboard.py  # prints the table and the machines' lines to paste here
make lint-bench-numbers
```

The four x86-64 column groups are bench.yml's `record-x86_64` job, a matrix of two jobs. Each job
runs both scripts under gcc and under the pinned clang on its own GitHub runner: one on a CPU
without AVX-512, and one, with `BENCH_MACHINE=avx512`, on a CPU with AVX-512 IFMA. A runner's CPU
model is drawn, not chosen, so each job first reads `/proc/cpuinfo` and stops when it drew the wrong
kind; `gh run rerun <run> --failed` draws again. The runners with AVX-512 IFMA are several CPU
models, and a record compares with the one before it only on the same model.
`gh workflow run bench.yml --ref <branch>` starts both jobs, and with `-f avx512_model=8573C` the
second also stops unless its model name holds that text. The CSVs the jobs keep in their
`results-linux-x86_64` and `results-linux-x86_64-avx512` artifacts,
`results-primitives-linux-x86_64[-avx512]-<compiler>.csv` and
`results-record-linux-x86_64[-avx512]-<compiler>.csv` for gcc and clang, go into `bench/`.

The two arm64 column groups are bench.yml's `record-arm64` job, which starts with the others. It
runs both scripts under gcc and the pinned clang on GitHub's `ubuntu-26.04-arm` runner, whose core
is an Arm Neoverse N2, and it stops on any other core. Its gcc is 15, which builds the SVE2 copy of
the NEON ChaCha20 (decision 242). The CSVs it keeps in its
`results-linux-arm64-n2` artifact, `results-primitives-linux-arm64-n2-<compiler>.csv` and
`results-record-linux-arm64-n2-<compiler>.csv`, go into `bench/`.
