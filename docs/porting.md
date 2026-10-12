# Porting chapulin to a platform

chapulin makes no assumption about your core beyond C11, libc and a `size_t`
of at least 32 bits. `ct.h` refuses a build with a narrower `size_t`, such as
one for a 16-bit MSP430, because counts the code keeps in a `size_t` would
truncate. That leaves you four decisions. Three have safe defaults you can
take without reading further; the fourth, entropy, has no default and cannot
have one.

This document covers what you decide and, more usefully, what you can check.
Every claim below is something you can reproduce on your own target rather than
take on trust. Writing it turned up a case where the mitigation was defeated by
an optimiser on a target no lint covered, which is the reason the checking
section exists.

## 1. The widening multiply

A multiply whose duration depends on its operands leaks the operands. chapulin
multiplies secrets in three modules: `poly1305.c` (the one-time key times the
accumulator), `x25519.c` (the ladder, driven by the secret scalar) and
`mlkem_poly.c` (polynomials derived from the shared secret).

Two different hazards, with different answers.

**Your core has no hardware multiplier.** The compiler turns every `*` into a
call to its runtime library, and those routines loop once per multiplier bit and
add only where a bit is set — the iteration count is the operand's bit length
and the add count is its Hamming weight. `softmul.c` handles this with no action
from you: it defines `__mulsi3` and `__muldi3`, the names the ABI emits, so the
linker resolves them in-tree instead of pulling the branching versions.

One measured defect, now repaired. The Bootlin riscv32 gcc 14.3 at `-Os` for
rv32ic rewrote the mask select in `softmul.c`'s `__muldi3`, `a & (0 - bit)`,
as `a * bit`, and on a core with no multiplier that 64-bit product is a call
to `__muldi3` from inside `__muldi3`: the routine never returned. At `-O2` it
kept the mask. The mask is now the bit shifted to the top and
arithmetic-shifted back down, a form gcc keeps at `-O1`, `-O2`, `-O3` and
`-Os`, and the rv32ic spec of `lint-wide-multiply-gcc` (below) counts the
calls to `__muldi3` per file under that gcc and holds `softmul.c` at zero.
`lint-runtime-symbols` measures clang, which keeps either mask form. If you
ship a compiler neither lint measures, run the lint with it, or read
`softmul.o`'s disassembly for a call to its own name before you trust it.

**Your core has a multiplier whose timing you cannot document.** This is the
default and needs no flag. `ct.h` builds every widening product from four 16x16
pieces. Measured, the pinned handshake's crypto costs 18% more on mips32r2, and
the decomposition is 2.2 kB of flash; the Speed and flash section of
[`docs/performance.md`](performance.md) has every target's figures.

**Your core's multiply is documented constant-time.** Pass
`-DCH_NATIVE_WIDEMUL` and take the speed back. Do this only with a vendor
statement in hand — RISC-V's Zkt, Arm's FEAT_DIT, Intel's DOITM. Those
extensions exist because the base architectures do not promise it, which is why
`ct.h` names no architecture as exempt: no preprocessor macro carries the claim,
and clang defines no `__ARM_FEATURE_DIT` even at `-march=armv8.4-a+dit`.

`-DCH_CT_WIDEMUL` forces the decomposition and beats `-DCH_NATIVE_WIDEMUL` when
both are set.

**Your program runs on an arm64 or x86-64 host.** A `TRUST=webpki` client,
`ROLE=server` and `ROLE=both` build a host object there, which holds both
multiplies and takes neither flag above (decisions 87 and 89). Set
`CH_CPU_CONSTANT_TIME_MULTIPLY` in `ch_cfg.cpu` for a session whose thread's
multiply runs in constant time: on arm64 a core with FEAT_DIT where the thread
has set PSTATE.DIT, on x86-64 a part in Intel's DOIT list where the operating
system has set DOITM. Leave it clear otherwise. The object runs the native
multiply for a session with the bit and the decomposition for one without it, so
one object serves CPUs and thread modes that differ. Nothing in this tree sets
either mode or reads it.

The same bit picks the X25519 field. A host object holds a second field of five
51-bit words, `x25519_wide.c`, whose products are 64x64->128 multiplies, beside
the 16-word field every object holds. A session with the bit runs the wide
field, and one without it the 16-word field on the decomposition, so the bit
states the multiply at both widths: Arm's and Intel's lists name both. No build
variable chooses the field, and a device object, a 64-bit one among them, holds
the 16-word field alone (decisions 52 and 89).

The bit picks P-256's arithmetic the same way. A host object holds a field and a
scalar of four 64-bit words, `p256_wide_field.c` and `p256_wide_scalar.c`, with
the point arithmetic over them, beside the eight 32-bit words of `p256_field.c`
and `p256_scalar.c` that every object with the curve holds. A session with the
bit signs and exchanges keys on the 64-bit words, and one without it on the
32-bit words over the decomposition (decision 94). The host object also holds a
86 KiB table of multiples of the curve's generator, constants that a session with
the bit reads for a signature's and a key generation's multiplication, every entry
of a row at each step. A device object holds no table.

A host object computes ChaCha20 several blocks at a time in 128-bit vectors in
every session, eight on NEON on arm64 and four on SSE2 on x86-64, which every
core of those architectures has, so no bit picks the path and no build variable
chooses it (decisions 82, 86 and 89). The path needs no timing statement: it
runs adds, exclusive-ors and rotations, as the portable loop does (decision
82). A device object runs the portable loop alone.

A host session with `CH_CPU_CONSTANT_TIME_MULTIPLY` also runs Poly1305 four
blocks at a time on the vector unit's widening multiply, NEON's UMULL and UMLAL
or SSE2's PMULUDQ. The bit states that every widening multiply the session
runs, scalar or vector, runs in constant time, so the vendor statement behind
it must cover those instructions as well as the scalar multiply, and on x86-64
AVX-512 IFMA's 52-bit products, which `CH_CPU_AVX512_IFMA` runs beside the bit
(below). A session
without the bit runs the portable Poly1305 and its 16x16 decomposition
(decision 83).

On x86-64 three more bits say what the CPU has, and none states a timing.
`CH_CPU_AVX2` says the CPU has AVX2 and its operating system saves the 256-bit
registers, and it moves the ChaCha20 keystream to 256-bit vectors, eight blocks
a pass. In an object with the AES-GCM suites it also moves SHA-384's message
schedule to 256-bit registers, in `sha512_avx2.c`, for the session's transcript
and key schedule (decision 128). `CH_CPU_VAES` says the CPU also has VAES and VPCLMULQDQ on those
registers. Beside `CH_CPU_CONSTANT_TIME_AES` it moves AES-GCM's whole blocks to
them; the AES bit's statement covers those forms, and `CH_CPU_VAES` without it
runs nothing (decision 90). `CH_CPU_AVX512_IFMA` says the CPU has AVX-512F and
AVX-512 IFMA and its operating system saves the opmask and 512-bit registers;
with it a session runs RSA verification's public operation on `rsa_ifma.c`, in
digits of 52 bits, eight to a 512-bit register, for an odd modulus of 2,048
bits or more whose bit length is a multiple of 64. A session with `CH_CPU_AVX2`
and without the IFMA bit runs the same moduli on `rsa_avx2.c`, in digits of 28
bits, or 27 above 3,072 bits, four to a 256-bit register (decision 122).
`x509.c` verifies the chain links of `TRUST=ca-rsa` with `rsa_pss_verify`,
which takes no `cpu`, so they run `rsa_mont64.c` whatever the two bits say.
With `CH_CPU_AVX512_IFMA` the ChaCha20 keystream also runs sixteen blocks a pass
on `chacha20_avx512.c` in place of the AVX2 kernel, and beside
`CH_CPU_CONSTANT_TIME_MULTIPLY` the session signs with RSA on `rsa_ifma_sign.c`
and runs a Poly1305 update of 512 bytes or more on `poly1305_ifma.c` (decisions
120 and 121). Set each from your probe alone: a session whose bit names
instructions its CPU lacks faults on the first one.

Three bits state the hash instructions: `CH_CPU_CONSTANT_TIME_SHA256` on both
architectures, and `CH_CPU_CONSTANT_TIME_SHA512` and `CH_CPU_CONSTANT_TIME_SHA3`
on arm64. Each says the CPU has the instructions and states that they run in
constant time in the session's thread's mode, because a hash reads HMAC keys and
traffic secrets. A session hands its `ch_cfg.cpu` to every hash call of its
transcript, its key schedule and its record and packet keys. With the SHA-256
bit those calls run SHA-256, and HMAC, HKDF and the key schedule over it, on
the instructions, and without it on the portable code. With the SHA-512 bit an
arm64 session does the same for SHA-384, the hash of TLS_AES_256_GCM_SHA384,
and each hash follows its own bit alone. The vendor statement behind a bit must
cover the instructions `cpu_cfg.h` lists for it. A hash call that takes no
`ch_cfg.cpu`, such as a certificate's, a signature's or the DRBG's, runs no
hash instruction in any object. A host object's SHA-384 with no `ch_cfg.cpu`,
and without the SHA-512 bit on arm64 or `CH_CPU_AVX2` on x86-64, runs plain C
that needs no statement, `sha512.c` over `sha512_compress_blocks.c`, in place
of the byte loops and `sha512_compress.c` a device object runs (decision 127).
With the SHA-3 bit
an arm64 session runs SHA-3, SHAKE and ML-KEM's hashes on the SHA-3
instructions, in an object that clang compiled. In an object that gcc compiled
the bit picks nothing, because gcc writes lanes of the Keccak state to stack
slots no wipe clears (decision 99).

### Check it on your target, because the compiler can undo it

The decomposition is C, and an optimiser is free to prove one of the four
pieces zero, collapse the rest, and rebuild the instruction the decomposition
existed to avoid. It does. Measured with clang 22 at `-Os`, counting widening
multiplies in the three modules that multiply secrets:

| target | before the fix below | now |
| --- | --- | --- |
| Cortex-M0 / M3 / M4, ARMv7-A, mips32r2 | 0 | 0 |
| rv32imac | **1** | 0 |

That one was real. `mlk_compress` takes a compile-time `d`, and the two
smallest values bound its operand under 2^16 — `d=1` reaches 8320 and `d=4`
reaches 54912. The optimiser proved the operand's high half zero and emitted
`slli` then `mulhu` for the `d=1` call inlined into `mlk_poly_tomsg`, which
decodes the shared secret. `mlk_compress` now calls `ct_widemul_opaque`, which
reads its operands through `volatile` so the inference cannot be made, and
which recombines its four products with compare-carries rather than
`ct_widemul`'s ladder: LLVM's AggressiveInstCombine knows the ladder, and three
other shift-and-mask shapes, as the high word of a 32x32 product, and where
the low word is dead -- `mlk_compress` reads only the high word -- it puts the
widening multiply back, volatile operands or not. `ct.h` states both forms.

The cost is confined to that caller: `poly1305`'s block and `x25519`'s `mul`
are instruction-for-instruction unchanged, because their operands are wide by
construction and nothing in them is provably zero. A blanket barrier inside
`ct_widemul` would have cost 45% of poly1305's block on a Cortex-M3.

`make lint-wide-multiply` runs five specs under the pinned clang. Three
compile for Cortex-M3, mips32r2 and rv32imac, freestanding at `-Os`, over
every source of a device object that a secret passes through
(`CODEGEN32_SRCS` in the Makefile: the chain from `ct.c` to `tls.c`, plus
`drbg.c` and `softmul.c`). They count per file the widening multiplies, the
divisions and the calls into the compiler's 64-bit division runtime, and in
the arithmetic files under the record layer the conditional branches too
("What each compiler branches on today", below). The other two
(`WIDE64_SPECS` in the Makefile) compile for arm64 and x86-64, hosted at
`-O2`, as `make lib` compiles a host object. They compile the sources that
only a host object holds (`WIDE64_CEILING`) and a host object's copies of the
arithmetic files `WIDE64_HOST_COPIES` names, which the 32-bit specs compile
too. They count per file the divisions, the calls into the compiler's 128-bit
runtime and the conditional branches, and they read no division and no
runtime call in any file. `docs/decisions.md` 126 lists what these two specs
do not compile, the four files of the AES instructions among them. The tables
of counts below hold the 32-bit specs alone.

`make lint-wide-multiply-gcc` counts the same things in the same device
sources under gcc, which is what a firmware tree ships, and no gcc spec
compiles for a 64-bit target. Each CI lane runs it with its own toolchain;
the riscv32 lane's gcc matches two specs, rv32imac and rv32ic, and the mips
lane's matches two, at `-Os` and at `-O2`. Point it at the compiler you ship:

```bash
make lint-wide-multiply-gcc WIDEMUL_GCC=/path/to/arm-none-eabi-gcc
```

The Makefile reads the driver's `-dumpmachine` and runs the spec whose machine
prefix matches; no match fails rather than skips. For a core the list does not
carry, add a spec:

```bash
make lint-wide-multiply-gcc WIDEMUL_GCC=/path/to/my-gcc \
  WIDEMUL_SPECS='mycore:gcc:my-machine-prefix:-mcpu=mycpu,-mthumb:$(WIDEMUL_OPS_ARM):$(BRANCH_OPS_ARM)'
```

The six fields are a label; `clang` or `gcc`; the machine (clang's target
triple, or the prefix of gcc's `-dumpmachine`); the comma-separated flags that
select your core; the comma-separated tokens that count as a wide multiply or
a division on your ISA; and the comma-separated conditional-branch mnemonics
of your ISA. The Makefile holds one list of each per ISA (`WIDEMUL_OPS_ARM`
and `BRANCH_OPS_ARM`, and the mips and rv32 pairs), and a make variable
named inside the single quotes expands when the lint reads the spec. A
token counts every instruction whose mnemonic begins with it, so a
condition-code or width suffix (`umullne`, `udiveq`, `umull.w`) cannot slip
past it, and a token that begins with `__` counts every call to a runtime
routine whose name begins with it, which is where a 64-bit division goes. Both
can only over-count, and an over-count fails loudly. Run it with the compiler
and flags you actually ship, since this is a property of codegen and not of
the source; the lint passes `-Os` before the flags, so a level in the flags
field wins, which is how the mips gcc spec below runs a second time at `-O2`.
A new spec starts from the default multiply ceilings and no branch ceilings,
so the first thing it reports is the conditional-branch count of each
arithmetic file it compiles. Read every file it reports above its multiply
ceiling as the finding it is. The one public division, `ch_writable_len`'s
in tls_write.c, is the exception: a compiler that copies it into two paths,
as the mips gcc does at `-O2`, reports two, which you record for your label
with `WIDEMUL_CEILING_SPEC="mycore/tls_write.c:2"`. Record the branch counts
with
`BRANCH_CEILING="mycore/ct.c:2 mycore/sha256.c:12 ..."` once you have read
the branches and found each to be loop control.

### What each compiler emits today

Counts per file at `-Os`, and for the mips gcc at `-O2` as well, read from
the lint. Every source not listed is at zero under every compiler.

| compiler | poly1305.c | x25519.c | mlkem_poly.c | p256_scalar.c | tls_write.c |
| --- | --- | --- | --- | --- | --- |
| clang 23, Cortex-M3, mips32r2, rv32imac | 0 | 0 | 0 | 0 | 1 |
| Arm GNU gcc 15.3, Cortex-M3 | 0 | 0 | 0 | 0 | 1 |
| gcc 12.4 (Ubuntu 24.04), mips32r2 | 0 | 0 | 0 | 0 | 1 |
| gcc 12.4 (Ubuntu 24.04), mips32r2, `-O2` | 2 `madd` | 0 | 0 | 2 `madd` | 2 `divu` |
| Bootlin gcc 14.3, rv32imac | 0 | 0 | 0 | 0 | 1 |
| Bootlin gcc 14.3, rv32ic | 0 | 0 | 0 | 0 | 1 |

tls_write.c's column is the one public division, `ch_writable_len`'s: the
caller's buffer length by the length of a record. It is one division
instruction, `udiv` on Cortex-M3 and `divu` on mips32r2 and rv32imac, and on
rv32ic one call to `__udivsi3`. At `-O2` the mips gcc copies the function's
body into both arms of `record_plaintext_max`'s choice between `peer_limit`
and `CH_TX_PT`, so one arm divides by `peer_limit + REC_OVERHEAD` and the
other by `CH_TX_PT + REC_OVERHEAD`. Each path still runs one division, and
every operand is a public length.

rv32ic has no multiply or divide instruction to count, so that spec counts
the runtime routines instead: a 64-bit product is a call to `__muldi3`, which
a chapulin build resolves to `softmul.c`'s constant-time routine.
`softmul.c` itself is at zero calls to `__muldi3` there, which is what that
spec exists to hold.

sha3.c held a division until its round was written out lane by lane: `% 5`
over Keccak's lane counters, which clang lowered to one multiply-high and
each gcc to five divisions (`docs/decisions.md` 98). poly1305.c, x25519.c and
mlkem_poly.c were not always at zero under gcc. gcc rewrites
`(uint64_t)lh + hl`, a 64-bit sum of two products it can prove narrow, into
one widening multiply-accumulate, and `x & (0 - bit)` into `x * bit`, a
widening multiply by a secret bit: two `umlal` in poly1305 and in mlkem_poly
and two `umull` and two `umlal` in x25519 under the Arm gcc, one `mulhu` in
x25519 under the riscv32 gcc. The lint recorded those counts as ceilings until
`ct_widemul` moved to a recombination that never widens a product,
`ct_widemul_s` and x25519's `cswap` moved their masks to an arithmetic shift of
the sign bit (`ct_widemul_s` has held no mask since decision 125), and the
three files went to zero under every `-Os` spec
([#106](https://github.com/c4milo/chapulin/issues/106)). The violation
`test/violations/inv16-widemul-mid-widened.violation` puts the old sum back
and requires `lint-wide-multiply-gcc` to fail.

The device specs compile at `-Os`, and the mips gcc spec runs once more at
`-O2`, the one compiler and level where a secret-bearing file holds a
widening multiply. Two files do: poly1305.c and p256_scalar.c each read two
`madd`. Each count of two is a record, not an allowance, and this is what the
two record ([#122](https://github.com/c4milo/chapulin/issues/122)).

At `-O2` the mips gcc inlines `ct_widemul` into poly1305's block, whose 25
word products hand it 75 sums of the shape `product + x`. On mips32r2 that
shape is one machine pattern, `madd`, a multiply-accumulate through the
64-bit HI/LO pair, and the register allocator takes it for two of the 75
(`mtlo`, `madd`, `mflo`) where the other 73 get `mul` and `addu`; `-O1`
gives four and `-O3` two. The operands are the same 16-bit halves either
way, so the two change which multiplier runs, not the operand width the
decomposition narrows. The zero at `-Os` is not the recombination's doing:
there the Arm, mips and riscv32 gccs all keep `ct_widemul` out of line, 28
to 30 references in poly1305's assembly, so the `-Os` specs read the
recombination once per file and never inlined under the block's register
pressure. The `-O2` spec is the one that does. clang inlines it at every
level and reads zero at every level.

Steering the C was measured before the record was chosen. The one form that
hands gcc no `product + x` sum at all splits every product into 16-bit
columns before any add. It holds zero at `-O1`, `-O2`, `-O3` and `-Os` under
every compiler in the table, and it costs 38% of AEAD seal (81,976 to
112,908 instructions per 1 KB) and 19% of x25519 (38.9 M to 46.4 M) on
mips32r2, measured with `bench/insn-mips.sh`, and 26% to 42% of poly1305's
block statically under clang on the three targets. Two cheaper forms that
split only some of the products also read zero on this gcc, but each still
hands it such a sum, so their zero is the allocator's choice and the next
gcc need not repeat it. Reassociating the ladder's sums reads two, and the
compare-carry recombination `ct_widemul_opaque` uses reads four. The ladder
stays. The violation
`test/violations/inv16-widemul-compare-carries.violation` writes that
compare-carry form into `ct_widemul` and requires `test/docker-mips.sh`, the
local run of the mips lane, to fail: the `-O2` spec reads four against its
ceiling of two, and the `-Os` spec reads zero.

p256_scalar.c's two `madd` come from one call, `mont_mul`'s
`ct_widemul(t[0], N0_INV)`, and unlike poly1305's their operands can be read
from the assembly. `t[0]` is the low word of the sum `mont_mul` builds, and
`N0_INV` is `-n^-1 mod 2^32`, a constant of the curve's order `n`. Both
`madd` are the ladder's middle products. `madd $3,$13` multiplies
`srl $3,$19,16`, the word's high half, by `li $13,0xbc4f`, `N0_INV`'s low
half. `madd $31,$24` multiplies `andi $31,$19,0xffff`, the word's low half,
by `li $24,0xee00`, `N0_INV`'s high half. gcc holds both halves of the
constant in registers, so it computes two of `ct_widemul`'s sums in the
multiplier's accumulator in place of `mul` and `addu`: `hl + (ll >> 16)`, and
the low half of that sum plus `lh`. Every operand is 16 bits wide, and the
file's other 13 products stay on `mul`. The violation
`test/violations/p256-scalar-widemul-native.violation` writes `mont_mul`'s
inner product as one 32x32 multiply and requires `test/docker-mips.sh` to
fail.

### What each compiler branches on today

The same pass counts the conditional branches per file — `b<cond>`, `cbz`,
`cbnz`, `tbb`, `tbh` and the IT instruction on arm; `beq`, `bne` and the
four compare-with-zero forms on mips; the six base branches and `c.beqz` and
`c.bnez` on rv32 — in the arithmetic files under the record layer
(`BRANCH_SRCS` in the Makefile), and holds each at the ceiling
`BRANCH_CEILING` records for that compiler
([#141](https://github.com/c4milo/chapulin/issues/141)). The eight device
specs compile 22 of those files, and the two tables below hold every count
the lint prints for them. Read from the lint:

| compiler | ct | ct_wipe | sha256 | sha3 | hkdf | chacha20 | poly1305 | aead | x25519 | mlkem | mlkem_poly | drbg | softmul |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| clang 23, Cortex-M3 | 2 | 1 | 17 | 38 | 19 | 9 | 19 | 4 | 33 | 14 | 45 | 9 | 0 |
| clang 23, mips32r2 | 2 | 1 | 16 | 25 | 16 | 7 | 18 | 2 | 31 | 13 | 38 | 8 | 0 |
| clang 23, rv32imac | 2 | 1 | 17 | 32 | 18 | 8 | 18 | 2 | 31 | 14 | 38 | 9 | 0 |
| Arm GNU gcc 15.3, Cortex-M3 | 1 | 1 | 12 | 21 | 19 | 7 | 14 | 2 | 23 | 14 | 39 | 8 | 0 |
| gcc 12.4 (Ubuntu 24.04), mips32r2 | 1 | 1 | 12 | 17 | 18 | 6 | 14 | 2 | 20 | 14 | 43 | 7 | 0 |
| gcc 12.4 (Ubuntu 24.04), mips32r2, `-O2` | 2 | 1 | 23 | 32 | 23 | 7 | 21 | 2 | 28 | 18 | 41 | 8 | 0 |
| Bootlin gcc 14.3, rv32imac | 1 | 1 | 15 | 22 | 23 | 10 | 15 | 4 | 24 | 20 | 41 | 10 | 0 |
| Bootlin gcc 14.3, rv32ic | 1 | 1 | 15 | 22 | 23 | 10 | 15 | 4 | 24 | 20 | 41 | 10 | 2 |

| compiler | p256_field | p256_scalar | rsa_sign | sha512 | sha512_compress | aes | quic_aes_soft | aes_extern | gcm |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| clang 23, Cortex-M3 | 24 | 15 | 29 | 24 | 4 | 3 | 12 | 0 | 22 |
| clang 23, mips32r2 | 21 | 14 | 27 | 20 | 4 | 2 | 12 | 0 | 16 |
| clang 23, rv32imac | 21 | 14 | 27 | 23 | 4 | 3 | 12 | 0 | 20 |
| Arm GNU gcc 15.3, Cortex-M3 | 14 | 12 | 26 | 12 | 4 | 3 | 9 | 0 | 15 |
| gcc 12.4 (Ubuntu 24.04), mips32r2 | 13 | 12 | 23 | 12 | 4 | 3 | 9 | 0 | 13 |
| gcc 12.4 (Ubuntu 24.04), mips32r2, `-O2` | 24 | 14 | 26 | 27 | 4 | 3 | 12 | 0 | 16 |
| Bootlin gcc 14.3, rv32imac | 20 | 18 | 27 | 14 | 5 | 4 | 12 | 0 | 23 |
| Bootlin gcc 14.3, rv32ic | 20 | 18 | 27 | 14 | 5 | 4 | 12 | 0 | 23 |

`BRANCH_SRCS` lists more files than these 22. The rest are a host object's:
its vector kernels, its hashes on the CPU's instructions, its SHA-512
compression function in plain C, its arithmetic on 64-bit words, and the
copies of the files above that it compiles for itself. Its copy of `sha512.c`
is that file's first arm, and it compiles no `sha512_compress.c`:
`sha512_compress_blocks.c` takes that file's place (decision 127). So the
`sha512` and `sha512_compress` columns count a device object's code alone.
Two more specs count them, arm64 and x86-64 under the pinned clang, hosted
and at `-O2`, which is how a host object is built
([decision 126](decisions.md#engineering)). `BRANCH_CEILING` records those
counts, and no table here repeats them.

Few of these are zero, and the lint does not claim they branch on public
data: it cannot tell a loop counter from a word. They are what each compiler
emits for `ct_memeq`'s loop and `ct_wipe`'s test of `n`, the block loops,
x25519's 255-step ladder, Keccak's round and lane counters, `hkdf`'s length
checks, the loops over words, bytes, bits and rounds in the P-256, RSA,
SHA-512, AES and GCM files, and `softmul`'s fixed 32 and 64 iterations (the
two `bne` on rv32ic, the one core where it compiles to anything), read and
recorded. The comments above `BRANCH_SRCS` and `BRANCH_CEILING` in the
Makefile hold the readings, and they name the branches that are not loop
control: tests of a hash length, of an RSA modulus and of whether a tag
matched, none of them a secret. `hkdf.c` compiles under `-DCH_HASH_SHA384`,
as a `SUITE=aesgcm` object compiles it, so its count holds HMAC over SHA-256
and over SHA-384. `aes_extern.c` holds no loop and counts zero: each entry
copies a key or calls `ch_aes_block`. The Cortex-M3 clang counts include IT
blocks — 15 of sha3's 38 and 11 of mlkem_poly's 45. A predicated
instruction takes the same cycles on that core whether or not its condition
holds, so an IT block is no timing leak there; the count holds them because
an IT block is the form clang gives an `if` on a word, and a count of
`b<cond>` alone would pass that form through.

What the lint holds is that no count grows. What the ceilings record is a
choice each compiler made: the compare-carries `ct_widemul_opaque` takes,
`mid < lh` and `lo < ll`, and the sign masks in x25519's `cswap` and in
`poly1305_final` are branch-free in C, and every compiler in the
tables lowers them to a predicated instruction (`it lo`, `movlo`), to `sltu`
or to an arithmetic shift. Until this count that was the compiler's choice,
with nothing holding it. Two violations show what an `if` on a word does to
the count. `test/violations/inv16-poly1305-final-sign-branch.violation`
writes `poly1305_final`'s select of `h` or `h - p` as an `if` on the sign of
the last word, and poly1305's count rises by one under all eight specs.
`test/violations/inv16-widemul-s-sign-branch.violation` writes
`ct_widemul_s` as the unsigned product with two corrections of its high
word, each an `if` on an operand's sign: clang lowers both to a mask and
its count does not move, and every gcc emits two branches on
the operands' signs where x25519 inlines the routine — two IT blocks on the
Cortex-M3, two `bgez` on mips32r2, two `bge` on rv32 — so the gcc lint
objects. That is the split the multiply count found first
([#106](https://github.com/c4milo/chapulin/issues/106)), and why both
compiler families are measured.

`ct_widemul_s` held those two corrections as masks of the sign bits until
clang for x86-64 wrote one as a jump: in x25519's `mul` the mask of a row's
word is the same for the whole row, and the compiler picked between a word
of the other operand and zero with a jump on the sign. The routine is now
the signed ladder, which reads no sign bit by itself. The Cortex-M3 clang
count for x25519 fell from 34 to 33 with it, the IT block that mask had
been. `test/violations/inv16-widemul-s-sign-mask.violation` puts the masks
back, and the m3 spec and the x86-64 spec both object
([decision 125](decisions.md#engineering)).

The count does not see a jump through a register (`jr`, `jalr`, a load into
`pc`), which is a return as often as a table jump; no file it covers has a
switch. The protocol files above the record layer are not counted: they
branch on lengths, types and states the peer sent in the clear, several
dozen each, and a count there would record the parser and move with every
feature. A new spec must record a ceiling for every file it counts before
it passes, so a compiler the tables do not carry cannot pass on counts
nobody read.

### The shift routines gcc calls at `-Os`

No 32-bit core here shifts a 64-bit value by a register in one instruction,
so the compiler builds the shift from 32-bit ones. clang writes it inline for
Cortex-M3, mips32r2 and rv32imac, and so do the Arm gcc and the mips gcc at
`-O2`, with predicated instructions or conditional moves. gcc at `-Os` for
mips32 and riscv32 calls its runtime library instead: `__ashldi3` for a left
shift, `__lshrdi3` for a logical right shift and `__ashrdi3` for an
arithmetic one.

Those routines branch. Each was disassembled from the `libgcc.a` of Ubuntu's
gcc-mips-linux-gnu 12.4.0 and of the Bootlin riscv32 gcc 14.3.0, and each
holds two conditional branches:

- `beqz` on the distance, which returns the value as it came when the
  distance is zero;
- `blez` on 32 less the distance, which chooses between a shift inside one
  32-bit word and a shift from one word into the other.

Both read the distance alone, and neither reads the value shifted. So the
time a call takes tells whether its distance is zero and whether it is 32 or
more, and nothing about the value. A call is allowed where the distance is
public, and nowhere else.

The same pass counts the calls per file and holds each count at the ceiling
`SHIFT_CALL_CEILING` records in the Makefile. A file with no entry there is
held at zero, which is every file under clang, the Arm gcc and the mips gcc
at `-O2`. The mips gcc at `-Os` and the Bootlin gcc for rv32imac and for
rv32ic emit the same 13 calls in 9 files. Read from the lint and from the C:

| file | function | shift | distance |
| --- | --- | --- | --- |
| aead.c | `mac` | `aad_len >> (8 * i)` and `n >> (8 * i)` | loop counter |
| gcm.c | `write_length_bits`, twice in `hash_finish` | `bits >> (8 * (7 - i))` | loop counter |
| quic_packet.c | `quic_nonce` | `pn >> (8 * i)` | loop counter |
| quic_token.c | `write_instant` | `seconds >> shift` | loop counter |
| record.c | `nonce_of` | `d->seq >> (8 * i)` | loop counter |
| sha256.c | `sha256_final` | `bits >> (56 - 8 * i)` | loop counter |
| sha3.c | `xor_byte` | `byte << (8 * (at % 8))` | a byte's position in its lane |
| sha3.c | `byte_at`, twice in `block_bytes` | `lane >> (8 * (at % 8))` | a byte's position in its lane |
| sha512.c | `store_be64` | `v >> (56 - 8 * i)` | loop counter |
| srv_ticket.c | `write_instant` | `seconds >> shift` | loop counter |

A loop counter steps through the eight bytes of a 64-bit value. A byte's
position in its lane counts the bytes the sponge absorbed or squeezed so far,
which is a length. `quic_nonce`'s packet number, sha3.c's lane and sha512.c's
word can be secret, and each is the value shifted, not the distance.

One call was on a distance that is not public. `quic_pn_decode` computed RFC
9000 Appendix A.3's window as `1 << (8 * pn_len)`, and RFC 9001 §9.5 makes
the encoded length of a packet number a secret. Under both gcc above that was
a call to `__ashldi3`, whose second branch read whether `pn_len` is 4. No
count saw it: the multiply tokens name no shift routine, and the branch is in
libgcc, which the branch count does not compile. `quic_pn_decode` now builds
the window from byte masks and shifts by constants alone. The violation
`test/violations/inv16-quic-pn-window-64bit-shift.violation` writes the 64-bit
shift back and requires `test/docker-mips.sh` to fail: quic_packet.c then
reads two calls against its ceiling of one.

What a port checks:

- The count holds the calls your compiler emits only when you run the lint
  with it. Another gcc, another 32-bit target or another level may call the
  routines where the compilers above do not.
- The statement about the routines is about the two `libgcc.a` files named
  above. Disassemble `__ashldi3`, `__lshrdi3` and `__ashrdi3` in the runtime
  library your image links, and require that every branch reads the distance
  alone. The Bootlin toolchain carries one libgcc, built for ilp32d, so an
  ilp32 image takes the routines from elsewhere: `bench/insn-rv32.sh`
  supplies its own, written the way `libgcc2.c` writes them.

### What the decomposition does not cover

It removes the 32-to-64 multiply, and the table above is the measurement.
What remains after that is the 32-to-32 one. Arm
documents that as single-cycle on the M3, so the guarantee is complete there.
mips32r2 does not document its own — GCC's 4K scheduler model says the
three-operand `mul` stalls by operand size — so on that part the decomposition
narrows the exposure rather than closing it. A core that must not depend on that
needs a build with no multiply instruction at all, which chapulin does not
supply for a core that has one.

## 2. Entropy

`ch_rand_bytes` is yours, and no check here can grade it: a weak generator
completes the handshake and produces a session anyone can read. Choose
`RAND=extern` and supply the hook, or `RAND=drbg` and seed the reference
generator at boot. A host whose sessions each need a source of their own,
to replay a connection from a seed in a test or to run sessions on several
threads with no shared state, chooses `RAND=session` and sets
`cfg.rand_bytes` per session instead. `docs/entropy.md` covers the
reasoning and the failure modes.

## 3. The receive buffer

You size it and the client advertises that size as its `record_size_limit`
(RFC 8449), so a peer can never send a record it cannot hold. `CH_MIN_RXBUF` is
the floor for your build. In pinned mode the server's Certificate must also fit:
about 600 bytes for P-256, about 1.2 kB for RSA-3072.

## 4. Authentication

One mode per build. A pinned key (`TRUST=raw-rsa` or `TRUST=raw-ecdsa`) or a
CA (`TRUST=ca-rsa`), and `docs/ca.md` covers the CA path including the revocation
epoch. Neither has a default that is right for every deployment.

## Checking the object you link

If you link the packaged object, `bin/chapulin.o`, instead of compiling the
sources in your own build, you compile against its headers under defines you
write yourself, and nothing in the link checks that they are the object's
defines. A define you forget changes the layout of `ch_tls` or `ch_cfg`, or
the value of `CH_MIN_RXBUF`, on your side only, and the program still links. Every
packaged object exports its build record (`build.h`): the axes, struct sizes
and bounds it was compiled with. Compare it once at startup, before the first
session:

```c
#include "build.h"

if (!ch_build_matches(&ch_build)) {
    // this program's defines are not the object's: do not start a session
}
```

The record's symbol name carries the object's transport: `ch_build_info_tcp_blocking`,
`ch_build_info_tcp_nonblocking` or `ch_build_info_quic_nonblocking`. `build.h` defines `ch_build` as the
name your defines select, so the call above reads the record of the transport
you compile for, and a program built for another transport than the object's
fails to link.

A program in another language reads the same symbol. `ch_build_info` is twelve
`uint32_t` fields with no padding, and each `CH_BUILD_` macro is the value
your defines give the field of the same name. Compare `version` first and the
other fields only when it matches. A Zig program that depends on the
package imports its module `chapulin`, the Zig API (`docs/zig.md`), whose
`buildMatches()` calls the same predicate on its own object's record. The
module's `chapulin.c` holds the headers, which translate-c makes under the
object's own defines (`docs/building.md`). Zig's translate-c turns the
`ch_build` macro into a constant that Zig refuses to evaluate, because its
value is an extern variable, so a program that calls the predicate itself
writes the record's own name:

```zig
const chapulin = @import("chapulin");
const c = chapulin.c;

if (!chapulin.buildMatches()) return error.ChapulinBuildMismatch;
if (c.ch_build_matches(&c.ch_build_info_tcp_nonblocking) == 0) return error.ChapulinBuildMismatch;
```

The module of an object of another transport declares no
`ch_build_info_tcp_nonblocking`, so that mistake stops the compile. A Zig
program that links a make-built object instead `@cImport`s `build.h` under
the defines `make print-lib-def` prints. `docs/decisions.md` 56 lists what the
record holds, which defines it leaves out and why, and entry 61 says why its
name carries the transport.

A packaged object for a `TRUST=webpki` client, `ROLE=server` or
`ROLE=both`, built on an arm64 or x86-64 host, is a host object: its
defines include `-DCH_CPU_RUNTIME`, and its `ch_cfg` holds `cpu`, which
every init call refuses until you set it (`cpu_cfg.h`,
`docs/building.md`). Compile against it with that define, as with every
other define `make print-lib-def` prints. A program that leaves it out
computes a record without the `CH_BUILD_CPU_RUNTIME` bit, so
`ch_build_matches` returns 0. A firmware tree that compiles the sources in its own build passes no such
define and gets the portable object, whose `ch_cfg` has no `cpu` field,
and `cpu_cfg.h` stops a build that passes it for a target outside the two
architectures (`docs/decisions.md` 89).

## Linking two transports into one image

One image can link one packaged object of each of two transports: a
`TRANSPORT=tcp-nonblocking` object beside a `TRANSPORT=quic-nonblocking` one, or a
`TRANSPORT=tcp-blocking` object beside a `TRANSPORT=quic-nonblocking` one. cocuyo does this for
DNS over TLS and DNS over QUIC, and a server does it for HTTP/2 beside
HTTP/3. Six exports that objects of both transports carry take the
transport into their symbol names, and a header maps each to the name you
call:

| You call | Symbol, per transport | Mapped in |
|---|---|---|
| `ch_build` | `ch_build_info_tcp_blocking`, `ch_build_info_tcp_nonblocking`, `ch_build_info_quic_nonblocking` | `build.h` |
| `ch_srv_check` | `ch_srv_check_tcp_blocking`, `ch_srv_check_tcp_nonblocking`, `ch_srv_check_quic_nonblocking` | `srv.h` |
| `ch_pubkey_from_pem` | `ch_pubkey_from_pem_tcp_blocking`, `ch_pubkey_from_pem_tcp_nonblocking`, `ch_pubkey_from_pem_quic_nonblocking` | `x509_ca.h` |
| `ch_ticket_obfuscated_age` | `ch_ticket_obfuscated_age_tcp_blocking`, `ch_ticket_obfuscated_age_tcp_nonblocking`, `ch_ticket_obfuscated_age_quic_nonblocking` | `ticket.h` |
| `ch_alert_sent` | `ch_alert_sent_tcp_blocking`, `ch_alert_sent_tcp_nonblocking`, `ch_alert_sent_quic_nonblocking` | `alert.h` |
| `ch_alert_received` | `ch_alert_received_tcp_blocking`, `ch_alert_received_tcp_nonblocking`, `ch_alert_received_quic_nonblocking` | `alert.h` |

Compile the calls to each object in a translation unit of its own, under that
object's defines. The two objects' headers disagree about `ch_cfg` and
`ch_tls`, so no one translation unit can include both. Each unit calls
`ch_build_matches(&ch_build)` and reads its own object's record. In Zig,
import each object's module under a name of its own, and each module's
`buildMatches()` reads its own object's record (`docs/zig.md`).

Two pairs do not link, and the linker's duplicate-symbol error is the
refusal:

- **A `TRANSPORT=tcp-blocking` object beside a `TRANSPORT=tcp-nonblocking` one.** Both export
  `ch_read`, `ch_write`, `ch_writable_len` and `ch_close`, and `ch_export`
  under `EXPORTER=on`. A tcp-nonblocking object does everything a tcp-blocking one
  does, with your code driving the socket, so link the tcp-nonblocking
  object alone.
- **Two `RAND=drbg` objects.** Both export `ch_drbg_seed` and `ch_rand_bytes`,
  and each carries a generator of its own. Build one object `RAND=drbg` at
  most. A `RAND=drbg` object beside a `RAND=extern` one links when your image
  defines no `ch_rand_bytes`: the `RAND=extern` object then draws from the
  other object's generator, so the image has one. That generator is
  single-task (`drbg.h`), so an image that runs sessions on several threads
  builds every object `RAND=extern` or `RAND=session` instead. A
  `RAND=session` object names no `ch_rand_bytes` at all, so it links beside
  an object of any pattern.

Two objects of one transport do not link either, for the same reason as the
first pair: build `ROLE=both` for a client and a server over one transport.

The image defines each hook once for every chapulin object it links, and for
every user of chapulin it links, such as cocuyo beside a program that uses
chapulin through colibri:

- `ch_rand_bytes` (`rand.h`), which every `RAND=extern` object imports. The
  image defines it unless one of its objects is `RAND=drbg`, whose generator
  is then the image's. There is one per image. It must be safe to call from
  several threads at once, because an image that runs one thread per core
  runs sessions on every core. A hook that reads state held per thread,
  as cocuyo's does, meets this. A `RAND=session` object imports none: each
  of its sessions draws from the source its own `ch_cfg` names, and an
  image whose objects are all `RAND=session` defines no `ch_rand_bytes`
  (`docs/decisions.md` 77).
- `ch_assert_fail` (`ch_assert.h`), which every object imports.
- `ch_keylog` (`keylog.h`) where an object is built `KEYLOG=on`, and
  `ch_aes_block` (`aes_block.h`) where one is built `AES=extern`. It
  takes a key length, 16 or 32 bytes, and a `SUITE=aesgcm` object passes
  it TLS traffic keys, which is why that build also needs
  `-DCH_AES_EXTERN_CONSTANT_TIME` (`docs/decisions.md` entry 68). The
  library calls it from whichever thread runs the session and holds no lock
  around it, so calls can overlap. A hook over state held per thread needs
  nothing more; a hook over one AES peripheral shared by every thread
  arbitrates access to it itself. `ch_keylog`'s first argument is
  `cfg.io`. A Zig program whose sessions run through the API does not own
  `cfg.io`, so it writes its context into `session.hook.context` after
  `init`, and its `ch_keylog` reads it back with
  `chapulin.hookContext(io)` (`docs/zig.md`).

The library draws at these points and no others, from `ch_rand_bytes` or,
under `RAND=session`, from the session's own `cfg.rand_bytes`:

- **A client:** in `ch_connect`, `ch_record_init` and `ch_quic_init`, for its
  key share, its ClientHello random and, where it offers X25519MLKEM768, the
  ML-KEM seed. A `TRUST=webpki` client also draws in the call that delivers a
  HelloRetryRequest naming secp256r1, for its P-256 key share
  (`docs/decisions.md` 63).
- **A server:** in `ch_srv_check` when an RSA-PSS identity is provisioned,
  for the signature's salt; in `ch_srv_record_init`, `ch_srv_quic_init` and
  `ch_srv_accept`, for its x25519 key share; in the call that delivers the
  ClientHello, for the ServerHello random, the ML-KEM encapsulation where it
  selects X25519MLKEM768, the P-256 key share where it selects secp256r1 and
  the salt where it signs with RSA-PSS; and in the
  call that delivers the client Finished when `cfg.srv.ticket_key` and
  `cfg.srv.now_seconds` are set, for the ticket's AEAD nonce,
  `ticket_age_add` and `ticket_nonce`.
- **Never** for a key update, a QUIC Retry token, header protection, or a
  packet seal or open.

`test/lib-pair-check.sh`, which `make check` runs, links four supported pairs
and starts a session in each half, and requires the two refused pairs to fail
to link. `docs/decisions.md` 61 lists every export two objects share
and why each is renamed or refused.

## What our verification does and does not tell you about your build

- **The proofs describe the single-multiply form.** They run on a development
  machine, where the runner passes `-DCH_NATIVE_WIDEMUL`. They carry to your
  build because `proof/ctwidemul_harness.c` proves the decomposition computes
  the same product — at 8-bit operands, the widest bound whose formula
  converges. Wider operands are unproven, except where a proof needs
  less than equality: the x25519 ladder rests on a product bound, and
  `x25519_mul_ct` proves that bound on the decomposition at the ladder's
  full operand range.
- **`make timing` runs on the host, not your target.** It forces the
  decomposition so it measures the shipped path, but a Welch t-test on a
  development machine tells you the C has no data-dependent branch. Whether
  your part's multiply is uniform is a question for your silicon vendor.
- **The branch count records what your compiler chose; it does not close
  the question.** `lint-wide-multiply` holds each arithmetic file's
  conditional-branch count at a ceiling measured per compiler, and those
  ceilings are public loop control, not zero. A compiler the table does not
  carry may lower a select to a branch, and the lint sees that only when you
  run it with that compiler: add the spec, read and record its counts, and
  read the histogram it prints when one grows.
- **The memory numbers are measured on arm64.** A 32-bit target shrinks the
  pointer fields; [`docs/performance.md`](performance.md) says which numbers
  move.
