# Porting chapulin to a platform

chapulin makes no assumption about your core beyond C11 and libc. That leaves
you four decisions. Three have safe defaults you can take without reading
further; the fourth, entropy, has no default and cannot have one.

This document covers what you decide and, more usefully, what you can check.
Every claim below is something you can reproduce on your own target rather than
take on trust. Writing it turned up a case where the mitigation was defeated by
an optimiser on a target nothing gated, which is the reason the checking section
exists.

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
ship a compiler neither gate measures, run the gate with it, or read
`softmul.o`'s disassembly for a call to its own name before you trust it.

**Your core has a multiplier whose timing you cannot document.** This is the
default and needs no flag. `ct.h` builds every widening product from four 16x16
pieces, which costs roughly 29% of the pinned handshake's crypto on mips32r2
and 2.3 kB of flash (measured; see the README's Speed and flash table).

**Your core's multiply is documented constant-time.** Pass
`-DCH_NATIVE_WIDEMUL` and take the speed back. Do this only with a vendor
statement in hand — RISC-V's Zkt, Arm's FEAT_DIT, Intel's DOITM. Those
extensions exist because the base architectures do not promise it, which is why
`ct.h` names no architecture as exempt: no preprocessor macro carries the claim,
and clang defines no `__ARM_FEATURE_DIT` even at `-march=armv8.4-a+dit`.

`-DCH_CT_WIDEMUL` forces the decomposition and beats `-DCH_NATIVE_WIDEMUL` when
both are set.

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

`make lint-wide-multiply` gates Cortex-M3, mips32r2 and rv32imac under the
pinned clang, over every source a secret passes through (`CODEGEN_SRCS` in the
Makefile: the chain from `ct.c` to `tls.c`, plus `drbg.c` and `softmul.c`),
and counts per file the widening multiplies, the divisions and the calls into
the compiler's 64-bit division runtime. `make lint-wide-multiply-gcc` is the
same count under gcc, which is what a firmware tree ships; each CI lane runs it
with its own toolchain; the riscv32 lane's gcc matches two specs, rv32imac
and rv32ic, and the mips lane's matches two, at `-Os` and at `-O2`. Point it
at the compiler you ship:

```bash
make lint-wide-multiply-gcc WIDEMUL_GCC=/path/to/arm-none-eabi-gcc
```

The Makefile reads the driver's `-dumpmachine` and runs the spec whose machine
prefix matches; no match fails rather than skips. For a core the list does not
carry, add a spec:

```bash
make lint-wide-multiply-gcc WIDEMUL_GCC=/path/to/my-gcc \
  WIDEMUL_SPECS="mycore:gcc:my-machine-prefix:-mcpu=mycpu,-mthumb:umull,umlal,umaal,smull,smlal,udiv,sdiv,__aeabi_uidiv,__aeabi_uldiv"
```

The five fields are a label; `clang` or `gcc`; the machine (clang's target
triple, or the prefix of gcc's `-dumpmachine`); the comma-separated flags that
select your core; and the comma-separated tokens that count on your ISA. A
token counts every instruction whose mnemonic begins with it, so a
condition-code or width suffix (`umullne`, `udiveq`, `umull.w`) cannot slip
past it, and a token that begins with `__` counts every call to a runtime
routine whose name begins with it, which is where a 64-bit division goes. Both
can only over-count, and an over-count fails loudly. Run it with the compiler
and flags you actually ship, since this is a property of codegen and not of
the source; the gate passes `-Os` before the flags, so a level in the flags
field wins, which is how the mips gcc spec below runs a second time at `-O2`.
A new spec starts from the default ceilings, so the first
thing it reports is how your compiler lowers sha3's public `% 5`; record that
count for your label with `WIDEMUL_CEILING_SPEC="mycore/sha3.c:5"`, and read
every other file it reports above zero as the finding it is.

### What each compiler emits today

Counts per file at `-Os`, and for the mips gcc at `-O2` as well, read from
the gate. Every source not listed is at zero under every compiler.

| compiler | poly1305.c | x25519.c | mlkem_poly.c | sha3.c (public `% 5`) |
| --- | --- | --- | --- | --- |
| clang 23, Cortex-M3, mips32r2, rv32imac | 0 | 0 | 0 | 1 multiply-high |
| Arm GNU gcc 15.3, Cortex-M3 | 0 | 0 | 0 | 5 `udiv` |
| gcc 12.4 (Ubuntu 24.04), mips32r2 | 0 | 0 | 0 | 5 `div` |
| gcc 12.4 (Ubuntu 24.04), mips32r2, `-O2` | 2 `madd` | 0 | 0 | 5 `div` |
| Bootlin gcc 14.3, rv32imac | 0 | 0 | 0 | 5 `rem` |
| Bootlin gcc 14.3, rv32ic | 0 | 0 | 0 | 5 `__modsi3` |

rv32ic has no multiply or divide instruction to count, so that spec counts
the runtime routines instead: a 64-bit product is a call to `__muldi3`, which
a chapulin build resolves to `softmul.c`'s constant-time routine, and the
`% 5` is a call to `__modsi3`. `softmul.c` itself is at zero calls to
`__muldi3` there, which is what that spec exists to hold.

The sha3 column is Keccak's `% 5` over public loop counters, which divides no
secret. The three gcc rows were not always zero. gcc rewrites
`(uint64_t)lh + hl`, a 64-bit sum of two products it can prove narrow, into
one widening multiply-accumulate, and `x & (0 - bit)` into `x * bit`, a
widening multiply by a secret bit: two `umlal` in poly1305 and in mlkem_poly
and two `umull` and two `umlal` in x25519 under the Arm gcc, one `mulhu` in
x25519 under the riscv32 gcc. The gate recorded those counts as ceilings until
`ct_widemul` moved to a recombination that never widens a product,
`ct_widemul_s` and x25519's `cswap` moved their masks to an arithmetic shift of
the sign bit, and every row went to zero
([#106](https://github.com/c4milo/chapulin/issues/106)). The violation
`test/violations/inv16-widemul-mid-widened.violation` puts the old sum back
and requires the gcc gate to fail.

The gate compiles at `-Os`, and the mips gcc spec runs once more at `-O2`,
the one compiler and level where a secret-bearing file is not at zero. Its
count of two is a record, not an allowance, and this is what it records
([#122](https://github.com/c4milo/chapulin/issues/122)).

At `-O2` the mips gcc inlines `ct_widemul` into poly1305's block, whose 25
limb products hand it 75 sums of the shape `product + x`. On mips32r2 that
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

The Arm gcc lowers sha3's `% 5` to four `umull` at `-O2` where `-Os` gave
five `udiv`; both divide public loop counters.

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
generator at boot. `docs/entropy.md` covers the reasoning and the failure modes.

## 3. The receive buffer

You size it and the client advertises that size as its `record_size_limit`
(RFC 8449), so a peer can never send a record it cannot hold. `CH_MIN_RXBUF` is
the floor for your build. In pinned mode the server's Certificate must also fit:
about 600 bytes for P-256, about 1.2 kB for RSA-3072.

## 4. Authentication

One mode per build. A pinned key (`PIN=rsa` or `PIN=ecdsa`) or a CA
(`TRUST=ca`), and `docs/ca.md` covers the CA path including the revocation
epoch. Neither has a default that is right for every deployment.

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
- **The memory numbers are measured on arm64.** A 32-bit target shrinks the
  pointer fields; the README says which numbers move.
