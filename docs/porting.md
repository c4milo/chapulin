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

One measured exception, not yet repaired. The Bootlin riscv32 gcc 14.3 at
`-Os` for rv32ic rewrites the mask select in `softmul.c`'s `__muldi3`,
`acc += a & mask`, as a multiply by the selected bit, and on a core with no
multiplier that multiply is a call to `__muldi3` from inside `__muldi3`: the
routine never returns. At `-O2` it keeps the mask. `lint-runtime-symbols`
measures clang, which keeps the mask at both levels, and nothing gates gcc on
rv32ic yet. Until `softmul.c` is reworked, build it under gcc at `-O2`, or read
its disassembly for a call to its own name before you trust it.

**Your core has a multiplier whose timing you cannot document.** This is the
default and needs no flag. `ct.h` builds every widening product from four 16x16
pieces, which costs roughly 33% of the pinned handshake's crypto and 1.7 kB of
flash (measured; see the README's Speed and flash table).

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
reads its operands through `volatile` so the inference cannot be made.

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
with its own toolchain. Point it at the compiler you ship:

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
the source; the gate compiles at `-Os`, so put your own level in the flags
field if it differs. A new spec starts from the default ceilings, so the first
thing it reports is how your compiler lowers sha3's public `% 5`; record that
count for your label with `WIDEMUL_CEILING_SPEC="mycore/sha3.c:5"`, and read
every other file it reports above zero as the finding it is.

### What each compiler emits today

Counts per file at `-Os`, read from the gate. Every source not listed is at
zero under every compiler.

| compiler | poly1305.c | x25519.c | mlkem_poly.c | sha3.c (public `% 5`) |
| --- | --- | --- | --- | --- |
| clang 23, Cortex-M3, mips32r2, rv32imac | 0 | 0 | 0 | 1 multiply-high |
| Arm GNU gcc 15.3, Cortex-M3 | 2 `umlal` | 2 `umull`, 2 `umlal` | 2 `umlal` | 5 `udiv` |
| gcc 12.4 (Ubuntu 24.04), mips32r2 | 0 | 0 | 0 | 5 `div` |
| Bootlin gcc 14.3, rv32imac | 0 | 1 `mulhu` | 0 | 5 `rem` |

The sha3 column is Keccak's `% 5` over public loop counters, which divides no
secret. The gcc entries in the other three columns are a leak, recorded and
not accepted: gcc rewrites `(uint64_t)lh + hl` on two products it can prove
narrow into one widening multiply-accumulate, and `x & (0 - bit)` into
`x * bit`, a widening multiply by a secret bit. The gate holds those counts so
they cannot grow and fails on any file above its own. The repair is a rework of
`ct_widemul`, `ct_mulsmall` and `ct_widemul_s` in `ct.h` that has not landed.
Until it does, a Cortex-M3 built with gcc runs `umull` and `umlal` on secret
limbs in those three modules, and the gate's zero holds for the other
twenty-one files; under clang it holds for all twenty-four.

### What the decomposition does not cover

It removes the 32-to-64 multiply where the compiler keeps its pieces apart,
which under gcc is not yet everywhere; the table above says where. What
remains after that is the 32-to-32 one. Arm
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
  converges. Wider operands are unproven.
- **`make timing` runs on the host, not your target.** It forces the
  decomposition so it measures the shipped path, but a Welch t-test on a
  development machine tells you the C has no data-dependent branch. Whether
  your part's multiply is uniform is a question for your silicon vendor.
- **The memory numbers are measured on arm64.** A 32-bit target shrinks the
  pointer fields; the README says which numbers move.
