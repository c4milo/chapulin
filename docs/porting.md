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

`make lint-wide-multiply` gates Cortex-M3, mips32r2 and rv32imac. Point it at
your own target too:

```bash
make lint-wide-multiply WIDEMUL_SPECS="mycore:my-triple:-mcpu=mycpu:umull,smull,umlal,smlal"
```

The four fields are a label, the compiler triple, the CPU flag, and the
comma-separated opcodes that count as widening on your ISA. It disassembles
what your compiler emits and fails if any module exceeds its ceiling. Run it
with the compiler and flags you actually ship, since this is a property of
codegen and not of the source.

### What the decomposition does not cover

It removes the 32-to-64 multiply. What remains is the 32-to-32 one. Arm
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
