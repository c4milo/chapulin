# mips32r2 codegen notes

Counts read from llvm-objdump disassembly of the objects behind
bench/insn-mips.sh (Alpine clang version 22.1.3,
-target mips-linux-musl -march=mips32r2 -Os). Static instruction counts;
bench/audit-mips.sh regenerates this file and fails if the shapes below
change.

## poly1305.c blocks(): mul only, 100 multiplies per block

blocks() keeps its single 16-byte block loop. The loop body is
622 instructions with 100 mul per block and nothing
in the hi/lo multiplier: multu 0, maddu 0, mult 0.
ct_widemul builds each of the 25 limb products from four 16x16 pieces,
so the 25 products cost 100 mul. mips32r2 documents no timing for mul
either, but the operands are 16 bits wide by construction, which is what
the decomposition buys here.

## p256.c mont_mul(): maddu for every product

mont_mul multiplies through the hi/lo accumulator: 3 maddu,
0 multu, 1 mul. Each v = a[i]*b[j] + t[j] + c step preloads
hi/lo with mtlo/mthi (the t[j] + c partial) and issues one maddu; the
one mul computes u = t[0]*m0inv, where only the low word matters. Both
eight-iteration CIOS inner loops carry one maddu each
(1 and 1), the outer limb loop spans them, and
the trailing compare and subtract loops close the function; nothing
unrolls at -Os. The 2 jal calls are memset (the t[] zeroing) and
memcpy (the no-subtract exit).

## chacha20.c block(): rounds looped, state in registers

clang does not unroll the rounds. block() carries 4 branch or
jump instructions: 3 loop back-edges (state copy-in, the
ten-iteration double-round loop, add-and-serialize) plus 1 return.
The round loop body is 97 instructions for two rounds (eight
quarter-rounds) per iteration and contains 0 loads or stores:
the sixteen state words and their temporaries stay in registers for all
20 rounds, spilling nothing.
