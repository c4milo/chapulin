# Performance work in chapulin

The method every performance change follows is pepegrillo's
[docs/performance.md](https://github.com/c4milo/pepegrillo/blob/main/docs/performance.md); read it
first. This appendix is what that method leaves to the project: chapulin's instruments, its
admission rule and the pitfalls it has paid for. Two things set this tree apart from the others that
share the method: what binds is SRAM and code size before instructions, and constant time is a
correctness property, never a cost to trade (`ct.[ch]`).

## The instruments

- `bench/sram.sh` measures the README's memory numbers; they are never estimated, and a change to
  the code re-measures them. `bench/device-ram.sh` measures a device build's RAM.
- `bench/insn-m3.sh` and `bench/insn-mips.sh` count the instructions a handshake and a record take
  on the Cortex-M3 and MIPS builds; `bench/aead.sh` times the AEAD.
- On the host, `/usr/bin/time -v` under `run.sh`'s exact launch line gives a run's memory and time.
- The units of work are a handshake, a record, a byte of SRAM and a byte of code. A laptop's speed
  is a filter; the device numbers are the judge.

## The admission rule

A change stays when it lowers SRAM, code size or instructions past the noise on the device builds
and raises none of them past it; a change that trades constant time for any of the three is
refused, whatever it saves. The README's numbers change in the same commit as the code that moves
them.

## Pitfalls this tree has paid for

None recorded yet. The first performance change that pays one adds it here, as symptom, cause and
rule.

## Commands

```bash
bench/sram.sh
bench/device-ram.sh
bench/insn-m3.sh
bench/insn-mips.sh
bench/aead.sh
```
