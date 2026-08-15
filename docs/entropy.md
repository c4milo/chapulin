# Seeding the generator on parts without a hardware RNG

The reference target (RTL8382-class, mips32r2) has no random number
peripheral and MIPS has no randomness instruction, so `ch_rand_bytes`
comes from the fast-key-erasure generator in `drbg.[ch]`, and the
security of every handshake reduces to the quality of its 32-byte seed.
The stack draws randomness at exactly two points, both in the handshake:
the ephemeral x25519 private key and the ClientHello random. In pinned
mode the ephemeral key carries all confidentiality, so a guessable seed
means a passive attacker can decrypt everything.

Devices that generate keys at first boot, before any entropy exists, are
a documented disaster class: Heninger, Durumeric, Wustrow, Halderman,
"Mining Your Ps and Qs" (USENIX Security 2012) factored keys across
whole device fleets that seeded from nothing. The rules below exist to
keep chapulin devices out of that paper's sequel.

## Layer the seed — never one source alone

Mix all of the following into the boot seed (concatenate and hash with
`sha256_of`, or XOR into the reseed input). Each is listed with the
attack it fails against alone.

1. **A factory-provisioned per-device secret** (32 random bytes written
   to flash at manufacturing, like the PSK or pin). Strong against
   remote attackers from the first instruction; alone it fails when
   firmware dumps or supply-chain copies leak flash contents, because
   the "random" stream becomes replayable.
2. **A persisted seed file, rewritten every boot.** At boot, read it,
   mix it into the seed, and immediately overwrite it with fresh
   generator output; at clean shutdown, overwrite it again. Each boot
   then inherits the accumulated history of every previous boot
   (Linux's boot-time seed file works this way). Alone it fails against
   flash cloning: two devices imaged from the same flash replay the
   same stream until they diverge.
3. **Timing jitter as a topper.** Sample a cycle counter (MIPS `Count`)
   against an independent clock domain — packet-arrival interrupts, a
   watchdog oscillator, link-state changes — and mix the low bits of
   many samples. Jitter between unsynchronized clocks is the standard
   TRNG-less entropy source, but its rate is hard to certify on any
   given board, so it tops up the seed rather than being it.

The generator itself (fast key erasure over ChaCha20, after Bernstein's
"Fast-key-erasure random-number generators", 2017,
https://blog.cr.yp.to/20170723-random.html) makes every request replace
its key from its own keystream before output leaves, so compromising a
device's state later does not reveal traffic it already protected.
Reseeding after boot is optional; when late entropy arrives, reseed with
a hash of fresh bytes and current generator output, so the state never
gets worse.

## What not to do

- Do not seed from a bare counter, the boot time, a MAC address, or any
  value an attacker on the same network can enumerate.
- Do not skip seeding: `ch_rand_bytes` faults on an unseeded generator
  by design (`CH_ASSERT`), because a handshake with predictable
  randomness is worse than no handshake.
- Do not share one factory secret across devices; per-device, like the
  PSK and the pin.
