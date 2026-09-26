# Seeding the generator on parts without a hardware RNG

The reference target (a mips32r2 core) has no random number peripheral
and MIPS has no randomness instruction, so `ch_rand_bytes`
comes from the fast-key-erasure generator in `drbg.[ch]`, and the
security of every handshake reduces to the quality of its seed.
INV-4 in [invariants.md](invariants.md) lists every call that draws
randomness. What the draws protect:

- **The key-exchange secret.** A client and a server each draw an
  ephemeral x25519 private key per handshake. In pinned mode the
  ephemeral key carries all confidentiality, so a guessable seed means a
  passive attacker can decrypt everything. A P-256 scalar is the whole
  secret of a secp256r1 key exchange in the same way. A `TRUST=webpki`
  client draws one when a HelloRetryRequest names secp256r1, and a server
  draws one when it selects secp256r1 (`docs/decisions.md` 63).
- **The ML-KEM half of X25519MLKEM768.** A `KEX=pq` or `TRUST=webpki`
  client draws the 64-byte (d, z) seed that fixes its ML-KEM key pair. A
  server that selects the hybrid draws 32 bytes of encapsulation
  randomness that fix the ML-KEM shared secret. A guessable draw on
  either side gives away the post-quantum half of that key exchange.
- **The hello randoms.** A client draws the 32-byte ClientHello random
  and a server the 32-byte ServerHello random, once per handshake. Both
  travel in the clear.
- **A resumption ticket.** A server draws 24 bytes per ticket it issues:
  the ticket's AEAD nonce, its `ticket_age_add` and its `ticket_nonce`.
  A repeated ticket nonce under one ticket key breaks the ticket seal, so
  a server's tickets are only as good as its seed.
- **An RSA-PSS salt.** A server with an RSA identity draws a 32-byte salt
  each time it signs: once in `ch_srv_check` at boot, and once per
  handshake that signs with rsa_pss_rsae_sha256. The signature carries
  the salt in the clear.

An ECDSA signature draws nothing: `p256_sign` derives its nonce from the
key and the message by RFC 6979, so a weak seed cannot repeat an ECDSA
nonce.

Devices that generate keys at first boot, before any entropy exists, are
a documented disaster class: Heninger, Durumeric, Wustrow, Halderman,
"Mining Your Ps and Qs" (USENIX Security 2012) factored keys across
whole device fleets that seeded from nothing. The rules below exist to
keep chapulin devices out of that paper's sequel.

## Declare which generator the image uses

The build names the pattern, and there is no default.

| Declaration | The image does this | The packaged object holds this |
| --- | --- | --- |
| `RAND=extern` (`-DCH_RAND_EXTERN`) | Defines `ch_rand_bytes` itself: a hardware RNG, or a generator of its own | `ch_rand_bytes` stays undefined, so an image that never wired one fails to link |
| `RAND=drbg` (`-DCH_RAND_DRBG`) | Calls `ch_drbg_seed` once at boot, with at least 32 bytes concatenated as below | `drbg.c`, with `ch_drbg_seed` and `ch_rand_bytes` exported beside the four public calls |

A build that names neither stops at an `#error` in `cfg.h`. That is the
only part of this page a compiler can enforce. No library can grade an
integrator's generator: a weak one completes the handshake, sends a key
share that looks uniform on the wire, and returns `CH_OK`. Requiring the
declaration does not make the generator good. It makes the choice one
somebody made rather than one nobody looked at.

Under `RAND=drbg` the packaged object defines and exports
`ch_rand_bytes`, so an image that also defines one fails to link with a
duplicate symbol. An image moving from `extern` to `drbg` deletes its
hook and moves its entropy into the `ch_drbg_seed` call.

## Layer the seed — never one source alone

Concatenate all of the following into one buffer, and pass the whole
buffer to `ch_drbg_seed` once. The call hashes the buffer with SHA-256,
and the digest becomes the generator key, so the image needs no hash of
its own. A buffer shorter than `CH_DRBG_SEED_MIN`, 32 bytes, is a
programmer error, and the call faults on it (`CH_ASSERT`). Wipe the
buffer after the call: anyone who reads it can compute every byte the
generator produces. `test/entropy_recipe.c` is this recipe in C, and
`make lib-check RAND=drbg` links it against the packaged object, so a
recipe that calls a function the object does not export fails there.
Each source is listed with the attack it fails against alone.

1. **A factory-provisioned per-device secret** (32 random bytes written
   to flash at manufacturing, like the PSK or pin). Strong against
   remote attackers from the first instruction; alone it fails when
   firmware dumps or supply-chain copies leak flash contents, because
   the "random" stream becomes replayable.
2. **A persisted seed file, rewritten every boot.** At boot, read it,
   add it to the seed buffer, and immediately overwrite it with fresh
   generator output; at clean shutdown, overwrite it again. Each boot
   then inherits the accumulated history of every previous boot
   (Linux's boot-time seed file works this way). Alone it fails against
   flash cloning: two devices imaged from the same flash replay the
   same stream until they diverge.
3. **Timing jitter as a topper.** Sample a cycle counter (MIPS `Count`)
   against an independent clock domain — packet-arrival interrupts, a
   watchdog oscillator, link-state changes — and add the low bits of
   many samples to the seed buffer. Jitter between unsynchronized
   clocks is the standard TRNG-less entropy source, but its rate is
   hard to certify on any given board, so it tops up the seed rather
   than being it.

The generator itself (fast key erasure over ChaCha20, after Bernstein's
"Fast-key-erasure random-number generators", 2017,
https://blog.cr.yp.to/20170723-random.html) makes every request replace
its key from its own keystream before output leaves, so compromising a
device's state later does not reveal traffic it already protected.
Reseeding after boot is optional. When entropy arrives after boot, draw
32 bytes of generator output, concatenate the fresh bytes after them,
and pass the whole buffer to `ch_drbg_seed`. The new key is the hash of
both, so the state never gets worse.

Three steps on this page read generator output: rewriting the seed
file, the reseed above, and the hybrid reseed below. The image reads it
with `ch_rand_bytes`, which the packaged `RAND=drbg` object exports for
that reason, and `test/entropy_recipe.c` does the first two.

## Parts with a hardware TRNG

A hardware source changes where the seed comes from, not the shape of
the wiring. Three patterns, strongest default first:

1. **TRNG feeds the DRBG; the DRBG feeds `ch_rand_bytes`.** The default
   even when the part has a real source. Raw physical sources drift with
   temperature and voltage, can bias, and can fail silently — the
   failure class the SP 800-90B health tests exist for. Behind the
   DRBG, a degraded source degrades seed diversity instead of feeding
   every output directly; output rate stays independent of the TRNG's,
   so `ch_rand_bytes` latency is deterministic; and fast key erasure
   adds the backtracking resistance the raw source lacks.
2. **Hybrid reseed.** Seed from the TRNG at boot; on a schedule or on
   wake-from-sleep, pass `ch_drbg_seed` output the generator just drew
   concatenated with fresh TRNG bytes (the recipe `ch_drbg_seed`'s
   comment gives). The state then never gets worse than either input,
   and a TRNG that quietly dies after boot leaves the generator no
   weaker than pattern 1.
3. **TRNG wired directly as `ch_rand_bytes`.** Earned, not default:
   appropriate only when the RNG block carries its own conditioning and
   on-chip health tests that the vendor documents — the certified
   DRBG-behind-TRNG designs. The criterion is the documentation of
   conditioning and failure detection, not the vendor.

The reference target has none of this — no random-number peripheral,
and no randomness instruction in mips32r2 — so that target always
links the DRBG and seeds it as described above. The patterns here are
for better-equipped parts.

## What not to do

- Do not seed from a bare counter, the boot time, a MAC address, or any
  value an attacker on the same network can enumerate.
- Do not skip seeding: `ch_rand_bytes` faults on an unseeded generator
  by design (`CH_ASSERT`), because a handshake with predictable
  randomness is worse than no handshake.
- Do not share one factory secret across devices; per-device, like the
  PSK and the pin.
