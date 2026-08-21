# Rotating the pinned key

Raw-pin mode trusts raw public keys, not certificate chains, so there
is no CA to vouch for a new server key. Instead the config holds up to
two pins: `server_pubkey` (slot A, the current key) and
`server_pubkey2` (slot B, the staged next key). The handshake accepts
a server that proves possession of either one and records which slot
matched in `ch_tls.pin_slot` (1 = A, 2 = B). That field is public
information: read it after each connect to watch a rotation move
through the fleet.

Slot B is optional and follows every slot-A rule — the same length
limits per build, and the odd-modulus check in the RSA build. Pinned
mode still requires slot A; a config with only slot B is an error.

## The procedure

1. **Stage the next key.** Generate the new server key pair and keep
   the private half offline. Push the public half to every device as
   slot B, over the TLS session itself. The new trust anchor travels
   inside the channel it will replace, the same way ticket-based PSK
   refresh already works.
2. **Switch the server.** When enough of the fleet holds slot B, move
   the server to the new key. Updated devices now match slot B — watch
   `pin_slot` flip from 1 to 2. Devices that missed the push still
   match slot A on the old server until you migrate them.
3. **Promote and restage.** Push a config that moves the new key into
   slot A and stages a fresh next key in slot B. The fleet then always
   holds one live pin and one staged pin, and the next rotation starts
   at step 2.

Retire the old private key only after step 3 reaches every device you
still care about; until then it is the recovery path for stragglers.

## Devices that stay offline

A device that sleeps through both pushes wakes up holding two pins the
server no longer uses. It cannot connect, and no protocol step can fix
that: the only keys it trusts are gone. Such a device needs the same
out-of-band re-provisioning as a device with a corrupted PSK. The
two-slot set shrinks the flag-day window from "the whole fleet at one
instant" to "whatever stayed offline across a full rotation cycle"; it
does not remove the recovery path.

## CA mode: the slots hold the CA key

A `TRUST=ca` build reads the same two slots as CA keys: slot A holds
the live CA key, slot B the staged next one. `pin_slot` reports which
CA key verified the presented chain.

Routine server-key rotation stops touching devices in this mode. The
server takes a new leaf certificate from the same CA, and every device
verifies it against the pin it already holds. The slot procedure
exists for the rarer event: rotating the CA key itself.

The three steps carry over unchanged, with the CA key in place of the
server key. Stage the new CA public key in slot B over the TLS
session. Move issuance to the new CA and roll servers onto its leaves;
watch `pin_slot` flip from 1 to 2. Then promote the new key to slot A
and stage the next one. The offline-device recovery path is the same
as above.

Two CA-mode specifics:

- **The rotation window has a tax.** Verification tries slot A first,
  so between staging and promotion every connect to a rotated server
  pays one wasted signature verify against slot A before slot B
  matches. Promote promptly. A stored hint that records the last
  matching slot would remove the waste, but it is not worth persistent
  state and code for a once-per-connection cost.
- **A stolen CA key has no device-side revocation.** The device checks
  no revocation lists and no expiry, so whoever holds the CA private
  key authenticates as any server to every device. The only remedy is
  this procedure run fleet-wide under pressure: stage a new CA key,
  reissue every leaf, promote, retire the stolen key. Custody rules
  that keep the root offline (see [ca.md](ca.md)) exist so you never
  run that drill for real.
