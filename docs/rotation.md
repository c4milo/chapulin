# Rotating the pinned server key

Pinned mode trusts raw public keys, not certificate chains, so there is
no CA to vouch for a new server key. Instead the config holds up to two
pins: `server_pubkey` (slot A, the current key) and `server_pubkey2`
(slot B, the staged next key). The handshake accepts a server that
proves possession of either one and records which slot matched in
`ch_tls.pin_slot` (1 = A, 2 = B). That field is public information:
read it after each connect to watch a rotation move through the fleet.

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
