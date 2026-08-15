import Spec

/-!
Line-protocol dispatcher for the differential oracle (`test/diff.c`
drives it over pipes). One request per line, `op arg1 arg2 ...`; byte
arguments are lowercase hex with `-` for the empty string, numeric
arguments (lengths, counters, sequence numbers, content types) are
decimal. One response line per request: hex bytes (`-` when empty),
`FAIL` for an AEAD open mismatch or a degenerate P-256 sign/pub input,
or `ERR <why>`. P-256 r/s travel as raw 32-byte hex; DER stays on the
C side.
-/

open Spec.Bytes

def hexArg? (s : String) : Option ByteArray :=
  if s == "-" then some ByteArray.empty else hexToBytes? s

def emit (b : ByteArray) : String :=
  if b.size == 0 then "-" else bytesToHex b

def selftestAll : String :=
  let mods : List (String × Bool) := [
    ("sha256", Spec.Sha256.selftest),
    ("hkdf", Spec.Hkdf.selftest),
    ("chacha", Spec.ChaCha.selftest),
    ("poly", Spec.Poly.selftest),
    ("aead", Spec.Aead.selftest),
    ("record", Spec.Record.selftest),
    ("x25519", Spec.X25519.selftest),
    ("p256", Spec.P256.selftest)]
  match mods.find? (fun m => !m.2) with
  | some (name, _) => s!"FAIL {name}"
  | none => "ok"

def dispatch : List String → Option String
  | ["selftest"] => some selftestAll
  | ["sha256", m] => do
    return emit (Spec.Sha256.sha256 (← hexArg? m))
  | ["hmac", k, m] => do
    return emit (Spec.Hkdf.hmac (← hexArg? k) (← hexArg? m))
  | ["hkdf_extract", salt, ikm] => do
    return emit (Spec.Hkdf.extract (← hexArg? salt) (← hexArg? ikm))
  | ["hkdf_expand", prk, info, len] => do
    let l ← len.toNat?
    -- RFC 5869 §2.3 caps L at 255*HashLen; past it the one-octet counter wraps.
    if l > 255 * Spec.Hkdf.hashLen then return "ERR hkdf_expand len over 255*HashLen"
    return emit (Spec.Hkdf.expand (← hexArg? prk) (← hexArg? info) l)
  | ["expand_label", secret, label, ctx, len] => do
    let lab ← String.fromUTF8? (← hexArg? label)
    return emit (Spec.Hkdf.expandLabel (← hexArg? secret) lab (← hexArg? ctx) (← len.toNat?))
  | ["schedule", psk, ecdhe, h1, h2] => do
    let (cHs, sHs, cAp, sAp) :=
      Spec.Hkdf.schedule (← hexArg? psk) (← hexArg? ecdhe) (← hexArg? h1) (← hexArg? h2)
    return s!"{emit cHs} {emit sHs} {emit cAp} {emit sAp}"
  | ["chacha20", key, nonce, counter, data] => do
    let k ← hexArg? key
    let n ← hexArg? nonce
    guard (k.size == 32 && n.size == 12)
    return emit (Spec.ChaCha.xor k n (UInt32.ofNat (← counter.toNat?)) (← hexArg? data))
  | ["poly1305", key, msg] => do
    let k ← hexArg? key
    guard (k.size == 32)
    return emit (Spec.Poly.mac k (← hexArg? msg))
  | ["aead_seal", key, nonce, aad, pt] => do
    let k ← hexArg? key
    let n ← hexArg? nonce
    guard (k.size == 32 && n.size == 12)
    return emit (Spec.Aead.seal k n (← hexArg? aad) (← hexArg? pt))
  | ["aead_open", key, nonce, aad, ct, tag] => do
    let k ← hexArg? key
    let n ← hexArg? nonce
    let t ← hexArg? tag
    guard (k.size == 32 && n.size == 12 && t.size == 16)
    match Spec.Aead.open? k n (← hexArg? aad) (← hexArg? ct) t with
    | some pt => return emit pt
    | none => return "FAIL"
  | ["rec_seal", secret, seq, ctype, pt] => do
    let s ← hexArg? secret
    let c ← ctype.toNat?
    guard (s.size == 32 && c < 256)
    return emit (Spec.Record.seal s (← seq.toNat?) (UInt8.ofNat c) (← hexArg? pt))
  | ["x25519", scalar, point] => do
    let k ← hexArg? scalar
    let u ← hexArg? point
    guard (k.size == 32 && u.size == 32)
    return emit (Spec.X25519.scalarMult k u)
  | ["x25519_base", scalar] => do
    let k ← hexArg? scalar
    guard (k.size == 32)
    return emit (Spec.X25519.base k)
  | ["p256_pub", d] => do
    let db ← hexArg? d
    guard (db.size == 32)
    match Spec.P256.pubKey? (bytesToNatBE db) with
    | some pub => return emit pub
    | none => return "FAIL"
  | ["p256_sign", d, k, hash] => do
    let db ← hexArg? d
    let kb ← hexArg? k
    let h ← hexArg? hash
    guard (db.size == 32 && kb.size == 32 && h.size == 32)
    match Spec.P256.ecdsaSign (bytesToNatBE db) (bytesToNatBE kb) (bytesToNatBE h) with
    | some (r, s) =>
      return s!"{bytesToHex (natToBytesBE r 32)} {bytesToHex (natToBytesBE s 32)}"
    | none => return "FAIL"
  | ["p256_verify", pub, hash, r, s] => do
    let pb ← hexArg? pub
    let h ← hexArg? hash
    let rb ← hexArg? r
    let sb ← hexArg? s
    guard (pb.size == 64 && h.size == 32 && rb.size == 32 && sb.size == 32)
    return if Spec.P256.ecdsaVerify pb h (bytesToNatBE rb) (bytesToNatBE sb) then "1" else "0"
  | _ => none

partial def loop (stdin stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return  -- EOF
  let toks := (line.trimAscii.toString.splitOn " ").filter (· ≠ "")
  let resp :=
    if toks.isEmpty then "ERR empty line"
    else (dispatch toks).getD "ERR unknown op or bad args"
  stdout.putStrLn resp
  stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
