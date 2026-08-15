import Spec

/-!
Line-protocol dispatcher for the differential oracle (`test/diff.c`
drives it over pipes). One request per line, `op arg1 arg2 ...`; byte
arguments are lowercase hex with `-` for the empty string, numeric
arguments (lengths, counters, sequence numbers, content types) are
decimal. One response line per request: hex bytes (`-` when empty),
`FAIL` for an AEAD open mismatch, or `ERR <why>`.
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
    ("x25519", Spec.X25519.selftest)]
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
    return emit (Spec.Hkdf.expand (← hexArg? prk) (← hexArg? info) (← len.toNat?))
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
