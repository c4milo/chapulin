import Spec

/-!
Line-protocol dispatcher for the differential oracle (`test/diff_test.c`
drives it over pipes). One request per line, `op arg1 arg2 ...`; byte
arguments are lowercase hex with `-` for the empty string, numeric
arguments (lengths, counters, sequence numbers, content types) are
decimal. One response line per request: hex bytes (`-` when empty),
`FAIL` for an input the modeled function itself refuses (an AEAD open
mismatch, a degenerate P-256 sign/pub input, a refused ML-KEM
encapsulation key, an unsatisfiable RSA sign or X.509 mint), or
`ERR <why>` for a request outside the protocol. P-256 r/s travel as raw 32-byte hex; DER stays on the
C side.
-/

open Spec.Bytes

def hexArg? (s : String) : Option ByteArray :=
  if s == "-" then some ByteArray.empty else hexToBytes? s

def emit (b : ByteArray) : String :=
  if b.size == 0 then "-" else bytesToHex b

def emitNat? (n : Option Nat) : String :=
  match n with
  | some v => toString v
  | none => "-"

def selftestAll : String :=
  let mods : List (String × Bool) := [
    ("sha256", Spec.Sha256.selftest),
    ("sha3", Spec.Sha3.selftest),
    ("mlkem", Spec.MlKem.selftest),
    ("hkdf", Spec.Hkdf.selftest),
    ("chacha", Spec.ChaCha.selftest),
    ("poly", Spec.Poly.selftest),
    ("aead", Spec.Aead.selftest),
    ("record", Spec.Record.selftest),
    ("x25519", Spec.X25519.selftest),
    ("p256", Spec.P256.selftest),
    ("rsa", Spec.Rsa.selftest),
    ("x509", Spec.X509.selftest),
    ("drbg", Spec.Drbg.selftest),
    ("handshake", Spec.Handshake.selftest),
    ("hsparse", Spec.Hsparse.selftest)]
  match mods.find? (fun m => !m.2) with
  | some (name, _) => s!"FAIL {name}"
  | none => "ok"

def dispatch : List String → Option String
  | ["selftest"] => some selftestAll
  | ["sha256", m] => do
    return emit (Spec.Sha256.sha256 (← hexArg? m))
  | ["sha3_256", m] => do
    return emit (Spec.Sha3.sha3_256 (← hexArg? m))
  | ["sha3_512", m] => do
    return emit (Spec.Sha3.sha3_512 (← hexArg? m))
  | ["shake128", m, len] => do
    let l ← len.toNat?
    -- The XOF output is unbounded; cap a request the way drbg is
    -- capped, so a broken driver line cannot ask for megabytes.
    guard (l <= 4096)
    return emit (Spec.Sha3.shake128 (← hexArg? m) l)
  | ["shake256", m, len] => do
    let l ← len.toNat?
    guard (l <= 4096)
    return emit (Spec.Sha3.shake256 (← hexArg? m) l)
  | ["mlkem_keygen", d, z] => do
    let db ← hexArg? d
    let zb ← hexArg? z
    guard (db.size == 32 && zb.size == 32)
    let (ek, dk) := Spec.MlKem.keygen db zb
    return s!"{emit ek} {emit dk}"
  | ["mlkem_encaps", ek, m] => do
    let ekb ← hexArg? ek
    let mb ← hexArg? m
    guard (mb.size == 32)
    -- FIPS 203 §7.2: an encapsulation key that fails the modulus check
    -- is refused, the FAIL string the aead rows already use.
    match Spec.MlKem.encaps ekb mb with
    | some (ct, ss) => return s!"{emit ct} {emit ss}"
    | none => return "FAIL"
  | ["mlkem_decaps", dk, ct] => do
    let dkb ← hexArg? dk
    let ctb ← hexArg? ct
    guard (dkb.size == 2400 && ctb.size == 1088)
    return emit (Spec.MlKem.decaps dkb ctb)
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
    let c ← hexArg? ctx
    let l ← len.toNat?
    -- RFC 9846 §7.1: label<7..255> ("tls13 " + Label) and context<0..255>
    -- are one-byte vectors, so oversize inputs are unencodable; RFC 5869
    -- §2.3 caps L at 255*HashLen. Truncating instead would mint
    -- well-formed output for inputs the RFCs reject.
    if lab.utf8ByteSize + 6 > 255 then return "ERR expand_label label unencodable"
    if c.size > 255 then return "ERR expand_label context unencodable"
    if l > 255 * Spec.Hkdf.hashLen then return "ERR expand_label len over 255*HashLen"
    return emit (Spec.Hkdf.expandLabel (← hexArg? secret) lab c l)
  | ["schedule", psk, ecdhe, h1, h2] => do
    let (cHs, sHs, cAp, sAp) :=
      Spec.Hkdf.schedule (← hexArg? psk) (← hexArg? ecdhe) (← hexArg? h1) (← hexArg? h2)
    return s!"{emit cHs} {emit sHs} {emit cAp} {emit sAp}"
  | ["chacha20", key, nonce, counter, data] => do
    let k ← hexArg? key
    let n ← hexArg? nonce
    let ctr ← counter.toNat?
    guard (k.size == 32 && n.size == 12)
    -- UInt32.ofNat would alias 2^32 back onto 0; reject, never wrap.
    if ctr > 0xffffffff then return "ERR chacha20 counter over 32 bits"
    return emit (Spec.ChaCha.xor k n (UInt32.ofNat ctr) (← hexArg? data))
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
    let q ← seq.toNat?
    let c ← ctype.toNat?
    let p ← hexArg? pt
    guard (s.size == 32 && c < 256)
    -- RFC 9846 §5.1 caps sender plaintext at 2^14, and §5.5 stops one
    -- before the u64 sequence wraps (the C refuses UINT64_MAX). Untended,
    -- both would truncate mod 2^16 / 2^64 into valid-looking records.
    if p.size > 0x4000 then return "ERR rec_seal plaintext over 2^14"
    if q >= 0xffffffffffffffff then return "ERR rec_seal seq at the wrap guard"
    return emit (Spec.Record.seal s q (UInt8.ofNat c) p)
  | ["rec_open", secret, seq, rec] => do
    let s ← hexArg? secret
    let q ← seq.toNat?
    let r ← hexArg? rec
    guard (s.size == 32)
    -- RFC 9846 §5.3 keeps the reader's sequence number 64-bit and unwrapped,
    -- the same guard rec_seal stops at; past it the nonce would repeat.
    if q >= 0xffffffffffffffff then return "ERR rec_open seq at the wrap guard"
    -- One reply for every refusal: the RFC's alerts differ (record_overflow,
    -- bad_record_mac, unexpected_message) but the oracle compares the
    -- accept/refuse boundary, and distinct strings would flag a spec-and-C
    -- disagreement about which MUST fired first as a mismatch.
    match Spec.Record.open? s q r with
    | some (content, ctype) => return s!"ok {ctype.toNat} {emit content}"
    | none => return "ERR rec_open reject"
  | ["x25519", scalar, point] => do
    let k ← hexArg? scalar
    let u ← hexArg? point
    guard (k.size == 32 && u.size == 32)
    return emit (Spec.X25519.scalarMult k u)
  | ["x25519_base", scalar] => do
    let k ← hexArg? scalar
    guard (k.size == 32)
    return emit (Spec.X25519.base k)
  | ["drbg", key, nstr] => do
    let k ← hexArg? key
    let n ← nstr.toNat?
    guard (k.size == 32 && n <= 4096)
    let (k2, out) := Spec.Drbg.next k n
    return s!"{emit k2} {emit out}"
  | ["traffic_upd", secret] => do
    let s ← hexArg? secret
    guard (s.size == 32)
    return emit (Spec.Record.nextSecret s)
  | ["hsseq", mode, letters] => do
    let m ← match mode with
      | "psk" => some Spec.Handshake.Mode.psk
      | "pinned" => some Spec.Handshake.Mode.pinned
      | _ => none
    let msgs ← Spec.Handshake.seq? (if letters == "-" then "" else letters)
    return if Spec.Handshake.accepts m msgs then "1" else "0"
  -- The four RFC 9846 §4 message parsers take one whole Handshake
  -- structure — msg_type, uint24 length, body — and reply with the
  -- fields the client needs. Every refusal is one string, as `rec_open`
  -- does: the RFC fixes different alerts for different checks (§4.2's
  -- illegal_parameter and unsupported_extension, §9.2's
  -- missing_extension, §6.2's decode_error) and some it leaves to the
  -- implementation, so distinct strings would flag a spec-and-C
  -- disagreement about which MUST fired first as a mismatch. The alert
  -- itself lives in the model, where `Spec.Hsparse.Alert` names it.
  | ["hs_server_hello", mode, kex, msg] => do
    let m ← hexArg? msg
    -- `psk` and `nopsk` are hsparse.h's `psk_mode`: whether this
    -- client's ClientHello offered a PSK, which RFC 9846 §4.2 makes
    -- the test for whether a pre_shared_key response is admissible.
    let offered ← match mode with
      | "psk" => some true
      | "nopsk" => some false
      | _ => none
    -- `x25519` and `pq` are the Makefile's KEX values: the build's one
    -- offered group, which fixes the key_share group and share size.
    let k ← Spec.Hsparse.kexOf? kex
    return match Spec.Hsparse.parseServerHello k offered m with
      | .ok (.serverHello f) =>
        s!"sh {emit f.keyExchange} {emitNat? f.selectedIdentity}"
      | .ok (.helloRetryRequest f) => s!"hrr {emit f.cookie}"
      | .error _ => "ERR hs_server_hello reject"
  | ["hs_encrypted_extensions", msg] => do
    let m ← hexArg? msg
    return match Spec.Hsparse.parseEncryptedExtensions m with
      | .ok f => s!"ok {emitNat? f.recordSizeLimit}"
      | .error _ => "ERR hs_encrypted_extensions reject"
  | ["hs_certificate", msg] => do
    let m ← hexArg? msg
    return match Spec.Hsparse.parseCertificate m with
      | .ok f => s!"ok {f.entryCount} {emit f.leafCert}"
      | .error _ => "ERR hs_certificate reject"
  | ["hs_certificate_verify", alg, msg] => do
    let scheme ← Spec.Hsparse.schemeOf? alg
    let m ← hexArg? msg
    return match Spec.Hsparse.parseCertificateVerify scheme m with
      | .ok f => s!"ok {f.algorithm} {emit f.signature}"
      | .error _ => "ERR hs_certificate_verify reject"
  | ["hs_verify_content", hash] => do
    let h ← hexArg? hash
    -- RFC 9846 §4.4.3 signs over the transcript hash, which is
    -- SHA-256 under this profile's one cipher suite.
    guard (h.size == 32)
    return emit (Spec.Hsparse.verifyContent h)
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
  | ["rsa_verify", n, e, hash, sig] => do
    let nb ← hexArg? n
    let eNat ← e.toNat?
    let h ← hexArg? hash
    let sb ← hexArg? sig
    guard (h.size == 32)
    return if Spec.Rsa.pssVerify (bytesToNatBE nb) eNat h sb then "1" else "0"
  | ["rsa_sign", n, d, _e, salt, hash] => do
    let nb ← hexArg? n
    let db ← hexArg? d
    let saltb ← hexArg? salt
    let h ← hexArg? hash
    guard (saltb.size == 32 && h.size == 32)
    match Spec.Rsa.rsaSign (bytesToNatBE nb) (bytesToNatBE db) h saltb with
    | some sig => return emit sig
    | none => return "FAIL"
  | ["x509parse", alg, caKey, list] => do
    let a ← Spec.X509.algOf? alg
    let ck ← hexArg? caKey
    let l ← hexArg? list
    return match Spec.X509.parse a ck l with
      | some (key, some epoch) => s!"ok {bytesToHex key} {epoch}"
      | some (key, none) => s!"ok {bytesToHex key} -"
      | none => "ERR x509 reject"
  | ["x509mint", "rsa", n, d, salt, serial, issuer, validity, subject, leafKey, exts] => do
    let nb ← hexArg? n
    let db ← hexArg? d
    let saltB ← hexArg? salt
    let serialB ← hexArg? serial
    let issuerB ← hexArg? issuer
    let validityB ← hexArg? validity
    let subjectB ← hexArg? subject
    let leafKeyB ← hexArg? leafKey
    let extsB ← hexArg? exts
    guard (saltB.size == 32)
    match Spec.X509.mint (.rsa (bytesToNatBE nb) (bytesToNatBE db) saltB) serialB issuerB
        validityB subjectB leafKeyB extsB with
    | some out => return emit out
    | none => return "FAIL"
  | ["x509mint", "p256", d, k, serial, issuer, validity, subject, leafKey, exts] => do
    let db ← hexArg? d
    let kb ← hexArg? k
    let serialB ← hexArg? serial
    let issuerB ← hexArg? issuer
    let validityB ← hexArg? validity
    let subjectB ← hexArg? subject
    let leafKeyB ← hexArg? leafKey
    let extsB ← hexArg? exts
    guard (db.size == 32 && kb.size == 32)
    match Spec.X509.mint (.p256 (bytesToNatBE db) (bytesToNatBE kb)) serialB issuerB validityB
        subjectB leafKeyB extsB with
    | some out => return emit out
    | none => return "FAIL"
  | ["x509mintchain", "rsa", caN, caD, intN, intD, salt, serial, issuer, validity, subject,
      leafKey, leafExts, intExts] => do
    let caNB ← hexArg? caN
    let caDB ← hexArg? caD
    let intNB ← hexArg? intN
    let intDB ← hexArg? intD
    let saltB ← hexArg? salt
    let serialB ← hexArg? serial
    let issuerB ← hexArg? issuer
    let validityB ← hexArg? validity
    let subjectB ← hexArg? subject
    let leafKeyB ← hexArg? leafKey
    let leafExtsB ← hexArg? leafExts
    let intExtsB ← hexArg? intExts
    guard (saltB.size == 32)
    match Spec.X509.mintChain (.rsa (bytesToNatBE caNB) (bytesToNatBE caDB) saltB)
        (.rsa (bytesToNatBE intNB) (bytesToNatBE intDB) saltB) serialB issuerB validityB
        subjectB leafKeyB leafExtsB intExtsB with
    | some out => return emit out
    | none => return "FAIL"
  | ["x509mintchain", "p256", caD, caK, intD, intK, serial, issuer, validity, subject,
      leafKey, leafExts, intExts] => do
    let caDB ← hexArg? caD
    let caKB ← hexArg? caK
    let intDB ← hexArg? intD
    let intKB ← hexArg? intK
    let serialB ← hexArg? serial
    let issuerB ← hexArg? issuer
    let validityB ← hexArg? validity
    let subjectB ← hexArg? subject
    let leafKeyB ← hexArg? leafKey
    let leafExtsB ← hexArg? leafExts
    let intExtsB ← hexArg? intExts
    guard (caDB.size == 32 && caKB.size == 32 && intDB.size == 32 && intKB.size == 32)
    match Spec.X509.mintChain (.p256 (bytesToNatBE caDB) (bytesToNatBE caKB))
        (.p256 (bytesToNatBE intDB) (bytesToNatBE intKB)) serialB issuerB validityB subjectB
        leafKeyB leafExtsB intExtsB with
    | some out => return emit out
    | none => return "FAIL"
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
