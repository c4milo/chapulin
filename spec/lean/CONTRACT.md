# Spec module contract

The Lean spec is a differential oracle for the C stack. Rules:

1. **Independence**: write every function from the RFC text (cite the
   section in a doc comment). Never look at the C sources; if you need a
   detail, it is in the RFC. Definitional style: arithmetic over `Nat`
   with explicit `mod`, no performance tricks unless a vector demands it.
2. **Signatures are fixed** (namespaces and types exactly as below).
3. Every module ends with a `selftest (_ : Unit) : Bool`, `true` iff
   all checks pass, under `set_option compiler.extract_closed false in`.
   Lean computes an argument-free definition, and every closed term the
   compiler lifts out of a body, when the program starts. A
   `selftest : Bool` made every start of `diffspec` run P-384's
   signatures, 11 seconds before the first request. Most check the RFC's published vectors; Record, Drbg, and X509
   have no third-party vectors and their selftests are structural
   (framing, nonce construction, rekeying, mint/parse round trips) —
   the differential and, for Record, the planned RFC 8448 trace replay
   carry the known-answer weight there.

```
Spec.Sha256.sha256    : ByteArray → ByteArray                          -- FIPS 180-4, 32 bytes out
Spec.Sha512.sha512    : ByteArray → ByteArray                          -- FIPS 180-4 §6.4, 64 bytes out
Spec.Sha512.sha384    : ByteArray → ByteArray                          -- FIPS 180-4 §6.5, 48 bytes out
Spec.P384.ecdsaVerify : (pub hash : ByteArray) → (r s : Nat) → Bool    -- FIPS 186-4 §6.4 over P-384,
                        -- X‖Y 96 bytes, a 48-byte hash; the caller truncates or pads any other length
Spec.RsaPkcs1.pkcs1Verify : (n e : Nat) → (digest sig : ByteArray) → Bool
                        -- RFC 8017 §8.2.2, the DigestInfo chosen by the digest length: 32 SHA-256, 48 SHA-384.
                        -- Domain: any n; the C admits 256..CH_RSA_MODULUS_MAX bytes in 8-byte
                        -- steps (512 under CH_TRUST_WEBPKI, the build this verifier ships in),
                        -- and the differential samples 2048, 3072 and 4096 bits at both digests.
Spec.Sha3.sha3_256    : ByteArray → ByteArray                          -- FIPS 202, 32 bytes out
Spec.Sha3.sha3_512    : ByteArray → ByteArray                          -- FIPS 202, 64 bytes out
Spec.Sha3.shake128    : ByteArray → (outLen : Nat) → ByteArray         -- FIPS 202 XOF
Spec.Sha3.shake256    : ByteArray → (outLen : Nat) → ByteArray         -- FIPS 202 XOF
Spec.MlKem.keygen     : (d z : ByteArray) → ByteArray × ByteArray      -- FIPS 203 §7.1,
                        -- ML-KEM-768: (ek, dk) = (1184, 2400) bytes from the
                        -- two 32-byte seeds, via §6.1's derandomized
                        -- ML-KEM.KeyGen_internal. Line op:
                        -- `mlkem_keygen <d> <z>` → `<ek> <dk>`.
Spec.MlKem.encaps     : (ek m : ByteArray) → Option (ByteArray × ByteArray)
                        -- FIPS 203 §7.2 with §6.2's derandomized
                        -- ML-KEM.Encaps_internal: some (ct, ss) =
                        -- (1088, 32) bytes; none when ek fails §7.2's
                        -- checks: not 1184 bytes, or a coefficient not
                        -- reduced mod q.
                        -- Line op: `mlkem_encaps <ek> <m>` →
                        -- `<ct> <ss>` / `FAIL`.
Spec.MlKem.decaps     : (dk ct : ByteArray) → ByteArray                -- FIPS 203 §7.3
                        -- via §6.3's ML-KEM.Decaps_internal: the 32-byte
                        -- shared secret; a tampered ciphertext yields the
                        -- implicit-reject secret J(z ‖ ct), never an error.
                        -- Line op: `mlkem_decaps <dk> <ct>` → `<ss>`.
Spec.Hkdf.hmac        : (key msg : ByteArray) → ByteArray              -- RFC 2104 w/ SHA-256
Spec.Hkdf.extract     : (salt ikm : ByteArray) → ByteArray             -- RFC 5869
Spec.Hkdf.expand      : (prk info : ByteArray) → (len : Nat) → ByteArray
Spec.Hkdf.expandLabel : (secret : ByteArray) → (label : String) →
                        (ctx : ByteArray) → (len : Nat) → ByteArray    -- RFC 9846 §7.1
Spec.Hkdf.schedule    : (psk ecdhe helloHash finHash : ByteArray) →
                        (ByteArray × ByteArray × ByteArray × ByteArray)
                        -- (cHs, sHs, cAp, sAp) per RFC 9846 §7.1 with a PSK and
                        -- no early data: early = extract 0 psk;
                        -- hs = extract (deriveSecret early "derived" empty) ecdhe;
                        -- cHs/sHs from helloHash; master from hs;
                        -- cAp/sAp from finHash. ecdhe is the key-exchange
                        -- IKM at any length — HKDF sets no size — and the
                        -- builds feed two: 32 octets (x25519) or 64 (the
                        -- hybrid's mlkem_ss then x25519_ss, RFC 10024's order).
Spec.ChaCha.xor       : (key nonce : ByteArray) → (counter : UInt32) →
                        (data : ByteArray) → ByteArray                 -- RFC 8439 §2.4
Spec.Poly.mac         : (key msg : ByteArray) → ByteArray              -- RFC 8439 §2.5, Nat mod 2^130-5
Spec.Aead.seal        : (key nonce aad pt : ByteArray) → ByteArray     -- RFC 8439 §2.8, ct ++ tag
Spec.Aead.open?       : (key nonce aad ct tag : ByteArray) → Option ByteArray
Spec.Record.seal      : (trafficSecret : ByteArray) → (seq : Nat) →
                        (ctype : UInt8) → (pt : ByteArray) → ByteArray
                        -- RFC 9846 §7.3: key/iv = expandLabel secret "key"/"iv",
                        -- nonce = iv XOR seq (BE, low 8 bytes), inner = pt ++ [ctype],
                        -- header 17 03 03 len, out = header ++ seal(...)
Spec.Drbg.next        : (key : ByteArray) → (n : Nat) →
                        (ByteArray × ByteArray)                        -- fast key erasure over ChaCha20:
                        -- (next key, n output bytes) from one request
Spec.Record.open?     : (trafficSecret : ByteArray) → (seq : Nat) →
                        (rec : ByteArray) → Option (ByteArray × UInt8)
                        -- RFC 9846 §5.2-5.4 deprotection, the inverse of seal:
                        -- outer type 17, the length field against the record,
                        -- the §5.2 record_overflow and §5.4 inner ceilings, the
                        -- AEAD tag under the §5.3 nonce, then §5.4's scan from
                        -- the end for the content type. The type is handed back
                        -- as found — which types are legal where belongs to the
                        -- reader above this layer, as it does in the C, so the
                        -- two model the same function. Line op:
                        -- `rec_open <secret> <seq> <record>` →
                        -- `ok <ctype> <content>` / `ERR rec_open reject`.
Spec.Record.nextSecret : (secret : ByteArray) → ByteArray             -- RFC 9846 §7.2 "traffic upd"
Spec.X25519.scalarMult : (scalar point : ByteArray) → ByteArray        -- RFC 7748 §5, Nat mod 2^255-19
Spec.X25519.base       : (scalar : ByteArray) → ByteArray              -- point = 9
Spec.P256.pubKey?     : (d : Nat) → Option ByteArray                   -- FIPS 186-4 §D.1.2.3, X‖Y 64 bytes
Spec.P256.ecdsaSign   : (d k z : Nat) → Option (Nat × Nat)             -- FIPS 186-4 §6.4, (r, s);
                        -- none for d/k outside [1, n-1] or r/s = 0. The spec
                        -- signs so the oracle can mint valid signatures; the C
                        -- side only ever verifies.
Spec.P256.ecdsaVerify : (pub hash : ByteArray) → (r s : Nat) → Bool    -- SEC 1 v2 §4.1.4
Spec.HandshakeParser.parseServerHello : (kex : Kex) → (suiteOffer : SuiteOffer) →
                        (pskOffered : Bool) → (msg : ByteArray) →
                        Except Alert ServerHelloKind                    -- RFC 9846 §4.2.3, §4.2.4.
                        -- Takes the whole Handshake structure of §4 (msg_type,
                        -- uint24 length, body); handshake_parser.c's entry points take the
                        -- body, so the driver frames it. kex is the Makefile's
                        -- KEX variable for a raw or ca build, and twoGroups for
                        -- every TRUST=webpki build. x25519 lists x25519
                        -- (0x001D) alone and pq lists RFC 10024's
                        -- X25519MLKEM768 (0x11EC) alone; twoGroups
                        -- (docs/decisions.md entry 53) lists X25519MLKEM768
                        -- then x25519. Every build sends a key share for each
                        -- group it lists. A ServerHello may select any listed
                        -- group, and that group fixes the server share size
                        -- (32, or 1120 — the ML-KEM-768 ciphertext then the
                        -- x25519 value). A HelloRetryRequest may name a listed
                        -- group the hello sent no share for, which no build
                        -- has, and must ask for a change, so every accepted
                        -- retry carries a cookie (§4.2.4, §4.3.8).
                        -- suiteOffer names the cipher_suites list the
                        -- ClientHello sends (§4.2.2). chacha lists TLS_CHACHA20_POLY1305_SHA256 (0x1303)
                        -- alone, the offer of every client build but one.
                        -- chachaAndAes, the SUITE=aesgcm TRUST=webpki
                        -- client (docs/decisions.md entries 45 and 58),
                        -- lists 0x1303, then TLS_AES_128_GCM_SHA256
                        -- (0x1301), then TLS_AES_256_GCM_SHA384 (0x1302).
                        -- A ServerHello
                        -- or HelloRetryRequest may carry any listed suite,
                        -- and both report it. Whether a ServerHello carries
                        -- the suite of the retry before it (§4.2.4) turns on
                        -- whether a retry happened, so neither parser
                        -- checks it.
                        -- pskOffered is handshake_parser.h's
                        -- psk_mode: §4.3 makes a pre_shared_key response
                        -- admissible only if the ClientHello offered one, which
                        -- the message alone cannot settle.
                        -- Everything else the profile fixes is a byte compare
                        -- against a constant: legacy_version 0x0303, the empty
                        -- legacy_session_id_echo handshake_message.c offers, the build's
                        -- cipher suites, the build's groups. Line op:
                        -- `hs_server_hello <psk|nopsk> <x25519|pq|two-groups>
                        -- <chacha|aesgcm> <msg>` →
                        -- `sh <group> <key_exchange> <selected_identity|-> <suite>`
                        -- / `hrr <cookie|-> <selected_group|-> <suite>`
                        -- / `ERR hs_server_hello reject`.
                        -- The chacha and aesgcm tokens spell the Makefile's
                        -- SUITE values for chacha and chachaAndAes.
                        -- group is the accepted key_share's NamedGroup in
                        -- decimal, read from the message on both sides:
                        -- the C stores it in server_hello_info.group, which
                        -- the handshake copies to ch_tls.group. selected_group
                        -- is the retry key_share's NamedGroup in decimal.
                        -- suite is the message's cipher_suite in decimal.
Spec.HandshakeParser.parseEncryptedExtensions : (serverNameSent : Bool) →
                        (alpnOffered : List ByteArray) → (certTypesOffered : List Nat) →
                        (msg : ByteArray) → Except Alert EncryptedExtensions
                        -- RFC 9846 §4.4.1.
                        -- serverNameSent says whether the ClientHello
                        -- carried server_name: TRUST=webpki's does when its
                        -- configuration has a hostname, and RFC 6066 §3 then
                        -- admits one empty acknowledgement, with data there a
                        -- decode_error; otherwise, and always in the raw and
                        -- ca builds, the acknowledgement is unrequested.
                        -- alpnOffered is the ProtocolNameList the hello
                        -- offered (RFC 7301 §3.1), empty for none; a
                        -- selection must name one of them, and is reported as
                        -- its index. certTypesOffered is the CertificateType
                        -- list its server_certificate_type offered (RFC 7250
                        -- §4.1), empty for none; a selection is one octet the
                        -- list holds (§4.2), and an empty list makes the
                        -- extension unrequested. Line op:
                        -- `hs_encrypted_extensions <sni|nosni> <alpn|-> <types|-> <msg>`
                        -- → `ok <record_size_limit|-> <alpn_index|-> <cert_type|->`
                        -- (RFC 8449 §4, decimal, the extension's own value;
                        -- handshake_parser_ee.c stores it less the inner
                        -- content-type octet) / `ERR ... reject`. alpn is the
                        -- ProtocolNameList's hex and types the CertificateType
                        -- list's hex, one octet per type; cert_type is decimal.
Spec.HandshakeParser.parseCertificate : (msg : ByteArray) → Except Alert Certificate
                        -- RFC 9846 §4.5.1: the empty certificate_request_context
                        -- then the exact-fill CertificateEntry list, whose
                        -- per-entry extensions must be ones the client offered —
                        -- none. Line op: `hs_certificate <msg>` →
                        -- `ok <entry_count> <leaf_cert_data>` / `ERR ... reject`.
Spec.HandshakeParser.parseCertificateVerify : (offer : SignatureOffer) → (msg : ByteArray) →
                        Except Alert CertificateVerify                 -- RFC 9846 §4.5.2:
                        -- one of `offer.certificateVerifyCodes`, then an
                        -- exact-fill `opaque signature<0..2^16-1>`. offer is a
                        -- pinned build's one Scheme, or the TRUST=webpki build's
                        -- five, of which the three leaf-key schemes pass; every
                        -- other scheme gets one verdict. The signature's
                        -- length is the verifier's business, not the parser's.
                        -- Line op: `hs_certificate_verify <rsa|p256|webpki> <msg>` →
                        -- `ok <algorithm> <signature>` / `ERR ... reject`.
Spec.HandshakeParser.verifyContent : (transcriptHash : ByteArray) → ByteArray  -- RFC 9846 §4.5.2's
                        -- 130 signed octets: 64 spaces, the context string, a
                        -- zero, the hash. Line op: `hs_verify_content <hash>`.
Spec.Rsa.pssVerify    : (n e : Nat) → (mHash sig : ByteArray) → Bool    -- RFC 8017 §8.1.2,
                        -- rsa_pss_rsae_sha256: SHA-256, MGF1-SHA256, saltLen 32. Domain: any n;
                        -- the C admits 256..CH_RSA_MODULUS_MAX bytes in 8-byte steps (384 in the
                        -- device modes, 512 under CH_TRUST_WEBPKI), and the differential samples
                        -- 2048, 3072 and 4096 bits against a C built with that define.
Spec.Rsa.pssSign      : (n d : Nat) → (mHash salt : ByteArray) →
                        Option ByteArray                                -- RFC 8017 §8.1.1;
                        -- rsaSign is an alias. The spec signs so the oracle can mint
                        -- signatures the C verifier must accept; the C side only verifies.
                        -- salt is explicit so a fixed value gives a reproducible signature.
Spec.Pem.decode?      : (derMax : Nat) → ByteArray → Option ByteArray
                        -- RFC 7468 §2 armour and RFC 4648 §4 base64 for one
                        -- CERTIFICATE block. Domain: the text at most
                        -- `pemMax derMax` bytes; the BEGIN boundary exactly,
                        -- terminated by LF or CRLF; CR and LF ignored anywhere
                        -- in the body, so every text under the cap decodes
                        -- alike at any width (four characters or wider always
                        -- fits; narrower can exceed the cap at full size);
                        -- RFC 4648 §3.5 canonical padding with the unused bits
                        -- zero; the END boundary; nothing but CR and LF after
                        -- it. Four deliberate departures from the RFCs, all
                        -- narrowing: no explanatory text before the boundary
                        -- (§5.2 allows it), no second block, a bare CR is not a
                        -- line terminator (§3's ABNF admits it), and an empty
                        -- body is rejected. Line op: `pemdecode <derMax> <hex>`
                        -- → `ok <der>` / `ERR pem reject`.
Spec.X509Ca.caKey?    : Alg → (derMax : Nat) → ByteArray → Option ByteArray
                        -- provisioning: one PEM certificate to the SPKI key
                        -- bytes ch_cfg.server_pubkey takes. Composes
                        -- Spec.Pem.decode? with the RFC 5280 §4.1 walk. NOT
                        -- Spec.X509.parse's profile, and the differences are
                        -- the point: the signature's framing is read and its
                        -- bytes never checked, validity and issuer and subject
                        -- go unread, basicConstraints must say cA TRUE and any
                        -- pathLenConstraint is accepted (§4.2.1.9), keyUsage is
                        -- optional and must permit keyCertSign when present
                        -- (§4.2.1.3), extendedKeyUsage is not required and is
                        -- rejected when critical like any unrecognized critical
                        -- extension (§4.2). Decoding is not authenticating: this
                        -- yields bytes, never a verdict. Line op:
                        -- `pemcakey <alg> <derMax> <hex>` → `ok <key>` /
                        -- `ERR pemcakey reject`.
Spec.WebpkiTime.readTime : ByteArray → (off : Nat) → Option (Nat × Nat)
                        -- RFC 5280 §4.1.2.5: one Time TLV at off — UTCTime
                        -- YYMMDDHHMMSSZ, its two-digit year 1950..2049 by the
                        -- section's rule, or GeneralizedTime YYYYMMDDHHMMSSZ,
                        -- admitted from 2050 — with X.690 §10.1's minimal length
                        -- and every field in range, the day held to its month in
                        -- its year. `some (packed, end)`: the decimal number
                        -- YYYYMMDDHHMMSS and the offset past the Time. Line op:
                        -- `webpki_time <hex>` → `ok <packed> <end>` /
                        -- `ERR webpki_time reject`.
Spec.WebpkiTime.packSeconds : Nat → Nat
                        -- seconds since 1970-01-01T00:00:00Z in the same packed
                        -- form, over the proleptic Gregorian calendar (RFC 3339
                        -- §5.7's leap rule), clamped at 253402300799
                        -- (9999-12-31T23:59:59Z) so the result stays inside
                        -- readTime's range. Line op: `webpki_pack <seconds>` →
                        -- `<packed>`.
Spec.WebpkiName.hostnameOk : List UInt8 → Bool
                        -- the reference name's shape: 1..253 bytes of
                        -- [A-Za-z0-9.-], every label 1..63 bytes (RFC 1035
                        -- §2.3.4), no label that starts or ends with '-' (RFC
                        -- 1123 §2.1), a last label not all digits (RFC 6066 §3
                        -- forbids an IP literal in server_name). Line op:
                        -- `webpki_hostname <hex>` → `1`/`0`.
Spec.WebpkiName.matchSan : ByteArray → List UInt8 → Bool
                        -- RFC 6125 §6.4 over the dNSName entries of one whole
                        -- GeneralNames (RFC 5280 §4.2.1.6): ASCII
                        -- case-insensitive equality, or a wildcard that is the
                        -- whole leftmost label of the presented name, stands for
                        -- exactly one label of the host and has two labels after
                        -- it. Every entry's tag must be one of GeneralName's nine
                        -- DER identifier bytes and its length minimal and inside
                        -- the SEQUENCE; one entry that breaks either refuses the
                        -- whole GeneralNames. Line op: `webpki_san <san> <host>` →
                        -- `1`/`0`.
Spec.X509.parse       : Alg → (caKey list : ByteArray) →
                        Option (ByteArray × Option Nat)
                        -- profiled chain acceptance over the RFC 9846 §4.5.1
                        -- CertificateEntry list (empty per-entry extensions):
                        -- one entry, the leaf verified directly under caKey;
                        -- or two, the leaf then the intermediate — the
                        -- intermediate verified under caKey and the leaf under
                        -- the intermediate's SPKI. Each certificate: at most
                        -- `certMax alg` bytes — 768 (p256) or 1536 (rsa),
                        -- mirroring x509.h's per-build CH_X509_MAX defaults
                        -- (the C cap is overridable per build; the spec models
                        -- the defaults) — in canonical DER (X.690 §10, with
                        -- §8.19-minimal extnID subidentifiers), the RFC 5280
                        -- v3 profile with its
                        -- arm's extensions — leaf: keyUsage(digitalSignature)
                        -- + extendedKeyUsage(serverAuth); intermediate:
                        -- keyUsage(keyCertSign) + basicConstraints(CA=TRUE,
                        -- pathLen 0), extendedKeyUsage forbidden. `some`
                        -- carries the leaf's SPKI key bytes (RSA modulus
                        -- value, or P-256 X‖Y) paired with its notBefore's
                        -- revocation-epoch number: `some (yy*336 +
                        -- (mm-1)*28 + (dd-1))` (0..16799) when the notBefore
                        -- is epoch-shaped — UTCTime, all twelve leading
                        -- characters ASCII digits, YY 00..49, MM 01..12,
                        -- DD 01..28, HHMMSS zero — and `none` in the pair for
                        -- every other valid Time shape (extraction stays
                        -- permissive; the C driver enforces the epoch rule).
                        -- The intermediate's validity digits go unread. Alg
                        -- is rsa (e = 65537, caKey = modulus bytes) or p256
                        -- (caKey = X‖Y). Line op:
                        -- `x509parse <alg> <cakey> <list>` →
                        -- `ok <key> <epoch>` (`-` when the notBefore is not
                        -- epoch-shaped) / `ERR x509 reject`.
Spec.X509.mint        : CaKey → (serial issuer validity subject leafKey exts :
                        ByteArray) → Option ByteArray
                        -- canonical CA-signed leaf as a one-entry
                        -- CertificateEntry list; the driver supplies every
                        -- field and the CA private key (rsa n/d and a 32-byte
                        -- PSS salt, or p256 d/k), so the C parser must accept
                        -- every minted certificate. `ecdsaSigDer` is the
                        -- spec-side ECDSA-Sig-Value encoder the p256 arm signs
                        -- through. Line ops: `x509mint rsa <n> <d> <salt>
                        -- <serial> <issuer> <validity> <subject> <leafkey>
                        -- <exts>` and `x509mint p256 <d> <k> <serial> ...same
                        -- fields` → `<list>` / `FAIL`.
Spec.X509.mintChain   : (ca int : CaKey) → (serial issuer validity subject
                        leafKey leafExts intExts : ByteArray) →
                        Option ByteArray
                        -- canonical chained pair as a two-entry
                        -- CertificateEntry list: the leaf (leafExts) signed by
                        -- the intermediate key, then the intermediate — its
                        -- SPKI is int's own public key, its extensions
                        -- intExts — signed by the CA. Both certificates share
                        -- the driver-supplied serial, issuer, validity, and
                        -- subject. The C parser must accept every minted
                        -- chain whose extensions are on-profile; off-profile
                        -- intExts mint chains the profile check alone must
                        -- reject. Line ops: `x509mintchain rsa <ca_n> <ca_d>
                        -- <int_n> <int_d> <salt> <serial> <issuer> <validity>
                        -- <subject> <leafkey> <leafexts> <intexts>` and
                        -- `x509mintchain p256 <ca_d> <ca_k> <int_d> <int_k>
                        -- <serial> ...same fields` → `<list>` / `FAIL`.
Spec.WebpkiSpki.readSpki? : ByteArray → Option (KeyAlg × ByteArray)
                        -- TRUST=webpki SubjectPublicKeyInfo (RFC 5280 §4.1.2.7): the
                        -- AlgorithmIdentifier decoded and judged — rsaEncryption with
                        -- NULL (RFC 3279 §2.3.1), id-ecPublicKey with prime256v1 or
                        -- secp384r1 (RFC 5480 §2.1.1) — then the key: RSAPublicKey as
                        -- two DER INTEGERs, exponent 65537, modulus bit length a
                        -- multiple of 64 from 2048 to 8 * modulusMax (512, the
                        -- CH_TRUST_WEBPKI CH_RSA_MODULUS_MAX) and odd, returned as its
                        -- big-endian bytes; or 0x04 ‖ X ‖ Y, returned as X ‖ Y. Whole
                        -- TLV, exact-fill; the C reads a stream and the driver
                        -- projects. The curve check is the verifier's. Line op:
                        -- `webpki_spki <spki>` → `ok <rsa|p256|p384> <key>` /
                        -- `ERR webpki_spki reject`.
Spec.WebpkiSigalg.readSigalg? : ByteArray → Option SigAlg
                        -- the certificate signatureAlgorithm (RFC 5280 §4.1.1.2),
                        -- decoded and judged: sha256WithRSAEncryption and
                        -- sha384WithRSAEncryption with NULL (RFC 4055 §5),
                        -- ecdsa-with-SHA256 and ecdsa-with-SHA384 with no parameters
                        -- (RFC 5758 §3.2). Whole TLV. Line op: `webpki_sigalg <der>` →
                        -- `ok <rsa_sha256|rsa_sha384|ecdsa_sha256|ecdsa_sha384>` /
                        -- `ERR webpki_sigalg reject`.
Spec.WebpkiSigalg.verify : SigAlg → KeyAlg → (key tbs sig : ByteArray) → Bool
                        -- the hash the algorithm names over tlv 0x30 tbs, then RFC 8017
                        -- §8.2.2 with e = 65537 for an RSA algorithm and key, or ECDSA
                        -- over the curve's message hash — FIPS 186-4 §6.4's leftmost
                        -- min(N, outlen) bits as coordinate-length bytes — for an ECDSA
                        -- algorithm and an EC key; false for a family mismatch or a tbs
                        -- over certMax (3072, CH_WEBPKI_CERT_MAX). Line op:
                        -- `webpki_verify <name> <spki> <tbs> <sig>` → 1/0, the spki read
                        -- with readSpki? (refused → 0).
Spec.WebpkiSigalg.sign : SigAlg → Signer → (tbs : ByteArray) → Option (ByteArray × ByteArray)
                        -- the inverse the oracle mints with: (the signer's SPKI in
                        -- encodeSpki's encoding, the signature), none for a family
                        -- mismatch. Line ops: `webpki_sign <name> rsa <n> <d> <tbs>` and
                        -- `webpki_sign <name> p256|p384 <d> <k> <tbs>` → `<spki> <sig>` /
                        -- `FAIL`.
Spec.WebpkiCert.parseCertificate? : (isCa : Bool) → (cert : ByteArray) → Option Certificate
                        -- one TRUST=webpki certificate (RFC 5280 §4.1) under an arm, false
                        -- for the leaf and true for an issuer: at most certificateMax
                        -- (3072, CH_WEBPKI_CERT_MAX) bytes, exact-fill at every level;
                        -- version 3 (§4.1.2.1); a serial readSerial accepts, at most 20
                        -- value bytes (§4.1.2.2); a signature field readSigalg? accepts,
                        -- which the outer signatureAlgorithm equals byte for byte
                        -- (§4.1.1.2); issuer and subject as whole Name TLVs; a validity
                        -- of two readTime values, notBefore no later than notAfter; an
                        -- SPKI readSpki? accepts; readExtensions? at the extensions field
                        -- and nothing after it, so no unique identifier (§4.1.2.8); a BIT
                        -- STRING signature with zero unused bits and one byte or more.
                        -- `some` carries every range as an offset and a length into the
                        -- certificate, the whole SubjectPublicKeyInfo TLV among them. The
                        -- alert a refusal names is not modeled. Line op:
                        -- `webpki_cert <0|1> <cert>` → `ok <tbs off len> <issuer off len>
                        -- <subject off len> <notBefore> <notAfter> <spki off len>
                        -- <rsa|p256|p384> <key> <sigalg> <sig off len>
                        -- <san off len | - 0> <seen> <cA> <pathLen | ->` /
                        -- `ERR webpki_cert reject`.
Spec.WebpkiCert.readExtensions? : (isCa : Bool) → (b : ByteArray) → (off : Nat) →
                        Option (Extensions × Nat)
                        -- extensions [3] EXPLICIT at off (§4.1): 1 to extensionCountMax (16)
                        -- Extensions of at most extensionTlvMax (1024) bytes, §8.19-minimal
                        -- extnIDs, each read at most once — keyUsage with the arm's bit
                        -- among others (readKeyUsage, §4.2.1.3); extendedKeyUsage with
                        -- id-kp-serverAuth among its purposes on the leaf and unread on an
                        -- issuer (§4.2.1.12); basicConstraints in canonical DER, cA equal to
                        -- the arm, critical on an issuer, a pathLenConstraint only with cA
                        -- and at most 32767 (§4.2.1.9); subjectAltName recorded, unread
                        -- (§4.2.1.6) — and every other extension skipped when not critical
                        -- and refused when critical (§4.2). The leaf needs keyUsage,
                        -- extendedKeyUsage and subjectAltName, an issuer keyUsage and
                        -- basicConstraints. Driven through `webpki_cert`.
Spec.Webpki.verifyChain : Config → (list : ByteArray) → Verdict
                        -- the TRUST=webpki chain walk (docs/webpki.md, "The chain
                        -- walk") over one RFC 9846 §4.5.1 CertificateEntry list:
                        -- readEntries? frames 1 to flightEntries (4) entries of at
                        -- most certificateMax (3072) bytes; entry 0 parses under the
                        -- leaf arm, its validity covers the clock at both ends
                        -- inclusive, and a dNSName of its subjectAltName matches the
                        -- hostname; then walkFrom consults the anchors at each depth
                        -- before reading the next entry, and reads at most chainMax
                        -- (3) certificates. `ok` carries the leaf's key, the count of
                        -- certificates read and the index of the first anchor that
                        -- verified the last of them. The four refusals are the four pairs
                        -- of return code and alert the C tells apart: rejected
                        -- (CH_EPROTO), expired, unauthenticated (bad_certificate) and
                        -- unknownCa. The alert itself is not modeled. Line op:
                        -- `webpki_chain <packed clock> <hostname> <anchors> <pins> <list>`
                        -- → `ok <rsa|p256|p384> <key> <path> <anchor> <1|0>` / the
                        -- refusal's name, where <anchors> is `-` or `name.spki` hex pairs
                        -- joined by commas, <pins> is `-` or hex pins joined by commas,
                        -- and the last field is Spec.WebpkiPin.pathPinned over the path.
Spec.Webpki.walkFrom  : Config → (cert : ByteArray) → Certificate → (rest : List ByteArray) →
                        (read : Nat) → Step
                        -- steps 6a to 6g from one certificate: the first anchor whose
                        -- subject Name equals this certificate's issuer Name and whose
                        -- key verifies it ends the walk, `reached` with read and that
                        -- anchor's index; otherwise the next entry is read as an issuer,
                        -- checked against the clock, this certificate's issuer Name and
                        -- its own pathLenConstraint, and must verify this certificate.
                        -- Driven through `webpki_chain`.
Spec.WebpkiPin.verifyRawKey : (pins : List ByteArray) → (list : ByteArray) → RawVerdict
                        -- an RFC 7250 RawPublicKey CertificateEntry list (RFC 9846
                        -- §4.5.1): exactly one entry of 1 to spkiMax (550,
                        -- CH_WEBPKI_SPKI_MAX) bytes with an empty extensions vector and
                        -- nothing after it, whose bytes readSpki? reads whole, and a pin
                        -- equal to their SHA-256 (RFC 7858 §4.2). The four refusals are
                        -- the pairs of return code and alert the C tells apart: rejected
                        -- (framing, bad_certificate), unsupported_extension,
                        -- unsupported_certificate and unpinned (CH_EAUTH). Line op:
                        -- `webpki_raw <pins> <list>` → `ok <rsa|p256|p384> <key>` / the
                        -- refusal's name.
Spec.WebpkiPin.pathPinned : (pins : List ByteArray) → (anchors : List Anchor) →
                        (list : ByteArray) → (path anchor : Nat) → Bool
                        -- a pin names the SubjectPublicKeyInfo of one of the first `path`
                        -- entries, each parsed under the arm the walk read it under, or
                        -- of the anchor at index `anchor`; an entry after the path does
                        -- not count. Driven through `webpki_chain` on accepted chains,
                        -- the domain webpki_pin.h's contract names.
Spec.Handshake.step   : (mode : Mode) → State → Msg → Option State      -- RFC 9846 §4 order of
                        -- server-to-client messages after the ClientHello; none = fatal
                        -- (unexpected_message). Msg has one constructor per line-protocol
                        -- letter (S H E C R V F N K A L); Mode is psk or pinned. `pinned`
                        -- models the raw-pin build; CA builds share the
                        -- message order but no sequence oracle covers them — the e2e
                        -- run does.
Spec.Handshake.accepts : (mode : Mode) → (msgs : List Msg) → Bool       -- fold step from start;
                        -- accept iff every message is legal and the handshake completes
                        -- (connected, optionally then close_notify). Line op:
                        -- `handshake_sequence <mode> <letters>` → 1/0, `-` for the empty sequence.
Spec.Epoch.check      : (bound stored : Nat) → (cert : Option Nat) → Bool
                        -- docs/ca.md, INV-21: handshake.c's epoch_check over one
                        -- leaf. cert is the certificate reader's epoch number —
                        -- `some e` when the notBefore is epoch-shaped
                        -- (leaf.epoch_ok set, value leaf.epoch), `none` for any
                        -- other valid date. Accepts iff
                        -- `stored ≤ e ≤ stored + bound`; the C's two refusals
                        -- differ only by alert. No line op: see "Epoch is not an
                        -- oracle" below.
Spec.Epoch.commit     : (stored : Nat) → (cert : Option Nat) → Nat
                        -- hsa_epoch_commit: raise the stored epoch to e when e is
                        -- strictly higher, else leave it. Takes no bound, because
                        -- the C function reads none.
Spec.Epoch.step       : (bound stored : Nat) → (cert : Option Nat) → Nat
                        -- one CA-mode handshake: commit only where check
                        -- accepted. That is the C's call order — epoch_check in
                        -- hsa_server_auth, hsa_epoch_commit in run after
                        -- expect_finished — and it is what bounds the result.
Spec.Epoch.storedAfter : (bound stored : Nat) → (certs : List (Option Nat)) → Nat
                        -- ch_tls.epoch after one handshake per certificate, in
                        -- order: `certs.foldl (step bound) stored`.
Spec.Epoch.acceptedCount : (bound : Nat) → Nat → List (Option Nat) → Nat
                        -- how many of those handshakes the check accepted, each
                        -- judged against the stored epoch as it stood then.
```

Shared helpers live in `Spec/Bytes.lean` (hex, BE/LE Nat coding, xor).
`Spec/Weierstrass.lean` is the curve arithmetic `Spec/P256.lean` and
`Spec/P384.lean` share: each instantiates it at its own constants and
keeps its own selftest, so the shared module has none and no line op.
It is the one module that imports Mathlib directly.
Build with `lake build` inside `spec/`. The build depends on Mathlib:
`lakefile.toml` pins it to the tag `v4.33.0`, the release that targets
the toolchain `lean-toolchain` pins, and `lake-manifest.json` records
the commit that tag named. Run `lake exe cache get` inside `spec/` once
after clone, and again when the pin moves. It downloads Mathlib's
compiled files; without them `lake build` compiles Mathlib from source,
which takes hours, so `make` checks for the files before every `lake
build` and names the command when they are missing. CI runs the same
command in `.github/actions/fetch-mathlib`.

## Epoch is not an oracle

`Spec/Epoch.lean` breaks two rules this file states elsewhere, and
both breaks are deliberate.

It has no line op and no `selftest`. Both functions live in
`handshake_auth.c`: `epoch_check` is `static` there, so nothing
outside that translation unit can call it at all, and while
`hsa_epoch_commit` has external linkage — the state machine in
`handshake.c` calls it after the server Finished — driving it from
`test/diff_test.c` would mean building a whole `handshake_state` with
the epoch callbacks configured, not passing two numbers. So the
differential still has nothing to compare against, and a selftest
would have nothing to check. Rule 3 asks every module for a selftest
because every other module is an oracle; here an unreached one would
be dead code.

That makes the module weaker than the rest of `spec/`, and the weaker
claim is the honest one. On docs/invariants.md's check scale a Lean
theorem "reaches the C only through the differential's agreement" —
and this module has no differential. Its theorems constrain the model
and nothing else. They say what the ordering and bound rule
guarantees for a device that applies it as the model does; no run
compares that model against the C. A C change that breaks the rule —
inverting the comparison in `hsa_epoch_commit`, dropping the bound term
from `epoch_check`, or moving the commit to where a rejected
certificate reaches it — leaves `lake build` green. INV-21 lists what
does guard those on the C side: the `CH_ASSERT` on
`server_finished_ok`, `test_epoch_cfg`, and the e2e `ca-epoch-*` legs.
Reading these definitions against those two C functions is a manual
step, and the module is written for it: both functions are short, and
`check` and `commit` sit next to the C names they model.

The model also drops three things the C does, each named in the
module's own doc comment: the `cfg.epoch_load == NULL` check that turns
the feature off, the `epoch_status`/`epoch_seen` reporting, and the
rule that a commit may run only after the server Finished — that last
one is message order, which `CH_ASSERT(h->server_finished_ok)` enforces
in the C and `Spec.Handshake` models as a trace property.

## Where the C and the model split a check

Both sides must refuse the same messages, but they need not refuse them
in the same function. `handshake_parser.c` is a framing parser: it hands what it
read to `handshake.c`, which decides whether the handshake can go on.
The model has no layer above it, so it makes those decisions where it
reads the field. Seven checks fall on opposite sides of that line, and
`test/diff_handshake_parser.h` projects the C answer down to the model's
boundary rather than weakening the model to match the split:

| check | C decides | model decides |
| --- | --- | --- |
| ServerHello with no key_share | `hello_exchange`, on `have_share` | `parseServerHello` |
| selected_identity outside the one offered index | `hsf_accept_server_hello` (`handshake_flight.c`), on `psk_ok`, and under `TRUST=webpki` on `HSP_SEEN_PRE_SHARED_KEY` | `parseServerHello` |
| HelloRetryRequest that asks for no change: no cookie | `hsf_read_server_hello` (`handshake_flight.c`), on an absent cookie | `parseServerHello` |
| CertificateEntry carrying an unoffered extension | the trust mode's certificate parser | `parseCertificate` |
| ServerHello that ignores the offered PSK | `hsf_accept_server_hello` (`handshake_flight.c`), on `psk_ok`: a raw or ca build ends the handshake, and a `TRUST=webpki` build goes on as a full handshake (docs/decisions.md 55) | nothing — both parsers accept it; whether resumption was required sits above them |
| two-group ServerHello that selects x25519 when `ch_cfg.require_pq` kept x25519 off the hello | `hsf_accept_server_hello` (`handshake_flight.c`), against `ch_cfg.require_pq` | nothing — both parsers accept either listed group; the flag sits above them |
| ServerHello after a HelloRetryRequest whose cipher suite is not the retry's (§4.2.4) | `hsf_read_server_hello` (`handshake_flight.c`), against `handshake_state.suite`, which the retry wrote | nothing — both parsers accept any listed suite; whether a retry happened sits above them |

The first four end the handshake on both sides, with one exception:
the unoffered CertificateEntry extension is refused only in a CA-mode
build, where `x509_verify_leaf` requires empty per-entry extensions. A pinned
build never reads the entries — it hashes the certificate into the
transcript and authenticates by the signature — so §4.5.1's MUST-abort
for that extension is unenforced there. The unread extension changes
nothing the signature does not already cover, so the gap is by design;
the model refuses the extension in both builds, and the driver projects
the CA-build verdict.

One more went the other way — the model bounded the CertificateVerify
signature by the pinned key's size, which §4.5.2 does not do and
`handshake_parser.c` leaves to the verifier — and the model gave the check up
rather than the driver paper over it.

## Proven properties

The spec also carries theorems, proved in the same module as the
definition they are about and checked by `lake build`. Where the
differential run shows C-and-spec agreement on the compared domain,
these theorems say what that agreement buys: a property known of the
model, not just a matching answer. All of them quantify over every
input; none assume the RFC vectors.

```
Spec.ChaCha.xor_xor          xor k n c (xor k n c d) = d               -- keystream determinism:
                             -- decryption is encryption (RFC 8439 §2.4)
Spec.Aead.open?_seal         open? of seal's ct (first |pt| bytes) and tag (last 16)
                             -- returns `some pt` for all key/nonce/aad/pt
Spec.Aead.open?_ne_tag       tag ≠ recomputed Poly1305 tag → open? = none
                             -- (needs Spec.Bytes.bytesToHex_inj: open? compares hex)
Spec.Record.aeadOpen_seal    splitting Record.seal's output at 5 and 5+|pt|+1 and
                             -- AEAD-opening with the §7.3 key/iv and §5.3 nonce returns
                             -- `some (pt ++ [ctype])`. `open?_seal` states the same
                             -- round trip at the record layer, where deprotection
                             -- now lives; this one remains as its AEAD-layer step.
Spec.Hkdf.expand_size        (expand prk info len).size = len          -- RFC 5869 §2.3 "first
Spec.Hkdf.expandLabel_size   (expandLabel s l c len).size = len        -- L octets of T"
Spec.Sha256.sha256_size      (sha256 msg).size = 32
Spec.Sha3.sha3_256_size      (sha3_256 msg).size = 32                  -- FIPS 202 §6.1-6.2
Spec.Sha3.sha3_512_size      (sha3_512 msg).size = 64
Spec.Sha3.shake128_size      (shake128 msg outLen).size = outLen
Spec.Sha3.shake256_size      (shake256 msg outLen).size = outLen
Spec.Sha3.absorb_size        (absorb rate padded).size = 200           -- the state string
Spec.Sha3.squeeze_size       (squeeze rate state outLen).size = outLen -- at a real rate
Spec.Sha3.pad_blocks         (pad rate domain msg).size % rate = 0     -- §B.2 pad10*1
Spec.Sha3.pad_prefix         padding keeps the message as a prefix
Spec.MlKem.keygen_ek_size    (keygen d z).1.size = 1184                -- FIPS 203 §6.1 key sizes
Spec.MlKem.keygen_dk_size    z.size = 32 → (keygen d z).2.size = 2400
Spec.MlKem.encaps_ct_size    encaps ek m = some (ct, ss) → ct.size = 1088   -- §6.2
Spec.MlKem.decaps_size       (decaps dk ct).size = 32                  -- §6.3, both the normal
                             -- and the implicit-reject branch
Spec.MlKem.byteEncode_size   (byteEncode F d).size = 32 * d            -- §4.2.1 ByteEncode_d,
Spec.MlKem.encode3_size      (encode3 v d).size = 96 * d               -- and over a rank-3 vector
Spec.Drbg.next_key_eq_block  the next key is the counter-0 ChaCha20 block under the
                             -- current key, so key advance does not depend on how many
                             -- output bytes the request asked for (next_key_indep)
Spec.Drbg.next_key_out_disjoint
                             -- the next key comes from keystream bytes 0..31 and the
                             -- output from 32 onward: no output byte is a key byte,
                             -- which is what fast key erasure rests on
Spec.Drbg.next_out_prefix    a shorter request is a prefix of a longer one under the
                             -- same key: every request is cut from one stream
Spec.Pem.decode?_encode      armour then decode is the identity: for non-empty der
                             -- within derMax whose armoured text fits pemMax,
                             -- decode? derMax (encode w der) = some der at EVERY
                             -- line width w — the decoder accepts all of the
                             -- encoder's range, independent of the C
Spec.Pem.b64Value?_table     b64Value? of the i-th RFC 4648 §4 alphabet character
                             -- is some i, all 64 — the table is the RFC's, not
                             -- a transcription of pem.c's compares
Spec.Pem.decode?_size        decode? derMax input = some d → d.size ≤ derMax
Spec.Pem.decode?_sound       an accepted input has the RFC 7468 frame: the text is
                             -- beginLine, one line terminator, a dash-free body, endLine,
                             -- and a tail of line terminators only — and the body's
                             -- base64, CR and LF removed, is the returned DER
Spec.Pem.encode_fits         (encode w der).size ≤ pemMax derMax for der.size ≤ derMax
                             -- at every width w ≥ 4; encode_fits_zero adds width 0, the
                             -- single-line form — decode?_encode's fits-the-cap
                             -- hypothesis, discharged
Spec.Pem.b64Decode?_isSome_iff
                             -- base64 decode succeeds exactly on the texts B64Grammar
                             -- admits: a non-empty alphabet body plus at most two
                             -- trailing pads, length a multiple of four counting pads,
                             -- and 4 ^ npad dividing the last body value — RFC 4648
                             -- §4 with §3.5's canonical padding, as an iff
Spec.X509Ca.isCaTrue_iff     isCaTrue accepts exactly tlv 0x30 caTrue, alone or
                             -- followed by one INTEGER TLV filling the SEQUENCE
                             -- (any pathLenConstraint content bytes, empty or non-minimal included, unread) — the two
                             -- anchor encodings and nothing else
Spec.Pem.b64Value?_inv       a byte that decodes to v IS the v-th alphabet
                             -- character — with b64Value?_table, the accepted
                             -- alphabet is pinned in both directions
Spec.Pem.b64Value?_lt        b64Value? c = some v → v < 64
Spec.X509Ca.readCertificate_frames
                             an accepted certificate is exactly SEQUENCE(TBS,
                             -- sigAlg, BIT STRING) with the unused-bits octet
                             -- zero and a nonempty signature — trailing bytes
                             -- and inter-TLV junk are build failures
Spec.X509Ca.caKey?_p256_size caKey? .p256 = some k → k.size = 64
Spec.X509Ca.caKey?_rsa_size  caKey? .rsa = some k → 256 ≤ k.size ≤ 384, 8 | k.size
                             -- both tighten what proof/x509ca_harness.c asserts
                             -- of the C entry (the harness holds 0 < len <= max)
Spec.Weierstrass, the curve arithmetic P256 and P384 instantiate, over any
  curve y² = x³ - 3x + b; every theorem about the curve takes `Fact p.Prime`
  and `2 < p` as hypotheses (`weierstrass` is Mathlib's WeierstrassCurve over
  ZMod p with a₄ = -3, a₆ = b; `ofPoint` reads a Mathlib point back as the
  reduced Nat pair):
  powMod_eq                    powMod b e m = b ^ e % m, with no hypothesis on m
  inv_cast                     ((inv x m : ℕ) : ZMod m) = (x : ZMod m)⁻¹ for x ≢ 0,
                               -- m prime — Fermat's little theorem
  inv_mul                      x * inv x m % m = 1 for x % m ≠ 0, m prime
  Curve.onCurve_iff            onCurve x y = true ↔ weierstrass.Equation x y for x y < p
  Curve.add_ofPoint            add (ofPoint P) (ofPoint Q) = ofPoint (P + Q): the affine
                               -- group law is Mathlib's, the P + (-P) = O test and
                               -- the tangent case included (SEC 1 v2 §2.2.1)
  Curve.onCurve_add            closure: on-curve inputs whose sum is affine give an
                               -- on-curve result, when 4a³ + 27b² ≢ 0 (mod p)
  Curve.smul_ofPoint           smul k (ofPoint P) = ofPoint (k • P): double-and-add
                               -- is Mathlib's nsmul
  Curve.ecdsaVerify_ecdsaSign  ecdsaSign d k z = some (r, s) → pubKey? d = some pub →
                               -- ecdsaVerify pub hash r s = true, for a hash of
                               -- coordLen bytes with z its integer, under n prime,
                               -- n • G = 0, G on the curve and p < 2^(8·coordLen).
                               -- Completeness, not soundness: it says the oracle's
                               -- signatures are ones the C must accept
Spec.P256 and Spec.P384 restate seven of these (all but inv_cast) at their
  own constants, under the same names: powMod_eq, inv_mul, onCurve_iff,
  add_ofPoint, onCurve_add, smul_ofPoint, ecdsaVerify_ecdsaSign. `decide`
  discharges `2 < p`, the discriminant, `G` on the curve and
  `p < 2^(8·coordLen)`; `Fact p.Prime`, `Fact n.Prime` and `n • basePoint = 0`
  stay hypotheses, because no tactic certifies a 256- or 384-bit prime
Spec.WebpkiTime.packSeconds_mono
                             a ≤ b → packSeconds a ≤ packSeconds b: the packed clock
                             -- keeps the order of clocks, which is what lets
                             -- notBefore <= now <= notAfter compare packed numbers
Spec.WebpkiTime.readTime_range
                             readTime b off = some (p, end) →
                             -- 19500101000000 ≤ p ≤ 99991231235959: an accepted Time
                             -- packs inside the range the clamped clock stays in
Spec.WebpkiName.hostnameOk_length
                             hostnameOk h → 1 ≤ h.length ≤ 253, the CBMC bound
Spec.WebpkiName.hostnameOk_no_nul
Spec.WebpkiName.hostnameOk_no_star
                             hostnameOk h → 0 ∉ h, and '*' ∉ h: an accepted reference
                             -- name holds neither byte
Spec.WebpkiName.hostnameOk_label_edges
                             hostnameOk h → label ∈ h.splitOn dot → the label's first
                             -- and last bytes, when it has them, are letters or
                             -- digits: no label starts or ends with '-'
Spec.WebpkiName.matchDnsName_mem
                             every byte of a matching presented name is a byte of the
                             -- reference name up to case, or one of the two bytes of
                             -- the wildcard label "*."
Spec.WebpkiName.matchDnsName_no_nul
                             against an accepted reference name, a matching presented
                             -- name holds no NUL
Spec.WebpkiName.matchDnsName_star
                             against an accepted reference name, the only '*' a matching
                             -- presented name can hold is its leading wildcard label:
                             -- the name is "*." then a suffix with no '*'
Spec.WebpkiName.generalNames?_tags
                             generalNames? b = some es → every entry's tag is in
                             -- generalNameTags: a universal tag, a number above 8, the
                             -- wrong constructed bit or the high-tag-number form
                             -- refuses the GeneralNames instead of being skipped
Spec.WebpkiName.matchSan_sound
                             a match is a dNSName entry of a well-formed GeneralNames
                             -- that matchDnsName accepts — no other GeneralName type,
                             -- no fallback to the subject common name
Spec.WebpkiSpki.readSpki?_rsa_key
                             an accepted RSA key is 256..512 bytes in multiples of 8,
                             -- 2^(8·size − 1) ≤ its value, and its value is odd: the byte
                             -- form of the check rsa_pkcs1_verify applies
Spec.WebpkiSpki.readSpki?_p256_size   an accepted P-256 key is 64 bytes
Spec.WebpkiSpki.readSpki?_p384_size   an accepted P-384 key is 96 bytes
Spec.WebpkiSigalg.readSigalg?_iff
                             readSigalg? b = some a ↔ b = encode a: the decoding reader
                             -- accepts exactly the four encodings the C byte-compares, and
                             -- each names one algorithm
Spec.WebpkiSigalg.curveHash_p256_sha384
                             a 48-byte digest's P-256 message hash is its first 32 bytes
                             -- — the bytes the C's p256_ecdsa_verify reads from the digest
Spec.WebpkiSigalg.curveHash_p384_sha256
                             a 32-byte digest's P-384 message hash is 16 zero bytes then
                             -- the digest — the bytes the C builds
Spec.WebpkiSigalg.curveHash_whole
                             a digest as long as the order is used whole
Spec.WebpkiSigalg.bytesToNatBE_append
                             bytesToNatBE (hi ++ lo) = bytesToNatBE hi * 256 ^ lo.size +
                             -- bytesToNatBE lo: big-endian decoding of a concatenation,
                             -- which curveHash_p256_sha384 and
                             -- bytesToNatBE_zeroPad_append use
Spec.WebpkiSigalg.bytesToNatBE_zeroPad_append
                             zero bytes on the left keep a big-endian value
Spec.WebpkiSigalg.verify_tbs_cap, verify_rsa_sigalg_ec_key, verify_ecdsa_sigalg_rsa_key
                             a tbs over certMax, an RSA algorithm under an EC key and an
                             -- ECDSA algorithm under an RSA key all verify false
Spec.WebpkiCert.parseCertificate?_frames
                             an accepted certificate is exactly tlv 0x30 (tlv 0x30 tbs ++
                             -- encode sigAlg ++ tlv 0x03 sig), where tbs is the input's
                             -- bytes at the recorded range, which lies inside the input,
                             -- sigAlg is the recorded algorithm, and sig holds a zero
                             -- unused-bits octet and a signature byte after it
Spec.WebpkiCert.readExtensions?_subjectAltName, parseCertificate?_subjectAltName
                             the recorded subjectAltName range lies inside the extensions
                             -- field, and so inside the certificate's TBS content
Spec.WebpkiCert.readExtensions?_complete, parseCertificate?_complete
                             the leaf saw keyUsage, extendedKeyUsage and subjectAltName,
                             -- with cA false; an issuer saw keyUsage and basicConstraints,
                             -- with cA true
Spec.WebpkiCert.parseCertificate?_spki
                             the recorded SubjectPublicKeyInfo range lies inside the TBS
                             -- content and reads back through readSpki? as the recorded
                             -- key, so the bytes an SPKI pin hashes are the key's own
Spec.Webpki.anchorIndex?_verifies
                             the anchor index a walk reports names an anchor that names
                             -- the issuer and verifies the certificate, and no anchor
                             -- before it does
Spec.Webpki.walkFrom_reached, verifyChain_ok
                             an accepted chain has a verified signature path to an
                             -- anchor: HasPath holds from the leaf, so every step of
                             -- the path parsed under the issuer arm, covered the clock,
                             -- was named by the certificate below it, stayed inside its
                             -- own pathLenConstraint and verified that certificate,
                             -- and the path ends at the anchor anchorIndex? names, at
                             -- the index and after the count of certificates the
                             -- verdict reports. The key the verdict carries is the
                             -- leaf's own, the leaf's validity covered the clock, and a
                             -- dNSName of the leaf's subjectAltName matched cfg.hostname
Spec.WebpkiPin.verifyRawKey_ok
                             an accepted raw public key list is one entry of 1 to
                             -- spkiMax bytes and nothing after it, whose bytes readSpki?
                             -- reads whole as the returned key and whose SHA-256 is one
                             -- of the pins
Spec.Record.nonce_inj        distinct sequence numbers below 2^64 give distinct record
                             -- nonces (RFC 9846 §5.3): within one traffic key the
                             -- nonce never repeats
Spec.Bytes.natToBytesBE_inj  big-endian encoding is injective below 2^(8*len)
                             -- (Record.nonce_inj rests on it)
Spec.Handshake, over every accepting trace (both modes unless noted):
  count_finished_of_accepts       exactly one Finished (§4.5.3)
  finished_mem_of_accepts         no accepting trace omits Finished
  psk_no_certificate              PSK: no Certificate anywhere (§2.2)
  pinned_one_certificate          pinned: exactly one Certificate (§4.5.1)
  pinned_one_certificateVerify    pinned: exactly one CertificateVerify (§4.5.2)
  pinned_cert_order               pinned: every prefix with CertificateVerify has
                                  Certificate, every prefix with Finished has
                                  CertificateVerify — with the unit counts this is
                                  C before CV before F (§4.5)
  count_serverHello_of_accepts    exactly one ServerHello, HRR path included (§4.2.3)
  count_encryptedExtensions_of_accepts
                                  exactly one EncryptedExtensions (§4.4.1)
  no_certificateRequest_of_accepts
                                  none: the client offers no certificate and fails
                                  closed rather than answer §4.4.2 with an empty one
  psk_no_certificateVerify        PSK: no CertificateVerify either (§2.2)
  no_post_handshake_before_finished
                                  every prefix holding a NewSessionTicket, KeyUpdate or
                                  application data already holds the Finished — the
                                  handshake precedes traffic (§4.7.1, §4.7.3, §5.1)
  closeNotify_at_most_one         at most one close_notify (§6.1)
  closeNotify_last                nothing follows a close_notify (§6.1)
  connected_stable                a run of post-handshake messages from `connected` stays
                                  connected, so acceptance does not depend on how many
                                  arrive (§4.7.1, §4.7.3, §5.1)
  accepts_decompose               every accepting trace is a flight of at most
                                  `flightBound mode` messages (4 under PSK, 6 under
                                  pinned) reaching `connected`, then post-handshake
                                  messages, then an optional single close_notify —
                                  so the flight decides acceptance and everything
                                  after it is covered by `connected_stable`
  accepts_of_flight               the converse: a flight that reaches `connected` accepts
  hrr_at_most_one                 at most one HelloRetryRequest (§4.2.4)
```

Size lemmas (`Poly.mac_size`, `ChaCha.block_size`, `Aead.seal_size`,
`Record.seal_size`, `Hkdf.hmac_size`) and the `Spec/Bytes.lean` proof
toolkit (fold characterizations, `xorBytes` involution,
`bytesToHex_inj`) support the above and are exported for future proofs.

Not proved, deliberately: functional correctness of the C (CBMC plus
the differential carry that), cryptographic security notions, and the
primality of the NIST constants — the P-256 and P-384 theorems take `p`
prime, `n` prime and `n • G = 0` as hypotheses, because no tactic in
Mathlib certifies a 256- or 384-bit prime and a primality certificate
is out of scope. Not proved yet: the x25519 ladder's group law and the
RSA arithmetic. Mathlib carries the number theory they need, so they
are open work rather than out of scope.

Spec.Epoch, over the monotonic revocation epoch (docs/ca.md, INV-21). `bound` is
quantified, so every statement covers every build's CH_EPOCH_BOUND:
  commit_ge                     a commit never lowers the stored epoch
  commit_le_of_check            a commit the check admitted raises it by at most
                                bound; with commit_ge, an admitted commit that
                                moves at all lands in (stored, stored + bound]
  commit_takes_any_epoch        the bound belongs to the call order, not to
                                hsa_epoch_commit: for every bound and stored epoch a
                                certificate bound+1 steps ahead is one the check
                                refuses and the commit would take
  step_idem                     replaying an accepted certificate changes nothing
  storedAfter_ge                over a list of certificates the stored epoch
                                never decreases
  storedAfter_le                and rises by at most bound per accepted
                                certificate: n completed handshakes end no higher
                                than stored + bound * n — the jump bound rule,
                                which no single-step statement expresses
  storedAfter_eq_of_none_accepted
                                a run that accepted nothing ends where it started
  storedAfter_le_maxEpoch       a device at or below CH_EPOCH_MAX that sees only
                                in-range numbers keeps one, so the stored side of
                                `stored + bound` also stays inside uint32

## Proof status by module

The machine-versus-convention line for the spec, kept honest by `make
lint-spec` (hygiene: no escape hatches in the model; every theorem the
`Spec` modules declare rests on Lean's three standard axioms only, private
theorems included). "Vector-checked"
means the module's selftest plus the differential oracle carry it;
"proven" means theorems beyond that.

| module | theorems | what is proven vs only vector-checked |
| --- | --- | --- |
| Bytes | 24 | proof toolkit: fold characterizations, xor involution and left cancellation, hex injectivity, big-endian round trip and injectivity |
| Drbg | 13 | key advance (the next key is the counter-0 block, independent of the request size), key/output disjointness within one keystream, request-prefix consistency, session key chain |
| HandshakeParser | 13 | message-grammar soundness, quantified over all three `Kex` builds and both `SuiteOffer` values: an accepted ServerHello echoes the empty legacy_session_id the profile offers, carries a cipher suite the build offers, selects a group the build lists in supported_groups and carries a key_exchange of exactly `serverShareSize` octets for that group (32 x25519, 1120 hybrid), and any selected_identity it reports is the single index one offered identity puts in range; an accepted HelloRetryRequest carries a cipher suite the build offers and a cookie or a selected group, and a selected group is one the build listed and sent no key share for, so a retry in the x25519 and pq builds carries a cookie and never a group; a result is a HelloRetryRequest exactly when the Random is §4.2.4's fixed value; an accepted record_size_limit is at least 64 under every offer; an accepted ALPN selection is an index into the offered protocols; an accepted server_certificate_type names a type the ClientHello offered; an accepted CertificateVerify reports an offered scheme that is never RSASSA-PKCS1-v1_5, so a pinned build's is its own pinned SignatureScheme and the webpki build's is one of rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384 |
| Handshake | 17 | state-machine safety invariants: exactly one ServerHello, EncryptedExtensions and Finished; no certificate flight under PSK; pinned flight shape and order; HRR bound; no CertificateRequest; no post-handshake message before Finished; close_notify at most once and last |
| Record | 8 | seal/open round trip at both the AEAD and record layers, record size, nonce size, nonce injectivity (distinct sequence numbers never share a nonce), and that an accepted record never carries content type invalid(0) |
| ChaCha | 5 | block size, structural lemmas, keystream prefix stability; keystream itself vector-checked |
| Hkdf | 5 | output lengths, schedule wiring and secret sizes; derivations vector-checked |
| Aead | 4 | seal/open round trip, tag rejection, output size, pad16 alignment |
| Rsa | 4 | PSS signature and hash size contracts on both sign and verify; the arithmetic stays vector-checked |
| Sha256 | 4 | structural lemmas, padding block alignment and message prefix; compression function vector-checked |
| Sha512 | 5 | output sizes for both hashes (64 and 48 bytes, one private lemma over the shared digest), compression size, padding block alignment and message prefix; compression function vector-checked |
| Weierstrass | 8 | the curve arithmetic P256 and P384 share, proved once over any odd prime `p`: `powMod` is modular exponentiation with no hypothesis on the modulus; Fermat inversion is the field inverse in `ZMod m` and inverts modulo `m`; membership is Mathlib's Weierstrass equation over `ZMod p`; `add` and `smul` agree with Mathlib's `+` and `nsmul` on points read through `ofPoint`, so the group law is Mathlib's, the `P + (-P) = O` test and the tangent case included; closure; and a signature the oracle mints verifies under the key it derives, given `n` prime and `n • G = 0`. No selftest and no line op: nothing drives it but its two instantiations |
| P384 | 7 | `Weierstrass` at the P-384 constants, and its theorems restated at them: `decide` discharges `2 < p`, the discriminant, `G` on the curve and `p < 2^384`; `p` and `n` prime and `n • G = 0` stay hypotheses, because no tactic certifies them. Soundness of the verifier stays executable oracle only: the RFC 6979 A.2.6 vectors and the differential |
| RsaPkcs1 | 4 | the encoding is exactly the modulus length; a signature of the wrong length never verifies and a signed one has the right length; a digest length naming no hash never verifies; the arithmetic stays vector-checked |
| Sha3 | 8 | output lengths for the two hashes and two XOFs, sponge state size, padding block alignment and message prefix; the permutation itself vector-checked |
| MlKem | 6 | FIPS 203 §6.1-6.3 output-length contracts (ek 1184, dk 2400, ct 1088, shared secret 32 on both decapsulation branches) and the ByteEncode length law they rest on; the NTT, sampling, and compression arithmetic stay vector-checked |
| Poly | 1 | MAC size; arithmetic vector-checked |
| P256 | 7 | `Weierstrass` at the P-256 constants, and its theorems restated at them: `decide` discharges `2 < p`, the discriminant, `G` on the curve and `p < 2^256`; `p` and `n` prime and `n • G = 0` stay hypotheses, because no tactic certifies them. Soundness of the verifier stays executable oracle only: the RFC 6979 A.2.5 vector and the differential |
| Pem | 10 | the accepted alphabet pinned in both directions against RFC 4648 §4's table; decode? never yields more than the cap and the bound is attained; armour-then-decode is the identity for every non-empty DER within the caps at every width whose text fits — each hypothesis carries an evaluated countermodel; an accepted input has the RFC 7468 frame with the body's base64 the returned DER; armour at any width of four or more, or as one line, fits the cap, discharging the round trip's fits hypothesis; base64 acceptance characterized as an iff against the declarative grammar |
| WebpkiTime | 2 | the packed clock keeps the order of clocks (monotone over every count of seconds, the clamp included), and an accepted Time packs inside [19500101000000, 99991231235959]; the field parsing and the calendar conversion stay vector-checked |
| WebpkiName | 9 | an accepted reference name holds no NUL and no '*' and is 1..253 bytes; every label of it starts and ends with a letter or digit, never '-'; every byte of a matching presented name is a reference byte up to case or one of the wildcard label's two, so against an accepted reference name a matching presented name holds no NUL and no '*' but a leading "*."; every entry of an accepted GeneralNames has one of GeneralName's nine tags; a match is a dNSName entry of such a GeneralNames and nothing else. The label length rules, the all-digit last label and the wildcard's own arithmetic stay vector-checked |
| X509Ca | 6 | isCaTrue accepts exactly the two anchor encodings (the iff is kernel-checked false without its encodeLen-domain bound); an accepted certificate has exactly the SEQUENCE(TBS, sigAlg, BIT STRING) shape with the signature framing intact; the extracted key is exactly 64 bytes or 256..384 in 8-byte steps, tightening the CBMC harness's bound. Acceptance policy beyond the frame is executable oracle only: the differential's minted anchors, near shapes and mutations |
| WebpkiSpki | 3 | the accepted RSA key is 256..512 bytes in multiples of 8 with its top bit set and odd, stated over the returned bytes from a reader that judges the decoded integer; the EC keys are 64 and 96 bytes. Acceptance beyond that is executable oracle only: the differential's spec-encoded keys and their perturbations |
| WebpkiSigalg | 9 | the decoding reader accepts exactly the four canonical encodings, one algorithm each (the byte-compare view and the decode view agree); FIPS 186-4 §6.4's integer rule equals the C's byte cut for P-256 with SHA-384 and its zero pad for P-384 with SHA-256, with the pad lemma and big-endian concatenation lemma under them; the cap and both family mismatches refuse. The signature arithmetic is the RSA, P-256 and P-384 modules' and stays vector-checked |
| WebpkiCert | 6 | an accepted certificate is exactly one Certificate SEQUENCE whose TBS content is the recorded range of the input and whose outer signatureAlgorithm is the encoding of the recorded algorithm; the recorded subjectAltName range lies inside the extensions field and the TBS content; the recorded SubjectPublicKeyInfo range lies inside the TBS content and reads back as the recorded key; the leaf saw keyUsage, extendedKeyUsage and subjectAltName with cA false, an issuer keyUsage and basicConstraints with cA true. Which values each extension admits, the caps and the other fields stay executable oracle only: the corpus certificates, their single-byte changes and the random extension lists of the differential |
| Webpki | 3 | soundness of the walk: an accepted chain has a verified signature path to an anchor, stated as an inductive `HasPath` and proved for every walk that reaches one, of the length and ending at the anchor index the verdict reports, and that index names the first anchor that verifies; the leaf the accepted key comes from parsed under the leaf arm, was valid at the clock and matched `cfg.hostname` through a dNSName of its own subjectAltName. The entry framing and which refusal each failure names stay executable oracle only: the 25 corpus chains, the 5 captures and their clock, hostname, anchor, entry and byte mutations in the differential |
| WebpkiPin | 1 | soundness of the raw public key rule: an accepted list is one CertificateEntry of 1 to `spkiMax` bytes and nothing after it, whose bytes `readSpki?` reads whole as the returned key and whose SHA-256 is one of the pins. Which refusal each failure names, and path pinning, stay executable oracle only: the corpus keys framed as raw entries with their reframings, byte changes and random lists, and the chain rows under a pin on each entry, each anchor and nothing, in the differential |
| X25519 | 2 | RFC 7748 §5 clamping: every decoded scalar is a multiple of the cofactor 8, and has bit 254 set with bit 255 clear. The first keeps `k * P` in the prime-order subgroup, the second fixes the ladder's iteration count. The ladder arithmetic itself stays vector-checked |
| X509Der | 19 | DER canonicality: a length, a TLV, and an INTEGER are accepted only in the one encoding X.690 §10.1 and §8.3.2 admit, so the reader is DER-strict rather than BER-lenient; plus the encode/decode round trips and the §8.19.2 subidentifier rule |
| X509 | 4 | parse soundness: an accepted list reports a key only after a signature over the complete DER of the TBSCertificate that carried it verified under the pinned key, or under an intermediate the pinned key itself signed; the entry is a byte range of the list and no third entry can follow. Acceptance policy beyond that is executable oracle only: mint/parse round trips for the single leaf and the chained pair (self-checked signatures; OpenSSL material is exercised by the C strictness suite) and the differential |
| Epoch | 8 | the ordering and bound rule over the epoch value: commit monotonicity, the per-certificate bound, the run-level `stored + bound * accepted` ceiling, replay idempotence, and range preservation. Model only — no differential covers this module (below) |

No module carries zero theorems. P-256 and P-384 were the last two and
the most security-critical. `Spec/Weierstrass.lean` now defines their
arithmetic once and proves it against Mathlib's `WeierstrassCurve`;
each curve instantiates it, and the primality of the constants stays a
hypothesis rather than a claim. The missing theorems, in value order:
X25519 ladder invariants, then the RSA arithmetic lemmas. Both need
number theory, which Mathlib now supplies.
The clamping guarantees needed none, so they came first: they are
properties of the scalar, not of the group, and no differential row
could have caught a clamping bug, since the C and the spec would agree
while both were wrong. The mint-then-parse round trip is deliberately
not on the list: it is completeness, not soundness, a parser that
accepted everything would satisfy it, and the differential already
mints and parses on every row against the real C. The RSA arithmetic is
statable today without an interface change — the factorization enters
as a hypothesis, not an argument — and its proof can draw on Mathlib's
number theory.

None of these theorems say anything about the C. They constrain the
model the differential compares against, so a spec regression fails
`lake build` instead of silently weakening the oracle, and they state
relations across runs — key independence, nonce injectivity, request
prefixes — that a differential row, being one input and one output,
cannot express.

## Writing proofs here

A theorem is read far more often than it is written, and it is read by
someone deciding whether to trust the C. Optimize for that reader.

**The statement is the audit unit.** Its proof is checked by Lean's
kernel; nobody has to follow the tactic script. So a long proof of a
short statement costs an auditor nothing, while a short proof of a
sprawling statement costs everything. Keep a statement to a few lines
and carry no hypothesis it does not need.

**Never restate a definition's internals in a hypothesis — derive
them.** A theorem that assumes how `mint` builds its TBSCertificate,
rather than unfolding the `mint` call it was handed, keeps compiling
after that layout changes: the hypotheses become unsatisfiable and the
theorem turns vacuously true, with nothing failing. Derive what you
need from the call, so a layout change breaks the proof instead of
hollowing the statement.

**Prove the direction that carries weight.** `parse (mint x) = some x`
is completeness, and a parser that accepted everything would satisfy
it. `parse list = some k → a signature over that list verified` is
soundness. Prefer soundness; say which one a theorem gives when it is
not obvious.

Style, in rough order of how much it buys:

- **Name hypotheses for what they say**, never `h1`, `h2`, `hx`. Use
  `h_fits`, `h_minimal`, `h_verified`. The rule the C follows —
  names spell words out — does not stop at the language boundary.
- **Break a goal with `have`**, one named intermediate claim at a time,
  instead of one tactic block that lands the whole thing.
- **Chain equalities with `calc`** rather than a dense `rw` sequence.
  The chain reads like the mathematics; the sequence reads like a
  diff.
- **Go forward, not backward.** `obtain` and `rcases` on what you have
  beat `apply` on what you want, because the reader can follow along
  without running Lean.
- **`refine` with `?_` holes** instead of a bare `apply`, so each
  remaining goal is written down rather than conjured.
- **One deduction per line.** Wrap at 100 columns like everything else.
- **Factor repeated case analysis into a private lemma.** Three
  branches doing the same four steps with different constants is one
  lemma taking those constants. Both directions of an iff repeating
  one arithmetic argument is the same rule.
- **Search the library before writing a lemma.** A private induction
  that re-proves `List.all_takeWhile` or `List.take_left` costs lines
  and review and adds nothing the import did not already carry. Ask
  `exact?` first; grep `Init/Data/List` second.
- **Never state a definitional equality as a lemma.** If `rfl` proves
  it, the kernel already knows it: unfold at the use site with
  `simp only [f]` instead of naming a restatement of `f`'s body.
- **State an equation, not a bundle of consequences.** An invariant
  returned as `∃ x, f = x ∧ bound x ∧ special-case x` makes every
  caller destructure and reassemble. When the quantity has a closed
  form, state `f = the-closed-form` and let callers rewrite once.
- **Inline a fact with one caller** unless its name carries audit
  weight. A one-line `decide` used once reads better at its use site
  than as a named theorem the reader must chase.
- **Cite the standard** in the doc comment — RFC section, X.690 clause,
  FIPS paragraph — the same as the definitions do. `missingDocs` is on,
  so a public declaration without one fails `make check`; the linter
  cannot read a trailing `--` comment, only a `/-- ... -/` block.
- **Delete the debris** once it is green: redundant `have`s, commented
  `rw` chains, single rewrites that collapse into one `rw [a, b, c]`.
  Four of Lean's own linters check this — `unreachableTactic`,
  `unnecessarySimpa`, `unusedRCasesPattern`, `tactic.unusedName`, on in
  `lakefile.toml` — and `make lint-spec` turns their warnings into
  errors, so `make check` fails on debris.

**Prove it, then shrink it.** Most of the simplifications above are
invisible until a working proof exists: the closed form of an
invariant, the library lemma an induction duplicates, the case
analysis two directions share. So treat the first green build as the
midpoint, not the finish. Freeze every public statement byte-for-byte
and make a second pass over the scripts alone; the kernel re-checks
the result, and a diff that touches no public statement is the proof
the pass stayed inside its lane. A simplification that does not build
reverts — small honest wins beat big broken ones.

Naming follows Mathlib's scheme, so a name reads the same on both sides
of an import: `snake_case`, `foo_of_bar` for an implication, suffixes
`_size`, `_inj`, `_canonical`, `_sound`. A Lean reader should
recognize the shape without being told.

**Pick the smallest tactic that closes the goal.** Mathlib is a
dependency, so its tactics are available: `by_contra`, `linarith`,
`nlinarith`, `positivity`, `qify`, `field_simp` and `gcongr` among
them. Prefer the smaller tactic where it suffices, because a reader can
tell what it did: `omega` over `linarith` for linear arithmetic over
`Nat` and `Int`, `decide` for a finite check, the explicit lemma over
`gcongr`. A goal that needs the heavier tactic gets it; the rule says
to try the smaller one first.

Everything in this section is machine-checked except two rules: naming
hypotheses and the choice of tactic. No linter reads intent, so review
checks those two.

`omega`, `decide`, `norm_cast`, and `push_cast` carry most of the
arithmetic here. The model's inductive types derive `DecidableEq`, so
`Decidable.em` is constructive on them.
