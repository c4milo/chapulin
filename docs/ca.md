# Operating a CA for chapulin devices

Status: the parser and its proofs are in the tree; the `TRUST=ca`
build that uses them lands next. This document is the operational
contract that build depends on. Read it before issuing anything.

## The trust model in one paragraph

A device pins one public key — the CA key — in the two provisioning
slots the pinned-key mode already uses. The server presents its leaf
certificate alone, or the leaf plus the one intermediate that signed
it. The device checks signatures up to the pinned key and checks the
certificate shape against a fixed profile. It checks nothing else: no
names, no expiry, no revocation lists. Everything this document
requires exists to make that small check sufficient.

## What the CA must sign

One signature algorithm per device build, everywhere in the chain:

- RSA builds: RSASSA-PSS, SHA-256, MGF1-SHA-256, salt length 32.
  OpenSSL emits the exact accepted encoding with
  `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sha256`.
  PKCS#1 v1.5 signatures are rejected, always.
- ECDSA builds: ecdsa-with-SHA256 over P-256. OpenSSL's default for
  a P-256 key.

Leaf certificates carry exactly this extension profile:

    keyUsage = critical, digitalSignature
    extendedKeyUsage = serverAuth
    basicConstraints = CA:FALSE

extendedKeyUsage must be exactly serverAuth: a leaf without it, or
with any other purpose, never authenticates a server. This is the
device-side fence against mixed issuance — see "One purpose per
hierarchy" below.

Intermediate certificates (optional, at most one) carry:

    basicConstraints = critical, CA:TRUE, pathlen:0
    keyUsage = critical, keyCertSign, cRLSign

The pathlen:0 pins the hierarchy's depth at issuance: an
intermediate that could sign further CAs is off-profile.

Size: a certificate must fit the build's cap — 1536 bytes for RSA
builds, 768 for ECDSA (the `CH_X509_MAX` default; a build can raise
it). Ordinary subjects and the profile extensions fit with hundreds
of bytes to spare; measure once if your names run long.

Serial numbers: positive, at most 20 value bytes. Random 20-byte
serials work.

Validity dates: present and well-formed (UTCTime or GeneralizedTime,
Zulu), but the device never reads the values — no clock exists. Set
them for your own tooling's benefit.

## Issuance recipes

A three-tier hierarchy with OpenSSL 3, RSA build shown; drop the two
`-sigopt` flags and use P-256 keys for the ECDSA build. The e2e
suite runs these same commands.

    # Root, offline. Signs intermediates only.
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root.key
    openssl req -new -x509 -key root.key -subj "/CN=fleet-root" -days 3650 \
      -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out root.pem

    # Intermediate, online signer.
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out int.key
    openssl req -new -key int.key -subj "/CN=fleet-intermediate" |
    openssl x509 -req -CA root.pem -CAkey root.key -days 365 \
      -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
      -extfile int.cnf -out int.pem

    # Leaf, per server, short-lived.
    openssl req -new -key server.key -subj "/CN=controller-01" |
    openssl x509 -req -CA int.pem -CAkey int.key -days 14 \
      -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
      -extfile leaf.cnf -out leaf.pem

with `leaf.cnf` and `int.cnf` holding the extension profiles above.
A flat hierarchy (root signs leaves directly) drops the middle step;
devices then pin the root key and servers send the leaf alone.

Go as the issuing CA works with two template settings: set
`SignatureAlgorithm: x509.SHA256WithRSAPSS` explicitly (Go's RSA
default is PKCS#1 v1.5, which devices reject) and the KU/EKU/BC
values above. ECDSA templates match by default.

## Verify an issued certificate

Before any device sees a new CA's output, check one issued leaf
against the profile. All four checks must pass:

    # 1. Signature algorithm: rsassaPss (RSA builds) or
    #    ecdsa-with-SHA256 (ECDSA builds), with SHA-256 throughout.
    openssl x509 -in leaf.pem -noout -text | grep -A2 "Signature Algorithm"

    # 2. The extension profile, exactly.
    openssl x509 -in leaf.pem -noout -ext keyUsage,extendedKeyUsage,basicConstraints

    # 3. Size within the build's cap (1536 RSA / 768 ECDSA).
    openssl x509 -in leaf.pem -outform DER | wc -c

    # 4. The chain verifies to your pinned anchor.
    openssl verify -CAfile pinned.pem [-untrusted int.pem] leaf.pem

Expect "Digital Signature", "TLS Web Server Authentication", and
"CA:FALSE". Any other critical extension in the full `-text` output
means rejection on the device. The definitive check is a staging
device, or the repository's strictness suite pointed at your
material via `test/gen_x509vectors.py <dir>`.

## Server configuration

Send the leaf alone (flat hierarchy) or leaf then intermediate —
never the root, never anything else. A third certificate fails the
handshake. Watch OpenSSL's auto-chain behavior: `s_server` and
libraries with default settings append the CA certificate the moment
it sits in their store (a habitual `-CAfile` is enough), turning a
working fleet into a fail-closed outage. Keep the CA certificate out
of the server's store, or set `SSL_MODE_NO_AUTO_CHAIN`.

## Leaf lifetime

Recommended: 14 days. The trade: shorter lifetimes shrink the value
of a stolen leaf key (reissuance is this system's revocation), longer
lifetimes tolerate longer device offline periods and reissuance
outages. Justify your number against the tail of your fleet's
offline distribution, not its mean: with a 7-day lifetime and 2% of
devices offline for 10 days at a time, that 2% returns to servers
whose leaves it has never seen — which works — but a device that
sleeps through a CA-key rotation needs the slot-B path, and a server
whose reissuance stalled past the lifetime strands everyone. Days to
weeks; never hours.

## Reissuance is the freshness mechanism

The device cannot check dates, so freshness is enforced by issuance
policy, never device-side. That makes the reissuance pipeline a hard
dependency of fleet connectivity:

- Monitor reissuance freshness and alert on staleness. This is an
  operational precondition, not a nice-to-have.
- Write the recovery path before deploying: who re-signs when the
  signer is down, where the emergency long-lived leaf lives, and who
  holds its key.
- What reissuance does not cover: an attacker holding a stolen leaf
  private key presents its still-valid certificate until the CA key
  itself rotates. Reissuance revokes keys the attacker does not
  hold. State this in your threat model rather than assuming
  otherwise.

## Key custody

The root key lives in an HSM or on an offline signer. This is a hard
requirement: a CA-key compromise is fleet-wide and recoverable only
by rotating the pinned key on every device. With an intermediate,
the root touches nothing but intermediate issuance, and the online
signer holds only the intermediate key.

## One purpose per hierarchy

Sign server leaves with this hierarchy and nothing else. The EKU
check means a certificate without exactly serverAuth never
authenticates a server, so client or device certificates issued for
mTLS do not become controller identities — but keep the hierarchies
separate anyway; the fence should never take load.

## CA software examples

The device's contract is the profile, not a vendor. Any issuer whose
output passes "Verify an issued certificate" works. Verified recipes
for common software follow; version floors and behaviors were checked
against vendor documentation and source at the time of writing — the
verification section remains the gate.

### HashiCorp Vault (both arms; RSA arm needs Vault >= 1.12)

Vault signs through Go's crypto/x509, which emits exactly the PSS
AlgorithmIdentifier this profile pins (SHA-256, MGF1-SHA-256, salt
32) when `use_pss=true` — the parameter exists on root generation,
`sign-intermediate`, and issuing roles since Vault 1.12. Serials stay
under 20 value bytes by construction. Leave `config/urls` and
`permitted_dns_domains` unset: the first adds AIA/CRLDP bytes, the
second a critical Name Constraints extension the device rejects.

    vault secrets enable -path=pki pki
    vault write pki/root/generate/internal common_name="fleet-root" \
        key_type=rsa key_bits=3072 use_pss=true max_path_length=1 ttl=87600h
    # Optional intermediate: max_path_length=0 gives CA:TRUE, pathlen:0.
    #   vault write pki/root/sign-intermediate csr=@int.csr use_pss=true \
    #       max_path_length=0 ttl=43800h
    vault write pki/roles/chapulin \
        allowed_domains="fleet.example" allow_subdomains=true \
        key_type=rsa key_bits=3072 use_pss=true \
        key_usage="DigitalSignature" client_flag=false ttl=336h
    vault write pki/issue/chapulin common_name="controller-01.fleet.example"

`client_flag=false` is load-bearing: Vault's default adds clientAuth
to the EKU, which the device rejects. The ECDSA arm is the same with
`key_type=ec key_bits=256` and no `use_pss` (no version floor).
`basic_constraints_valid_for_non_ca=true` adds CA:FALSE to leaves;
the device accepts leaves with or without it. Convert issued PEM to
DER at provisioning (`format=der` works on the issue endpoints).

### smallstep step-ca (both arms; RSA arm needs templates end to end)

step-ca also signs through Go crypto, so the encodings match — but
its defaults need two corrections: leaves get serverAuth+clientAuth
without a template, and RSA signatures are PKCS#1 v1.5 unless the
template says otherwise. The leaf template:

    {
      "subject": {{ toJson .Subject }},
      "sans": {{ toJson .SANs }},
      "keyUsage": ["digitalSignature"],
      "extKeyUsage": ["serverAuth"],
      "signatureAlgorithm": "SHA256-RSAPSS"
    }

attached to the provisioner via `options.x509.templateFile`. The
intermediate needs its own template with `"basicConstraints":
{ "isCA": true, "maxPathLen": 0 }`, `"keyUsage": ["certSign",
"crlSign"]`, and the same `signatureAlgorithm` line — the
root-to-intermediate signature is otherwise v1.5. The ECDSA arm
drops the `signatureAlgorithm` lines (a P-256 CA signs
ecdsa-with-SHA256 natively) and can use the stock intermediate-ca
profile.

### cfssl (ECDSA arm only)

cfssl derives the signature algorithm from the CA key and can never
produce RSASSA-PSS — a 3072-bit RSA CA would sign v1.5 with SHA-384,
wrong twice. With a P-256 CA key it signs ecdsa-with-SHA256; a
signing profile with `"usages": ["digital signature", "server auth"]`
and no issuer/OCSP/CRL URLs matches the leaf profile. Do not attempt
the RSA arm with cfssl.

### EJBCA and Microsoft AD CS (viable, verify the encoding first)

Both support PSS (EJBCA: signing algorithm SHA256WithRSAandMGF1;
AD CS: `AlternateSignatureAlgorithm=1` with a SHA-256 CNG key — a
CA-wide switch) and ECDSA P-256, and both keep serials within 20
bytes. Neither goes through Go's encoder, and the profile pins one
exact PSS parameter encoding — so before trusting either, issue one
certificate and run the verification section; if the signature
AlgorithmIdentifier's bytes differ from the profile, the device
rejects it. Strip AIA/CDP/policy extensions from the template or
profile to protect the size budget, and on AD CS note the PSS switch
applies to everything that CA issues.

## External and managed CAs

A CA you do not operate can serve chapulin fleets; the requirements
move into your agreement with the operator:

- The operator issues from a hierarchy dedicated to your fleet —
  in practice, a dedicated intermediate. Devices pin the
  intermediate's key (or your dedicated root's), never a shared
  root: the device checks no names, so pinning a key that signs for
  other customers would let any of their serverAuth certificates
  authenticate as your controller. Exclusivity of the pinned key is
  the entire security requirement.
- The operator signs with the build's algorithm and encoding, the
  profile extensions, and your chosen lifetime — the recipes above,
  which any mainstream CA software can produce.
- The dedicated intermediate is freshly minted for you, with
  basicConstraints CA:TRUE pathlen:0 and no name constraints. A
  pre-existing intermediate almost never fits: the device rejects a
  missing pathlen:0, and it must reject a critical Name Constraints
  extension — it processes no names, and RFC 5280 requires rejecting
  a critical extension it cannot honor. Scope the intermediate by
  exclusivity of its key, not by names.
- The operational preconditions become contract terms: reissuance
  freshness monitoring, custody of the signing key, the recovery
  path, and single-purpose issuance under the dedicated key.
- Their expiry bookkeeping cannot strand your devices — the device
  never reads dates — but their reissuance cadence is still your
  freshness mechanism, so their pipeline reliability bounds yours.

Public CAs remain out of scope: their trust model requires expiry
and name checking the device deliberately does not have, and (for
Let's Encrypt specifically) their signature algorithms sit outside
the profile on both arms. See docs/decisions.md.

A public-CA-fronted server still works today, through pinned-key
mode: it hashes the certificate without parsing it and verifies the
server's key directly, so keep the server's keypair stable across
renewals (certbot: `--reuse-key`) and pin that key. The public CA's
certificates, algorithms, and rotation schedule never reach the
device.

## Flash wear

Writing the pinned key at provisioning and at rare rotations is
fine. Do not design anything that persists per-connection or
per-epoch state without checking the flash's write-cycle budget;
the documented guidance for this hardware class is to persist such
state at most daily.
