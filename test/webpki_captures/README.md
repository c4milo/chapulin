# Web PKI captures

The four public certificate chains docs/webpki.md measures, as the wire
carried them, and the published roots that anchor them.
`test/gen_webpki_corpus.py` renders both into `test/webpki_corpus.h`,
where they form the `webpki_capture_chains` table.

## Chains

Captured 2026-09-15T11:19:15Z, 1789471155 seconds since the epoch, with

    openssl s_client -showcerts -servername HOST -connect HOST:443 </dev/null

under OpenSSL 3.6.4. Each `HOST.pem` holds the Certificate message's
entries in wire order, leaf first, and nothing else.

| file | entries | largest entry | Certificate body | most extensions in one certificate | largest extension TLV |
| --- | --- | --- | --- | --- | --- |
| `s3.amazonaws.com.pem` | 3 | 2104 B | 4419 B | 10 | 653 B |
| `storage.googleapis.com.pem` | 3 | 1382 B | 3791 B | 10 | 264 B |
| `r2.cloudflarestorage.com.pem` | 3 | 1337 B | 2925 B | 10 | 425 B |
| `acme-v02.api.letsencrypt.org.pem` | 4 | 1140 B | 3605 B | 10 | 273 B |

`Certificate body` is the handshake message without its four-byte
header. The generator prints the same five numbers per capture on every
run; compare them by hand against docs/webpki.md's bounds table.

The leaves' validity, as captured:

| host | notBefore | notAfter |
| --- | --- | --- |
| `s3.amazonaws.com` | 2025-11-18T00:00:00Z | 2026-11-06T23:59:59Z |
| `storage.googleapis.com` | 2026-08-10T08:41:53Z | 2026-11-02T08:41:52Z |
| `r2.cloudflarestorage.com` | 2026-06-11T05:59:16Z | 2026-09-09T06:59:11Z |
| `acme-v02.api.letsencrypt.org` | 2026-07-29T22:14:57Z | 2026-10-27T22:14:56Z |

Cloudflare served `r2.cloudflarestorage.com` a leaf whose notAfter was
six days before the capture. A second handshake at 2026-09-15T11:32:54Z,
to another edge (172.64.66.1), served the same leaf, serial
`5937E176BBE096D50E8CE129D872C364`. The header therefore carries that
chain twice: with `now_seconds` at the capture time, where the verdict is
`expired`, and at 2026-09-01T00:00:00Z, inside the leaf's validity, where
it is `ok`. The other three rows use the capture time as `now_seconds` and
expect `ok`.

## Anchors

`anchors/` holds the five published roots the four chains end in. Every
capture row carries all five, so a walk consults anchors whose Name it
never matches before it finds the one it needs.

| file | subject | published at | SHA-256 fingerprint |
| --- | --- | --- | --- |
| `AmazonRootCA1.pem` | Amazon Root CA 1 | https://www.amazontrust.com/repository/AmazonRootCA1.pem | `8E:CD:E6:88:4F:3D:87:B1:12:5B:A3:1A:C3:FC:B1:3D:70:16:DE:7F:57:CC:90:4F:E1:CB:97:C6:AE:98:19:6E` |
| `SFSRootCAG2.pem` | Starfield Services Root Certificate Authority - G2 | https://www.amazontrust.com/repository/SFSRootCAG2.pem | `56:8D:69:05:A2:C8:87:08:A4:B3:02:51:90:ED:CF:ED:B1:97:4A:60:6A:13:C6:E5:29:0F:CB:2A:E6:3E:DA:B5` |
| `GTSRootR1.pem` | GTS Root R1 | https://pki.goog/repo/certs/gtsr1.pem | `D9:47:43:2A:BD:E7:B7:FA:90:FC:2E:6B:59:10:1B:12:80:E0:E1:C7:E4:E4:0F:A3:C6:88:7F:FF:57:A7:F4:CF` |
| `GTSRootR4.pem` | GTS Root R4 | https://pki.goog/repo/certs/gtsr4.pem | `34:9D:FA:40:58:C5:E2:63:12:3B:39:8A:E7:95:57:3C:4E:13:13:C8:3F:E6:8F:93:55:6C:D5:E8:03:1B:3C:7D` |
| `ISRGRootX2.pem` | ISRG Root X2 | https://letsencrypt.org/certs/isrg-root-x2.pem | `69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70` |

Each copy comes from the macOS 26.6.2 system root store: on 2026-09-15,

    security find-certificate -a -p -c "<subject CN>" /System/Library/Keychains/SystemRootCertificates.keychain

printed it, and a re-wrap as PEM produced the file. No copy comes from a
publisher download; the `published at` column names where to find one. The
fingerprint column is `openssl x509 -noout -fingerprint -sha256` over the
file, the SHA-256 of the DER certificate; compare it against the
publisher's copy before trusting the file for anything but this test.

The generator checks four of the five against the wire: where a captured
entry carries an anchor's subject Name, its subjectPublicKeyInfo must
equal the anchor's. That covers Amazon Root CA 1 (`s3.amazonaws.com`
entry 2, cross-signed by Starfield), GTS Root R1
(`storage.googleapis.com` entry 2), GTS Root R4
(`r2.cloudflarestorage.com` entry 2) and ISRG Root X2
(`acme-v02.api.letsencrypt.org` entry 3). Starfield Services Root G2
appears in no captured entry, so its fingerprint is its only check.

Anchor sizes, which docs/webpki.md's "Trust anchors" section quotes:
the subjectPublicKeyInfo TLV is 120 B for a P-384 key, 294 B for
RSA-2048 and 550 B for RSA-4096.

## Refreshing

Run the `s_client` command per host, keep the PEM blocks in wire order in
`HOST.pem`, set `CAPTURE_TIME_UTC` in `test/gen_webpki_corpus.py` and the
capture time and tables above, then run `make webpki-corpus`. The
generator fails if `openssl verify -purpose sslserver -verify_hostname
HOST -attime NOW_SECONDS` with the five anchors as `-CAfile` reaches a
verdict other than the row's `expected`.

If a re-capture serves `r2.cloudflarestorage.com` a leaf that is valid at
the capture time, drop the `r2.cloudflarestorage.com.at_capture` row from
`CAPTURE_ROWS`, set the remaining r2 row to `CAPTURE_TIME_UTC`, delete
`R2_VALID_CLOCK_UTC`, and delete the paragraph above that records the
expired leaf.
