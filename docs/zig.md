# The Zig API

A Zig program runs chapulin's tcp-nonblocking and QUIC sessions through Zig
values, Zig errors and session types it places in its own memory. It
never builds a `ch_cfg` or writes a C callback. The API is nine files at
the repository root: `chapulin.zig`, `chapulin_tcp.zig`,
`chapulin_quic.zig`, `chapulin_quic_token.zig`, `chapulin_ticket.zig`,
`chapulin_pem.zig`, `chapulin_dnssec.zig`, `chapulin_cpu.zig` and
`chapulin_cfg.zig`. `chapulin_quic_token.zig` holds the Retry token calls,
`chapulin_ticket.zig` holds `Ticket`, `chapulin_pem.zig` holds `Chain`,
`EcdsaP256Key`, `RsaKey`, `MlDsa87Key` and `Anchors`, `chapulin_dnssec.zig`
holds the DNSSEC calls, `chapulin_cpu.zig` holds `Cpu` and `cpu_bits`, and
`chapulin_cfg.zig` builds each `ch_cfg`. The API is chapulin.hpp's kind of
wrapper: each call
forwards to the C call of the same name. It adds four things and no
more:

- the options a session is configured from, and the `ch_cfg` they set;
- one Zig error per result code;
- the callbacks C calls, which copy bytes between the caller's slices and
  the session;
- storage: the receive buffer, the latest ticket, the peer's transport
  parameters, a P-256 key that a PEM file decodes to and, under
  `RAND=session`, the session's `std.Random`.

Every TLS rule stays in C. Where a caller needs a record length, a write
size or a ticket's age, the API calls the C function that computes it
(docs/decisions.md 72 and 73).

## Adding the dependency

Zig 0.16.0. The package's options are the Makefile's variables
(docs/building.md), `HOST_TARGET` among them: a check sets it empty to
build the device object for a host target, as it sets make's
(docs/decisions.md 89), and a program leaves it unset:

```zig
const chapulin = b.dependency("chapulin", .{
    .target = target,
    .RAND = .@"extern",
    .TRANSPORT = .@"tcp-nonblocking",
    .ROLE = .both,
    .TRUST = .webpki,
    .EXPORTER = .on,
});
module.addImport("chapulin", chapulin.module("chapulin"));
```

The module `chapulin` carries the object. A program links it by
importing the module, once however many of its modules import it, and
adds no object of its own: a second `addObjectFile` of `chapulin.o`
defines every public name twice, and the link fails. The named lazy path
`chapulin.o` stays for a program that compiles the headers as C.

In the program:

```zig
const chapulin = @import("chapulin");

pub fn main() !void {
    if (!chapulin.build_matches()) return error.WrongObject;
    // ...
}
```

`chapulin.c` is the object's public headers, translated by translate-c
under the defines the object compiled with (docs/decisions.md 70). What
the API leaves out, a program uses there under its C name:
`chapulin.c.ch_drbg_seed`, `chapulin.c.CH_TX_PT`,
`chapulin.c.ch_build_matches`.

The image still defines the hooks the object imports: `ch_rand_bytes`
under `RAND=extern`, `ch_assert_fail`, `ch_keylog` under `KEYLOG=on`, and
`ch_aes_block` under `AES=extern` (docs/porting.md). The module exports
none of them. A `RAND=drbg` object defines `ch_rand_bytes` itself, and a
`RAND=session` object names none: each session draws from the
`std.Random` its options carry (Random bytes, below).

### Two objects in one program

colibri links a tcp-nonblocking object and a QUIC object into one image.
Each is a dependency of its own, imported under a name of its own:

```zig
const h2 = b.dependency("chapulin", .{ .target = target, .RAND = .@"extern", .TRANSPORT = .@"tcp-nonblocking", .ROLE = .both, .TRUST = .webpki, .EXPORTER = .on });
const quic = b.dependency("chapulin", .{ .target = target, .RAND = .@"extern", .TRANSPORT = .@"quic-nonblocking", .ROLE = .both, .TRUST = .webpki, .SUITE = .aesgcm, .KEYLOG = .on });
module.addImport("chapulin_h2", h2.module("chapulin"));
module.addImport("chapulin_quic", quic.module("chapulin"));
```

The two modules' types are distinct: `chapulin_h2.ClientOptions` is not
`chapulin_quic.ClientOptions`. Only types Zig compares by structure, such as
byte slices, arrays and integers, pass between them. A program that
serves both keeps options of its own and converts them once per object.

Zig refuses one file in two modules of one program. So `build.zig`
copies the API files into a directory of each configuration's own,
beside `defines.txt`, the object's define list, which makes two
configurations' directories differ.

## One module per configuration

Each file declares every call. A declaration whose C name the object
lacks is a `@compileError` that names the build option that adds it, so
a use of it fails to compile. A program asks what an object has through
`chapulin.c`, with `@hasDecl` and `@hasField`, because `@hasDecl` is true
for a `@compileError` declaration too.

| Declaration | Present when the object has |
|---|---|
| `ClientOptions` | a client role: its transport's client entry point, `ch_connect`, `ch_tcp_init` or `ch_quic_init` |
| `ServerOptions`, `EcdsaP256Identity`, `RsaPssIdentity` | a server role (`ch_cfg.srv`) outside PROFILE=cnsa2 |
| `MlDsa87Identity` | a host server role or the PROFILE=cnsa2 server (`srv.mldsa87`, docs/decisions.md 162 and 180) |
| `Chain`, `EcdsaP256Key`, `RsaKey` | a server role (`ch_chain_from_pem`, `ch_p256_key_from_pem`, `ch_rsa_key_from_pem`) outside PROFILE=cnsa2 |
| `MlDsa87Key` | `ch_mldsa_key_from_pem`, which the same objects as `MlDsa87Identity` export |
| `Anchors` | `ch_anchors_from_pem` (TRUST=webpki) |
| `tcp.Client` | `ch_tcp_init` |
| `tcp.Server` | `ch_srv_tcp_init` |
| `tcp.alert_record_len`, `tcp.key_update_record_len` | `ch_tcp_whole_len` |
| `quic.Client` | `ch_quic_init` |
| `quic.Server`, `quic.retry_tag`, `quic.token_mint`, `quic.token_check`, `quic.TokenCheck`, `quic.ChooseVersion` | `ch_srv_quic_init` |
| `quic.Level`, `quic.Direction`, `quic.KeySet`, `quic.level_count` | `ch_quic_initial_keys` |
| `Trust.web_pki`, `Trust.pins`, `TrustAnchor`, `CertType`, `server_cert_type` | `ch_cfg.anchors` (TRUST=webpki) |
| `Trust.pinned` | no `ch_cfg.anchors` |
| `ClientOptions.alpn`, `alpn_selected` | `ch_cfg.alpn_protocols` |
| `ClientOptions.random` and `ServerOptions.random` other than `void`, and `RandomSource` other than `void` | `ch_cfg.rand_bytes` (RAND=session) |
| `Cpu`, `cpu_bits`, and `ClientOptions.cpu`, `ServerOptions.cpu` and `EcdsaP256Key.init_from_pem`'s `cpu` other than `void` | `ch_cfg.cpu` (a host object, `-DCH_CPU_RUNTIME`) |
| `ServerOptions.cipher_suites` | `ch_srv_cfg.cipher_suites` (SUITE=aesgcm) |
| `ServerOptions.choose_version` other than `void` | `ch_srv_cfg.choose_version` (a QUIC server role) |
| `ClientOptions.cipher_suites` | `ch_cfg.cipher_suites` (SUITE=aesgcm TRUST=webpki) |
| `suite` | `ch_tls.suite` |
| `export_keying_material` | `ch_export` (EXPORTER=on) |
| `hook_context` | `ch_keylog` (KEYLOG=on) |
| `dnssec.Algorithm`, `dnssec.DigestType`, `dnssec.Hash`, `dnssec.verify` | `dnssec.h`'s five calls (DNSSEC=on) |
| `Error.Discard`, `Error.AeadLimit` | `CH_QUIC_DISCARD` (a QUIC object) |
| `Error.KeyUpdateLimit` | `CH_KEY_UPDATE_LIMIT` (a TCP object) |
| a record session's `key_update` | never: the name is reserved |

Each public header declares a call only under the defines of the
objects that define it, so `@hasDecl(chapulin.c, name)` answers whether
the object has that call, and a program that calls one the object lacks
fails to compile rather than to link. `matches.zig` holds that rule for
every configuration the check builds, and the script holds it for
`x509_ca.h`, `pem_files.h` and `drbg.h` where `chapulin.c` is not
translated from them
(How it is checked). `Trust` is declared in every object; its variants
are the trust mode's. A value field an object lacks has type `void`, so
a literal that sets it does not compile.

## Values

Every slice and pointer in a value is borrowed and must outlive the
session, as `ch_cfg`'s pointers must (`cfg.h`, `srv_cfg.h`). The session
keeps a copy of the `ch_cfg`, not of what it points at. Lists are Zig
types (docs/decisions.md 168):

- a server identity's `chain` is `[]const []const u8`, DER, end-entity
  first;
- `Trust.web_pki.anchors` is `[]const TrustAnchor`, each `.{ .name,
  .spki }`, a root's subject Name and SubjectPublicKeyInfo, each the
  whole DER TLV;
- `alpn` is `[]const []const u8`, the protocol names.

A session type takes `Limits` at compile time, as it takes its receive
length: `chain_max`, 8 by default and 255 at most, the certificates of
each identity's chain, and `anchors_max`, 256 by default, the roots a
client takes. Pass `.{}` for the defaults. The session holds storage for
that many entries and builds the C lists there in `init`, which answers
`error.Invalid` for a longer list. An ALPN list holds `CH_ALPN_MAX`
names at most in every session. The builder is `chapulin_cfg.zig`,
which the module does not export, so no program names the C list types.
A test build reaches it as `chapulin.testing`.

`SpkiPin` is `[CH_SPKI_PIN_LEN]u8`, the SHA-256 of a DER SubjectPublicKeyInfo;
a slice of them is `ch_cfg.spki_pins` as it is.

`Clock` is the caller's clock, in a `TRUST=webpki` or server object
alone. Its `now_seconds` is a C function that answers seconds since
1970-01-01T00:00:00Z, and its `clock_io`, null by default, is the
argument it gets. Each `init` calls it once and judges the whole
connection at that answer.

### Trust

The client's trust, whose variants are the object's trust mode's:

| Variant | Field | `ch_cfg` fields |
|---|---|---|
| `web_pki` | `anchors` | `anchors`, `anchor_count` |
| | `server_name` | `hostname`, `hostname_len` |
| | `clock`, a `Clock` | `now_seconds`, `clock_io` |
| | `pins`, empty by default | `spki_pins`, `spki_pin_count` |
| `pins` | `pins` | `spki_pins`, `spki_pin_count` |
| | `server_name`, optional | `hostname`, `hostname_len` |
| `pinned` | `server_pubkey` | `server_pubkey`, `server_pubkey_len` |
| | `server_pubkey2`, optional | `server_pubkey2`, `server_pubkey2_len` |

`webpki_cfg.h` and `cfg.h` state each field's rules, and `init` answers
`error.Invalid` for a value C refuses.

### ClientOptions

| Field | `ch_cfg` fields |
|---|---|
| `trust` | the fields `Trust` names |
| `alpn`, empty by default | `alpn_protocols`, `alpn_count` |
| `ticket`, null by default | `ticket`, the `Ticket`'s own bytes, whose layout is `c.ch_saved_ticket`'s |
| `ticket_age_ms`, 0 by default | `ticket_age_ms` |
| `takes_tickets`, true by default | none in the options' `ch_cfg`: a session's `init` sets `on_ticket` to the API's callback when it is true, and leaves `on_ticket` NULL when it is false |
| `require_pq`, false by default | `require_pq` |
| `quic_version`, null by default, `TRANSPORT=quic-nonblocking` alone | `quic_original_version`, the version's code, or 0 for null, which `init` refuses |
| `cipher_suites`, empty for the build's order, SUITE=aesgcm TRUST=webpki alone | `cipher_suites`, `cipher_suite_count` |
| `random`, null by default, `RAND=session` alone | `rand_bytes` and `rand_io`, through the session's own copy |
| `cpu`, null by default, a host object alone | `cpu`: `CH_CPU_PROBED`, and the bit of each field of the `Cpu` value that is true, or 0 for null, which `init` refuses. `constant_time_multiply` is the caller's statement about the widening multiply on its CPU and in its thread's mode, and runs the native multiply, and X25519 on the 51-bit-word field |
| `context`, null by default | none in `ch_cfg`: a session's `init` stores it in the session's `hook`, which `cfg.io` points at, and `hook_context` returns it in `ch_keylog` |

A session's `init` takes the options by `*const` pointer, builds that
`ch_cfg`, adds its buffer, callbacks and `io` to it, and under
`RAND=session` its source. It copies what it keeps and keeps no pointer
to the options. With a ticket, a raw or
ca mode's `ch_cfg` leaves the two `server_pubkey` slots
unset, because `ch_cfg` takes one auth mode. The age is the time since `on_ticket` handed the ticket over,
in milliseconds. C refuses a ticket older than its lifetime or older than
seven days (`ticket.h`, RFC 9846 §4.3.11.1 and §4.7.1), so `init`
answers `error.Invalid` for it: an age of exactly the lifetime is still
offered, and one millisecond more is refused.

### Ticket

A NewSessionTicket (RFC 9846 §4.7.1) that outlives its session: the
`c.ch_ticket` `on_ticket` received, by value, as `ticket`, and the
identity bytes it pointed at, as `identity`. `ticket.identity` is null,
because the bytes it named are valid during `on_ticket` alone. It is an
extern struct with the layout of `c.ch_saved_ticket` (`ticket.h`), which
a comptime check holds, so `init` points `ch_cfg.ticket` at it
as it is, and `saved()` names it as that type.

- `take_ticket()` on a client session moves the latest ticket out.
- `Ticket.from_fields(&.{ .identity, .psk, .age_add, .lifetime_seconds,
  .epoch, .binding or .trust_hash, .quic_version })` rebuilds one from
  fields a program stored. `lifetime_seconds` is `ticket.lifetime_s`.
  It refuses an identity longer than `CH_TICKET_ID_MAX` and a psk that is
  not `SHA256_LEN` or, in an object whose `HKDF_HASH_MAX` is
  `SHA384_LEN`, that length. It keeps an empty identity, and `init`
  refuses it, as every C client entry refuses an identity that is not 1
  to `CH_TICKET_ID_MAX` bytes. `binding` is a field under TRUST=webpki
  alone, `trust_hash` one in every other object, and `quic_version`, a
  `?quic.Version`, under
  `TRANSPORT=quic-nonblocking` alone: null writes 0, which `init` refuses
  as a resuming ticket's version.
- `Ticket.from_on_ticket(ticket)` copies what `on_ticket` hands over,
  through `ch_ticket_save`, for a program that writes its own
  `on_ticket`. It answers null for a ticket that call refuses: an
  identity that is NULL, empty or longer than `CH_TICKET_ID_MAX`, which C
  drops before `on_ticket`.

A program that copies a Ticket owns zeroing that copy. C never hands
over a ticket whose lifetime is 0, so `take_ticket` never returns one.

A client session sets `on_ticket` only when the options' `takes_tickets`
is true, which is the default. Under TRUST=webpki, the init call of a
session that sets `on_ticket` hashes the hostname, the anchors and the
SPKI pins. The hash runs on the SHA-256 path that the `cpu` value names,
and every ticket that the session receives is bound to it
(docs/decisions.md 132). Set `takes_tickets` to false for a client that
never offers a ticket. Then `init` runs no hash, the session keeps no
ticket, and `take_ticket` returns null. A client with `takes_tickets`
false can still offer a ticket in `ticket`, and the ticket still
resumes. Its `init` then hashes once, to check the ticket's binding.

A ticket one object received may be offered through another object of
the same program. A TRUST=webpki client binds a ticket to the hostname,
the anchors and the SPKI pins (`webpki_ticket.h`), not to the transport
or the ALPN protocol. A chapulin server passes over a ticket whose
ALPN protocol is not the connection's (`srv_resume.c`), and the resuming
hello still offers the certificate path, so that costs a full handshake
(docs/decisions.md 55). A QUIC ticket belongs to the QUIC version of the
connection that received it, `ticket.quic_version` (RFC 9369 §5): a
client's `init` refuses it in a connection whose `quic_version` is the
other one, and a chapulin server that chose the other version passes it
over.

### ServerOptions

| Field | `ch_cfg` fields |
|---|---|
| `ecdsa_p256`, null by default | `srv.ecdsa_p256`: `chain`, `chain_count`, `priv`, `priv_len = 32`, `pub`, `pub_len = 64` |
| `rsa_pss`, null by default | `srv.rsa_pss`: `chain`, `chain_count`, `priv`, the key's `c_key()`, `priv_len = @sizeOf(c.ch_rsa_priv)`, `pub`, `pub_len` |
| `mldsa87`, null by default, a host object alone | `srv.mldsa87`: `chain`, `chain_count`, `priv`, `priv_len = 4896`, `pub`, `pub_len = 2592` |
| `cookie_key` | `srv.cookie_key` |
| `ticket_key`, null for no tickets | `srv.ticket_key` |
| `ticket_key_previous`, null for none | `srv.ticket_key_previous` |
| `clock`, null for no clock | `now_seconds`, `clock_io` |
| `alpn`, empty by default | `alpn_protocols`, `alpn_count` |
| `require_server_name` | `srv.require_server_name` |
| `cipher_suites`, empty for the default order | `srv.cipher_suites`, `srv.cipher_suite_count` |
| `quic_version`, null by default, `TRANSPORT=quic-nonblocking` alone | `quic_original_version`, as for a client: the Version field of the client's first Initial packet |
| `choose_version`, null by default, `TRANSPORT=quic-nonblocking` alone | none in the options' `ch_cfg`: the session's `init` points `srv.choose_version` at its own adapter, which calls this `quic.ChooseVersion` with the options' `context`. null keeps the original version |
| `random`, null by default, `RAND=session` alone | `rand_bytes` and `rand_io`, as for a client |
| `cpu`, null by default, a host object alone | `cpu`, as for a client |
| `context`, null by default | none in `ch_cfg`, as for a client; `choose_version` gets it too |

`EcdsaP256Identity` takes the chain, the leaf's point X||Y as
`*const [64]u8` and the private scalar as `*const [32]u8`.
`RsaPssIdentity` takes the chain, the modulus and a `*const RsaKey`. In a
host object the key holds its five CRT integers after its modulus and
private exponent (`rsa_sign.h`), and a session that states its multiply
signs with them. A session's `init`
answers `error.Invalid` for a chain longer than its `Limits.chain_max`.
`check()`, which takes the options by `*const` pointer, holds its chains at 255, the most `chain_count`'s `u8` holds,
and runs
`ch_srv_check`: each provisioned key signs, and the signature verifies.
It also refuses a `cookie_key`, `ticket_key` or `ticket_key_previous`
that a server init call refuses. It takes no session.

### PEM files

Three values decode the files an operator holds, through the three calls
that `pem_files.h` declares (docs/decisions.md 131). None reads a file:
the program reads it into a slice and passes the slice. `Chain.from_pem`
and `Anchors.from_pem` return a value. Each key's `init_from_pem` fills
the key in place. Each answers `error.Invalid` for a file that the C call
refuses.

| Value | C call | What it holds |
|---|---|---|
| `Chain` | `ch_chain_from_pem` | `certs`, the DER slices the call filled, which the identities' `chain` takes; `leaf()` is the end-entity certificate's DER |
| `EcdsaP256Key` | `ch_p256_key_from_pem` | `private_key` and `public_key`, what `EcdsaP256Identity` points at; `init_from_pem` takes the `cpu` value and the leaf the key must match |
| `RsaKey` | `ch_rsa_key_from_pem` | the key, which `RsaPssIdentity.private_key` points at, as bytes the API promises nothing about; `public_key()` is its modulus, which `RsaPssIdentity.public_key` takes; `init_from_pem` takes the `cpu` value and the leaf the key must match; `wipe` zeroes the key |
| `MlDsa87Key` | `ch_mldsa_key_from_pem` | `private_key` and `public_key`, what `MlDsa87Identity` points at; `init_from_pem` takes the `cpu` value and the leaf the key must match |
| `Anchors` | `ch_anchors_from_pem` | `anchors`, the `TrustAnchor` values the call filled, which `Trust.web_pki.anchors` takes |

`Chain.from_pem` and `Anchors.from_pem` take two rooms that the program
places and sizes: a DER room, and a slice of `[]const u8` or of
`TrustAnchor` with one entry for each block. The call fills them, and
refuses a file that does not fit them. A DER room of `pem.len / 4 * 3`
bytes holds the DER of any file. A chain holds 255 certificates at most.
`Anchors.from_pem` takes the session type's `Limits` first and refuses a
bundle of more than `anchors_max` roots, which that session could not
take. Each call has the C call write its entries into an array on its
own stack, because a bundle has no C cap and the API allocates nothing.
The value's slices point into the DER room, so both rooms stay where
`from_pem` filled them for as long as a session uses them.

`EcdsaP256Key.init_from_pem` takes `cpu` first, the `?Cpu` that `ServerOptions.cpu`
takes, in a host object alone, and `void` in every other object. A host
object refuses null, and computes the point on the wide P-256 field
under `constant_time_multiply`. `cpu_bits` gives the C value a `?Cpu`
sets. The value holds the private scalar: `wipe()` zeroes it once no
session uses it. The program wipes the key file's text itself after
`init_from_pem` returns, on success and on error. The `defer` below does so.

```zig
var chain_der: [16384]u8 = undefined;
var chain_entries: [12][]const u8 = undefined;
const chain = try chapulin.Chain.from_pem(chain_file, &chain_der, &chain_entries);
var key: chapulin.EcdsaP256Key = .{};
defer std.crypto.secureZero(u8, key_file);
try key.init_from_pem(cpu, key_file, chain.leaf());
const server: chapulin.ServerOptions = .{ .ecdsa_p256 = .{
    .chain = chain.certs,
    .public_key = &key.public_key,
    .private_key = &key.private_key,
}, .cookie_key = &cookie_key, .cpu = cpu };
```

### Random bytes

Under `RAND=session` each session draws from the source its own options
name (`rand.h`, docs/entropy.md). `ClientOptions.random` and `ServerOptions.random`
are `?std.Random`, null by default; in any other build they are `void`,
and the sessions draw from the image's `ch_rand_bytes`.

- **The session stores it.** `init` copies the `std.Random` into the
  session's `random` field, a `RandomSource`, and points
  `ch_cfg.rand_io` at that copy and `ch_cfg.rand_bytes` at an adapter
  that fills each draw's `out[0..n]` from it. The copy lives as long as
  the session, which must not move after `init`.
- **A value without one is refused at init.** A null `random` leaves
  `rand_bytes` NULL, C answers `CH_EINVAL`, and `init` returns
  `error.Invalid` with nothing sent. The refusal is C's, like every other
  configuration rule. A Zig field's default cannot depend on the build,
  so a field that is required here and absent elsewhere would need a
  second copy of each value struct.
- **`ServerOptions.check`** holds the value for its one call: the RSA-PSS
  signature it makes draws its salt from it.
- **The source.** In production it is a CSPRNG, such as
  `std.crypto.random`. A deterministic stream gives predictable keys to
  anyone who knows its seed, so a seeded `std.Random.DefaultPrng` per
  session, which replays a connection byte for byte, is for tests.
- **Threads.** A session draws from its own source alone, so sessions on
  different threads share no entropy state in chapulin and need no lock
  around its draws.

### The CPU

A host object, which the package builds for a `TRUST=webpki` client,
`ROLE=server` and `ROLE=both` on an arm64 or x86-64 target, takes the
caller's description of its CPU in `ch_cfg.cpu` (`cpu_cfg.h`,
docs/decisions.md 89). `ClientOptions.cpu` and `ServerOptions.cpu` are `?Cpu`, null by
default; in any other object they are `void`, and `Cpu` is a
`@compileError`. For an x86-64 host object the package adds the CPU
feature evex512 to the target, whatever CPU the program builds for:
`rsa_ifma.c`'s functions take and return 512-bit vectors, and Zig turns
evex512 off for a CPU without AVX-512. evex512 alone turns on no
instruction, so the object holds AVX-512 instructions in the functions of
the AVX-512 kernels alone, `rsa_ifma.c`, `rsa_ifma_sign.c`,
`chacha20_avx512.c` and `poly1305_ifma.c`, under their target attributes,
and in `avx512_wipe.c`'s block of assembly, as make's does
(docs/decisions.md 119 to 121).

- **A value states what the caller found.** `Cpu` holds eleven bools,
  false by default: `constant_time_aes`, `constant_time_multiply`, `avx2`,
  `vaes`, `constant_time_sha256`, `constant_time_sha512`,
  `constant_time_sha3`, `avx512_ifma`, `avx512`, `bmi2_adx` and `bmi1`.
  `init` writes
  `CH_CPU_PROBED` and the bit of each one that is true. `Cpu{}` says the
  caller looked and states nothing more. The five named `constant_time_`
  state a timing, and `cpu_cfg.h` says what each claims. `avx2`, `vaes`,
  `avx512_ifma`, `avx512`, `bmi2_adx` and `bmi1` are x86-64's and say what
  the CPU has: with
  `avx2` the session's ChaCha20
  runs in 256-bit vectors, and with `vaes` beside `constant_time_aes` its
  AES-GCM runs on VAES and VPCLMULQDQ (docs/decisions.md 90). With `avx2`
  and without `avx512_ifma` the session runs RSA verification's public
  operation on `rsa_avx2.c`, in digits of 28 bits, or 27 above 3,072
  bits, four to a 256-bit register, for the moduli `avx512_ifma` names
  below (docs/decisions.md 122).
  `avx512_ifma` says the CPU has AVX-512F and AVX-512 IFMA and its
  operating system saves the 512-bit registers, and with it the session
  runs RSA verification's public operation on `rsa_ifma.c`, in digits of
  52 bits, eight to a 512-bit register, for an odd modulus of 2,048 bits
  or more whose bit length is a multiple of 64, and its ChaCha20 keystream
  sixteen blocks a pass on `chacha20_avx512.c` in place of the AVX2 kernel.
  Beside `constant_time_multiply`, whose statement covers IFMA's 52-bit
  products, the session also signs with RSA on `rsa_ifma_sign.c` and runs
  a Poly1305 update of 512 bytes or more on `poly1305_ifma.c`
  (docs/decisions.md 120 and 121). `x509.c` verifies the chain links of
  `TRUST=ca-rsa` with `rsa_pss_verify`, which takes no `cpu`, so they run
  `rsa_mont64.c` whatever the two fields say.
  `avx512` says the CPU has AVX-512F, AVX-512BW and AVX-512VL, and VAES
  and VPCLMULQDQ on the 512-bit registers, and beside `vaes` and
  `constant_time_aes` the session runs each AES-GCM seal and open whole,
  four blocks to a 512-bit register, on `gcm_avx512_kernel.c`. It picks
  nothing else, so a caller can leave it clear and keep `avx512_ifma`'s
  kernels (docs/decisions.md 130). `bmi2_adx` says the CPU has BMI2 and
  ADX, and beside `constant_time_multiply` the session computes an X25519
  shared secret on `x25519_adx.c`'s four 64-bit words (docs/decisions.md
  165) and its P-256 point arithmetic on `p256_adx.h`'s copy of the wide
  files. By itself it runs an ECDSA P-256 verification on that copy
  (docs/decisions.md 171). `bmi1` says the CPU has BMI1, and beside
  `bmi2_adx` the session runs SHA-3 and SHAKE on `sha3_hw.c`'s copy of
  `sha3.c`, whose chi is ANDN and whose rotations are RORX, so its
  ML-DSA-87 hashes run there. ML-KEM's hashes run `sha3.c` whatever the
  field says (docs/decisions.md 217).
  The three hash fields say the CPU has the SHA-256, the SHA-512 or the
  SHA-3 instructions. With `constant_time_sha256` the session hashes its
  transcript and derives its keys over SHA-256 on them, and with
  `constant_time_sha512` an arm64 session does the same over SHA-384.
  With `constant_time_sha3` an arm64 session runs ML-KEM's hashes on the
  SHA-3 instructions, in an object that clang compiled, which an object
  `zig build` compiles is (docs/decisions.md 93 and 99).
- **A value without one is refused at init.** A null `cpu` leaves the
  field 0, C answers `CH_EINVAL`, and `init` and `ServerOptions.check` return
  `error.Invalid` with nothing sent. So does `avx2`, `vaes`,
  `avx512_ifma`, `avx512`, `bmi2_adx` or `bmi1` in an arm64 object, and `constant_time_sha512` or
  `constant_time_sha3` in an x86-64 one: each object defines its own
  architecture's bits. Both refusals are C's.
- **The probe is the caller's.** chapulin and its API probe nothing and
  set no CPU mode. A caller states the constant-time bits only where it
  can: on arm64 a core with FEAT_DIT and a thread that has set
  PSTATE.DIT, and on x86-64 a part on Intel's DOIT list whose operating
  system has set DOITM.

### Codes and reports

- `Group`: `ch_group`'s code points, `x25519`, `x25519mlkem768`,
  `secp256r1`.
- `Suite`: `ch_suite`'s, `cipher_suites`' and `srv.cipher_suites`' code points.
- `State`: `start`, `connected`, `closed`, `failed`.
- `CertType`: `x509`, `raw_public_key`.
- `AlertDescription`: RFC 9846 §6's alert descriptions, with the RFC's
  names, which `std.crypto.tls.Alert.Description` uses too, and `_` for
  any other byte. `alert_sent`, `alert_received`, a QUIC session's
  `alert` and `fail` carry one. `alert_of(code)` converts a C alert byte,
  null for 0.
- `build_matches()`: `ch_build_matches` over the object's own record,
  `ch_build_info_<transport>`. A test that checks a changed record calls
  `chapulin.c.ch_build_matches` with its own.
- `Hook`: what `ch_cfg.io` points at in every session. Its `context` is
  the options' `context`, which a session's `init` stores.
- `hook_context(io)`: the caller's context from the `io` argument
  `ch_keylog` receives. The API owns `cfg.io`, and this is how the
  image's `ch_keylog` finds the connection it logs for.

## Errors

One Zig error per result code, named as chapulin.hpp's `Status` names
it. Each call's error set is the part of `chapulin.Error` its C call
returns. A set of more than one error has a name in its session's file:
`tcp.RecordInError`, `tcp.ServerRecordInError`, `tcp.RecordOutError`,
`tcp.ReadError`, `tcp.WriteError`, `tcp.FailError`, `quic.CryptoInError`,
`quic.ServerCryptoInError`, `quic.CryptoOutError`, `quic.SealError`,
`quic.OpenError` and `quic.TokenMintError`. `tcp.InitError`,
`tcp.EndError`, `tcp.ExportError` and `quic.InitError` name the sets of
one error that a session call returns.

| C code | Zig | The session after it |
|---|---|---|
| `CH_EIO` | `error.Io` | Dead. An output slice could not take what C sent. |
| `CH_EPROTO` | `error.Proto` | Dead after a protocol failure, and after the peer's fatal alert, which `alert_received` names. As it was for bytes delivered to a session that failed or closed, and for `read` or `write` before the handshake completed, which keeps running. |
| `CH_EAUTH` | `error.Auth` | Dead. |
| `CH_ECAP` | `error.Cap` | Live from `record_out`, `crypto_out`, `seal`, `seal_close` and `token_mint`: the caller's buffer was short. Dead from `record_in`, `crypto_in` and `read`: the peer's message could never fit. |
| `CH_EINVAL` | `error.Invalid` | Nothing was sent. From `init`, failed until the next `init`: C refused the configuration, a stale ticket or a server identity its flight could not use among the refusals. From any other call, as it was: the call came out of order or an argument was refused. A server's `record_in` never returns it, and its `crypto_in` returns it only for a level the call refuses on entry. |
| `CH_QUIC_DISCARD` | `error.Discard` | Live. The caller drops the packet. |
| `CH_QUIC_AEAD_LIMIT` | `error.AeadLimit` | Dead. |
| `CH_KEY_UPDATE_LIMIT` | `error.KeyUpdateLimit` | Dead. The peer sent one KeyUpdate past `CH_KEY_UPDATE_RUN_MAX` in a row (docs/decisions.md 138). |
| `CH_TCP_AGAIN` | none | `read` returns `pt_len = 0`. |
| `CH_ECLOSED` | none | No call returns it. |

`write`'s `error.Cap` has two sources: the API's own refusal of a `pt`
longer than `writable_len(output.len)`, which seals nothing and leaves
the session as it was, and C's, when a record cannot be sealed, which
leaves it dead. `token_check` answers `CH_EPROTO` and `CH_EAUTH` as the
values `.not_retry` and `.invalid`, because they judge a token, not a
session.

`from_code(E, code)` is the mapping every call uses: nothing for
`CH_OK`, and otherwise the error of `E` that the code stands for. A code
`E` does not name is one the call's header says it never returns, and it
panics. A program that calls a C function the API leaves out maps its
result with `from_code(chapulin.Error, code)`.

## tcp-nonblocking sessions

`TRANSPORT=tcp-nonblocking`. `tcp.Client(receive_len, limits)` and
`tcp.Server(receive_len, limits)` are types whose size is known at compile
time, so a program places a session in a static, in a connection struct
or on the stack, with no allocation. Each holds the C session, `tcp`,
the receive buffer `cfg.buf`, `receive`, the `hook`, the source `random`
under `RAND=session`, the slices the callbacks copy between during one
call, `io`, the storage of its lists under `limits`, `lists`, and, on the
client, the latest ticket. Do not move a session after `init`: `cfg.io`
points at its hook, `cfg.rand_io` at its `random`, and `cfg`'s lists at
its `lists`. colibri sizes both at 20,480 bytes.

| Zig call | C call | Errors |
|---|---|---|
| `Client.init(options)` | the options' `ch_cfg`, built into `lists`, then `ch_tcp_init` with the API's `send` and `recv`, the API's `on_ticket` when `takes_tickets` is true, and under `RAND=session` the options' `random` | Invalid |
| `Client.record_out(output)` | `ch_tcp_out`; after a failed `record_in`, the failure's alert record, then `error.Invalid` | Invalid, Cap |
| `Client.record_in(input)` | `ch_tcp_in`; returns the bytes consumed | Invalid, Proto, Auth, Cap |
| `Client.take_ticket()` | none: moves the slot out and zeroes it | none |
| `Server.init(options, sni_buf)` | the options' `ch_cfg`, built into `lists`, then `ch_srv_tcp_init` with the API's `send`, `recv` and `on_record_out`, and under `RAND=session` the options' `random`; `sni_buf` is `srv.sni_buf` and `srv.sni_cap` | Invalid |
| `Server.record_in(input, output)` | `ch_srv_tcp_in`, whose flight goes into `output`; returns `Progress{ consumed, written }` | Proto, Auth, Cap, Io |
| `Server.output_len()` | the bytes the last `record_in` wrote into `output`, which a failed `record_in` also sets: `Progress.written` on success | none |
| `Server.sni()` | `sni_buf[0..ch_sni_len]`, null when 0 | none |
| `state()` | `ch_tcp_state` | none |
| `alert_sent()`, `alert_received()` | `ch_alert_sent`, `ch_alert_received` on the session's `ch_tls` (alert.h), as an `AlertDescription`; each null when 0 | none |
| `read(input, pt, reply)` | `ch_tcp_whole_len`, then `ch_read` | Invalid, Proto, Auth, Cap, Io, KeyUpdateLimit |
| `write(pt, output)` | `ch_writable_len`, then `ch_write` | Proto, Cap, Io |
| `write_parts(parts, output)` | `ch_writable_len` over the parts' lengths together, then `ch_write_parts` over a `c.ch_part` for each slice of `parts`, `parts_max` at most | Proto, Cap, Io |
| `writable_len(cap)` | `ch_writable_len` | none |
| `end(output)` | `ch_close` | Io |
| `fail(description, output)` | `ch_fail` | Invalid, Proto, Cap, Io |
| `close()` | `ch_tcp_close`, then the ticket slot zeroed | none |
| `export_keying_material(label, context, out)` | `ch_export` | Invalid |
| `alpn_selected()` | the name `ch_alpn_selected` indexes; null for `CH_ALPN_NONE` | none |
| `group()`, `suite()` | `ch_group`, `ch_suite`; null while 0 | none |
| `psk_selected()`, `server_cert_type()`, `peer_limit()`, `read_closed()` | `ch_psk_selected`, `ch_server_cert_type`, `ch_peer_limit`, `ch_read_closed` | none |
| `reply_len()` | the bytes the last `read` wrote into `reply`, which a failed read also sets | none |

A session in an object without SUITE=aesgcm runs ChaCha20 alone, and
`ch_suite` answers ChaCha20 for it, before the handshake too. A SUITE=aesgcm
TRUST=webpki client offers three, in the order `ClientOptions.cipher_suites`
names or, when it is empty, in the build's order: AES-256-GCM first in a
host object whose `ClientOptions.cpu` states `constant_time_aes`, ChaCha20 alone
in a host object without it, and ChaCha20 first on `AES=extern`
(docs/decisions.md 80 and 89). The API probes no CPU; a program that
probes its own passes the order it chose.

A record session's `key_update` is reserved: no C call starts a
tcp-nonblocking KeyUpdate, so it is a `@compileError` that says so. `write`
sends one inside `ch_write`, as the answer a peer's request owes or as
the last record an AES-GCM write key seals, so no such call is planned
(docs/decisions.md 78 and 138).

### A handshake

```zig
var client: chapulin.tcp.Client(20_480, .{}) = undefined;
const anchors = [_]chapulin.TrustAnchor{.{ .name = root_name, .spki = root_spki }};
const alpn = [_][]const u8{"http/1.1"};

try client.init(&.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "s3.example.test", .clock = .{ .now_seconds = wallClock } } },
    .alpn = &alpn,
});
send(output[0..try client.record_out(&output)]); // the ClientHello
// each time bytes arrive, until state() is .connected:
const consumed = try client.record_in(input);
send(output[0..try client.record_out(&output)]);
```

`record_in` takes whole records and leaves a trailing partial record for
the caller to present again, unchanged, with more bytes after it. A
server's `record_in` writes its whole flight into `output`, one record at
a time, and answers `error.Io` when `output` cannot take one; the
session is then dead.

When `record_in` fails, the side that failed has one alert record for
the caller to send before it closes the connection. A client's
`record_out` returns it, all of it when `output` holds it, and then
`error.Invalid`. A server's `record_in` has already written it into
`output`, after the records of the flight that went out before the
failure, and `output_len()` counts them all, because the error returns no
`Progress`. The record is in the clear before the failing side's write
key is installed, 7 bytes, and sealed after, `alert_record_len` bytes: a
client installs its key right after the ServerHello and a server right
after it has sent its own (tcp_nonblocking.h). `alert_sent` names the
alert. A `record_in` that fails on the peer's fatal alert has nothing to
send (RFC 9846 §6.2): `record_out` answers `error.Invalid` at once, and
`output_len()` counts only the records written before that alert.

```zig
const progress = server.record_in(input, &output) catch |err| {
    send(output[0..server.output_len()]); // the flight so far, then the alert
    return err;
};
```

### Reading

`read` passes at most one whole record of `input` to `ch_read`:
`ch_tcp_whole_len` says how many bytes that is, and `ch_read` reads
them through the API's `recv`. The `Read` it returns says:

- `consumed`: input bytes taken. 0 while `input` holds less than a
  record; one whole record; or the 5-byte header of a record whose
  length field is above 2^14 + 256, which `ch_read` refuses with
  `error.Proto`.
- `pt_len`: plaintext written into `pt`. 0 when the record held a
  ticket or a KeyUpdate. Plaintext `pt` cannot hold stays in the receive
  buffer, and the next `read` returns it and takes no input.
- `reply_len`: bytes `ch_read` sent into `reply`, the alert of a read
  that failed, or 0.
- `peer_closed`: `ch_read` returned 0, because the peer's close_notify
  arrived, now or earlier, or because this side closed.

A caller calls `read` until `consumed` and `pt_len` are both 0. An error
reports no `Read`. It leaves the session dead, except `error.Invalid`
for an empty `pt` and `error.Proto` for a session that is not
connected, which change nothing.

`reply` takes what `ch_read` sends: one alert record of
`alert_record_len`, 24 bytes, when the read fails, and `alert_sent` names
its alert. A read that fails on the peer's fatal alert sends nothing,
because RFC 9846 §6.2 has both sides close at once, and `alert_received`
names the peer's alert. So a `reply` of `alert_record_len` bytes is never
short. A `reply` too short for the alert fails the read with `error.Io`.
A KeyUpdate that asks for an answer gets it from the next `write`
(RFC 9846 §4.7.3), and `read` sends nothing for it. `read` takes at most
`CH_KEY_UPDATE_RUN_MAX` KeyUpdates in a row, and a record of application
data with one byte or more ends a run. The next one fails the read with
`error.KeyUpdateLimit` and the session with it, and `alert_sent` names
unexpected_message (docs/decisions.md 138).

### Writing and closing

`write` seals all of `pt` into `output` and returns the bytes written.
When `pt.len > writable_len(output.len)` it seals nothing and returns
`error.Cap`, and the session is as it was, so a caller that seals one
message at a time sizes `output` once and never loops. `ch_write` cuts
records of the smaller of `CH_TX_PT` and `peer_limit()`, and
`ch_writable_len` counts in the same limit, so a caller needs neither
number to size a write. At `TX_RECORD=16384` a record carries 16,384
bytes; the API adds nothing for it. A write carries one KeyUpdate record
of `key_update_record_len` bytes before its records when a peer's
request is owed an answer, and, under `SUITE=aesgcm`, among its records
when it takes an AES-GCM write key to its ceiling; one record serves
both, and `writable_len` counts it. A caller that sizes `output` for its
largest message adds `key_update_record_len` bytes there, or such a
write returns `error.Cap` with nothing sealed.

`write_parts(parts, output)` seals several buffers as one run of
plaintext, in the records `write` seals for them joined, under the same
rules: when the parts' lengths together pass `writable_len(output.len)`
it seals nothing and returns `error.Cap`. Each part is a `[]const u8`, so
an h2 DATA frame goes out as `write_parts(&.{ header, payload }, output)`
with no copy into one buffer (docs/decisions.md 167). A call takes
`parts_max` parts, 16, at most, and answers `error.Cap` with nothing
sealed for more. The call copies each slice into a `c.ch_part` on its
own stack, because a Zig slice has no defined layout, and the API
allocates nothing.

`end(output)` sends this side's close_notify into `output`, at most
`alert_record_len` bytes, and wipes the session's keys: that is
`ch_close`. It answers `error.Io` when `output` could not take the alert,
and the session is closed either way. The peer's close_notify closes the
peer's direction alone (RFC 9846 §6.1): `read` reports `peer_closed`,
`read_closed()` is true, and `write` still sends until this side calls
`end`. A side that called `end` reads nothing more. The name is
`std.crypto.tls.Client.end`'s, which sends close_notify too.

`fail(description, output)` fails a connected session with the fatal
alert `description`, an `AlertDescription`, names, for an error the caller found itself: that
is `ch_fail`. It sends the sealed alert into `output`, at most
`alert_record_len` bytes, and wipes the session's keys. A description
that is not an error alert of RFC 9846 §6.2 answers `error.Invalid`, and
a session that is not connected `error.Proto`; neither sends a byte or
changes the session. `error.Io` says `output` could not take the alert,
and the session failed all the same (docs/decisions.md 164).

`close()` calls `ch_tcp_close`, which wipes every secret and
marks the session dead, and then zeroes the ticket slot. A connected
caller calls `end` first.

### Secrets the API holds

The ticket slot holds a resumption PSK. `take_ticket` returns the ticket
and zeroes the slot with `std.crypto.secureZero`, and `close` in both
transports zeroes it too, after the C call has wiped the session's
keys. `on_ticket` zeroes the slot before it copies a newer ticket in, and
each init zeroes it before the C init call.

## QUIC sessions

`TRANSPORT=quic-nonblocking`. The types:

- `Level`: `initial`, `handshake`, `application`, and `level_count`.
- `Direction`: `read`, `write`.
- `KeySet`: `previous`, `current`, `next`, the 1-RTT receive set `open`
  reports.
- `Outgoing`: where a server's `crypto_in` writes the CRYPTO bytes it
  produces, one buffer per level, and `written`, which `crypto_in` adds
  to and never resets.
- `Opened`: `pn`, `pt_len` and `key_set`.
- `Version`: `v1` and `v2`, the Version field values `quic_cfg.h` names,
  and any other `u32`, which C refuses where it derives no keys.
- `ChooseVersion`: `*const fn (context: ?*anyopaque) Version`, a server's
  choice of the negotiated version (`srv_cfg.h`). The session's adapter
  calls it once per connection with the options' `context`, after
  `peer_transport_params` holds the client's transport parameters and
  before anything is selected or sent, and C fails the session with
  `error.Io` for a version it does not derive.
- `RetryConnectionIds`: the two connection IDs a Retry token carries,
  `original_dcid` and `retry_scid`, each with its length, in the layout
  of `c.ch_quic_retry_cids`, which a comptime check holds.
  `RetryConnectionIds.init(original_dcid, retry_scid)` copies both in and
  answers `error.Invalid` for one over `CH_QUIC_DCID_MAX` bytes.
- `TokenCheck`: `.retry` with the `RetryConnectionIds` the token carried,
  `.not_retry` or `.invalid`.

`quic.Client(receive_len, limits)` and `quic.Server(receive_len, limits)`
hold the C session, `quic`, the receive buffer, the storage of its lists,
the hook, under `RAND=session` the
source `random`, the caller's `peer_params` slice, the length of what
arrived there, the client's ticket slot and the server's current
`Outgoing`. colibri passes a
`peer_params` of 1,024 bytes and a `sni_buf` of 255.

| Zig call | C call | Errors |
|---|---|---|
| `Client.init(options, transport_params, peer_params)` | the options' `ch_cfg`, built into `lists`, then `ch_quic_init` with the API's `on_level_ready` and `on_transport_params`, the API's `on_ticket` when `takes_tickets` is true, and under `RAND=session` the options' `random` | Invalid |
| `Server.init(options, transport_params, peer_params, sni_buf)` | the options' `ch_cfg`, built into `lists`, then `ch_srv_quic_init` with the API's `on_level_ready`, `on_transport_params`, `srv.on_crypto_out` and, when the options carry a `choose_version`, `srv.choose_version`, and under `RAND=session` the options' `random` | Invalid |
| `initial_keys(dcid)` | `ch_quic_initial_keys` | Invalid |
| `Client.crypto_in(level, bytes)` | `ch_quic_crypto_in` | Invalid (live), Proto, Auth, Cap |
| `Client.crypto_out(level, out)` | `ch_quic_crypto_out` | Invalid, Cap (live) |
| `Server.crypto_in(level, bytes, outgoing)` | `ch_srv_quic_crypto_in` | Invalid (live), Proto, Auth, Cap, Io |
| `Client.take_ticket()`, `Server.sni()` | as in a tcp-nonblocking session | none |
| `keys_ready(level, direction)` | the bit `CH_QUIC_LEVEL_BIT` names in `ch_quic_levels_ready` | none |
| `peer_transport_params()` | the body `on_transport_params` copied, null before it arrives | Cap, when it was longer than `peer_params` |
| `seal(level, version, pn, pn_len, hdr, pt, out)`, `seal_close(...)` | `ch_quic_seal`, `ch_quic_seal_close`; return the packet's length | Invalid, Cap |
| `open(level, version, pkt, pn_off, largest_pn, current_phase_lowest_pn)` | `ch_quic_open`, in place | Invalid, Discard, AeadLimit |
| `retry_ok(version, pseudo, tag)` | `ch_quic_retry_ok` | none |
| `Client.switch_version(version)` | `ch_quic_switch_version` | Invalid |
| `negotiated_version()` | `ch_quic_negotiated_version` | none |
| `key_update()`, `key_phase()`, `drop_previous_keys()`, `discard(level)` | `ch_quic_key_update`, `ch_quic_key_phase`, `ch_quic_drop_previous_keys`, `ch_quic_discard` | Invalid for `key_update` and `discard` |
| `state()`, `alert()`, `error_code()` | `ch_quic_state`, `ch_quic_alert` as an `AlertDescription`, null when 0, `ch_quic_error_code` | none |
| `close()` | `ch_quic_close`, then the ticket slot zeroed | none |
| `alpn_selected()`, `group()`, `suite()`, `psk_selected()`, `server_cert_type()` | as in a tcp-nonblocking session | none |
| `quic.retry_tag(version, pseudo, tag)` | `ch_srv_quic_retry_tag` | Invalid |
| `quic.token_mint(key, version, address, ids, issued_seconds, out)` | `ch_srv_quic_token_mint`, the token bound to `version`, the original version; returns the token's length | Invalid, Cap |
| `quic.token_check(key, version, token, address, now_seconds, lifetime_seconds)` | `ch_srv_quic_token_check` under `version`; a token minted under another version is `.invalid` | Invalid |

`seal`'s `error.Invalid` includes RFC 9001 §6.6's confidentiality limit:
once a key set has sealed its limit, `ch_quic_seal` refuses every later
packet under it until `key_update` writes a new set (`quic.h`). A retry
does not clear it.

The server calls take no session, because a Retry comes before one (RFC
9000 §8.1.2). A QUIC session reports no peer alert: QUIC carries no alert
record, so the peer's CONNECTION_CLOSE is the caller's to read, and
`alert` names the alert this side's failure chose.

### A handshake

```zig
var outgoing: chapulin.quic.Outgoing = .{ .buffers = .{ &initial_buf, &handshake_buf, &application_buf } };
try server.init(&server_options, &server_params, &server_peer, &sni_buf);
try client.init(&client_options, &client_params, &client_peer);
try client.initial_keys(dcid);
try server.initial_keys(dcid);

const hello = try client.crypto_out(.initial, &message);
try server.crypto_in(.initial, message[0..hello], &outgoing);
try client.crypto_in(.initial, initial_buf[0..outgoing.written[0]]);
try client.crypto_in(.handshake, handshake_buf[0..outgoing.written[1]]);
const finished = try client.crypto_out(.handshake, &message);
try server.crypto_in(.handshake, message[0..finished], &outgoing);
// client.state() and server.state() are .connected, and the server's
// ticket waits at the application level of outgoing.
```

A client calls `crypto_out` at each level after `crypto_in`, because
`ch_quic_crypto_in` refuses more bytes while a message is staged
(`quic.h`). `keys_ready` answers which keys each step installed; no key
leaves the session, and the API's `on_level_ready` does nothing, because
`ch_quic_levels_ready` reports the same bits after the call. Header protection
runs inside `seal` and `open`, as in C (RFC 9001 §9.5).

## What stays out

- **The blocking transport.** `ch_connect` and `ch_srv_accept` call
  `cfg.send` and `cfg.recv`, which block. A tcp-blocking object's module
  offers the options, `build_matches`, `ServerOptions.check` and `chapulin.c`.
- **The image's hooks, the DRBG and CA provisioning.** `ch_rand_bytes`,
  `ch_assert_fail`, `ch_keylog`, `ch_aes_block`, `ch_drbg_seed` and
  `ch_pubkey_from_pem` stay the program's, through `chapulin.c`. Under
  `RAND=session` the API takes the source, as `ClientOptions.random` and
  `ServerOptions.random`, because it is a value of each session.
- **An external PSK, the CA epoch callbacks and `pin_slot`.** They serve
  device builds. Each is one `ch_cfg` or `ch_tls` field a later version
  can add.
- **A tcp-nonblocking KeyUpdate the caller starts.** Reserved, above.
- **Private fields.** Zig has none, so a session's `tcp` or `quic`
  field, and an `RsaKey`'s `bytes`, is visible. The API promises nothing about them.

The constants a caller sizes storage by keep their C names in
`chapulin.c`: `CH_TX_PT`, `CH_TX_STAGE`, `CH_MIN_RXBUF`, `CH_ALPN_MAX`,
`CH_SPKI_PIN_MAX`, `CH_SPKI_PIN_LEN`, `CH_TICKET_ID_MAX`,
`CH_SRV_COOKIE_KEY_LEN`, `CH_SRV_TICKET_KEY_LEN`, `CH_QUIC_TOKEN_KEY_LEN`,
`CH_QUIC_TOKEN_MAX`, `CH_TRANSPORT_PARAMS_MAX`, `CH_QUIC_RETRY_TAG_LEN`,
`CH_KEY_UPDATE_RUN_MAX` and the rest. The API's types use them and rename
none.

## Sizes

`record` and `quic` are the translated `c.ch_tcp` and `c.ch_quic`,
held by value. `ch_build_matches` compares `@sizeOf(c.ch_tcp)`,
`@sizeOf(c.ch_quic)`, `@sizeOf(c.ch_tls)`, `@sizeOf(c.ch_cfg)` and
`@sizeOf(c.ch_ticket)` with the object's record, so `build_matches`
covers the C part of every session and every `Ticket`. The rest, the
receive buffer, the hook, the `std.Random` under `RAND=session`, `io` and
the ticket's identity bytes, is Zig's alone: C writes the receive buffer
through `cfg.buf`, and passes `cfg.io`, the hook's address, and
`cfg.rand_io`, the `std.Random`'s, to the API's callbacks unread.

## How it is checked

`make lint-zig-build` runs `test/zig-build-check.sh`, which builds
`test/zig-consumer` against the default object, colibri's four objects,
stompy's (`TX_RECORD=16384`), a tcp-nonblocking `ROLE=both` object under
`SUITE=aesgcm` and colibri's QUIC object holding both widening multiplies,
each through the module alone (INV-36):

- `matches.zig` requires `chapulin.c` to declare every export, to
  declare no `ch_` function the object neither exports nor imports (`nm
  -u` lists the imports, the hooks), and the build record to match,
  directly and through `build_matches`. The second rule costs no time
  the check can measure: with it and without it, a recompile of
  `matches.zig` took 1.8 to 2.4 s and a warm run of the script 4.6 to
  5.8 s on an M-series Mac at a load average near 20. build.zig
  translates three headers only for an object that exports a call of
  theirs. These are `x509_ca.h` for `ch_pubkey_from_pem`, `pem_files.h`
  for one of its three calls, and `drbg.h` for `ch_drbg_seed`. A C
  program of any object can include each one. So where `chapulin.c`
  leaves one out, the script translates it with `zig translate-c` under
  the same defines and holds the result to the second rule.
- `unit.zig`, the API's unit tests: each value's `ch_cfg`, through
  `chapulin.testing`, against the `ch_cfg` written out field by field,
  each list's C entries and the first list over each cap, the Ticket constructors and their
  bounds, the error of every code, and every declaration the object has,
  compiled. Under `RAND=session`, a client refused at init without a
  `random`, and one whose ClientHello random is the second fill of the
  `std.Random` it was given. For each PEM value the object has, a
  refused file is `error.Invalid`. A DER room one byte short and a slice
  of no entry are refused too. A refused key is zero, and `wipe()` zeroes
  the scalar.
- `loop.zig`, for each ROLE=both object: a client and a server of that
  object against each other. They use the r2 chain, its root_p384
  anchor, its clock and its leaf key, the fixture the C loop tests use.
  The chain, the key and the anchor are decoded through `Chain`,
  `EcdsaP256Key` and `Anchors` from the PEM files of
  `test/pem_fixtures.h`. The key file holds an EC PARAMETERS block above
  the key, as `openssl ecparam -genkey` writes it. Each value is held
  equal to `test/webpki_corpus.h`'s before a session uses it. In a tcp-nonblocking session:
  - a handshake that selects ALPN `http/1.1` and X25519MLKEM768 and
    reports the server name;
  - a write of three `CH_TX_PT` records and 100 bytes each way;
  - a write one byte past `writable_len` refused whole;
  - two h2 DATA frames, each a 9-byte header and a payload one byte
    longer than a record, through `write_parts`: four records that the
    server reads as the parts joined, and a call one byte short refused
    whole;
  - the exporter on both sides;
  - the ticket taken, rebuilt through `Ticket.from_fields` and resumed;
  - a ticket at exactly its lifetime offered and one millisecond past it
    refused;
  - a client with `takes_tickets` false, first with no ticket and then
    with the ticket taken above, which still resumes. Each time it keeps
    no ticket that the server writes, and its `take_ticket` returns null.
    Its session holds no `on_ticket`. Under TRUST=webpki its
    `ch_tls.takes_tickets` is 0 and its stored configuration hash is all
    zero. The client with the default holds 1 and a hash that is not
    zero. The Zig object exports no hash call to count, so the loop reads
    those fields. `bin/webpki_session_test` counts the calls in C;
  - a close in each direction;
  - four refusals: an impostor anchor, a clock that answers 0, a server
    output one byte short of its flight, and a record header no peer may
    send;
  - `alert_sent` after the first and the last refusal, and the server
    reading the alert each one sent as the client's fatal alert:
    `alert_received` names it and the server sends nothing back;
  - each side's handshake failure on each side of its write key: a
    client that refuses the ServerHello in the clear and a Certificate
    sealed, whose alert `record_out` returns once, and a server that
    refuses a first message in the clear and a client Finished sealed,
    whose alert `output_len` counts. The other side reads each one as its
    peer's fatal alert and sends nothing back;
  - under `SUITE=aesgcm`, each side's write across its AES-GCM write
    key's ceiling (docs/decisions.md 78), under each AES-GCM suite in
    turn (`loop_key_limit.zig`). No call sets a sequence number, so the
    test writes the writer's write sequence number and the reader's read
    sequence number, two records below the ceiling, into `record.t`.
    `writable_len` counts the KeyUpdate record to the byte for the record
    that crosses the ceiling and for none before it. One write across it
    seals exactly one 27-byte KeyUpdate record among its records and
    counts it, and one byte less of `output` is refused whole. The reader
    reads the plaintext on both sides of the KeyUpdate and sends nothing,
    neither side reports an alert, and the next write goes out under the
    next key;
  - in every object, one KeyUpdate past a run of `CH_KEY_UPDATE_RUN_MAX`
    (docs/decisions.md 138), which the server's `read` refuses with
    `error.KeyUpdateLimit`, and `alert_sent` names unexpected_message
    (`loop_key_update_run.zig`). The server reads each KeyUpdate in a call
    of its own. No call sends a KeyUpdate alone, so the test sets the
    client's `key_update_owed` before each write of one byte. It hands
    the server the KeyUpdate record and drops the data record, which
    would end the run. Then it moves the server's read sequence number
    past the dropped record.

  Over QUIC:
  - a handshake at each level, with `keys_ready` checked at each step;
  - the transport parameters each side received;
  - one packet each way, and a tampered one discarded;
  - a key update, the Retry tag and a Retry token, which is `.invalid`
    under the other version;
  - the ticket resumed, and the stale ticket refused with no alert
    chosen;
  - a client with `takes_tickets` false, checked as in a tcp-nonblocking session;
  - a server whose `choose_version` answers version 2 from its hook's
    context, once, a client that switches to it, and the packets and the
    key update in version 2;
  - that connection's ticket, which records version 2, refused in a
    version 1 connection and resumed in a version 2 one;
  - under `KEYLOG=on`, `hook_context` finding the client's context.
- `pair.zig` starts a client on each of colibri's two objects in one
  image, and computes a ticket's age through each object's call.

check-slow runs the script over every lib-check build's configuration as
well, among them `RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking
ROLE=both`, whose `loop.zig` runs the tcp-nonblocking steps above with a
seeded `std.Random` per side, and whose program defines no
`ch_rand_bytes`, so its link shows the object imports none.

Both runs also build colibri's HTTP/2 object with `build.zig` alone for
`x86_64-linux-gnu` at `-Dcpu=baseline`, a CPU without AVX-512, on every
machine, and require only that the build succeeds: make builds only for
its own compiler's target, so nothing compares the object. On an arm64
machine it is the one build that needs the evex512 feature above, and
`inv36-zig-x86-64-host-drops-evex512`, which takes the feature off,
fails it.

Seventeen mutants in `test/violations/` break the API, the module, the
public headers or the reverse check in `matches.zig`, and the script
catches each. INV-36 names them. The script also catches
`inv38-zig-writable-len-skips-key-update`, which stops `ch_writable_len`
counting the KeyUpdate record (INV-38): the `SUITE=aesgcm` loop's
`writable_len` rows fail.
