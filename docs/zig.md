# The Zig API

A Zig program runs chapulin's record-mode and QUIC sessions through Zig
values, Zig errors and session types it places in its own memory. It
never builds a `ch_cfg` or writes a C callback. The API is three files at
the repository root, `chapulin.zig`, `chapulin_record.zig` and
`chapulin_quic.zig`, and it is chapulin.hpp's kind of wrapper: each call
forwards to the C call of the same name. It adds four things and no
more:

- values a session is configured from, and the `ch_cfg` each one sets;
- one Zig error per result code;
- the callbacks C calls, which copy bytes between the caller's slices and
  the session;
- storage: the receive buffer, the latest ticket, the peer's transport
  parameters and, under `RAND=session`, the session's `std.Random`.

Every TLS rule stays in C. Where a caller needs a record length, a write
size or a ticket's age, the API calls the C function that computes it
(docs/decisions.md 72 and 73).

## Adding the dependency

Zig 0.16.0. The package's options are the Makefile's variables
(docs/building.md):

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
    if (!chapulin.buildMatches()) return error.WrongObject;
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
`std.Random` its values carry (Random bytes, below).

### Two objects in one program

colibri links a tcp-nonblocking object and a QUIC object into one image.
Each is a dependency of its own, imported under a name of its own:

```zig
const h2 = b.dependency("chapulin", .{ .target = target, .RAND = .@"extern", .TRANSPORT = .@"tcp-nonblocking", .ROLE = .both, .TRUST = .webpki, .EXPORTER = .on });
const quic = b.dependency("chapulin", .{ .target = target, .RAND = .@"extern", .TRANSPORT = .@"quic-nonblocking", .ROLE = .both, .TRUST = .webpki, .SUITE = .aesgcm, .AES = .hw, .KEYLOG = .on, .CH_NATIVE_AES = true });
module.addImport("chapulin_h2", h2.module("chapulin"));
module.addImport("chapulin_quic", quic.module("chapulin"));
```

The two modules' types are distinct: `chapulin_h2.Client` is not
`chapulin_quic.Client`. Only types Zig compares by structure, such as
byte slices, arrays and integers, pass between them. A program that
serves both keeps values of its own and converts them once per object.

Zig refuses one file in two modules of one program. So `build.zig`
copies the three files into a directory of each configuration's own,
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
| `Client` | a client role: its transport's client entry point, `ch_connect`, `ch_record_init` or `ch_quic_init` |
| `Server`, `EcdsaP256Identity`, `RsaPssIdentity`, `cert` | a server role (`ch_cfg.srv`) |
| `record.Client` | `ch_record_init` |
| `record.Server` | `ch_srv_record_init` |
| `record.alert_record_len`, `record.key_update_record_len` | `ch_record_whole_len` |
| `quic.Client` | `ch_quic_init` |
| `quic.Server`, `quic.retryTag`, `quic.tokenMint`, `quic.tokenCheck`, `quic.TokenCheck`, `quic.ChooseVersion` | `ch_srv_quic_init` |
| `quic.Level`, `quic.Direction`, `quic.KeySet`, `quic.level_count` | `ch_quic_initial_keys` |
| `Trust.web_pki`, `Trust.pins`, `trustAnchor`, `CertType`, `serverCertType` | `ch_cfg.anchors` (TRUST=webpki) |
| `Trust.pinned` | no `ch_cfg.anchors` |
| `Client.alpn`, `alpnProtocol`, `alpnSelected` | `ch_cfg.alpn_protocols` |
| `Client.random` and `Server.random` other than `void`, and `RandomSource` other than `void` | `ch_cfg.rand_bytes` (RAND=session) |
| `Server.cipher_suites` | `ch_srv_cfg.cipher_suites` (SUITE=aesgcm) |
| `Server.choose_version` other than `void` | `ch_srv_cfg.choose_version` (a QUIC server role) |
| `Client.cipher_suites` | `ch_cfg.cipher_suites` (SUITE=aesgcm TRUST=webpki) |
| `suite` | `ch_tls.suite` |
| `exportKeyingMaterial` | `ch_export` (EXPORTER=on) |
| `hookContext` | `ch_keylog` (KEYLOG=on) |
| `Error.Discard`, `Error.AeadLimit` | `CH_QUIC_DISCARD` (a QUIC object) |
| a record session's `keyUpdate` | never: the name is reserved |

Each public header declares a call only under the defines of the
objects that define it, so `@hasDecl(chapulin.c, name)` answers whether
the object has that call, and a program that calls one the object lacks
fails to compile rather than to link. `matches.zig` holds that rule for
every configuration the check builds, and the script holds it for
`x509_ca.h` and `drbg.h` where `chapulin.c` is not translated from them
(How it is checked). `Trust` is declared in every object; its variants
are the trust mode's. A value field an object lacks has type `void`, so
a literal that sets it does not compile.

## Values

Every slice and pointer in a value is borrowed and must outlive the
session, as `ch_cfg`'s pointers must (`cfg.h`, `srv_cfg.h`). The session
keeps a copy of the `ch_cfg`, not of what it points at. List elements
are the C types, built by three helpers, so the API copies no list:

- `trustAnchor(subject, spki)`: a `c.ch_trust_anchor` from a root's
  subject Name and SubjectPublicKeyInfo, each the whole DER TLV;
- `alpnProtocol(name)`: a `c.ch_alpn_protocol`;
- `cert(der)`: a `c.ch_cert`, one certificate of a server's chain.

`SpkiPin` is `[SHA256_LEN]u8`, the SHA-256 of a DER SubjectPublicKeyInfo;
a slice of them is `ch_cfg.spki_pins` as it is.

### Trust

The client's trust, whose variants are the object's trust mode's:

| Variant | Field | `ch_cfg` fields |
|---|---|---|
| `web_pki` | `anchors` | `anchors`, `anchor_count` |
| | `server_name` | `hostname`, `hostname_len` |
| | `now_seconds` | `now_seconds` |
| | `pins`, empty by default | `spki_pins`, `spki_pin_count` |
| `pins` | `pins` | `spki_pins`, `spki_pin_count` |
| | `server_name`, optional | `hostname`, `hostname_len` |
| `pinned` | `server_pubkey` | `server_pubkey`, `server_pubkey_len` |
| | `server_pubkey2`, optional | `server_pubkey2`, `server_pubkey2_len` |

`webpki_cfg.h` and `cfg.h` state each field's rules, and `init` answers
`error.Invalid` for a value C refuses.

### Client

| Field | `ch_cfg` fields |
|---|---|
| `trust` | the fields `Trust` names |
| `alpn`, empty by default | `alpn_protocols`, `alpn_count` |
| `ticket`, null by default | `psk`, `psk_len`, `psk_id`, `psk_id_len`, `resumption = 1`, `ticket_epoch`, `ticket_lifetime_s`, and `ticket_binding` under TRUST=webpki |
| `ticket_age_ms`, 0 by default | `ticket_age_ms`, and `obfuscated_age` from `c.ch_ticket_obfuscated_age(&ticket.ticket, ticket_age_ms)` |
| `require_pq`, false by default | `require_pq` |
| `quic_version`, null by default, `TRANSPORT=quic-nonblocking` alone | `quic_original_version`, the version's code, or 0 for null, which `init` refuses |
| `cipher_suites`, empty for the build's order, SUITE=aesgcm TRUST=webpki alone | `cipher_suites`, `cipher_suite_count` |
| `random`, null by default, `RAND=session` alone | `rand_bytes` and `rand_io`, through the session's own copy |

`toCfg()` returns that `ch_cfg`, and a session's `init` adds its buffer,
callbacks and `io` to it, and under `RAND=session` its source. With a
ticket, a raw or ca mode's `toCfg` leaves the two `server_pubkey` slots
unset, because `ch_cfg` takes one auth mode. The age is the time since `on_ticket` handed the ticket over,
in milliseconds. C refuses a ticket older than its lifetime or older than
seven days (`ticket.h`, RFC 9846 §4.3.11.1 and §4.6.1), so `init`
answers `error.Invalid` for it: an age of exactly the lifetime is still
offered, and one millisecond more is refused.

### Ticket

A NewSessionTicket (RFC 9846 §4.6.1) that outlives its session: the
`c.ch_ticket` `on_ticket` received, by value, as `ticket`, and the
identity bytes it pointed at, as `identity`. `ticket.identity` is null,
because the bytes it named are valid during `on_ticket` alone.
`ch_ticket_obfuscated_age` reads `age_add` alone, so a copy serves.

- `takeTicket()` on a client session moves the latest ticket out.
- `Ticket.fromFields(.{ .identity, .psk, .age_add, .lifetime_s, .epoch,
  .binding })` rebuilds one from fields a program stored. It refuses an
  identity longer than `CH_TICKET_ID_MAX` and a psk that is not
  `SHA256_LEN` or, in an object whose `HKDF_HASH_MAX` is `SHA384_LEN`,
  that length. `binding` is a field under TRUST=webpki alone.
- `Ticket.fromOnTicket(ticket)` copies what `on_ticket` hands over, for a
  program that writes its own `on_ticket`. It answers null for an
  identity longer than `CH_TICKET_ID_MAX`, which C drops before
  `on_ticket`.

A program that copies a Ticket owns zeroing that copy. C never hands
over a ticket whose lifetime is 0, so `takeTicket` never returns one.

A ticket one object received may be offered through another object of
the same program. A TRUST=webpki client binds a ticket to the hostname,
the anchors and the SPKI pins (`webpki_ticket.h`), not to the transport
or the ALPN protocol. A chapulin server passes over a ticket whose ALPN
protocol is not the connection's (`srv_resume.c`), and the resuming
hello still offers the certificate path, so that costs a full handshake
(docs/decisions.md 55).

### Server

| Field | `ch_cfg` fields |
|---|---|
| `ecdsa_p256`, null by default | `srv.ecdsa_p256`: `chain`, `chain_count`, `priv`, `priv_len = 32`, `pub`, `pub_len = 64` |
| `rsa_pss`, null by default | `srv.rsa_pss`: `chain`, `chain_count`, `priv`, `priv_len = @sizeOf(c.ch_rsa_priv)`, `pub`, `pub_len` |
| `cookie_key` | `srv.cookie_key` |
| `ticket_key`, null for no tickets | `srv.ticket_key` |
| `now_seconds`, 0 for no clock | `srv.now_seconds` |
| `alpn`, empty by default | `alpn_protocols`, `alpn_count` |
| `require_server_name` | `srv.require_server_name` |
| `cipher_suites`, empty for the default order | `srv.cipher_suites`, `srv.cipher_suite_count` |
| `quic_version`, null by default, `TRANSPORT=quic-nonblocking` alone | `quic_original_version`, as for a client: the Version field of the client's first Initial packet |
| `choose_version`, null by default, `TRANSPORT=quic-nonblocking` alone | none in `toCfg`: the session's `init` points `srv.choose_version` at its own adapter, which calls this `quic.ChooseVersion` with the session's `hook.context`. null keeps the original version |
| `random`, null by default, `RAND=session` alone | `rand_bytes` and `rand_io`, as for a client |

`EcdsaP256Identity` takes the chain, the leaf's point X||Y as
`*const [64]u8` and the private scalar as `*const [32]u8`.
`RsaPssIdentity` takes the chain, the modulus and a
`*const c.ch_rsa_priv`. `toCfg()` answers `error.Invalid` for a chain
longer than `chain_count`'s `u8` holds, and `check()` runs
`ch_srv_check`: each provisioned key signs, and the signature verifies.
It takes no session.

### Random bytes

Under `RAND=session` each session draws from the source its own values
name (`rand.h`, docs/entropy.md). `Client.random` and `Server.random`
are `?std.Random`, null by default; in any other build they are `void`,
and the sessions draw from the image's `ch_rand_bytes`.

- **The session stores it.** `init` copies the `std.Random` into the
  session's `random` field, a `RandomSource`, and `attachRandom` points
  `ch_cfg.rand_io` at that copy and `ch_cfg.rand_bytes` at an adapter
  that fills each draw's `out[0..n]` from it. The copy lives as long as
  the session, which must not move after `init`.
- **A value without one is refused at init.** A null `random` leaves
  `rand_bytes` NULL, C answers `CH_EINVAL`, and `init` returns
  `error.Invalid` with nothing sent. The refusal is C's, like every other
  configuration rule. A Zig field's default cannot depend on the build,
  so a field that is required here and absent elsewhere would need a
  second copy of each value struct.
- **`Server.check`** holds the value for its one call: the RSA-PSS
  signature it makes draws its salt from it.
- **The source.** In production it is a CSPRNG, such as
  `std.crypto.random`. A deterministic stream gives predictable keys to
  anyone who knows its seed, so a seeded `std.Random.DefaultPrng` per
  session, which replays a connection byte for byte, is for tests.
- **Threads.** A session draws from its own source alone, so sessions on
  different threads share no entropy state in chapulin and need no lock
  around its draws.

### Codes and reports

- `Group`: `ch_tls.group`'s code points, `x25519`, `x25519mlkem768`,
  `secp256r1`.
- `Suite`: `ch_tls.suite`'s, `cipher_suites`' and `srv.cipher_suites`' code points.
- `State`: `start`, `connected`, `closed`, `failed`.
- `CertType`: `x509`, `raw_public_key`.
- `buildMatches()`: `ch_build_matches` over the object's own record,
  `ch_build_info_<transport>`. A test that checks a changed record calls
  `chapulin.c.ch_build_matches` with its own.
- `Hook`: what `ch_cfg.io` points at in every session. Its `context` is
  the caller's. A session's `init` sets it to null, and the caller writes
  `session.hook.context` after `init`.
- `hookContext(io)`: the caller's context from the `io` argument
  `ch_keylog` receives. The API owns `cfg.io`, and this is how the
  image's `ch_keylog` finds the connection it logs for.

## Errors

One Zig error per result code, named as chapulin.hpp's `Status` names
it. Each call's error set is the part of `chapulin.Error` its C call
returns.

| C code | Zig | The session after it |
|---|---|---|
| `CH_EIO` | `error.Io` | Dead. An output slice could not take what C sent. |
| `CH_EPROTO` | `error.Proto` | Dead after a protocol failure, and after the peer's fatal alert, which `alertReceived` names. As it was for bytes delivered to a session that failed or closed, and for `read` or `write` before the handshake completed, which keeps running. |
| `CH_EAUTH` | `error.Auth` | Dead. |
| `CH_ECAP` | `error.Cap` | Live from `recordOut`, `cryptoOut`, `seal`, `sealClose` and `tokenMint`: the caller's buffer was short. Dead from `recordIn`, `cryptoIn` and `read`: the peer's message could never fit. |
| `CH_EINVAL` | `error.Invalid` | Nothing was sent. From `init`, failed until the next `init`: C refused the configuration, a stale ticket or a server identity its flight could not use among the refusals. From any other call, as it was: the call came out of order or an argument was refused. A server's `recordIn` never returns it, and its `cryptoIn` returns it only for a level the call refuses on entry. |
| `CH_QUIC_DISCARD` | `error.Discard` | Live. The caller drops the packet. |
| `CH_QUIC_AEAD_LIMIT` | `error.AeadLimit` | Dead. |
| `CH_RECORD_AGAIN` | none | `read` returns `pt_len = 0`. |
| `CH_ECLOSED` | none | No call returns it. |

`write`'s `error.Cap` has two sources: the API's own refusal of a `pt`
longer than `writableLen(output.len)`, which seals nothing and leaves
the session as it was, and C's, when a record cannot be sealed, which
leaves it dead. `tokenCheck` answers `CH_EPROTO` and `CH_EAUTH` as the
values `.not_retry` and `.invalid`, because they judge a token, not a
session.

`fromCode(E, code)` is the mapping every call uses: nothing for
`CH_OK`, and otherwise the error of `E` that the code stands for. A code
`E` does not name is one the call's header says it never returns, and it
panics. A program that calls a C function the API leaves out maps its
result with `fromCode(chapulin.Error, code)`.

## Record-mode sessions

`TRANSPORT=tcp-nonblocking`. `record.Client(receive_len)` and
`record.Server(receive_len)` are types whose size is known at compile
time, so a program places a session in a static, in a connection struct
or on the stack, with no allocation. Each holds the C session, `record`,
the receive buffer `cfg.buf`, `receive`, the `hook`, the source `random`
under `RAND=session`, the slices the callbacks copy between during one
call, `io`, and, on the client, the latest ticket. Do not move a session
after `init`: `cfg.io` points at its hook, and `cfg.rand_io` at its
`random`. colibri sizes both at 20,480 bytes.

| Zig call | C call | Errors |
|---|---|---|
| `Client.init(values)` | `Client.toCfg`, then `ch_record_init` with the API's `send`, `recv` and `on_ticket`, and under `RAND=session` the values' `random` | Invalid |
| `Client.recordOut(output)` | `ch_record_out`; after a failed `recordIn`, the failure's alert record, then `error.Invalid` | Invalid, Cap |
| `Client.recordIn(input)` | `ch_record_in`; returns the bytes consumed | Invalid, Proto, Auth, Cap |
| `Client.takeTicket()` | none: moves the slot out and zeroes it | none |
| `Server.init(values, sni_buf)` | `Server.toCfg`, then `ch_srv_record_init` with the API's `send`, `recv` and `on_record_out`, and under `RAND=session` the values' `random`; `sni_buf` is `srv.sni_buf` and `srv.sni_cap` | Invalid |
| `Server.recordIn(input, output)` | `ch_srv_record_in`, whose flight goes into `output`; returns `Progress{ consumed, written }` | Proto, Auth, Cap, Io |
| `Server.outputLen()` | the bytes the last `recordIn` wrote into `output`, which a failed `recordIn` also sets: `Progress.written` on success | none |
| `Server.sni()` | `sni_buf[0..ch_tls.sni_len]`, null when 0 | none |
| `recordState()` | `ch_record_state` | none |
| `alertSent()`, `alertReceived()` | `ch_alert_sent`, `ch_alert_received` on `record.t` (alert.h); each null when 0 | none |
| `read(input, pt, reply)` | `ch_record_whole_len`, then `ch_read` | Invalid, Proto, Auth, Cap, Io |
| `write(pt, output)` | `ch_writable_len`, then `ch_write` | Proto, Cap, Io |
| `writableLen(cap)` | `ch_writable_len` | none |
| `close(output)` | `ch_close` | Io |
| `recordClose()` | `ch_record_close`, then the ticket slot zeroed | none |
| `exportKeyingMaterial(label, context, out)` | `ch_export` | Invalid |
| `alpnSelected()` | the name `ch_tls.alpn_selected` indexes; null for `CH_ALPN_NONE` | none |
| `group()`, `suite()` | `ch_tls.group`, `ch_tls.suite`; null while 0 | none |
| `pskSelected()`, `serverCertType()`, `peerLimit()`, `readClosed()` | the `ch_tls` fields of those names | none |
| `replyLen()` | the bytes the last `read` wrote into `reply`, which a failed read also sets | none |

A client in an object without SUITE=aesgcm offers ChaCha20 alone and
writes no `ch_tls.suite`, so its `suite()` stays null. A SUITE=aesgcm
TRUST=webpki client offers three, in the order `Client.cipher_suites`
names or, when it is empty, in the build's order: AES-256-GCM first in an
object built `AES=hw` with `CH_NATIVE_AES`, and ChaCha20 first in any
other (docs/decisions.md 80). The API probes no CPU; a program that
probes its own passes the order it chose.

A record session's `keyUpdate` is reserved: no C call starts a
record-mode KeyUpdate, so it is a `@compileError` that says so. `write`
sends one inside `ch_write` as the last record an AES-GCM write key
seals, and `read` answers the peer's KeyUpdate inside `ch_read`, so no
such call is planned (docs/decisions.md 78).

### A handshake

```zig
var client: chapulin.record.Client(20_480) = undefined;
const anchors = [_]chapulin.c.ch_trust_anchor{chapulin.trustAnchor(root_name, root_spki)};
const alpn = [_]chapulin.c.ch_alpn_protocol{chapulin.alpnProtocol("http/1.1")};

try client.init(.{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "s3.example.test", .now_seconds = now } },
    .alpn = &alpn,
});
send(output[0..try client.recordOut(&output)]); // the ClientHello
// each time bytes arrive, until recordState() is .connected:
const consumed = try client.recordIn(input);
send(output[0..try client.recordOut(&output)]);
```

`recordIn` takes whole records and leaves a trailing partial record for
the caller to present again, unchanged, with more bytes after it. A
server's `recordIn` writes its whole flight into `output`, one record at
a time, and answers `error.Io` when `output` cannot take one; the
session is then dead.

When `recordIn` fails, the side that failed has one alert record for
the caller to send before it closes the connection. A client's
`recordOut` returns it, all of it when `output` holds it, and then
`error.Invalid`. A server's `recordIn` has already written it into
`output`, after the records of the flight that went out before the
failure, and `outputLen()` counts them all, because the error returns no
`Progress`. The record is in the clear before the failing side's write
key is installed, 7 bytes, and sealed after, `alert_record_len` bytes: a
client installs its key right after the ServerHello and a server right
after it has sent its own (tcp_nonblocking.h). `alertSent` names the
alert. A `recordIn` that fails on the peer's fatal alert has nothing to
send (RFC 9846 §6.2): `recordOut` answers `error.Invalid` at once, and
`outputLen()` counts only the records written before that alert.

```zig
const progress = server.recordIn(input, &output) catch |err| {
    send(output[0..server.outputLen()]); // the flight so far, then the alert
    return err;
};
```

### Reading

`read` passes at most one whole record of `input` to `ch_read`:
`ch_record_whole_len` says how many bytes that is, and `ch_read` reads
them through the API's `recv`. The `Read` it returns says:

- `consumed`: input bytes taken. 0 while `input` holds less than a
  record; one whole record; or the 5-byte header of a record whose
  length field is above 2^14 + 256, which `ch_read` refuses with
  `error.Proto`.
- `pt_len`: plaintext written into `pt`. 0 when the record held a
  ticket or a KeyUpdate. Plaintext `pt` cannot hold stays in the receive
  buffer, and the next `read` returns it and takes no input.
- `reply_len`: bytes `ch_read` sent into `reply`.
- `peer_closed`: `ch_read` returned 0, because the peer's close_notify
  arrived, now or earlier, or because this side closed.

A caller calls `read` until `consumed` and `pt_len` are both 0. An error
reports no `Read`. It leaves the session dead, except `error.Invalid`
for an empty `pt` and `error.Proto` for a session that is not
connected, which change nothing.

`reply` takes what `ch_read` sends. It answers a KeyUpdate in the record
that asks for an answer (RFC 9846 §4.7.3) with one sealed KeyUpdate
record of `key_update_record_len`, 27 bytes. A record carries at most one
KeyUpdate, as its last message: RFC 9846 §5.1 lets no handshake message
span the key change a KeyUpdate makes, so `ch_read` refuses a record
with bytes after one (INV-39). A read that fails adds one alert record
of `alert_record_len`, 24 bytes, and `alertSent` names its alert. A read
that fails on the peer's fatal alert adds nothing, because RFC 9846 §6.2
has both sides close at once, and `alertReceived` names the peer's
alert. So a `reply` of
`key_update_record_len + alert_record_len` bytes is never short. A
`reply` too short for what `ch_read` sends fails the read with
`error.Io` and the session with it.

### Writing and closing

`write` seals all of `pt` into `output` and returns the bytes written.
When `pt.len > writableLen(output.len)` it seals nothing and returns
`error.Cap`, and the session is as it was, so a caller that seals one
message at a time sizes `output` once and never loops. `ch_write` cuts
records of the smaller of `CH_TX_PT` and `peerLimit()`, and
`ch_writable_len` counts in the same limit, so a caller needs neither
number to size a write. At `TX_RECORD=16384` a record carries 16,384
bytes; the API adds nothing for it. Under `SUITE=aesgcm`, a write that
takes an AES-GCM write key to its ceiling carries one KeyUpdate record
among its records, `key_update_record_len` bytes, and `writableLen`
counts it. A caller that sizes `output` for its largest message adds
`key_update_record_len` bytes there, or the write that crosses the
ceiling returns `error.Cap` with nothing sealed.

`close(output)` sends this side's close_notify into `output`, at most
`alert_record_len` bytes, and wipes the session's keys: that is
`ch_close`. It answers `error.Io` when `output` could not take the alert,
and the session is closed either way. The peer's close_notify closes the
peer's direction alone (RFC 9846 §6.1): `read` reports `peer_closed`,
`readClosed()` is true, and `write` still sends until this side calls
`close`. A side that called `close` reads nothing more.

`recordClose()` calls `ch_record_close`, which wipes every secret and
marks the session dead, and then zeroes the ticket slot. A connected
caller calls `close` first.

### Secrets the API holds

The ticket slot holds a resumption PSK. `takeTicket` returns the ticket
and zeroes the slot with `std.crypto.secureZero`, and `recordClose` and
the QUIC `close` zero it too, after the C call has wiped the session's
keys. `on_ticket` zeroes the slot before it copies a newer ticket in, and
each init zeroes it before the C init call.

## QUIC sessions

`TRANSPORT=quic-nonblocking`. The types:

- `Level`: `initial`, `handshake`, `application`, and `level_count`.
- `Direction`: `read`, `write`.
- `KeySet`: `previous`, `current`, `next`, the 1-RTT receive set `open`
  reports.
- `Outgoing`: where a server's `cryptoIn` writes the CRYPTO bytes it
  produces, one buffer per level, and `written`, which `cryptoIn` adds
  to and never resets.
- `Opened`: `pn`, `pt_len` and `key_set`.
- `Version`: `v1` and `v2`, the Version field values `quic_cfg.h` names,
  and any other `u32`, which C refuses where it derives no keys.
- `ChooseVersion`: `*const fn (context: ?*anyopaque) Version`, a server's
  choice of the negotiated version (`srv_cfg.h`). The session's adapter
  calls it once per connection with its `hook.context`, after
  `peerTransportParams` holds the client's transport parameters and
  before anything is selected or sent, and C fails the session with
  `error.Io` for a version it does not derive.
- `TokenCheck`: `.retry` with the connection IDs the token carried,
  `.not_retry` or `.invalid`.

`quic.Client(receive_len)` and `quic.Server(receive_len)` hold the C
session, `quic`, the receive buffer, the hook, under `RAND=session` the
source `random`, the caller's `peer_params` slice, the length of what
arrived there, the client's ticket slot and the server's current
`Outgoing`. colibri passes a
`peer_params` of 1,024 bytes and a `sni_buf` of 255.

| Zig call | C call | Errors |
|---|---|---|
| `Client.init(values, transport_params, peer_params)` | `Client.toCfg`, then `ch_quic_init` with the API's `on_level_ready`, `on_transport_params` and `on_ticket`, and under `RAND=session` the values' `random` | Invalid |
| `Server.init(values, transport_params, peer_params, sni_buf)` | `Server.toCfg`, then `ch_srv_quic_init` with the API's `on_level_ready`, `on_transport_params`, `srv.on_crypto_out` and, when the values carry a `choose_version`, `srv.choose_version`, and under `RAND=session` the values' `random` | Invalid |
| `initialKeys(dcid)` | `ch_quic_initial_keys` | Invalid |
| `Client.cryptoIn(level, bytes)` | `ch_quic_crypto_in` | Invalid (live), Proto, Auth, Cap |
| `Client.cryptoOut(level, out)` | `ch_quic_crypto_out` | Invalid, Cap (live) |
| `Server.cryptoIn(level, bytes, outgoing)` | `ch_srv_quic_crypto_in` | Invalid (live), Proto, Auth, Cap, Io |
| `Client.takeTicket()`, `Server.sni()` | as in record mode | none |
| `keysReady(level, direction)` | the bit `CH_QUIC_LEVEL_BIT` names in `ch_quic.levels_ready` | none |
| `peerTransportParams()` | the body `on_transport_params` copied, null before it arrives | Cap, when it was longer than `peer_params` |
| `seal(level, version, pn, pn_len, hdr, pt, out)`, `sealClose(...)` | `ch_quic_seal`, `ch_quic_seal_close`; return the packet's length | Invalid, Cap |
| `open(level, version, pkt, pn_off, largest_pn, current_phase_lowest_pn)` | `ch_quic_open`, in place | Invalid, Discard, AeadLimit |
| `retryOk(version, pseudo, tag)` | `ch_quic_retry_ok` | none |
| `Client.switchVersion(version)` | `ch_quic_switch_version` | Invalid |
| `negotiatedVersion()` | `ch_quic_negotiated_version` | none |
| `keyUpdate()`, `keyPhase()`, `dropPreviousKeys()`, `discard(level)` | `ch_quic_key_update`, `ch_quic_key_phase`, `ch_quic_drop_previous_keys`, `ch_quic_discard` | Invalid for `keyUpdate` and `discard` |
| `state()`, `alert()`, `errorCode()` | `ch_quic_state`, `ch_quic_alert`, `ch_quic_error_code` | none |
| `alertSent()`, `alertReceived()` | `ch_alert_sent`, `ch_alert_received` on `quic.t` (alert.h): `alertSent` answers what `alert` answers, and `alertReceived` is null, because QUIC carries no alert record | none |
| `close()` | `ch_quic_close`, then the ticket slot zeroed | none |
| `alpnSelected()`, `group()`, `suite()`, `pskSelected()`, `serverCertType()` | as in record mode | none |
| `quic.retryTag(version, pseudo, tag)` | `ch_srv_quic_retry_tag` | Invalid |
| `quic.tokenMint(key, address, cids, issued_seconds, out)` | `ch_srv_quic_token_mint`; returns the token's length | Invalid, Cap |
| `quic.tokenCheck(key, token, address, now_seconds, lifetime_seconds)` | `ch_srv_quic_token_check` | Invalid |

`seal`'s `error.Invalid` includes RFC 9001 §6.6's confidentiality limit:
once a key set has sealed its limit, `ch_quic_seal` refuses every later
packet under it until `keyUpdate` writes a new set (`quic.h`). A retry
does not clear it.

The server calls take no session, because a Retry comes before one (RFC
9000 §8.1.2).

### A handshake

```zig
var outgoing: chapulin.quic.Outgoing = .{ .buffers = .{ &initial_buf, &handshake_buf, &application_buf } };
try server.init(server_values, &server_params, &server_peer, &sni_buf);
try client.init(client_values, &client_params, &client_peer);
try client.initialKeys(dcid);
try server.initialKeys(dcid);

const hello = try client.cryptoOut(.initial, &message);
try server.cryptoIn(.initial, message[0..hello], &outgoing);
try client.cryptoIn(.initial, initial_buf[0..outgoing.written[0]]);
try client.cryptoIn(.handshake, handshake_buf[0..outgoing.written[1]]);
const finished = try client.cryptoOut(.handshake, &message);
try server.cryptoIn(.handshake, message[0..finished], &outgoing);
// client.state() and server.state() are .connected, and the server's
// ticket waits at the application level of outgoing.
```

A client calls `cryptoOut` at each level after `cryptoIn`, because
`ch_quic_crypto_in` refuses more bytes while a message is staged
(`quic.h`). `keysReady` answers which keys each step installed; no key
leaves the session, and the API's `on_level_ready` does nothing, because
`levels_ready` holds the same bits in the same call. Header protection
runs inside `seal` and `open`, as in C (RFC 9001 §9.5).

## What stays out

- **The blocking transport.** `ch_connect` and `ch_srv_accept` call
  `cfg.send` and `cfg.recv`, which block. A tcp-blocking object's module
  offers the values, `buildMatches`, `Server.check` and `chapulin.c`.
- **The image's hooks, the DRBG and CA provisioning.** `ch_rand_bytes`,
  `ch_assert_fail`, `ch_keylog`, `ch_aes_block`, `ch_drbg_seed` and
  `ch_pubkey_from_pem` stay the program's, through `chapulin.c`. Under
  `RAND=session` the API takes the source, as `Client.random` and
  `Server.random`, because it is a value of each session.
- **An external PSK, the CA epoch callbacks and `pin_slot`.** They serve
  device builds. Each is one `ch_cfg` or `ch_tls` field a later version
  can add.
- **A record-mode KeyUpdate the caller starts.** Reserved, above.
- **Alert names.** No public header declares the `ALERT_` constants, so
  `alert`, `alertSent` and `alertReceived` return the AlertDescription
  byte.
- **Private fields.** Zig has none, so a session's `record` or `quic`
  field is visible. The API promises nothing about them.

The constants a caller sizes storage by keep their C names in
`chapulin.c`: `CH_TX_PT`, `CH_TX_STAGE`, `CH_MIN_RXBUF`, `CH_ALPN_MAX`,
`CH_WEBPKI_ANCHOR_MAX`, `CH_SPKI_PIN_MAX`, `CH_TICKET_ID_MAX`,
`CH_SRV_COOKIE_KEY_LEN`, `CH_SRV_TICKET_KEY_LEN`, `CH_QUIC_TOKEN_KEY_LEN`,
`CH_QUIC_TOKEN_MAX`, `CH_TRANSPORT_PARAMS_MAX`, `GCM_TAG`, `SHA256_LEN`
and the rest. The API's types use them and rename none.

## Sizes

`record` and `quic` are the translated `c.ch_record` and `c.ch_quic`,
held by value. `ch_build_matches` compares `@sizeOf(c.ch_record)`,
`@sizeOf(c.ch_quic)`, `@sizeOf(c.ch_tls)`, `@sizeOf(c.ch_cfg)` and
`@sizeOf(c.ch_ticket)` with the object's record, so `buildMatches`
covers the C part of every session and every `Ticket`. The rest, the
receive buffer, the hook, the `std.Random` under `RAND=session`, `io` and
the ticket's identity bytes, is Zig's alone: C writes the receive buffer
through `cfg.buf`, and passes `cfg.io`, the hook's address, and
`cfg.rand_io`, the `std.Random`'s, to the API's callbacks unread.

## How it is checked

`make lint-zig-build` runs `test/zig-build-check.sh`, which builds
`test/zig-consumer` against the default object, colibri's four objects,
stompy's (`TX_RECORD=16384`) and a record-mode `ROLE=both` object under
`SUITE=aesgcm AES=hw`, each through the module alone (INV-36):

- `matches.zig` requires `chapulin.c` to declare every export, to
  declare no `ch_` function the object neither exports nor imports (`nm
  -u` lists the imports, the hooks), and the build record to match,
  directly and through `buildMatches`. The second rule costs no time
  the check can measure: with it and without it, a recompile of
  `matches.zig` took 1.8 to 2.4 s and a warm run of the script 4.6 to
  5.8 s on an M-series Mac at a load average near 20. build.zig
  translates `x509_ca.h` only for an object that exports
  `ch_pubkey_from_pem`, and `drbg.h` only for one that exports
  `ch_drbg_seed`, while a C program of any object can include either
  one. So where `chapulin.c` leaves one out, the script translates it
  with `zig translate-c` under the same defines and holds the result to
  the second rule.
- `unit.zig`, the API's unit tests: each value's `toCfg` against the
  `ch_cfg` written out field by field, the Ticket constructors and their
  bounds, the error of every code, and every declaration the object has,
  compiled. Under `RAND=session`, a client refused at init without a
  `random`, and one whose ClientHello random is the second fill of the
  `std.Random` it was given.
- `loop.zig`, for each ROLE=both object: a client and a server of that
  object against each other. They use the r2 chain, its root_p384
  anchor, its clock and its leaf key from `test/webpki_corpus.h`, the
  fixture the C loop tests use. In record mode:
  - a handshake that selects ALPN `http/1.1` and X25519MLKEM768 and
    reports the server name;
  - a write of three `CH_TX_PT` records and 100 bytes each way;
  - a write one byte past `writableLen` refused whole;
  - the exporter on both sides;
  - the ticket taken, rebuilt through `Ticket.fromFields` and resumed;
  - a ticket at exactly its lifetime offered and one millisecond past it
    refused;
  - a close in each direction;
  - four refusals: an impostor anchor, a clock of 0, a server output one
    byte short of its flight, and a record header no peer may send;
  - `alertSent` after the first and the last refusal, and the server
    reading the alert each one sent as the client's fatal alert:
    `alertReceived` names it and the server sends nothing back;
  - each side's handshake failure on each side of its write key: a
    client that refuses the ServerHello in the clear and a Certificate
    sealed, whose alert `recordOut` returns once, and a server that
    refuses a first message in the clear and a client Finished sealed,
    whose alert `outputLen` counts. The other side reads each one as its
    peer's fatal alert and sends nothing back;
  - under `SUITE=aesgcm`, each side's write across its AES-GCM write
    key's ceiling (docs/decisions.md 78), under each AES-GCM suite in
    turn (`loop_key_limit.zig`). No call sets a sequence number, so the
    test writes the writer's write sequence number and the reader's read
    sequence number, two records below the ceiling, into `record.t`.
    `writableLen` counts the KeyUpdate record to the byte for the record
    that crosses the ceiling and for none before it. One write across it
    seals exactly one 27-byte KeyUpdate record among its records and
    counts it, and one byte less of `output` is refused whole. The reader
    reads the plaintext on both sides of the KeyUpdate and sends nothing,
    neither side reports an alert, and the next write goes out under the
    next key.

  Over QUIC:
  - a handshake at each level, with `keysReady` checked at each step;
  - the transport parameters each side received;
  - one packet each way, and a tampered one discarded;
  - a key update, the Retry tag and a Retry token;
  - the ticket resumed, and the stale ticket refused with no alert
    chosen;
  - a server whose `choose_version` answers version 2 from its hook's
    context, once, a client that switches to it, and the packets and the
    key update in version 2;
  - under `KEYLOG=on`, `hookContext` finding the client's context.
- `pair.zig` starts a client on each of colibri's two objects in one
  image, and computes a ticket's age through each object's call, directly
  and through `Client.toCfg`.

check-slow runs the script over every lib-check leg's configuration as
well, among them `RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking
ROLE=both`, whose `loop.zig` runs the record-mode steps above with a
seeded `std.Random` per side, and whose program defines no
`ch_rand_bytes`, so its link shows the object imports none.

Twelve mutants in `test/violations/` break the API, the module, the
public headers or the reverse check in `matches.zig`, and the script
catches each. INV-36 names them. The script also catches
`inv38-zig-writable-len-skips-key-update`, which stops `ch_writable_len`
counting the KeyUpdate record (INV-38): the `SUITE=aesgcm` loop's
`writableLen` rows fail.
