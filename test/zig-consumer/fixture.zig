//! The server identity and the client trust both loops use: the r2 corpus
//! chain, its root_p384 anchor, its hostname and clock, and its leaf key,
//! all from test/webpki_corpus.h, the fixture test/webpki_loop_test.c and
//! test/quic_loop_webpki.h use through test/webpki_r2_chain.h. A raw-ecdsa
//! client pins the leaf's point instead of trusting the anchor.
//!
//! The chain, the key and the anchor the loops run on are decoded through
//! the API from the PEM files test/pem_fixtures.h holds, the files
//! test/gen_pem_fixtures.py wrote with openssl, and each is held equal to
//! webpki_corpus.h's before a session uses it.
const std = @import("std");
const chapulin = @import("chapulin");
const corpus = @import("corpus");
const pem = @import("pem");
const hooks = @import("hooks.zig");
const c = chapulin.c;

const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");
const has_quic = @hasField(c.ch_ticket, "quic_version");
const has_cpu = @hasField(c.ch_cfg, "cpu");

/// Under RAND=session, the streams each side's sessions draw from: one
/// seeded stream per side, so a failure replays exactly. A test fixture
/// and never a source a program ships: a deterministic stream gives
/// predictable keys (cfg.h), and a program passes std.crypto.random or a
/// CSPRNG of its own.
var client_stream = std.Random.DefaultPrng.init(0x11);
var server_stream = std.Random.DefaultPrng.init(0x22);

/// The value of Client.random: the client's stream under RAND=session, and
/// void in every other build.
pub fn clientRandom() if (has_rand_session) ?std.Random else void {
    return if (has_rand_session) client_stream.random() else {};
}

fn serverRandom() if (has_rand_session) ?std.Random else void {
    return if (has_rand_session) server_stream.random() else {};
}

/// The value of Client.cpu and Server.cpu: in a host object, the
/// probe's bit, the AES instructions, which the machines that run these
/// loops have and a SUITE=aesgcm loop runs its AES-GCM suites on, and the
/// statement that the multiply runs in constant time, which runs the
/// native copies, as a host test binary's CH_NATIVE_WIDEMUL does where no
/// secret is at risk (docs/decisions.md 89), and void in every other
/// build.
pub fn cpuAnswer() if (has_cpu) ?chapulin.Cpu else void {
    return if (has_cpu) .{ .constant_time_aes = true, .constant_time_multiply = true } else {};
}

/// Where every source of random bytes here stands: the image's byte
/// counter under RAND=extern, and each side's stream under RAND=session.
pub const Draws = struct { counter: u8, client: std.Random.DefaultPrng, server: std.Random.DefaultPrng };

pub fn draws() Draws {
    return .{ .counter = hooks.next, .client = client_stream, .server = server_stream };
}

/// Sets every source back to where draws found it, so a handshake started
/// again from fresh sessions draws the same bytes and sends the same
/// messages, of the same lengths.
pub fn rewind(to: Draws) void {
    hooks.next = to.counter;
    client_stream = to.client;
    server_stream = to.server;
}

/// The corpus row the chain comes from, whose verdict is "ok".
pub fn r2Row() *const corpus.webpki_corpus_chain {
    for (&corpus.webpki_corpus_chains) |*row| {
        if (std.mem.eql(u8, std.mem.span(row.name), "r2")) return row;
    }
    @panic("webpki_corpus.h has no r2 row");
}

pub fn hostname() []const u8 {
    return std.mem.span(r2Row().hostname);
}

/// The anchor that carries the root's Name over another key.
const anchors = if (has_webpki) struct {
    const impostor = [_]c.ch_trust_anchor{chapulin.trustAnchor(&corpus.webpki_corpus_name_root_p384, &corpus.webpki_corpus_spki_impostor_p384)};
} else struct {};

/// The values decoded from the PEM files, once, and the rooms they point
/// into, kept where the sessions point at them. Each room is sized from
/// its file, as a program sizes it. The DER takes at most three quarters
/// of the text, and the entries take one per block.
var decoded = false;
var chain_der: [pem.pem_fixture_r2_chain.len / 4 * 3]u8 = undefined;
var chain_entries: [2]c.ch_cert = undefined;
var pem_chain: chapulin.Chain = .{};
var pem_key: chapulin.EcdsaP256Key = .{};
var bundle_der: [pem.pem_fixture_bundle.len / 4 * 3]u8 = undefined;
var bundle_entries: [6]c.ch_trust_anchor = undefined;
var pem_anchors: if (has_webpki) chapulin.Anchors else void = if (has_webpki) .{} else {};

/// Decodes the r2 chain file and its key file, under the EC PARAMETERS
/// block that `openssl ecparam -genkey` writes. Under TRUST=webpki it
/// decodes the curl-style bundle too, whose last root is root_p384. It
/// holds each value to webpki_corpus.h's.
fn decodeFiles() void {
    if (decoded) return;
    pem_chain = chapulin.Chain.fromPem(&pem.pem_fixture_r2_chain, &chain_der, &chain_entries) catch @panic("the r2 chain file does not decode");
    splitChain();
    if (pem_chain.certs.len != chain.len) @panic("the r2 chain file does not hold two certificates");
    for (pem_chain.certs, &chain) |got, want| {
        if (!std.mem.eql(u8, got.der[0..got.len], want.der[0..want.len])) @panic("a certificate of the r2 chain file is not the corpus's");
    }
    pem_key.fromPem(cpuAnswer(), &pem.pem_fixture_key_sec1_params, pem_chain.leaf()) catch @panic("the r2 key file does not decode");
    if (!std.mem.eql(u8, &pem_key.private_key, &corpus.webpki_corpus_server_priv) or
        !std.mem.eql(u8, &pem_key.public_key, &corpus.webpki_corpus_server_pub)) @panic("the r2 key file's key is not the corpus's");
    if (has_webpki) {
        pem_anchors = chapulin.Anchors.fromPem(&pem.pem_fixture_bundle, &bundle_der, &bundle_entries) catch @panic("the bundle does not decode");
        const root = pem_anchors.anchors[pem_anchors.anchors.len - 1];
        if (!std.mem.eql(u8, root.name[0..root.name_len], &corpus.webpki_corpus_name_root_p384) or
            !std.mem.eql(u8, root.spki[0..root.spki_len], &corpus.webpki_corpus_spki_root_p384)) @panic("the bundle's last root is not root_p384");
    }
    decoded = true;
}

pub const Anchor = enum { root, impostor };

/// A clock that answers the u64 its clock_io points at, so a test sets the instant an init
/// call reads by writing that variable, and a client and a server read one each.
pub fn clockAt(seconds: *const u64) chapulin.Clock {
    return .{ .now_seconds = readSeconds, .clock_io = @constCast(seconds) };
}

fn readSeconds(clock_io: ?*anyopaque) callconv(.c) u64 {
    const seconds: *const u64 = @ptrCast(@alignCast(clock_io.?));
    return seconds.*;
}

/// The instants the fixture's client and server clocks answer.
pub var client_seconds: u64 = 0;
pub var server_seconds: u64 = 0;

/// A client of this object's trust mode that accepts the r2 server: the
/// root anchor, the hostname and the row's clock under TRUST=webpki, and
/// the leaf's point pinned under TRUST=raw-ecdsa. anchor picks the
/// impostor for a refusal, and now_seconds overrides the clock.
pub fn trust(anchor: Anchor, now_seconds: ?u64) chapulin.Trust {
    if (!has_webpki) return .{ .pinned = .{ .server_pubkey = &corpus.webpki_corpus_server_pub } };
    decodeFiles();
    return .{ .web_pki = .{
        .anchors = switch (anchor) {
            .root => pem_anchors.anchors[pem_anchors.anchors.len - 1 ..],
            .impostor => &anchors.impostor,
        },
        .server_name = hostname(),
        .clock = blk: {
            client_seconds = now_seconds orelse r2Row().now_seconds;
            break :blk clockAt(&client_seconds);
        },
    } };
}

/// The chain's two certificates, pointing into its Certificate message:
/// the 4-byte handshake header, the empty certificate_request_context, the
/// 3-byte list length, then per entry a 3-byte length, the certificate and
/// an empty extensions vector (RFC 9846 section 4.5.1).
var chain: [2]c.ch_cert = undefined;

fn splitChain() void {
    const message: []const u8 = &corpus.webpki_corpus_message_r2;
    var off: usize = 4 + 1 + 3;
    for (&chain) |*entry| {
        const len = std.mem.readInt(u24, message[off..][0..3], .big);
        entry.* = chapulin.cert(message[off + 3 ..][0..len]);
        off += 3 + len;
        off += 2 + std.mem.readInt(u16, message[off..][0..2], .big);
    }
    if (off != message.len) @panic("the r2 Certificate message does not frame two entries");
}

pub const cookie_key = [_]u8{7} ** c.CH_SRV_COOKIE_KEY_LEN;
pub const ticket_key = [_]u8{0x61} ** c.CH_SRV_TICKET_KEY_LEN;

/// This tree's server with the r2 identity, sealing tickets under
/// ticket_key at clock now_seconds and selecting from alpn.
pub fn server(alpn: []const c.ch_alpn_protocol, now_seconds: u64) chapulin.Server {
    decodeFiles();
    return .{
        .ecdsa_p256 = .{
            .chain = pem_chain.certs,
            .public_key = &pem_key.public_key,
            .private_key = &pem_key.private_key,
        },
        .cookie_key = &cookie_key,
        .ticket_key = &ticket_key,
        .clock = blk: {
            server_seconds = now_seconds;
            break :blk clockAt(&server_seconds);
        },
        .alpn = alpn,
        .random = serverRandom(),
        .cpu = cpuAnswer(),
    };
}

/// A Ticket rebuilt from its fields, as a program that stored them after
/// the handshake rebuilds it for the next connection, the QUIC version it
/// arrived in included.
pub fn stored(taken: *const chapulin.Ticket) !chapulin.Ticket {
    const t = &taken.ticket;
    const identity = taken.identity[0..t.identity_len];
    const psk = t.psk[0..t.psk_len];
    var fields: chapulin.Ticket.Fields = if (has_webpki)
        .{ .identity = identity, .psk = psk, .age_add = t.age_add, .lifetime_s = t.lifetime_s, .epoch = t.epoch, .binding = &t.binding }
    else
        .{ .identity = identity, .psk = psk, .age_add = t.age_add, .lifetime_s = t.lifetime_s, .epoch = t.epoch };
    if (has_quic) fields.quic_version = @as(chapulin.quic.Version, @enumFromInt(t.quic_version));
    return chapulin.Ticket.fromFields(fields);
}

/// Whether every byte of value is zero.
pub fn zeroed(value: anytype) bool {
    return std.mem.allEqual(u8, std.mem.asBytes(value), 0);
}

/// Whether a client's init set on_ticket as its values' takes_tickets
/// says, and under TRUST=webpki whether it wrote ch_tls.takes_tickets and
/// stored a configuration hash to match. The Zig object exports no hash
/// call to count. bin/webpki_session_test counts the calls, and requires
/// one hash at init exactly when on_ticket is set
/// (test/webpki_ticket_rows.h).
pub fn clientTakesTickets(t: *const c.ch_tls, takes: bool) !void {
    try check((t.cfg.on_ticket != null) == takes, "on_ticket does not follow takes_tickets");
    if (!has_webpki) return;
    try check(t.takes_tickets == @intFromBool(takes), "ch_tls.takes_tickets does not follow takes_tickets");
    try check(zeroed(&t.ticket_config_hash) != takes, "the stored configuration hash does not follow takes_tickets");
}

pub fn check(ok: bool, what: []const u8) !void {
    if (ok) return;
    std.debug.print("loop: {s}\n", .{what});
    return error.CheckFailed;
}
