//! The server identity and the client trust both loops use: the r2 corpus
//! chain, its root_p384 anchor, its hostname and clock, and its leaf key,
//! all from test/webpki_corpus.h, the fixture test/webpki_loop_test.c and
//! test/quic_loop_webpki.h use through test/webpki_r2_chain.h. A raw-ecdsa
//! client pins the leaf's point instead of trusting the anchor.
const std = @import("std");
const chapulin = @import("chapulin");
const corpus = @import("corpus");
const hooks = @import("hooks.zig");
const c = chapulin.c;

const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");
const has_quic = @hasField(c.ch_ticket, "quic_version");
const has_aes_runtime = @hasField(c.ch_cfg, "aes_instructions");
const has_widemul_runtime = @hasField(c.ch_cfg, "widemul");

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

/// The value of Client.aes_instructions and Server.aes_instructions: the
/// instructions present under AES=runtime, which the machines that run
/// these loops have, as an AES=hw object needs them, and void in every
/// other build.
pub fn aesAnswer() if (has_aes_runtime) ?chapulin.AesInstructions else void {
    return if (has_aes_runtime) .present else {};
}

/// The value of Client.widemul and Server.widemul: under WIDEMUL=runtime
/// the answer that the multiply runs in constant time, which runs the
/// native copies, as a host test binary's CH_NATIVE_WIDEMUL does where no
/// secret is at risk, and void in every other build.
pub fn widemulAnswer() if (has_widemul_runtime) ?chapulin.Widemul else void {
    return if (has_widemul_runtime) .constant_time else {};
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

/// The anchor the chain verifies under, and one that carries its Name over
/// another key.
const anchors = if (has_webpki) struct {
    const root = [_]c.ch_trust_anchor{chapulin.trustAnchor(&corpus.webpki_corpus_name_root_p384, &corpus.webpki_corpus_spki_root_p384)};
    const impostor = [_]c.ch_trust_anchor{chapulin.trustAnchor(&corpus.webpki_corpus_name_root_p384, &corpus.webpki_corpus_spki_impostor_p384)};
} else struct {};

pub const Anchor = enum { root, impostor };

/// A client of this object's trust mode that accepts the r2 server: the
/// root anchor, the hostname and the row's clock under TRUST=webpki, and
/// the leaf's point pinned under TRUST=raw-ecdsa. anchor picks the
/// impostor for a refusal, and now_seconds overrides the clock.
pub fn trust(anchor: Anchor, now_seconds: ?u64) chapulin.Trust {
    if (!has_webpki) return .{ .pinned = .{ .server_pubkey = &corpus.webpki_corpus_server_pub } };
    return .{ .web_pki = .{
        .anchors = switch (anchor) {
            .root => &anchors.root,
            .impostor => &anchors.impostor,
        },
        .server_name = hostname(),
        .now_seconds = now_seconds orelse r2Row().now_seconds,
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
    splitChain();
    return .{
        .ecdsa_p256 = .{
            .chain = &chain,
            .public_key = &corpus.webpki_corpus_server_pub,
            .private_key = &corpus.webpki_corpus_server_priv,
        },
        .cookie_key = &cookie_key,
        .ticket_key = &ticket_key,
        .now_seconds = now_seconds,
        .alpn = alpn,
        .random = serverRandom(),
        .aes_instructions = aesAnswer(),
        .widemul = widemulAnswer(),
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

pub fn check(ok: bool, what: []const u8) !void {
    if (ok) return;
    std.debug.print("loop: {s}\n", .{what});
    return error.CheckFailed;
}
