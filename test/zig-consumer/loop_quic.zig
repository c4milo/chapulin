//! A QUIC client and server of one QUIC ROLE=both object against each
//! other, through the API alone: the handshake over cryptoIn and
//! cryptoOut at each level with keysReady checked at each step, the
//! transport parameters each side received, one 1-RTT packet sealed and
//! opened each way and a tampered one discarded, a key update, the Retry
//! integrity tag and a Retry token, the ticket taken at the 1-RTT level
//! and resumed through Ticket.fromFields, a stale ticket refused, and
//! close. Under KEYLOG=on, ch_keylog finds the client's context through
//! chapulin.hookContext.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const hooks = @import("hooks.zig");
const c = chapulin.c;
const check = fixture.check;
const quic = chapulin.quic;

/// colibri's receive length, peer_params length and sni_buf (docs/zig.md).
const receive_len = 20_480;
var client: quic.Client(receive_len) = undefined;
var server: quic.Server(receive_len) = undefined;
var sni_buf: [255]u8 = undefined;
var client_peer: [1024]u8 = undefined;
var server_peer: [1024]u8 = undefined;

const client_params = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const server_params = [_]u8{ 0x05, 0x06, 0x07 };
const client_alpn = [_]c.ch_alpn_protocol{chapulin.alpnProtocol("h3")};
const server_alpn = [_]c.ch_alpn_protocol{ chapulin.alpnProtocol("hq-interop"), chapulin.alpnProtocol("h3") };
const server_now = 1_700_000_000;
/// RFC 9001 appendix A's Destination Connection ID.
const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

var buffers: [quic.level_count][4096]u8 = undefined;
var outgoing: quic.Outgoing = undefined;
var message: [4096]u8 = undefined;
/// What ch_keylog should find through chapulin.hookContext.
var client_context: u8 = 0;

fn sent(level: quic.Level) []const u8 {
    const i = @intFromEnum(level);
    return buffers[i][0..outgoing.written[i]];
}

fn clientValues() chapulin.Client {
    return .{ .trust = fixture.trust(.root, null), .alpn = &client_alpn };
}

fn handshake(values: chapulin.Client) !void {
    outgoing = .{ .buffers = .{ &buffers[0], &buffers[1], &buffers[2] } };
    try server.init(fixture.server(&server_alpn, server_now), &server_params, &server_peer, &sni_buf);
    try client.init(values, &client_params, &client_peer);
    client.hook.context = &client_context;
    try client.initialKeys(&dcid);
    try server.initialKeys(&dcid);
    try check(client.keysReady(.initial, .write) and !client.keysReady(.handshake, .read), "the client's Initial keys are not the only ones ready");

    var n = try client.cryptoOut(.initial, &message);
    try server.cryptoIn(.initial, message[0..n], &outgoing);
    try check(server.keysReady(.handshake, .write) and server.keysReady(.application, .write), "the server's flight left its write keys unready");
    try client.cryptoIn(.initial, sent(.initial));
    try check(client.keysReady(.handshake, .read) and !client.keysReady(.application, .read), "the ServerHello did not ready the client's Handshake keys alone");
    if (@hasDecl(c, "ch_keylog")) {
        try check(chapulin.hookContext(hooks.keylog_io) == @as(*anyopaque, &client_context), "ch_keylog did not find the client's context");
    }
    try client.cryptoIn(.handshake, sent(.handshake));
    n = try client.cryptoOut(.handshake, &message);
    try check(client.state() == .connected and client.keysReady(.application, .read), "the client did not connect");
    try server.cryptoIn(.handshake, message[0..n], &outgoing);
    try check(server.state() == .connected, "the server did not connect");
}

/// One 1-RTT packet each way, with an empty connection ID and a two-byte
/// packet number, and a tampered one the client drops.
fn packets() !void {
    const pt = "one packet each way";
    var pkt: [64]u8 = undefined;
    var n = try server.seal(.application, 5, 2, &.{ 0x41, 0x00, 0x05 }, pt, &pkt);
    var opened = try client.open(.application, pkt[0..n], 1, 0, 0);
    try check(opened.pn == 5 and opened.key_set == .current and std.mem.eql(u8, pkt[3..][0..opened.pt_len], pt), "the client did not open the server's packet");
    n = try client.seal(.application, 6, 2, &.{ 0x41, 0x00, 0x06 }, pt, &pkt);
    opened = try server.open(.application, pkt[0..n], 1, 0, 0);
    try check(opened.pn == 6 and std.mem.eql(u8, pkt[3..][0..opened.pt_len], pt), "the server did not open the client's packet");

    n = try server.seal(.application, 7, 2, &.{ 0x41, 0x00, 0x07 }, pt, &pkt);
    pkt[n - 1] ^= 1;
    try check(client.open(.application, pkt[0..n], 1, 6, 0) == error.Discard and client.state() == .connected, "a tampered packet was not discarded");
}

/// The server updates its 1-RTT keys, and the client opens the next
/// packet under its next receive set and updates its own (RFC 9001
/// section 6.2).
fn keyUpdate() !void {
    const pt = "after a key update";
    var pkt: [64]u8 = undefined;
    try server.keyUpdate();
    try check(server.keyPhase() == 1, "keyUpdate did not flip the server's key phase");
    const n = try server.seal(.application, 8, 2, &.{ 0x45, 0x00, 0x08 }, pt, &pkt);
    const opened = try client.open(.application, pkt[0..n], 1, 6, 0);
    try check(opened.key_set == .next and opened.pn == 8, "the client did not open the updated packet under its next keys");
    try client.keyUpdate();
    try check(client.keyPhase() == 1, "keyUpdate did not flip the client's key phase");
    client.dropPreviousKeys();
}

/// The Retry integrity tag and a Retry token, which take no session.
fn retryAndTokens() !void {
    const pseudo = "a Retry pseudo-packet";
    var tag: [c.GCM_TAG]u8 = undefined;
    quic.retryTag(pseudo, &tag);
    try check(client.retryOk(pseudo, &tag), "retryOk refused retryTag's tag");
    tag[0] ^= 1;
    try check(!client.retryOk(pseudo, &tag), "retryOk took a changed tag");

    const key = [_]u8{0x71} ** c.CH_QUIC_TOKEN_KEY_LEN;
    const address = [_]u8{ 192, 0, 2, 1, 0x11, 0x51 };
    var cids = std.mem.zeroes(c.ch_quic_retry_cids);
    cids.original_dcid_len = dcid.len;
    @memcpy(cids.original_dcid[0..dcid.len], &dcid);
    var token: [c.CH_QUIC_TOKEN_MAX]u8 = undefined;
    const n = try quic.tokenMint(&key, &address, &cids, 100, &token);
    const found = try quic.tokenCheck(&key, token[0..n], &address, 110, 60);
    try check(found == .retry and std.meta.eql(found.retry, cids), "tokenCheck did not return the minted connection IDs");
    try check(try quic.tokenCheck(&key, "", &address, 110, 60) == .not_retry, "an empty token was not not_retry");
    token[n - 1] ^= 1;
    try check(try quic.tokenCheck(&key, token[0..n], &address, 110, 60) == .invalid, "a changed token was not invalid");
    try check(quic.tokenCheck(&key, token[0..n], "", 110, 60) == error.Invalid, "an empty address was taken");
}

fn takeTicket() !chapulin.Ticket {
    try client.cryptoIn(.application, sent(.application));
    const taken = client.takeTicket() orelse return error.NoTicket;
    try check(fixture.zeroed(&client.ticket), "takeTicket left bytes in the ticket slot");
    return taken;
}

pub fn run() !void {
    try handshake(clientValues());
    try check(std.mem.eql(u8, client.alpnSelected() orelse "", "h3") and std.mem.eql(u8, server.alpnSelected() orelse "", "h3"), "ALPN did not select h3 on both ends");
    const client_saw = (try client.peerTransportParams()) orelse "";
    const server_saw = (try server.peerTransportParams()) orelse "";
    try check(std.mem.eql(u8, client_saw, &server_params) and std.mem.eql(u8, server_saw, &client_params), "the transport parameters differ from what each side sent");
    try check(!client.pskSelected() and client.errorCode() == 0, "the full handshake reports a PSK or an error");
    try packets();
    try keyUpdate();
    try retryAndTokens();
    const taken = try takeTicket();
    client.close();
    server.close();
    try check(client.state() == .closed and !client.keysReady(.application, .write), "close left keys ready");

    const ticket = try fixture.stored(&taken);
    var values = clientValues();
    values.ticket = &ticket;
    values.ticket_age_ms = 1000;
    try handshake(values);
    try check(client.pskSelected() and server.pskSelected(), "the ticket did not resume");
    try packets();
    try client.cryptoIn(.application, sent(.application));
    try check(client.ticket != null, "the resumed session received no ticket");
    client.close();
    try check(fixture.zeroed(&client.ticket), "close left the ticket in the slot");

    // An age of exactly the lifetime is still offered, and one
    // millisecond more is refused before a byte is sent (ticket.h).
    values.ticket_age_ms = @as(u64, ticket.ticket.lifetime_s) * 1000;
    try client.init(values, &client_params, &client_peer);
    client.close();
    values.ticket_age_ms += 1;
    try check(client.init(values, &client_params, &client_peer) == error.Invalid and client.state() == .failed, "a stale ticket was not refused");
    std.debug.print("a QUIC client and server ran through the API: a handshake at each level, a packet each way, a key update, the Retry tag and token, a resumed ticket, a stale one refused, and close\n", .{});
}
