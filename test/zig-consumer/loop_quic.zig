//! A QUIC client and server of one QUIC ROLE=both object against each
//! other, through the API alone: the handshake over crypto_in and
//! crypto_out at each level with keys_ready checked at each step, the
//! version each side negotiated and the switches C refuses, the transport
//! parameters each side received, one 1-RTT packet sealed and opened each
//! way and a tampered one discarded, a key update, the Retry integrity tag
//! and a Retry token bound to its version, the ticket taken at the 1-RTT
//! level and resumed through Ticket.from_fields, a stale ticket refused, a
//! client whose takes_tickets is false that keeps no ticket and still
//! resumes one, a server whose choose_version answers version 2 and a
//! client that switches to it, that connection's ticket refused in version
//! 1 and resumed in version 2, and close. Under KEYLOG=on, ch_keylog finds
//! the client's context through chapulin.hook_context.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const hooks = @import("hooks.zig");
const c = chapulin.c;
const check = fixture.check;
const quic = chapulin.quic;

/// colibri's receive length, peer_params length and sni_buf (docs/zig.md).
const receive_len = 20_480;
var client: quic.Client(receive_len, .{}) = undefined;
var server: quic.Server(receive_len, .{}) = undefined;
var sni_buf: [255]u8 = undefined;
var client_peer: [1024]u8 = undefined;
var server_peer: [1024]u8 = undefined;

const client_params = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
const server_params = [_]u8{ 0x05, 0x06, 0x07 };
const client_alpn = [_][]const u8{"h3"};
const server_alpn = [_][]const u8{ "hq-interop", "h3" };
const server_now = 1_700_000_000;
/// RFC 9001 appendix A's Destination Connection ID.
const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

var buffers: [quic.level_count][4096]u8 = undefined;
var outgoing: quic.Outgoing = undefined;
var message: [4096]u8 = undefined;
/// What ch_keylog should find through chapulin.hook_context.
var client_context: u8 = 0;
/// What chooseV2 should be handed, and how many times it ran.
var server_context: u8 = 0;
var choose_calls: usize = 0;

/// The server's choose_version in the last run: version 2, from the
/// context the server's hook carries.
fn chooseV2(context: ?*anyopaque) quic.Version {
    if (context == @as(?*anyopaque, &server_context)) choose_calls += 1;
    return .v2;
}

fn sent(level: quic.Level) []const u8 {
    const i = @intFromEnum(level);
    return buffers[i][0..outgoing.written[i]];
}

fn clientValues() chapulin.ClientOptions {
    return .{ .trust = fixture.trust(.root, null), .alpn = &client_alpn, .quic_version = .v1, .random = fixture.clientRandom(), .cpu = fixture.cpuAnswer() };
}

/// A handshake of a version 1 client and server, whose server chooses the
/// negotiated version when choose is set. The client switches to the
/// server's version before it reads the server's first byte, as colibri
/// does when the Version field of the server's first Initial packet
/// differs from the client's.
fn handshake(values: chapulin.ClientOptions, choose: ?quic.ChooseVersion) !void {
    return handshakeWith(values, .v1, choose);
}

/// A handshake whose server's original version is version and which
/// chooses nothing, the client's original version being the same.
fn handshakeIn(values: chapulin.ClientOptions, version: quic.Version) !void {
    return handshakeWith(values, version, null);
}

fn handshakeWith(values: chapulin.ClientOptions, original: quic.Version, choose: ?quic.ChooseVersion) !void {
    outgoing = .{ .buffers = .{ &buffers[0], &buffers[1], &buffers[2] } };
    var server_values = fixture.server(&server_alpn, server_now);
    server_values.quic_version = original;
    server_values.choose_version = choose;
    server_values.context = &server_context;
    try server.init(&server_values, &server_params, &server_peer, &sni_buf);
    var client_values = values;
    client_values.context = &client_context;
    try client.init(&client_values, &client_params, &client_peer);
    try client.initial_keys(&dcid);
    try server.initial_keys(&dcid);
    try check(client.keys_ready(.initial, .write) and !client.keys_ready(.handshake, .read), "the client's Initial keys are not the only ones ready");
    // Both sides negotiate the original version, and C refuses a switch to
    // it, the version the session already negotiated.
    try check(client.negotiated_version() == original and server.negotiated_version() == original, "a session did not negotiate its original version");
    try check(client.switch_version(original) == error.Invalid, "a switch to the negotiated version was taken");

    var n = try client.crypto_out(.initial, &message);
    try server.crypto_in(.initial, message[0..n], &outgoing);
    try check(server.keys_ready(.handshake, .write) and server.keys_ready(.application, .write), "the server's flight left its write keys unready");
    const version = server.negotiated_version();
    if (version != client.negotiated_version()) try client.switch_version(version);
    try client.crypto_in(.initial, sent(.initial));
    // The server's first CRYPTO bytes fixed the negotiated version, so C
    // refuses a switch to the other one now.
    const other: quic.Version = if (version == .v1) .v2 else .v1;
    try check(client.switch_version(other) == error.Invalid and client.negotiated_version() == version, "a switch after the server's first byte was taken");
    try check(client.keys_ready(.handshake, .read) and !client.keys_ready(.application, .read), "the ServerHello did not ready the client's Handshake keys alone");
    if (@hasDecl(c, "ch_keylog")) {
        try check(chapulin.hook_context(hooks.keylog_io) == @as(*anyopaque, &client_context), "ch_keylog did not find the client's context");
    }
    try client.crypto_in(.handshake, sent(.handshake));
    n = try client.crypto_out(.handshake, &message);
    try check(client.state() == .connected and client.keys_ready(.application, .read), "the client did not connect");
    try server.crypto_in(.handshake, message[0..n], &outgoing);
    try check(server.state() == .connected, "the server did not connect");
}

/// One 1-RTT packet each way in the negotiated version, with an empty
/// connection ID and a two-byte packet number, and a tampered one the
/// client drops.
fn packets() !void {
    const pt = "one packet each way";
    const v = client.negotiated_version();
    var pkt: [64]u8 = undefined;
    var n = try server.seal(.application, v, 5, 2, &.{ 0x41, 0x00, 0x05 }, pt, &pkt);
    var opened = try client.open(.application, v, pkt[0..n], 1, 0, 0);
    try check(opened.pn == 5 and opened.key_set == .current and std.mem.eql(u8, pkt[3..][0..opened.pt_len], pt), "the client did not open the server's packet");
    n = try client.seal(.application, v, 6, 2, &.{ 0x41, 0x00, 0x06 }, pt, &pkt);
    opened = try server.open(.application, v, pkt[0..n], 1, 0, 0);
    try check(opened.pn == 6 and std.mem.eql(u8, pkt[3..][0..opened.pt_len], pt), "the server did not open the client's packet");

    n = try server.seal(.application, v, 7, 2, &.{ 0x41, 0x00, 0x07 }, pt, &pkt);
    // A 1-RTT packet in a version the session did not negotiate is refused
    // before it is read, and the session stays live.
    const other: quic.Version = if (v == .v1) .v2 else .v1;
    try check(client.open(.application, other, pkt[0..n], 1, 6, 0) == error.Invalid and client.state() == .connected, "a packet in another version was opened");
    pkt[n - 1] ^= 1;
    try check(client.open(.application, v, pkt[0..n], 1, 6, 0) == error.Discard and client.state() == .connected, "a tampered packet was not discarded");
}

/// The server updates its 1-RTT keys, and the client opens the next
/// packet under its next receive set and updates its own (RFC 9001
/// section 6.2).
fn key_update() !void {
    const pt = "after a key update";
    var pkt: [64]u8 = undefined;
    try server.key_update();
    try check(server.key_phase() == 1, "key_update did not flip the server's key phase");
    const v = client.negotiated_version();
    const n = try server.seal(.application, v, 8, 2, &.{ 0x45, 0x00, 0x08 }, pt, &pkt);
    const opened = try client.open(.application, v, pkt[0..n], 1, 6, 0);
    try check(opened.key_set == .next and opened.pn == 8, "the client did not open the updated packet under its next keys");
    try client.key_update();
    try check(client.key_phase() == 1, "key_update did not flip the client's key phase");
    client.drop_previous_keys();
}

/// The Retry integrity tag and a Retry token, which take no session.
fn retryAndTokens() !void {
    const pseudo = "a Retry pseudo-packet";
    var tag: [c.GCM_TAG]u8 = undefined;
    // 0x0a0a0a0a is a version RFC 9000 section 15 reserves, whose keys no
    // object derives.
    try check(quic.retry_tag(@enumFromInt(0x0a0a0a0a), pseudo, &tag) == error.Invalid, "retry_tag took a version this object does not derive");
    try quic.retry_tag(.v2, pseudo, &tag);
    try check(!client.retry_ok(.v2, pseudo, &tag), "retry_ok took a Retry in a version other than the original");
    try quic.retry_tag(.v1, pseudo, &tag);
    try check(client.retry_ok(.v1, pseudo, &tag), "retry_ok refused retry_tag's tag");
    try check(!client.retry_ok(.v2, pseudo, &tag), "retry_ok took a Retry in a version other than the original");
    tag[0] ^= 1;
    try check(!client.retry_ok(.v1, pseudo, &tag), "retry_ok took a changed tag");

    const key = [_]u8{0x71} ** c.CH_QUIC_TOKEN_KEY_LEN;
    const address = [_]u8{ 192, 0, 2, 1, 0x11, 0x51 };
    const cids = try quic.RetryConnectionIds.init(&dcid, "");
    const longest = [_]u8{0x7a} ** (c.CH_QUIC_DCID_MAX + 1);
    const both = try quic.RetryConnectionIds.init(longest[0..c.CH_QUIC_DCID_MAX], longest[0..c.CH_QUIC_DCID_MAX]);
    try check(both.original_dcid_len == c.CH_QUIC_DCID_MAX and both.retry_scid_len == c.CH_QUIC_DCID_MAX, "RetryConnectionIds refused two IDs of CH_QUIC_DCID_MAX bytes");
    try check(quic.RetryConnectionIds.init(&longest, "") == error.Invalid and quic.RetryConnectionIds.init("", &longest) == error.Invalid, "RetryConnectionIds took an ID over CH_QUIC_DCID_MAX bytes");
    var token: [c.CH_QUIC_TOKEN_MAX]u8 = undefined;
    const n = try quic.token_mint(&key, .v1, &address, &cids, 100, &token);
    const found = try quic.token_check(&key, .v1, token[0..n], &address, 110, 60);
    try check(found == .retry and std.meta.eql(found.retry, cids), "token_check did not return the minted connection IDs");
    // The token is bound to the version it was minted under.
    try check(try quic.token_check(&key, .v2, token[0..n], &address, 110, 60) == .invalid, "a version 1 token checked under version 2");
    try check(try quic.token_check(&key, .v1, "", &address, 110, 60) == .not_retry, "an empty token was not not_retry");
    token[n - 1] ^= 1;
    try check(try quic.token_check(&key, .v1, token[0..n], &address, 110, 60) == .invalid, "a changed token was not invalid");
    try check(quic.token_check(&key, .v1, token[0..n], "", 110, 60) == error.Invalid, "an empty address was taken");
    try check(quic.token_mint(&key, @enumFromInt(0), &address, &cids, 100, &token) == error.Invalid, "a token minted under no version");
}

fn take_ticket() !chapulin.Ticket {
    try client.crypto_in(.application, sent(.application));
    const taken = client.take_ticket() orelse return error.NoTicket;
    try check(fixture.zeroed(&client.ticket), "take_ticket left bytes in the ticket slot");
    return taken;
}

/// A client whose takes_tickets is false, first with no ticket and then
/// with ticket, which still resumes. Its init sets no on_ticket and stores
/// no hash, and it keeps none of the server's tickets.
fn ticketsOff(ticket: *const chapulin.Ticket) !void {
    var values = clientValues();
    values.takes_tickets = false;
    values.ticket_age_ms = 1000;
    for ([_]?*const chapulin.Ticket{ null, ticket }) |presented| {
        values.ticket = presented;
        try handshake(values, null);
        const resumed = presented != null;
        try check(client.psk_selected() == resumed and server.psk_selected() == resumed, "the PSK selection of a client whose takes_tickets is false does not match its ticket");
        try fixture.clientTakesTickets(&fixture.quicPriv(&client.quic).t, false);
        try check(sent(.application).len > 0, "the server wrote no ticket");
        try client.crypto_in(.application, sent(.application));
        try check(client.take_ticket() == null, "a client whose takes_tickets is false kept a ticket");
        client.close();
        server.close();
    }
}

pub fn run() !void {
    try handshake(clientValues(), null);
    try fixture.clientTakesTickets(&fixture.quicPriv(&client.quic).t, true);
    try check(std.mem.eql(u8, client.alpn_selected() orelse "", "h3") and std.mem.eql(u8, server.alpn_selected() orelse "", "h3"), "ALPN did not select h3 on both ends");
    const client_saw = (try client.peer_transport_params()) orelse "";
    const server_saw = (try server.peer_transport_params()) orelse "";
    try check(std.mem.eql(u8, client_saw, &server_params) and std.mem.eql(u8, server_saw, &client_params), "the transport parameters differ from what each side sent");
    try check(!client.psk_selected() and client.error_code() == 0, "the full handshake reports a PSK or an error");
    try packets();
    try key_update();
    try retryAndTokens();
    const taken = try take_ticket();
    client.close();
    server.close();
    try check(client.state() == .closed and !client.keys_ready(.application, .write), "close left keys ready");

    const ticket = try fixture.stored(&taken);
    var values = clientValues();
    values.ticket = &ticket;
    values.ticket_age_ms = 1000;
    try handshake(values, null);
    try check(client.psk_selected() and server.psk_selected(), "the ticket did not resume");
    try packets();
    try client.crypto_in(.application, sent(.application));
    try check(client.ticket != null, "the resumed session received no ticket");
    client.close();
    try check(fixture.zeroed(&client.ticket), "close left the ticket in the slot");

    // An age of exactly the lifetime is still offered, and one
    // millisecond more is refused before a byte is sent (ticket.h).
    values.ticket_age_ms = @as(u64, ticket.ticket.lifetime_s) * 1000;
    try client.init(&values, &client_params, &client_peer);
    client.close();
    values.ticket_age_ms += 1;
    try check(client.init(&values, &client_params, &client_peer) == error.Invalid and client.state() == .failed, "a stale ticket was not refused");
    // An init refusal sends nothing, so it chose no alert (alert.h).
    try check(client.alert() == null, "an init refusal reported an alert");
    try ticketsOff(&ticket);

    // The server chooses version 2 once, from its hook's context, and the
    // packets and the key update run in version 2 at both ends.
    try handshake(clientValues(), chooseV2);
    try check(choose_calls == 1 and client.negotiated_version() == .v2 and server.negotiated_version() == .v2, "the server's choice of version 2 was not negotiated");
    try packets();
    try key_update();
    // Its ticket belongs to version 2: C refuses it in a connection that
    // starts in version 1, and it resumes one that starts in version 2.
    const taken_v2 = try take_ticket();
    client.close();
    server.close();
    try check(taken_v2.ticket.quic_version == c.CH_QUIC_VERSION_2, "the ticket did not record version 2");
    const ticket_v2 = try fixture.stored(&taken_v2);
    var values_v2 = clientValues();
    values_v2.ticket = &ticket_v2;
    values_v2.ticket_age_ms = 1000;
    try check(client.init(&values_v2, &client_params, &client_peer) == error.Invalid, "a version 2 ticket started a version 1 connection");
    values_v2.quic_version = .v2;
    try handshakeIn(values_v2, .v2);
    try check(client.psk_selected() and server.psk_selected() and client.negotiated_version() == .v2, "the version 2 ticket did not resume in version 2");
    client.close();
    server.close();
    std.debug.print("a QUIC client and server ran through the API: a handshake at each level, a packet each way, a key update, the Retry tag and token, a resumed ticket, a stale one refused, a client that takes no tickets, first with no ticket and then with one it resumes, version 2 chosen by the server and its ticket resumed in version 2, and close\n", .{});
}
