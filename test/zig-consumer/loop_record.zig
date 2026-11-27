//! A tcp-nonblocking client and server of one tcp-nonblocking ROLE=both object
//! against each other, through the API alone: the handshake, ALPN, the
//! server name, data both ways across several records, each sealed where it
//! lies, a seal that does not fit, an h2 frame's header and payload sealed
//! as one run, the exporter, a ticket taken and resumed through
//! Ticket.from_fields, a stale ticket refused, a client whose takes_tickets
//! is false that keeps no ticket and still resumes one, close in each
//! direction and close, four refusals, the last of whose alerts the
//! server reads as the client's fatal alert and does not answer, and each
//! side's handshake failure before and after its write key, whose alert
//! record the other side reads. At TX_RECORD=16384 the records carry
//! CH_TX_PT bytes each. Under SUITE=aesgcm, loop_key_limit.zig then has
//! each side write across its AES-GCM write key's ceiling, and
//! loop_key_update_run.zig has the server refuse one KeyUpdate past the
//! run limit in every object.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const key_limit = @import("loop_key_limit.zig");
const key_update_run = @import("loop_key_update_run.zig");
const c = chapulin.c;
const check = fixture.check;
const tcp = chapulin.tcp;

/// colibri's handshake buffer length (docs/zig.md). Each session takes its
/// own here; a server with many handshakes in flight keeps a pool of them.
const receive_len = 20_480;
pub var client: tcp.Client(.{}) = undefined;
pub var server: tcp.Server(.{}) = undefined;
var client_handshake: [receive_len]u8 = undefined;
var server_handshake: [receive_len]u8 = undefined;
var sni_buf: [255]u8 = undefined;

/// Bytes one side wrote and the other has not read.
pub const Pipe = struct {
    bytes: [1 << 17]u8 = undefined,
    len: usize = 0,
    off: usize = 0,

    /// The room after what the pipe holds.
    pub fn free(p: *Pipe) []u8 {
        return p.bytes[p.len..];
    }
    pub fn pending(p: *Pipe) []u8 {
        return p.bytes[p.off..p.len];
    }
    /// Marks n more bytes written into free().
    pub fn push(p: *Pipe, n: usize) void {
        p.len += n;
    }
    /// Marks n bytes of pending() read, and starts over once all are.
    pub fn pop(p: *Pipe, n: usize) void {
        p.off += n;
        if (p.off == p.len) {
            p.off = 0;
            p.len = 0;
        }
    }
};
pub var to_server: Pipe = .{};
pub var to_client: Pipe = .{};

const http11 = "http/1.1";
const client_alpn = [_][]const u8{ "h2", http11 };
const server_alpn = [_][]const u8{http11};
/// The server's clock, which it writes into tickets and judges them by.
const server_now = 1_700_000_000;

pub fn clientValues() chapulin.ClientOptions {
    return .{ .trust = fixture.trust(.root, null), .alpn = &client_alpn, .random = fixture.clientRandom(), .cpu = fixture.cpuAnswer() };
}

/// The server each handshake below runs against.
pub fn serverValues() chapulin.ServerOptions {
    return fixture.server(&server_alpn, server_now);
}

/// Moves what the client staged into the server, and what the server
/// wrote into its pipe. Returns the bytes of the server's flight.
fn clientToServer() !usize {
    to_server.push(try client.record_out(to_server.free()));
    if (to_server.pending().len == 0) return 0;
    const progress = try server.record_in(to_server.pending(), to_client.free());
    to_server.pop(progress.consumed);
    to_client.push(progress.written);
    return progress.written;
}

fn serverToClient() !void {
    if (to_client.pending().len == 0) return;
    to_client.pop(try client.record_in(to_client.pending()));
}

/// One handshake between fresh sessions. The client is connected once
/// record_out has handed its Finished over, and what the server writes
/// after that, the ticket, is read with read.
pub fn handshake(server_values: chapulin.ServerOptions, values: chapulin.ClientOptions) !void {
    to_server = .{};
    to_client = .{};
    try server.init(&server_values, &sni_buf, &server_handshake);
    try client.init(&values, &client_handshake);
    for (0..4) |_| {
        _ = try clientToServer();
        if (client.state() == .connected) break;
        try serverToClient();
    }
    try check(client.state() == .connected and server.state() == .connected, "the handshake did not connect both ends");
}

var received: [1 << 16]u8 = undefined;
var reply: [256]u8 = undefined;

/// Reads everything wire holds through reader's read, one record at a
/// time, and returns the plaintext and the number of records that
/// carried some. read opens each record in the pipe's own bytes, so the
/// plaintext is copied out before the pipe drops the record.
pub fn drain(reader: anytype, wire: *Pipe) !struct { []const u8, usize } {
    var got: usize = 0;
    var records: usize = 0;
    while (true) {
        const r = try reader.read(wire.pending(), &reply);
        @memcpy(received[got..][0..r.plaintext.len], r.plaintext);
        got += r.plaintext.len;
        if (r.plaintext.len > 0) records += 1;
        wire.pop(r.consumed);
        if (r.consumed == 0) break;
    }
    return .{ received[0..got], records };
}

/// Seals data through the API into the first cap bytes of wire's free room
/// and marks what it wrote: the plaintext goes at plaintext_offset, seal
/// seals it there, and a KeyUpdate that seal wrote into side moves in
/// front of the records, the order the peer reads them in. Returns the
/// bytes it pushed.
pub fn seal_in(writer: anytype, wire: *Pipe, data: []const u8, cap: usize) !usize {
    const room = wire.free();
    @memcpy(room[tcp.plaintext_offset..][0..data.len], data);
    var side: [tcp.key_update_record_len]u8 = undefined;
    const sealed = try writer.seal(room[0..cap], data.len, &side);
    if (sealed.side.len > 0) {
        @memmove(room[sealed.side.len..][0..sealed.records.len], sealed.records);
        @memcpy(room[0..sealed.side.len], sealed.side);
    }
    const n = sealed.side.len + sealed.records.len;
    wire.push(n);
    return n;
}

/// seal_in into all of wire's free room but the side record's length,
/// which a KeyUpdate in front of the records takes.
pub fn seal_to(writer: anytype, wire: *Pipe, data: []const u8) !usize {
    return seal_in(writer, wire, data, wire.free().len - tcp.key_update_record_len);
}

/// data from writer to reader in one seal, across records.
fn transfer(writer: anytype, reader: anytype, wire: *Pipe, data: []const u8) !usize {
    _ = try seal_to(writer, wire, data);
    const got, const records = try drain(reader, wire);
    try check(std.mem.eql(u8, got, data), "the plaintext read differs from what was written");
    return records;
}

var payload: [3 * c.CH_TX_PT + 100]u8 = undefined;

fn exchange() !void {
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i *% 7);
    const records = try transfer(&client, &server, &to_server, &payload);
    try check(records >= 4, "a write longer than three records of CH_TX_PT went out in fewer than four");
    _ = try transfer(&server, &client, &to_client, &payload);

    // A seal one byte past what the buffer holds seals nothing and leaves
    // the session connected; the same seal into the whole buffer then
    // reads back, so no record was sealed in between.
    const message = "one record";
    const sealed = try seal_to(&client, &to_server, message);
    try check(client.writable_len(sealed) == message.len and client.writable_len(sealed - 1) < message.len, "writable_len does not match what seal sealed");
    const refused = seal_in(&client, &to_server, message, sealed - 1);
    try check(refused == error.Cap and client.state() == .connected, "a seal that did not fit was not refused whole");
    _ = try seal_in(&client, &to_server, message, sealed);
    const got, _ = try drain(&server, &to_server);
    try check(std.mem.eql(u8, got, message ++ message), "a refused seal sealed part of its plaintext");
    try sealFrames();
    try sealRefusals();
}

/// A 9-byte header and a payload one byte longer than a record, as an h2
/// DATA frame holds them, written as one run where the records go: the
/// server reads them joined, in two records, and a seal one byte short of
/// what the run needs seals nothing. The second seal's records follow the
/// first's on the wire.
fn sealFrames() !void {
    const header = [_]u8{ 0, 0x40, 0, 0, 1, 0, 0, 0, 1 };
    const body = payload[0 .. c.CH_TX_PT + 1];
    var frame_bytes: [header.len + c.CH_TX_PT + 1]u8 = undefined;
    @memcpy(frame_bytes[0..header.len], &header);
    @memcpy(frame_bytes[header.len..], body);
    const sealed = try seal_to(&client, &to_server, &frame_bytes);
    try check(sealed == frame_bytes.len + 2 * (c.REC_HDR + 1 + c.AEAD_TAG), "one frame of a header and a record and a byte of payload did not seal as two records");
    try check(client.writable_len(sealed) == frame_bytes.len, "writable_len does not match what seal sealed");
    const refused = seal_in(&client, &to_server, &frame_bytes, sealed - 1);
    try check(refused == error.Cap and client.state() == .connected, "a frame that did not fit was not refused whole");
    _ = try seal_in(&client, &to_server, &frame_bytes, sealed);
    const got, const records = try drain(&server, &to_server);
    try check(records == 4, "two frames of a header and a record and a byte of payload went out in other than four records");
    for (0..2) |i| {
        const one = got[i * frame_bytes.len .. (i + 1) * frame_bytes.len];
        try check(std.mem.eql(u8, one, &frame_bytes), "the server read other bytes than the frame");
    }
    try check(got.len == 2 * frame_bytes.len, "the server read more than the two frames");
}

/// A seal of no plaintext writes nothing, and a side buffer shorter than a
/// KeyUpdate record is refused before anything is sealed.
fn sealRefusals() !void {
    var side: [tcp.key_update_record_len]u8 = undefined;
    const none = try client.seal(to_server.free(), 0, &side);
    try check(none.records.len == 0 and none.side.len == 0, "a seal of no plaintext wrote a record");
    const room = to_server.free();
    @memcpy(room[tcp.plaintext_offset..][0..4], "ping");
    try check(client.seal(room, 4, side[0 .. side.len - 1]) == error.Invalid and client.state() == .connected, "seal took a side buffer shorter than a KeyUpdate record");
    try check(to_server.pending().len == 0, "a refused seal left bytes on the wire");
}

fn exporter() !void {
    if (!@hasDecl(c, "ch_export")) return;
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try client.export_keying_material("EXPORTER-Channel-Binding", "", &a);
    try server.export_keying_material("EXPORTER-Channel-Binding", "", &b);
    try check(std.mem.eql(u8, &a, &b), "the two ends export different keying material");
}

/// The server's ticket, through read and take_ticket, and the slot zeroed.
fn take_ticket() !chapulin.Ticket {
    _ = try drain(&client, &to_client);
    const taken = client.take_ticket() orelse return error.NoTicket;
    try check(fixture.zeroed(&client.ticket), "take_ticket left bytes in the ticket slot");
    try check(taken.ticket.lifetime_s > 0 and taken.ticket.identity == null, "the ticket lost its lifetime or kept an identity pointer");
    return taken;
}

/// A client whose takes_tickets is false, first with no ticket and then
/// with taken, which still resumes. Its init sets no on_ticket and stores
/// no hash, and it keeps none of the server's tickets.
fn ticketsOff(taken: *const chapulin.Ticket) !void {
    const ticket = try fixture.stored(taken);
    var values = clientValues();
    values.takes_tickets = false;
    values.ticket_age_ms = 1000;
    for ([_]?*const chapulin.Ticket{ null, &ticket }) |presented| {
        values.ticket = presented;
        try handshake(serverValues(), values);
        const resumed = presented != null;
        try check(client.psk_selected() == resumed and server.psk_selected() == resumed, "the PSK selection of a client whose takes_tickets is false does not match its ticket");
        try fixture.clientTakesTickets(&fixture.tcpPriv(&client.tcp).t, false);
        try check(to_client.pending().len > 0, "the server wrote no ticket");
        _ = try drain(&client, &to_client);
        try check(to_client.pending().len == 0 and client.take_ticket() == null, "a client whose takes_tickets is false kept a ticket");
        client.close();
        server.close();
    }
}

/// The client closes its direction, and the server reads that close_notify
/// and still writes, as RFC 9846 section 6.1 leaves its direction open,
/// then closes its own. A side that sent its close_notify has wiped its
/// keys, so it reads no more.
fn closeBothWays() !void {
    const sent = try client.end(to_server.free());
    to_server.push(sent);
    try check(sent == tcp.alert_record_len and client.state() == .closed, "close did not send one alert record");
    const r = try server.read(to_server.pending(), &reply);
    to_server.pop(r.consumed);
    try check(r.peer_closed and server.read_closed() and server.state() == .connected, "the server did not read the client's close_notify");
    _ = try seal_to(&server, &to_client, "after");
    to_client.push(try server.end(to_client.free()));
    const back = try client.read(to_client.pending(), &reply);
    try check(back.peer_closed and back.consumed == 0, "a closed client read on");
    client.close();
    server.close();
    try check(server.state() == .closed, "close left the session open");
}

/// Resumes with the ticket rebuilt from its fields, at ages around the
/// lifetime, then closes.
fn resumeTicket(taken: *const chapulin.Ticket) !void {
    const ticket = try fixture.stored(taken);
    var values = clientValues();
    values.ticket = &ticket;
    values.ticket_age_ms = 1000;
    try handshake(serverValues(), values);
    try check(client.psk_selected() and server.psk_selected(), "the ticket did not resume");
    // The next ticket sits in the slot, and close zeroes it.
    _ = try drain(&client, &to_client);
    try check(client.ticket != null, "the resumed session received no ticket");
    client.close();
    try check(fixture.zeroed(&client.ticket), "close left the ticket in the slot");

    // An age of exactly the lifetime is still offered, and one
    // millisecond more is refused before a byte is sent (ticket.h).
    values.ticket_age_ms = @as(u64, ticket.ticket.lifetime_s) * 1000;
    try client.init(&values, &client_handshake);
    client.close();
    values.ticket_age_ms += 1;
    try check(client.init(&values, &client_handshake) == error.Invalid and client.state() == .failed, "a stale ticket was not refused");
}

/// An anchor that did not sign the chain, a clock of 0 beside anchors,
/// a server output one byte short of its flight, and a record header
/// whose length no peer may send.
fn refusals() !void {
    if (@hasField(c.ch_cfg, "anchors")) {
        try server.init(&serverValues(), &sni_buf, &server_handshake);
        try client.init(&.{ .trust = fixture.trust(.impostor, null), .alpn = &client_alpn, .random = fixture.clientRandom(), .cpu = fixture.cpuAnswer() }, &client_handshake);
        to_server = .{};
        to_client = .{};
        _ = try clientToServer();
        try check(serverToClient() == error.Auth, "an impostor anchor was not refused");
        try check(client.alert_sent() == .unknown_ca and client.alert_received() == null, "alert_sent did not name the handshake's unknown_ca");
        // The client refused the Certificate after its write key went in,
        // so its unknown_ca is sealed.
        try clientAlertReachesServer(.unknown_ca, tcp.alert_record_len);
        try check(client.init(&.{ .trust = fixture.trust(.root, 0), .random = fixture.clientRandom(), .cpu = fixture.cpuAnswer() }, &client_handshake) == error.Invalid, "a clock of 0 was accepted");
    }
    // The server's first flight twice, from the same draws: once whole, to
    // learn its length, and once into an output one byte short of it. The
    // length changes with the draws, because DER writes the r and s of the
    // flight's ECDSA signature in as few bytes as each value needs, with a
    // zero byte in front of a value whose top bit is set.
    const start = fixture.draws();
    try startPair();
    try serverAnswersHello();
    const flight_len = to_client.pending().len;
    fixture.rewind(start);
    try startPair();
    var short: [8192]u8 = undefined;
    const refused = server.record_in(to_server.pending(), short[0 .. flight_len - 1]);
    try check(refused == error.Io and server.state() == .failed, "a flight that did not fit was not refused");

    try handshake(serverValues(), clientValues());
    var oversize = [_]u8{ 0x17, 0x03, 0x03, 0xff, 0xff };
    const waiting = try client.read(oversize[0..4], &reply);
    try check(waiting.consumed == 0 and waiting.plaintext.len == 0, "read took a part of a header");
    try check(client.read(&oversize, &reply) == error.Proto, "read waited on a record no peer may send");
    // The client's read sent the alert its failure chose into reply, and
    // staged nothing for record_out. The server reads that alert as the
    // peer's fatal alert and sends nothing back (RFC 9846 section 6.2).
    const sent = client.alert_sent() orelse return error.NoAlertSent;
    try check(client.alert_received() == null and client.record_out(to_server.free()) == error.Invalid, "the client's failed read staged an alert or reported one received");
    var answer: [256]u8 = undefined;
    try check(server.read(reply[0..client.reply_len()], &answer) == error.Proto, "the server read on after the client's fatal alert");
    try check(server.alert_received() == sent and server.alert_sent() == null and server.reply_len() == 0, "the server answered the client's fatal alert");
}

/// The failed client's alert record, handed to the server: record_out
/// returns all len bytes of it, then error.Invalid, and the server reads it
/// as the client's fatal alert and writes nothing into output.
fn clientAlertReachesServer(alert: chapulin.AlertDescription, len: usize) !void {
    to_server = .{};
    const n = try client.record_out(to_server.free());
    to_server.push(n);
    try check(n == len and client.record_out(to_server.free()) == error.Invalid, "record_out did not return the client's alert record once");
    try check(server.record_in(to_server.pending(), to_client.free()) == error.Proto, "the server read on after the client's fatal alert");
    try check(server.alert_received() == alert and server.alert_sent() == null and server.output_len() == 0, "the server did not read the client's alert, or answered it");
}

/// What the failed server wrote into output, output_len bytes, handed to
/// the client in its handshake: the client reads the alert as the server's
/// fatal alert and stages nothing for record_out.
fn serverAlertReachesClient(alert: chapulin.AlertDescription) !void {
    to_client.push(server.output_len());
    try check(serverToClient() == error.Proto, "the client read on after the server's fatal alert");
    try check(client.alert_received() == alert and client.alert_sent() == null, "the client did not read the server's alert");
    try check(client.record_out(to_server.free()) == error.Invalid, "the client answered the server's fatal alert");
}

/// Fresh sessions, with the ClientHello in to_server and nothing sent yet.
fn startPair() !void {
    try server.init(&serverValues(), &sni_buf, &server_handshake);
    try client.init(&clientValues(), &client_handshake);
    to_server = .{};
    to_client = .{};
    to_server.push(try client.record_out(to_server.free()));
}

/// Hands the ClientHello in to_server to the server, and the flight it
/// writes into to_client.
fn serverAnswersHello() !void {
    const progress = try server.record_in(to_server.pending(), to_client.free());
    to_server.pop(progress.consumed);
    to_client.push(progress.written);
}

/// Each side's handshake failure on each side of its write key. The alert
/// goes in the clear before the key, REC_HDR + 2 bytes, and sealed after,
/// alert_record_len bytes, and the other side reads it.
/// fail on a connected client: a description outside RFC 9846 §6.2's
/// error alerts is refused with nothing sent, record_overflow goes out as
/// one sealed alert that the server reads as the client's fatal alert, and
/// a second fail on the failed session is refused. An output too short
/// for the alert is refused on entry, with the session as it was.
fn callerFails() !void {
    try handshake(serverValues(), clientValues());
    to_server = .{};
    for ([_]u8{ 0, 90, 1, 255 }) |description| {
        try check(client.fail(@enumFromInt(description), to_server.free()) == error.Invalid, "fail took a description that is not an error alert");
    }
    try check(client.state() == .connected and client.alert_sent() == null, "a refused fail changed the session");
    const n = try client.fail(.record_overflow, to_server.free());
    to_server.push(n);
    try check(n == tcp.alert_record_len and client.state() == .failed and client.alert_sent() == .record_overflow, "fail did not send one sealed record_overflow");
    try check(client.fail(.record_overflow, to_server.free()) == error.Proto, "fail sent on a failed session");
    try check(server.read(to_server.pending(), &reply) == error.Proto, "the server read on after the client's fatal alert");
    try check(server.alert_received() == .record_overflow and server.alert_sent() == null and server.reply_len() == 0, "the server did not read the client's record_overflow, or answered it");

    try handshake(serverValues(), clientValues());
    var short: [tcp.alert_record_len - 1]u8 = undefined;
    try check(client.fail(.decode_error, &short) == error.Invalid and client.state() == .connected and client.alert_sent() == null, "fail into a short output changed the session");
    try check(client.end(&short) == error.Invalid and client.state() == .connected, "end into a short output changed the session");
}

fn failureAlerts() !void {
    // The client, before its key: the ServerHello selects a suite the
    // client did not offer, TLS_AES_128_CCM_SHA256, which no build offers.
    // Its cipher_suite follows the record and message headers,
    // legacy_version, random and the empty legacy_session_id_echo, and
    // holds the suite the server's default order picked: ChaCha20, or
    // AES-256-GCM in a host object whose server states the AES instructions
    // (docs/decisions.md 80 and 89).
    try startPair();
    try serverAnswersHello();
    const suite_at = c.REC_HDR + 4 + 2 + 32 + 1;
    const flight = to_client.pending();
    const picked = std.mem.readInt(u16, flight[suite_at..][0..2], .big);
    try check(picked == c.SUITE_CHACHA20_POLY1305_SHA256 or picked == c.SUITE_AES_256_GCM_SHA384, "the ServerHello's cipher_suite is not a default pick where the test looks");
    flight[suite_at + 1] = 0x04;
    try check(serverToClient() == error.Proto, "the client took a suite it did not offer");
    const refused_hello = client.alert_sent() orelse return error.NoAlertSent;
    try clientAlertReachesServer(refused_hello, c.REC_HDR + 2);

    // The server, before its key: a first message whose type is the
    // ServerHello's. Its unexpected_message goes into output in the clear.
    try startPair();
    to_server.pending()[c.REC_HDR] = 2;
    try check(server.record_in(to_server.pending(), to_client.free()) == error.Proto, "the server took a ServerHello as its first message");
    try check(server.alert_sent() == .unexpected_message and server.output_len() == c.REC_HDR + 2, "the server did not write unexpected_message in the clear");
    try serverAlertReachesClient(.unexpected_message);

    // The server, under its application write key: the client Finished
    // with one bit of its tag flipped. Its bad_record_mac goes into output
    // sealed, and the connected client reads it with read and replies with
    // nothing.
    try startPair();
    try serverAnswersHello();
    try serverToClient();
    to_server.push(try client.record_out(to_server.free()));
    try check(client.state() == .connected, "the client did not connect once its Finished went out");
    const finished = to_server.pending();
    finished[finished.len - 1] ^= 1;
    try check(server.record_in(finished, to_client.free()) == error.Proto, "the server took a Finished whose tag does not verify");
    try check(server.alert_sent() == .bad_record_mac and server.output_len() == tcp.alert_record_len, "the server did not write a sealed bad_record_mac");
    to_client.push(server.output_len());
    try check(client.read(to_client.pending(), &reply) == error.Proto, "the client read on after the server's fatal alert");
    try check(client.alert_received() == .bad_record_mac and client.alert_sent() == null and client.reply_len() == 0, "the client did not read the server's alert, or answered it");
}

pub fn run() !void {
    try handshake(serverValues(), clientValues());
    const alpn_ok = std.mem.eql(u8, client.alpn_selected() orelse "", http11) and std.mem.eql(u8, server.alpn_selected() orelse "", http11);
    try check(alpn_ok, "ALPN did not select http/1.1 on both ends");
    try check(std.mem.eql(u8, server.sni() orelse "", fixture.hostname()), "the server did not report the hostname");
    try check(client.group() == .x25519mlkem768 and server.group() == .x25519mlkem768, "the group is not X25519MLKEM768");
    try check(!client.psk_selected() and client.server_cert_type() == .x509, "the full handshake reports a PSK or a raw key");
    try fixture.clientTakesTickets(&fixture.tcpPriv(&client.tcp).t, true);
    const taken = try take_ticket();
    try exchange();
    try exporter();
    try closeBothWays();
    try resumeTicket(&taken);
    try ticketsOff(&taken);
    try refusals();
    try failureAlerts();
    try callerFails();
    try key_limit.run();
    try key_update_run.run();
    const across = if (key_limit.runs) ", each side's write across its AES-GCM write key's ceiling under both AES-GCM suites" else "";
    std.debug.print("a tcp-nonblocking client and server ran through the API at CH_TX_PT {d}: a handshake, {d} bytes each way, two frames of a header and a payload sealed where they lie, a resumed ticket, a stale one refused, a client that takes no tickets, first with no ticket and then with one it resumes, both closes, four refusals, each side's failure alert on each side of its write key{s}, and error.KeyUpdateLimit for one KeyUpdate past a run of {d}\n", .{ c.CH_TX_PT, payload.len, across, c.CH_KEY_UPDATE_RUN_MAX });
}
