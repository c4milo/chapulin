//! A record-mode client and server of one tcp-nonblocking ROLE=both object
//! against each other, through the API alone: the handshake, ALPN, the
//! server name, data both ways across several records, a write that does
//! not fit, the exporter, a ticket taken and resumed through
//! Ticket.fromFields, a stale ticket refused, close in each direction and
//! recordClose, four refusals, the last of whose alerts the server reads
//! as the client's fatal alert and does not answer, and each side's
//! handshake failure before and after its write key, whose alert record the
//! other side reads. At TX_RECORD=16384 the records carry CH_TX_PT bytes
//! each. Under SUITE=aesgcm, loop_key_limit.zig then has each side write
//! across its AES-GCM write key's ceiling.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const key_limit = @import("loop_key_limit.zig");
const c = chapulin.c;
const check = fixture.check;
const record = chapulin.record;

/// colibri's receive length (docs/zig.md).
const receive_len = 20_480;
pub var client: record.Client(receive_len) = undefined;
pub var server: record.Server(receive_len) = undefined;
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
const client_alpn = [_]c.ch_alpn_protocol{ chapulin.alpnProtocol("h2"), chapulin.alpnProtocol(http11) };
const server_alpn = [_]c.ch_alpn_protocol{chapulin.alpnProtocol(http11)};
/// The server's clock, which it writes into tickets and judges them by.
const server_now = 1_700_000_000;

pub fn clientValues() chapulin.Client {
    return .{ .trust = fixture.trust(.root, null), .alpn = &client_alpn, .random = fixture.clientRandom(), .aes_instructions = fixture.aesAnswer(), .widemul = fixture.widemulAnswer() };
}

/// The server each handshake below runs against.
pub fn serverValues() chapulin.Server {
    return fixture.server(&server_alpn, server_now);
}

/// Moves what the client staged into the server, and what the server
/// wrote into its pipe. Returns the bytes of the server's flight.
fn clientToServer() !usize {
    to_server.push(try client.recordOut(to_server.free()));
    if (to_server.pending().len == 0) return 0;
    const progress = try server.recordIn(to_server.pending(), to_client.free());
    to_server.pop(progress.consumed);
    to_client.push(progress.written);
    return progress.written;
}

fn serverToClient() !void {
    if (to_client.pending().len == 0) return;
    to_client.pop(try client.recordIn(to_client.pending()));
}

/// One handshake between fresh sessions. The client is connected once
/// recordOut has handed its Finished over, and what the server writes
/// after that, the ticket, is read with read.
pub fn handshake(server_values: chapulin.Server, values: chapulin.Client) !void {
    to_server = .{};
    to_client = .{};
    try server.init(server_values, &sni_buf);
    try client.init(values);
    for (0..4) |_| {
        _ = try clientToServer();
        if (client.recordState() == .connected) break;
        try serverToClient();
    }
    try check(client.recordState() == .connected and server.recordState() == .connected, "the handshake did not connect both ends");
}

var received: [1 << 16]u8 = undefined;
var reply: [256]u8 = undefined;

/// Reads everything wire holds through reader's read, one record at a
/// time, and returns the plaintext and the number of records that
/// carried some.
pub fn drain(reader: anytype, wire: *Pipe) !struct { []const u8, usize } {
    var got: usize = 0;
    var records: usize = 0;
    while (true) {
        const r = try reader.read(wire.pending(), received[got..], &reply);
        wire.pop(r.consumed);
        got += r.pt_len;
        if (r.consumed > 0 and r.pt_len > 0) records += 1;
        if (r.consumed == 0 and r.pt_len == 0) break;
    }
    return .{ received[0..got], records };
}

/// data from writer to reader in one write, across records.
fn transfer(writer: anytype, reader: anytype, wire: *Pipe, data: []const u8) !usize {
    wire.push(try writer.write(data, wire.free()));
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

    // A write one byte past what the output holds seals nothing and
    // leaves the session connected; the same write into the whole
    // output then reads back, so no record was sealed in between.
    const message = "one record";
    const sealed = try client.write(message, to_server.free());
    to_server.push(sealed);
    try check(client.writableLen(sealed) == message.len and client.writableLen(sealed - 1) < message.len, "writableLen does not match what write sealed");
    const refused = client.write(message, to_server.free()[0 .. sealed - 1]);
    try check(refused == error.Cap and client.recordState() == .connected, "a write that did not fit was not refused whole");
    to_server.push(try client.write(message, to_server.free()[0..sealed]));
    const got, _ = try drain(&server, &to_server);
    try check(std.mem.eql(u8, got, message ++ message), "a refused write sealed part of its plaintext");
}

fn exporter() !void {
    if (!@hasDecl(c, "ch_export")) return;
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try client.exportKeyingMaterial("EXPORTER-Channel-Binding", "", &a);
    try server.exportKeyingMaterial("EXPORTER-Channel-Binding", "", &b);
    try check(std.mem.eql(u8, &a, &b), "the two ends export different keying material");
}

/// The server's ticket, through read and takeTicket, and the slot zeroed.
fn takeTicket() !chapulin.Ticket {
    _ = try drain(&client, &to_client);
    const taken = client.takeTicket() orelse return error.NoTicket;
    try check(fixture.zeroed(&client.ticket), "takeTicket left bytes in the ticket slot");
    try check(taken.ticket.lifetime_s > 0 and taken.ticket.identity == null, "the ticket lost its lifetime or kept an identity pointer");
    return taken;
}

/// The client closes its direction, and the server reads that close_notify
/// and still writes, as RFC 9846 section 6.1 leaves its direction open,
/// then closes its own. A side that sent its close_notify has wiped its
/// keys, so it reads no more.
fn closeBothWays() !void {
    const sent = try client.close(to_server.free());
    to_server.push(sent);
    try check(sent == record.alert_record_len and client.recordState() == .closed, "close did not send one alert record");
    const r = try server.read(to_server.pending(), &received, &reply);
    to_server.pop(r.consumed);
    try check(r.peer_closed and server.readClosed() and server.recordState() == .connected, "the server did not read the client's close_notify");
    to_client.push(try server.write("after", to_client.free()));
    to_client.push(try server.close(to_client.free()));
    const back = try client.read(to_client.pending(), &received, &reply);
    try check(back.peer_closed and back.consumed == 0, "a closed client read on");
    client.recordClose();
    server.recordClose();
    try check(server.recordState() == .closed, "recordClose left the session open");
}

/// Resumes with the ticket rebuilt from its fields, at ages around the
/// lifetime, then closes.
fn resumeTicket(taken: *const chapulin.Ticket) !void {
    const ticket = try fixture.stored(taken);
    var values = clientValues();
    values.ticket = &ticket;
    values.ticket_age_ms = 1000;
    try handshake(serverValues(), values);
    try check(client.pskSelected() and server.pskSelected(), "the ticket did not resume");
    // The next ticket sits in the slot, and recordClose zeroes it.
    _ = try drain(&client, &to_client);
    try check(client.ticket != null, "the resumed session received no ticket");
    client.recordClose();
    try check(fixture.zeroed(&client.ticket), "recordClose left the ticket in the slot");

    // An age of exactly the lifetime is still offered, and one
    // millisecond more is refused before a byte is sent (ticket.h).
    values.ticket_age_ms = @as(u64, ticket.ticket.lifetime_s) * 1000;
    try client.init(values);
    client.recordClose();
    values.ticket_age_ms += 1;
    try check(client.init(values) == error.Invalid and client.recordState() == .failed, "a stale ticket was not refused");
}

/// An anchor that did not sign the chain, a clock of 0 beside anchors,
/// a server output one byte short of its flight, and a record header
/// whose length no peer may send.
fn refusals() !void {
    if (@hasField(c.ch_cfg, "anchors")) {
        try server.init(serverValues(), &sni_buf);
        try client.init(.{ .trust = fixture.trust(.impostor, null), .alpn = &client_alpn, .random = fixture.clientRandom(), .aes_instructions = fixture.aesAnswer(), .widemul = fixture.widemulAnswer() });
        to_server = .{};
        to_client = .{};
        _ = try clientToServer();
        try check(serverToClient() == error.Auth, "an impostor anchor was not refused");
        try check(client.alertSent() == 48 and client.alertReceived() == null, "alertSent did not name the handshake's unknown_ca");
        // The client refused the Certificate after its write key went in,
        // so its unknown_ca is sealed.
        try clientAlertReachesServer(48, record.alert_record_len);
        try check(client.init(.{ .trust = fixture.trust(.root, 0), .random = fixture.clientRandom(), .aes_instructions = fixture.aesAnswer(), .widemul = fixture.widemulAnswer() }) == error.Invalid, "a clock of 0 was accepted");
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
    const refused = server.recordIn(to_server.pending(), short[0 .. flight_len - 1]);
    try check(refused == error.Io and server.recordState() == .failed, "a flight that did not fit was not refused");

    try handshake(serverValues(), clientValues());
    const oversize = [_]u8{ 0x17, 0x03, 0x03, 0xff, 0xff };
    const waiting = try client.read(oversize[0..4], &received, &reply);
    try check(waiting.consumed == 0 and waiting.pt_len == 0, "read took a part of a header");
    try check(client.read(&oversize, &received, &reply) == error.Proto, "read waited on a record no peer may send");
    // The client's read sent the alert its failure chose into reply, and
    // staged nothing for recordOut. The server reads that alert as the
    // peer's fatal alert and sends nothing back (RFC 9846 section 6.2).
    const sent = client.alertSent() orelse return error.NoAlertSent;
    try check(client.alertReceived() == null and client.recordOut(to_server.free()) == error.Invalid, "the client's failed read staged an alert or reported one received");
    var answer: [256]u8 = undefined;
    try check(server.read(reply[0..client.replyLen()], &received, &answer) == error.Proto, "the server read on after the client's fatal alert");
    try check(server.alertReceived() == sent and server.alertSent() == null and server.replyLen() == 0, "the server answered the client's fatal alert");
}

/// The failed client's alert record, handed to the server: recordOut
/// returns all len bytes of it, then error.Invalid, and the server reads it
/// as the client's fatal alert and writes nothing into output.
fn clientAlertReachesServer(alert: u8, len: usize) !void {
    to_server = .{};
    const n = try client.recordOut(to_server.free());
    to_server.push(n);
    try check(n == len and client.recordOut(to_server.free()) == error.Invalid, "recordOut did not return the client's alert record once");
    try check(server.recordIn(to_server.pending(), to_client.free()) == error.Proto, "the server read on after the client's fatal alert");
    try check(server.alertReceived() == alert and server.alertSent() == null and server.outputLen() == 0, "the server did not read the client's alert, or answered it");
}

/// What the failed server wrote into output, outputLen bytes, handed to
/// the client in its handshake: the client reads the alert as the server's
/// fatal alert and stages nothing for recordOut.
fn serverAlertReachesClient(alert: u8) !void {
    to_client.push(server.outputLen());
    try check(serverToClient() == error.Proto, "the client read on after the server's fatal alert");
    try check(client.alertReceived() == alert and client.alertSent() == null, "the client did not read the server's alert");
    try check(client.recordOut(to_server.free()) == error.Invalid, "the client answered the server's fatal alert");
}

/// Fresh sessions, with the ClientHello in to_server and nothing sent yet.
fn startPair() !void {
    try server.init(serverValues(), &sni_buf);
    try client.init(clientValues());
    to_server = .{};
    to_client = .{};
    to_server.push(try client.recordOut(to_server.free()));
}

/// Hands the ClientHello in to_server to the server, and the flight it
/// writes into to_client.
fn serverAnswersHello() !void {
    const progress = try server.recordIn(to_server.pending(), to_client.free());
    to_server.pop(progress.consumed);
    to_client.push(progress.written);
}

/// Each side's handshake failure on each side of its write key. The alert
/// goes in the clear before the key, REC_HDR + 2 bytes, and sealed after,
/// alert_record_len bytes, and the other side reads it.
fn failureAlerts() !void {
    // The client, before its key: the ServerHello selects a suite the
    // client did not offer, TLS_AES_128_CCM_SHA256, which no build offers.
    // Its cipher_suite follows the record and message headers,
    // legacy_version, random and the empty legacy_session_id_echo, and
    // holds the suite the server's default order picked: ChaCha20, or
    // AES-256-GCM on AES=hw (docs/decisions.md 80).
    try startPair();
    try serverAnswersHello();
    const suite_at = c.REC_HDR + 4 + 2 + 32 + 1;
    const flight = to_client.pending();
    const picked = std.mem.readInt(u16, flight[suite_at..][0..2], .big);
    try check(picked == c.SUITE_CHACHA20_POLY1305_SHA256 or picked == c.SUITE_AES_256_GCM_SHA384, "the ServerHello's cipher_suite is not a default pick where the test looks");
    flight[suite_at + 1] = 0x04;
    try check(serverToClient() == error.Proto, "the client took a suite it did not offer");
    const refused_hello = client.alertSent() orelse return error.NoAlertSent;
    try clientAlertReachesServer(refused_hello, c.REC_HDR + 2);

    // The server, before its key: a first message whose type is the
    // ServerHello's. Its unexpected_message goes into output in the clear.
    try startPair();
    to_server.pending()[c.REC_HDR] = 2;
    try check(server.recordIn(to_server.pending(), to_client.free()) == error.Proto, "the server took a ServerHello as its first message");
    try check(server.alertSent() == 10 and server.outputLen() == c.REC_HDR + 2, "the server did not write unexpected_message in the clear");
    try serverAlertReachesClient(10);

    // The server, under its application write key: the client Finished
    // with one bit of its tag flipped. Its bad_record_mac goes into output
    // sealed, and the connected client reads it with read and replies with
    // nothing.
    try startPair();
    try serverAnswersHello();
    try serverToClient();
    to_server.push(try client.recordOut(to_server.free()));
    try check(client.recordState() == .connected, "the client did not connect once its Finished went out");
    const finished = to_server.pending();
    finished[finished.len - 1] ^= 1;
    try check(server.recordIn(finished, to_client.free()) == error.Proto, "the server took a Finished whose tag does not verify");
    try check(server.alertSent() == 20 and server.outputLen() == record.alert_record_len, "the server did not write a sealed bad_record_mac");
    to_client.push(server.outputLen());
    try check(client.read(to_client.pending(), &received, &reply) == error.Proto, "the client read on after the server's fatal alert");
    try check(client.alertReceived() == 20 and client.alertSent() == null and client.replyLen() == 0, "the client did not read the server's alert, or answered it");
}

pub fn run() !void {
    try handshake(serverValues(), clientValues());
    const alpn_ok = std.mem.eql(u8, client.alpnSelected() orelse "", http11) and std.mem.eql(u8, server.alpnSelected() orelse "", http11);
    try check(alpn_ok, "ALPN did not select http/1.1 on both ends");
    try check(std.mem.eql(u8, server.sni() orelse "", fixture.hostname()), "the server did not report the hostname");
    try check(client.group() == .x25519mlkem768 and server.group() == .x25519mlkem768, "the group is not X25519MLKEM768");
    try check(!client.pskSelected() and client.serverCertType() == .x509, "the full handshake reports a PSK or a raw key");
    const taken = try takeTicket();
    try exchange();
    try exporter();
    try closeBothWays();
    try resumeTicket(&taken);
    try refusals();
    try failureAlerts();
    try key_limit.run();
    const across = if (key_limit.runs) ", and each side's write across its AES-GCM write key's ceiling under both AES-GCM suites" else "";
    std.debug.print("a record-mode client and server ran through the API at CH_TX_PT {d}: a handshake, {d} bytes each way, a resumed ticket, a stale one refused, both closes, four refusals and each side's failure alert on each side of its write key{s}\n", .{ c.CH_TX_PT, payload.len, across });
}
