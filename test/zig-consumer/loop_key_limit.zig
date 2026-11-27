//! Each side of a tcp-nonblocking pair writing across its AES-GCM write key's
//! ceiling, in a SUITE=aesgcm object (docs/decisions.md 78 and 248). An
//! AES-GCM write key seals at most REC_AES_GCM_RECORDS_MAX records
//! (record.h). seal changes the key before a write whose records the key
//! cannot all seal: it writes the KeyUpdate into side, and every record of
//! the write goes out under the next key. test/key_limit_cases.h checks the
//! C calls; this checks the Zig calls over them. The test writes the
//! writer's write sequence number and the reader's read sequence number two
//! records below the ceiling, and every step after that goes through the
//! API alone. Under each AES-GCM suite:
//!
//! - writable_len counts no KeyUpdate record, because seal writes it into
//!   side;
//! - a seal of the one data record the key has left writes no KeyUpdate;
//! - the next seal, of two records, refuses whole a buffer one byte less
//!   than its records, and then writes the KeyUpdate, at the key's last
//!   sequence number, into side and both records under the next key;
//! - read reads the KeyUpdate record as a record of no plaintext, then the
//!   two records, and sends nothing into reply: this KeyUpdate's
//!   request_update is 0, so the reader owes none;
//! - neither side reports an alert;
//! - the next seal writes no KeyUpdate, and the reader reads it under the
//!   key the KeyUpdate moved it to.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const loop = @import("loop_record.zig");
const c = chapulin.c;
const check = fixture.check;
const tcp = chapulin.tcp;

/// Whether the object seals records under AES-GCM: only a SUITE=aesgcm
/// object holds the AES-GCM suites, and only its server takes a suite
/// order (srv_cfg.h).
pub const runs = @hasField(c.ch_srv_cfg, "cipher_suites");

/// REC_AES_GCM_RECORDS_MAX, 2^24 (record.h). chapulin.c declares it, and
/// matches.zig requires that, because tls.h's comments name it
/// (tools/public-constants.py).
const ceiling: u64 = c.REC_AES_GCM_RECORDS_MAX;
/// The plaintext of one record here. The loop's receive buffer lets each
/// side's record_size_limit allow at least CH_TX_PT bytes, so records
/// carry CH_TX_PT bytes each.
const per_record: usize = c.CH_TX_PT;
/// The bytes rec_seal adds to each record: the header, the inner content
/// type and the tag (record.h).
const overhead: usize = c.REC_OVERHEAD;

/// One write of two records: a whole record, then 100 bytes.
var data: [per_record + 100]u8 = undefined;
var got: [data.len]u8 = undefined;
/// Room for everything one read may send: the alert of a read that fails.
var reply: [tcp.alert_record_len]u8 = undefined;

/// Each server selects the one suite its list names.
const aes_128 = [_]chapulin.Suite{.aes_128_gcm_sha256};
const aes_256 = [_]chapulin.Suite{.aes_256_gcm_sha384};

/// Under each AES-GCM suite, a fresh pair whose server selects it. The
/// client writes across its ceiling, then the server across its own.
pub fn run() !void {
    if (!runs) return;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i *% 5 +% 1);
    for ([_][]const chapulin.Suite{ &aes_128, &aes_256 }) |suites| {
        var values = loop.serverValues();
        values.cipher_suites = suites;
        try loop.handshake(values, loop.clientValues());
        try check(loop.client.suite() == suites[0] and loop.server.suite() == suites[0], "the server did not select the AES-GCM suite its list names");
        // The server's ticket, read before the client's read sequence
        // number is moved.
        _ = try loop.drain(&loop.client, &loop.to_client);
        try crossCeiling(&loop.client, &loop.server, &loop.to_server);
        try crossCeiling(&loop.server, &loop.client, &loop.to_client);
        loop.client.close();
        loop.server.close();
    }
}

/// writer writes across its write key's ceiling into wire, and reader
/// reads what arrives.
fn crossCeiling(writer: anytype, reader: anytype, wire: *loop.Pipe) !void {
    try check(wire.pending().len == 0 and writer.peer_limit() >= per_record, "the pipe holds bytes, or the peer's limit is below CH_TX_PT");
    // No call of the API sets a sequence number, and writing up to the
    // ceiling would seal 2^24 - 2 records per direction and suite. So the
    // test writes the two fields, as test/key_limit_cases.h does in C, with
    // the values those records would leave. The API promises nothing about
    // a session's fields (docs/zig.md, "What stays out").
    fixture.tcpPriv(&writer.tcp).t.wr.seq = ceiling - 2;
    fixture.tcpPriv(&reader.tcp).t.rd.seq = ceiling - 2;

    // writable_len counts no KeyUpdate record: seal writes it into side.
    const whole = per_record + overhead;
    const key_update = tcp.key_update_record_len;
    try check(writer.writable_len(whole) == per_record and writer.writable_len(2 * whole) == 2 * per_record, "writable_len counted a KeyUpdate record");

    // The key has one data record left, so a seal of one record writes no
    // KeyUpdate.
    const one = try loop.seal_in(writer, wire, data[0..per_record], whole);
    try check(one == whole, "a seal of the key's last data record wrote a KeyUpdate record");
    try readRecords(reader, wire, &.{.{ whole, per_record }}, data[0..per_record]);

    // The key has no data record left. A seal of two records into one byte
    // less than its records is refused whole; into exactly its records it
    // writes the KeyUpdate into side, under the old key's last sequence
    // number, and both records under the next key.
    const rest = data.len - per_record;
    const sealed = data.len + 2 * overhead;
    try check(writer.writable_len(sealed) == data.len and writer.writable_len(sealed - 1) == data.len - 1, "writable_len does not match the seal across the ceiling");
    try check(loop.seal_in(writer, wire, &data, sealed - 1) == error.Cap, "a seal across the ceiling into one byte less than its records was not refused");
    try check(wire.pending().len == 0 and fixture.tcpPriv(&writer.tcp).t.wr.seq == ceiling - 1, "a refused seal sealed a record");
    const written = try loop.seal_in(writer, wire, &data, sealed);
    try check(written == key_update + sealed, "seal did not write one KeyUpdate record into side and the two records");
    try readRecords(reader, wire, &.{ .{ key_update, 0 }, .{ whole, per_record }, .{ rest + overhead, rest } }, &data);
    try checkNoAlerts(writer, reader);

    // The next seal, under the next key, writes no KeyUpdate.
    const next = "under the next key";
    try check(writer.writable_len(next.len + overhead) == next.len, "writable_len counted a KeyUpdate record under the next key");
    const sent = try loop.seal_to(writer, wire, next);
    try check(sent == next.len + overhead, "the seal after the ceiling wrote more than one record");
    try readRecords(reader, wire, &.{.{ sent, next.len }}, next);
    try checkNoAlerts(writer, reader);
}

/// reader reads one record of wire for each entry of records, each with
/// the length and plaintext length it names and no reply, and what it read
/// is want.
fn readRecords(reader: anytype, wire: *loop.Pipe, records: []const struct { usize, usize }, want: []const u8) !void {
    var at: usize = 0;
    for (records) |one| {
        const r = try reader.read(wire.pending(), &reply);
        @memcpy(got[at..][0..r.plaintext.len], r.plaintext);
        at += r.plaintext.len;
        wire.pop(r.consumed);
        try check(r.consumed == one[0] and r.plaintext.len == one[1] and r.reply_len == 0, "the reader did not read the records the writer sealed, or it answered");
    }
    try check(wire.pending().len == 0 and std.mem.eql(u8, got[0..at], want), "the plaintext read across the ceiling differs from what was written");
}

/// Both sessions still connected, and neither has sent or received an
/// alert.
fn checkNoAlerts(a: anytype, b: anytype) !void {
    try check(a.state() == .connected and b.state() == .connected, "a session left the connected state across the ceiling");
    try check(a.alert_sent() == null and a.alert_received() == null, "the writer reported an alert across the ceiling");
    try check(b.alert_sent() == null and b.alert_received() == null, "the reader reported an alert across the ceiling");
}
