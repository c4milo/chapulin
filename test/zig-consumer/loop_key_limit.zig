//! Each side of a record-mode pair writing across its AES-GCM write key's
//! ceiling, in a SUITE=aesgcm object (docs/decisions.md 78). An AES-GCM
//! write key seals at most REC_AES_GCM_RECORDS_MAX records (record.h), and
//! ch_write sends the KeyUpdate that retires the key as the last of them.
//! test/key_limit_cases.h checks the C calls; this checks the Zig calls
//! over them. The test writes the writer's write sequence number and the
//! reader's read sequence number two records below the ceiling, and every
//! step after that goes through the API alone. Under each AES-GCM suite:
//!
//! - writableLen counts no KeyUpdate record for the one data record the
//!   key has left, and counts one for the record after it, to the byte;
//! - write refuses whole a write across the ceiling into one byte less
//!   than its records, and then seals it into exactly its records: the
//!   first record, one KeyUpdate record of key_update_record_len bytes
//!   and the second record;
//! - read returns the plaintext on both sides of the KeyUpdate, reads the
//!   KeyUpdate record as a record of no plaintext, and sends nothing into
//!   reply, because the KeyUpdate's request_update is 0;
//! - neither side reports an alert;
//! - the next write sends no KeyUpdate, and the reader reads it under the
//!   key the KeyUpdate moved it to.
const std = @import("std");
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const loop = @import("loop_record.zig");
const c = chapulin.c;
const check = fixture.check;
const record = chapulin.record;

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
/// Room for everything one read may send: a KeyUpdate answer and an alert.
var reply: [record.key_update_record_len + record.alert_record_len]u8 = undefined;

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
        loop.client.recordClose();
        loop.server.recordClose();
    }
}

/// writer writes across its write key's ceiling into wire, and reader
/// reads what arrives.
fn crossCeiling(writer: anytype, reader: anytype, wire: *loop.Pipe) !void {
    try check(wire.pending().len == 0 and writer.peerLimit() >= per_record, "the pipe holds bytes, or the peer's limit is below CH_TX_PT");
    // No call of the API sets a sequence number, and writing up to the
    // ceiling would seal 2^24 - 2 records per direction and suite. So the
    // test writes the two fields, as test/key_limit_cases.h does in C, with
    // the values those records would leave. The API promises nothing about
    // a session's fields (docs/zig.md, "What stays out").
    writer.record.t.wr.seq = ceiling - 2;
    reader.record.t.rd.seq = ceiling - 2;

    // The key has one data record left, so a write of one record sends no
    // KeyUpdate. A second record goes out after the KeyUpdate record: it
    // fits once the KeyUpdate record and its own overhead fit beside the
    // first record, and not one byte sooner.
    const whole = per_record + overhead;
    const key_update = record.key_update_record_len;
    try check(writer.writableLen(whole) == per_record, "writableLen counted a KeyUpdate record one record before the ceiling");
    const second = whole + key_update + overhead;
    try check(writer.writableLen(second) == per_record and writer.writableLen(second + 1) == per_record + 1, "writableLen did not count the KeyUpdate record at the ceiling");

    // One write across the ceiling, into exactly the bytes writableLen
    // counts for it: the first record, the KeyUpdate record and a second
    // record of rest bytes. One byte fewer is refused whole.
    const rest = data.len - per_record;
    const sealed = second + rest;
    try check(writer.writableLen(sealed) == data.len and writer.writableLen(sealed - 1) == data.len - 1, "writableLen does not match the write across the ceiling");
    try check(writer.write(&data, wire.free()[0 .. sealed - 1]) == error.Cap, "a write across the ceiling into one byte less than its records was not refused");
    const written = try writer.write(&data, wire.free()[0..sealed]);
    try check(written == sealed, "write did not count the KeyUpdate record among the bytes it sealed");
    wire.push(written);

    // The reader reads the first record under the old key, the KeyUpdate
    // record, which carries no plaintext and asks for no answer, and the
    // second record under the next key.
    const records = [_]struct { usize, usize }{ .{ whole, per_record }, .{ key_update, 0 }, .{ rest + overhead, rest } };
    var at: usize = 0;
    for (records) |want| {
        const r = try reader.read(wire.pending(), got[at..], &reply);
        wire.pop(r.consumed);
        at += r.pt_len;
        try check(r.consumed == want[0] and r.pt_len == want[1] and r.reply_len == 0, "the reader did not read one record, one KeyUpdate record and one record, or it answered");
    }
    try check(wire.pending().len == 0 and std.mem.eql(u8, got[0..at], &data), "the plaintext read across the ceiling differs from what was written");
    try checkNoAlerts(writer, reader);

    // The next write, under the next key, sends no KeyUpdate.
    const next = "under the next key";
    try check(writer.writableLen(next.len + overhead) == next.len, "writableLen counted a KeyUpdate record under the next key");
    const sent = try writer.write(next, wire.free());
    wire.push(sent);
    const r = try reader.read(wire.pending(), &got, &reply);
    wire.pop(r.consumed);
    try check(sent == next.len + overhead and r.consumed == sent and r.reply_len == 0, "the write after the ceiling sent more than one record");
    try check(std.mem.eql(u8, got[0..r.pt_len], next), "the write after the ceiling did not read back");
    try checkNoAlerts(writer, reader);
}

/// Both sessions still connected, and neither has sent or received an
/// alert.
fn checkNoAlerts(a: anytype, b: anytype) !void {
    try check(a.recordState() == .connected and b.recordState() == .connected, "a session left the connected state across the ceiling");
    try check(a.alertSent() == null and a.alertReceived() == null, "the writer reported an alert across the ceiling");
    try check(b.alertSent() == null and b.alertReceived() == null, "the reader reported an alert across the ceiling");
}
