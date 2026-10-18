//! The run limit of a record-mode pair (docs/decisions.md 138): the server
//! reads CH_KEY_UPDATE_RUN_MAX KeyUpdates in a row, one a call, and its read
//! of one more returns error.KeyUpdateLimit. test/session_update_run_tests.h
//! and test/tcp_nonblocking_record_end_tests.h check the C calls; this
//! checks read's error set. fromCode panics on a code that set does not
//! name (chapulin.zig), so a set without KeyUpdateLimit would let one
//! peer stop the process.
//!
//! No call sends a KeyUpdate alone: write sends one before its data when
//! an answer is owed. So the test sets the client's key_update_owed before
//! each write of one byte, hands the server the KeyUpdate record, and drops
//! the data record, which would end the run. That record took sequence
//! number 0 of the client's next key, so the test also moves the server's
//! read sequence number past it. The API promises nothing about a
//! session's fields (docs/zig.md, "What stays out").
const chapulin = @import("chapulin");
const fixture = @import("fixture.zig");
const loop = @import("loop_record.zig");
const c = chapulin.c;
const check = fixture.check;
const record = chapulin.record;

/// CH_KEY_UPDATE_RUN_MAX (session.h).
const run_max: usize = c.CH_KEY_UPDATE_RUN_MAX;
/// The bytes rec_seal adds to each record (record.h).
const overhead: usize = c.REC_OVERHEAD;
/// One write of one byte while an answer is owed: the KeyUpdate record,
/// then a record of one byte.
const write_len = record.key_update_record_len + overhead + 1;

var wire: [write_len]u8 = undefined;
var got: [16]u8 = undefined;
/// Room for everything one read may send: the alert of a read that fails.
var reply: [record.alert_record_len]u8 = undefined;

/// A fresh pair. The client sends run_max + 1 KeyUpdates and no data, and
/// the server reads each one in a call of its own.
pub fn run() !void {
    try loop.handshake(loop.serverValues(), loop.clientValues());
    // The server's ticket, read before the run starts.
    _ = try loop.drain(&loop.client, &loop.to_client);
    for (0..run_max + 1) |i| {
        loop.client.record.t.key_update_owed = 1;
        const sent = try loop.client.write("k", &wire);
        try check(sent == write_len, "a write that owes an answer did not send a KeyUpdate record and a record of one byte");
        if (i > 0) loop.server.record.t.rd.seq = 1;
        const update = wire[0..record.key_update_record_len];
        if (i < run_max) {
            const r = try loop.server.read(update, &got, &reply);
            try check(r.consumed == update.len and r.pt_len == 0 and r.reply_len == 0, "the server did not read a KeyUpdate of the run as one record of no plaintext, or it sent a record");
        } else {
            try check(loop.server.read(update, &got, &reply) == error.KeyUpdateLimit, "the KeyUpdate past a full run did not fail read with error.KeyUpdateLimit");
        }
    }
    try check(loop.server.recordState() == .failed and loop.server.alertSent() == 10, "the run limit did not fail the server with unexpected_message");
    try check(loop.server.replyLen() == record.alert_record_len, "the server's failed read did not send its alert record");
    loop.client.recordClose();
    loop.server.recordClose();
}
