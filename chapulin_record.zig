//! Record-mode sessions over a TRANSPORT=tcp-nonblocking object: the
//! handshake through recordIn and recordOut, then read, write and close,
//! each a C call of tcp_nonblocking.h, srv_tcp_nonblocking.h or tls.h
//! (docs/zig.md).
//!
//! C calls cfg.send and cfg.recv from ch_read, ch_write and ch_close. The
//! API's own send and recv copy between those callbacks and the slices of
//! the one call that is running, so no callback blocks and no byte waits
//! in the session between calls.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

// tcp_nonblocking.h declares ch_record_init only in an object with a client,
// which alone defines it.
const has_client = @hasDecl(c, "ch_record_init");
const has_server = @hasDecl(c, "ch_srv_record_init");
const has_record = @hasDecl(c, "ch_record_whole_len");

/// A client whose receive buffer, cfg.buf, holds receive_len bytes. Do not
/// move it after init: cfg.io points at its hook.
pub const Client = if (has_client) clientOf else @compileError("record.Client needs TRANSPORT=tcp-nonblocking with ROLE=client or ROLE=both");
fn clientOf(comptime receive_len: usize) type {
    return Session(.client, receive_len);
}

/// A server with the same storage, less the ticket slot.
pub const Server = if (has_server) serverOf else @compileError("record.Server needs TRANSPORT=tcp-nonblocking with ROLE=server or ROLE=both");
fn serverOf(comptime receive_len: usize) type {
    return Session(.server, receive_len);
}

/// What a server's recordIn did: input bytes it took, and bytes of its
/// flight it wrote into output.
pub const Progress = struct { consumed: usize, written: usize };

/// What read did. consumed: input bytes taken, 0, one whole record, or the
/// 5-byte header of a record whose length field no peer may send. pt_len:
/// plaintext written into pt, 0 when the record held a ticket or a
/// KeyUpdate. reply_len: bytes ch_read sent into reply. peer_closed: ch_read
/// returned 0, because the peer's close_notify arrived, now or earlier, or
/// this side closed.
pub const Read = struct { consumed: usize, pt_len: usize, reply_len: usize, peer_closed: bool };

/// The wire length of one sealed alert record, 24 bytes: what close
/// writes, and what a read that fails adds to reply (CH_ALERT_RECORD_LEN).
pub const alert_record_len: usize = if (has_record) c.CH_ALERT_RECORD_LEN else @compileError("alert_record_len needs TRANSPORT=tcp-nonblocking");

/// The wire length of one sealed KeyUpdate record, 27 bytes
/// (CH_KEY_UPDATE_RECORD_LEN). ch_read answers a KeyUpdate that asks for
/// an answer, and a record carries at most one KeyUpdate, as its last
/// message (RFC 9846 §5.1), so a read of one record writes at most one of
/// these into reply, and alert_record_len more if it fails.
pub const key_update_record_len: usize = if (has_record) c.CH_KEY_UPDATE_RECORD_LEN else @compileError("key_update_record_len needs TRANSPORT=tcp-nonblocking");

const Side = enum { client, server };

/// The slices the API's send and recv copy between during one call.
const Io = struct {
    /// What recv hands to ch_read, and how many bytes it has handed out.
    input: []const u8 = &.{},
    taken: usize = 0,
    /// Where send and on_record_out copy what C sends, and how many bytes
    /// they hold.
    output: []u8 = &.{},
    written: usize = 0,
    /// Set when send could not take all of what C sent.
    refused: bool = false,
    /// Bytes the last read wrote into reply.
    reply_len: usize = 0,

    fn begin(io: *Io, input: []const u8, output: []u8) void {
        io.input = input;
        io.taken = 0;
        io.output = output;
        io.written = 0;
        io.refused = false;
    }

    /// Drops the borrowed slices, so no callback outside a call reads them.
    fn end(io: *Io) void {
        io.input = &.{};
        io.output = &.{};
    }

    fn put(io: *Io, bytes: []const u8) c_int {
        if (bytes.len > io.output.len - io.written) {
            io.refused = true;
            return -1;
        }
        @memcpy(io.output[io.written..][0..bytes.len], bytes);
        io.written += bytes.len;
        return 0;
    }

    fn take(io: *Io, into: []u8) c_int {
        const n = @min(into.len, io.input.len - io.taken);
        @memcpy(into[0..n], io.input[io.taken..][0..n]);
        io.taken += n;
        return @intCast(n);
    }
};

fn Session(comptime side: Side, comptime receive_len: usize) type {
    return struct {
        const Self = @This();

        /// The C session. The API promises nothing about its fields.
        record: c.ch_record,
        /// The receive buffer, cfg.buf.
        receive: [receive_len]u8,
        /// What cfg.io points at.
        hook: chapulin.Hook,
        /// The slices the API's callbacks copy between during one call.
        io: Io,
        /// The latest ticket on_ticket copied. A server has none.
        ticket: if (side == .client) ?chapulin.Ticket else void,

        /// Client: Client.toCfg, then ch_record_init with the API's send,
        /// recv and on_ticket. Server: Server.toCfg, then
        /// ch_srv_record_init with the API's send, recv and on_record_out;
        /// sni_buf is where this connection's server_name is copied
        /// (srv.sni_buf, srv.sni_cap). On error.Invalid the session is
        /// failed until the next init.
        pub const init = if (side == .client) initClient else initServer;
        /// Client: ch_record_in. Server: ch_srv_record_in, which writes the
        /// server's flight into output.
        pub const recordIn = if (side == .client) recordInClient else recordInServer;
        /// ch_record_out: bytes the client owes, 0 when it owes none.
        pub const recordOut = if (side == .client) recordOutClient else @compileError("a server writes its flight from recordIn");
        /// Moves the latest ticket out and zeroes the slot.
        pub const takeTicket = if (side == .client) takeTicketClient else @compileError("a server receives no ticket");
        /// The server_name the client sent: sni_buf[0..ch_tls.sni_len], null when 0.
        pub const sni = if (side == .server) sniServer else @compileError("a client sends server_name and reports none");
        /// ch_export (EXPORTER=on).
        pub const exportKeyingMaterial = if (@hasDecl(c, "ch_export")) exportOf else @compileError("exportKeyingMaterial needs EXPORTER=on");
        /// The protocol ALPN selected, null for CH_ALPN_NONE.
        pub const alpnSelected = if (@hasField(c.ch_tls, "alpn_selected")) alpnSelectedOf else @compileError("alpnSelected needs TRUST=webpki or a server role");
        /// ch_tls.suite, null while 0. A client offers ChaCha20 alone
        /// outside SUITE=aesgcm and writes no suite there.
        pub const suite = if (@hasField(c.ch_tls, "suite")) suiteOf else @compileError("suite needs SUITE=aesgcm or a server role");
        /// ch_tls.server_cert_type.
        pub const serverCertType = if (@hasField(c.ch_tls, "server_cert_type")) serverCertTypeOf else @compileError("serverCertType needs TRUST=webpki");
        /// Reserved. No C call starts a record-mode KeyUpdate, so this side
        /// starts none; read answers the peer's inside ch_read.
        pub const keyUpdate = @compileError("chapulin has no call that starts a record-mode KeyUpdate");

        fn initClient(self: *Self, values: chapulin.Client) error{Invalid}!void {
            self.prepare();
            var cfg = values.toCfg();
            self.setCallbacks(&cfg);
            cfg.on_ticket = onTicket;
            return chapulin.fromCode(error{Invalid}, c.ch_record_init(&self.record, &cfg));
        }

        fn initServer(self: *Self, values: chapulin.Server, sni_buf: []u8) error{Invalid}!void {
            self.prepare();
            var cfg = values.toCfg() catch |err| {
                // What ch_srv_record_init leaves after a refusal.
                self.record = std.mem.zeroes(c.ch_record);
                self.record.t.state = c.CH_ST_FAILED;
                return err;
            };
            self.setCallbacks(&cfg);
            cfg.srv.on_record_out = onRecordOut;
            cfg.srv.sni_buf = if (sni_buf.len == 0) null else sni_buf.ptr;
            cfg.srv.sni_cap = sni_buf.len;
            return chapulin.fromCode(error{Invalid}, c.ch_srv_record_init(&self.record, &cfg));
        }

        fn prepare(self: *Self) void {
            self.hook = .{};
            self.io = .{};
            self.zeroTicketSlot();
        }

        fn setCallbacks(self: *Self, cfg: *c.ch_cfg) void {
            cfg.buf = &self.receive;
            cfg.buf_len = receive_len;
            cfg.send = send;
            cfg.recv = recv;
            cfg.io = &self.hook;
        }

        fn recordInClient(self: *Self, input: []u8) error{ Invalid, Proto, Auth, Cap }!usize {
            var consumed: usize = 0;
            try chapulin.fromCode(error{ Invalid, Proto, Auth, Cap }, c.ch_record_in(&self.record, input.ptr, input.len, &consumed));
            return consumed;
        }

        fn recordInServer(self: *Self, input: []u8, output: []u8) error{ Proto, Auth, Cap, Io }!Progress {
            var consumed: usize = 0;
            self.io.begin(&.{}, output);
            defer self.io.end();
            try chapulin.fromCode(error{ Proto, Auth, Cap, Io }, c.ch_srv_record_in(&self.record, input.ptr, input.len, &consumed));
            return .{ .consumed = consumed, .written = self.io.written };
        }

        fn recordOutClient(self: *Self, output: []u8) error{ Invalid, Cap }!usize {
            var n: usize = 0;
            try chapulin.fromCode(error{ Invalid, Cap }, c.ch_record_out(&self.record, output.ptr, output.len, &n));
            return n;
        }

        fn takeTicketClient(self: *Self) ?chapulin.Ticket {
            const taken = self.ticket;
            self.zeroTicketSlot();
            return taken;
        }

        /// Leaves the ticket slot null with every byte zero. Storing null
        /// leaves the payload's bytes undefined: Zig 0.16.0's LLVM backend
        /// writes zeros over them, and its own x86_64 backend, the default
        /// for a Debug build on Linux x86_64, writes 0xAA over them. So the
        /// null is stored first and the bytes zeroed after it, and the
        /// assert holds that zero bytes read as null.
        fn zeroTicketSlot(self: *Self) void {
            if (side == .client) {
                self.ticket = null;
                std.crypto.secureZero(u8, std.mem.asBytes(&self.ticket));
                std.debug.assert(self.ticket == null);
            }
        }

        fn sniServer(self: *const Self) ?[]const u8 {
            const t = &self.record.t;
            if (t.sni_len == 0) return null;
            return t.cfg.srv.sni_buf[0..t.sni_len];
        }

        /// ch_record_state.
        pub fn recordState(self: *const Self) chapulin.State {
            return @enumFromInt(c.ch_record_state(&self.record));
        }

        /// ch_record_alert: the alert a failure chose, null when none did.
        pub fn recordAlert(self: *const Self) ?u8 {
            const alert = c.ch_record_alert(&self.record);
            return if (alert == 0) null else alert;
        }

        /// Reads at most one whole record of input: ch_record_whole_len
        /// says how many bytes that is, and ch_read reads them through the
        /// API's recv. Plaintext pt cannot hold stays in the receive buffer
        /// and comes out of the next read, which takes no input. A caller
        /// calls read until consumed and pt_len are both 0.
        ///
        /// reply takes what ch_read sends: key_update_record_len bytes for
        /// a KeyUpdate in the record that asks for an answer (RFC 9846
        /// §4.7.3), and alert_record_len more when the read fails. A
        /// record carries at most one KeyUpdate, as its last message (RFC
        /// 9846 §5.1), so a reply of key_update_record_len +
        /// alert_record_len bytes is never short. A reply too short for
        /// what ch_read sends fails the read with error.Io and the session
        /// with it.
        pub fn read(self: *Self, input: []const u8, pt: []u8, reply: []u8) error{ Invalid, Proto, Auth, Cap, Io }!Read {
            const whole = c.ch_record_whole_len(input.ptr, input.len);
            self.io.begin(input[0..whole], reply);
            defer self.io.end();
            const rc = c.ch_read(&self.record.t, pt.ptr, pt.len);
            self.io.reply_len = self.io.written;
            var out: Read = .{ .consumed = self.io.taken, .pt_len = 0, .reply_len = self.io.written, .peer_closed = false };
            if (rc > 0) {
                out.pt_len = @intCast(rc);
            } else if (rc == 0) {
                out.peer_closed = true;
            } else if (rc != c.CH_RECORD_AGAIN) {
                try chapulin.fromCode(error{ Invalid, Proto, Auth, Cap, Io }, rc);
            }
            return out;
        }

        /// Seals all of pt into output and returns the bytes written, or
        /// returns error.Cap with nothing sealed and the session as it was
        /// when pt.len > writableLen(output.len). It never seals part of
        /// pt, as ch_write does not.
        pub fn write(self: *Self, pt: []const u8, output: []u8) error{ Proto, Cap, Io }!usize {
            if (pt.len > self.writableLen(output.len)) return error.Cap;
            self.io.begin(&.{}, output);
            defer self.io.end();
            try chapulin.fromCode(error{ Proto, Cap, Io }, c.ch_write(&self.record.t, pt.ptr, pt.len));
            return self.io.written;
        }

        /// The most plaintext one write seals into cap bytes: ch_writable_len.
        pub fn writableLen(self: *const Self, cap: usize) usize {
            return c.ch_writable_len(&self.record.t, cap);
        }

        /// ch_close: sends this side's close_notify into output, at most
        /// alert_record_len bytes, and wipes the session's keys. error.Io
        /// when output could not take the alert; the session is closed
        /// either way.
        pub fn close(self: *Self, output: []u8) error{Io}!usize {
            self.io.begin(&.{}, output);
            defer self.io.end();
            c.ch_close(&self.record.t);
            if (self.io.refused) return error.Io;
            return self.io.written;
        }

        /// ch_record_close, then the ticket slot zeroed: every secret
        /// wiped and the session dead. A connected caller calls close first.
        pub fn recordClose(self: *Self) void {
            c.ch_record_close(&self.record);
            self.zeroTicketSlot();
        }

        fn exportOf(self: *const Self, label: [:0]const u8, context: []const u8, out: []u8) error{Invalid}!void {
            return chapulin.fromCode(error{Invalid}, c.ch_export(&self.record.t, label.ptr, context.ptr, context.len, out.ptr, out.len));
        }

        fn alpnSelectedOf(self: *const Self) ?[]const u8 {
            const t = &self.record.t;
            if (t.alpn_selected == c.CH_ALPN_NONE) return null;
            const entry = t.cfg.alpn_protocols[t.alpn_selected];
            return entry.name[0..entry.name_len];
        }

        /// ch_tls.group, null while 0.
        pub fn group(self: *const Self) ?chapulin.Group {
            const code = self.record.t.group;
            return if (code == 0) null else @enumFromInt(code);
        }

        fn suiteOf(self: *const Self) ?chapulin.Suite {
            const code = self.record.t.suite;
            return if (code == 0) null else @enumFromInt(code);
        }

        /// ch_tls.psk_selected: a PSK authenticated the handshake.
        pub fn pskSelected(self: *const Self) bool {
            return self.record.t.psk_selected != 0;
        }

        fn serverCertTypeOf(self: *const Self) chapulin.CertType {
            return @enumFromInt(self.record.t.server_cert_type);
        }

        /// ch_tls.peer_limit: the most plaintext per record the peer takes.
        pub fn peerLimit(self: *const Self) u16 {
            return self.record.t.peer_limit;
        }

        /// ch_tls.read_closed: the peer's close_notify arrived.
        pub fn readClosed(self: *const Self) bool {
            return self.record.t.read_closed != 0;
        }

        /// Bytes the last read wrote into reply, which a failed read also sets.
        pub fn replyLen(self: *const Self) usize {
            return self.io.reply_len;
        }

        fn fromHook(io: ?*anyopaque) *Self {
            const hook: *chapulin.Hook = @ptrCast(@alignCast(io.?));
            return @fieldParentPtr("hook", hook);
        }

        fn send(io: ?*anyopaque, p: [*c]const u8, n: usize) callconv(.c) c_int {
            return fromHook(io).io.put(p[0..n]);
        }

        fn recv(io: ?*anyopaque, p: [*c]u8, n: usize) callconv(.c) c_int {
            return fromHook(io).io.take(p[0..n]);
        }

        fn onRecordOut(io: ?*anyopaque, p: [*c]const u8, n: usize) callconv(.c) c_int {
            return fromHook(io).io.put(p[0..n]);
        }

        fn onTicket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
            const self = fromHook(io);
            self.zeroTicketSlot();
            if (side == .client) self.ticket = chapulin.Ticket.fromOnTicket(ticket);
        }
    };
}
