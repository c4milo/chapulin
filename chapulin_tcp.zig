//! Sessions over a TRANSPORT=tcp-nonblocking object: the
//! handshake through record_in and record_out, then read, seal and end,
//! each a C call of tcp_nonblocking.h, srv_tcp_nonblocking.h or tls.h
//! (docs/zig.md).
//!
//! No call sends through a send or reads through a recv. read opens each
//! record in the caller's input (ch_read_in_place), and seal seals the
//! caller's plaintext where it lies (ch_seal_in_place), so a connected
//! session copies no record. A session holds no receive or send buffer:
//! init takes the handshake buffer, which the session gives back wiped
//! when it connects, fails or closes (docs/decisions.md 247 and 248).
const std = @import("std");
const chapulin = @import("chapulin.zig");
const cfg_of = @import("chapulin_cfg.zig");
const c = chapulin.c;
/// Whether a session reports a suite of its own: ch_tls_priv holds suite under SUITE=aesgcm, whose
/// ch_cfg takes cipher_suites, and in a server role, whose ch_cfg takes srv (session.h).
const has_suite = @hasField(c.ch_cfg, "cipher_suites") or @hasField(c.ch_cfg, "srv");

// tcp_nonblocking.h declares ch_tcp_init only in an object with a client,
// which alone defines it.
const has_client = @hasDecl(c, "ch_tcp_init");
const has_server = @hasDecl(c, "ch_srv_tcp_init");
const has_tcp = @hasDecl(c, "ch_tcp_whole_len");

/// A client whose lists hold the anchors and ALPN names limits allows
/// (chapulin.Limits; pass .{} for the defaults). Do not move it after init:
/// cfg.io points at its hook, and cfg's lists at its own arrays.
pub const Client = if (has_client) ClientSession else @compileError("tcp.Client needs TRANSPORT=tcp-nonblocking with ROLE=client or ROLE=both");
fn ClientSession(comptime limits: chapulin.Limits) type {
    return Session(.client, limits);
}

/// A server with the same storage, less the ticket slot.
pub const Server = if (has_server) ServerSession else @compileError("tcp.Server needs TRANSPORT=tcp-nonblocking with ROLE=server or ROLE=both");
fn ServerSession(comptime limits: chapulin.Limits) type {
    return Session(.server, limits);
}

/// What a server's record_in did: input bytes it took, and bytes of its
/// flight it wrote into output.
pub const Progress = struct { consumed: usize, written: usize };

/// What read did (ch_read_result). consumed: input bytes taken, which the
/// caller drops: 0 while input holds less than the next whole record, one
/// whole record, or the records that finished a post-handshake message in
/// parts. plaintext: the record's plaintext, a slice of input that
/// ch_read_in_place opened in place, empty for a record that carries no
/// data. reply_len: 0 for a read that succeeds; a failed read reports it
/// through the session's reply_len(). peer_closed: the peer's close_notify
/// arrived, now or earlier, or this side closed (CH_ECLOSED).
pub const Read = struct { consumed: usize, plaintext: []u8, reply_len: usize, peer_closed: bool };

/// The wire length of one sealed alert record, 24 bytes: what end and fail
/// write, what a read that fails writes into reply, and the least reply read
/// and output end and fail take (CH_ALERT_RECORD_LEN).
pub const alert_record_len: usize = if (has_tcp) c.CH_ALERT_RECORD_LEN else @compileError("alert_record_len needs TRANSPORT=tcp-nonblocking");

/// The wire length of one sealed KeyUpdate record, 27 bytes
/// (CH_KEY_UPDATE_RECORD_LEN), and the least side seal takes. seal writes
/// one into side before its records when the peer asked for one, or when
/// an AES-GCM write key cannot seal every record of the write. read writes
/// none.
pub const key_update_record_len: usize = if (has_tcp) c.CH_KEY_UPDATE_RECORD_LEN else @compileError("key_update_record_len needs TRANSPORT=tcp-nonblocking");

/// Where seal reads the plaintext in its buffer: REC_HDR bytes in, the room
/// the first record's header takes.
pub const plaintext_offset: usize = if (has_tcp) c.REC_HDR else @compileError("plaintext_offset needs TRANSPORT=tcp-nonblocking");

/// What seal wrote (ch_seal_result). records: the sealed records, a slice
/// at the front of the caller's buffer. side: the record seal wrote into
/// side, empty when it wrote none: a KeyUpdate. The caller sends side
/// first, then records.
pub const Sealed = struct { records: []u8, side: []u8 };

/// What each call can answer, one error set per C call (chapulin.Error names each code).
pub const InitError = error{Invalid};
pub const RecordInError = error{ Invalid, Proto, Auth, Cap };
pub const ServerRecordInError = error{ Proto, Auth, Cap, Io };
pub const RecordOutError = error{ Invalid, Cap };
pub const ReadError = error{ Invalid, Proto, Auth, Cap, KeyUpdateLimit };
pub const SealError = error{ Invalid, Proto, Cap };
pub const EndError = error{ Invalid, Proto, Cap };
pub const FailError = error{ Invalid, Proto, Cap };
pub const ExportError = error{Invalid};

const Side = enum { client, server };

/// The slice the API's on_record_out copies into during one call.
const Io = struct {
    /// Where on_record_out copies what the C server pushes, and how many
    /// bytes it holds.
    output: []u8 = &.{},
    written: usize = 0,
    /// Set when on_record_out could not take all of what C pushed.
    refused: bool = false,
    /// Bytes the last read wrote into reply.
    reply_len: usize = 0,
    /// Bytes the last seal wrote into side.
    side_len: usize = 0,
    /// Bytes a server's last record_in wrote into output.
    output_len: usize = 0,

    fn begin(io: *Io, output: []u8) void {
        io.output = output;
        io.written = 0;
        io.refused = false;
    }

    /// Drops the borrowed slice, so no callback outside a call writes it.
    fn end(io: *Io) void {
        io.output = &.{};
    }

    /// Copies all of bytes into output, or refuses them whole.
    fn put(io: *Io, bytes: []const u8) bool {
        if (bytes.len > io.output.len - io.written) {
            io.refused = true;
            return false;
        }
        @memcpy(io.output[io.written..][0..bytes.len], bytes);
        io.written += bytes.len;
        return true;
    }
};

fn Session(comptime side: Side, comptime limits: chapulin.Limits) type {
    return struct {
        const Self = @This();

        /// The C session. The API promises nothing about its fields.
        tcp: c.ch_tcp,
        /// The C arrays init builds from the values' lists, which cfg points at.
        lists: cfg_of.Lists(limits),
        /// What cfg.io points at.
        hook: chapulin.Hook,
        /// What cfg.rand_io points at under RAND=session: the std.Random
        /// init took from the values, which every draw fills from.
        random: chapulin.RandomSource,
        /// The slice the API's on_record_out copies into during one call,
        /// and what the last read and seal wrote beside their main output.
        io: Io,
        /// The latest ticket on_ticket copied. A server has none.
        ticket: if (side == .client) ?chapulin.Ticket else void,
        /// The sni_buf init took, where the C server copies server_name. A
        /// client has none.
        sni_buf: if (side == .server) []u8 else void,

        /// Client: the ch_cfg the options build, then ch_tcp_init with,
        /// when the options' takes_tickets is true, on_ticket. Server: the
        /// ch_cfg the options build, then ch_srv_tcp_init with the API's
        /// on_record_out; sni_buf is
        /// where this connection's server_name is copied (srv.sni_buf,
        /// srv.sni_cap). handshake_buf is cfg.buf, which the handshake alone
        /// uses: the session wipes it and gives it back when state() is
        /// .connected, .failed or .closed, and never reads it again. One
        /// handshake uses one buffer at a time, so a program that runs many
        /// handshakes keeps a pool of them (tcp_nonblocking.h). Each stores
        /// the options' context in its hook, and under RAND=session the
        /// options' random, and points rand_bytes at it. On error.Invalid
        /// the session is failed until the next init.
        pub const init = if (side == .client) init_client else init_server;
        /// Client: ch_tcp_in. Server: ch_srv_tcp_in, which writes the
        /// server's flight into output, and after a failure the failure's
        /// alert record, which output_len counts.
        pub const record_in = if (side == .client) record_in_client else record_in_server;
        /// ch_tcp_out: bytes the client owes, 0 when it owes none. After
        /// a failed record_in, the failure's alert record, and error.Invalid
        /// once all of it has been returned.
        pub const record_out = if (side == .client) record_out_client else @compileError("a server writes its flight from record_in");
        /// Bytes the last record_in wrote into output, which a failed
        /// record_in also sets: the records of the flight before the
        /// failure, then the failure's alert record
        /// (srv_tcp_nonblocking.h). Progress.written when it succeeds.
        pub const output_len = if (side == .server) output_len_server else @compileError("a client's record_in writes no output; record_out returns its bytes");
        /// Moves the latest ticket out and zeroes the slot.
        pub const take_ticket = if (side == .client) take_ticket_client else @compileError("a server receives no ticket");
        /// The server_name the client sent: sni_buf[0..ch_tls.sni_len], null when 0.
        pub const sni = if (side == .server) sni_server else @compileError("a client sends server_name and reports none");
        /// ch_export (EXPORTER=on).
        pub const export_keying_material = if (@hasDecl(c, "ch_export")) export_of else @compileError("export_keying_material needs EXPORTER=on");
        /// The protocol ALPN selected, null for CH_ALPN_NONE.
        pub const alpn_selected = if (@hasDecl(c, "ch_alpn_selected")) alpn_selected_of else @compileError("alpn_selected needs TRUST=webpki or a server role");
        /// ch_tls.suite, null while 0. A client offers ChaCha20 alone
        /// outside SUITE=aesgcm and writes no suite there.
        pub const suite = if (has_suite) suite_of else @compileError("suite needs SUITE=aesgcm or a server role");
        /// ch_tls.server_cert_type.
        pub const server_cert_type = if (@hasDecl(c, "ch_server_cert_type")) server_cert_type_of else @compileError("server_cert_type needs TRUST=webpki");
        /// Reserved. No C call starts a tcp-nonblocking KeyUpdate: seal
        /// writes one into side, as the answer the peer's request owes or
        /// when an AES-GCM write key cannot seal every record of a write.
        pub const key_update = @compileError("chapulin has no call that starts a tcp-nonblocking KeyUpdate");

        fn init_client(self: *Self, options: *const chapulin.ClientOptions, handshake_buf: []u8) InitError!void {
            self.prepare(options.context);
            var cfg = cfg_of.client_cfg(options, limits, &self.lists) catch |err| {
                self.fail_init();
                return err;
            };
            self.set_callbacks(&cfg, handshake_buf);
            if (options.takes_tickets) cfg.on_ticket = on_ticket;
            cfg_of.attach_random(&cfg, &self.random, options.random);
            return chapulin.from_code(InitError, c.ch_tcp_init(&self.tcp, &cfg));
        }

        fn init_server(self: *Self, options: *const chapulin.ServerOptions, sni_buf: []u8, handshake_buf: []u8) InitError!void {
            self.prepare(options.context);
            var cfg = cfg_of.server_cfg(options, limits, &self.lists) catch |err| {
                self.fail_init();
                return err;
            };
            self.set_callbacks(&cfg, handshake_buf);
            cfg.srv.on_record_out = on_record_out;
            cfg.srv.sni_buf = if (sni_buf.len == 0) null else sni_buf.ptr;
            cfg.srv.sni_cap = sni_buf.len;
            self.sni_buf = sni_buf;
            cfg_of.attach_random(&cfg, &self.random, options.random);
            return chapulin.from_code(InitError, c.ch_srv_tcp_init(&self.tcp, &cfg));
        }

        /// What an init call leaves after a refusal, for a list longer than its Limits cap:
        /// the session the C init call leaves when it refuses a configuration, failed and
        /// otherwise zero (tcp_nonblocking.h). A zero ch_cfg names no buffer, so the call
        /// refuses it.
        fn fail_init(self: *Self) void {
            const zero = std.mem.zeroes(c.ch_cfg);
            const rc = if (side == .client) c.ch_tcp_init(&self.tcp, &zero) else c.ch_srv_tcp_init(&self.tcp, &zero);
            std.debug.assert(rc == c.CH_EINVAL);
        }

        /// The ch_tls inside the C session, which the record-layer calls and the report
        /// calls take (ch_tcp_tls). The report calls change nothing, so a method of a
        /// const session passes its pointer without const.
        fn tls(self: *const Self) *c.ch_tls {
            return c.ch_tcp_tls(@constCast(&self.tcp));
        }

        fn prepare(self: *Self, context: ?*anyopaque) void {
            self.hook = .{ .context = context };
            self.io = .{};
            self.zero_ticket_slot();
        }

        fn set_callbacks(self: *Self, cfg: *c.ch_cfg, handshake_buf: []u8) void {
            cfg.buf = if (handshake_buf.len == 0) null else handshake_buf.ptr;
            cfg.buf_len = handshake_buf.len;
            cfg.io = &self.hook;
        }

        fn record_in_client(self: *Self, input: []u8) RecordInError!usize {
            var consumed: usize = 0;
            try chapulin.from_code(RecordInError, c.ch_tcp_in(&self.tcp, input.ptr, input.len, &consumed));
            return consumed;
        }

        fn record_in_server(self: *Self, input: []u8, output: []u8) ServerRecordInError!Progress {
            var consumed: usize = 0;
            self.io.begin(output);
            defer self.io.end();
            const rc = c.ch_srv_tcp_in(&self.tcp, input.ptr, input.len, &consumed);
            self.io.output_len = self.io.written;
            try chapulin.from_code(ServerRecordInError, rc);
            return .{ .consumed = consumed, .written = self.io.written };
        }

        fn record_out_client(self: *Self, output: []u8) RecordOutError!usize {
            var n: usize = 0;
            try chapulin.from_code(RecordOutError, c.ch_tcp_out(&self.tcp, output.ptr, output.len, &n));
            return n;
        }

        fn take_ticket_client(self: *Self) ?chapulin.Ticket {
            const taken = self.ticket;
            self.zero_ticket_slot();
            return taken;
        }

        /// Leaves the ticket slot null with every byte zero. Storing null
        /// leaves the payload's bytes undefined: Zig 0.16.0's LLVM backend
        /// writes zeros over them, and its own x86_64 backend, the default
        /// for a Debug build on Linux x86_64, writes 0xAA over them. So the
        /// null is stored first and the bytes zeroed after it, and the
        /// assert holds that zero bytes read as null.
        fn zero_ticket_slot(self: *Self) void {
            if (side == .client) {
                self.ticket = null;
                std.crypto.secureZero(u8, std.mem.asBytes(&self.ticket));
                std.debug.assert(self.ticket == null);
            }
        }

        fn output_len_server(self: *const Self) usize {
            return self.io.output_len;
        }

        fn sni_server(self: *const Self) ?[]const u8 {
            const len = c.ch_sni_len(self.tls());
            if (len == 0) return null;
            return self.sni_buf[0..len];
        }

        /// ch_tcp_state.
        pub fn state(self: *const Self) chapulin.State {
            return @enumFromInt(c.ch_tcp_state(&self.tcp));
        }

        /// ch_alert_sent: the fatal alert this side's failure chose, null
        /// when none did. The failing call emits it: a client's record_in
        /// stages it for record_out, a server's record_in writes it into
        /// output, read writes it into reply and seal into side.
        pub fn alert_sent(self: *const Self) ?chapulin.AlertDescription {
            return chapulin.alert_of(c.ch_alert_sent(self.tls()));
        }

        /// ch_alert_received: the fatal alert the peer sent, null when none
        /// arrived. A session that failed on it sent nothing in answer.
        pub fn alert_received(self: *const Self) ?chapulin.AlertDescription {
            return chapulin.alert_of(c.ch_alert_received(self.tls()));
        }

        /// Opens the next record of input where it lies: ch_read_in_place.
        /// The caller passes the bytes it holds and drops the first
        /// consumed of them after the call. A Read whose consumed is 0 says
        /// input holds less than the next whole record: the caller keeps
        /// the bytes, unchanged, and calls again with more after them. That
        /// holds for the records of a post-handshake message in parts too,
        /// which the session keeps no copy of. A caller calls read until
        /// consumed is 0.
        ///
        /// reply takes the alert of a read that fails, alert_record_len
        /// bytes, which reply_len() counts, and a reply shorter than that is
        /// error.Invalid before any byte is read. A KeyUpdate that asks for
        /// an answer gets it from the next seal (RFC 9846 §4.7.3). A record
        /// that fails has its bytes wiped in input. error.KeyUpdateLimit is
        /// CH_KEY_UPDATE_LIMIT: the peer sent one KeyUpdate past
        /// CH_KEY_UPDATE_RUN_MAX in a row (public_sizes.h).
        pub fn read(self: *Self, input: []u8, reply: []u8) ReadError!Read {
            var result = std.mem.zeroes(c.ch_read_result);
            self.io.reply_len = 0;
            const rc = c.ch_read_in_place(self.tls(), input.ptr, input.len, reply.ptr, reply.len, &result);
            self.io.reply_len = result.reply_len;
            var out: Read = .{ .consumed = result.consumed, .plaintext = input[0..0], .reply_len = result.reply_len, .peer_closed = false };
            if (rc == c.CH_OK) {
                out.plaintext = input[result.pt_off..][0..result.pt_len];
            } else if (rc == c.CH_ECLOSED) {
                out.peer_closed = true;
            } else if (rc != c.CH_TCP_AGAIN) {
                try chapulin.from_code(ReadError, rc);
            }
            return out;
        }

        /// Seals pt_len bytes of plaintext where they lie: ch_seal_in_place.
        /// The caller writes the plaintext at buf[plaintext_offset..], and
        /// seal cuts it into records and seals each one in buf, which then
        /// holds the records from its first byte. It seals all of the
        /// plaintext or none: error.Cap with nothing sealed and the session
        /// as it was when pt_len > writable_len(buf.len). side_buf takes a
        /// KeyUpdate record that goes before the records, and a side_buf
        /// shorter than key_update_record_len is error.Invalid. error.Cap with the
        /// session failed when no key can seal the write: side_buf then holds
        /// the internal_error alert, which side_len() counts, and state() is
        /// .failed (tcp_nonblocking.h).
        pub fn seal(self: *Self, buf: []u8, pt_len: usize, side_buf: []u8) SealError!Sealed {
            var result = std.mem.zeroes(c.ch_seal_result);
            self.io.side_len = 0;
            const rc = c.ch_seal_in_place(self.tls(), buf.ptr, buf.len, pt_len, side_buf.ptr, side_buf.len, &result);
            self.io.side_len = result.side_len;
            try chapulin.from_code(SealError, rc);
            return .{ .records = buf[0..result.records_len], .side = side_buf[0..result.side_len] };
        }

        /// The most plaintext one seal seals in a buffer of cap bytes:
        /// ch_writable_len. It counts no KeyUpdate, which goes into side.
        pub fn writable_len(self: *const Self, cap: usize) usize {
            return c.ch_writable_len(self.tls(), cap);
        }

        /// Bytes the last seal wrote into side_buf, which a seal that failed
        /// the session also sets.
        pub fn side_len(self: *const Self) usize {
            return self.io.side_len;
        }

        /// ch_close_out: writes this side's close_notify into output,
        /// alert_record_len bytes, returns its length, and wipes the
        /// session's keys. error.Invalid when output is shorter than
        /// alert_record_len and error.Proto when the session is not
        /// connected, both with the session as it was. error.Cap when the
        /// write key seals no more records; the session is closed then.
        pub fn end(self: *Self, output: []u8) EndError!usize {
            var n: usize = 0;
            try chapulin.from_code(EndError, c.ch_close_out(self.tls(), output.ptr, output.len, &n));
            return n;
        }

        /// ch_fail_out: writes the fatal alert description names into
        /// output, alert_record_len bytes, returns its length, wipes the
        /// session's keys and fails the session, for an error the caller
        /// found itself (tcp_nonblocking.h). error.Invalid when description
        /// is not one of RFC 9846 §6.2's error alerts or output is shorter
        /// than alert_record_len, and error.Proto when the session is not
        /// connected, both with the session as it was. error.Cap when the
        /// write key seals no more records; the session failed then.
        pub fn fail(self: *Self, description: chapulin.AlertDescription, output: []u8) FailError!usize {
            var n: usize = 0;
            try chapulin.from_code(FailError, c.ch_fail_out(self.tls(), @intFromEnum(description), output.ptr, output.len, &n));
            return n;
        }

        /// ch_tcp_close, then the ticket slot zeroed: every secret
        /// wiped and the session dead. A connected caller calls end first.
        pub fn close(self: *Self) void {
            c.ch_tcp_close(&self.tcp);
            self.zero_ticket_slot();
        }

        fn export_of(self: *const Self, label: [:0]const u8, context: []const u8, out: []u8) ExportError!void {
            return chapulin.from_code(ExportError, c.ch_export(self.tls(), label.ptr, context.ptr, context.len, out.ptr, out.len));
        }

        fn alpn_selected_of(self: *const Self) ?[]const u8 {
            const index = c.ch_alpn_selected(self.tls());
            if (index == c.CH_ALPN_NONE) return null;
            // The list init copied into lists, which cfg.alpn_protocols points at.
            const entry = self.lists.alpn[index];
            return entry.name[0..entry.name_len];
        }

        /// ch_tls.group, null while 0.
        pub fn group(self: *const Self) ?chapulin.Group {
            const code = c.ch_group(self.tls());
            return if (code == 0) null else @enumFromInt(code);
        }

        fn suite_of(self: *const Self) ?chapulin.Suite {
            const code = c.ch_suite(self.tls());
            return if (code == 0) null else @enumFromInt(code);
        }

        /// ch_tls.psk_selected: a PSK authenticated the handshake.
        pub fn psk_selected(self: *const Self) bool {
            return c.ch_psk_selected(self.tls()) != 0;
        }

        fn server_cert_type_of(self: *const Self) chapulin.CertType {
            return @enumFromInt(c.ch_server_cert_type(self.tls()));
        }

        /// ch_tls.peer_limit: the most plaintext per record the peer takes.
        pub fn peer_limit(self: *const Self) u16 {
            return c.ch_peer_limit(self.tls());
        }

        /// ch_tls.read_closed: the peer's close_notify arrived.
        pub fn read_closed(self: *const Self) bool {
            return c.ch_read_closed(self.tls()) != 0;
        }

        /// Bytes the last read wrote into reply, which a failed read also sets.
        pub fn reply_len(self: *const Self) usize {
            return self.io.reply_len;
        }

        fn from_hook(io: ?*anyopaque) *Self {
            const hook: *chapulin.Hook = @ptrCast(@alignCast(io.?));
            // A host object aligns c.ch_tcp to 16 (docs/decisions.md 249), and hook's alignment
            // is its own. The session was allocated at its own alignment, so the cast holds.
            return @alignCast(@fieldParentPtr("hook", hook));
        }

        /// cfg.srv.on_record_out's rule: 0 for a whole record taken.
        fn on_record_out(io: ?*anyopaque, p: [*c]const u8, n: usize) callconv(.c) c_int {
            return if (from_hook(io).io.put(p[0..n])) 0 else -1;
        }

        fn on_ticket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
            const self = from_hook(io);
            self.zero_ticket_slot();
            if (side == .client) self.ticket = chapulin.Ticket.from_on_ticket(ticket);
        }
    };
}
