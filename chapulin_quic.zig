//! QUIC sessions over a TRANSPORT=quic-nonblocking object: CRYPTO bytes in
//! and out per encryption level, and packet protection, each a C call of
//! quic.h, srv_quic.h or quic_token.h (docs/zig.md).
const std = @import("std");
const chapulin = @import("chapulin.zig");
const cfg_of = @import("chapulin_cfg.zig");
const c = chapulin.c;
/// Whether a session reports a suite of its own: ch_tls_priv holds suite under SUITE=aesgcm, whose
/// ch_cfg takes cipher_suites, and in a server role, whose ch_cfg takes srv (session.h).
const has_suite = @hasField(c.ch_cfg, "cipher_suites") or @hasField(c.ch_cfg, "srv");

const has_quic = @hasDecl(c, "ch_quic_initial_keys");
// quic.h declares ch_quic_init only in an object with a client, which alone
// defines it.
const has_client = @hasDecl(c, "ch_quic_init");
const has_server = @hasDecl(c, "ch_srv_quic_init");

/// The encryption levels (quic_cfg.h).
pub const Level = if (has_quic) enum(u8) {
    initial = c.CH_LEVEL_INITIAL,
    handshake = c.CH_LEVEL_HANDSHAKE,
    application = c.CH_LEVEL_APPLICATION,
} else @compileError("quic.Level needs TRANSPORT=quic-nonblocking");

/// How many levels there are: CH_LEVEL_APPLICATION + 1.
pub const level_count: usize = if (has_quic) c.CH_LEVEL_APPLICATION + 1 else @compileError("quic.level_count needs TRANSPORT=quic-nonblocking");

/// The direction of a level's keys (quic_cfg.h).
pub const Direction = if (has_quic) enum(u8) {
    read = c.CH_KEY_READ,
    write = c.CH_KEY_WRITE,
} else @compileError("quic.Direction needs TRANSPORT=quic-nonblocking");

/// A QUIC Version field value (quic_cfg.h): the original version a
/// chapulin.ClientOptions or chapulin.ServerOptions names, and the version each packet
/// call and switch_version take. Any other value converts too, and C
/// decides whether it derives that version's keys.
pub const Version = if (has_quic) enum(u32) {
    v1 = c.CH_QUIC_VERSION_1,
    v2 = c.CH_QUIC_VERSION_2,
    _,
} else @compileError("quic.Version needs TRANSPORT=quic-nonblocking");

/// The 1-RTT receive key set ch_quic_open reports (quic_keys.h).
pub const KeySet = if (has_quic) enum(u8) {
    previous = c.CH_QUIC_KEY_PREVIOUS,
    current = c.CH_QUIC_KEY_CURRENT,
    next = c.CH_QUIC_KEY_NEXT,
} else @compileError("quic.KeySet needs TRANSPORT=quic-nonblocking");

/// Where a server's crypto_in writes the CRYPTO bytes it produces, one
/// buffer per Level. crypto_in adds to written and never resets it.
pub const Outgoing = struct {
    buffers: [level_count][]u8,
    written: [level_count]usize = @splat(0),
};

/// What open recovered: the packet number, the plaintext length after the
/// packet number field, and the receive key set that opened it.
pub const Opened = struct { pn: u64, pt_len: usize, key_set: KeySet };

/// A server's choice of the negotiated version, srv.choose_version
/// (srv_cfg.h), called with the options' context once per connection,
/// after peer_transport_params holds the client's transport parameters and
/// before anything is selected or sent. C fails the session for a version
/// it does not derive.
pub const ChooseVersion = if (has_server) *const fn (context: ?*anyopaque) Version else @compileError("quic.ChooseVersion needs a QUIC server role");

/// The Retry token calls and their types, which take no session (chapulin_quic_token.zig).
const token = @import("chapulin_quic_token.zig");
pub const RetryConnectionIds = token.RetryConnectionIds;
pub const TokenCheck = token.TokenCheck;
pub const TokenMintError = token.TokenMintError;
pub const retry_tag = token.retry_tag;
pub const token_mint = token.token_mint;
pub const token_check = token.token_check;

/// A client whose lists hold the anchors and ALPN names limits allows
/// (chapulin.Limits; pass .{} for the defaults). Do not move it after init:
/// cfg.io points at its hook, and cfg's lists at its own arrays.
pub const Client = if (has_client) ClientSession else @compileError("quic.Client needs TRANSPORT=quic-nonblocking with ROLE=client or ROLE=both");
fn ClientSession(comptime receive_len: usize, comptime limits: chapulin.Limits) type {
    return Session(.client, receive_len, limits);
}

/// A server. Its flight goes into the Outgoing given to each crypto_in.
pub const Server = if (has_server) ServerSession else @compileError("quic.Server needs TRANSPORT=quic-nonblocking with ROLE=server or ROLE=both");
fn ServerSession(comptime receive_len: usize, comptime limits: chapulin.Limits) type {
    return Session(.server, receive_len, limits);
}

/// What each call can answer, one error set per C call (chapulin.Error names each code).
pub const InitError = error{Invalid};
pub const CryptoInError = error{ Invalid, Proto, Auth, Cap };
pub const ServerCryptoInError = error{ Invalid, Proto, Auth, Cap, Io };
pub const CryptoOutError = error{ Invalid, Cap };
pub const SealError = error{ Invalid, Cap };
pub const OpenError = error{ Invalid, Discard, AeadLimit };

const Side = enum { client, server };

fn Session(comptime side: Side, comptime receive_len: usize, comptime limits: chapulin.Limits) type {
    return struct {
        const Self = @This();

        /// The C session. The API promises nothing about its fields.
        quic: c.ch_quic,
        /// The receive buffer, cfg.buf.
        receive: [receive_len]u8,
        /// The C arrays init builds from the values' lists, which cfg points at.
        lists: cfg_of.Lists(limits),
        /// What cfg.io points at.
        hook: chapulin.Hook,
        /// What cfg.rand_io points at under RAND=session: the std.Random
        /// init took from the values, which every draw fills from.
        random: chapulin.RandomSource,
        /// Where on_transport_params copies the peer's transport parameters.
        peer_params: []u8,
        /// Their length, null before they arrive. Above peer_params.len
        /// when they did not fit, and then nothing was copied.
        peer_params_len: ?usize,
        /// The latest ticket on_ticket copied. A server has none.
        ticket: if (side == .client) ?chapulin.Ticket else void,
        /// The sni_buf init took, where the C server copies server_name. A
        /// client has none.
        sni_buf: if (side == .server) []u8 else void,
        /// The Outgoing the running crypto_in writes into. A client has none.
        outgoing: if (side == .server) ?*Outgoing else void,
        /// The options' choose_version, which on_choose_version calls. A client has none.
        choose: if (side == .server) ?ChooseVersion else void,

        /// Client: the ch_cfg the options build, then ch_quic_init with the API's
        /// on_level_ready, on_transport_params and, when the options'
        /// takes_tickets is true, on_ticket. Server: the ch_cfg the options
        /// build, then ch_srv_quic_init with the API's
        /// on_level_ready, on_transport_params, srv.on_crypto_out and,
        /// when the options carry one, srv.choose_version; sni_buf is
        /// srv.sni_buf and srv.sni_cap. transport_params is
        /// borrowed for the session, because a server writes it when its
        /// flight goes out. Each stores the options' context in its hook,
        /// and under RAND=session the options' random, and points
        /// rand_bytes at it. On error.Invalid the session is failed until
        /// the next init.
        pub const init = if (side == .client) init_client else init_server;
        /// Client: ch_quic_crypto_in. Server: ch_srv_quic_crypto_in,
        /// which writes the server's CRYPTO bytes into outgoing.
        pub const crypto_in = if (side == .client) crypto_in_client else crypto_in_server;
        /// ch_quic_crypto_out: the message the client owes at level,
        /// whole, or 0 bytes. A client calls it at each level after crypto_in.
        pub const crypto_out = if (side == .client) crypto_out_client else @compileError("a server writes its CRYPTO bytes from crypto_in");
        /// Moves the latest ticket out and zeroes the slot.
        pub const take_ticket = if (side == .client) take_ticket_client else @compileError("a server receives no ticket");
        /// ch_quic_switch_version: makes version the negotiated version, once,
        /// before the first CRYPTO byte from the server is delivered.
        pub const switch_version = if (side == .client) switch_version_client else @compileError("RFC 9369 section 4.1 gives the version switch to a client");
        /// The server_name the client sent: sni_buf[0..ch_tls.sni_len], null when 0.
        pub const sni = if (side == .server) sni_server else @compileError("a client sends server_name and reports none");
        /// ch_tls.suite, null while 0.
        pub const suite = if (has_suite) suite_of else @compileError("suite needs SUITE=aesgcm or a server role");
        /// ch_tls.server_cert_type.
        pub const server_cert_type = if (@hasDecl(c, "ch_server_cert_type")) server_cert_type_of else @compileError("server_cert_type needs TRUST=webpki");

        fn init_client(self: *Self, options: *const chapulin.ClientOptions, transport_params: []const u8, peer_params: []u8) InitError!void {
            self.prepare(options.context, peer_params);
            var cfg = cfg_of.client_cfg(options, limits, &self.lists) catch |err| {
                self.fail_init();
                return err;
            };
            self.set_callbacks(&cfg, transport_params);
            if (options.takes_tickets) cfg.on_ticket = on_ticket;
            cfg_of.attach_random(&cfg, &self.random, options.random);
            return chapulin.from_code(InitError, c.ch_quic_init(&self.quic, &cfg));
        }

        fn init_server(self: *Self, options: *const chapulin.ServerOptions, transport_params: []const u8, peer_params: []u8, sni_buf: []u8) InitError!void {
            self.prepare(options.context, peer_params);
            var cfg = cfg_of.server_cfg(options, limits, &self.lists) catch |err| {
                self.fail_init();
                return err;
            };
            self.set_callbacks(&cfg, transport_params);
            cfg.srv.on_crypto_out = on_crypto_out;
            self.choose = options.choose_version;
            if (self.choose != null) cfg.srv.choose_version = on_choose_version;
            cfg.srv.sni_buf = if (sni_buf.len == 0) null else sni_buf.ptr;
            cfg.srv.sni_cap = sni_buf.len;
            self.sni_buf = sni_buf;
            cfg_of.attach_random(&cfg, &self.random, options.random);
            return chapulin.from_code(InitError, c.ch_srv_quic_init(&self.quic, &cfg));
        }

        /// What an init call leaves after a refusal, for a list longer than its Limits cap:
        /// the session the C init call leaves when it refuses a configuration, failed and
        /// otherwise zero (quic.h). A zero ch_cfg names no buffer, so the call refuses it.
        fn fail_init(self: *Self) void {
            const zero = std.mem.zeroes(c.ch_cfg);
            const rc = if (side == .client) c.ch_quic_init(&self.quic, &zero) else c.ch_srv_quic_init(&self.quic, &zero);
            std.debug.assert(rc == c.CH_EINVAL);
        }

        /// The ch_tls inside the C session, which the report calls take (ch_quic_tls).
        /// The report calls change nothing, so a method of a const session passes its
        /// pointer without const.
        fn tls(self: *const Self) *c.ch_tls {
            return c.ch_quic_tls(@constCast(&self.quic));
        }

        fn prepare(self: *Self, context: ?*anyopaque, peer_params: []u8) void {
            self.hook = .{ .context = context };
            self.peer_params = peer_params;
            self.peer_params_len = null;
            self.zero_ticket_slot();
            if (side == .server) {
                self.outgoing = null;
                self.choose = null;
            }
        }

        fn set_callbacks(self: *Self, cfg: *c.ch_cfg, transport_params: []const u8) void {
            cfg.buf = &self.receive;
            cfg.buf_len = receive_len;
            cfg.io = &self.hook;
            cfg.transport_params = transport_params.ptr;
            cfg.transport_params_len = transport_params.len;
            cfg.on_level_ready = on_level_ready;
            cfg.on_transport_params = on_transport_params;
        }

        fn crypto_in_client(self: *Self, level: Level, bytes: []const u8) CryptoInError!void {
            return chapulin.from_code(CryptoInError, c.ch_quic_crypto_in(&self.quic, @intFromEnum(level), bytes.ptr, bytes.len));
        }

        fn crypto_in_server(self: *Self, level: Level, bytes: []const u8, outgoing: *Outgoing) ServerCryptoInError!void {
            self.outgoing = outgoing;
            defer self.outgoing = null;
            return chapulin.from_code(ServerCryptoInError, c.ch_srv_quic_crypto_in(&self.quic, @intFromEnum(level), bytes.ptr, bytes.len));
        }

        fn crypto_out_client(self: *Self, level: Level, out: []u8) CryptoOutError!usize {
            var n: usize = 0;
            try chapulin.from_code(CryptoOutError, c.ch_quic_crypto_out(&self.quic, @intFromEnum(level), out.ptr, out.len, &n));
            return n;
        }

        fn switch_version_client(self: *Self, version: Version) error{Invalid}!void {
            return chapulin.from_code(error{Invalid}, c.ch_quic_switch_version(&self.quic, @intFromEnum(version)));
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

        fn sni_server(self: *const Self) ?[]const u8 {
            const len = c.ch_sni_len(self.tls());
            if (len == 0) return null;
            return self.sni_buf[0..len];
        }

        /// ch_quic_initial_keys: the Initial keys from the Destination
        /// Connection ID, again after a Retry.
        pub fn initial_keys(self: *Self, dcid: []const u8) error{Invalid}!void {
            return chapulin.from_code(error{Invalid}, c.ch_quic_initial_keys(&self.quic, dcid.ptr, dcid.len));
        }

        /// Whether one direction at one level can protect or open packets:
        /// its bit in ch_quic_levels_ready.
        pub fn keys_ready(self: *const Self, level: Level, direction: Direction) bool {
            const bit: u8 = switch (level) {
                inline else => |l| switch (direction) {
                    inline else => |d| c.CH_QUIC_LEVEL_BIT(@intFromEnum(l), @intFromEnum(d)),
                },
            };
            return c.ch_quic_levels_ready(&self.quic) & bit != 0;
        }

        /// The peer's quic_transport_parameters body, null before it
        /// arrives. error.Cap when it was longer than peer_params.
        pub fn peer_transport_params(self: *const Self) error{Cap}!?[]const u8 {
            const n = self.peer_params_len orelse return null;
            if (n > self.peer_params.len) return error.Cap;
            return self.peer_params[0..n];
        }

        /// ch_quic_seal: one packet, hdr.len + pt.len + 16 bytes, into out.
        /// version is the packet's Version field, the negotiated version at
        /// .application. error.Invalid includes a version level does not
        /// admit and RFC 9001 §6.6's confidentiality limit: once a key set
        /// has sealed its limit, ch_quic_seal refuses every later packet
        /// under it until key_update writes a new set (quic.h). It is not an
        /// error a retry clears. At .application the packet's Key Phase bit
        /// is key_phase(), whatever hdr holds there.
        pub fn seal(self: *Self, level: Level, version: Version, pn: u64, pn_len: usize, hdr: []const u8, pt: []const u8, out: []u8) SealError!usize {
            var n: usize = 0;
            try chapulin.from_code(SealError, c.ch_quic_seal(&self.quic, @intFromEnum(level), @intFromEnum(version), pn, pn_len, hdr.ptr, hdr.len, pt.ptr, pt.len, out.ptr, out.len, &n));
            return n;
        }

        /// ch_quic_seal_close: the one packet a failed session sends at
        /// level, carrying the caller's CONNECTION_CLOSE.
        pub fn seal_close(self: *Self, level: Level, version: Version, pn: u64, pn_len: usize, hdr: []const u8, pt: []const u8, out: []u8) SealError!usize {
            var n: usize = 0;
            try chapulin.from_code(SealError, c.ch_quic_seal_close(&self.quic, @intFromEnum(level), @intFromEnum(version), pn, pn_len, hdr.ptr, hdr.len, pt.ptr, pt.len, out.ptr, out.len, &n));
            return n;
        }

        /// ch_quic_open: unprotects pkt in place. version is the packet's
        /// Version field, the negotiated version at .application.
        pub fn open(self: *Self, level: Level, version: Version, pkt: []u8, pn_off: usize, largest_pn: u64, current_phase_lowest_pn: u64) OpenError!Opened {
            var key_set: u8 = 0;
            var pn: u64 = 0;
            var pt_len: usize = 0;
            try chapulin.from_code(OpenError, c.ch_quic_open(&self.quic, @intFromEnum(level), @intFromEnum(version), pkt.ptr, pkt.len, pn_off, largest_pn, current_phase_lowest_pn, &key_set, &pn, &pt_len));
            return .{ .pn = pn, .pt_len = pt_len, .key_set = @enumFromInt(key_set) };
        }

        /// ch_quic_retry_ok: whether tag is the Retry integrity tag of pseudo
        /// in version, which is false for any version but the original.
        pub fn retry_ok(self: *const Self, version: Version, pseudo: []const u8, tag: *const [c.CH_QUIC_RETRY_TAG_LEN]u8) bool {
            return c.ch_quic_retry_ok(&self.quic, @intFromEnum(version), pseudo.ptr, pseudo.len, tag) != 0;
        }

        /// ch_quic_negotiated_version: the version every Handshake and 1-RTT
        /// packet carries, the original one until a client's switch_version.
        pub fn negotiated_version(self: *const Self) Version {
            return @enumFromInt(c.ch_quic_negotiated_version(&self.quic));
        }

        /// ch_quic_key_update.
        pub fn key_update(self: *Self) error{Invalid}!void {
            return chapulin.from_code(error{Invalid}, c.ch_quic_key_update(&self.quic));
        }

        /// ch_quic_key_phase.
        pub fn key_phase(self: *const Self) u1 {
            return @intCast(c.ch_quic_key_phase(&self.quic));
        }

        /// ch_quic_drop_previous_keys.
        pub fn drop_previous_keys(self: *Self) void {
            c.ch_quic_drop_previous_keys(&self.quic);
        }

        /// ch_quic_discard: drops both directions' keys at level.
        pub fn discard(self: *Self, level: Level) error{Invalid}!void {
            return chapulin.from_code(error{Invalid}, c.ch_quic_discard(&self.quic, @intFromEnum(level)));
        }

        /// ch_quic_state.
        pub fn state(self: *const Self) chapulin.State {
            return @enumFromInt(c.ch_quic_state(&self.quic));
        }

        /// ch_quic_alert: the alert a failure chose, null when none did. QUIC
        /// carries no alert record, so no call reports a peer's alert: the
        /// peer's CONNECTION_CLOSE is the caller's to read.
        pub fn alert(self: *const Self) ?chapulin.AlertDescription {
            return chapulin.alert_of(c.ch_quic_alert(&self.quic));
        }

        /// ch_quic_error_code: what the caller puts in CONNECTION_CLOSE.
        pub fn error_code(self: *const Self) u64 {
            return c.ch_quic_error_code(&self.quic);
        }

        /// ch_quic_close, then the ticket slot zeroed: every key wiped and
        /// the session dead.
        pub fn close(self: *Self) void {
            c.ch_quic_close(&self.quic);
            self.zero_ticket_slot();
        }

        /// The protocol ALPN selected, null for CH_ALPN_NONE.
        pub fn alpn_selected(self: *const Self) ?[]const u8 {
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

        fn from_hook(io: ?*anyopaque) *Self {
            const hook: *chapulin.Hook = @ptrCast(@alignCast(io.?));
            return @fieldParentPtr("hook", hook);
        }

        /// Does nothing: ch_quic_levels_ready reports the same bits after the
        /// same call, and keys_ready reads them (quic.h).
        fn on_level_ready(_: ?*anyopaque, _: u8, _: u8) callconv(.c) void {}

        fn on_transport_params(io: ?*anyopaque, body: [*c]const u8, n: usize) callconv(.c) void {
            const self = from_hook(io);
            self.peer_params_len = n;
            if (n <= self.peer_params.len) @memcpy(self.peer_params[0..n], body[0..n]);
        }

        fn on_crypto_out(io: ?*anyopaque, level: u8, p: [*c]const u8, n: usize) callconv(.c) c_int {
            const self = from_hook(io);
            const out = self.outgoing orelse return -1;
            if (level >= level_count) return -1;
            const buffer = out.buffers[level];
            if (n > buffer.len - out.written[level]) return -1;
            @memcpy(buffer[out.written[level]..][0..n], p[0..n]);
            out.written[level] += n;
            return 0;
        }

        /// Installed only when choose is set, so it answers what that
        /// function answers and checks nothing: C refuses a version it does
        /// not derive.
        fn on_choose_version(io: ?*anyopaque) callconv(.c) u32 {
            const self = from_hook(io);
            return @intFromEnum(self.choose.?(self.hook.context));
        }

        fn on_ticket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
            const self = from_hook(io);
            self.zero_ticket_slot();
            if (side == .client) self.ticket = chapulin.Ticket.from_on_ticket(ticket);
        }
    };
}
