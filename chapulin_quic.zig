//! QUIC sessions over a TRANSPORT=quic-nonblocking object: CRYPTO bytes in
//! and out per encryption level, and packet protection, each a C call of
//! quic.h, srv_quic.h or quic_token.h (docs/zig.md).
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_quic = @hasDecl(c, "ch_quic_initial_keys");
// quic.h declares ch_quic_init in a ROLE=server object too, which does not
// define it. ticket.h declares the client's ticket call in an object with a
// client alone.
const has_client = @hasDecl(c, "ch_quic_init") and @hasDecl(c, "ch_ticket_obfuscated_age");
const has_server = @hasDecl(c, "ch_srv_quic_init");

/// The encryption levels (cfg.h).
pub const Level = if (has_quic) enum(u8) {
    initial = c.CH_LEVEL_INITIAL,
    handshake = c.CH_LEVEL_HANDSHAKE,
    application = c.CH_LEVEL_APPLICATION,
} else @compileError("quic.Level needs TRANSPORT=quic-nonblocking");

/// How many levels there are: CH_LEVEL_APPLICATION + 1.
pub const level_count: usize = if (has_quic) c.CH_LEVEL_APPLICATION + 1 else @compileError("quic.level_count needs TRANSPORT=quic-nonblocking");

/// The direction of a level's keys (cfg.h).
pub const Direction = if (has_quic) enum(u8) {
    read = c.CH_KEY_READ,
    write = c.CH_KEY_WRITE,
} else @compileError("quic.Direction needs TRANSPORT=quic-nonblocking");

/// The 1-RTT receive key set ch_quic_open reports (quic_keys.h).
pub const KeySet = if (has_quic) enum(u8) {
    previous = c.CH_QUIC_KEY_PREVIOUS,
    current = c.CH_QUIC_KEY_CURRENT,
    next = c.CH_QUIC_KEY_NEXT,
} else @compileError("quic.KeySet needs TRANSPORT=quic-nonblocking");

/// Where a server's cryptoIn writes the CRYPTO bytes it produces, one
/// buffer per Level. cryptoIn adds to written and never resets it.
pub const Outgoing = struct {
    buffers: [level_count][]u8,
    written: [level_count]usize = @splat(0),
};

/// What open recovered: the packet number, the plaintext length after the
/// packet number field, and the receive key set that opened it.
pub const Opened = struct { pn: u64, pt_len: usize, key_set: KeySet };

/// What tokenCheck found. retry: the token verified, and these are the
/// connection IDs it carried. not_retry: CH_EPROTO, the token is empty or
/// not a Retry token. invalid: CH_EAUTH, a Retry token that fails its tag,
/// its lengths or its time window (quic_token.h).
pub const TokenCheck = if (has_server) union(enum) {
    retry: c.ch_quic_retry_cids,
    not_retry,
    invalid,
} else @compileError("quic.TokenCheck needs a QUIC server role");

/// A client. Do not move it after init: cfg.io points at its hook.
pub const Client = if (has_client) clientOf else @compileError("quic.Client needs TRANSPORT=quic-nonblocking with ROLE=client or ROLE=both");
fn clientOf(comptime receive_len: usize) type {
    return Session(.client, receive_len);
}

/// A server. Its flight goes into the Outgoing given to each cryptoIn.
pub const Server = if (has_server) serverOf else @compileError("quic.Server needs TRANSPORT=quic-nonblocking with ROLE=server or ROLE=both");
fn serverOf(comptime receive_len: usize) type {
    return Session(.server, receive_len);
}

/// ch_srv_quic_retry_tag: the Retry integrity tag over pseudo (RFC 9001 §5.8).
pub const retryTag = if (has_server) retryTagOf else @compileError("quic.retryTag needs a QUIC server role");
fn retryTagOf(pseudo: []const u8, tag: *[c.GCM_TAG]u8) void {
    c.ch_srv_quic_retry_tag(pseudo.ptr, pseudo.len, tag);
}

/// ch_srv_quic_token_mint: a Retry token for the client at address.
pub const tokenMint = if (has_server) tokenMintOf else @compileError("quic.tokenMint needs a QUIC server role");
fn tokenMintOf(key: *const [c.CH_QUIC_TOKEN_KEY_LEN]u8, address: []const u8, cids: *const c.ch_quic_retry_cids, issued_seconds: u64, out: []u8) error{ Invalid, Cap }!usize {
    var n: usize = 0;
    try chapulin.fromCode(error{ Invalid, Cap }, c.ch_srv_quic_token_mint(key, address.ptr, address.len, cids, issued_seconds, out.ptr, out.len, &n));
    return n;
}

/// ch_srv_quic_token_check. error.Invalid for an address the call refuses.
pub const tokenCheck = if (has_server) tokenCheckOf else @compileError("quic.tokenCheck needs a QUIC server role");
fn tokenCheckOf(key: *const [c.CH_QUIC_TOKEN_KEY_LEN]u8, token: []const u8, address: []const u8, now_seconds: u64, lifetime_seconds: u64) error{Invalid}!TokenCheck {
    var cids = std.mem.zeroes(c.ch_quic_retry_cids);
    const rc = c.ch_srv_quic_token_check(key, token.ptr, token.len, address.ptr, address.len, now_seconds, lifetime_seconds, &cids);
    if (rc == c.CH_EPROTO) return .not_retry;
    if (rc == c.CH_EAUTH) return .invalid;
    try chapulin.fromCode(error{Invalid}, rc);
    return .{ .retry = cids };
}

const Side = enum { client, server };

fn Session(comptime side: Side, comptime receive_len: usize) type {
    return struct {
        const Self = @This();

        /// The C session. The API promises nothing about its fields.
        quic: c.ch_quic,
        /// The receive buffer, cfg.buf.
        receive: [receive_len]u8,
        /// What cfg.io points at.
        hook: chapulin.Hook,
        /// Where on_transport_params copies the peer's transport parameters.
        peer_params: []u8,
        /// Their length, null before they arrive. Above peer_params.len
        /// when they did not fit, and then nothing was copied.
        peer_params_len: ?usize,
        /// The latest ticket on_ticket copied. A server has none.
        ticket: if (side == .client) ?chapulin.Ticket else void,
        /// The Outgoing the running cryptoIn writes into. A client has none.
        outgoing: if (side == .server) ?*Outgoing else void,

        /// Client: Client.toCfg, then ch_quic_init with the API's
        /// on_level_ready, on_transport_params and on_ticket. Server:
        /// Server.toCfg, then ch_srv_quic_init with the API's
        /// on_level_ready, on_transport_params and srv.on_crypto_out;
        /// sni_buf is srv.sni_buf and srv.sni_cap. transport_params is
        /// borrowed for the session, because a server writes it when its
        /// flight goes out. On error.Invalid the session is failed until
        /// the next init.
        pub const init = if (side == .client) initClient else initServer;
        /// Client: ch_quic_crypto_in. Server: ch_srv_quic_crypto_in,
        /// which writes the server's CRYPTO bytes into outgoing.
        pub const cryptoIn = if (side == .client) cryptoInClient else cryptoInServer;
        /// ch_quic_crypto_out: the message the client owes at level,
        /// whole, or 0 bytes. A client calls it at each level after cryptoIn.
        pub const cryptoOut = if (side == .client) cryptoOutClient else @compileError("a server writes its CRYPTO bytes from cryptoIn");
        /// Moves the latest ticket out and zeroes the slot.
        pub const takeTicket = if (side == .client) takeTicketClient else @compileError("a server receives no ticket");
        /// The server_name the client sent: sni_buf[0..ch_tls.sni_len], null when 0.
        pub const sni = if (side == .server) sniServer else @compileError("a client sends server_name and reports none");
        /// ch_tls.suite, null while 0.
        pub const suite = if (@hasField(c.ch_tls, "suite")) suiteOf else @compileError("suite needs SUITE=aesgcm or a server role");
        /// ch_tls.server_cert_type.
        pub const serverCertType = if (@hasField(c.ch_tls, "server_cert_type")) serverCertTypeOf else @compileError("serverCertType needs TRUST=webpki");

        fn initClient(self: *Self, values: chapulin.Client, transport_params: []const u8, peer_params: []u8) error{Invalid}!void {
            self.prepare(peer_params);
            var cfg = values.toCfg();
            self.setCallbacks(&cfg, transport_params);
            cfg.on_ticket = onTicket;
            return chapulin.fromCode(error{Invalid}, c.ch_quic_init(&self.quic, &cfg));
        }

        fn initServer(self: *Self, values: chapulin.Server, transport_params: []const u8, peer_params: []u8, sni_buf: []u8) error{Invalid}!void {
            self.prepare(peer_params);
            var cfg = values.toCfg() catch |err| {
                // What ch_srv_quic_init leaves after a refusal.
                self.quic = std.mem.zeroes(c.ch_quic);
                self.quic.t.state = c.CH_ST_FAILED;
                return err;
            };
            self.setCallbacks(&cfg, transport_params);
            cfg.srv.on_crypto_out = onCryptoOut;
            cfg.srv.sni_buf = if (sni_buf.len == 0) null else sni_buf.ptr;
            cfg.srv.sni_cap = sni_buf.len;
            return chapulin.fromCode(error{Invalid}, c.ch_srv_quic_init(&self.quic, &cfg));
        }

        fn prepare(self: *Self, peer_params: []u8) void {
            self.hook = .{};
            self.peer_params = peer_params;
            self.peer_params_len = null;
            self.zeroTicketSlot();
            if (side == .server) self.outgoing = null;
        }

        fn setCallbacks(self: *Self, cfg: *c.ch_cfg, transport_params: []const u8) void {
            cfg.buf = &self.receive;
            cfg.buf_len = receive_len;
            cfg.io = &self.hook;
            cfg.transport_params = transport_params.ptr;
            cfg.transport_params_len = transport_params.len;
            cfg.on_level_ready = onLevelReady;
            cfg.on_transport_params = onTransportParams;
        }

        fn cryptoInClient(self: *Self, level: Level, bytes: []const u8) error{ Invalid, Proto, Auth, Cap }!void {
            return chapulin.fromCode(error{ Invalid, Proto, Auth, Cap }, c.ch_quic_crypto_in(&self.quic, @intFromEnum(level), bytes.ptr, bytes.len));
        }

        fn cryptoInServer(self: *Self, level: Level, bytes: []const u8, outgoing: *Outgoing) error{ Invalid, Proto, Auth, Cap, Io }!void {
            self.outgoing = outgoing;
            defer self.outgoing = null;
            return chapulin.fromCode(error{ Invalid, Proto, Auth, Cap, Io }, c.ch_srv_quic_crypto_in(&self.quic, @intFromEnum(level), bytes.ptr, bytes.len));
        }

        fn cryptoOutClient(self: *Self, level: Level, out: []u8) error{ Invalid, Cap }!usize {
            var n: usize = 0;
            try chapulin.fromCode(error{ Invalid, Cap }, c.ch_quic_crypto_out(&self.quic, @intFromEnum(level), out.ptr, out.len, &n));
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
            const t = &self.quic.t;
            if (t.sni_len == 0) return null;
            return t.cfg.srv.sni_buf[0..t.sni_len];
        }

        /// ch_quic_initial_keys: the Initial keys from the Destination
        /// Connection ID, again after a Retry.
        pub fn initialKeys(self: *Self, dcid: []const u8) error{Invalid}!void {
            return chapulin.fromCode(error{Invalid}, c.ch_quic_initial_keys(&self.quic, dcid.ptr, dcid.len));
        }

        /// Whether one direction at one level can protect or open packets:
        /// its bit in ch_quic.levels_ready.
        pub fn keysReady(self: *const Self, level: Level, direction: Direction) bool {
            const bit: u8 = switch (level) {
                inline else => |l| switch (direction) {
                    inline else => |d| c.CH_QUIC_LEVEL_BIT(@intFromEnum(l), @intFromEnum(d)),
                },
            };
            return self.quic.levels_ready & bit != 0;
        }

        /// The peer's quic_transport_parameters body, null before it
        /// arrives. error.Cap when it was longer than peer_params.
        pub fn peerTransportParams(self: *const Self) error{Cap}!?[]const u8 {
            const n = self.peer_params_len orelse return null;
            if (n > self.peer_params.len) return error.Cap;
            return self.peer_params[0..n];
        }

        /// ch_quic_seal: one packet, hdr.len + pt.len + 16 bytes, into out.
        /// error.Invalid includes RFC 9001 §6.6's confidentiality limit: once
        /// a key set has sealed its limit, ch_quic_seal refuses every later
        /// packet under it until keyUpdate writes a new set (quic.h). It is
        /// not an error a retry clears.
        pub fn seal(self: *Self, level: Level, pn: u64, pn_len: usize, hdr: []const u8, pt: []const u8, out: []u8) error{ Invalid, Cap }!usize {
            var n: usize = 0;
            try chapulin.fromCode(error{ Invalid, Cap }, c.ch_quic_seal(&self.quic, @intFromEnum(level), pn, pn_len, hdr.ptr, hdr.len, pt.ptr, pt.len, out.ptr, out.len, &n));
            return n;
        }

        /// ch_quic_seal_close: the one packet a failed session sends at
        /// level, carrying the caller's CONNECTION_CLOSE.
        pub fn sealClose(self: *Self, level: Level, pn: u64, pn_len: usize, hdr: []const u8, pt: []const u8, out: []u8) error{ Invalid, Cap }!usize {
            var n: usize = 0;
            try chapulin.fromCode(error{ Invalid, Cap }, c.ch_quic_seal_close(&self.quic, @intFromEnum(level), pn, pn_len, hdr.ptr, hdr.len, pt.ptr, pt.len, out.ptr, out.len, &n));
            return n;
        }

        /// ch_quic_open: unprotects pkt in place.
        pub fn open(self: *Self, level: Level, pkt: []u8, pn_off: usize, largest_pn: u64, current_phase_lowest_pn: u64) error{ Invalid, Discard, AeadLimit }!Opened {
            var key_set: u8 = 0;
            var pn: u64 = 0;
            var pt_len: usize = 0;
            try chapulin.fromCode(error{ Invalid, Discard, AeadLimit }, c.ch_quic_open(&self.quic, @intFromEnum(level), pkt.ptr, pkt.len, pn_off, largest_pn, current_phase_lowest_pn, &key_set, &pn, &pt_len));
            return .{ .pn = pn, .pt_len = pt_len, .key_set = @enumFromInt(key_set) };
        }

        /// ch_quic_retry_ok: whether tag is the Retry integrity tag of pseudo.
        pub fn retryOk(self: *const Self, pseudo: []const u8, tag: *const [c.GCM_TAG]u8) bool {
            return c.ch_quic_retry_ok(&self.quic, pseudo.ptr, pseudo.len, tag) != 0;
        }

        /// ch_quic_key_update.
        pub fn keyUpdate(self: *Self) error{Invalid}!void {
            return chapulin.fromCode(error{Invalid}, c.ch_quic_key_update(&self.quic));
        }

        /// ch_quic_key_phase.
        pub fn keyPhase(self: *const Self) u1 {
            return @intCast(c.ch_quic_key_phase(&self.quic));
        }

        /// ch_quic_drop_previous_keys.
        pub fn dropPreviousKeys(self: *Self) void {
            c.ch_quic_drop_previous_keys(&self.quic);
        }

        /// ch_quic_discard: drops both directions' keys at level.
        pub fn discard(self: *Self, level: Level) error{Invalid}!void {
            return chapulin.fromCode(error{Invalid}, c.ch_quic_discard(&self.quic, @intFromEnum(level)));
        }

        /// ch_quic_state.
        pub fn state(self: *const Self) chapulin.State {
            return @enumFromInt(c.ch_quic_state(&self.quic));
        }

        /// ch_quic_alert: the alert a failure chose, null when none did.
        pub fn alert(self: *const Self) ?u8 {
            const code = c.ch_quic_alert(&self.quic);
            return if (code == 0) null else code;
        }

        /// ch_quic_error_code: what the caller puts in CONNECTION_CLOSE.
        pub fn errorCode(self: *const Self) u64 {
            return c.ch_quic_error_code(&self.quic);
        }

        /// ch_quic_close, then the ticket slot zeroed: every key wiped and
        /// the session dead.
        pub fn close(self: *Self) void {
            c.ch_quic_close(&self.quic);
            self.zeroTicketSlot();
        }

        /// The protocol ALPN selected, null for CH_ALPN_NONE.
        pub fn alpnSelected(self: *const Self) ?[]const u8 {
            const t = &self.quic.t;
            if (t.alpn_selected == c.CH_ALPN_NONE) return null;
            const entry = t.cfg.alpn_protocols[t.alpn_selected];
            return entry.name[0..entry.name_len];
        }

        /// ch_tls.group, null while 0.
        pub fn group(self: *const Self) ?chapulin.Group {
            const code = self.quic.t.group;
            return if (code == 0) null else @enumFromInt(code);
        }

        fn suiteOf(self: *const Self) ?chapulin.Suite {
            const code = self.quic.t.suite;
            return if (code == 0) null else @enumFromInt(code);
        }

        /// ch_tls.psk_selected: a PSK authenticated the handshake.
        pub fn pskSelected(self: *const Self) bool {
            return self.quic.t.psk_selected != 0;
        }

        fn serverCertTypeOf(self: *const Self) chapulin.CertType {
            return @enumFromInt(self.quic.t.server_cert_type);
        }

        fn fromHook(io: ?*anyopaque) *Self {
            const hook: *chapulin.Hook = @ptrCast(@alignCast(io.?));
            return @fieldParentPtr("hook", hook);
        }

        /// Does nothing: ch_quic.levels_ready holds the same bits in the
        /// same call, and keysReady reads them (quic.h).
        fn onLevelReady(_: ?*anyopaque, _: u8, _: u8) callconv(.c) void {}

        fn onTransportParams(io: ?*anyopaque, body: [*c]const u8, n: usize) callconv(.c) void {
            const self = fromHook(io);
            self.peer_params_len = n;
            if (n <= self.peer_params.len) @memcpy(self.peer_params[0..n], body[0..n]);
        }

        fn onCryptoOut(io: ?*anyopaque, level: u8, p: [*c]const u8, n: usize) callconv(.c) c_int {
            const self = fromHook(io);
            const out = self.outgoing orelse return -1;
            if (level >= level_count) return -1;
            const buffer = out.buffers[level];
            if (n > buffer.len - out.written[level]) return -1;
            @memcpy(buffer[out.written[level]..][0..n], p[0..n]);
            out.written[level] += n;
            return 0;
        }

        fn onTicket(io: ?*anyopaque, ticket: [*c]const c.ch_ticket) callconv(.c) void {
            const self = fromHook(io);
            self.zeroTicketSlot();
            if (side == .client) self.ticket = chapulin.Ticket.fromOnTicket(ticket);
        }
    };
}
