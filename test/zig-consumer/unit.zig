//! The API's unit tests, built against one object as bin/unit: the ch_cfg
//! each value's toCfg builds, field by field, the Ticket constructors, the
//! error each ch_err code maps to, and every declaration this object has,
//! compiled. Each test skips what its object lacks, so every configuration
//! runs the part of the API it has.
const std = @import("std");
const chapulin = @import("chapulin");
const c = chapulin.c;
const hooks = @import("hooks.zig");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

comptime {
    hooks.define(&.{c});
}

// A client role: the client entry point of the object's transport, which a
// header declares only where the object defines it.
const has_client = @hasDecl(c, "ch_connect") or @hasDecl(c, "ch_record_init") or @hasDecl(c, "ch_quic_init");
const has_server = @hasField(c.ch_cfg, "srv");
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_alpn = @hasField(c.ch_cfg, "alpn_protocols");
const has_quic = @hasDecl(c, "CH_QUIC_DISCARD");
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");

/// Fails naming the first ch_cfg field whose value differs, nested ones
/// included.
fn expectFields(comptime T: type, want: T, got: T) !void {
    inline for (@typeInfo(T).@"struct".fields) |field| {
        const w = @field(want, field.name);
        const g = @field(got, field.name);
        if (@typeInfo(field.type) == .@"struct") {
            try expectFields(field.type, w, g);
        } else if (!std.meta.eql(w, g)) {
            std.debug.print("ch_cfg.{s} differs\n", .{field.name});
            return error.TestExpectedEqual;
        }
    }
}

// The error each code maps to, written out apart from chapulin.zig's table.
test "each ch_err code maps to its error, and CH_OK to none" {
    const E = chapulin.Error;
    try chapulin.fromCode(E, c.CH_OK);
    try expectError(error.Io, chapulin.fromCode(E, c.CH_EIO));
    try expectError(error.Proto, chapulin.fromCode(E, c.CH_EPROTO));
    try expectError(error.Auth, chapulin.fromCode(E, c.CH_EAUTH));
    try expectError(error.Cap, chapulin.fromCode(E, c.CH_ECAP));
    try expectError(error.Invalid, chapulin.fromCode(E, c.CH_EINVAL));
    if (has_quic) {
        try expectError(error.Discard, chapulin.fromCode(E, c.CH_QUIC_DISCARD));
        try expectError(error.AeadLimit, chapulin.fromCode(E, c.CH_QUIC_AEAD_LIMIT));
    }
    // A call's own set keeps the codes it names.
    try expectError(error.Cap, chapulin.fromCode(error{ Invalid, Cap }, c.CH_ECAP));
    try expectError(error.Invalid, chapulin.fromCode(error{ Invalid, Cap }, c.CH_EINVAL));
}

const anchor_name = [_]u8{ 0x30, 0x01, 0x00 };
const anchor_spki = [_]u8{ 0x30, 0x01, 0x01 };
const pins = [_]chapulin.SpkiPin{ @splat(0xa1), @splat(0xa2) };
const alpn_names = [_][]const u8{ "h2", "http/1.1" };

/// A ticket whose every field holds a value no default gives it, version 2
/// among them in a QUIC object.
fn sampleTicket() !chapulin.Ticket {
    const psk = [_]u8{0x5a} ** c.SHA256_LEN;
    const binding = [_]u8{0x6b} ** c.SHA256_LEN;
    var fields: chapulin.Ticket.Fields = if (has_webpki)
        .{ .identity = "identity", .psk = &psk, .age_add = 0xfedc_ba98, .lifetime_s = 7200, .epoch = 9, .binding = &binding }
    else
        .{ .identity = "identity", .psk = &psk, .age_add = 0xfedc_ba98, .lifetime_s = 7200, .epoch = 9 };
    if (has_quic) fields.quic_version = .v2;
    return chapulin.Ticket.fromFields(fields);
}

/// The fields toCfg sets for a ticket, on top of want.
fn wantTicket(want: *c.ch_cfg, ticket: *const chapulin.Ticket, age_ms: u64) void {
    want.psk = &ticket.ticket.psk;
    want.psk_len = c.SHA256_LEN;
    want.psk_id = &ticket.identity;
    want.psk_id_len = "identity".len;
    want.resumption = 1;
    want.obfuscated_age = c.ch_ticket_obfuscated_age(&ticket.ticket, age_ms);
    want.ticket_age_ms = age_ms;
    want.ticket_lifetime_s = 7200;
    want.ticket_epoch = 9;
    if (has_webpki) want.ticket_binding = &ticket.ticket.binding;
    if (has_quic) want.ticket_quic_version = c.CH_QUIC_VERSION_2;
}

test "Client.toCfg under TRUST=webpki: anchors, hostname, clock, pins, ALPN, a ticket and require_pq" {
    if (!has_client or !has_webpki) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{chapulin.trustAnchor(&anchor_name, &anchor_spki)};
    const alpn = [_]c.ch_alpn_protocol{ chapulin.alpnProtocol(alpn_names[0]), chapulin.alpnProtocol(alpn_names[1]) };
    const ticket = try sampleTicket();
    const age_ms: u64 = (1 << 32) + 1234;
    const got = (chapulin.Client{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "s3.example.test", .now_seconds = 1782864000, .pins = &pins } },
        .alpn = &alpn,
        .ticket = &ticket,
        .ticket_age_ms = age_ms,
        .require_pq = true,
    }).toCfg();
    var want = std.mem.zeroes(c.ch_cfg);
    want.anchors = &anchors;
    want.anchor_count = 1;
    want.hostname = "s3.example.test";
    want.hostname_len = "s3.example.test".len;
    want.now_seconds = 1782864000;
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    want.alpn_protocols = &alpn;
    want.alpn_count = 2;
    want.require_pq = 1;
    wantTicket(&want, &ticket, age_ms);
    try expectFields(c.ch_cfg, want, got);
    // toCfg passes the whole 64-bit age, and the obfuscated age is its sum with
    // age_add modulo 2^32 (RFC 9846 section 4.3.11.1).
    try expectEqual(@as(u32, 1234 +% 0xfedc_ba98), got.obfuscated_age);
}

test "Client.toCfg under TRUST=webpki: pins alone, with and without a server name" {
    if (!has_client or !has_webpki) return error.SkipZigTest;
    var want = std.mem.zeroes(c.ch_cfg);
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    try expectFields(c.ch_cfg, want, (chapulin.Client{ .trust = .{ .pins = .{ .pins = &pins } } }).toCfg());
    want.hostname = "dns.example";
    want.hostname_len = "dns.example".len;
    try expectFields(c.ch_cfg, want, (chapulin.Client{ .trust = .{ .pins = .{ .pins = &pins, .server_name = "dns.example" } } }).toCfg());
}

test "Client.toCfg under SUITE=aesgcm TRUST=webpki: the suite order, empty for the build's own" {
    if (!has_client or !@hasField(c.ch_cfg, "cipher_suites")) return error.SkipZigTest;
    const suites = [_]chapulin.Suite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    var values: chapulin.Client = .{ .trust = .{ .pins = .{ .pins = &pins } } };
    var want = std.mem.zeroes(c.ch_cfg);
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    try expectFields(c.ch_cfg, want, values.toCfg());
    values.cipher_suites = &suites;
    want.cipher_suites = @ptrCast(&suites);
    want.cipher_suite_count = 2;
    try expectFields(c.ch_cfg, want, values.toCfg());
}

test "Client.toCfg under a raw or ca mode: both pins, and a ticket in their place" {
    if (!has_client or has_webpki) return error.SkipZigTest;
    const key = [_]u8{0x11} ** 64;
    const next = [_]u8{0x22} ** 64;
    var want = std.mem.zeroes(c.ch_cfg);
    want.server_pubkey = &key;
    want.server_pubkey_len = key.len;
    want.server_pubkey2 = &next;
    want.server_pubkey2_len = next.len;
    try expectFields(c.ch_cfg, want, (chapulin.Client{ .trust = .{ .pinned = .{ .server_pubkey = &key, .server_pubkey2 = &next } } }).toCfg());
    const ticket = try sampleTicket();
    want = std.mem.zeroes(c.ch_cfg);
    wantTicket(&want, &ticket, 250);
    const values: chapulin.Client = .{ .trust = .{ .pinned = .{ .server_pubkey = &key } }, .ticket = &ticket, .ticket_age_ms = 250 };
    try expectFields(c.ch_cfg, want, values.toCfg());
}

test "Server.toCfg: both identities, the keys, the clock, ALPN, the SNI rule and the suite order" {
    if (!has_server) return error.SkipZigTest;
    const chain = [_]c.ch_cert{ chapulin.cert("leaf"), chapulin.cert("intermediate") };
    const point = [_]u8{0x31} ** 64;
    const scalar = [_]u8{0x32} ** 32;
    const modulus = [_]u8{0x33} ** 256;
    const rsa_key = std.mem.zeroes(c.ch_rsa_priv);
    const cookie_key = [_]u8{0x34} ** c.CH_SRV_COOKIE_KEY_LEN;
    const ticket_key = [_]u8{0x35} ** c.CH_SRV_TICKET_KEY_LEN;
    const alpn = [_]c.ch_alpn_protocol{chapulin.alpnProtocol(alpn_names[1])};
    var values: chapulin.Server = .{
        .ecdsa_p256 = .{ .chain = &chain, .public_key = &point, .private_key = &scalar },
        .rsa_pss = .{ .chain = chain[1..], .public_key = &modulus, .private_key = &rsa_key },
        .cookie_key = &cookie_key,
        .ticket_key = &ticket_key,
        .now_seconds = 1700000000,
        .alpn = &alpn,
        .require_server_name = true,
    };
    const suites = [_]chapulin.Suite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    if (@hasField(c.ch_srv_cfg, "cipher_suites")) values.cipher_suites = &suites;
    var want = std.mem.zeroes(c.ch_cfg);
    want.srv.ecdsa_p256 = .{ .chain = &chain, .chain_count = 2, .priv = &scalar, .priv_len = 32, .@"pub" = &point, .pub_len = 64 };
    want.srv.rsa_pss = .{ .chain = chain[1..].ptr, .chain_count = 1, .priv = &rsa_key, .priv_len = @sizeOf(c.ch_rsa_priv), .@"pub" = &modulus, .pub_len = 256 };
    want.srv.cookie_key = &cookie_key;
    want.srv.ticket_key = &ticket_key;
    want.srv.now_seconds = 1700000000;
    want.alpn_protocols = &alpn;
    want.alpn_count = 1;
    want.srv.require_server_name = 1;
    if (@hasField(c.ch_srv_cfg, "cipher_suites")) {
        want.srv.cipher_suites = @ptrCast(&suites);
        want.srv.cipher_suite_count = 2;
    }
    try expectFields(c.ch_cfg, want, try values.toCfg());

    // chain_count is a u8: 255 certificates fit it and 256 do not.
    const long = [_]c.ch_cert{chapulin.cert("x")} ** 256;
    values.ecdsa_p256.?.chain = long[0..255];
    try expectEqual(@as(u8, 255), (try values.toCfg()).srv.ecdsa_p256.chain_count);
    values.ecdsa_p256.?.chain = &long;
    try expectError(error.Invalid, values.toCfg());
    try expectError(error.Invalid, values.check());
}

test "Client.toCfg and Server.toCfg under TRANSPORT=quic-nonblocking: the original version, and 0 for none" {
    if (!has_quic) return error.SkipZigTest;
    const key = [_]u8{0x11} ** 64;
    if (has_client) {
        var values: chapulin.Client = .{ .trust = if (has_webpki) .{ .pins = .{ .pins = &pins } } else .{ .pinned = .{ .server_pubkey = &key } } };
        try expectEqual(@as(u32, 0), values.toCfg().quic_original_version);
        values.quic_version = .v1;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_1), values.toCfg().quic_original_version);
        values.quic_version = .v2;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_2), values.toCfg().quic_original_version);
    }
    if (has_server) {
        const cookie_key = [_]u8{0x34} ** c.CH_SRV_COOKIE_KEY_LEN;
        var values: chapulin.Server = .{ .cookie_key = &cookie_key, .now_seconds = 0 };
        try expectEqual(@as(u32, 0), (try values.toCfg()).quic_original_version);
        values.quic_version = .v1;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_1), (try values.toCfg()).quic_original_version);
    }
}

test "Ticket.fromFields: the identity cap and the hash lengths" {
    const id_max = [_]u8{0x41} ** (c.CH_TICKET_ID_MAX + 1);
    const psk = [_]u8{0x42} ** 48;
    const binding = [_]u8{0} ** c.SHA256_LEN;
    const Fields = chapulin.Ticket.Fields;
    var fields: Fields = if (has_webpki)
        .{ .identity = id_max[0..c.CH_TICKET_ID_MAX], .psk = psk[0..32], .age_add = 1, .lifetime_s = 2, .binding = &binding }
    else
        .{ .identity = id_max[0..c.CH_TICKET_ID_MAX], .psk = psk[0..32], .age_add = 1, .lifetime_s = 2 };
    const ticket = try chapulin.Ticket.fromFields(fields);
    try expectEqual(@as(usize, c.CH_TICKET_ID_MAX), ticket.ticket.identity_len);
    try expect(ticket.ticket.identity == null);
    try expectEqual(@as(u32, 1), ticket.ticket.age_add);
    try expectEqual(@as(u32, 2), ticket.ticket.lifetime_s);
    fields.identity = &id_max;
    try expectError(error.Invalid, chapulin.Ticket.fromFields(fields));
    fields.identity = "id";
    fields.psk = psk[0..31];
    try expectError(error.Invalid, chapulin.Ticket.fromFields(fields));
    fields.psk = &psk;
    if (c.HKDF_HASH_MAX == 48) {
        try expectEqual(@as(usize, 48), (try chapulin.Ticket.fromFields(fields)).ticket.psk_len);
    } else {
        try expectError(error.Invalid, chapulin.Ticket.fromFields(fields));
    }
}

test "Ticket.fromFields and fromOnTicket under TRANSPORT=quic-nonblocking: the ticket's version, and 0 for none" {
    if (!has_quic) return error.SkipZigTest;
    const psk = [_]u8{0x42} ** c.SHA256_LEN;
    const binding = [_]u8{0} ** c.SHA256_LEN;
    var fields: chapulin.Ticket.Fields = if (has_webpki)
        .{ .identity = "id", .psk = &psk, .age_add = 1, .lifetime_s = 2, .binding = &binding }
    else
        .{ .identity = "id", .psk = &psk, .age_add = 1, .lifetime_s = 2 };
    try expectEqual(@as(u32, 0), (try chapulin.Ticket.fromFields(fields)).ticket.quic_version);
    fields.quic_version = .v1;
    try expectEqual(@as(u32, c.CH_QUIC_VERSION_1), (try chapulin.Ticket.fromFields(fields)).ticket.quic_version);
    var handed = std.mem.zeroes(c.ch_ticket);
    handed.identity = "id";
    handed.identity_len = 2;
    handed.quic_version = c.CH_QUIC_VERSION_2;
    try expectEqual(@as(u32, c.CH_QUIC_VERSION_2), chapulin.Ticket.fromOnTicket(&handed).?.ticket.quic_version);
}

test "Ticket.fromOnTicket copies the identity and drops the pointer to it" {
    var handed = std.mem.zeroes(c.ch_ticket);
    const identity = "handed over";
    handed.identity = identity;
    handed.identity_len = identity.len;
    handed.psk_len = c.SHA256_LEN;
    handed.age_add = 77;
    const kept = chapulin.Ticket.fromOnTicket(&handed).?;
    try expect(kept.ticket.identity == null);
    try expect(std.mem.eql(u8, identity, kept.identity[0..kept.ticket.identity_len]));
    try expectEqual(@as(u32, 77), kept.ticket.age_add);
    handed.identity_len = c.CH_TICKET_ID_MAX + 1;
    try expect(chapulin.Ticket.fromOnTicket(&handed) == null);
}

/// A std.Random that writes a byte counter and counts its fills, so a
/// test can tell which bytes a session drew and from where.
const CountingRandom = struct {
    fills: usize = 0,
    next: u8 = 1,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *CountingRandom = @ptrCast(@alignCast(ptr));
        self.fills += 1;
        for (buf) |*byte| {
            byte.* = self.next;
            self.next +%= 1;
        }
    }

    fn random(self: *CountingRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

test "RAND=session: init refuses a value with no random, and a session draws from the one it stores" {
    if (!has_rand_session or !@hasDecl(c, "ch_record_init") or !has_webpki) return error.SkipZigTest;
    // Placeholders: init checks that each field is set, and no
    // certificate arrives here.
    const placeholder = [_]u8{ 0x30, 0x00 };
    const anchors = [_]c.ch_trust_anchor{chapulin.trustAnchor(&placeholder, &placeholder)};
    var values: chapulin.Client = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "dns.example", .now_seconds = 1789000000 } } };
    var session: chapulin.record.Client(c.CH_MIN_RXBUF) = undefined;
    try expectError(error.Invalid, session.init(values));
    try expect(session.recordState() == .failed);

    var counting: CountingRandom = .{};
    values.random = counting.random();
    try session.init(values);
    // The session holds its own copy, which rand_io names, and every
    // draw was a fill of it: the x25519 scalar first, then the random.
    try expect(session.record.t.cfg.rand_io == @as(?*anyopaque, @ptrCast(&session.random)));
    try expect(counting.fills >= 2);
    var hello: [c.CH_TX_STAGE]u8 = undefined;
    const n = try session.recordOut(&hello);
    try expect(n >= 11 + 32);
    for (hello[11..][0..32], 33..) |byte, want| try expectEqual(@as(u8, @intCast(want)), byte);
    session.recordClose();
}

/// Refers to each named declaration of T, so it compiles.
fn compile(comptime T: type, comptime names: []const []const u8) void {
    inline for (names) |name| _ = &@field(T, name);
}

test "every declaration this object has compiles" {
    compile(chapulin, &.{ "fromCode", "buildMatches", "Group", "Suite", "State", "Hook", "RandomSource", "attachRandom" });
    try expect(chapulin.buildMatches());
    if (has_client) compile(chapulin, &.{ "Client", "Ticket", "Trust" });
    if (has_server) compile(chapulin, &.{ "Server", "cert", "EcdsaP256Identity", "RsaPssIdentity" });
    if (has_webpki) compile(chapulin, &.{ "trustAnchor", "CertType" });
    if (has_alpn) compile(chapulin, &.{"alpnProtocol"});
    if (@hasDecl(c, "ch_keylog")) compile(chapulin, &.{"hookContext"});
    const record = [_][]const u8{ "init", "recordIn", "recordState", "alertSent", "alertReceived", "read", "write", "writableLen", "close", "recordClose", "group", "pskSelected", "peerLimit", "readClosed", "replyLen" };
    const quic = [_][]const u8{ "init", "cryptoIn", "initialKeys", "keysReady", "peerTransportParams", "seal", "sealClose", "open", "retryOk", "negotiatedVersion", "keyUpdate", "keyPhase", "dropPreviousKeys", "discard", "state", "alert", "alertSent", "alertReceived", "errorCode", "close", "alpnSelected", "group", "pskSelected" };
    if (@hasDecl(c, "ch_record_init")) compileSession(chapulin.record.Client(c.CH_MIN_RXBUF), &(record ++ .{ "recordOut", "takeTicket" }));
    if (@hasDecl(c, "ch_srv_record_init")) compileSession(chapulin.record.Server(c.CH_MIN_RXBUF), &(record ++ .{ "sni", "outputLen" }));
    if (has_quic) compile(chapulin.quic, &.{"Version"});
    if (@hasDecl(c, "ch_quic_init")) compileSession(chapulin.quic.Client(c.CH_MIN_RXBUF), &(quic ++ .{ "cryptoOut", "takeTicket", "switchVersion" }));
    if (@hasDecl(c, "ch_srv_quic_init")) {
        compileSession(chapulin.quic.Server(c.CH_MIN_RXBUF), &(quic ++ .{"sni"}));
        compile(chapulin.quic, &.{ "retryTag", "tokenMint", "tokenCheck", "ChooseVersion" });
    }
}

/// compile, and the calls a session declares only where its ch_tls or the
/// object has what they read.
fn compileSession(comptime T: type, comptime names: []const []const u8) void {
    compile(T, names);
    if (@hasField(c.ch_tls, "alpn_selected")) compile(T, &.{"alpnSelected"});
    if (@hasField(c.ch_tls, "suite")) compile(T, &.{"suite"});
    if (@hasField(c.ch_tls, "server_cert_type")) compile(T, &.{"serverCertType"});
    if (@hasDecl(c, "ch_export") and @hasDecl(T, "exportKeyingMaterial")) compile(T, &.{"exportKeyingMaterial"});
}
