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

/// The C arrays the ch_cfg builder fills at the default Limits, which every cfg below points
/// into. chapulin.testing is that builder, which a test build alone reaches.
var lists: chapulin.testing.Lists(.{}) = undefined;

/// The ch_cfg values build, into the shared lists.
fn cfgOf(values: anytype) error{Invalid}!c.ch_cfg {
    if (comptime has_server and @TypeOf(values) == chapulin.Server) return chapulin.testing.serverCfg(values, .{}, &lists);
    return chapulin.testing.clientCfg(values, .{}, &lists);
}

comptime {
    hooks.define(&.{c});
}

// A client role: the client entry point of the object's transport, which a
// header declares only where the object defines it.
const has_client = @hasDecl(c, "ch_connect") or @hasDecl(c, "ch_record_init") or @hasDecl(c, "ch_quic_init");
const has_server = @hasField(c.ch_cfg, "srv");
// A PROFILE=cnsa2 server holds the ML-DSA-87 slot alone, and every other
// host server holds it beside the ECDSA and RSA slots (docs/decisions.md
// 180), as chapulin.zig reads them.
const has_mldsa_server = has_server and @hasField(c.ch_srv_cfg, "mldsa87");
const has_classic_server = has_server and @hasField(c.ch_srv_cfg, "ecdsa_p256");
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_alpn = @hasField(c.ch_cfg, "alpn_protocols");
const has_quic = @hasDecl(c, "CH_QUIC_DISCARD");
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");
const has_cpu = @hasField(c.ch_cfg, "cpu");

/// Fails naming the first ch_cfg field whose value differs, nested ones
/// included.
/// A clock that answers the u64 its clock_io points at (fixture.zig's clockAt).
fn readSeconds(clock_io: ?*anyopaque) callconv(.c) u64 {
    const seconds: *const u64 = @ptrCast(@alignCast(clock_io.?));
    return seconds.*;
}

fn clockAt(seconds: *const u64) chapulin.Clock {
    return .{ .now_seconds = readSeconds, .clock_io = @constCast(seconds) };
}

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
    } else {
        try expectError(error.KeyUpdateLimit, chapulin.fromCode(E, c.CH_KEY_UPDATE_LIMIT));
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
        .{ .identity = "identity", .psk = &psk, .age_add = 0xfedc_ba98, .lifetime_s = 7200, .epoch = 9, .trust_hash = &binding };
    if (has_quic) fields.quic_version = .v2;
    return chapulin.Ticket.fromFields(fields);
}

/// The fields toCfg sets for a ticket, on top of want: the ticket's own bytes and its age.
fn wantTicket(want: *c.ch_cfg, ticket: *const chapulin.Ticket, age_ms: u64) void {
    want.ticket = ticket.saved();
    want.ticket_age_ms = age_ms;
}

test "the Client values\' ch_cfg under TRUST=webpki: anchors, hostname, clock, pins, ALPN, a ticket and require_pq" {
    if (!has_client or !has_webpki) return error.SkipZigTest;
    const anchors = [_]chapulin.TrustAnchor{.{ .name = &anchor_name, .spki = &anchor_spki }};
    const alpn = [_][]const u8{ alpn_names[0], alpn_names[1] };
    const ticket = try sampleTicket();
    const age_ms: u64 = (1 << 32) + 1234;
    const seconds: u64 = 1782864000;
    const clock = clockAt(&seconds);
    const got = (try cfgOf(chapulin.Client{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "s3.example.test", .clock = clock, .pins = &pins } },
        .alpn = &alpn,
        .ticket = &ticket,
        .ticket_age_ms = age_ms,
        .require_pq = true,
    }));
    var want = std.mem.zeroes(c.ch_cfg);
    want.anchors = &lists.anchors;
    want.anchor_count = 1;
    want.hostname = "s3.example.test";
    want.hostname_len = "s3.example.test".len;
    want.now_seconds = clock.now_seconds;
    want.clock_io = clock.clock_io;
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    want.alpn_protocols = &lists.alpn;
    want.alpn_count = 2;
    want.require_pq = 1;
    wantTicket(&want, &ticket, age_ms);
    try expectFields(c.ch_cfg, want, got);
    // toCfg passes the whole 64-bit age, and the ticket's own fields, which the C entries read.
    try expectEqual(age_ms, got.ticket_age_ms);
    try expectEqual(@as(u32, 7200), got.ticket.*.ticket.lifetime_s);
    try expectEqual(@as(u32, 9), got.ticket.*.ticket.epoch);
    // The lists hold each value's C form, pointing at the caller's bytes.
    try expectEqual(@as([*c]const u8, &anchor_name), lists.anchors[0].name);
    try expectEqual(anchor_name.len, lists.anchors[0].name_len);
    try expectEqual(@as([*c]const u8, &anchor_spki), lists.anchors[0].spki);
    try expectEqual(anchor_spki.len, lists.anchors[0].spki_len);
    for (alpn_names, lists.alpn[0..2]) |name, entry| {
        try expectEqual(@as([*c]const u8, name.ptr), entry.name);
        try expectEqual(name.len, entry.name_len);
    }
}

test "the Client values\' ch_cfg under TRUST=webpki: a list over its cap is refused" {
    if (!has_client or !has_webpki) return error.SkipZigTest;
    const one: chapulin.TrustAnchor = .{ .name = &anchor_name, .spki = &anchor_spki };
    const many = [_]chapulin.TrustAnchor{one} ** (chapulin.Limits{}).anchors_max ++ [_]chapulin.TrustAnchor{one};
    const web = struct {
        fn values(anchors: []const chapulin.TrustAnchor, alpn: []const []const u8) chapulin.Client {
            return .{ .trust = .{ .web_pki = .{ .anchors = anchors, .server_name = "s3.example.test", .clock = clockAt(&no_seconds) } }, .alpn = alpn };
        }
        const no_seconds: u64 = 0;
    };
    // The last list each cap takes, and the first it refuses.
    _ = try cfgOf(web.values(many[1..], &.{}));
    try expectError(error.Invalid, cfgOf(web.values(&many, &.{})));
    const names = [_][]const u8{"h2"} ** (c.CH_ALPN_MAX + 1);
    _ = try cfgOf(web.values(many[0..1], names[1..]));
    try expectError(error.Invalid, cfgOf(web.values(many[0..1], &names)));
}

test "the Client values\' ch_cfg under TRUST=webpki: pins alone, with and without a server name" {
    if (!has_client or !has_webpki) return error.SkipZigTest;
    var want = std.mem.zeroes(c.ch_cfg);
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    try expectFields(c.ch_cfg, want, (try cfgOf(chapulin.Client{ .trust = .{ .pins = .{ .pins = &pins } } })));
    want.hostname = "dns.example";
    want.hostname_len = "dns.example".len;
    try expectFields(c.ch_cfg, want, (try cfgOf(chapulin.Client{ .trust = .{ .pins = .{ .pins = &pins, .server_name = "dns.example" } } })));
}

test "the Client values\' ch_cfg under SUITE=aesgcm TRUST=webpki: the suite order, empty for the build's own" {
    if (!has_client or !@hasField(c.ch_cfg, "cipher_suites")) return error.SkipZigTest;
    const suites = [_]chapulin.Suite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    var values: chapulin.Client = .{ .trust = .{ .pins = .{ .pins = &pins } } };
    var want = std.mem.zeroes(c.ch_cfg);
    want.spki_pins = @ptrCast(&pins);
    want.spki_pin_count = 2;
    try expectFields(c.ch_cfg, want, (try cfgOf(values)));
    values.cipher_suites = &suites;
    want.cipher_suites = @ptrCast(&suites);
    want.cipher_suite_count = 2;
    try expectFields(c.ch_cfg, want, (try cfgOf(values)));
}

test "the Client values\' ch_cfg and Server.toCfg in a host object: CH_CPU_PROBED and each bit the values state, and 0 for none" {
    if (!has_cpu) return error.SkipZigTest;
    const descriptions = [_]?chapulin.Cpu{
        null,
        .{},
        .{ .constant_time_aes = true },
        .{ .constant_time_multiply = true },
        .{ .avx2 = true },
        .{ .vaes = true },
        .{ .constant_time_sha256 = true },
        .{ .constant_time_sha512 = true },
        .{ .constant_time_sha3 = true },
        .{ .avx512_ifma = true },
        .{ .avx512 = true },
        .{ .constant_time_aes = true, .constant_time_multiply = true, .avx2 = true, .vaes = true, .constant_time_sha256 = true, .constant_time_sha512 = true, .constant_time_sha3 = true, .avx512_ifma = true, .avx512 = true },
    };
    const probed = c.CH_CPU_PROBED;
    const codes = [_]u32{
        0,
        probed,
        probed | c.CH_CPU_CONSTANT_TIME_AES,
        probed | c.CH_CPU_CONSTANT_TIME_MULTIPLY,
        probed | c.CH_CPU_AVX2,
        probed | c.CH_CPU_VAES,
        probed | c.CH_CPU_CONSTANT_TIME_SHA256,
        probed | c.CH_CPU_CONSTANT_TIME_SHA512,
        probed | c.CH_CPU_CONSTANT_TIME_SHA3,
        probed | c.CH_CPU_AVX512_IFMA,
        probed | c.CH_CPU_AVX512,
        probed | c.CH_CPU_CONSTANT_TIME_AES | c.CH_CPU_CONSTANT_TIME_MULTIPLY | c.CH_CPU_AVX2 | c.CH_CPU_VAES | c.CH_CPU_CONSTANT_TIME_SHA256 | c.CH_CPU_CONSTANT_TIME_SHA512 | c.CH_CPU_CONSTANT_TIME_SHA3 | c.CH_CPU_AVX512_IFMA | c.CH_CPU_AVX512,
    };
    for (descriptions, codes) |description, code| {
        if (has_client) {
            const key = [_]u8{0x11} ** 64;
            const trust: chapulin.Trust = if (has_webpki) .{ .pins = .{ .pins = &pins } } else .{ .pinned = .{ .server_pubkey = &key } };
            const values: chapulin.Client = .{ .trust = trust, .cpu = description };
            try expectEqual(code, (try cfgOf(values)).cpu);
        }
        if (has_server) {
            const key = [_]u8{7} ** c.CH_SRV_COOKIE_KEY_LEN;
            const values: chapulin.Server = .{ .cookie_key = &key, .cpu = description };
            try expectEqual(code, (try cfgOf(values)).cpu);
        }
    }
}

test "the Client values\' ch_cfg under a raw or ca mode: both pins, and a ticket beside them" {
    if (!has_client or has_webpki) return error.SkipZigTest;
    const key = [_]u8{0x11} ** 64;
    const next = [_]u8{0x22} ** 64;
    var want = std.mem.zeroes(c.ch_cfg);
    want.server_pubkey = &key;
    want.server_pubkey_len = key.len;
    want.server_pubkey2 = &next;
    want.server_pubkey2_len = next.len;
    try expectFields(c.ch_cfg, want, (try cfgOf(chapulin.Client{ .trust = .{ .pinned = .{ .server_pubkey = &key, .server_pubkey2 = &next } } })));
    // The pin stays set: the C entries offer the ticket in its place.
    const ticket = try sampleTicket();
    want = std.mem.zeroes(c.ch_cfg);
    want.server_pubkey = &key;
    want.server_pubkey_len = key.len;
    wantTicket(&want, &ticket, 250);
    const values: chapulin.Client = .{ .trust = .{ .pinned = .{ .server_pubkey = &key } }, .ticket = &ticket, .ticket_age_ms = 250 };
    try expectFields(c.ch_cfg, want, (try cfgOf(values)));
}

test "the Server values\' ch_cfg: the ML-DSA-87 identity and its chain's u8" {
    if (!has_mldsa_server) return error.SkipZigTest;
    const chain = [_][]const u8{"leaf"};
    const public_key = [_]u8{0x31} ** 2592;
    const private_key = [_]u8{0x32} ** 4896;
    const cookie_key = [_]u8{0x34} ** c.CH_SRV_COOKIE_KEY_LEN;
    var values: chapulin.Server = .{
        .mldsa87 = .{ .chain = &chain, .public_key = &public_key, .private_key = &private_key },
        .cookie_key = &cookie_key,
    };
    var want = std.mem.zeroes(c.ch_cfg);
    want.srv.mldsa87 = .{ .chain = &lists.mldsa_chain, .chain_count = 1, .priv = &private_key, .priv_len = 4896, .@"pub" = &public_key, .pub_len = 2592 };
    want.srv.cookie_key = &cookie_key;
    try expectFields(c.ch_cfg, want, try cfgOf(values));
    try expectEqual(@as([*c]const u8, chain[0].ptr), lists.mldsa_chain[0].der);
    // Limits.chain_max certificates fit, and one more does not.
    const long = [_][]const u8{"x"} ** ((chapulin.Limits{}).chain_max + 1);
    values.mldsa87.?.chain = long[1..];
    _ = try cfgOf(values);
    values.mldsa87.?.chain = &long;
    try expectError(error.Invalid, cfgOf(values));
}

test "the Server values\' ch_cfg: both identities, the keys, the clock, ALPN, the SNI rule and the suite order" {
    if (!has_classic_server) return error.SkipZigTest;
    const chain = [_][]const u8{ "leaf", "intermediate" };
    const point = [_]u8{0x31} ** 64;
    const scalar = [_]u8{0x32} ** 32;
    const modulus = [_]u8{0x33} ** 256;
    const rsa_key = std.mem.zeroes(c.ch_rsa_priv);
    const cookie_key = [_]u8{0x34} ** c.CH_SRV_COOKIE_KEY_LEN;
    const ticket_key = [_]u8{0x35} ** c.CH_SRV_TICKET_KEY_LEN;
    const alpn = [_][]const u8{alpn_names[1]};
    const seconds: u64 = 1700000000;
    const clock = clockAt(&seconds);
    var values: chapulin.Server = .{
        .ecdsa_p256 = .{ .chain = &chain, .public_key = &point, .private_key = &scalar },
        .rsa_pss = .{ .chain = chain[1..], .public_key = &modulus, .private_key = &rsa_key },
        .cookie_key = &cookie_key,
        .ticket_key = &ticket_key,
        .clock = clock,
        .alpn = &alpn,
        .require_server_name = true,
    };
    const suites = [_]chapulin.Suite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
    if (@hasField(c.ch_srv_cfg, "cipher_suites")) values.cipher_suites = &suites;
    var want = std.mem.zeroes(c.ch_cfg);
    want.srv.ecdsa_p256 = .{ .chain = &lists.ecdsa_chain, .chain_count = 2, .priv = &scalar, .priv_len = 32, .@"pub" = &point, .pub_len = 64 };
    want.srv.rsa_pss = .{ .chain = &lists.rsa_chain, .chain_count = 1, .priv = &rsa_key, .priv_len = @sizeOf(c.ch_rsa_priv), .@"pub" = &modulus, .pub_len = 256 };
    want.srv.cookie_key = &cookie_key;
    want.srv.ticket_key = &ticket_key;
    want.now_seconds = clock.now_seconds;
    want.clock_io = clock.clock_io;
    want.alpn_protocols = &lists.alpn;
    want.alpn_count = 1;
    want.srv.require_server_name = 1;
    if (@hasField(c.ch_srv_cfg, "cipher_suites")) {
        want.srv.cipher_suites = @ptrCast(&suites);
        want.srv.cipher_suite_count = 2;
    }
    try expectFields(c.ch_cfg, want, try cfgOf(values));
    for (chain, lists.ecdsa_chain[0..2]) |der, entry| {
        try expectEqual(@as([*c]const u8, der.ptr), entry.der);
        try expectEqual(der.len, entry.len);
    }
    try expectEqual(@as([*c]const u8, chain[1].ptr), lists.rsa_chain[0].der);

    // Limits.chain_max certificates fit the default lists, and one more does not.
    const long = [_][]const u8{"x"} ** 256;
    const chain_max = (chapulin.Limits{}).chain_max;
    values.ecdsa_p256.?.chain = long[0..chain_max];
    try expectEqual(@as(u8, chain_max), (try cfgOf(values)).srv.ecdsa_p256.chain_count);
    values.ecdsa_p256.?.chain = long[0 .. chain_max + 1];
    try expectError(error.Invalid, cfgOf(values));
    // check holds its lists at the C cap: chain_count is a u8, so 256 do not fit.
    values.ecdsa_p256.?.chain = &long;
    try expectError(error.Invalid, values.check());
}

test "the Client values\' ch_cfg and Server.toCfg under TRANSPORT=quic-nonblocking: the original version, and 0 for none" {
    if (!has_quic) return error.SkipZigTest;
    const key = [_]u8{0x11} ** 64;
    if (has_client) {
        var values: chapulin.Client = .{ .trust = if (has_webpki) .{ .pins = .{ .pins = &pins } } else .{ .pinned = .{ .server_pubkey = &key } } };
        try expectEqual(@as(u32, 0), (try cfgOf(values)).quic_original_version);
        values.quic_version = .v1;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_1), (try cfgOf(values)).quic_original_version);
        values.quic_version = .v2;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_2), (try cfgOf(values)).quic_original_version);
    }
    if (has_server) {
        const cookie_key = [_]u8{0x34} ** c.CH_SRV_COOKIE_KEY_LEN;
        var values: chapulin.Server = .{ .cookie_key = &cookie_key };
        try expectEqual(@as(u32, 0), (try cfgOf(values)).quic_original_version);
        values.quic_version = .v1;
        try expectEqual(@as(u32, c.CH_QUIC_VERSION_1), (try cfgOf(values)).quic_original_version);
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
        .{ .identity = id_max[0..c.CH_TICKET_ID_MAX], .psk = psk[0..32], .age_add = 1, .lifetime_s = 2, .trust_hash = &binding };
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
        .{ .identity = "id", .psk = &psk, .age_add = 1, .lifetime_s = 2, .trust_hash = &binding };
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
    const anchors = [_]chapulin.TrustAnchor{.{ .name = &placeholder, .spki = &placeholder }};
    const seconds: u64 = 1789000000;
    var values: chapulin.Client = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "dns.example", .clock = clockAt(&seconds) } } };
    // A host object's init refuses a value without CH_CPU_PROBED, so the
    // value states the probe's bit, and the first refusal is the random's.
    if (comptime has_cpu) values.cpu = .{};
    var session: chapulin.record.Client(c.CH_MIN_RXBUF, .{}) = undefined;
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

test "the PEM files: a refusal is error.Invalid, a room is the caller's, and a refused key is zero" {
    if (!has_server and !has_webpki) return error.SkipZigTest;
    const not_pem = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n";
    // One certificate's outer fields, a one-byte UTF8String subject and a
    // NULL key: 27 bytes of DER, which both rooms below hold exactly.
    const one = "-----BEGIN CERTIFICATE-----\nMBkwEgIBATAAMAAwADADDAFhMAIFADAAAwEA\n-----END CERTIFICATE-----\n";
    var der: [27]u8 = undefined;
    if (has_server) {
        var entries: [1][]const u8 = undefined;
        try expectError(error.Invalid, chapulin.Chain.fromPem(not_pem, &der, &entries));
        const chain = try chapulin.Chain.fromPem(one, &der, &entries);
        try expectEqual(@as([*]const u8, &der), chain.certs[0].ptr);
        try expectEqual(@as(usize, 1), chain.certs.len);
        try expectEqual(@as(usize, 27), chain.leaf().len);
        try expectError(error.Invalid, chapulin.Chain.fromPem(one, der[0..26], &entries));
        try expectError(error.Invalid, chapulin.Chain.fromPem(one, &der, entries[0..0]));
        try expectEqual(@as(usize, 0), (chapulin.Chain{}).leaf().len);
        if (has_classic_server) {
            var key: chapulin.EcdsaP256Key = .{};
            @memset(&key.private_key, 0x5a);
            try expectError(error.Invalid, key.fromPem(if (has_cpu) .{} else {}, not_pem, chain.leaf()));
            try expect(std.mem.allEqual(u8, &key.private_key, 0) and std.mem.allEqual(u8, &key.public_key, 0));
            @memset(&key.private_key, 0x5a);
            key.wipe();
            try expect(std.mem.allEqual(u8, &key.private_key, 0));
        }
        if (has_mldsa_server) {
            var key: chapulin.MlDsa87Key = .{};
            @memset(&key.private_key, 0x5a);
            try expectError(error.Invalid, key.fromPem(.{}, not_pem, chain.leaf()));
            try expect(std.mem.allEqual(u8, &key.private_key, 0) and std.mem.allEqual(u8, &key.public_key, 0));
            @memset(&key.private_key, 0x5a);
            key.wipe();
            try expect(std.mem.allEqual(u8, &key.private_key, 0));
        }
    }
    if (has_webpki) {
        var entries: [1]chapulin.TrustAnchor = undefined;
        try expectError(error.Invalid, chapulin.Anchors.fromPem(.{}, "# a comment, and no block\n", &der, &entries));
        const anchors = try chapulin.Anchors.fromPem(.{}, one, &der, &entries);
        try expectEqual(@as(usize, 1), anchors.anchors.len);
        try expectError(error.Invalid, chapulin.Anchors.fromPem(.{}, one, der[0..26], &entries));
        // A bundle over the session type's anchors_max is refused, as a session would refuse it.
        try expectError(error.Invalid, chapulin.Anchors.fromPem(.{ .anchors_max = 0 }, one, &der, &entries));
    }
}

test "DNSSEC=on: the hashes match std.crypto, and P-256, P-384 and Ed25519 signatures std.crypto makes verify" {
    if (!@hasDecl(c, "ch_dnssec_verify")) return error.SkipZigTest;
    const dnssec = chapulin.dnssec;
    const msg = "chapulin dnssec through the Zig API";
    var out: [c.CH_DNSSEC_DIGEST_MAX]u8 = undefined;

    var h256 = try dnssec.Hash.init(.ecdsap256sha256, &.{}, &.{});
    h256.update(msg[0..5]);
    h256.update(msg[5..]);
    var want256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &want256, .{});
    const digest = h256.final(&out);
    try std.testing.expectEqualSlices(u8, &want256, digest);

    var h512 = try dnssec.Hash.init(.rsasha512, &.{}, &.{});
    h512.update(msg);
    var want512: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(msg, &want512, .{});
    var out512: [c.CH_DNSSEC_DIGEST_MAX]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &want512, h512.final(&out512));

    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = try Ecdsa.KeyPair.generateDeterministic([_]u8{0x42} ** Ecdsa.KeyPair.seed_length);
    const sig = (try kp.sign(msg, null)).toBytes();
    const key = kp.public_key.toUncompressedSec1();
    try dnssec.verify(.ecdsap256sha256, key[1..], &want256, &sig);
    var bad = sig;
    bad[63] ^= 1;
    try expectError(error.Auth, dnssec.verify(.ecdsap256sha256, key[1..], &want256, &bad));
    try expectError(error.Invalid, dnssec.verify(.ecdsap256sha256, key[1..], &want512, &sig));

    // The digest types, for DS records and NSEC3 owner names.
    var h1 = dnssec.Hash.digest(.sha1);
    h1.update(msg);
    var want1: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(msg, &want1, .{});
    var out1: [c.CH_DNSSEC_DIGEST_MAX]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &want1, h1.final(&out1));

    // P-384: std.crypto signs over SHA-384.
    const Ecdsa384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const kp384 = try Ecdsa384.KeyPair.generateDeterministic([_]u8{0x33} ** Ecdsa384.KeyPair.seed_length);
    const sig384 = (try kp384.sign(msg, null)).toBytes();
    const key384 = kp384.public_key.toUncompressedSec1();
    var h384 = try dnssec.Hash.init(.ecdsap384sha384, &.{}, &.{});
    h384.update(msg);
    var out384: [c.CH_DNSSEC_DIGEST_MAX]u8 = undefined;
    try dnssec.verify(.ecdsap384sha384, key384[1..], h384.final(&out384), &sig384);

    // Ed25519: std.crypto signs, and the hash takes R and the key at init.
    const Ed25519 = std.crypto.sign.Ed25519;
    const ed = try Ed25519.KeyPair.generateDeterministic([_]u8{0x24} ** Ed25519.KeyPair.seed_length);
    const ed_sig = (try ed.sign(msg, null)).toBytes();
    const ed_key = ed.public_key.toBytes();
    var hed = try dnssec.Hash.init(.ed25519, &ed_key, &ed_sig);
    hed.update(msg);
    var outed: [c.CH_DNSSEC_DIGEST_MAX]u8 = undefined;
    const hram = hed.final(&outed);
    try dnssec.verify(.ed25519, &ed_key, hram, &ed_sig);
    var ed_bad = ed_sig;
    ed_bad[0] ^= 1;
    try expectError(error.Auth, dnssec.verify(.ed25519, &ed_key, hram, &ed_bad));
    try expectError(error.Invalid, dnssec.Hash.init(.ed25519, ed_key[0..31], &ed_sig));
}

/// Refers to each named declaration of T, so it compiles.
fn compile(comptime T: type, comptime names: []const []const u8) void {
    inline for (names) |name| _ = &@field(T, name);
}

test "every declaration this object has compiles" {
    compile(chapulin, &.{ "fromCode", "buildMatches", "Limits", "Group", "Suite", "State", "Hook", "RandomSource", "attachRandom" });
    try expect(chapulin.buildMatches());
    if (has_client) compile(chapulin, &.{ "Client", "Ticket", "Trust" });
    if (has_classic_server) compile(chapulin, &.{ "Server", "EcdsaP256Identity", "RsaPssIdentity", "Chain", "EcdsaP256Key" });
    if (has_mldsa_server) compile(chapulin, &.{ "Server", "MlDsa87Identity", "Chain", "MlDsa87Key" });
    if (has_webpki) compile(chapulin, &.{ "TrustAnchor", "CertType", "Anchors" });
    if (@hasDecl(c, "ch_keylog")) compile(chapulin, &.{"hookContext"});
    if (@hasDecl(c, "ch_dnssec_verify")) compile(chapulin.dnssec, &.{ "Algorithm", "DigestType", "Hash", "verify" });
    const record = [_][]const u8{ "init", "recordIn", "recordState", "alertSent", "alertReceived", "read", "write", "writableLen", "close", "recordClose", "group", "pskSelected", "peerLimit", "readClosed", "replyLen" };
    const quic = [_][]const u8{ "init", "cryptoIn", "initialKeys", "keysReady", "peerTransportParams", "seal", "sealClose", "open", "retryOk", "negotiatedVersion", "keyUpdate", "keyPhase", "dropPreviousKeys", "discard", "state", "alert", "alertSent", "alertReceived", "errorCode", "close", "alpnSelected", "group", "pskSelected" };
    if (@hasDecl(c, "ch_record_init")) compileSession(chapulin.record.Client(c.CH_MIN_RXBUF, .{}), &(record ++ .{ "recordOut", "takeTicket" }));
    if (@hasDecl(c, "ch_srv_record_init")) compileSession(chapulin.record.Server(c.CH_MIN_RXBUF, .{}), &(record ++ .{ "sni", "outputLen" }));
    if (has_quic) compile(chapulin.quic, &.{"Version"});
    if (@hasDecl(c, "ch_quic_init")) compileSession(chapulin.quic.Client(c.CH_MIN_RXBUF, .{}), &(quic ++ .{ "cryptoOut", "takeTicket", "switchVersion" }));
    if (@hasDecl(c, "ch_srv_quic_init")) {
        compileSession(chapulin.quic.Server(c.CH_MIN_RXBUF, .{}), &(quic ++ .{"sni"}));
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
