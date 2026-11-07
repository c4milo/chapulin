//! The ch_cfg a session's options build, the C arrays its lists become, and the two helpers the
//! sibling files share: the RAND=session adapter and a QUIC version's code. The record and QUIC
//! sessions' init calls and ServerOptions.check call it. chapulin.zig does not export it, so a program
//! names none of it: the C structs of a chain, an anchor list and an ALPN list stay behind the
//! Zig values (docs/decisions.md 168). A test build alone reaches it, as chapulin.testing, so the
//! API's unit tests can hold each value to its ch_cfg field.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_server = @hasField(c.ch_cfg, "srv");
const has_mldsa_server = has_server and @hasField(c.ch_srv_cfg, "mldsa87");
const has_classic_server = has_server and @hasField(c.ch_srv_cfg, "ecdsa_p256");
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_alpn = @hasField(c.ch_cfg, "alpn_protocols");
const has_suite_order = has_server and @hasField(c.ch_srv_cfg, "cipher_suites");
const has_quic = @hasField(c.ch_cfg, "quic_original_version");
const has_client_suite_order = @hasField(c.ch_cfg, "cipher_suites");
const has_cpu = @hasField(c.ch_cfg, "cpu");
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");

/// The C arrays a session's options become under limits, which a session holds and ch_cfg points
/// at. Each array a build does not use is void.
pub fn Lists(comptime limits: chapulin.Limits) type {
    if (limits.chain_max == 0 or limits.chain_max > 255) @compileError("Limits.chain_max is 1 to 255, the range of chain_count");
    return struct {
        anchors: if (has_webpki) [limits.anchors_max]c.ch_trust_anchor else void,
        alpn: if (has_alpn) [c.CH_ALPN_MAX]c.ch_alpn_protocol else void,
        ecdsa_chain: if (has_classic_server) [limits.chain_max]c.ch_cert else void,
        rsa_chain: if (has_classic_server) [limits.chain_max]c.ch_cert else void,
        mldsa_chain: if (has_mldsa_server) [limits.chain_max]c.ch_cert else void,
    };
}

/// The ch_cfg a client's options set, with its lists copied into lists, which must outlive the
/// session as the options must. A session's init adds its own buffer, callbacks and io to it, and
/// under RAND=session its source. error.Invalid for a list longer than its Limits cap, or an ALPN
/// list longer than CH_ALPN_MAX.
pub fn client_cfg(options: *const chapulin.ClientOptions, comptime limits: chapulin.Limits, lists: *Lists(limits)) error{Invalid}!c.ch_cfg {
    var cfg = std.mem.zeroes(c.ch_cfg);
    if (has_webpki) switch (options.trust) {
        .web_pki => |web| {
            cfg.anchors = try fill(chapulin.TrustAnchor, c.ch_trust_anchor, &lists.anchors, web.anchors, trust_anchor_of);
            cfg.anchor_count = web.anchors.len;
            cfg.hostname = web.server_name.ptr;
            cfg.hostname_len = web.server_name.len;
            set_clock(&cfg, web.clock);
            set_pins(&cfg, web.pins);
        },
        .pins => |pinned| {
            set_pins(&cfg, pinned.pins);
            if (pinned.server_name) |name| {
                cfg.hostname = name.ptr;
                cfg.hostname_len = name.len;
            }
        },
    } else {
        const pinned = options.trust.pinned;
        cfg.server_pubkey = pinned.server_pubkey.ptr;
        cfg.server_pubkey_len = pinned.server_pubkey.len;
        if (pinned.server_pubkey2) |next| {
            cfg.server_pubkey2 = next.ptr;
            cfg.server_pubkey2_len = next.len;
        }
    }
    if (has_alpn) {
        cfg.alpn_protocols = try fill([]const u8, c.ch_alpn_protocol, &lists.alpn, options.alpn, alpn_protocol_of);
        cfg.alpn_count = options.alpn.len;
    }
    if (options.ticket) |ticket| cfg.ticket = ticket.saved();
    cfg.ticket_age_ms = options.ticket_age_ms;
    cfg.require_pq = @intFromBool(options.require_pq);
    if (has_quic) cfg.quic_original_version = version_code(options.quic_version);
    if (has_client_suite_order) {
        cfg.cipher_suites = if (options.cipher_suites.len == 0) null else @ptrCast(options.cipher_suites.ptr);
        cfg.cipher_suite_count = options.cipher_suites.len;
    }
    if (has_cpu) cfg.cpu = chapulin.cpu_bits(options.cpu);
    return cfg;
}

/// The ch_cfg a server's options set, with its lists copied into lists, which must outlive the
/// session as the options must. A session's init completes it as it completes client_cfg's.
/// error.Invalid for a list longer than its Limits cap, or an ALPN list longer than
/// CH_ALPN_MAX. A chain fits chain_count's u8, because Limits.chain_max is 255 at most.
pub fn server_cfg(options: *const chapulin.ServerOptions, comptime limits: chapulin.Limits, lists: *Lists(limits)) error{Invalid}!c.ch_cfg {
    var cfg = std.mem.zeroes(c.ch_cfg);
    if (has_mldsa_server) {
        if (options.mldsa87) |id| cfg.srv.mldsa87 = .{
            .chain = try fill([]const u8, c.ch_cert, &lists.mldsa_chain, id.chain, cert_of),
            .chain_count = @intCast(id.chain.len),
            .priv = id.private_key,
            .priv_len = id.private_key.len,
            .@"pub" = id.public_key,
            .pub_len = id.public_key.len,
        };
    }
    if (has_classic_server) try set_classic_identities(&cfg, options, &lists.ecdsa_chain, &lists.rsa_chain);
    cfg.srv.cookie_key = options.cookie_key;
    cfg.srv.ticket_key = if (options.ticket_key) |key| key else null;
    if (options.clock) |clock| set_clock(&cfg, clock);
    cfg.alpn_protocols = try fill([]const u8, c.ch_alpn_protocol, &lists.alpn, options.alpn, alpn_protocol_of);
    cfg.alpn_count = options.alpn.len;
    cfg.srv.require_server_name = @intFromBool(options.require_server_name);
    if (has_suite_order) {
        cfg.srv.cipher_suites = if (options.cipher_suites.len == 0) null else @ptrCast(options.cipher_suites.ptr);
        cfg.srv.cipher_suite_count = options.cipher_suites.len;
    }
    if (has_quic) cfg.quic_original_version = version_code(options.quic_version);
    if (has_cpu) cfg.cpu = chapulin.cpu_bits(options.cpu);
    return cfg;
}

/// The ECDSA and RSA slots of every server outside PROFILE=cnsa2, with each chain copied into its
/// array of lists.
fn set_classic_identities(cfg: *c.ch_cfg, options: *const chapulin.ServerOptions, ecdsa_chain: []c.ch_cert, rsa_chain: []c.ch_cert) error{Invalid}!void {
    if (options.ecdsa_p256) |id| cfg.srv.ecdsa_p256 = .{
        .chain = try fill([]const u8, c.ch_cert, ecdsa_chain, id.chain, cert_of),
        .chain_count = @intCast(id.chain.len),
        .priv = id.private_key,
        .priv_len = id.private_key.len,
        .@"pub" = id.public_key,
        .pub_len = id.public_key.len,
    };
    if (options.rsa_pss) |id| cfg.srv.rsa_pss = .{
        .chain = try fill([]const u8, c.ch_cert, rsa_chain, id.chain, cert_of),
        .chain_count = @intCast(id.chain.len),
        .priv = id.private_key.c_key(),
        .priv_len = @sizeOf(c.ch_rsa_priv),
        .@"pub" = id.public_key.ptr,
        .pub_len = id.public_key.len,
    };
}

/// Each item through convert into room, or error.Invalid when room holds fewer. An empty list is
/// null, as ch_cfg takes it.
fn fill(comptime Item: type, comptime Entry: type, room: []Entry, items: []const Item, comptime convert: fn (Item) Entry) error{Invalid}!?[*]const Entry {
    if (items.len > room.len) return error.Invalid;
    for (items, room[0..items.len]) |item, *entry| entry.* = convert(item);
    return if (items.len == 0) null else room.ptr;
}

fn trust_anchor_of(anchor: chapulin.TrustAnchor) c.ch_trust_anchor {
    return .{ .name = anchor.name.ptr, .name_len = anchor.name.len, .spki = anchor.spki.ptr, .spki_len = anchor.spki.len };
}

fn alpn_protocol_of(name: []const u8) c.ch_alpn_protocol {
    return .{ .name = name.ptr, .name_len = name.len };
}

fn cert_of(der: []const u8) c.ch_cert {
    return .{ .der = der.ptr, .len = der.len };
}

fn set_clock(cfg: *c.ch_cfg, clock: chapulin.Clock) void {
    cfg.now_seconds = clock.now_seconds;
    cfg.clock_io = clock.clock_io;
}

fn set_pins(cfg: *c.ch_cfg, pins: []const chapulin.SpkiPin) void {
    cfg.spki_pins = if (pins.len == 0) null else @ptrCast(pins.ptr);
    cfg.spki_pin_count = pins.len;
}

/// The code an optional version sets in ch_cfg, quic_original_version or ticket_quic_version:
/// the version's, or 0 for null, which C refuses as an original version and as a resuming
/// ticket's version.
pub fn version_code(version: if (has_quic) ?chapulin.quic.Version else void) u32 {
    if (!has_quic) return 0;
    return if (version) |v| @intFromEnum(v) else 0;
}

/// Under RAND=session, stores random in source and points cfg at it: rand_io is source, and
/// rand_bytes the adapter that fills each draw from it. A null random leaves rand_bytes NULL, which
/// every init call and ch_srv_check refuse with CH_EINVAL, so the refusal stays C's. It does
/// nothing in any other build. The sessions' init calls and ServerOptions.check call it.
pub fn attach_random(cfg: *c.ch_cfg, source: *chapulin.RandomSource, random: if (has_rand_session) ?std.Random else void) void {
    if (has_rand_session) {
        if (random) |r| {
            source.* = r;
            cfg.rand_bytes = fill_random;
            cfg.rand_io = source;
        }
    }
}

/// ch_cfg.rand_bytes under RAND=session: fills out[0..n] from the
/// std.Random rand_io points at. A std.Random's fill returns nothing and
/// cannot fail, which is the contract cfg.h states for rand_bytes.
fn fill_random(rand_io: ?*anyopaque, out: [*c]u8, n: usize) callconv(.c) void {
    const source: *const std.Random = @ptrCast(@alignCast(rand_io.?));
    source.bytes(out[0..n]);
}
