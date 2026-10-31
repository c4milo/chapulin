//! The ch_cfg a session's values build, and the C arrays its lists become. The record and QUIC
//! sessions' init calls and Server.check call it. chapulin.zig does not export it, so a program
//! names none of it: the C structs of a chain, an anchor list and an ALPN list stay behind the
//! Zig values (docs/decisions.md 168). A test build alone reaches it, as chapulin.testing, so the
//! API's unit tests can hold each value to its ch_cfg field.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_server = @hasField(c.ch_cfg, "srv");
const has_mldsa_server = has_server and @hasField(c.ch_srv_cfg, "mldsa87");
const has_classic_server = has_server and !has_mldsa_server;
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_alpn = @hasField(c.ch_cfg, "alpn_protocols");
const has_suite_order = has_server and @hasField(c.ch_srv_cfg, "cipher_suites");
const has_quic = @hasField(c.ch_cfg, "quic_original_version");
const has_client_suite_order = @hasField(c.ch_cfg, "cipher_suites");
const has_cpu = @hasField(c.ch_cfg, "cpu");

/// The C arrays a session's values become under limits, which a session holds and ch_cfg points
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

/// The ch_cfg a client's values set, with its lists copied into lists, which must outlive the
/// session as the values must. A session's init adds its own buffer, callbacks and io to it, and
/// under RAND=session its source. error.Invalid for a list longer than its Limits cap, or an ALPN
/// list longer than CH_ALPN_MAX.
pub fn clientCfg(values: chapulin.Client, comptime limits: chapulin.Limits, lists: *Lists(limits)) error{Invalid}!c.ch_cfg {
    var cfg = std.mem.zeroes(c.ch_cfg);
    if (has_webpki) switch (values.trust) {
        .web_pki => |web| {
            cfg.anchors = try fill(chapulin.TrustAnchor, c.ch_trust_anchor, &lists.anchors, web.anchors, trustAnchorOf);
            cfg.anchor_count = web.anchors.len;
            cfg.hostname = web.server_name.ptr;
            cfg.hostname_len = web.server_name.len;
            setClock(&cfg, web.clock);
            setPins(&cfg, web.pins);
        },
        .pins => |pinned| {
            setPins(&cfg, pinned.pins);
            if (pinned.server_name) |name| {
                cfg.hostname = name.ptr;
                cfg.hostname_len = name.len;
            }
        },
    } else {
        const pinned = values.trust.pinned;
        cfg.server_pubkey = pinned.server_pubkey.ptr;
        cfg.server_pubkey_len = pinned.server_pubkey.len;
        if (pinned.server_pubkey2) |next| {
            cfg.server_pubkey2 = next.ptr;
            cfg.server_pubkey2_len = next.len;
        }
    }
    if (has_alpn) {
        cfg.alpn_protocols = try fill([]const u8, c.ch_alpn_protocol, &lists.alpn, values.alpn, alpnProtocolOf);
        cfg.alpn_count = values.alpn.len;
    }
    if (values.ticket) |ticket| cfg.ticket = ticket.saved();
    cfg.ticket_age_ms = values.ticket_age_ms;
    cfg.require_pq = @intFromBool(values.require_pq);
    if (has_quic) cfg.quic_original_version = chapulin.quic.versionCode(values.quic_version);
    if (has_client_suite_order) {
        cfg.cipher_suites = if (values.cipher_suites.len == 0) null else @ptrCast(values.cipher_suites.ptr);
        cfg.cipher_suite_count = values.cipher_suites.len;
    }
    if (has_cpu) cfg.cpu = chapulin.cpuBits(values.cpu);
    return cfg;
}

/// The ch_cfg a server's values set, with its lists copied into lists, which must outlive the
/// session as the values must. A session's init completes it as it completes clientCfg's.
/// error.Invalid for a list longer than its Limits cap, or an ALPN list longer than
/// CH_ALPN_MAX. A chain fits chain_count's u8, because Limits.chain_max is 255 at most.
pub fn serverCfg(values: chapulin.Server, comptime limits: chapulin.Limits, lists: *Lists(limits)) error{Invalid}!c.ch_cfg {
    var cfg = std.mem.zeroes(c.ch_cfg);
    if (has_mldsa_server) {
        if (values.mldsa87) |id| cfg.srv.mldsa87 = .{
            .chain = try fill([]const u8, c.ch_cert, &lists.mldsa_chain, id.chain, certOf),
            .chain_count = @intCast(id.chain.len),
            .priv = id.private_key,
            .priv_len = id.private_key.len,
            .@"pub" = id.public_key,
            .pub_len = id.public_key.len,
        };
    }
    if (has_classic_server) try setClassicIdentities(&cfg, values, &lists.ecdsa_chain, &lists.rsa_chain);
    cfg.srv.cookie_key = values.cookie_key;
    cfg.srv.ticket_key = if (values.ticket_key) |key| key else null;
    if (values.clock) |clock| setClock(&cfg, clock);
    cfg.alpn_protocols = try fill([]const u8, c.ch_alpn_protocol, &lists.alpn, values.alpn, alpnProtocolOf);
    cfg.alpn_count = values.alpn.len;
    cfg.srv.require_server_name = @intFromBool(values.require_server_name);
    if (has_suite_order) {
        cfg.srv.cipher_suites = if (values.cipher_suites.len == 0) null else @ptrCast(values.cipher_suites.ptr);
        cfg.srv.cipher_suite_count = values.cipher_suites.len;
    }
    if (has_quic) cfg.quic_original_version = chapulin.quic.versionCode(values.quic_version);
    if (has_cpu) cfg.cpu = chapulin.cpuBits(values.cpu);
    return cfg;
}

/// The ECDSA and RSA slots of every server outside PROFILE=cnsa2, with each chain copied into its
/// array of lists.
fn setClassicIdentities(cfg: *c.ch_cfg, values: chapulin.Server, ecdsa_chain: []c.ch_cert, rsa_chain: []c.ch_cert) error{Invalid}!void {
    if (values.ecdsa_p256) |id| cfg.srv.ecdsa_p256 = .{
        .chain = try fill([]const u8, c.ch_cert, ecdsa_chain, id.chain, certOf),
        .chain_count = @intCast(id.chain.len),
        .priv = id.private_key,
        .priv_len = id.private_key.len,
        .@"pub" = id.public_key,
        .pub_len = id.public_key.len,
    };
    if (values.rsa_pss) |id| cfg.srv.rsa_pss = .{
        .chain = try fill([]const u8, c.ch_cert, rsa_chain, id.chain, certOf),
        .chain_count = @intCast(id.chain.len),
        .priv = id.private_key,
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

fn trustAnchorOf(anchor: chapulin.TrustAnchor) c.ch_trust_anchor {
    return .{ .name = anchor.name.ptr, .name_len = anchor.name.len, .spki = anchor.spki.ptr, .spki_len = anchor.spki.len };
}

fn alpnProtocolOf(name: []const u8) c.ch_alpn_protocol {
    return .{ .name = name.ptr, .name_len = name.len };
}

fn certOf(der: []const u8) c.ch_cert {
    return .{ .der = der.ptr, .len = der.len };
}

fn setClock(cfg: *c.ch_cfg, clock: chapulin.Clock) void {
    cfg.now_seconds = clock.now_seconds;
    cfg.clock_io = clock.clock_io;
}

fn setPins(cfg: *c.ch_cfg, pins: []const chapulin.SpkiPin) void {
    cfg.spki_pins = if (pins.len == 0) null else @ptrCast(pins.ptr);
    cfg.spki_pin_count = pins.len;
}
