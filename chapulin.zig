//! chapulin's Zig API: the values a session is configured from, the error each result code maps to,
//! and the build record check. The record-mode sessions are in chapulin_record.zig and the QUIC
//! sessions in chapulin_quic.zig. docs/zig.md is the reference.
//!
//! Each call forwards to the C call of the same name and adds nothing the C core lacks: it builds
//! ch_cfg from values, maps result codes to errors, and copies bytes between the caller's slices
//! and the C callbacks. Every TLS rule stays in C.
//!
//! The module is compiled once per object, against that object's translated headers, `c`. A
//! declaration whose C name the object lacks is a @compileError that names the build option that
//! adds it.
const std = @import("std");

/// The object's public headers, translated by translate-c under the defines the object compiled
/// with (docs/decisions.md 70). What the API leaves out is used through it under its C name.
pub const c = @import("chapulin_c");
/// Record-mode sessions (TRANSPORT=tcp-nonblocking).
pub const record = @import("chapulin_record.zig");
/// QUIC sessions (TRANSPORT=quic-nonblocking).
pub const quic = @import("chapulin_quic.zig");

// A client role: the object's client entry point, whichever its transport.
// Each header declares a call only in the objects that define it.
const has_client = @hasDecl(c, "ch_connect") or @hasDecl(c, "ch_record_init") or @hasDecl(c, "ch_quic_init");
const has_server = @hasField(c.ch_cfg, "srv");
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_alpn = @hasField(c.ch_cfg, "alpn_protocols");
const has_suite_order = has_server and @hasField(c.ch_srv_cfg, "cipher_suites");
// TRANSPORT=quic-nonblocking: every session names its original version in
// ch_cfg (cfg.h), and quic.Version is the type that names one.
const has_quic = @hasField(c.ch_cfg, "quic_original_version");
const has_choose_version = has_server and @hasField(c.ch_srv_cfg, "choose_version");
// A client that offers more than one suite (SUITE=aesgcm TRUST=webpki)
// takes an order of its own in ch_cfg.cipher_suites (webpki_cfg.h).
const has_client_suite_order = @hasField(c.ch_cfg, "cipher_suites");
// RAND=session: each session names its own source of random bytes in ch_cfg (cfg.h), where every
// other build draws from the image's ch_rand_bytes.
const has_rand_session = @hasField(c.ch_cfg, "rand_bytes");
// A host object, AES=runtime and WIDEMUL=runtime: each session states what the caller found
// about its CPU in ch_cfg (cpu_cfg.h).
const has_cpu = @hasField(c.ch_cfg, "cpu");
const has_aes_runtime = @hasField(c.ch_cfg, "aes_instructions");
const has_widemul_runtime = @hasField(c.ch_cfg, "widemul");

/// One error per ch_err code a call returns, named as chapulin.hpp's Status names it. Each call's
/// error set is the part of this one its C call returns. CH_RECORD_AGAIN and CH_ECLOSED are no
/// error here: record sessions' read reports the first as pt_len 0, and no call returns the second.
/// A TCP object's set lacks Discard and AeadLimit, whose codes only a QUIC object's headers
/// declare.
pub const Error = if (@hasDecl(c, "CH_QUIC_DISCARD")) AnyError else error{ Io, Proto, Auth, Cap, Invalid };
const AnyError = error{
    /// CH_EIO: an output slice could not take what C sent. The session is dead.
    Io,
    /// CH_EPROTO: a protocol failure, and the session is dead; or bytes for a session that failed
    /// or closed, or read and write before the handshake completed, and the session is as it was.
    Proto,
    /// CH_EAUTH: authentication failed. The session is dead.
    Auth,
    /// CH_ECAP: a buffer was short. From recordOut, cryptoOut, seal,
    /// sealClose and tokenMint, and from write's own check, the session is
    /// live; from recordIn, cryptoIn and read, and from ch_write, it is dead.
    Cap,
    /// CH_EINVAL: a configuration or an argument was refused, or a call
    /// came out of order, and nothing was sent. From init the session is
    /// failed until the next init; from any other call it is as it was.
    Invalid,
    /// CH_QUIC_DISCARD: the caller drops the packet. The session is live.
    Discard,
    /// CH_QUIC_AEAD_LIMIT: RFC 9001 §6.6's integrity limit. The session is dead.
    AeadLimit,
};

/// The C code each error stands for.
fn codeOf(comptime err: AnyError) c_int {
    return switch (err) {
        error.Io => c.CH_EIO,
        error.Proto => c.CH_EPROTO,
        error.Auth => c.CH_EAUTH,
        error.Cap => c.CH_ECAP,
        error.Invalid => c.CH_EINVAL,
        error.Discard => c.CH_QUIC_DISCARD,
        error.AeadLimit => c.CH_QUIC_AEAD_LIMIT,
    };
}

/// Nothing for CH_OK, and otherwise the error of E that code stands for. E is the error set of one
/// C call, a part of Error. A code E does not name is one that call's header says it never returns,
/// and it panics, as a broken contract is a programmer error. A program that calls a C function the
/// API leaves out maps its result with fromCode(Error, code).
pub fn fromCode(comptime E: type, code: c_int) E!void {
    if (code == c.CH_OK) return;
    inline for (@typeInfo(E).error_set.?) |member| {
        if (code == comptime codeOf(@field(Error, member.name))) return @field(E, member.name);
    }
    @panic("chapulin: a C call returned a code its header does not name");
}

/// A root's subject Name and SubjectPublicKeyInfo, each the whole DER TLV (webpki_cfg.h).
pub const trustAnchor = if (has_webpki) trustAnchorOf else @compileError("trustAnchor needs TRUST=webpki");
fn trustAnchorOf(subject: []const u8, spki: []const u8) c.ch_trust_anchor {
    return .{ .name = subject.ptr, .name_len = subject.len, .spki = spki.ptr, .spki_len = spki.len };
}

/// One protocol name to offer or select through ALPN (RFC 7301).
pub const alpnProtocol = if (has_alpn) alpnProtocolOf else @compileError("alpnProtocol needs TRUST=webpki, TRANSPORT=quic-nonblocking or a server role");
fn alpnProtocolOf(name: []const u8) c.ch_alpn_protocol {
    return .{ .name = name.ptr, .name_len = name.len };
}

/// One DER certificate of a server's chain.
pub const cert = if (has_server) certOf else @compileError("cert needs ROLE=server or ROLE=both");
fn certOf(der: []const u8) c.ch_cert {
    return .{ .der = der.ptr, .len = der.len };
}

/// The SHA-256 of a DER SubjectPublicKeyInfo. A slice of them is ch_cfg.spki_pins as it is.
pub const SpkiPin = [c.SHA256_LEN]u8;

/// How a client judges the server. The variants are the object's trust
/// mode's. Every slice is borrowed and must outlive the session.
pub const Trust = if (has_webpki) union(enum) {
    web_pki: struct {
        /// Roots the chain may end at: anchors, anchor_count.
        anchors: []const c.ch_trust_anchor,
        /// The name the leaf must carry, also sent as server_name: hostname, hostname_len.
        server_name: []const u8,
        /// Seconds since 1970-01-01T00:00:00Z: now_seconds.
        now_seconds: u64,
        /// Pins the verified path must also match: spki_pins, spki_pin_count.
        pins: []const SpkiPin = &.{},
    },
    pins: struct {
        /// The keys the server may prove it holds: spki_pins, spki_pin_count.
        pins: []const SpkiPin,
        /// Sent as server_name and judged against nothing: hostname, hostname_len.
        server_name: ?[]const u8 = null,
    },
} else union(enum) {
    pinned: struct {
        /// The server's key (TRUST=raw-*) or its CA's (TRUST=ca-*): server_pubkey, server_pubkey_len.
        server_pubkey: []const u8,
        /// The staged next key during rotation: server_pubkey2, server_pubkey2_len.
        server_pubkey2: ?[]const u8 = null,
    },
};

/// What a client sets. Every slice and pointer is borrowed and must outlive
/// the session, as ch_cfg's must (cfg.h).
pub const Client = if (has_client) ClientValues else @compileError("Client needs ROLE=client or ROLE=both");
const ClientValues = struct {
    /// How the server is judged: the fields Trust names.
    trust: Trust,
    /// Protocols to offer, most preferred first: alpn_protocols, alpn_count.
    alpn: if (has_alpn) []const c.ch_alpn_protocol else void = if (has_alpn) &.{} else {},
    /// A ticket to resume with: psk, psk_len, psk_id, psk_id_len, resumption, ticket_epoch,
    /// ticket_lifetime_s, under TRUST=webpki ticket_binding, and under TRANSPORT=quic-nonblocking
    /// ticket_quic_version. Under a raw or ca mode it leaves the server_pubkey slots unset, because
    /// ch_cfg takes one auth mode.
    ticket: ?*const Ticket = null,
    /// The ticket's age in milliseconds: ticket_age_ms, and obfuscated_age
    /// through ch_ticket_obfuscated_age. init answers error.Invalid for an
    /// age above the ticket's lifetime or above seven days (ticket.h).
    ticket_age_ms: u64 = 0,
    /// Refuse a key exchange other than X25519MLKEM768: require_pq.
    require_pq: bool = false,
    /// The QUIC version of the first Initial packet, under TRANSPORT=quic-nonblocking alone:
    /// quic_original_version. null leaves it 0, which init refuses with error.Invalid, so a
    /// configuration that names no version fails where C refuses it. void in every other build.
    quic_version: if (has_quic) ?quic.Version else void = if (has_quic) null else {},
    /// Suites to offer, most preferred first, empty for the build's order:
    /// cipher_suites, cipher_suite_count.
    cipher_suites: if (has_client_suite_order) []const Suite else void = if (has_client_suite_order) &.{} else {},
    /// The session's source of random bytes, under RAND=session alone: rand_bytes and rand_io,
    /// through the copy the session's init stores (attachRandom). null leaves rand_bytes NULL,
    /// which init refuses with error.Invalid. void in every other build.
    random: if (has_rand_session) ?std.Random else void = if (has_rand_session) null else {},
    /// What the caller states about its CPU, in a host object alone: cpu. null leaves it 0, which
    /// init refuses with error.Invalid. void in every other build.
    cpu: if (has_cpu) ?Cpu else void = if (has_cpu) null else {},
    /// What the caller's CPU probe found, under AES=runtime alone: aes_instructions. null leaves
    /// it 0, which init refuses with error.Invalid. void in every other build.
    aes_instructions: if (has_aes_runtime) ?AesInstructions else void = if (has_aes_runtime) null else {},
    /// The answer about the widening multiply, under WIDEMUL=runtime alone, as aes_instructions is.
    widemul: if (has_widemul_runtime) ?Widemul else void = if (has_widemul_runtime) null else {},

    /// The ch_cfg these values set. A session's init adds its own buffer,
    /// callbacks and io to it, and under RAND=session its source.
    pub fn toCfg(values: ClientValues) c.ch_cfg {
        var cfg = std.mem.zeroes(c.ch_cfg);
        if (has_webpki) switch (values.trust) {
            .web_pki => |web| {
                cfg.anchors = if (web.anchors.len == 0) null else web.anchors.ptr;
                cfg.anchor_count = web.anchors.len;
                cfg.hostname = web.server_name.ptr;
                cfg.hostname_len = web.server_name.len;
                cfg.now_seconds = web.now_seconds;
                setPins(&cfg, web.pins);
            },
            .pins => |pinned| {
                setPins(&cfg, pinned.pins);
                if (pinned.server_name) |name| {
                    cfg.hostname = name.ptr;
                    cfg.hostname_len = name.len;
                }
            },
        } else if (values.ticket == null) {
            const pinned = values.trust.pinned;
            cfg.server_pubkey = pinned.server_pubkey.ptr;
            cfg.server_pubkey_len = pinned.server_pubkey.len;
            if (pinned.server_pubkey2) |next| {
                cfg.server_pubkey2 = next.ptr;
                cfg.server_pubkey2_len = next.len;
            }
        }
        if (has_alpn) {
            cfg.alpn_protocols = if (values.alpn.len == 0) null else values.alpn.ptr;
            cfg.alpn_count = values.alpn.len;
        }
        if (values.ticket) |ticket| {
            cfg.psk = &ticket.ticket.psk;
            cfg.psk_len = ticket.ticket.psk_len;
            cfg.psk_id = &ticket.identity;
            cfg.psk_id_len = ticket.ticket.identity_len;
            cfg.resumption = 1;
            cfg.obfuscated_age = c.ch_ticket_obfuscated_age(&ticket.ticket, values.ticket_age_ms);
            cfg.ticket_age_ms = values.ticket_age_ms;
            cfg.ticket_lifetime_s = ticket.ticket.lifetime_s;
            cfg.ticket_epoch = ticket.ticket.epoch;
            if (has_webpki) cfg.ticket_binding = &ticket.ticket.binding;
            if (has_quic) cfg.ticket_quic_version = ticket.ticket.quic_version;
        }
        cfg.require_pq = @intFromBool(values.require_pq);
        if (has_quic) cfg.quic_original_version = quic.versionCode(values.quic_version);
        if (has_client_suite_order) {
            cfg.cipher_suites = if (values.cipher_suites.len == 0) null else @ptrCast(values.cipher_suites.ptr);
            cfg.cipher_suite_count = values.cipher_suites.len;
        }
        if (has_cpu) cfg.cpu = cpuBits(values.cpu);
        if (has_aes_runtime) cfg.aes_instructions = if (values.aes_instructions) |a| @intFromEnum(a) else 0;
        if (has_widemul_runtime) cfg.widemul = if (values.widemul) |w| @intFromEnum(w) else 0;
        return cfg;
    }
};

fn setPins(cfg: *c.ch_cfg, pins: []const SpkiPin) void {
    cfg.spki_pins = if (pins.len == 0) null else @ptrCast(pins.ptr);
    cfg.spki_pin_count = pins.len;
}

/// A NewSessionTicket that outlives the session, by value (chapulin_ticket.zig).
pub const Ticket = @import("chapulin_ticket.zig").Ticket;

/// An ecdsa_secp256r1_sha256 identity: srv.ecdsa_p256.
pub const EcdsaP256Identity = if (has_server) struct {
    /// DER certificates, leaf first: chain, chain_count.
    chain: []const c.ch_cert,
    /// The leaf's point X||Y: pub, pub_len.
    public_key: *const [64]u8,
    /// The private scalar, big-endian: priv, priv_len.
    private_key: *const [32]u8,
} else @compileError("EcdsaP256Identity needs ROLE=server or ROLE=both");

/// An rsa_pss_rsae_sha256 identity: srv.rsa_pss.
pub const RsaPssIdentity = if (has_server) struct {
    /// DER certificates, leaf first: chain, chain_count.
    chain: []const c.ch_cert,
    /// The modulus, big-endian: pub, pub_len.
    public_key: []const u8,
    /// The modulus and the private exponent: priv, priv_len = @sizeOf(c.ch_rsa_priv).
    private_key: *const c.ch_rsa_priv,
} else @compileError("RsaPssIdentity needs ROLE=server or ROLE=both");

/// What a server sets. Every slice and pointer is borrowed and must outlive the session.
pub const Server = if (has_server) ServerValues else @compileError("Server needs ROLE=server or ROLE=both");
const ServerValues = struct {
    /// srv.ecdsa_p256; null leaves the slot unprovisioned.
    ecdsa_p256: ?EcdsaP256Identity = null,
    /// srv.rsa_pss; null leaves the slot unprovisioned.
    rsa_pss: ?RsaPssIdentity = null,
    /// The HelloRetryRequest cookie key: srv.cookie_key.
    cookie_key: *const [c.CH_SRV_COOKIE_KEY_LEN]u8,
    /// The key tickets are sealed under, null for no tickets: srv.ticket_key.
    ticket_key: ?*const [c.CH_SRV_TICKET_KEY_LEN]u8 = null,
    /// The caller's clock for this connection, 0 for none: srv.now_seconds.
    now_seconds: u64,
    /// Protocols to select from, in this server's order: alpn_protocols, alpn_count.
    alpn: []const c.ch_alpn_protocol = &.{},
    /// Refuse a ClientHello with no server_name: srv.require_server_name.
    require_server_name: bool = false,
    /// Suites in this server's order, empty for the default: srv.cipher_suites, cipher_suite_count.
    cipher_suites: if (has_suite_order) []const Suite else void = if (has_suite_order) &.{} else {},
    /// The Version field of the client's first Initial packet, under TRANSPORT=quic-nonblocking
    /// alone, as Client.quic_version is: quic_original_version. void in every other build.
    quic_version: if (has_quic) ?quic.Version else void = if (has_quic) null else {},
    /// The negotiated version's chooser, under TRANSPORT=quic-nonblocking
    /// alone: srv.choose_version, through the session's own adapter
    /// (quic.ChooseVersion). null keeps the original version.
    choose_version: if (has_choose_version) ?quic.ChooseVersion else void = if (has_choose_version) null else {},
    /// The session's source of random bytes, under RAND=session alone, as
    /// Client.random is. check draws from it too, for the RSA-PSS salt.
    random: if (has_rand_session) ?std.Random else void = if (has_rand_session) null else {},
    /// What the caller states about its CPU, in a host object alone, as Client.cpu is.
    cpu: if (has_cpu) ?Cpu else void = if (has_cpu) null else {},
    /// What the caller's CPU probe found, under AES=runtime alone, as Client.aes_instructions is.
    aes_instructions: if (has_aes_runtime) ?AesInstructions else void = if (has_aes_runtime) null else {},
    /// The answer about the widening multiply, under WIDEMUL=runtime alone, as Client.widemul is.
    widemul: if (has_widemul_runtime) ?Widemul else void = if (has_widemul_runtime) null else {},

    /// The ch_cfg these values set, which a session's init completes as it
    /// completes Client.toCfg's. error.Invalid for a chain longer than
    /// chain_count's u8 holds, the width of a C field.
    pub fn toCfg(values: ServerValues) error{Invalid}!c.ch_cfg {
        var cfg = std.mem.zeroes(c.ch_cfg);
        if (values.ecdsa_p256) |id| cfg.srv.ecdsa_p256 = .{
            .chain = id.chain.ptr,
            .chain_count = std.math.cast(u8, id.chain.len) orelse return error.Invalid,
            .priv = id.private_key,
            .priv_len = id.private_key.len,
            .@"pub" = id.public_key,
            .pub_len = id.public_key.len,
        };
        if (values.rsa_pss) |id| cfg.srv.rsa_pss = .{
            .chain = id.chain.ptr,
            .chain_count = std.math.cast(u8, id.chain.len) orelse return error.Invalid,
            .priv = id.private_key,
            .priv_len = @sizeOf(c.ch_rsa_priv),
            .@"pub" = id.public_key.ptr,
            .pub_len = id.public_key.len,
        };
        cfg.srv.cookie_key = values.cookie_key;
        cfg.srv.ticket_key = if (values.ticket_key) |key| key else null;
        cfg.srv.now_seconds = values.now_seconds;
        cfg.alpn_protocols = if (values.alpn.len == 0) null else values.alpn.ptr;
        cfg.alpn_count = values.alpn.len;
        cfg.srv.require_server_name = @intFromBool(values.require_server_name);
        if (has_suite_order) {
            cfg.srv.cipher_suites = if (values.cipher_suites.len == 0) null else @ptrCast(values.cipher_suites.ptr);
            cfg.srv.cipher_suite_count = values.cipher_suites.len;
        }
        if (has_quic) cfg.quic_original_version = quic.versionCode(values.quic_version);
        if (has_cpu) cfg.cpu = cpuBits(values.cpu);
        if (has_aes_runtime) cfg.aes_instructions = if (values.aes_instructions) |a| @intFromEnum(a) else 0;
        if (has_widemul_runtime) cfg.widemul = if (values.widemul) |w| @intFromEnum(w) else 0;
        return cfg;
    }

    /// ch_srv_check: each provisioned key signs, and the signature verifies. It takes no session
    /// and runs no I/O. Under RAND=session the RSA-PSS signature draws its salt from random, which
    /// C holds for the call alone.
    pub fn check(values: ServerValues) error{Invalid}!void {
        var cfg = try values.toCfg();
        var source: RandomSource = undefined;
        attachRandom(&cfg, &source, values.random);
        return fromCode(error{Invalid}, c.ch_srv_check(&cfg));
    }
};

/// ch_cfg.cpu in a host object (cpu_cfg.h): what the caller's own probe found, and what it states.
/// A value sets CH_CPU_PROBED and the bit of each field that is true.
pub const Cpu = if (has_cpu) CpuBits else @compileError("Cpu needs a host object: TRUST=webpki, ROLE=server or ROLE=both on arm64 or x86-64");
const CpuBits = struct {
    /// CH_CPU_CONSTANT_TIME_AES: the AES and carry-less multiply instructions, which the caller
    /// states run in constant time in the mode the session's thread runs in.
    constant_time_aes: bool = false,
    /// CH_CPU_CONSTANT_TIME_MULTIPLY: the caller states the widening multiply runs in constant time.
    constant_time_multiply: bool = false,
    /// CH_CPU_AVX2 and CH_CPU_VAES: x86-64 bits, which an arm64 object refuses.
    avx2: bool = false,
    vaes: bool = false,
};

/// ch_cfg.cpu for what found states, and 0 for null.
fn cpuBits(found: ?CpuBits) u32 {
    const cpu = found orelse return 0;
    return c.CH_CPU_PROBED | (if (cpu.constant_time_aes) c.CH_CPU_CONSTANT_TIME_AES else 0) |
        (if (cpu.constant_time_multiply) c.CH_CPU_CONSTANT_TIME_MULTIPLY else 0) |
        (if (cpu.avx2) c.CH_CPU_AVX2 else 0) | (if (cpu.vaes) c.CH_CPU_VAES else 0);
}

/// ch_cfg.aes_instructions under AES=runtime (cfg.h): what the caller's own CPU probe found.
pub const AesInstructions = if (has_aes_runtime) AesAnswer else @compileError("AesInstructions needs AES=runtime");
const AesAnswer = enum(u8) { present = c.CH_AES_INSTRUCTIONS_PRESENT, absent = c.CH_AES_INSTRUCTIONS_ABSENT };

/// ch_cfg.widemul under WIDEMUL=runtime (cpu_cfg.h): the caller's answer about its multiply.
pub const Widemul = if (has_widemul_runtime) WidemulAnswer else @compileError("Widemul needs WIDEMUL=runtime");
const WidemulAnswer = enum(u8) { constant_time = c.CH_WIDEMUL_CONSTANT_TIME, not_stated = c.CH_WIDEMUL_NOT_STATED };

/// ch_tls.group's code points (cfg.h).
pub const Group = enum(u16) {
    x25519 = c.CH_GROUP_X25519,
    x25519mlkem768 = c.CH_GROUP_X25519MLKEM768,
    secp256r1 = c.CH_GROUP_SECP256R1,
    _,
};

/// ch_tls.suite's, cipher_suites' and srv.cipher_suites' code points (suite.h).
pub const Suite = enum(u16) {
    chacha20_poly1305_sha256 = c.SUITE_CHACHA20_POLY1305_SHA256,
    aes_128_gcm_sha256 = c.SUITE_AES_128_GCM_SHA256,
    aes_256_gcm_sha384 = c.SUITE_AES_256_GCM_SHA384,
    _,
};

/// ch_tls.state (session.h).
pub const State = enum(u8) {
    start = c.CH_ST_START,
    connected = c.CH_ST_CONNECTED,
    closed = c.CH_ST_CLOSED,
    failed = c.CH_ST_FAILED,
};

/// ch_tls.server_cert_type (webpki_cfg.h).
pub const CertType = if (has_webpki) enum(u8) {
    x509 = c.CH_CERT_TYPE_X509,
    raw_public_key = c.CH_CERT_TYPE_RAW_PUBLIC_KEY,
    _,
} else @compileError("CertType needs TRUST=webpki");

/// ch_build_matches over this object's build record,
/// ch_build_info_<transport> (build.h). Call it once at start. A test that
/// checks a changed record calls chapulin.c.ch_build_matches with its own.
pub fn buildMatches() bool {
    const info = if (@hasDecl(c, "ch_build_info_quic_nonblocking"))
        &c.ch_build_info_quic_nonblocking
    else if (@hasDecl(c, "ch_build_info_tcp_nonblocking"))
        &c.ch_build_info_tcp_nonblocking
    else
        &c.ch_build_info_tcp_blocking;
    return c.ch_build_matches(info) == 1;
}

/// What ch_cfg.io points at in every session. context is the caller's, for ch_keylog: a session's
/// init sets it to null, and the caller writes session.hook.context after init.
pub const Hook = extern struct { context: ?*anyopaque = null };

/// What a session stores under RAND=session: the std.Random its values
/// carried, which ch_cfg.rand_io points at for the session's lifetime, so
/// the session must not move after init. void in every other build.
pub const RandomSource = if (has_rand_session) std.Random else void;

/// Under RAND=session, stores random in source and points cfg at it: rand_io is source, and
/// rand_bytes the adapter that fills each draw from it. A null random leaves rand_bytes NULL, which
/// every init call and ch_srv_check refuse with CH_EINVAL, so the refusal stays C's. It does
/// nothing in any other build. The sessions' init calls and Server.check call it.
pub fn attachRandom(cfg: *c.ch_cfg, source: *RandomSource, random: if (has_rand_session) ?std.Random else void) void {
    if (has_rand_session) {
        if (random) |r| {
            source.* = r;
            cfg.rand_bytes = fillRandom;
            cfg.rand_io = source;
        }
    }
}

/// ch_cfg.rand_bytes under RAND=session: fills out[0..n] from the
/// std.Random rand_io points at. A std.Random's fill returns nothing and
/// cannot fail, which is the contract cfg.h states for rand_bytes.
fn fillRandom(rand_io: ?*anyopaque, out: [*c]u8, n: usize) callconv(.c) void {
    const source: *const std.Random = @ptrCast(@alignCast(rand_io.?));
    source.bytes(out[0..n]);
}

/// The caller's context, from the io argument ch_keylog receives (KEYLOG=on).
pub const hookContext = if (@hasDecl(c, "ch_keylog")) hookContextOf else @compileError("hookContext needs KEYLOG=on");
fn hookContextOf(io: ?*anyopaque) ?*anyopaque {
    const hook: *const Hook = @ptrCast(@alignCast(io orelse return null));
    return hook.context;
}
