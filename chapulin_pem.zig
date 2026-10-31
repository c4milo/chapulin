//! The PEM files of the Zig API: a server's certificate chain and P-256 private key, and a
//! client's CA bundle. The three C calls that pem_files.h declares decode them, and chapulin.zig
//! declares the values as chapulin.Chain, chapulin.EcdsaP256Key and chapulin.Anchors. A chain
//! and a bundle decode into rooms the caller places and sizes, and each value names the entries
//! the C call filled. A key decodes into the value's own storage. It sits in a file of its own
//! because chapulin.zig stands near the 500-line cap CLAUDE.md sets and make lint-size holds.
//! docs/zig.md is the reference.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_server = @hasField(c.ch_cfg, "srv");
const has_webpki = @hasField(c.ch_cfg, "anchors");
const has_cpu = @hasField(c.ch_cfg, "cpu");
// The key call each server role's object exports: the P-256 one, or the
// ML-DSA-87 one in a PROFILE=cnsa2 server (docs/decisions.md 162).
const has_p256_key = has_server and @hasDecl(c, "ch_p256_key_from_pem");
const has_mldsa_key = has_server and @hasDecl(c, "ch_mldsa_key_from_pem");

/// A server's certificate chain, decoded from a PEM file by ch_chain_from_pem into the caller's
/// rooms. certs is the start of the caller's slices that the call filled. Each slice points into
/// the caller's DER room. So both rooms stay where fromPem filled them for as long as a session
/// uses certs.
pub const Chain = if (has_server) struct {
    /// The certificates' DER, end-entity first, as the identities' chain fields take them.
    certs: []const []const u8 = &.{},

    /// ch_chain_from_pem: one or more CERTIFICATE blocks, end-entity first, into der and slices.
    /// error.Invalid for a file pem_files.h refuses, for DER over der.len bytes, and for more
    /// blocks than slices.len or 255. The C call writes its entries into an array on this call's
    /// stack, 255 of them at the C cap, and fromPem copies each entry's DER slice into slices.
    pub fn fromPem(pem: []const u8, der: []u8, slices: [][]const u8) error{Invalid}!@This() {
        var entries: [255]c.ch_cert = undefined;
        var count: u8 = 0;
        try chapulin.fromCode(error{Invalid}, c.ch_chain_from_pem(pem.ptr, pem.len, der.ptr, der.len, &entries, @min(slices.len, entries.len), &count));
        for (entries[0..count], slices[0..count]) |entry, *slice| slice.* = entry.der[0..entry.len];
        return .{ .certs = slices[0..count] };
    }

    /// The end-entity certificate's DER, which EcdsaP256Key.fromPem holds the key to.
    pub fn leaf(self: @This()) []const u8 {
        if (self.certs.len == 0) return &.{};
        return self.certs[0];
    }
} else @compileError("Chain needs ROLE=server or ROLE=both");

/// A P-256 private key, decoded from a PEM file by ch_p256_key_from_pem: the scalar and its point,
/// which EcdsaP256Identity.private_key and public_key point at. The scalar is a secret: wipe zeroes
/// it once no session uses it. The program wipes the key file's text after fromPem returns, on
/// success and on error.
pub const EcdsaP256Key = if (has_p256_key) struct {
    private_key: [32]u8 = undefined,
    public_key: [64]u8 = undefined,

    /// ch_p256_key_from_pem: one PRIVATE KEY (PKCS #8) or EC PRIVATE KEY (SEC 1) block that holds
    /// a P-256 key. leaf, the end-entity certificate's DER, carries the key's point. An EC
    /// PARAMETERS block that names prime256v1 may come before an EC PRIVATE KEY block. cpu is the
    /// value a session's Server.cpu takes, in a host object alone, where null is refused.
    /// error.Invalid for a cpu, a file or a leaf that pem_files.h refuses, and both fields are then
    /// zero.
    pub fn fromPem(self: *@This(), cpu: if (has_cpu) ?chapulin.Cpu else void, pem: []const u8, leaf: []const u8) error{Invalid}!void {
        const bits: u32 = if (has_cpu) chapulin.cpuBits(cpu) else 0;
        return chapulin.fromCode(error{Invalid}, c.ch_p256_key_from_pem(bits, pem.ptr, pem.len, leaf.ptr, leaf.len, &self.private_key, &self.public_key));
    }

    /// Writes zero over the scalar, through a write the compiler keeps.
    pub fn wipe(self: *@This()) void {
        std.crypto.secureZero(u8, &self.private_key);
    }
} else @compileError("EcdsaP256Key needs ROLE=server or ROLE=both outside PROFILE=cnsa2");

/// An ML-DSA-87 key pair, expanded from a PEM file's 32-byte seed by ch_mldsa_key_from_pem:
/// the secret and public keys MlDsa87Identity.private_key and public_key point at. The secret
/// key is a secret: wipe zeroes it once no session uses it.
pub const MlDsa87Key = if (has_mldsa_key) struct {
    private_key: [4896]u8 = undefined,
    public_key: [2592]u8 = undefined,

    /// ch_mldsa_key_from_pem: one PRIVATE KEY block, a PKCS #8 OneAsymmetricKey of
    /// id-ml-dsa-87 in the seed form or the both form. leaf, the end-entity certificate's DER,
    /// carries the public key. cpu is the value a session's Server.cpu takes, where null is
    /// refused. error.Invalid for a cpu, a file or a leaf that pem_files.h refuses, and both
    /// fields are then zero.
    pub fn fromPem(self: *@This(), cpu: ?chapulin.Cpu, pem: []const u8, leaf: []const u8) error{Invalid}!void {
        return chapulin.fromCode(error{Invalid}, c.ch_mldsa_key_from_pem(chapulin.cpuBits(cpu), pem.ptr, pem.len, leaf.ptr, leaf.len, &self.private_key, &self.public_key));
    }

    /// Writes zero over the secret key, through a write the compiler keeps.
    pub fn wipe(self: *@This()) void {
        std.crypto.secureZero(u8, &self.private_key);
    }
} else @compileError("MlDsa87Key needs PROFILE=cnsa2 ROLE=server");

/// A client's trust anchors, decoded from a CA bundle by ch_anchors_from_pem into the caller's
/// rooms. anchors is the start of the caller's room that the call filled. Each anchor points into
/// the caller's DER room. So both rooms stay where fromPem filled them for as long as a session
/// uses anchors.
pub const Anchors = if (has_webpki) struct {
    /// The anchors, in the bundle's order, as Trust.web_pki.anchors takes them.
    anchors: []const chapulin.TrustAnchor = &.{},

    /// ch_anchors_from_pem: one or more CERTIFICATE blocks, with the text lines around them
    /// skipped, each read for its subject Name and SubjectPublicKeyInfo, into der and room.
    /// A BEGIN line of any other label refuses the file (pem_files.h).
    /// error.Invalid for a file pem_files.h refuses, for DER over der.len bytes, and for more
    /// blocks than room.len or limits.anchors_max. limits is the session type's, so a bundle
    /// that its session could not take is refused here. The C call writes its entries into an
    /// array of limits.anchors_max on this call's stack, because a bundle has no C cap and the
    /// API allocates nothing (docs/decisions.md 168).
    pub fn fromPem(comptime limits: chapulin.Limits, pem: []const u8, der: []u8, room: []chapulin.TrustAnchor) error{Invalid}!@This() {
        var entries: [limits.anchors_max]c.ch_trust_anchor = undefined;
        var count: usize = 0;
        try chapulin.fromCode(error{Invalid}, c.ch_anchors_from_pem(pem.ptr, pem.len, der.ptr, der.len, &entries, @min(room.len, entries.len), &count));
        for (entries[0..count], room[0..count]) |entry, *anchor| anchor.* = .{ .name = entry.name[0..entry.name_len], .spki = entry.spki[0..entry.spki_len] };
        return .{ .anchors = room[0..count] };
    }
} else @compileError("Anchors needs TRUST=webpki");
