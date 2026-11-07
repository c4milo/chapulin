//! The DNSSEC calls of the Zig API (https://github.com/c4milo/chapulin/issues/189): a hash of an
//! RRSIG's signed data, and the check of its signature against a DNSKEY's key field. The four C
//! calls dnssec.h declares do the work, in an object built with DNSSEC=on, and chapulin.zig
//! declares this file as chapulin.dnssec. It sits in a file of its own because chapulin.zig
//! stands near the 500-line cap CLAUDE.md sets and make lint-size holds. docs/zig.md is the
//! reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_dnssec = @hasDecl(c, "ch_dnssec_verify");

/// The DNSSEC algorithm numbers the calls take (IANA's registry).
pub const Algorithm = if (has_dnssec) enum(u8) {
    rsasha256 = c.CH_DNSSEC_ALG_RSASHA256,
    rsasha512 = c.CH_DNSSEC_ALG_RSASHA512,
    ecdsap256sha256 = c.CH_DNSSEC_ALG_ECDSAP256SHA256,
    ecdsap384sha384 = c.CH_DNSSEC_ALG_ECDSAP384SHA384,
    ed25519 = c.CH_DNSSEC_ALG_ED25519,
} else @compileError("chapulin.dnssec.Algorithm needs DNSSEC=on");

/// The digest types Hash.init_digest takes, RFC 9904's DS numbers. sha1 serves an NSEC3 owner-name
/// hash too, whose hash algorithm 1 is SHA-1.
pub const DigestType = if (has_dnssec) enum(u8) {
    sha1 = c.CH_DNSSEC_DIGEST_SHA1,
    sha256 = c.CH_DNSSEC_DIGEST_SHA256,
    sha384 = c.CH_DNSSEC_DIGEST_SHA384,
} else @compileError("chapulin.dnssec.DigestType needs DNSSEC=on");

/// The hash of an RRSIG's signed data: SHA-256 for rsasha256 and ecdsap256sha256, SHA-384 for
/// ecdsap384sha384, and SHA-512 for rsasha512 and ed25519, which hashes R and the key first. init starts it, update adds
/// bytes, and final writes the digest, which verify takes.
pub const Hash = if (has_dnssec) struct {
    state: c.ch_dnssec_hash = undefined,

    /// ch_dnssec_hash_init, with the DNSKEY's key field and the RRSIG's signature, which verify
    /// takes too. error.Invalid for ed25519 with a key that is not 32 bytes or a signature that
    /// is not 64.
    pub fn init(algorithm: Algorithm, key: []const u8, sig: []const u8) error{Invalid}!@This() {
        var self: @This() = .{};
        try chapulin.from_code(error{Invalid}, c.ch_dnssec_hash_init(&self.state, @intFromEnum(algorithm), key.ptr, key.len, sig.ptr, sig.len));
        return self;
    }

    /// ch_dnssec_digest_init: a plain hash, for a DS digest or an NSEC3 owner-name hash. Every
    /// DigestType has a hash, so the C call's refusal does not arise.
    pub fn init_digest(digest_type: DigestType) @This() {
        var self: @This() = .{};
        chapulin.from_code(error{Invalid}, c.ch_dnssec_digest_init(&self.state, @intFromEnum(digest_type))) catch unreachable;
        return self;
    }

    /// ch_dnssec_hash_update.
    pub fn update(self: *@This(), bytes: []const u8) void {
        c.ch_dnssec_hash_update(&self.state, bytes.ptr, bytes.len);
    }

    /// ch_dnssec_hash_final: the digest, 32 or 64 bytes of out. The state is wiped.
    pub fn final(self: *@This(), out: *[c.CH_DNSSEC_DIGEST_MAX]u8) []const u8 {
        const n = c.ch_dnssec_hash_final(&self.state, out);
        return out[0..n];
    }
} else @compileError("chapulin.dnssec.Hash needs DNSSEC=on");

/// ch_dnssec_verify: the signature sig over digest under key, the DNSKEY's key field as it
/// arrived. error.Auth for a signature the key does not verify, and error.Invalid for a digest of
/// the wrong length or a key dnssec.h refuses.
pub const verify = if (has_dnssec) verify_of else @compileError("chapulin.dnssec.verify needs DNSSEC=on");

fn verify_of(algorithm: Algorithm, key: []const u8, digest: []const u8, sig: []const u8) error{ Auth, Invalid }!void {
    return chapulin.from_code(error{ Auth, Invalid }, c.ch_dnssec_verify(@intFromEnum(algorithm), key.ptr, key.len, digest.ptr, digest.len, sig.ptr, sig.len));
}
