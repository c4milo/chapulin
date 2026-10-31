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
} else @compileError("chapulin.dnssec.Algorithm needs DNSSEC=on");

/// The hash of an RRSIG's signed data: SHA-256 for rsasha256 and ecdsap256sha256, and SHA-512
/// for rsasha512. init starts it, update adds bytes, and final writes the digest, which check
/// takes.
pub const Hash = if (has_dnssec) struct {
    state: c.ch_dnssec_hash = undefined,

    /// ch_dnssec_hash_init. Every Algorithm has a hash, so the C call's refusal does not arise.
    pub fn init(algorithm: Algorithm) @This() {
        var self: @This() = .{};
        chapulin.fromCode(error{Invalid}, c.ch_dnssec_hash_init(&self.state, @intFromEnum(algorithm))) catch unreachable;
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
pub const verify = if (has_dnssec) verifyOf else @compileError("chapulin.dnssec.verify needs DNSSEC=on");

fn verifyOf(algorithm: Algorithm, key: []const u8, digest: []const u8, sig: []const u8) error{ Auth, Invalid }!void {
    return chapulin.fromCode(error{ Auth, Invalid }, c.ch_dnssec_verify(@intFromEnum(algorithm), key.ptr, key.len, digest.ptr, digest.len, sig.ptr, sig.len));
}
