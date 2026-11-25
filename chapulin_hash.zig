//! The hashes, HMAC and HKDF of the Zig API (docs/decisions.md 246): SHA-256, SHA-384 and SHA-512 as
//! a stream and over a whole input, SHA3-256 and SHA3-512, SHAKE128 and SHAKE256, HMAC, and HKDF's
//! Extract and Expand. The 24 C calls hash.h declares do the work, in an object built with HASH=on,
//! and chapulin.zig declares this file as chapulin.hash. Every call takes a Cpu, which runs each
//! hash where a session's would run. It sits in a file of its own for the reason chapulin_dnssec.zig
//! does. docs/zig.md is the reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_hash = @hasDecl(c, "ch_hkdf_expand");

/// CH_SHA256_LEN, CH_SHA384_LEN and CH_SHA512_LEN: the SHA-2 digest lengths.
pub const sha256_len = if (has_hash) c.CH_SHA256_LEN else @compileError("chapulin.hash.sha256_len needs HASH=on");
pub const sha384_len = if (has_hash) c.CH_SHA384_LEN else @compileError("chapulin.hash.sha384_len needs HASH=on");
pub const sha512_len = if (has_hash) c.CH_SHA512_LEN else @compileError("chapulin.hash.sha512_len needs HASH=on");
/// CH_SHA3_256_LEN and CH_SHA3_512_LEN: the SHA-3 digest lengths.
pub const sha3_256_len = if (has_hash) c.CH_SHA3_256_LEN else @compileError("chapulin.hash.sha3_256_len needs HASH=on");
pub const sha3_512_len = if (has_hash) c.CH_SHA3_512_LEN else @compileError("chapulin.hash.sha3_512_len needs HASH=on");
/// CH_HKDF_INFO_LEN_MAX: the longest info hkdf_expand takes.
pub const hkdf_info_len_max = if (has_hash) c.CH_HKDF_INFO_LEN_MAX else @compileError("chapulin.hash.hkdf_info_len_max needs HASH=on");

/// A SHA-2 hash as a stream over one of hash.h's state types. init takes the Cpu, which the state
/// keeps, so update and final take none.
fn Sha2Stream(comptime State: type, comptime length: comptime_int, comptime init_call: anytype, comptime update_call: anytype, comptime final_call: anytype) type {
    return struct {
        state: State = undefined,

        /// The digest's length in bytes.
        pub const digest_len = length;

        /// The init call: a state that hashes under cpu. error.Invalid for a Cpu that names a bit
        /// of the other architecture.
        pub fn init(cpu: chapulin.Cpu) error{Invalid}!@This() {
            var self: @This() = .{};
            try chapulin.from_code(error{Invalid}, init_call(&self.state, chapulin.cpu_bits(cpu)));
            return self;
        }

        /// The update call: adds bytes.
        pub fn update(self: *@This(), bytes: []const u8) void {
            update_call(&self.state, bytes.ptr, bytes.len);
        }

        /// The final call: the digest of every byte added, in out. The state is wiped, and a next
        /// hash starts with init.
        pub fn final(self: *@This(), out: *[length]u8) void {
            final_call(&self.state, out);
        }
    };
}

/// ch_sha256_init, ch_sha256_update and ch_sha256_final.
pub const Sha256 = if (has_hash) Sha2Stream(c.ch_sha256_state, c.CH_SHA256_LEN, c.ch_sha256_init, c.ch_sha256_update, c.ch_sha256_final) else @compileError("chapulin.hash.Sha256 needs HASH=on");
/// ch_sha384_init, ch_sha384_update and ch_sha384_final.
pub const Sha384 = if (has_hash) Sha2Stream(c.ch_sha384_state, c.CH_SHA384_LEN, c.ch_sha384_init, c.ch_sha384_update, c.ch_sha384_final) else @compileError("chapulin.hash.Sha384 needs HASH=on");
/// ch_sha512_init, ch_sha512_update and ch_sha512_final.
pub const Sha512 = if (has_hash) Sha2Stream(c.ch_sha512_state, c.CH_SHA512_LEN, c.ch_sha512_init, c.ch_sha512_update, c.ch_sha512_final) else @compileError("chapulin.hash.Sha512 needs HASH=on");

/// ch_sha256_hash: the SHA-256 digest of bytes, in out. The destination comes first, as in
/// chapulin.scram. error.Invalid for a Cpu the object refuses.
pub const sha256 = if (has_hash) sha256_of else @compileError("chapulin.hash.sha256 needs HASH=on");
fn sha256_of(cpu: chapulin.Cpu, out: *[sha256_len]u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_sha256_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out));
}

/// ch_sha384_hash: the SHA-384 digest of bytes, in out.
pub const sha384 = if (has_hash) sha384_of else @compileError("chapulin.hash.sha384 needs HASH=on");
fn sha384_of(cpu: chapulin.Cpu, out: *[sha384_len]u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_sha384_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out));
}

/// ch_sha512_hash: the SHA-512 digest of bytes, in out.
pub const sha512 = if (has_hash) sha512_of else @compileError("chapulin.hash.sha512 needs HASH=on");
fn sha512_of(cpu: chapulin.Cpu, out: *[sha512_len]u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_sha512_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out));
}

/// ch_sha3_256_hash: the SHA3-256 digest of bytes, in out.
pub const sha3_256 = if (has_hash) sha3_256_of else @compileError("chapulin.hash.sha3_256 needs HASH=on");
fn sha3_256_of(cpu: chapulin.Cpu, out: *[sha3_256_len]u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_sha3_256_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out));
}

/// ch_sha3_512_hash: the SHA3-512 digest of bytes, in out.
pub const sha3_512 = if (has_hash) sha3_512_of else @compileError("chapulin.hash.sha3_512 needs HASH=on");
fn sha3_512_of(cpu: chapulin.Cpu, out: *[sha3_512_len]u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_sha3_512_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out));
}

/// SHAKE128 or SHAKE256 as a stream: init, absorb, then squeeze, and last wipe.
fn ShakeStream(comptime init_call: anytype) type {
    return struct {
        state: c.ch_shake_state = undefined,

        /// The init call: a state under cpu. error.Invalid for a Cpu the object refuses.
        pub fn init(cpu: chapulin.Cpu) error{Invalid}!@This() {
            var self: @This() = .{};
            try chapulin.from_code(error{Invalid}, init_call(&self.state, chapulin.cpu_bits(cpu)));
            return self;
        }

        /// ch_shake_absorb: adds bytes to the message, before the first squeeze of one byte or
        /// more. An absorb after it fails the C call's assertion.
        pub fn absorb(self: *@This(), bytes: []const u8) void {
            c.ch_shake_absorb(&self.state, bytes.ptr, bytes.len);
        }

        /// ch_shake_squeeze: the next out.len bytes of the output, in out.
        pub fn squeeze(self: *@This(), out: []u8) void {
            c.ch_shake_squeeze(&self.state, out.ptr, out.len);
        }

        /// ch_shake_wipe: wipes the state once it has squeezed what the caller needs.
        pub fn wipe(self: *@This()) void {
            c.ch_shake_wipe(&self.state);
        }
    };
}

/// ch_shake128_init and the stream calls.
pub const Shake128 = if (has_hash) ShakeStream(c.ch_shake128_init) else @compileError("chapulin.hash.Shake128 needs HASH=on");
/// ch_shake256_init and the stream calls.
pub const Shake256 = if (has_hash) ShakeStream(c.ch_shake256_init) else @compileError("chapulin.hash.Shake256 needs HASH=on");

/// ch_shake128_hash: the first out.len bytes of SHAKE128 of bytes, in out.
pub const shake128 = if (has_hash) shake128_of else @compileError("chapulin.hash.shake128 needs HASH=on");
fn shake128_of(cpu: chapulin.Cpu, out: []u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_shake128_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out.ptr, out.len));
}

/// ch_shake256_hash: the first out.len bytes of SHAKE256 of bytes, in out.
pub const shake256 = if (has_hash) shake256_of else @compileError("chapulin.hash.shake256 needs HASH=on");
fn shake256_of(cpu: chapulin.Cpu, out: []u8, bytes: []const u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_shake256_hash(chapulin.cpu_bits(cpu), bytes.ptr, bytes.len, out.ptr, out.len));
}

/// The hashes hmac, hkdf_extract and hkdf_expand take: hash.h's CH_HASH_ALGORITHM_ numbers.
pub const Algorithm = if (has_hash) enum(u8) {
    sha256 = c.CH_HASH_ALGORITHM_SHA256,
    sha384 = c.CH_HASH_ALGORITHM_SHA384,
    sha512 = c.CH_HASH_ALGORITHM_SHA512,

    /// The digest length, which hmac's out and hkdf_extract's prk hold, and hkdf_expand's prk.
    pub fn digest_len(algorithm: @This()) usize {
        return switch (algorithm) {
            .sha256 => c.CH_SHA256_LEN,
            .sha384 => c.CH_SHA384_LEN,
            .sha512 => c.CH_SHA512_LEN,
        };
    }

    /// CH_HKDF_EXPAND_LEN_MAX: the most bytes hkdf_expand writes under this hash.
    pub fn hkdf_expand_len_max(algorithm: @This()) usize {
        return c.CH_HKDF_EXPAND_LEN_MAX(algorithm.digest_len());
    }
} else @compileError("chapulin.hash.Algorithm needs HASH=on");

/// What hmac takes. A caller names each field, so the key and the message do not change places.
pub const HmacOptions = if (has_hash) struct {
    algorithm: Algorithm,
    key: []const u8,
    message: []const u8,
} else @compileError("chapulin.hash.HmacOptions needs HASH=on");

/// ch_hmac: HMAC of the message under the key, in out, whose length is the algorithm's digest
/// length. error.Invalid for another out length or a Cpu the object refuses.
pub const hmac = if (has_hash) hmac_of else @compileError("chapulin.hash.hmac needs HASH=on");
fn hmac_of(cpu: chapulin.Cpu, out: []u8, options: *const HmacOptions) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_hmac(
        chapulin.cpu_bits(cpu),
        @intFromEnum(options.algorithm),
        options.key.ptr,
        options.key.len,
        options.message.ptr,
        options.message.len,
        out.ptr,
        out.len,
    ));
}

/// What hkdf_extract takes. An empty salt is RFC 5869's default.
pub const HkdfExtractOptions = if (has_hash) struct {
    algorithm: Algorithm,
    salt: []const u8,
    ikm: []const u8,
} else @compileError("chapulin.hash.HkdfExtractOptions needs HASH=on");

/// ch_hkdf_extract: HKDF-Extract's PRK, in prk, whose length is the algorithm's digest length.
/// error.Invalid for another prk length or a Cpu the object refuses.
pub const hkdf_extract = if (has_hash) hkdf_extract_of else @compileError("chapulin.hash.hkdf_extract needs HASH=on");
fn hkdf_extract_of(cpu: chapulin.Cpu, prk: []u8, options: *const HkdfExtractOptions) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_hkdf_extract(
        chapulin.cpu_bits(cpu),
        @intFromEnum(options.algorithm),
        options.salt.ptr,
        options.salt.len,
        options.ikm.ptr,
        options.ikm.len,
        prk.ptr,
        prk.len,
    ));
}

/// What hkdf_expand takes. prk holds the algorithm's digest length, as hkdf_extract writes it.
pub const HkdfExpandOptions = if (has_hash) struct {
    algorithm: Algorithm,
    prk: []const u8,
    info: []const u8,
} else @compileError("chapulin.hash.HkdfExpandOptions needs HASH=on");

/// ch_hkdf_expand: out.len bytes of HKDF-Expand's OKM, in out. error.Invalid for a prk of another
/// length, an info longer than hkdf_info_len_max, an empty out, an out longer than the
/// algorithm's hkdf_expand_len_max, or a Cpu the object refuses.
pub const hkdf_expand = if (has_hash) hkdf_expand_of else @compileError("chapulin.hash.hkdf_expand needs HASH=on");
fn hkdf_expand_of(cpu: chapulin.Cpu, out: []u8, options: *const HkdfExpandOptions) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_hkdf_expand(
        chapulin.cpu_bits(cpu),
        @intFromEnum(options.algorithm),
        options.prk.ptr,
        options.prk.len,
        options.info.ptr,
        options.info.len,
        out.ptr,
        out.len,
    ));
}
