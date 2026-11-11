//! The JWS calls of the Zig API (docs/decisions.md 221): the check of a JSON Web Signature, which
//! a JWT login token carries, and base64url, which a token writes its parts in. The three C calls
//! jws.h declares do the work, in an object built with JWS=on, and chapulin.zig declares this file
//! as chapulin.jws. It sits in a file of its own for the reason chapulin_dnssec.zig does.
//! docs/zig.md is the reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_jws = @hasDecl(c, "ch_jws_verify");

/// The JWS algorithms verify takes (RFC 7518 section 3.1, RFC 8037 section 3.1).
pub const Algorithm = if (has_jws) enum(u8) {
    rs256 = c.CH_JWS_RS256,
    es256 = c.CH_JWS_ES256,
    eddsa = c.CH_JWS_EDDSA,
} else @compileError("chapulin.jws.Algorithm needs JWS=on");

/// What verify takes. A caller names each field, so no two slices change places.
pub const VerifyOptions = if (has_jws) struct {
    /// The algorithm of the key's own configuration, never the token header's word alone.
    algorithm: Algorithm,
    /// The public key in the algorithm's form (jws.h): RFC 3110's form for rs256, X then Y for
    /// es256, and the 32-byte key for eddsa.
    key: []const u8,
    /// The JWS Signing Input: the token's first two parts and the '.' between them.
    input: []const u8,
    /// The signature, after base64url_decode.
    signature: []const u8,
} else @compileError("chapulin.jws.VerifyOptions needs JWS=on");

/// ch_jws_verify: the signature over the input under the key. error.Auth for a signature that the
/// key does not verify, one of the wrong length among them, and error.Invalid for a key jws.h
/// refuses.
pub const verify = if (has_jws) verify_of else @compileError("chapulin.jws.verify needs JWS=on");

fn verify_of(options: *const VerifyOptions) error{ Auth, Invalid }!void {
    return chapulin.from_code(error{ Auth, Invalid }, c.ch_jws_verify(
        @intFromEnum(options.algorithm),
        options.key.ptr,
        options.key.len,
        options.input.ptr,
        options.input.len,
        options.signature.ptr,
        options.signature.len,
    ));
}

/// CH_BASE64URL_LEN: the length of the base64url text of byte_count bytes.
pub const base64url_len = if (has_jws) base64url_len_of else @compileError("chapulin.jws.base64url_len needs JWS=on");

fn base64url_len_of(byte_count: usize) usize {
    return c.CH_BASE64URL_LEN(byte_count);
}

/// CH_BASE64URL_DECODED_LEN_MAX: the most bytes that text_len characters decode to.
pub const base64url_decoded_len_max = if (has_jws) base64url_decoded_len_max_of else @compileError("chapulin.jws.base64url_decoded_len_max needs JWS=on");

fn base64url_decoded_len_max_of(text_len: usize) usize {
    return c.CH_BASE64URL_DECODED_LEN_MAX(text_len);
}

/// ch_base64url_encode: the base64url text of bytes, with no padding, in the first characters of
/// text. The destination comes first, as in std.base64. error.Cap when text is shorter than
/// base64url_len(bytes.len), and then nothing is written.
pub const base64url_encode = if (has_jws) base64url_encode_of else @compileError("chapulin.jws.base64url_encode needs JWS=on");

fn base64url_encode_of(text: []u8, bytes: []const u8) error{Cap}![]u8 {
    var text_len: usize = 0;
    try chapulin.from_code(error{Cap}, c.ch_base64url_encode(bytes.ptr, bytes.len, text.ptr, text.len, &text_len));
    return text[0..text_len];
}

/// ch_base64url_decode: the bytes of canonical base64url text, in the first bytes of out. The
/// destination comes first, as in std.base64. error.Cap when out is shorter than the decoded
/// length, and error.Invalid for text jws.h refuses.
pub const base64url_decode = if (has_jws) base64url_decode_of else @compileError("chapulin.jws.base64url_decode needs JWS=on");

fn base64url_decode_of(out: []u8, text: []const u8) error{ Cap, Invalid }![]u8 {
    var out_len: usize = 0;
    try chapulin.from_code(error{ Cap, Invalid }, c.ch_base64url_decode(text.ptr, text.len, out.ptr, out.len, &out_len));
    return out[0..out_len];
}
