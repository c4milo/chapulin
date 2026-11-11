//! The parts of SCRAM-SHA-256 in the Zig API (docs/decisions.md 222): SHA-256, HMAC-SHA-256,
//! PBKDF2-HMAC-SHA-256, a compare in constant time, base64 and the tls-server-end-point channel
//! binding. The seven C calls scram.h declares do the work, in an object built with SCRAM=on, and
//! chapulin.zig declares this file as chapulin.scram. It sits in a file of its own for the reason
//! chapulin_dnssec.zig does. docs/zig.md is the reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;

const has_scram = @hasDecl(c, "ch_hmac_sha256");

/// CH_SHA256_LEN: the length of a SHA-256 digest and of an HMAC-SHA-256 tag.
pub const sha256_len = if (has_scram) c.CH_SHA256_LEN else @compileError("chapulin.scram.sha256_len needs SCRAM=on");

/// CH_TLS_SERVER_END_POINT_LEN_MAX: the longest tls-server-end-point value.
pub const tls_server_end_point_len_max = if (has_scram) c.CH_TLS_SERVER_END_POINT_LEN_MAX else @compileError("chapulin.scram.tls_server_end_point_len_max needs SCRAM=on");

/// CH_PBKDF2_OUT_LEN_MAX: the most bytes one pbkdf2_hmac_sha256 call writes.
pub const pbkdf2_out_len_max = if (has_scram) c.CH_PBKDF2_OUT_LEN_MAX else @compileError("chapulin.scram.pbkdf2_out_len_max needs SCRAM=on");

/// ch_sha256: the SHA-256 digest of bytes, in out. The destination comes first, as in
/// std.crypto's hash. SCRAM calls it H().
pub const sha256 = if (has_scram) sha256_of else @compileError("chapulin.scram.sha256 needs SCRAM=on");

fn sha256_of(out: *[sha256_len]u8, bytes: []const u8) void {
    c.ch_sha256(bytes.ptr, bytes.len, out);
}

/// What hmac_sha256 takes. A caller names each field, so the key and the message do not change
/// places.
pub const HmacOptions = if (has_scram) struct {
    key: []const u8,
    message: []const u8,
} else @compileError("chapulin.scram.HmacOptions needs SCRAM=on");

/// ch_hmac_sha256: HMAC-SHA-256 of the message under the key, in out.
pub const hmac_sha256 = if (has_scram) hmac_sha256_of else @compileError("chapulin.scram.hmac_sha256 needs SCRAM=on");

fn hmac_sha256_of(out: *[sha256_len]u8, options: *const HmacOptions) void {
    c.ch_hmac_sha256(options.key.ptr, options.key.len, options.message.ptr, options.message.len, out);
}

/// What pbkdf2_hmac_sha256 takes. A caller names each field, so the password and the salt do not
/// change places.
pub const Pbkdf2Options = if (has_scram) struct {
    password: []const u8,
    salt: []const u8,
    /// RFC 7677 section 4 asks for 4096 or more. A server that takes it from a peer bounds it.
    iteration_count: u32,
} else @compileError("chapulin.scram.Pbkdf2Options needs SCRAM=on");

/// ch_pbkdf2_hmac_sha256: PBKDF2 with HMAC-SHA-256, which SCRAM calls Hi(). It fills out, whose
/// length is the key's. error.Invalid for an iteration_count of 0, an empty out, or an out longer
/// than pbkdf2_out_len_max.
pub const pbkdf2_hmac_sha256 = if (has_scram) pbkdf2_hmac_sha256_of else @compileError("chapulin.scram.pbkdf2_hmac_sha256 needs SCRAM=on");

fn pbkdf2_hmac_sha256_of(out: []u8, options: *const Pbkdf2Options) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_pbkdf2_hmac_sha256(
        options.password.ptr,
        options.password.len,
        options.salt.ptr,
        options.salt.len,
        options.iteration_count,
        out.ptr,
        out.len,
    ));
}

/// ch_ct_compare: whether a and b hold the same bytes, in a time that does not show where they
/// differ. Slices of different lengths are different, and a length is public. The name is
/// std.crypto.timing_safe.eql's.
pub const timing_safe_eql = if (has_scram) timing_safe_eql_of else @compileError("chapulin.scram.timing_safe_eql needs SCRAM=on");

fn timing_safe_eql_of(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return c.ch_ct_compare(a.ptr, b.ptr, a.len) == c.CH_OK;
}

/// CH_BASE64_LEN: the length of the base64 text of byte_count bytes.
pub const base64_len = if (has_scram) base64_len_of else @compileError("chapulin.scram.base64_len needs SCRAM=on");

fn base64_len_of(byte_count: usize) usize {
    return c.CH_BASE64_LEN(byte_count);
}

/// CH_BASE64_DECODED_LEN_MAX: the most bytes that text_len characters decode to.
pub const base64_decoded_len_max = if (has_scram) base64_decoded_len_max_of else @compileError("chapulin.scram.base64_decoded_len_max needs SCRAM=on");

fn base64_decoded_len_max_of(text_len: usize) usize {
    return c.CH_BASE64_DECODED_LEN_MAX(text_len);
}

/// ch_base64_encode: the padded base64 text of bytes, in the first characters of text. The
/// destination comes first, as in std.base64. error.Cap when text is shorter than
/// base64_len(bytes.len), and then nothing is written.
pub const base64_encode = if (has_scram) base64_encode_of else @compileError("chapulin.scram.base64_encode needs SCRAM=on");

fn base64_encode_of(text: []u8, bytes: []const u8) error{Cap}![]u8 {
    var text_len: usize = 0;
    try chapulin.from_code(error{Cap}, c.ch_base64_encode(bytes.ptr, bytes.len, text.ptr, text.len, &text_len));
    return text[0..text_len];
}

/// ch_base64_decode: the bytes of canonical base64 text, in the first bytes of out. error.Cap when
/// out is shorter than the decoded length, and error.Invalid for text scram.h refuses.
pub const base64_decode = if (has_scram) base64_decode_of else @compileError("chapulin.scram.base64_decode needs SCRAM=on");

fn base64_decode_of(out: []u8, text: []const u8) error{ Cap, Invalid }![]u8 {
    var out_len: usize = 0;
    try chapulin.from_code(error{ Cap, Invalid }, c.ch_base64_decode(text.ptr, text.len, out.ptr, out.len, &out_len));
    return out[0..out_len];
}

/// ch_tls_server_end_point: the tls-server-end-point channel binding of a server's end-entity
/// certificate in DER, in the first bytes of out: 32, 48 or 64 of them. error.Invalid for bytes
/// that are not one certificate, or whose signature algorithm names no hash RFC 5929 takes.
pub const tls_server_end_point = if (has_scram) tls_server_end_point_of else @compileError("chapulin.scram.tls_server_end_point needs SCRAM=on");

fn tls_server_end_point_of(out: *[tls_server_end_point_len_max]u8, cert: []const u8) error{Invalid}![]u8 {
    var out_len: usize = 0;
    try chapulin.from_code(error{Invalid}, c.ch_tls_server_end_point(cert.ptr, cert.len, out, &out_len));
    return out[0..out_len];
}
