//! The QUIC Retry token calls of the Zig API, each a C call of quic_token.h or srv_quic.h that
//! takes no session, because a Retry comes before one (RFC 9000 §8.1.2). chapulin_quic.zig
//! declares each under its own name, as chapulin.quic.token_mint and the rest. It sits in a file
//! of its own because chapulin_quic.zig stood at the 500-line cap CLAUDE.md sets and make
//! lint-size holds. docs/zig.md is the reference.
const chapulin = @import("chapulin.zig");
const c = chapulin.c;
const Version = chapulin.quic.Version;

const has_server = @hasDecl(c, "ch_srv_quic_init");

/// What token_mint can answer.
pub const TokenMintError = error{ Invalid, Cap };

/// The two connection IDs a Retry token carries (quic_token.h, ch_quic_retry_cids):
/// original_dcid, the Destination Connection ID of the client's first Initial, and retry_scid,
/// the Source Connection ID of the server's Retry. Each length counts bytes, at most
/// CH_QUIC_DCID_MAX. Its layout is the C struct's, so token_mint passes it as it is.
pub const RetryConnectionIds = if (has_server) extern struct {
    original_dcid: [c.CH_QUIC_DCID_MAX]u8 = @splat(0),
    original_dcid_len: u8 = 0,
    retry_scid: [c.CH_QUIC_DCID_MAX]u8 = @splat(0),
    retry_scid_len: u8 = 0,

    comptime {
        if (@sizeOf(RetryConnectionIds) != @sizeOf(c.ch_quic_retry_cids) or
            @offsetOf(RetryConnectionIds, "retry_scid") != @offsetOf(c.ch_quic_retry_cids, "retry_scid") or
            @offsetOf(RetryConnectionIds, "retry_scid_len") != @offsetOf(c.ch_quic_retry_cids, "retry_scid_len"))
            @compileError("RetryConnectionIds' layout is not ch_quic_retry_cids'");
    }

    /// Both IDs copied in, or error.Invalid for one longer than CH_QUIC_DCID_MAX.
    pub fn init(original_dcid: []const u8, retry_scid: []const u8) error{Invalid}!RetryConnectionIds {
        if (original_dcid.len > c.CH_QUIC_DCID_MAX or retry_scid.len > c.CH_QUIC_DCID_MAX) return error.Invalid;
        var ids: RetryConnectionIds = .{};
        @memcpy(ids.original_dcid[0..original_dcid.len], original_dcid);
        @memcpy(ids.retry_scid[0..retry_scid.len], retry_scid);
        ids.original_dcid_len = @intCast(original_dcid.len);
        ids.retry_scid_len = @intCast(retry_scid.len);
        return ids;
    }
} else @compileError("quic.RetryConnectionIds needs a QUIC server role");

/// What token_check found. retry: the token verified, and these are the
/// connection IDs it carried. not_retry: CH_EPROTO, the token is empty or
/// not a Retry token. invalid: CH_EAUTH, a Retry token that fails its tag,
/// its lengths or its time window (quic_token.h).
pub const TokenCheck = if (has_server) union(enum) {
    retry: RetryConnectionIds,
    not_retry,
    invalid,
} else @compileError("quic.TokenCheck needs a QUIC server role");

/// ch_srv_quic_retry_tag: the Retry integrity tag over pseudo (RFC 9001 §5.8)
/// under version's key and nonce, the original version a Retry is sent in.
/// error.Invalid for a version the object derives no keys for.
pub const retry_tag = if (has_server) retry_tag_of else @compileError("quic.retry_tag needs a QUIC server role");
fn retry_tag_of(version: Version, pseudo: []const u8, tag: *[c.CH_QUIC_RETRY_TAG_LEN]u8) error{Invalid}!void {
    return chapulin.from_code(error{Invalid}, c.ch_srv_quic_retry_tag(@intFromEnum(version), pseudo.ptr, pseudo.len, tag));
}

/// ch_srv_quic_token_mint: a Retry token for the client at address, bound
/// to version, the original version the Retry goes out in.
pub const token_mint = if (has_server) token_mint_of else @compileError("quic.token_mint needs a QUIC server role");
fn token_mint_of(key: *const [c.CH_QUIC_TOKEN_KEY_LEN]u8, version: Version, address: []const u8, ids: *const RetryConnectionIds, issued_seconds: u64, out: []u8) TokenMintError!usize {
    var n: usize = 0;
    try chapulin.from_code(TokenMintError, c.ch_srv_quic_token_mint(key, @intFromEnum(version), address.ptr, address.len, @ptrCast(ids), issued_seconds, out.ptr, out.len, &n));
    return n;
}

/// ch_srv_quic_token_check under version, the Version field of the Initial
/// that carried the token. error.Invalid for an address or a version the
/// call refuses; a token minted under another version is .invalid.
pub const token_check = if (has_server) token_check_of else @compileError("quic.token_check needs a QUIC server role");
fn token_check_of(key: *const [c.CH_QUIC_TOKEN_KEY_LEN]u8, version: Version, token: []const u8, address: []const u8, now_seconds: u64, lifetime_seconds: u64) error{Invalid}!TokenCheck {
    var ids: RetryConnectionIds = .{};
    const rc = c.ch_srv_quic_token_check(key, @intFromEnum(version), token.ptr, token.len, address.ptr, address.len, now_seconds, lifetime_seconds, @ptrCast(&ids));
    if (rc == c.CH_EPROTO) return .not_retry;
    if (rc == c.CH_EAUTH) return .invalid;
    try chapulin.from_code(error{Invalid}, rc);
    return .{ .retry = ids };
}
