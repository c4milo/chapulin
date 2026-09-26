//! One object's program: it imports the module "chapulin" of one
//! dependency and links that dependency's object. It compiles only when
//! the module declares every name the object exports, which the build
//! passes as exports.names. It exits 0 when ch_build_matches finds the
//! object's build record equal to what the module's types compute, and 1
//! when it does not.
const std = @import("std");
const c = @import("chapulin");
const exports = @import("exports");
const hooks = @import("hooks.zig");

comptime {
    hooks.define(&.{c});
    for (exports.names) |name| {
        if (!@hasDecl(c, name)) @compileError("the module declares no " ++ name ++ ", which the object exports");
    }
    // A caller sizes the keys its configuration points at by these
    // lengths, so a module that declares the configuration declares them:
    // a server's two keys (srv_cfg.h) and a QUIC server's Retry token key
    // (quic_token.h). Each is evaluated, so a length the module declares
    // and cannot compute fails here as well.
    if (@hasDecl(c, "ch_srv_cfg")) keyLength(c, "SRV_COOKIE_KEY_LEN");
    if (@hasDecl(c, "ch_srv_cfg")) keyLength(c, "SRV_TICKET_KEY_LEN");
    if (@hasDecl(c, "ch_srv_quic_token_mint")) keyLength(c, "CH_QUIC_TOKEN_KEY_LEN");
}

fn keyLength(comptime module: type, comptime name: []const u8) void {
    if (!@hasDecl(module, name)) @compileError("the module declares no " ++ name ++ ", which a key is sized by");
    _ = @as(usize, @field(module, name));
}

pub fn main() u8 {
    if (c.ch_build_matches(hooks.record(c)) == 1) return 0;
    std.debug.print("matches: the object's build record differs from the module's types\n", .{});
    return 1;
}
