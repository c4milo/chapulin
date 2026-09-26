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
}

pub fn main() u8 {
    if (c.ch_build_matches(hooks.record(c)) == 1) return 0;
    std.debug.print("matches: the object's build record differs from the module's types\n", .{});
    return 1;
}
