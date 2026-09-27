//! One object's program: it imports the module "chapulin" of one
//! dependency, which carries that dependency's object, and reads the
//! translated headers through chapulin.c. It compiles only when chapulin.c
//! declares every name the object exports, which the build passes as
//! exports.names, and every length and cap the object's public headers
//! name, which it passes as exports.constants. It exits 0 when
//! ch_build_matches finds the object's build record equal to what the
//! translated types compute, through chapulin.c and through
//! chapulin.buildMatches, and 1 when it does not.
const std = @import("std");
const chapulin = @import("chapulin");
const c = chapulin.c;
const exports = @import("exports");
const hooks = @import("hooks.zig");

comptime {
    hooks.define(&.{c});
    for (exports.names) |name| {
        if (!@hasDecl(c, name)) @compileError("chapulin.c declares no " ++ name ++ ", which the object exports");
    }
    // A public header names the lengths and caps a caller sizes its
    // storage by, and tools/public-constants.py lists the ones this
    // object's headers name. Each is evaluated, so a length chapulin.c
    // declares and cannot compute fails here as well.
    for (exports.constants) |name| {
        if (!@hasDecl(c, name)) @compileError("chapulin.c declares no " ++ name ++ ", which a public header names");
        _ = @as(usize, @field(c, name));
    }
}

pub fn main() u8 {
    if (c.ch_build_matches(hooks.record(c)) == 1 and chapulin.buildMatches()) return 0;
    std.debug.print("matches: the object's build record differs from the translated types\n", .{});
    return 1;
}
