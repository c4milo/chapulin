//! One object's program: it imports the module "chapulin" of one
//! dependency, which carries that dependency's object, and reads the
//! translated headers through chapulin.c. It compiles only when chapulin.c
//! declares every name the object exports, which the build passes as
//! exports.names; when every function chapulin.c declares under a ch_ name
//! is one the object exports or imports, the imports passed as
//! exports.imports; and when chapulin.c declares every length and cap the
//! object's public headers name, which the build passes as
//! exports.constants. It exits 0 when ch_build_matches finds the object's
//! build record equal to what the translated types compute, through
//! chapulin.c and through chapulin.buildMatches, and 1 when it does not.
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
    // The reverse. A program that calls a function the headers declare and
    // the object does not define compiles and then fails to link, so each
    // public header declares a call only under the defines of the objects
    // that define it (INV-36). chapulin.c holds a few thousand
    // declarations, and the quota covers a walk over all of them.
    @setEvalBranchQuota(100_000);
    for (std.meta.declarations(c)) |decl| {
        if (!isFunction(decl.name)) continue;
        if (!provided(decl.name)) @compileError("chapulin.c declares " ++ decl.name ++ ", which the object neither exports nor imports");
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

/// The calls the public headers define as static inline functions, so
/// chapulin.c defines each one and no object exports it: build.h's
/// ch_build_matches, result.h's ch_result_text and session_report.h's
/// read calls.
const inline_calls = [_][]const u8{
    "ch_build_matches",    "ch_result_text",  "ch_state",              "ch_group",
    "ch_suite",            "ch_psk_selected", "ch_pin_slot",           "ch_epoch",
    "ch_epoch_seen",       "ch_epoch_status", "ch_epoch_store_failed", "ch_alpn_selected",
    "ch_server_cert_type", "ch_sni_len",      "ch_read_closed",        "ch_peer_limit",
};

/// Whether chapulin.c declares name as a function under a ch_ name. The
/// names passed over are ch_build, build.h's macro for the build record,
/// which translate-c makes a constant Zig refuses to evaluate (hooks.zig),
/// and inline_calls.
fn isFunction(comptime name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "ch_")) return false;
    if (std.mem.eql(u8, name, "ch_build")) return false;
    for (inline_calls) |call| {
        if (std.mem.eql(u8, name, call)) return false;
    }
    return @typeInfo(@TypeOf(@field(c, name))) == .@"fn";
}

/// Whether the object exports or imports the function chapulin.c declares
/// as name. A header macro that gives a call its transport's symbol name,
/// ch_srv_check's among them, makes name and that symbol one function, so
/// the two are compared as functions and not as names.
fn provided(comptime name: []const u8) bool {
    for (exports.names ++ exports.imports) |symbol| {
        if (!@hasDecl(c, symbol)) continue;
        if (@TypeOf(@field(c, symbol)) != @TypeOf(@field(c, name))) continue;
        if (&@field(c, symbol) == &@field(c, name)) return true;
    }
    return false;
}

pub fn main() u8 {
    if (c.ch_build_matches(hooks.record(c)) == 1 and chapulin.buildMatches()) return 0;
    std.debug.print("matches: the object's build record differs from the translated types\n", .{});
    return 1;
}
