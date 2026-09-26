//! The hooks a chapulin object imports, defined once for every object a
//! program links, as docs/porting.md says an image defines them. No
//! program here completes a handshake, so ch_rand_bytes is the one hook
//! that runs, and each of the others stops the program if it does.
const std = @import("std");

/// Exports the hooks the objects of modules import. Each module is one
/// object's module "chapulin", which declares a hook exactly when its
/// object imports it: ch_keylog under KEYLOG=on and ch_aes_block where an
/// AES=extern object compiles AES. ch_assert_fail is imported by every
/// object, and ch_rand_bytes by every object but a RAND=drbg one, which
/// declares ch_drbg_seed and defines the generator for the whole image.
pub fn define(comptime modules: []const type) void {
    @export(&assertFail, .{ .name = "ch_assert_fail" });
    if (!declaredByAny(modules, "ch_drbg_seed")) @export(&randBytes, .{ .name = "ch_rand_bytes" });
    if (declaredByAny(modules, "ch_keylog")) @export(&keylog, .{ .name = "ch_keylog" });
    if (declaredByAny(modules, "ch_aes_block")) @export(&aesBlock, .{ .name = "ch_aes_block" });
}

/// The build record of the object whose module is c. build.h's ch_build
/// is a macro for the transport's record, and translate-c makes it a
/// constant whose value is that extern variable, which Zig refuses to
/// evaluate. The module declares one of the three records, and this
/// takes the one it declares.
pub fn record(comptime c: type) *const c.ch_build_info {
    if (@hasDecl(c, "ch_build_info_quic_nonblocking")) return &c.ch_build_info_quic_nonblocking;
    if (@hasDecl(c, "ch_build_info_tcp_nonblocking")) return &c.ch_build_info_tcp_nonblocking;
    return &c.ch_build_info_tcp_blocking;
}

fn declaredByAny(comptime modules: []const type, comptime name: []const u8) bool {
    inline for (modules) |module| {
        if (@hasDecl(module, name)) return true;
    }
    return false;
}

fn assertFail(cond: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.print("ASSERT {s}:{d}: {s}\n", .{ file, line, cond });
    std.process.abort();
}

/// Not a generator: a byte counter every object draws from. It never
/// writes an all-zero draw of more than one byte, which every draw site
/// in the library checks (INV-4), and no session here runs far enough for
/// its values to matter.
var next: u8 = 1;

fn randBytes(p: [*]u8, n: usize) callconv(.c) void {
    for (p[0..n]) |*byte| {
        byte.* = next;
        next +%= 1;
    }
}

fn keylog(_: ?*anyopaque, _: [*:0]const u8, _: [*]const u8, _: [*]const u8, _: usize) callconv(.c) void {
    std.process.abort();
}

fn aesBlock(_: [*]const u8, _: usize, _: [*]const u8, out: [*]u8) callconv(.c) void {
    @memset(out[0..16], 0);
    std.process.abort();
}
