//! The hooks a chapulin object imports, defined once for every object a
//! program links, as docs/porting.md says an image defines them. The loop
//! programs complete handshakes, so ch_rand_bytes and, under KEYLOG=on,
//! ch_keylog run. ch_keylog keeps the io it was last given, which the QUIC
//! loop reads back through chapulin.hookContext, and every other hook stops
//! the program if it runs.
const std = @import("std");

/// Exports the hooks the objects of modules import. Each module is one
/// object's chapulin.c, which declares a hook exactly when its object
/// imports it: ch_keylog under KEYLOG=on and ch_aes_block where an
/// AES=extern object compiles AES. ch_assert_fail is imported by every
/// object, and ch_rand_bytes by every object but a RAND=drbg one, which
/// declares ch_drbg_seed and defines the generator for the whole image.
pub fn define(comptime modules: []const type) void {
    @export(&assertFail, .{ .name = "ch_assert_fail" });
    if (!declaredByAny(modules, "ch_drbg_seed")) @export(&randBytes, .{ .name = "ch_rand_bytes" });
    if (declaredByAny(modules, "ch_keylog")) @export(&keylog, .{ .name = "ch_keylog" });
    if (declaredByAny(modules, "ch_aes_block")) @export(&aesBlock, .{ .name = "ch_aes_block" });
}

/// The build record of the object whose translated headers are c. build.h's
/// ch_build is a macro for the transport's record, and translate-c makes
/// it a constant whose value is that extern variable, which Zig refuses to
/// evaluate. c declares one of the three records, and this takes the one
/// it declares.
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

/// Not a generator: a byte counter every object draws from, so both ends
/// of a loop draw different key shares and a failure replays exactly. It
/// never writes an all-zero draw of more than one byte, which every draw
/// site in the library checks (INV-4).
var next: u8 = 1;

fn randBytes(p: [*]u8, n: usize) callconv(.c) void {
    for (p[0..n]) |*byte| {
        byte.* = next;
        next +%= 1;
    }
}

/// The io the last ch_keylog call was given, and how many calls there were.
pub var keylog_io: ?*anyopaque = null;
pub var keylog_calls: usize = 0;

fn keylog(io: ?*anyopaque, _: [*:0]const u8, _: [*]const u8, _: [*]const u8, _: usize) callconv(.c) void {
    keylog_io = io;
    keylog_calls += 1;
}

fn aesBlock(_: [*]const u8, _: usize, _: [*]const u8, out: [*]u8) callconv(.c) void {
    @memset(out[0..16], 0);
    std.process.abort();
}
