//! Makes every defined symbol of a relocatable object local, except the
//! names it is given, and writes the result.
//!
//!     localize_symbols <input.o> <output.o> <name>...
//!
//! build.zig runs it on the object it partially links. It does what
//! `objcopy -G name` does for `make lib` on ELF and `nmedit -s` does on
//! Mach-O, so the Zig build needs neither binutils nor Xcode's tools, and it
//! reads the object of any target the build compiles for
//! (docs/decisions.md 69). The names are C names: the tool adds Mach-O's
//! leading underscore itself.
//!
//! It reads ELF32 and ELF64 in either byte order (localize_elf.zig) and
//! 64-bit little-endian Mach-O (localize_macho.zig). It refuses anything
//! it cannot rewrite completely: another format, a structure that may hold
//! a symbol index it does not renumber, a common symbol, and a name to keep
//! that the object does not define as a global. A refusal names its reason
//! and writes no output.
const std = @import("std");
const rules = @import("localize_rules.zig");
const elf = @import("localize_elf.zig");
const macho = @import("localize_macho.zig");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) std.process.fatal("usage: localize_symbols <input.o> <output.o> <name>...", .{});
    const cwd = std.Io.Dir.cwd();
    const bytes = cwd.readFileAlloc(init.io, args[1], arena, .unlimited) catch |err| {
        std.process.fatal("{s}: {t}", .{ args[1], err });
    };
    var report = rules.Report{ .arena = arena };
    localize(arena, bytes, args[3..], &report) catch |err| switch (err) {
        error.Refused => std.process.fatal("{s}: {s}", .{ args[1], report.message }),
        else => |other| return other,
    };
    try cwd.writeFile(init.io, .{ .sub_path = args[2], .data = bytes });
}

/// Rewrites bytes in place. The format is read from the first four bytes.
pub fn localize(arena: std.mem.Allocator, bytes: []u8, names: []const []const u8, report: *rules.Report) !void {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) return elf.localize(arena, bytes, names, report);
    if (bytes.len >= 4 and std.mem.readInt(u32, bytes[0..4], .little) == macho.magic_64) return macho.localize(arena, bytes, names, report);
    return report.refuse("the file is neither ELF nor 64-bit little-endian Mach-O", .{});
}

test {
    _ = rules;
}
